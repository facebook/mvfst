/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <fizz/crypto/Utils.h>
#include <folly/stats/Histogram.h>
#include <quic/common/test/TestUtils.h>
#include <quic/tools/tperf/TperfDSRSender.h>
#include <quic/tools/tperf/TperfQLogger.h>
#include <quic/tools/tperf/TperfServer.h>

namespace quic::tperf {

class ServerStreamHandler : public quic::QuicSocket::ConnectionSetupCallback,
                            public quic::QuicSocket::ConnectionCallback,
                            public quic::QuicSocket::ReadCallback,
                            public quic::QuicSocket::WriteCallback,
                            public quic::QuicTimerCallback,
                            public QuicSocketLite::ByteEventCallback {
 public:
  explicit ServerStreamHandler(
      folly::EventBase* evbIn,
      uint64_t blockSize,
      uint32_t numStreams,
      uint64_t maxBytesPerStream,
      folly::AsyncUDPSocket& sock,
      bool dsrEnabled,
      uint32_t burstDeadlineMs,
      uint64_t maxPacingRate,
      TPerfServer::DoneCallback* doneCallback)
      : evb_(std::make_shared<FollyQuicEventBase>(evbIn)),
        udpSock_(FollyQuicAsyncUDPSocket(evb_, sock)),
        blockSize_(blockSize),
        numStreams_(numStreams),
        maxBytesPerStream_(maxBytesPerStream),
        dsrEnabled_(dsrEnabled),
        burstDeadlineMs_(burstDeadlineMs),
        maxPacingRate_(maxPacingRate),
        doneCallback_(doneCallback) {
    buf_ = folly::IOBuf::createCombined(blockSize_);
  }

  void setQuicSocket(std::shared_ptr<quic::QuicSocket> socket) {
    sock_ = socket;
  }

  void onNewBidirectionalStream(quic::StreamId id) noexcept override {
    LOG(INFO) << "Got bidirectional stream id=" << id;
    sock_->setReadCallback(id, this);
  }

  void onNewUnidirectionalStream(quic::StreamId id) noexcept override {
    LOG(INFO) << "Got unidirectional stream id=" << id;
    sock_->setReadCallback(id, this);
  }

  void onStopSending(
      quic::StreamId id,
      quic::ApplicationErrorCode error) noexcept override {
    LOG(INFO) << "Got StopSending stream id=" << id << " error=" << error;
  }

  void onConnectionEnd() noexcept override {
    LOG(INFO) << "Socket closed";
    auto srtt = sock_->getTransportInfo().srtt.count();
    sock_.reset();
    if (burstDeadlineMs_ > 0) {
      auto resultStr =
          fmt::format("Burst send stats, burst size of {}\n", blockSize_);
      resultStr += fmt::format("  * total bursts sent: {}\n", batchN_);
      resultStr +=
          fmt::format("  * delivered: {}\n", burstSendStats_.delivered);
      resultStr += fmt::format(
          "  * missed deadline: {}\n", burstSendStats_.missedDeadline);

      resultStr += fmt::format("Burst ack latency stats, microseconds:\n");
      resultStr += fmt::format(
          "  * p5: {}\n",
          burstSendAckedLatencyHistogramMicroseconds_.getPercentileEstimate(
              0.05));
      resultStr += fmt::format(
          "  * p50: {}\n",
          burstSendAckedLatencyHistogramMicroseconds_.getPercentileEstimate(
              0.5));
      resultStr += fmt::format(
          "  * p95: {}\n",
          burstSendAckedLatencyHistogramMicroseconds_.getPercentileEstimate(
              0.95));

      resultStr += fmt::format(
          "Burst true (tx-based) ack latency stats, microseconds:\n");
      resultStr += fmt::format(
          "  * p5: {}\n",
          burstSendTrueAckedLatencyHistogramMicroseconds_.getPercentileEstimate(
              0.05));
      resultStr += fmt::format(
          "  * p50: {}\n",
          burstSendTrueAckedLatencyHistogramMicroseconds_.getPercentileEstimate(
              0.5));
      resultStr += fmt::format(
          "  * p95: {}\n",
          burstSendTrueAckedLatencyHistogramMicroseconds_.getPercentileEstimate(
              0.95));

      resultStr += fmt::format("\nmvfst srtt: {}\n", srtt);

      if (doneCallback_) {
        doneCallback_->onDone(resultStr);
      } else {
        LOG(ERROR) << resultStr;
      }
    }
  }

  void onConnectionSetupError(QuicError error) noexcept override {
    onConnectionError(std::move(error));
  }

  void onConnectionError(QuicError error) noexcept override {
    LOG(ERROR) << "Conn errorCoded=" << toString(error.code)
               << ", errorMsg=" << error.message;
  }

  void onTransportReady() noexcept override {
    if (maxPacingRate_ != std::numeric_limits<uint64_t>::max()) {
      sock_->setMaxPacingRate(maxPacingRate_);
    }
    LOG(INFO) << "Starting sends to client.";
    if (burstDeadlineMs_ > 0) {
      doBurstSending();
    } else {
      for (uint32_t i = 0; i < numStreams_; i++) {
        createNewStream();
      }
    }
  }

  void createNewStream() noexcept {
    if (!sock_) {
      VLOG(4) << __func__ << ": socket is closed.";
      return;
    }
    auto stream = sock_->createUnidirectionalStream();
    VLOG(5) << "New Stream with id = " << stream.value();
    CHECK(stream.hasValue());
    bytesPerStream_[stream.value()] = 0;
    notifyDataForStream(stream.value());
  }

  void notifyDataForStream(quic::StreamId id) {
    evb_->runInEventBaseThread([&, id]() {
      if (!sock_) {
        VLOG(5) << "notifyDataForStream(" << id << "): socket is closed.";
        return;
      }
      auto res = sock_->notifyPendingWriteOnStream(id, this);
      if (res.hasError()) {
        LOG(FATAL) << quic::toString(res.error());
      }
    });
  }

  void readAvailable(quic::StreamId id) noexcept override {
    LOG(INFO) << "read available for stream id=" << id;
  }

  void readError(quic::StreamId id, QuicError error) noexcept override {
    LOG(ERROR) << "Got read error on stream=" << id
               << " error=" << toString(error);
    // A read error only terminates the ingress portion of the stream state.
    // Your application should probably terminate the egress portion via
    // resetStream
  }

  void onStreamWriteReady(quic::StreamId id, uint64_t maxToSend) noexcept
      override {
    bool eof = false;
    uint64_t toSend = std::min<uint64_t>(maxToSend, blockSize_);
    if (maxBytesPerStream_ > 0) {
      toSend =
          std::min<uint64_t>(toSend, maxBytesPerStream_ - bytesPerStream_[id]);
      bytesPerStream_[id] += toSend;
      if (bytesPerStream_[id] >= maxBytesPerStream_) {
        eof = true;
      }
    }
    if (dsrEnabled_ && (((id - 3) / 4) % 2) == 0) {
      dsrSend(id, toSend, eof);
    } else {
      regularSend(id, toSend, eof);
    }
    if (!eof) {
      notifyDataForStream(id);
    } else {
      bytesPerStream_.erase(id);
      createNewStream();
    }
  }

  void onStreamWriteError(quic::StreamId id, QuicError error) noexcept
      override {
    LOG(ERROR) << "write error with stream=" << id
               << " error=" << toString(error);
  }

  folly::EventBase* getEventBase() {
    return evb_->getBackingEventBase();
  }

 private:
  void dsrSend(quic::StreamId id, uint64_t toSend, bool eof) {
    if (streamsHavingDSRSender_.find(id) == streamsHavingDSRSender_.end()) {
      auto dsrSender =
          std::make_unique<TperfDSRSender>(buf_->clone(), udpSock_);
      auto serverTransport = dynamic_cast<QuicServerTransport*>(sock_.get());
      dsrSender->setCipherInfo(serverTransport->getOneRttCipherInfo());
      auto res =
          sock_->setDSRPacketizationRequestSender(id, std::move(dsrSender));
      if (res.hasError()) {
        LOG(FATAL) << "Got error on write: " << quic::toString(res.error());
      }
      // OK I don't know when to erase it...
      streamsHavingDSRSender_.insert(id);
      // Some real data has to be written before BufMeta is written, and we
      // can only do it once:
      res = sock_->writeChain(id, folly::IOBuf::copyBuffer("Lame"), false);
      if (res.hasError()) {
        LOG(FATAL) << "Got error on write: " << quic::toString(res.error());
      }
    }
    BufferMeta bufferMeta(toSend);
    auto res = sock_->writeBufMeta(id, bufferMeta, eof, nullptr);
    if (res.hasError()) {
      LOG(FATAL) << "Got error on write: " << quic::toString(res.error());
    }
  }

  void regularSend(quic::StreamId id, uint64_t toSend, bool eof) {
    auto sendBuffer = buf_->clone();
    sendBuffer->append(toSend);
    auto res = sock_->writeChain(id, std::move(sendBuffer), eof, nullptr);
    if (res.hasError()) {
      LOG(FATAL) << "Got error on write: " << quic::toString(res.error());
    }
  }

  void doBurstSending() {
    if (!sock_) {
      return;
    }

    VLOG(4) << "sending batch " << batchN_;
    ++batchN_;

    auto stream = sock_->createUnidirectionalStream();
    VLOG(5) << "New Stream with id = " << stream.value();
    CHECK(stream.hasValue());
    streamBurstSendResult_.streamId = *stream;
    streamBurstSendResult_.acked = false;
    streamBurstSendResult_.startTs = Clock::now();

    auto sendBuffer = buf_->clone();
    sendBuffer->append(blockSize_);
    CHECK_GT(blockSize_, 0);
    auto r = sock_->registerTxCallback(*stream, 0, this);
    if (r.hasError()) {
      LOG(FATAL) << "Got error on registerTxCallback: "
                 << quic::toString(r.error());
    }
    auto res = sock_->writeChain(
        *stream,
        std::move(sendBuffer),
        true /* eof */,
        this /* byte events callback */);
    if (res.hasError()) {
      LOG(FATAL) << "Got error on write: " << quic::toString(res.error());
    }

    // Schedule deadline.
    evb_->scheduleTimeoutHighRes(
        this, std::chrono::milliseconds(burstDeadlineMs_));
  }

  void onByteEvent(QuicSocketLite::ByteEvent byteEvent) override {
    CHECK_EQ(byteEvent.id, streamBurstSendResult_.streamId);
    auto now = Clock::now();
    if (byteEvent.type == QuicSocketLite::ByteEvent::Type::TX) {
      streamBurstSendResult_.trueTxStartTs = now;
    } else if (byteEvent.type == QuicSocketLite::ByteEvent::Type::ACK) {
      auto ackedLatencyUs =
          std::chrono::duration_cast<std::chrono::microseconds>(
              now - streamBurstSendResult_.startTs);
      burstSendAckedLatencyHistogramMicroseconds_.addValue(
          ackedLatencyUs.count());

      auto trueAckedLatencyUs =
          std::chrono::duration_cast<std::chrono::microseconds>(
              now - streamBurstSendResult_.trueTxStartTs);
      burstSendTrueAckedLatencyHistogramMicroseconds_.addValue(
          trueAckedLatencyUs.count());
      VLOG(4) << "got stream " << byteEvent.id << " offset " << byteEvent.offset
              << " acked (" << trueAckedLatencyUs.count() << "us)";

      streamBurstSendResult_.acked = true;
      ++burstSendStats_.delivered;
    }
  }

  void onByteEventCanceled(
      QuicSocketLite::ByteEventCancellation cancellation) override {
    VLOG(4) << "got stream " << cancellation.id << " offset "
            << cancellation.offset << " cancelled";
  }

  void timeoutExpired() noexcept override {
    if (!sock_) {
      return;
    }

    if (!streamBurstSendResult_.acked) {
      LOG(ERROR) << "resetting stream " << streamBurstSendResult_.streamId
                 << " on deadline";
      ++burstSendStats_.missedDeadline;
      sock_->resetStream(
          streamBurstSendResult_.streamId,
          GenericApplicationErrorCode::NO_ERROR);
    }
    doBurstSending();
  }

  void callbackCanceled() noexcept override {}

 private:
  std::shared_ptr<quic::QuicSocket> sock_;
  std::shared_ptr<FollyQuicEventBase> evb_;
  FollyQuicAsyncUDPSocket udpSock_;
  uint64_t blockSize_;
  std::unique_ptr<folly::IOBuf> buf_;
  uint32_t numStreams_;
  uint64_t maxBytesPerStream_;
  std::unordered_map<quic::StreamId, uint64_t> bytesPerStream_;
  std::set<quic::StreamId> streamsHavingDSRSender_;
  bool dsrEnabled_;
  uint32_t burstDeadlineMs_;
  uint64_t maxPacingRate_;

  // Burst sending machinery.
  uint64_t batchN_{0};
  struct {
    quic::StreamId streamId;
    bool acked{false};
    TimePoint startTs;
    TimePoint trueTxStartTs;
  } streamBurstSendResult_;
  struct {
    uint64_t missedDeadline{0};
    uint64_t delivered{0};
  } burstSendStats_;
  folly::Histogram<uint64_t> burstSendAckedLatencyHistogramMicroseconds_{
      100, /* bucket size */
      0, /* min */
      1000000 /* 1 sec max delay */};
  folly::Histogram<uint64_t> burstSendTrueAckedLatencyHistogramMicroseconds_{
      100, /* bucket size */
      0, /* min */
      1000000 /* 1 sec max delay */};
  TPerfServer::DoneCallback* doneCallback_{nullptr};
};

class TPerfServerTransportFactory : public quic::QuicServerTransportFactory {
 public:
  ~TPerfServerTransportFactory() override = default;

  TPerfServerTransportFactory(
      uint64_t blockSize,
      uint32_t numStreams,
      uint64_t maxBytesPerStream,
      bool dsrEnabled,
      uint32_t burstDeadlineMs,
      uint64_t maxPacingRate,
      std::string qloggerPath,
      std::string pacingObserver,
      TPerfServer::DoneCallback* doneCallback)
      : blockSize_(blockSize),
        numStreams_(numStreams),
        maxBytesPerStream_(maxBytesPerStream),
        dsrEnabled_(dsrEnabled),
        burstDeadlineMs_(burstDeadlineMs),
        maxPacingRate_(maxPacingRate),
        qloggerPath_(qloggerPath),
        pacingObserver_(pacingObserver),
        doneCallback_(doneCallback) {}

  quic::QuicServerTransport::Ptr make(
      folly::EventBase* evb,
      std::unique_ptr<folly::AsyncUDPSocket> sock,
      const folly::SocketAddress&,
      QuicVersion,
      std::shared_ptr<const fizz::server::FizzServerContext> ctx) noexcept
      override {
    CHECK_EQ(evb, sock->getEventBase());
    auto serverHandler = std::make_unique<ServerStreamHandler>(
        evb,
        blockSize_,
        numStreams_,
        maxBytesPerStream_,
        *sock,
        dsrEnabled_,
        burstDeadlineMs_,
        maxPacingRate_,
        doneCallback_);
    auto transport = quic::QuicServerTransport::make(
        evb, std::move(sock), serverHandler.get(), serverHandler.get(), ctx);
    if (!qloggerPath_.empty()) {
      auto qlogger =
          std::make_shared<TperfQLogger>(VantagePoint::Server, qloggerPath_);
      setPacingObserver(qlogger, transport.get(), pacingObserver_);
      transport->setQLogger(std::move(qlogger));
    }
    serverHandler->setQuicSocket(transport);
    handlers_.push_back(std::move(serverHandler));
    return transport;
  }

 private:
  void setPacingObserver(
      std::shared_ptr<TperfQLogger>& qlogger,
      quic::QuicServerTransport* transport,
      const std::string& pacingObserverType) {
    if (pacingObserverType == "time") {
      qlogger->setPacingObserver(
          std::make_unique<FixedBucketQLogPacingObserver>(qlogger, 3ms));
    } else if (pacingObserverType == "rtt") {
      qlogger->setPacingObserver(std::make_unique<RttBucketQLogPacingObserver>(
          qlogger, *transport->getState()));
    } else if (pacingObserverType == "ack") {
      qlogger->setPacingObserver(std::make_unique<QLogPacingObserver>(qlogger));
    }
  }

  std::vector<std::unique_ptr<ServerStreamHandler>> handlers_;
  uint64_t blockSize_;
  uint32_t numStreams_;
  uint64_t maxBytesPerStream_;
  bool dsrEnabled_;
  uint32_t burstDeadlineMs_;
  uint64_t maxPacingRate_;
  std::string qloggerPath_;
  std::string pacingObserver_;
  TPerfServer::DoneCallback* doneCallback_{nullptr};
};

TPerfServer::TPerfServer(
    const std::string& host,
    uint16_t port,
    uint64_t blockSize,
    uint64_t writesPerLoop,
    quic::CongestionControlType congestionControlType,
    bool gso,
    uint32_t maxCwndInMss,
    bool pacing,
    uint32_t numStreams,
    uint64_t maxBytesPerStream,
    uint32_t maxReceivePacketSize,
    bool useInplaceWrite,
    bool dsrEnabled,
    bool overridePacketSize,
    double latencyFactor,
    bool useAckReceiveTimestamps,
    uint32_t maxAckReceiveTimestampsToSend,
    bool useL4sEcn,
    bool readEcn,
    uint32_t dscp,
    uint32_t numServerWorkers,
    uint32_t burstDeadlineMs,
    uint64_t maxPacingRate,
    bool logAppRateLimited,
    bool logLoss,
    bool logRttSample,
    std::string qloggerPath,
    const std::string& pacingObserver,
    DoneCallback* doneCallback)
    : host_(host),
      port_(port),
      acceptObserver_(std::make_unique<TPerfAcceptObserver>(
          logAppRateLimited,
          logLoss,
          logRttSample)),
      latencyFactor_(latencyFactor),
      useAckReceiveTimestamps_(useAckReceiveTimestamps),
      maxAckReceiveTimestampsToSend_(maxAckReceiveTimestampsToSend),
      useL4sEcn_(useL4sEcn),
      readEcn_(readEcn),
      dscp_(dscp),
      numServerWorkers_(numServerWorkers),
      burstDeadlineMs_(burstDeadlineMs),
      maxPacingRate_(maxPacingRate) {
  fizz::CryptoUtils::init();
  eventBase_.setName("tperf_server");
  quic::TransportSettings settings;
  if (useInplaceWrite && gso) {
    settings.dataPathType = DataPathType::ContinuousMemory;
  } else {
    settings.dataPathType = DataPathType::ChainedMemory;
  }
  settings.maxCwndInMss = maxCwndInMss;
  settings.writeConnectionDataPacketsLimit = writesPerLoop;
  settings.defaultCongestionController = congestionControlType;
  settings.pacingEnabled = pacing;
  if (pacing) {
    settings.pacingTickInterval = 200us;
    settings.writeLimitRttFraction = 0;
  }
  if (gso) {
    settings.batchingMode = QuicBatchingMode::BATCHING_MODE_GSO;
    settings.maxBatchSize = writesPerLoop;
  }
  settings.maxRecvPacketSize = maxReceivePacketSize;
  settings.canIgnorePathMTU = overridePacketSize;
  settings.copaDeltaParam = latencyFactor_;
  if (useAckReceiveTimestamps_) {
    LOG(INFO) << " Using ACK receive timestamps on server";
    settings.maybeAckReceiveTimestampsConfigSentToPeer.assign(
        {maxAckReceiveTimestampsToSend_, kDefaultReceiveTimestampsExponent});
  }

  if (useL4sEcn_) {
    settings.enableEcnOnEgress = true;
    settings.useL4sEcn = true;
    settings.minBurstPackets = 1;
    settings.experimentalPacer = true;
    settings.ccaConfig.onlyGrowCwndWhenLimited = true;
    settings.ccaConfig.leaveHeadroomForCwndLimited = true;
  }

  settings.readEcnOnIngress = readEcn_;
  settings.dscpValue = dscp_;

  server_ = QuicServer::createQuicServer(settings);
  server_->setQuicServerTransportFactory(
      std::make_unique<TPerfServerTransportFactory>(
          blockSize,
          numStreams,
          maxBytesPerStream,
          dsrEnabled,
          burstDeadlineMs_,
          maxPacingRate_,
          qloggerPath,
          pacingObserver,
          doneCallback));
  auto serverCtx = quic::test::createServerCtx();
  serverCtx->setClock(std::make_shared<fizz::SystemClock>());
  server_->setFizzContext(serverCtx);

  server_->setCongestionControllerFactory(
      std::make_shared<ServerCongestionControllerFactory>());
}

void TPerfServer::start() {
  // Create a SocketAddress and the default or passed in host.
  folly::SocketAddress addr1(host_.c_str(), port_);
  addr1.setFromHostPort(host_, port_);
  server_->start(addr1, numServerWorkers_);
  auto workerEvbs = server_->getWorkerEvbs();
  for (auto evb : workerEvbs) {
    server_->addAcceptObserver(evb, acceptObserver_.get());
  }
  LOG(INFO) << "tperf server started at: " << addr1.describe();
  eventBase_.loopForever();
}

} // namespace quic::tperf
