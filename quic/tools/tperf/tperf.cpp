/*
 * Copyright (c) Facebook, Inc. and its affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 *
 */

#include <glog/logging.h>

#include <fizz/crypto/Utils.h>
#include <folly/init/Init.h>
#include <folly/io/async/HHWheelTimer.h>
#include <folly/portability/GFlags.h>
#include <folly/stats/Histogram.h>

#include <quic/client/QuicClientTransport.h>
#include <quic/common/test/TestUtils.h>
#include <quic/congestion_control/CongestionControllerFactory.h>
#include <quic/fizz/client/handshake/FizzClientQuicHandshakeContext.h>
#include <quic/server/QuicServer.h>
#include <quic/server/QuicServerTransport.h>
#include <quic/server/QuicSharedUDPSocketFactory.h>
#include <quic/tools/tperf/PacingObserver.h>
#include <quic/tools/tperf/TperfQLogger.h>

DEFINE_string(host, "::1", "TPerf server hostname/IP");
DEFINE_int32(port, 6666, "TPerf server port");
DEFINE_string(mode, "server", "Mode to run in: 'client' or 'server'");
DEFINE_int32(duration, 10, "Duration of test in seconds");
DEFINE_uint64(
    block_size,
    4096,
    "Amount of data written to stream each iteration");
DEFINE_uint64(writes_per_loop, 5, "Amount of socket writes per event loop");
DEFINE_uint64(window, 64 * 1024, "Flow control window size");
DEFINE_string(congestion, "newreno", "newreno/cubic/bbr/none");
DEFINE_bool(pacing, false, "Enable pacing");
DEFINE_bool(gso, false, "Enable GSO writes to the socket");
DEFINE_uint32(
    client_transport_timer_resolution_ms,
    1,
    "Timer resolution for Ack and Loss tiemout in client transport");
DEFINE_string(
    server_qlogger_path,
    "",
    "Path to the directory where qlog files will be written. File will be named"
    " as <CID>.qlog where CID is the DCID from client's perspective.");
DEFINE_uint32(
    max_cwnd_mss,
    quic::kLargeMaxCwndInMss,
    "Max cwnd in the unit of mss");
DEFINE_uint32(num_streams, 1, "Number of streams to send on simultaneously");
DEFINE_uint64(
    bytes_per_stream,
    0,
    "Maximum number of bytes per stream. "
    "0 (the default) means the stream lives for the whole duration of the test.");
DEFINE_string(
    pacing_observer,
    "none",
    "none/time/rtt/ack: Pacing observer bucket type: per 3ms, per rtt or per ack");
DEFINE_uint32(
    max_receive_packet_size,
    std::max(
        quic::kDefaultV4UDPSendPacketLen,
        quic::kDefaultV6UDPSendPacketLen),
    "Maximum packet size to advertise to the peer.");

namespace quic {
namespace tperf {

class ServerStreamHandler : public quic::QuicSocket::ConnectionCallback,
                            public quic::QuicSocket::ReadCallback,
                            public quic::QuicSocket::WriteCallback {
 public:
  explicit ServerStreamHandler(
      folly::EventBase* evbIn,
      uint64_t blockSize,
      uint32_t numStreams,
      uint64_t maxBytesPerStream)
      : evb_(evbIn),
        blockSize_(blockSize),
        numStreams_(numStreams),
        maxBytesPerStream_(maxBytesPerStream) {}

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
    sock_.reset();
  }

  void onConnectionError(
      std::pair<quic::QuicErrorCode, std::string> error) noexcept override {
    LOG(ERROR) << "Socket error=" << toString(error.first);
  }

  void onTransportReady() noexcept override {
    LOG(INFO) << "Starting sends to client.";
    for (uint32_t i = 0; i < numStreams_; i++) {
      createNewStream();
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

  void readError(
      quic::StreamId id,
      std::pair<quic::QuicErrorCode, folly::Optional<folly::StringPiece>>
          error) noexcept override {
    LOG(ERROR) << "Got read error on stream=" << id
               << " error=" << toString(error);
    // A read error only terminates the ingress portion of the stream state.
    // Your application should probably terminate the egress portion via
    // resetStream
  }

  void onStreamWriteReady(
      quic::StreamId id,
      uint64_t maxToSend) noexcept override {
    bool eof = false;
    uint64_t toSend = maxToSend;
    if (maxBytesPerStream_ > 0) {
      toSend =
          std::min<uint64_t>(toSend, maxBytesPerStream_ - bytesPerStream_[id]);
      bytesPerStream_[id] += toSend;
      if (bytesPerStream_[id] >= maxBytesPerStream_) {
        eof = true;
      }
    }
    auto buf = folly::IOBuf::createChain(toSend, blockSize_);
    auto curBuf = buf.get();
    do {
      curBuf->append(curBuf->capacity());
      curBuf = curBuf->next();
    } while (curBuf != buf.get());
    auto res = sock_->writeChain(id, std::move(buf), eof, true, nullptr);
    if (res.hasError()) {
      LOG(FATAL) << "Got error on write: " << quic::toString(res.error());
    }
    if (!eof) {
      notifyDataForStream(id);
    } else {
      bytesPerStream_.erase(id);
      createNewStream();
    }
  }

  void onStreamWriteError(
      quic::StreamId id,
      std::pair<quic::QuicErrorCode, folly::Optional<folly::StringPiece>>
          error) noexcept override {
    LOG(ERROR) << "write error with stream=" << id
               << " error=" << toString(error);
  }

  folly::EventBase* getEventBase() {
    return evb_;
  }

 private:
  std::shared_ptr<quic::QuicSocket> sock_;
  folly::EventBase* evb_;
  uint64_t blockSize_;
  uint32_t numStreams_;
  uint64_t maxBytesPerStream_;
  std::unordered_map<quic::StreamId, uint64_t> bytesPerStream_;
};

class TPerfServerTransportFactory : public quic::QuicServerTransportFactory {
 public:
  ~TPerfServerTransportFactory() override = default;

  explicit TPerfServerTransportFactory(
      uint64_t blockSize,
      uint32_t numStreams,
      uint64_t maxBytesPerStream)
      : blockSize_(blockSize),
        numStreams_(numStreams),
        maxBytesPerStream_(maxBytesPerStream) {}

  quic::QuicServerTransport::Ptr make(
      folly::EventBase* evb,
      std::unique_ptr<folly::AsyncUDPSocket> sock,
      const folly::SocketAddress&,
      std::shared_ptr<const fizz::server::FizzServerContext>
          ctx) noexcept override {
    CHECK_EQ(evb, sock->getEventBase());
    auto serverHandler = std::make_unique<ServerStreamHandler>(
        evb, blockSize_, numStreams_, maxBytesPerStream_);
    auto transport = quic::QuicServerTransport::make(
        evb, std::move(sock), *serverHandler, ctx);
    if (!FLAGS_server_qlogger_path.empty()) {
      auto qlogger = std::make_shared<TperfQLogger>(
          VantagePoint::Server, FLAGS_server_qlogger_path);
      setPacingObserver(qlogger, transport.get(), FLAGS_pacing_observer);
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
};

class TPerfServer {
 public:
  explicit TPerfServer(
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
      uint32_t maxReceivePacketSize)
      : host_(host), port_(port), server_(QuicServer::createQuicServer()) {
    eventBase_.setName("tperf_server");
    server_->setQuicServerTransportFactory(
        std::make_unique<TPerfServerTransportFactory>(
            blockSize, numStreams, maxBytesPerStream));
    auto serverCtx = quic::test::createServerCtx();
    serverCtx->setClock(std::make_shared<fizz::SystemClock>());
    server_->setFizzContext(serverCtx);
    quic::TransportSettings settings;
    settings.maxCwndInMss = maxCwndInMss;
    settings.writeConnectionDataPacketsLimit = writesPerLoop;
    settings.defaultCongestionController = congestionControlType;
    settings.pacingEnabled = pacing;
    if (pacing) {
      settings.pacingTimerTickInterval = 200us;
    }
    if (gso) {
      settings.batchingMode = QuicBatchingMode::BATCHING_MODE_GSO;
      settings.maxBatchSize = 16;
    }
    settings.maxRecvPacketSize = maxReceivePacketSize;
    settings.canIgnorePathMTU = true;
    server_->setTransportSettings(settings);
  }

  void start() {
    // Create a SocketAddress and the default or passed in host.
    folly::SocketAddress addr1(host_.c_str(), port_);
    addr1.setFromHostPort(host_, port_);
    server_->start(addr1, 0);
    LOG(INFO) << "tperf server started at: " << addr1.describe();
    eventBase_.loopForever();
  }

 private:
  std::string host_;
  uint16_t port_;
  folly::EventBase eventBase_;
  std::shared_ptr<quic::QuicServer> server_;
};

class TPerfClient : public quic::QuicSocket::ConnectionCallback,
                    public quic::QuicSocket::ReadCallback,
                    public quic::QuicSocket::WriteCallback,
                    public folly::HHWheelTimer::Callback {
 public:
  TPerfClient(
      const std::string& host,
      uint16_t port,
      std::chrono::milliseconds transportTimerResolution,
      int32_t duration,
      uint64_t window,
      bool gso,
      quic::CongestionControlType congestionControlType,
      uint32_t maxReceivePacketSize)
      : host_(host),
        port_(port),
        eventBase_(transportTimerResolution),
        duration_(duration),
        window_(window),
        gso_(gso),
        congestionControlType_(congestionControlType),
        maxReceivePacketSize_(maxReceivePacketSize) {
    eventBase_.setName("tperf_client");
  }

  void timeoutExpired() noexcept override {
    quicClient_->closeNow(folly::none);
    constexpr double bytesPerMegabit = 131072;
    LOG(INFO) << "Received " << receivedBytes_ << " bytes in "
              << duration_.count() << " seconds.";
    LOG(INFO) << "Overall throughput: "
              << (receivedBytes_ / bytesPerMegabit) / duration_.count()
              << "Mb/s";
    // Per Stream Stats
    LOG(INFO) << "Average per Stream throughput: "
              << ((receivedBytes_ / receivedStreams_) / bytesPerMegabit) /
            duration_.count()
              << "Mb/s over " << receivedStreams_ << " streams";
    if (receivedStreams_ != 1) {
      LOG(INFO) << "Histogram per Stream bytes: " << std::endl;
      LOG(INFO) << "Lo\tHi\tNum\tSum";
      for (const auto bytes : bytesPerStream_) {
        bytesPerStreamHistogram_.addValue(bytes.second);
      }
      std::ostringstream os;
      bytesPerStreamHistogram_.toTSV(os);
      std::vector<std::string> lines;
      folly::split("\n", os.str(), lines);
      for (const auto& line : lines) {
        LOG(INFO) << line;
      }
    }
  }

  virtual void callbackCanceled() noexcept override {}

  void readAvailable(quic::StreamId streamId) noexcept override {
    auto readData = quicClient_->read(streamId, 0);
    if (readData.hasError()) {
      LOG(FATAL) << "TPerfClient failed read from stream=" << streamId
                 << ", error=" << (uint32_t)readData.error();
    }

    auto readBytes = readData->first->computeChainDataLength();
    receivedBytes_ += readBytes;
    bytesPerStream_[streamId] += readBytes;
    if (readData.value().second) {
      bytesPerStreamHistogram_.addValue(bytesPerStream_[streamId]);
      bytesPerStream_.erase(streamId);
    }
  }

  void readError(
      quic::StreamId /*streamId*/,
      std::pair<quic::QuicErrorCode, folly::Optional<folly::StringPiece>>
      /*error*/) noexcept override {
    // A read error only terminates the ingress portion of the stream state.
    // Your application should probably terminate the egress portion via
    // resetStream
  }

  void onNewBidirectionalStream(quic::StreamId id) noexcept override {
    LOG(INFO) << "TPerfClient: new bidirectional stream=" << id;
    quicClient_->setReadCallback(id, this);
  }

  void onNewUnidirectionalStream(quic::StreamId id) noexcept override {
    VLOG(5) << "TPerfClient: new unidirectional stream=" << id;
    if (!timerScheduled_) {
      timerScheduled_ = true;
      eventBase_.timer().scheduleTimeout(this, duration_);
    }
    quicClient_->setReadCallback(id, this);
    receivedStreams_++;
  }

  void onTransportReady() noexcept override {
    LOG(INFO) << "TPerfClient: onTransportReady";
  }

  void onStopSending(
      quic::StreamId id,
      quic::ApplicationErrorCode /*error*/) noexcept override {
    VLOG(10) << "TPerfClient got StopSending stream id=" << id;
  }

  void onConnectionEnd() noexcept override {
    LOG(INFO) << "TPerfClient connection end";

    eventBase_.terminateLoopSoon();
  }

  void onConnectionError(
      std::pair<quic::QuicErrorCode, std::string> error) noexcept override {
    LOG(ERROR) << "TPerfClient error: " << toString(error.first);
    eventBase_.terminateLoopSoon();
  }

  void onStreamWriteReady(
      quic::StreamId id,
      uint64_t maxToSend) noexcept override {
    LOG(INFO) << "TPerfClient stream" << id
              << " is write ready with maxToSend=" << maxToSend;
  }

  void onStreamWriteError(
      quic::StreamId id,
      std::pair<quic::QuicErrorCode, folly::Optional<folly::StringPiece>>
          error) noexcept override {
    LOG(ERROR) << "TPerfClient write error with stream=" << id
               << " error=" << toString(error);
  }

  void start() {
    folly::SocketAddress addr(host_.c_str(), port_);

    auto sock = std::make_unique<folly::AsyncUDPSocket>(&eventBase_);
    auto fizzClientContext =
        FizzClientQuicHandshakeContext::Builder()
            .setCertificateVerifier(test::createTestCertificateVerifier())
            .build();
    quicClient_ = std::make_shared<quic::QuicClientTransport>(
        &eventBase_, std::move(sock), std::move(fizzClientContext));
    quicClient_->setHostname("tperf");
    quicClient_->addNewPeerAddress(addr);
    quicClient_->setCongestionControllerFactory(
        std::make_shared<DefaultCongestionControllerFactory>());
    auto settings = quicClient_->getTransportSettings();
    settings.advertisedInitialUniStreamWindowSize = window_;
    // TODO figure out what actually to do with conn flow control and not sent
    // limit.
    settings.advertisedInitialConnectionWindowSize =
        std::numeric_limits<uint32_t>::max();
    settings.connectUDP = true;
    settings.shouldRecvBatch = true;
    settings.defaultCongestionController = congestionControlType_;
    if (congestionControlType_ == quic::CongestionControlType::BBR) {
      settings.pacingEnabled = true;
      settings.pacingTimerTickInterval = 200us;
    }
    if (gso_) {
      settings.batchingMode = QuicBatchingMode::BATCHING_MODE_GSO;
      settings.maxBatchSize = 16;
    }
    settings.maxRecvPacketSize = maxReceivePacketSize_;
    settings.canIgnorePathMTU = true;
    quicClient_->setTransportSettings(settings);

    LOG(INFO) << "TPerfClient connecting to " << addr.describe();
    quicClient_->start(this);
    eventBase_.loopForever();
  }

  ~TPerfClient() override = default;

 private:
  bool timerScheduled_{false};
  std::string host_;
  uint16_t port_;
  std::shared_ptr<quic::QuicClientTransport> quicClient_;
  folly::EventBase eventBase_;
  uint64_t receivedBytes_{0};
  uint64_t receivedStreams_{0};
  std::map<quic::StreamId, uint64_t> bytesPerStream_;
  folly::Histogram<uint64_t> bytesPerStreamHistogram_{1024,
                                                      0,
                                                      1024 * 1024 * 1024};
  std::chrono::seconds duration_;
  uint64_t window_;
  bool gso_;
  quic::CongestionControlType congestionControlType_;
  uint32_t maxReceivePacketSize_;
};

} // namespace tperf
} // namespace quic

using namespace quic::tperf;

quic::CongestionControlType flagsToCongestionControlType(
    const std::string& congestionControlType) {
  if (congestionControlType == "cubic") {
    return quic::CongestionControlType::Cubic;
  } else if (congestionControlType == "newreno") {
    return quic::CongestionControlType::NewReno;
  } else if (congestionControlType == "bbr") {
    return quic::CongestionControlType::BBR;
  } else if (congestionControlType == "copa") {
    return quic::CongestionControlType::Copa;
  } else if (congestionControlType == "none") {
    return quic::CongestionControlType::None;
  }
  throw std::invalid_argument(folly::to<std::string>(
      "Unknown congestion controller ", congestionControlType));
}

int main(int argc, char* argv[]) {
#if FOLLY_HAVE_LIBGFLAGS
  // Enable glog logging to stderr by default.
  gflags::SetCommandLineOptionWithMode(
      "logtostderr", "1", gflags::SET_FLAGS_DEFAULT);
#endif
  gflags::ParseCommandLineFlags(&argc, &argv, false);
  folly::Init init(&argc, &argv);
  fizz::CryptoUtils::init();

  if (FLAGS_mode == "server") {
    TPerfServer server(
        FLAGS_host,
        FLAGS_port,
        FLAGS_block_size,
        FLAGS_writes_per_loop,
        flagsToCongestionControlType(FLAGS_congestion),
        FLAGS_gso,
        FLAGS_max_cwnd_mss,
        FLAGS_pacing,
        FLAGS_num_streams,
        FLAGS_bytes_per_stream,
        FLAGS_max_receive_packet_size);
    server.start();
  } else if (FLAGS_mode == "client") {
    if (FLAGS_num_streams != 1) {
      LOG(ERROR) << "num_streams option is server only";
      return 1;
    }
    if (FLAGS_bytes_per_stream != 0) {
      LOG(ERROR) << "bytes_per_stream option is server only";
      return 1;
    }
    TPerfClient client(
        FLAGS_host,
        FLAGS_port,
        std::chrono::milliseconds(FLAGS_client_transport_timer_resolution_ms),
        FLAGS_duration,
        FLAGS_window,
        FLAGS_gso,
        flagsToCongestionControlType(FLAGS_congestion),
        FLAGS_max_receive_packet_size);
    client.start();
  }
  return 0;
}
