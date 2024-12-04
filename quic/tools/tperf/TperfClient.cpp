/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <sstream>

#include <fizz/crypto/Utils.h>
#include <folly/io/async/AsyncUDPSocket.h>
#include <quic/common/test/TestClientUtils.h>
#include <quic/common/udpsocket/FollyQuicAsyncUDPSocket.h>
#include <quic/fizz/client/handshake/FizzClientQuicHandshakeContext.h>
#include <quic/tools/tperf/TperfClient.h>

namespace quic::tperf {

TPerfClient::TPerfClient(
    const std::string& host,
    uint16_t port,
    std::chrono::milliseconds transportTimerResolution,
    int32_t duration,
    uint64_t window,
    bool autotuneWindow,
    bool gso,
    quic::CongestionControlType congestionControlType,
    uint32_t maxReceivePacketSize,
    bool useInplaceWrite,
    std::string knobsStr,
    bool useAckReceiveTimestamps,
    uint32_t maxAckReceiveTimestampsToSend,
    bool useL4sEcn,
    bool readEcn,
    uint32_t dscp)
    : host_(host),
      port_(port),
      fEvb_(transportTimerResolution),
      qEvb_(std::make_shared<FollyQuicEventBase>(&fEvb_)),
      duration_(duration),
      window_(window),
      autotuneWindow_(autotuneWindow),
      gso_(gso),
      congestionControlType_(congestionControlType),
      maxReceivePacketSize_(maxReceivePacketSize),
      useInplaceWrite_(useInplaceWrite),
      knobsStr_(knobsStr),
      useAckReceiveTimestamps_(useAckReceiveTimestamps),
      maxAckReceiveTimestampsToSend_(maxAckReceiveTimestampsToSend),
      useL4sEcn_(useL4sEcn),
      readEcn_(readEcn),
      dscp_(dscp) {
  fizz::CryptoUtils::init();
  fEvb_.setName("tperf_client");
}

void TPerfClient::timeoutExpired() noexcept {
  quicClient_->closeNow(none);
  constexpr double bytesPerMegabit = 131072;
  LOG(INFO) << "Received " << receivedBytes_ << " bytes in "
            << duration_.count() << " seconds.";
  LOG(INFO) << "Overall throughput: "
            << (receivedBytes_ / bytesPerMegabit) / duration_.count() << "Mb/s";
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
    folly::split('\n', os.str(), lines);
    for (const auto& line : lines) {
      LOG(INFO) << line;
    }
    LOG(INFO) << "Per stream bytes breakdown: ";
    for (const auto& [k, v] : bytesPerStream_) {
      LOG(INFO) << fmt::format("stream: {}, bytes: {}", k, v);
    }
  }
}

void TPerfClient::readAvailable(quic::StreamId streamId) noexcept {
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

void TPerfClient::readError(
    quic::StreamId /*streamId*/,
    QuicError
    /*error*/) noexcept {
  // A read error only terminates the ingress portion of the stream state.
  // Your application should probably terminate the egress portion via
  // resetStream
}

void TPerfClient::onNewBidirectionalStream(quic::StreamId id) noexcept {
  LOG(INFO) << "TPerfClient: new bidirectional stream=" << id;
  quicClient_->setReadCallback(id, this);
}

void TPerfClient::onNewUnidirectionalStream(quic::StreamId id) noexcept {
  VLOG(5) << "TPerfClient: new unidirectional stream=" << id;
  if (!timerScheduled_) {
    timerScheduled_ = true;
    fEvb_.timer().scheduleTimeout(this, duration_);
  }
  quicClient_->setReadCallback(id, this);
  receivedStreams_++;
}

void TPerfClient::onTransportReady() noexcept {
  LOG(INFO) << "TPerfClient: onTransportReady";
}

void TPerfClient::onStopSending(
    quic::StreamId id,
    quic::ApplicationErrorCode /*error*/) noexcept {
  VLOG(10) << "TPerfClient got StopSending stream id=" << id;
}

void TPerfClient::onConnectionEnd() noexcept {
  LOG(INFO) << "TPerfClient connection end";

  fEvb_.terminateLoopSoon();
}

void TPerfClient::onConnectionSetupError(QuicError error) noexcept {
  onConnectionError(std::move(error));
}

void TPerfClient::onConnectionError(QuicError error) noexcept {
  LOG(ERROR) << "TPerfClient error: " << toString(error.code);
  fEvb_.terminateLoopSoon();
}

void TPerfClient::onStreamWriteReady(
    quic::StreamId id,
    uint64_t maxToSend) noexcept {
  LOG(INFO) << "TPerfClient stream" << id
            << " is write ready with maxToSend=" << maxToSend;
}

void TPerfClient::onStreamWriteError(
    quic::StreamId id,
    QuicError error) noexcept {
  LOG(ERROR) << "TPerfClient write error with stream=" << id
             << " error=" << toString(error);
}

void TPerfClient::start() {
  folly::SocketAddress addr(host_.c_str(), port_);
  auto sock = std::make_unique<folly::AsyncUDPSocket>(&fEvb_);
  auto sockWrapper =
      std::make_unique<FollyQuicAsyncUDPSocket>(qEvb_, std::move(sock));

  auto fizzClientContext =
      FizzClientQuicHandshakeContext::Builder()
          .setCertificateVerifier(test::createTestCertificateVerifier())
          .build();
  quicClient_ = std::make_shared<quic::QuicClientTransport>(
      qEvb_, std::move(sockWrapper), std::move(fizzClientContext));
  quicClient_->setHostname("tperf");
  quicClient_->addNewPeerAddress(addr);
  quicClient_->setCongestionControllerFactory(
      std::make_shared<DefaultCongestionControllerFactory>());
  auto settings = quicClient_->getTransportSettings();
  settings.advertisedInitialUniStreamFlowControlWindow =
      std::numeric_limits<uint32_t>::max();
  settings.advertisedInitialConnectionFlowControlWindow = window_;
  settings.autotuneReceiveConnFlowControl = autotuneWindow_;
  settings.connectUDP = true;
  settings.shouldUseRecvmmsgForBatchRecv = true;
  settings.maxRecvBatchSize = 64;
  settings.numGROBuffers_ = 64;
  settings.defaultCongestionController = congestionControlType_;
  if (congestionControlType_ == quic::CongestionControlType::BBR ||
      congestionControlType_ == CongestionControlType::BBRTesting) {
    settings.pacingEnabled = true;
    settings.pacingTickInterval = 200us;
    settings.writeLimitRttFraction = 0;
  }
  if (gso_) {
    settings.batchingMode = QuicBatchingMode::BATCHING_MODE_GSO;
    settings.maxBatchSize = 16;
  }
  settings.maxRecvPacketSize = maxReceivePacketSize_;
  if (!knobsStr_.empty()) {
    settings.knobs.push_back(
        {kDefaultQuicTransportKnobSpace,
         kDefaultQuicTransportKnobId,
         knobsStr_});
  }

  if (useAckReceiveTimestamps_) {
    LOG(INFO) << " Using ACK receive timestamps on client";

    settings.maybeAckReceiveTimestampsConfigSentToPeer.assign(
        {maxAckReceiveTimestampsToSend_, kDefaultReceiveTimestampsExponent});
  }
  if (useInplaceWrite_) {
    settings.maxBatchSize = 1;
    settings.dataPathType = DataPathType::ContinuousMemory;
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

  quicClient_->setTransportSettings(settings);

  LOG(INFO) << "TPerfClient connecting to " << addr.describe();
  quicClient_->start(this, this);
  fEvb_.loopForever();
}

} // namespace quic::tperf
