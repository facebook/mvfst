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

#include <quic/client/QuicClientTransport.h>
#include <quic/common/test/TestUtils.h>
#include <quic/server/QuicServer.h>
#include <quic/server/QuicServerTransport.h>
#include <quic/server/QuicSharedUDPSocketFactory.h>

namespace quic {
namespace tperf {

class ServerSingleStreamHandler : public quic::QuicSocket::ConnectionCallback,
                                  public quic::QuicSocket::ReadCallback,
                                  public quic::QuicSocket::WriteCallback {
 public:
  using StreamData = std::pair<folly::IOBufQueue, bool>;

  explicit ServerSingleStreamHandler(
      folly::EventBase* evbIn,
      uint64_t blockSize)
      : evb_(evbIn), blockSize_(blockSize) {}

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
  }

  void onConnectionError(
      std::pair<quic::QuicErrorCode, std::string> error) noexcept override {
    LOG(ERROR) << "Socket error=" << toString(error.first);
  }

  void onTransportReady() noexcept override {
    LOG(INFO) << "Starting sends to client.";
    auto stream = sock_->createUnidirectionalStream();
    CHECK(stream.hasValue());
    sock_->notifyPendingWriteOnStream(stream.value(), this);
  }

  void notifyDataForStream(quic::StreamId id) {
    evb_->runInEventBaseThread([&, id]() {
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
    auto buf = folly::IOBuf::createChain(maxToSend * 2, blockSize_);
    auto curBuf = buf.get();
    do {
      curBuf->append(curBuf->capacity());
      curBuf = curBuf->next();
    } while (curBuf != buf.get());
    auto res = sock_->writeChain(id, std::move(buf), false, true, nullptr);
    if (res.hasError()) {
      LOG(FATAL) << "Go error on write: " << quic::toString(res.error());
    }
    notifyDataForStream(id);
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
};

class TPerfServerTransportFactory : public quic::QuicServerTransportFactory {
 public:
  ~TPerfServerTransportFactory() override = default;

  explicit TPerfServerTransportFactory(uint64_t blockSize)
      : blockSize_(blockSize) {}

  quic::QuicServerTransport::Ptr make(
      folly::EventBase* evb,
      std::unique_ptr<folly::AsyncUDPSocket> sock,
      const folly::SocketAddress&,
      std::shared_ptr<const fizz::server::FizzServerContext>
          ctx) noexcept override {
    CHECK_EQ(evb, sock->getEventBase());
    auto serverHandler =
        std::make_unique<ServerSingleStreamHandler>(evb, blockSize_);
    auto transport = quic::QuicServerTransport::make(
        evb, std::move(sock), *serverHandler, ctx);
    auto settings = transport->getTransportSettings();
    serverHandler->setQuicSocket(transport);
    LOG(ERROR) << "pushing a handler!";
    handlers_.push_back(std::move(serverHandler));
    return transport;
  }

  std::vector<std::unique_ptr<ServerSingleStreamHandler>> handlers_;
  uint64_t blockSize_;
};

class TPerfServer {
 public:
  explicit TPerfServer(
      const std::string& host,
      uint16_t port,
      uint64_t blockSize,
      uint64_t writesPerLoop,
      quic::CongestionControlType congestionControlType,
      bool gso)
      : host_(host), port_(port), server_(QuicServer::createQuicServer()) {
    server_->setQuicServerTransportFactory(
        std::make_unique<TPerfServerTransportFactory>(blockSize));
    server_->setFizzContext(quic::test::createServerCtx());
    quic::TransportSettings settings;
    settings.writeConnectionDataPacketsLimit = writesPerLoop;
    settings.defaultCongestionController = congestionControlType;
    if (congestionControlType == quic::CongestionControlType::BBR) {
      settings.pacingEnabled = true;
    }
    if (gso) {
      settings.batchingMode = QuicBatchingMode::BATCHING_MODE_GSO;
      settings.maxBatchSize = 16;
    }
    server_->setTransportSettings(settings);
  }

  void start() {
    // Create a SocketAddress and the default or passed in host.
    folly::SocketAddress addr1(host_.c_str(), port_);
    addr1.setFromHostPort(host_, port_);
    server_->start(addr1, 0);
    LOG(INFO) << "tperf server started at: " << addr1.describe();
    eventbase_.loopForever();
  }

 private:
  std::string host_;
  uint16_t port_;
  folly::EventBase eventbase_;
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
      int32_t duration,
      uint64_t window)
      : host_(host), port_(port), duration_(duration), window_(window) {}

  void timeoutExpired() noexcept override {
    quicClient_->closeNow(folly::none);
    constexpr double bytesPerMegabit = 131072;
    LOG(INFO) << "Received " << receivedBytes_ << " bytes in "
              << duration_.count() << " seconds.";
    LOG(INFO) << (receivedBytes_ / bytesPerMegabit) / duration_.count()
              << "Mb/s";
  }

  virtual void callbackCanceled() noexcept override {}

  void readAvailable(quic::StreamId streamId) noexcept override {
    auto readData = quicClient_->read(streamId, 0);
    if (readData.hasError()) {
      LOG(FATAL) << "TPerfClient failed read from stream=" << streamId
                 << ", error=" << (uint32_t)readData.error();
    }

    receivedBytes_ += readData->first->computeChainDataLength();
  }

  void readError(
      quic::StreamId streamId,
      std::pair<quic::QuicErrorCode, folly::Optional<folly::StringPiece>>
          error) noexcept override {
    LOG(ERROR) << "TPerfClient failed read from stream=" << streamId
               << ", error=" << toString(error);
    // A read error only terminates the ingress portion of the stream state.
    // Your application should probably terminate the egress portion via
    // resetStream
  }

  void onNewBidirectionalStream(quic::StreamId id) noexcept override {
    LOG(INFO) << "TPerfClient: new bidirectional stream=" << id;
    quicClient_->setReadCallback(id, this);
  }

  void onNewUnidirectionalStream(quic::StreamId id) noexcept override {
    LOG(INFO) << "TPerfClient: new unidirectional stream=" << id;
    eventBase_.timer().scheduleTimeout(this, duration_);
    quicClient_->setReadCallback(id, this);
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
    quicClient_ = std::make_shared<quic::QuicClientTransport>(
        &eventBase_, std::move(sock));
    quicClient_->setHostname("tperf");
    quicClient_->setCertificateVerifier(test::createTestCertificateVerifier());
    quicClient_->addNewPeerAddress(addr);
    auto settings = quicClient_->getTransportSettings();
    settings.advertisedInitialUniStreamWindowSize = window_;
    settings.advertisedInitialConnectionWindowSize = 10 * window_;
    quicClient_->setTransportSettings(settings);

    LOG(INFO) << "TPerfClient connecting to " << addr.describe();
    quicClient_->start(this);
    eventBase_.loopForever();
  }

  ~TPerfClient() override = default;

 private:
  std::string host_;
  uint16_t port_;
  std::shared_ptr<quic::QuicClientTransport> quicClient_;
  folly::EventBase eventBase_;
  size_t receivedBytes_{0};
  std::chrono::seconds duration_;
  uint64_t window_;
};

} // namespace tperf
} // namespace quic

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
DEFINE_bool(gso, false, "Enable GSO writes to the socket");

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
        FLAGS_gso);
    server.start();
  } else if (FLAGS_mode == "client") {
    TPerfClient client(FLAGS_host, FLAGS_port, FLAGS_duration, FLAGS_window);
    client.start();
  }
  return 0;
}
