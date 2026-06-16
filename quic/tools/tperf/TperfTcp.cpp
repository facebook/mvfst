/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <quic/tools/tperf/TperfTcp.h>

#include <algorithm>
#include <array>
#include <chrono>
#include <cstddef>
#include <memory>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include <fizz/client/AsyncFizzClient.h>
#include <fizz/client/FizzClientContext.h>
#include <fizz/crypto/Utils.h>
#include <fizz/protocol/CertificateVerifier.h>
#include <fizz/server/AsyncFizzServer.h>
#include <fizz/server/FizzServerContext.h>
#include <folly/SocketAddress.h>
#include <folly/io/IOBuf.h>
#include <folly/io/async/AsyncServerSocket.h>
#include <folly/io/async/AsyncSocket.h>
#include <folly/io/async/EventBase.h>
#include <folly/io/async/HHWheelTimer.h>
#include <quic/common/MvfstLogging.h>
#include <quic/common/test/TestClientUtils.h>
#include <quic/common/test/TestUtils.h>

namespace quic::tperf {
namespace {

constexpr std::string_view kTperfAlpn = "tperf";
constexpr size_t kReadBufferSize = 64ULL * 1024;

std::shared_ptr<fizz::client::FizzClientContext> createTcpClientContext() {
  auto clientCtx = std::make_shared<fizz::client::FizzClientContext>();
  clientCtx->setClock(std::make_shared<fizz::SystemClock>());
  clientCtx->setSupportedAlpns({std::string(kTperfAlpn)});
  clientCtx->setSupportedGroups(
      {fizz::NamedGroup::x25519, fizz::NamedGroup::secp256r1});
  clientCtx->setDefaultShares({fizz::NamedGroup::x25519});
  return clientCtx;
}

// Builds a FizzServerContext seeded with a test certificate from
// quic/common/test. The cert is not chained to any real CA and the server
// presents it to every peer. This is intended for tperf-style local/lab
// benchmarking only -- do not use it to stand up a TLS endpoint that talks
// to production clients.
std::shared_ptr<fizz::server::FizzServerContext> createTcpServerContext() {
  auto serverCtx = std::make_shared<fizz::server::FizzServerContext>();
  quic::test::setupCtxWithTestCert(*serverCtx);
  serverCtx->setClock(std::make_shared<fizz::SystemClock>());
  serverCtx->setSupportedAlpns({std::string(kTperfAlpn)});
  return serverCtx;
}

// Returns a TestCertificateVerifier that accepts any peer certificate without
// checking the issuer chain, the hostname, or expiry. This is the verifier
// tperf hands to the Fizz client so the TLS handshake succeeds against the
// matching test-cert server above. It is for local/lab benchmarking only and
// must NOT be used against production endpoints.
std::shared_ptr<const fizz::CertificateVerifier>
createTcpCertificateVerifier() {
  return std::make_shared<quic::test::TestCertificateVerifier>();
}

void initFizzCrypto() {
  fizz::Error err;
  FIZZ_THROW_ON_ERROR(fizz::CryptoUtils::init(err), err);
}

} // namespace

class TPerfTcpClient::Impl : public folly::AsyncSocket::ConnectCallback,
                             public folly::AsyncTransportWrapper::ReadCallback,
                             public folly::HHWheelTimer::Callback {
 public:
  explicit Impl(TPerfTcpClientConfig config)
      : host_(std::move(config.host)),
        port_(config.port),
        duration_(config.duration) {
    initFizzCrypto();
    eventBase_.setName("tperf_tcp_client");
  }

  void start() {
    folly::SocketAddress addr(host_.c_str(), port_);
    tcpClient_ = fizz::client::AsyncFizzClient::UniquePtr(
        new fizz::client::AsyncFizzClient(
            &eventBase_, createTcpClientContext()));
    MVLOG_INFO << "TPerfTcpClient connecting to " << addr.describe();
    MVLOG_WARNING
        << "tperf TCP TLS uses test certificates and a no-op certificate "
           "verifier (TestCertificateVerifier). This mode is for local/lab "
           "benchmarking only. Do NOT run against production hosts.";
    tcpClient_->connect(
        addr,
        this,
        createTcpCertificateVerifier(),
        std::string(kTperfAlpn),
        folly::none,
        std::chrono::seconds(10));
    eventBase_.loopForever();
  }

  void connectSuccess() noexcept override {
    MVLOG_INFO << "TPerfTcpClient: TLS handshake complete";
    tcpClient_->setReadCB(this);
    startTime_ = std::chrono::steady_clock::now();
    timerScheduled_ = true;
    eventBase_.timer().scheduleTimeout(this, duration_);
  }

  // NOLINTNEXTLINE(bugprone-exception-escape)
  void connectErr(const folly::AsyncSocketException& ex) noexcept override {
    MVLOG_ERROR << "TPerfTcpClient connect error: " << ex.what();
    finished_ = true;
    if (tcpClient_) {
      tcpClient_->closeNow();
    }
    eventBase_.terminateLoopSoon();
  }

  void getReadBuffer(
      void* _Nonnull* _Nonnull bufReturn,
      size_t* _Nonnull lenReturn) override {
    *bufReturn = readBuffer_.data();
    *lenReturn = readBuffer_.size();
  }

  void readDataAvailable(size_t len) noexcept override {
    receivedBytes_ += len;
  }

  void readEOF() noexcept override {
    if (!finished_) {
      MVLOG_INFO << "TPerfTcpClient received EOF";
    }
    finish();
  }

  void readErr(const folly::AsyncSocketException& ex) noexcept override {
    if (!finished_) {
      MVLOG_ERROR << "TPerfTcpClient read error: " << ex.what();
    }
    finish();
  }

  void timeoutExpired() noexcept override {
    finish();
  }

  void callbackCanceled() noexcept override {}

 private:
  // NOLINTNEXTLINE(bugprone-exception-escape)
  void finish() noexcept {
    if (finished_) {
      return;
    }
    finished_ = true;
    if (timerScheduled_) {
      cancelTimeout();
    }
    constexpr double bytesPerMegabit = 131072;
    const auto elapsed =
        std::chrono::duration_cast<std::chrono::duration<double>>(
            std::chrono::steady_clock::now() - startTime_)
            .count();
    MVLOG_INFO << "Received " << receivedBytes_ << " bytes in " << elapsed
               << " seconds.";
    if (elapsed > 0.0) {
      MVLOG_INFO << "Overall throughput: "
                 << (static_cast<double>(receivedBytes_) / bytesPerMegabit) /
              elapsed
                 << "Mb/s";
    } else {
      MVLOG_INFO << "Overall throughput: n/a (elapsed time too small)";
    }
    if (tcpClient_) {
      tcpClient_->closeNow();
    }
    eventBase_.terminateLoopSoon();
  }

  std::string host_;
  uint16_t port_;
  folly::EventBase eventBase_;
  fizz::client::AsyncFizzClient::UniquePtr tcpClient_;
  std::array<uint8_t, kReadBufferSize> readBuffer_{};
  uint64_t receivedBytes_{0};
  std::chrono::seconds duration_;
  std::chrono::steady_clock::time_point startTime_{};
  bool timerScheduled_{false};
  bool finished_{false};
};

namespace {

class TcpServerConnection
    : public fizz::server::AsyncFizzServer::HandshakeCallback,
      public folly::AsyncTransportWrapper::ReadCallback,
      public folly::AsyncTransportWrapper::WriteCallback {
 public:
  TcpServerConnection(
      folly::EventBase* eventBase,
      folly::NetworkSocket fd,
      std::shared_ptr<const fizz::server::FizzServerContext> serverCtx,
      const TPerfTcpServerConfig& config)
      : blockSize_(config.blockSize),
        writesPerLoop_(std::max<uint64_t>(config.writesPerLoop, 1)),
        writeBuffer_(folly::IOBuf::createCombined(blockSize_)) {
    auto socket = folly::AsyncSocket::newSocket(eventBase, fd);
    tcpServer_ = fizz::server::AsyncFizzServer::UniquePtr(
        new fizz::server::AsyncFizzServer(std::move(socket), serverCtx));
  }

  void start() {
    tcpServer_->accept(this);
  }

  void fizzHandshakeSuccess(
      fizz::server::AsyncFizzServer* /* transport */) noexcept override {
    MVLOG_INFO << "TPerfTcpServer: TLS handshake complete";
    tcpServer_->setReadCB(this);
    writeMore();
  }

  void fizzHandshakeError(
      fizz::server::AsyncFizzServer* /* transport */,
      folly::exception_wrapper ex) noexcept override {
    MVLOG_ERROR << "TPerfTcpServer handshake error: " << ex.what();
    closeNow();
  }

  void fizzHandshakeAttemptFallback(
      fizz::server::AttemptVersionFallback /* fallback */) override {
    MVLOG_ERROR << "TPerfTcpServer received unsupported TLS fallback attempt";
    closeNow();
  }

  void getReadBuffer(
      void* _Nonnull* _Nonnull bufReturn,
      size_t* _Nonnull lenReturn) override {
    *bufReturn = readBuffer_.data();
    *lenReturn = readBuffer_.size();
  }

  void readDataAvailable(size_t /* len */) noexcept override {}

  void readEOF() noexcept override {
    if (active_) {
      MVLOG_INFO << "TPerfTcpServer received EOF after writing "
                 << bytesWritten_ << " bytes";
    }
    closeNow();
  }

  void readErr(const folly::AsyncSocketException& ex) noexcept override {
    if (active_) {
      MVLOG_ERROR << "TPerfTcpServer read error: " << ex.what();
    }
    closeNow();
  }

  void writeSuccess() noexcept override {
    if (pendingWrites_ > 0) {
      --pendingWrites_;
      bytesWritten_ += blockSize_;
    }
    writeMore();
  }

  void writeErr(
      size_t bytesWritten,
      const folly::AsyncSocketException& ex) noexcept override {
    bytesWritten_ += bytesWritten;
    if (active_) {
      MVLOG_ERROR << "TPerfTcpServer write error after writing "
                  << bytesWritten_ << " bytes: " << ex.what();
    }
    closeNow();
  }

 private:
  void writeMore() noexcept {
    while (active_ && pendingWrites_ < writesPerLoop_) {
      auto buffer = writeBuffer_->clone();
      if (buffer == nullptr) {
        break;
      }
      buffer->append(blockSize_);
      ++pendingWrites_;
      tcpServer_->writeChain(this, std::move(buffer));
    }
  }

  // NOLINTNEXTLINE(bugprone-exception-escape)
  void closeNow() noexcept {
    if (!active_) {
      return;
    }
    active_ = false;
    if (tcpServer_) {
      tcpServer_->closeNow();
    }
  }

  fizz::server::AsyncFizzServer::UniquePtr tcpServer_;
  std::array<uint8_t, kReadBufferSize> readBuffer_{};
  uint64_t blockSize_;
  uint64_t writesPerLoop_;
  std::unique_ptr<folly::IOBuf> writeBuffer_;
  uint64_t pendingWrites_{0};
  uint64_t bytesWritten_{0};
  bool active_{true};
};

} // namespace

class TPerfTcpServer::Impl : public folly::AsyncServerSocket::AcceptCallback {
 public:
  explicit Impl(TPerfTcpServerConfig config)
      : config_(std::move(config)), serverCtx_(createTcpServerContext()) {
    initFizzCrypto();
    eventBase_.setName("tperf_tcp_server");
  }

  void start() {
    folly::SocketAddress addr;
    addr.setFromHostPort(config_.host, config_.port);

    serverSocket_ = folly::AsyncServerSocket::UniquePtr(
        new folly::AsyncServerSocket(&eventBase_));
    serverSocket_->bind(addr);
    serverSocket_->listen(1024);
    serverSocket_->addAcceptCallback(this, &eventBase_);
    serverSocket_->startAccepting();
    MVLOG_INFO << "tperf TCP/TLS server started at: "
               << serverSocket_->getAddress().describe();
    MVLOG_WARNING
        << "tperf TCP TLS uses test certificates and a no-op certificate "
           "verifier (TestCertificateVerifier). This mode is for local/lab "
           "benchmarking only. Do NOT run against production hosts.";
    eventBase_.loopForever();
  }

  // NOLINTNEXTLINE(bugprone-exception-escape)
  void connectionAccepted(
      folly::NetworkSocket fd,
      const folly::SocketAddress& clientAddr,
      AcceptInfo /* info */) noexcept override {
    MVLOG_INFO << "TPerfTcpServer accepted connection from "
               << clientAddr.describe();
    auto connection = std::make_unique<TcpServerConnection>(
        &eventBase_, fd, serverCtx_, config_);
    connection->start();
    connections_.push_back(std::move(connection));
  }

  void acceptError(folly::exception_wrapper ex) noexcept override {
    MVLOG_ERROR << "TPerfTcpServer accept error: " << ex.what();
  }

 private:
  TPerfTcpServerConfig config_;
  folly::EventBase eventBase_;
  std::shared_ptr<fizz::server::FizzServerContext> serverCtx_;
  folly::AsyncServerSocket::UniquePtr serverSocket_;
  std::vector<std::unique_ptr<TcpServerConnection>> connections_;
};

TPerfTcpClient::TPerfTcpClient(TPerfTcpClientConfig config)
    : impl_(std::make_unique<Impl>(std::move(config))) {}

TPerfTcpClient::~TPerfTcpClient() = default;

void TPerfTcpClient::start() {
  impl_->start();
}

TPerfTcpServer::TPerfTcpServer(TPerfTcpServerConfig config)
    : impl_(std::make_unique<Impl>(std::move(config))) {}

TPerfTcpServer::~TPerfTcpServer() = default;

void TPerfTcpServer::start() {
  impl_->start();
}

} // namespace quic::tperf
