/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <folly/io/SocketOptionMap.h>
#include <folly/io/async/AsyncSSLSocket.h>
#include <folly/io/async/AsyncUDPSocket.h>

#include <quic/api/QuicSocket.h>
#include <quic/client/connector/QuicConnector.h>
#include <quic/common/udpsocket/FollyQuicAsyncUDPSocket.h>
#include <quic/congestion_control/CongestionControllerFactory.h>
#include <quic/fizz/client/handshake/FizzClientQuicHandshakeContext.h>

#include <memory>

using namespace std;

namespace quic {

QuicConnector::QuicConnector(Callback* cb) : cb_(CHECK_NOTNULL(cb)) {}

void QuicConnector::onConnectionSetupError(QuicError code) noexcept {
  if (cb_) {
    cb_->onConnectError(std::move(code));
  }
  cleanUp();
}

void QuicConnector::onReplaySafe() noexcept {
  if (cb_) {
    cb_->onConnectSuccess();
  }
  cancelTimerCallback();
  cleanUpAndCloseSocket();
}

void QuicConnector::connect(
    folly::EventBase* eventBase,
    Optional<folly::SocketAddress> localAddr,
    const folly::SocketAddress& connectAddr,
    std::shared_ptr<const fizz::client::FizzClientContext> fizzContext,
    std::shared_ptr<const fizz::CertificateVerifier> verifier,
    std::shared_ptr<quic::QuicPskCache> quicPskCache,
    quic::TransportSettings transportSettings,
    const std::vector<QuicVersion>& supportedQuicVersions,
    std::chrono::milliseconds connectTimeout,
    const folly::SocketOptionMap& socketOptions,
    const Optional<std::string>& sni,
    std::shared_ptr<quic::QLogger> qLogger,
    std::shared_ptr<quic::LoopDetectorCallback> quicLoopDetectorCallback,
    std::shared_ptr<quic::QuicTransportStatsCallback>
        quicTransportStatsCallback) {
  if (isBusy()) {
    LOG(ERROR) << "Already connecting...";
    return;
  }
  qEvb_ = std::make_shared<FollyQuicEventBase>(eventBase);
  auto sock = std::make_unique<FollyQuicAsyncUDPSocket>(qEvb_);
  quicClient_ = quic::QuicClientTransport::newClient(
      qEvb_,
      std::move(sock),
      quic::FizzClientQuicHandshakeContext::Builder()
          .setFizzClientContext(std::move(fizzContext))
          .setCertificateVerifier(std::move(verifier))
          .setPskCache(std::move(quicPskCache))
          .build(),
      0 /* connectionIdSize */);
  quicClient_->setHostname(sni.value_or(connectAddr.getAddressStr()));
  quicClient_->addNewPeerAddress(connectAddr);
  if (localAddr.hasValue()) {
    quicClient_->setLocalAddress(*localAddr);
  }
  quicClient_->setCongestionControllerFactory(
      std::make_shared<quic::DefaultCongestionControllerFactory>());
  quicClient_->setTransportStatsCallback(std::move(quicTransportStatsCallback));

  // Always use connected UDP sockets
  transportSettings.connectUDP = true;
  quicClient_->setTransportSettings(std::move(transportSettings));
  quicClient_->setQLogger(std::move(qLogger));
  quicClient_->setLoopDetectorCallback(std::move(quicLoopDetectorCallback));
  quicClient_->setSocketOptions(socketOptions);
  quicClient_->setSupportedVersions(supportedQuicVersions);

  VLOG(4) << "connecting to " << connectAddr.describe();

  doConnect(connectTimeout);
}

void QuicConnector::connect(
    std::shared_ptr<quic::FollyQuicEventBase> qEvb,
    std::shared_ptr<quic::QuicClientTransport> quicClient,
    std::chrono::milliseconds connectTimeout) {
  qEvb_ = qEvb;
  quicClient_ = std::move(quicClient);
  doConnect(connectTimeout);
}

void QuicConnector::doConnect(std::chrono::milliseconds connectTimeout) {
  connectStart_ = std::chrono::steady_clock::now();
  quicClient_->scheduleTimeout(this, connectTimeout);
  quicClient_->start(this, nullptr);
}

void QuicConnector::reset() {
  cleanUpAndCloseSocket();
}

void QuicConnector::cleanUp() {
  quicClient_.reset();
  connectStart_ = TimePoint{};
}

void QuicConnector::cleanUpAndCloseSocket() {
  if (quicClient_) {
    auto error = QuicError(
        quic::QuicErrorCode(quic::TransportErrorCode::NO_ERROR),
        std::string("closing the connection"));
    quicClient_->close(std::move(error));
  }
  cleanUp();
}

std::chrono::milliseconds QuicConnector::timeElapsed() {
  return timePointInitialized(connectStart_) ? millisecondsSince(connectStart_)
                                             : std::chrono::milliseconds(0);
}

void QuicConnector::timeoutExpired() noexcept {
  auto error = QuicError(
      quic::QuicErrorCode(quic::LocalErrorCode::CONNECT_FAILED),
      std::string("connect operation timed out"));
  if (quicClient_) {
    quicClient_->close(error);
  }
  onConnectionSetupError(std::move(error));
}

} // namespace quic
