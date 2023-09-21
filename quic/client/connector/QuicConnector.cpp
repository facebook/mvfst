/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <quic/client/connector/QuicConnector.h>

#include <folly/io/SocketOptionMap.h>
#include <folly/io/async/AsyncSSLSocket.h>
#include <quic/api/QuicSocket.h>
#include <quic/congestion_control/CongestionControllerFactory.h>
#include <quic/fizz/client/handshake/FizzClientQuicHandshakeContext.h>

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
  cancelTimeout();
  cleanUpAndCloseSocket();
}

void QuicConnector::connect(
    folly::EventBase* eventBase,
    folly::Optional<folly::SocketAddress> localAddr,
    const folly::SocketAddress& connectAddr,
    std::shared_ptr<const fizz::client::FizzClientContext> fizzContext,
    std::shared_ptr<const fizz::CertificateVerifier> verifier,
    std::shared_ptr<quic::QuicPskCache> quicPskCache,
    quic::TransportSettings transportSettings,
    const std::vector<QuicVersion>& supportedQuicVersions,
    std::chrono::milliseconds connectTimeout,
    const folly::SocketOptionMap& socketOptions,
    const folly::Optional<std::string>& sni,
    std::shared_ptr<quic::QLogger> qLogger,
    std::shared_ptr<quic::LoopDetectorCallback> quicLoopDetectorCallback,
    std::shared_ptr<quic::QuicTransportStatsCallback>
        quicTransportStatsCallback) {
  if (isBusy()) {
    LOG(ERROR) << "Already connecting...";
    return;
  }

  auto sock = std::make_unique<QuicAsyncUDPSocketWrapperImpl>(eventBase);
  quicClient_ = quic::QuicClientTransport::newClient(
      eventBase,
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
  quicClient_->setTransportSettings(std::move(transportSettings));
  quicClient_->setQLogger(std::move(qLogger));
  quicClient_->setLoopDetectorCallback(std::move(quicLoopDetectorCallback));
  quicClient_->setSocketOptions(socketOptions);
  quicClient_->setSupportedVersions(supportedQuicVersions);

  VLOG(4) << "connecting to " << connectAddr.describe();

  doConnect(connectTimeout);
}

void QuicConnector::connect(
    std::shared_ptr<quic::QuicClientTransport> quicClient,
    std::chrono::milliseconds connectTimeout) {
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
        quic::QuicErrorCode(quic::LocalErrorCode::SHUTTING_DOWN),
        std::string("shutting down"));
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
