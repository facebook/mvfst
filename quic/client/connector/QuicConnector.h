/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#pragma once

#include <fizz/client/AsyncFizzClient.h>
#include <folly/io/SocketOptionMap.h>
#include <quic/api/LoopDetectorCallback.h>
#include <quic/api/QuicSocket.h>
#include <quic/client/QuicClientTransport.h>
#include <quic/common/TimeUtil.h>
#include <quic/fizz/client/handshake/QuicPskCache.h>
#include <quic/logging/QLogger.h>

namespace quic {

/**
 * A QUIC connector class that connects to an address, reports success/error and
 * drops the connection.
 */
class QuicConnector : private quic::QuicSocket::ConnectionSetupCallback,
                      private folly::HHWheelTimer::Callback {
 public:
  /**
   * Callback to report success/error and first packet processed.
   */
  class Callback {
   public:
    virtual ~Callback() = default;
    virtual void onConnectError(QuicError errorCode) = 0;
    virtual void onConnectSuccess() = 0;
  };

  QuicConnector(Callback* cb);

  void connect(
      folly::EventBase* eventBase,
      folly::Optional<folly::SocketAddress> localAddr,
      const folly::SocketAddress& connectAddr,
      std::shared_ptr<const fizz::client::FizzClientContext> fizzContext,
      std::shared_ptr<const fizz::CertificateVerifier> verifier,
      std::shared_ptr<quic::QuicPskCache> quicPskCache,
      quic::TransportSettings transportSettings,
      const std::vector<QuicVersion>& supportedQuicVersions,
      std::chrono::milliseconds connectTimeout =
          std::chrono::milliseconds(1000),
      const folly::SocketOptionMap& socketOptions = folly::emptySocketOptionMap,
      const folly::Optional<std::string>& sni = folly::none,
      std::shared_ptr<quic::QLogger> qLogger = nullptr,
      std::shared_ptr<quic::LoopDetectorCallback> quicLoopDetectorCallback =
          nullptr,
      std::shared_ptr<quic::QuicTransportStatsCallback>
          quicTransportStatsCallback = nullptr);

  [[nodiscard]] bool isBusy() const {
    return quicClient_ != nullptr;
  }

  void reset();

  std::chrono::milliseconds timeElapsed();

  // For testing.
  void connect(
      std::shared_ptr<quic::QuicClientTransport> quicClient,
      std::chrono::milliseconds connectTimeout);

 private:
  void doConnect(std::chrono::milliseconds connectTimeout);
  void cleanUp();
  void cleanUpAndCloseSocket();
  void timeoutExpired() noexcept override;

  // QuicSocket::ConnectionSetupCallback overrides.
  void onFirstPeerPacketProcessed() noexcept override {}
  void onConnectionSetupError(QuicError code) noexcept override;
  void onTransportReady() noexcept override {}
  void onReplaySafe() noexcept override;

  Callback* cb_;
  TimePoint connectStart_;
  std::shared_ptr<quic::QuicClientTransport> quicClient_{nullptr};
};

} // namespace quic
