/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#pragma once

#include <quic/api/QuicStreamAsyncTransport.h>
#include <quic/client/QuicClientTransport.h>

namespace quic {

/**
 * Adaptor from QuicClientTransport to folly::AsyncTransport,
 * for experiments with QUIC in code using folly::AsyncSockets.
 */
class QuicClientAsyncTransport : public QuicStreamAsyncTransport,
                                 public QuicSocket::ConnectionSetupCallback,
                                 public QuicSocket::ConnectionCallback {
 public:
  using UniquePtr = std::unique_ptr<
      QuicClientAsyncTransport,
      folly::DelayedDestruction::Destructor>;
  explicit QuicClientAsyncTransport(
      const std::shared_ptr<QuicClientTransport>& clientSock);

 protected:
  ~QuicClientAsyncTransport() override = default;

  //
  // QuicSocket::ConnectionCallback
  //
  void onNewBidirectionalStream(StreamId id) noexcept override;
  void onNewUnidirectionalStream(StreamId id) noexcept override;
  void onStopSending(StreamId id, ApplicationErrorCode error) noexcept override;
  void onConnectionEnd() noexcept override;
  void onConnectionSetupError(QuicError code) noexcept override {
    onConnectionError(std::move(code));
  }
  void onConnectionError(QuicError code) noexcept override;
  void onTransportReady() noexcept override;
};
} // namespace quic
