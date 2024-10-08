/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#pragma once

#include <quic/api/QuicSocketLite.h>

namespace quic {

enum class CloseState { OPEN, GRACEFUL_CLOSING, CLOSED };

class QuicTransportBaseLite : virtual public QuicSocketLite {
 public:
  QuicTransportBaseLite(
      std::shared_ptr<QuicEventBase> evb,
      bool useConnectionEndWithErrorCallback)
      : evb_(evb),
        useConnectionEndWithErrorCallback_(useConnectionEndWithErrorCallback) {}

  bool good() const override;

  bool error() const override;

  uint64_t bufferSpaceAvailable() const;

  /**
   * Returns whether or not the connection has a write cipher. This will be used
   * to decide to return the onTransportReady() callbacks.
   */
  virtual bool hasWriteCipher() const = 0;

  void setConnectionSetupCallback(
      folly::MaybeManagedPtr<ConnectionSetupCallback> callback) final;

  void setConnectionCallback(
      folly::MaybeManagedPtr<ConnectionCallback> callback) final;

  void setReceiveWindow(StreamId, size_t /*recvWindowSize*/) override {}

  void setSendBuffer(StreamId, size_t /*maxUnacked*/, size_t /*maxUnsent*/)
      override {}

  [[nodiscard]] std::shared_ptr<QuicEventBase> getEventBase() const override;

  folly::Expected<StreamTransportInfo, LocalErrorCode> getStreamTransportInfo(
      StreamId id) const override;

  const QuicConnectionStateBase* getState() const override {
    return conn_.get();
  }

  const folly::SocketAddress& getPeerAddress() const override;

  Optional<std::string> getAppProtocol() const override;

  uint64_t getConnectionBufferAvailable() const override;

 protected:
  void resetConnectionCallbacks() {
    connSetupCallback_ = nullptr;
    connCallback_ = nullptr;
  }

  bool processCancelCode(const QuicError& cancelCode);

  void processConnectionSetupCallbacks(QuicError&& cancelCode);
  void processConnectionCallbacks(QuicError&& cancelCode);

  std::shared_ptr<QuicEventBase> evb_;

  CloseState closeState_{CloseState::OPEN};

  folly::MaybeManagedPtr<ConnectionSetupCallback> connSetupCallback_{nullptr};
  folly::MaybeManagedPtr<ConnectionCallback> connCallback_{nullptr};
  // A flag telling transport if the new onConnectionEnd(error) cb must be used.
  bool useConnectionEndWithErrorCallback_{false};

  std::
      unique_ptr<QuicConnectionStateBase, folly::DelayedDestruction::Destructor>
          conn_;
};

} // namespace quic
