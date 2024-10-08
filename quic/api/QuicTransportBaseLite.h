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
  QuicTransportBaseLite(bool useConnectionEndWithErrorCallback)
      : useConnectionEndWithErrorCallback_(useConnectionEndWithErrorCallback) {}

  bool good() const override;

  bool error() const override;

  /**
   * Returns whether or not the connection has a write cipher. This will be used
   * to decide to return the onTransportReady() callbacks.
   */
  virtual bool hasWriteCipher() const = 0;

  void setConnectionSetupCallback(
      folly::MaybeManagedPtr<ConnectionSetupCallback> callback) final;

  void setConnectionCallback(
      folly::MaybeManagedPtr<ConnectionCallback> callback) final;

  folly::Expected<StreamTransportInfo, LocalErrorCode> getStreamTransportInfo(
      StreamId id) const override;

  const QuicConnectionStateBase* getState() const override {
    return conn_.get();
  }

  const folly::SocketAddress& getPeerAddress() const override;

 protected:
  void resetConnectionCallbacks() {
    connSetupCallback_ = nullptr;
    connCallback_ = nullptr;
  }

  bool processCancelCode(const QuicError& cancelCode);

  void processConnectionSetupCallbacks(QuicError&& cancelCode);
  void processConnectionCallbacks(QuicError&& cancelCode);

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
