/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#pragma once

#include <quic/api/QuicSocketLite.h>

namespace quic {

class QuicTransportBaseLite : virtual public QuicSocketLite {
 public:
  QuicTransportBaseLite(bool useConnectionEndWithErrorCallback)
      : useConnectionEndWithErrorCallback_(useConnectionEndWithErrorCallback) {}

  void setConnectionSetupCallback(
      folly::MaybeManagedPtr<ConnectionSetupCallback> callback) final;

  void setConnectionCallback(
      folly::MaybeManagedPtr<ConnectionCallback> callback) final;

 protected:
  void resetConnectionCallbacks() {
    connSetupCallback_ = nullptr;
    connCallback_ = nullptr;
  }

  bool processCancelCode(const QuicError& cancelCode);

  void processConnectionSetupCallbacks(QuicError&& cancelCode);
  void processConnectionCallbacks(QuicError&& cancelCode);

  folly::MaybeManagedPtr<ConnectionSetupCallback> connSetupCallback_{nullptr};
  folly::MaybeManagedPtr<ConnectionCallback> connCallback_{nullptr};
  // A flag telling transport if the new onConnectionEnd(error) cb must be used.
  bool useConnectionEndWithErrorCallback_{false};
};

} // namespace quic
