/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#pragma once

#include <quic/server/QuicUDPSocketFactory.h>

namespace quic {

class QuicReusePortUDPSocketFactory : public QuicUDPSocketFactory {
 public:
  ~QuicReusePortUDPSocketFactory() override {}
  QuicReusePortUDPSocketFactory() {}

  std::unique_ptr<folly::AsyncUDPSocket> make(folly::EventBase* evb, int)
      override {
    auto sock = std::make_unique<folly::AsyncUDPSocket>(evb);
    sock->setReusePort(true);
    sock->setReuseAddr(false);
    return sock;
  }
};
} // namespace quic
