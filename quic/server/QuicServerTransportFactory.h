/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#pragma once

#include <fizz/server/FizzServerContext.h>
#include <quic/common/QuicAsyncUDPSocketWrapper.h>
#include <quic/server/QuicServerTransport.h>

namespace quic {

class QuicServerTransportFactory {
 public:
  virtual ~QuicServerTransportFactory() {}

  virtual QuicServerTransport::Ptr make(
      folly::EventBase* evb,
      std::unique_ptr<QuicAsyncUDPSocketWrapper> socket,
      const folly::SocketAddress& addr,
      QuicVersion quicVersion,
      std::shared_ptr<const fizz::server::FizzServerContext> ctx) noexcept = 0;
};
} // namespace quic
