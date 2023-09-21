/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#pragma once

#include <folly/io/async/AsyncTransport.h>
#include <quic/server/QuicServerTransportFactory.h>

namespace quic {

class QuicAsyncTransportAcceptor : public quic::QuicServerTransportFactory {
 public:
  // Hook/Callback function to be invoked when a new connection is accepted and
  // passed in the associated AsyncTransport.
  using AsyncTransportHook =
      folly::Function<void(folly::AsyncTransport::UniquePtr)>;

  QuicAsyncTransportAcceptor(
      folly::EventBase* evb,
      AsyncTransportHook asyncTransportHook);
  ~QuicAsyncTransportAcceptor() override = default;

  // quic::QuicServerTransportFactory
  quic::QuicServerTransport::Ptr make(
      folly::EventBase* evb,
      std::unique_ptr<QuicAsyncUDPSocketWrapper> sock,
      const folly::SocketAddress&,
      QuicVersion quickVersion,
      std::shared_ptr<const fizz::server::FizzServerContext> ctx) noexcept
      override;

 private:
  AsyncTransportHook asyncTransportHook_;
  folly::EventBase* evb_;
};

} // namespace quic
