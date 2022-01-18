/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#pragma once

#include <folly/io/async/AsyncTransport.h>
#include <quic/server/QuicServerTransportFactory.h>
#include <wangle/acceptor/Acceptor.h>

namespace quic {

class QuicAsyncTransportAcceptor : public wangle::Acceptor,
                                   public quic::QuicServerTransportFactory {
 public:
  using ManagedConnectionFactory = folly::Function<wangle::ManagedConnection*(
      folly::AsyncTransport::UniquePtr)>;

  QuicAsyncTransportAcceptor(
      folly::EventBase* evb,
      ManagedConnectionFactory connectionFactory);
  ~QuicAsyncTransportAcceptor() override = default;

  // quic::QuicServerTransportFactory
  quic::QuicServerTransport::Ptr make(
      folly::EventBase* evb,
      std::unique_ptr<folly::AsyncUDPSocket> sock,
      const folly::SocketAddress&,
      QuicVersion quickVersion,
      std::shared_ptr<const fizz::server::FizzServerContext> ctx) noexcept
      override;

 private:
  ManagedConnectionFactory connectionFactory_;
  folly::EventBase* evb_;
};

} // namespace quic
