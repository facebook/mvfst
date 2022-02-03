/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <quic/server/async_tran/QuicAsyncTransportAcceptor.h>

#include <quic/server/QuicServerTransport.h>
#include <quic/server/async_tran/QuicServerAsyncTransport.h>

namespace quic {

QuicAsyncTransportAcceptor::QuicAsyncTransportAcceptor(
    folly::EventBase* evb,
    ManagedConnectionFactory connectionFactory)
    : wangle::Acceptor(wangle::ServerSocketConfig()),
      connectionFactory_(std::move(connectionFactory)),
      evb_(evb) {
  Acceptor::initDownstreamConnectionManager(evb_);
}

quic::QuicServerTransport::Ptr QuicAsyncTransportAcceptor::make(
    folly::EventBase* evb,
    std::unique_ptr<folly::AsyncUDPSocket> sock,
    const folly::SocketAddress&,
    QuicVersion,
    std::shared_ptr<const fizz::server::FizzServerContext> ctx) noexcept {
  CHECK_EQ(evb, evb_);
  quic::QuicServerAsyncTransport::UniquePtr asyncWrapper(
      new quic::QuicServerAsyncTransport());
  auto transport = quic::QuicServerTransport::make(
      evb, std::move(sock), asyncWrapper.get(), asyncWrapper.get(), ctx);
  asyncWrapper->setServerSocket(transport);
  wangle::ManagedConnection* managedConnection =
      connectionFactory_(std::move(asyncWrapper));
  Acceptor::addConnection(managedConnection);
  return transport;
}

} // namespace quic
