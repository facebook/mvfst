/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#pragma once

#include <folly/io/async/ScopedEventBaseThread.h>
#include <quic/server/QuicServer.h>
#include <quic/server/async_tran/QuicAsyncTransportAcceptor.h>

namespace quic {

/**
 * QUIC server with single stream connections wrapped into folly:AsyncTransport
 * adaptor. For experiments with QUIC in existing code using
 * folly::AsyncServerSocket and wangle::Acceptor.
 */
class QuicAsyncTransportServer {
 public:
  explicit QuicAsyncTransportServer(
      QuicAsyncTransportAcceptor::ManagedConnectionFactory connectionFactory);
  virtual ~QuicAsyncTransportServer() = default;

  void setFizzContext(
      std::shared_ptr<const fizz::server::FizzServerContext> ctx);

  void start(const folly::SocketAddress& address, size_t numThreads = 0);

  quic::QuicServer& quicServer() {
    return *quicServer_;
  }

  void shutdown();

 protected:
  void setTransportSettings();
  void createAcceptors();

  QuicAsyncTransportAcceptor::ManagedConnectionFactory connectionFactory_;
  std::shared_ptr<quic::QuicServer> quicServer_;
  std::vector<std::unique_ptr<QuicAsyncTransportAcceptor>> acceptors_;
  std::vector<std::unique_ptr<folly::ScopedEventBaseThread>> workerEvbs_;
  std::shared_ptr<const fizz::server::FizzServerContext> fizzCtx_;
};

} // namespace quic
