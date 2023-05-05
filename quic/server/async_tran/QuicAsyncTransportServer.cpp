/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <quic/server/async_tran/QuicAsyncTransportServer.h>

#include <quic/server/QuicServerTransport.h>

namespace quic {

QuicAsyncTransportServer::QuicAsyncTransportServer(
    QuicAsyncTransportAcceptor::AsyncTransportHook asyncTransportHook)
    : asyncTransportHook_(std::move(asyncTransportHook)),
      quicServer_(quic::QuicServer::createQuicServer()) {
  CHECK(asyncTransportHook_);
}

void QuicAsyncTransportServer::setFizzContext(
    std::shared_ptr<const fizz::server::FizzServerContext> ctx) {
  fizzCtx_ = std::move(ctx);
}

void QuicAsyncTransportServer::setTransportSettings(
    const quic::TransportSettings& ts) {
  quicServer_->setTransportSettings(ts);
}

void QuicAsyncTransportServer::start(
    const folly::SocketAddress& address,
    size_t numThreads) {
  if (numThreads == 0) {
    numThreads = std::thread::hardware_concurrency();
  }
  std::vector<folly::EventBase*> evbs;
  for (size_t i = 0; i < numThreads; ++i) {
    auto scopedEvb = std::make_unique<folly::ScopedEventBaseThread>();
    evbs.push_back(scopedEvb->getEventBase());
    workerEvbs_.push_back(std::move(scopedEvb));
  }

  start(address, std::move(evbs));
}

void QuicAsyncTransportServer::start(
    const folly::SocketAddress& address,
    std::vector<folly::EventBase*> evbs) {
  quicServer_->initialize(address, evbs, false /* useDefaultTransport */);
  quicServer_->waitUntilInitialized();
  createAcceptors(evbs);
  quicServer_->start();
}

void QuicAsyncTransportServer::createAcceptors(
    std::vector<folly::EventBase*>& evbs) {
  for (auto evb : evbs) {
    quicServer_->setFizzContext(evb, fizzCtx_);
    auto acceptor = std::make_unique<QuicAsyncTransportAcceptor>(
        evb, [this](folly::AsyncTransport::UniquePtr tran) {
          asyncTransportHook_(std::move(tran));
        });
    quicServer_->addTransportFactory(evb, acceptor.get());
    acceptors_.push_back(std::move(acceptor));
  }
}

void QuicAsyncTransportServer::shutdown() {
  quicServer_->rejectNewConnections([]() { return true; });
  quicServer_->shutdown();
  quicServer_.reset();
}
} // namespace quic
