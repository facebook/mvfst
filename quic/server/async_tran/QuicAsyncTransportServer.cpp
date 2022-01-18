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
    QuicAsyncTransportAcceptor::ManagedConnectionFactory connectionFactory)
    : connectionFactory_(std::move(connectionFactory)),
      quicServer_(quic::QuicServer::createQuicServer()) {}

void QuicAsyncTransportServer::setFizzContext(
    std::shared_ptr<const fizz::server::FizzServerContext> ctx) {
  fizzCtx_ = std::move(ctx);
}

void QuicAsyncTransportServer::setTransportSettings() {
  quic::TransportSettings transportSettings;
  uint64_t flowControl = 2024 * 1024 * 1024;
  transportSettings.advertisedInitialConnectionWindowSize = flowControl;
  transportSettings.advertisedInitialBidiLocalStreamWindowSize = flowControl;
  transportSettings.advertisedInitialBidiRemoteStreamWindowSize = flowControl;
  transportSettings.advertisedInitialUniStreamWindowSize = flowControl;
  quicServer_->setTransportSettings(transportSettings);
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
    workerEvbs_.push_back(std::move(scopedEvb));
    auto workerEvb = workerEvbs_.back()->getEventBase();
    evbs.push_back(workerEvb);
  }
  setTransportSettings();
  quicServer_->initialize(address, evbs, false /* useDefaultTransport */);
  quicServer_->waitUntilInitialized();
  createAcceptors();
  quicServer_->start();
}

void QuicAsyncTransportServer::createAcceptors() {
  for (auto& worker : workerEvbs_) {
    auto evb = worker->getEventBase();
    quicServer_->setFizzContext(evb, fizzCtx_);
    auto acceptor = std::make_unique<QuicAsyncTransportAcceptor>(
        evb, [this](folly::AsyncTransport::UniquePtr tran) {
          return connectionFactory_(std::move(tran));
        });
    quicServer_->addTransportFactory(evb, acceptor.get());
    acceptors_.push_back(std::move(acceptor));
  }
}

void QuicAsyncTransportServer::shutdown() {
  quicServer_->rejectNewConnections([]() { return true; });
  for (size_t i = 0; i < workerEvbs_.size(); i++) {
    workerEvbs_[i]->getEventBase()->runInEventBaseThreadAndWait(
        [&] { acceptors_[i]->dropAllConnections(); });
  }
  quicServer_->shutdown();
  quicServer_.reset();
}
} // namespace quic
