/*
 * Copyright (c) Facebook, Inc. and its affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 *
 */

#include <quic/server/QuicServer.h>

#include <folly/Random.h>
#include <folly/io/async/EventBaseManager.h>
#include <quic/codec/DefaultConnectionIdAlgo.h>
#include <quic/codec/QuicHeaderCodec.h>
#include <quic/server/QuicReusePortUDPSocketFactory.h>
#include <quic/server/QuicServer.h>
#include <quic/server/QuicServerTransport.h>
#include <quic/server/QuicSharedUDPSocketFactory.h>

namespace quic {

namespace {
// Determine which worker to route to
// This **MUST** be kept in sync with the BPF program (if supplied)
size_t getWorkerToRouteTo(
    const RoutingData& routingData,
    size_t numWorkers,
    ConnectionIdAlgo* connIdAlgo) {
  return connIdAlgo->parseConnectionId(routingData.destinationConnId).workerId %
      numWorkers;
}
} // namespace

QuicServer::QuicServer() {
  listenerSocketFactory_ = std::make_unique<QuicReusePortUDPSocketFactory>();
  socketFactory_ = std::make_unique<QuicSharedUDPSocketFactory>();
}

void QuicServer::setQuicServerTransportFactory(
    std::unique_ptr<QuicServerTransportFactory> factory) {
  transportFactory_ = std::move(factory);
}

void QuicServer::setQuicUDPSocketFactory(
    std::unique_ptr<QuicUDPSocketFactory> factory) {
  socketFactory_ = std::move(factory);
}

void QuicServer::setListenerSocketFactory(
    std::unique_ptr<QuicUDPSocketFactory> factory) {
  listenerSocketFactory_ = std::move(factory);
}

void QuicServer::setCongestionControllerFactory(
    std::shared_ptr<CongestionControllerFactory> ccFactory) {
  CHECK(!initialized_)
      << " Congestion Control Factorty must be set before the server is "
      << "initialized.";
  CHECK(ccFactory);
  ccFactory_ = std::move(ccFactory);
}

void QuicServer::setSupportedVersion(const std::vector<QuicVersion>& versions) {
  supportedVersions_ = versions;
}

void QuicServer::setProcessId(ProcessId id) noexcept {
  processId_ = id;
}

ProcessId QuicServer::getProcessId() const noexcept {
  return processId_;
}

bool QuicServer::isInitialized() const noexcept {
  return initialized_;
}

void QuicServer::start(const folly::SocketAddress& address, size_t maxWorkers) {
  CHECK(ctx_) << "Must set a TLS context for the Quic server";
  CHECK_LE(maxWorkers, std::numeric_limits<uint8_t>::max());
  size_t numCpu = std::thread::hardware_concurrency();
  if (maxWorkers == 0) {
    maxWorkers = numCpu;
  }
  auto numWorkers = std::min(numCpu, maxWorkers);
  std::vector<folly::EventBase*> evbs;
  for (size_t i = 0; i < numWorkers; ++i) {
    auto scopedEvb = std::make_unique<folly::ScopedEventBaseThread>();
    workerEvbs_.push_back(std::move(scopedEvb));
    if (evbObserver_) {
      workerEvbs_.back()->getEventBase()->runInEventBaseThreadAndWait([&] {
        workerEvbs_.back()->getEventBase()->setObserver(evbObserver_);
      });
    }
    auto workerEvb = workerEvbs_.back()->getEventBase();
    evbs.push_back(workerEvb);
  }
  initialize(address, evbs, true /* useDefaultTransport */);
  start();
}

void QuicServer::initialize(
    const folly::SocketAddress& address,
    const std::vector<folly::EventBase*>& evbs,
    bool useDefaultTransport) {
  CHECK(!evbs.empty());
  CHECK_LE(evbs.size(), std::numeric_limits<uint8_t>::max())
      << "Quic Server does not support more than "
      << std::numeric_limits<uint8_t>::max() << " workers";
  CHECK(shutdown_);
  shutdown_ = false;

  // setting default stateless reset token if not set
  if (!transportSettings_.statelessResetTokenSecret) {
    std::array<uint8_t, kStatelessResetTokenSecretLength> secret;
    folly::Random::secureRandom(secret.data(), secret.size());
    transportSettings_.statelessResetTokenSecret = secret;
  }

  // it the connid algo factory is not set, use default impl
  if (!connIdAlgoFactory_) {
    connIdAlgoFactory_ = std::make_unique<DefaultConnectionIdAlgoFactory>();
    connIdAlgo_ = connIdAlgoFactory_->make();
  } else {
    connIdAlgo_ = connIdAlgoFactory_->make();
  }
  if (!ccFactory_) {
    ccFactory_ = std::make_shared<DefaultCongestionControllerFactory>();
  }
  initializeWorkers(evbs, useDefaultTransport);
  bindWorkersToSocket(address, evbs);
}

void QuicServer::initializeWorkers(
    const std::vector<folly::EventBase*>& evbs,
    bool useDefaultTransport) {
  CHECK(workers_.empty());
  for (auto& workerEvb : evbs) {
    auto worker = newWorkerWithoutSocket();
    if (useDefaultTransport) {
      CHECK(transportFactory_) << "Transport factory is not set";
      worker->setTransportFactory(transportFactory_.get());
      worker->setFizzContext(ctx_);
    }
    if (healthCheckToken_) {
      worker->setHealthCheckToken(*healthCheckToken_);
    }
    if (transportStatsFactory_) {
      workerEvb->runInEventBaseThread(
          [self = this->shared_from_this(),
           workerEvb,
           workerPtr = worker.get(),
           transportStatsFactory = transportStatsFactory_.get()] {
            if (self->shutdown_) {
              return;
            }
            auto statsCallback = transportStatsFactory->make(workerEvb);
            CHECK(statsCallback);
            workerPtr->setTransportInfoCallback(std::move(statsCallback));
          });
    }
    worker->setConnectionIdAlgo(connIdAlgoFactory_->make());
    worker->setCongestionControllerFactory(ccFactory_);
    worker->setWorkerId(workers_.size());
    workers_.push_back(std::move(worker));
    evbToWorkers_.emplace(workerEvb, workers_.back().get());
  }
}

std::unique_ptr<QuicServerWorker> QuicServer::newWorkerWithoutSocket() {
  auto worker = std::make_unique<QuicServerWorker>(this->shared_from_this());
  worker->setNewConnectionSocketFactory(socketFactory_.get());
  worker->setSupportedVersions(supportedVersions_);
  worker->setTransportSettings(transportSettings_);
  worker->rejectNewConnections(rejectNewConnections_);
  worker->setProcessId(processId_);
  worker->setHostId(hostId_);
  return worker;
}

void QuicServer::bindWorkersToSocket(
    const folly::SocketAddress& address,
    const std::vector<folly::EventBase*>& evbs) {
  auto numWorkers = evbs.size();
  for (size_t i = 0; i < numWorkers; ++i) {
    auto workerEvb = evbs[i];
    workerEvb->runImmediatelyOrRunInEventBaseThreadAndWait(
        [address,
         self = this->shared_from_this(),
         workerEvb,
         numWorkers,
         processId = processId_,
         idx = i] {
          std::lock_guard<std::mutex> guard(self->startMutex_);
          if (self->shutdown_) {
            return;
          }
          auto workerSocket = self->listenerSocketFactory_->make(workerEvb, -1);
          auto it = self->evbToWorkers_.find(workerEvb);
          CHECK(it != self->evbToWorkers_.end());
          auto worker = it->second;
          int takeoverOverFd = -1;
          if (self->listeningFDs_.size() > idx) {
            takeoverOverFd = self->listeningFDs_[idx];
          }
          // dup the takenover socket on only one worker and bind the rest
          if (takeoverOverFd >= 0) {
            VLOG(4) << "Setting dup()'ed fd for address=" << address
                    << " on workerId=" << (int)worker->getWorkerId();
            workerSocket->setFD(
                folly::NetworkSocket::fromFd(::dup(takeoverOverFd)),
                // set ownership to OWNS to allow ::close()'ing of of the fd
                // when this server goes away
                folly::AsyncUDPSocket::FDOwnership::OWNS);
            worker->setSocket(std::move(workerSocket));
          } else {
            VLOG(4) << "No valid takenover fd found for address=" << address
                    << ". binding on worker=" << worker
                    << " workerId=" << (int)worker->getWorkerId()
                    << " processId=" << (int)processId;
            worker->setSocket(std::move(workerSocket));
            worker->bind(address);
          }
          if (idx == (numWorkers - 1)) {
            VLOG(4) << "Initialized all workers in the eventbase";
            self->initialized_ = true;
            self->startCv_.notify_all();
          }
        });
  }
}

void QuicServer::start() {
  CHECK(initialized_);
  // initialize the thread local ptr to workers
  runOnAllWorkers([&](auto worker) mutable {
    // pass in no-op deleter to ThreadLocalPtr since the destruction of
    // QuicServerWorker is managed by the QuicServer
    workerPtr_.reset(
        worker, [](auto /* worker */, folly::TLPDestructionMode) {});
  });
  for (auto& worker : workers_) {
    worker->getEventBase()->runInEventBaseThread(
        [&worker] { worker->start(); });
  }
}

void QuicServer::allowBeingTakenOver(const folly::SocketAddress& addr) {
  // synchronously bind workers to takeover handler port.
  // This method should not be called from a worker
  CHECK(!workers_.empty());
  CHECK(!shutdown_);

  // this function shouldn't be called from worker's thread
  for (auto& worker : workers_) {
    DCHECK(
        // if the eventbase is not running, it returns true for isInEvbThread()
        !worker->getEventBase()->isRunning() ||
        !worker->getEventBase()->isInEventBaseThread());
  }
  // TODO workers_ (vector) is not protected against concurrent modifications
  auto numWorkers = workers_.size();
  for (size_t i = 0; i < numWorkers; ++i) {
    auto workerEvb = workers_[i]->getEventBase();
    workerEvb->runImmediatelyOrRunInEventBaseThreadAndWait([&] {
      std::lock_guard<std::mutex> guard(startMutex_);
      CHECK(initialized_);
      auto localListenSocket = listenerSocketFactory_->make(workerEvb, -1);
      auto it = evbToWorkers_.find(workerEvb);
      CHECK(it != evbToWorkers_.end());
      auto worker = it->second;
      worker->allowBeingTakenOver(std::move(localListenSocket), addr);
    });
  }
  VLOG(4) << "Bind all workers in the eventbase to takeover handler port";
  takeoverHandlerInitialized_ = true;
}

void QuicServer::pauseRead() {
  runOnAllWorkers([&](auto worker) mutable { worker->pauseRead(); });
}

void QuicServer::routeDataToWorker(
    const folly::SocketAddress& client,
    RoutingData&& routingData,
    NetworkData&& networkData) {
  // figure out worker idx
  if (!initialized_) {
    // drop the packet if we are not initialized. This is a janky memory
    // barrier.
    VLOG(4) << "Dropping data since quic-server is not initialized";
    if (workerPtr_) {
      QUIC_STATS(
          workerPtr_->getTransportInfoCallback(),
          onPacketDropped,
          QuicTransportStatsCallback::PacketDropReason::WORKER_NOT_INITIALIZED);
    }
    return;
  }

  if (shutdown_) {
    VLOG(4) << "Dropping data since quic server is shutdown";
    if (workerPtr_) {
      QUIC_STATS(
          workerPtr_->getTransportInfoCallback(),
          onPacketDropped,
          QuicTransportStatsCallback::PacketDropReason::SERVER_SHUTDOWN);
    }
    return;
  }

  // For initial or zeroRtt packets, pick the worker that kernel / bpf routed to
  // Without this, when (bpf / kernel) hash and userspace hash get out of sync
  // (e.g. due to shuffling of sockets in the hash ring), it results in
  // very high amount of 'misses'
  if (routingData.isUsingClientConnId && workerPtr_) {
    CHECK(workerPtr_->getEventBase()->isInEventBaseThread());
    workerPtr_->dispatchPacketData(
        client, std::move(routingData), std::move(networkData));
    return;
  }

  auto workerToRunOn =
      getWorkerToRouteTo(routingData, workers_.size(), connIdAlgo_.get());
  auto& worker = workers_[workerToRunOn];
  VLOG_IF(4, !worker->getEventBase()->isInEventBaseThread())
      << " Routing to worker in different EVB, to workerId=" << workerToRunOn;
  worker->getEventBase()->runInEventBaseThread(
      [server = this->shared_from_this(),
       cl = client,
       routingData = std::move(routingData),
       w = worker.get(),
       buf = std::move(networkData)]() mutable {
        if (server->shutdown_) {
          return;
        }
        w->dispatchPacketData(cl, std::move(routingData), std::move(buf));
      });
}

void QuicServer::handleWorkerError(LocalErrorCode error) {
  shutdown(error);
}

void QuicServer::waitUntilInitialized() {
  std::unique_lock<std::mutex> guard(startMutex_);
  if (shutdown_ || initialized_) {
    return;
  }
  for (auto& worker : workers_) {
    DCHECK(!worker->getEventBase()->isInEventBaseThread());
  }
  startCv_.wait(guard, [&] { return initialized_ || shutdown_; });
}

QuicServer::~QuicServer() {
  shutdown(LocalErrorCode::SHUTTING_DOWN);
}

void QuicServer::shutdown(LocalErrorCode error) {
  if (shutdown_) {
    return;
  }
  for (auto& worker : workers_) {
    DCHECK(!worker->getEventBase()->isInEventBaseThread());
  }
  shutdown_ = true;
  for (auto& worker : workers_) {
    worker->getEventBase()->runInEventBaseThreadAndWait([&] {
      worker->shutdownAllConnections(error);
      workerPtr_.reset();
    });
    // protecting the erase in map with the mutex since
    // the erase could potentally affect concurrent accesses from other threads
    std::lock_guard<std::mutex> guard(startMutex_);
    evbToWorkers_.erase(worker->getEventBase());
    evbToAcceptors_.erase(worker->getEventBase());
  }
  startCv_.notify_all();
}

bool QuicServer::hasShutdown() const noexcept {
  return shutdown_;
}

void QuicServer::runOnAllWorkers(std::function<void(QuicServerWorker*)> func) {
  std::lock_guard<std::mutex> guard(startMutex_);
  if (shutdown_) {
    return;
  }
  for (auto& worker : workers_) {
    worker->getEventBase()->runInEventBaseThread(
        [&worker, self = this->shared_from_this(), func]() mutable {
          if (self->shutdown_) {
            return;
          }
          func(worker.get());
        });
  }
}

void QuicServer::setHostId(uint16_t hostId) noexcept {
  CHECK(!initialized_) << "Host id must be set before initializing Quic server";
  hostId_ = hostId;
}

void QuicServer::setHealthCheckToken(const std::string& healthCheckToken) {
  // Make sure the token satisfies the required properties, i.e. it is not a
  // valid quic header.
  auto parsed = parseHeader(*folly::IOBuf::copyBuffer(healthCheckToken));
  CHECK(!parsed.hasValue());
  CHECK_GT(healthCheckToken.size(), kMinHealthCheckTokenSize);
  healthCheckToken_ = healthCheckToken;
  runOnAllWorkers([healthCheckToken](auto worker) mutable {
    worker->setHealthCheckToken(healthCheckToken);
  });
}

void QuicServer::setFizzContext(
    std::shared_ptr<const fizz::server::FizzServerContext> ctx) {
  ctx_ = ctx;
  runOnAllWorkers([ctx](auto worker) mutable { worker->setFizzContext(ctx); });
}

void QuicServer::setFizzContext(
    folly::EventBase* evb,
    std::shared_ptr<const fizz::server::FizzServerContext> ctx) {
  CHECK(evb);
  CHECK(ctx);
  evb->runImmediatelyOrRunInEventBaseThreadAndWait([&] {
    std::lock_guard<std::mutex> guard(startMutex_);
    if (shutdown_) {
      return;
    }
    auto it = evbToWorkers_.find(evb);
    CHECK(it != evbToWorkers_.end());
    it->second->setFizzContext(ctx);
  });
}

void QuicServer::setTransportSettings(TransportSettings transportSettings) {
  transportSettings_ = transportSettings;
  runOnAllWorkers([transportSettings](auto worker) mutable {
    worker->setTransportSettings(transportSettings);
  });
}

void QuicServer::rejectNewConnections(bool reject) {
  rejectNewConnections_ = reject;
  runOnAllWorkers(
      [reject](auto worker) mutable { worker->rejectNewConnections(reject); });
}

void QuicServer::setEventBaseObserver(
    std::shared_ptr<folly::EventBaseObserver> observer) {
  if (shutdown_ || workerEvbs_.empty()) {
    return;
  }
  workerEvbs_.front()->getEventBase()->runInEventBaseThreadAndWait(
      [&] { evbObserver_ = observer; });
  runOnAllWorkers([observer](auto worker) {
    worker->getEventBase()->setObserver(observer);
  });
};

void QuicServer::startPacketForwarding(const folly::SocketAddress& destAddr) {
  if (initialized_) {
    runOnAllWorkers([destAddr](auto worker) mutable {
      worker->startPacketForwarding(destAddr);
    });
  }
}

void QuicServer::stopPacketForwarding(std::chrono::milliseconds delay) {
  std::lock_guard<std::mutex> guard(startMutex_);
  if (!initialized_ || shutdown_) {
    return;
  }
  for (auto& worker : workers_) {
    worker->getEventBase()->runInEventBaseThread(
        [&worker, self = this->shared_from_this(), delay]() mutable {
          if (self->shutdown_) {
            return;
          }
          worker->getEventBase()->runAfterDelay(
              [&worker, self]() mutable {
                if (worker && !self->shutdown_) {
                  worker->stopPacketForwarding();
                }
              },
              delay.count());
        });
  }
}

void QuicServer::setTransportStatsCallbackFactory(
    std::unique_ptr<QuicTransportStatsCallbackFactory> statsFactory) {
  CHECK(statsFactory);
  transportStatsFactory_ = std::move(statsFactory);
}

void QuicServer::setConnectionIdAlgoFactory(
    std::unique_ptr<ConnectionIdAlgoFactory> connIdAlgoFactory) {
  CHECK(!initialized_);
  CHECK(connIdAlgoFactory);
  connIdAlgoFactory_ = std::move(connIdAlgoFactory);
}

void QuicServer::addTransportFactory(
    folly::EventBase* evb,
    QuicServerTransportFactory* acceptor) {
  CHECK(evb);
  CHECK(acceptor);
  evb->runImmediatelyOrRunInEventBaseThreadAndWait([&] {
    std::lock_guard<std::mutex> guard(startMutex_);
    if (shutdown_) {
      return;
    }
    evbToAcceptors_.emplace(evb, acceptor);
    auto it = evbToWorkers_.find(evb);
    if (it != evbToWorkers_.end()) {
      it->second->setTransportFactory(acceptor);
    } else {
      VLOG(3) << "Couldn't find associated worker for the given eventbase";
    }
  });
}

const folly::SocketAddress& QuicServer::getAddress() const {
  CHECK(initialized_) << "Quic server is not initialized. "
                      << "Consider calling waitUntilInitialized() before this ";
  return workers_[0]->getAddress();
}

void QuicServer::setListeningFDs(const std::vector<int>& fds) {
  std::lock_guard<std::mutex> guard(startMutex_);
  listeningFDs_ = fds;
}

int QuicServer::getListeningSocketFD() const {
  CHECK(initialized_) << "Quic server is not initialized. "
                      << "Consider calling waitUntilInitialized() before this ";
  return workers_[0]->getFD();
}

std::vector<int> QuicServer::getAllListeningSocketFDs() const noexcept {
  CHECK(initialized_) << "Quic server is not initialized. "
                      << "Consider calling waitUntilInitialized() before this ";
  std::vector<int> sockets;
  for (const auto& worker : workers_) {
    if (worker->getFD() != -1) {
      sockets.push_back(worker->getFD());
    }
  }
  return sockets;
}

TakeoverProtocolVersion QuicServer::getTakeoverProtocolVersion() const
    noexcept {
  return workers_[0]->getTakeoverProtocolVersion();
}

int QuicServer::getTakeoverHandlerSocketFD() const {
  CHECK(takeoverHandlerInitialized_) << "TakeoverHanders are not initialized. ";
  return workers_[0]->getTakeoverHandlerSocketFD();
}

std::vector<folly::EventBase*> QuicServer::getWorkerEvbs() const noexcept {
  CHECK(initialized_) << "Quic server is not initialized. ";
  std::vector<folly::EventBase*> ebvs;
  for (const auto& worker : workers_) {
    ebvs.push_back(worker->getEventBase());
  }
  return ebvs;
}

} // namespace quic
