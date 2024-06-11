/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <quic/server/QuicServer.h>

#include <folly/Random.h>
#include <folly/io/async/EventBaseManager.h>
#include <folly/portability/GFlags.h>
#include <quic/codec/DefaultConnectionIdAlgo.h>
#include <quic/codec/QuicHeaderCodec.h>
#include <quic/server/QuicReusePortUDPSocketFactory.h>
#include <quic/server/QuicServerTransport.h>
#include <quic/server/QuicSharedUDPSocketFactory.h>
#include <quic/server/SlidingWindowRateLimiter.h>
#include <iterator>

FOLLY_GFLAGS_DEFINE_bool(
    qs_io_uring_use_async_recv,
    true,
    "io_uring backend use async recv");
FOLLY_GFLAGS_DEFINE_int32(
    qs_conn_id_version,
    0,
    "connection id format version quic server used for encoding. only non-zero version is honored");

namespace {
using namespace quic;
// Determine which worker to route to
// This **MUST** be kept in sync with the BPF program (if supplied)
size_t getWorkerToRouteTo(
    const RoutingData& routingData,
    size_t numWorkers,
    ConnectionIdAlgo* connIdAlgo) {
  return connIdAlgo->parseConnectionId(routingData.destinationConnId)
             ->workerId %
      numWorkers;
}

constexpr std::string_view kQuicServerNotInitialized =
    "Quic server is not initialized. "
    "Consider calling waitUntilInitialized() prior to: ";

void checkRunningInThread(const std::thread::id expectedThreadId) {
  CHECK(std::this_thread::get_id() == expectedThreadId);
}

// these two functions either delete the IOExecutor if we own it, or otherwise
// no-op
void ownedEvbDeleter(folly::IOExecutor* evb) {
  std::default_delete<folly::IOExecutor>()(evb);
}

void unownedEvbDeleter(folly::IOExecutor*) {}

} // namespace
//
namespace quic {

QuicServer::QuicServer() : mainThreadId_(std::this_thread::get_id()) {
#ifdef _WIN32
  listenerSocketFactory_ = std::make_unique<QuicReusePortUDPSocketFactory>(
      true /* reusePort*/, true /* reuseAddr */);
#else
  listenerSocketFactory_ = std::make_unique<QuicReusePortUDPSocketFactory>();
#endif
  socketFactory_ = std::make_unique<QuicSharedUDPSocketFactory>();
  if (FLAGS_qs_conn_id_version) {
    // only set cidVersion_ if gflag is non-zero. otherwise,
    // cidVersion_ is V1 by default
    cidVersion_ = (ConnectionIdVersion)FLAGS_qs_conn_id_version;
  }
}

void QuicServer::setQuicServerTransportFactory(
    std::unique_ptr<QuicServerTransportFactory> factory) {
  checkRunningInThread(mainThreadId_);
  transportFactory_ = std::move(factory);
}

void QuicServer::setQuicUDPSocketFactory(
    std::unique_ptr<QuicUDPSocketFactory> factory) {
  checkRunningInThread(mainThreadId_);
  socketFactory_ = std::move(factory);
}

void QuicServer::setListenerSocketFactory(
    std::unique_ptr<QuicUDPSocketFactory> factory) {
  checkRunningInThread(mainThreadId_);
  listenerSocketFactory_ = std::move(factory);
}

void QuicServer::setCongestionControllerFactory(
    std::shared_ptr<CongestionControllerFactory> ccFactory) {
  checkRunningInThread(mainThreadId_);
  CHECK(!initialized_) << kQuicServerNotInitialized << __func__;
  CHECK(ccFactory);
  ccFactory_ = std::move(ccFactory);
}

void QuicServer::setRateLimit(
    std::function<uint64_t()> count,
    std::chrono::seconds window) {
  checkRunningInThread(mainThreadId_);
  rateLimit_ = folly::make_optional<RateLimit>(std::move(count), window);
}

void QuicServer::setUnfinishedHandshakeLimit(std::function<int()> limitFn) {
  checkRunningInThread(mainThreadId_);
  unfinishedHandshakeLimitFn_ = std::move(limitFn);
}

void QuicServer::setSupportedVersion(const std::vector<QuicVersion>& versions) {
  checkRunningInThread(mainThreadId_);
  supportedVersions_ = versions;
}

void QuicServer::setProcessId(ProcessId id) noexcept {
  checkRunningInThread(mainThreadId_);
  processId_ = id;
}

ProcessId QuicServer::getProcessId() const noexcept {
  return processId_;
}

bool QuicServer::isInitialized() const noexcept {
  return initialized_;
}

void QuicServer::start(const folly::SocketAddress& address, size_t maxWorkers) {
  checkRunningInThread(mainThreadId_);
  CHECK(ctx_) << "Must set a TLS context for the Quic server";
  CHECK_LE(maxWorkers, std::numeric_limits<uint8_t>::max());
  size_t numCpu = std::thread::hardware_concurrency();
  if (maxWorkers == 0) {
    maxWorkers = numCpu;
  }
  auto const backendDetails = getEventBaseBackendDetails();
  backendSupportsMultishotCallback_ = backendDetails.supportsRecvmsgMultishot;
  auto numWorkers = std::min(numCpu, maxWorkers);

  // ::start() is the api for QuicServer to construct and own the EventBases the
  // QuicServerWorkers are running on
  std::vector<MaybeOwnedEvbPtr> ownedEvbs;
  ownedEvbs.reserve(numWorkers);
  for (size_t i = 0; i < numWorkers; ++i) {
    auto scopedEvb = std::make_unique<folly::ScopedEventBaseThread>(
        folly::EventBase::Options().setBackendFactory(backendDetails.factory),
        nullptr,
        "");

    ownedEvbs.push_back({scopedEvb.release(), ownedEvbDeleter});
  }
  initializeImpl(address, std::move(ownedEvbs), true /* useDefaultTransport */);
  start();
}

void QuicServer::initialize(
    const folly::SocketAddress& address,
    const std::vector<folly::EventBase*>& evbs,
    bool useDefaultTransport) {
  checkRunningInThread(mainThreadId_);

  // transform evbs to std::vector<MaybeOwnedEvbPtr> with no ownership
  std::vector<MaybeOwnedEvbPtr> unownedEvbs;
  unownedEvbs.reserve(evbs.size());

  for (auto* evb : evbs) {
    unownedEvbs.push_back(
        {static_cast<folly::IOExecutor*>(evb), unownedEvbDeleter});
  }

  initializeImpl(address, std::move(unownedEvbs), useDefaultTransport);
}

void QuicServer::initializeImpl(
    const folly::SocketAddress& address,
    std::vector<MaybeOwnedEvbPtr> evbs,
    bool useDefaultTransport) {
  checkRunningInThread(mainThreadId_);
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
  }
  connIdAlgo_ = connIdAlgoFactory_->make();

  if (!ccFactory_) {
    ccFactory_ = std::make_shared<ServerCongestionControllerFactory>();
  }

  workerEvbs_.swap(evbs);

  initializeWorkers(useDefaultTransport);
  bindWorkersToSocket(address);
}

void QuicServer::initializeWorkers(bool useDefaultTransport) {
  CHECK(workers_.empty());
  // iterate in the order of insertion in vector
  auto workerEvbs = workerEvbs_.rlock();
  for (size_t i = 0; i < workerEvbs->size(); ++i) {
    auto worker = newWorkerWithoutSocket();
    if (useDefaultTransport) {
      CHECK(transportFactory_) << "Transport factory is not set";
      worker->setTransportFactory(transportFactory_.get());
      worker->setFizzContext(ctx_);
    }
    worker->setWorkerId(i);
    workers_.push_back(std::move(worker));
    evbToWorkers_.emplace(
        (*workerEvbs)[i]->getEventBase(), workers_.back().get());
  }
}

std::unique_ptr<QuicServerWorker> QuicServer::newWorkerWithoutSocket() {
  QuicServerWorker::SetEventCallback sec;
  if (FLAGS_qs_io_uring_use_async_recv) {
    sec = backendSupportsMultishotCallback_
        ? QuicServerWorker::SetEventCallback::RECVMSG_MULTISHOT
        : QuicServerWorker::SetEventCallback::RECVMSG;
  } else {
    sec = QuicServerWorker::SetEventCallback::NONE;
  }
  auto worker =
      std::make_unique<QuicServerWorker>(this->shared_from_this(), sec);
  worker->setNewConnectionSocketFactory(socketFactory_.get());
  worker->setSupportedVersions(supportedVersions_);
  worker->setTransportSettings(transportSettings_);
  worker->rejectNewConnections(rejectNewConnections_);
  worker->setProcessId(processId_);
  worker->setHostId(hostId_);
  worker->setConnectionIdVersion(cidVersion_);
  if (healthCheckToken_) {
    worker->setHealthCheckToken(*healthCheckToken_);
  }
  if (transportStatsFactory_) {
    auto statsCallback = transportStatsFactory_->make();
    CHECK(statsCallback);
    worker->setTransportStatsCallback(std::move(statsCallback));
  }
  worker->setConnectionIdAlgo(connIdAlgoFactory_->make());
  worker->setCongestionControllerFactory(ccFactory_);
  if (rateLimit_) {
    worker->setRateLimiter(std::make_unique<SlidingWindowRateLimiter>(
        rateLimit_->count, rateLimit_->window));
  }
  worker->setUnfinishedHandshakeLimit(unfinishedHandshakeLimitFn_);
  worker->setTransportSettingsOverrideFn(transportSettingsOverrideFn_);
  return worker;
}

void QuicServer::bindWorkersToSocket(const folly::SocketAddress& address) {
  auto workerEvbs = workerEvbs_.rlock();
  auto numWorkers = workerEvbs->size();
  CHECK(!initialized_);
  boundAddress_ = address;
  for (size_t i = 0; i < numWorkers; ++i) {
    auto* workerEvb = (*workerEvbs)[i]->getEventBase();
    workerEvb->runImmediatelyOrRunInEventBaseThreadAndWait(
        [self = this->shared_from_this(),
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
          worker->setSocketOptions(&self->socketOptions_);
          // dup the takenover socket on only one worker and bind the rest
          if (takeoverOverFd >= 0) {
            workerSocket->setFD(
                folly::NetworkSocket::fromFd(::dup(takeoverOverFd)),
                // set ownership to OWNS to allow ::close()'ing of of the fd
                // when this server goes away
                FollyAsyncUDPSocketAlias::FDOwnership::OWNS);
            worker->setSocket(std::move(workerSocket));
            if (idx == 0) {
              self->boundAddress_ = worker->getAddress();
            }
            VLOG(4) << "Set up dup()'ed fd for address=" << self->boundAddress_
                    << " on workerId=" << (int)worker->getWorkerId();
            worker->applyAllSocketOptions();
          } else {
            VLOG(4) << "No valid takenover fd found for address="
                    << self->boundAddress_ << ". binding on worker=" << worker
                    << " workerId=" << (int)worker->getWorkerId()
                    << " processId=" << (int)processId;
            worker->setSocket(std::move(workerSocket));
            worker->bind(self->boundAddress_, self->bindOptions_);
            if (idx == 0) {
              self->boundAddress_ = worker->getAddress();
            }
          }
          if (idx == (numWorkers - 1)) {
            VLOG(4) << "Initialized all workers in the eventbase";
            self->initialized_ = true;
            folly::call_once(
                self->startDone_, [self]() { self->startDoneBaton_.post(); });
          }
        });
  }
}

void QuicServer::start() {
  checkRunningInThread(mainThreadId_);
  CHECK(initialized_) << kQuicServerNotInitialized << __func__;
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
  checkRunningInThread(mainThreadId_);
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
    workerEvb->runInEventBaseThreadAndWait([&] {
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

folly::SocketAddress QuicServer::overrideTakeoverHandlerAddress(
    const folly::SocketAddress& addr) {
  checkRunningInThread(mainThreadId_);
  // synchronously bind workers to takeover handler port.
  // This method should not be called from a worker
  CHECK(!workers_.empty());
  CHECK(!shutdown_);
  CHECK(takeoverHandlerInitialized_) << "TakeoverHanders are not initialized. ";

  // this function shouldn't be called from worker's thread
  for (auto& worker : workers_) {
    DCHECK(
        // if the eventbase is not running, it returns true for isInEvbThread()
        !worker->getEventBase()->isRunning() ||
        !worker->getEventBase()->isInEventBaseThread());
  }
  folly::SocketAddress boundAddress;
  for (auto& worker : workers_) {
    worker->getEventBase()->runInEventBaseThreadAndWait([&] {
      std::lock_guard<std::mutex> guard(startMutex_);
      CHECK(initialized_);
      auto workerEvb = worker->getEventBase();
      auto localListenSocket = listenerSocketFactory_->make(workerEvb, -1);
      boundAddress = worker->overrideTakeoverHandlerAddress(
          std::move(localListenSocket), addr);
    });
  }
  return boundAddress;
}

void QuicServer::pauseRead() {
  checkRunningInThread(mainThreadId_);
  runOnAllWorkersSync([&](auto worker) mutable { worker->pauseRead(); });
}

void QuicServer::routeDataToWorker(
    const folly::SocketAddress& client,
    RoutingData&& routingData,
    NetworkData&& networkData,
    Optional<QuicVersion> quicVersion,
    folly::EventBase*,
    bool isForwardedData) {
  // figure out worker idx
  if (!initialized_) {
    // drop the packet if we are not initialized. This is a janky memory
    // barrier.
    VLOG(4) << "Dropping data since quic-server is not initialized";
    if (workerPtr_) {
      QUIC_STATS(
          workerPtr_->getTransportStatsCallback(),
          onPacketDropped,
          PacketDropReason::WORKER_NOT_INITIALIZED);
    }
    return;
  }

  if (shutdown_) {
    VLOG(4) << "Dropping data since quic server is shutdown";
    if (workerPtr_) {
      QUIC_STATS(
          workerPtr_->getTransportStatsCallback(),
          onPacketDropped,
          PacketDropReason::SERVER_SHUTDOWN);
    }
    return;
  }

  // For initial or zeroRtt packets, pick the worker that kernel / bpf routed to
  // Without this, when (bpf / kernel) hash and userspace hash get out of sync
  // (e.g. due to shuffling of sockets in the hash ring), it results in
  // very high amount of 'misses'
  if (routingData.clientChosenDcid && workerPtr_) {
    CHECK(workerPtr_->getEventBase()->isInEventBaseThread());
    workerPtr_->dispatchPacketData(
        client,
        std::move(routingData),
        std::move(networkData),
        quicVersion,
        isForwardedData);
    return;
  }

  auto workerToRunOn =
      getWorkerToRouteTo(routingData, workers_.size(), connIdAlgo_.get());
  auto& worker = workers_[workerToRunOn];
  VLOG_IF(4, !worker->getEventBase()->isInEventBaseThread())
      << " Routing to worker in different EVB, to workerId=" << workerToRunOn;
  folly::EventBase* workerEvb = worker->getEventBase();
  bool isInEvb = workerEvb->isInEventBaseThread();
  if (isInEvb) {
    worker->dispatchPacketData(
        client,
        std::move(routingData),
        std::move(networkData),
        quicVersion,
        isForwardedData);
    return;
  }
  worker->getEventBase()->runInEventBaseThread([server =
                                                    this->shared_from_this(),
                                                cl = client,
                                                routingData =
                                                    std::move(routingData),
                                                w = worker.get(),
                                                buf = std::move(networkData),
                                                isForwarded = isForwardedData,
                                                quicVersion]() mutable {
    if (server->shutdown_) {
      return;
    }
    w->dispatchPacketData(
        cl, std::move(routingData), std::move(buf), quicVersion, isForwarded);
  });
}

void QuicServer::handleWorkerError(LocalErrorCode error) {
  shutdown(error);
}

void QuicServer::waitUntilInitialized() {
  if (shutdown_ || initialized_) {
    return;
  }
  for (auto& worker : workers_) {
    CHECK(!worker->getEventBase()->isInEventBaseThread());
  }
  // block until all workers have been initialized or shutdown completed
  startDoneBaton_.wait();
  CHECK(initialized_ || shutdown_);
}

QuicServer::~QuicServer() {
  shutdown(LocalErrorCode::SHUTTING_DOWN);
}

void QuicServer::shutdown(LocalErrorCode error) {
  if (shutdown_) {
    return;
  }
  shutdown_ = true;
  for (auto& worker : workers_) {
    worker->getEventBase()->runImmediatelyOrRunInEventBaseThreadAndWait([&] {
      worker->shutdownAllConnections(error);
      workerPtr_.reset();
    });
    // protecting the erase in map with the mutex since
    // the erase could potentially affect concurrent accesses from other threads
    std::lock_guard<std::mutex> guard(startMutex_);
    evbToWorkers_.erase(worker->getEventBase());
  }
  folly::call_once(startDone_, [this]() { this->startDoneBaton_.post(); });
}

bool QuicServer::hasShutdown() const noexcept {
  return shutdown_;
}

void QuicServer::runOnAllWorkers(
    const std::function<void(QuicServerWorker*)>& func) {
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

void QuicServer::runOnAllWorkersSync(
    const std::function<void(QuicServerWorker*)>& func) {
  std::lock_guard<std::mutex> guard(startMutex_);
  if (shutdown_) {
    return;
  }
  for (auto& worker : workers_) {
    worker->getEventBase()->runImmediatelyOrRunInEventBaseThreadAndWait(
        [&worker, self = this->shared_from_this(), func]() mutable {
          if (self->shutdown_) {
            return;
          }
          func(worker.get());
        });
  }
}

void QuicServer::setHostId(uint32_t hostId) noexcept {
  checkRunningInThread(mainThreadId_);
  CHECK(!initialized_) << kQuicServerNotInitialized << __func__;
  hostId_ = hostId;
}

void QuicServer::setConnectionIdVersion(
    ConnectionIdVersion cidVersion) noexcept {
  checkRunningInThread(mainThreadId_);
  CHECK(!initialized_) << kQuicServerNotInitialized << __func__;
  if (FLAGS_qs_conn_id_version) {
    LOG(ERROR) << "Connection Id Version has been set to " << (int)cidVersion_
               << " by --qs_conn_id_version from the command line.";
  } else {
    cidVersion_ = cidVersion;
  }
}

void QuicServer::setTransportSettingsOverrideFn(
    TransportSettingsOverrideFn fn) {
  checkRunningInThread(mainThreadId_);
  CHECK(!initialized_) << kQuicServerNotInitialized << __func__;
  transportSettingsOverrideFn_ = std::move(fn);
}

void QuicServer::setHealthCheckToken(const std::string& healthCheckToken) {
  checkRunningInThread(mainThreadId_);
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
  checkRunningInThread(mainThreadId_);
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

const TransportSettings& QuicServer::getTransportSettings() const noexcept {
  return transportSettings_;
}

void QuicServer::setTransportSettings(TransportSettings transportSettings) {
  checkRunningInThread(mainThreadId_);
  transportSettings_ = transportSettings;
  runOnAllWorkers([transportSettings](auto worker) mutable {
    worker->setTransportSettings(transportSettings);
  });
}

void QuicServer::rejectNewConnections(std::function<bool()> rejectFn) {
  rejectNewConnections_ = rejectFn;
  runOnAllWorkers([rejectFn](auto worker) mutable {
    worker->rejectNewConnections(rejectFn);
  });
}

void QuicServer::blockListedSrcPort(
    std::function<bool(uint16_t)> isBlockListedSrcPort) {
  checkRunningInThread(mainThreadId_);
  isBlockListedSrcPort_ = isBlockListedSrcPort;
  runOnAllWorkers([isBlockListedSrcPort](auto worker) mutable {
    worker->setIsBlockListedSrcPort(isBlockListedSrcPort);
  });
}

void QuicServer::startPacketForwarding(const folly::SocketAddress& destAddr) {
  checkRunningInThread(mainThreadId_);
  if (initialized_) {
    runOnAllWorkersSync([destAddr](auto worker) mutable {
      worker->startPacketForwarding(destAddr);
    });
  }
}

void QuicServer::stopPacketForwarding(std::chrono::milliseconds delay) {
  checkRunningInThread(mainThreadId_);
  std::lock_guard<std::mutex> guard(startMutex_);
  if (!initialized_ || shutdown_) {
    return;
  }
  for (auto& worker : workers_) {
    worker->getEventBase()->runInEventBaseThreadAndWait(
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
  checkRunningInThread(mainThreadId_);
  CHECK(statsFactory);
  transportStatsFactory_ = std::move(statsFactory);
}

void QuicServer::setConnectionIdAlgoFactory(
    std::unique_ptr<ConnectionIdAlgoFactory> connIdAlgoFactory) {
  checkRunningInThread(mainThreadId_);
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
    auto it = evbToWorkers_.find(evb);
    if (it != evbToWorkers_.end()) {
      it->second->setTransportFactory(acceptor);
    } else {
      VLOG(3) << "Couldn't find associated worker for the given eventbase";
    }
  });
}

const folly::SocketAddress& QuicServer::getAddress() const {
  CHECK(initialized_) << kQuicServerNotInitialized << __func__;
  return boundAddress_;
}

void QuicServer::setListeningFDs(const std::vector<int>& fds) {
  checkRunningInThread(mainThreadId_);
  std::lock_guard<std::mutex> guard(startMutex_);
  listeningFDs_ = fds;
}

int QuicServer::getListeningSocketFD() const {
  CHECK(initialized_) << kQuicServerNotInitialized << __func__;
  return workers_[0]->getFD();
}

std::vector<int> QuicServer::getAllListeningSocketFDs() const noexcept {
  checkRunningInThread(mainThreadId_);
  CHECK(initialized_) << kQuicServerNotInitialized << __func__;
  std::vector<int> sockets(workers_.size());
  for (const auto& worker : workers_) {
    if (worker->getFD() != -1) {
      CHECK_LT(worker->getWorkerId(), workers_.size());
      sockets.at(worker->getWorkerId()) = worker->getFD();
    }
  }
  return sockets;
}

void QuicServer::getAllConnectionsStats(
    std::vector<QuicConnectionStats>& stats) {
  runOnAllWorkersSync(
      [&stats](auto worker) mutable { worker->getAllConnectionsStats(stats); });
}

TakeoverProtocolVersion QuicServer::getTakeoverProtocolVersion()
    const noexcept {
  return workers_[0]->getTakeoverProtocolVersion();
}

int QuicServer::getTakeoverHandlerSocketFD() const {
  checkRunningInThread(mainThreadId_);
  CHECK(takeoverHandlerInitialized_) << "TakeoverHanders are not initialized. ";
  return workers_[0]->getTakeoverHandlerSocketFD();
}

std::vector<folly::EventBase*> QuicServer::getWorkerEvbs() const noexcept {
  checkRunningInThread(mainThreadId_);
  CHECK(initialized_) << kQuicServerNotInitialized << __func__;
  std::vector<folly::EventBase*> ebvs;
  for (const auto& worker : workers_) {
    ebvs.push_back(worker->getEventBase());
  }
  return ebvs;
}

bool QuicServer::addAcceptObserver(
    folly::EventBase* evb,
    AcceptObserver* observer) {
  CHECK(initialized_) << kQuicServerNotInitialized << __func__;
  CHECK(evb);
  bool success = false;
  evb->runImmediatelyOrRunInEventBaseThreadAndWait([&] {
    std::lock_guard<std::mutex> guard(startMutex_);
    if (shutdown_) {
      return;
    }
    auto it = evbToWorkers_.find(evb);
    if (it != evbToWorkers_.end()) {
      it->second->addAcceptObserver(observer);
      success = true;
    } else {
      VLOG(3) << "Couldn't find associated worker for the given eventbase, "
              << "unable to add AcceptObserver";
      success = false;
    }
  });
  return success;
}

bool QuicServer::removeAcceptObserver(
    folly::EventBase* evb,
    AcceptObserver* observer) {
  CHECK(initialized_) << kQuicServerNotInitialized << __func__;
  CHECK(evb);
  bool success = false;
  evb->runImmediatelyOrRunInEventBaseThreadAndWait([&] {
    std::lock_guard<std::mutex> guard(startMutex_);
    if (shutdown_) {
      return;
    }
    auto it = evbToWorkers_.find(evb);
    if (it != evbToWorkers_.end()) {
      success = it->second->removeAcceptObserver(observer);
    } else {
      VLOG(3) << "Couldn't find associated worker for the given eventbase, "
              << "unable to remove AcceptObserver";
      success = false;
    }
  });
  return success;
}

void QuicServer::setSocketOptions(
    const folly::SocketOptionMap& options) noexcept {
  checkRunningInThread(mainThreadId_);
  socketOptions_ = options;
}

/**
 * Sets whether the underlying socket should set the IPV6_ONLY socket option
 * or not. If set to false, IPv4-mapped IPv6 addresses will be enabled on the
 * socket.
 */
void QuicServer::setBindV6Only(bool bindV6Only) {
  checkRunningInThread(mainThreadId_);
  bindOptions_.bindV6Only = bindV6Only;
}

} // namespace quic
