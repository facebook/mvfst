/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <quic/common/MvfstLogging.h>
#include <quic/server/QuicServer.h>

#include <folly/Random.h>
#include <folly/io/async/EventBaseManager.h>
#include <folly/portability/GFlags.h>
#include <folly/system/HardwareConcurrency.h>
#include <quic/codec/DefaultConnectionIdAlgo.h>
#include <quic/codec/QuicHeaderCodec.h>
#include <quic/server/QuicReusePortUDPSocketFactory.h>
#include <quic/server/QuicServerTransport.h>
#include <quic/server/QuicSharedUDPSocketFactory.h>
#include <quic/server/SlidingWindowRateLimiter.h>
#include <iterator>

FOLLY_GFLAGS_DEFINE_int32(
    qs_conn_id_version,
    0,
    "connection id format version quic server used for encoding. only non-zero version is honored");

namespace {
using namespace quic;

[[maybe_unused]] constexpr std::string_view kQuicServerNotInitialized =
    "Quic server is not initialized. "
    "Consider calling waitUntilInitialized() prior to: ";

void checkRunningInThread(const std::thread::id expectedThreadId) {
  MVCHECK(std::this_thread::get_id() == expectedThreadId);
}

// these two functions either delete the IOExecutor if we own it, or otherwise
// no-op
void ownedEvbDeleter(folly::IOExecutor* evb) {
  std::default_delete<folly::IOExecutor>()(evb);
}

void unownedEvbDeleter(folly::IOExecutor*) {}

void validateHealthCheckToken(const std::string& healthCheckToken) {
  // Make sure the token satisfies the required properties, i.e. it is not a
  // valid quic header.
  auto parsed = parseHeader(*BufHelpers::copyBuffer(healthCheckToken));
  MVCHECK(!parsed.has_value());
  MVCHECK_GT(healthCheckToken.size(), kMinHealthCheckTokenSize);
}

} // namespace

//
namespace quic {

QuicServer::QuicServer(TransportSettings transportSettings)
    : transportSettings_(
          validateTransportSettings(std::move(transportSettings))),
      mainThreadId_(std::this_thread::get_id()) {
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

QuicServer::QuicServer(ServerOptions options)
    : QuicServer(options.transportSettings) {
  supportedVersions_ = std::move(options.supportedVersions);
  socketOptions_ = std::move(options.socketOptions);
  bindOptions_ = options.bindOptions;
  processId_ = options.processId;
  hostId_ = options.hostId;
  if (options.cidVersion && !FLAGS_qs_conn_id_version) {
    cidVersion_ = *options.cidVersion;
  }
  if (options.listenerSocketFactory) {
    listenerSocketFactory_ = std::move(options.listenerSocketFactory);
  }
  if (options.socketFactory) {
    socketFactory_ = std::move(options.socketFactory);
  }
  connIdAlgoFactory_ = std::move(options.connIdAlgoFactory);
  transportStatsFactory_ = std::move(options.transportStatsFactory);
  rejectNewConnections_ = std::move(options.rejectNewConnections);
  isPrimingEnabled_ = std::move(options.isPrimingEnabled);
  isBlockListedSrcPort_ = std::move(options.isBlockListedSrcPort);
  if (options.healthCheckToken) {
    validateHealthCheckToken(*options.healthCheckToken);
  }
  healthCheckToken_ = std::move(options.healthCheckToken);
  if (options.rateLimitCount) {
    rateLimit_.emplace(
        std::move(options.rateLimitCount), options.rateLimitWindow);
  }
  unfinishedHandshakeLimitFn_ = std::move(options.unfinishedHandshakeLimitFn);
  transportSettingsOverrideFn_ = std::move(options.transportSettingsOverrideFn);
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
  MVCHECK(!initialized_, kQuicServerNotInitialized << __func__);
  MVCHECK(ccFactory);
  ccFactory_ = std::move(ccFactory);
}

void QuicServer::setBatchWriterFactoryOverride(
    quic::BatchWriterFactoryOverride override) {
  checkRunningInThread(mainThreadId_);
  MVCHECK(!initialized_, kQuicServerNotInitialized << __func__);
  batchWriterFactoryOverride_ = std::move(override);
}

const quic::BatchWriterFactoryOverride&
QuicServer::getBatchWriterFactoryOverride() const noexcept {
  return batchWriterFactoryOverride_;
}

void QuicServer::forEachListenerSocket(
    folly::FunctionRef<void(const folly::AsyncUDPSocket*)> fn) const {
  for (const auto& worker : workers_) {
    const auto* sock = worker->getListenerSocket();
    if (sock != nullptr) {
      fn(sock);
    }
  }
}

void QuicServer::setRateLimit(
    std::function<uint64_t()> count,
    std::chrono::seconds window) {
  checkRunningInThread(mainThreadId_);
  rateLimit_ = quic::make_optional<RateLimit>(std::move(count), window);
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

size_t QuicServer::numWorkersToCreate(
    size_t maxWorkers,
    size_t numCpu) noexcept {
  if (maxWorkers == 0) {
    maxWorkers = numCpu;
  }
  return std::min(
      {numCpu,
       maxWorkers,
       static_cast<size_t>(std::numeric_limits<uint8_t>::max())});
}

void QuicServer::start(const quic::SocketAddress& address, size_t maxWorkers) {
  checkRunningInThread(mainThreadId_);
  MVCHECK(ctx_, "Must set a TLS context for the Quic server");
  MVCHECK_LE(
      maxWorkers,
      std::numeric_limits<uint8_t>::max(),
      "Quic server doesn't support more than "
          << (int)std::numeric_limits<uint8_t>::max() << " workers");
  auto const backendDetails = getEventBaseBackendDetails();
  backendSupportsMultishotCallback_ = backendDetails.supportsRecvmsgMultishot;
  const size_t numCpu = folly::available_concurrency();
  auto numWorkers = numWorkersToCreate(maxWorkers, numCpu);
  if (maxWorkers == 0 && numWorkers < numCpu) {
    MVLOG_WARNING << "Starting " << numWorkers
                  << " quic workers on a host with " << numCpu
                  << " cpus; Quic server doesn't support more workers";
  }

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
    const quic::SocketAddress& address,
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
    const quic::SocketAddress& address,
    std::vector<MaybeOwnedEvbPtr> evbs,
    bool useDefaultTransport) {
  checkRunningInThread(mainThreadId_);
  MVCHECK(!evbs.empty());
  MVCHECK_LE(
      evbs.size(),
      std::numeric_limits<uint16_t>::max(),
      "Quic Server does not support more than "
          << std::numeric_limits<uint16_t>::max() << " workers");
  MVCHECK(shutdown_);
  shutdown_ = false;

  // it the connid algo factory is not set, use default impl
  if (!connIdAlgoFactory_) {
    connIdAlgoFactory_ = std::make_unique<DefaultConnectionIdAlgoFactory>();
  }

  if (!ccFactory_) {
    ccFactory_ = std::make_shared<ServerCongestionControllerFactory>();
  }

  workerEvbs_.swap(evbs);

  initializeWorkers(useDefaultTransport);
  bindWorkersToSocket(address);
}

void QuicServer::initializeWorkers(bool useDefaultTransport) {
  MVVLOG(4) << "Initializing workers";
  MVCHECK(workers_.empty());
  // iterate in the order of insertion in vector
  auto workerEvbs = workerEvbs_.rlock();
  runState_.peers.clear();
  runState_.peers.reserve(workerEvbs->size());
  for (size_t i = 0; i < workerEvbs->size(); ++i) {
    runState_.peers.push_back(
        WorkerEndpoint{
            .evb = (*workerEvbs)[i]->getEventBase(),
            .target = std::make_shared<DispatchTarget>()});
  }
  for (size_t i = 0; i < workerEvbs->size(); ++i) {
    auto worker = newWorkerWithoutSocket(i);
    if (useDefaultTransport) {
      MVCHECK(transportFactory_, "Transport factory is not set");
      worker->setTransportFactory(transportFactory_.get());
      worker->setFizzContext(ctx_);
    }
    worker->setWorkerId(i);
    workers_.push_back(std::move(worker));
    evbToWorkers_.emplace(
        (*workerEvbs)[i]->getEventBase(), workers_.back().get());
  }
}

std::unique_ptr<QuicServerWorker> QuicServer::newWorkerWithoutSocket(
    size_t workerIndex) {
  auto worker = std::make_unique<QuicServerWorker>(
      &runState_, workerIndex, transportSettings_);
  worker->setNewConnectionSocketFactory(socketFactory_.get());
  worker->setSupportedVersions(supportedVersions_);
  worker->rejectNewConnections(rejectNewConnections_);
  worker->setPrimingEnabledCallback(isPrimingEnabled_);
  worker->setIsBlockListedSrcPort(isBlockListedSrcPort_);
  worker->setProcessId(processId_);
  worker->setHostId(hostId_);
  worker->setConnectionIdVersion(cidVersion_);
  if (healthCheckToken_) {
    worker->setHealthCheckToken(*healthCheckToken_);
  }
  if (transportStatsFactory_) {
    auto statsCallback = transportStatsFactory_->make();
    MVCHECK(statsCallback);
    worker->setTransportStatsCallback(std::move(statsCallback));
  }
  worker->setConnectionIdAlgo(connIdAlgoFactory_->make());
  worker->setCongestionControllerFactory(ccFactory_);
  worker->setBatchWriterFactoryOverride(batchWriterFactoryOverride_);
  if (rateLimit_) {
    worker->setRateLimiter(
        std::make_unique<SlidingWindowRateLimiter>(
            rateLimit_->count, rateLimit_->window));
  }
  worker->setUnfinishedHandshakeLimit(unfinishedHandshakeLimitFn_);
  worker->setTransportSettingsOverrideFn(transportSettingsOverrideFn_);
  worker->setShouldRegisterKnobParamHandlerFn(
      shouldRegisterKnobParamHandlerFn_);
  worker->setQuicExperimentHandlerFn(quicExperimentHandlerFn_);
  return worker;
}

void QuicServer::bindWorkersToSocket(const quic::SocketAddress& address) {
  auto workerEvbs = workerEvbs_.rlock();
  auto numWorkers = workerEvbs->size();
  MVCHECK(!initialized_);
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
          MVCHECK(it != self->evbToWorkers_.end());
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
            MVVLOG(4) << "Set up dup()'ed fd for address="
                      << self->boundAddress_
                      << " on workerId=" << (int)worker->getWorkerId();
            worker->applyAllSocketOptions();
          } else {
            MVVLOG(4) << "No valid takenover fd found for address="
                      << self->boundAddress_ << ". binding on worker=" << worker
                      << " workerId=" << (int)worker->getWorkerId()
                      << " processId=" << (int)processId;
            worker->setSocket(std::move(workerSocket));
            worker->bind(self->boundAddress_, self->bindOptions_);
            if (idx == 0) {
              self->boundAddress_ = worker->getAddress();
            }
          }
          self->runState_.peers[idx].target->worker = worker;
          if (idx == (numWorkers - 1)) {
            MVVLOG(4) << "Initialized all workers in the eventbase";
            self->initialized_ = true;
            folly::call_once(
                self->startDone_, [self]() { self->startDoneBaton_.post(); });
          }
        });
  }
}

void QuicServer::start() {
  checkRunningInThread(mainThreadId_);
  MVCHECK(initialized_, kQuicServerNotInitialized << __func__);
  for (auto& worker : workers_) {
    worker->getEventBase()->runInEventBaseThread(
        [&worker] { worker->start(); });
  }
}

quic::Expected<void, QuicError> QuicServer::enableZeroCopy() {
  checkRunningInThread(mainThreadId_);
  if (workers_.empty()) {
    return quic::make_unexpected(QuicError(
        QuicErrorCode(TransportErrorCode::INTERNAL_ERROR),
        "QuicServer::enableZeroCopy called before workers initialized"));
  }
  Optional<QuicError> firstError;
  for (auto& worker : workers_) {
    worker->getEventBase()->runImmediatelyOrRunInEventBaseThreadAndWait(
        [&worker, &firstError]() mutable {
          auto result = worker->enableZeroCopy();
          if (result.hasError() && !firstError.has_value()) {
            firstError = result.error();
          }
        });
  }
  if (firstError.has_value()) {
    return quic::make_unexpected(*firstError);
  }
  return {};
}

void QuicServer::allowBeingTakenOver(const quic::SocketAddress& addr) {
  // synchronously bind workers to takeover handler port.
  // This method should not be called from a worker
  checkRunningInThread(mainThreadId_);
  MVCHECK(!workers_.empty());
  MVCHECK(!shutdown_);

  // this function shouldn't be called from worker's thread
  for ([[maybe_unused]] auto& worker : workers_) {
    MVDCHECK(
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
      MVCHECK(initialized_);
      auto localListenSocket = listenerSocketFactory_->make(workerEvb, -1);
      auto it = evbToWorkers_.find(workerEvb);
      MVCHECK(it != evbToWorkers_.end());
      auto worker = it->second;
      worker->allowBeingTakenOver(std::move(localListenSocket), addr);
    });
  }
  MVVLOG(4) << "Bind all workers in the eventbase to takeover handler port";
  takeoverHandlerInitialized_ = true;
}

quic::SocketAddress QuicServer::overrideTakeoverHandlerAddress(
    const quic::SocketAddress& addr) {
  checkRunningInThread(mainThreadId_);
  // synchronously bind workers to takeover handler port.
  // This method should not be called from a worker
  MVCHECK(!workers_.empty());
  MVCHECK(!shutdown_);
  MVCHECK(takeoverHandlerInitialized_, "TakeoverHanders are not initialized. ");

  // this function shouldn't be called from worker's thread
  for ([[maybe_unused]] auto& worker : workers_) {
    MVDCHECK(
        // if the eventbase is not running, it returns true for isInEvbThread()
        !worker->getEventBase()->isRunning() ||
        !worker->getEventBase()->isInEventBaseThread());
  }
  quic::SocketAddress boundAddress;
  for (auto& worker : workers_) {
    worker->getEventBase()->runInEventBaseThreadAndWait([&] {
      std::lock_guard<std::mutex> guard(startMutex_);
      MVCHECK(initialized_);
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

void QuicServer::requestShutdown(LocalErrorCode error) {
  runState_.requestStop(error);
}

QuicServerWorker* FOLLY_NULLABLE
QuicServer::findWorkerForEvb(folly::EventBase* evb) {
  for (auto& worker : workers_) {
    if (worker->getEventBase() == evb) {
      return worker.get();
    }
  }
  return nullptr;
}

void QuicServer::waitUntilInitialized() {
  if (shutdown_ || initialized_) {
    return;
  }
  for (auto& worker : workers_) {
    MVCHECK(!worker->getEventBase()->isInEventBaseThread());
  }
  // block until all workers have been initialized or shutdown completed
  startDoneBaton_.wait();
  MVCHECK(initialized_ || shutdown_);
}

QuicServer::~QuicServer() {
  shutdown(LocalErrorCode::SHUTTING_DOWN);
}

void QuicServer::shutdown(LocalErrorCode error) {
  if (shutdown_) {
    return;
  }
  runState_.latchStop(error);
  shutdown_ = true;
  auto reason = runState_.latchedStopReason(error);
  for (auto& worker : workers_) {
    worker->getEventBase()->runImmediatelyOrRunInEventBaseThreadAndWait(
        [&] { worker->stopLocal(reason); });
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
  // TODO(damlaj): T205141168; lift commmented checkRunningInThread check below
  // checkRunningInThread(mainThreadId_);
  if (hostId_ == hostId) {
    MVLOG_WARNING << "HostId is already set to " << hostId;
    return;
  }
  hostId_ = hostId;
  MVVLOG(4) << "Setting hostId to " << hostId_ << " for quic server ";
  if (initialized_) {
    runOnAllWorkersSync(
        [hostId](auto worker) mutable { worker->setHostId(hostId); });
  }
}

void QuicServer::setConnectionIdVersion(
    ConnectionIdVersion cidVersion) noexcept {
  checkRunningInThread(mainThreadId_);
  MVCHECK(!initialized_, kQuicServerNotInitialized << __func__);
  if (FLAGS_qs_conn_id_version) {
    MVLOG_ERROR << "Connection Id Version has been set to " << (int)cidVersion_
                << " by --qs_conn_id_version from the command line.";
  } else {
    cidVersion_ = cidVersion;
  }
}

void QuicServer::setTransportSettingsOverrideFn(
    TransportSettingsOverrideFn fn) {
  checkRunningInThread(mainThreadId_);
  MVCHECK(!initialized_, kQuicServerNotInitialized << __func__);
  transportSettingsOverrideFn_ = std::move(fn);
}

void QuicServer::setShouldRegisterKnobParamHandlerFn(
    ShouldRegisterKnobParamHandlerFn fn) {
  checkRunningInThread(mainThreadId_);
  MVCHECK(!initialized_, kQuicServerNotInitialized << __func__);
  shouldRegisterKnobParamHandlerFn_ = std::move(fn);
}

void QuicServer::setQuicExperimentHandlerFn(QuicExperimentHandlerFn fn) {
  checkRunningInThread(mainThreadId_);
  MVCHECK(!initialized_, kQuicServerNotInitialized << __func__);
  quicExperimentHandlerFn_ = std::move(fn);
}

void QuicServer::setHealthCheckToken(const std::string& healthCheckToken) {
  checkRunningInThread(mainThreadId_);
  validateHealthCheckToken(healthCheckToken);
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
  MVCHECK(evb);
  MVCHECK(ctx);
  evb->runImmediatelyOrRunInEventBaseThreadAndWait([&] {
    std::lock_guard<std::mutex> guard(startMutex_);
    if (shutdown_) {
      return;
    }
    auto it = evbToWorkers_.find(evb);
    MVCHECK(it != evbToWorkers_.end());
    it->second->setFizzContext(ctx);
  });
}

const TransportSettings& QuicServer::getTransportSettings() const noexcept {
  return transportSettings_;
}

void QuicServer::rejectNewConnections(
    std::function<bool(const quic::SocketAddress&)> rejectFn) {
  rejectNewConnections_ = rejectFn;
  runOnAllWorkers([rejectFn](auto worker) mutable {
    worker->rejectNewConnections(rejectFn);
  });
}

void QuicServer::setPrimingEnabledCallback(
    std::function<bool()> isPrimingEnabled) {
  isPrimingEnabled_ = isPrimingEnabled;
  runOnAllWorkers([isPrimingEnabled](auto worker) mutable {
    worker->setPrimingEnabledCallback(isPrimingEnabled);
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

void QuicServer::startPacketForwarding(const quic::SocketAddress& destAddr) {
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
  MVCHECK(statsFactory);
  transportStatsFactory_ = std::move(statsFactory);
}

void QuicServer::setConnectionIdAlgoFactory(
    std::unique_ptr<ConnectionIdAlgoFactory> connIdAlgoFactory) {
  checkRunningInThread(mainThreadId_);
  MVCHECK(!initialized_);
  MVCHECK(connIdAlgoFactory);
  connIdAlgoFactory_ = std::move(connIdAlgoFactory);
}

void QuicServer::addTransportFactory(
    folly::EventBase* evb,
    QuicServerTransportFactory* acceptor) {
  MVCHECK(evb);
  MVCHECK(acceptor);
  evb->runImmediatelyOrRunInEventBaseThreadAndWait([&] {
    std::lock_guard<std::mutex> guard(startMutex_);
    if (shutdown_) {
      return;
    }
    auto it = evbToWorkers_.find(evb);
    if (it != evbToWorkers_.end()) {
      it->second->setTransportFactory(acceptor);
    } else {
      MVVLOG(3) << "Couldn't find associated worker for the given eventbase";
    }
  });
}

const quic::SocketAddress& QuicServer::getAddress() const {
  MVCHECK(initialized_, kQuicServerNotInitialized << __func__);
  return boundAddress_;
}

void QuicServer::setListeningFDs(const std::vector<int>& fds) {
  checkRunningInThread(mainThreadId_);
  std::lock_guard<std::mutex> guard(startMutex_);
  listeningFDs_ = fds;
}

int QuicServer::getListeningSocketFD() const {
  MVCHECK(initialized_, kQuicServerNotInitialized << __func__);
  return workers_[0]->getFD();
}

std::vector<int> QuicServer::getAllListeningSocketFDs() const noexcept {
  checkRunningInThread(mainThreadId_);
  MVCHECK(initialized_, kQuicServerNotInitialized << __func__);
  std::vector<int> sockets(workers_.size());
  for (const auto& worker : workers_) {
    if (worker->getFD() != -1) {
      MVCHECK_LT(worker->getWorkerId(), workers_.size());
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
  MVCHECK(takeoverHandlerInitialized_, "TakeoverHanders are not initialized. ");
  return workers_[0]->getTakeoverHandlerSocketFD();
}

std::vector<folly::EventBase*> QuicServer::getWorkerEvbs() const noexcept {
  checkRunningInThread(mainThreadId_);
  MVCHECK(initialized_, kQuicServerNotInitialized << __func__);
  std::vector<folly::EventBase*> ebvs;
  for (const auto& worker : workers_) {
    ebvs.push_back(worker->getEventBase());
  }
  return ebvs;
}

bool QuicServer::addAcceptObserver(
    folly::EventBase* evb,
    AcceptObserver* observer) {
  MVCHECK(initialized_, kQuicServerNotInitialized << __func__);
  MVCHECK(evb);
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
      MVVLOG(3) << "Couldn't find associated worker for the given eventbase, "
                << "unable to add AcceptObserver";
      success = false;
    }
  });
  return success;
}

bool QuicServer::removeAcceptObserver(
    folly::EventBase* evb,
    AcceptObserver* observer) {
  MVCHECK(initialized_, kQuicServerNotInitialized << __func__);
  MVCHECK(evb);
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
      MVVLOG(3) << "Couldn't find associated worker for the given eventbase, "
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

// STATIC
TransportSettings QuicServer::validateTransportSettings(
    TransportSettings transportSettings) {
  // setting default stateless reset token if not set
  if (!transportSettings.statelessResetTokenSecret) {
    std::array<uint8_t, kStatelessResetTokenSecretLength> secret;
    folly::Random::secureRandom(secret.data(), secret.size());
    transportSettings.statelessResetTokenSecret = secret;
  }
  return transportSettings;
}

} // namespace quic
