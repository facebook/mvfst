/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <quic/state/QuicPathManager.h>
#include <quic/state/StateData.h>

namespace quic {

// The maximum number of paths that can be tracked by the path manager.
constexpr uint32_t kMaxPathCount = 256;

QuicPathManager::QuicPathManager(
    QuicConnectionStateBase& conn,
    PathValidationCallback* callback)
    : conn_(conn), pathValidationCallback_(callback) {
  nextPathId_ = folly::Random::rand32(
      std::numeric_limits<uint32_t>::max() - kMaxPathCount);
}

quic::Expected<PathIdType, QuicError> QuicPathManager::addPath(
    const folly::SocketAddress& localAddress,
    const folly::SocketAddress& peerAddress,
    std::unique_ptr<QuicAsyncUDPSocket> socket) {
  auto it = pathTupleToId_.find({localAddress, peerAddress});
  if (it != pathTupleToId_.end()) {
    return quic::make_unexpected(
        QuicError(LocalErrorCode::PATH_MANAGER_ERROR, "Path already exists"));
  }

  PathIdType id = generatePathId();
  pathTupleToId_[{localAddress, peerAddress}] = id;

  pathIdToInfo_.emplace(
      std::piecewise_construct,
      std::forward_as_tuple(id),
      std::forward_as_tuple(
          id,
          localAddress,
          peerAddress,
          std::move(socket),
          PathStatus::NotValid));

  return id;
}

const PathInfo& QuicPathManager::getOrAddPath(
    const folly::SocketAddress& localAddress,
    const folly::SocketAddress& peerAddress) {
  auto it = pathTupleToId_.find({localAddress, peerAddress});
  if (it != pathTupleToId_.end()) {
    return *CHECK_NOTNULL(getPath(it->second));
  }
  PathIdType id = generatePathId();
  pathTupleToId_[{localAddress, peerAddress}] = id;

  pathIdToInfo_.emplace(
      std::piecewise_construct,
      std::forward_as_tuple(id),
      std::forward_as_tuple(
          id,
          localAddress,
          peerAddress,
          nullptr, // Socket
          PathStatus::NotValid));

  return pathIdToInfo_.at(id);
}

quic::Expected<PathIdType, QuicError> QuicPathManager::addValidatedPath(
    const folly::SocketAddress& localAddress,
    const folly::SocketAddress& peerAddress) {
  if (pathTupleToId_.find({localAddress, peerAddress}) !=
      pathTupleToId_.end()) {
    return quic::make_unexpected(
        QuicError(LocalErrorCode::PATH_MANAGER_ERROR, "Path already exists"));
  }

  PathIdType id = generatePathId();
  pathTupleToId_[{localAddress, peerAddress}] = id;

  pathIdToInfo_.emplace(
      std::piecewise_construct,
      std::forward_as_tuple(id),
      std::forward_as_tuple(
          id,
          localAddress,
          peerAddress,
          nullptr, // Socket
          PathStatus::Validated));

  return id;
}

quic::Expected<void, QuicError> QuicPathManager::removePath(PathIdType pathId) {
  if (conn_.currentPathId == pathId) {
    return quic::make_unexpected(QuicError(
        LocalErrorCode::PATH_MANAGER_ERROR, "Cannot remove current path"));
  }
  auto it = pathIdToInfo_.find(pathId);
  if (it == pathIdToInfo_.end()) {
    return quic::make_unexpected(
        QuicError(LocalErrorCode::PATH_MANAGER_ERROR, "Path not found"));
  }

  if (it->second.socket) {
    it->second.socket->pauseRead();
  }

  pathTupleToId_.erase({it->second.localAddress, it->second.peerAddress});
  pathIdToInfo_.erase(it);
  return {};
}

const PathInfo* QuicPathManager::getPath(PathIdType pathId) const {
  auto it = pathIdToInfo_.find(pathId);
  if (it == pathIdToInfo_.end()) {
    return nullptr;
  }
  return &it->second;
}

const PathInfo* QuicPathManager::getPath(
    const folly::SocketAddress& localAddress,
    const folly::SocketAddress& peerAddress) {
  auto it = pathTupleToId_.find({localAddress, peerAddress});
  if (it == pathTupleToId_.end()) {
    return nullptr;
  }
  return CHECK_NOTNULL(getPath(it->second));
}

Expected<uint64_t, QuicError> QuicPathManager::getNewPathChallengeData(
    PathIdType pathId) {
  auto it = pathIdToInfo_.find(pathId);
  if (it == pathIdToInfo_.end()) {
    return quic::make_unexpected(QuicError(
        LocalErrorCode::PATH_NOT_EXISTS,
        std::string(
            "Could not generate path challenge data for non-existent path id")));
  }

  // Higher 32 bits are path id, lower 32 bits are random
  uint64_t challengeData =
      (static_cast<uint64_t>(pathId) << 32) + folly::Random::rand32();

  it->second.outstandingChallengeData = challengeData;
  return challengeData;
}

const PathInfo* QuicPathManager::getPathByChallengeData(
    uint64_t challengeData) {
  return getPathByChallengeDataImpl(challengeData);
}

PathInfo* QuicPathManager::getPathByChallengeDataImpl(uint64_t challengeData) {
  // Higher 32 bits are path id, lower 32 bits are random
  auto pathId = static_cast<uint32_t>(challengeData >> 32);
  auto it = pathIdToInfo_.find(pathId);
  if (it == pathIdToInfo_.end()) {
    return nullptr;
  } else {
    return &it->second;
  }
}

PathIdType QuicPathManager::generatePathId() {
  return nextPathId_++;
}

void QuicPathManager::onPathChallengeSent(
    const PathChallengeFrame& pathChallenge) {
  auto maybePath = getPathByChallengeDataImpl(pathChallenge.pathData);
  if (maybePath) {
    auto& path = *maybePath;
    conn_.pendingEvents.pathChallenges.erase(path.id);

    if (path.status != PathStatus::Validated) {
      path.lastChallengeSentTimestamp = Clock::now();
      VLOG(6) << "Path challenge sent for path=" << path.id << " at "
              << path.lastChallengeSentTimestamp->time_since_epoch().count();

      auto pto = conn_.lossState.srtt +
          std::max(4 * conn_.lossState.rttvar, kGranularity) +
          conn_.lossState.maxAckDelay;
      auto validationTimeout =
          std::max(3 * pto, 6 * conn_.transportSettings.initialRtt);
      auto timeoutMs =
          std::chrono::ceil<std::chrono::milliseconds>(validationTimeout);
      path.pathResponeDeadline = *path.lastChallengeSentTimestamp + timeoutMs;

      if (path.status == PathStatus::Validating &&
          pathsPendingResponse_.size() > 1) {
        // The path is already in the pending response list and there are other
        // paths in the list, remove it and add it again at the back to maintain
        // the order of the list.
        pathsPendingResponse_.erase(
            std::remove(
                pathsPendingResponse_.begin(),
                pathsPendingResponse_.end(),
                path.id),
            pathsPendingResponse_.end());
      }
      pathsPendingResponse_.emplace_back(path.id);

      path.status = PathStatus::Validating;

      // Signal the transport to schedule the path validation timeout if it's
      // not already scheduled
      conn_.pendingEvents.schedulePathValidationTimeout = true;
    }
  }
}

const PathInfo* QuicPathManager::onPathResponseReceived(
    const PathResponseFrame& pathResponse) {
  auto maybePath = getPathByChallengeDataImpl(pathResponse.pathData);
  if (!maybePath) {
    // This is either a stale response or a response from a path that was has
    // timed out and failed validation. Either way, we can ignore it.
    return nullptr;
  }
  auto& path = *maybePath;
  CHECK(path.status == PathStatus::Validating) << "Inconsistent path state";
  CHECK(path.lastChallengeSentTimestamp.has_value())
      << "Inconsistent path state. Missing last challenge sent timestamp";

  path.status = PathStatus::Validated;

  VLOG(6) << "Path response received for path=" << path.id << " at "
          << Clock::now().time_since_epoch().count();

  path.rttSample = std::chrono::duration_cast<std::chrono::microseconds>(
      Clock::now() - *path.lastChallengeSentTimestamp);

  path.outstandingChallengeData.reset();
  path.lastChallengeSentTimestamp.reset();
  path.pathResponeDeadline.reset();

  // Remove the path from the pending response list
  pathsPendingResponse_.erase(
      std::remove(
          pathsPendingResponse_.begin(), pathsPendingResponse_.end(), path.id),
      pathsPendingResponse_.end());

  // TODO: JBESHAY MIGRATION - Update qlog events to be path
  // specific

  if (conn_.qLogger) {
    conn_.qLogger->addPathValidationEvent(true);
  }

  if (pathValidationCallback_) {
    pathValidationCallback_->onPathValidationResult(path);
  }

  conn_.pendingEvents.schedulePathValidationTimeout =
      !pathsPendingResponse_.empty();

  VLOG(6) << "Path validated with RTT=" << path.rttSample.value().count()
          << " pending response count=" << pathsPendingResponse_.size();

  return maybePath;
}

Optional<TimePoint> QuicPathManager::getEarliestChallengeTimeout() const {
  if (pathsPendingResponse_.empty()) {
    return std::nullopt;
  }
  auto pathInfo = getPath(pathsPendingResponse_.front());
  CHECK(pathInfo) << "Inconsistent path state";

  return pathInfo->pathResponeDeadline;
}

void QuicPathManager::onPathValidationTimeoutExpired() {
  VLOG(6) << "Path validation timeout expired";
  auto it = pathsPendingResponse_.begin();
  auto timeNow = Clock::now();
  while (it != pathsPendingResponse_.end()) {
    auto pathId = *it;
    auto pathInfoIt = pathIdToInfo_.find(pathId);
    CHECK(pathInfoIt != pathIdToInfo_.end()) << "Inconsistent path state";
    auto& pathInfo = pathInfoIt->second;

    if (pathInfo.status == PathStatus::Validating) {
      CHECK(pathInfo.pathResponeDeadline.has_value())
          << "Inconsistent path state";

      if (timeNow > *pathInfo.pathResponeDeadline) {
        // The path has timed out and failed validation
        pathInfo.status = PathStatus::NotValid;
        pathInfo.outstandingChallengeData.reset();
        pathInfo.lastChallengeSentTimestamp.reset();
        pathInfo.pathResponeDeadline.reset();

        // TODO: JBESHAY MIGRATION - We will probably need some callback to
        // comunicate this back to the transport, at least for the client.

        // Remove the path from the pending
        it = pathsPendingResponse_.erase(it);

        if (conn_.qLogger) {
          conn_.qLogger->addPathValidationEvent(false);
        }

        if (pathValidationCallback_) {
          pathValidationCallback_->onPathValidationResult(pathInfo);
        }
      } else {
        it++;
      }
    } else {
      it++;
    }
  }

  conn_.pendingEvents.schedulePathValidationTimeout =
      !pathsPendingResponse_.empty();
}

void QuicPathManager::setPathValidationCallback(
    PathValidationCallback* callback) {
  pathValidationCallback_ = callback;
}

void QuicPathManager::cacheCurrentCongestionAndRttState() {
  auto pathInfo = pathIdToInfo_.find(conn_.currentPathId);
  CHECK(pathInfo != pathIdToInfo_.end()) << "Inconsistent path state";

  CachedCongestionControlAndRtt state;
  state.recordTime = Clock::now();
  state.congestionController = std::move(conn_.congestionController);
  state.srtt = conn_.lossState.srtt;
  state.lrtt = conn_.lossState.lrtt;
  state.rttvar = conn_.lossState.rttvar;
  state.mrtt = conn_.lossState.mrtt;

  pathInfo->second.cachedCCAndRttState = std::move(state);
}

bool QuicPathManager::maybeRestoreCongestionControlAndRttStateForCurrentPath() {
  auto pathInfoIt = pathIdToInfo_.find(conn_.currentPathId);
  CHECK(pathInfoIt != pathIdToInfo_.end()) << "Inconsistent path state";
  auto& pathInfo = pathInfoIt->second;
  auto& cachedState = pathInfo.cachedCCAndRttState;
  bool ccaRestored = false;
  if (pathInfo.status == PathStatus::Validated && cachedState.has_value() &&
      (Clock::now() - cachedState->recordTime <=
       kTimeToRetainLastCongestionAndRttState)) {
    // The path is validated, it has a cached state, and it is not stale.
    // Restore that state
    conn_.congestionController = std::move(cachedState->congestionController);
    ccaRestored = true;

    conn_.lossState.srtt = cachedState->srtt;
    conn_.lossState.lrtt = cachedState->lrtt;
    conn_.lossState.rttvar = cachedState->rttvar;
    conn_.lossState.mrtt = cachedState->mrtt;
    VLOG(6) << "Recovered cached state for path " << pathInfo.id << " for peer "
            << pathInfo.peerAddress.describe();
  } else {
    // No valid state to restore.
    if (pathInfo.rttSample) {
      // We have a valid RTT sample. Use it to initialize the RTT state.
      auto rttSample = pathInfo.rttSample.value();
      conn_.lossState.srtt = rttSample;
      conn_.lossState.lrtt = rttSample;
      conn_.lossState.rttvar = 0us;
      conn_.lossState.mrtt = rttSample;
    } else {
      // We have nothing. Just reset everything.
      conn_.lossState.srtt = 0us;
      conn_.lossState.lrtt = 0us;
      conn_.lossState.rttvar = 0us;
      conn_.lossState.mrtt = kDefaultMinRtt;
    }
  }

  // Reset the cached state. If it was there, we either used or it's stale
  cachedState.reset();
  return ccaRestored;
}

void QuicPathManager::onPathPacketSent(
    PathIdType pathId,
    uint16_t encodedPacketSize) {
  auto pathInfoIt = pathIdToInfo_.find(pathId);
  if (pathInfoIt != pathIdToInfo_.end() &&
      pathInfoIt->second.status != PathStatus::Validated) {
    // We are on an unvalidated path, we need to track what we write
    if (pathInfoIt->second.writableBytes > encodedPacketSize) {
      pathInfoIt->second.writableBytes -= encodedPacketSize;
    } else {
      pathInfoIt->second.writableBytes = 0;
    }
  }
}

void QuicPathManager::onPathPacketReceived(PathIdType pathId) {
  auto pathInfoIt = pathIdToInfo_.find(pathId);
  if (pathInfoIt != pathIdToInfo_.end() &&
      pathInfoIt->second.status != PathStatus::Validated) {
    // We are reading from an unvalidated path. Every incoming packet gives us
    // credit for writing more packets (as many as limitedCwndInMss)
    if (pathInfoIt->second.writableBytes <
        kDefaultMaxCwndInMss * conn_.udpSendPacketLen) {
      pathInfoIt->second.writableBytes +=
          (conn_.transportSettings.limitedCwndInMss * conn_.udpSendPacketLen);
    }
  }
}

void QuicPathManager::dropAllSockets() {
  for (auto& kv : pathIdToInfo_) {
    kv.second.socket.reset();
  }
}

} // namespace quic
