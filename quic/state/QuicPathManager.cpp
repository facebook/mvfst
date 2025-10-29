/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <quic/state/QuicPathManager.h>
#include <quic/state/StateData.h>

namespace quic {

// The maximum number of paths that can be concurrently tracked by the path
// manager.
constexpr uint32_t kMaxPathCount = 8;

QuicPathManager::QuicPathManager(
    QuicConnectionStateBase& conn,
    PathValidationCallback* callback)
    : conn_(conn), pathValidationCallback_(callback) {
  nextPathId_ = folly::Random::rand32(std::numeric_limits<uint32_t>::max() / 2);
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

  if (pathIdToInfo_.size() >= kMaxPathCount) {
    maybeReapUnusedPaths(/* force= */ true);
    if (pathIdToInfo_.size() >= kMaxPathCount) {
      return quic::make_unexpected(
          QuicError(LocalErrorCode::PATH_MANAGER_ERROR, "Too many paths"));
    }
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

quic::Expected<std::reference_wrapper<const PathInfo>, QuicError>
QuicPathManager::getOrAddPath(
    const folly::SocketAddress& localAddress,
    const folly::SocketAddress& peerAddress) {
  auto it = pathTupleToId_.find({localAddress, peerAddress});
  if (it != pathTupleToId_.end()) {
    return std::cref(*CHECK_NOTNULL(getPath(it->second)));
  }
  auto idRes = addPath(localAddress, peerAddress, nullptr);
  if (idRes.hasError()) {
    return quic::make_unexpected(idRes.error());
  }

  return std::cref(pathIdToInfo_.at(idRes.value()));
}

quic::Expected<PathIdType, QuicError> QuicPathManager::addValidatedPath(
    const folly::SocketAddress& localAddress,
    const folly::SocketAddress& peerAddress) {
  auto idRes = addPath(localAddress, peerAddress, nullptr);
  if (idRes.hasError()) {
    return quic::make_unexpected(idRes.error());
  }

  auto& pathInfo = pathIdToInfo_.at(idRes.value());
  pathInfo.status = PathStatus::Validated;
  pathInfo.pathValidationTime = Clock::now();

  return pathInfo.id;
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

  if (it->second.destinationConnectionId) {
    conn_.retirePeerConnectionId(it->second.destinationConnectionId.value());
  }

  pathTupleToId_.erase({it->second.localAddress, it->second.peerAddress});
  pathIdToInfo_.erase(it);

  // Remove any pending path events
  conn_.pendingEvents.pathChallenges.erase(pathId);
  conn_.pendingEvents.pathResponses.erase(pathId);

  // Remove the path from the pending response list if present
  pathsPendingResponse_.erase(
      std::remove(
          pathsPendingResponse_.begin(), pathsPendingResponse_.end(), pathId),
      pathsPendingResponse_.end());
  conn_.pendingEvents.schedulePathValidationTimeout =
      !pathsPendingResponse_.empty();

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
  it->second.firstChallengeSentTimestamp.reset();
  it->second.lastChallengeSentTimestamp.reset();
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
  if (it != pathIdToInfo_.end() &&
      it->second.outstandingChallengeData.has_value() &&
      it->second.outstandingChallengeData.value() == challengeData) {
    return &it->second;
  } else {
    return nullptr;
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
    VLOG(6) << "Path challenge sent for path=" << path.id << " at "
            << Clock::now().time_since_epoch().count();

    if (path.status != PathStatus::Validated) {
      path.lastChallengeSentTimestamp = Clock::now();

      if (!path.firstChallengeSentTimestamp.has_value()) {
        // This path challenge data has not been sent before. Update the
        // timeout.
        path.firstChallengeSentTimestamp = path.lastChallengeSentTimestamp;

        auto pto = conn_.lossState.srtt +
            std::max(4 * conn_.lossState.rttvar, kGranularity) +
            conn_.lossState.maxAckDelay;
        auto validationTimeout =
            std::max(3 * pto, 6 * conn_.transportSettings.initialRtt);
        auto timeoutMs =
            std::chrono::ceil<std::chrono::milliseconds>(validationTimeout);
        path.pathResponseDeadline =
            *path.firstChallengeSentTimestamp + timeoutMs;

        // The path may already be in the pending response list. Remove it and
        // add it again at the back to maintain the order of the list.
        pathsPendingResponse_.erase(
            std::remove(
                pathsPendingResponse_.begin(),
                pathsPendingResponse_.end(),
                path.id),
            pathsPendingResponse_.end());
        pathsPendingResponse_.emplace_back(path.id);
        path.status = PathStatus::Validating;

        // Signal the transport to schedule the path validation timeout if it's
        // not already scheduled
        conn_.pendingEvents.schedulePathValidationTimeout = true;
      }
    }
  }
}

const PathInfo* QuicPathManager::onPathResponseReceived(
    const PathResponseFrame& pathResponse,
    PathIdType /*incomingPathId*/) {
  auto maybePath = getPathByChallengeDataImpl(pathResponse.pathData);
  if (!maybePath) {
    // We can ignore this path response. This is either:
    // - a duplicate response
    // - a response from a path that was has timed out and failed validation.
    // Note that it's ok to receive a path response on a path other than the one
    // we sent the challenge on. See
    // https://www.rfc-editor.org/rfc/rfc9000.html#section-8.2.2
    return nullptr;
  }
  auto& path = *maybePath;
  if (path.status == PathStatus::Validated) {
    // We've already validated this path. Ignore the duplicate response.
    return nullptr;
  }

  path.status = PathStatus::Validated;
  path.pathValidationTime = Clock::now();

  VLOG(6) << "Path response received for path=" << path.id << " at "
          << path.pathValidationTime->time_since_epoch().count();

  path.rttSample = std::chrono::duration_cast<std::chrono::microseconds>(
      Clock::now() - *path.lastChallengeSentTimestamp);

  path.outstandingChallengeData.reset();
  path.firstChallengeSentTimestamp.reset();
  path.lastChallengeSentTimestamp.reset();
  path.pathResponseDeadline.reset();

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

  return pathInfo->pathResponseDeadline;
}

void QuicPathManager::onPathValidationTimeoutExpired(TimePoint timeNow) {
  VLOG(6) << "Path validation timeout expired";
  auto it = pathsPendingResponse_.begin();
  while (it != pathsPendingResponse_.end()) {
    auto pathId = *it;
    auto pathInfoIt = pathIdToInfo_.find(pathId);
    CHECK(pathInfoIt != pathIdToInfo_.end()) << "Inconsistent path state";
    auto& pathInfo = pathInfoIt->second;

    if (pathInfo.status == PathStatus::Validating) {
      CHECK(pathInfo.pathResponseDeadline.has_value())
          << "Inconsistent path state";

      if (timeNow > *pathInfo.pathResponseDeadline) {
        // The path has timed out and failed validation
        pathInfo.status = PathStatus::NotValid;
        pathInfo.outstandingChallengeData.reset();
        pathInfo.firstChallengeSentTimestamp.reset();
        pathInfo.lastChallengeSentTimestamp.reset();
        pathInfo.pathResponseDeadline.reset();

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

quic::Expected<std::unique_ptr<QuicAsyncUDPSocket>, QuicError>
QuicPathManager::switchCurrentPath(PathIdType switchToPathId) {
  if (switchToPathId == conn_.currentPathId) {
    return {};
  }

  auto it = pathIdToInfo_.find(switchToPathId);
  if (it == pathIdToInfo_.end()) {
    return quic::make_unexpected(QuicError(
        LocalErrorCode::PATH_NOT_EXISTS,
        std::string("Cannot switch to non-existent path id")));
  }
  auto& switchToPath = it->second;

  auto switchFromPathId = conn_.currentPathId;
  conn_.currentPathId = switchToPath.id;
  conn_.localAddress = switchToPath.localAddress;
  conn_.peerAddress = switchToPath.peerAddress;

  if (switchToPath.destinationConnectionId) {
    auto& destinationConnectionId = conn_.nodeType == QuicNodeType::Client
        ? conn_.serverConnectionId
        : conn_.clientConnectionId;
    CHECK(destinationConnectionId)
        << "Connection ID not initialized for active connection";
    // Cache the current destination CID for the path we are switching away
    // from. This will be retired when the path is removed.
    auto setCidRes =
        setDestinationCidForPath(switchFromPathId, *destinationConnectionId);
    CHECK(!setCidRes.hasError()) << setCidRes.error();

    destinationConnectionId = *switchToPath.destinationConnectionId;
    switchToPath.destinationConnectionId.reset();
  }

  return std::move(switchToPath.socket);
}

void QuicPathManager::maybeReapUnusedPaths(bool force) {
  // We only need to maintain the current path and the fallback path when it is
  // set.
  auto shouldReap = conn_.fallbackPathId.has_value() ? pathIdToInfo_.size() > 2
                                                     : pathIdToInfo_.size() > 1;
  if (!shouldReap) {
    return;
  }

  // Find the path with the smallest id that is
  // - not the current path or the fallback path
  // - not pending validation
  // - validated but earlier than maxAge ago
  PathIdType minPathId = nextPathId_;
  for (auto& it : pathIdToInfo_) {
    if (it.first == conn_.currentPathId) {
      continue;
    }
    if (conn_.fallbackPathId && it.first == *conn_.fallbackPathId) {
      continue;
    }
    if (!force &&
        (it.second.status == PathStatus::Validating ||
         it.second.outstandingChallengeData)) {
      // Besides force, the first condition covers the path after the path
      // challenge as been written. The second condition covers the path before
      // the path challenge has been written.
      continue;
    }
    if (!force && it.second.pathValidationTime &&
        (Clock::now() - it.second.pathValidationTime.value()) <
            kTimeToRetainOldPaths) {
      continue;
    }
    if (it.first < minPathId) {
      minPathId = it.first;
    }
  }
  if (minPathId != nextPathId_) {
    // We found a path to reap
    auto removeResult = removePath(minPathId);
    CHECK(!removeResult.hasError()) << removeResult.error();
  }
}

quic::Expected<void, QuicError> QuicPathManager::addSocketToPath(
    PathIdType pathId,
    std::unique_ptr<QuicAsyncUDPSocket> socket) {
  auto it = pathIdToInfo_.find(pathId);
  if (it == pathIdToInfo_.end()) {
    return quic::make_unexpected(QuicError(
        LocalErrorCode::PATH_NOT_EXISTS,
        std::string("Could not add socket for non-existent path id")));
  }
  if (pathId == conn_.currentPathId) {
    return quic::make_unexpected(QuicError(
        LocalErrorCode::PATH_MANAGER_ERROR,
        std::string("Cannot add socket for current connection path")));
  }

  it->second.socket = std::move(socket);
  return {};
}

Expected<void, QuicError> QuicPathManager::assignDestinationCidForPath(
    PathIdType pathId) {
  if (pathId == conn_.currentPathId) {
    return quic::make_unexpected(QuicError(
        LocalErrorCode::PATH_MANAGER_ERROR,
        std::string("Cannot update destination CID for current path")));
  }

  auto it = pathIdToInfo_.find(pathId);
  if (it == pathIdToInfo_.end()) {
    return quic::make_unexpected(QuicError(
        LocalErrorCode::PATH_NOT_EXISTS,
        std::string("Cannot update destination CID for non-existent path id")));
  }
  auto& path = it->second;
  Optional<ConnectionId> cidToRetire;
  if (path.destinationConnectionId) {
    // This path already has a destination CID. Retire it after we assign a new
    // one.
    cidToRetire = *path.destinationConnectionId;
  }

  auto nextCidResult = conn_.getNextAvailablePeerConnectionId();
  if (nextCidResult.hasError()) {
    return quic::make_unexpected(nextCidResult.error());
  }
  path.destinationConnectionId = nextCidResult.value();

  VLOG(4) << "Assigned destination CID=" << *path.destinationConnectionId
          << " for path=" << path.id;

  if (cidToRetire) {
    conn_.retirePeerConnectionId(*cidToRetire);
  }

  return {};
}

Expected<void, QuicError> QuicPathManager::setDestinationCidForPath(
    PathIdType pathId,
    ConnectionId cid) {
  auto it = pathIdToInfo_.find(pathId);
  if (it == pathIdToInfo_.end()) {
    return quic::make_unexpected(QuicError(
        LocalErrorCode::PATH_NOT_EXISTS,
        std::string("Cannot update destination CID for non-existent path id")));
  }
  auto& path = it->second;
  if (path.destinationConnectionId &&
      path.destinationConnectionId.value() != cid) {
    // This path already has a different destination CID. Retire it as we set
    // the new one.
    conn_.retirePeerConnectionId(*path.destinationConnectionId);
  }

  path.destinationConnectionId = cid;

  return {};
}

} // namespace quic
