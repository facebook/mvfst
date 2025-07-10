/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <quic/logging/QLogger.h>
#include <quic/priority/HTTPPriorityQueue.h>
#include <quic/state/QuicPriorityQueue.h>
#include <quic/state/QuicStreamManager.h>
#include <quic/state/QuicStreamUtilities.h>
#include <quic/state/QuicTransportStatsCallback.h>
#include <quic/state/StateData.h>

namespace quic {

/**
 * Updates the head of line blocked time for the stream. This should be called
 * on new data received or even data being read from the stream.
 * There are 2 cases when you can become head of line blocked:
 * 1. You're not previously holb. You receive new data which cannot be read.
 * 2. You are not head of line blocked. You read data from the stream, but you
 *    discover a hole.
 *
 * You can become not head of line blocked if the following conditions happen:
 * 1. You were head of line blocked, and you receive something that allows you
 *    to read from the stream.
 * 2. You were head of line blocked, but you receive a reset from the peer.
 */
static void updateHolBlockedTime(QuicStreamState& stream) {
  if (stream.readBuffer.empty() ||
      (stream.currentReadOffset == stream.readBuffer.front().offset)) {
    if (stream.lastHolbTime) {
      stream.totalHolbTime +=
          std::chrono::duration_cast<std::chrono::microseconds>(
              Clock::now() - *stream.lastHolbTime);
      stream.lastHolbTime.reset();
    }
    return;
  }

  if (stream.lastHolbTime) {
    return;
  }
  stream.lastHolbTime = Clock::now();
  stream.holbCount++;
}

static bool isStreamUnopened(
    StreamId streamId,
    StreamId nextAcceptableStreamId) {
  return streamId >= nextAcceptableStreamId;
}

// If a stream is un-opened, these automatically creates all lower streams.
// Returns false if the stream is closed or already opened.
static LocalErrorCode openPeerStreamIfNotClosed(
    StreamId streamId,
    StreamIdSet& openStreams,
    StreamId& nextAcceptableStreamId,
    StreamId maxStreamId,
    std::vector<StreamId>* newStreams) {
  if (streamId < nextAcceptableStreamId) {
    return LocalErrorCode::CREATING_EXISTING_STREAM;
  }
  if (streamId >= maxStreamId) {
    return LocalErrorCode::STREAM_LIMIT_EXCEEDED;
  }

  StreamId start = nextAcceptableStreamId;
  auto numNewStreams = (streamId - start) / detail::kStreamIncrement;
  if (newStreams) {
    newStreams->reserve(newStreams->size() + numNewStreams);
  }
  openStreams.add(start, streamId);
  while (start <= streamId) {
    if (newStreams) {
      newStreams->push_back(start);
    }
    start += detail::kStreamIncrement;
  }

  if (streamId >= nextAcceptableStreamId) {
    nextAcceptableStreamId = streamId + detail::kStreamIncrement;
  }
  return LocalErrorCode::NO_ERROR;
}

static LocalErrorCode openLocalStreamIfNotClosed(
    StreamId streamId,
    StreamIdSet& openStreams,
    StreamId& nextAcceptableStreamId,
    StreamId maxStreamId) {
  if (streamId < nextAcceptableStreamId) {
    return LocalErrorCode::CREATING_EXISTING_STREAM;
  }
  if (streamId >= maxStreamId) {
    return LocalErrorCode::STREAM_LIMIT_EXCEEDED;
  }

  openStreams.add(nextAcceptableStreamId, streamId);
  if (streamId >= nextAcceptableStreamId) {
    nextAcceptableStreamId = streamId + detail::kStreamIncrement;
  }
  return LocalErrorCode::NO_ERROR;
}

void QuicStreamManager::setWriteQueueMaxNextsPerStream(
    uint64_t maxNextsPerStream) {
  if (oldWriteQueue_) {
    oldWriteQueue_->setMaxNextsPerStream(maxNextsPerStream);
  }
  dynamic_cast<HTTPPriorityQueue&>(writeQueue())
      .advanceAfterNext(maxNextsPerStream);
}

bool QuicStreamManager::streamExists(StreamId streamId) {
  if (isLocalStream(nodeType_, streamId)) {
    if (isUnidirectionalStream(streamId)) {
      return openUnidirectionalLocalStreams_.contains(streamId);
    } else {
      return openBidirectionalLocalStreams_.contains(streamId);
    }
  } else {
    if (isUnidirectionalStream(streamId)) {
      return openUnidirectionalPeerStreams_.contains(streamId);
    } else {
      return openBidirectionalPeerStreams_.contains(streamId);
    }
  }
}

QuicStreamState* QuicStreamManager::findStream(StreamId streamId) {
  auto lookup = streams_.find(streamId);
  if (lookup == streams_.end()) {
    return nullptr;
  } else {
    return &lookup->second;
  }
}

quic::Expected<void, QuicError>
QuicStreamManager::setMaxLocalBidirectionalStreams(
    uint64_t maxStreams,
    bool force) {
  if (maxStreams > kMaxMaxStreams) {
    return quic::make_unexpected(QuicError(
        TransportErrorCode::STREAM_LIMIT_ERROR,
        "Attempt to set maxStreams beyond the max allowed."));
  }
  StreamId maxStreamId = maxStreams * detail::kStreamIncrement +
      initialLocalBidirectionalStreamId_;
  if (force || maxStreamId > maxLocalBidirectionalStreamId_) {
    maxLocalBidirectionalStreamId_ = maxStreamId;
    maxLocalBidirectionalStreamIdIncreased_ = true;
  }
  return {};
}

quic::Expected<void, QuicError>
QuicStreamManager::setMaxLocalUnidirectionalStreams(
    uint64_t maxStreams,
    bool force) {
  if (maxStreams > kMaxMaxStreams) {
    return quic::make_unexpected(QuicError(
        TransportErrorCode::STREAM_LIMIT_ERROR,
        "Attempt to set maxStreams beyond the max allowed."));
  }
  StreamId maxStreamId = maxStreams * detail::kStreamIncrement +
      initialLocalUnidirectionalStreamId_;
  if (force || maxStreamId > maxLocalUnidirectionalStreamId_) {
    maxLocalUnidirectionalStreamId_ = maxStreamId;
    maxLocalUnidirectionalStreamIdIncreased_ = true;
  }
  return {};
}

// Public API now returns Expected to propagate internal errors
quic::Expected<void, QuicError>
QuicStreamManager::setMaxRemoteBidirectionalStreams(uint64_t maxStreams) {
  return setMaxRemoteBidirectionalStreamsInternal(maxStreams, false);
}

// Public API now returns Expected to propagate internal errors
quic::Expected<void, QuicError>
QuicStreamManager::setMaxRemoteUnidirectionalStreams(uint64_t maxStreams) {
  return setMaxRemoteUnidirectionalStreamsInternal(maxStreams, false);
}

quic::Expected<void, QuicError>
QuicStreamManager::setMaxRemoteBidirectionalStreamsInternal(
    uint64_t maxStreams,
    bool force) {
  if (maxStreams > kMaxMaxStreams) {
    return quic::make_unexpected(QuicError(
        TransportErrorCode::STREAM_LIMIT_ERROR,
        "Attempt to set maxStreams beyond the max allowed."));
  }
  StreamId maxStreamId = maxStreams * detail::kStreamIncrement +
      initialRemoteBidirectionalStreamId_;
  if (force || maxStreamId > maxRemoteBidirectionalStreamId_) {
    maxRemoteBidirectionalStreamId_ = maxStreamId;
  }
  return {};
}

quic::Expected<void, QuicError>
QuicStreamManager::setMaxRemoteUnidirectionalStreamsInternal(
    uint64_t maxStreams,
    bool force) {
  if (maxStreams > kMaxMaxStreams) {
    return quic::make_unexpected(QuicError(
        TransportErrorCode::STREAM_LIMIT_ERROR,
        "Attempt to set maxStreams beyond the max allowed."));
  }
  StreamId maxStreamId = maxStreams * detail::kStreamIncrement +
      initialRemoteUnidirectionalStreamId_;
  if (force || maxStreamId > maxRemoteUnidirectionalStreamId_) {
    maxRemoteUnidirectionalStreamId_ = maxStreamId;
  }
  return {};
}

bool QuicStreamManager::consumeMaxLocalBidirectionalStreamIdIncreased() {
  bool res = maxLocalBidirectionalStreamIdIncreased_;
  maxLocalBidirectionalStreamIdIncreased_ = false;
  return res;
}

bool QuicStreamManager::consumeMaxLocalUnidirectionalStreamIdIncreased() {
  bool res = maxLocalUnidirectionalStreamIdIncreased_;
  maxLocalUnidirectionalStreamIdIncreased_ = false;
  return res;
}

quic::Expected<void, LocalErrorCode> QuicStreamManager::setPriorityQueue(
    std::unique_ptr<PriorityQueue> queue) {
  if (oldWriteQueue_) {
    LOG(ERROR) << "Cannot change priority queue when the old queue is in use";
    return quic::make_unexpected(LocalErrorCode::INTERNAL_ERROR);
  }
  if (!writeQueue().empty()) {
    LOG(ERROR) << "Cannot change priority queue when the queue is not empty";
    return quic::make_unexpected(LocalErrorCode::INTERNAL_ERROR);
  }
  writeQueue_ = std::move(queue);
  return {};
}

bool QuicStreamManager::setStreamPriority(
    StreamId id,
    const PriorityQueue::Priority& newPriority,
    bool connFlowControlOpen,
    const std::shared_ptr<QLogger>& qLogger) {
  auto stream = findStream(id);
  if (stream) {
    if (writeQueue().equalPriority(stream->priority, newPriority)) {
      return false;
    }
    stream->priority = newPriority;
    updateWritableStreams(*stream, connFlowControlOpen);
    if (qLogger) {
      qLogger->addPriorityUpdate(
          id, writeQueue().toLogFields(stream->priority));
    }
    return true;
  }
  return false;
}

quic::Expected<void, QuicError> QuicStreamManager::refreshTransportSettings(
    const TransportSettings& settings) {
  transportSettings_ = &settings;
  auto resultBidi = setMaxRemoteBidirectionalStreamsInternal(
      transportSettings_->advertisedInitialMaxStreamsBidi, true);
  if (!resultBidi.has_value()) {
    // Propagate the error
    return quic::make_unexpected(resultBidi.error());
  }
  auto resultUni = setMaxRemoteUnidirectionalStreamsInternal(
      transportSettings_->advertisedInitialMaxStreamsUni, true);
  if (!resultUni.has_value()) {
    // Propagate the error
    return quic::make_unexpected(resultUni.error());
  }

  // TODO: The dependency on HTTPPriorityQueue here seems out of place in
  // the long term
  if (!writeQueue_) {
    writeQueue_ = std::make_unique<HTTPPriorityQueue>();
  }
  return updatePriorityQueueImpl(transportSettings_->useNewPriorityQueue);
}

quic::Expected<void, QuicError> QuicStreamManager::updatePriorityQueueImpl(
    bool useNewPriorityQueue) {
  if (!useNewPriorityQueue && !oldWriteQueue_) {
    if (writeQueue_->empty() && connFlowControlBlocked_.empty()) {
      oldWriteQueue_ = std::make_unique<deprecated::PriorityQueue>();
    } else {
      return quic::make_unexpected(QuicError(
          QuicErrorCode(LocalErrorCode::INTERNAL_ERROR),
          "Cannot change priority queue when the queue is not empty"));
    }
  } else if (useNewPriorityQueue && oldWriteQueue_) {
    if (oldWriteQueue_->empty()) {
      oldWriteQueue_.reset();
    } else {
      return quic::make_unexpected(QuicError(
          QuicErrorCode(LocalErrorCode::INTERNAL_ERROR),
          "Cannot change to new priority queue when the queue is not empty"));
    }
  } // else no change

  return {};
}

quic::Expected<QuicStreamState*, QuicError>
QuicStreamManager::getOrCreateOpenedLocalStream(StreamId streamId) {
  auto& openLocalStreams = isUnidirectionalStream(streamId)
      ? openUnidirectionalLocalStreams_
      : openBidirectionalLocalStreams_;
  if (openLocalStreams.contains(streamId)) {
    auto it = streams_.emplace(
        std::piecewise_construct,
        std::forward_as_tuple(streamId),
        std::forward_as_tuple(streamId, conn_));
    if (!it.second) {
      return quic::make_unexpected(QuicError(
          TransportErrorCode::STREAM_STATE_ERROR, "Creating an active stream"));
    }
    QUIC_STATS(conn_.statsCallback, onNewQuicStream);
    return &it.first->second;
  }
  return nullptr;
}

quic::Expected<QuicStreamState*, QuicError> QuicStreamManager::getStream(
    StreamId streamId,
    OptionalIntegral<StreamGroupId> streamGroupId) {
  if (isRemoteStream(nodeType_, streamId)) {
    auto streamResult =
        getOrCreatePeerStream(streamId, std::move(streamGroupId));
    // If successful (has value, which could be nullptr or a valid ptr), update
    // state.
    if (streamResult.has_value()) {
      updateAppIdleState();
    }
    // Propagate error, or return the contained value (ptr or nullptr)
    return streamResult;
  }

  // Handle local streams
  auto it = streams_.find(streamId);
  if (it != streams_.end()) {
    // Stream state already exists
    updateAppIdleState();
    return &it->second;
  }

  // Try to get/create state for an already opened (but not instantiated) local
  // stream
  auto streamResult = getOrCreateOpenedLocalStream(streamId);
  if (!streamResult.has_value()) {
    // This indicates an internal error during lazy creation
    // Propagate as QuicError
    return quic::make_unexpected(QuicError(
        TransportErrorCode::INTERNAL_ERROR,
        "Failed to create local stream state"));
  }
  auto* stream = streamResult.value(); // Can be nullptr if not in open set

  // Check if the stream is genuinely unopened locally
  auto nextAcceptableStreamId = isUnidirectionalStream(streamId)
      ? nextAcceptableLocalUnidirectionalStreamId_
      : nextAcceptableLocalBidirectionalStreamId_;
  if (!stream && isStreamUnopened(streamId, nextAcceptableStreamId)) {
    // The stream ID is higher than the next acceptable one, meaning it hasn't
    // been opened yet. This was previously a throw -> return error.
    return quic::make_unexpected(QuicError(
        TransportErrorCode::STREAM_STATE_ERROR,
        "Trying to get unopened local stream"));
  }

  // If stream is null here, it means streamId < nextAcceptableStreamId
  // but it wasn't found in the `streams_` map and wasn't lazily created.
  // This implies it was previously closed and removed.
  // Returning nullptr is the correct behavior in this case.

  updateAppIdleState();
  return stream; // Can be nullptr if stream was closed
}

// Note: This function returns LocalErrorCode because it's primarily used
// internally or by APIs that expect local errors for stream creation failures.
// However, the underlying call to createStream returns QuicError, which we must
// handle.
quic::Expected<QuicStreamState*, LocalErrorCode>
QuicStreamManager::createNextBidirectionalStream(
    OptionalIntegral<StreamGroupId> streamGroupId) {
  auto streamResult =
      createStream(nextBidirectionalStreamId_, std::move(streamGroupId));
  if (streamResult.has_value()) {
    nextBidirectionalStreamId_ += detail::kStreamIncrement;
    return streamResult.value();
  } else {
    // createStream failed, map the QuicError to a suitable LocalErrorCode
    // This mapping loses original error detail but fits the expected return
    // type. Callers needing the precise QuicError should call createStream
    // directly.
    auto& error = streamResult.error();
    LOG(WARNING) << "createStream failed: "
                 << error.message; // Log the original error
    if (error.code == TransportErrorCode::STREAM_LIMIT_ERROR) {
      return quic::make_unexpected(LocalErrorCode::STREAM_LIMIT_EXCEEDED);
    } else if (error.code == TransportErrorCode::STREAM_STATE_ERROR) {
      return quic::make_unexpected(
          LocalErrorCode::CREATING_EXISTING_STREAM); // Or other state error?
    } else {
      return quic::make_unexpected(LocalErrorCode::INTERNAL_ERROR);
    }
  }
}

quic::Expected<StreamGroupId, LocalErrorCode>
QuicStreamManager::createNextBidirectionalStreamGroup() {
  return createNextStreamGroup(
      nextBidirectionalStreamGroupId_, openBidirectionalLocalStreamGroups_);
}

// Note: Similar to createNextBidirectionalStream regarding LocalErrorCode
// return.
quic::Expected<QuicStreamState*, LocalErrorCode>
QuicStreamManager::createNextUnidirectionalStream(
    OptionalIntegral<StreamGroupId> streamGroupId) {
  auto streamResult =
      createStream(nextUnidirectionalStreamId_, std::move(streamGroupId));
  if (streamResult.has_value()) {
    nextUnidirectionalStreamId_ += detail::kStreamIncrement;
    return streamResult.value();
  } else {
    // Map QuicError to LocalErrorCode
    auto& error = streamResult.error();
    LOG(WARNING) << "createStream failed: " << error.message;
    if (error.code == TransportErrorCode::STREAM_LIMIT_ERROR) {
      return quic::make_unexpected(LocalErrorCode::STREAM_LIMIT_EXCEEDED);
    } else if (error.code == TransportErrorCode::STREAM_STATE_ERROR) {
      return quic::make_unexpected(LocalErrorCode::CREATING_EXISTING_STREAM);
    } else {
      return quic::make_unexpected(LocalErrorCode::INTERNAL_ERROR);
    }
  }
}

QuicStreamState* FOLLY_NULLABLE QuicStreamManager::instantiatePeerStream(
    StreamId streamId,
    OptionalIntegral<StreamGroupId> groupId) {
  if (groupId) {
    auto& seenSet = isUnidirectionalStream(streamId)
        ? peerUnidirectionalStreamGroupsSeen_
        : peerBidirectionalStreamGroupsSeen_;
    if (!seenSet.contains(*groupId)) {
      newPeerStreamGroups_.insert(*groupId);
      seenSet.add(*groupId);
    }
  }

  if (transportSettings_->notifyOnNewStreamsExplicitly) {
    if (!groupId) {
      newPeerStreams_.push_back(streamId);
    } else {
      newGroupedPeerStreams_.push_back(streamId);
    }
  }
  // Use try_emplace to avoid potential double-check issues if called directly
  auto [it, inserted] =
      streams_.try_emplace(streamId, streamId, groupId, conn_);

  if (!inserted && it->second.groupId != groupId) {
    LOG(ERROR) << "Stream " << streamId
               << " already exists with different group ID";
    return nullptr;
  }

  if (inserted) {
    QUIC_STATS(conn_.statsCallback, onNewQuicStream);
  }
  return &it->second;
}

quic::Expected<StreamGroupId, LocalErrorCode>
QuicStreamManager::createNextUnidirectionalStreamGroup() {
  return createNextStreamGroup(
      nextUnidirectionalStreamGroupId_, openUnidirectionalLocalStreamGroups_);
}

quic::Expected<StreamGroupId, LocalErrorCode>
QuicStreamManager::createNextStreamGroup(
    StreamGroupId& groupId,
    StreamIdSet& streamGroups) {
  auto maxLocalStreamGroupId = std::min(
      transportSettings_->advertisedMaxStreamGroups *
          detail::kStreamGroupIncrement,
      detail::kMaxStreamGroupId);
  if (groupId >= maxLocalStreamGroupId) {
    return quic::make_unexpected(LocalErrorCode::STREAM_LIMIT_EXCEEDED);
  }

  auto id = groupId;
  groupId += detail::kStreamIncrement;
  streamGroups.add(id);

  return id;
}

// Returns QuicError for transport-level issues (limits, state), nullptr if
// closed.
quic::Expected<QuicStreamState*, QuicError>
QuicStreamManager::getOrCreatePeerStream(
    StreamId streamId,
    OptionalIntegral<StreamGroupId> streamGroupId) {
  // Validate stream direction based on node type
  if (nodeType_ == QuicNodeType::Client && isClientStream(streamId)) {
    return quic::make_unexpected(QuicError(
        TransportErrorCode::STREAM_STATE_ERROR,
        "Attempted getting client peer stream on client"));
  } else if (nodeType_ == QuicNodeType::Server && isServerStream(streamId)) {
    return quic::make_unexpected(QuicError(
        TransportErrorCode::STREAM_STATE_ERROR,
        "Attempted getting server peer stream on server"));
  } else if (!isClientStream(streamId) && !isServerStream(streamId)) {
    // Validate stream ID format itself
    return quic::make_unexpected(QuicError(
        TransportErrorCode::STREAM_STATE_ERROR, "Invalid stream ID format"));
  }

  // Validate group properties if group is specified
  if (streamGroupId) {
    if (nodeType_ == QuicNodeType::Client &&
        isClientStreamGroup(*streamGroupId)) {
      return quic::make_unexpected(QuicError(
          TransportErrorCode::STREAM_STATE_ERROR,
          "Received a client stream group id on client"));
    } else if (
        nodeType_ == QuicNodeType::Server &&
        isServerStreamGroup(*streamGroupId)) {
      return quic::make_unexpected(QuicError(
          TransportErrorCode::STREAM_STATE_ERROR,
          "Received a server stream group id on server"));
    }

    // Validate group ID limit (peer perspective)
    auto maxPeerStreamGroupId = std::min(
        conn_.transportSettings
                .advertisedMaxStreamGroups * // Use conn_.transportSettings here
            detail::kStreamGroupIncrement,
        detail::kMaxStreamGroupId);
    if (*streamGroupId >= maxPeerStreamGroupId) {
      // Peer used a group ID we didn't advertise support for
      return quic::make_unexpected(QuicError(
          TransportErrorCode::STREAM_LIMIT_ERROR, // Or
                                                  // FEATURE_NEGOTIATION_ERROR?
                                                  // Limit seems better.
          "Invalid peer stream group id (exceeds limit)"));
    }
  }

  // Check if stream state already exists in the map
  auto peerStreamIt = streams_.find(streamId);
  if (peerStreamIt != streams_.end()) {
    // TODO: Validate streamGroupId if provided matches existing stream's group?
    // If streamGroupId.has_value() && peerStreamIt->second.groupId !=
    // streamGroupId ... return error?
    return &peerStreamIt->second;
  }

  // Check if stream was previously opened (in the StreamIdSet)
  auto& openPeerStreams = isUnidirectionalStream(streamId)
      ? openUnidirectionalPeerStreams_
      : openBidirectionalPeerStreams_;
  if (openPeerStreams.contains(streamId)) {
    // Stream was already open, create the state for it lazily.
    auto* streamPtr = instantiatePeerStream(streamId, streamGroupId);
    if (!streamPtr) {
      // Propagate internal inconsistency as QuicError
      return quic::make_unexpected(QuicError(
          TransportErrorCode::INTERNAL_ERROR,
          "Failed to instantiate known open peer stream"));
    }
    return streamPtr;
  }

  // Stream state doesn't exist and it's not marked as open yet.
  // Try to open it (and streams below it) now.
  auto& nextAcceptableStreamId = isUnidirectionalStream(streamId)
      ? nextAcceptablePeerUnidirectionalStreamId_
      : nextAcceptablePeerBidirectionalStreamId_;
  auto maxStreamId = isUnidirectionalStream(streamId)
      ? maxRemoteUnidirectionalStreamId_
      : maxRemoteBidirectionalStreamId_;

  // Determine where to store newly opened stream IDs for notification
  auto* newPeerStreamsList =
      streamGroupId ? &newGroupedPeerStreams_ : &newPeerStreams_;
  bool notifyExplicitly = transportSettings_->notifyOnNewStreamsExplicitly;

  // openPeerStreamIfNotClosed checks limits and adds to the StreamIdSet
  auto openedResult = openPeerStreamIfNotClosed(
      streamId,
      openPeerStreams,
      nextAcceptableStreamId,
      maxStreamId,
      notifyExplicitly ? nullptr : newPeerStreamsList);

  // Check if the peer exceeded the stream limit
  if (openedResult == LocalErrorCode::STREAM_LIMIT_EXCEEDED) {
    // This was previously a throw -> return error
    return quic::make_unexpected(QuicError(
        TransportErrorCode::STREAM_LIMIT_ERROR, "Peer exceeded stream limit."));
  }

  // Check if stream ID was below nextAcceptable (already seen/closed)
  if (openedResult == LocalErrorCode::CREATING_EXISTING_STREAM) {
    // This means streamId < nextAcceptableStreamId, but it wasn't found in
    // streams_ map and wasn't in openPeerStreams set -> implies it was closed.
    return nullptr; // Correctly indicates a closed stream
  }

  // If we reached here, openedResult must be NO_ERROR.
  DCHECK(openedResult == LocalErrorCode::NO_ERROR);

  // Check if peer saturated the limit *after* opening this stream
  if (nextAcceptableStreamId >= maxStreamId && conn_.statsCallback) {
    auto limitSaturatedFn = isBidirectionalStream(streamId)
        ? &QuicTransportStatsCallback::onPeerMaxBidiStreamsLimitSaturated
        : &QuicTransportStatsCallback::onPeerMaxUniStreamsLimitSaturated;
    folly::invoke(limitSaturatedFn, conn_.statsCallback);
  }

  // Stream(s) successfully marked as open, now instantiate the specific one
  // requested.
  auto* streamPtr = instantiatePeerStream(streamId, streamGroupId);
  if (!streamPtr) {
    // Propagate internal inconsistency as QuicError
    return quic::make_unexpected(QuicError(
        TransportErrorCode::INTERNAL_ERROR,
        "Failed to instantiate newly opened peer stream"));
  }
  return streamPtr;
}

// Returns QuicError for transport-level issues (limits, state, internal)
quic::Expected<QuicStreamState*, QuicError> QuicStreamManager::createStream(
    StreamId streamId,
    OptionalIntegral<StreamGroupId> streamGroupId) {
  // Validate stream direction based on node type
  if (nodeType_ == QuicNodeType::Client && !isClientStream(streamId)) {
    // Previously threw -> return error
    return quic::make_unexpected(QuicError(
        TransportErrorCode::STREAM_STATE_ERROR,
        "Attempted creating non-client stream on client"));
  } else if (nodeType_ == QuicNodeType::Server && !isServerStream(streamId)) {
    // Previously threw -> return error
    return quic::make_unexpected(QuicError(
        TransportErrorCode::STREAM_STATE_ERROR,
        "Attempted creating non-server stream on server"));
  }
  bool isUni = isUnidirectionalStream(streamId);

  // Validate group properties if group is specified
  if (streamGroupId) {
    const auto& openGroups = isUni ? openUnidirectionalLocalStreamGroups_
                                   : openBidirectionalLocalStreamGroups_;
    if (!openGroups.contains(*streamGroupId)) {
      // Previously threw -> return error
      return quic::make_unexpected(QuicError(
          TransportErrorCode::STREAM_STATE_ERROR,
          "Attempted creating a stream in non-existent local group"));
    }

    // Ensure group ID matches node type
    if (nodeType_ == QuicNodeType::Client &&
        !isClientStreamGroup(*streamGroupId)) {
      // Previously threw -> return error
      return quic::make_unexpected(QuicError(
          TransportErrorCode::STREAM_STATE_ERROR,
          "Attempted creating a stream in non-client stream group on client"));
    } else if (
        nodeType_ == QuicNodeType::Server &&
        !isServerStreamGroup(*streamGroupId)) {
      // Previously threw -> return error
      return quic::make_unexpected(QuicError(
          TransportErrorCode::STREAM_STATE_ERROR,
          "Attempted creating a stream in non-server stream group on server"));
    }
  }

  // Check if stream was already implicitly opened but not yet instantiated
  auto openedStreamResult = getOrCreateOpenedLocalStream(streamId);
  if (!openedStreamResult.has_value()) {
    // Propagate internal error as QuicError
    return openedStreamResult;
  }
  if (openedStreamResult.value()) {
    // Stream was opened, now instantiated. Check/update group ID.
    if (streamGroupId.has_value() &&
        openedStreamResult.value()->groupId != streamGroupId) {
      if (openedStreamResult.value()->groupId.has_value()) {
        // Previously threw -> return error
        return quic::make_unexpected(QuicError(
            TransportErrorCode::STREAM_STATE_ERROR,
            "Stream exists lazily with different group ID"));
      }
      openedStreamResult.value()->groupId = streamGroupId;
    }
    return openedStreamResult.value();
  }
  // Stream doesn't exist and wasn't previously opened; try to open it now.
  auto& nextAcceptableStreamId = isUni
      ? nextAcceptableLocalUnidirectionalStreamId_
      : nextAcceptableLocalBidirectionalStreamId_;
  auto maxStreamId =
      isUni ? maxLocalUnidirectionalStreamId_ : maxLocalBidirectionalStreamId_;
  auto& openLocalStreams =
      isUni ? openUnidirectionalLocalStreams_ : openBidirectionalLocalStreams_;

  // Use openLocalStreamIfNotClosed to check limits and mark as open in
  // StreamIdSet
  auto openedResultCode = openLocalStreamIfNotClosed(
      streamId, openLocalStreams, nextAcceptableStreamId, maxStreamId);

  if (openedResultCode == LocalErrorCode::STREAM_LIMIT_EXCEEDED) {
    return quic::make_unexpected(QuicError(
        TransportErrorCode::STREAM_LIMIT_ERROR,
        "Cannot create stream: limit exceeded"));
  }
  if (openedResultCode == LocalErrorCode::CREATING_EXISTING_STREAM) {
    return quic::make_unexpected(QuicError(
        TransportErrorCode::STREAM_STATE_ERROR,
        "Cannot create stream: already exists or closed"));
  }
  DCHECK(openedResultCode == LocalErrorCode::NO_ERROR);

  // Stream is now officially open, instantiate its state in the map.
  auto [it, inserted] =
      streams_.try_emplace(streamId, streamId, streamGroupId, conn_);

  if (!inserted) {
    // Propagate internal error as QuicError
    LOG(ERROR) << "Failed to emplace stream " << streamId
               << " after opening check";
    return quic::make_unexpected(QuicError(
        TransportErrorCode::INTERNAL_ERROR,
        "Failed to emplace stream state after opening"));
  }

  QUIC_STATS(conn_.statsCallback, onNewQuicStream);
  updateAppIdleState();
  return &it->second;
}

quic::Expected<void, QuicError> QuicStreamManager::removeClosedStream(
    StreamId streamId) {
  auto it = streams_.find(streamId);
  if (it == streams_.end()) {
    VLOG(10) << "Trying to remove already closed stream=" << streamId;
    return {};
  }
  VLOG(10) << "Removing closed stream=" << streamId;
  DCHECK(it->second.inTerminalStates());

  // Clear from various tracking sets
  if (conn_.pendingEvents.resets.contains(streamId)) {
    conn_.pendingEvents.resets.erase(streamId);
  }
  if (conn_.transportSettings.unidirectionalStreamsReadCallbacksFirst &&
      isUnidirectionalStream(streamId)) {
    unidirectionalReadableStreams_.erase(streamId);
  } else {
    readableStreams_.erase(streamId);
  }
  peekableStreams_.erase(streamId);
  removeWritable(it->second); // Also removes from loss sets and write queue
  blockedStreams_.erase(streamId);
  deliverableStreams_.erase(streamId);
  txStreams_.erase(streamId);
  windowUpdates_.erase(streamId);
  stopSendingStreams_.erase(streamId);
  flowControlUpdated_.erase(streamId);
  connFlowControlBlocked_.erase(streamId);
  // Adjust control stream count if needed
  if (it->second.isControl) {
    DCHECK_GT(numControlStreams_, 0);
    numControlStreams_--;
  }

  // Erase the main stream state
  streams_.erase(it);
  QUIC_STATS(conn_.statsCallback, onQuicStreamClosed);

  // Handle stream limit updates for remote streams
  if (isRemoteStream(nodeType_, streamId)) {
    auto& openPeerStreams = isUnidirectionalStream(streamId)
        ? openUnidirectionalPeerStreams_
        : openBidirectionalPeerStreams_;
    openPeerStreams.remove(streamId);
    // Check if we should send a stream limit update. We need to send an
    // update every time we've closed a number of streams >= the set windowing
    // fraction.
    uint64_t initialStreamLimit = isUnidirectionalStream(streamId)
        ? transportSettings_->advertisedInitialMaxStreamsUni
        : transportSettings_->advertisedInitialMaxStreamsBidi;
    uint64_t streamWindow = initialStreamLimit / streamLimitWindowingFraction_;

    uint64_t openableRemoteStreams = isUnidirectionalStream(streamId)
        ? openableRemoteUnidirectionalStreams()
        : openableRemoteBidirectionalStreams();
    // The "credit" here is how much available stream space we have based on
    // what the initial stream limit was set to.
    uint64_t streamCredit =
        initialStreamLimit - openableRemoteStreams - openPeerStreams.size();
    if (streamCredit >= streamWindow) {
      if (isUnidirectionalStream(streamId)) {
        uint64_t maxStreams = (maxRemoteUnidirectionalStreamId_ -
                               initialRemoteUnidirectionalStreamId_) /
            detail::kStreamIncrement;
        auto result =
            setMaxRemoteUnidirectionalStreams(maxStreams + streamCredit);
        if (!result.has_value()) {
          return quic::make_unexpected(result.error());
        }
        remoteUnidirectionalStreamLimitUpdate_ = maxStreams + streamCredit;

      } else {
        uint64_t maxStreams = (maxRemoteBidirectionalStreamId_ -
                               initialRemoteBidirectionalStreamId_) /
            detail::kStreamIncrement;
        auto result =
            setMaxRemoteBidirectionalStreams(maxStreams + streamCredit);
        if (!result.has_value()) {
          return quic::make_unexpected(result.error());
        }
        remoteBidirectionalStreamLimitUpdate_ = maxStreams + streamCredit;
      }
    }
  } else {
    // Local stream closed, remove from local open set
    auto& openLocalStreams = isUnidirectionalStream(streamId)
        ? openUnidirectionalLocalStreams_
        : openBidirectionalLocalStreams_;
    openLocalStreams.remove(streamId);
  }

  updateAppIdleState();
  return {};
}

void QuicStreamManager::addToReadableStreams(const QuicStreamState& stream) {
  if (conn_.transportSettings.unidirectionalStreamsReadCallbacksFirst &&
      isUnidirectionalStream(stream.id)) {
    unidirectionalReadableStreams_.emplace(stream.id);
  } else {
    readableStreams_.emplace(stream.id);
  }
}

void QuicStreamManager::removeFromReadableStreams(
    const QuicStreamState& stream) {
  if (conn_.transportSettings.unidirectionalStreamsReadCallbacksFirst &&
      isUnidirectionalStream(stream.id)) {
    unidirectionalReadableStreams_.erase(stream.id);
  } else {
    readableStreams_.erase(stream.id);
  }
}

void QuicStreamManager::updateReadableStreams(QuicStreamState& stream) {
  updateHolBlockedTime(stream);
  if (stream.hasReadableData() || stream.streamReadError.has_value()) {
    addToReadableStreams(stream);
  } else {
    removeFromReadableStreams(stream);
  }
}

void QuicStreamManager::updateWritableStreams(
    QuicStreamState& stream,
    bool connFlowControlOpen) {
  // Check for terminal write errors first
  if (stream.streamWriteError.has_value() && !stream.reliableSizeToPeer) {
    CHECK(stream.lossBuffer.empty());
    CHECK(stream.lossBufMetas.empty());
    removeWritable(stream);
    return;
  }

  // Check if paused
  // pausedButDisabled adds a hard dep on writeQueue being an HTTPPriorityQueue.
  auto httpPri = HTTPPriorityQueue::Priority(stream.priority);
  if (oldWriteQueue_ && httpPri->paused &&
      !transportSettings_->disablePausedPriority) {
    removeWritable(stream);
    return;
  }

  // Update writable/loss sets based on data/meta presence
  if (stream.hasWritableData()) {
    writableStreams_.emplace(stream.id);
  } else {
    writableStreams_.erase(stream.id);
  }
  if (stream.hasWritableBufMeta()) {
    writableDSRStreams_.emplace(stream.id);
  } else {
    writableDSRStreams_.erase(stream.id);
  }
  if (!stream.lossBuffer.empty()) {
    lossStreams_.emplace(stream.id);
  } else {
    lossStreams_.erase(stream.id);
  }
  if (!stream.lossBufMetas.empty()) {
    lossDSRStreams_.emplace(stream.id);
  } else {
    lossDSRStreams_.erase(stream.id);
  }

  // Update the actual scheduling queues (PriorityQueue or control set)
  connFlowControlOpen |= bool(oldWriteQueue_);
  if (stream.hasSchedulableData(connFlowControlOpen) ||
      stream.hasSchedulableDsr(connFlowControlOpen)) {
    if (stream.isControl) {
      controlWriteQueue_.emplace(stream.id);
    } else {
      if (oldWriteQueue_) {
        const static deprecated::Priority kPausedDisabledPriority(7, true);
        auto oldPri = httpPri->paused
            ? kPausedDisabledPriority
            : deprecated::Priority(
                  httpPri->urgency, httpPri->incremental, httpPri->order);
        oldWriteQueue_->insertOrUpdate(stream.id, oldPri);
      } else {
        const static PriorityQueue::Priority kPausedDisabledPriority(
            HTTPPriorityQueue::Priority(7, true));
        writeQueue().insertOrUpdate(
            PriorityQueue::Identifier::fromStreamID(stream.id),
            httpPri->paused && transportSettings_->disablePausedPriority
                ? kPausedDisabledPriority
                : stream.priority);
      }
    }
  } else {
    // Not schedulable, remove from queues
    if (stream.isControl) {
      controlWriteQueue_.erase(stream.id);
    } else {
      if (oldWriteQueue_) {
        oldWriteQueue_->erase(stream.id);
      } else {
        writeQueue().erase(PriorityQueue::Identifier::fromStreamID(stream.id));
      }
    }
  }
}

void QuicStreamManager::updatePeekableStreams(QuicStreamState& stream) {
  // Stream is peekable if it has data OR a read error to report via peekError()
  if (stream.hasPeekableData() || stream.streamReadError.has_value()) {
    peekableStreams_.emplace(stream.id);
  } else {
    peekableStreams_.erase(stream.id);
  }
}

void QuicStreamManager::updateAppIdleState() {
  bool currentNonCtrlStreams = hasNonCtrlStreams();
  if (isAppIdle_ && !currentNonCtrlStreams) {
    // We were app limited, and we continue to be app limited.
    return;
  } else if (!isAppIdle_ && currentNonCtrlStreams) {
    // We were not app limited, and we continue to be not app limited.
    return;
  }
  isAppIdle_ = !currentNonCtrlStreams;
  if (conn_.congestionController) {
    conn_.congestionController->setAppIdle(isAppIdle_, Clock::now());
  }
}

void QuicStreamManager::setStreamAsControl(QuicStreamState& stream) {
  if (!stream.isControl) {
    stream.isControl = true;
    numControlStreams_++;
  }
  updateAppIdleState();
}

bool QuicStreamManager::isAppIdle() const {
  return isAppIdle_;
}

void QuicStreamManager::clearOpenStreams() {
  // Call stats callback before clearing
  QUIC_STATS_FOR_EACH(
      streams().cbegin(),
      streams().cend(),
      conn_.statsCallback,
      onQuicStreamClosed);

  // Clear all stream sets and maps
  openBidirectionalLocalStreams_.clear();
  openUnidirectionalLocalStreams_.clear();
  openBidirectionalPeerStreams_.clear();
  openUnidirectionalPeerStreams_.clear();
  openBidirectionalLocalStreamGroups_.clear();
  openUnidirectionalLocalStreamGroups_.clear();
  peerUnidirectionalStreamGroupsSeen_.clear();
  peerBidirectionalStreamGroupsSeen_.clear();
  streams_.clear();
}

} // namespace quic
