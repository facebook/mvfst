/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#pragma once

#include <folly/container/F14Map.h>
#include <folly/container/F14Set.h>
#include <quic/QuicConstants.h>
#include <quic/codec/Types.h>
#include <quic/state/QuicStreamPrioritiesObserver.h>
#include <quic/state/StreamData.h>
#include <quic/state/TransportSettings.h>
#include <numeric>

namespace quic {
namespace detail {

constexpr uint8_t kStreamIncrement = 0x04;
constexpr uint8_t kStreamGroupIncrement = 0x04;
constexpr uint64_t kMaxStreamGroupId = 128 * kStreamGroupIncrement;

} // namespace detail

class QuicStreamManager {
 public:
  explicit QuicStreamManager(
      QuicConnectionStateBase& conn,
      QuicNodeType nodeType,
      const TransportSettings& transportSettings)
      : conn_(conn),
        nodeType_(nodeType),
        transportSettings_(&transportSettings) {
    if (nodeType == QuicNodeType::Server) {
      nextAcceptablePeerBidirectionalStreamId_ = 0x00;
      nextAcceptablePeerUnidirectionalStreamId_ = 0x02;
      nextAcceptableLocalBidirectionalStreamId_ = 0x01;
      nextAcceptableLocalUnidirectionalStreamId_ = 0x03;
      nextBidirectionalStreamId_ = 0x01;
      nextUnidirectionalStreamId_ = 0x03;
      initialLocalBidirectionalStreamId_ = 0x01;
      initialLocalUnidirectionalStreamId_ = 0x03;
      initialRemoteBidirectionalStreamId_ = 0x00;
      initialRemoteUnidirectionalStreamId_ = 0x02;
    } else {
      nextAcceptablePeerBidirectionalStreamId_ = 0x01;
      nextAcceptablePeerUnidirectionalStreamId_ = 0x03;
      nextAcceptableLocalBidirectionalStreamId_ = 0x00;
      nextAcceptableLocalUnidirectionalStreamId_ = 0x02;
      nextBidirectionalStreamId_ = 0x00;
      nextUnidirectionalStreamId_ = 0x02;
      initialLocalBidirectionalStreamId_ = 0x00;
      initialLocalUnidirectionalStreamId_ = 0x02;
      initialRemoteBidirectionalStreamId_ = 0x01;
      initialRemoteUnidirectionalStreamId_ = 0x03;
    }
    nextBidirectionalStreamGroupId_ = nextBidirectionalStreamId_;
    nextUnidirectionalStreamGroupId_ = nextUnidirectionalStreamId_;
    refreshTransportSettings(transportSettings);
    writeQueue_.setMaxNextsPerStream(
        transportSettings.priorityQueueWritesPerStream);
  }

  /**
   * Constructor to facilitate migration of a QuicStreamManager to another
   * QuicConnectionStateBase
   */
  explicit QuicStreamManager(
      QuicConnectionStateBase& conn,
      QuicNodeType nodeType,
      const TransportSettings& transportSettings,
      QuicStreamManager&& other)
      : conn_(conn),
        nodeType_(nodeType),
        transportSettings_(&transportSettings) {
    nextAcceptablePeerBidirectionalStreamId_ =
        other.nextAcceptablePeerBidirectionalStreamId_;
    nextAcceptablePeerUnidirectionalStreamId_ =
        other.nextAcceptablePeerUnidirectionalStreamId_;
    nextAcceptableLocalBidirectionalStreamId_ =
        other.nextAcceptableLocalBidirectionalStreamId_;
    nextAcceptableLocalUnidirectionalStreamId_ =
        other.nextAcceptableLocalUnidirectionalStreamId_;
    nextBidirectionalStreamId_ = other.nextBidirectionalStreamId_;
    nextUnidirectionalStreamId_ = other.nextUnidirectionalStreamId_;
    nextBidirectionalStreamGroupId_ = other.nextBidirectionalStreamGroupId_;
    nextUnidirectionalStreamGroupId_ = other.nextUnidirectionalStreamGroupId_;
    maxLocalBidirectionalStreamId_ = other.maxLocalBidirectionalStreamId_;
    maxLocalUnidirectionalStreamId_ = other.maxLocalUnidirectionalStreamId_;
    maxRemoteBidirectionalStreamId_ = other.maxRemoteBidirectionalStreamId_;
    maxRemoteUnidirectionalStreamId_ = other.maxRemoteUnidirectionalStreamId_;
    initialLocalBidirectionalStreamId_ =
        other.initialLocalBidirectionalStreamId_;
    initialLocalUnidirectionalStreamId_ =
        other.initialLocalUnidirectionalStreamId_;
    initialRemoteBidirectionalStreamId_ =
        other.initialRemoteBidirectionalStreamId_;
    initialRemoteUnidirectionalStreamId_ =
        other.initialRemoteUnidirectionalStreamId_;

    streamLimitWindowingFraction_ = other.streamLimitWindowingFraction_;
    remoteBidirectionalStreamLimitUpdate_ =
        other.remoteBidirectionalStreamLimitUpdate_;
    remoteUnidirectionalStreamLimitUpdate_ =
        other.remoteUnidirectionalStreamLimitUpdate_;
    numControlStreams_ = other.numControlStreams_;
    openBidirectionalPeerStreams_ =
        std::move(other.openBidirectionalPeerStreams_);
    openUnidirectionalPeerStreams_ =
        std::move(other.openUnidirectionalPeerStreams_);
    openBidirectionalLocalStreams_ =
        std::move(other.openBidirectionalLocalStreams_);
    openUnidirectionalLocalStreams_ =
        std::move(other.openUnidirectionalLocalStreams_);
    openBidirectionalLocalStreamGroups_ =
        std::move(other.openBidirectionalLocalStreamGroups_);
    openUnidirectionalLocalStreamGroups_ =
        std::move(other.openUnidirectionalLocalStreamGroups_);
    newPeerStreams_ = std::move(other.newPeerStreams_);
    newPeerStreamGroups_ = std::move(other.newPeerStreamGroups_);
    peerStreamGroupsSeen_ = std::move(other.peerStreamGroupsSeen_);
    newGroupedPeerStreams_ = std::move(other.newGroupedPeerStreams_);
    blockedStreams_ = std::move(other.blockedStreams_);
    stopSendingStreams_ = std::move(other.stopSendingStreams_);
    streamPriorityLevelsNoCtrl_ = std::move(other.streamPriorityLevelsNoCtrl_);
    windowUpdates_ = std::move(other.windowUpdates_);
    flowControlUpdated_ = std::move(other.flowControlUpdated_);
    lossStreams_ = std::move(other.lossStreams_);
    lossDSRStreams_ = std::move(other.lossDSRStreams_);
    readableStreams_ = std::move(other.readableStreams_);
    peekableStreams_ = std::move(other.peekableStreams_);
    writeQueue_ = std::move(other.writeQueue_);
    controlWriteQueue_ = std::move(other.controlWriteQueue_);
    writableStreams_ = std::move(other.writableStreams_);
    writableDSRStreams_ = std::move(other.writableDSRStreams_);
    txStreams_ = std::move(other.txStreams_);
    deliverableStreams_ = std::move(other.deliverableStreams_);
    closedStreams_ = std::move(other.closedStreams_);
    isAppIdle_ = other.isAppIdle_;
    maxLocalBidirectionalStreamIdIncreased_ =
        other.maxLocalBidirectionalStreamIdIncreased_;
    maxLocalUnidirectionalStreamIdIncreased_ =
        other.maxLocalUnidirectionalStreamIdIncreased_;

    /**
     * We can't simply std::move the streams as the underlying
     * QuicStreamState(s) hold a reference to the other.conn_.
     */
    for (auto& pair : other.streams_) {
      streams_.emplace(
          std::piecewise_construct,
          std::forward_as_tuple(pair.first),
          std::forward_as_tuple(
              /* migrate state to new conn ref */ conn_,
              std::move(pair.second)));
    }
  }
  /*
   * Create the state for a stream if it does not exist and return it. Note this
   * function is only used internally or for testing.
   */
  folly::Expected<QuicStreamState*, LocalErrorCode> createStream(
      StreamId streamId,
      folly::Optional<StreamGroupId> streamGroupId = folly::none);

  /*
   * Create a new bidirectional stream group.
   */
  folly::Expected<StreamGroupId, LocalErrorCode>
  createNextBidirectionalStreamGroup();

  /*
   * Create and return the state for the next available bidirectional stream.
   */
  folly::Expected<QuicStreamState*, LocalErrorCode>
  createNextBidirectionalStream(
      folly::Optional<StreamGroupId> streamGroupId = folly::none);

  /*
   * Create a new unidirectional stream group.
   */
  folly::Expected<StreamGroupId, LocalErrorCode>
  createNextUnidirectionalStreamGroup();

  /*
   * Create and return the state for the next available unidirectional stream.
   */
  folly::Expected<QuicStreamState*, LocalErrorCode>
  createNextUnidirectionalStream(
      folly::Optional<StreamGroupId> streamGroupId = folly::none);

  /*
   * Return the stream state or create it if the state has not yet been created.
   * Note that this is only valid for streams that are currently open.
   */
  QuicStreamState* FOLLY_NULLABLE getStream(
      StreamId streamId,
      folly::Optional<StreamGroupId> streamGroupId = folly::none);

  /*
   * Remove all the state for a stream that is being closed.
   */
  void removeClosedStream(StreamId streamId);

  /*
   * Update the current readable streams for the given stream state. This will
   * either add or remove it from the collection of currently readable streams.
   */
  void updateReadableStreams(QuicStreamState& stream);

  /*
   * Update the current peehable streams for the given stream state. This will
   * either add or remove it from the collection of currently peekable streams.
   */
  void updatePeekableStreams(QuicStreamState& stream);

  /*
   * Update the current writable streams for the given stream state. This will
   * either add or remove it from the collection of currently writable streams.
   */
  void updateWritableStreams(QuicStreamState& stream);

  /*
   * Find a open and active (we have created state for it) stream and return its
   * state.
   */
  QuicStreamState* FOLLY_NULLABLE findStream(StreamId streamId);

  /*
   * Check whether the stream exists. This returns false for the crypto stream,
   * thus the caller must check separately for the crypto stream.
   */
  bool streamExists(StreamId streamId);

  uint64_t openableLocalBidirectionalStreams() {
    CHECK_GE(
        maxLocalBidirectionalStreamId_,
        nextAcceptableLocalBidirectionalStreamId_);
    return (maxLocalBidirectionalStreamId_ -
            nextAcceptableLocalBidirectionalStreamId_) /
        detail::kStreamIncrement;
  }

  uint64_t openableLocalUnidirectionalStreams() {
    CHECK_GE(
        maxLocalUnidirectionalStreamId_,
        nextAcceptableLocalUnidirectionalStreamId_);
    return (maxLocalUnidirectionalStreamId_ -
            nextAcceptableLocalUnidirectionalStreamId_) /
        detail::kStreamIncrement;
  }

  uint64_t openableRemoteBidirectionalStreams() {
    CHECK_GE(
        maxRemoteBidirectionalStreamId_,
        nextAcceptablePeerBidirectionalStreamId_);
    return (maxRemoteBidirectionalStreamId_ -
            nextAcceptablePeerBidirectionalStreamId_) /
        detail::kStreamIncrement;
  }

  uint64_t openableRemoteUnidirectionalStreams() {
    CHECK_GE(
        maxRemoteUnidirectionalStreamId_,
        nextAcceptablePeerUnidirectionalStreamId_);
    return (maxRemoteUnidirectionalStreamId_ -
            nextAcceptablePeerUnidirectionalStreamId_) /
        detail::kStreamIncrement;
  }

  /*
   * Returns the next acceptable (usable) remote bidirectional stream ID.
   *
   * If the maximum has been reached, empty optional returned.
   */
  folly::Optional<StreamId> nextAcceptablePeerBidirectionalStreamId() {
    const auto max = maxRemoteBidirectionalStreamId_;
    const auto next = nextAcceptablePeerBidirectionalStreamId_;
    CHECK_GE(max, next);
    if (max == next) {
      return folly::none;
    }
    return next;
  }

  /*
   * Returns the next acceptable (usable) remote undirectional stream ID.
   *
   * If the maximum has been reached, empty optional returned.
   */
  folly::Optional<StreamId> nextAcceptablePeerUnidirectionalStreamId() {
    const auto max = maxRemoteUnidirectionalStreamId_;
    const auto next = nextAcceptablePeerUnidirectionalStreamId_;
    CHECK_GE(max, next);
    if (max == next) {
      return folly::none;
    }
    return next;
  }

  /*
   * Returns the next acceptable (usable) local bidirectional stream ID.
   *
   * If the maximum has been reached, empty optional returned.
   */
  folly::Optional<StreamId> nextAcceptableLocalBidirectionalStreamId() {
    const auto max = maxLocalBidirectionalStreamId_;
    const auto next = nextAcceptableLocalBidirectionalStreamId_;
    CHECK_GE(max, next);
    if (max == next) {
      return folly::none;
    }
    return next;
  }

  /*
   * Returns the next acceptable (usable) local unidirectional stream ID.
   *
   * If the maximum has been reached, empty optional returned.
   */
  folly::Optional<StreamId> nextAcceptableLocalUnidirectionalStreamId() {
    const auto max = maxLocalUnidirectionalStreamId_;
    const auto next = nextAcceptableLocalUnidirectionalStreamId_;
    CHECK_GE(max, next);
    if (max == next) {
      return folly::none;
    }
    return next;
  }

  /*
   * Clear all the currently open streams.
   */
  void clearOpenStreams() {
    openBidirectionalLocalStreams_.clear();
    openUnidirectionalLocalStreams_.clear();
    openBidirectionalPeerStreams_.clear();
    openUnidirectionalPeerStreams_.clear();
    openBidirectionalLocalStreamGroups_.clear();
    openUnidirectionalLocalStreamGroups_.clear();
    peerStreamGroupsSeen_.clear();
    streams_.clear();
  }

  /*
   * Return a const reference to the underlying container holding the stream
   * state. Only really useful for iterating.
   */
  const auto& streams() const {
    return streams_;
  }

  /*
   * Call the given function on every currently open stream's state.
   */
  void streamStateForEach(const std::function<void(QuicStreamState&)>& f) {
    for (auto& s : streams_) {
      f(s.second);
    }
  }

  // Considers _any_ type of stream data being lost.
  FOLLY_NODISCARD bool hasLoss() const {
    return !lossStreams_.empty() || !lossDSRStreams_.empty();
  }

  // Considers non-DSR data being lost.
  FOLLY_NODISCARD bool hasNonDSRLoss() const {
    return !lossStreams_.empty();
  }

  // Considers non-DSR data being lost.
  FOLLY_NODISCARD bool hasDSRLoss() const {
    return !lossDSRStreams_.empty();
  }

  // Should only used directly by tests.
  void removeLoss(StreamId id) {
    lossStreams_.erase(id);
    lossDSRStreams_.erase(id);
  }

  // Should only used directly by tests.
  void addLoss(StreamId id) {
    lossStreams_.insert(id);
  }

  /**
   * Update stream priority if the stream indicated by id exists, and the
   * passed in values are different from current priority. Return true if
   * stream priority is update, false otherwise.
   */
  bool setStreamPriority(StreamId id, Priority priority);

  // TODO figure out a better interface here.
  /*
   * Returns a mutable reference to the container holding the writable stream
   * IDs.
   */
  auto& writableStreams() {
    return writableStreams_;
  }

  auto& writableDSRStreams() {
    return writableDSRStreams_;
  }

  // TODO figure out a better interface here.
  /*
   * Returns a mutable reference to the container holding the writable stream
   * IDs.
   */
  auto& controlWriteQueue() {
    return controlWriteQueue_;
  }

  auto& writeQueue() {
    return writeQueue_;
  }

  /*
   * Returns if there are any writable streams.
   */
  bool hasWritable() const {
    return !writeQueue_.empty() || !controlWriteQueue_.empty();
  }

  FOLLY_NODISCARD bool hasDSRWritable() const {
    return !writableDSRStreams_.empty();
  }

  bool hasNonDSRWritable() const {
    return !writableStreams_.empty() || !controlWriteQueue_.empty();
  }

  /*
   * Add a writable stream id.
   */
  void addWritable(const QuicStreamState& stream) {
    if (stream.isControl) {
      // Control streams get their own queue.
      CHECK(stream.hasSchedulableData());
      controlWriteQueue_.insert(stream.id);
    } else {
      CHECK(stream.hasSchedulableData() || stream.hasSchedulableDsr());
      writeQueue_.insertOrUpdate(stream.id, stream.priority);
    }
    if (stream.hasWritableData()) {
      writableStreams_.insert(stream.id);
    }
    if (stream.hasWritableBufMeta()) {
      LOG(ERROR) << "writable DSR: " << stream.id;
      writableDSRStreams_.insert(stream.id);
    }
    if (!stream.lossBuffer.empty()) {
      lossStreams_.insert(stream.id);
    }
    if (!stream.lossBufMetas.empty()) {
      lossDSRStreams_.insert(stream.id);
    }
  }

  /*
   * Remove a writable stream id.
   */
  void removeWritable(const QuicStreamState& stream) {
    if (stream.isControl) {
      controlWriteQueue_.erase(stream.id);
    } else {
      writeQueue_.erase(stream.id);
    }
    writableStreams_.erase(stream.id);
    writableDSRStreams_.erase(stream.id);
    lossStreams_.erase(stream.id);
    lossDSRStreams_.erase(stream.id);
  }

  /*
   * Clear the writable streams.
   */
  void clearWritable() {
    writableStreams_.clear();
    writableDSRStreams_.clear();
    writeQueue_.clear();
    controlWriteQueue_.clear();
  }

  /*
   * Returns a const reference to the underlying blocked streams container.
   */
  const auto& blockedStreams() const {
    return blockedStreams_;
  }

  /*
   * Queue a blocked event for the given stream id at the given offset.
   */
  void queueBlocked(StreamId streamId, uint64_t offset) {
    blockedStreams_.emplace(streamId, StreamDataBlockedFrame(streamId, offset));
  }

  /*
   * Remove a blocked stream.
   */
  void removeBlocked(StreamId streamId) {
    blockedStreams_.erase(streamId);
  }

  /*
   * Returns if there are any blocked streams.
   */
  bool hasBlocked() const {
    return !blockedStreams_.empty();
  }

  /*
   * Set the max number of local bidirectional streams. Can only be increased
   * unless force is true.
   */
  void setMaxLocalBidirectionalStreams(uint64_t maxStreams, bool force = false);

  /*
   * Set the max number of local unidirectional streams. Can only be increased
   * unless force is true.
   */
  void setMaxLocalUnidirectionalStreams(
      uint64_t maxStreams,
      bool force = false);

  /*
   * Set the max number of remote bidirectional streams. Can only be increased
   * unless force is true.
   */
  void setMaxRemoteBidirectionalStreams(uint64_t maxStreams);

  /*
   * Set the max number of remote unidirectional streams. Can only be increased
   * unless force is true.
   */
  void setMaxRemoteUnidirectionalStreams(uint64_t maxStreams);

  /*
   * Returns true if MaxLocalBidirectionalStreamId was increased
   * since last call of this function (resets flag).
   */
  bool consumeMaxLocalBidirectionalStreamIdIncreased();

  /*
   * Returns true if MaxLocalUnidirectionalStreamId was increased
   * since last call of this function (resets flag).
   */
  bool consumeMaxLocalUnidirectionalStreamIdIncreased();

  void refreshTransportSettings(const TransportSettings& settings);

  /*
   * Sets the "window-by" fraction for sending stream limit updates. E.g.
   * setting the fraction to two when the initial stream limit was 100 will
   * cause the stream manager to update the relevant stream limit update when
   * 50 streams have been closed.
   */
  void setStreamLimitWindowingFraction(uint64_t fraction) {
    if (fraction > 0) {
      streamLimitWindowingFraction_ = fraction;
    }
  }

  /*
   * The next value that should be sent in a bidirectional max streams frame,
   * if any. This is potentially updated every time a bidirectional stream is
   * closed. Calling this function "consumes" the update.
   */
  folly::Optional<uint64_t> remoteBidirectionalStreamLimitUpdate() {
    auto ret = remoteBidirectionalStreamLimitUpdate_;
    remoteBidirectionalStreamLimitUpdate_.reset();
    return ret;
  }

  /*
   * The next value that should be sent in a unidirectional max streams frame,
   * if any. This is potentially updated every time a unidirectional stream is
   * closed. Calling this function "consumes" the update.
   */
  folly::Optional<uint64_t> remoteUnidirectionalStreamLimitUpdate() {
    auto ret = remoteUnidirectionalStreamLimitUpdate_;
    remoteUnidirectionalStreamLimitUpdate_.reset();
    return ret;
  }

  /*
   * Returns a const reference to the underlying stream window updates
   * container.
   */
  const auto& windowUpdates() const {
    return windowUpdates_;
  }

  /*
   * Returns whether a given stream id has a pending window update.
   */
  bool pendingWindowUpdate(StreamId streamId) {
    return windowUpdates_.count(streamId) > 0;
  }

  /*
   * Queue a pending window update for the given stream id.
   */
  void queueWindowUpdate(StreamId streamId) {
    windowUpdates_.emplace(streamId);
  }

  /*
   * Clear the window updates.
   */
  void removeWindowUpdate(StreamId streamId) {
    windowUpdates_.erase(streamId);
  }

  /*
   * Returns whether any stream has a pending window update.
   */
  bool hasWindowUpdates() const {
    return !windowUpdates_.empty();
  }

  // TODO figure out a better interface here.
  /*
   * Return a mutable reference to the underlying closed streams container.
   */
  auto& closedStreams() {
    return closedStreams_;
  }

  /*
   * Add a closed stream.
   */
  void addClosed(StreamId streamId) {
    closedStreams_.insert(streamId);
  }

  /*
   * Returns a const reference to the underlying deliverable streams container.
   */
  const auto& deliverableStreams() const {
    return deliverableStreams_;
  }

  /*
   * Add a deliverable stream.
   */
  void addDeliverable(StreamId streamId) {
    deliverableStreams_.insert(streamId);
  }

  /*
   * Remove a deliverable stream.
   */
  void removeDeliverable(StreamId streamId) {
    deliverableStreams_.erase(streamId);
  }

  /*
   * Pop a deliverable stream id and return it.
   */
  folly::Optional<StreamId> popDeliverable() {
    auto itr = deliverableStreams_.begin();
    if (itr == deliverableStreams_.end()) {
      return folly::none;
    }
    StreamId ret = *itr;
    deliverableStreams_.erase(itr);
    return ret;
  }

  /*
   * Returns if there are any deliverable streams.
   */
  bool hasDeliverable() const {
    return !deliverableStreams_.empty();
  }

  /*
   * Returns if the stream is in the deliverable container.
   */
  bool deliverableContains(StreamId streamId) const {
    return deliverableStreams_.count(streamId) > 0;
  }

  /*
   * Returns a const reference to the underlying TX streams container.
   */
  FOLLY_NODISCARD const auto& txStreams() const {
    return txStreams_;
  }

  /*
   * Add a stream to list of streams that have transmitted.
   */
  void addTx(StreamId streamId) {
    txStreams_.insert(streamId);
  }

  /*
   * Remove a TX stream.
   */
  void removeTx(StreamId streamId) {
    txStreams_.erase(streamId);
  }

  /*
   * Pop a TX stream id and return it.
   */
  folly::Optional<StreamId> popTx() {
    auto itr = txStreams_.begin();
    if (itr == txStreams_.end()) {
      return folly::none;
    } else {
      StreamId ret = *itr;
      txStreams_.erase(itr);
      return ret;
    }
  }

  /*
   * Returns if there are any TX streams.
   */
  FOLLY_NODISCARD bool hasTx() const {
    return !txStreams_.empty();
  }

  /*
   * Returns if the stream is in the TX container.
   */
  FOLLY_NODISCARD bool txContains(StreamId streamId) const {
    return txStreams_.count(streamId) > 0;
  }

  // TODO figure out a better interface here.
  /*
   * Returns a mutable reference to the underlying readable streams container.
   */
  auto& readableStreams() {
    return readableStreams_;
  }

  // TODO figure out a better interface here.
  /*
   * Returns a mutable reference to the underlying peekable streams container.
   */
  auto& peekableStreams() {
    return peekableStreams_;
  }

  /*
   * Returns a mutable reference to the underlying container of streams which
   * had their flow control updated.
   */
  const auto& flowControlUpdated() {
    return flowControlUpdated_;
  }

  /*
   * Consume the flow control updated streams using the parameter vector.
   */
  auto consumeFlowControlUpdated(std::vector<StreamId>&& storage) {
    std::vector<StreamId> result = storage;
    result.clear();
    result.reserve(flowControlUpdated_.size());
    result.insert(
        result.end(), flowControlUpdated_.begin(), flowControlUpdated_.end());
    flowControlUpdated_.clear();
    return result;
  }

  /*
   * Queue a stream which has had its flow control updated.
   */
  void queueFlowControlUpdated(StreamId streamId) {
    flowControlUpdated_.emplace(streamId);
  }

  /*
   * Pop and return a stream which has had its flow control updated.
   */
  folly::Optional<StreamId> popFlowControlUpdated() {
    auto itr = flowControlUpdated_.begin();
    if (itr == flowControlUpdated_.end()) {
      return folly::none;
    } else {
      StreamId ret = *itr;
      flowControlUpdated_.erase(itr);
      return ret;
    }
  }

  /*
   * Remove the specified stream from the flow control updated container.
   */
  void removeFlowControlUpdated(StreamId streamId) {
    flowControlUpdated_.erase(streamId);
  }

  /*
   * Returns if the the given stream is in the flow control updated container.
   */
  bool flowControlUpdatedContains(StreamId streamId) {
    return flowControlUpdated_.count(streamId) > 0;
  }

  /*
   * Clear the flow control updated container.
   */
  void clearFlowControlUpdated() {
    flowControlUpdated_.clear();
  }

  // TODO figure out a better interface here.
  /*
   * Returns a mutable reference to the underlying open bidirectional peer
   * streams container.
   */
  auto& openBidirectionalPeerStreams() {
    return openBidirectionalPeerStreams_;
  }

  // TODO figure out a better interface here.
  /*
   * Returns a mutable reference to the underlying open peer unidirectional
   * streams container.
   */
  auto& openUnidirectionalPeerStreams() {
    return openUnidirectionalPeerStreams_;
  }

  // TODO figure out a better interface here.
  /*
   * Returns a mutable reference to the underlying open local unidirectional
   * streams container.
   */
  auto& openUnidirectionalLocalStreams() {
    return openUnidirectionalLocalStreams_;
  }

  // TODO figure out a better interface here.
  /*
   * Returns a mutable reference to the underlying open local unidirectional
   * streams container.
   */
  auto& openBidirectionalLocalStreams() {
    return openBidirectionalLocalStreams_;
  }

  // TODO figure out a better interface here.
  /*
   * Returns a mutable reference to the underlying new peer streams container.
   */
  auto& newPeerStreams() {
    return newPeerStreams_;
  }

  /*
   * Consume the new peer streams using the parameter vector.
   */
  auto consumeNewPeerStreams(std::vector<StreamId>&& storage) {
    return swapStreams(newPeerStreams_, std::move(storage));
  }

  /*
   * Consume the new peer streams in groups using the parameter vector.
   */
  auto consumeNewGroupedPeerStreams(std::vector<StreamId>&& storage) {
    return swapStreams(newGroupedPeerStreams_, std::move(storage));
  }

  /*
   * Consume the new peer stream groups using the parameter vector.
   */
  auto consumeNewPeerStreamGroups() {
    decltype(newPeerStreamGroups_) result;
    result.swap(newPeerStreamGroups_);
    return result;
  }

  /*
   * Returns the number of streams open and active (for which we have created
   * the stream state).
   */
  size_t streamCount() {
    return streams_.size();
  }

  /*
   * Returns a const reference to the container of streams with pending
   * StopSending events.
   */
  const auto& stopSendingStreams() const {
    return stopSendingStreams_;
  }

  /*
   * Consume the stop sending streams.
   */
  auto consumeStopSending() {
    std::vector<std::pair<StreamId, ApplicationErrorCode>> result;
    result.reserve(stopSendingStreams_.size());
    result.insert(
        result.end(), stopSendingStreams_.begin(), stopSendingStreams_.end());
    stopSendingStreams_.clear();
    return result;
  }

  /*
   * Clear the StopSending streams.
   */
  void clearStopSending() {
    stopSendingStreams_.clear();
  }

  /*
   * Add a stream to the StopSending streams.
   */
  void addStopSending(StreamId streamId, ApplicationErrorCode error) {
    stopSendingStreams_.emplace(streamId, error);
  }

  /*
   * Returns if the stream manager has any non-control streams.
   */
  bool hasNonCtrlStreams() {
    return streams_.size() != numControlStreams_;
  }

  /*
   * Returns number of control streams.
   */
  auto numControlStreams() {
    return numControlStreams_;
  }

  /*
   * Sets the given stream to be tracked as a control stream.
   */
  void setStreamAsControl(QuicStreamState& stream);

  /*
   * Clear the tracking of streams which can trigger API callbacks.
   */
  void clearActionable() {
    deliverableStreams_.clear();
    txStreams_.clear();
    readableStreams_.clear();
    peekableStreams_.clear();
    flowControlUpdated_.clear();
  }

  bool isAppIdle() const;

  /*
   * Sets an observer that will be notified whenever the set of stream
   * priorities changes
   */
  void setPriorityChangesObserver(QuicStreamPrioritiesObserver* observer);

  /*
   * Stops notifications for changes to the set of stream priorities
   */
  void resetPriorityChangesObserver();

  /*
   * Returns the highest priority level used by any stream
   * (Highest priority is lowest value)
   */
  [[nodiscard]] PriorityLevel getHighestPriorityLevel() const;

  /*
   * Returns number of bidirectional groups.
   */
  [[nodiscard]] bool getNumBidirectionalGroups() const {
    return openBidirectionalLocalStreamGroups_.size();
  }

  /*
   * Returns number of unidirectional group exists.
   */
  [[nodiscard]] bool getNumUnidirectionalGroups() const {
    return openUnidirectionalLocalStreamGroups_.size();
  }

  [[nodiscard]] size_t getNumNewPeerStreamGroups() const {
    return newPeerStreamGroups_.size();
  }

  [[nodiscard]] size_t getNumPeerStreamGroupsSeen() const {
    return peerStreamGroupsSeen_.size();
  }

 private:
  // Updates the congestion controller app-idle state, after a change in the
  // number of streams.
  // App-idle state is set to true if there was at least one non-control
  // before the update and there are none after. It is set to false if instead
  // there were no non-control streams before and there is at least one at the
  // time of calling
  void updateAppIdleState();

  QuicStreamState* FOLLY_NULLABLE
  getOrCreateOpenedLocalStream(StreamId streamId);

  QuicStreamState* FOLLY_NULLABLE getOrCreatePeerStream(
      StreamId streamId,
      folly::Optional<StreamGroupId> streamGroupId = folly::none);

  void setMaxRemoteBidirectionalStreamsInternal(
      uint64_t maxStreams,
      bool force);
  void setMaxRemoteUnidirectionalStreamsInternal(
      uint64_t maxStreams,
      bool force);

  void addToStreamPriorityMap(const QuicStreamState& streamState);
  void notifyStreamPriorityChanges();

  // helper to create a new peer stream.
  QuicStreamState* FOLLY_NULLABLE instantiatePeerStream(
      StreamId streamId,
      folly::Optional<StreamGroupId> groupId);

  folly::Expected<StreamGroupId, LocalErrorCode> createNextStreamGroup(
      StreamGroupId& groupId,
      folly::F14FastSet<StreamGroupId>& streamGroups);

  /*
   * Helper to consume new stream ids.
   */
  std::vector<StreamId> swapStreams(
      std::vector<StreamId>& src,
      std::vector<StreamId>&& dst) {
    std::vector<StreamId> result = dst;
    result.clear();
    result.reserve(src.size());
    result.insert(result.end(), src.begin(), src.end());
    src.clear();
    return result;
  }

  QuicConnectionStateBase& conn_;
  QuicNodeType nodeType_;

  // Next acceptable bidirectional stream id that can be opened by the peer.
  // Used to keep track of closed streams.
  StreamId nextAcceptablePeerBidirectionalStreamId_{0};

  // Next acceptable unidirectional stream id that can be opened by the peer.
  // Used to keep track of closed streams.
  StreamId nextAcceptablePeerUnidirectionalStreamId_{0};

  // Next acceptable bidirectional stream id that can be opened locally.
  // Used to keep track of closed streams.
  StreamId nextAcceptableLocalBidirectionalStreamId_{0};

  // Next acceptable bidirectional stream id that can be opened locally.
  // Used to keep track of closed streams.
  StreamId nextAcceptableLocalUnidirectionalStreamId_{0};

  // Next bidirectional stream id to use when creating a stream.
  StreamId nextBidirectionalStreamId_{0};

  // Next bidirectional stream group id to use.
  StreamGroupId nextBidirectionalStreamGroupId_{0};

  // Next unidirectional stream id to use when creating a stream.
  StreamId nextUnidirectionalStreamId_{0};

  // Next unidirectional stream group id to use.
  StreamGroupId nextUnidirectionalStreamGroupId_{0};

  StreamId maxLocalBidirectionalStreamId_{0};

  StreamId maxLocalUnidirectionalStreamId_{0};

  StreamId maxRemoteBidirectionalStreamId_{0};

  StreamId maxRemoteUnidirectionalStreamId_{0};

  StreamId initialLocalBidirectionalStreamId_{0};

  StreamId initialLocalUnidirectionalStreamId_{0};

  StreamId initialRemoteBidirectionalStreamId_{0};

  StreamId initialRemoteUnidirectionalStreamId_{0};

  // The fraction to determine the window by which we will signal the need to
  // send stream limit updates
  uint64_t streamLimitWindowingFraction_{2};

  // Contains the value of a stream window update that should be sent for
  // remote bidirectional streams.
  folly::Optional<uint64_t> remoteBidirectionalStreamLimitUpdate_;

  // Contains the value of a stream window update that should be sent for
  // remote bidirectional streams.
  folly::Optional<uint64_t> remoteUnidirectionalStreamLimitUpdate_;

  uint64_t numControlStreams_{0};

  // Bidirectional streams that are opened by the peer on the connection.
  folly::F14FastSet<StreamId> openBidirectionalPeerStreams_;

  // Unidirectional streams that are opened by the peer on the connection.
  folly::F14FastSet<StreamId> openUnidirectionalPeerStreams_;

  // Bidirectional streams that are opened locally on the connection.
  folly::F14FastSet<StreamId> openBidirectionalLocalStreams_;

  // Unidirectional streams that are opened locally on the connection.
  folly::F14FastSet<StreamId> openUnidirectionalLocalStreams_;

  // Bidirectional stream groupss that are opened locally on the connection.
  folly::F14FastSet<StreamGroupId> openBidirectionalLocalStreamGroups_;

  // Unidirectional stream groups that are opened locally on the connection.
  folly::F14FastSet<StreamGroupId> openUnidirectionalLocalStreamGroups_;

  // A map of streams that are active.
  folly::F14FastMap<StreamId, QuicStreamState> streams_;

  // Recently opened peer streams.
  std::vector<StreamId> newPeerStreams_;

  // Recently opened peer streams with groups.
  std::vector<StreamId> newGroupedPeerStreams_;

  // Recently opened peer stream groups.
  folly::F14FastSet<StreamGroupId> newPeerStreamGroups_;

  // Peer group ids seen.
  folly::F14FastSet<StreamGroupId> peerStreamGroupsSeen_;

  // Map of streams that were blocked
  folly::F14FastMap<StreamId, StreamDataBlockedFrame> blockedStreams_;

  // Map of streams where the peer was asked to stop sending
  folly::F14FastMap<StreamId, ApplicationErrorCode> stopSendingStreams_;

  // Map of non-control stream priority levels
  folly::F14FastMap<StreamId, PriorityLevel> streamPriorityLevelsNoCtrl_;

  // Streams that had their stream window change and potentially need a window
  // update sent
  folly::F14FastSet<StreamId> windowUpdates_;

  // Streams that had their flow control updated
  folly::F14FastSet<StreamId> flowControlUpdated_;

  // Streams that have bytes in loss buffer
  folly::F14FastSet<StreamId> lossStreams_;

  // DSR Streams that have bytes in loss buff meta
  folly::F14FastSet<StreamId> lossDSRStreams_;

  // Set of streams that have pending reads
  folly::F14FastSet<StreamId> readableStreams_;

  // Set of streams that have pending peeks
  folly::F14FastSet<StreamId> peekableStreams_;

  // Set of !control streams that have writable data used for frame scheduling
  PriorityQueue writeQueue_;

  // Set of control streams that have writable data
  std::set<StreamId> controlWriteQueue_;

  folly::F14FastSet<StreamId> writableStreams_;
  folly::F14FastSet<StreamId> writableDSRStreams_;

  // Streams that may be able to call TxCallback
  folly::F14FastSet<StreamId> txStreams_;

  // Streams that may be able to callback DeliveryCallback
  folly::F14FastSet<StreamId> deliverableStreams_;

  // Streams that are closed but we still have state for
  folly::F14FastSet<StreamId> closedStreams_;

  // Observer to notify on changes in the streamPriorityLevels_ map
  QuicStreamPrioritiesObserver* priorityChangesObserver_{nullptr};

  // Record whether or not we are app-idle.
  bool isAppIdle_{false};

  const TransportSettings* FOLLY_NONNULL transportSettings_;

  bool maxLocalBidirectionalStreamIdIncreased_{false};
  bool maxLocalUnidirectionalStreamIdIncreased_{false};
};

} // namespace quic
