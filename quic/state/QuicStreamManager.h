/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#pragma once

#include <quic/mvfst-config.h>

#include <quic/QuicConstants.h>
#include <quic/codec/Types.h>
#include <quic/common/Expected.h>
#include <quic/priority/PriorityQueue.h>
#include <quic/state/StreamData.h>
#include <quic/state/TransportSettings.h>
#include <numeric>
#include <set>

namespace quic {
class QLogger;

// Default priority for datagrams when scheduling with streams
extern const PriorityQueue::Priority kDefaultDatagramPriority;

namespace detail {

constexpr uint8_t kStreamIncrement = 0x04;
constexpr uint8_t kStreamGroupIncrement = 0x04;
constexpr uint64_t kMaxStreamGroupId = 128 * kStreamGroupIncrement;

} // namespace detail

/*
 * Class for containing a set of stream IDs, which wraps a IntervalSet.
 * This saves space when the set contains "contiguous" stream IDs for a given
 * type. For example, 0, 4, 8, ... 400 is internally represented by a single
 * entry, [0, 400].
 */
class StreamIdSet {
 public:
  explicit StreamIdSet(StreamId base) : base_(static_cast<uint8_t>(base)) {}

  StreamIdSet() : base_(0) {}

  void add(StreamId id) {
    add(id, id);
  }

  void remove(StreamId id) {
    id -= base_;
    CHECK_EQ(id % detail::kStreamIncrement, 0);
    id /= detail::kStreamIncrement;
    streams_.withdraw(Interval<StreamId>(id, id));
  }

  void add(StreamId first, StreamId last) {
    first -= base_;
    last -= base_;
    CHECK_EQ(first % detail::kStreamIncrement, 0);
    CHECK_EQ(last % detail::kStreamIncrement, 0);
    first /= detail::kStreamIncrement;
    last /= detail::kStreamIncrement;
    streams_.insert(first, last);
  }

  [[nodiscard]] bool contains(StreamId id) const {
    id -= base_;
    id /= detail::kStreamIncrement;
    return streams_.contains(id, id);
  }

  [[nodiscard]] size_t size() const {
    size_t ret = 0;
    for (const auto& [start, end] : streams_) {
      ret += end - start + 1;
    }
    return ret;
  }

  void clear() {
    streams_.clear();
  }

 private:
  IntervalSet<StreamId, 1, std::vector> streams_;
  uint8_t base_;
};

class QuicStreamManager {
 public:
  QuicStreamManager(
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
      peerUnidirectionalStreamGroupsSeen_ = StreamIdSet(0x02);
      peerBidirectionalStreamGroupsSeen_ = StreamIdSet(0x00);
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
      peerUnidirectionalStreamGroupsSeen_ = StreamIdSet(0x03);
      peerBidirectionalStreamGroupsSeen_ = StreamIdSet(0x01);
    }
    nextBidirectionalStreamGroupId_ = nextBidirectionalStreamId_;
    nextUnidirectionalStreamGroupId_ = nextUnidirectionalStreamId_;
    openBidirectionalLocalStreams_ =
        StreamIdSet(initialLocalBidirectionalStreamId_);
    openUnidirectionalLocalStreams_ =
        StreamIdSet(initialLocalUnidirectionalStreamId_);
    openBidirectionalPeerStreams_ =
        StreamIdSet(initialRemoteBidirectionalStreamId_);
    openUnidirectionalPeerStreams_ =
        StreamIdSet(initialRemoteUnidirectionalStreamId_);
    openBidirectionalLocalStreamGroups_ =
        StreamIdSet(nextBidirectionalStreamGroupId_);
    openUnidirectionalLocalStreamGroups_ =
        StreamIdSet(nextUnidirectionalStreamGroupId_);

    // Call refreshTransportSettings which now returns Expected
    auto refreshResult = refreshTransportSettings(transportSettings);
    if (refreshResult.hasError()) {
      // Constructor cannot return error easily. Log or handle internally.
      LOG(ERROR) << "Failed initial transport settings refresh: "
                 << refreshResult.error().message;
      // Consider throwing here if construction must fail, or setting an error
      // state. For now, logging is consistent with previous changes.
    }
  }

  /**
   * Constructor to facilitate migration of a QuicStreamManager to another
   * QuicConnectionStateBase
   */
  QuicStreamManager(
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
    peerUnidirectionalStreamGroupsSeen_ =
        std::move(other.peerUnidirectionalStreamGroupsSeen_);
    peerBidirectionalStreamGroupsSeen_ = // Added missing move
        std::move(other.peerBidirectionalStreamGroupsSeen_);
    newGroupedPeerStreams_ = std::move(other.newGroupedPeerStreams_);
    blockedStreams_ = std::move(other.blockedStreams_);
    stopSendingStreams_ = std::move(other.stopSendingStreams_);
    windowUpdates_ = std::move(other.windowUpdates_);
    flowControlUpdated_ = std::move(other.flowControlUpdated_);
    lossStreams_ = std::move(other.lossStreams_);
    readableStreams_ = std::move(other.readableStreams_);
    unidirectionalReadableStreams_ =
        std::move(other.unidirectionalReadableStreams_);
    peekableStreams_ = std::move(other.peekableStreams_);
    writeQueue_ = std::move(other.writeQueue_);
    controlWriteQueue_ = std::move(other.controlWriteQueue_);
    writableStreams_ = std::move(other.writableStreams_);
    txStreams_ = std::move(other.txStreams_);
    deliverableStreams_ = std::move(other.deliverableStreams_);
    closedStreams_ = std::move(other.closedStreams_);
    isAppIdle_ = other.isAppIdle_;
    maxLocalBidirectionalStreamIdIncreased_ =
        other.maxLocalBidirectionalStreamIdIncreased_;
    maxLocalUnidirectionalStreamIdIncreased_ =
        other.maxLocalUnidirectionalStreamIdIncreased_;

    for (auto& pair : other.streams_) {
      streams_.emplace(
          std::piecewise_construct,
          std::forward_as_tuple(pair.first),
          std::forward_as_tuple(
              conn_, // Use the new conn ref
              std::move(pair.second)));
    }
    // Call refreshTransportSettings which now returns Expected
    auto refreshResult = refreshTransportSettings(transportSettings);
    if (refreshResult.hasError()) {
      // Constructor cannot return error easily. Log or handle internally.
      LOG(ERROR) << "Failed initial transport settings refresh: "
                 << refreshResult.error().message;
      // Consider throwing here if construction must fail, or setting an error
      // state. For now, logging is consistent with previous changes.
    }
  }

  /*
   * Create the state for a stream if it does not exist and return it.
   */
  [[nodiscard]] quic::Expected<QuicStreamState*, QuicError> createStream(
      StreamId streamId,
      OptionalIntegral<StreamGroupId> streamGroupId = std::nullopt);

  /*
   * Create a new bidirectional stream group.
   */
  [[nodiscard]] quic::Expected<StreamGroupId, LocalErrorCode>
  createNextBidirectionalStreamGroup();

  /*
   * Create and return the state for the next available bidirectional stream.
   */
  [[nodiscard]] quic::Expected<QuicStreamState*, LocalErrorCode>
  createNextBidirectionalStream(
      OptionalIntegral<StreamGroupId> streamGroupId = std::nullopt);

  /*
   * Create a new unidirectional stream group.
   */
  [[nodiscard]] quic::Expected<StreamGroupId, LocalErrorCode>
  createNextUnidirectionalStreamGroup();

  /*
   * Create and return the state for the next available unidirectional stream.
   */
  [[nodiscard]] quic::Expected<QuicStreamState*, LocalErrorCode>
  createNextUnidirectionalStream(
      OptionalIntegral<StreamGroupId> streamGroupId = std::nullopt);

  /*
   * Return the stream state or create it if the state has not yet been created.
   */
  [[nodiscard]] quic::Expected<QuicStreamState*, QuicError> getStream(
      StreamId streamId,
      OptionalIntegral<StreamGroupId> streamGroupId = std::nullopt);

  /*
   * Remove all the state for a stream that is being closed.
   */
  [[nodiscard]] quic::Expected<void, QuicError> removeClosedStream(
      StreamId streamId);

  /*
   * Update the current readable streams for the given stream state.
   */
  void updateReadableStreams(QuicStreamState& stream);

  /*
   * Update the current peehable streams for the given stream state.
   */
  void updatePeekableStreams(QuicStreamState& stream);

  /*
   * Update the current writable streams for the given stream state.
   */
  void updateWritableStreams(
      QuicStreamState& stream,
      bool connFlowControlOpen = true);

  /*
   * Find a open and active (we have created state for it) stream and return its
   * state.
   */
  QuicStreamState* FOLLY_NULLABLE findStream(StreamId streamId);

  /*
   * Check whether the stream exists.
   */
  bool streamExists(StreamId streamId);

  /*
   * Optimized stream lookup that handles lazy state materialization.
   *
   * Fast path: If stream state is already materialized, returns it immediately.
   * Slow path: If stream exists but state not materialized, creates state.
   *
   * Returns:
   * - Pointer to stream state if stream exists (may materialize state lazily)
   * - nullptr if stream doesn't exist or was closed
   *
   * This is the recommended replacement for streamExists() + getStream()
   * pattern. Safe for both local and remote streams.
   */
  QuicStreamState* FOLLY_NULLABLE getStreamIfExists(StreamId streamId);

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

  Optional<StreamId> nextAcceptablePeerBidirectionalStreamId() {
    const auto max = maxRemoteBidirectionalStreamId_;
    const auto next = nextAcceptablePeerBidirectionalStreamId_;
    CHECK_GE(max, next);
    if (max == next) {
      return std::nullopt;
    }
    return next;
  }

  Optional<StreamId> nextAcceptablePeerUnidirectionalStreamId() {
    const auto max = maxRemoteUnidirectionalStreamId_;
    const auto next = nextAcceptablePeerUnidirectionalStreamId_;
    CHECK_GE(max, next);
    if (max == next) {
      return std::nullopt;
    }
    return next;
  }

  Optional<StreamId> nextAcceptableLocalBidirectionalStreamId() {
    const auto max = maxLocalBidirectionalStreamId_;
    const auto next = nextAcceptableLocalBidirectionalStreamId_;
    CHECK_GE(max, next);
    if (max == next) {
      return std::nullopt;
    }
    return next;
  }

  Optional<StreamId> nextAcceptableLocalUnidirectionalStreamId() {
    const auto max = maxLocalUnidirectionalStreamId_;
    const auto next = nextAcceptableLocalUnidirectionalStreamId_;
    CHECK_GE(max, next);
    if (max == next) {
      return std::nullopt;
    }
    return next;
  }

  /*
   * Clear all the currently open streams.
   */
  void clearOpenStreams();

  /*
   * Return a const reference to the underlying container holding the stream
   * state.
   */
  [[nodiscard]] const auto& streams() const {
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

  [[nodiscard]] bool hasLoss() const {
    return !lossStreams_.empty();
  }

  void removeLoss(StreamId id) {
    lossStreams_.erase(id);
  }

  void addLoss(StreamId id) {
    lossStreams_.insert(id);
  }

  quic::Expected<void, LocalErrorCode> setPriorityQueue(
      std::unique_ptr<PriorityQueue> queue);

  /**
   * Update stream priority if the stream indicated by id exists.
   */
  bool setStreamPriority(
      StreamId id,
      const PriorityQueue::Priority& priority,
      bool connFlowControlOpen = true,
      const std::shared_ptr<QLogger>& qLogger = nullptr);

  auto& controlWriteQueue() {
    return controlWriteQueue_;
  }

  auto& writeQueue() {
    return *writeQueue_;
  }

  [[nodiscard]] bool hasWritable() const {
    return !writeQueue_->empty() || !controlWriteQueue_.empty();
  }

  void removeWritable(const QuicStreamState& stream) {
    if (stream.isControl) {
      controlWriteQueue_.erase(stream.id);
    } else {
      writeQueue().erase(PriorityQueue::Identifier::fromStreamID(stream.id));
      connFlowControlBlocked_.erase(stream.id);
    }
    writableStreams_.erase(stream.id);
    lossStreams_.erase(stream.id);
  }

  void clearWritable() {
    writableStreams_.clear();
    writeQueue().clear();
    controlWriteQueue_.clear();
  }

  [[nodiscard]] const auto& blockedStreams() const {
    return blockedStreams_;
  }

  void queueBlocked(StreamId streamId, uint64_t offset) {
    blockedStreams_.emplace(streamId, StreamDataBlockedFrame(streamId, offset));
  }

  void removeBlocked(StreamId streamId) {
    blockedStreams_.erase(streamId);
  }

  [[nodiscard]] bool hasBlocked() const {
    return !blockedStreams_.empty();
  }

  /*
   * Set the max number of local bidirectional streams.
   */
  [[nodiscard]] quic::Expected<void, QuicError> setMaxLocalBidirectionalStreams(
      uint64_t maxStreams,
      bool force = false);

  /*
   * Set the max number of local unidirectional streams.
   */
  [[nodiscard]] quic::Expected<void, QuicError>
  setMaxLocalUnidirectionalStreams(uint64_t maxStreams, bool force = false);

  /*
   * Set the max number of remote bidirectional streams.
   */
  [[nodiscard]] quic::Expected<void, QuicError>
  setMaxRemoteBidirectionalStreams(uint64_t maxStreams);

  /*
   * Set the max number of remote unidirectional streams.
   */
  [[nodiscard]] quic::Expected<void, QuicError>
  setMaxRemoteUnidirectionalStreams(uint64_t maxStreams);

  bool consumeMaxLocalBidirectionalStreamIdIncreased();
  bool consumeMaxLocalUnidirectionalStreamIdIncreased();

  // This function messes with the connection state and you should think very
  // hard before calling it
  [[nodiscard]] quic::Expected<void, QuicError> refreshTransportSettings(
      const TransportSettings& settings);

  void setStreamLimitWindowingFraction(uint64_t fraction) {
    if (fraction > 0) {
      streamLimitWindowingFraction_ = fraction;
    }
  }

  Optional<uint64_t> remoteBidirectionalStreamLimitUpdate() {
    auto ret = remoteBidirectionalStreamLimitUpdate_;
    remoteBidirectionalStreamLimitUpdate_.reset();
    return ret;
  }

  Optional<uint64_t> remoteUnidirectionalStreamLimitUpdate() {
    auto ret = remoteUnidirectionalStreamLimitUpdate_;
    remoteUnidirectionalStreamLimitUpdate_.reset();
    return ret;
  }

  [[nodiscard]] const auto& windowUpdates() const {
    return windowUpdates_;
  }

  bool pendingWindowUpdate(StreamId streamId) {
    return windowUpdates_.count(streamId) > 0;
  }

  void queueWindowUpdate(StreamId streamId) {
    windowUpdates_.emplace(streamId);
  }

  void removeWindowUpdate(StreamId streamId) {
    windowUpdates_.erase(streamId);
  }

  [[nodiscard]] bool hasWindowUpdates() const {
    return !windowUpdates_.empty();
  }

  auto& closedStreams() {
    return closedStreams_;
  }

  void addClosed(StreamId streamId) {
    closedStreams_.insert(streamId);
  }

  [[nodiscard]] const auto& deliverableStreams() const {
    return deliverableStreams_;
  }

  void addDeliverable(StreamId streamId) {
    deliverableStreams_.insert(streamId);
  }

  void removeDeliverable(StreamId streamId) {
    deliverableStreams_.erase(streamId);
  }

  Optional<StreamId> popDeliverable() {
    auto itr = deliverableStreams_.begin();
    if (itr == deliverableStreams_.end()) {
      return std::nullopt;
    }
    StreamId ret = *itr;
    deliverableStreams_.erase(itr);
    return ret;
  }

  [[nodiscard]] bool hasDeliverable() const {
    return !deliverableStreams_.empty();
  }

  [[nodiscard]] bool deliverableContains(StreamId streamId) const {
    return deliverableStreams_.count(streamId) > 0;
  }

  [[nodiscard]] const auto& txStreams() const {
    return txStreams_;
  }

  void addTx(StreamId streamId) {
    txStreams_.insert(streamId);
  }

  void removeTx(StreamId streamId) {
    txStreams_.erase(streamId);
  }

  Optional<StreamId> popTx() {
    auto itr = txStreams_.begin();
    if (itr == txStreams_.end()) {
      return std::nullopt;
    } else {
      StreamId ret = *itr;
      txStreams_.erase(itr);
      return ret;
    }
  }

  [[nodiscard]] bool hasTx() const {
    return !txStreams_.empty();
  }

  [[nodiscard]] bool txContains(StreamId streamId) const {
    return txStreams_.count(streamId) > 0;
  }

  auto& readableStreams() {
    return readableStreams_;
  }

  auto& readableUnidirectionalStreams() {
    return unidirectionalReadableStreams_;
  }

  auto& peekableStreams() {
    return peekableStreams_;
  }

  const auto& flowControlUpdated() {
    return flowControlUpdated_;
  }

  std::vector<StreamId> consumeFlowControlUpdated() {
    std::vector<StreamId> result(
        flowControlUpdated_.begin(), flowControlUpdated_.end());
    flowControlUpdated_.clear();
    return result;
  }

  void queueFlowControlUpdated(StreamId streamId) {
    flowControlUpdated_.emplace(streamId);
  }

  Optional<StreamId> popFlowControlUpdated() {
    auto itr = flowControlUpdated_.begin();
    if (itr == flowControlUpdated_.end()) {
      return std::nullopt;
    } else {
      StreamId ret = *itr;
      flowControlUpdated_.erase(itr);
      return ret;
    }
  }

  void removeFlowControlUpdated(StreamId streamId) {
    flowControlUpdated_.erase(streamId);
  }

  bool flowControlUpdatedContains(StreamId streamId) {
    return flowControlUpdated_.count(streamId) > 0;
  }

  void clearFlowControlUpdated() {
    flowControlUpdated_.clear();
  }

  auto& openBidirectionalPeerStreams() {
    return openBidirectionalPeerStreams_;
  }

  auto& openUnidirectionalPeerStreams() {
    return openUnidirectionalPeerStreams_;
  }

  auto& openUnidirectionalLocalStreams() {
    return openUnidirectionalLocalStreams_;
  }

  auto& openBidirectionalLocalStreams() {
    return openBidirectionalLocalStreams_;
  }

  auto& newPeerStreams() {
    return newPeerStreams_;
  }

  std::vector<StreamId> consumeNewPeerStreams() {
    std::vector<StreamId> res{std::move(newPeerStreams_)};
    return res;
  }

  std::vector<StreamId> consumeNewGroupedPeerStreams() {
    std::vector<StreamId> res{std::move(newGroupedPeerStreams_)};
    return res;
  }

  auto consumeNewPeerStreamGroups() {
    decltype(newPeerStreamGroups_) result{std::move(newPeerStreamGroups_)};
    return result;
  }

  size_t streamCount() {
    return streams_.size();
  }

  [[nodiscard]] const auto& stopSendingStreams() const {
    return stopSendingStreams_;
  }

  auto consumeStopSending() {
    std::vector<std::pair<const StreamId, const ApplicationErrorCode>> result(
        stopSendingStreams_.begin(), stopSendingStreams_.end());
    stopSendingStreams_.clear();
    return result;
  }

  void clearStopSending() {
    stopSendingStreams_.clear();
  }

  void addStopSending(StreamId streamId, ApplicationErrorCode error) {
    stopSendingStreams_.emplace(streamId, error);
  }

  bool hasNonCtrlStreams() {
    return streams_.size() != numControlStreams_;
  }

  auto numControlStreams() {
    return numControlStreams_;
  }

  void setStreamAsControl(QuicStreamState& stream);

  void clearActionable() {
    deliverableStreams_.clear();
    txStreams_.clear();
    readableStreams_.clear();
    unidirectionalReadableStreams_.clear();
    peekableStreams_.clear();
    flowControlUpdated_.clear();
  }

  [[nodiscard]] bool isAppIdle() const;

  [[nodiscard]] bool getNumBidirectionalGroups() const {
    return openBidirectionalLocalStreamGroups_.size();
  }

  [[nodiscard]] bool getNumUnidirectionalGroups() const {
    return openUnidirectionalLocalStreamGroups_.size();
  }

  [[nodiscard]] size_t getNumNewPeerStreamGroups() const {
    return newPeerStreamGroups_.size();
  }

  [[nodiscard]] size_t getNumPeerStreamGroupsSeen() const {
    return peerUnidirectionalStreamGroupsSeen_.size() +
        peerBidirectionalStreamGroupsSeen_.size();
  }

  void setWriteQueueMaxNextsPerStream(uint64_t maxNextsPerStream);

  void addConnFCBlockedStream(StreamId id) {
    connFlowControlBlocked_.insert(id);
  }

  void onMaxData() {
    for (auto id : connFlowControlBlocked_) {
      auto stream = findStream(id);
      if (stream) {
        writeQueue().insertOrUpdate(
            PriorityQueue::Identifier::fromStreamID(id), stream->priority);
      }
    }
    connFlowControlBlocked_.clear();
  }

 private:
  void updateAppIdleState();

  [[nodiscard]] quic::Expected<QuicStreamState*, QuicError>
  getOrCreateOpenedLocalStream(StreamId streamId);

  [[nodiscard]] quic::Expected<QuicStreamState*, QuicError>
  getOrCreatePeerStream(
      StreamId streamId,
      OptionalIntegral<StreamGroupId> streamGroupId = std::nullopt);

  [[nodiscard]] quic::Expected<void, QuicError>
  setMaxRemoteBidirectionalStreamsInternal(uint64_t maxStreams, bool force);
  [[nodiscard]] quic::Expected<void, QuicError>
  setMaxRemoteUnidirectionalStreamsInternal(uint64_t maxStreams, bool force);

  QuicStreamState* FOLLY_NULLABLE instantiatePeerStream(
      StreamId streamId,
      OptionalIntegral<StreamGroupId> groupId);

  [[nodiscard]] quic::Expected<StreamGroupId, LocalErrorCode>
  createNextStreamGroup(StreamGroupId& groupId, StreamIdSet& streamGroups);

  void addToReadableStreams(const QuicStreamState& stream);
  void removeFromReadableStreams(const QuicStreamState& stream);

  QuicConnectionStateBase& conn_;
  QuicNodeType nodeType_;

  StreamId nextAcceptablePeerBidirectionalStreamId_{0};
  StreamId nextAcceptablePeerUnidirectionalStreamId_{0};
  StreamId nextAcceptableLocalBidirectionalStreamId_{0};
  StreamId nextAcceptableLocalUnidirectionalStreamId_{0};
  StreamId nextBidirectionalStreamId_{0};
  StreamGroupId nextBidirectionalStreamGroupId_{0};
  StreamId nextUnidirectionalStreamId_{0};
  StreamGroupId nextUnidirectionalStreamGroupId_{0};

  StreamId maxLocalBidirectionalStreamId_{0};
  StreamId maxLocalUnidirectionalStreamId_{0};
  StreamId maxRemoteBidirectionalStreamId_{0};
  StreamId maxRemoteUnidirectionalStreamId_{0};

  StreamId initialLocalBidirectionalStreamId_{0};
  StreamId initialLocalUnidirectionalStreamId_{0};
  StreamId initialRemoteBidirectionalStreamId_{0};
  StreamId initialRemoteUnidirectionalStreamId_{0};

  uint64_t streamLimitWindowingFraction_{2};
  Optional<uint64_t> remoteBidirectionalStreamLimitUpdate_;
  Optional<uint64_t> remoteUnidirectionalStreamLimitUpdate_;

  uint64_t numControlStreams_{0};

  StreamIdSet openBidirectionalPeerStreams_;
  StreamIdSet openUnidirectionalPeerStreams_;
  StreamIdSet openBidirectionalLocalStreams_;
  StreamIdSet openUnidirectionalLocalStreams_;
  StreamIdSet openBidirectionalLocalStreamGroups_;
  StreamIdSet openUnidirectionalLocalStreamGroups_;

  UnorderedMap<StreamId, QuicStreamState> streams_;

  std::vector<StreamId> newPeerStreams_;
  std::vector<StreamId> newGroupedPeerStreams_;
  UnorderedSet<StreamGroupId> newPeerStreamGroups_;
  StreamIdSet peerUnidirectionalStreamGroupsSeen_;
  StreamIdSet peerBidirectionalStreamGroupsSeen_;

  UnorderedMap<StreamId, StreamDataBlockedFrame> blockedStreams_;
  UnorderedMap<StreamId, ApplicationErrorCode> stopSendingStreams_;
  UnorderedSet<StreamId> windowUpdates_;
  UnorderedSet<StreamId> flowControlUpdated_;

  // Streams that were removed from the write queue because they are blocked
  // on connection flow control.
  UnorderedSet<StreamId> connFlowControlBlocked_;

  // Streams that have bytes in loss buffer
  UnorderedSet<StreamId> lossStreams_;
  UnorderedSet<StreamId> readableStreams_;
  UnorderedSet<StreamId> unidirectionalReadableStreams_;
  UnorderedSet<StreamId> peekableStreams_;

  std::unique_ptr<PriorityQueue> writeQueue_;
  std::set<StreamId> controlWriteQueue_;
  UnorderedSet<StreamId> writableStreams_;
  UnorderedSet<StreamId> txStreams_;
  UnorderedSet<StreamId> deliverableStreams_;
  UnorderedSet<StreamId> closedStreams_;

  bool isAppIdle_{false};
  const TransportSettings* FOLLY_NONNULL transportSettings_;
  bool maxLocalBidirectionalStreamIdIncreased_{false};
  bool maxLocalUnidirectionalStreamIdIncreased_{false};
};

} // namespace quic
