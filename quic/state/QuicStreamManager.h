/*
 * Copyright (c) Facebook, Inc. and its affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 *
 */

#pragma once

#include <quic/QuicConstants.h>
#include <quic/codec/Types.h>
#include <quic/state/StreamData.h>
#include <quic/state/TransportSettings.h>
#include <deque>
#include <map>
#include <numeric>
#include <queue>
#include <set>
#include <unordered_map>

namespace quic {
namespace detail {

constexpr uint8_t kStreamIncrement = 0x04;
}

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
    refreshTransportSettings(transportSettings);
  }
  /*
   * Create the state for a stream if it does not exist and return it. Note this
   * function is only used internally or for testing.
   */
  folly::Expected<QuicStreamState*, LocalErrorCode> createStream(
      StreamId streamId);

  /*
   * Create and return the state for the next available bidirectional stream.
   */
  folly::Expected<QuicStreamState*, LocalErrorCode>
  createNextBidirectionalStream();

  /*
   * Create and return the state for the next available unidirectional stream.
   */
  folly::Expected<QuicStreamState*, LocalErrorCode>
  createNextUnidirectionalStream();

  /*
   * Return the stream state or create it if the state has not yet been created.
   * Note that this is only valid for streams that are currently open.
   */
  QuicStreamState* FOLLY_NONNULL getStream(StreamId streamId);

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
   * Update the current loss streams for the given stream state. This will
   * either add or remove it from the collection of streams with outstanding
   * loss.
   */
  void updateLossStreams(QuicStreamState& stream);

  /*
   * Find a open and active (we have created state for it) stream and return its
   * state.
   */
  QuicStreamState* FOLLY_NULLABLE findStream(StreamId streamId);

  /*
   * Check whether the stream exists. This returns false for the crypto stream,
   * thus the caller must check separately for the crypto stream.
   */
  bool streamExists(StreamId streamId) {
    return std::binary_search(
               openBidirectionalPeerStreams_.begin(),
               openBidirectionalPeerStreams_.end(),
               streamId) ||
        std::binary_search(
               openUnidirectionalPeerStreams_.begin(),
               openUnidirectionalPeerStreams_.end(),
               streamId) ||
        std::binary_search(
               openLocalStreams_.begin(), openLocalStreams_.end(), streamId);
  }

  uint64_t openableLocalBidirectionalStreams() {
    return (maxLocalBidirectionalStreamId_ -
            nextAcceptableLocalBidirectionalStreamId_) /
        detail::kStreamIncrement;
  }

  uint64_t openableLocalUnidirectionalStreams() {
    return (maxLocalUnidirectionalStreamId_ -
            nextAcceptableLocalUnidirectionalStreamId_) /
        detail::kStreamIncrement;
  }

  uint64_t openableRemoteBidirectionalStreams() {
    return (maxRemoteBidirectionalStreamId_ -
            nextAcceptablePeerBidirectionalStreamId_) /
        detail::kStreamIncrement;
  }

  uint64_t openableRemoteUnidirectionalStreams() {
    return (maxRemoteUnidirectionalStreamId_ -
            nextAcceptablePeerUnidirectionalStreamId_) /
        detail::kStreamIncrement;
  }

  /*
   * Clear the new peer streams, presumably after all have been processed.
   */
  void clearNewPeerStreams() {
    newPeerStreams_.clear();
  }

  /*
   * Clear all the currently open streams.
   */
  void clearOpenStreams() {
    openLocalStreams_.clear();
    openBidirectionalPeerStreams_.clear();
    openUnidirectionalPeerStreams_.clear();
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

  const auto& lossStreams() const {
    return lossStreams_;
  }

  void addLoss(StreamId streamId) {
    lossStreams_.push_back(streamId);
  }

  bool hasLoss() const {
    return !lossStreams_.empty();
  }

  // TODO figure out a better interface here.
  /*
   * Returns a mutable reference to the container holding the writable stream
   * IDs.
   */
  auto& writableStreams() {
    return writableStreams_;
  }

  /*
   * Returns if there are any writable streams.
   */
  bool hasWritable() const {
    return !writableStreams_.empty();
  }

  /*
   * Returns if the current writable streams contains the given id.
   */
  bool writableContains(StreamId streamId) const {
    return writableStreams_.count(streamId) > 0;
  }

  /*
   * Add a writable stream id.
   */
  void addWritable(StreamId streamId) {
    writableStreams_.insert(streamId);
  }

  /*
   * Remove a writable stream id.
   */
  void removeWritable(StreamId streamId) {
    writableStreams_.erase(streamId);
  }

  /*
   * Clear the writable streams.
   */
  void clearWritable() {
    writableStreams_.clear();
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
    remoteBidirectionalStreamLimitUpdate_ = folly::none;
    return ret;
  }

  /*
   * The next value that should be sent in a unidirectional max streams frame,
   * if any. This is potentially updated every time a unidirectional stream is
   * closed. Calling this function "consumes" the update.
   */
  folly::Optional<uint64_t> remoteUnidirectionalStreamLimitUpdate() {
    auto ret = remoteUnidirectionalStreamLimitUpdate_;
    remoteUnidirectionalStreamLimitUpdate_ = folly::none;
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
    } else {
      StreamId ret = *itr;
      deliverableStreams_.erase(itr);
      return ret;
    }
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
   * Returns a const reference to the underlying data rejected streams
   * container.
   */
  const auto& dataRejectedStreams() const {
    return dataRejectedStreams_;
  }

  /*
   * Add a data rejected stream.
   */
  void addDataRejected(StreamId streamId) {
    dataRejectedStreams_.insert(streamId);
  }

  /*
   * Returns a const reference to the underlying data expired streams container.
   */
  const auto& dataExpiredStreams() const {
    return dataExpiredStreams_;
  }

  /*
   * Clear the data rejected streams.
   */
  void clearDataRejected() {
    dataRejectedStreams_.clear();
  }

  /*
   * Add a data expired stream.
   */
  void addDataExpired(StreamId streamId) {
    dataExpiredStreams_.insert(streamId);
  }

  /*
   * Clear the data expired streams.
   */
  void clearDataExpired() {
    dataExpiredStreams_.clear();
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
   * Returns a mutable reference to the underlying open local streams container.
   */
  auto& openLocalStreams() {
    return openLocalStreams_;
  }

  // TODO figure out a better interface here.
  /*
   * Returns a mutable reference to the underlying new peer streams container.
   */
  auto& newPeerStreams() {
    return newPeerStreams_;
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
   * Sets the given stream to be tracked as a control stream.
   */
  void setStreamAsControl(QuicStreamState& stream);

  /*
   * Clear the tracking of streams which can trigger API callbacks.
   */
  void clearActionable() {
    deliverableStreams_.clear();
    readableStreams_.clear();
    peekableStreams_.clear();
    dataExpiredStreams_.clear();
    dataRejectedStreams_.clear();
  }

  bool isAppIdle() const;

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

  QuicStreamState* FOLLY_NULLABLE getOrCreatePeerStream(StreamId streamId);

  void setMaxRemoteBidirectionalStreamsInternal(
      uint64_t maxStreams,
      bool force);
  void setMaxRemoteUnidirectionalStreamsInternal(
      uint64_t maxStreams,
      bool force);

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

  // Next unidirectional stream id to use when creating a stream.
  StreamId nextUnidirectionalStreamId_{0};

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
  // Ordered by id.
  std::deque<StreamId> openBidirectionalPeerStreams_;

  // Unidirectional streams that are opened by the peer on the connection.
  // Ordered by id.
  std::deque<StreamId> openUnidirectionalPeerStreams_;

  // Streams that are opened locally on the connection. Ordered by id.
  std::deque<StreamId> openLocalStreams_;

  // A map of streams that are active.
  std::map<StreamId, QuicStreamState> streams_;

  std::deque<StreamId> newPeerStreams_;

  // List of streams that have pending reads
  std::set<StreamId> readableStreams_;

  // List of streams that have pending peeks
  std::set<StreamId> peekableStreams_;

  // List of streams that have writable data
  std::set<StreamId> writableStreams_;

  // List of streams that were blocked
  std::unordered_map<StreamId, StreamDataBlockedFrame> blockedStreams_;

  // List of streams where the peer was asked to stop sending
  std::unordered_map<StreamId, ApplicationErrorCode> stopSendingStreams_;

  // List of streams that have expired data
  std::set<StreamId> dataExpiredStreams_;

  // List of streams that have rejected data
  std::set<StreamId> dataRejectedStreams_;

  // Streams that may be able to callback DeliveryCallback
  std::set<StreamId> deliverableStreams_;

  // Streams that had their stream window change and potentially need a window
  // update sent
  std::unordered_set<StreamId> windowUpdates_;

  // Streams that had their flow control updated
  std::set<StreamId> flowControlUpdated_;

  // Streams that are closed but we still have state for
  std::set<StreamId> closedStreams_;

  // Data structure to keep track of stream that have detected lost data
  std::vector<StreamId> lossStreams_;

  // Record whether or not we are app-idle.
  bool isAppIdle_{false};

  const TransportSettings* transportSettings_;
};

} // namespace quic
