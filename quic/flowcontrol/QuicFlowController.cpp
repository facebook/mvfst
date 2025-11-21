/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <quic/flowcontrol/QuicFlowController.h>

#include <quic/QuicConstants.h>
#include <quic/QuicException.h>
#include <quic/logging/QLogger.h>

#include <quic/state/StreamData.h>
#include <algorithm>
#include <limits>

namespace quic {
namespace {
Optional<uint64_t> calculateNewWindowUpdate(
    uint64_t curReadOffset,
    uint64_t curAdvertisedOffset,
    uint64_t windowSize,
    const std::chrono::microseconds& srtt,
    const TransportSettings& transportSettings,
    const Optional<TimePoint>& lastSendTime,
    const TimePoint& updateTime) {
  DCHECK_LE(curReadOffset, curAdvertisedOffset);
  auto nextAdvertisedOffset = curReadOffset + windowSize;
  if (nextAdvertisedOffset == curAdvertisedOffset) {
    // No change in flow control
    return std::nullopt;
  }
  bool enoughTimeElapsed = lastSendTime && updateTime > *lastSendTime &&
      (updateTime - *lastSendTime) >
          transportSettings.flowControlRttFrequency * srtt;
  // If we are autotuning then frequent updates aren't required.
  if (!transportSettings.disableFlowControlTimeBasedUpdates &&
      enoughTimeElapsed && !transportSettings.autotuneReceiveConnFlowControl) {
    return nextAdvertisedOffset;
  }
  // The logic here is that we want to send updates when we have read
  // windowSize / flowControlWindowFrequency bytes.
  auto remaining = curAdvertisedOffset - curReadOffset;
  bool enoughWindowElapsed = [&]() {
    if (remaining > windowSize) {
      return false;
    }
    return (windowSize - remaining) *
        transportSettings.flowControlWindowFrequency >
        windowSize;
  }();
  if (enoughWindowElapsed) {
    return nextAdvertisedOffset;
  }
  return std::nullopt;
}

template <typename T>
[[nodiscard]] inline quic::Expected<void, QuicError> incrementWithOverFlowCheck(
    T& num,
    T diff) {
  if (num > std::numeric_limits<T>::max() - diff) {
    return quic::make_unexpected(QuicError(
        QuicErrorCode(LocalErrorCode::INTERNAL_ERROR),
        "flow control state overflow"));
  }
  num += diff;
  return {};
}

template <typename T>
[[nodiscard]] inline quic::Expected<void, QuicError> decrementWithOverFlowCheck(
    T& num,
    T diff) {
  if (num < std::numeric_limits<T>::min() + diff) {
    return quic::make_unexpected(QuicError(
        QuicErrorCode(LocalErrorCode::INTERNAL_ERROR),
        "flow control state overflow"));
  }
  num -= diff;
  return {};
}

inline uint64_t calculateMaximumData(const QuicStreamState& stream) {
  return std::max(
      stream.currentReadOffset + stream.flowControlState.windowSize,
      stream.flowControlState.advertisedMaxOffset);
}
} // namespace

void maybeIncreaseFlowControlWindow(
    const Optional<TimePoint>& timeOfLastFlowControlUpdate,
    TimePoint updateTime,
    std::chrono::microseconds srtt,
    uint64_t& windowSize) {
  if (!timeOfLastFlowControlUpdate || srtt == 0us) {
    return;
  }
  CHECK(updateTime > *timeOfLastFlowControlUpdate);
  if (std::chrono::duration_cast<decltype(srtt)>(
          updateTime - *timeOfLastFlowControlUpdate) < 2 * srtt) {
    VLOG(10) << "doubling flow control window";
    windowSize *= 2;
  }
}

void maybeIncreaseConnectionFlowControlWindow(
    QuicConnectionStateBase::ConnectionFlowControlState& flowControlState,
    TimePoint updateTime,
    std::chrono::microseconds srtt) {
  maybeIncreaseFlowControlWindow(
      flowControlState.timeOfLastFlowControlUpdate,
      updateTime,
      srtt,
      flowControlState.windowSize);
}

void maybeIncreaseStreamFlowControlWindow(
    QuicStreamState::StreamFlowControlState& flowControlState,
    TimePoint updateTime,
    std::chrono::microseconds srtt) {
  maybeIncreaseFlowControlWindow(
      flowControlState.timeOfLastFlowControlUpdate,
      updateTime,
      srtt,
      flowControlState.windowSize);
}

bool maybeSendConnWindowUpdate(
    QuicConnectionStateBase& conn,
    TimePoint updateTime) {
  if (conn.pendingEvents.connWindowUpdate) {
    // There is a pending flow control event already, and no point sending
    // again.
    return false;
  }
  auto& flowControlState = conn.flowControlState;
  auto newAdvertisedOffset = calculateNewWindowUpdate(
      flowControlState.sumCurReadOffset,
      flowControlState.advertisedMaxOffset,
      flowControlState.windowSize,
      conn.lossState.srtt,
      conn.transportSettings,
      flowControlState.timeOfLastFlowControlUpdate,
      updateTime);
  if (newAdvertisedOffset) {
    conn.pendingEvents.connWindowUpdate = true;
    QUIC_STATS(conn.statsCallback, onConnFlowControlUpdate);
    if (conn.qLogger) {
      conn.qLogger->addTransportStateUpdate(
          getFlowControlEvent(newAdvertisedOffset.value()));
    }
    if (conn.transportSettings.autotuneReceiveConnFlowControl) {
      maybeIncreaseConnectionFlowControlWindow(
          flowControlState, updateTime, conn.lossState.srtt);
    }
    return true;
  }
  return false;
}

bool maybeSendStreamWindowUpdate(
    QuicStreamState& stream,
    TimePoint updateTime) {
  auto& flowControlState = stream.flowControlState;
  if (!stream.shouldSendFlowControl()) {
    return false;
  }
  if (stream.conn.streamManager->pendingWindowUpdate(stream.id)) {
    return false;
  }
  auto newAdvertisedOffset = calculateNewWindowUpdate(
      stream.currentReadOffset,
      flowControlState.advertisedMaxOffset,
      flowControlState.windowSize,
      stream.conn.lossState.srtt,
      stream.conn.transportSettings,
      flowControlState.timeOfLastFlowControlUpdate,
      updateTime);
  if (newAdvertisedOffset) {
    VLOG(10) << "Queued flow control update for stream=" << stream.id
             << " offset=" << *newAdvertisedOffset;
    stream.conn.streamManager->queueWindowUpdate(stream.id);
    QUIC_STATS(stream.conn.statsCallback, onStreamFlowControlUpdate);
    return true;
  }
  return false;
}

quic::Expected<void, QuicError> updateFlowControlOnStreamData(
    QuicStreamState& stream,
    uint64_t previousMaxOffsetObserved,
    uint64_t bufferEndOffset) {
  if (stream.flowControlState.advertisedMaxOffset < bufferEndOffset) {
    return quic::make_unexpected(QuicError(
        TransportErrorCode::FLOW_CONTROL_ERROR,
        fmt::format("Stream flow control violation on stream {}", stream.id)));
  }
  auto curMaxOffsetObserved =
      std::max(previousMaxOffsetObserved, bufferEndOffset);
  auto& connFlowControlState = stream.conn.flowControlState;
  uint64_t connMaxObservedOffset = connFlowControlState.sumMaxObservedOffset;
  auto incrementResult = incrementWithOverFlowCheck(
      connMaxObservedOffset, curMaxOffsetObserved - previousMaxOffsetObserved);
  if (!incrementResult.has_value()) {
    return incrementResult;
  }
  if (connMaxObservedOffset > connFlowControlState.advertisedMaxOffset) {
    return quic::make_unexpected(QuicError(
        TransportErrorCode::FLOW_CONTROL_ERROR,
        "Connection flow control violation"));
  }
  return incrementWithOverFlowCheck(
      connFlowControlState.sumMaxObservedOffset,
      curMaxOffsetObserved - previousMaxOffsetObserved);
}

quic::Expected<void, QuicError> updateFlowControlOnRead(
    QuicStreamState& stream,
    uint64_t lastReadOffset,
    TimePoint readTime) {
  DCHECK_GE(stream.currentReadOffset, lastReadOffset);
  uint64_t diff = 0;
  if (stream.reliableSizeFromPeer &&
      stream.currentReadOffset >= *stream.reliableSizeFromPeer) {
    CHECK(stream.finalReadOffset.has_value())
        << "We got a reset from the peer, but the finalReadOffset is not set.";
    // We've read all reliable bytes, so we can advance the currentReadOffset
    // to the final size.
    diff = *stream.finalReadOffset - lastReadOffset;
    stream.currentReadOffset = *stream.finalReadOffset;
  } else {
    diff = stream.currentReadOffset - lastReadOffset;
  }
  auto incrementResult = incrementWithOverFlowCheck(
      stream.conn.flowControlState.sumCurReadOffset, diff);
  if (!incrementResult.has_value()) {
    return incrementResult;
  }
  if (maybeSendConnWindowUpdate(stream.conn, readTime)) {
    VLOG(4) << "Read trigger conn window update "
            << " readOffset=" << stream.conn.flowControlState.sumCurReadOffset
            << " maxOffset=" << stream.conn.flowControlState.advertisedMaxOffset
            << " window=" << stream.conn.flowControlState.windowSize;
  }
  if (maybeSendStreamWindowUpdate(stream, readTime)) {
    VLOG(4) << "Read trigger stream window update stream=" << stream.id
            << " readOffset=" << stream.currentReadOffset
            << " maxOffset=" << stream.flowControlState.advertisedMaxOffset
            << " window=" << stream.flowControlState.windowSize;
  }
  return {};
}

quic::Expected<void, QuicError> updateFlowControlOnReceiveReset(
    QuicStreamState& stream,
    TimePoint resetTime) {
  CHECK(stream.reliableSizeFromPeer.has_value())
      << "updateFlowControlOnReceiveReset has been called, "
      << "but reliableSizeFromPeer has not been set";
  CHECK(stream.finalReadOffset.has_value())
      << "updateFlowControlOnReceiveReset has been called, "
      << "but finalReadOffset has not been set";
  if (stream.currentReadOffset >= *stream.reliableSizeFromPeer) {
    // We only advance the currentReadOffset to the final size if the
    // application has read all of the reliable bytes. We don't do this
    // earlier because we'll buffer additional data that arrives.
    auto diff = *stream.finalReadOffset - stream.currentReadOffset;
    stream.currentReadOffset = *stream.finalReadOffset;
    auto incrementResult = incrementWithOverFlowCheck(
        stream.conn.flowControlState.sumCurReadOffset, diff);
    if (!incrementResult.has_value()) {
      return incrementResult;
    }
    if (maybeSendConnWindowUpdate(stream.conn, resetTime)) {
      VLOG(4) << "Reset trigger conn window update "
              << " readOffset=" << stream.conn.flowControlState.sumCurReadOffset
              << " maxOffset="
              << stream.conn.flowControlState.advertisedMaxOffset
              << " window=" << stream.conn.flowControlState.windowSize;
    }
  }
  return {};
}

quic::Expected<void, QuicError> updateFlowControlOnWriteToSocket(
    QuicStreamState& stream,
    uint64_t length) {
  auto incrementResult = incrementWithOverFlowCheck(
      stream.conn.flowControlState.sumCurWriteOffset, length);
  if (!incrementResult.has_value()) {
    return incrementResult;
  }
  DCHECK_GE(stream.conn.flowControlState.sumCurStreamBufferLen, length);
  stream.conn.flowControlState.sumCurStreamBufferLen -= length;
  if (stream.conn.flowControlState.sumCurWriteOffset ==
      stream.conn.flowControlState.peerAdvertisedMaxOffset) {
    if (stream.conn.qLogger) {
      stream.conn.qLogger->addTransportStateUpdate(
          getFlowControlEvent(stream.conn.flowControlState.sumCurWriteOffset));
    }
    QUIC_STATS(stream.conn.statsCallback, onConnFlowControlBlocked);
  }
  return {};
}

quic::Expected<void, QuicError> updateFlowControlOnWriteToStream(
    QuicStreamState& stream,
    uint64_t length) {
  return incrementWithOverFlowCheck(
      stream.conn.flowControlState.sumCurStreamBufferLen, length);
}

quic::Expected<void, QuicError> updateFlowControlOnResetStream(
    QuicStreamState& stream,
    Optional<uint64_t> reliableSize) {
  uint64_t decrementAmount = 0;
  if (reliableSize && *reliableSize > 0) {
    // This is the amount of pending data that we are "throwing away"
    if (stream.pendingWrites.chainLength() + stream.currentWriteOffset >
        *reliableSize) {
      decrementAmount +=
          (stream.pendingWrites.chainLength() + stream.currentWriteOffset -
           std::max(*reliableSize, stream.currentWriteOffset));
    }
  } else {
    decrementAmount = static_cast<uint64_t>(stream.pendingWrites.chainLength());
  }

  return decrementWithOverFlowCheck(
      stream.conn.flowControlState.sumCurStreamBufferLen, decrementAmount);
}

void maybeWriteBlockAfterAPIWrite(QuicStreamState& stream) {
  // Only write blocked when stream becomes blocked
  if (getSendStreamFlowControlBytesWire(stream) == 0 &&
      stream.pendingWrites.empty()) {
    stream.conn.streamManager->queueBlocked(
        stream.id, stream.flowControlState.peerAdvertisedMaxOffset);
    if (stream.conn.qLogger) {
      stream.conn.qLogger->addTransportStateUpdate(
          getFlowControlEvent(stream.conn.flowControlState.sumCurWriteOffset));
    }
    QUIC_STATS(stream.conn.statsCallback, onStreamFlowControlBlocked);
  }
}

void maybeWriteDataBlockedAfterSocketWrite(QuicConnectionStateBase& conn) {
  if (getSendConnFlowControlBytesWire(conn) == 0) {
    conn.pendingEvents.sendDataBlocked = true;
  }
  return;
}

void maybeWriteBlockAfterSocketWrite(QuicStreamState& stream) {
  // Only write blocked when the flow control bytes are used up and there are
  // still pending data
  if (stream.streamWriteError && !stream.reliableSizeToPeer) {
    // Note that we don't want to return prematurely if we've sent a reliable
    // reset to the peer, because there could still be data that we want to
    // write on the stream and we might be blocked on flow control.
    return;
  }
  if (stream.finalWriteOffset && stream.hasSentFIN()) {
    return;
  }

  bool shouldEmitStreamBlockedFrame = false;
  if (stream.conn.transportSettings.useNewStreamBlockedCondition) {
    // If we've exhausted the flow control window after the write, emit a
    // preemptive stream blocked frame.
    shouldEmitStreamBlockedFrame =
        getSendStreamFlowControlBytesWire(stream) == 0;
  } else {
    shouldEmitStreamBlockedFrame =
        getSendStreamFlowControlBytesWire(stream) == 0 &&
        !stream.pendingWrites.empty();
  }

  if (shouldEmitStreamBlockedFrame &&
      !stream.flowControlState.pendingBlockedFrame) {
    stream.conn.streamManager->queueBlocked(
        stream.id, stream.flowControlState.peerAdvertisedMaxOffset);
    stream.flowControlState.pendingBlockedFrame = true;
    if (stream.conn.qLogger) {
      stream.conn.qLogger->addTransportStateUpdate(
          getFlowControlEvent(stream.flowControlState.peerAdvertisedMaxOffset));
    }
    QUIC_STATS(stream.conn.statsCallback, onStreamFlowControlBlocked);
  }
}

void handleStreamWindowUpdate(
    QuicStreamState& stream,
    uint64_t maximumData,
    PacketNum packetNum) {
  if (stream.sendState == StreamSendState::Closed ||
      stream.sendState == StreamSendState::ResetSent) {
    // Flow control updates are not meaningful.
    return;
  }
  if (stream.flowControlState.peerAdvertisedMaxOffset <= maximumData) {
    stream.flowControlState.peerAdvertisedMaxOffset = maximumData;
    stream.flowControlState.pendingBlockedFrame = false;
    if (stream.flowControlState.peerAdvertisedMaxOffset >
        stream.currentWriteOffset + stream.pendingWrites.chainLength()) {
      updateFlowControlList(stream);
    }
    stream.conn.streamManager->updateWritableStreams(
        stream, getSendConnFlowControlBytesWire(stream.conn) > 0);
    if (stream.conn.qLogger) {
      stream.conn.qLogger->addTransportStateUpdate(
          getRxStreamWU(stream.id, packetNum, maximumData));
    }
  }
  // Peer sending a smaller max offset than previously advertised is legal but
  // ignored.
}

void handleConnWindowUpdate(
    QuicConnectionStateBase& conn,
    const MaxDataFrame& frame,
    PacketNum packetNum) {
  if (conn.flowControlState.peerAdvertisedMaxOffset <= frame.maximumData) {
    conn.flowControlState.peerAdvertisedMaxOffset = frame.maximumData;
    conn.streamManager->onMaxData();
    if (conn.qLogger) {
      conn.qLogger->addTransportStateUpdate(
          getRxConnWU(packetNum, frame.maximumData));
    }
  }
  // Peer sending a smaller max offset than previously advertised is legal but
  // ignored.
}

void handleConnBlocked(QuicConnectionStateBase& conn) {
  conn.pendingEvents.connWindowUpdate = true;
  VLOG(4) << "Blocked triggered conn window update";
}

void handleStreamBlocked(QuicStreamState& stream) {
  if (stream.conn.transportSettings.autotuneReceiveStreamFlowControl) {
    maybeIncreaseStreamFlowControlWindow(
        stream.flowControlState, Clock::now(), stream.conn.lossState.srtt);
  }
  stream.conn.streamManager->queueWindowUpdate(stream.id);
  VLOG(4) << "Blocked triggered stream window update stream=" << stream.id;
}

uint64_t getSendStreamFlowControlBytesWire(const QuicStreamState& stream) {
  DCHECK_GE(
      stream.flowControlState.peerAdvertisedMaxOffset,
      stream.nextOffsetToWrite());
  return stream.flowControlState.peerAdvertisedMaxOffset -
      stream.nextOffsetToWrite();
}

uint64_t getSendStreamFlowControlBytesAPI(const QuicStreamState& stream) {
  auto sendFlowControlBytes = getSendStreamFlowControlBytesWire(stream);
  auto dataInBuffer = stream.pendingWrites.chainLength();
  if (dataInBuffer > sendFlowControlBytes) {
    return 0;
  } else {
    return sendFlowControlBytes - dataInBuffer;
  }
}

uint64_t getSendConnFlowControlBytesWire(const QuicConnectionStateBase& conn) {
  DCHECK_GE(
      conn.flowControlState.peerAdvertisedMaxOffset,
      conn.flowControlState.sumCurWriteOffset);
  return conn.flowControlState.peerAdvertisedMaxOffset -
      conn.flowControlState.sumCurWriteOffset;
}

uint64_t getSendConnFlowControlBytesAPI(const QuicConnectionStateBase& conn) {
  auto connFlowControlBytes = getSendConnFlowControlBytesWire(conn);
  if (conn.flowControlState.sumCurStreamBufferLen > connFlowControlBytes) {
    return 0;
  } else {
    return connFlowControlBytes - conn.flowControlState.sumCurStreamBufferLen;
  }
}

uint64_t getRecvStreamFlowControlBytes(const QuicStreamState& stream) {
  if (stream.flowControlState.advertisedMaxOffset < stream.currentReadOffset) {
    // It's possible for current read offset to exceed advertised offset,
    // because of the way we handle eofs with current read offset. We increment
    // read offset to be 1 over the FIN offset to indicate that we have read the
    // FIN.
    DCHECK_EQ(
        stream.currentReadOffset,
        stream.flowControlState.advertisedMaxOffset + 1);
    return 0;
  }
  return stream.flowControlState.advertisedMaxOffset - stream.currentReadOffset;
}

uint64_t getRecvConnFlowControlBytes(const QuicConnectionStateBase& conn) {
  DCHECK_GE(
      conn.flowControlState.advertisedMaxOffset,
      conn.flowControlState.sumCurReadOffset);
  return conn.flowControlState.advertisedMaxOffset -
      conn.flowControlState.sumCurReadOffset;
}

void onConnWindowUpdateSent(
    QuicConnectionStateBase& conn,
    uint64_t maximumDataSent,
    TimePoint sentTime) {
  DCHECK_GE(maximumDataSent, conn.flowControlState.advertisedMaxOffset);
  conn.flowControlState.advertisedMaxOffset = maximumDataSent;
  conn.flowControlState.timeOfLastFlowControlUpdate = sentTime;
  conn.pendingEvents.connWindowUpdate = false;
  VLOG(4) << "sent window for conn";
}

void onStreamWindowUpdateSent(
    QuicStreamState& stream,
    uint64_t maximumDataSent,
    TimePoint sentTime) {
  stream.flowControlState.advertisedMaxOffset = maximumDataSent;
  stream.flowControlState.timeOfLastFlowControlUpdate = sentTime;
  stream.conn.streamManager->removeWindowUpdate(stream.id);
  VLOG(4) << "sent window for stream=" << stream.id;
}

void onConnWindowUpdateLost(QuicConnectionStateBase& conn) {
  conn.pendingEvents.connWindowUpdate = true;
  VLOG(4) << "Loss triggered conn window update";
}

void onStreamWindowUpdateLost(QuicStreamState& stream) {
  if (!stream.shouldSendFlowControl()) {
    return;
  }
  stream.conn.streamManager->queueWindowUpdate(stream.id);
  VLOG(4) << "Loss triggered stream window update stream=" << stream.id;
}

void onBlockedLost(QuicStreamState& stream) {
  maybeWriteBlockAfterSocketWrite(stream);
}

void onDataBlockedLost(QuicConnectionStateBase& conn) {
  maybeWriteDataBlockedAfterSocketWrite(conn);
}

void updateFlowControlList(QuicStreamState& stream) {
  stream.conn.streamManager->queueFlowControlUpdated(stream.id);
}

void updateFlowControlStateWithSettings(
    QuicConnectionStateBase::ConnectionFlowControlState& flowControlState,
    const TransportSettings& transportSettings) {
  flowControlState.windowSize =
      transportSettings.advertisedInitialConnectionFlowControlWindow;
  flowControlState.advertisedMaxOffset =
      transportSettings.advertisedInitialConnectionFlowControlWindow;
}

MaxDataFrame generateMaxDataFrame(const QuicConnectionStateBase& conn) {
  return MaxDataFrame(
      std::max(
          conn.flowControlState.sumCurReadOffset +
              conn.flowControlState.windowSize,
          conn.flowControlState.advertisedMaxOffset));
}

MaxStreamDataFrame generateMaxStreamDataFrame(const QuicStreamState& stream) {
  return MaxStreamDataFrame(stream.id, calculateMaximumData(stream));
}

} // namespace quic
