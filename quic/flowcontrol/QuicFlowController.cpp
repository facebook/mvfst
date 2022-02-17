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
#include <limits>

namespace quic {
namespace {
folly::Optional<uint64_t> calculateNewWindowUpdate(
    uint64_t curReadOffset,
    uint64_t curAdvertisedOffset,
    uint64_t windowSize,
    const std::chrono::microseconds& srtt,
    const TransportSettings& transportSettings,
    const folly::Optional<TimePoint>& lastSendTime,
    const TimePoint& updateTime) {
  DCHECK_LE(curReadOffset, curAdvertisedOffset);
  auto nextAdvertisedOffset = curReadOffset + windowSize;
  if (nextAdvertisedOffset == curAdvertisedOffset) {
    // No change in flow control
    return folly::none;
  }
  bool enoughTimeElapsed = lastSendTime && updateTime > *lastSendTime &&
      (updateTime - *lastSendTime) >
          transportSettings.flowControlRttFrequency * srtt;
  // If we are autotuning then frequent updates aren't required.
  if (enoughTimeElapsed && !transportSettings.autotuneReceiveConnFlowControl) {
    return nextAdvertisedOffset;
  }
  bool enoughWindowElapsed = (curAdvertisedOffset - curReadOffset) *
          transportSettings.flowControlWindowFrequency <
      windowSize;
  if (enoughWindowElapsed) {
    return nextAdvertisedOffset;
  }
  return folly::none;
}

template <typename T>
inline void incrementWithOverFlowCheck(T& num, T diff) {
  if (num > std::numeric_limits<T>::max() - diff) {
    throw QuicInternalException(
        "flow control state overflow", LocalErrorCode::INTERNAL_ERROR);
  }
  num += diff;
}

template <typename T>
inline void decrementWithOverFlowCheck(T& num, T diff) {
  if (num < std::numeric_limits<T>::min() + diff) {
    throw QuicInternalException(
        "flow control state overflow", LocalErrorCode::INTERNAL_ERROR);
  }
  num -= diff;
}

inline uint64_t calculateMaximumData(const QuicStreamState& stream) {
  return std::max(
      stream.currentReadOffset + stream.flowControlState.windowSize,
      stream.flowControlState.advertisedMaxOffset);
}
} // namespace

void maybeIncreaseConnectionFlowControlWindow(
    QuicConnectionStateBase::ConnectionFlowControlState& flowControlState,
    TimePoint updateTime,
    std::chrono::microseconds srtt) {
  if (!flowControlState.timeOfLastFlowControlUpdate || srtt == 0us) {
    return;
  }
  CHECK(updateTime > *flowControlState.timeOfLastFlowControlUpdate);
  if (std::chrono::duration_cast<decltype(srtt)>(
          updateTime - *flowControlState.timeOfLastFlowControlUpdate) <
      2 * srtt) {
    flowControlState.windowSize *= 2;
  }
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

void updateFlowControlOnStreamData(
    QuicStreamState& stream,
    uint64_t previousMaxOffsetObserved,
    uint64_t bufferEndOffset) {
  if (stream.flowControlState.advertisedMaxOffset < bufferEndOffset) {
    throw QuicTransportException(
        folly::to<std::string>(
            "Stream flow control violation on stream ", stream.id),
        TransportErrorCode::FLOW_CONTROL_ERROR);
  }
  auto curMaxOffsetObserved =
      std::max(previousMaxOffsetObserved, bufferEndOffset);
  auto& connFlowControlState = stream.conn.flowControlState;
  uint64_t connMaxObservedOffset = connFlowControlState.sumMaxObservedOffset;
  incrementWithOverFlowCheck(
      connMaxObservedOffset, curMaxOffsetObserved - previousMaxOffsetObserved);
  if (connMaxObservedOffset > connFlowControlState.advertisedMaxOffset) {
    throw QuicTransportException(
        "Connection flow control violation",
        TransportErrorCode::FLOW_CONTROL_ERROR);
  }
  incrementWithOverFlowCheck(
      connFlowControlState.sumMaxObservedOffset,
      curMaxOffsetObserved - previousMaxOffsetObserved);
}

void updateFlowControlOnRead(
    QuicStreamState& stream,
    uint64_t lastReadOffset,
    TimePoint readTime) {
  DCHECK_GE(stream.currentReadOffset, lastReadOffset);
  auto diff = stream.currentReadOffset - lastReadOffset;
  incrementWithOverFlowCheck(
      stream.conn.flowControlState.sumCurReadOffset, diff);
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
}

void updateFlowControlOnWriteToSocket(
    QuicStreamState& stream,
    uint64_t length) {
  incrementWithOverFlowCheck(
      stream.conn.flowControlState.sumCurWriteOffset, length);
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
}

void updateFlowControlOnWriteToStream(
    QuicStreamState& stream,
    uint64_t length) {
  incrementWithOverFlowCheck(
      stream.conn.flowControlState.sumCurStreamBufferLen, length);
}

void updateFlowControlOnResetStream(QuicStreamState& stream) {
  decrementWithOverFlowCheck(
      stream.conn.flowControlState.sumCurStreamBufferLen,
      static_cast<uint64_t>(
          stream.writeBuffer.chainLength() + stream.writeBufMeta.length));
}

void maybeWriteBlockAfterAPIWrite(QuicStreamState& stream) {
  // Only write blocked when stream becomes blocked
  if (getSendStreamFlowControlBytesWire(stream) == 0 &&
      stream.writeBuffer.empty() && stream.writeBufMeta.length == 0) {
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
  if (stream.streamWriteError) {
    return;
  }
  if (stream.finalWriteOffset && stream.hasSentFIN()) {
    return;
  }
  if (getSendStreamFlowControlBytesWire(stream) == 0 &&
      (!stream.writeBuffer.empty() || stream.writeBufMeta.length > 0)) {
    stream.conn.streamManager->queueBlocked(
        stream.id, stream.flowControlState.peerAdvertisedMaxOffset);
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
  if (stream.flowControlState.peerAdvertisedMaxOffset <= maximumData) {
    stream.flowControlState.peerAdvertisedMaxOffset = maximumData;
    if (stream.flowControlState.peerAdvertisedMaxOffset >
        stream.currentWriteOffset + stream.writeBuffer.chainLength() +
            stream.writeBufMeta.length) {
      updateFlowControlList(stream);
    }
    stream.conn.streamManager->updateWritableStreams(stream);
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
  auto dataInBuffer =
      stream.writeBuffer.chainLength() + stream.writeBufMeta.length;
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
      transportSettings.advertisedInitialConnectionWindowSize;
  flowControlState.advertisedMaxOffset =
      transportSettings.advertisedInitialConnectionWindowSize;
}

MaxDataFrame generateMaxDataFrame(const QuicConnectionStateBase& conn) {
  return MaxDataFrame(std::max(
      conn.flowControlState.sumCurReadOffset + conn.flowControlState.windowSize,
      conn.flowControlState.advertisedMaxOffset));
}

MaxStreamDataFrame generateMaxStreamDataFrame(const QuicStreamState& stream) {
  return MaxStreamDataFrame(stream.id, calculateMaximumData(stream));
}

} // namespace quic
