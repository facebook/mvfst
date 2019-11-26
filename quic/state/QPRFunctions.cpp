/*
 * Copyright (c) Facebook, Inc. and its affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 *
 */

#include <quic/state/QPRFunctions.h>
#include <quic/flowcontrol/QuicFlowController.h>
#include <quic/state/QuicStreamFunctions.h>
#include <quic/state/QuicStreamUtilities.h>

namespace quic {
namespace {

// shrink the buffers until offset, either by popping up or trimming from start
void shrinkBuffers(std::deque<StreamBuffer>& buffers, uint64_t offset) {
  while (!buffers.empty()) {
    auto curr = buffers.begin();
    if (curr->offset >= offset) {
      // the buffers are supposed to be sorted, so we are done here
      break;
    }
    size_t currSize = curr->data.chainLength();
    if (curr->offset + currSize <= offset) {
      buffers.pop_front();
    } else {
      uint64_t amount = offset - curr->offset;
      curr->data.trimStartAtMost(amount);
      curr->offset += amount;
      break;
    }
  }
}

void shrinkBuffers(
    folly::F14FastMap<uint64_t, StreamBuffer>& buffers,
    uint64_t offset) {
  // Do a linear search of the entire buffer, there can be exactly one trimmed
  // buffer, since we are changing the offset for that single buffer we need to
  // change the offset in the StreamBuffer, but keep it keyed on the same
  // offset as before so we still remove it on ack.
  for (auto itr = buffers.begin(); itr != buffers.end();) {
    if (itr->second.offset >= offset) {
      itr++;
      continue;
    }
    if (itr->second.offset + itr->second.data.chainLength() <= offset) {
      itr = buffers.erase(itr);
    } else {
      uint64_t amount = offset - itr->second.offset;
      itr->second.data.trimStartAtMost(amount);
      itr->second.offset += amount;
      itr++;
    }
  }
}

void shrinkRetransmittableBuffers(
    QuicStreamState* stream,
    uint64_t minimumRetransmittableOffset) {
  if (minimumRetransmittableOffset > stream->currentWriteOffset) {
    uint64_t amount = minimumRetransmittableOffset - stream->currentWriteOffset;
    auto trimmed = stream->writeBuffer.trimStartAtMost(amount);
    stream->currentWriteOffset = minimumRetransmittableOffset;

    // pretends we sent extra bits here as we moved currentWriteOffset
    updateFlowControlOnWriteToStream(*stream, amount - trimmed);
    updateFlowControlOnWriteToSocket(*stream, amount);
    maybeWriteBlockAfterSocketWrite(*stream);
    stream->conn.streamManager->updateWritableStreams(*stream);
  }
  VLOG(10) << __func__ << ": shrinking retransmissionBuffer to "
           << minimumRetransmittableOffset;
  shrinkBuffers(stream->retransmissionBuffer, minimumRetransmittableOffset);
  shrinkBuffers(stream->lossBuffer, minimumRetransmittableOffset);
}

void shrinkReadBuffer(QuicStreamState* stream) {
  if (stream->currentReceiveOffset > 0) {
    uint64_t offsetSeen = stream->currentReceiveOffset - 1;
    updateFlowControlOnStreamData(
        *stream, stream->maxOffsetObserved, offsetSeen);
    stream->maxOffsetObserved = std::max(stream->maxOffsetObserved, offsetSeen);
  }
  uint64_t lastReadOffset = stream->currentReadOffset;
  stream->currentReadOffset = stream->currentReceiveOffset;
  shrinkBuffers(stream->readBuffer, stream->currentReadOffset);

  // pretends we read stream.currentReadOffset - lastReadOffset bytes
  updateFlowControlOnRead(*stream, lastReadOffset, Clock::now());
  // may become readable after shrink
  stream->conn.streamManager->updateReadableStreams(*stream);
  stream->conn.streamManager->updatePeekableStreams(*stream);
}
} // namespace

folly::Optional<uint64_t> advanceCurrentReceiveOffset(
    QuicStreamState* stream,
    uint64_t offset) {
  if (offset <= stream->currentReceiveOffset ||
      offset <= stream->currentReadOffset) {
    return folly::none;
  }

  // do not go beyond EOF offset
  if (stream->finalReadOffset) {
    offset = std::min(offset, *stream->finalReadOffset);
  }
  stream->currentReceiveOffset = offset;
  shrinkReadBuffer(stream);

  // Check if we have a pending MinStreamDataFrame for this stream
  auto& frames = stream->conn.pendingEvents.frames;
  auto it = find_if(frames.begin(), frames.end(), [&](QuicSimpleFrame& frame) {
    MinStreamDataFrame* minStreamData = frame.asMinStreamDataFrame();
    if (!minStreamData) {
      return false;
    }
    return minStreamData->streamId == stream->id;
  });

  MinStreamDataFrame minStreamDataFrame = generateMinStreamDataFrame(*stream);
  if (it == frames.end()) {
    frames.emplace_back(minStreamDataFrame);
  } else {
    // update existing pending MinStreamDataFrame
    MinStreamDataFrame& frame = *it->asMinStreamDataFrame();
    frame = minStreamDataFrame;
  }
  return offset;
}

void onRecvMinStreamDataFrame(
    QuicStreamState* stream,
    const MinStreamDataFrame& frame,
    PacketNum packetNum) {
  if (isReceivingStream(stream->conn.nodeType, stream->id) ||
      (isSendingStream(stream->conn.nodeType, stream->id) &&
       stream->sendState != StreamSendState::Open_E)) {
    throw QuicTransportException(
        "MinStreamDataFrame on receiving-only stream or "
        "sending-only stream but not opened",
        TransportErrorCode::PROTOCOL_VIOLATION);
  }

  if (frame.maximumData < frame.minimumStreamOffset) {
    throw QuicTransportException(
        "Invalid data",
        TransportErrorCode::FRAME_ENCODING_ERROR,
        FrameType::MIN_STREAM_DATA);
  }

  if (frame.minimumStreamOffset <= stream->minimumRetransmittableOffset) {
    // nothing to do
    return;
  }

  handleStreamWindowUpdate(*stream, frame.maximumData, packetNum);

  uint64_t minimumStreamOffset = frame.minimumStreamOffset;
  // do not go beyond EOF offset
  if (stream->finalWriteOffset) {
    minimumStreamOffset =
        std::min(minimumStreamOffset, *stream->finalWriteOffset);
  }
  stream->minimumRetransmittableOffset = minimumStreamOffset;
  shrinkRetransmittableBuffers(stream, stream->minimumRetransmittableOffset);

  // remove the stale pending ExpiredStreamDataFrame if exists
  auto& frames = stream->conn.pendingEvents.frames;
  auto it = find_if(frames.begin(), frames.end(), [&](QuicSimpleFrame& frame) {
    ExpiredStreamDataFrame* expiredFrame = frame.asExpiredStreamDataFrame();
    if (!expiredFrame) {
      return false;
    }
    return expiredFrame->minimumStreamOffset <=
        stream->minimumRetransmittableOffset;
  });
  if (it != frames.end()) {
    frames.erase(it);
  }
  stream->conn.streamManager->addDataRejected(stream->id);
}

folly::Optional<uint64_t> advanceMinimumRetransmittableOffset(
    QuicStreamState* stream,
    uint64_t minimumStreamOffset) {
  if (minimumStreamOffset <= stream->minimumRetransmittableOffset) {
    return folly::none;
  }

  // take flow control into consideration
  minimumStreamOffset = std::min(
      minimumStreamOffset, stream->flowControlState.peerAdvertisedMaxOffset);
  // do not go beyond EOF offset
  if (stream->finalWriteOffset) {
    minimumStreamOffset =
        std::min(minimumStreamOffset, *stream->finalWriteOffset);
  }
  stream->minimumRetransmittableOffset = minimumStreamOffset;

  shrinkRetransmittableBuffers(stream, stream->minimumRetransmittableOffset);
  auto& frames = stream->conn.pendingEvents.frames;
  auto it = find_if(frames.begin(), frames.end(), [&](QuicSimpleFrame& frame) {
    ExpiredStreamDataFrame* expiredFrame = frame.asExpiredStreamDataFrame();
    if (!expiredFrame) {
      return false;
    }
    return expiredFrame->streamId == stream->id;
  });

  if (it == frames.end()) {
    frames.emplace_back(
        ExpiredStreamDataFrame(stream->id, minimumStreamOffset));
  } else {
    // update the existing pending ExpiredStreamDataFrame
    ExpiredStreamDataFrame& frame = *it->asExpiredStreamDataFrame();
    frame.minimumStreamOffset = minimumStreamOffset;
  }
  return minimumStreamOffset;
}

void onRecvExpiredStreamDataFrame(
    QuicStreamState* stream,
    const ExpiredStreamDataFrame& frame) {
  if (isSendingStream(stream->conn.nodeType, stream->id)) {
    throw QuicTransportException(
        "ExpiredStreamDataFrame on unidirectional sending stream",
        TransportErrorCode::PROTOCOL_VIOLATION);
  }

  // ignore the frames that don't advance the offset.
  // this may happen due to loss and reordering
  if (frame.minimumStreamOffset <= stream->currentReceiveOffset ||
      frame.minimumStreamOffset <= stream->currentReadOffset) {
    return;
  }

  uint64_t minimumStreamOffset = frame.minimumStreamOffset;
  // do not go beyond EOF offset
  if (stream->finalReadOffset) {
    minimumStreamOffset =
        std::min(minimumStreamOffset, *stream->finalReadOffset);
  }
  stream->currentReceiveOffset = minimumStreamOffset;
  shrinkReadBuffer(stream);

  // remove the stale pending MinStreamDataFrame if exists
  auto& frames = stream->conn.pendingEvents.frames;
  auto it = find_if(frames.begin(), frames.end(), [&](QuicSimpleFrame& frame) {
    MinStreamDataFrame* minStreamData = frame.asMinStreamDataFrame();
    if (!minStreamData) {
      return false;
    }
    return minStreamData->minimumStreamOffset <= stream->currentReceiveOffset;
  });
  if (it != frames.end()) {
    frames.erase(it);
  }
  stream->conn.streamManager->addDataExpired(stream->id);
}
} // namespace quic
