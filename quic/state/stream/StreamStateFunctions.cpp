/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <quic/state/stream/StreamStateFunctions.h>

#include <quic/flowcontrol/QuicFlowController.h>

namespace quic {

void resetQuicStream(
    QuicStreamState& stream,
    ApplicationErrorCode error,
    Optional<uint64_t> reliableSize) {
  updateFlowControlOnResetStream(stream, reliableSize);
  if (reliableSize && *reliableSize > 0) {
    stream.reliableSizeToPeer = *reliableSize;
    stream.removeFromRetransmissionBufStartingAtOffset(*reliableSize);
    stream.removeFromWriteBufStartingAtOffset(*reliableSize);
    stream.removeFromPendingWritesStartingAtOffset(*reliableSize);
    stream.removeFromLossBufStartingAtOffset(*reliableSize);
    stream.removeFromRetransmissionBufMetasStartingAtOffset(*reliableSize);
    stream.removeFromWriteBufMetaStartingAtOffset(*reliableSize);
    stream.removeFromLossBufMetasStartingAtOffset(*reliableSize);
    stream.streamWriteError = error;
  } else {
    stream.reliableSizeToPeer = folly::none;
    stream.retransmissionBuffer.clear();
    stream.writeBuffer.move();
    ChainedByteRangeHead(std::move(stream.pendingWrites)); // Will be destructed
    stream.lossBuffer.clear();
    stream.streamWriteError = error;
    stream.writeBufMeta.length = 0;
    stream.retransmissionBufMetas.clear();
    stream.lossBufMetas.clear();
    if (stream.dsrSender) {
      stream.dsrSender->release();
      stream.dsrSender.reset();
    }
  }
  stream.conn.streamManager->updateReadableStreams(stream);
  stream.conn.streamManager->updateWritableStreams(stream);
}

void onResetQuicStream(QuicStreamState& stream, const RstStreamFrame& frame) {
  if (stream.finalReadOffset &&
      stream.finalReadOffset.value() != frame.finalSize) {
    throw QuicTransportException(
        "Read offset mismatch, " +
            folly::to<std::string>(stream.finalReadOffset.value()) +
            " != " + folly::to<std::string>(frame.finalSize),
        TransportErrorCode::FINAL_SIZE_ERROR);
  }
  if (stream.reliableSizeFromPeer && frame.reliableSize &&
      *frame.reliableSize > *stream.reliableSizeFromPeer) {
    // It is legal to send a RESET_STREAM_AT frame with a lower offset
    // than before, but not to send one with a higher offset than before. Due
    // to reordering, we may receive a RESET_STREAM_AT frame with a higher
    // offset than before. In this case, we should ignore the frame.
    return;
  }

  stream.reliableSizeFromPeer =
      frame.reliableSize.hasValue() ? *frame.reliableSize : 0;
  // Mark eofoffset:
  if (stream.maxOffsetObserved > frame.finalSize) {
    throw QuicTransportException(
        "Reset in middle of stream", TransportErrorCode::FINAL_SIZE_ERROR);
  }
  // Verify that the flow control is consistent.
  updateFlowControlOnStreamData(
      stream, stream.maxOffsetObserved, frame.finalSize);
  // Drop non-reliable data:
  stream.removeFromReadBufferStartingAtOffset(*stream.reliableSizeFromPeer);
  stream.finalReadOffset = frame.finalSize;
  stream.streamReadError = frame.errorCode;
  bool appReadAllBytes = stream.currentReadOffset > *stream.finalReadOffset;
  if (!appReadAllBytes) {
    // If the currentReadOffset > finalReadOffset we have already processed
    // all the bytes until FIN, so we don't need to do anything for the read
    // side of the flow controller.
    auto lastReadOffset = stream.currentReadOffset;
    stream.currentReadOffset = frame.finalSize;
    stream.maxOffsetObserved = frame.finalSize;
    updateFlowControlOnRead(stream, lastReadOffset, Clock::now());
  }
  stream.conn.streamManager->updateReadableStreams(stream);
  stream.conn.streamManager->updateWritableStreams(stream);
  QUIC_STATS(stream.conn.statsCallback, onQuicStreamReset, frame.errorCode);
}

bool isAllDataReceived(const QuicStreamState& stream) {
  bool receivedDataTillFin = false;
  // Check if we have read everything till (inclusive) EOF
  if (stream.finalReadOffset &&
      *stream.finalReadOffset <= stream.currentReadOffset) {
    // this is the case that the last StreamFrame has FIN and no data.
    receivedDataTillFin = true;
  } else if (
      stream.finalReadOffset && stream.readBuffer.size() == 1 &&
      stream.currentReadOffset == stream.readBuffer.at(0).offset &&
      (stream.readBuffer.at(0).offset +
           stream.readBuffer.at(0).data.chainLength() ==
       stream.finalReadOffset)) {
    receivedDataTillFin = true;
  }
  return receivedDataTillFin;
}

bool isAllDataReceivedUntil(const QuicStreamState& stream, uint64_t offset) {
  if (stream.currentReadOffset > offset) {
    // The application has already read all the data until offset.
    return true;
  }

  if (!stream.readBuffer.empty() &&
      stream.currentReadOffset == stream.readBuffer.front().offset &&
      stream.readBuffer.front().offset +
              stream.readBuffer.front().data.chainLength() >
          offset) {
    // The application hasn't read all of the data until offset, but the
    // data that hasn't been read yet by the application has been
    // buffered by the QUIC layer.
    return true;
  }

  return false;
}
} // namespace quic
