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
  // Mark eofoffset:
  if (stream.maxOffsetObserved > frame.finalSize) {
    throw QuicTransportException(
        "Reset in middle of stream", TransportErrorCode::FINAL_SIZE_ERROR);
  }
  // Verify that the flow control is consistent.
  updateFlowControlOnStreamData(
      stream, stream.maxOffsetObserved, frame.finalSize);
  // Drop read buffer:
  stream.readBuffer.clear();
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
} // namespace quic
