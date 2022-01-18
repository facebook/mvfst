/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <quic/state/stream/StreamStateFunctions.h>

#include <quic/flowcontrol/QuicFlowController.h>

namespace quic {

void resetQuicStream(QuicStreamState& stream, ApplicationErrorCode error) {
  updateFlowControlOnResetStream(stream);
  stream.retransmissionBuffer.clear();
  stream.writeBuffer.move();
  stream.readBuffer.clear();
  stream.lossBuffer.clear();
  stream.streamWriteError = error;
  stream.writeBufMeta.length = 0;
  stream.retransmissionBufMetas.clear();
  stream.lossBufMetas.clear();
  if (stream.dsrSender) {
    stream.dsrSender->release();
    stream.dsrSender.reset();
  }
  stream.conn.streamManager->updateReadableStreams(stream);
  stream.conn.streamManager->updateWritableStreams(stream);
  stream.conn.streamManager->removeLoss(stream.id);
}

void onResetQuicStream(QuicStreamState& stream, const RstStreamFrame& frame) {
  if (stream.finalReadOffset &&
      stream.finalReadOffset.value() != frame.offset) {
    throw QuicTransportException(
        "Read offset mismatch, " +
            folly::to<std::string>(stream.finalReadOffset.value()) +
            " != " + folly::to<std::string>(frame.offset),
        TransportErrorCode::FINAL_SIZE_ERROR);
  }
  // Mark eofoffset:
  if (stream.maxOffsetObserved > frame.offset) {
    throw QuicTransportException(
        "Reset in middle of stream", TransportErrorCode::FINAL_SIZE_ERROR);
  }
  // Verify that the flow control is consistent.
  updateFlowControlOnStreamData(stream, stream.maxOffsetObserved, frame.offset);
  // Drop read buffer:
  stream.readBuffer.clear();
  stream.finalReadOffset = frame.offset;
  stream.streamReadError = frame.errorCode;
  bool appReadAllBytes = stream.finalReadOffset &&
      stream.currentReadOffset > *stream.finalReadOffset;
  if (!appReadAllBytes) {
    // If the currentReadOffset > finalReadOffset we have already processed
    // all the bytes until FIN, so we don't need to do anything for the read
    // side of the flow controller.
    auto lastReadOffset = stream.currentReadOffset;
    stream.currentReadOffset = frame.offset;
    stream.maxOffsetObserved = frame.offset;
    updateFlowControlOnRead(stream, lastReadOffset, Clock::now());
  }
  stream.conn.streamManager->updateReadableStreams(stream);
  stream.conn.streamManager->updateWritableStreams(stream);
  stream.conn.streamManager->updateLossStreams(stream);
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
