/*
 * Copyright (c) Facebook, Inc. and its affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 *
 */

// override-include-guard

#include <quic/state/QuicStreamUtilities.h>
#include <quic/state/stream/StreamStateFunctions.h>

namespace quic {

inline void
Handler<StreamStateMachine, StreamStates::Open, ReadStreamFrame>::handle(
    QuicStreamState& stream,
    ReadStreamFrame frame) {
  if (isSendingStream(stream.conn.nodeType, stream.id)) {
    throw QuicTransportException(
        "ReadStreamFrame on unidirectional sending stream",
        TransportErrorCode::STREAM_STATE_ERROR);
  }
  VLOG_IF(10, frame.fin) << "Open: Received data with fin"
                         << " stream=" << stream.id << " " << stream.conn;
  appendDataToReadBuffer(
      stream, StreamBuffer(std::move(frame.data), frame.offset, frame.fin));
  if (isAllDataReceived(stream)) {
    if (isUnidirectionalStream(stream.id)) {
      VLOG(10) << "Open: Transition to Closed"
               << " stream=" << stream.id << " " << stream.conn;
      transit<StreamStates::Closed>(stream);
    } else {
      VLOG(10) << "Open: Transition to HalfClosedRemote"
               << " stream=" << stream.id << " " << stream.conn;
      transit<StreamStates::HalfClosedRemote>(stream);
    }
  }
  stream.conn.streamManager->updateReadableStreams(stream);
}

inline void
Handler<StreamStateMachine, StreamStates::Open, StopSendingFrame>::handle(
    QuicStreamState& stream,
    StopSendingFrame frame) {
  if (isBidirectionalStream(stream.id) ||
      isSendingStream(stream.conn.nodeType, stream.id)) {
    stream.conn.streamManager->addStopSending(stream.id, frame.errorCode);
  } else {
    throw QuicTransportException(
        "StopSendingFrame on unidirectional receiving stream",
        TransportErrorCode::STREAM_STATE_ERROR);
  }
}

inline void
Handler<StreamStateMachine, StreamStates::Open, RstStreamFrame>::handle(
    QuicStreamState& stream,
    RstStreamFrame rst) {
  if (isSendingStream(stream.conn.nodeType, stream.id)) {
    throw QuicTransportException(
        "RstStreamFrame on unidirectional sending stream",
        TransportErrorCode::STREAM_STATE_ERROR);
  }
  // We transit before invoking onResetQuicStream because it will check the
  // state of the stream for flow control.
  transit<StreamStates::WaitingForRstAck>(stream);
  onResetQuicStream(stream, std::move(rst));
  if (isBidirectionalStream(stream.id)) {
    // TODO: remove.
    appendPendingStreamReset(
        stream.conn, stream, GenericApplicationErrorCode::NO_ERROR);
  } else {
    transit<StreamStates::Closed>(stream);
  }
}

inline void
Handler<StreamStateMachine, StreamStates::Open, StreamEvents::SendReset>::
    handle(QuicStreamState& stream, StreamEvents::SendReset rst) {
  if (isReceivingStream(stream.conn.nodeType, stream.id)) {
    throw QuicTransportException(
        "SendReset on unidirectional receiving stream",
        TransportErrorCode::STREAM_STATE_ERROR);
  }
  resetQuicStream(stream, rst.errorCode);
  appendPendingStreamReset(stream.conn, stream, rst.errorCode);
  // Move the state machine:
  transit<StreamStates::WaitingForRstAck>(stream);
}

inline void
Handler<StreamStateMachine, StreamStates::Open, StreamEvents::AckStreamFrame>::
    handle(QuicStreamState& stream, StreamEvents::AckStreamFrame ack) {
  if (isReceivingStream(stream.conn.nodeType, stream.id)) {
    throw QuicTransportException(
        "AckStreamFrame on unidirectional receiving stream",
        TransportErrorCode::STREAM_STATE_ERROR);
  }
  // Clean up the acked buffers from the retransmissionBuffer.

  auto ackedBuffer = std::lower_bound(
      stream.retransmissionBuffer.begin(),
      stream.retransmissionBuffer.end(),
      ack.ackedFrame.offset,
      [](const auto& buffer, const auto& offset) {
        return buffer.offset < offset;
      });

  // Since the StreamFrames that are ACKed are computed from the outstanding
  // packets, we always know that the retransmission buffer corresponds to
  // 1 buffer in the retranmission buffer.
  CHECK(ackedBuffer != stream.retransmissionBuffer.end());
  DCHECK_EQ(ackedBuffer->offset, ack.ackedFrame.offset);

  DCHECK_EQ(ackedBuffer->data.chainLength(), ack.ackedFrame.len);
  DCHECK_EQ(ackedBuffer->eof, ack.ackedFrame.fin);

  VLOG(10) << "Open: acked stream data stream=" << stream.id
           << " offset=" << ackedBuffer->offset
           << " len=" << ackedBuffer->data.chainLength()
           << " eof=" << ackedBuffer->eof << " " << stream.conn;
  stream.retransmissionBuffer.erase(ackedBuffer);
  // This stream may be able to invoke some deliveryCallbacks:
  stream.conn.streamManager->addDeliverable(stream.id);

  // Check for whether or not we have ACKed all bytes until our FIN.
  if (allBytesTillFinAcked(stream)) {
    if (isUnidirectionalStream(stream.id)) {
      transit<StreamStates::Closed>(stream);
    } else {
      transit<StreamStates::HalfClosedLocal>(stream);
    }
  }
}
} // namespace quic
