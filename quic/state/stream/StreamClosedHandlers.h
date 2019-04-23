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
Handler<StreamStateMachine, StreamStates::Closed, ReadStreamFrame>::handle(
    QuicStreamState& stream,
    ReadStreamFrame frame) {
  if (isSendingStream(stream.conn.nodeType, stream.id)) {
    throw QuicTransportException(
        "ReadStreamFrame on unidirectional sending stream",
        TransportErrorCode::STREAM_STATE_ERROR);
  }
  VLOG_IF(10, frame.fin) << "Closed: Received data with fin"
                         << " stream=" << stream.id << " " << stream.conn;
  appendDataToReadBuffer(
      stream, StreamBuffer(std::move(frame.data), frame.offset, frame.fin));
}

inline void
Handler<StreamStateMachine, StreamStates::Closed, StopSendingFrame>::handle(
    QuicStreamState& stream,
    StopSendingFrame /* frame */) {
  if (isReceivingStream(stream.conn.nodeType, stream.id)) {
    throw QuicTransportException(
        "StopSendingFrame on unidirectional receiving stream",
        TransportErrorCode::STREAM_STATE_ERROR);
  }
}

inline void
Handler<StreamStateMachine, StreamStates::Closed, RstStreamFrame>::handle(
    QuicStreamState& stream,
    RstStreamFrame rst) {
  if (isSendingStream(stream.conn.nodeType, stream.id)) {
    throw QuicTransportException(
        "RstStreamFrame on unidirectional sending stream",
        TransportErrorCode::STREAM_STATE_ERROR);
  }
  // This will check whether the reset is still consistent with the stream.
  onResetQuicStream(stream, std::move(rst));
}

inline void Handler<
    StreamStateMachine,
    StreamStates::Closed,
    StreamEvents::AckStreamFrame>::
    handle(QuicStreamState& stream, StreamEvents::AckStreamFrame /*ack*/) {
  // do nothing here, we're done with handling our write data.
  if (isReceivingStream(stream.conn.nodeType, stream.id)) {
    throw QuicTransportException(
        "AckStreamFrame on unidirectional receiving stream",
        TransportErrorCode::STREAM_STATE_ERROR);
  }
  DCHECK(stream.retransmissionBuffer.empty());
  DCHECK(stream.writeBuffer.empty());
}

inline void
Handler<StreamStateMachine, StreamStates::Closed, StreamEvents::RstAck>::handle(
    QuicStreamState& stream,
    StreamEvents::RstAck /*ack*/) {
  if (isReceivingStream(stream.conn.nodeType, stream.id)) {
    throw QuicTransportException(
        "RstAck on unidirectional receiving stream",
        TransportErrorCode::STREAM_STATE_ERROR);
  }
  // Just discard the ack if we are already in Closed state.
}

inline void
Handler<StreamStateMachine, StreamStates::Closed, StreamEvents::SendReset>::
    handle(QuicStreamState& stream, StreamEvents::SendReset) {
  if (isReceivingStream(stream.conn.nodeType, stream.id)) {
    throw QuicTransportException(
        "SendReset on unidirectional receiving stream",
        TransportErrorCode::STREAM_STATE_ERROR);
  }
  // Discard the send reset.
}
} // namespace quic
