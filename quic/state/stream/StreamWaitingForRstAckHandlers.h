/*
 * Copyright (c) Facebook, Inc. and its affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 *
 */

// override-include-guard

#include <quic/state/stream/StreamStateFunctions.h>

namespace quic {

inline void
Handler<StreamStateMachine, StreamStates::WaitingForRstAck, ReadStreamFrame>::
    handle(QuicStreamState& stream, ReadStreamFrame frame) {
  if (isSendingStream(stream.conn.nodeType, stream.id)) {
    throw QuicTransportException(
        "ReadStreamFrame on unidirectional sending stream",
        TransportErrorCode::STREAM_STATE_ERROR);
  }
  VLOG_IF(10, frame.fin) << "WaitingForRstAck: Received data with fin"
                         << " stream=" << stream.id << " " << stream.conn;
  appendDataToReadBuffer(
      stream, StreamBuffer(std::move(frame.data), frame.offset, frame.fin));
}

inline void Handler<
    StreamStateMachine,
    StreamStates::WaitingForRstAck,
    StreamEvents::AckStreamFrame>::
    handle(QuicStreamState& stream, StreamEvents::AckStreamFrame /*ack*/) {
  // do nothing here. We should have already dumped the stream state before
  // we got here.
  DCHECK(stream.retransmissionBuffer.empty());
  DCHECK(stream.writeBuffer.empty());
}

inline void
Handler<StreamStateMachine, StreamStates::WaitingForRstAck, StopSendingFrame>::
    handle(QuicStreamState& stream, StopSendingFrame /*frame*/) {
  if (isReceivingStream(stream.conn.nodeType, stream.id)) {
    throw QuicTransportException(
        "StopSendingFrame on unidirectional receiving stream",
        TransportErrorCode::STREAM_STATE_ERROR);
  }
}

inline void
Handler<StreamStateMachine, StreamStates::WaitingForRstAck, RstStreamFrame>::
    handle(QuicStreamState& stream, RstStreamFrame rst) {
  if (isSendingStream(stream.conn.nodeType, stream.id)) {
    throw QuicTransportException(
        "RstStreamFrame on unidirectional sending stream",
        TransportErrorCode::STREAM_STATE_ERROR);
  }
  // This will make sure all the states are consistent between resets.
  onResetQuicStream(stream, std::move(rst));
}

inline void Handler<
    StreamStateMachine,
    StreamStates::WaitingForRstAck,
    StreamEvents::RstAck>::
    handle(QuicStreamState& stream, StreamEvents::RstAck /*ack*/) {
  stream.conn.streamManager->addClosed(stream.id);
  VLOG(10) << "WaitingForRstAck: Transition to closed stream=" << stream.id
           << " " << stream.conn;
  transit<StreamStates::Closed>(stream);
}

inline void Handler<
    StreamStateMachine,
    StreamStates::WaitingForRstAck,
    StreamEvents::SendReset>::
    handle(QuicStreamState& /*stream*/, StreamEvents::SendReset) {
  // do nothing.
}
} // namespace quic
