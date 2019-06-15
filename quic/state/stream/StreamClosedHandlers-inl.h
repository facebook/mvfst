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
inline void Handler<
    StreamReceiveStateMachine,
    StreamReceiveStates::Closed,
    ReadStreamFrame>::
    handle(
        QuicStreamState::Recv& /*state*/,
        ReadStreamFrame&& frame,
        QuicStreamState& stream) {
  CHECK(!isSendingStream(stream.conn.nodeType, stream.id));
  VLOG_IF(10, frame.fin) << "Closed: Received data with fin"
                         << " stream=" << stream.id << " " << stream.conn;
  appendDataToReadBuffer(
      stream, StreamBuffer(std::move(frame.data), frame.offset, frame.fin));
}

inline void
Handler<StreamSendStateMachine, StreamSendStates::Closed, StopSendingFrame>::
    handle(
        QuicStreamState::Send& /*state*/,
        StopSendingFrame&& /*frame*/,
        QuicStreamState& /*stream*/) {
  // no-op, we're already done sending
}

inline void Handler<
    StreamReceiveStateMachine,
    StreamReceiveStates::Closed,
    RstStreamFrame>::
    handle(
        QuicStreamState::Recv& /*state*/,
        RstStreamFrame&& rst,
        QuicStreamState& stream) {
  // This will check whether the reset is still consistent with the stream.
  onResetQuicStream(stream, std::move(rst));
}

inline void Handler<
    StreamSendStateMachine,
    StreamSendStates::Closed,
    StreamEvents::AckStreamFrame>::
    handle(
        QuicStreamState::Send& /*state*/,
        StreamEvents::AckStreamFrame&& /*ack*/,
        QuicStreamState& stream) {
  DCHECK(stream.retransmissionBuffer.empty());
  DCHECK(stream.writeBuffer.empty());
}

inline void Handler<
    StreamSendStateMachine,
    StreamSendStates::Closed,
    StreamEvents::RstAck>::
    handle(
        QuicStreamState::Send& /*state*/,
        StreamEvents::RstAck&& /*ack*/,
        QuicStreamState& /*stream*/) {
  // Just discard the ack if we are already in Closed state.
}

inline void Handler<
    StreamSendStateMachine,
    StreamSendStates::Closed,
    StreamEvents::SendReset>::
    handle(
        QuicStreamState::Send& /*state*/,
        StreamEvents::SendReset&&,
        QuicStreamState& /*stream*/) {
  // TODO: remove this as a valid state transition
  VLOG(4) << "Ignoring SendReset from closed state.";
  // Discard the send reset.
}
} // namespace quic
