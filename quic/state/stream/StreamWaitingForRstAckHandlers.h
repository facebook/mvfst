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
inline void Handler<
    StreamSendStateMachine,
    StreamSendStates::ResetSent,
    StreamEvents::AckStreamFrame>::
    handle(
        QuicStreamState::Send& /*state*/,
        StreamEvents::AckStreamFrame /*ack*/,
        QuicStreamState& stream) {
  // do nothing here. We should have already dumped the stream state before
  // we got here.
  DCHECK(stream.retransmissionBuffer.empty());
  DCHECK(stream.writeBuffer.empty());
}

inline void
Handler<StreamSendStateMachine, StreamSendStates::ResetSent, StopSendingFrame>::
    handle(
        QuicStreamState::Send& /*state*/,
        StopSendingFrame /*frame*/,
        QuicStreamState& /*stream*/) {
  // no-op, we already sent a reset
}

inline void Handler<
    StreamSendStateMachine,
    StreamSendStates::ResetSent,
    StreamEvents::RstAck>::
    handle(
        QuicStreamState::Send& state,
        StreamEvents::RstAck /*ack*/,
        QuicStreamState& stream) {
  VLOG(10) << "ResetSent: Transition to closed stream=" << stream.id << " "
           << stream.conn;
  transit<StreamSendStates::Closed>(state);
  if (stream.inTerminalStates()) {
    stream.conn.streamManager->addClosed(stream.id);
  }
}

inline void Handler<
    StreamSendStateMachine,
    StreamSendStates::ResetSent,
    StreamEvents::SendReset>::
    handle(
        QuicStreamState::Send& /*state*/,
        StreamEvents::SendReset,
        QuicStreamState& /*stream*/) {
  // do nothing.
}
} // namespace quic
