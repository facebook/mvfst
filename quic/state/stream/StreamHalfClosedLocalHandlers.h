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
Handler<StreamStateMachine, StreamStates::HalfClosedLocal, RstStreamFrame>::
    handle(QuicStreamState& stream, RstStreamFrame rst) {
  // We transition before invoking onResetQuicStream so that reset stream
  // can use the state to make decisions.
  VLOG(10) << "HalfClosedLocal: Received reset, transition to closed"
           << " stream=" << stream.id << " " << stream.conn;
  transit<StreamStates::Closed>(stream);
  onResetQuicStream(stream, std::move(rst));
  stream.conn.streamManager->addClosed(stream.id);
}

inline void
Handler<StreamStateMachine, StreamStates::HalfClosedLocal, ReadStreamFrame>::
    handle(QuicStreamState& stream, ReadStreamFrame frame) {
  VLOG_IF(10, frame.fin) << "HalfClosedLocal: Received data with fin"
                         << " stream=" << stream.id
                         << " offset=" << frame.offset
                         << " readOffset=" << stream.currentReadOffset << " "
                         << stream.conn;
  appendDataToReadBuffer(
      stream, StreamBuffer(std::move(frame.data), frame.offset, frame.fin));
  if (isAllDataReceived(stream)) {
    stream.conn.streamManager->addClosed(stream.id);
    VLOG(10) << "HalfClosedLocal: Transition to closed"
             << " stream=" << stream.id << " " << stream.conn;
    transit<StreamStates::Closed>(stream);
  }
  stream.conn.streamManager->updateReadableStreams(stream);
}

inline void Handler<
    StreamStateMachine,
    StreamStates::HalfClosedLocal,
    StreamEvents::AckStreamFrame>::
    handle(QuicStreamState& stream, StreamEvents::AckStreamFrame /*ack*/) {
  // do nothing here, we already got acks for all the bytes till fin.
  DCHECK(stream.retransmissionBuffer.empty());
  DCHECK(stream.writeBuffer.empty());
}

inline void
Handler<StreamStateMachine, StreamStates::HalfClosedLocal, StopSendingFrame>::
    handle(QuicStreamState& /*stream*/, StopSendingFrame /*frame*/) {}

inline void Handler<
    StreamStateMachine,
    StreamStates::HalfClosedLocal,
    StreamEvents::SendReset>::
    handle(QuicStreamState& stream, StreamEvents::SendReset rst) {
  resetQuicStream(stream, rst.errorCode);
  appendPendingStreamReset(stream.conn, stream, rst.errorCode);
  // Move the state machine:
  VLOG(10) << "HalfClosedLocal: Transition to WaitingForRstAck"
           << " stream=" << stream.id << " " << stream.conn;
  transit<StreamStates::WaitingForRstAck>(stream);
}
} // namespace quic
