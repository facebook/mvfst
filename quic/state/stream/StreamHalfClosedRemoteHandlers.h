/*
 * Copyright (c) Facebook, Inc. and its affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 *
 */

// override-include-guard

#include <quic/QuicException.h>
#include <quic/state/stream/StreamStateFunctions.h>

namespace quic {

inline void
Handler<StreamStateMachine, StreamStates::HalfClosedRemote, ReadStreamFrame>::
    handle(QuicStreamState& stream, ReadStreamFrame frame) {
  VLOG_IF(10, frame.fin) << "HalfClosedRemote: Received data with fin"
                         << " stream=" << stream.id << " " << stream.conn;
  appendDataToReadBuffer(
      stream, StreamBuffer(std::move(frame.data), frame.offset, frame.fin));
}

inline void Handler<
    StreamStateMachine,
    StreamStates::HalfClosedRemote,
    StreamEvents::AckStreamFrame>::
    handle(QuicStreamState& stream, StreamEvents::AckStreamFrame ack) {
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
  CHECK_EQ(ackedBuffer->offset, ack.ackedFrame.offset);
  CHECK_EQ(ackedBuffer->data.chainLength(), ack.ackedFrame.len);

  VLOG(10) << "HalfClosedRemote: stream data acked stream=" << stream.id
           << " offset=" << ackedBuffer->offset
           << " len=" << ackedBuffer->data.chainLength()
           << " eof=" << ackedBuffer->eof << " " << stream.conn;
  stream.retransmissionBuffer.erase(ackedBuffer);
  // This stream may be able to invoke some deliveryCallbacks:
  stream.conn.streamManager->addDeliverable(stream.id);

  // Check for whether or not we have ACKed all bytes until our FIN.
  if (allBytesTillFinAcked(stream)) {
    stream.conn.streamManager->addClosed(stream.id);
    VLOG(10) << "HalfClosedRemote: Transition to closed stream=" << stream.id
             << " " << stream.conn;
    transit<StreamStates::Closed>(stream);
  }
}

inline void
Handler<StreamStateMachine, StreamStates::HalfClosedRemote, StopSendingFrame>::
    handle(QuicStreamState& stream, StopSendingFrame frame) {
  stream.conn.streamManager->addStopSending(stream.id, frame.errorCode);
}

inline void
Handler<StreamStateMachine, StreamStates::HalfClosedRemote, RstStreamFrame>::
    handle(QuicStreamState& stream, RstStreamFrame rst) {
  // We transit before invoking onResetQuicStream because it will check the
  // state of the stream for flow control.
  transit<StreamStates::WaitingForRstAck>(stream);
  onResetQuicStream(stream, std::move(rst));
  // TODO: remove.
  appendPendingStreamReset(stream.conn, stream, ApplicationErrorCode::STOPPING);
}

inline void Handler<
    StreamStateMachine,
    StreamStates::HalfClosedRemote,
    StreamEvents::SendReset>::
    handle(QuicStreamState& stream, StreamEvents::SendReset rst) {
  resetQuicStream(stream, rst.errorCode);
  appendPendingStreamReset(stream.conn, stream, rst.errorCode);
  // Move the state machine:
  transit<StreamStates::WaitingForRstAck>(stream);
}
} // namespace quic
