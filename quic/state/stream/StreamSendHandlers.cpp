/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <quic/state/stream/StreamSendHandlers.h>

#include <quic/flowcontrol/QuicFlowController.h>
#include <quic/state/QuicStreamFunctions.h>

namespace quic {

/**
 *  Welcome to the send state machine, we got fun and games.
 *
 * This is a simplified version of the send state machine defined in the
 * transport specification.  The "Invalid" state is used for unidirectional
 * streams that do not have that half (eg: an ingress uni stream is in send
 * state Invalid)
 *
 * Send State Machine
 * ==================
 *
 * [ Initial State ]
 *      |
 *      | Send Stream
 *      |
 *      v
 * Send::Open ---------------+
 *      |                    |
 *      | Ack all bytes      | Send RST
 *      | ti FIN             |
 *      v                    v
 * Send::Closed <------  ResetSent
 *                RST
 *                Acked
 */

void sendStopSendingSMHandler(
    QuicStreamState& stream,
    const StopSendingFrame& frame) {
  switch (stream.sendState) {
    case StreamSendState::Open: {
      CHECK(
          isBidirectionalStream(stream.id) ||
          isSendingStream(stream.conn.nodeType, stream.id));
      if (stream.conn.nodeType == QuicNodeType::Server &&
          getSendStreamFlowControlBytesWire(stream) == 0 &&
          !stream.finalWriteOffset) {
        VLOG(3) << "Client gives up a flow control blocked stream";
      }
      stream.conn.streamManager->addStopSending(stream.id, frame.errorCode);
      break;
    }
    case StreamSendState::Closed: {
      break;
    }
    case StreamSendState::ResetSent: {
      // no-op, we already sent a reset
      break;
    }
    case StreamSendState::Invalid: {
      throw QuicTransportException(
          folly::to<std::string>(
              "Invalid transition from state=",
              streamStateToString(stream.sendState)),
          TransportErrorCode::STREAM_STATE_ERROR);
    }
  }
}

void sendRstSMHandler(QuicStreamState& stream, ApplicationErrorCode errorCode) {
  switch (stream.sendState) {
    case StreamSendState::Open: {
      resetQuicStream(stream, errorCode);
      appendPendingStreamReset(stream.conn, stream, errorCode);
      stream.sendState = StreamSendState::ResetSent;
      break;
    }
    case StreamSendState::Closed: {
      VLOG(4) << "Ignoring SendReset from closed state.";
      break;
    }
    case StreamSendState::ResetSent: {
      // do nothing
      break;
    }
    case StreamSendState::Invalid: {
      throw QuicTransportException(
          folly::to<std::string>(
              "Invalid transition from state=",
              streamStateToString(stream.sendState)),
          TransportErrorCode::STREAM_STATE_ERROR);
    }
  }
}

void sendAckSMHandler(
    QuicStreamState& stream,
    const WriteStreamFrame& ackedFrame) {
  switch (stream.sendState) {
    case StreamSendState::Open: {
      if (!ackedFrame.fromBufMeta) {
        // Clean up the acked buffers from the retransmissionBuffer.
        auto ackedBuffer = stream.retransmissionBuffer.find(ackedFrame.offset);
        if (ackedBuffer != stream.retransmissionBuffer.end()) {
          CHECK_EQ(ackedFrame.offset, ackedBuffer->second->offset);
          CHECK_EQ(ackedFrame.len, ackedBuffer->second->data.chainLength());
          CHECK_EQ(ackedFrame.fin, ackedBuffer->second->eof);
          VLOG(10) << "Open: acked stream data stream=" << stream.id
                   << " offset=" << ackedBuffer->second->offset
                   << " len=" << ackedBuffer->second->data.chainLength()
                   << " eof=" << ackedBuffer->second->eof << " " << stream.conn;
          stream.updateAckedIntervals(
              ackedBuffer->second->offset,
              ackedBuffer->second->data.chainLength(),
              ackedBuffer->second->eof);
          stream.retransmissionBuffer.erase(ackedBuffer);
        }
      } else {
        auto ackedBuffer =
            stream.retransmissionBufMetas.find(ackedFrame.offset);
        if (ackedBuffer != stream.retransmissionBufMetas.end()) {
          CHECK_EQ(ackedFrame.offset, ackedBuffer->second.offset);
          CHECK_EQ(ackedFrame.len, ackedBuffer->second.length);
          CHECK_EQ(ackedFrame.fin, ackedBuffer->second.eof);
          VLOG(10) << "Open: acked stream data bufmeta=" << stream.id
                   << " offset=" << ackedBuffer->second.offset
                   << " len=" << ackedBuffer->second.length
                   << " eof=" << ackedBuffer->second.eof << " " << stream.conn;
          stream.updateAckedIntervals(
              ackedBuffer->second.offset,
              ackedBuffer->second.length,
              ackedBuffer->second.eof);
          stream.retransmissionBufMetas.erase(ackedBuffer);
        }
      }

      // This stream may be able to invoke some deliveryCallbacks:
      stream.conn.streamManager->addDeliverable(stream.id);

      // Check for whether or not we have ACKed all bytes until our FIN.
      if (allBytesTillFinAcked(stream)) {
        stream.sendState = StreamSendState::Closed;
        if (stream.inTerminalStates()) {
          stream.conn.streamManager->addClosed(stream.id);
        }
      }
      break;
    }
    case StreamSendState::Closed:
    case StreamSendState::ResetSent: {
      DCHECK(stream.retransmissionBuffer.empty());
      DCHECK(stream.writeBuffer.empty());
      break;
    }
    case StreamSendState::Invalid: {
      throw QuicTransportException(
          folly::to<std::string>(
              "Invalid transition from state=",
              streamStateToString(stream.sendState)),
          TransportErrorCode::STREAM_STATE_ERROR);
      break;
    }
  }
}

void sendRstAckSMHandler(QuicStreamState& stream) {
  switch (stream.sendState) {
    case StreamSendState::ResetSent: {
      VLOG(10) << "ResetSent: Transition to closed stream=" << stream.id << " "
               << stream.conn;
      stream.sendState = StreamSendState::Closed;
      if (stream.inTerminalStates()) {
        stream.conn.streamManager->addClosed(stream.id);
      }
      break;
    }
    case StreamSendState::Closed: {
      // Just discard the ack if we are already in Closed state.
      break;
    }
    case StreamSendState::Open:
    case StreamSendState::Invalid: {
      throw QuicTransportException(
          folly::to<std::string>(
              "Invalid transition from state=",
              streamStateToString(stream.sendState)),
          TransportErrorCode::STREAM_STATE_ERROR);
    }
  }
}

} // namespace quic
