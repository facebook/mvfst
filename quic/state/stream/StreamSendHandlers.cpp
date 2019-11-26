// Copyright (c) Facebook, Inc. and its affiliates. All Rights Reserved

#include <quic/state/stream/StreamSendHandlers.h>
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
    case StreamSendState::Open_E: {
      CHECK(
          isBidirectionalStream(stream.id) ||
          isSendingStream(stream.conn.nodeType, stream.id));
      stream.conn.streamManager->addStopSending(stream.id, frame.errorCode);
      break;
    }
    case StreamSendState::Closed_E: {
      break;
    }
    case StreamSendState::ResetSent_E: {
      // no-op, we already sent a reset
      break;
    }
    case StreamSendState::Invalid_E: {
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
    case StreamSendState::Open_E: {
      resetQuicStream(stream, errorCode);
      appendPendingStreamReset(stream.conn, stream, errorCode);
      stream.sendState = StreamSendState::ResetSent_E;
      break;
    }
    case StreamSendState::Closed_E: {
      VLOG(4) << "Ignoring SendReset from closed state.";
      break;
    }
    case StreamSendState::ResetSent_E: {
      // do nothing
      break;
    }
    case StreamSendState::Invalid_E: {
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
    case StreamSendState::Open_E: {
      // Clean up the acked buffers from the retransmissionBuffer.
      auto ackedBuffer = std::lower_bound(
          stream.retransmissionBuffer.begin(),
          stream.retransmissionBuffer.end(),
          ackedFrame.offset,
          [](const auto& buffer, const auto& offset) {
            return buffer.offset < offset;
          });

      if (ackedBuffer != stream.retransmissionBuffer.end()) {
        if (streamFrameMatchesRetransmitBuffer(
                stream, ackedFrame, *ackedBuffer)) {
          VLOG(10) << "Open: acked stream data stream=" << stream.id
                   << " offset=" << ackedBuffer->offset
                   << " len=" << ackedBuffer->data.chainLength()
                   << " eof=" << ackedBuffer->eof << " " << stream.conn;
          stream.retransmissionBuffer.erase(ackedBuffer);
        } else {
          VLOG(10)
              << "Open: received an ack for already discarded buffer; stream="
              << stream.id << " offset=" << ackedBuffer->offset
              << " len=" << ackedBuffer->data.chainLength()
              << " eof=" << ackedBuffer->eof << " " << stream.conn;
        }
      }

      // This stream may be able to invoke some deliveryCallbacks:
      stream.conn.streamManager->addDeliverable(stream.id);

      // Check for whether or not we have ACKed all bytes until our FIN.
      if (allBytesTillFinAcked(stream)) {
        stream.sendState = StreamSendState::Closed_E;
        if (stream.inTerminalStates()) {
          stream.conn.streamManager->addClosed(stream.id);
        }
      }
      break;
    }
    case StreamSendState::Closed_E:
    case StreamSendState::ResetSent_E: {
      DCHECK(stream.retransmissionBuffer.empty());
      DCHECK(stream.writeBuffer.empty());
      break;
    }
    case StreamSendState::Invalid_E: {
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
    case StreamSendState::ResetSent_E: {
      VLOG(10) << "ResetSent: Transition to closed stream=" << stream.id << " "
               << stream.conn;
      stream.sendState = StreamSendState::Closed_E;
      if (stream.inTerminalStates()) {
        stream.conn.streamManager->addClosed(stream.id);
      }
      break;
    }
    case StreamSendState::Closed_E: {
      // Just discard the ack if we are already in Closed state.
      break;
    }
    case StreamSendState::Open_E:
    case StreamSendState::Invalid_E: {
      throw QuicTransportException(
          folly::to<std::string>(
              "Invalid transition from state=",
              streamStateToString(stream.sendState)),
          TransportErrorCode::STREAM_STATE_ERROR);
    }
  }
}

} // namespace quic
