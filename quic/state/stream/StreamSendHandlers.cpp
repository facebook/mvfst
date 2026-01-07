/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <quic/common/MvfstLogging.h>
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
 * Send::Open ------------------------------+
 *      |                                   |
 *      | Ack all bytes                     |
 *      | till FIN                          | Send RST
 *      |                                   |
 *      v                                   v
 * Send::Closed <---------------------- ResetSent
 *               RST ACKed and all bytes
 *               till smallest ACKed
 *               reliable reset offset
 *               ACKed.
 *
 */
quic::Expected<void, QuicError> sendStopSendingSMHandler(
    QuicStreamState& stream,
    const StopSendingFrame& frame) {
  switch (stream.sendState) {
    case StreamSendState::Open: {
      MVCHECK(
          isBidirectionalStream(stream.id) ||
          isSendingStream(stream.conn.nodeType, stream.id));
      if (stream.conn.nodeType == QuicNodeType::Server &&
          getSendStreamFlowControlBytesWire(stream) == 0 &&
          !stream.finalWriteOffset) {
        MVVLOG(3) << "Client gives up a flow control blocked stream";
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
      return quic::make_unexpected(QuicError(
          TransportErrorCode::STREAM_STATE_ERROR,
          fmt::format(
              "Invalid transition from state={}",
              streamStateToString(stream.sendState))));
    }
  }
  return {};
}

quic::Expected<void, QuicError> sendRstSMHandler(
    QuicStreamState& stream,
    ApplicationErrorCode errorCode,
    const Optional<uint64_t>& reliableSize) {
  switch (stream.sendState) {
    // TODO: Allow the sending of multiple RESET_STREAM OR RESET_STREAM_AT
    // frames.
    case StreamSendState::Open: {
      // We're assuming that higher-level functions perform the necessary
      // error checks before calling this function, which is why we're doing
      // CHECKs here.
      if (reliableSize && stream.reliableSizeToPeer) {
        MVCHECK_LE(
            *reliableSize,
            *stream.reliableSizeToPeer,
            "It is illegal to increase the reliable size");
      }
      if (stream.appErrorCodeToPeer) {
        MVCHECK_EQ(
            *stream.appErrorCodeToPeer,
            errorCode,
            "Cannot change application error code in a reset");
      }
      if (!stream.reliableSizeToPeer &&
          stream.sendState == StreamSendState::ResetSent) {
        MVCHECK(
            !reliableSize || *reliableSize == 0,
            "RESET_STREAM frame was previously sent, and we "
                << "are increasing the reliable size");
      }
      stream.appErrorCodeToPeer = errorCode;
      auto resetResult = resetQuicStream(stream, errorCode, reliableSize);
      if (!resetResult.has_value()) {
        return resetResult;
      }
      appendPendingStreamReset(stream.conn, stream, errorCode, reliableSize);
      stream.sendState = StreamSendState::ResetSent;
      break;
    }
    case StreamSendState::Closed: {
      MVVLOG(4) << "Ignoring SendReset from closed state.";
      break;
    }
    case StreamSendState::ResetSent: {
      // do nothing
      break;
    }
    case StreamSendState::Invalid: {
      return quic::make_unexpected(QuicError(
          TransportErrorCode::STREAM_STATE_ERROR,
          fmt::format(
              "Invalid transition from state={}",
              streamStateToString(stream.sendState))));
    }
  }
  return {};
}

quic::Expected<void, QuicError> sendAckSMHandler(
    QuicStreamState& stream,
    const WriteStreamFrame& ackedFrame) {
  switch (stream.sendState) {
    case StreamSendState::Open:
    case StreamSendState::ResetSent: {
      // Clean up the acked buffers from the retransmissionBuffer.
      auto ackedBuffer = stream.retransmissionBuffer.find(ackedFrame.offset);
      if (ackedBuffer != stream.retransmissionBuffer.end()) {
        MVCHECK_EQ(ackedFrame.offset, ackedBuffer->second->offset);
        MVCHECK_EQ(ackedFrame.len, ackedBuffer->second->data.chainLength());
        MVCHECK_EQ(ackedFrame.fin, ackedBuffer->second->eof);
        MVVLOG(10) << "Open: acked stream data stream=" << stream.id
                   << " offset=" << ackedBuffer->second->offset
                   << " len=" << ackedBuffer->second->data.chainLength()
                   << " eof=" << ackedBuffer->second->eof << " " << stream.conn;
        auto updateResult = stream.updateAckedIntervals(
            ackedBuffer->second->offset,
            ackedBuffer->second->data.chainLength(),
            ackedBuffer->second->eof);
        if (!updateResult.has_value()) {
          return quic::make_unexpected(QuicError(
              TransportErrorCode::INTERNAL_ERROR,
              "Failed to update acked intervals"));
        }
        stream.retransmissionBuffer.erase(ackedBuffer);
      }

      // This stream may be able to invoke some deliveryCallbacks:
      stream.conn.streamManager->addDeliverable(stream.id);

      // Check for whether or not we have ACKed all bytes until our FIN or,
      // in the case that we've sent a Reset, until the minimum reliable size of
      // some reset acked by the peer.
      bool allReliableDataDelivered =
          (stream.minReliableSizeAcked &&
           (*stream.minReliableSizeAcked == 0 ||
            stream.allBytesAckedTill(*stream.minReliableSizeAcked - 1)));
      if (allBytesTillFinAcked(stream) || allReliableDataDelivered) {
        stream.sendState = StreamSendState::Closed;
        if (stream.inTerminalStates()) {
          stream.conn.streamManager->addClosed(stream.id);
        }
      }
      break;
    }
    case StreamSendState::Closed: {
      MVDCHECK(stream.retransmissionBuffer.empty());
      MVDCHECK(stream.pendingWrites.empty());
      break;
    }
    case StreamSendState::Invalid: {
      return quic::make_unexpected(QuicError(
          TransportErrorCode::STREAM_STATE_ERROR,
          fmt::format(
              "Invalid transition from state={}",
              streamStateToString(stream.sendState))));
    }
  }
  return {};
}

quic::Expected<void, QuicError> sendRstAckSMHandler(
    QuicStreamState& stream,
    Optional<uint64_t> reliableSize) {
  switch (stream.sendState) {
    case StreamSendState::ResetSent: {
      MVVLOG(10) << "ResetSent: Transition to closed stream=" << stream.id
                 << " " << stream.conn;
      // Note that we set minReliableSizeAcked to 0 for non-reliable resets.
      if (!stream.minReliableSizeAcked.has_value()) {
        stream.minReliableSizeAcked = reliableSize.value_or(0);
      } else {
        stream.minReliableSizeAcked =
            std::min(*stream.minReliableSizeAcked, reliableSize.value_or(0));
      }

      if (*stream.minReliableSizeAcked == 0 ||
          stream.allBytesAckedTill(*stream.minReliableSizeAcked - 1)) {
        // We can only transition to Closed if we have successfully delivered
        // all reliable data in some reset that was ACKed by the peer.
        stream.sendState = StreamSendState::Closed;
        if (stream.inTerminalStates()) {
          stream.conn.streamManager->addClosed(stream.id);
        }
      }
      break;
    }
    case StreamSendState::Closed: {
      // Just discard the ack if we are already in Closed state.
      break;
    }
    case StreamSendState::Open:
    case StreamSendState::Invalid: {
      return quic::make_unexpected(QuicError(
          TransportErrorCode::STREAM_STATE_ERROR,
          fmt::format(
              "Invalid transition from state={}",
              streamStateToString(stream.sendState))));
    }
  }
  return {};
}

} // namespace quic
