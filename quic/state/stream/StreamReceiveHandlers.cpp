/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <quic/flowcontrol/QuicFlowController.h>
#include <quic/state/stream/StreamReceiveHandlers.h>
#include <quic/state/stream/StreamStateFunctions.h>

namespace quic {

/**
 *  Welcome to the receive state machine, we got fun and games.
 *
 * This is a simplified version of the receive state machine defined in the
 * transport specification.
 *
 * Receive State Machine
 * =====================
 *
 * [ Initial State ]
 *      |
 *      |  Stream
 *      |
 *      v
 * Receive::Open  -----------+
 *      |                    |
 *      | Receive all        | Receive RST, and
 *      | bytes till FIN     | all reliable bytes
 *      | or reliable size   | have been received
 *      v                    |
 * Receive::Closed <---------+
 *
 */
quic::Expected<void, QuicError> receiveReadStreamFrameSMHandler(
    QuicStreamState& stream,
    ReadStreamFrame&& frame) {
  switch (stream.recvState) {
    case StreamRecvState::Open: {
      VLOG_IF(10, frame.fin) << "Open: Received data with fin"
                             << " stream=" << stream.id << " " << stream.conn;
      auto appendResult = appendDataToReadBuffer(
          stream, StreamBuffer(std::move(frame.data), frame.offset, frame.fin));
      if (!appendResult.has_value()) {
        return appendResult;
      }
      bool allDataTillReliableSizeReceived = stream.reliableSizeFromPeer &&
          (*stream.reliableSizeFromPeer == 0 ||
           isAllDataReceivedUntil(stream, *stream.reliableSizeFromPeer - 1));
      if (isAllDataReceived(stream) || allDataTillReliableSizeReceived) {
        VLOG(10) << "Open: Transition to Closed" << " stream=" << stream.id
                 << " " << stream.conn;
        stream.recvState = StreamRecvState::Closed;
        if (stream.inTerminalStates()) {
          stream.conn.streamManager->addClosed(stream.id);
        }
      }

      stream.conn.streamManager->updateReadableStreams(stream);
      stream.conn.streamManager->updatePeekableStreams(stream);
      break;
    }
    case StreamRecvState::Closed: {
      CHECK(!isSendingStream(stream.conn.nodeType, stream.id));
      VLOG(10) << "Closed: Received discarding data stream=" << stream.id
               << " fin=" << frame.fin << " " << stream.conn;
      break;
    }
    case StreamRecvState::Invalid: {
      return quic::make_unexpected(QuicError(
          TransportErrorCode::STREAM_STATE_ERROR,
          fmt::format(
              "Invalid transition from state={}",
              streamStateToString(stream.recvState))));
    }
  }
  return {};
}

quic::Expected<void, QuicError> receiveRstStreamSMHandler(
    QuicStreamState& stream,
    const RstStreamFrame& rst) {
  switch (stream.recvState) {
    case StreamRecvState::Closed: {
      // This will check whether the reset is still consistent with the
      // stream.
      auto resetResult = onResetQuicStream(stream, rst);
      if (!resetResult.has_value()) {
        return resetResult;
      }
      break;
    }
    case StreamRecvState::Open: {
      // We transit the receive state machine to Closed before invoking
      // onResetQuicStream because it will check the state of the stream for
      // flow control.
      if (!rst.reliableSize || *rst.reliableSize == 0 ||
          isAllDataReceivedUntil(stream, *rst.reliableSize - 1)) {
        // We can only transition to Closed if all of the reliable data has
        // been received, otherwise we are going to ignore incoming stream
        // frames.
        stream.recvState = StreamRecvState::Closed;
        if (stream.inTerminalStates()) {
          stream.conn.streamManager->addClosed(stream.id);
        }
      }
      auto resetResult = onResetQuicStream(stream, rst);
      if (!resetResult.has_value()) {
        return resetResult;
      }
      break;
    }
    case StreamRecvState::Invalid: {
      return quic::make_unexpected(QuicError(
          TransportErrorCode::STREAM_STATE_ERROR,
          fmt::format(
              "Invalid transition from state={}",
              streamStateToString(stream.recvState))));
    }
  }
  return {};
}

} // namespace quic
