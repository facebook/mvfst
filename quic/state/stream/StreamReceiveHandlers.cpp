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
 *      | Receive all        | Receive RST
 *      | bytes til FIN      |
 *      v                    |
 * Receive::Closed <---------+
 *
 */

void receiveReadStreamFrameSMHandler(
    QuicStreamState& stream,
    ReadStreamFrame&& frame) {
  switch (stream.recvState) {
    case StreamRecvState::Open_E: {
      VLOG_IF(10, frame.fin) << "Open: Received data with fin"
                             << " stream=" << stream.id << " " << stream.conn;
      appendDataToReadBuffer(
          stream, StreamBuffer(std::move(frame.data), frame.offset, frame.fin));
      if (isAllDataReceived(stream)) {
        VLOG(10) << "Open: Transition to Closed"
                 << " stream=" << stream.id << " " << stream.conn;
        stream.recvState = StreamRecvState::Closed_E;
        if (stream.inTerminalStates()) {
          stream.conn.streamManager->addClosed(stream.id);
        }
      }

      stream.conn.streamManager->updateReadableStreams(stream);
      stream.conn.streamManager->updatePeekableStreams(stream);
      break;
    }
    case StreamRecvState::Closed_E: {
      CHECK(!isSendingStream(stream.conn.nodeType, stream.id));
      VLOG_IF(10, frame.fin) << "Closed: Received data with fin"
                             << " stream=" << stream.id << " " << stream.conn;
      appendDataToReadBuffer(
          stream, StreamBuffer(std::move(frame.data), frame.offset, frame.fin));
      break;
    }
    case StreamRecvState::Invalid_E: {
      throw QuicTransportException(
          folly::to<std::string>(
              "Invalid transition from state=",
              streamStateToString(stream.recvState)),
          TransportErrorCode::STREAM_STATE_ERROR);
    }
  }
}

void receiveRstStreamSMHandler(QuicStreamState& stream, RstStreamFrame&& rst) {
  switch (stream.recvState) {
    case StreamRecvState::Closed_E: {
      // This will check whether the reset is still consistent with the stream.
      onResetQuicStream(stream, std::move(rst));
      break;
    }
    case StreamRecvState::Open_E: {
      // We transit the receive state machine to Closed before invoking
      // onResetQuicStream because it will check the state of the stream for
      // flow control.
      stream.recvState = StreamRecvState::Closed_E;
      if (stream.inTerminalStates()) {
        stream.conn.streamManager->addClosed(stream.id);
      }
      onResetQuicStream(stream, std::move(rst));
      break;
    }
    case StreamRecvState::Invalid_E: {
      throw QuicTransportException(
          folly::to<std::string>(
              "Invalid transition from state=",
              streamStateToString(stream.recvState)),
          TransportErrorCode::STREAM_STATE_ERROR);
      break;
    }
  }
}

} // namespace quic
