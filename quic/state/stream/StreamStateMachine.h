/*
 * Copyright (c) Facebook, Inc. and its affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 *
 */

#pragma once

#include <quic/codec/Types.h>
#include <quic/state/QuicStreamFunctions.h>
#include <quic/state/StateData.h>
#include <quic/state/StateMachine.h>
#include <quic/state/StreamData.h>

namespace quic {

struct StreamEvents {
  // Send a reset on the stream.
  struct SendReset {
    ApplicationErrorCode errorCode;

    explicit SendReset(ApplicationErrorCode errorCodeIn)
        : errorCode(errorCodeIn) {}
  };

  // Got an ack for the stream frame.
  struct AckStreamFrame {
    explicit AckStreamFrame(const WriteStreamFrame& ackedFrameIn)
        : ackedFrame(ackedFrameIn) {}
    const WriteStreamFrame& ackedFrame;
  };

  struct RstAck {
    explicit RstAck(const RstStreamFrame& rst) : rstStreamFrame(rst) {}
    const RstStreamFrame& rstStreamFrame;
  };
};

// Transition the stream to an error state if there is an invalid state
// transition.
[[noreturn]] inline void StreamSendStateMachineInvalidHandler(
    const QuicStreamState& state) {
  throw QuicTransportException(
      folly::to<std::string>(
          "Invalid transition from state=",
          folly::variant_match(
              state.send.state,
              [](const StreamSendStates::Open&) { return "Open"; },
              [](const StreamSendStates::ResetSent&) { return "ResetSent"; },
              [](const StreamSendStates::Closed&) { return "Closed"; },
              [](const StreamSendStates::Invalid&) { return "Invalid"; })),
      TransportErrorCode::STREAM_STATE_ERROR);
}

struct StreamSendStateMachine {
  using StateData = QuicStreamState::Send;
  using UserData = QuicStreamState;
  static constexpr auto InvalidEventHandler =
      &StreamSendStateMachineInvalidHandler;
};

// Transition the stream to an error state if there is an invalid state
// transition.
[[noreturn]] inline void StreamReceiveStateMachineInvalidHandler(
    const QuicStreamState& state) {
  throw QuicTransportException(
      folly::to<std::string>(
          "Invalid transition from state=",
          folly::variant_match(
              state.recv.state,
              [](const StreamReceiveStates::Open&) { return "Open"; },
              [](const StreamReceiveStates::Closed&) { return "Closed"; },
              [](const StreamReceiveStates::Invalid&) { return "Invalid"; })),
      TransportErrorCode::STREAM_STATE_ERROR);
}

struct StreamReceiveStateMachine {
  using StateData = QuicStreamState::Recv;
  using UserData = QuicStreamState;
  static constexpr auto InvalidEventHandler =
      &StreamReceiveStateMachineInvalidHandler;
};

/**
 *  Welcome to the stream state machine, we got fun and games.
 *
 * This is a simplified version of the state machines defined in the transport
 * specification.  The "Invalid" state is used for unidirectional streams that
 * do not have that half (eg: an ingress uni stream is in send state Invalid)
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
 *
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

QUIC_DECLARE_STATE_HANDLER(
    StreamReceiveStateMachine,
    StreamReceiveStates::Open,
    ReadStreamFrame,
    StreamReceiveStates::Closed)

QUIC_DECLARE_STATE_HANDLER(
    StreamReceiveStateMachine,
    StreamReceiveStates::Open,
    RstStreamFrame,
    StreamReceiveStates::Closed)

QUIC_DECLARE_STATE_HANDLER(
    StreamSendStateMachine,
    StreamSendStates::Open,
    StreamEvents::SendReset,
    StreamSendStates::ResetSent)

QUIC_DECLARE_STATE_HANDLER(
    StreamSendStateMachine,
    StreamSendStates::Open,
    StreamEvents::AckStreamFrame,
    StreamSendStates::Closed)

QUIC_DECLARE_STATE_HANDLER(
    StreamSendStateMachine,
    StreamSendStates::Open,
    StopSendingFrame)

QUIC_DECLARE_STATE_HANDLER(
    StreamSendStateMachine,
    StreamSendStates::ResetSent,
    StreamEvents::AckStreamFrame)

QUIC_DECLARE_STATE_HANDLER(
    StreamSendStateMachine,
    StreamSendStates::ResetSent,
    StopSendingFrame)

QUIC_DECLARE_STATE_HANDLER(
    StreamSendStateMachine,
    StreamSendStates::ResetSent,
    StreamEvents::RstAck,
    StreamSendStates::Closed)

QUIC_DECLARE_STATE_HANDLER(
    StreamSendStateMachine,
    StreamSendStates::ResetSent,
    StreamEvents::SendReset)

QUIC_DECLARE_STATE_HANDLER(
    StreamReceiveStateMachine,
    StreamReceiveStates::Closed,
    ReadStreamFrame)

QUIC_DECLARE_STATE_HANDLER(
    StreamSendStateMachine,
    StreamSendStates::Closed,
    StreamEvents::RstAck)

QUIC_DECLARE_STATE_HANDLER(
    StreamSendStateMachine,
    StreamSendStates::Closed,
    StreamEvents::AckStreamFrame)

QUIC_DECLARE_STATE_HANDLER(
    StreamSendStateMachine,
    StreamSendStates::Closed,
    StopSendingFrame)

QUIC_DECLARE_STATE_HANDLER(
    StreamReceiveStateMachine,
    StreamReceiveStates::Closed,
    RstStreamFrame)

QUIC_DECLARE_STATE_HANDLER(
    StreamSendStateMachine,
    StreamSendStates::Closed,
    StreamEvents::SendReset)
} // namespace quic

#include <quic/state/stream/StreamClosedHandlers-inl.h>
#include <quic/state/stream/StreamOpenHandlers-inl.h>
#include <quic/state/stream/StreamWaitingForRstAckHandlers-inl.h>
