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
inline void StreamStateMachineInvalidHandler(const QuicStreamState& state) {
  throw QuicTransportException(
      folly::to<std::string>(
          "Invalid transition from state=",
          folly::variant_match(
              state.state,
              [](const StreamStates::Open&) { return "Open"; },
              [](const StreamStates::HalfClosedLocal&) {
                return "HalfClosedLocal";
              },
              [](const StreamStates::HalfClosedRemote&) {
                return "HalfClosedRemote";
              },
              [](const StreamStates::WaitingForRstAck&) {
                return "WaitingForRstAck";
              },
              [](const StreamStates::Closed&) { return "Closed"; })),
      TransportErrorCode::STREAM_STATE_ERROR);
}

struct StreamStateMachine {
  using StateData = QuicStreamState;
  static constexpr auto InvalidEventHandler = &StreamStateMachineInvalidHandler;
};

/**
 *  Welcome to the stream state machine, we got fun and games.
 *
 *  ACK = Ack of stream frame.
 *
 *
 *  Stream / ACK                 Stream/ ACK
 *    |--|                         |----|
 *    |  v  All bytes till FIN     |    v            All bytes till FIN
 *    Open ---------------------> HalfClosedRemote ------------------------|
 *     |  |        recv                    |                acked          |
 *     |  |                                |                               |
 *     |  |     SendReset / Reset          |                               |
 *     |  ----------------------------|    |                               |
 *     |                              |    |                               |
 *     |  All bytes till FIN acked    |    |                               |
 *     |                              |    |                               |
 *     |                              |    |                               |
 *     | Stream / ACK                 |    | SendReset /                   |
 *     |   |---|                      |    | Reset                         |
 *     v   |   v         SendReset    v    v                 RstAck        v
 *    HalfClosedLocal --------------> WaitingForRstAck---------------------|
 *     |                                  |   ^                            |
 *     |                                  |---|                            |
 *     | Reset /                         Stream / ACK / Reset / SendReset  |
 *     | All bytes till FIN recv                                           |
 *     |--------------------------------------------------------------> Closed
 *                                                                      |   ^
 *                                                                      |---|
 *                                                                     Stream /
 *                                                                     Reset /
 *                                                                     RstAck /
 *                                                                     Ack /
 *                                                                     SendReset
 */

QUIC_DECLARE_STATE_HANDLER(
    StreamStateMachine,
    StreamStates::Open,
    ReadStreamFrame,
    StreamStates::HalfClosedRemote,
    StreamStates::Closed);

QUIC_DECLARE_STATE_HANDLER(
    StreamStateMachine,
    StreamStates::Open,
    RstStreamFrame,
    StreamStates::WaitingForRstAck,
    StreamStates::Closed);

QUIC_DECLARE_STATE_HANDLER(
    StreamStateMachine,
    StreamStates::Open,
    StreamEvents::SendReset,
    StreamStates::WaitingForRstAck);

QUIC_DECLARE_STATE_HANDLER(
    StreamStateMachine,
    StreamStates::Open,
    StreamEvents::AckStreamFrame,
    StreamStates::HalfClosedLocal,
    StreamStates::Closed);

QUIC_DECLARE_STATE_HANDLER(
    StreamStateMachine,
    StreamStates::Open,
    StopSendingFrame);

QUIC_DECLARE_STATE_HANDLER(
    StreamStateMachine,
    StreamStates::HalfClosedLocal,
    RstStreamFrame,
    StreamStates::Closed);

QUIC_DECLARE_STATE_HANDLER(
    StreamStateMachine,
    StreamStates::HalfClosedLocal,
    ReadStreamFrame,
    StreamStates::Closed);

QUIC_DECLARE_STATE_HANDLER(
    StreamStateMachine,
    StreamStates::HalfClosedLocal,
    StreamEvents::AckStreamFrame);

QUIC_DECLARE_STATE_HANDLER(
    StreamStateMachine,
    StreamStates::HalfClosedLocal,
    StopSendingFrame);

QUIC_DECLARE_STATE_HANDLER(
    StreamStateMachine,
    StreamStates::HalfClosedLocal,
    StreamEvents::SendReset,
    StreamStates::WaitingForRstAck);

QUIC_DECLARE_STATE_HANDLER(
    StreamStateMachine,
    StreamStates::HalfClosedRemote,
    ReadStreamFrame);

QUIC_DECLARE_STATE_HANDLER(
    StreamStateMachine,
    StreamStates::HalfClosedRemote,
    StreamEvents::AckStreamFrame,
    StreamStates::Closed);

QUIC_DECLARE_STATE_HANDLER(
    StreamStateMachine,
    StreamStates::HalfClosedRemote,
    StopSendingFrame);

QUIC_DECLARE_STATE_HANDLER(
    StreamStateMachine,
    StreamStates::HalfClosedRemote,
    StreamEvents::SendReset,
    StreamStates::WaitingForRstAck);

QUIC_DECLARE_STATE_HANDLER(
    StreamStateMachine,
    StreamStates::HalfClosedRemote,
    RstStreamFrame,
    StreamStates::WaitingForRstAck);

QUIC_DECLARE_STATE_HANDLER(
    StreamStateMachine,
    StreamStates::WaitingForRstAck,
    ReadStreamFrame);

QUIC_DECLARE_STATE_HANDLER(
    StreamStateMachine,
    StreamStates::WaitingForRstAck,
    StreamEvents::AckStreamFrame);

QUIC_DECLARE_STATE_HANDLER(
    StreamStateMachine,
    StreamStates::WaitingForRstAck,
    StopSendingFrame);

QUIC_DECLARE_STATE_HANDLER(
    StreamStateMachine,
    StreamStates::WaitingForRstAck,
    RstStreamFrame);

QUIC_DECLARE_STATE_HANDLER(
    StreamStateMachine,
    StreamStates::WaitingForRstAck,
    StreamEvents::RstAck,
    StreamStates::Closed);

QUIC_DECLARE_STATE_HANDLER(
    StreamStateMachine,
    StreamStates::WaitingForRstAck,
    StreamEvents::SendReset);

QUIC_DECLARE_STATE_HANDLER(
    StreamStateMachine,
    StreamStates::Closed,
    ReadStreamFrame);

QUIC_DECLARE_STATE_HANDLER(
    StreamStateMachine,
    StreamStates::Closed,
    StreamEvents::RstAck);

QUIC_DECLARE_STATE_HANDLER(
    StreamStateMachine,
    StreamStates::Closed,
    StreamEvents::AckStreamFrame);

QUIC_DECLARE_STATE_HANDLER(
    StreamStateMachine,
    StreamStates::Closed,
    StopSendingFrame);

QUIC_DECLARE_STATE_HANDLER(
    StreamStateMachine,
    StreamStates::Closed,
    RstStreamFrame);

QUIC_DECLARE_STATE_HANDLER(
    StreamStateMachine,
    StreamStates::Closed,
    StreamEvents::SendReset);
} // namespace quic

#include <quic/state/stream/StreamClosedHandlers.h>
#include <quic/state/stream/StreamHalfClosedLocalHandlers.h>
#include <quic/state/stream/StreamHalfClosedRemoteHandlers.h>
#include <quic/state/stream/StreamOpenHandlers.h>
#include <quic/state/stream/StreamWaitingForRstAckHandlers.h>
