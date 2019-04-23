/*
 * Copyright (c) Facebook, Inc. and its affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 *
 */

#pragma once

#include <quic/congestion_control/QuicCubic.h>
#include <quic/flowcontrol/QuicFlowController.h>
#include <quic/server/handshake/ServerHandshake.h>
#include <quic/state/StateData.h>
#include <quic/state/StateMachine.h>

#include <folly/IPAddress.h>
#include <folly/io/async/AsyncSocketException.h>

#include <vector>

namespace quic {

struct ServerStates {
  struct Handshaking {};
  struct Established {};
  struct Closed {};
  struct Error {};
};

struct ServerEvents {
  struct ReadData {
    folly::SocketAddress peer;
    NetworkData networkData;
  };

  struct WriteData {
    Buf buf;
  };

  struct Close {};
};

using ServerState = boost::variant<
    ServerStates::Handshaking,
    ServerStates::Established,
    ServerStates::Closed,
    ServerStates::Error>;

struct CongestionAndRttState {
  // The corresponding peer address
  folly::SocketAddress peerAddress;

  // Time when this state is recorded, i.e. when migration happens
  TimePoint recordTime;

  // Congestion controller
  std::unique_ptr<CongestionController> congestionController;

  // Smooth rtt
  std::chrono::microseconds srtt;
  // Latest rtt
  std::chrono::microseconds lrtt;
  // Rtt var
  std::chrono::microseconds rttvar;
};

struct ConnectionMigrationState {
  uint32_t numMigrations{0};

  // Previous validated peer addresses, not containing current peer address
  std::vector<folly::SocketAddress> previousPeerAddresses;

  // Congestion state and rtt stats of last validated peer
  folly::Optional<CongestionAndRttState> lastCongestionAndRtt;
};

struct QuicServerConnectionState : public QuicConnectionStateBase {
  ~QuicServerConnectionState() override = default;

  ServerState state;

  // Data which we cannot read yet, because the handshake has not completed.
  // Zero rtt protected packets
  std::unique_ptr<std::vector<ServerEvents::ReadData>> pendingZeroRttData;
  // One rtt protected packets
  std::unique_ptr<std::vector<ServerEvents::ReadData>> pendingOneRttData;

  // Current state of connection migration
  ConnectionMigrationState migrationState;

  // Parameters to generate server chosen connection id
  folly::Optional<ServerConnectionIdParams> serverConnIdParams;

  // Source address token that can be saved to client via PSK.
  // Address with higher index is more recently used.
  std::vector<folly::IPAddress> tokenSourceAddresses;

  ServerHandshake* serverHandshakeLayer;

  // Whether transport parameters from psk match current server parameters.
  // A false value indicates 0-rtt is rejected.
  folly::Optional<bool> transportParamsMatching;

  // Whether source address token matches client ip.
  // A false value indicates either 0-rtt is rejected or inflight bytes are
  // limited until CFIN depending on matching policy.
  folly::Optional<bool> sourceTokenMatching;

  QuicServerConnectionState() : QuicConnectionStateBase(QuicNodeType::Server) {
    state = ServerStates::Handshaking();
    // Create the crypto stream.
    cryptoState = std::make_unique<QuicCryptoState>();
    congestionController = std::make_unique<Cubic>(*this);
    // TODO: this is wrong, it should be the handshake finish time. But i need
    // a relatively sane time now to make the timestamps all sane.
    connectionTime = Clock::now();
    supportedVersions =
        std::vector<QuicVersion>{{QuicVersion::MVFST, QuicVersion::QUIC_DRAFT}};
    originalVersion = QuicVersion::MVFST;
    serverHandshakeLayer = new ServerHandshake(*cryptoState);
    handshakeLayer.reset(serverHandshakeLayer);
    // We shouldn't normally need to set this until we're starting the
    // transport, however writing unit tests is much easier if we set this here.
    updateFlowControlStateWithSettings(flowControlState, transportSettings);
    pendingZeroRttData =
        std::make_unique<std::vector<ServerEvents::ReadData>>();
    pendingOneRttData = std::make_unique<std::vector<ServerEvents::ReadData>>();
    streamManager = std::make_unique<QuicStreamManager>(*this, this->nodeType);
  }
};

// Transition to error state on invalid state transition.
void ServerInvalidStateHandler(QuicServerConnectionState& state);

struct QuicServerStateMachine {
  using StateData = QuicServerConnectionState;
  static constexpr auto InvalidEventHandler = &ServerInvalidStateHandler;
};

/*
 * Handshaking -> Closed
 * TODO: full state machine.
 */

QUIC_DECLARE_STATE_HANDLER(
    QuicServerStateMachine,
    ServerStates::Handshaking,
    ServerEvents::ReadData);

QUIC_DECLARE_STATE_HANDLER(
    QuicServerStateMachine,
    ServerStates::Handshaking,
    ServerEvents::Close,
    ServerStates::Closed);

QUIC_DECLARE_STATE_HANDLER(
    QuicServerStateMachine,
    ServerStates::Closed,
    ServerEvents::ReadData,
    ServerStates::Closed);

QUIC_DECLARE_STATE_HANDLER(
    QuicServerStateMachine,
    ServerStates::Closed,
    ServerEvents::Close);

void processClientInitialParams(
    QuicServerConnectionState& conn,
    ClientTransportParameters clientParams);

void updateHandshakeState(QuicServerConnectionState& conn);

bool validateAndUpdateSourceToken(
    QuicServerConnectionState& conn,
    std::vector<folly::IPAddress> sourceAddresses);

void updateWritableByteLimitOnRecvPacket(QuicServerConnectionState& conn);

void updateTransportParamsFromTicket(
    QuicServerConnectionState& conn,
    uint64_t initialMaxStreamDataBidiLocal,
    uint64_t initialMaxStreamDataBidiRemote,
    uint64_t initialMaxStreamDataUni,
    uint64_t initialMaxData,
    uint64_t idleTimeout,
    uint64_t maxRecvPacketSize);

void onConnectionMigration(
    QuicServerConnectionState& conn,
    const folly::SocketAddress& newPeerAddress);
} // namespace quic

#include <quic/server/state/ServerStateMachine-inl.h>
