/*
 * Copyright (c) Facebook, Inc. and its affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 *
 */

#pragma once

#include <folly/io/async/AsyncSocketException.h>
#include <quic/client/handshake/ClientHandshake.h>
#include <quic/congestion_control/QuicCubic.h>
#include <quic/flowcontrol/QuicFlowController.h>
#include <quic/handshake/TransportParameters.h>
#include <quic/state/QuicStateFunctions.h>
#include <quic/state/StateData.h>
#include <quic/state/StateMachine.h>

namespace quic {

struct ClientStates {
  struct Handshaking {};
  struct Error {};
};

struct ClientEvents {
  struct ReadData {
    folly::SocketAddress peer;
    Buf buf;
    folly::Optional<folly::AsyncSocketException> error;
  };
};

using ClientState =
    boost::variant<ClientStates::Handshaking, ClientStates::Error>;

struct QuicClientConnectionState : public QuicConnectionStateBase {
  ~QuicClientConnectionState() override = default;

  ClientState state;

  // Whether version negotiation was done. We might need to error out
  // all the callbacks as a result.
  bool versionNegotiationNeeded{false};

  // The stateless reset token sent by the server.
  folly::Optional<StatelessResetToken> statelessResetToken;

  // Initial destination connection id.
  folly::Optional<ConnectionId> initialDestinationConnectionId;

  ClientHandshake* clientHandshakeLayer;

  // Packet number in which client initial was sent. Receipt of data on the
  // crypto stream from the server can implicitly ack the client initial packet.
  // TODO: use this to get rid of the data in the crypto stream.
  // folly::Optional<PacketNum> clientInitialPacketNum;

  QuicClientConnectionState() : QuicConnectionStateBase(QuicNodeType::Client) {
    state = ClientStates::Handshaking();
    cryptoState = std::make_unique<QuicCryptoState>();
    congestionController = std::make_unique<Cubic>(*this);
    // TODO: this is wrong, it should be the handshake finish time. But i need
    // a relatively sane time now to make the timestamps all sane.
    connectionTime = Clock::now();
    supportedVersions = {QuicVersion::MVFST, QuicVersion::QUIC_DRAFT};
    originalVersion = QuicVersion::MVFST;
    clientHandshakeLayer = new ClientHandshake(*cryptoState);
    handshakeLayer.reset(clientHandshakeLayer);
    // We shouldn't normally need to set this until we're starting the
    // transport, however writing unit tests is much easier if we set this here.
    updateFlowControlStateWithSettings(flowControlState, transportSettings);
    streamManager = std::make_unique<QuicStreamManager>(*this, this->nodeType);
  }
};

void ClientInvalidStateHandler(QuicClientConnectionState& state);

struct QuicClientStateMachine {
  using StateData = QuicClientConnectionState;
  static constexpr auto InvalidEventHandler = &ClientInvalidStateHandler;
};

/**
 * Undos the clients state to be the original state of the client. This is
 * intended to be used in the case version negotiation is performed.
 */
std::unique_ptr<QuicClientConnectionState> undoAllClientStateForVersionMismatch(
    std::unique_ptr<QuicClientConnectionState> conn,
    QuicVersion /* negotiatedVersion */);

void processServerInitialParams(
    QuicClientConnectionState& conn,
    ServerTransportParameters serverParams,
    PacketNum packetNum);

void updateTransportParamsFromCachedEarlyParams(
    QuicClientConnectionState& conn,
    const CachedServerTransportParameters& transportParams);

} // namespace quic
