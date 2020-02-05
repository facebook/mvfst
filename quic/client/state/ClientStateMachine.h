/*
 * Copyright (c) Facebook, Inc. and its affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 *
 */

#pragma once

#include <folly/io/async/AsyncSocketException.h>
#include <quic/client/handshake/CachedServerTransportParameters.h>
#include <quic/client/handshake/ClientHandshake.h>
#include <quic/client/handshake/ClientHandshakeFactory.h>
#include <quic/congestion_control/QuicCubic.h>
#include <quic/flowcontrol/QuicFlowController.h>
#include <quic/handshake/TransportParameters.h>
#include <quic/state/QuicStateFunctions.h>
#include <quic/state/StateData.h>

namespace quic {

struct QuicClientConnectionState : public QuicConnectionStateBase {
  ~QuicClientConnectionState() override = default;

  // The stateless reset token sent by the server.
  folly::Optional<StatelessResetToken> statelessResetToken;

  // The retry token sent by the server.
  std::string retryToken;

  // Initial destination connection id.
  folly::Optional<ConnectionId> initialDestinationConnectionId;

  std::shared_ptr<ClientHandshakeFactory> handshakeFactory;
  ClientHandshake* clientHandshakeLayer;

  // Save the server transport params here so that client can access the value
  // when it wants to write the values to psk cache
  // TODO Save TicketTransportParams here instead of in QuicClientTransport
  uint64_t peerAdvertisedInitialMaxStreamsBidi{0};
  uint64_t peerAdvertisedInitialMaxStreamsUni{0};

  // Packet number in which client initial was sent. Receipt of data on the
  // crypto stream from the server can implicitly ack the client initial packet.
  // TODO: use this to get rid of the data in the crypto stream.
  // folly::Optional<PacketNum> clientInitialPacketNum;

  explicit QuicClientConnectionState(
      std::shared_ptr<ClientHandshakeFactory> handshakeFactoryIn)
      : QuicConnectionStateBase(QuicNodeType::Client),
        handshakeFactory(std::move(handshakeFactoryIn)) {
    cryptoState = std::make_unique<QuicCryptoState>();
    congestionController = std::make_unique<Cubic>(*this);
    // TODO: this is wrong, it should be the handshake finish time. But i need
    // a relatively sane time now to make the timestamps all sane.
    connectionTime = Clock::now();
    originalVersion = QuicVersion::MVFST;
    DCHECK(handshakeFactory);
    auto tmpClientHandshake =
        handshakeFactory->makeClientHandshake(*cryptoState);
    clientHandshakeLayer = tmpClientHandshake.get();
    handshakeLayer = std::move(tmpClientHandshake);
    // We shouldn't normally need to set this until we're starting the
    // transport, however writing unit tests is much easier if we set this here.
    updateFlowControlStateWithSettings(flowControlState, transportSettings);
    streamManager = std::make_unique<QuicStreamManager>(
        *this, this->nodeType, transportSettings);
    transportSettings.selfActiveConnectionIdLimit =
        kDefaultActiveConnectionIdLimit;
  }
};

/**
 * Undos the clients state to be the original state of the client.
 */
std::unique_ptr<QuicClientConnectionState> undoAllClientStateCommon(
    std::unique_ptr<QuicClientConnectionState> conn);

std::unique_ptr<QuicClientConnectionState> undoAllClientStateForRetry(
    std::unique_ptr<QuicClientConnectionState> conn);

void processServerInitialParams(
    QuicClientConnectionState& conn,
    ServerTransportParameters serverParams,
    PacketNum packetNum);

void updateTransportParamsFromCachedEarlyParams(
    QuicClientConnectionState& conn,
    const CachedServerTransportParameters& transportParams);

} // namespace quic
