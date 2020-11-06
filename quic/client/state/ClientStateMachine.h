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
#include <quic/client/handshake/ClientHandshakeFactory.h>
#include <quic/congestion_control/QuicCubic.h>
#include <quic/flowcontrol/QuicFlowController.h>
#include <quic/handshake/TransportParameters.h>
#include <quic/state/QuicStateFunctions.h>
#include <quic/state/StateData.h>

namespace quic {

struct CachedServerTransportParameters;

struct QuicClientConnectionState : public QuicConnectionStateBase {
  ~QuicClientConnectionState() override = default;

  // The stateless reset token sent by the server.
  folly::Optional<StatelessResetToken> statelessResetToken;

  // The retry token sent by the server.
  std::string retryToken;

  // This is the destination connection id that will be sent in the outgoing
  // client initial packet. It is modified in the event of a retry.
  folly::Optional<ConnectionId> initialDestinationConnectionId;

  // This is the original destination connection id. It is the same as the
  // initialDestinationConnectionId when there is no retry involved. When
  // there is retry involved, this is the value of the destination connection
  // id sent in the very first initial packet.
  folly::Optional<ConnectionId> originalDestinationConnectionId;

  std::shared_ptr<ClientHandshakeFactory> handshakeFactory;
  ClientHandshake* clientHandshakeLayer;

  folly::Optional<TimePoint> lastCloseSentTime;

  // Save the server transport params here so that client can access the value
  // when it wants to write the values to psk cache
  // TODO Save TicketTransportParams here instead of in QuicClientTransport
  bool serverInitialParamsSet_{false};
  uint64_t peerAdvertisedInitialMaxData{0};
  uint64_t peerAdvertisedInitialMaxStreamDataBidiLocal{0};
  uint64_t peerAdvertisedInitialMaxStreamDataBidiRemote{0};
  uint64_t peerAdvertisedInitialMaxStreamDataUni{0};
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
    auto tmpClientHandshake = handshakeFactory->makeClientHandshake(this);
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
std::unique_ptr<QuicClientConnectionState> undoAllClientStateForRetry(
    std::unique_ptr<QuicClientConnectionState> conn);

void processServerInitialParams(
    QuicClientConnectionState& conn,
    ServerTransportParameters serverParams,
    PacketNum packetNum);

void cacheServerInitialParams(
    QuicClientConnectionState& conn,
    uint64_t peerAdvertisedInitialMaxData,
    uint64_t peerAdvertisedInitialMaxStreamDataBidiLocal,
    uint64_t peerAdvertisedInitialMaxStreamDataBidiRemote,
    uint64_t peerAdvertisedInitialMaxStreamDataUni,
    uint64_t peerAdvertisedInitialMaxStreamsBidi,
    uint64_t peerAdvertisedInitialMaxStreamUni);

CachedServerTransportParameters getServerCachedTransportParameters(
    const QuicClientConnectionState& conn);

void updateTransportParamsFromCachedEarlyParams(
    QuicClientConnectionState& conn,
    const CachedServerTransportParameters& transportParams);

} // namespace quic
