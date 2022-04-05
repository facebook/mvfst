/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
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

struct PendingClientData {
  NetworkDataSingle networkData;
  folly::SocketAddress peer;

  PendingClientData(
      NetworkDataSingle networkDataIn,
      folly::SocketAddress peerIn)
      : networkData(std::move(networkDataIn)), peer(std::move(peerIn)) {}
};

struct QuicClientConnectionState : public QuicConnectionStateBase {
  ~QuicClientConnectionState() override = default;

  // Zero rtt write header cipher.
  std::unique_ptr<PacketNumberCipher> zeroRttWriteHeaderCipher;
  // Write cipher for 0-RTT data
  std::unique_ptr<Aead> zeroRttWriteCipher;

  // The stateless reset token sent by the server.
  folly::Optional<StatelessResetToken> statelessResetToken;

  // The retry token sent by the server.
  std::string retryToken;

  // The new token that potentially verifies the address of the
  // client.
  std::string newToken;

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

  struct HappyEyeballsState {
    // Delay timer
    folly::HHWheelTimer::Callback* connAttemptDelayTimeout{nullptr};

    // IPv6 peer address
    folly::SocketAddress v6PeerAddress;

    // IPv4 peer address
    folly::SocketAddress v4PeerAddress;

    // The address that this socket will try to connect to after connection
    // attempt delay timeout fires
    folly::SocketAddress secondPeerAddress;

    // The UDP socket that will be used for the second connection attempt
    std::unique_ptr<folly::AsyncUDPSocket> secondSocket;

    // Whether should write to the first UDP socket
    bool shouldWriteToFirstSocket{true};

    // Whether should write to the second UDP socket
    bool shouldWriteToSecondSocket{false};

    // Whether HappyEyeballs has finished
    // The signal of finishing is first successful decryption of a packet
    bool finished{false};
  };

  HappyEyeballsState happyEyeballsState;

  // Short header packets we received but couldn't yet decrypt.
  std::vector<PendingClientData> pendingOneRttData;
  // Handshake packets we received but couldn't yet decrypt.
  std::vector<PendingClientData> pendingHandshakeData;

  explicit QuicClientConnectionState(
      std::shared_ptr<ClientHandshakeFactory> handshakeFactoryIn)
      : QuicConnectionStateBase(QuicNodeType::Client),
        handshakeFactory(std::move(handshakeFactoryIn)) {
    cryptoState = std::make_unique<QuicCryptoState>();
    congestionController = std::make_unique<Cubic>(*this);
    connectionTime = Clock::now();
    originalVersion = QuicVersion::MVFST;
    DCHECK(handshakeFactory);
    auto tmpClientHandshake =
        std::move(*handshakeFactory).makeClientHandshake(this);
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
