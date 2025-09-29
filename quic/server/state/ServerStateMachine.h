/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#pragma once

#include <glog/logging.h>
#include <memory>

#include <quic/QuicException.h>
#include <quic/codec/Types.h>
#include <quic/common/NetworkData.h>
#include <quic/congestion_control/CongestionControllerFactory.h>
#include <quic/congestion_control/QuicCubic.h>
#include <quic/flowcontrol/QuicFlowController.h>

#include <quic/loss/QuicLossFunctions.h>
#include <quic/server/handshake/ServerHandshake.h>
#include <quic/server/handshake/ServerHandshakeFactory.h>
#include <quic/server/state/ServerConnectionIdRejector.h>
#include <quic/state/AckHandlers.h>
#include <quic/state/QuicStateFunctions.h>
#include <quic/state/QuicStreamFunctions.h>
#include <quic/state/SimpleFrameFunctions.h>
#include <quic/state/StateData.h>

#include <folly/ExceptionWrapper.h>
#include <folly/IPAddress.h>
#include <folly/Overload.h>
#include <folly/Random.h>
#include <folly/io/async/AsyncSocketException.h>

namespace quic {

enum ServerState {
  Open,
  Closed,
};

struct ServerEvents {
  struct ReadData {
    folly::SocketAddress localAddress;
    ReceivedUdpPacket udpPacket;
    folly::SocketAddress peerAddress;
  };

  struct Close {};
};

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
  // Minimum rtt
  std::chrono::microseconds mrtt;
};

struct ConnectionMigrationState {
  uint32_t numMigrations{0};
};

/**
 * State used during processing of MAX_PACING_RATE_KNOB frames.
 */
struct MaxPacingRateKnobState {
  uint64_t lastMaxRateBytesPerSec = std::numeric_limits<uint64_t>::max();
  bool frameOutOfOrderDetected = false;
};

struct QuicServerConnectionState : public QuicConnectionStateBase {
  ~QuicServerConnectionState() override {
    streamManager->clearOpenStreams();
  }

  ServerState state;

  // Data which we cannot read yet, because the handshake has not completed.
  // Zero rtt protected packets
  std::unique_ptr<std::vector<ServerEvents::ReadData>> pendingZeroRttData;
  // One rtt protected packets
  std::unique_ptr<std::vector<ServerEvents::ReadData>> pendingOneRttData;

  // Current state of connection migration
  ConnectionMigrationState migrationState;

  // Parameters to generate server chosen connection id
  Optional<ServerConnectionIdParams> serverConnIdParams;

  // ConnectionIdAlgo implementation to encode and decode ConnectionId with
  // various info, such as routing related info.
  ConnectionIdAlgo* connIdAlgo{nullptr};

  // ServerConnectionIdRejector can reject a ConnectionId from ConnectionIdAlgo
  ServerConnectionIdRejector* connIdRejector{nullptr};

  // Source address token that can be saved to client via PSK.
  // Address with higher index is more recently used.
  std::vector<folly::IPAddress> tokenSourceAddresses;

  ServerHandshake* serverHandshakeLayer;

  // Whether transport parameters from psk match current server parameters.
  // A false value indicates 0-rtt is rejected.
  Optional<bool> transportParamsMatching;

  Optional<uint64_t> maybeCwndHintBytes;

  // Whether source address token matches client ip.
  // A false value indicates either 0-rtt is rejected or inflight bytes are
  // limited until CFIN depending on matching policy.
  Optional<bool> sourceTokenMatching;

  // Server address of VIP. Currently used as input for stateless reset token.
  folly::SocketAddress serverAddr;

  // Whether we've sent the handshake done signal yet.
  bool sentHandshakeDone{false};

  // Whether we've sent the new_token frame yet.
  bool sentNewTokenFrame{false};

  // Number of bytes the server has written during the handshake.
  uint64_t numHandshakeBytesSent{0};

  // Whether or not the client has verified their address (thru CFIN or
  // NewToken).
  bool isClientAddrVerified{false};

  // State for max pacing rate knob. Currently used to detect out of order
  // MAX_PACING_RATE_KNOB frames.
  MaxPacingRateKnobState maxPacingRateKnobState{};

  // Sequence number of the last received MAX_PACING_RATE_KNOB_SEQUENCED.
  Optional<uint64_t> maybeLastMaxPacingRateKnobSeqNum{std::nullopt};

  Optional<ConnectionIdData> createAndAddNewSelfConnId() override;

  QuicServerConnectionState(
      std::shared_ptr<ServerHandshakeFactory> handshakeFactory)
      : QuicConnectionStateBase(QuicNodeType::Server) {
    state = ServerState::Open;
    // Create the crypto stream.
    cryptoState = std::make_unique<QuicCryptoState>();
    congestionController = std::make_unique<Cubic>(*this);
    connectionTime = Clock::now();
    supportedVersions = std::vector<QuicVersion>{
        {QuicVersion::MVFST,
         QuicVersion::MVFST_EXPERIMENTAL,
         QuicVersion::MVFST_EXPERIMENTAL2,
         QuicVersion::MVFST_EXPERIMENTAL3,
         QuicVersion::MVFST_EXPERIMENTAL4,
         QuicVersion::MVFST_EXPERIMENTAL5,
         QuicVersion::MVFST_ALIAS,
         QuicVersion::QUIC_V1,
         QuicVersion::QUIC_V1_ALIAS,
         QuicVersion::QUIC_V1_ALIAS2,
         QuicVersion::MVFST_PRIMING}};
    originalVersion = QuicVersion::MVFST;
    DCHECK(handshakeFactory);
    auto tmpServerHandshake =
        std::move(*handshakeFactory).makeServerHandshake(this);
    serverHandshakeLayer = tmpServerHandshake.get();
    handshakeLayer = std::move(tmpServerHandshake);
    // We shouldn't normally need to set this until we're starting the
    // transport, however writing unit tests is much easier if we set this here.
    updateFlowControlStateWithSettings(flowControlState, transportSettings);
    pendingZeroRttData =
        std::make_unique<std::vector<ServerEvents::ReadData>>();
    pendingOneRttData = std::make_unique<std::vector<ServerEvents::ReadData>>();
    streamManager = std::make_unique<QuicStreamManager>(
        *this, this->nodeType, transportSettings);
    pathManager = std::make_unique<QuicPathManager>(*this);
    connIdsRetiringSoon.emplace(SmallVec<ConnectionId, 5>{});
  }
};

// Transition to error state on invalid state transition.
void ServerInvalidStateHandler(QuicServerConnectionState& state);

[[nodiscard]] quic::Expected<void, QuicError> onServerReadData(
    QuicServerConnectionState& conn,
    ServerEvents::ReadData& readData);

[[nodiscard]] quic::Expected<void, QuicError> onServerReadDataFromOpen(
    QuicServerConnectionState& conn,
    ServerEvents::ReadData& readData);

[[nodiscard]] quic::Expected<void, QuicError> onServerReadDataFromClosed(
    QuicServerConnectionState& conn,
    ServerEvents::ReadData& readData);

void onServerClose(QuicServerConnectionState& conn);

void onServerCloseOpenState(QuicServerConnectionState& conn);

[[nodiscard]] quic::Expected<void, QuicError> processClientInitialParams(
    QuicServerConnectionState& conn,
    const ClientTransportParameters& clientParams);

[[nodiscard]] quic::Expected<void, QuicError> updateHandshakeState(
    QuicServerConnectionState& conn);

bool validateAndUpdateSourceToken(
    QuicServerConnectionState& conn,
    std::vector<folly::IPAddress> sourceAddresses);

void updateWritableByteLimitOnRecvPacket(QuicServerConnectionState& conn);

void maybeUpdateTransportFromAppToken(
    QuicServerConnectionState& conn,
    const Optional<BufPtr>& appToken);

[[nodiscard]] quic::Expected<void, QuicError> onConnectionMigration(
    QuicServerConnectionState& conn,
    PathIdType readPathId,
    bool isIntentional = false);

} // namespace quic
