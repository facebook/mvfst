/*
 * Copyright (c) Facebook, Inc. and its affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 *
 */

#include <quic/server/state/ServerStateMachine.h>

#include <quic/congestion_control/CongestionControllerFactory.h>
#include <quic/flowcontrol/QuicFlowController.h>
#include <quic/handshake/TransportParameters.h>
#include <quic/state/QuicPacingFunctions.h>
#include <quic/state/QuicStreamFunctions.h>
#include <quic/state/QuicTransportStatsCallback.h>

namespace quic {

namespace {
bool maybeNATRebinding(
    const folly::SocketAddress& newPeerAddress,
    const folly::SocketAddress& oldPeerAddress) {
  auto& newIPAddr = newPeerAddress.getIPAddress();
  auto& oldIPAddr = oldPeerAddress.getIPAddress();

  // Port changed
  if (newIPAddr == oldIPAddr) {
    return true;
  }

  return newIPAddr.isV4() && oldIPAddr.isV4() &&
      newIPAddr.inSubnet(oldIPAddr, 24);
}

CongestionAndRttState moveCurrentCongestionAndRttState(
    QuicServerConnectionState& conn) {
  CongestionAndRttState state;
  state.peerAddress = conn.peerAddress;
  state.recordTime = Clock::now();
  state.congestionController = std::move(conn.congestionController);
  state.srtt = conn.lossState.srtt;
  state.lrtt = conn.lossState.lrtt;
  state.rttvar = conn.lossState.rttvar;
  return state;
}

void resetCongestionAndRttState(QuicServerConnectionState& conn) {
  CHECK(conn.congestionControllerFactory)
      << "CongestionControllerFactory is not set.";
  conn.congestionController =
      conn.congestionControllerFactory->makeCongestionController(
          conn, conn.transportSettings.defaultCongestionController);
  conn.lossState.srtt = std::chrono::microseconds::zero();
  conn.lossState.lrtt = std::chrono::microseconds::zero();
  conn.lossState.rttvar = std::chrono::microseconds::zero();
}

void recoverOrResetCongestionAndRttState(
    QuicServerConnectionState& conn,
    const folly::SocketAddress& peerAddress) {
  auto& lastState = conn.migrationState.lastCongestionAndRtt;
  if (lastState && lastState->peerAddress == peerAddress &&
      (Clock::now() - lastState->recordTime <=
       kTimeToRetainLastCongestionAndRttState)) {
    // recover from matched non-stale state
    conn.congestionController = std::move(lastState->congestionController);
    conn.lossState.srtt = lastState->srtt;
    conn.lossState.lrtt = lastState->lrtt;
    conn.lossState.rttvar = lastState->rttvar;
    conn.migrationState.lastCongestionAndRtt = folly::none;
  } else {
    resetCongestionAndRttState(conn);
  }
}
} // namespace

void ServerInvalidStateHandler(QuicServerConnectionState& state) {
  throw QuicInternalException(
      folly::to<std::string>(
          "Invalid transition from state=",
          folly::variant_match(
              state.state,
              [](const ServerStates::Handshaking&) { return "Handshaking"; },
              [](const ServerStates::Established&) { return "Established"; },
              [](const ServerStates::Closed&) { return "Closed"; },
              [](const ServerStates::Error&) { return "Error"; })),
      LocalErrorCode::INVALID_STATE_TRANSITION);
}

void processClientInitialParams(
    QuicServerConnectionState& conn,
    ClientTransportParameters clientParams) {
  // TODO validate that we didn't receive original connection ID, stateless
  // reset token, or preferred address.
  auto maxData = getIntegerParameter(
      TransportParameterId::initial_max_data, clientParams.parameters);
  auto maxStreamDataBidiLocal = getIntegerParameter(
      TransportParameterId::initial_max_stream_data_bidi_local,
      clientParams.parameters);
  auto maxStreamDataBidiRemote = getIntegerParameter(
      TransportParameterId::initial_max_stream_data_bidi_remote,
      clientParams.parameters);
  auto maxStreamDataUni = getIntegerParameter(
      TransportParameterId::initial_max_stream_data_uni,
      clientParams.parameters);
  auto maxStreamsBidi = getIntegerParameter(
      TransportParameterId::initial_max_streams_bidi, clientParams.parameters);
  auto maxStreamsUni = getIntegerParameter(
      TransportParameterId::initial_max_streams_uni, clientParams.parameters);
  auto idleTimeout = getIntegerParameter(
      TransportParameterId::idle_timeout, clientParams.parameters);
  auto ackDelayExponent = getIntegerParameter(
      TransportParameterId::ack_delay_exponent, clientParams.parameters);
  auto packetSize = getIntegerParameter(
      TransportParameterId::max_packet_size, clientParams.parameters);
  auto partialReliability = getIntegerParameter(
      static_cast<TransportParameterId>(kPartialReliabilityParameterId),
      clientParams.parameters);
  if (!packetSize || *packetSize == 0) {
    packetSize = kDefaultMaxUDPPayload;
  }
  if (*packetSize < kMinMaxUDPPayload) {
    throw QuicTransportException(
        folly::to<std::string>(
            "Max packet size too small. received max_packetSize = ",
            *packetSize),
        TransportErrorCode::TRANSPORT_PARAMETER_ERROR);
  }

  VLOG(10) << "Client advertised flow control ";
  VLOG(10) << "conn=" << maxData.value_or(0);
  VLOG(10) << " stream bidi local=" << maxStreamDataBidiLocal.value_or(0)
           << " ";
  VLOG(10) << " stream bidi remote=" << maxStreamDataBidiRemote.value_or(0)
           << " ";
  VLOG(10) << " stream uni=" << maxStreamDataUni.value_or(0) << " ";
  VLOG(10) << conn;
  conn.flowControlState.peerAdvertisedMaxOffset = maxData.value_or(0);
  conn.flowControlState.peerAdvertisedInitialMaxStreamOffsetBidiLocal =
      maxStreamDataBidiLocal.value_or(0);
  conn.flowControlState.peerAdvertisedInitialMaxStreamOffsetBidiRemote =
      maxStreamDataBidiRemote.value_or(0);
  conn.flowControlState.peerAdvertisedInitialMaxStreamOffsetUni =
      maxStreamDataUni.value_or(0);
  conn.streamManager->setMaxLocalBidirectionalStreams(
      maxStreamsBidi.value_or(0));
  conn.streamManager->setMaxLocalUnidirectionalStreams(
      maxStreamsUni.value_or(0));
  conn.peerIdleTimeout = std::chrono::seconds(idleTimeout.value_or(0));
  conn.peerIdleTimeout =
      std::min(std::chrono::seconds(*idleTimeout), kMaxIdleTimeout);
  if (ackDelayExponent && *ackDelayExponent > kMaxAckDelayExponent) {
    throw QuicTransportException(
        "ack_delay_exponent too large",
        TransportErrorCode::TRANSPORT_PARAMETER_ERROR);
  }
  conn.peerAckDelayExponent =
      ackDelayExponent.value_or(kDefaultAckDelayExponent);
  // TODO: udpSendPacketLen should also be limited by PMTU
  if (conn.transportSettings.canIgnorePathMTU) {
    conn.udpSendPacketLen = *packetSize;
  }

  if (partialReliability && *partialReliability != 0 &&
      conn.transportSettings.partialReliabilityEnabled) {
    conn.partialReliabilityEnabled = true;
  }
  VLOG(10) << "conn.partialReliabilityEnabled="
           << conn.partialReliabilityEnabled;
}

void updateHandshakeState(QuicServerConnectionState& conn) {
  // Zero RTT read cipher is available after chlo is processed with the
  // condition that early data attempt is accepted.
  auto handshakeLayer = conn.serverHandshakeLayer;
  auto zeroRttReadCipher = handshakeLayer->getZeroRttReadCipher();
  auto zeroRttHeaderCipher = handshakeLayer->getZeroRttReadHeaderCipher();
  // One RTT write cipher is available at Fizz layer after chlo is processed.
  // However, the cipher is only exported to QUIC if early data attempt is
  // accepted. Otherwise, the cipher will be available after cfin is
  // processed.
  auto oneRttWriteCipher = handshakeLayer->getOneRttWriteCipher();
  // One RTT read cipher is available after cfin is processed.
  auto oneRttReadCipher = handshakeLayer->getOneRttReadCipher();

  auto oneRttWriteHeaderCipher = handshakeLayer->getOneRttWriteHeaderCipher();
  auto oneRttReadHeaderCipher = handshakeLayer->getOneRttReadHeaderCipher();

  if (zeroRttReadCipher) {
    QUIC_TRACE(fst_trace, conn, "derived 0-rtt read cipher");
    conn.readCodec->setZeroRttReadCipher(std::move(zeroRttReadCipher));
  }
  if (zeroRttHeaderCipher) {
    conn.readCodec->setZeroRttHeaderCipher(std::move(zeroRttHeaderCipher));
  }
  if (oneRttWriteHeaderCipher) {
    conn.oneRttWriteHeaderCipher = std::move(oneRttWriteHeaderCipher);
  }
  if (oneRttReadHeaderCipher) {
    conn.readCodec->setOneRttHeaderCipher(std::move(oneRttReadHeaderCipher));
  }

  if (oneRttWriteCipher) {
    QUIC_TRACE(fst_trace, conn, "derived 1-rtt write cipher");
    CHECK(!conn.oneRttWriteCipher.get());
    conn.oneRttWriteCipher = std::move(oneRttWriteCipher);

    updatePacingOnKeyEstablished(conn);

    // We negotiate the transport parameters whenever we have the 1-RTT write
    // keys available.
    auto clientParams = handshakeLayer->getClientTransportParams();
    if (!clientParams) {
      throw QuicTransportException(
          "No client transport params",
          TransportErrorCode::TRANSPORT_PARAMETER_ERROR);
    }
    processClientInitialParams(conn, std::move(*clientParams));
  }
  if (oneRttReadCipher) {
    QUIC_TRACE(fst_trace, conn, "derived 1-rtt read cipher");
    // Clear limit because CFIN is received at this point
    conn.writableBytesLimit = folly::none;
    conn.readCodec->setOneRttReadCipher(std::move(oneRttReadCipher));
  }
  auto handshakeWriteCipher = handshakeLayer->getHandshakeWriteCipher();
  auto handshakeReadCipher = handshakeLayer->getHandshakeReadCipher();
  if (handshakeWriteCipher) {
    conn.handshakeWriteCipher = std::move(handshakeWriteCipher);
  }
  if (handshakeReadCipher) {
    conn.readCodec->setHandshakeReadCipher(std::move(handshakeReadCipher));
  }
  auto handshakeWriteHeaderCipher =
      handshakeLayer->getHandshakeWriteHeaderCipher();
  auto handshakeReadHeaderCipher =
      handshakeLayer->getHandshakeReadHeaderCipher();
  if (handshakeWriteHeaderCipher) {
    conn.handshakeWriteHeaderCipher = std::move(handshakeWriteHeaderCipher);
  }
  if (handshakeReadHeaderCipher) {
    conn.readCodec->setHandshakeHeaderCipher(
        std::move(handshakeReadHeaderCipher));
  }
  if (handshakeLayer->isHandshakeDone()) {
    conn.readCodec->onHandshakeDone(Clock::now());
  }
}

bool validateAndUpdateSourceToken(
    QuicServerConnectionState& conn,
    std::vector<folly::IPAddress> sourceAddresses) {
  DCHECK(conn.peerAddress.isInitialized());
  bool foundMatch = false;
  for (int ii = sourceAddresses.size() - 1; ii >= 0; --ii) {
    // TODO T33014230 subnect matching
    if (conn.peerAddress.getIPAddress() == sourceAddresses[ii]) {
      foundMatch = true;
      // If peer address is found in the token, move the element to the end
      // of vector to increase its favorability.
      sourceAddresses.erase(sourceAddresses.begin() + ii);
      sourceAddresses.push_back(conn.peerAddress.getIPAddress());
    }
  }
  conn.sourceTokenMatching = foundMatch;
  bool acceptZeroRtt = foundMatch;
  if (!foundMatch) {
    // Add peer address to token for next resumption
    if (sourceAddresses.size() >= kMaxNumTokenSourceAddresses) {
      sourceAddresses.erase(sourceAddresses.begin());
    }
    sourceAddresses.push_back(conn.peerAddress.getIPAddress());

    switch (conn.transportSettings.zeroRttSourceTokenMatchingPolicy) {
      case ZeroRttSourceTokenMatchingPolicy::REJECT_IF_NO_EXACT_MATCH:
        acceptZeroRtt = false;
        break;
      case ZeroRttSourceTokenMatchingPolicy::LIMIT_IF_NO_EXACT_MATCH:
        acceptZeroRtt = true;
        conn.writableBytesLimit =
            conn.transportSettings.limitedCwndInMss * conn.udpSendPacketLen;
        break;
    }
  }
  // Save the source token so that it can be written to client via NST later
  conn.tokenSourceAddresses = std::move(sourceAddresses);

  return acceptZeroRtt;
}

void updateWritableByteLimitOnRecvPacket(QuicServerConnectionState& conn) {
  // When we receive a packet we increase the limit again. The reasoning this is
  // that a peer can do the same by opening a new connection.
  if (conn.writableBytesLimit) {
    conn.writableBytesLimit = *conn.writableBytesLimit +
        conn.transportSettings.limitedCwndInMss * conn.udpSendPacketLen;
  }
}

void updateTransportParamsFromTicket(
    QuicServerConnectionState& conn,
    uint64_t initialMaxBidiLocalStreamData,
    uint64_t initialMaxBidiRemoteStreamData,
    uint64_t initialMaxUniStreamData,
    uint64_t initialMaxData,
    uint64_t idleTimeout,
    uint64_t maxRecvPacketSize) {
  conn.transportSettings.advertisedInitialBidiLocalStreamWindowSize =
      initialMaxBidiLocalStreamData;
  conn.transportSettings.advertisedInitialBidiRemoteStreamWindowSize =
      initialMaxBidiRemoteStreamData;
  conn.transportSettings.advertisedInitialUniStreamWindowSize =
      initialMaxUniStreamData;
  conn.transportSettings.advertisedInitialConnectionWindowSize = initialMaxData;
  conn.transportSettings.idleTimeout = std::chrono::seconds(idleTimeout);
  conn.transportSettings.maxRecvPacketSize = maxRecvPacketSize;
  updateFlowControlStateWithSettings(
      conn.flowControlState, conn.transportSettings);
}

void onConnectionMigration(
    QuicServerConnectionState& conn,
    const folly::SocketAddress& newPeerAddress) {
  if (conn.migrationState.numMigrations >= kMaxNumMigrationsAllowed) {
    QUIC_STATS(
        conn.infoCallback,
        onPacketDropped,
        PacketDropReason::PEER_ADDRESS_CHANGE);
    throw QuicTransportException(
        "Too many migrations", TransportErrorCode::INVALID_MIGRATION);
  }
  ++conn.migrationState.numMigrations;

  // NAT rebinding, no path validation & keep congestion state unchanged
  if (maybeNATRebinding(newPeerAddress, conn.peerAddress)) {
    conn.peerAddress = newPeerAddress;
    return;
  }

  auto& previousPeerAddresses = conn.migrationState.previousPeerAddresses;
  auto it = std::find(
      previousPeerAddresses.begin(),
      previousPeerAddresses.end(),
      newPeerAddress);
  if (it == previousPeerAddresses.end()) {
    // Send new path challenge
    uint64_t pathData;
    folly::Random::secureRandom(&pathData, sizeof(pathData));
    conn.pendingEvents.pathChallenge = PathChallengeFrame(pathData);

    // Limit amount of bytes that can be sent to unvalidated source
    conn.writableBytesLimit =
        conn.transportSettings.limitedCwndInMss * conn.udpSendPacketLen;
  } else {
    previousPeerAddresses.erase(it);
  }

  // Cancel current path validation if any
  if (conn.outstandingPathValidation) {
    conn.pendingEvents.schedulePathValidationTimeout = false;
    conn.outstandingPathValidation = folly::none;

    recoverOrResetCongestionAndRttState(conn, newPeerAddress);
  } else {
    // Only add validated addresses to previousPeerAddresses
    conn.migrationState.previousPeerAddresses.push_back(conn.peerAddress);

    // Current peer address is validated,
    // remember its congestion state and rtt stats
    CongestionAndRttState state = moveCurrentCongestionAndRttState(conn);
    recoverOrResetCongestionAndRttState(conn, newPeerAddress);
    conn.migrationState.lastCongestionAndRtt = std::move(state);
  }

  conn.peerAddress = newPeerAddress;
}
} // namespace quic
