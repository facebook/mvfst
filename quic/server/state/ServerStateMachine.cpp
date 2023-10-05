/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <quic/server/handshake/TokenGenerator.h>
#include <quic/server/state/ServerStateMachine.h>

#include <quic/api/QuicTransportFunctions.h>
#include <quic/common/BufUtil.h>
#include <quic/congestion_control/CongestionControllerFactory.h>
#include <quic/congestion_control/TokenlessPacer.h>
#include <quic/fizz/handshake/FizzCryptoFactory.h>
#include <quic/flowcontrol/QuicFlowController.h>
#include <quic/handshake/TransportParameters.h>
#include <quic/logging/QLoggerConstants.h>
#include <quic/state/DatagramHandlers.h>
#include <quic/state/QuicPacingFunctions.h>
#include <quic/state/QuicStreamFunctions.h>
#include <quic/state/QuicTransportStatsCallback.h>
#include <quic/state/SimpleFrameFunctions.h>
#include <quic/state/stream/StreamReceiveHandlers.h>
#include <quic/state/stream/StreamSendHandlers.h>

namespace quic {
using namespace std::chrono_literals;

namespace {
constexpr size_t kConnIdEncodingRetryLimit = 32;

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
  state.mrtt = conn.lossState.mrtt;
  return state;
}

void resetCongestionAndRttState(QuicServerConnectionState& conn) {
  CHECK(conn.congestionControllerFactory)
      << "CongestionControllerFactory is not set.";
  conn.congestionController =
      conn.congestionControllerFactory->makeCongestionController(
          conn, conn.transportSettings.defaultCongestionController);
  conn.lossState.srtt = 0us;
  conn.lossState.lrtt = 0us;
  conn.lossState.rttvar = 0us;
  conn.lossState.mrtt = kDefaultMinRtt;
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
    conn.lossState.mrtt = lastState->mrtt;
    conn.migrationState.lastCongestionAndRtt.reset();
  } else {
    resetCongestionAndRttState(conn);
  }
}

void maybeSetExperimentalSettings(QuicServerConnectionState& conn) {
  // no-op versions
  if (conn.version == QuicVersion::MVFST_EXPERIMENTAL) {
    // MVFST_EXPERIMENTAL is used to set initCwnd
    // QuicServerWorker.cpp before CC is initialized.
  } else if (conn.version == QuicVersion::MVFST_EXPERIMENTAL2) {
  } else if (conn.version == QuicVersion::MVFST_EXPERIMENTAL3) {
  }
}

/**
 * Only certain frames are allowed/disallowed in unprotected (initial,
 * handshake) and zero-rtt packets.
 */
bool isUnprotectedPacketFrameInvalid(const QuicFrame& quicFrame) {
  switch (quicFrame.type()) {
    case QuicFrame::Type::PaddingFrame:
    case QuicFrame::Type::ReadAckFrame:
    case QuicFrame::Type::ConnectionCloseFrame:
    case QuicFrame::Type::ReadCryptoFrame:
    case QuicFrame::Type::PingFrame:
      return false;
    case QuicFrame::Type::RstStreamFrame:
    case QuicFrame::Type::MaxDataFrame:
    case QuicFrame::Type::MaxStreamDataFrame:
    case QuicFrame::Type::DataBlockedFrame:
    case QuicFrame::Type::StreamDataBlockedFrame:
    case QuicFrame::Type::StreamsBlockedFrame:
    case QuicFrame::Type::ReadStreamFrame:
    case QuicFrame::Type::ReadNewTokenFrame:
    case QuicFrame::Type::DatagramFrame:
    case QuicFrame::Type::NoopFrame:
    case QuicFrame::Type::ImmediateAckFrame:
    case QuicFrame::Type::QuicSimpleFrame:
      return true;
  }
  folly::assume_unreachable();
}

bool isZeroRttPacketSimpleFrameInvalid(const QuicSimpleFrame& quicSimpleFrame) {
  switch (quicSimpleFrame.type()) {
    case QuicSimpleFrame::Type::HandshakeDoneFrame:
    case QuicSimpleFrame::Type::RetireConnectionIdFrame:
    case QuicSimpleFrame::Type::PathResponseFrame:
    case QuicSimpleFrame::Type::AckFrequencyFrame:
      return true;
    case QuicSimpleFrame::Type::StopSendingFrame:
    case QuicSimpleFrame::Type::PathChallengeFrame:
    case QuicSimpleFrame::Type::NewConnectionIdFrame:
    case QuicSimpleFrame::Type::MaxStreamsFrame:
    case QuicSimpleFrame::Type::KnobFrame:
    case QuicSimpleFrame::Type::NewTokenFrame:
      return false;
  }
  folly::assume_unreachable();
}

bool isZeroRttPacketFrameInvalid(const QuicFrame& quicFrame) {
  switch (quicFrame.type()) {
    case QuicFrame::Type::ReadAckFrame:
    case QuicFrame::Type::ReadCryptoFrame:
    case QuicFrame::Type::ReadNewTokenFrame:
    case QuicFrame::Type::ImmediateAckFrame:
      return true;
    case QuicFrame::Type::PingFrame:
    case QuicFrame::Type::ConnectionCloseFrame:
    case QuicFrame::Type::PaddingFrame:
    case QuicFrame::Type::RstStreamFrame:
    case QuicFrame::Type::MaxDataFrame:
    case QuicFrame::Type::MaxStreamDataFrame:
    case QuicFrame::Type::DataBlockedFrame:
    case QuicFrame::Type::StreamDataBlockedFrame:
    case QuicFrame::Type::StreamsBlockedFrame:
    case QuicFrame::Type::ReadStreamFrame:
    case QuicFrame::Type::DatagramFrame:
    case QuicFrame::Type::NoopFrame:
      return false;
    case QuicFrame::Type::QuicSimpleFrame:
      return isZeroRttPacketSimpleFrameInvalid(*quicFrame.asQuicSimpleFrame());
  }
  folly::assume_unreachable();
}
} // namespace

void processClientInitialParams(
    QuicServerConnectionState& conn,
    const ClientTransportParameters& clientParams) {
  auto preferredAddress = getIntegerParameter(
      TransportParameterId::preferred_address, clientParams.parameters);
  auto origConnId = getIntegerParameter(
      TransportParameterId::original_destination_connection_id,
      clientParams.parameters);
  auto statelessResetToken = getIntegerParameter(
      TransportParameterId::stateless_reset_token, clientParams.parameters);
  auto retrySourceConnId = getIntegerParameter(
      TransportParameterId::retry_source_connection_id,
      clientParams.parameters);

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
  auto activeConnectionIdLimit = getIntegerParameter(
      TransportParameterId::active_connection_id_limit,
      clientParams.parameters);
  auto minAckDelay = getIntegerParameter(
      TransportParameterId::min_ack_delay, clientParams.parameters);
  auto maxAckDelay = getIntegerParameter(
      TransportParameterId::max_ack_delay, clientParams.parameters);
  auto maxDatagramFrameSize = getIntegerParameter(
      TransportParameterId::max_datagram_frame_size, clientParams.parameters);
  auto peerAdvertisedMaxStreamGroups = getIntegerParameter(
      static_cast<TransportParameterId>(
          TransportParameterId::stream_groups_enabled),
      clientParams.parameters);

  auto isAckReceiveTimestampsEnabled = getIntegerParameter(
      TransportParameterId::ack_receive_timestamps_enabled,
      clientParams.parameters);
  auto maxReceiveTimestampsPerAck = getIntegerParameter(
      TransportParameterId::max_receive_timestamps_per_ack,
      clientParams.parameters);
  auto receiveTimestampsExponent = getIntegerParameter(
      TransportParameterId::receive_timestamps_exponent,
      clientParams.parameters);
  if (conn.version == QuicVersion::QUIC_DRAFT ||
      conn.version == QuicVersion::QUIC_V1 ||
      conn.version == QuicVersion::QUIC_V1_ALIAS) {
    auto initialSourceConnId = getConnIdParameter(
        TransportParameterId::initial_source_connection_id,
        clientParams.parameters);
    if (!initialSourceConnId ||
        initialSourceConnId.value() !=
            conn.readCodec->getClientConnectionId()) {
      throw QuicTransportException(
          "Initial CID does not match.",
          TransportErrorCode::TRANSPORT_PARAMETER_ERROR);
    }
  }
  auto knobFrameSupported = getIntegerParameter(
      static_cast<TransportParameterId>(
          TransportParameterId::knob_frames_supported),
      clientParams.parameters);

  // validate that we didn't receive original connection ID, stateless
  // reset token, or preferred address.
  if (preferredAddress && *preferredAddress != 0) {
    throw QuicTransportException(
        "Preferred Address is received by server",
        TransportErrorCode::TRANSPORT_PARAMETER_ERROR);
  }

  if (origConnId && *origConnId != 0) {
    throw QuicTransportException(
        "OriginalDestinationConnectionId is received by server",
        TransportErrorCode::TRANSPORT_PARAMETER_ERROR);
  }

  if (statelessResetToken && statelessResetToken.value() != 0) {
    throw QuicTransportException(
        "Stateless Reset Token is received by server",
        TransportErrorCode::TRANSPORT_PARAMETER_ERROR);
  }

  if (retrySourceConnId && retrySourceConnId.value() != 0) {
    throw QuicTransportException(
        "Retry Source Connection ID is received by server",
        TransportErrorCode::TRANSPORT_PARAMETER_ERROR);
  }

  if (maxAckDelay && *maxAckDelay >= kMaxAckDelay) {
    throw QuicTransportException(
        "Max Ack Delay is greater than 2^14 ",
        TransportErrorCode::TRANSPORT_PARAMETER_ERROR);
  }

  // TODO Validate active_connection_id_limit
  if (packetSize && *packetSize < kMinMaxUDPPayload) {
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
  conn.peerIdleTimeout = std::chrono::milliseconds(idleTimeout.value_or(0));
  conn.peerIdleTimeout = timeMin(conn.peerIdleTimeout, kMaxIdleTimeout);
  if (ackDelayExponent && *ackDelayExponent > kMaxAckDelayExponent) {
    throw QuicTransportException(
        "ack_delay_exponent too large",
        TransportErrorCode::TRANSPORT_PARAMETER_ERROR);
  }
  conn.peerAckDelayExponent =
      ackDelayExponent.value_or(kDefaultAckDelayExponent);
  if (minAckDelay.hasValue()) {
    conn.peerMinAckDelay = std::chrono::microseconds(minAckDelay.value());
  }
  if (maxDatagramFrameSize.hasValue()) {
    if (maxDatagramFrameSize.value() > 0 &&
        maxDatagramFrameSize.value() <= kMaxDatagramPacketOverhead) {
      throw QuicTransportException(
          "max_datagram_frame_size too small",
          TransportErrorCode::TRANSPORT_PARAMETER_ERROR);
    }
    conn.datagramState.maxWriteFrameSize = maxDatagramFrameSize.value();
  }

  // Default to max because we can probe PMTU now, and this will be the upper
  // limit
  uint64_t maxUdpPayloadSize = kDefaultMaxUDPPayload;
  if (packetSize) {
    maxUdpPayloadSize = std::min(*packetSize, maxUdpPayloadSize);
    conn.peerMaxUdpPayloadSize = maxUdpPayloadSize;
    if (conn.transportSettings.canIgnorePathMTU) {
      if (*packetSize > kDefaultMaxUDPPayload) {
        // A good peer should never set oversized limit, so to be safe we
        // fallback to default
        conn.udpSendPacketLen = kDefaultUDPSendPacketLen;
      } else {
        // Otherwise, canIgnorePathMTU forces us to immediately set
        // udpSendPacketLen
        // TODO: rename "canIgnorePathMTU" to "forciblySetPathMTU"
        conn.udpSendPacketLen = maxUdpPayloadSize;
      }
    }
  }

  conn.peerActiveConnectionIdLimit =
      activeConnectionIdLimit.value_or(kDefaultActiveConnectionIdLimit);

  if (peerAdvertisedMaxStreamGroups) {
    conn.peerAdvertisedMaxStreamGroups = *peerAdvertisedMaxStreamGroups;
  }
  if (isAckReceiveTimestampsEnabled.has_value() &&
      isAckReceiveTimestampsEnabled.value() == 1) {
    if (maxReceiveTimestampsPerAck.has_value() &&
        receiveTimestampsExponent.has_value()) {
      conn.maybePeerAckReceiveTimestampsConfig.assign(
          {std::min(
               static_cast<uint8_t>(maxReceiveTimestampsPerAck.value()),
               static_cast<uint8_t>(
                   conn.transportSettings.maxReceiveTimestampsPerAckStored)),
           std::max(
               static_cast<uint8_t>(receiveTimestampsExponent.value()),
               static_cast<uint8_t>(0))});
    }
  }

  conn.peerAdvertisedKnobFrameSupport = knobFrameSupported.value_or(0) > 0;
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
    conn.usedZeroRtt = true;
    if (conn.qLogger) {
      conn.qLogger->addTransportStateUpdate(kDerivedZeroRttReadCipher);
    }
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
    if (conn.qLogger) {
      conn.qLogger->addTransportStateUpdate(kDerivedOneRttWriteCipher);
    }
    if (conn.oneRttWriteCipher) {
      throw QuicTransportException(
          "Duplicate 1-rtt write cipher", TransportErrorCode::CRYPTO_ERROR);
    }
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
    if (conn.qLogger) {
      conn.qLogger->addTransportStateUpdate(kDerivedOneRttReadCipher);
    }
    // Clear limit because CFIN is received at this point
    conn.isClientAddrVerified = true;
    conn.writableBytesLimit.reset();
    conn.readCodec->setOneRttReadCipher(std::move(oneRttReadCipher));
  }
  auto handshakeReadCipher = handshakeLayer->getHandshakeReadCipher();
  auto handshakeReadHeaderCipher =
      handshakeLayer->getHandshakeReadHeaderCipher();
  if (handshakeReadCipher) {
    CHECK(handshakeReadHeaderCipher);
    conn.readCodec->setHandshakeReadCipher(std::move(handshakeReadCipher));
    conn.readCodec->setHandshakeHeaderCipher(
        std::move(handshakeReadHeaderCipher));
  }
  if (handshakeLayer->isHandshakeDone()) {
    CHECK(conn.oneRttWriteCipher);
    if (!conn.sentHandshakeDone) {
      sendSimpleFrame(conn, HandshakeDoneFrame());
      conn.sentHandshakeDone = true;
    }

    if (!conn.sentNewTokenFrame &&
        conn.transportSettings.retryTokenSecret.has_value()) {
      // Create NewToken struct – defaults timestamp to now
      NewToken token(conn.peerAddress.getIPAddress());

      // Encrypt two tuple -> (clientIp, curTimeInMs)
      TokenGenerator generator(conn.transportSettings.retryTokenSecret.value());
      auto encryptedToken = generator.encryptToken(token);
      CHECK(encryptedToken.has_value());

      sendSimpleFrame(conn, NewTokenFrame(std::move(encryptedToken.value())));
      QUIC_STATS(conn.statsCallback, onNewTokenIssued);

      conn.sentNewTokenFrame = true;
    }
  }
}

bool validateAndUpdateSourceToken(
    QuicServerConnectionState& conn,
    std::vector<folly::IPAddress> sourceAddresses) {
  DCHECK(conn.peerAddress.isInitialized());
  bool foundMatch = false;
  for (int ii = sourceAddresses.size() - 1; ii >= 0; --ii) {
    // TODO T33014230 subnet matching
    if (conn.peerAddress.getIPAddress() == sourceAddresses[ii]) {
      foundMatch = true;
      // If peer address is found in the token, move the element to the end
      // of vector to increase its favorability.
      sourceAddresses.erase(sourceAddresses.begin() + ii);
      sourceAddresses.push_back(conn.peerAddress.getIPAddress());
      conn.isClientAddrVerified = true;
    }
  }
  conn.sourceTokenMatching = foundMatch;
  bool acceptZeroRtt =
      (conn.transportSettings.zeroRttSourceTokenMatchingPolicy !=
       ZeroRttSourceTokenMatchingPolicy::ALWAYS_REJECT) &&
      foundMatch;

  if (!foundMatch) {
    // Add peer address to token for next resumption
    if (sourceAddresses.size() >= kMaxNumTokenSourceAddresses) {
      sourceAddresses.erase(sourceAddresses.begin());
    }
    sourceAddresses.push_back(conn.peerAddress.getIPAddress());

    switch (conn.transportSettings.zeroRttSourceTokenMatchingPolicy) {
      case ZeroRttSourceTokenMatchingPolicy::ALWAYS_REJECT:
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
  } else if (
      !conn.isClientAddrVerified &&
      conn.transportSettings.enableWritableBytesLimit) {
    conn.writableBytesLimit =
        conn.transportSettings.limitedCwndInMss * conn.udpSendPacketLen;
  }
}

void updateTransportParamsFromTicket(
    QuicServerConnectionState& conn,
    uint64_t idleTimeout,
    uint64_t maxRecvPacketSize,
    uint64_t initialMaxData,
    uint64_t initialMaxStreamDataBidiLocal,
    uint64_t initialMaxStreamDataBidiRemote,
    uint64_t initialMaxStreamDataUni,
    uint64_t initialMaxStreamsBidi,
    uint64_t initialMaxStreamsUni) {
  conn.transportSettings.idleTimeout = std::chrono::milliseconds(idleTimeout);
  conn.transportSettings.maxRecvPacketSize = maxRecvPacketSize;

  conn.transportSettings.advertisedInitialConnectionFlowControlWindow =
      initialMaxData;
  conn.transportSettings.advertisedInitialBidiLocalStreamFlowControlWindow =
      initialMaxStreamDataBidiLocal;
  conn.transportSettings.advertisedInitialBidiRemoteStreamFlowControlWindow =
      initialMaxStreamDataBidiRemote;
  conn.transportSettings.advertisedInitialUniStreamFlowControlWindow =
      initialMaxStreamDataUni;
  updateFlowControlStateWithSettings(
      conn.flowControlState, conn.transportSettings);

  conn.transportSettings.advertisedInitialMaxStreamsBidi =
      initialMaxStreamsBidi;
  conn.transportSettings.advertisedInitialMaxStreamsUni = initialMaxStreamsUni;
}

void onConnectionMigration(
    QuicServerConnectionState& conn,
    const folly::SocketAddress& newPeerAddress,
    bool isIntentional) {
  if (conn.migrationState.numMigrations >=
      conn.transportSettings.maxNumMigrationsAllowed) {
    if (conn.qLogger) {
      conn.qLogger->addPacketDrop(
          0,
          PacketDropReason(PacketDropReason::PEER_ADDRESS_CHANGE)._to_string());
    }
    QUIC_STATS(
        conn.statsCallback,
        onPacketDropped,
        PacketDropReason::PEER_ADDRESS_CHANGE);
    throw QuicTransportException(
        "Too many migrations", TransportErrorCode::INVALID_MIGRATION);
  }
  ++conn.migrationState.numMigrations;

  bool hasPendingPathChallenge = conn.pendingEvents.pathChallenge.has_value();
  // Clear any pending path challenge frame that is not sent
  conn.pendingEvents.pathChallenge.reset();

  auto& previousPeerAddresses = conn.migrationState.previousPeerAddresses;
  auto it = std::find(
      previousPeerAddresses.begin(),
      previousPeerAddresses.end(),
      newPeerAddress);
  if (it == previousPeerAddresses.end()) {
    // send new path challenge
    conn.pendingEvents.pathChallenge.emplace(folly::Random::secureRand64());

    // If we are already in the middle of a migration reset
    // the available bytes in the rate-limited window, but keep the
    // window.
    conn.pathValidationLimiter =
        std::make_unique<PendingPathRateLimiter>(conn.udpSendPacketLen);
  } else {
    previousPeerAddresses.erase(it);
  }

  // At this point, path validation scheduled, writable bytes limit set
  // However if this is NAT rebinding, keep congestion state unchanged
  bool isNATRebinding = maybeNATRebinding(newPeerAddress, conn.peerAddress);

  // Cancel current path validation if any
  if (hasPendingPathChallenge || conn.outstandingPathValidation) {
    conn.pendingEvents.schedulePathValidationTimeout = false;
    conn.outstandingPathValidation.reset();

    // Only change congestion & rtt state if not NAT rebinding
    if (!isNATRebinding) {
      recoverOrResetCongestionAndRttState(conn, newPeerAddress);
    }
  } else {
    // Only add validated addresses to previousPeerAddresses
    conn.migrationState.previousPeerAddresses.push_back(conn.peerAddress);

    // Only change congestion & rtt state if not NAT rebinding
    if (!isNATRebinding) {
      // Current peer address is validated,
      // remember its congestion state and rtt stats
      CongestionAndRttState state = moveCurrentCongestionAndRttState(conn);
      recoverOrResetCongestionAndRttState(conn, newPeerAddress);
      conn.migrationState.lastCongestionAndRtt = std::move(state);
    }
  }

  if (conn.qLogger) {
    conn.qLogger->addConnectionMigrationUpdate(isIntentional);
  }
  conn.peerAddress = newPeerAddress;
}

void onServerReadData(
    QuicServerConnectionState& conn,
    ServerEvents::ReadData& readData) {
  switch (conn.state) {
    case ServerState::Open:
      onServerReadDataFromOpen(conn, readData);
      return;
    case ServerState::Closed:
      onServerReadDataFromClosed(conn, readData);
      return;
  }
}

static void handleCipherUnavailable(
    CipherUnavailable* originalData,
    QuicServerConnectionState& conn,
    size_t packetSize,
    ServerEvents::ReadData& readData) {
  if (!originalData->packet || originalData->packet->empty()) {
    VLOG(10) << "drop because no data " << conn;
    if (conn.qLogger) {
      conn.qLogger->addPacketDrop(packetSize, kNoData);
    }
    QUIC_STATS(
        conn.statsCallback, onPacketDropped, PacketDropReason::EMPTY_DATA);
    return;
  }
  if (originalData->protectionType != ProtectionType::ZeroRtt &&
      originalData->protectionType != ProtectionType::KeyPhaseZero) {
    VLOG(10) << "drop because unexpected protection level " << conn;
    if (conn.qLogger) {
      conn.qLogger->addPacketDrop(packetSize, kUnexpectedProtectionLevel);
    }
    QUIC_STATS(
        conn.statsCallback,
        onPacketDropped,
        PacketDropReason::UNEXPECTED_PROTECTION_LEVEL);
    return;
  }

  size_t combinedSize =
      (conn.pendingZeroRttData ? conn.pendingZeroRttData->size() : 0) +
      (conn.pendingOneRttData ? conn.pendingOneRttData->size() : 0);
  if (combinedSize >= conn.transportSettings.maxPacketsToBuffer) {
    VLOG(10) << "drop because max buffered " << conn;
    if (conn.qLogger) {
      conn.qLogger->addPacketDrop(packetSize, kMaxBuffered);
    }
    QUIC_STATS(
        conn.statsCallback, onPacketDropped, PacketDropReason::MAX_BUFFERED);
    return;
  }

  auto& pendingData = originalData->protectionType == ProtectionType::ZeroRtt
      ? conn.pendingZeroRttData
      : conn.pendingOneRttData;
  if (pendingData) {
    if (conn.qLogger) {
      conn.qLogger->addPacketBuffered(originalData->protectionType, packetSize);
    }
    QUIC_STATS(
        conn.statsCallback,
        onPacketDropped,
        PacketDropReason::PARSE_ERROR_PACKET_BUFFERED);
    ServerEvents::ReadData pendingReadData;
    pendingReadData.peer = readData.peer;
    pendingReadData.networkData = NetworkDataSingle(
        ReceivedPacket(std::move(originalData->packet)),
        readData.networkData.receiveTimePoint);
    pendingData->emplace_back(std::move(pendingReadData));
    VLOG(10) << "Adding pending data to "
             << toString(originalData->protectionType)
             << " buffer size=" << pendingData->size() << " " << conn;
  } else {
    VLOG(10) << "drop because " << toString(originalData->protectionType)
             << " buffer no longer available " << conn;
    if (conn.qLogger) {
      conn.qLogger->addPacketDrop(packetSize, kBufferUnavailable);
    }
    QUIC_STATS(
        conn.statsCallback,
        onPacketDropped,
        PacketDropReason::BUFFER_UNAVAILABLE);
    return;
  }
}

void onServerReadDataFromOpen(
    QuicServerConnectionState& conn,
    ServerEvents::ReadData& readData) {
  CHECK_EQ(conn.state, ServerState::Open);
  // Don't bother parsing if the data is empty.
  if (!readData.networkData.packet.buf ||
      readData.networkData.packet.buf->computeChainDataLength() == 0) {
    return;
  }
  bool firstPacketFromPeer = false;
  if (!conn.readCodec) {
    firstPacketFromPeer = true;

    folly::io::Cursor cursor(readData.networkData.packet.buf.get());
    auto initialByte = cursor.readBE<uint8_t>();
    auto parsedLongHeader = parseLongHeaderInvariant(initialByte, cursor);
    if (!parsedLongHeader) {
      VLOG(4) << "Could not parse initial packet header";
      if (conn.qLogger) {
        conn.qLogger->addPacketDrop(
            0,
            PacketDropReason(PacketDropReason::PARSE_ERROR_LONG_HEADER_INITIAL)
                ._to_string());
      }
      QUIC_STATS(
          conn.statsCallback,
          onPacketDropped,
          PacketDropReason::PARSE_ERROR_LONG_HEADER_INITIAL);
      return;
    }
    QuicVersion version = parsedLongHeader->invariant.version;
    if (version == QuicVersion::VERSION_NEGOTIATION) {
      VLOG(4) << "Server droppiong VN packet";
      if (conn.qLogger) {
        conn.qLogger->addPacketDrop(
            0,
            PacketDropReason(PacketDropReason::INVALID_PACKET_VN)._to_string());
      }
      QUIC_STATS(
          conn.statsCallback,
          onPacketDropped,
          PacketDropReason::INVALID_PACKET_VN);
      return;
    }

    const auto& clientConnectionId = parsedLongHeader->invariant.srcConnId;
    const auto& initialDestinationConnectionId =
        parsedLongHeader->invariant.dstConnId;

    if (initialDestinationConnectionId.size() < kDefaultConnectionIdSize) {
      VLOG(4) << "Initial connectionid too small";
      if (conn.qLogger) {
        conn.qLogger->addPacketDrop(
            0,
            PacketDropReason(PacketDropReason::INITIAL_CONNID_SMALL)
                ._to_string());
      }
      QUIC_STATS(
          conn.statsCallback,
          onPacketDropped,
          PacketDropReason::INITIAL_CONNID_SMALL);
      return;
    }

    CHECK(conn.connIdAlgo) << "ConnectionIdAlgo is not set.";
    CHECK(!conn.serverConnectionId.has_value());
    // serverConnIdParams must be set by the QuicServerTransport
    CHECK(conn.serverConnIdParams);

    auto newServerConnIdData = conn.createAndAddNewSelfConnId();
    CHECK(newServerConnIdData.has_value());
    conn.serverConnectionId = newServerConnIdData->connId;

    auto customTransportParams = setSupportedExtensionTransportParameters(conn);

    QUIC_STATS(conn.statsCallback, onStatelessReset);
    conn.serverHandshakeLayer->accept(
        std::make_shared<ServerTransportParametersExtension>(
            version,
            conn.transportSettings.advertisedInitialConnectionFlowControlWindow,
            conn.transportSettings
                .advertisedInitialBidiLocalStreamFlowControlWindow,
            conn.transportSettings
                .advertisedInitialBidiRemoteStreamFlowControlWindow,
            conn.transportSettings.advertisedInitialUniStreamFlowControlWindow,
            conn.transportSettings.advertisedInitialMaxStreamsBidi,
            conn.transportSettings.advertisedInitialMaxStreamsUni,
            conn.transportSettings.disableMigration,
            conn.transportSettings.idleTimeout,
            conn.transportSettings.ackDelayExponent,
            conn.transportSettings.maxRecvPacketSize,
            *newServerConnIdData->token,
            conn.serverConnectionId.value(),
            initialDestinationConnectionId,
            customTransportParams));
    conn.transportParametersEncoded = true;
    const CryptoFactory& cryptoFactory =
        conn.serverHandshakeLayer->getCryptoFactory();
    conn.readCodec = std::make_unique<QuicReadCodec>(QuicNodeType::Server);
    conn.readCodec->setInitialReadCipher(cryptoFactory.getClientInitialCipher(
        initialDestinationConnectionId, version));
    conn.readCodec->setClientConnectionId(clientConnectionId);
    conn.readCodec->setServerConnectionId(*conn.serverConnectionId);
    if (conn.qLogger) {
      conn.qLogger->setScid(conn.serverConnectionId);
      conn.qLogger->setDcid(initialDestinationConnectionId);
    }
    conn.readCodec->setCodecParameters(CodecParameters(
        conn.peerAckDelayExponent,
        version,
        conn.transportSettings.maybeAckReceiveTimestampsConfigSentToPeer));
    conn.initialWriteCipher = cryptoFactory.getServerInitialCipher(
        initialDestinationConnectionId, version);

    conn.readCodec->setInitialHeaderCipher(
        cryptoFactory.makeClientInitialHeaderCipher(
            initialDestinationConnectionId, version));
    conn.initialHeaderCipher = cryptoFactory.makeServerInitialHeaderCipher(
        initialDestinationConnectionId, version);
    conn.peerAddress = conn.originalPeerAddress;
  }
  BufQueue udpData;
  udpData.append(std::move(readData.networkData.packet.buf));
  for (uint16_t processedPackets = 0;
       !udpData.empty() && processedPackets < kMaxNumCoalescedPackets;
       processedPackets++) {
    size_t dataSize = udpData.chainLength();
    auto parsedPacket = conn.readCodec->parsePacket(udpData, conn.ackStates);
    size_t packetSize = dataSize - udpData.chainLength();

    switch (parsedPacket.type()) {
      case CodecResult::Type::CIPHER_UNAVAILABLE: {
        handleCipherUnavailable(
            parsedPacket.cipherUnavailable(), conn, packetSize, readData);
        break;
      }
      case CodecResult::Type::RETRY: {
        VLOG(10) << "drop because the server is not supposed to "
                 << "receive a retry " << conn;
        if (conn.qLogger) {
          conn.qLogger->addPacketDrop(packetSize, kRetry);
        }
        QUIC_STATS(
            conn.statsCallback,
            onPacketDropped,
            PacketDropReason::UNEXPECTED_RETRY);
        break;
      }
      case CodecResult::Type::STATELESS_RESET: {
        VLOG(10) << "drop because reset " << conn;
        if (conn.qLogger) {
          conn.qLogger->addPacketDrop(packetSize, kReset);
        }
        QUIC_STATS(
            conn.statsCallback,
            onPacketDropped,
            PacketDropReason::UNEXPECTED_RESET);
        break;
      }
      case CodecResult::Type::NOTHING: {
        VLOG(10) << "drop cipher unavailable, no data " << conn;
        if (conn.qLogger) {
          conn.qLogger->addPacketDrop(packetSize, kCipherUnavailable);
        }
        QUIC_STATS(
            conn.statsCallback,
            onPacketDropped,
            PacketDropReason::UNEXPECTED_NOTHING);
        if (firstPacketFromPeer) {
          throw QuicInternalException(
              "Failed to decrypt first packet from peer",
              LocalErrorCode::CONNECTION_ABANDONED);
        }
        break;
      }
      case CodecResult::Type::REGULAR_PACKET:
        break;
    }

    RegularQuicPacket* regularOptional = parsedPacket.regularPacket();
    if (!regularOptional) {
      // We were unable to parse the packet, drop for now. All the drop reasons
      // should have already been logged into QLogger and QuicTrace inside the
      // previous switch-case block. All stats have already been updated.
      VLOG(10) << "Not able to parse QUIC packet " << conn;
      continue;
    }
    if (regularOptional->frames.empty()) {
      // This packet had a pareseable header (most probably short header)
      // but no data. This is a protocol violation so we throw an exception.
      // This drop has not been recorded in the switch-case block above
      // so we record it here.
      if (conn.qLogger) {
        conn.qLogger->addPacketDrop(
            packetSize,
            PacketDropReason(PacketDropReason::PROTOCOL_VIOLATION)
                ._to_string());
      }
      QUIC_STATS(
          conn.statsCallback,
          onPacketDropped,
          PacketDropReason::PROTOCOL_VIOLATION);
      throw QuicTransportException(
          "Packet has no frames", TransportErrorCode::PROTOCOL_VIOLATION);
    }

    auto protectionLevel = regularOptional->header.getProtectionType();
    auto encryptionLevel = protectionTypeToEncryptionLevel(protectionLevel);

    auto packetNum = regularOptional->header.getPacketSequenceNum();
    auto packetNumberSpace = regularOptional->header.getPacketNumberSpace();

    auto& regularPacket = *regularOptional;

    bool isProtectedPacket = protectionLevel == ProtectionType::ZeroRtt ||
        protectionLevel == ProtectionType::KeyPhaseZero ||
        protectionLevel == ProtectionType::KeyPhaseOne;

    bool isZeroRttPacket = protectionLevel == ProtectionType::ZeroRtt;

    if (!isProtectedPacket || isZeroRttPacket) {
      // there are some frame restrictions
      auto isFrameInvalidFn = !isProtectedPacket
          ? isUnprotectedPacketFrameInvalid
          : isZeroRttPacketFrameInvalid;
      for (auto& quicFrame : regularPacket.frames) {
        bool isFrameInvalid = isFrameInvalidFn(quicFrame);
        if (isFrameInvalid) {
          QUIC_STATS(
              conn.statsCallback,
              onPacketDropped,
              PacketDropReason::PROTOCOL_VIOLATION);
          if (conn.qLogger) {
            conn.qLogger->addPacketDrop(
                packetSize,
                PacketDropReason(PacketDropReason::PROTOCOL_VIOLATION)
                    ._to_string());
          }
          throw QuicTransportException(
              "Invalid frame", TransportErrorCode::PROTOCOL_VIOLATION);
        }
      }
    }

    CHECK(conn.clientConnectionId);
    if (conn.qLogger) {
      conn.qLogger->addPacket(regularPacket, packetSize);
    }
    // We assume that the higher layer takes care of validating that the version
    // is supported.
    if (!conn.version) {
      LongHeader* longHeader = regularPacket.header.asLong();
      if (!longHeader) {
        throw QuicTransportException(
            "Invalid packet type", TransportErrorCode::PROTOCOL_VIOLATION);
      }
      conn.version = longHeader->getVersion();
      maybeSetExperimentalSettings(conn);
    }

    if (conn.peerAddress != readData.peer) {
      QUIC_STATS(conn.statsCallback, onPeerAddressChanged);
      auto migrationDenied = (encryptionLevel != EncryptionLevel::AppData) ||
          conn.transportSettings.disableMigration;
      if (migrationDenied) {
        if (conn.qLogger) {
          conn.qLogger->addPacketDrop(
              packetSize,
              PacketDropReason(PacketDropReason::PEER_ADDRESS_CHANGE)
                  ._to_string());
        }
        QUIC_STATS(
            conn.statsCallback,
            onPacketDropped,
            PacketDropReason::PEER_ADDRESS_CHANGE);
        if (!conn.transportSettings.closeIfMigrationDuringHandshake) {
          return;
        }
        const char* errMsg = encryptionLevel != EncryptionLevel::AppData
            ? "Migration not allowed during handshake"
            : "Migration disabled";
        throw QuicTransportException(
            errMsg, TransportErrorCode::INVALID_MIGRATION);
      }
    }

    auto& ackState = getAckState(conn, packetNumberSpace);
    uint64_t distanceFromExpectedPacketNum = updateLargestReceivedPacketNum(
        conn, ackState, packetNum, readData.networkData.receiveTimePoint);
    if (distanceFromExpectedPacketNum > 0) {
      QUIC_STATS(conn.statsCallback, onOutOfOrderPacketReceived);
    }
    DCHECK(hasReceivedPackets(conn));

    bool pktHasRetransmittableData = false;
    bool pktHasCryptoData = false;
    bool isNonProbingPacket = false;
    bool handshakeConfirmedThisLoop = false;

    for (auto& quicFrame : regularPacket.frames) {
      switch (quicFrame.type()) {
        case QuicFrame::Type::ReadAckFrame: {
          VLOG(10) << "Server received ack frame packet=" << packetNum << " "
                   << conn;
          isNonProbingPacket = true;
          ReadAckFrame& ackFrame = *quicFrame.asReadAckFrame();
          conn.lastProcessedAckEvents.emplace_back(processAckFrame(
              conn,
              packetNumberSpace,
              ackFrame,
              [&](const OutstandingPacketWrapper&,
                  const QuicWriteFrame& packetFrame,
                  const ReadAckFrame&) {
                switch (packetFrame.type()) {
                  case QuicWriteFrame::Type::WriteStreamFrame: {
                    const WriteStreamFrame& frame =
                        *packetFrame.asWriteStreamFrame();
                    VLOG(4)
                        << "Server received ack for stream=" << frame.streamId
                        << " offset=" << frame.offset << " fin=" << frame.fin
                        << " len=" << frame.len << " " << conn;
                    auto ackedStream =
                        conn.streamManager->getStream(frame.streamId);
                    if (ackedStream) {
                      sendAckSMHandler(*ackedStream, frame);
                    }
                    break;
                  }
                  case QuicWriteFrame::Type::WriteCryptoFrame: {
                    const WriteCryptoFrame& frame =
                        *packetFrame.asWriteCryptoFrame();
                    auto cryptoStream =
                        getCryptoStream(*conn.cryptoState, encryptionLevel);
                    processCryptoStreamAck(
                        *cryptoStream, frame.offset, frame.len);
                    break;
                  }
                  case QuicWriteFrame::Type::RstStreamFrame: {
                    const RstStreamFrame& frame =
                        *packetFrame.asRstStreamFrame();
                    VLOG(4) << "Server received ack for reset stream="
                            << frame.streamId << " " << conn;
                    auto stream = conn.streamManager->getStream(frame.streamId);
                    if (stream) {
                      sendRstAckSMHandler(*stream);
                    }
                    break;
                  }
                  case QuicWriteFrame::Type::WriteAckFrame: {
                    const WriteAckFrame& frame = *packetFrame.asWriteAckFrame();
                    DCHECK(!frame.ackBlocks.empty());
                    VLOG(4) << "Server received ack for largestAcked="
                            << frame.ackBlocks.front().end << " " << conn;
                    commonAckVisitorForAckFrame(ackState, frame);
                    break;
                  }
                  case QuicWriteFrame::Type::PingFrame:
                    conn.pendingEvents.cancelPingTimeout = true;
                    return;
                  case QuicWriteFrame::Type::QuicSimpleFrame: {
                    const QuicSimpleFrame& frame =
                        *packetFrame.asQuicSimpleFrame();
                    // ACK of HandshakeDone is a server-specific behavior.
                    if (frame.asHandshakeDoneFrame()) {
                      // Call handshakeConfirmed outside of the packet
                      // processing loop to avoid a re-entrancy.
                      handshakeConfirmedThisLoop = true;
                    }
                    break;
                  }
                  default: {
                    break;
                  }
                }
              },
              markPacketLoss,
              readData.networkData.receiveTimePoint));
          break;
        }
        case QuicFrame::Type::RstStreamFrame: {
          RstStreamFrame& frame = *quicFrame.asRstStreamFrame();
          VLOG(10) << "Server received reset stream=" << frame.streamId << " "
                   << conn;
          pktHasRetransmittableData = true;
          isNonProbingPacket = true;
          auto stream = conn.streamManager->getStream(frame.streamId);
          if (!stream) {
            break;
          }
          receiveRstStreamSMHandler(*stream, frame);
          break;
        }
        case QuicFrame::Type::ReadCryptoFrame: {
          pktHasRetransmittableData = true;
          pktHasCryptoData = true;
          isNonProbingPacket = true;
          ReadCryptoFrame& cryptoFrame = *quicFrame.asReadCryptoFrame();
          VLOG(10) << "Server received crypto data offset="
                   << cryptoFrame.offset
                   << " len=" << cryptoFrame.data->computeChainDataLength()
                   << " currentReadOffset="
                   << getCryptoStream(*conn.cryptoState, encryptionLevel)
                          ->currentReadOffset
                   << " " << conn;
          appendDataToReadBuffer(
              *getCryptoStream(*conn.cryptoState, encryptionLevel),
              StreamBuffer(
                  std::move(cryptoFrame.data), cryptoFrame.offset, false));
          break;
        }
        case QuicFrame::Type::ReadStreamFrame: {
          ReadStreamFrame& frame = *quicFrame.asReadStreamFrame();
          VLOG(10) << "Server received stream data for stream="
                   << frame.streamId << ", offset=" << frame.offset
                   << " len=" << frame.data->computeChainDataLength()
                   << " fin=" << frame.fin << " " << conn;
          pktHasRetransmittableData = true;
          isNonProbingPacket = true;
          auto stream = conn.streamManager->getStream(
              frame.streamId, frame.streamGroupId);
          // Ignore data from closed streams that we don't have the
          // state for any more.
          if (stream) {
            receiveReadStreamFrameSMHandler(*stream, std::move(frame));
          }
          break;
        }
        case QuicFrame::Type::MaxDataFrame: {
          MaxDataFrame& connWindowUpdate = *quicFrame.asMaxDataFrame();
          VLOG(10) << "Server received max data offset="
                   << connWindowUpdate.maximumData << " " << conn;
          pktHasRetransmittableData = true;
          isNonProbingPacket = true;
          handleConnWindowUpdate(conn, connWindowUpdate, packetNum);
          break;
        }
        case QuicFrame::Type::MaxStreamDataFrame: {
          MaxStreamDataFrame& streamWindowUpdate =
              *quicFrame.asMaxStreamDataFrame();
          VLOG(10) << "Server received max stream data stream="
                   << streamWindowUpdate.streamId
                   << " offset=" << streamWindowUpdate.maximumData << " "
                   << conn;
          if (isReceivingStream(conn.nodeType, streamWindowUpdate.streamId)) {
            throw QuicTransportException(
                "Received MaxStreamDataFrame for receiving stream.",
                TransportErrorCode::STREAM_STATE_ERROR);
          }
          pktHasRetransmittableData = true;
          isNonProbingPacket = true;
          auto stream =
              conn.streamManager->getStream(streamWindowUpdate.streamId);
          if (stream) {
            handleStreamWindowUpdate(
                *stream, streamWindowUpdate.maximumData, packetNum);
          }
          break;
        }
        case QuicFrame::Type::DataBlockedFrame: {
          VLOG(10) << "Server received blocked " << conn;
          pktHasRetransmittableData = true;
          isNonProbingPacket = true;
          handleConnBlocked(conn);
          break;
        }
        case QuicFrame::Type::StreamDataBlockedFrame: {
          StreamDataBlockedFrame& blocked =
              *quicFrame.asStreamDataBlockedFrame();
          VLOG(10) << "Server received blocked stream=" << blocked.streamId
                   << " " << conn;
          pktHasRetransmittableData = true;
          isNonProbingPacket = true;
          auto stream = conn.streamManager->getStream(blocked.streamId);
          if (stream) {
            handleStreamBlocked(*stream);
          }
          break;
        }
        case QuicFrame::Type::StreamsBlockedFrame: {
          StreamsBlockedFrame& blocked = *quicFrame.asStreamsBlockedFrame();
          // peer wishes to open a stream, but is unable to due to the maximum
          // stream limit set by us
          // TODO implement the handler
          isNonProbingPacket = true;
          VLOG(10) << "Server received streams blocked limit="
                   << blocked.streamLimit << ", " << conn;
          break;
        }
        case QuicFrame::Type::ConnectionCloseFrame: {
          isNonProbingPacket = true;
          ConnectionCloseFrame& connFrame = *quicFrame.asConnectionCloseFrame();
          auto errMsg = folly::to<std::string>(
              "Server closed by peer reason=", connFrame.reasonPhrase);
          VLOG(4) << errMsg << " " << conn;
          // we want to deliver app callbacks with the peer supplied error,
          // but send a NO_ERROR to the peer.
          if (conn.qLogger) {
            conn.qLogger->addTransportStateUpdate(getPeerClose(errMsg));
          }
          conn.peerConnectionError =
              QuicError(QuicErrorCode(connFrame.errorCode), std::move(errMsg));
          if (getSendConnFlowControlBytesWire(conn) == 0 &&
              conn.flowControlState.sumCurStreamBufferLen) {
            VLOG(2) << "Client gives up a flow control blocked connection";
          }
          return;
        }
        case QuicFrame::Type::PingFrame:
          isNonProbingPacket = true;
          // Ping isn't retransmittable data. But we would like to ack them
          // early.
          pktHasRetransmittableData = true;
          conn.pendingEvents.notifyPingReceived = true;
          break;
        case QuicFrame::Type::PaddingFrame:
          break;
        case QuicFrame::Type::QuicSimpleFrame: {
          auto dstConnId =
              regularPacket.header.getHeaderForm() == HeaderForm::Short
              ? regularPacket.header.asShort()->getConnectionId()
              : regularPacket.header.asLong()->getDestinationConnId();
          pktHasRetransmittableData = true;
          QuicSimpleFrame& simpleFrame = *quicFrame.asQuicSimpleFrame();
          isNonProbingPacket |= updateSimpleFrameOnPacketReceived(
              conn, simpleFrame, dstConnId, readData.peer != conn.peerAddress);
          break;
        }
        case QuicFrame::Type::DatagramFrame: {
          DatagramFrame& frame = *quicFrame.asDatagramFrame();
          VLOG(10) << "Server received datagram data: "
                   << " len=" << frame.length;
          // Datagram isn't retransmittable. But we would like to ack them
          // early. So, make Datagram frames count towards ack policy
          pktHasRetransmittableData = true;
          handleDatagram(conn, frame, readData.networkData.receiveTimePoint);
          break;
        }
        case QuicFrame::Type::ImmediateAckFrame: {
          if (!conn.transportSettings.minAckDelay.hasValue()) {
            // We do not accept IMMEDIATE_ACK frames. This is a protocol
            // violation.
            throw QuicTransportException(
                "Received IMMEDIATE_ACK frame without announcing min_ack_delay",
                TransportErrorCode::PROTOCOL_VIOLATION,
                FrameType::IMMEDIATE_ACK);
          }
          // Send an ACK from any packet number space.
          if (conn.ackStates.initialAckState) {
            conn.ackStates.initialAckState->needsToSendAckImmediately = true;
          }
          if (conn.ackStates.handshakeAckState) {
            conn.ackStates.handshakeAckState->needsToSendAckImmediately = true;
          }
          conn.ackStates.appDataAckState.needsToSendAckImmediately = true;
          break;
        }
        default: {
          break;
        }
      }
    }

    if (handshakeConfirmedThisLoop) {
      handshakeConfirmed(conn);
    }

    // Update writable limit before processing the handshake data. This is so
    // that if we haven't decided whether or not to validate the peer, we won't
    // increase the limit.
    updateWritableByteLimitOnRecvPacket(conn);

    if (conn.peerAddress != readData.peer) {
      // TODO use new conn id, make sure the other endpoint has new conn id
      if (isNonProbingPacket) {
        if (packetNum == ackState.largestRecvdPacketNum) {
          ShortHeader* shortHeader = regularPacket.header.asShort();
          bool intentionalMigration = false;
          if (shortHeader &&
              shortHeader->getConnectionId() != conn.serverConnectionId) {
            intentionalMigration = true;
          }
          onConnectionMigration(conn, readData.peer, intentionalMigration);
        }
      } else {
        // Server will need to response with PathResponse to the new address
        // while not updating peerAddress to new address
        if (conn.qLogger) {
          conn.qLogger->addPacketDrop(
              packetSize,
              PacketDropReason(PacketDropReason::PEER_ADDRESS_CHANGE)
                  ._to_string());
        }
        QUIC_STATS(
            conn.statsCallback,
            onPacketDropped,
            PacketDropReason::PEER_ADDRESS_CHANGE);
        throw QuicTransportException(
            "Probing not supported yet", TransportErrorCode::INVALID_MIGRATION);
      }
    }

    // Try reading bytes off of crypto, and performing a handshake.
    auto data = readDataFromCryptoStream(
        *getCryptoStream(*conn.cryptoState, encryptionLevel));
    if (data) {
      conn.serverHandshakeLayer->doHandshake(std::move(data), encryptionLevel);

      try {
        updateHandshakeState(conn);
      } catch (...) {
        if (conn.qLogger) {
          conn.qLogger->addPacketDrop(
              packetSize,
              PacketDropReason(PacketDropReason::TRANSPORT_PARAMETER_ERROR)
                  ._to_string());
        }
        QUIC_STATS(
            conn.statsCallback,
            onPacketDropped,
            PacketDropReason::TRANSPORT_PARAMETER_ERROR);
        throw;
      }
    }
    updateAckSendStateOnRecvPacket(
        conn,
        ackState,
        distanceFromExpectedPacketNum,
        pktHasRetransmittableData,
        pktHasCryptoData,
        packetNumberSpace == PacketNumberSpace::Initial);
    if (encryptionLevel == EncryptionLevel::Handshake &&
        conn.initialWriteCipher) {
      conn.initialWriteCipher.reset();
      conn.initialHeaderCipher.reset();
      conn.readCodec->setInitialReadCipher(nullptr);
      conn.readCodec->setInitialHeaderCipher(nullptr);
      implicitAckCryptoStream(conn, EncryptionLevel::Initial);
    }
    QUIC_STATS(conn.statsCallback, onPacketProcessed);
  }
  VLOG_IF(4, !udpData.empty())
      << "Leaving " << udpData.chainLength()
      << " bytes unprocessed after attempting to process "
      << kMaxNumCoalescedPackets << " packets.";
}

void onServerReadDataFromClosed(
    QuicServerConnectionState& conn,
    ServerEvents::ReadData& readData) {
  CHECK_EQ(conn.state, ServerState::Closed);
  BufQueue udpData;
  udpData.append(std::move(readData.networkData.packet.buf));
  auto packetSize = udpData.empty() ? 0 : udpData.chainLength();
  if (!conn.readCodec) {
    // drop data. We closed before we even got the first packet. This is
    // normally not possible but might as well.
    if (conn.qLogger) {
      conn.qLogger->addPacketDrop(
          packetSize,
          PacketDropReason(PacketDropReason::SERVER_STATE_CLOSED)._to_string());
    }
    QUIC_STATS(
        conn.statsCallback,
        onPacketDropped,
        PacketDropReason::SERVER_STATE_CLOSED);
    return;
  }

  if (conn.peerConnectionError) {
    // We already got a peer error. We can ignore any further peer errors.
    if (conn.qLogger) {
      conn.qLogger->addPacketDrop(
          packetSize,
          PacketDropReason(PacketDropReason::SERVER_STATE_CLOSED)._to_string());
    }
    QUIC_STATS(
        conn.statsCallback,
        onPacketDropped,
        PacketDropReason::SERVER_STATE_CLOSED);
    return;
  }
  auto parsedPacket = conn.readCodec->parsePacket(udpData, conn.ackStates);
  switch (parsedPacket.type()) {
    case CodecResult::Type::CIPHER_UNAVAILABLE: {
      VLOG(10) << "drop cipher unavailable " << conn;
      if (conn.qLogger) {
        conn.qLogger->addPacketDrop(packetSize, kCipherUnavailable);
      }
      QUIC_STATS(
          conn.statsCallback,
          onPacketDropped,
          PacketDropReason::CIPHER_UNAVAILABLE);
      break;
    }
    case CodecResult::Type::RETRY: {
      VLOG(10) << "drop because the server is not supposed to "
               << "receive a retry " << conn;
      if (conn.qLogger) {
        conn.qLogger->addPacketDrop(packetSize, kRetry);
      }
      QUIC_STATS(
          conn.statsCallback,
          onPacketDropped,
          PacketDropReason::UNEXPECTED_RETRY);
      break;
    }
    case CodecResult::Type::STATELESS_RESET: {
      VLOG(10) << "drop because reset " << conn;
      if (conn.qLogger) {
        conn.qLogger->addPacketDrop(packetSize, kReset);
      }
      QUIC_STATS(
          conn.statsCallback,
          onPacketDropped,
          PacketDropReason::UNEXPECTED_RESET);
      break;
    }
    case CodecResult::Type::NOTHING: {
      VLOG(10) << "drop cipher unavailable, no data " << conn;
      if (conn.qLogger) {
        conn.qLogger->addPacketDrop(packetSize, kCipherUnavailable);
      }
      QUIC_STATS(
          conn.statsCallback,
          onPacketDropped,
          PacketDropReason::UNEXPECTED_NOTHING);
      break;
    }
    case CodecResult::Type::REGULAR_PACKET:
      break;
  }
  auto regularOptional = parsedPacket.regularPacket();
  if (!regularOptional) {
    // We were unable to parse the packet, drop for now.
    // Packet drop has already been added to qlog and stats
    VLOG(10) << "Not able to parse QUIC packet " << conn;
    return;
  }
  if (regularOptional->frames.empty()) {
    // This packet had a pareseable header (most probably short header)
    // but no data. This is a protocol violation so we throw an exception.
    // This drop has not been recorded in the switch-case block above
    // so we record it here.
    if (conn.qLogger) {
      conn.qLogger->addPacketDrop(
          packetSize,
          PacketDropReason(PacketDropReason::PROTOCOL_VIOLATION)._to_string());
    }
    QUIC_STATS(
        conn.statsCallback,
        onPacketDropped,
        PacketDropReason::PROTOCOL_VIOLATION);
    throw QuicTransportException(
        "Packet has no frames", TransportErrorCode::PROTOCOL_VIOLATION);
  }

  auto& regularPacket = *regularOptional;
  auto packetNum = regularPacket.header.getPacketSequenceNum();
  auto pnSpace = regularPacket.header.getPacketNumberSpace();
  if (conn.qLogger) {
    conn.qLogger->addPacket(regularPacket, packetSize);
  }

  // Only process the close frames in the packet
  for (auto& quicFrame : regularPacket.frames) {
    switch (quicFrame.type()) {
      case QuicFrame::Type::ConnectionCloseFrame: {
        ConnectionCloseFrame& connFrame = *quicFrame.asConnectionCloseFrame();
        auto errMsg = folly::to<std::string>(
            "Server closed by peer reason=", connFrame.reasonPhrase);
        VLOG(4) << errMsg << " " << conn;
        if (conn.qLogger) {
          conn.qLogger->addTransportStateUpdate(getPeerClose(errMsg));
        }
        // we want to deliver app callbacks with the peer supplied error,
        // but send a NO_ERROR to the peer.
        conn.peerConnectionError =
            QuicError(QuicErrorCode(connFrame.errorCode), std::move(errMsg));
        break;
      }
      default:
        break;
    }
  }

  // We only need to set the largest received packet number in order to
  // determine whether or not we need to send a new close.
  auto& largestRecvdPacketNum =
      getAckState(conn, pnSpace).largestRecvdPacketNum;
  largestRecvdPacketNum =
      std::max<PacketNum>(largestRecvdPacketNum.value_or(packetNum), packetNum);
}

void onServerClose(QuicServerConnectionState& conn) {
  switch (conn.state) {
    case ServerState::Open:
      onServerCloseOpenState(conn);
      return;
    case ServerState::Closed:
      return;
  }
}

void onServerCloseOpenState(QuicServerConnectionState& conn) {
  conn.state = ServerState::Closed;
}

folly::Optional<ConnectionIdData>
QuicServerConnectionState::createAndAddNewSelfConnId() {
  // Should be set right after server transport construction.
  CHECK(connIdAlgo);
  CHECK(serverConnIdParams);

  CHECK(transportSettings.statelessResetTokenSecret);

  StatelessResetGenerator generator(
      transportSettings.statelessResetTokenSecret.value(),
      serverAddr.getFullyQualified());

  // The default connectionId algo has 36 bits of randomness.
  auto encodedCid = connIdAlgo->encodeConnectionId(*serverConnIdParams);
  size_t encodedTimes = 1;
  while (encodedCid && connIdRejector &&
         connIdRejector->rejectConnectionId(*encodedCid) &&
         encodedTimes < kConnIdEncodingRetryLimit) {
    encodedCid = connIdAlgo->encodeConnectionId(*serverConnIdParams);
    encodedTimes++;
  }
  LOG_IF(ERROR, encodedTimes == kConnIdEncodingRetryLimit)
      << "Quic CIDRejector rejected all conneectionIDs";
  if (encodedCid.hasError()) {
    return folly::none;
  }
  QUIC_STATS(statsCallback, onConnectionIdCreated, encodedTimes);
  auto newConnIdData =
      ConnectionIdData{*encodedCid, nextSelfConnectionIdSequence++};
  newConnIdData.token = generator.generateToken(newConnIdData.connId);
  selfConnectionIds.push_back(newConnIdData);
  return newConnIdData;
}

std::vector<TransportParameter> setSupportedExtensionTransportParameters(
    QuicServerConnectionState& conn) {
  std::vector<TransportParameter> customTransportParams;
  const auto& ts = conn.transportSettings;
  if (ts.datagramConfig.enabled) {
    CustomIntegralTransportParameter maxDatagramFrameSize(
        static_cast<uint64_t>(TransportParameterId::max_datagram_frame_size),
        conn.datagramState.maxReadFrameSize);
    customTransportParams.push_back(maxDatagramFrameSize.encode());
  }

  if (ts.advertisedMaxStreamGroups > 0) {
    CustomIntegralTransportParameter streamGroupsEnabledParam(
        static_cast<uint64_t>(TransportParameterId::stream_groups_enabled),
        ts.advertisedMaxStreamGroups);

    if (!setCustomTransportParameter(
            streamGroupsEnabledParam, customTransportParams)) {
      LOG(ERROR) << "failed to set stream groups enabled transport parameter";
    }
  }

  CustomIntegralTransportParameter ackReceiveTimestampsEnabled(
      static_cast<uint64_t>(
          TransportParameterId::ack_receive_timestamps_enabled),
      ts.maybeAckReceiveTimestampsConfigSentToPeer.has_value() ? 1 : 0);
  customTransportParams.push_back(ackReceiveTimestampsEnabled.encode());

  if (ts.maybeAckReceiveTimestampsConfigSentToPeer.has_value()) {
    CustomIntegralTransportParameter maxReceiveTimestampsPerAck(
        static_cast<uint64_t>(
            TransportParameterId::max_receive_timestamps_per_ack),
        ts.maybeAckReceiveTimestampsConfigSentToPeer
            ->maxReceiveTimestampsPerAck);
    customTransportParams.push_back(maxReceiveTimestampsPerAck.encode());

    CustomIntegralTransportParameter receiveTimestampsExponent(
        static_cast<uint64_t>(
            TransportParameterId::receive_timestamps_exponent),
        ts.maybeAckReceiveTimestampsConfigSentToPeer
            ->receiveTimestampsExponent);
    customTransportParams.push_back(receiveTimestampsExponent.encode());
  }

  if (ts.minAckDelay) {
    CustomIntegralTransportParameter minAckDelay(
        static_cast<uint64_t>(TransportParameterId::min_ack_delay),
        ts.minAckDelay.value().count());
    customTransportParams.push_back(minAckDelay.encode());
  }

  if (ts.advertisedKnobFrameSupport) {
    CustomIntegralTransportParameter knobFrameSupport(
        static_cast<uint64_t>(TransportParameterId::knob_frames_supported), 1);
    customTransportParams.push_back(knobFrameSupport.encode());
  }

  return customTransportParams;
}
} // namespace quic
