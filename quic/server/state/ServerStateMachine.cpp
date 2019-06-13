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
using namespace std::chrono_literals;

namespace {
using PacketDropReason = QuicTransportStatsCallback::PacketDropReason;
} // namespace
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
  conn.lossState.srtt = 0us;
  conn.lossState.lrtt = 0us;
  conn.lossState.rttvar = 0us;
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
  conn.peerIdleTimeout = std::chrono::milliseconds(idleTimeout.value_or(0));
  conn.peerIdleTimeout = timeMin(conn.peerIdleTimeout, kMaxIdleTimeout);
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
    // TODO T33014230 subnet matching
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

  conn.transportSettings.advertisedInitialConnectionWindowSize = initialMaxData;
  conn.transportSettings.advertisedInitialBidiLocalStreamWindowSize =
      initialMaxStreamDataBidiLocal;
  conn.transportSettings.advertisedInitialBidiRemoteStreamWindowSize =
      initialMaxStreamDataBidiRemote;
  conn.transportSettings.advertisedInitialUniStreamWindowSize =
      initialMaxStreamDataUni;
  updateFlowControlStateWithSettings(
      conn.flowControlState, conn.transportSettings);

  conn.transportSettings.advertisedInitialMaxStreamsBidi =
      initialMaxStreamsBidi;
  conn.transportSettings.advertisedInitialMaxStreamsUni = initialMaxStreamsUni;
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

  // At this point, path validation scheduled, writable bytes limit set
  // However if this is NAT rebinding, keep congestion state unchanged
  bool isNATRebinding = maybeNATRebinding(newPeerAddress, conn.peerAddress);

  // Cancel current path validation if any
  if (conn.outstandingPathValidation) {
    conn.pendingEvents.schedulePathValidationTimeout = false;
    conn.outstandingPathValidation = folly::none;

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

void onServerReadDataFromOpen(
    QuicServerConnectionState& conn,
    ServerEvents::ReadData& readData) {
  CHECK_EQ(conn.state, ServerState::Open);
  // Don't bother parsing if the data is empty.
  if (!readData.networkData.data ||
      readData.networkData.data->computeChainDataLength() == 0) {
    return;
  }
  if (!conn.readCodec) {
    // First packet from the peer
    folly::io::Cursor cursor(readData.networkData.data.get());
    auto initialByte = cursor.readBE<uint8_t>();
    auto parsedLongHeader = parseLongHeaderInvariant(initialByte, cursor);
    if (!parsedLongHeader) {
      VLOG(4) << "Could not parse initial packet header";
      QUIC_STATS(
          conn.infoCallback, onPacketDropped, PacketDropReason::PARSE_ERROR);
      return;
    }
    QuicVersion version = parsedLongHeader->invariant.version;
    if (version == QuicVersion::VERSION_NEGOTIATION) {
      VLOG(4) << "Server droppiong VN packet";
      QUIC_STATS(
          conn.infoCallback, onPacketDropped, PacketDropReason::INVALID_PACKET);
      return;
    }

    const auto& clientConnectionId = parsedLongHeader->invariant.srcConnId;
    const auto& initialDestinationConnectionId =
        parsedLongHeader->invariant.dstConnId;

    if (initialDestinationConnectionId.size() < kDefaultConnectionIdSize) {
      VLOG(4) << "Initial connectionid too small";
      QUIC_STATS(
          conn.infoCallback,
          onPacketDropped,
          PacketDropReason::INITIAL_CONNID_SMALL);
      return;
    }

    CHECK(conn.connIdAlgo) << "ConnectionIdAlgo is not set.";
    CHECK(!conn.serverConnectionId.hasValue());
    // serverConnIdParams must be set by the QuicServerTransport
    CHECK(conn.serverConnIdParams);

    conn.serverConnectionId =
        conn.connIdAlgo->encodeConnectionId(*conn.serverConnIdParams);
    StatelessResetGenerator generator(
        conn.transportSettings.statelessResetTokenSecret.value(),
        conn.serverAddr.getFullyQualified());
    StatelessResetToken token =
        generator.generateToken(*conn.serverConnectionId);

    conn.serverHandshakeLayer->accept(
        std::make_shared<ServerTransportParametersExtension>(
            version,
            conn.supportedVersions,
            conn.transportSettings.advertisedInitialConnectionWindowSize,
            conn.transportSettings.advertisedInitialBidiLocalStreamWindowSize,
            conn.transportSettings.advertisedInitialBidiRemoteStreamWindowSize,
            conn.transportSettings.advertisedInitialUniStreamWindowSize,
            conn.transportSettings.advertisedInitialMaxStreamsBidi,
            conn.transportSettings.advertisedInitialMaxStreamsUni,
            conn.transportSettings.idleTimeout,
            conn.transportSettings.ackDelayExponent,
            conn.transportSettings.maxRecvPacketSize,
            conn.transportSettings.partialReliabilityEnabled,
            token));
    QuicFizzFactory fizzFactory;
    conn.readCodec = std::make_unique<QuicReadCodec>(QuicNodeType::Server);
    conn.readCodec->setInitialReadCipher(
        getClientInitialCipher(&fizzFactory, initialDestinationConnectionId));
    conn.readCodec->setClientConnectionId(clientConnectionId);
    conn.readCodec->setCodecParameters(
        CodecParameters(conn.peerAckDelayExponent));
    conn.initialWriteCipher =
        getServerInitialCipher(&fizzFactory, initialDestinationConnectionId);

    auto serverInitialTrafficSecret = makeServerInitialTrafficSecret(
        &fizzFactory, initialDestinationConnectionId);
    auto clientInitialTrafficSecret = makeClientInitialTrafficSecret(
        &fizzFactory, initialDestinationConnectionId);
    conn.readCodec->setInitialHeaderCipher(makeClientInitialHeaderCipher(
        &fizzFactory, initialDestinationConnectionId));
    conn.initialHeaderCipher = makeServerInitialHeaderCipher(
        &fizzFactory, initialDestinationConnectionId);
    conn.peerAddress = conn.originalPeerAddress;
  }
  folly::IOBufQueue udpData{folly::IOBufQueue::cacheChainLength()};
  udpData.append(std::move(readData.networkData.data));
  for (uint16_t processedPackets = 0;
       !udpData.empty() && processedPackets < kMaxNumCoalescedPackets;
       processedPackets++) {
    size_t dataSize = udpData.chainLength();
    auto parsedPacket = conn.readCodec->parsePacket(udpData, conn.ackStates);
    size_t packetSize = dataSize - udpData.chainLength();
    bool parseSuccess = folly::variant_match(
        parsedPacket,
        [&](QuicPacket&) { return true; },
        [&](folly::Optional<CipherUnavailable>& originalData) {
          if (!originalData.hasValue()) {
            VLOG(10) << "drop cipher unavailable, no data " << conn;
            QUIC_TRACE(packet_drop, conn, "cipher_unavailable");
            return false;
          }
          if (!originalData->packet || originalData->packet->empty()) {
            VLOG(10) << "drop because no data " << conn;
            QUIC_TRACE(packet_drop, conn, "no_data");
            return false;
          }
          if (originalData->protectionType != ProtectionType::ZeroRtt &&
              originalData->protectionType != ProtectionType::KeyPhaseZero) {
            VLOG(10) << "drop because unexpected protection level " << conn;
            QUIC_TRACE(packet_drop, conn, "unexpected_protection_level");
            return false;
          }

          size_t combinedSize =
              (conn.pendingZeroRttData ? conn.pendingZeroRttData->size() : 0) +
              (conn.pendingOneRttData ? conn.pendingOneRttData->size() : 0);
          if (combinedSize >= conn.transportSettings.maxPacketsToBuffer) {
            VLOG(10) << "drop because max buffered " << conn;
            QUIC_TRACE(packet_drop, conn, "max_buffered");
            return false;
          }

          auto& pendingData =
              originalData->protectionType == ProtectionType::ZeroRtt
              ? conn.pendingZeroRttData
              : conn.pendingOneRttData;
          if (pendingData) {
            QUIC_TRACE(
                packet_buffered,
                conn,
                originalData->packetNum,
                originalData->protectionType,
                packetSize);
            ServerEvents::ReadData pendingReadData;
            pendingReadData.peer = readData.peer;
            pendingReadData.networkData = NetworkData(
                std::move(originalData->packet),
                readData.networkData.receiveTimePoint);
            pendingData->emplace_back(std::move(pendingReadData));
            VLOG(10) << "Adding pending data to "
                     << toString(originalData->protectionType)
                     << " buffer size=" << pendingData->size() << " " << conn;
          } else {
            VLOG(10) << "drop because "
                     << toString(originalData->protectionType)
                     << " buffer no longer available " << conn;
            QUIC_TRACE(packet_drop, conn, "buffer_unavailable");
          }
          return false;
        },
        [&](const auto&) {
          VLOG(10) << "drop because reset " << conn;
          QUIC_TRACE(packet_drop, conn, "reset");
          return false;
        });
    if (!parseSuccess) {
      // We were unable to parse the packet, drop for now.
      VLOG(10) << "Not able to parse QUIC packet " << conn;
      QUIC_STATS(
          conn.infoCallback, onPacketDropped, PacketDropReason::PARSE_ERROR);
      continue;
    }
    auto& packet = boost::get<QuicPacket>(parsedPacket);
    // Before we know what the protection level of the packet is, we should
    // not throw an error.
    auto regularOptional = boost::get<RegularQuicPacket>(&packet);
    if (!regularOptional) {
      QUIC_TRACE(packet_drop, conn, "not_regular");
      VLOG(10) << "drop, not regular packet " << conn;
      QUIC_STATS(
          conn.infoCallback, onPacketDropped, PacketDropReason::INVALID_PACKET);
      continue;
    }
    auto protectionLevel = folly::variant_match(
        regularOptional->header,
        [](auto& header) { return header.getProtectionType(); });
    auto encryptionLevel = protectionTypeToEncryptionLevel(protectionLevel);

    auto packetNum = folly::variant_match(
        regularOptional->header,
        [](const auto& h) { return h.getPacketSequenceNum(); });
    auto packetNumberSpace = folly::variant_match(
        regularOptional->header,
        [](auto& header) { return header.getPacketNumberSpace(); });

    // TODO: enforce constraints on other protection levels.
    auto& regularPacket = *regularOptional;

    bool isProtectedPacket = protectionLevel == ProtectionType::ZeroRtt ||
        protectionLevel == ProtectionType::KeyPhaseZero ||
        protectionLevel == ProtectionType::KeyPhaseOne;

    if (!isProtectedPacket) {
      for (auto& quicFrame : regularPacket.frames) {
        auto isPadding = boost::get<PaddingFrame>(&quicFrame);
        auto isAck = boost::get<ReadAckFrame>(&quicFrame);
        auto isClose = boost::get<ConnectionCloseFrame>(&quicFrame);
        auto isCrypto = boost::get<ReadCryptoFrame>(&quicFrame);
        // TODO: add path challenge and response
        if (!isPadding && !isAck && !isClose && !isCrypto) {
          QUIC_STATS(
              conn.infoCallback,
              onPacketDropped,
              PacketDropReason::PROTOCOL_VIOLATION);
          throw QuicTransportException(
              "Invalid frame", TransportErrorCode::PROTOCOL_VIOLATION);
        }
      }
    }

    // TODO: remove this when we actually negotiate connid and version
    if (!conn.clientConnectionId) {
      conn.clientConnectionId = folly::variant_match(
          regularPacket.header,
          [](const LongHeader& longHeader) {
            return longHeader.getSourceConnId();
          },
          [](const ShortHeader& shortHeader) {
            return shortHeader.getConnectionId();
          });
      // change the connection id when we switch
      CHECK(conn.clientConnectionId);
      // TODO: if conn.serverConnIdParams->clientConnId != conn.clientConnId,
      // we need to update sourceAddressMap_.
      // TODO: need to remove ServerConnectionIdParams::clientConnId, it is no
      // longer needed.
      conn.serverConnIdParams->clientConnId = *conn.clientConnectionId;
      conn.readCodec->setServerConnectionId(*conn.serverConnectionId);
    }
    QUIC_TRACE(packet_recvd, conn, packetNum, packetSize);
    // We assume that the higher layer takes care of validating that the version
    // is supported.
    if (!conn.version) {
      conn.version = boost::get<LongHeader>(regularPacket.header).getVersion();
    }

    if (conn.peerAddress != readData.peer) {
      if (packetNumberSpace != PacketNumberSpace::AppData) {
        QUIC_STATS(
            conn.infoCallback,
            onPacketDropped,
            PacketDropReason::PEER_ADDRESS_CHANGE);
        throw QuicTransportException(
            "Migration not allowed during handshake",
            TransportErrorCode::INVALID_MIGRATION);
      }

      if (conn.transportSettings.disableMigration) {
        QUIC_STATS(
            conn.infoCallback,
            onPacketDropped,
            PacketDropReason::PEER_ADDRESS_CHANGE);
        throw QuicTransportException(
            "Migration disabled", TransportErrorCode::INVALID_MIGRATION);
      }
    }

    auto& ackState = getAckState(conn, packetNumberSpace);
    auto outOfOrder = updateLargestReceivedPacketNum(
        ackState, packetNum, readData.networkData.receiveTimePoint);
    DCHECK(hasReceivedPackets(conn));

    bool pktHasRetransmittableData = false;
    bool pktHasCryptoData = false;
    bool isNonProbingPacket = false;

    // TODO: possibly drop the packet here, but rolling back state of
    // what we've already processed is difficult.
    for (auto& quicFrame : regularPacket.frames) {
      folly::variant_match(
          quicFrame,
          [&](ReadAckFrame& ackFrame) {
            VLOG(10) << "Server received ack frame packet=" << packetNum << " "
                     << conn;
            isNonProbingPacket = true;
            processAckFrame(
                conn,
                packetNumberSpace,
                ackFrame,
                [&](const OutstandingPacket&,
                    const QuicWriteFrame& packetFrame,
                    const ReadAckFrame&) {
                  folly::variant_match(
                      packetFrame,
                      [&](const WriteStreamFrame& frame) {
                        VLOG(4) << "Server received ack for stream="
                                << frame.streamId << " offset=" << frame.offset
                                << " fin=" << frame.fin << " len=" << frame.len
                                << " " << conn;
                        auto ackedStream =
                            conn.streamManager->getStream(frame.streamId);
                        if (ackedStream) {
                          invokeStreamSendStateMachine(
                              conn,
                              *ackedStream,
                              StreamEvents::AckStreamFrame(frame));
                        }
                      },
                      [&](const WriteCryptoFrame& frame) {
                        auto cryptoStream =
                            getCryptoStream(*conn.cryptoState, encryptionLevel);
                        processCryptoStreamAck(
                            *cryptoStream, frame.offset, frame.len);
                      },
                      [&](const RstStreamFrame& frame) {
                        VLOG(4) << "Server received ack for reset stream="
                                << frame.streamId << " " << conn;
                        auto stream =
                            conn.streamManager->getStream(frame.streamId);
                        if (stream) {
                          invokeStreamSendStateMachine(
                              conn, *stream, StreamEvents::RstAck(frame));
                        }
                      },
                      [&](const WriteAckFrame& frame) {
                        DCHECK(!frame.ackBlocks.empty());
                        VLOG(4) << "Server received ack for largestAcked="
                                << frame.ackBlocks.back().end << " " << conn;
                        commonAckVisitorForAckFrame(ackState, frame);
                      },
                      [&](const auto& /*frame*/) {
                        // Ignore other frames.
                      });
                },
                markPacketLoss,
                readData.networkData.receiveTimePoint);
          },
          [&](RstStreamFrame& frame) {
            VLOG(10) << "Server received reset stream=" << frame.streamId << " "
                     << conn;
            pktHasRetransmittableData = true;
            isNonProbingPacket = true;
            auto stream = conn.streamManager->getStream(frame.streamId);
            if (!stream) {
              return;
            }
            invokeStreamReceiveStateMachine(conn, *stream, frame);
          },
          [&](ReadCryptoFrame& cryptoFrame) {
            pktHasRetransmittableData = true;
            pktHasCryptoData = true;
            isNonProbingPacket = true;
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
          },
          [&](ReadStreamFrame& frame) {
            VLOG(10) << "Server received stream data for stream="
                     << frame.streamId << ", offset=" << frame.offset
                     << " len=" << frame.data->computeChainDataLength()
                     << " fin=" << frame.fin << " " << conn;
            pktHasRetransmittableData = true;
            isNonProbingPacket = true;
            auto stream = conn.streamManager->getStream(frame.streamId);
            // Ignore data from closed streams that we don't have the
            // state for any more.
            if (stream) {
              invokeStreamReceiveStateMachine(conn, *stream, frame);
            }
          },
          [&](MaxDataFrame& connWindowUpdate) {
            VLOG(10) << "Server received max data offset="
                     << connWindowUpdate.maximumData << " " << conn;
            pktHasRetransmittableData = true;
            isNonProbingPacket = true;
            handleConnWindowUpdate(conn, connWindowUpdate, packetNum);
          },
          [&](MaxStreamDataFrame& streamWindowUpdate) {
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
          },
          [&](MaxStreamsFrame& maxStreamsFrame) {
            VLOG(10) << "Server received max streams frame stream="
                     << maxStreamsFrame.maxStreams << " " << conn;
            isNonProbingPacket = true;
            if (maxStreamsFrame.isForBidirectionalStream()) {
              conn.streamManager->setMaxLocalBidirectionalStreams(
                  maxStreamsFrame.maxStreams);
            } else {
              conn.streamManager->setMaxLocalUnidirectionalStreams(
                  maxStreamsFrame.maxStreams);
            }
          },
          [&](DataBlockedFrame&) {
            VLOG(10) << "Server received blocked " << conn;
            pktHasRetransmittableData = true;
            isNonProbingPacket = true;
            handleConnBlocked(conn);
          },
          [&](StreamDataBlockedFrame& blocked) {
            VLOG(10) << "Server received blocked stream=" << blocked.streamId
                     << " " << conn;
            pktHasRetransmittableData = true;
            isNonProbingPacket = true;
            auto stream = conn.streamManager->getStream(blocked.streamId);
            if (stream) {
              handleStreamBlocked(*stream);
            }
          },
          [&](StreamsBlockedFrame& blocked) {
            // peer wishes to open a stream, but is unable to due to the maximum
            // stream limit set by us
            // TODO implement the handler
            isNonProbingPacket = true;
            VLOG(10) << "Server received streams blocked limit="
                     << blocked.streamLimit << ", " << conn;
          },
          [&](ConnectionCloseFrame& connFrame) {
            isNonProbingPacket = true;
            auto errMsg = folly::to<std::string>(
                "Server closed by peer reason=", connFrame.reasonPhrase);
            VLOG(4) << errMsg << " " << conn;
            // we want to deliver app callbacks with the peer supplied error,
            // but send a NO_ERROR to the peer.
            QUIC_TRACE(recvd_close, conn, errMsg.c_str());
            conn.peerConnectionError = std::make_pair(
                QuicErrorCode(connFrame.errorCode), std::move(errMsg));
            throw QuicTransportException(
                "Peer closed", TransportErrorCode::NO_ERROR);
          },
          [&](ApplicationCloseFrame& appClose) {
            isNonProbingPacket = true;
            auto errMsg = folly::to<std::string>(
                "Server closed by peer reason=", appClose.reasonPhrase);
            VLOG(10) << errMsg << " " << conn;
            // we want to deliver app callbacks with the peer supplied error,
            // but send a NO_ERROR to the peer.
            QUIC_TRACE(recvd_close, conn, errMsg.c_str());
            conn.peerConnectionError = std::make_pair(
                QuicErrorCode(appClose.errorCode), std::move(errMsg));
            throw QuicTransportException(
                "Peer closed", TransportErrorCode::NO_ERROR);
          },
          [&](PaddingFrame&) {},
          [&](QuicSimpleFrame& simpleFrame) {
            pktHasRetransmittableData = true;
            isNonProbingPacket |= updateSimpleFrameOnPacketReceived(
                conn,
                simpleFrame,
                packetNum,
                readData.peer != conn.peerAddress);
          },
          [&](auto&) {
            // TODO update isNonProbingPacket
          });
    }

    // Update writable limit before processing the handshake data. This is so
    // that if we haven't decided whether or not to validate the peer, we won't
    // increase the limit.
    updateWritableByteLimitOnRecvPacket(conn);

    if (conn.peerAddress != readData.peer) {
      // TODO use new conn id, make sure the other endpoint has new conn id
      if (isNonProbingPacket) {
        if (packetNum == ackState.largestReceivedPacketNum) {
          onConnectionMigration(conn, readData.peer);
        }
      } else {
        // Server will need to response with PathResponse to the new address
        // while not updating peerAddress to new address
        QUIC_STATS(
            conn.infoCallback,
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
        QUIC_STATS(
            conn.infoCallback,
            onPacketDropped,
            QuicTransportStatsCallback::PacketDropReason::
                TRANSPORT_PARAMETER_ERROR);
        throw;
      }
    }
    updateAckSendStateOnRecvPacket(
        conn,
        ackState,
        outOfOrder,
        pktHasRetransmittableData,
        pktHasCryptoData);
    QUIC_STATS(conn.infoCallback, onPacketProcessed);
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
  if (!conn.readCodec) {
    // drop data. We closed before we even got the first packet. This is
    // normally not possible but might as well.
    QUIC_STATS(
        conn.infoCallback,
        onPacketDropped,
        PacketDropReason::SERVER_STATE_CLOSED);
    return;
  }
  if (conn.peerConnectionError) {
    // We already got a peer error. We can ignore any futher peer errors.
    QUIC_TRACE(packet_drop, conn, "ignoring peer close");
    QUIC_STATS(
        conn.infoCallback,
        onPacketDropped,
        PacketDropReason::SERVER_STATE_CLOSED);
    return;
  }
  folly::IOBufQueue udpData{folly::IOBufQueue::cacheChainLength()};
  udpData.append(std::move(readData.networkData.data));
  auto packetSize = udpData.empty() ? 0 : udpData.chainLength();
  auto parsedPacket = conn.readCodec->parsePacket(udpData, conn.ackStates);
  bool parseSuccess = folly::variant_match(
      parsedPacket,
      [&](QuicPacket&) { return true; },
      [&](folly::Optional<CipherUnavailable>&) {
        VLOG(10) << "drop cipher unavailable " << conn;
        QUIC_TRACE(packet_drop, conn, "cipher_unavailable");
        return false;
      },
      [&](const auto&) {
        VLOG(10) << "drop because reset " << conn;
        QUIC_TRACE(packet_drop, conn, "reset");
        return false;
      });
  if (!parseSuccess) {
    // We were unable to parse the packet, drop for now.
    VLOG(10) << "Not able to parse QUIC packet " << conn;
    QUIC_STATS(
        conn.infoCallback, onPacketDropped, PacketDropReason::PARSE_ERROR);
    return;
  }
  auto& packet = boost::get<QuicPacket>(parsedPacket);
  // Before we know what the protection level of the packet is, we should
  // not throw an error.
  auto regularOptional = boost::get<RegularQuicPacket>(&packet);
  if (!regularOptional) {
    QUIC_TRACE(packet_drop, conn, "not_regular");
    VLOG(10) << "drop, not regular packet " << conn;
    QUIC_STATS(
        conn.infoCallback, onPacketDropped, PacketDropReason::INVALID_PACKET);
    return;
  }
  auto& regularPacket = *regularOptional;

  auto protectionLevel = folly::variant_match(
      regularPacket.header,
      [](auto& header) { return header.getProtectionType(); });

  auto packetNum = folly::variant_match(
      regularOptional->header,
      [](const auto& h) { return h.getPacketSequenceNum(); });
  auto pnSpace = folly::variant_match(
      regularOptional->header,
      [](const auto& h) { return h.getPacketNumberSpace(); });

  QUIC_TRACE(packet_recvd, conn, packetNum, packetSize);

  bool isProtectedPacket = protectionLevel == ProtectionType::ZeroRtt ||
      protectionLevel == ProtectionType::KeyPhaseZero ||
      protectionLevel == ProtectionType::KeyPhaseOne;

  // Only process the close frames in the packet
  for (auto& quicFrame : regularPacket.frames) {
    folly::variant_match(
        quicFrame,
        [&](ConnectionCloseFrame& connFrame) {
          auto errMsg = folly::to<std::string>(
              "Server closed by peer reason=", connFrame.reasonPhrase);
          VLOG(4) << errMsg << " " << conn;
          // we want to deliver app callbacks with the peer supplied error,
          // but send a NO_ERROR to the peer.
          QUIC_TRACE(recvd_close, conn, errMsg.c_str());
          conn.peerConnectionError = std::make_pair(
              QuicErrorCode(connFrame.errorCode), std::move(errMsg));
        },
        [&](ApplicationCloseFrame& appClose) {
          if (!isProtectedPacket) {
            return;
          }
          auto errMsg = folly::to<std::string>(
              "Server closed by peer reason=", appClose.reasonPhrase);
          VLOG(10) << errMsg << " " << conn;
          // we want to deliver app callbacks with the peer supplied error,
          // but send a NO_ERROR to the peer.
          QUIC_TRACE(recvd_close, conn, errMsg.c_str());
          conn.peerConnectionError = std::make_pair(
              QuicErrorCode(appClose.errorCode), std::move(errMsg));
        },
        [&](auto&) { return; });
  }

  // We only need to set the largest received packet number in order to
  // determine whether or not we need to send a new close.
  auto& largestReceivedPacketNum =
      getAckState(conn, pnSpace).largestReceivedPacketNum;
  largestReceivedPacketNum = std::max<PacketNum>(
      largestReceivedPacketNum.value_or(packetNum), packetNum);
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

} // namespace quic
