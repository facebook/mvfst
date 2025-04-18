/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <quic/client/state/ClientStateMachine.h>
#include <quic/codec/Types.h>
#include <quic/loss/QuicLossFunctions.h>

#include <quic/QuicConstants.h>
#include <quic/client/handshake/CachedServerTransportParameters.h>
#include <quic/codec/Decode.h>
#include <quic/common/TimeUtil.h>
#include <quic/congestion_control/CongestionControllerFactory.h>
#include <quic/flowcontrol/QuicFlowController.h>
#include <quic/handshake/TransportParameters.h>
#include <quic/state/QuicStateFunctions.h>
#include <quic/state/QuicStreamUtilities.h>
#include <quic/state/StateData.h>

namespace quic {

std::unique_ptr<QuicClientConnectionState> undoAllClientStateForRetry(
    std::unique_ptr<QuicClientConnectionState> conn) {
  // Create a new connection state and copy over properties that don't change
  // across stateless retry.
  auto newConn = std::make_unique<QuicClientConnectionState>(
      std::move(conn->handshakeFactory));
  newConn->observerContainer = conn->observerContainer;
  newConn->qLogger = conn->qLogger;
  newConn->clientConnectionId = conn->clientConnectionId;
  newConn->initialDestinationConnectionId =
      conn->initialDestinationConnectionId;
  newConn->originalDestinationConnectionId =
      conn->originalDestinationConnectionId;
  // TODO: don't carry server connection id over to the new connection.
  newConn->serverConnectionId = conn->serverConnectionId;
  newConn->ackStates.initialAckState->nextPacketNum =
      conn->ackStates.initialAckState->nextPacketNum;
  newConn->ackStates.handshakeAckState->nextPacketNum =
      conn->ackStates.handshakeAckState->nextPacketNum;
  newConn->ackStates.appDataAckState.nextPacketNum =
      conn->ackStates.appDataAckState.nextPacketNum;
  newConn->version = conn->version;
  newConn->originalVersion = conn->originalVersion;
  newConn->originalPeerAddress = conn->originalPeerAddress;
  newConn->peerAddress = conn->peerAddress;
  newConn->udpSendPacketLen = conn->udpSendPacketLen;
  newConn->supportedVersions = conn->supportedVersions;
  newConn->transportSettings = conn->transportSettings;
  newConn->initialWriteCipher = std::move(conn->initialWriteCipher);
  newConn->readCodec = std::make_unique<QuicReadCodec>(QuicNodeType::Client);
  newConn->readCodec->setClientConnectionId(*conn->clientConnectionId);
  newConn->readCodec->setCodecParameters(CodecParameters(
      conn->peerAckDelayExponent,
      conn->originalVersion.value(),
      conn->transportSettings.maybeAckReceiveTimestampsConfigSentToPeer,
      conn->transportSettings.advertisedExtendedAckFeatures));
  newConn->earlyDataAppParamsValidator =
      std::move(conn->earlyDataAppParamsValidator);
  newConn->earlyDataAppParamsGetter = std::move(conn->earlyDataAppParamsGetter);
  newConn->happyEyeballsState = std::move(conn->happyEyeballsState);
  newConn->flowControlState = std::move(conn->flowControlState);
  newConn->bufAccessor = conn->bufAccessor;
  newConn->pendingOneRttData.reserve(
      newConn->transportSettings.maxPacketsToBuffer);
  if (conn->congestionControllerFactory) {
    newConn->congestionControllerFactory = conn->congestionControllerFactory;
    if (conn->congestionController) {
      // we have to recreate congestion controller
      // because it holds references to the old state
      newConn->congestionController =
          newConn->congestionControllerFactory->makeCongestionController(
              *newConn, conn->congestionController->type());
    }
  }

  // only copy over zero-rtt data
  for (auto& outstandingPacket : conn->outstandings.packets) {
    auto& packetHeader = outstandingPacket.packet.header;
    if (packetHeader.getPacketNumberSpace() == PacketNumberSpace::AppData &&
        packetHeader.getProtectionType() == ProtectionType::ZeroRtt) {
      newConn->outstandings.packets.push_back(std::move(outstandingPacket));
      newConn->outstandings.packetCount[PacketNumberSpace::AppData]++;
    }
  }

  newConn->lossState = conn->lossState;
  newConn->nodeType = conn->nodeType;
  newConn->streamManager = std::make_unique<QuicStreamManager>(
      *newConn,
      newConn->nodeType,
      newConn->transportSettings,
      std::move(*conn->streamManager));

  auto result = markZeroRttPacketsLost(*newConn, markPacketLoss);
  if (result.hasError()) {
    LOG(FATAL) << "error marking packets lost";
  }

  return newConn;
}

folly::Expected<folly::Unit, QuicError> processServerInitialParams(
    QuicClientConnectionState& conn,
    const ServerTransportParameters& serverParams,
    PacketNum packetNum) {
  auto maxData = getIntegerParameter(
      TransportParameterId::initial_max_data, serverParams.parameters);
  auto maxStreamDataBidiLocal = getIntegerParameter(
      TransportParameterId::initial_max_stream_data_bidi_local,
      serverParams.parameters);
  auto maxStreamDataBidiRemote = getIntegerParameter(
      TransportParameterId::initial_max_stream_data_bidi_remote,
      serverParams.parameters);
  auto maxStreamDataUni = getIntegerParameter(
      TransportParameterId::initial_max_stream_data_uni,
      serverParams.parameters);
  auto idleTimeout = getIntegerParameter(
      TransportParameterId::idle_timeout, serverParams.parameters);
  auto maxStreamsBidi = getIntegerParameter(
      TransportParameterId::initial_max_streams_bidi, serverParams.parameters);
  auto maxStreamsUni = getIntegerParameter(
      TransportParameterId::initial_max_streams_uni, serverParams.parameters);
  auto ackDelayExponent = getIntegerParameter(
      TransportParameterId::ack_delay_exponent, serverParams.parameters);
  auto packetSize = getIntegerParameter(
      TransportParameterId::max_packet_size, serverParams.parameters);
  auto statelessResetToken =
      getStatelessResetTokenParameter(serverParams.parameters);
  auto activeConnectionIdLimit = getIntegerParameter(
      TransportParameterId::active_connection_id_limit,
      serverParams.parameters);
  auto maxDatagramFrameSize = getIntegerParameter(
      TransportParameterId::max_datagram_frame_size, serverParams.parameters);
  auto peerAdvertisedMaxStreamGroups = getIntegerParameter(
      static_cast<TransportParameterId>(
          TransportParameterId::stream_groups_enabled),
      serverParams.parameters);
  auto minAckDelay = getIntegerParameter(
      TransportParameterId::min_ack_delay, serverParams.parameters);

  auto isAckReceiveTimestampsEnabled = getIntegerParameter(
      TransportParameterId::ack_receive_timestamps_enabled,
      serverParams.parameters);
  auto maxReceiveTimestampsPerAck = getIntegerParameter(
      TransportParameterId::max_receive_timestamps_per_ack,
      serverParams.parameters);
  auto receiveTimestampsExponent = getIntegerParameter(
      TransportParameterId::receive_timestamps_exponent,
      serverParams.parameters);
  auto knobFrameSupported = getIntegerParameter(
      static_cast<TransportParameterId>(
          TransportParameterId::knob_frames_supported),
      serverParams.parameters);
  auto extendedAckFeatures = getIntegerParameter(
      static_cast<TransportParameterId>(
          TransportParameterId::extended_ack_features),
      serverParams.parameters);

  auto reliableResetTpIter = findParameter(
      serverParams.parameters,
      static_cast<TransportParameterId>(
          TransportParameterId::reliable_stream_reset));
  if (reliableResetTpIter != serverParams.parameters.end()) {
    if (!reliableResetTpIter->value->empty()) {
      return folly::makeUnexpected(QuicError(
          TransportErrorCode::TRANSPORT_PARAMETER_ERROR,
          "Reliable reset transport parameter must be empty"));
    }
    conn.peerAdvertisedReliableStreamResetSupport = true;
  } else {
    conn.peerAdvertisedReliableStreamResetSupport = false;
  }
  if (conn.version == QuicVersion::QUIC_V1 ||
      conn.version == QuicVersion::QUIC_V1_ALIAS ||
      conn.version == QuicVersion::QUIC_V1_ALIAS2) {
    auto initialSourceConnId = getConnIdParameter(
        TransportParameterId::initial_source_connection_id,
        serverParams.parameters);
    auto originalDestinationConnId = getConnIdParameter(
        TransportParameterId::original_destination_connection_id,
        serverParams.parameters);
    if (!initialSourceConnId || !originalDestinationConnId ||
        initialSourceConnId.value() !=
            conn.readCodec->getServerConnectionId() ||
        originalDestinationConnId.value() !=
            conn.originalDestinationConnectionId) {
      return folly::makeUnexpected(QuicError(
          TransportErrorCode::TRANSPORT_PARAMETER_ERROR,
          "Initial CID does not match."));
    }
  }

  // TODO Validate active_connection_id_limit

  if (!packetSize || *packetSize == 0) {
    packetSize = kDefaultUDPSendPacketLen;
  }
  if (*packetSize < kMinMaxUDPPayload) {
    return folly::makeUnexpected(QuicError(
        TransportErrorCode::TRANSPORT_PARAMETER_ERROR,
        folly::to<std::string>(
            "Max packet size too small. received max_packetSize = ",
            *packetSize)));
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
  auto resultBidi = conn.streamManager->setMaxLocalBidirectionalStreams(
      maxStreamsBidi.value_or(0));
  if (resultBidi.hasError()) {
    return folly::makeUnexpected(resultBidi.error());
  }
  conn.peerAdvertisedInitialMaxStreamsBidi = maxStreamsBidi.value_or(0);
  auto resultUni = conn.streamManager->setMaxLocalUnidirectionalStreams(
      maxStreamsUni.value_or(0));
  if (resultUni.hasError()) {
    return folly::makeUnexpected(resultUni.error());
  }
  conn.peerAdvertisedInitialMaxStreamsUni = maxStreamsUni.value_or(0);
  conn.peerIdleTimeout = std::chrono::milliseconds(idleTimeout.value_or(0));
  conn.peerIdleTimeout = timeMin(conn.peerIdleTimeout, kMaxIdleTimeout);
  if (ackDelayExponent && *ackDelayExponent > kMaxAckDelayExponent) {
    return folly::makeUnexpected(QuicError(
        TransportErrorCode::TRANSPORT_PARAMETER_ERROR,
        "ack_delay_exponent too large"));
  }
  conn.peerAckDelayExponent =
      ackDelayExponent.value_or(kDefaultAckDelayExponent);
  if (minAckDelay.has_value()) {
    conn.peerMinAckDelay = std::chrono::microseconds(minAckDelay.value());
  }
  if (conn.transportSettings.canIgnorePathMTU) {
    *packetSize = std::min<uint64_t>(*packetSize, kDefaultMaxUDPPayload);
    conn.udpSendPacketLen = *packetSize;
  }

  // Currently no-op for a client; it doesn't issue connection ids
  // to the server.
  conn.peerActiveConnectionIdLimit =
      activeConnectionIdLimit.value_or(kDefaultActiveConnectionIdLimit);

  conn.statelessResetToken = std::move(statelessResetToken);
  // Update the existing streams, because we allow streams to be created before
  // the connection is established.
  conn.streamManager->streamStateForEach(
      [&conn, &packetNum](QuicStreamState& s) {
        auto windowSize = isUnidirectionalStream(s.id)
            ? conn.transportSettings.advertisedInitialUniStreamFlowControlWindow
            : isLocalStream(conn.nodeType, s.id)
            ? conn.transportSettings
                  .advertisedInitialBidiLocalStreamFlowControlWindow
            : conn.transportSettings
                  .advertisedInitialBidiRemoteStreamFlowControlWindow;
        handleStreamWindowUpdate(s, windowSize, packetNum);
      });
  if (maxDatagramFrameSize.has_value()) {
    if (maxDatagramFrameSize.value() > 0 &&
        maxDatagramFrameSize.value() <= kMaxDatagramPacketOverhead) {
      return folly::makeUnexpected(QuicError(
          TransportErrorCode::TRANSPORT_PARAMETER_ERROR,
          "max_datagram_frame_size too small"));
    }
    conn.datagramState.maxWriteFrameSize = maxDatagramFrameSize.value();
  }

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
  conn.peerAdvertisedExtendedAckFeatures = extendedAckFeatures.value_or(0);

  return folly::unit;
}

void cacheServerInitialParams(
    QuicClientConnectionState& conn,
    uint64_t peerAdvertisedInitialMaxData,
    uint64_t peerAdvertisedInitialMaxStreamDataBidiLocal,
    uint64_t peerAdvertisedInitialMaxStreamDataBidiRemote,
    uint64_t peerAdvertisedInitialMaxStreamDataUni,
    uint64_t peerAdvertisedInitialMaxStreamsBidi,
    uint64_t peerAdvertisedInitialMaxStreamUni,
    bool peerAdvertisedKnobFrameSupport,
    bool peerAdvertisedAckReceiveTimestampsEnabled,
    uint64_t peerAdvertisedMaxReceiveTimestampsPerAck,
    uint64_t peerAdvertisedReceiveTimestampsExponent,
    bool peerAdvertisedReliableStreamResetSupport,
    ExtendedAckFeatureMaskType peerAdvertisedExtendedAckFeatures) {
  conn.serverInitialParamsSet_ = true;
  conn.peerAdvertisedInitialMaxData = peerAdvertisedInitialMaxData;
  conn.peerAdvertisedInitialMaxStreamDataBidiLocal =
      peerAdvertisedInitialMaxStreamDataBidiLocal;
  conn.peerAdvertisedInitialMaxStreamDataBidiRemote =
      peerAdvertisedInitialMaxStreamDataBidiRemote;
  conn.peerAdvertisedInitialMaxStreamDataUni =
      peerAdvertisedInitialMaxStreamDataUni;
  conn.peerAdvertisedInitialMaxStreamsBidi =
      peerAdvertisedInitialMaxStreamsBidi;
  conn.peerAdvertisedInitialMaxStreamsUni = peerAdvertisedInitialMaxStreamUni;
  conn.peerAdvertisedKnobFrameSupport = peerAdvertisedKnobFrameSupport;
  conn.peerAdvertisedReliableStreamResetSupport =
      peerAdvertisedReliableStreamResetSupport;

  if (peerAdvertisedAckReceiveTimestampsEnabled) {
    conn.maybePeerAckReceiveTimestampsConfig.assign(
        {std::min(
             static_cast<uint8_t>(peerAdvertisedMaxReceiveTimestampsPerAck),
             static_cast<uint8_t>(
                 conn.transportSettings.maxReceiveTimestampsPerAckStored)),
         std::max(
             static_cast<uint8_t>(peerAdvertisedReceiveTimestampsExponent),
             static_cast<uint8_t>(0))});
  } else {
    conn.maybePeerAckReceiveTimestampsConfig.clear();
  }
  conn.peerAdvertisedExtendedAckFeatures = peerAdvertisedExtendedAckFeatures;
}

CachedServerTransportParameters getServerCachedTransportParameters(
    const QuicClientConnectionState& conn) {
  DCHECK(conn.serverInitialParamsSet_);

  CachedServerTransportParameters transportParams;

  transportParams.idleTimeout = conn.peerIdleTimeout.count();
  transportParams.maxRecvPacketSize = conn.udpSendPacketLen;
  transportParams.initialMaxData = conn.peerAdvertisedInitialMaxData;
  transportParams.initialMaxStreamDataBidiLocal =
      conn.peerAdvertisedInitialMaxStreamDataBidiLocal;
  transportParams.initialMaxStreamDataBidiRemote =
      conn.peerAdvertisedInitialMaxStreamDataBidiRemote;
  transportParams.initialMaxStreamDataUni =
      conn.peerAdvertisedInitialMaxStreamDataUni;
  transportParams.initialMaxStreamsBidi =
      conn.peerAdvertisedInitialMaxStreamsBidi;
  transportParams.initialMaxStreamsUni =
      conn.peerAdvertisedInitialMaxStreamsUni;
  transportParams.knobFrameSupport = conn.peerAdvertisedKnobFrameSupport;
  transportParams.ackReceiveTimestampsEnabled =
      conn.maybePeerAckReceiveTimestampsConfig.has_value();
  transportParams.reliableStreamResetSupport =
      conn.peerAdvertisedReliableStreamResetSupport;
  if (conn.maybePeerAckReceiveTimestampsConfig) {
    transportParams.maxReceiveTimestampsPerAck =
        conn.maybePeerAckReceiveTimestampsConfig->maxReceiveTimestampsPerAck;
    transportParams.receiveTimestampsExponent =
        conn.maybePeerAckReceiveTimestampsConfig->receiveTimestampsExponent;
  }
  transportParams.extendedAckFeatures = conn.peerAdvertisedExtendedAckFeatures;

  return transportParams;
}

folly::Expected<folly::Unit, QuicError>
updateTransportParamsFromCachedEarlyParams(
    QuicClientConnectionState& conn,
    const CachedServerTransportParameters& transportParams) {
  conn.peerIdleTimeout = std::chrono::milliseconds(transportParams.idleTimeout);
  conn.flowControlState.peerAdvertisedMaxOffset =
      transportParams.initialMaxData;
  conn.flowControlState.peerAdvertisedInitialMaxStreamOffsetBidiLocal =
      transportParams.initialMaxStreamDataBidiLocal;
  conn.flowControlState.peerAdvertisedInitialMaxStreamOffsetBidiRemote =
      transportParams.initialMaxStreamDataBidiRemote;
  conn.flowControlState.peerAdvertisedInitialMaxStreamOffsetUni =
      transportParams.initialMaxStreamDataUni;
  auto resultBidi = conn.streamManager->setMaxLocalBidirectionalStreams(
      transportParams.initialMaxStreamsBidi);
  if (resultBidi.hasError()) {
    return folly::makeUnexpected(resultBidi.error());
  }
  auto resultUni = conn.streamManager->setMaxLocalUnidirectionalStreams(
      transportParams.initialMaxStreamsUni);
  if (resultUni.hasError()) {
    return folly::makeUnexpected(resultUni.error());
  }
  conn.peerAdvertisedKnobFrameSupport = transportParams.knobFrameSupport;
  conn.peerAdvertisedReliableStreamResetSupport =
      transportParams.reliableStreamResetSupport;
  if (transportParams.ackReceiveTimestampsEnabled) {
    conn.maybePeerAckReceiveTimestampsConfig.assign(
        {std::min(
             static_cast<uint8_t>(transportParams.maxReceiveTimestampsPerAck),
             static_cast<uint8_t>(
                 conn.transportSettings.maxReceiveTimestampsPerAckStored)),
         std::max(
             static_cast<uint8_t>(transportParams.receiveTimestampsExponent),
             static_cast<uint8_t>(0))});
  } else {
    conn.maybePeerAckReceiveTimestampsConfig.clear();
  }
  conn.peerAdvertisedExtendedAckFeatures = transportParams.extendedAckFeatures;
  return folly::unit;
}
} // namespace quic
