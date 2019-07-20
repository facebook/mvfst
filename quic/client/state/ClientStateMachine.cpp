/*
 * Copyright (c) Facebook, Inc. and its affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 *
 */

#include <quic/client/state/ClientStateMachine.h>

#include <folly/io/async/AsyncSocketException.h>
#include <quic/client/handshake/ClientHandshake.h>
#include <quic/congestion_control/QuicCubic.h>
#include <quic/flowcontrol/QuicFlowController.h>
#include <quic/handshake/TransportParameters.h>
#include <quic/state/QuicStateFunctions.h>
#include <quic/state/StateData.h>

namespace quic {

std::unique_ptr<QuicClientConnectionState> undoAllClientStateCommon(
    std::unique_ptr<QuicClientConnectionState> conn) {
  // Create a new connection state and copy over properties that don't change
  // across stateless retry.
  auto newConn = std::make_unique<QuicClientConnectionState>();
  newConn->qLogger = conn->qLogger;
  newConn->clientConnectionId = conn->clientConnectionId;
  newConn->initialDestinationConnectionId =
      conn->initialDestinationConnectionId;
  // TODO: don't carry server connection id over to the new connection.
  newConn->serverConnectionId = conn->serverConnectionId;
  newConn->ackStates.initialAckState.nextPacketNum =
      conn->ackStates.initialAckState.nextPacketNum;
  newConn->ackStates.handshakeAckState.nextPacketNum =
      conn->ackStates.handshakeAckState.nextPacketNum;
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
      conn->peerAckDelayExponent, conn->originalVersion.value()));
  return newConn;
}

std::unique_ptr<QuicClientConnectionState> undoAllClientStateForRetry(
    std::unique_ptr<QuicClientConnectionState> conn) {
  return undoAllClientStateCommon(std::move(conn));
}

void processServerInitialParams(
    QuicClientConnectionState& conn,
    ServerTransportParameters serverParams,
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
  auto partialReliability = getIntegerParameter(
      static_cast<TransportParameterId>(kPartialReliabilityParameterId),
      serverParams.parameters);

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
  // TODO Make idleTimeout disableable via transport parameter.
  conn.streamManager->setMaxLocalBidirectionalStreams(
      maxStreamsBidi.value_or(0));
  conn.peerAdvertisedInitialMaxStreamsBidi = maxStreamsBidi.value_or(0);
  conn.streamManager->setMaxLocalUnidirectionalStreams(
      maxStreamsUni.value_or(0));
  conn.peerAdvertisedInitialMaxStreamsUni = maxStreamsUni.value_or(0);
  conn.peerIdleTimeout = std::chrono::milliseconds(idleTimeout.value_or(0));
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

  conn.statelessResetToken = std::move(statelessResetToken);
  // Update the existing streams, because we allow streams to be created before
  // the connection is established.
  conn.streamManager->streamStateForEach([&conn,
                                          &packetNum](QuicStreamState& s) {
    auto windowSize = isUnidirectionalStream(s.id)
        ? conn.transportSettings.advertisedInitialUniStreamWindowSize
        : isLocalStream(conn.nodeType, s.id)
            ? conn.transportSettings.advertisedInitialBidiLocalStreamWindowSize
            : conn.transportSettings
                  .advertisedInitialBidiRemoteStreamWindowSize;
    handleStreamWindowUpdate(s, windowSize, packetNum);
  });
}

void updateTransportParamsFromCachedEarlyParams(
    QuicClientConnectionState& conn,
    const CachedServerTransportParameters& transportParams) {
  conn.peerIdleTimeout = std::chrono::milliseconds(transportParams.idleTimeout);
  if (conn.transportSettings.canIgnorePathMTU) {
    conn.udpSendPacketLen = transportParams.maxRecvPacketSize;
  }
  conn.flowControlState.peerAdvertisedMaxOffset =
      transportParams.initialMaxData;
  conn.flowControlState.peerAdvertisedInitialMaxStreamOffsetBidiLocal =
      transportParams.initialMaxStreamDataBidiLocal;
  conn.flowControlState.peerAdvertisedInitialMaxStreamOffsetBidiRemote =
      transportParams.initialMaxStreamDataBidiRemote;
  conn.flowControlState.peerAdvertisedInitialMaxStreamOffsetUni =
      transportParams.initialMaxStreamDataUni;
  conn.streamManager->setMaxLocalBidirectionalStreams(
      transportParams.initialMaxStreamsBidi);
  conn.streamManager->setMaxLocalUnidirectionalStreams(
      transportParams.initialMaxStreamsUni);
}

void ClientInvalidStateHandler(QuicClientConnectionState& state) {
  state.state = ClientStates::Error();
}

} // namespace quic
