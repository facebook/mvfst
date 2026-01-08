/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <quic/server/handshake/DefaultAppTokenValidator.h>

#include <quic/QuicConstants.h>
#include <quic/api/QuicSocket.h>
#include <quic/api/QuicTransportFunctions.h>
#include <quic/fizz/server/handshake/AppToken.h>
#include <quic/handshake/TransportParameters.h>
#include <quic/server/state/ServerStateMachine.h>

#include <fizz/server/ResumptionState.h>
#include <folly/IPAddress.h>
#include <quic/common/Optional.h>

#include <quic/common/MvfstLogging.h>

#include <chrono>
#include <string>
#include <vector>

namespace quic {

DefaultAppTokenValidator::DefaultAppTokenValidator(
    QuicServerConnectionState* conn)
    : conn_(conn) {}

bool DefaultAppTokenValidator::validate(
    const fizz::server::ResumptionState& resumptionState) const {
  conn_->transportParamsMatching = false;
  conn_->sourceTokenMatching = false;
  bool validated = true;

  SCOPE_EXIT {
    if (validated) {
      QUIC_STATS(conn_->statsCallback, onZeroRttAccepted);
      if (conn_->version == QuicVersion::MVFST_PRIMING) {
        QUIC_STATS(conn_->statsCallback, onZeroRttPrimingAccepted);
      }
    } else {
      QUIC_STATS(conn_->statsCallback, onZeroRttRejected);
      if (conn_->version == QuicVersion::MVFST_PRIMING) {
        QUIC_STATS(conn_->statsCallback, onZeroRttPrimingRejected);
      }
    }
  };

  if (!resumptionState.appToken) {
    MVVLOG(10) << "App token does not exist";
    return validated = false;
  }

  auto appToken = decodeAppToken(*resumptionState.appToken);
  if (!appToken) {
    MVVLOG(10) << "Failed to decode app token";
    return validated = false;
  }

  auto& params = appToken->transportParams.parameters;

  // Reject tickets that do not have the minimum number of params in the ticket.
  // This is a minimum to allow sending additional optional params
  // that can be ignored by servers that don't support them.
  if (params.size() < kMinimumNumOfParamsInTheTicket) {
    MVVLOG(10)
        << "Number of parameters in the ticket is less than the minimum expected";
    return validated = false;
  }

  auto ticketIdleTimeoutResult =
      getIntegerParameter(TransportParameterId::idle_timeout, params);
  if (ticketIdleTimeoutResult.hasError()) {
    throw QuicTransportException(
        "Error getting idle_timeout parameter ",
        *ticketIdleTimeoutResult.error().code.asTransportErrorCode());
  }
  const auto& ticketIdleTimeout = ticketIdleTimeoutResult.value();
  if (!ticketIdleTimeout ||
      conn_->transportSettings.idleTimeout !=
          std::chrono::milliseconds(*ticketIdleTimeout)) {
    MVVLOG(10) << "Changed idle timeout";
    return validated = false;
  }

  auto ticketPacketSizeResult =
      getIntegerParameter(TransportParameterId::max_packet_size, params);
  if (ticketPacketSizeResult.hasError()) {
    throw QuicTransportException(
        "Error getting max_packet_size parameter ",
        *ticketPacketSizeResult.error().code.asTransportErrorCode());
  }
  const auto& ticketPacketSize = ticketPacketSizeResult.value();
  if (!ticketPacketSize ||
      conn_->transportSettings.maxRecvPacketSize < *ticketPacketSize) {
    MVVLOG(10) << "Decreased max receive packet size";
    return validated = false;
  }

  // if the current max data is less than the one advertised previously we
  // reject the early data
  auto ticketMaxDataResult =
      getIntegerParameter(TransportParameterId::initial_max_data, params);
  if (ticketMaxDataResult.hasError()) {
    throw QuicTransportException(
        "Error getting initial_max_data parameter ",
        *ticketMaxDataResult.error().code.asTransportErrorCode());
  }
  const auto& ticketMaxData = ticketMaxDataResult.value();
  if (!ticketMaxData ||
      conn_->transportSettings.advertisedInitialConnectionFlowControlWindow <
          *ticketMaxData) {
    MVVLOG(10) << "Decreased max data";
    return validated = false;
  }

  auto ticketMaxStreamDataBidiLocalResult = getIntegerParameter(
      TransportParameterId::initial_max_stream_data_bidi_local, params);
  if (ticketMaxStreamDataBidiLocalResult.hasError()) {
    throw QuicTransportException(
        "Error getting initial_max_stream_data_bidi_local parameter",
        *ticketMaxStreamDataBidiLocalResult.error()
             .code.asTransportErrorCode());
  }
  const auto& ticketMaxStreamDataBidiLocal =
      ticketMaxStreamDataBidiLocalResult.value();

  auto ticketMaxStreamDataBidiRemoteResult = getIntegerParameter(
      TransportParameterId::initial_max_stream_data_bidi_remote, params);
  if (ticketMaxStreamDataBidiRemoteResult.hasError()) {
    throw QuicTransportException(
        "Error getting initial_max_stream_data_bidi_remote parameter",
        *ticketMaxStreamDataBidiRemoteResult.error()
             .code.asTransportErrorCode());
  }
  const auto& ticketMaxStreamDataBidiRemote =
      ticketMaxStreamDataBidiRemoteResult.value();

  auto ticketMaxStreamDataUniResult = getIntegerParameter(
      TransportParameterId::initial_max_stream_data_uni, params);
  if (ticketMaxStreamDataUniResult.hasError()) {
    throw QuicTransportException(
        "Error getting initial_max_stream_data_uni parameter",
        *ticketMaxStreamDataUniResult.error().code.asTransportErrorCode());
  }
  const auto& ticketMaxStreamDataUni = ticketMaxStreamDataUniResult.value();

  if (!ticketMaxStreamDataBidiLocal ||
      conn_->transportSettings
              .advertisedInitialBidiLocalStreamFlowControlWindow <
          *ticketMaxStreamDataBidiLocal ||
      !ticketMaxStreamDataBidiRemote ||
      conn_->transportSettings
              .advertisedInitialBidiRemoteStreamFlowControlWindow <
          *ticketMaxStreamDataBidiRemote ||
      !ticketMaxStreamDataUni ||
      conn_->transportSettings.advertisedInitialUniStreamFlowControlWindow <
          *ticketMaxStreamDataUni) {
    MVVLOG(10) << "Decreased max stream data";
    return validated = false;
  }

  auto ticketMaxStreamsBidiResult = getIntegerParameter(
      TransportParameterId::initial_max_streams_bidi, params);
  if (ticketMaxStreamsBidiResult.hasError()) {
    throw QuicTransportException(
        "Error getting initial_max_streams_bidi parameter",
        *ticketMaxStreamsBidiResult.error().code.asTransportErrorCode());
  }
  const auto& ticketMaxStreamsBidi = ticketMaxStreamsBidiResult.value();

  auto ticketMaxStreamsUniResult = getIntegerParameter(
      TransportParameterId::initial_max_streams_uni, params);
  if (ticketMaxStreamsUniResult.hasError()) {
    throw QuicTransportException(
        "Error getting initial_max_streams_uni parameter",
        *ticketMaxStreamsUniResult.error().code.asTransportErrorCode());
  }
  const auto& ticketMaxStreamsUni = ticketMaxStreamsUniResult.value();

  if (!ticketMaxStreamsBidi ||
      conn_->transportSettings.advertisedInitialMaxStreamsBidi <
          *ticketMaxStreamsBidi ||
      !ticketMaxStreamsUni ||
      conn_->transportSettings.advertisedInitialMaxStreamsUni <
          *ticketMaxStreamsUni) {
    MVVLOG(10) << "Decreased max streams";
    return validated = false;
  }

  auto ticketExtendedAckFeaturesResult =
      getIntegerParameter(TransportParameterId::extended_ack_features, params);
  uint64_t ticketExtendedAckFeatures = 0;
  if (ticketExtendedAckFeaturesResult.hasError()) {
    throw QuicTransportException(
        "Error getting extended_ack_features parameter",
        *ticketExtendedAckFeaturesResult.error().code.asTransportErrorCode());
  } else if (ticketExtendedAckFeaturesResult.value().has_value()) {
    ticketExtendedAckFeatures = *ticketExtendedAckFeaturesResult.value();
  }
  if (conn_->transportSettings.advertisedExtendedAckFeatures !=
      ticketExtendedAckFeatures) {
    MVVLOG(10) << "Extended ack support changed";
    return validated = false;
  }

  conn_->transportParamsMatching = true;

  if (!validateAndUpdateSourceToken(
          *conn_, std::move(appToken->sourceAddresses))) {
    MVVLOG(10) << "No exact match from source address token";
    return validated = false;
  }

  // If application has set validator and the token is invalid, reject 0-RTT.
  // If application did not set validator, it's valid.
  if (conn_->earlyDataAppParamsHandler &&
      !conn_->earlyDataAppParamsHandler->validate(
          resumptionState.alpn
              ? quic::Optional<std::string>(*resumptionState.alpn)
              : std::nullopt,
          appToken->appParams)) {
    MVVLOG(10) << "Invalid app params";
    return validated = false;
  }

  return validated;
}

} // namespace quic
