/*
 * Copyright (c) Facebook, Inc. and its affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 *
 */

#include <quic/server/handshake/DefaultAppTokenValidator.h>

#include <quic/QuicConstants.h>
#include <quic/api/QuicSocket.h>
#include <quic/api/QuicTransportFunctions.h>
#include <quic/handshake/TransportParameters.h>
#include <quic/server/state/ServerStateMachine.h>

#include <fizz/server/ResumptionState.h>
#include <folly/Function.h>
#include <folly/IPAddress.h>
#include <folly/Optional.h>

#include <glog/logging.h>

#include <chrono>
#include <cstdint>
#include <string>
#include <vector>

namespace quic {

DefaultAppTokenValidator::DefaultAppTokenValidator(
    QuicServerConnectionState* conn,
    folly::Function<bool(
        const folly::Optional<std::string>& alpn,
        const std::unique_ptr<folly::IOBuf>& appParams)>
        earlyDataAppParamsValidator)
    : conn_(conn),
      earlyDataAppParamsValidator_(std::move(earlyDataAppParamsValidator)) {}

bool DefaultAppTokenValidator::validate(
    const fizz::server::ResumptionState& resumptionState) {
  conn_->transportParamsMatching = false;
  conn_->sourceTokenMatching = false;

  if (!resumptionState.appToken) {
    VLOG(10) << "App token does not exist";
    return false;
  }

  auto appToken = decodeAppToken(*resumptionState.appToken);
  if (!appToken) {
    VLOG(10) << "Failed to decode app token";
    return false;
  }

  if (conn_->version != appToken->version) {
    VLOG(10) << "QuicVersion mismatch";
    return false;
  }

  auto& params = appToken->transportParams.parameters;

  // TODO T33454954 Simplify ticket transport params. see comments in D9324131
  // Currenly only initialMaxData, initialMaxStreamData, ackDelayExponent, and
  // maxRecvPacketSize are written into the ticket. In case new parameters
  // are added for making early data decision (although not likely), this
  // validator fails the check if number of parameters is not
  // kExpectedNumOfParamsInTheTicket.
  if (params.size() != kExpectedNumOfParamsInTheTicket) {
    VLOG(10) << "Unexpected number of parameters in the ticket";
    return false;
  }

  auto ticketIdleTimeout =
      getIntegerParameter(TransportParameterId::idle_timeout, params);
  if (!ticketIdleTimeout ||
      conn_->transportSettings.idleTimeout !=
          std::chrono::milliseconds(*ticketIdleTimeout)) {
    VLOG(10) << "Changed idle timeout";
    return false;
  }

  auto ticketPacketSize =
      getIntegerParameter(TransportParameterId::max_packet_size, params);
  if (!ticketPacketSize ||
      conn_->transportSettings.maxRecvPacketSize < *ticketPacketSize) {
    VLOG(10) << "Decreased max receive packet size";
    return false;
  }

  // if the current max data is less than the one advertised previously we
  // reject the early data
  auto ticketMaxData =
      getIntegerParameter(TransportParameterId::initial_max_data, params);
  if (!ticketMaxData ||
      conn_->transportSettings.advertisedInitialConnectionWindowSize <
          *ticketMaxData) {
    VLOG(10) << "Decreased max data";
    return false;
  }

  auto ticketMaxStreamDataBidiLocal = getIntegerParameter(
      TransportParameterId::initial_max_stream_data_bidi_local, params);
  auto ticketMaxStreamDataBidiRemote = getIntegerParameter(
      TransportParameterId::initial_max_stream_data_bidi_remote, params);
  auto ticketMaxStreamDataUni = getIntegerParameter(
      TransportParameterId::initial_max_stream_data_uni, params);
  if (!ticketMaxStreamDataBidiLocal ||
      conn_->transportSettings.advertisedInitialBidiLocalStreamWindowSize <
          *ticketMaxStreamDataBidiLocal ||
      !ticketMaxStreamDataBidiRemote ||
      conn_->transportSettings.advertisedInitialBidiRemoteStreamWindowSize <
          *ticketMaxStreamDataBidiRemote ||
      !ticketMaxStreamDataUni ||
      conn_->transportSettings.advertisedInitialUniStreamWindowSize <
          *ticketMaxStreamDataUni) {
    VLOG(10) << "Decreased max stream data";
    return false;
  }

  auto ticketMaxStreamsBidi = getIntegerParameter(
      TransportParameterId::initial_max_streams_bidi, params);
  auto ticketMaxStreamsUni = getIntegerParameter(
      TransportParameterId::initial_max_streams_uni, params);
  if (!ticketMaxStreamsBidi ||
      conn_->transportSettings.advertisedInitialMaxStreamsBidi <
          *ticketMaxStreamsBidi ||
      !ticketMaxStreamsUni ||
      conn_->transportSettings.advertisedInitialMaxStreamsUni <
          *ticketMaxStreamsUni) {
    VLOG(10) << "Decreased max stream data";
    return false;
  }

  // TODO max ack delay, is this really necessary?
  // spec says disable_migration should also be in the ticket. It shouldn't.

  conn_->transportParamsMatching = true;

  if (!validateAndUpdateSourceToken(
          *conn_, std::move(appToken->sourceAddresses))) {
    VLOG(10) << "No exact match from source address token";
    return false;
  }

  // If application has set validator and the token is invalid, reject 0-RTT.
  // If application did not set validator, it's valid.
  if (earlyDataAppParamsValidator_ &&
      !earlyDataAppParamsValidator_(
          resumptionState.alpn, appToken->appParams)) {
    VLOG(10) << "Invalid app params";
    return false;
  }

  updateTransportParamsFromTicket(
      *conn_,
      *ticketIdleTimeout,
      *ticketPacketSize,
      *ticketMaxData,
      *ticketMaxStreamDataBidiLocal,
      *ticketMaxStreamDataBidiRemote,
      *ticketMaxStreamDataUni,
      *ticketMaxStreamsBidi,
      *ticketMaxStreamsUni);

  return true;
}

} // namespace quic
