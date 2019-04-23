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
#include <folly/IPAddress.h>
#include <folly/Optional.h>

#include <glog/logging.h>

#include <chrono>
#include <cstdint>
#include <vector>

namespace quic {

DefaultAppTokenValidator::DefaultAppTokenValidator(
    QuicServerConnectionState* conn,
    QuicSocket::ConnectionCallback* connCallback)
    : conn_(conn), connCallback_(CHECK_NOTNULL(connCallback)) {}

bool DefaultAppTokenValidator::validate(
    const fizz::server::ResumptionState& resumptionState) const {
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

  if (!conn_->version ||
      appToken->transportParams.negotiated_version != *conn_->version) {
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

  auto ticketIdleTimeout =
      getIntegerParameter(TransportParameterId::idle_timeout, params);
  if (!ticketIdleTimeout) {
    VLOG(10) << "Idle timeout empty";
    return false;
  }

  auto ticketPacketSize =
      getIntegerParameter(TransportParameterId::max_packet_size, params);
  if (!ticketPacketSize ||
      conn_->transportSettings.maxRecvPacketSize < *ticketPacketSize) {
    VLOG(10) << "Decreased max receive packet size";
    return false;
  }

  auto ticketAckDelayExponent =
      getIntegerParameter(TransportParameterId::ack_delay_exponent, params);
  if (!ticketAckDelayExponent ||
      conn_->transportSettings.ackDelayExponent != *ticketAckDelayExponent) {
    VLOG(10) << "Ack delay exponent mismatch";
    return false;
  }

  conn_->transportParamsMatching = true;

  if (!validateAndUpdateSourceToken(
          *conn_, std::move(appToken->sourceAddresses))) {
    VLOG(10) << "No exact match from source address token";
    return false;
  }

  updateTransportParamsFromTicket(
      *conn_,
      *ticketMaxStreamDataBidiLocal,
      *ticketMaxStreamDataBidiRemote,
      *ticketMaxStreamDataUni,
      *ticketMaxData,
      *ticketIdleTimeout,
      *ticketPacketSize);

  return true;
}

} // namespace quic
