/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <quic/handshake/TransportParameters.h>
#include <quic/state/StateData.h>

#include <quic/common/BufUtil.h>

namespace quic {

Optional<uint64_t> getIntegerParameter(
    TransportParameterId id,
    const std::vector<TransportParameter>& parameters) {
  auto it = findParameter(parameters, id);
  if (it == parameters.end()) {
    return none;
  }
  auto parameterCursor = folly::io::Cursor(it->value.get());
  auto parameter = decodeQuicInteger(parameterCursor);
  if (!parameter) {
    throw QuicTransportException(
        folly::to<std::string>(
            "Failed to decode integer from TransportParameterId: ", u64_tp(id)),
        TransportErrorCode::TRANSPORT_PARAMETER_ERROR);
  }
  return parameter->first;
}

Optional<ConnectionId> getConnIdParameter(
    TransportParameterId id,
    const std::vector<TransportParameter>& parameters) {
  auto it = findParameter(parameters, id);
  if (it == parameters.end()) {
    return none;
  }

  auto value = it->value->clone();
  folly::io::Cursor cursor(value.get());

  // Constructor may throw an exception if the input is invalid.
  return ConnectionId(cursor, value->length());
}

Optional<StatelessResetToken> getStatelessResetTokenParameter(
    const std::vector<TransportParameter>& parameters) {
  auto it =
      findParameter(parameters, TransportParameterId::stateless_reset_token);
  if (it == parameters.end()) {
    return none;
  }

  auto value = it->value->clone();
  auto range = value->coalesce();
  if (range.size() != sizeof(StatelessResetToken)) {
    throw QuicTransportException(
        "Invalid reset token", TransportErrorCode::TRANSPORT_PARAMETER_ERROR);
  }
  StatelessResetToken token;
  memcpy(token.data(), range.data(), range.size());
  return token;
}

TransportParameter encodeIntegerParameter(
    TransportParameterId id,
    uint64_t value) {
  std::unique_ptr<folly::IOBuf> data = folly::IOBuf::create(8);
  BufAppender appender(data.get(), 8);
  auto encoded = encodeQuicInteger(
      value, [appender = std::move(appender)](auto val) mutable {
        appender.writeBE(val);
      });
  if (!encoded) {
    throw QuicTransportException(
        "Invalid integer parameter",
        TransportErrorCode::TRANSPORT_PARAMETER_ERROR);
  }
  return {id, std::move(data)};
}

std::vector<TransportParameter> getSupportedExtTransportParams(
    const QuicConnectionStateBase& conn) {
  using TpId = TransportParameterId;
  const auto& ts = conn.transportSettings;

  std::vector<TransportParameter> customTps;
  customTps.reserve(7);

  if (ts.datagramConfig.enabled) {
    customTps.push_back(encodeIntegerParameter(
        TransportParameterId::max_datagram_frame_size,
        conn.datagramState.maxReadFrameSize));
  }

  if (ts.advertisedMaxStreamGroups > 0) {
    customTps.push_back(encodeIntegerParameter(
        TpId::stream_groups_enabled, ts.advertisedMaxStreamGroups));
  }

  customTps.push_back(encodeIntegerParameter(
      TpId::ack_receive_timestamps_enabled,
      ts.maybeAckReceiveTimestampsConfigSentToPeer.has_value() ? 1 : 0));

  if (ts.maybeAckReceiveTimestampsConfigSentToPeer.has_value()) {
    customTps.push_back(encodeIntegerParameter(
        TpId::max_receive_timestamps_per_ack,
        ts.maybeAckReceiveTimestampsConfigSentToPeer
            ->maxReceiveTimestampsPerAck));

    customTps.push_back(encodeIntegerParameter(
        TpId::receive_timestamps_exponent,
        ts.maybeAckReceiveTimestampsConfigSentToPeer
            ->receiveTimestampsExponent));
  }

  if (ts.minAckDelay) {
    customTps.push_back(encodeIntegerParameter(
        TpId::min_ack_delay, ts.minAckDelay.value().count()));
  }

  if (ts.advertisedKnobFrameSupport) {
    customTps.push_back(encodeIntegerParameter(TpId::knob_frames_supported, 1));
  }

  return customTps;
}

} // namespace quic
