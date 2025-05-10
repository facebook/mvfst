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

folly::Expected<Optional<uint64_t>, QuicError> getIntegerParameter(
    TransportParameterId id,
    const std::vector<TransportParameter>& parameters) {
  auto it = findParameter(parameters, id);
  if (it == parameters.end()) {
    return Optional<uint64_t>(std::nullopt);
  }
  auto parameterCursor = Cursor(it->value.get());
  auto parameter = decodeQuicInteger(parameterCursor);
  if (!parameter) {
    return folly::makeUnexpected(QuicError(
        TransportErrorCode::TRANSPORT_PARAMETER_ERROR,
        folly::to<std::string>(
            "Failed to decode integer from TransportParameterId: ",
            u64_tp(id))));
  }
  return Optional<uint64_t>(parameter->first);
}

folly::Expected<Optional<ConnectionId>, QuicError> getConnIdParameter(
    TransportParameterId id,
    const std::vector<TransportParameter>& parameters) {
  auto it = findParameter(parameters, id);
  if (it == parameters.end()) {
    return Optional<ConnectionId>(std::nullopt);
  }

  auto value = it->value->clone();
  Cursor cursor(value.get());

  // Use the factory function instead of constructor
  auto connIdResult = ConnectionId::create(cursor, value->length());
  if (connIdResult.hasError()) {
    return folly::makeUnexpected(QuicError(
        TransportErrorCode::TRANSPORT_PARAMETER_ERROR,
        "Invalid connection ID parameter"));
  }
  return Optional<ConnectionId>(connIdResult.value());
}

folly::Expected<Optional<StatelessResetToken>, QuicError>
getStatelessResetTokenParameter(
    const std::vector<TransportParameter>& parameters) {
  auto it =
      findParameter(parameters, TransportParameterId::stateless_reset_token);
  if (it == parameters.end()) {
    return Optional<StatelessResetToken>(std::nullopt);
  }

  auto value = it->value->clone();
  auto range = value->coalesce();
  if (range.size() != sizeof(StatelessResetToken)) {
    return folly::makeUnexpected(QuicError(
        TransportErrorCode::TRANSPORT_PARAMETER_ERROR, "Invalid reset token"));
  }
  StatelessResetToken token;
  memcpy(token.data(), range.data(), range.size());
  return Optional<StatelessResetToken>(token);
}

folly::Expected<TransportParameter, QuicError> encodeIntegerParameter(
    TransportParameterId id,
    uint64_t value) {
  BufPtr data = BufHelpers::create(8);
  BufAppender appender(data.get(), 8);
  auto encoded = encodeQuicInteger(
      value, [appender = std::move(appender)](auto val) mutable {
        appender.writeBE(val);
      });
  if (!encoded) {
    return folly::makeUnexpected(QuicError(
        TransportErrorCode::TRANSPORT_PARAMETER_ERROR,
        "Invalid integer parameter"));
  }
  return TransportParameter{id, std::move(data)};
}

std::vector<TransportParameter> getSupportedExtTransportParams(
    const QuicConnectionStateBase& conn) {
  using TpId = TransportParameterId;
  const auto& ts = conn.transportSettings;

  std::vector<TransportParameter> customTps;
  customTps.reserve(7);

  if (ts.datagramConfig.enabled) {
    auto result = encodeIntegerParameter(
        TransportParameterId::max_datagram_frame_size,
        conn.datagramState.maxReadFrameSize);
    if (!result.hasError()) {
      customTps.push_back(result.value());
    }
  }

  if (ts.advertisedMaxStreamGroups > 0) {
    auto result = encodeIntegerParameter(
        TpId::stream_groups_enabled, ts.advertisedMaxStreamGroups);
    if (!result.hasError()) {
      customTps.push_back(result.value());
    }
  }

  auto ackTimestampsResult = encodeIntegerParameter(
      TpId::ack_receive_timestamps_enabled,
      ts.maybeAckReceiveTimestampsConfigSentToPeer.has_value() ? 1 : 0);
  if (!ackTimestampsResult.hasError()) {
    customTps.push_back(ackTimestampsResult.value());
  }

  if (ts.maybeAckReceiveTimestampsConfigSentToPeer.has_value()) {
    auto maxTimestampsResult = encodeIntegerParameter(
        TpId::max_receive_timestamps_per_ack,
        ts.maybeAckReceiveTimestampsConfigSentToPeer
            ->maxReceiveTimestampsPerAck);
    if (!maxTimestampsResult.hasError()) {
      customTps.push_back(maxTimestampsResult.value());
    }

    auto exponentResult = encodeIntegerParameter(
        TpId::receive_timestamps_exponent,
        ts.maybeAckReceiveTimestampsConfigSentToPeer
            ->receiveTimestampsExponent);
    if (!exponentResult.hasError()) {
      customTps.push_back(exponentResult.value());
    }
  }

  if (ts.minAckDelay) {
    auto minAckDelayResult = encodeIntegerParameter(
        TpId::min_ack_delay, ts.minAckDelay.value().count());
    if (!minAckDelayResult.hasError()) {
      customTps.push_back(minAckDelayResult.value());
    }
  }

  if (ts.advertisedKnobFrameSupport) {
    auto knobFrameResult =
        encodeIntegerParameter(TpId::knob_frames_supported, 1);
    if (!knobFrameResult.hasError()) {
      customTps.push_back(knobFrameResult.value());
    }
  }

  if (ts.advertisedReliableResetStreamSupport) {
    customTps.push_back(encodeEmptyParameter(TpId::reliable_stream_reset));
  }

  if (ts.advertisedExtendedAckFeatures) {
    auto extendedAckResult = encodeIntegerParameter(
        TpId::extended_ack_features, ts.advertisedExtendedAckFeatures);
    if (!extendedAckResult.hasError()) {
      customTps.push_back(extendedAckResult.value());
    }
  }

  return customTps;
}

} // namespace quic
