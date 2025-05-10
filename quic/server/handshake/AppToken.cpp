/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <quic/server/handshake/AppToken.h>

namespace quic {

folly::Expected<TicketTransportParameters, QuicError>
createTicketTransportParameters(
    uint64_t idleTimeout,
    uint64_t maxRecvPacketSize,
    uint64_t initialMaxData,
    uint64_t initialMaxStreamDataBidiLocal,
    uint64_t initialMaxStreamDataBidiRemote,
    uint64_t initialMaxStreamDataUni,
    uint64_t initialMaxStreamsBidi,
    uint64_t initialMaxStreamsUni,
    ExtendedAckFeatureMaskType extendedAckFeatures,
    Optional<uint64_t> cwndHintBytes) {
  TicketTransportParameters params;
  auto idleTimeoutResult =
      encodeIntegerParameter(TransportParameterId::idle_timeout, idleTimeout);
  if (idleTimeoutResult.hasError()) {
    return folly::makeUnexpected(idleTimeoutResult.error());
  }
  params.parameters.push_back(idleTimeoutResult.value());

  auto maxRecvPacketSizeResult = encodeIntegerParameter(
      TransportParameterId::max_packet_size, maxRecvPacketSize);
  if (maxRecvPacketSizeResult.hasError()) {
    return folly::makeUnexpected(maxRecvPacketSizeResult.error());
  }
  params.parameters.push_back(maxRecvPacketSizeResult.value());

  auto initialMaxDataResult = encodeIntegerParameter(
      TransportParameterId::initial_max_data, initialMaxData);
  if (initialMaxDataResult.hasError()) {
    return folly::makeUnexpected(initialMaxDataResult.error());
  }
  params.parameters.push_back(initialMaxDataResult.value());

  auto initialMaxStreamDataBidiLocalResult = encodeIntegerParameter(
      TransportParameterId::initial_max_stream_data_bidi_local,
      initialMaxStreamDataBidiLocal);
  if (initialMaxStreamDataBidiLocalResult.hasError()) {
    return folly::makeUnexpected(initialMaxStreamDataBidiLocalResult.error());
  }
  params.parameters.push_back(initialMaxStreamDataBidiLocalResult.value());

  auto initialMaxStreamDataBidiRemoteResult = encodeIntegerParameter(
      TransportParameterId::initial_max_stream_data_bidi_remote,
      initialMaxStreamDataBidiRemote);
  if (initialMaxStreamDataBidiRemoteResult.hasError()) {
    return folly::makeUnexpected(initialMaxStreamDataBidiRemoteResult.error());
  }
  params.parameters.push_back(initialMaxStreamDataBidiRemoteResult.value());

  auto initialMaxStreamDataUniResult = encodeIntegerParameter(
      TransportParameterId::initial_max_stream_data_uni,
      initialMaxStreamDataUni);
  if (initialMaxStreamDataUniResult.hasError()) {
    return folly::makeUnexpected(initialMaxStreamDataUniResult.error());
  }
  params.parameters.push_back(initialMaxStreamDataUniResult.value());

  auto initialMaxStreamsBidiResult = encodeIntegerParameter(
      TransportParameterId::initial_max_streams_bidi, initialMaxStreamsBidi);
  if (initialMaxStreamsBidiResult.hasError()) {
    return folly::makeUnexpected(initialMaxStreamsBidiResult.error());
  }
  params.parameters.push_back(initialMaxStreamsBidiResult.value());

  auto initialMaxStreamsUniResult = encodeIntegerParameter(
      TransportParameterId::initial_max_streams_uni, initialMaxStreamsUni);
  if (initialMaxStreamsUniResult.hasError()) {
    return folly::makeUnexpected(initialMaxStreamsUniResult.error());
  }
  params.parameters.push_back(initialMaxStreamsUniResult.value());

  auto extendedAckFeaturesResult = encodeIntegerParameter(
      TransportParameterId::extended_ack_features, extendedAckFeatures);
  if (extendedAckFeaturesResult.hasError()) {
    return folly::makeUnexpected(extendedAckFeaturesResult.error());
  }
  params.parameters.push_back(extendedAckFeaturesResult.value());

  if (cwndHintBytes) {
    auto cwndHintBytesResult = encodeIntegerParameter(
        TransportParameterId::cwnd_hint_bytes, *cwndHintBytes);
    if (cwndHintBytesResult.hasError()) {
      return folly::makeUnexpected(cwndHintBytesResult.error());
    }
    params.parameters.push_back(cwndHintBytesResult.value());
  }
  return params;
}

} // namespace quic
