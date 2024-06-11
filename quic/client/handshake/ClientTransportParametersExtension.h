/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#pragma once

#include <quic/handshake/TransportParameters.h>

namespace quic {

struct ClientTransportParametersExtension {
  ClientTransportParametersExtension(
      QuicVersion encodingVersion,
      uint64_t initialMaxData,
      uint64_t initialMaxStreamDataBidiLocal,
      uint64_t initialMaxStreamDataBidiRemote,
      uint64_t initialMaxStreamDataUni,
      uint64_t initialMaxStreamsBidi,
      uint64_t initialMaxStreamsUni,
      std::chrono::milliseconds idleTimeout,
      uint64_t ackDelayExponent,
      uint64_t maxRecvPacketSize,
      uint64_t activeConnectionIdLimit,
      ConnectionId initialSourceCid,
      std::vector<TransportParameter> customTransportParameters =
          std::vector<TransportParameter>())
      : encodingVersion_(encodingVersion),
        initialMaxData_(initialMaxData),
        initialMaxStreamDataBidiLocal_(initialMaxStreamDataBidiLocal),
        initialMaxStreamDataBidiRemote_(initialMaxStreamDataBidiRemote),
        initialMaxStreamDataUni_(initialMaxStreamDataUni),
        initialMaxStreamsBidi_(initialMaxStreamsBidi),
        initialMaxStreamsUni_(initialMaxStreamsUni),
        idleTimeout_(idleTimeout),
        ackDelayExponent_(ackDelayExponent),
        maxRecvPacketSize_(maxRecvPacketSize),
        activeConnectionLimit_(activeConnectionIdLimit),
        initialSourceCid_(initialSourceCid),
        customTransportParameters_(std::move(customTransportParameters)) {}

  const Optional<ServerTransportParameters>& getServerTransportParams() {
    return serverTransportParameters_;
  }

  std::vector<TransportParameter> getChloTransportParameters() {
    constexpr uint8_t kDefaultMinNumParams = 12;
    using TpId = TransportParameterId;
    // reserve exact size needed
    std::vector<TransportParameter> res;
    res.reserve(kDefaultMinNumParams + customTransportParameters_.size());

    res.push_back(encodeIntegerParameter(
        TpId::initial_max_stream_data_bidi_local,
        initialMaxStreamDataBidiLocal_));
    res.push_back(encodeIntegerParameter(
        TpId::initial_max_stream_data_bidi_remote,
        initialMaxStreamDataBidiRemote_));
    res.push_back(encodeIntegerParameter(
        TpId::initial_max_stream_data_uni, initialMaxStreamDataUni_));
    res.push_back(
        encodeIntegerParameter(TpId::initial_max_data, initialMaxData_));
    res.push_back(encodeIntegerParameter(
        TpId::initial_max_streams_bidi, initialMaxStreamsBidi_));
    res.push_back(encodeIntegerParameter(
        TpId::initial_max_streams_uni, initialMaxStreamsUni_));
    res.push_back(
        encodeIntegerParameter(TpId::idle_timeout, idleTimeout_.count()));
    res.push_back(
        encodeIntegerParameter(TpId::ack_delay_exponent, ackDelayExponent_));
    res.push_back(
        encodeIntegerParameter(TpId::max_packet_size, maxRecvPacketSize_));
    res.push_back(encodeIntegerParameter(
        TpId::active_connection_id_limit, activeConnectionLimit_));
    if (encodingVersion_ == QuicVersion::QUIC_V1 ||
        encodingVersion_ == QuicVersion::QUIC_V1_ALIAS ||
        encodingVersion_ == QuicVersion::QUIC_V1_ALIAS2) {
      res.push_back(encodeConnIdParameter(
          TpId::initial_source_connection_id, initialSourceCid_));
    }

    for (const auto& customParameter : customTransportParameters_) {
      res.push_back(customParameter);
    }

    return res;
  }

  const QuicVersion encodingVersion_;
  const uint64_t initialMaxData_;
  const uint64_t initialMaxStreamDataBidiLocal_;
  const uint64_t initialMaxStreamDataBidiRemote_;
  const uint64_t initialMaxStreamDataUni_;
  const uint64_t initialMaxStreamsBidi_;
  const uint64_t initialMaxStreamsUni_;
  const std::chrono::milliseconds idleTimeout_;
  const uint64_t ackDelayExponent_;
  const uint64_t maxRecvPacketSize_;
  const uint64_t activeConnectionLimit_;
  const ConnectionId initialSourceCid_;
  const std::vector<TransportParameter> customTransportParameters_;
  Optional<ServerTransportParameters> serverTransportParameters_;
};
} // namespace quic
