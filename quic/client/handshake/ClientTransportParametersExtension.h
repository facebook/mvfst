/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#pragma once

#include <quic/QuicException.h>
#include <quic/common/Expected.h>
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

  quic::Expected<std::vector<TransportParameter>, QuicError>
  getChloTransportParameters() {
    constexpr uint8_t kDefaultMinNumParams = 12;
    using TpId = TransportParameterId;
    // reserve exact size needed
    std::vector<TransportParameter> res;
    res.reserve(kDefaultMinNumParams + customTransportParameters_.size());

    auto bidiLocalResult = encodeIntegerParameter(
        TpId::initial_max_stream_data_bidi_local,
        initialMaxStreamDataBidiLocal_);
    if (!bidiLocalResult.has_value()) {
      return quic::make_unexpected(bidiLocalResult.error());
    }
    res.push_back(std::move(bidiLocalResult.value()));

    auto bidiRemoteResult = encodeIntegerParameter(
        TpId::initial_max_stream_data_bidi_remote,
        initialMaxStreamDataBidiRemote_);
    if (!bidiRemoteResult.has_value()) {
      return quic::make_unexpected(bidiRemoteResult.error());
    }
    res.push_back(std::move(bidiRemoteResult.value()));

    auto uniResult = encodeIntegerParameter(
        TpId::initial_max_stream_data_uni, initialMaxStreamDataUni_);
    if (!uniResult.has_value()) {
      return quic::make_unexpected(uniResult.error());
    }
    res.push_back(std::move(uniResult.value()));

    auto maxDataResult =
        encodeIntegerParameter(TpId::initial_max_data, initialMaxData_);
    if (!maxDataResult.has_value()) {
      return quic::make_unexpected(maxDataResult.error());
    }
    res.push_back(std::move(maxDataResult.value()));

    auto streamsBidiResult = encodeIntegerParameter(
        TpId::initial_max_streams_bidi, initialMaxStreamsBidi_);
    if (!streamsBidiResult.has_value()) {
      return quic::make_unexpected(streamsBidiResult.error());
    }
    res.push_back(std::move(streamsBidiResult.value()));

    auto streamsUniResult = encodeIntegerParameter(
        TpId::initial_max_streams_uni, initialMaxStreamsUni_);
    if (!streamsUniResult.has_value()) {
      return quic::make_unexpected(streamsUniResult.error());
    }
    res.push_back(std::move(streamsUniResult.value()));

    auto idleTimeoutResult =
        encodeIntegerParameter(TpId::idle_timeout, idleTimeout_.count());
    if (!idleTimeoutResult.has_value()) {
      return quic::make_unexpected(idleTimeoutResult.error());
    }
    res.push_back(std::move(idleTimeoutResult.value()));

    auto ackDelayResult =
        encodeIntegerParameter(TpId::ack_delay_exponent, ackDelayExponent_);
    if (!ackDelayResult.has_value()) {
      return quic::make_unexpected(ackDelayResult.error());
    }
    res.push_back(std::move(ackDelayResult.value()));

    auto maxPacketSizeResult =
        encodeIntegerParameter(TpId::max_packet_size, maxRecvPacketSize_);
    if (!maxPacketSizeResult.has_value()) {
      return quic::make_unexpected(maxPacketSizeResult.error());
    }
    res.push_back(std::move(maxPacketSizeResult.value()));

    auto activeConnLimitResult = encodeIntegerParameter(
        TpId::active_connection_id_limit, activeConnectionLimit_);
    if (!activeConnLimitResult.has_value()) {
      return quic::make_unexpected(activeConnLimitResult.error());
    }
    res.push_back(std::move(activeConnLimitResult.value()));

    if (encodingVersion_ == QuicVersion::QUIC_V1 ||
        encodingVersion_ == QuicVersion::QUIC_V1_ALIAS ||
        encodingVersion_ == QuicVersion::QUIC_V1_ALIAS2 ||
        encodingVersion_ == QuicVersion::MVFST_PRIMING) {
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
