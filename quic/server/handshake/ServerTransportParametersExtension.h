/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#pragma once

#include <fizz/server/ServerExtensions.h>
#include <quic/fizz/handshake/FizzTransportParameters.h>
#include <quic/server/handshake/StatelessResetGenerator.h>
#include <quic/state/StateData.h>

namespace {

std::vector<quic::TransportParameter> getClientDependentExtTransportParams(
    const quic::QuicConnectionStateBase& conn,
    const std::vector<quic::TransportParameter>& clientParams) {
  using TpId = quic::TransportParameterId;
  std::vector<quic::TransportParameter> params;

  if (conn.transportSettings.serverDirectEncapConfig.has_value()) {
    const auto& serverDirectEncapConfig =
        *conn.transportSettings.serverDirectEncapConfig;

    // See if the client supports direct encap. The value of the parameter,
    // if present, is the zone the client is in.
    auto getIntegerParamResult =
        getIntegerParameter(TpId::client_direct_encap, clientParams);
    if (getIntegerParamResult.hasError()) {
      return params;
    }

    const auto& maybeClientDirectEncapParam = getIntegerParamResult.value();
    if (!maybeClientDirectEncapParam) {
      return params;
    }

    uint64_t supportedZones = serverDirectEncapConfig.supportedZones;
    if ((*maybeClientDirectEncapParam & supportedZones) != 0) {
      params.push_back(encodeIPAddressParameter(
          TpId::server_direct_encap,
          serverDirectEncapConfig.directEncapAddress));
    }
  }

  return params;
}

} // namespace

namespace quic {

class ServerTransportParametersExtension : public fizz::ServerExtensions {
 public:
  ServerTransportParametersExtension(
      QuicVersion encodingVersion,
      uint64_t initialMaxData,
      uint64_t initialMaxStreamDataBidiLocal,
      uint64_t initialMaxStreamDataBidiRemote,
      uint64_t initialMaxStreamDataUni,
      uint64_t initialMaxStreamsBidi,
      uint64_t initialMaxStreamsUni,
      bool disableMigration,
      std::chrono::milliseconds idleTimeout,
      uint64_t ackDelayExponent,
      uint64_t maxRecvPacketSize,
      const StatelessResetToken& token,
      ConnectionId initialSourceCid,
      ConnectionId originalDestinationCid,
      const QuicConnectionStateBase& conn,
      std::vector<TransportParameter> customTransportParameters =
          std::vector<TransportParameter>())
      : encodingVersion_(encodingVersion),
        initialMaxData_(initialMaxData),
        initialMaxStreamDataBidiLocal_(initialMaxStreamDataBidiLocal),
        initialMaxStreamDataBidiRemote_(initialMaxStreamDataBidiRemote),
        initialMaxStreamDataUni_(initialMaxStreamDataUni),
        initialMaxStreamsBidi_(initialMaxStreamsBidi),
        initialMaxStreamsUni_(initialMaxStreamsUni),
        disableMigration_(disableMigration),
        idleTimeout_(idleTimeout),
        ackDelayExponent_(ackDelayExponent),
        maxRecvPacketSize_(maxRecvPacketSize),
        token_(token),
        initialSourceCid_(initialSourceCid),
        originalDestinationCid_(originalDestinationCid),
        customTransportParameters_(std::move(customTransportParameters)),
        conn_(conn) {}

  ~ServerTransportParametersExtension() override = default;

  std::vector<fizz::Extension> getExtensions(
      const fizz::ClientHello& chlo) override {
    fizz::validateTransportExtensions(chlo.extensions, encodingVersion_);
    auto clientParams =
        fizz::getClientExtension(chlo.extensions, encodingVersion_);

    if (!clientParams) {
      throw fizz::FizzException(
          "missing client quic transport parameters extension",
          fizz::AlertDescription::missing_extension);
    }
    clientTransportParameters_ = std::move(clientParams);

    std::vector<fizz::Extension> exts;

    ServerTransportParameters params;
    params.parameters.reserve(10);
    if (encodingVersion_ == QuicVersion::QUIC_V1 ||
        encodingVersion_ == QuicVersion::QUIC_V1_ALIAS ||
        encodingVersion_ == QuicVersion::QUIC_V1_ALIAS2 ||
        encodingVersion_ == QuicVersion::MVFST_PRIMING) {
      params.parameters.push_back(encodeConnIdParameter(
          TransportParameterId::original_destination_connection_id,
          originalDestinationCid_));
    }

    auto bidiLocalResult = encodeIntegerParameter(
        TransportParameterId::initial_max_stream_data_bidi_local,
        initialMaxStreamDataBidiLocal_);
    if (bidiLocalResult.hasError()) {
      throw fizz::FizzException(
          "Failed to encode initial_max_stream_data_bidi_local",
          fizz::AlertDescription::internal_error);
    }
    params.parameters.push_back(std::move(bidiLocalResult.value()));

    auto bidiRemoteResult = encodeIntegerParameter(
        TransportParameterId::initial_max_stream_data_bidi_remote,
        initialMaxStreamDataBidiRemote_);
    if (bidiRemoteResult.hasError()) {
      throw fizz::FizzException(
          "Failed to encode initial_max_stream_data_bidi_remote",
          fizz::AlertDescription::internal_error);
    }
    params.parameters.push_back(std::move(bidiRemoteResult.value()));

    auto uniResult = encodeIntegerParameter(
        TransportParameterId::initial_max_stream_data_uni,
        initialMaxStreamDataUni_);
    if (uniResult.hasError()) {
      throw fizz::FizzException(
          "Failed to encode initial_max_stream_data_uni",
          fizz::AlertDescription::internal_error);
    }
    params.parameters.push_back(std::move(uniResult.value()));

    auto maxDataResult = encodeIntegerParameter(
        TransportParameterId::initial_max_data, initialMaxData_);
    if (maxDataResult.hasError()) {
      throw fizz::FizzException(
          "Failed to encode initial_max_data",
          fizz::AlertDescription::internal_error);
    }
    params.parameters.push_back(std::move(maxDataResult.value()));

    auto streamsBidiResult = encodeIntegerParameter(
        TransportParameterId::initial_max_streams_bidi, initialMaxStreamsBidi_);
    if (streamsBidiResult.hasError()) {
      throw fizz::FizzException(
          "Failed to encode initial_max_streams_bidi",
          fizz::AlertDescription::internal_error);
    }
    params.parameters.push_back(std::move(streamsBidiResult.value()));

    auto streamsUniResult = encodeIntegerParameter(
        TransportParameterId::initial_max_streams_uni, initialMaxStreamsUni_);
    if (streamsUniResult.hasError()) {
      throw fizz::FizzException(
          "Failed to encode initial_max_streams_uni",
          fizz::AlertDescription::internal_error);
    }
    params.parameters.push_back(std::move(streamsUniResult.value()));

    auto idleTimeoutResult = encodeIntegerParameter(
        TransportParameterId::idle_timeout, idleTimeout_.count());
    if (idleTimeoutResult.hasError()) {
      throw fizz::FizzException(
          "Failed to encode idle_timeout",
          fizz::AlertDescription::internal_error);
    }
    params.parameters.push_back(std::move(idleTimeoutResult.value()));

    auto ackDelayResult = encodeIntegerParameter(
        TransportParameterId::ack_delay_exponent, ackDelayExponent_);
    if (ackDelayResult.hasError()) {
      throw fizz::FizzException(
          "Failed to encode ack_delay_exponent",
          fizz::AlertDescription::internal_error);
    }
    params.parameters.push_back(std::move(ackDelayResult.value()));

    auto maxPacketSizeResult = encodeIntegerParameter(
        TransportParameterId::max_packet_size, maxRecvPacketSize_);
    if (maxPacketSizeResult.hasError()) {
      throw fizz::FizzException(
          "Failed to encode max_packet_size",
          fizz::AlertDescription::internal_error);
    }
    params.parameters.push_back(std::move(maxPacketSizeResult.value()));

    // stateless reset token
    params.parameters.push_back(TransportParameter(
        TransportParameterId::stateless_reset_token,
        BufHelpers::copyBuffer(token_)));

    if (disableMigration_) {
      params.parameters.push_back(
          encodeEmptyParameter(TransportParameterId::disable_migration));
    }

    if (encodingVersion_ == QuicVersion::QUIC_V1 ||
        encodingVersion_ == QuicVersion::QUIC_V1_ALIAS ||
        encodingVersion_ == QuicVersion::QUIC_V1_ALIAS2 ||
        encodingVersion_ == QuicVersion::MVFST_PRIMING) {
      params.parameters.push_back(encodeConnIdParameter(
          TransportParameterId::initial_source_connection_id,
          initialSourceCid_));
    }

    for (const auto& customParameter : customTransportParameters_) {
      params.parameters.push_back(customParameter);
    }

    // Add direct encap parameters if connection state is available
    if (clientTransportParameters_.has_value()) {
      auto additionalParams = getClientDependentExtTransportParams(
          conn_, clientTransportParameters_->parameters);
      for (const auto& param : additionalParams) {
        params.parameters.push_back(param);
      }
    }

    exts.push_back(encodeExtension(params, encodingVersion_));
    return exts;
  }

  const Optional<ClientTransportParameters>& getClientTransportParams() {
    return clientTransportParameters_;
  }

 private:
  QuicVersion encodingVersion_;
  uint64_t initialMaxData_;
  uint64_t initialMaxStreamDataBidiLocal_;
  uint64_t initialMaxStreamDataBidiRemote_;
  uint64_t initialMaxStreamDataUni_;
  uint64_t initialMaxStreamsBidi_;
  uint64_t initialMaxStreamsUni_;
  bool disableMigration_;
  std::chrono::milliseconds idleTimeout_;
  uint64_t ackDelayExponent_;
  uint64_t maxRecvPacketSize_;
  Optional<ClientTransportParameters> clientTransportParameters_;
  StatelessResetToken token_;
  ConnectionId initialSourceCid_;
  ConnectionId originalDestinationCid_;
  std::vector<TransportParameter> customTransportParameters_;
  const QuicConnectionStateBase& conn_;
};
} // namespace quic
