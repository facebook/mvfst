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
        customTransportParameters_(std::move(customTransportParameters)) {}

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
    if (encodingVersion_ == QuicVersion::QUIC_DRAFT ||
        encodingVersion_ == QuicVersion::QUIC_V1 ||
        encodingVersion_ == QuicVersion::QUIC_V1_ALIAS) {
      params.parameters.push_back(encodeConnIdParameter(
          TransportParameterId::original_destination_connection_id,
          originalDestinationCid_));
    }
    params.parameters.push_back(encodeIntegerParameter(
        TransportParameterId::initial_max_stream_data_bidi_local,
        initialMaxStreamDataBidiLocal_));
    params.parameters.push_back(encodeIntegerParameter(
        TransportParameterId::initial_max_stream_data_bidi_remote,
        initialMaxStreamDataBidiRemote_));
    params.parameters.push_back(encodeIntegerParameter(
        TransportParameterId::initial_max_stream_data_uni,
        initialMaxStreamDataUni_));
    params.parameters.push_back(encodeIntegerParameter(
        TransportParameterId::initial_max_data, initialMaxData_));
    params.parameters.push_back(encodeIntegerParameter(
        TransportParameterId::initial_max_streams_bidi,
        initialMaxStreamsBidi_));
    params.parameters.push_back(encodeIntegerParameter(
        TransportParameterId::initial_max_streams_uni, initialMaxStreamsUni_));
    params.parameters.push_back(encodeIntegerParameter(
        TransportParameterId::idle_timeout, idleTimeout_.count()));
    params.parameters.push_back(encodeIntegerParameter(
        TransportParameterId::ack_delay_exponent, ackDelayExponent_));
    params.parameters.push_back(encodeIntegerParameter(
        TransportParameterId::max_packet_size, maxRecvPacketSize_));

    // stateless reset token
    params.parameters.push_back(TransportParameter(
        TransportParameterId::stateless_reset_token,
        folly::IOBuf::copyBuffer(token_)));

    if (disableMigration_) {
      params.parameters.push_back(
          encodeEmptyParameter(TransportParameterId::disable_migration));
    }

    if (encodingVersion_ == QuicVersion::QUIC_DRAFT ||
        encodingVersion_ == QuicVersion::QUIC_V1 ||
        encodingVersion_ == QuicVersion::QUIC_V1_ALIAS) {
      params.parameters.push_back(encodeConnIdParameter(
          TransportParameterId::initial_source_connection_id,
          initialSourceCid_));
    }

    for (const auto& customParameter : customTransportParameters_) {
      params.parameters.push_back(customParameter);
    }

    exts.push_back(encodeExtension(params, encodingVersion_));
    return exts;
  }

  folly::Optional<ClientTransportParameters> getClientTransportParams() {
    return std::move(clientTransportParameters_);
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
  folly::Optional<ClientTransportParameters> clientTransportParameters_;
  StatelessResetToken token_;
  ConnectionId initialSourceCid_;
  ConnectionId originalDestinationCid_;
  std::vector<TransportParameter> customTransportParameters_;
};
} // namespace quic
