/*
 * Copyright (c) Facebook, Inc. and its affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 *
 */

#pragma once

#include <fizz/server/ServerExtensions.h>
#include <quic/handshake/TransportParameters.h>

namespace quic {

class ServerTransportParametersExtension : public fizz::ServerExtensions {
 public:
  ServerTransportParametersExtension(
      QuicVersion negotiatedVersion,
      const std::vector<QuicVersion>& supportedVersions,
      uint64_t initialMaxData,
      uint64_t initialMaxStreamDataBidiLocal,
      uint64_t initialMaxStreamDataBidiRemote,
      uint64_t initialMaxStreamDataUni,
      std::chrono::milliseconds idleTimeout,
      uint64_t ackDelayExponent,
      uint64_t maxRecvPacketSize,
      TransportPartialReliabilitySetting partialReliability)
      : negotiatedVersion_(negotiatedVersion),
        supportedVersions_(supportedVersions),
        initialMaxData_(initialMaxData),
        initialMaxStreamDataBidiLocal_(initialMaxStreamDataBidiLocal),
        initialMaxStreamDataBidiRemote_(initialMaxStreamDataBidiRemote),
        initialMaxStreamDataUni_(initialMaxStreamDataUni),
        idleTimeout_(idleTimeout),
        ackDelayExponent_(ackDelayExponent),
        maxRecvPacketSize_(maxRecvPacketSize),
        partialReliability_(partialReliability) {}

  ~ServerTransportParametersExtension() override = default;

  std::vector<fizz::Extension> getExtensions(
      const fizz::ClientHello& chlo) override {
    auto clientParams =
        fizz::getExtension<ClientTransportParameters>(chlo.extensions);

    if (!clientParams) {
      throw fizz::FizzException(
          "missing client quic transport parameters extension",
          fizz::AlertDescription::missing_extension);
    }
    clientTransportParameters_ = std::move(clientParams);

    std::vector<fizz::Extension> exts;

    ServerTransportParameters params;
    params.negotiated_version = negotiatedVersion_;
    params.supported_versions = supportedVersions_;
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
        std::numeric_limits<uint32_t>::max()));
    params.parameters.push_back(encodeIntegerParameter(
        TransportParameterId::initial_max_streams_uni,
        std::numeric_limits<uint32_t>::max()));
    params.parameters.push_back(encodeIntegerParameter(
        TransportParameterId::idle_timeout, idleTimeout_.count()));
    params.parameters.push_back(encodeIntegerParameter(
        TransportParameterId::ack_delay_exponent, ackDelayExponent_));
    params.parameters.push_back(encodeIntegerParameter(
        TransportParameterId::max_packet_size, maxRecvPacketSize_));
    TransportParameter statelessReset;
    statelessReset.parameter = TransportParameterId::stateless_reset_token;
    // TODO: replace this with a real stateless reset token.
    statelessReset.value = folly::IOBuf::copyBuffer(kTestStatelessResetToken);
    params.parameters.push_back(std::move(statelessReset));

    uint64_t partialReliabilitySetting = 0;
    if (partialReliability_) {
      partialReliabilitySetting = 1;
    }
    params.parameters.push_back(encodeIntegerParameter(
        static_cast<TransportParameterId>(kPartialReliabilityParameterId),
        partialReliabilitySetting));

    exts.push_back(encodeExtension(params));
    return exts;
  }

  folly::Optional<ClientTransportParameters> getClientTransportParams() {
    return std::move(clientTransportParameters_);
  }

 private:
  QuicVersion negotiatedVersion_;
  std::vector<QuicVersion> supportedVersions_;
  uint64_t initialMaxData_;
  uint64_t initialMaxStreamDataBidiLocal_;
  uint64_t initialMaxStreamDataBidiRemote_;
  uint64_t initialMaxStreamDataUni_;
  std::chrono::milliseconds idleTimeout_;
  uint64_t ackDelayExponent_;
  uint64_t maxRecvPacketSize_;
  TransportPartialReliabilitySetting partialReliability_;
  folly::Optional<ClientTransportParameters> clientTransportParameters_;
};
} // namespace quic
