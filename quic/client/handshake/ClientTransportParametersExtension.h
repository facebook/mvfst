/*
 * Copyright (c) Facebook, Inc. and its affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 *
 */

#pragma once

#include <fizz/client/ClientExtensions.h>
#include <quic/handshake/FizzTransportParameters.h>

namespace quic {

class ClientTransportParametersExtension : public fizz::ClientExtensions {
 public:
  ClientTransportParametersExtension(
      folly::Optional<QuicVersion> initialVersion,
      uint64_t initialMaxData,
      uint64_t initialMaxStreamDataBidiLocal,
      uint64_t initialMaxStreamDataBidiRemote,
      uint64_t initialMaxStreamDataUni,
      std::chrono::milliseconds idleTimeout,
      uint64_t ackDelayExponent,
      uint64_t maxRecvPacketSize,
      std::vector<TransportParameter> customTransportParameters =
          std::vector<TransportParameter>())
      : initialVersion_(initialVersion),
        initialMaxData_(initialMaxData),
        initialMaxStreamDataBidiLocal_(initialMaxStreamDataBidiLocal),
        initialMaxStreamDataBidiRemote_(initialMaxStreamDataBidiRemote),
        initialMaxStreamDataUni_(initialMaxStreamDataUni),
        idleTimeout_(idleTimeout),
        ackDelayExponent_(ackDelayExponent),
        maxRecvPacketSize_(maxRecvPacketSize),
        customTransportParameters_(customTransportParameters) {}

  ~ClientTransportParametersExtension() override = default;

  std::vector<fizz::Extension> getClientHelloExtensions() const override {
    std::vector<fizz::Extension> exts;

    ClientTransportParameters params;
    params.initial_version = initialVersion_;
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

    for (const auto& customParameter : customTransportParameters_) {
      params.parameters.push_back(customParameter);
    }

    exts.push_back(encodeExtension(params));
    return exts;
  }

  void onEncryptedExtensions(
      const std::vector<fizz::Extension>& exts) override {
    auto serverParams = fizz::getExtension<ServerTransportParameters>(exts);
    if (!serverParams) {
      throw fizz::FizzException(
          "missing server quic transport parameters extension",
          fizz::AlertDescription::missing_extension);
    }
    serverTransportParameters_ = std::move(serverParams);
  }

  folly::Optional<ServerTransportParameters> getServerTransportParams() {
    return std::move(serverTransportParameters_);
  }

 private:
  folly::Optional<QuicVersion> initialVersion_;
  uint64_t initialMaxData_;
  uint64_t initialMaxStreamDataBidiLocal_;
  uint64_t initialMaxStreamDataBidiRemote_;
  uint64_t initialMaxStreamDataUni_;
  std::chrono::milliseconds idleTimeout_;
  uint64_t ackDelayExponent_;
  uint64_t maxRecvPacketSize_;
  folly::Optional<ServerTransportParameters> serverTransportParameters_;
  std::vector<TransportParameter> customTransportParameters_;
};
} // namespace quic
