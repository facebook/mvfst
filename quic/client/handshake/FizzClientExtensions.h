/*
 * Copyright (c) Facebook, Inc. and its affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 *
 */

#pragma once

#include <fizz/client/ClientExtensions.h>
#include <quic/client/handshake/ClientTransportParametersExtension.h>
#include <quic/handshake/FizzTransportParameters.h>

namespace quic {

class FizzClientExtensions : public fizz::ClientExtensions {
 public:
  FizzClientExtensions(
      std::shared_ptr<ClientTransportParametersExtension> clientParameters)
      : clientParameters_(std::move(clientParameters)) {}

  ~FizzClientExtensions() override = default;

  std::vector<fizz::Extension> getClientHelloExtensions() const override {
    std::vector<fizz::Extension> exts;

    ClientTransportParameters params;
    params.initial_version = clientParameters_->initialVersion_;
    params.parameters.push_back(encodeIntegerParameter(
        TransportParameterId::initial_max_stream_data_bidi_local,
        clientParameters_->initialMaxStreamDataBidiLocal_));
    params.parameters.push_back(encodeIntegerParameter(
        TransportParameterId::initial_max_stream_data_bidi_remote,
        clientParameters_->initialMaxStreamDataBidiRemote_));
    params.parameters.push_back(encodeIntegerParameter(
        TransportParameterId::initial_max_stream_data_uni,
        clientParameters_->initialMaxStreamDataUni_));
    params.parameters.push_back(encodeIntegerParameter(
        TransportParameterId::initial_max_data,
        clientParameters_->initialMaxData_));
    params.parameters.push_back(encodeIntegerParameter(
        TransportParameterId::initial_max_streams_bidi,
        std::numeric_limits<uint32_t>::max()));
    params.parameters.push_back(encodeIntegerParameter(
        TransportParameterId::initial_max_streams_uni,
        std::numeric_limits<uint32_t>::max()));
    params.parameters.push_back(encodeIntegerParameter(
        TransportParameterId::idle_timeout,
        clientParameters_->idleTimeout_.count()));
    params.parameters.push_back(encodeIntegerParameter(
        TransportParameterId::ack_delay_exponent,
        clientParameters_->ackDelayExponent_));
    params.parameters.push_back(encodeIntegerParameter(
        TransportParameterId::max_packet_size,
        clientParameters_->maxRecvPacketSize_));
    params.parameters.push_back(encodeIntegerParameter(
        TransportParameterId::active_connection_id_limit,
        clientParameters_->activeConnectionLimit_));

    for (const auto& customParameter :
         clientParameters_->customTransportParameters_) {
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
    clientParameters_->serverTransportParameters_ = std::move(serverParams);
  }

 private:
  std::shared_ptr<ClientTransportParametersExtension> clientParameters_;
};
} // namespace quic
