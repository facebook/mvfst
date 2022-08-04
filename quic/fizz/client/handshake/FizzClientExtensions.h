/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#pragma once

#include <fizz/client/ClientExtensions.h>
#include <quic/client/handshake/ClientTransportParametersExtension.h>
#include <quic/fizz/handshake/FizzTransportParameters.h>

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
        clientParameters_->initialMaxStreamsBidi_));
    params.parameters.push_back(encodeIntegerParameter(
        TransportParameterId::initial_max_streams_uni,
        clientParameters_->initialMaxStreamsUni_));
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
    if (clientParameters_->encodingVersion_ == QuicVersion::QUIC_DRAFT ||
        clientParameters_->encodingVersion_ == QuicVersion::QUIC_V1 ||
        clientParameters_->encodingVersion_ == QuicVersion::QUIC_V1_ALIAS) {
      params.parameters.push_back(encodeConnIdParameter(
          TransportParameterId::initial_source_connection_id,
          clientParameters_->initialSourceCid_));
    }

    for (const auto& customParameter :
         clientParameters_->customTransportParameters_) {
      params.parameters.push_back(customParameter);
    }

    exts.push_back(
        encodeExtension(params, clientParameters_->encodingVersion_));
    return exts;
  }

  void onEncryptedExtensions(
      const std::vector<fizz::Extension>& exts) override {
    fizz::validateTransportExtensions(
        exts, clientParameters_->encodingVersion_);
    auto serverParams =
        fizz::getServerExtension(exts, clientParameters_->encodingVersion_);
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
