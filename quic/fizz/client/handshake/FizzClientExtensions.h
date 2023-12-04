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
    params.parameters = clientParameters_->getChloTransportParameters();

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
