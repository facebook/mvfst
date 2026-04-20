/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#pragma once

#include <fizz/client/ClientExtensions.h>
#include <fizz/extensions/clientpadding/Types.h>
#include <quic/client/handshake/ClientTransportParametersExtension.h>
#include <quic/fizz/handshake/FizzTransportParameters.h>

namespace quic {

class FizzClientExtensions : public fizz::ClientExtensions {
 public:
  FizzClientExtensions(
      std::shared_ptr<ClientTransportParametersExtension> clientParameters,
      uint16_t chloPaddingBytes)
      : clientParameters_(std::move(clientParameters)),
        chloPaddingBytes_(chloPaddingBytes) {}

  ~FizzClientExtensions() override = default;

  fizz::Status getClientHelloExtensions(
      std::vector<fizz::Extension>& ret,
      fizz::Error& err) const override {
    std::vector<fizz::Extension> exts;

    ClientTransportParameters params;
    auto paramsResult = clientParameters_->getChloTransportParameters();
    if (paramsResult.hasError()) {
      throw fizz::FizzException(
          "Failed to get client transport parameters: " +
              paramsResult.error().message,
          fizz::AlertDescription::internal_error);
    }
    params.parameters = std::move(paramsResult.value());

    exts.push_back(
        encodeExtension(params, clientParameters_->encodingVersion_));

    if (chloPaddingBytes_ > 0) {
      fizz::extensions::Padding padding{chloPaddingBytes_};
      fizz::Extension ext;
      FIZZ_RETURN_ON_ERROR(fizz::encodeExtension(ext, err, padding));
      exts.push_back(std::move(ext));
    }
    ret = std::move(exts);
    return fizz::Status::Success;
  }

  fizz::Status onEncryptedExtensions(
      fizz::Error& err,
      const std::vector<fizz::Extension>& exts) override {
    fizz::validateTransportExtensions(
        exts, clientParameters_->encodingVersion_);
    auto serverParams =
        fizz::getServerExtension(exts, clientParameters_->encodingVersion_);
    if (!serverParams) {
      return err.error(
          "missing server quic transport parameters extension",
          fizz::AlertDescription::missing_extension);
    }
    clientParameters_->serverTransportParameters_ = std::move(serverParams);
    return fizz::Status::Success;
  }

 private:
  std::shared_ptr<ClientTransportParametersExtension> clientParameters_;
  uint16_t chloPaddingBytes_{0};
};
} // namespace quic
