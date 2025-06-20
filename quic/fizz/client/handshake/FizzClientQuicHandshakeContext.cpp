/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <fizz/client/AsyncFizzClient.h>
#include <fizz/client/ECHPolicy.h>
#include <quic/fizz/client/handshake/FizzClientQuicHandshakeContext.h>

#include <quic/fizz/client/handshake/FizzClientHandshake.h>

namespace quic {

FizzClientQuicHandshakeContext::FizzClientQuicHandshakeContext(
    std::shared_ptr<const fizz::client::FizzClientContext> context,
    std::shared_ptr<const fizz::CertificateVerifier> verifier,
    std::shared_ptr<QuicPskCache> pskCache,
    std::shared_ptr<fizz::client::ECHPolicy> echPolicy,
    std::shared_ptr<fizz::client::ECHRetryCallback> echRetryCallback_,
    uint16_t chloPaddingBytes)
    : context_(std::move(context)),
      verifier_(std::move(verifier)),
      pskCache_(std::move(pskCache)),
      echPolicy_(std::move(echPolicy)),
      echRetryCallback_(std::move(echRetryCallback_)),
      chloPaddingBytes_(chloPaddingBytes) {}

FizzClientQuicHandshakeContext::FizzClientQuicHandshakeContext(
    std::shared_ptr<const fizz::client::FizzClientContext> context,
    std::shared_ptr<const fizz::CertificateVerifier> verifier,
    std::shared_ptr<QuicPskCache> pskCache,
    std::unique_ptr<FizzCryptoFactory> cryptoFactory,
    std::shared_ptr<fizz::client::ECHPolicy> echPolicy,
    std::shared_ptr<fizz::client::ECHRetryCallback> echRetryCallback,
    uint16_t chloPaddingBytes)
    : context_(std::move(context)),
      verifier_(std::move(verifier)),
      pskCache_(std::move(pskCache)),
      echPolicy_(std::move(echPolicy)),
      echRetryCallback_(std::move(echRetryCallback)),
      cryptoFactory_(std::move(cryptoFactory)),
      chloPaddingBytes_(chloPaddingBytes) {}

std::unique_ptr<ClientHandshake>
FizzClientQuicHandshakeContext::makeClientHandshake(
    QuicClientConnectionState* conn) && {
  if (!cryptoFactory_) {
    cryptoFactory_ = std::make_unique<FizzCryptoFactory>();
  }
  auto handshake = std::make_unique<FizzClientHandshake>(
      conn, shared_from_this(), std::move(cryptoFactory_));
  if (echRetryCallback_) {
    handshake->setECHRetryCallback(echRetryCallback_.get());
  }
  return handshake;
}

folly::Optional<QuicCachedPsk> FizzClientQuicHandshakeContext::getPsk(
    const Optional<std::string>& hostname) {
  if (!hostname || !pskCache_) {
    return folly::none;
  }

  auto res = pskCache_->getPsk(hostname.value());
  if (res) {
    return res.value();
  } else {
    return folly::none;
  }
}

void FizzClientQuicHandshakeContext::putPsk(
    const Optional<std::string>& hostname,
    QuicCachedPsk quicCachedPsk) {
  if (hostname && pskCache_) {
    pskCache_->putPsk(hostname.value(), std::move(quicCachedPsk));
  }
}

void FizzClientQuicHandshakeContext::removePsk(
    const Optional<std::string>& hostname) {
  if (hostname && pskCache_) {
    pskCache_->removePsk(hostname.value());
  }
}

Optional<std::vector<fizz::ech::ParsedECHConfig>>
FizzClientQuicHandshakeContext::getECHConfigs(const std::string& sni) const {
  if (!echPolicy_) {
    return std::nullopt;
  }
  auto result = echPolicy_->getConfig(sni);
  if (result.has_value()) {
    return Optional<std::vector<fizz::ech::ParsedECHConfig>>(
        std::move(result.value()));
  } else {
    return std::nullopt;
  }
}

std::shared_ptr<FizzClientQuicHandshakeContext>
FizzClientQuicHandshakeContext::Builder::build() && {
  if (!context_) {
    context_ = std::make_shared<const fizz::client::FizzClientContext>();
  }
  if (!verifier_) {
    verifier_ = std::make_shared<const fizz::DefaultCertificateVerifier>(
        fizz::VerificationContext::Client);
  }

  return std::shared_ptr<FizzClientQuicHandshakeContext>(
      new FizzClientQuicHandshakeContext(
          std::move(context_),
          std::move(verifier_),
          std::move(pskCache_),
          std::move(cryptoFactory_),
          std::move(echPolicy_),
          std::move(echRetryCallback_),
          chloPaddingBytes_));
}

} // namespace quic
