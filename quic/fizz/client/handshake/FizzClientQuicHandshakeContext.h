/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#pragma once

#include <quic/client/handshake/ClientHandshakeFactory.h>

#include <quic/fizz/client/handshake/QuicPskCache.h>
#include <quic/fizz/handshake/FizzCryptoFactory.h>

#include <fizz/client/FizzClientContext.h>
#include <fizz/protocol/DefaultCertificateVerifier.h>

namespace quic {

class FizzClientHandshake;

class FizzClientQuicHandshakeContext
    : public ClientHandshakeFactory,
      public std::enable_shared_from_this<FizzClientQuicHandshakeContext> {
 public:
  std::unique_ptr<ClientHandshake>
      makeClientHandshake(QuicClientConnectionState* conn) && override;

  const std::shared_ptr<const fizz::client::FizzClientContext>& getContext()
      const {
    return context_;
  }

  const std::shared_ptr<const fizz::CertificateVerifier>&
  getCertificateVerifier() const {
    return verifier_;
  }

  folly::Optional<QuicCachedPsk> getPsk(
      const folly::Optional<std::string>& hostname);
  void putPsk(
      const folly::Optional<std::string>& hostname,
      QuicCachedPsk quicCachedPsk);
  void removePsk(const folly::Optional<std::string>& hostname);

 private:
  /**
   * We make the constructor private so that users have to use the Builder
   * facility. This ensures that
   *   - This will ALWAYS be managed by a shared_ptr, which the implementation
   * expects.
   *   - We can enforce that the internal state of FizzClientContext is always
   * sane.
   */
  FizzClientQuicHandshakeContext(
      std::shared_ptr<const fizz::client::FizzClientContext> context,
      std::shared_ptr<const fizz::CertificateVerifier> verifier,
      std::shared_ptr<QuicPskCache> pskCache);

  FizzClientQuicHandshakeContext(
      std::shared_ptr<const fizz::client::FizzClientContext> context,
      std::shared_ptr<const fizz::CertificateVerifier> verifier,
      std::shared_ptr<QuicPskCache> pskCache,
      std::unique_ptr<FizzCryptoFactory> cryptoFactory);

  std::shared_ptr<const fizz::client::FizzClientContext> context_;
  std::shared_ptr<const fizz::CertificateVerifier> verifier_;
  std::shared_ptr<QuicPskCache> pskCache_;
  std::unique_ptr<FizzCryptoFactory> cryptoFactory_;

 public:
  class Builder {
   public:
    Builder&& setFizzClientContext(
        std::shared_ptr<const fizz::client::FizzClientContext> context) && {
      context_ = std::move(context);
      return std::move(*this);
    }

    Builder&& setCertificateVerifier(
        std::shared_ptr<const fizz::CertificateVerifier> verifier) && {
      verifier_ = std::move(verifier);
      return std::move(*this);
    }

    Builder&& setPskCache(std::shared_ptr<QuicPskCache> pskCache) && {
      pskCache_ = std::move(pskCache);
      return std::move(*this);
    }

    Builder&& setCryptoFactory(std::unique_ptr<FizzCryptoFactory> factory) && {
      cryptoFactory_ = std::move(factory);
      return std::move(*this);
    }

    std::shared_ptr<FizzClientQuicHandshakeContext> build() &&;

   private:
    std::shared_ptr<const fizz::client::FizzClientContext> context_;
    std::shared_ptr<const fizz::CertificateVerifier> verifier_;
    std::shared_ptr<QuicPskCache> pskCache_;
    std::unique_ptr<FizzCryptoFactory> cryptoFactory_;
  };
};

} // namespace quic
