/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#pragma once

#include <fizz/server/FizzServerContext.h>
#include <quic/fizz/handshake/FizzCryptoFactory.h>
#include <quic/server/handshake/ServerHandshakeFactory.h>

namespace quic {

class FizzServerHandshake;

class FizzServerQuicHandshakeContext
    : public ServerHandshakeFactory,
      public std::enable_shared_from_this<FizzServerQuicHandshakeContext> {
 public:
  std::unique_ptr<ServerHandshake>
      makeServerHandshake(QuicServerConnectionState* conn) && override;

  const std::shared_ptr<const fizz::server::FizzServerContext>& getContext()
      const {
    return context_;
  }

  /**
   * Returns a context configured specifically for MVFST_PRIMING with relaxed
   * 0-RTT ticket age check. This is a copy of the base context with custom
   * early data settings applied for priming use cases.
   */
  std::shared_ptr<const fizz::server::FizzServerContext> getPrimingContext()
      const;

 private:
  /**
   * We make the constructor private so that users have to use the Builder
   * facility. This ensures that
   *   - This will ALWAYS be managed by a shared_ptr, which the implementation
   * expects.
   *   - We can enforce that the internal state of FizzServerContext is always
   * sane.
   */
  explicit FizzServerQuicHandshakeContext(
      std::shared_ptr<const fizz::server::FizzServerContext> context);

  FizzServerQuicHandshakeContext(
      std::shared_ptr<const fizz::server::FizzServerContext> context,
      std::unique_ptr<CryptoFactory> cryptoFactory);

  std::shared_ptr<const fizz::server::FizzServerContext> context_;

  std::unique_ptr<CryptoFactory> cryptoFactory_;

  // Cached priming context with relaxed early data settings
  mutable std::shared_ptr<const fizz::server::FizzServerContext>
      primingContext_;

 public:
  class Builder {
   public:
    Builder&& setFizzServerContext(
        std::shared_ptr<const fizz::server::FizzServerContext> context) && {
      context_ = std::move(context);
      return std::move(*this);
    }

    Builder&& setCryptoFactory(
        std::unique_ptr<CryptoFactory> cryptoFactory) && {
      cryptoFactory_ = std::move(cryptoFactory);
      return std::move(*this);
    }

    std::shared_ptr<FizzServerQuicHandshakeContext> build() &&;

   private:
    std::shared_ptr<const fizz::server::FizzServerContext> context_;
    std::unique_ptr<CryptoFactory> cryptoFactory_;
  };
};

} // namespace quic
