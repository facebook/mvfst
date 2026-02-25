/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <quic/fizz/server/handshake/FizzServerQuicHandshakeContext.h>

#include <quic/fizz/server/handshake/FizzServerHandshake.h>

#include <fizz/protocol/Protocol.h>
#include <fizz/server/ReplayCache.h>
#include <chrono>

namespace quic {

FizzServerQuicHandshakeContext::FizzServerQuicHandshakeContext(
    std::shared_ptr<const fizz::server::FizzServerContext> context)
    : context_(std::move(context)) {}

FizzServerQuicHandshakeContext::FizzServerQuicHandshakeContext(
    std::shared_ptr<const fizz::server::FizzServerContext> context,
    std::unique_ptr<CryptoFactory> cryptoFactory)
    : context_(std::move(context)), cryptoFactory_(std::move(cryptoFactory)) {}

std::unique_ptr<ServerHandshake>
FizzServerQuicHandshakeContext::makeServerHandshake(
    QuicServerConnectionState* conn) && {
  if (!cryptoFactory_) {
    cryptoFactory_ = std::make_unique<FizzCryptoFactory>();
  }
  return std::make_unique<FizzServerHandshake>(
      conn, shared_from_this(), std::move(cryptoFactory_));
}

std::shared_ptr<FizzServerQuicHandshakeContext>
FizzServerQuicHandshakeContext::Builder::build() && {
  if (!context_) {
    context_ = std::make_shared<const fizz::server::FizzServerContext>();
  }

  return std::shared_ptr<FizzServerQuicHandshakeContext>(
      new FizzServerQuicHandshakeContext(
          std::move(context_), std::move(cryptoFactory_)));
}

std::shared_ptr<const fizz::server::FizzServerContext>
FizzServerQuicHandshakeContext::getPrimingContext() const {
  // Use lazy initialization to cache the priming context
  if (!primingContext_) {
    // Create a copy of the base context
    auto primingContext =
        std::make_shared<fizz::server::FizzServerContext>(*context_);

    // Configure early data settings with a relaxed tolerance for priming
    fizz::server::ClockSkewTolerance tolerance{
        std::chrono::milliseconds(-60 * 60 * 24 * 1000),
        std::chrono::milliseconds(60 * 60 * 24 * 1000)}; // 24 hours

    // Get the replay cache from the original context
    auto rawReplayCache = context_->getReplayCache();
    std::shared_ptr<fizz::server::ReplayCache> replayCache;
    if (rawReplayCache) {
      replayCache = std::shared_ptr<fizz::server::ReplayCache>(
          rawReplayCache, [](fizz::server::ReplayCache*) {} // no-op deleter
      );
    }

    // Apply the priming-specific early data settings
    primingContext->setEarlyDataSettings(
        context_->getAcceptEarlyData(fizz::ProtocolVersion::tls_1_3),
        tolerance,
        replayCache);

    primingContext_ = std::move(primingContext);
  }

  return primingContext_;
}

} // namespace quic
