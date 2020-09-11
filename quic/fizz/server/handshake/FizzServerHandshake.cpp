/*
 * Copyright (c) Facebook, Inc. and its affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 *
 */

#include <quic/fizz/server/handshake/FizzServerHandshake.h>

// This is necessary for the conversion between QuicServerConnectionState and
// QuicConnectionStateBase and can be removed once ServerHandshake accepts
// QuicServerConnectionState.
#include <quic/server/state/ServerStateMachine.h>

namespace quic {

FizzServerHandshake::FizzServerHandshake(
    QuicServerConnectionState* conn,
    std::shared_ptr<FizzServerQuicHandshakeContext> fizzContext)
    : ServerHandshake(conn), fizzContext_(std::move(fizzContext)) {}

void FizzServerHandshake::initializeImpl(
    std::shared_ptr<const fizz::server::FizzServerContext> context,
    HandshakeCallback* callback,
    std::unique_ptr<fizz::server::AppTokenValidator> validator) {
  auto ctx = std::make_shared<fizz::server::FizzServerContext>(*context);
  ctx->setFactory(cryptoFactory_.getFizzFactory());
  ctx->setSupportedCiphers({{fizz::CipherSuite::TLS_AES_128_GCM_SHA256}});
  ctx->setVersionFallbackEnabled(false);
  // Since Draft-17, client won't sent EOED
  ctx->setOmitEarlyRecordLayer(true);
  context_ = std::move(ctx);
  callback_ = callback;

  if (validator) {
    state_.appTokenValidator() = std::move(validator);
  } else {
    state_.appTokenValidator() = std::make_unique<FailingAppTokenValidator>();
  }
}

const CryptoFactory& FizzServerHandshake::getCryptoFactory() const {
  return cryptoFactory_;
}

} // namespace quic
