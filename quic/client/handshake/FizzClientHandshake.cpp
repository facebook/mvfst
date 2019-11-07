/*
 * Copyright (c) Facebook, Inc. and its affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 *
 */

#include <quic/client/handshake/FizzClientHandshake.h>

#include <quic/handshake/FizzCryptoFactory.h>

namespace quic {

FizzClientHandshake::FizzClientHandshake(
    QuicCryptoState& cryptoState,
    std::shared_ptr<FizzClientQuicHandshakeContext> fizzContext)
    : ClientHandshake(cryptoState), fizzContext_(std::move(fizzContext)) {}

void FizzClientHandshake::connect(
    std::shared_ptr<const fizz::client::FizzClientContext> context,
    std::shared_ptr<const fizz::CertificateVerifier> verifier,
    folly::Optional<std::string> hostname,
    folly::Optional<fizz::client::CachedPsk> cachedPsk,
    const std::shared_ptr<ClientTransportParametersExtension>& transportParams,
    HandshakeCallback* callback) {
  transportParams_ = transportParams;
  callback_ = callback;
  auto ctx = std::make_shared<fizz::client::FizzClientContext>(*context);
  auto cryptoFactory = std::make_shared<FizzCryptoFactory>();
  ctx->setFactory(cryptoFactory);
  cryptoFactory_ = std::move(cryptoFactory);
  ctx->setSupportedCiphers({fizz::CipherSuite::TLS_AES_128_GCM_SHA256});
  ctx->setCompatibilityMode(false);
  // Since Draft-17, EOED should not be sent
  ctx->setOmitEarlyRecordLayer(true);
  processActions(machine_.processConnect(
      state_,
      std::move(ctx),
      std::move(verifier),
      std::move(hostname),
      std::move(cachedPsk),
      transportParams));
}

} // namespace quic
