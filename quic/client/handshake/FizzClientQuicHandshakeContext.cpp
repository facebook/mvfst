/*
 * Copyright (c) Facebook, Inc. and its affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 *
 */

#include <quic/client/handshake/FizzClientQuicHandshakeContext.h>

#include <quic/client/handshake/FizzClientHandshake.h>

namespace quic {

FizzClientQuicHandshakeContext::FizzClientQuicHandshakeContext(
    std::shared_ptr<const fizz::client::FizzClientContext> context,
    std::shared_ptr<const fizz::CertificateVerifier> verifier)
    : context_(std::move(context)), verifier_(std::move(verifier)) {}

std::unique_ptr<ClientHandshake>
FizzClientQuicHandshakeContext::makeClientHandshake(
    QuicClientConnectionState* conn) {
  return std::make_unique<FizzClientHandshake>(conn, shared_from_this());
}

std::shared_ptr<FizzClientQuicHandshakeContext>
FizzClientQuicHandshakeContext::Builder::build() {
  if (!context_) {
    context_ = std::make_shared<const fizz::client::FizzClientContext>();
  }
  if (!verifier_) {
    verifier_ = std::make_shared<const fizz::DefaultCertificateVerifier>(
        fizz::VerificationContext::Client);
  }

  return std::shared_ptr<FizzClientQuicHandshakeContext>(
      new FizzClientQuicHandshakeContext(
          std::move(context_), std::move(verifier_)));
}

} // namespace quic
