/*
 * Copyright (c) Facebook, Inc. and its affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 *
 */

#include <quic/fizz/server/handshake/FizzServerQuicHandshakeContext.h>

#include <quic/fizz/server/handshake/FizzServerHandshake.h>

namespace quic {

FizzServerQuicHandshakeContext::FizzServerQuicHandshakeContext(
    std::shared_ptr<const fizz::server::FizzServerContext> context)
    : context_(std::move(context)) {}

std::unique_ptr<ServerHandshake>
FizzServerQuicHandshakeContext::makeServerHandshake(
    QuicServerConnectionState* conn) {
  return std::make_unique<FizzServerHandshake>(conn, shared_from_this());
}

std::shared_ptr<FizzServerQuicHandshakeContext>
FizzServerQuicHandshakeContext::Builder::build() {
  if (!context_) {
    context_ = std::make_shared<const fizz::server::FizzServerContext>();
  }

  return std::shared_ptr<FizzServerQuicHandshakeContext>(
      new FizzServerQuicHandshakeContext(std::move(context_)));
}

} // namespace quic
