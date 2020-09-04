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

std::unique_ptr<ServerHandshake>
FizzServerQuicHandshakeContext::makeServerHandshake(
    QuicServerConnectionState* conn) {
  return std::make_unique<FizzServerHandshake>(conn, shared_from_this());
}

} // namespace quic
