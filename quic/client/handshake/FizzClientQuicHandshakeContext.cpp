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

std::unique_ptr<ClientHandshake>
FizzClientQuicHandshakeContext::makeClientHandshake(
    QuicCryptoState& cryptoState) {
  return std::make_unique<FizzClientHandshake>(cryptoState, shared_from_this());
}

} // namespace quic
