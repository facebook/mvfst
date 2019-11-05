/*
 * Copyright (c) Facebook, Inc. and its affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 *
 */

#include <quic/client/handshake/FizzClientHandshake.h>

namespace quic {

FizzClientHandshake::FizzClientHandshake(
    QuicCryptoState& cryptoState,
    std::shared_ptr<FizzClientQuicHandshakeContext> fizzContext)
    : ClientHandshake(cryptoState), fizzContext_(std::move(fizzContext)) {}

} // namespace quic
