/*
 * Copyright (c) Facebook, Inc. and its affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 *
 */

#pragma once

#include <quic/client/handshake/ClientHandshakeFactory.h>

namespace quic {

class FizzClientHandshake;

class FizzClientQuicHandshakeContext
    : public ClientHandshakeFactory,
      public std::enable_shared_from_this<FizzClientQuicHandshakeContext> {
 public:
  std::unique_ptr<ClientHandshake> makeClientHandshake(
      QuicCryptoState& cryptoState) override;
};

} // namespace quic
