/*
 * Copyright (c) Facebook, Inc. and its affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 *
 */

#pragma once

#include <memory>

namespace quic {

class ClientHandshake;
struct QuicCryptoState;

class ClientHandshakeFactory {
 public:
  virtual ~ClientHandshakeFactory() = default;

  /**
   * Construct a new client handshake.
   * /!\ The ClientHandshake constructed might keep a reference to cryptoState.
   * It is up to the caller to ensure the lifetime of cryptoState exceed the one
   * of the ClientHandshake.
   */
  virtual std::unique_ptr<ClientHandshake> makeClientHandshake(
      QuicCryptoState& cryptoState) = 0;
};

} // namespace quic
