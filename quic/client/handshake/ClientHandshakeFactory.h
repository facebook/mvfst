/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#pragma once

#include <memory>

namespace quic {

class ClientHandshake;
struct QuicClientConnectionState;

class ClientHandshakeFactory {
 public:
  virtual ~ClientHandshakeFactory() = default;

  /**
   * Construct a new client handshake.
   */
  virtual std::unique_ptr<ClientHandshake> makeClientHandshake(
      QuicClientConnectionState* conn) && = 0;
};

} // namespace quic
