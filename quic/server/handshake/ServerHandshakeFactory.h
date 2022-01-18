/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#pragma once

#include <memory>

namespace quic {

class ServerHandshake;
struct QuicServerConnectionState;

class ServerHandshakeFactory {
 public:
  virtual ~ServerHandshakeFactory() = default;

  /**
   * Construct a new server handshake.
   */
  virtual std::unique_ptr<ServerHandshake> makeServerHandshake(
      QuicServerConnectionState* conn) && = 0;
};

} // namespace quic
