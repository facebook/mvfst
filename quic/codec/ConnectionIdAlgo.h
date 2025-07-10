/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#pragma once

#include <quic/QuicException.h>
#include <quic/codec/QuicConnectionId.h>
#include <quic/common/Expected.h>

namespace quic {

/**
 * Interface to encode and decode algorithms for ConnectionId given routing
 * info (embedded in ServerConnectionIdParams)
 *
 * NOTE: since several of these methods are called for every single packets,
 * and every single connection, it is important to not do any
 * blocking call in any of the implementation of these methods.
 */
class ConnectionIdAlgo {
 public:
  virtual ~ConnectionIdAlgo() = default;

  /**
   * Check if this implementation of algorithm can parse the given ConnectionId
   */
  virtual bool canParse(const ConnectionId& id) const noexcept = 0;

  /**
   * Parses ServerConnectionIdParams from the given connection id.
   */
  virtual quic::Expected<ServerConnectionIdParams, QuicError> parseConnectionId(
      const ConnectionId& id) noexcept = 0;

  /**
   * Encodes the given ServerConnectionIdParams into connection id
   */
  virtual quic::Expected<ConnectionId, QuicError> encodeConnectionId(
      const ServerConnectionIdParams& params) noexcept = 0;
};

/**
 * Factory interface to create ConnectionIdAlgo instance.
 */
class ConnectionIdAlgoFactory {
 public:
  virtual ~ConnectionIdAlgoFactory() = default;

  virtual std::unique_ptr<ConnectionIdAlgo> make() = 0;
};

} // namespace quic
