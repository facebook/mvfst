/*
 * Copyright (c) Facebook, Inc. and its affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 *
 */

#pragma once

#include <folly/Optional.h>
#include <quic/codec/QuicConnectionId.h>

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
  virtual bool canParse(const ConnectionId& id) const = 0;

  /**
   * Parses ServerConnectionIdParams from the given connection id.
   */
  virtual ServerConnectionIdParams parseConnectionId(
      const ConnectionId& id) = 0;

  /**
   * Encodes the given ServerConnectionIdParams into connection id
   */
  virtual ConnectionId encodeConnectionId(
      const ServerConnectionIdParams& params) = 0;
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
