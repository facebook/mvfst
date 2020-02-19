/*
 * Copyright (c) Facebook, Inc. and its affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 *
 */

#pragma once

#include <folly/Expected.h>
#include <quic/QuicException.h>
#include <quic/codec/ConnectionIdAlgo.h>
#include <quic/codec/QuicConnectionId.h>

namespace quic {

/**
 * Default implementation with algorithms to encode and decode for
 * ConnectionId given routing info (embedded in ServerConnectionIdParams)
 *
 * The schema for connection id is defined as follows:
 *
 * First 2 (0 - 1) bits are reserved for short version id of the connection id
 * If the load balancer (e.g. L4 lb) doesn't understand this version,
 * it can fallback to default routing
 * Next 16 (3 - 17) bits are reserved to be used for L4 LB
 * Next eight bits (18 - 25) are reserved for worker id
 * bit 26 is reserved for the Quic server id: server id is used to distinguish
 * between the takeover instance and the taken over one
   0     1          2 3 4 5 .. 17 18    19 20 .. 25 26          27 28 ... 63
  |SHORT VERSION|   For L4 LB           | WORKER_ID  | SERVER_ID |  ..
 */
class DefaultConnectionIdAlgo : public ConnectionIdAlgo {
 public:
  ~DefaultConnectionIdAlgo() override = default;

  /**
   * Check if this implementation of algorithm can parse the given ConnectionId
   */
  bool canParse(const ConnectionId& id) const noexcept override;

  /**
   * Parses ServerConnectionIdParams from the given connection id.
   */
  folly::Expected<ServerConnectionIdParams, QuicInternalException>
  parseConnectionId(const ConnectionId& id) noexcept override;

  /**
   * Encodes the given ServerConnectionIdParams into connection id
   */
  folly::Expected<ConnectionId, QuicInternalException> encodeConnectionId(
      const ServerConnectionIdParams& params) noexcept override;
};

/**
 * Factory Interface to create ConnectionIdAlgo instance.
 */
class DefaultConnectionIdAlgoFactory : public ConnectionIdAlgoFactory {
 public:
  ~DefaultConnectionIdAlgoFactory() override = default;

  std::unique_ptr<ConnectionIdAlgo> make() override {
    return std::make_unique<DefaultConnectionIdAlgo>();
  }
};

} // namespace quic
