/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#pragma once

#include <quic/common/BufUtil.h>
#include <quic/common/Optional.h>

namespace quic {

/**
 * Interface for handling early data (0-RTT) application parameters.
 *
 * Applications implement this interface to validate cached app params
 * and provide current app params for caching in session tickets.
 *
 * Ownership: The handler pointer is non-owning. The application must
 * ensure the handler outlives the connection.
 */
class EarlyDataAppParamsHandler {
 public:
  virtual ~EarlyDataAppParamsHandler() = default;

  /**
   * Validate app params during early data setup.
   *
   * Server side: Called during handshake while negotiating early data.
   * Client side: Called when transport is applying PSK from cache.
   *
   * @param alpn The negotiated ALPN (optional, may be absent).
   * @param appParams The encoded application parameters from PSK/cache.
   * @return true if params are valid for 0-RTT, false to reject early data.
   */
  virtual bool validate(
      const Optional<std::string>& alpn,
      const BufPtr& appParams) = 0;

  /**
   * Get current app params for caching/ticket generation.
   *
   * Server side: Called when transport writes NewSessionTicket.
   * Client side: Called when client receives NewSessionTicket for caching.
   *
   * @return Encoded application parameters, or nullptr if none.
   */
  virtual BufPtr get() = 0;
};

} // namespace quic
