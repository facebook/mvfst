/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#pragma once

#include <quic/logging/QLogger.h>

namespace quic {

// QLOG macro for logging via the qLogger member of a connection state.
// Usage: QLOG(conn, addPacket, packet, size);
// On mobile builds, this is a no-op to reduce binary size.
#define QLOG(conn, method, ...)            \
  do {                                     \
    if ((conn).qLogger) {                  \
      (conn).qLogger->method(__VA_ARGS__); \
    }                                      \
  } while (0)

} // namespace quic
