/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#pragma once

#include <quic/common/address/QuicSocketAddress.h>

#include <folly/portability/Sockets.h>

namespace quic {

/**
 * Construct a loopback QuicSocketAddress (127.0.0.1 or ::1) for the given
 * address family and port. Builds sockaddr_in/sockaddr_in6 directly — no
 * string parsing, no exceptions.
 */
QuicSocketAddress makeLoopbackAddress(
    sa_family_t family,
    uint16_t port) noexcept;

/**
 * Construct a wildcard/any QuicSocketAddress (0.0.0.0 or ::) for the given
 * address family and port. Builds sockaddr_in/sockaddr_in6 directly — no
 * string parsing, no exceptions.
 */
QuicSocketAddress makeAnyAddress(sa_family_t family, uint16_t port) noexcept;

} // namespace quic
