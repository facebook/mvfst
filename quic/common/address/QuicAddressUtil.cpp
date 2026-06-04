/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <quic/common/address/QuicAddressUtil.h>

#include <folly/portability/Sockets.h>

namespace quic {

QuicSocketAddress makeLoopbackAddress(
    sa_family_t family,
    uint16_t port) noexcept {
  if (family == AF_INET) {
    sockaddr_in sin{};
    sin.sin_family = AF_INET;
    sin.sin_port = htons(port);
    sin.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    return QuicSocketAddress(
        reinterpret_cast<const sockaddr*>(&sin), sizeof(sin));
  }
  // AF_INET6 (or any other family — default to v6 loopback)
  sockaddr_in6 sin6{};
  sin6.sin6_family = AF_INET6;
  sin6.sin6_port = htons(port);
  sin6.sin6_addr = in6addr_loopback;
  return QuicSocketAddress(
      reinterpret_cast<const sockaddr*>(&sin6), sizeof(sin6));
}

QuicSocketAddress makeAnyAddress(sa_family_t family, uint16_t port) noexcept {
  if (family == AF_INET) {
    sockaddr_in sin{};
    sin.sin_family = AF_INET;
    sin.sin_port = htons(port);
    sin.sin_addr.s_addr = htonl(INADDR_ANY);
    return QuicSocketAddress(
        reinterpret_cast<const sockaddr*>(&sin), sizeof(sin));
  }
  // AF_INET6
  sockaddr_in6 sin6{};
  sin6.sin6_family = AF_INET6;
  sin6.sin6_port = htons(port);
  sin6.sin6_addr = in6addr_any;
  return QuicSocketAddress(
      reinterpret_cast<const sockaddr*>(&sin6), sizeof(sin6));
}

} // namespace quic
