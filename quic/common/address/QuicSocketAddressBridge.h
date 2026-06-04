/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#pragma once

#include <type_traits>

#include <quic/common/address/QuicSocketAddress.h>

#include <folly/SocketAddress.h>

namespace quic {

/**
 * Convert quic::SocketAddress to folly::SocketAddress.
 *
 * On server builds (quic::SocketAddress == folly::SocketAddress): identity,
 * zero overhead. On mobile builds: constructs folly::SocketAddress via
 * setFromIpAddrPort() which is a simple variant assignment (cannot throw for
 * valid IP addresses).
 *
 * Not marked noexcept — folly::SocketAddress(IPAddress, uint16_t) calls
 * setFromIpAddrPort() which is not declared noexcept in folly's type system.
 */
template <typename T>
folly::SocketAddress toFollySocketAddress(const T& addr) {
  if constexpr (std::is_same_v<T, folly::SocketAddress>) {
    return addr;
  } else {
    if (!addr.isInitialized()) {
      return {};
    }
    // Use getIPAddress() (noexcept) + getPort() (noexcept) and construct
    // via SocketAddress(IPAddress, port) -> setFromIpAddrPort() which is
    // storage_ = IPAddr(ipAddr, port) — a simple variant assignment.
    // DO NOT use setFromSockaddr(const sockaddr_in*) — that chains through
    // the single-arg setFromSockaddr(const sockaddr*) which calls the
    // throwing folly::IPAddress(const sockaddr*) constructor.
    return folly::SocketAddress(addr.getIPAddress(), addr.getPort());
  }
}

/**
 * Convert folly::SocketAddress to quic::SocketAddress.
 *
 * On server builds: identity. On mobile builds: constructs
 * QuicSocketAddress from folly's sockaddr.
 *
 * mvfst is inet-only: a non-inet source (AF_UNIX/VSOCK) has no meaningful
 * QuicSocketAddress representation, so on mobile builds it converts to an
 * empty (uninitialized) result rather than a live object with a bogus family.
 */
template <typename DestT>
DestT fromFollySocketAddress(const folly::SocketAddress& addr) {
  if constexpr (std::is_same_v<DestT, folly::SocketAddress>) {
    return addr;
  } else {
    if (!addr.isInitialized() || !addr.isFamilyInet()) {
      return DestT();
    }
    sockaddr_storage storage{};
    auto len = addr.getAddress(&storage);
    return DestT(reinterpret_cast<const sockaddr*>(&storage), len);
  }
}

/**
 * Templated ref-returning helper for consumer noexcept methods that must
 * return const folly::SocketAddress&.
 *
 * On server builds the template parameter deduces to folly::SocketAddress,
 * so the if constexpr branch returns the original reference directly (zero
 * overhead, preserves reference identity). On mobile builds it converts +
 * caches.
 *
 * IMPORTANT: This MUST be a template (not an inline if constexpr in a
 * non-template method). In non-template functions like
 * HQSession::getPeerAddress(), both branches of if constexpr are type-
 * checked — the discarded branch would fail to compile if it tries to
 * return const QuicSocketAddress& as const folly::SocketAddress&.
 */
template <typename QuicAddr>
const folly::SocketAddress& toFollySocketAddressRef(
    const QuicAddr& quicAddr,
    folly::SocketAddress& cache) {
  if constexpr (std::is_same_v<QuicAddr, folly::SocketAddress>) {
    return quicAddr;
  } else {
    cache = toFollySocketAddress(quicAddr);
    return cache;
  }
}

/**
 * Mirror of toFollySocketAddressRef for the folly -> quic direction: a
 * ref-returning helper for hot-path consumers that forward a
 * const quic::SocketAddress& without owning it.
 *
 * On server builds DestT deduces to folly::SocketAddress, so the if constexpr
 * branch returns the input reference directly (zero copy, no cache write). On
 * mobile builds it converts into the caller-provided cache and returns a
 * reference to it.
 *
 * IMPORTANT: This MUST be a template for the same reason as
 * toFollySocketAddressRef — in a non-template caller both if constexpr
 * branches are type-checked, and returning const folly::SocketAddress& as
 * const QuicSocketAddress& would not compile on mobile.
 *
 * Prefer this over fromFollySocketAddress() on hot paths that only forward the
 * address: fromFollySocketAddress() returns by value and so copies on the
 * server/identity path, whereas this returns a reference.
 */
template <typename DestT>
const DestT& fromFollySocketAddressRef(
    const folly::SocketAddress& follyAddr,
    DestT& cache) {
  if constexpr (std::is_same_v<DestT, folly::SocketAddress>) {
    return follyAddr;
  } else {
    cache = fromFollySocketAddress<DestT>(follyAddr);
    return cache;
  }
}

} // namespace quic
