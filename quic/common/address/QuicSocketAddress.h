/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#pragma once

#include <cstring>
#include <ostream>
#include <string>

#include <folly/IPAddress.h>
#include <folly/portability/Sockets.h>

namespace quic {

/**
 * A non-throwing socket address type for use in mobile QUIC builds.
 *
 * Wraps sockaddr_storage + socklen_t internally. Only implements the subset
 * of folly::SocketAddress API that mvfst actually uses. Does NOT depend on
 * folly::SocketAddress — conversions live in a separate bridge header.
 *
 * All observer methods are noexcept. String formatting methods allocate but
 * do not throw logic errors. Comparison and hashing use normalized fields
 * (family + IP bytes + port), NOT raw memcmp on sockaddr_storage. operator<
 * orders family, then port, then IP — matching folly::SocketAddress so ordered
 * containers iterate identically when the mobile alias flips to this type.
 */
class QuicSocketAddress {
  sockaddr_storage storage_{};
  socklen_t len_{0};

 public:
  QuicSocketAddress() noexcept = default;
  QuicSocketAddress(folly::IPAddress ip, uint16_t port) noexcept;
  QuicSocketAddress(const sockaddr* addr, socklen_t len) noexcept;

  // Observers — all noexcept
  sa_family_t getFamily() const noexcept;
  uint16_t getPort() const noexcept;
  // folly parity: folly::SocketAddress returns `const IPAddress&`; we return by
  // value because the IPAddress is synthesized from storage_ on each call (this
  // type stores a sockaddr_storage, not a folly::IPAddress member).
  folly::IPAddress getIPAddress() const noexcept;
  bool isInitialized() const noexcept;
  socklen_t getAddress(sockaddr_storage* dest) const noexcept;
  // folly parity: folly::SocketAddress returns sizeof(sockaddr_in) for
  // AF_UNSPEC; we intentionally return 0 (len_) for an uninitialized address.
  socklen_t getActualSize() const noexcept;

  // String formatting — allocates but does not throw logic errors
  std::string describe() const;
  std::string getAddressStr() const;
  std::string getFullyQualified() const;

  // Validated construction — explicit status, not swallowed failure
  static bool trySetFromSockaddr(
      QuicSocketAddress& out,
      const sockaddr* addr,
      socklen_t len) noexcept;

  // Compatibility mutator for already-validated paths (e.g., recvmmsg output)
  void setFromSockaddr(const sockaddr* addr, socklen_t len) noexcept;

  // Comparison + hashing — all noexcept, compare normalized fields
  bool operator==(const QuicSocketAddress& other) const noexcept;
  bool operator!=(const QuicSocketAddress& other) const noexcept;
  bool operator<(const QuicSocketAddress& other) const noexcept;
};

/**
 * Hash functor for QuicSocketAddress.
 * Hashes normalized family + IP bytes + port (NOT raw sockaddr_storage).
 */
struct QuicSocketAddressHash {
  size_t operator()(const QuicSocketAddress& addr) const noexcept;
};

inline std::ostream& operator<<(
    std::ostream& os,
    const QuicSocketAddress& addr) {
  os << addr.describe();
  return os;
}

} // namespace quic

namespace std {
template <>
struct hash<quic::QuicSocketAddress> : quic::QuicSocketAddressHash {};
} // namespace std
