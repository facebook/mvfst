/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <quic/common/address/QuicSocketAddress.h>

#include <algorithm>

#include <fmt/core.h>

#include <folly/portability/Sockets.h>

namespace quic {

QuicSocketAddress::QuicSocketAddress(
    folly::IPAddress ip,
    uint16_t port) noexcept {
  if (ip.isV4()) {
    auto* sin = reinterpret_cast<sockaddr_in*>(&storage_);
    sin->sin_family = AF_INET;
    sin->sin_port = htons(port);
    sin->sin_addr = ip.asV4().toAddr();
    len_ = sizeof(sockaddr_in);
  } else if (ip.isV6()) {
    auto* sin6 = reinterpret_cast<sockaddr_in6*>(&storage_);
    sin6->sin6_family = AF_INET6;
    sin6->sin6_port = htons(port);
    sin6->sin6_addr = ip.asV6().toAddr();
    sin6->sin6_scope_id = ip.asV6().getScopeId();
    len_ = sizeof(sockaddr_in6);
  }
  // else: ip is uninitialized (AF_UNSPEC) — leave storage_ zeroed, len_ = 0
}

QuicSocketAddress::QuicSocketAddress(
    const sockaddr* addr,
    socklen_t len) noexcept {
  setFromSockaddr(addr, len);
}

sa_family_t QuicSocketAddress::getFamily() const noexcept {
  return storage_.ss_family;
}

uint16_t QuicSocketAddress::getPort() const noexcept {
  switch (storage_.ss_family) {
    case AF_INET:
      return ntohs(reinterpret_cast<const sockaddr_in*>(&storage_)->sin_port);
    case AF_INET6:
      return ntohs(reinterpret_cast<const sockaddr_in6*>(&storage_)->sin6_port);
    default:
      return 0;
  }
}

folly::IPAddress QuicSocketAddress::getIPAddress() const noexcept {
  auto result = folly::IPAddress::tryFromSockAddr(
      reinterpret_cast<const sockaddr*>(&storage_));
  if (result.hasValue()) {
    return result.value();
  }
  return folly::IPAddress();
}

bool QuicSocketAddress::isInitialized() const noexcept {
  return storage_.ss_family != AF_UNSPEC;
}

socklen_t QuicSocketAddress::getAddress(sockaddr_storage* dest) const noexcept {
  if (len_ == 0) {
    memset(dest, 0, sizeof(*dest));
    return 0;
  }
  memcpy(dest, &storage_, sizeof(*dest));
  return len_;
}

socklen_t QuicSocketAddress::getActualSize() const noexcept {
  return len_;
}

std::string QuicSocketAddress::describe() const {
  if (!isInitialized()) {
    return "[uninit]";
  }
  auto ip = getIPAddress();
  auto port = getPort();
  if (ip.isV6()) {
    return fmt::format("[{}]:{}", ip.str(), port);
  }
  return fmt::format("{}:{}", ip.str(), port);
}

std::string QuicSocketAddress::getAddressStr() const {
  if (!isInitialized()) {
    return "";
  }
  return getIPAddress().str();
}

std::string QuicSocketAddress::getFullyQualified() const {
  if (!isInitialized()) {
    return "";
  }
  auto ip = getIPAddress();
  return fmt::format("{}:{}", ip.toFullyQualified(), getPort());
}

/* static */ bool QuicSocketAddress::trySetFromSockaddr(
    QuicSocketAddress& out,
    const sockaddr* addr,
    socklen_t len) noexcept {
  // Reading sa_family is only safe once len covers that field.
  if (addr == nullptr ||
      len < static_cast<socklen_t>(sizeof(addr->sa_family))) {
    return false;
  }
  switch (addr->sa_family) {
    case AF_INET:
      if (len < sizeof(sockaddr_in)) {
        return false;
      }
      out.setFromSockaddr(addr, len);
      return true;
    case AF_INET6:
      if (len < sizeof(sockaddr_in6)) {
        return false;
      }
      out.setFromSockaddr(addr, len);
      return true;
    default:
      return false;
  }
}

void QuicSocketAddress::setFromSockaddr(
    const sockaddr* addr,
    socklen_t len) noexcept {
  memset(&storage_, 0, sizeof(storage_));
  len_ = 0;
  if (addr == nullptr) {
    return;
  }
  // The caller-supplied len can exceed the actual source buffer (e.g. callers
  // that pass sizeof(sockaddr_storage) regardless of the real family). Clamp
  // the number of bytes we read to the family-specific size so we never read
  // past the source, while also capping by our own storage size.
  size_t copyLen = std::min(static_cast<size_t>(len), sizeof(storage_));
  // Reading sa_family is only safe once len covers that field.
  if (len >= static_cast<socklen_t>(sizeof(addr->sa_family))) {
    switch (addr->sa_family) {
      case AF_INET:
        copyLen = std::min(copyLen, sizeof(sockaddr_in));
        break;
      case AF_INET6:
        copyLen = std::min(copyLen, sizeof(sockaddr_in6));
        break;
      default:
        break;
    }
  }
  memcpy(&storage_, addr, copyLen);
  len_ = static_cast<socklen_t>(copyLen);
}

bool QuicSocketAddress::operator==(
    const QuicSocketAddress& other) const noexcept {
  if (storage_.ss_family != other.storage_.ss_family) {
    return false;
  }
  switch (storage_.ss_family) {
    case AF_INET: {
      auto* a = reinterpret_cast<const sockaddr_in*>(&storage_);
      auto* b = reinterpret_cast<const sockaddr_in*>(&other.storage_);
      return a->sin_port == b->sin_port &&
          a->sin_addr.s_addr == b->sin_addr.s_addr;
    }
    case AF_INET6: {
      auto* a = reinterpret_cast<const sockaddr_in6*>(&storage_);
      auto* b = reinterpret_cast<const sockaddr_in6*>(&other.storage_);
      return a->sin6_port == b->sin6_port &&
          memcmp(&a->sin6_addr, &b->sin6_addr, sizeof(in6_addr)) == 0 &&
          a->sin6_scope_id == b->sin6_scope_id;
    }
    case AF_UNSPEC:
      return true;
    default:
      // For unsupported families, fall back to comparing raw bytes up to len_
      return len_ == other.len_ &&
          memcmp(&storage_, &other.storage_, len_) == 0;
  }
}

bool QuicSocketAddress::operator!=(
    const QuicSocketAddress& other) const noexcept {
  return !(*this == other);
}

bool QuicSocketAddress::operator<(
    const QuicSocketAddress& other) const noexcept {
  if (storage_.ss_family != other.storage_.ss_family) {
    return storage_.ss_family < other.storage_.ss_family;
  }
  switch (storage_.ss_family) {
    case AF_INET: {
      auto* a = reinterpret_cast<const sockaddr_in*>(&storage_);
      auto* b = reinterpret_cast<const sockaddr_in*>(&other.storage_);
      // Port-first to match folly::SocketAddress::operator<, so ordered
      // containers iterate identically whether keyed on this type or folly's.
      auto portA = ntohs(a->sin_port);
      auto portB = ntohs(b->sin_port);
      if (portA != portB) {
        return portA < portB;
      }
      return ntohl(a->sin_addr.s_addr) < ntohl(b->sin_addr.s_addr);
    }
    case AF_INET6: {
      auto* a = reinterpret_cast<const sockaddr_in6*>(&storage_);
      auto* b = reinterpret_cast<const sockaddr_in6*>(&other.storage_);
      // Port-first to match folly::SocketAddress::operator<.
      auto portA = ntohs(a->sin6_port);
      auto portB = ntohs(b->sin6_port);
      if (portA != portB) {
        return portA < portB;
      }
      auto cmp = memcmp(&a->sin6_addr, &b->sin6_addr, sizeof(in6_addr));
      if (cmp != 0) {
        return cmp < 0;
      }
      return a->sin6_scope_id < b->sin6_scope_id;
    }
    default:
      // Unsupported families (and AF_UNSPEC): provide a total order consistent
      // with operator==, which byte-compares up to len_. folly throws here, but
      // this type is noexcept, so we order on (len_, bytes) instead.
      if (len_ != other.len_) {
        return len_ < other.len_;
      }
      return memcmp(&storage_, &other.storage_, len_) < 0;
  }
}

size_t QuicSocketAddressHash::operator()(
    const QuicSocketAddress& addr) const noexcept {
  auto family = addr.getFamily();
  auto port = addr.getPort();
  auto ip = addr.getIPAddress();

  size_t seed = std::hash<sa_family_t>{}(family);
  seed ^= std::hash<uint16_t>{}(port) + 0x9e3779b9 + (seed << 6) + (seed >> 2);
  seed ^= ip.hash() + 0x9e3779b9 + (seed << 6) + (seed >> 2);
  return seed;
}

} // namespace quic
