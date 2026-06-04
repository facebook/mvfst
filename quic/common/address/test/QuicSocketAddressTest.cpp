/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <quic/common/address/QuicSocketAddress.h>

#include <quic/common/address/QuicAddressUtil.h>

#include <folly/portability/GTest.h>
#include <folly/portability/Sockets.h>

#include <sstream>
#include <unordered_set>

using namespace quic;

// =============================================================================
// Noexcept static_asserts
// =============================================================================

static_assert(
    std::is_nothrow_default_constructible_v<QuicSocketAddress>,
    "default ctor must be noexcept");

TEST(QuicSocketAddressTest, NoexceptGuarantees) {
  const QuicSocketAddress addr;
  static_assert(noexcept(addr.getFamily()));
  static_assert(noexcept(addr.getPort()));
  static_assert(noexcept(addr.getIPAddress()));
  static_assert(noexcept(addr.isInitialized()));
  static_assert(noexcept(addr.getActualSize()));

  sockaddr_storage dest{};
  static_assert(noexcept(addr.getAddress(&dest)));

  const QuicSocketAddress other;
  static_assert(noexcept(addr == other));
  static_assert(noexcept(addr != other));
  static_assert(noexcept(addr < other));

  QuicSocketAddress mutableAddr;
  sockaddr_in sin{};
  sin.sin_family = AF_INET;
  auto* sa = reinterpret_cast<const sockaddr*>(&sin);
  static_assert(noexcept(mutableAddr.setFromSockaddr(sa, sizeof(sin))));
  static_assert(noexcept(
      QuicSocketAddress::trySetFromSockaddr(mutableAddr, sa, sizeof(sin))));

  folly::IPAddress ip;
  static_assert(noexcept(QuicSocketAddress(ip, uint16_t{0})));
  static_assert(noexcept(QuicSocketAddress(sa, sizeof(sin))));
}

// =============================================================================
// Default-constructed state
// =============================================================================

TEST(QuicSocketAddressTest, DefaultConstructed) {
  QuicSocketAddress addr;
  EXPECT_FALSE(addr.isInitialized());
  EXPECT_EQ(addr.getFamily(), AF_UNSPEC);
  EXPECT_EQ(addr.getPort(), 0);
  EXPECT_EQ(addr.getActualSize(), 0u);

  auto ip = addr.getIPAddress();
  EXPECT_TRUE(ip.empty());
  EXPECT_FALSE(ip.isV4());
  EXPECT_FALSE(ip.isV6());

  sockaddr_storage dest{};
  memset(&dest, 0xFF, sizeof(dest));
  auto len = addr.getAddress(&dest);
  EXPECT_EQ(len, 0u);
  // dest should be zeroed
  sockaddr_storage zeroed{};
  EXPECT_EQ(memcmp(&dest, &zeroed, sizeof(dest)), 0);
}

TEST(QuicSocketAddressTest, DefaultConstructedStringFormatting) {
  QuicSocketAddress addr;
  EXPECT_EQ(addr.describe(), "[uninit]");
  EXPECT_EQ(addr.getAddressStr(), "");
  EXPECT_EQ(addr.getFullyQualified(), "");
}

// =============================================================================
// Construction from folly::IPAddress + port
// =============================================================================

TEST(QuicSocketAddressTest, ConstructFromIPv4AddressAndPort) {
  auto ip = folly::IPAddress("192.168.1.100");
  QuicSocketAddress addr(ip, 443);

  EXPECT_TRUE(addr.isInitialized());
  EXPECT_EQ(addr.getFamily(), AF_INET);
  EXPECT_EQ(addr.getPort(), 443);
  EXPECT_EQ(addr.getIPAddress(), ip);
  EXPECT_EQ(addr.getActualSize(), sizeof(sockaddr_in));
}

TEST(QuicSocketAddressTest, ConstructFromIPv6AddressAndPort) {
  auto ip = folly::IPAddress("::1");
  QuicSocketAddress addr(ip, 8080);

  EXPECT_TRUE(addr.isInitialized());
  EXPECT_EQ(addr.getFamily(), AF_INET6);
  EXPECT_EQ(addr.getPort(), 8080);
  EXPECT_EQ(addr.getIPAddress(), ip);
  EXPECT_EQ(addr.getActualSize(), sizeof(sockaddr_in6));
}

TEST(QuicSocketAddressTest, ConstructFromUninitializedIPAddress) {
  folly::IPAddress ip; // default, AF_UNSPEC
  QuicSocketAddress addr(ip, 1234);

  // An uninitialized IPAddress should result in an uninitialized address
  EXPECT_FALSE(addr.isInitialized());
  EXPECT_EQ(addr.getFamily(), AF_UNSPEC);
  EXPECT_EQ(addr.getPort(), 0);
}

// =============================================================================
// Construction from raw sockaddr
// =============================================================================

TEST(QuicSocketAddressTest, ConstructFromSockaddrIn) {
  sockaddr_in sin{};
  sin.sin_family = AF_INET;
  sin.sin_port = htons(9000);
  inet_pton(AF_INET, "10.0.0.1", &sin.sin_addr);

  QuicSocketAddress addr(reinterpret_cast<const sockaddr*>(&sin), sizeof(sin));

  EXPECT_TRUE(addr.isInitialized());
  EXPECT_EQ(addr.getFamily(), AF_INET);
  EXPECT_EQ(addr.getPort(), 9000);
  EXPECT_EQ(addr.getIPAddress(), folly::IPAddress("10.0.0.1"));
}

TEST(QuicSocketAddressTest, ConstructFromSockaddrIn6) {
  sockaddr_in6 sin6{};
  sin6.sin6_family = AF_INET6;
  sin6.sin6_port = htons(4433);
  inet_pton(AF_INET6, "2001:db8::1", &sin6.sin6_addr);

  QuicSocketAddress addr(
      reinterpret_cast<const sockaddr*>(&sin6), sizeof(sin6));

  EXPECT_TRUE(addr.isInitialized());
  EXPECT_EQ(addr.getFamily(), AF_INET6);
  EXPECT_EQ(addr.getPort(), 4433);
  EXPECT_EQ(addr.getIPAddress(), folly::IPAddress("2001:db8::1"));
}

// =============================================================================
// getIPAddress() round-trip
// =============================================================================

TEST(QuicSocketAddressTest, GetIPAddressV4) {
  auto expected = folly::IPAddress("172.16.254.1");
  QuicSocketAddress addr(expected, 80);
  EXPECT_EQ(addr.getIPAddress(), expected);
  EXPECT_TRUE(addr.getIPAddress().isV4());
}

TEST(QuicSocketAddressTest, GetIPAddressV6) {
  auto expected = folly::IPAddress("fe80::1");
  QuicSocketAddress addr(expected, 443);
  EXPECT_EQ(addr.getIPAddress(), expected);
  EXPECT_TRUE(addr.getIPAddress().isV6());
}

// =============================================================================
// getAddress() round-trip
// =============================================================================

TEST(QuicSocketAddressTest, GetAddressRoundTripV4) {
  auto ip = folly::IPAddress("192.168.0.1");
  QuicSocketAddress original(ip, 5000);

  sockaddr_storage storage{};
  auto len = original.getAddress(&storage);
  EXPECT_EQ(len, sizeof(sockaddr_in));

  // Reconstruct from the extracted sockaddr
  QuicSocketAddress roundTripped(
      reinterpret_cast<const sockaddr*>(&storage), len);
  EXPECT_EQ(roundTripped, original);
  EXPECT_EQ(roundTripped.getIPAddress(), ip);
  EXPECT_EQ(roundTripped.getPort(), 5000);
}

TEST(QuicSocketAddressTest, GetAddressRoundTripV6) {
  auto ip = folly::IPAddress("2001:db8::dead:beef");
  QuicSocketAddress original(ip, 6000);

  sockaddr_storage storage{};
  auto len = original.getAddress(&storage);
  EXPECT_EQ(len, sizeof(sockaddr_in6));

  QuicSocketAddress roundTripped(
      reinterpret_cast<const sockaddr*>(&storage), len);
  EXPECT_EQ(roundTripped, original);
  EXPECT_EQ(roundTripped.getIPAddress(), ip);
  EXPECT_EQ(roundTripped.getPort(), 6000);
}

// =============================================================================
// String formatting
// =============================================================================

TEST(QuicSocketAddressTest, DescribeIPv4) {
  QuicSocketAddress addr(folly::IPAddress("1.2.3.4"), 80);
  EXPECT_EQ(addr.describe(), "1.2.3.4:80");
}

TEST(QuicSocketAddressTest, DescribeIPv6) {
  QuicSocketAddress addr(folly::IPAddress("::1"), 443);
  EXPECT_EQ(addr.describe(), "[::1]:443");
}

TEST(QuicSocketAddressTest, GetAddressStrIPv4) {
  QuicSocketAddress addr(folly::IPAddress("10.0.0.1"), 80);
  EXPECT_EQ(addr.getAddressStr(), "10.0.0.1");
}

TEST(QuicSocketAddressTest, GetAddressStrIPv6) {
  QuicSocketAddress addr(folly::IPAddress("::1"), 80);
  EXPECT_EQ(addr.getAddressStr(), "::1");
}

TEST(QuicSocketAddressTest, GetFullyQualifiedIPv4) {
  QuicSocketAddress addr(folly::IPAddress("10.0.0.1"), 80);
  EXPECT_EQ(addr.getFullyQualified(), "10.0.0.1:80");
}

TEST(QuicSocketAddressTest, GetFullyQualifiedIPv6) {
  QuicSocketAddress addr(folly::IPAddress("::1"), 443);
  auto fq = addr.getFullyQualified();
  // Fully qualified v6 uses expanded hex: 0000:0000:...:0001
  EXPECT_NE(fq.find("0001"), std::string::npos);
  EXPECT_NE(fq.find(":443"), std::string::npos);
}

// =============================================================================
// trySetFromSockaddr
// =============================================================================

TEST(QuicSocketAddressTest, TrySetFromSockaddrIPv4) {
  sockaddr_in sin{};
  sin.sin_family = AF_INET;
  sin.sin_port = htons(7777);
  inet_pton(AF_INET, "192.168.1.1", &sin.sin_addr);

  QuicSocketAddress addr;
  bool ok = QuicSocketAddress::trySetFromSockaddr(
      addr, reinterpret_cast<const sockaddr*>(&sin), sizeof(sin));
  EXPECT_TRUE(ok);
  EXPECT_TRUE(addr.isInitialized());
  EXPECT_EQ(addr.getPort(), 7777);
  EXPECT_EQ(addr.getIPAddress(), folly::IPAddress("192.168.1.1"));
}

TEST(QuicSocketAddressTest, TrySetFromSockaddrIPv6) {
  sockaddr_in6 sin6{};
  sin6.sin6_family = AF_INET6;
  sin6.sin6_port = htons(8888);
  inet_pton(AF_INET6, "::1", &sin6.sin6_addr);

  QuicSocketAddress addr;
  bool ok = QuicSocketAddress::trySetFromSockaddr(
      addr, reinterpret_cast<const sockaddr*>(&sin6), sizeof(sin6));
  EXPECT_TRUE(ok);
  EXPECT_TRUE(addr.isInitialized());
  EXPECT_EQ(addr.getPort(), 8888);
}

TEST(QuicSocketAddressTest, TrySetFromSockaddrUnsupportedFamily) {
  sockaddr_un sun{};
  sun.sun_family = AF_UNIX;

  // Set up addr with known state first
  QuicSocketAddress addr(folly::IPAddress("1.2.3.4"), 1234);
  ASSERT_TRUE(addr.isInitialized());

  bool ok = QuicSocketAddress::trySetFromSockaddr(
      addr, reinterpret_cast<const sockaddr*>(&sun), sizeof(sun));
  EXPECT_FALSE(ok);
  // addr should be unchanged
  EXPECT_TRUE(addr.isInitialized());
  EXPECT_EQ(addr.getPort(), 1234);
  EXPECT_EQ(addr.getIPAddress(), folly::IPAddress("1.2.3.4"));
}

// =============================================================================
// setFromSockaddr
// =============================================================================

TEST(QuicSocketAddressTest, SetFromSockaddrIPv4) {
  sockaddr_in sin{};
  sin.sin_family = AF_INET;
  sin.sin_port = htons(5555);
  inet_pton(AF_INET, "10.10.10.10", &sin.sin_addr);

  QuicSocketAddress addr;
  addr.setFromSockaddr(reinterpret_cast<const sockaddr*>(&sin), sizeof(sin));

  EXPECT_TRUE(addr.isInitialized());
  EXPECT_EQ(addr.getFamily(), AF_INET);
  EXPECT_EQ(addr.getPort(), 5555);
}

TEST(QuicSocketAddressTest, SetFromSockaddrUnsupportedFamily) {
  sockaddr_un sun{};
  sun.sun_family = AF_UNIX;

  QuicSocketAddress addr;
  addr.setFromSockaddr(reinterpret_cast<const sockaddr*>(&sun), sizeof(sun));

  // Stores raw bytes: isInitialized() == true, but getPort() == 0
  EXPECT_TRUE(addr.isInitialized());
  EXPECT_EQ(addr.getFamily(), AF_UNIX);
  EXPECT_EQ(addr.getPort(), 0);
  EXPECT_TRUE(addr.getIPAddress().empty());
}

// =============================================================================
// Equality — normalized comparison (not raw memcmp)
// =============================================================================

TEST(QuicSocketAddressTest, EqualityDefaultConstructed) {
  QuicSocketAddress a;
  QuicSocketAddress b;
  EXPECT_EQ(a, b);
}

TEST(QuicSocketAddressTest, EqualitySameAddress) {
  QuicSocketAddress a(folly::IPAddress("1.2.3.4"), 80);
  QuicSocketAddress b(folly::IPAddress("1.2.3.4"), 80);
  EXPECT_EQ(a, b);
}

TEST(QuicSocketAddressTest, InequalityDifferentPort) {
  QuicSocketAddress a(folly::IPAddress("1.2.3.4"), 80);
  QuicSocketAddress b(folly::IPAddress("1.2.3.4"), 81);
  EXPECT_NE(a, b);
}

TEST(QuicSocketAddressTest, InequalityDifferentIP) {
  QuicSocketAddress a(folly::IPAddress("1.2.3.4"), 80);
  QuicSocketAddress b(folly::IPAddress("1.2.3.5"), 80);
  EXPECT_NE(a, b);
}

TEST(QuicSocketAddressTest, EqualityDifferentSinZeroPadding) {
  // Two sockaddr_in with same IP/port but different sin_zero padding
  // must compare equal (normalized comparison, not raw memcmp)
  sockaddr_in sin1{};
  sin1.sin_family = AF_INET;
  sin1.sin_port = htons(80);
  inet_pton(AF_INET, "10.0.0.1", &sin1.sin_addr);
  // sin_zero is already zeroed from value-initialization

  sockaddr_in sin2{};
  sin2.sin_family = AF_INET;
  sin2.sin_port = htons(80);
  inet_pton(AF_INET, "10.0.0.1", &sin2.sin_addr);
  // Fill sin_zero with garbage
  memset(sin2.sin_zero, 0xAB, sizeof(sin2.sin_zero));

  QuicSocketAddress a(reinterpret_cast<const sockaddr*>(&sin1), sizeof(sin1));
  QuicSocketAddress b(reinterpret_cast<const sockaddr*>(&sin2), sizeof(sin2));

  EXPECT_EQ(a, b);
}

TEST(QuicSocketAddressTest, EqualityPartiallyInitializedStorage) {
  // Construct two addresses from sockaddr_storage with different trailing bytes
  // They should compare equal if family + IP + port match
  sockaddr_storage ss1{};
  sockaddr_storage ss2{};

  // Fill ss2 with garbage first
  memset(&ss2, 0xFF, sizeof(ss2));

  auto* sin1 = reinterpret_cast<sockaddr_in*>(&ss1);
  auto* sin2 = reinterpret_cast<sockaddr_in*>(&ss2);

  sin1->sin_family = AF_INET;
  sin1->sin_port = htons(443);
  inet_pton(AF_INET, "192.168.1.1", &sin1->sin_addr);

  sin2->sin_family = AF_INET;
  sin2->sin_port = htons(443);
  inet_pton(AF_INET, "192.168.1.1", &sin2->sin_addr);

  QuicSocketAddress a(
      reinterpret_cast<const sockaddr*>(&ss1), sizeof(sockaddr_in));
  QuicSocketAddress b(
      reinterpret_cast<const sockaddr*>(&ss2), sizeof(sockaddr_in));

  EXPECT_EQ(a, b);
}

TEST(QuicSocketAddressTest, PartiallyInitializedNoFalseMatch) {
  // Two addresses with different IPs must NOT compare equal
  QuicSocketAddress a(folly::IPAddress("192.168.1.1"), 443);
  QuicSocketAddress b(folly::IPAddress("192.168.1.2"), 443);
  EXPECT_NE(a, b);
}

// =============================================================================
// operator<
// =============================================================================

TEST(QuicSocketAddressTest, LessThan) {
  QuicSocketAddress a(folly::IPAddress("1.2.3.4"), 80);
  QuicSocketAddress b(folly::IPAddress("1.2.3.5"), 80);
  // a < b because 1.2.3.4 < 1.2.3.5
  EXPECT_TRUE(a < b);
  EXPECT_FALSE(b < a);
}

TEST(QuicSocketAddressTest, LessThanSameIPDifferentPort) {
  QuicSocketAddress a(folly::IPAddress("1.2.3.4"), 80);
  QuicSocketAddress b(folly::IPAddress("1.2.3.4"), 81);
  EXPECT_TRUE(a < b);
  EXPECT_FALSE(b < a);
}

TEST(QuicSocketAddressTest, LessThanPortFirstMatchesFollyV4) {
  // A lower port with a higher IP must still sort first: port is the primary
  // key, matching folly::SocketAddress::operator<. IP-first ordering would
  // give the opposite result here.
  QuicSocketAddress lowPortHighIp(folly::IPAddress("1.2.3.5"), 80);
  QuicSocketAddress highPortLowIp(folly::IPAddress("1.2.3.4"), 81);
  EXPECT_TRUE(lowPortHighIp < highPortLowIp);
  EXPECT_FALSE(highPortLowIp < lowPortHighIp);
}

TEST(QuicSocketAddressTest, LessThanPortFirstMatchesFollyV6) {
  QuicSocketAddress lowPortHighIp(folly::IPAddress("2001:db8::2"), 80);
  QuicSocketAddress highPortLowIp(folly::IPAddress("2001:db8::1"), 81);
  EXPECT_TRUE(lowPortHighIp < highPortLowIp);
  EXPECT_FALSE(highPortLowIp < lowPortHighIp);
}

TEST(QuicSocketAddressTest, LessThanConsistentWithEqualityUnknownFamily) {
  // For unsupported families operator< falls back to the same byte comparison
  // as operator==, so the two agree: distinct values are strictly ordered and
  // equal values are unordered (a valid strict weak ordering).
  auto makeUnix = [](const char* path) {
    sockaddr_un sun{};
    sun.sun_family = AF_UNIX;
    strncpy(sun.sun_path, path, sizeof(sun.sun_path) - 1);
    QuicSocketAddress addr;
    addr.setFromSockaddr(reinterpret_cast<const sockaddr*>(&sun), sizeof(sun));
    return addr;
  };

  QuicSocketAddress a = makeUnix("/tmp/a");
  QuicSocketAddress b = makeUnix("/tmp/b");
  QuicSocketAddress aCopy = makeUnix("/tmp/a");

  // Distinct: not equal, and exactly one is ordered before the other.
  EXPECT_NE(a, b);
  EXPECT_NE(a < b, b < a);

  // Equal: agrees with operator== (neither is less than the other).
  EXPECT_EQ(a, aCopy);
  EXPECT_FALSE(a < aCopy);
  EXPECT_FALSE(aCopy < a);
}

// =============================================================================
// Hashing
// =============================================================================

TEST(QuicSocketAddressTest, HashConsistentWithEquality) {
  QuicSocketAddress a(folly::IPAddress("10.0.0.1"), 80);
  QuicSocketAddress b(folly::IPAddress("10.0.0.1"), 80);
  EXPECT_EQ(a, b);

  QuicSocketAddressHash hasher;
  EXPECT_EQ(hasher(a), hasher(b));
}

TEST(QuicSocketAddressTest, HashDeterministicForUninitialized) {
  QuicSocketAddress a;
  QuicSocketAddress b;
  QuicSocketAddressHash hasher;
  EXPECT_EQ(hasher(a), hasher(b));
}

TEST(QuicSocketAddressTest, HashDifferentForDifferentAddresses) {
  QuicSocketAddress a(folly::IPAddress("10.0.0.1"), 80);
  QuicSocketAddress b(folly::IPAddress("10.0.0.2"), 80);
  QuicSocketAddressHash hasher;
  // Not strictly required, but extremely unlikely to collide
  EXPECT_NE(hasher(a), hasher(b));
}

TEST(QuicSocketAddressTest, HashUsableInUnorderedSet) {
  std::unordered_set<QuicSocketAddress, QuicSocketAddressHash> s;
  s.insert(QuicSocketAddress(folly::IPAddress("10.0.0.1"), 80));
  s.insert(QuicSocketAddress(folly::IPAddress("10.0.0.1"), 80)); // duplicate
  s.insert(QuicSocketAddress(folly::IPAddress("10.0.0.2"), 80));
  EXPECT_EQ(s.size(), 2u);
}

TEST(QuicSocketAddressTest, HashIgnoresPaddingBytes) {
  // Same as equality test: different sin_zero should produce same hash
  sockaddr_in sin1{};
  sin1.sin_family = AF_INET;
  sin1.sin_port = htons(80);
  inet_pton(AF_INET, "10.0.0.1", &sin1.sin_addr);

  sockaddr_in sin2{};
  sin2.sin_family = AF_INET;
  sin2.sin_port = htons(80);
  inet_pton(AF_INET, "10.0.0.1", &sin2.sin_addr);
  memset(sin2.sin_zero, 0xAB, sizeof(sin2.sin_zero));

  QuicSocketAddress a(reinterpret_cast<const sockaddr*>(&sin1), sizeof(sin1));
  QuicSocketAddress b(reinterpret_cast<const sockaddr*>(&sin2), sizeof(sin2));

  QuicSocketAddressHash hasher;
  EXPECT_EQ(hasher(a), hasher(b));
}

// =============================================================================
// std::hash specialization
// =============================================================================

TEST(QuicSocketAddressTest, StdHashUsableInUnorderedSet) {
  // Verify std::hash<QuicSocketAddress> works without explicit hash functor
  std::unordered_set<QuicSocketAddress> s;
  s.insert(QuicSocketAddress(folly::IPAddress("10.0.0.1"), 80));
  s.insert(QuicSocketAddress(folly::IPAddress("10.0.0.1"), 80)); // duplicate
  s.insert(QuicSocketAddress(folly::IPAddress("10.0.0.2"), 80));
  EXPECT_EQ(s.size(), 2u);
}

// =============================================================================
// trySetFromSockaddr — truncated len validation
// =============================================================================

TEST(QuicSocketAddressTest, TrySetFromSockaddrTruncatedIPv4) {
  sockaddr_in sin{};
  sin.sin_family = AF_INET;
  sin.sin_port = htons(80);
  inet_pton(AF_INET, "10.0.0.1", &sin.sin_addr);

  QuicSocketAddress addr;
  // Pass a len smaller than sizeof(sockaddr_in)
  bool ok = QuicSocketAddress::trySetFromSockaddr(
      addr, reinterpret_cast<const sockaddr*>(&sin), 4);
  EXPECT_FALSE(ok);
  EXPECT_FALSE(addr.isInitialized());
}

TEST(QuicSocketAddressTest, TrySetFromSockaddrTruncatedIPv6) {
  sockaddr_in6 sin6{};
  sin6.sin6_family = AF_INET6;
  sin6.sin6_port = htons(443);
  inet_pton(AF_INET6, "::1", &sin6.sin6_addr);

  QuicSocketAddress addr;
  // Pass a len smaller than sizeof(sockaddr_in6)
  bool ok = QuicSocketAddress::trySetFromSockaddr(
      addr, reinterpret_cast<const sockaddr*>(&sin6), 4);
  EXPECT_FALSE(ok);
  EXPECT_FALSE(addr.isInitialized());
}

// =============================================================================
// trySetFromSockaddr — short len must not read sa_family (ASAN OOB guard)
// =============================================================================

TEST(QuicSocketAddressTest, TrySetFromSockaddrZeroLenLeavesUnchanged) {
  // A tiny real buffer (1 byte) so that reading the 2-byte sa_family field with
  // len==0 would be an out-of-bounds read. The guard must reject before
  // dereferencing sa_family.
  alignas(sockaddr) char buf[1] = {};

  QuicSocketAddress addr(folly::IPAddress("1.2.3.4"), 1234);
  ASSERT_TRUE(addr.isInitialized());

  bool ok = QuicSocketAddress::trySetFromSockaddr(
      addr, reinterpret_cast<const sockaddr*>(buf), 0);
  EXPECT_FALSE(ok);
  // out must be left unchanged
  EXPECT_TRUE(addr.isInitialized());
  EXPECT_EQ(addr.getPort(), 1234);
  EXPECT_EQ(addr.getIPAddress(), folly::IPAddress("1.2.3.4"));
}

TEST(QuicSocketAddressTest, TrySetFromSockaddrLenOneLeavesUnchanged) {
  // A tiny real buffer of exactly len==1 so that reading the 2-byte sa_family
  // field would read past the buffer. The guard must reject because len does
  // not cover sa_family.
  alignas(sockaddr) char buf[1] = {};

  QuicSocketAddress addr(folly::IPAddress("5.6.7.8"), 9999);
  ASSERT_TRUE(addr.isInitialized());

  bool ok = QuicSocketAddress::trySetFromSockaddr(
      addr, reinterpret_cast<const sockaddr*>(buf), 1);
  EXPECT_FALSE(ok);
  // out must be left unchanged
  EXPECT_TRUE(addr.isInitialized());
  EXPECT_EQ(addr.getPort(), 9999);
  EXPECT_EQ(addr.getIPAddress(), folly::IPAddress("5.6.7.8"));
}

// =============================================================================
// setFromSockaddr — oversized len is capped
// =============================================================================

TEST(QuicSocketAddressTest, SetFromSockaddrOversizedLenIsCapped) {
  sockaddr_in sin{};
  sin.sin_family = AF_INET;
  sin.sin_port = htons(80);
  inet_pton(AF_INET, "10.0.0.1", &sin.sin_addr);

  QuicSocketAddress addr;
  // Pass a len much larger than the actual sockaddr_in source buffer. The
  // implementation must NOT read past the source buffer (no ASAN
  // memcpy-param-overlap / out-of-bounds read).
  constexpr socklen_t oversizedLen = sizeof(sockaddr_storage) + 1024;
  addr.setFromSockaddr(reinterpret_cast<const sockaddr*>(&sin), oversizedLen);

  // len_ should be clamped to the family-specific expected size, never larger
  // than the actual source buffer.
  EXPECT_EQ(addr.getActualSize(), static_cast<socklen_t>(sizeof(sockaddr_in)));

  // Address should still be usable
  EXPECT_TRUE(addr.isInitialized());
  EXPECT_EQ(addr.getFamily(), AF_INET);
  EXPECT_EQ(addr.getPort(), 80);
  EXPECT_EQ(addr.getIPAddress(), folly::IPAddress("10.0.0.1"));

  // operator== should not crash (this was the original bug)
  QuicSocketAddress other;
  other.setFromSockaddr(reinterpret_cast<const sockaddr*>(&sin), oversizedLen);
  EXPECT_EQ(addr, other);
}

TEST(QuicSocketAddressTest, SetFromSockaddrOversizedLenIsCappedV6) {
  sockaddr_in6 sin6{};
  sin6.sin6_family = AF_INET6;
  sin6.sin6_port = htons(443);
  inet_pton(AF_INET6, "2001:db8::1", &sin6.sin6_addr);

  QuicSocketAddress addr;
  constexpr socklen_t oversizedLen = sizeof(sockaddr_storage) + 1024;
  addr.setFromSockaddr(reinterpret_cast<const sockaddr*>(&sin6), oversizedLen);

  EXPECT_EQ(addr.getActualSize(), static_cast<socklen_t>(sizeof(sockaddr_in6)));
  EXPECT_TRUE(addr.isInitialized());
  EXPECT_EQ(addr.getFamily(), AF_INET6);
  EXPECT_EQ(addr.getPort(), 443);
  EXPECT_EQ(addr.getIPAddress(), folly::IPAddress("2001:db8::1"));
}

TEST(QuicSocketAddressTest, SetFromSockaddrNullAddrLeavesZeroed) {
  QuicSocketAddress addr(folly::IPAddress("1.2.3.4"), 1234);
  ASSERT_TRUE(addr.isInitialized());

  addr.setFromSockaddr(nullptr, sizeof(sockaddr_in));

  EXPECT_FALSE(addr.isInitialized());
  EXPECT_EQ(addr.getFamily(), AF_UNSPEC);
  EXPECT_EQ(addr.getActualSize(), 0u);
}

TEST(QuicSocketAddressTest, ConstructFromNullSockaddrIsUninitialized) {
  QuicSocketAddress addr(nullptr, sizeof(sockaddr_in));
  EXPECT_FALSE(addr.isInitialized());
  EXPECT_EQ(addr.getFamily(), AF_UNSPEC);
  EXPECT_EQ(addr.getActualSize(), 0u);
}

// =============================================================================
// makeLoopbackAddress
// =============================================================================

TEST(QuicAddressUtilTest, MakeLoopbackAddressV4) {
  auto addr = makeLoopbackAddress(AF_INET, 4433);
  EXPECT_TRUE(addr.isInitialized());
  EXPECT_EQ(addr.getFamily(), AF_INET);
  EXPECT_EQ(addr.getPort(), 4433);
  EXPECT_TRUE(addr.getIPAddress().isLoopback());
  EXPECT_EQ(addr.getIPAddress(), folly::IPAddress("127.0.0.1"));
}

TEST(QuicAddressUtilTest, MakeLoopbackAddressV6) {
  auto addr = makeLoopbackAddress(AF_INET6, 4433);
  EXPECT_TRUE(addr.isInitialized());
  EXPECT_EQ(addr.getFamily(), AF_INET6);
  EXPECT_EQ(addr.getPort(), 4433);
  EXPECT_TRUE(addr.getIPAddress().isLoopback());
  EXPECT_EQ(addr.getIPAddress(), folly::IPAddress("::1"));
}

// =============================================================================
// makeAnyAddress
// =============================================================================

TEST(QuicAddressUtilTest, MakeAnyAddressV4) {
  auto addr = makeAnyAddress(AF_INET, 8080);
  EXPECT_TRUE(addr.isInitialized());
  EXPECT_EQ(addr.getFamily(), AF_INET);
  EXPECT_EQ(addr.getPort(), 8080);
  EXPECT_EQ(addr.getIPAddress(), folly::IPAddress("0.0.0.0"));
}

TEST(QuicAddressUtilTest, MakeAnyAddressV6) {
  auto addr = makeAnyAddress(AF_INET6, 8080);
  EXPECT_TRUE(addr.isInitialized());
  EXPECT_EQ(addr.getFamily(), AF_INET6);
  EXPECT_EQ(addr.getPort(), 8080);
  EXPECT_EQ(addr.getIPAddress(), folly::IPAddress("::"));
}

// =============================================================================
// ostream operator<<
// =============================================================================

TEST(QuicSocketAddressTest, OstreamOperator) {
  QuicSocketAddress addr(folly::IPAddress("1.2.3.4"), 443);
  std::ostringstream os;
  os << addr;
  EXPECT_EQ(os.str(), addr.describe());
}
