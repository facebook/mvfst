/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#if defined(__linux__) && !defined(ANDROID)

#include <quic/xsk/packet_utils.h>

#include <folly/IPAddress.h>
#include <gtest/gtest.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <netinet/udp.h>
#include <array>
#include <cstring>

using namespace facebook::xdpsocket;

namespace {

constexpr size_t kEthLen = sizeof(ethhdr);
constexpr size_t kIp4Len = sizeof(iphdr);
constexpr size_t kIp6Len = sizeof(ipv6hdr);
constexpr size_t kUdpLen = sizeof(udphdr);

// Reads udphdr->check from a packet buffer, given whether it's v4 or v6.
uint16_t readUdpChecksum(const char* packet, bool isV6) {
  const auto* udp = reinterpret_cast<const udphdr*>(
      packet + kEthLen + (isV6 ? kIp6Len : kIp4Len));
  return udp->check;
}

// Sets udphdr->check from a packet buffer, given whether it's v4 or v6.
void setUdpChecksum(char* packet, bool isV6, uint16_t value) {
  auto* udp =
      reinterpret_cast<udphdr*>(packet + kEthLen + (isV6 ? kIp6Len : kIp4Len));
  udp->check = value;
}

// Ones-complement sum of consecutive uint16_t values starting at `data`,
// folded to 16 bits. Mirrors what `skb_checksum_help()` does over the L4
// header + payload (after the sender has stamped the partial pseudo-header
// sum into the checksum field).
uint16_t onesComplementSum(const char* data, size_t len) {
  uint64_t sum = 0;
  while (len >= 2) {
    sum += *reinterpret_cast<const uint16_t*>(data);
    data += 2;
    len -= 2;
  }
  if (len == 1) {
    sum += static_cast<uint8_t>(*data);
  }
  while (sum >> 16) {
    sum = (sum & 0xffff) + (sum >> 16);
  }
  return static_cast<uint16_t>(sum);
}

} // namespace

class PacketUtilsTest : public ::testing::Test {};

// Verifies that `writePseudoHeaderChecksum()` produces a value that, when
// combined with the data checksum from L4 header onwards (the operation
// HW or skb_checksum_help() performs), equals the standard UDP checksum
// produced by `writeChecksum()`.
TEST_F(PacketUtilsTest, PseudoHeaderRoundTripIPv4) {
  const auto src = folly::IPAddress("192.0.2.10");
  const auto dst = folly::IPAddress("198.51.100.20");
  const std::array<uint8_t, 32> payload = {
      0xde, 0xad, 0xbe, 0xef, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66,
      0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x01, 0x02,
      0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c};

  // Build a representative packet (Eth + IPv4 + UDP + payload). We only
  // populate the fields that participate in the checksum.
  std::array<char, kEthLen + kIp4Len + kUdpLen + 32> packet{};
  auto* udp = reinterpret_cast<udphdr*>(packet.data() + kEthLen + kIp4Len);
  udp->source = htons(12345);
  udp->dest = htons(54321);
  udp->len = htons(kUdpLen + payload.size());
  udp->check = 0;
  std::memcpy(
      packet.data() + kEthLen + kIp4Len + kUdpLen,
      payload.data(),
      payload.size());

  const uint16_t udpDatagramLen = kUdpLen + payload.size();

  // Reference: full software checksum.
  std::array<char, packet.size()> referencePacket = packet;
  writeChecksum(dst, src, referencePacket.data(), udpDatagramLen);
  const uint16_t expectedFinalChecksum =
      readUdpChecksum(referencePacket.data(), /*isV6=*/false);

  // Subject under test: write pseudo-header partial sum.
  writePseudoHeaderChecksum(dst, src, packet.data(), udpDatagramLen);

  // Simulate skb_checksum_help: sum from L4 start (which now contains the
  // partial sum at the checksum offset) over the rest of the packet, fold,
  // complement.
  const uint16_t bytesSummed = onesComplementSum(
      packet.data() + kEthLen + kIp4Len, kUdpLen + payload.size());
  auto reconstructed = static_cast<uint16_t>(~bytesSummed);

  EXPECT_EQ(expectedFinalChecksum, reconstructed);
}

TEST_F(PacketUtilsTest, PseudoHeaderRoundTripIPv6) {
  const auto src = folly::IPAddress("2001:db8::1");
  const auto dst = folly::IPAddress("2001:db8::2");
  const std::array<uint8_t, 24> payload = {
      0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80, 0x90, 0xa0, 0xb0, 0xc0,
      0xd0, 0xe0, 0xf0, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09};

  std::array<char, kEthLen + kIp6Len + kUdpLen + 24> packet{};
  auto* udp = reinterpret_cast<udphdr*>(packet.data() + kEthLen + kIp6Len);
  udp->source = htons(443);
  udp->dest = htons(33333);
  udp->len = htons(kUdpLen + payload.size());
  udp->check = 0;
  std::memcpy(
      packet.data() + kEthLen + kIp6Len + kUdpLen,
      payload.data(),
      payload.size());

  const uint16_t udpDatagramLen = kUdpLen + payload.size();

  std::array<char, packet.size()> referencePacket = packet;
  writeChecksum(dst, src, referencePacket.data(), udpDatagramLen);
  const uint16_t expectedFinalChecksum =
      readUdpChecksum(referencePacket.data(), /*isV6=*/true);

  writePseudoHeaderChecksum(dst, src, packet.data(), udpDatagramLen);

  const uint16_t bytesSummed = onesComplementSum(
      packet.data() + kEthLen + kIp6Len, kUdpLen + payload.size());
  auto reconstructed = static_cast<uint16_t>(~bytesSummed);

  EXPECT_EQ(expectedFinalChecksum, reconstructed);
}

// Verifies that the pseudo-header partial sum depends only on the
// pseudo-header inputs (src, dst, proto, len), not on the payload bytes.
TEST_F(PacketUtilsTest, PseudoHeaderIndependentOfPayload) {
  const auto src = folly::IPAddress("203.0.113.1");
  const auto dst = folly::IPAddress("203.0.113.2");
  const uint16_t udpDatagramLen = kUdpLen + 16;

  std::array<char, kEthLen + kIp4Len + kUdpLen + 16> packetA{};
  std::array<char, kEthLen + kIp4Len + kUdpLen + 16> packetB{};
  // Different payload bytes:
  std::memset(packetA.data() + kEthLen + kIp4Len + kUdpLen, 0xAA, 16);
  std::memset(packetB.data() + kEthLen + kIp4Len + kUdpLen, 0x55, 16);

  writePseudoHeaderChecksum(dst, src, packetA.data(), udpDatagramLen);
  writePseudoHeaderChecksum(dst, src, packetB.data(), udpDatagramLen);

  EXPECT_EQ(
      readUdpChecksum(packetA.data(), /*isV6=*/false),
      readUdpChecksum(packetB.data(), /*isV6=*/false));
}

// Verifies that changing src/dst/length produces different partial sums,
// confirming the function actually consumes those inputs.
TEST_F(PacketUtilsTest, PseudoHeaderSensitiveToInputs) {
  const auto src = folly::IPAddress("192.0.2.1");
  const auto dst = folly::IPAddress("192.0.2.2");
  const auto otherDst = folly::IPAddress("192.0.2.3");

  std::array<char, kEthLen + kIp4Len + kUdpLen> packetA{};
  std::array<char, kEthLen + kIp4Len + kUdpLen> packetB{};

  writePseudoHeaderChecksum(dst, src, packetA.data(), kUdpLen);
  writePseudoHeaderChecksum(otherDst, src, packetB.data(), kUdpLen);

  EXPECT_NE(
      readUdpChecksum(packetA.data(), /*isV6=*/false),
      readUdpChecksum(packetB.data(), /*isV6=*/false));

  // Different length should also change the partial sum.
  std::array<char, kEthLen + kIp4Len + kUdpLen> packetC{};
  writePseudoHeaderChecksum(dst, src, packetC.data(), kUdpLen + 100);
  EXPECT_NE(
      readUdpChecksum(packetA.data(), /*isV6=*/false),
      readUdpChecksum(packetC.data(), /*isV6=*/false));
}

// Sanity: writePseudoHeaderChecksum touches only the UDP checksum field, not
// other parts of the packet.
TEST_F(PacketUtilsTest, PseudoHeaderOnlyTouchesChecksumField) {
  const auto src = folly::IPAddress("192.0.2.1");
  const auto dst = folly::IPAddress("192.0.2.2");

  std::array<char, kEthLen + kIp4Len + kUdpLen + 16> packet{};
  for (size_t i = 0; i < packet.size(); i++) {
    packet[i] = static_cast<char>(i ^ 0x5a);
  }
  // Zero out checksum field so the write is meaningful.
  setUdpChecksum(packet.data(), /*isV6=*/false, 0);

  std::array<char, packet.size()> before = packet;
  writePseudoHeaderChecksum(dst, src, packet.data(), kUdpLen + 16);

  // Compare byte-by-byte except the 2 bytes of the checksum field.
  const size_t csumOffset = kEthLen + kIp4Len + offsetof(struct udphdr, check);
  for (size_t i = 0; i < packet.size(); i++) {
    if (i == csumOffset || i == csumOffset + 1) {
      continue;
    }
    EXPECT_EQ(before[i], packet[i]) << "byte " << i << " was modified";
  }
}

#endif
