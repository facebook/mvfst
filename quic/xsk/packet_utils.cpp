/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#if defined(__linux__)

#include <folly/Benchmark.h>
#include <netinet/udp.h>
#include <quic/xsk/packet_utils.h>

namespace facebook::xdpsocket {

void writeMacHeader(const ethhdr* ethHdr, char*& buffer) {
  folly::doNotOptimizeAway(memcpy(buffer, ethHdr, sizeof(ethhdr)));
  buffer += sizeof(ethhdr);
}

uint16_t calculateIPv4Checksum(
    const unsigned char* header,
    size_t headerLength) {
  unsigned long sum = 0;

  // Sum 16-bit words
  for (size_t i = 0; i < headerLength; i += 2) {
    uint16_t word = (header[i] << 8) + header[i + 1];
    sum += word;
  }

  // Add carry if any
  while (sum >> 16) {
    sum = (sum & 0xFFFF) + (sum >> 16);
  }

  // Take the one's complement of the sum
  return static_cast<uint16_t>(~sum & 0xFFFF);
}

void writeIpHeader(
    const folly::IPAddress& dstAddr,
    const folly::IPAddress& srcAddr,
    const iphdr* ipHdr,
    uint16_t payloadLen,
    char*& buffer) {
  payloadLen += sizeof(iphdr);
  iphdr ipHdrCopy = *ipHdr;

  ipHdrCopy.tot_len = htons(payloadLen);
  folly::doNotOptimizeAway(memcpy(&ipHdrCopy.daddr, dstAddr.bytes(), 4));
  folly::doNotOptimizeAway(memcpy(&ipHdrCopy.saddr, srcAddr.bytes(), 4));

  ipHdrCopy.check =
      htons(calculateIPv4Checksum((unsigned char*)&ipHdrCopy, 20));
  if (ipHdrCopy.check == 0) {
    ipHdrCopy.check = 0xFFFF;
  }
  folly::doNotOptimizeAway(memcpy(buffer, &ipHdrCopy, sizeof(iphdr)));
  buffer += sizeof(iphdr);
}

void writeIpHeader(
    const folly::IPAddress& dstAddr,
    const folly::IPAddress& srcAddr,
    const ipv6hdr* ipv6Hdr,
    uint16_t payloadLen,
    char*& buffer) {
  ipv6hdr ipv6hdrCopy = *ipv6Hdr;

  ipv6hdrCopy.payload_len = htons(payloadLen);
  folly::doNotOptimizeAway(
      memcpy(ipv6hdrCopy.daddr.s6_addr32, dstAddr.bytes(), 16));
  folly::doNotOptimizeAway(
      memcpy(ipv6hdrCopy.saddr.s6_addr32, srcAddr.bytes(), 16));

  folly::doNotOptimizeAway(memcpy(buffer, &ipv6hdrCopy, sizeof(ipv6hdr)));
  buffer += sizeof(ipv6hdr);
}

void writeUdpHeader(
    uint16_t srcPort,
    uint16_t dstPort,
    uint16_t csum,
    uint16_t len,
    char*& buffer) {
  udphdr udpHeader = {};
  udpHeader.source = htons(srcPort);
  udpHeader.dest = htons(dstPort);
  udpHeader.len = htons(len);
  udpHeader.check = csum;

  folly::doNotOptimizeAway(memcpy(buffer, &udpHeader, sizeof(udphdr)));
  buffer += sizeof(udphdr);
}

void writeUdpPayload(const char* data, uint32_t len, char*& buffer) {
  folly::doNotOptimizeAway(memcpy(buffer, data, len));
  buffer += len;
}

void writeChecksum(
    const folly::IPAddress& dstAddr,
    const folly::IPAddress& srcAddr,
    char* packet,
    uint16_t len) {
  bool isV6 = dstAddr.isV6();

  // This is going to point to the beginning of the UDP header
  auto* payload =
      (uint32_t*)(packet + (isV6 ? sizeof(ipv6hdr) : sizeof(iphdr)) +
                  sizeof(ethhdr));

  uint64_t sum = (len + 17) << 8;

  // Checksum of source ip and dst ip
  const auto* srcIPPtr = (const uint16_t*)(srcAddr.bytes());
  const auto* dstIPPtr = (const uint16_t*)(dstAddr.bytes());

  int termination = srcAddr.isV6() ? 8 : 2;
  for (int i = 0; i < termination; i++) {
    sum += *srcIPPtr++;
    sum += *dstIPPtr++;
  }

  // Checksum of payload
  while (len >= 4) {
    sum += *payload++;
    len -= 4;
  }

  if (len >= 2) {
    sum = sum + *((uint16_t*)payload);
    len -= 2;
    if (len == 1) {
      sum = sum + *(((uint8_t*)payload) + 2);
      len--;
    }
  } else if (len == 1) {
    sum = sum + *((uint8_t*)payload);
    len--;
  }

  // Add the carry bits to the lower 16 bits
  while (sum >> 16) {
    sum = (sum & 0xffff) + (sum >> 16);
  }

  // Take the one's complement of the result
  auto checksum = (uint16_t)~sum;

  if (checksum == 0) {
    checksum = 0xFFFF;
  }

  auto* upd_hdr = (udphdr*)(packet + (isV6 ? sizeof(ipv6hdr) : sizeof(iphdr)) +
                            sizeof(ethhdr));
  upd_hdr->check = checksum;
}

} // namespace facebook::xdpsocket

#endif
