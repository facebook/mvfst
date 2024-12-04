/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#pragma once

#if defined(__linux__) && !defined(ANDROID)

#include <folly/IPAddress.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <cstring>

namespace facebook::xdpsocket {

void writeMacHeader(const ethhdr* ethHdr, char*& buffer);

void writeIpHeader(
    const folly::IPAddress& dstAddr,
    const folly::IPAddress& srcAddr,
    const iphdr* ipHdr,
    uint16_t payloadLen,
    char*& buffer);

void writeIpHeader(
    const folly::IPAddress& dstAddr,
    const folly::IPAddress& srcAddr,
    const ipv6hdr* ipv6Hdr,
    uint16_t payloadLen,
    char*& buffer);

void writeUdpHeader(
    uint16_t srcPort,
    uint16_t dstPort,
    uint16_t csum,
    uint16_t len,
    char*& buffer);

void writeUdpPayload(const char* data, uint32_t len, char*& buffer);

// The len should be the len in the udp header, not the payload len.
void writeChecksum(
    const folly::IPAddress& dstAddr,
    const folly::IPAddress& srcAddr,
    char* packet,
    uint16_t len);

} // namespace facebook::xdpsocket

#endif
