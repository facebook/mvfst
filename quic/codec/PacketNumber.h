/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#pragma once

#include <cstddef>
#include <cstdint>

namespace quic {

using PacketNum = uint64_t;

/**
 * Returns a decoded packet number by using the expectedNextPacketNum to
 * search for the most probable packet number that could satisfy that condition.
 */
PacketNum decodePacketNumber(
    uint64_t encodedPacketNum,
    size_t packetNumBytes,
    PacketNum expectedNextPacketNum);

struct PacketNumEncodingResult {
  PacketNum result;
  // This is packet number length in bytes
  size_t length;

  PacketNumEncodingResult(PacketNum resultIn, size_t lengthIn);
};

PacketNumEncodingResult encodePacketNumber(
    PacketNum packetNum,
    PacketNum largestAckedPacketNum);

} // namespace quic
