/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#pragma once

#include <quic/codec/Types.h>
#include <string>

namespace quic {
struct D6DProbePacket {
  D6DProbePacket() = delete;

  explicit D6DProbePacket(PacketNum packetNumIn, uint32_t packetSizeIn)
      : packetNum(packetNumIn), packetSize(packetSizeIn) {}

  // Packet num
  PacketNum packetNum;

  // Udp packet payload size
  uint32_t packetSize;
};

// States of d6d state machine, see
// https://tools.ietf.org/id/draft-ietf-tsvwg-datagram-plpmtud-21.html#name-state-machine
enum class D6DMachineState : uint8_t {
  // Connection is not established yet
  DISABLED = 0,
  // Probe using base pmtu
  BASE = 1,
  // Incrementally probe using larger pmtu
  SEARCHING = 2,
  // Sleep for raise timeout before going to SEARCHING
  SEARCH_COMPLETE = 3,
  // Effective pmtu is less than base pmtu, continue probing with smaller
  // packet
  ERROR = 4
};

/**
 * Two simple probe size raiser. Only server makes use of this value.
 * ConstantSize: raise pmtu at constant step size
 * BinarySearch: raise pmtu using binary search
 */
enum class ProbeSizeRaiserType : uint8_t { ConstantStep = 0, BinarySearch = 1 };

std::string toString(const D6DMachineState state);
std::string toString(const ProbeSizeRaiserType type);

} // namespace quic
