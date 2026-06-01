/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <quic/state/ClonedPacketIdentifier.h>

#include <functional>
#include <type_traits>

namespace quic {

ClonedPacketIdentifier::ClonedPacketIdentifier(
    PacketNumberSpace packetNumberSpaceIn,
    PacketNum packetNumberIn)
    : packetNumber(packetNumberIn), packetNumberSpace(packetNumberSpaceIn) {}

bool operator==(
    const ClonedPacketIdentifier& lhs,
    const ClonedPacketIdentifier& rhs) {
  return static_cast<std::underlying_type_t<PacketNumberSpace>>(
             lhs.packetNumberSpace) ==
      static_cast<std::underlying_type_t<PacketNumberSpace>>(
             rhs.packetNumberSpace) &&
      lhs.packetNumber == rhs.packetNumber;
}

size_t ClonedPacketIdentifierHash::operator()(
    const ClonedPacketIdentifier& clonedPacketIdentifier) const noexcept {
  // Order-dependent hash combine (golden-ratio mix)
  size_t seed = std::hash<std::underlying_type_t<PacketNumberSpace>>{}(
      static_cast<std::underlying_type_t<PacketNumberSpace>>(
          clonedPacketIdentifier.packetNumberSpace));
  seed ^= std::hash<PacketNum>{}(clonedPacketIdentifier.packetNumber) +
      0x9e3779b97f4a7c15ULL + (seed << 6) + (seed >> 2);
  return seed;
}
} // namespace quic
