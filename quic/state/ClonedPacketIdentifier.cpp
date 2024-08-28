/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <quic/state/ClonedPacketIdentifier.h>

#include <folly/hash/Hash.h>
#include <functional>

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
  return folly::hash::hash_combine(
      static_cast<std::underlying_type_t<PacketNumberSpace>>(
          clonedPacketIdentifier.packetNumberSpace),
      clonedPacketIdentifier.packetNumber);
}
} // namespace quic
