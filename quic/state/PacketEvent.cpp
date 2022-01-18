/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <quic/state/PacketEvent.h>

#include <folly/hash/Hash.h>
#include <functional>

namespace quic {

PacketEvent::PacketEvent(
    PacketNumberSpace packetNumberSpaceIn,
    PacketNum packetNumberIn)
    : packetNumberSpace(packetNumberSpaceIn), packetNumber(packetNumberIn) {}

bool operator==(const PacketEvent& lhs, const PacketEvent& rhs) {
  return static_cast<std::underlying_type_t<PacketNumberSpace>>(
             lhs.packetNumberSpace) ==
      static_cast<std::underlying_type_t<PacketNumberSpace>>(
             rhs.packetNumberSpace) &&
      lhs.packetNumber == rhs.packetNumber;
}

size_t PacketEventHash::operator()(
    const PacketEvent& packetEvent) const noexcept {
  return folly::hash::hash_combine(
      static_cast<std::underlying_type_t<PacketNumberSpace>>(
          packetEvent.packetNumberSpace),
      packetEvent.packetNumber);
}
} // namespace quic
