/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#pragma once

#include <quic/codec/Types.h>

namespace quic {

/**
 * There are cases that we may clone an outstanding packet and resend it as is.
 * When that happens, we assign a PacketEvent to both the original and cloned
 * packet if no PacketEvent is already associated with the original packet. If
 * the original packet already has a PacketEvent, we copy that value into the
 * cloned packet.
 * A connection maintains a set of PacketEvents. When a packet with a
 * PacketEvent is acked or lost, we search the set. If the PacketEvent is
 * present in the set, we process the ack or loss event (e.g. update RTT, notify
 * CongestionController, and detect loss with this packet) as well as frames in
 * the packet. Then we remove the PacketEvent from the set. If the PacketEvent
 * is absent in the set, we consider all frames contained in the packet are
 * already processed. We will still handle the ack or loss event and update the
 * connection. But no frame will be processed.
 *
 * TODO: Current PacketNum is an alias to uint64_t. We should just make
 * PacketNum be a type with both the space and the number, then PacketEvent will
 * just be an alias to this type.
 */
struct PacketEvent {
  PacketNumberSpace packetNumberSpace;
  PacketNum packetNumber;

  PacketEvent() = delete;
  PacketEvent(PacketNumberSpace packetNumberSpaceIn, PacketNum packetNumberIn);
};

// To work with F14 Set:
bool operator==(const PacketEvent& lhs, const PacketEvent& rhs);

struct PacketEventHash {
  size_t operator()(const PacketEvent& packetEvent) const noexcept;
};
} // namespace quic
