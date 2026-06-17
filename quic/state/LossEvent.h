/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#pragma once

#include <quic/QuicConstants.h>
#include <quic/common/Optional.h>
#include <quic/state/OutstandingPacket.h>

#include <algorithm>
#include <limits>
#include <vector>

namespace quic {

// Helper struct to group multiple lost packets into one event.
struct LossEvent {
  Optional<PacketNum> largestLostPacketNum;
  std::vector<PacketNum> lostPacketNumbers;
  uint64_t lostBytes{0};
  uint32_t lostPackets{0};
  const TimePoint lossTime;
  // The packet sent time of the lost packet with largest packet sent time in
  // this LossEvent.
  Optional<TimePoint> largestLostSentTime;
  // The packet sent time of the lost packet with smallest packet sent time in
  // this LossEvent.
  Optional<TimePoint> smallestLostSentTime;
  // Whether this LossEvent also indicates persistent congestion.
  bool persistentCongestion{false};

  explicit LossEvent(TimePoint time = Clock::now()) : lossTime(time) {}

  void addLostPacket(const OutstandingPacketWrapper& packet) {
    if (std::numeric_limits<uint64_t>::max() - lostBytes <
        packet.metadata.encodedSize) {
      throw QuicInternalException(
          "LossEvent: lostBytes overflow", LocalErrorCode::LOST_BYTES_OVERFLOW);
    }
    PacketNum packetNum = packet.packet.header.getPacketSequenceNum();
    largestLostPacketNum =
        std::max(packetNum, largestLostPacketNum.value_or(packetNum));
    lostPacketNumbers.push_back(packetNum);
    lostBytes += packet.metadata.encodedSize;
    lostPackets++;
    largestLostSentTime = std::max(
        packet.metadata.time,
        largestLostSentTime.value_or(packet.metadata.time));
    smallestLostSentTime = std::min(
        packet.metadata.time,
        smallestLostSentTime.value_or(packet.metadata.time));
  }
};

} // namespace quic
