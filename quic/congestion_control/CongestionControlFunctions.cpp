/*
 * Copyright (c) Facebook, Inc. and its affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 *
 */

#include <quic/congestion_control/CongestionControlFunctions.h>

#include <quic/QuicConstants.h>
#include <quic/common/TimeUtil.h>
#include <algorithm>

namespace quic {

uint64_t boundedCwnd(
    uint64_t cwndBytes,
    uint64_t packetLength,
    uint64_t maxCwndInMss,
    uint64_t minCwndInMss) noexcept {
  return std::max(
      std::min(cwndBytes, maxCwndInMss * packetLength),
      minCwndInMss * packetLength);
}

std::pair<std::chrono::microseconds, uint64_t> calculatePacingRate(
    const QuicConnectionStateBase& conn,
    uint64_t cwnd,
    uint64_t minCwndInMss,
    std::chrono::microseconds minimalInterval,
    std::chrono::microseconds rtt) {
  if (minimalInterval > rtt) {
    // We cannot really pace in this case.
    return std::make_pair(
        0us, conn.transportSettings.writeConnectionDataPacketsLimit);
  }
  uint64_t cwndInPackets = std::max(minCwndInMss, cwnd / conn.udpSendPacketLen);
  // Each interval we want to send cwndInpackets / (rtt / minimalInverval)
  // number of packets.
  uint64_t burstPerInterval = std::min(
      conn.transportSettings.maxBurstPackets,
      static_cast<uint64_t>(std::ceil(
          static_cast<double>(cwndInPackets) *
          static_cast<double>(minimalInterval.count()) /
          static_cast<double>(rtt.count()))));
  auto interval =
      timeMax(minimalInterval, rtt * burstPerInterval / cwndInPackets);
  return std::make_pair(interval, burstPerInterval);
}
} // namespace quic
