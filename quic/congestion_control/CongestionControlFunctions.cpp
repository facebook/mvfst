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
    std::chrono::microseconds minimalInterval,
    std::chrono::microseconds rtt) {
  if (minimalInterval > rtt) {
    // We cannot really pace in this case.
    return std::make_pair(
        std::chrono::microseconds::zero(),
        conn.transportSettings.writeConnectionDataPacketsLimit);
  }
  uint64_t cwndInPackets = std::max(
      conn.transportSettings.minCwndInMss, cwnd / conn.udpSendPacketLen);
  // Each interval we want to send cwndInpackets / (rtt / minimalInverval)
  // number of packets.
  uint64_t burstPerInterval = std::min(
      conn.transportSettings.maxBurstPackets,
      std::max(
          conn.transportSettings.minCwndInMss,
          (uint64_t)std::ceil(
              (double)cwndInPackets * (double)minimalInterval.count() /
              (double)rtt.count())));
  auto interval =
      timeMax(minimalInterval, rtt * burstPerInterval / cwndInPackets);
  return std::make_pair(interval, burstPerInterval);
}
} // namespace quic
