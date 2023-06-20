/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
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

PacingRate calculatePacingRate(
    const QuicConnectionStateBase& conn,
    uint64_t cwnd,
    uint64_t minCwndInMss,
    std::chrono::microseconds rtt) {
  if (conn.transportSettings.pacingTickInterval > rtt) {
    // We cannot really pace in this case.
    return PacingRate::Builder()
        .setInterval(0us)
        .setBurstSize(conn.transportSettings.writeConnectionDataPacketsLimit)
        .build();
  }
  uint64_t cwndInPackets = std::max(minCwndInMss, cwnd / conn.udpSendPacketLen);
  // Each interval we want to send cwndInpackets / (rtt / minimalInverval)
  // number of packets.
  uint64_t burstPerInterval = std::max(
      conn.transportSettings.minBurstPackets,
      static_cast<uint64_t>(std::ceil(
          static_cast<double>(cwndInPackets) *
          static_cast<double>(
              conn.transportSettings.pacingTickInterval.count()) /
          static_cast<double>(rtt.count()))));
  auto interval = timeMax(
      conn.transportSettings.pacingTickInterval,
      rtt * burstPerInterval / cwndInPackets);
  return PacingRate::Builder()
      .setInterval(interval)
      .setBurstSize(burstPerInterval)
      .build();
}
} // namespace quic
