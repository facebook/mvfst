/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <quic/congestion_control/CongestionControlFunctions.h>

#include <folly/portability/GTest.h>
#include <quic/QuicConstants.h>
#include <quic/state/StateData.h>

using namespace testing;

namespace quic {
namespace test {

class CongestionControlFunctionsTest : public Test {};

TEST_F(CongestionControlFunctionsTest, CalculatePacingRate) {
  QuicConnectionStateBase conn(QuicNodeType::Client);
  conn.udpSendPacketLen = 1;
  conn.transportSettings.minBurstPackets = 1;
  conn.transportSettings.pacingTickInterval = 10ms;
  std::chrono::microseconds rtt(1000 * 100);
  auto result =
      calculatePacingRate(conn, 50, conn.transportSettings.minCwndInMss, rtt);
  EXPECT_EQ(10ms, result.interval);
  EXPECT_EQ(5, result.burstSize);

  conn.transportSettings.pacingTickInterval = 1ms;
  auto result2 =
      calculatePacingRate(conn, 300, conn.transportSettings.minCwndInMss, rtt);
  EXPECT_EQ(1ms, result2.interval);
  EXPECT_EQ(3, result2.burstSize);
}

TEST_F(CongestionControlFunctionsTest, MinPacingRate) {
  QuicConnectionStateBase conn(QuicNodeType::Client);
  conn.udpSendPacketLen = 1;
  conn.transportSettings.pacingTickInterval = 1ms;
  auto result = calculatePacingRate(
      conn, 100, conn.transportSettings.minCwndInMss, 100ms);
  // 100 ms rtt, 1ms tick interval, 100 mss cwnd, 5 mss min burst -> 5 mss every
  // 5ms
  EXPECT_EQ(5ms, result.interval);
  EXPECT_EQ(conn.transportSettings.minBurstPackets, result.burstSize);
}

TEST_F(CongestionControlFunctionsTest, SmallCwnd) {
  QuicConnectionStateBase conn(QuicNodeType::Client);
  conn.udpSendPacketLen = 1;
  conn.transportSettings.minBurstPackets = 1;
  conn.transportSettings.pacingTickInterval = 1ms;
  auto result = calculatePacingRate(
      conn, 10, conn.transportSettings.minCwndInMss, 100000us);
  EXPECT_EQ(10ms, result.interval);
  EXPECT_EQ(1, result.burstSize);
}

TEST_F(CongestionControlFunctionsTest, RttSmallerThanInterval) {
  QuicConnectionStateBase conn(QuicNodeType::Client);
  conn.udpSendPacketLen = 1;
  conn.transportSettings.minBurstPackets = 1;
  conn.transportSettings.pacingTickInterval = 10ms;
  auto result =
      calculatePacingRate(conn, 10, conn.transportSettings.minCwndInMss, 1ms);
  EXPECT_EQ(std::chrono::milliseconds::zero(), result.interval);
  EXPECT_EQ(
      conn.transportSettings.writeConnectionDataPacketsLimit, result.burstSize);
}

} // namespace test
} // namespace quic
