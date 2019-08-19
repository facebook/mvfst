/*
 * Copyright (c) Facebook, Inc. and its affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 *
 */

#include <quic/congestion_control/CongestionControlFunctions.h>

#include <folly/portability/GTest.h>
#include <quic/QuicConstants.h>
#include <quic/state/StateData.h>

using namespace quic;
using namespace testing;

namespace quic {
namespace test {

class CongestionControlFunctionsTest : public Test {};

TEST_F(CongestionControlFunctionsTest, CalculatePacingRate) {
  QuicConnectionStateBase conn(QuicNodeType::Client);
  conn.udpSendPacketLen = 1;
  conn.transportSettings.pacingTimerTickInterval = 10ms;
  std::chrono::microseconds rtt(1000 * 100);
  auto result =
      calculatePacingRate(conn, 50, conn.transportSettings.minCwndInMss, rtt);
  EXPECT_EQ(10ms, result.first);
  EXPECT_EQ(5, result.second);

  conn.transportSettings.pacingTimerTickInterval = 1ms;
  auto result2 =
      calculatePacingRate(conn, 300, conn.transportSettings.minCwndInMss, rtt);
  EXPECT_EQ(1ms, result2.first);
  EXPECT_EQ(3, result2.second);
}

TEST_F(CongestionControlFunctionsTest, MinPacingRate) {
  QuicConnectionStateBase conn(QuicNodeType::Client);
  conn.udpSendPacketLen = 1;
  conn.transportSettings.pacingTimerTickInterval = 1ms;
  auto result = calculatePacingRate(
      conn, 100, conn.transportSettings.minCwndInMss, 100000us);
  EXPECT_EQ(1ms, result.first);
  EXPECT_EQ(1, result.second);
}

TEST_F(CongestionControlFunctionsTest, SmallCwnd) {
  QuicConnectionStateBase conn(QuicNodeType::Client);
  conn.udpSendPacketLen = 1;
  conn.transportSettings.pacingTimerTickInterval = 1ms;
  auto result = calculatePacingRate(
      conn, 10, conn.transportSettings.minCwndInMss, 100000us);
  EXPECT_EQ(10ms, result.first);
  EXPECT_EQ(1, result.second);
}

TEST_F(CongestionControlFunctionsTest, RttSmallerThanInterval) {
  QuicConnectionStateBase conn(QuicNodeType::Client);
  conn.udpSendPacketLen = 1;
  conn.transportSettings.pacingTimerTickInterval = 10ms;
  auto result =
      calculatePacingRate(conn, 10, conn.transportSettings.minCwndInMss, 1ms);
  EXPECT_EQ(std::chrono::milliseconds::zero(), result.first);
  EXPECT_EQ(
      conn.transportSettings.writeConnectionDataPacketsLimit, result.second);
}


} // namespace test
} // namespace quic
