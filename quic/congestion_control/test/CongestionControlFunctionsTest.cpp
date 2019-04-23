/*
 * Copyright (c) Facebook, Inc. and its affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 *
 */

// Copyright 2004-present Facebook.  All rights reserved.

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
  std::chrono::microseconds rtt(1000 * 100);
  auto result =
      calculatePacingRate(conn, 50, std::chrono::milliseconds(10), rtt);
  EXPECT_EQ(std::chrono::milliseconds(10), result.first);
  EXPECT_EQ(5, result.second);

  auto result2 =
      calculatePacingRate(conn, 300, std::chrono::milliseconds(1), rtt);
  EXPECT_EQ(std::chrono::milliseconds(1), result2.first);
  EXPECT_EQ(3, result2.second);
}

TEST_F(CongestionControlFunctionsTest, MinPacingRate) {
  QuicConnectionStateBase conn(QuicNodeType::Client);
  conn.udpSendPacketLen = 1;
  auto result = calculatePacingRate(
      conn,
      100,
      std::chrono::milliseconds(1),
      std::chrono::microseconds(1000 * 100));
  EXPECT_EQ(std::chrono::milliseconds(2), result.first);
  EXPECT_EQ(conn.transportSettings.minCwndInMss, result.second);
}

TEST_F(CongestionControlFunctionsTest, SmallCwnd) {
  QuicConnectionStateBase conn(QuicNodeType::Client);
  conn.udpSendPacketLen = 1;
  auto result = calculatePacingRate(
      conn,
      10,
      std::chrono::milliseconds(1),
      std::chrono::microseconds(1000 * 100));
  EXPECT_EQ(std::chrono::milliseconds(20), result.first);
  EXPECT_EQ(conn.transportSettings.minCwndInMss, result.second);
}

TEST_F(CongestionControlFunctionsTest, RttSmallerThanInterval) {
  QuicConnectionStateBase conn(QuicNodeType::Client);
  conn.udpSendPacketLen = 1;
  auto result = calculatePacingRate(
      conn, 10, std::chrono::milliseconds(10), std::chrono::milliseconds(1));
  EXPECT_EQ(std::chrono::milliseconds::zero(), result.first);
  EXPECT_EQ(
      conn.transportSettings.writeConnectionDataPacketsLimit, result.second);
}


} // namespace test
} // namespace quic
