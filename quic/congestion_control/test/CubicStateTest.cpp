/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <folly/portability/GTest.h>
#include <quic/common/test/TestUtils.h>
#include <quic/congestion_control/test/TestingCubic.h>

using namespace testing;

namespace quic {
namespace test {

class CubicStateTest : public Test {};

// ======= Hystart =======

TEST_F(CubicStateTest, HystartLoss) {
  QuicConnectionStateBase conn(QuicNodeType::Client);
  TestingCubic cubic(conn);
  auto packet = makeTestingWritePacket(0, 0, 0);
  CongestionController::LossEvent lossEvent(Clock::now());
  lossEvent.addLostPacket(packet);
  cubic.onPacketAckOrLoss(folly::none, lossEvent);
  EXPECT_EQ(CubicStates::FastRecovery, cubic.state());
}

TEST_F(CubicStateTest, HystartAck) {
  QuicConnectionStateBase conn(QuicNodeType::Client);
  TestingCubic cubic(conn);
  auto packet = makeTestingWritePacket(0, 0, 0);
  cubic.onPacketSent(packet);
  cubic.onPacketAckOrLoss(
      makeAck(0, 0, Clock::now(), packet.metadata.time), folly::none);
  EXPECT_EQ(CubicStates::Hystart, cubic.state());
}

// ======= Fast Recovery =======

TEST_F(CubicStateTest, FastRecoveryAck) {
  QuicConnectionStateBase conn(QuicNodeType::Client);
  TestingCubic cubic(conn);
  cubic.setStateForTest(CubicStates::FastRecovery);
  auto packet = makeTestingWritePacket(1, 1000, 1000);
  auto packet1 = makeTestingWritePacket(2, 1000, 2000);
  conn.lossState.largestSent = 2;
  cubic.onPacketSent(packet);
  cubic.onPacketSent(packet1);
  CongestionController::LossEvent loss;
  loss.addLostPacket(packet);
  cubic.onPacketAckOrLoss(folly::none, std::move(loss));
  cubic.onPacketAckOrLoss(
      makeAck(2, 1000, Clock::now(), packet1.metadata.time), folly::none);
  EXPECT_EQ(CubicStates::FastRecovery, cubic.state());
}

TEST_F(CubicStateTest, FastRecoveryAckToSteady) {
  QuicConnectionStateBase conn(QuicNodeType::Client);
  TestingCubic cubic(conn);
  auto packet = makeTestingWritePacket(0, 1, 1);
  // This moves the state machine to recovery, and mark endOfRecovery = 0
  cubic.onPacketSent(packet);
  CongestionController::LossEvent loss;
  loss.addLostPacket(packet);
  cubic.onPacketAckOrLoss(folly::none, std::move(loss));
  auto packet1 = makeTestingWritePacket(1, 1, 2);
  cubic.onPacketSent(packet1);
  cubic.onPacketAckOrLoss(
      makeAck(1, 1, Clock::now(), packet1.metadata.time), folly::none);
  EXPECT_EQ(CubicStates::Steady, cubic.state());
}

TEST_F(CubicStateTest, FastRecoveryLoss) {
  QuicConnectionStateBase conn(QuicNodeType::Client);
  TestingCubic cubic(conn);
  cubic.setStateForTest(CubicStates::FastRecovery);
  auto packet = makeTestingWritePacket(0, 0, 0);
  CongestionController::LossEvent lossEvent(Clock::now());
  lossEvent.addLostPacket(packet);
  cubic.onPacketAckOrLoss(folly::none, lossEvent);
  EXPECT_EQ(CubicStates::FastRecovery, cubic.state());
}

// ======= Steady =======

TEST_F(CubicStateTest, SteadyAck) {
  QuicConnectionStateBase conn(QuicNodeType::Client);
  TestingCubic cubic(conn);
  cubic.setStateForTest(CubicStates::Steady);
  auto packet = makeTestingWritePacket(0, 0, 0);
  cubic.onPacketSent(packet);
  cubic.onPacketAckOrLoss(
      makeAck(0, 0, Clock::now(), packet.metadata.time), folly::none);
  EXPECT_EQ(CubicStates::Steady, cubic.state());
}

TEST_F(CubicStateTest, SteadyLoss) {
  QuicConnectionStateBase conn(QuicNodeType::Client);
  TestingCubic cubic(conn);
  cubic.setStateForTest(CubicStates::Steady);
  auto packet = makeTestingWritePacket(0, 0, 0);
  CongestionController::LossEvent lossEvent(Clock::now());
  lossEvent.addLostPacket(packet);
  cubic.onPacketAckOrLoss(folly::none, lossEvent);
  EXPECT_EQ(CubicStates::FastRecovery, cubic.state());
}
} // namespace test
} // namespace quic
