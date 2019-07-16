/*
 * Copyright (c) Facebook, Inc. and its affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 *
 */

#include <folly/portability/GTest.h>
#include <quic/common/test/TestUtils.h>
#include <quic/congestion_control/test/TestingCubic.h>

using namespace quic;
using namespace quic::test;
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
      makeAck(0, 0, Clock::now(), packet.time), folly::none);
  EXPECT_EQ(CubicStates::Hystart, cubic.state());
}

TEST_F(CubicStateTest, HystartPace) {
  QuicConnectionStateBase conn(QuicNodeType::Client);
  auto qLogger = std::make_shared<FileQLogger>();
  conn.qLogger = qLogger;
  conn.transportSettings.pacingEnabled = true;
  conn.lossState.srtt = 2000000us;
  TestingCubic cubic(conn);
  cubic.setMinimalPacingInterval(10ms);
  EXPECT_EQ(CubicStates::Hystart, cubic.state());
  EXPECT_TRUE(cubic.canBePaced());

  std::vector<int> indices =
      getQLogEventIndices(QLogEventType::PacingMetricUpdate, qLogger);
  EXPECT_EQ(indices.size(), 1);
  auto tmp = std::move(qLogger->logs[indices[0]]);
  auto event = dynamic_cast<QLogPacingMetricUpdateEvent*>(tmp.get());
  EXPECT_EQ(event->pacingBurstSize, 1);
  EXPECT_EQ(event->pacingInterval, 10ms);
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
      makeAck(2, 1000, Clock::now(), packet1.time), folly::none);
  EXPECT_EQ(CubicStates::FastRecovery, cubic.state());
}

TEST_F(CubicStateTest, FastRecoveryAckToSteady) {
  QuicConnectionStateBase conn(QuicNodeType::Client);
  TestingCubic cubic(
      conn, 10000 /* initCwnd */, 10000 /* minCwnd */, 1000 /* ssthresh */);
  auto packet = makeTestingWritePacket(0, 1, 1);
  // This moves the state machine to recovery, and mark endOfRecovery = 0
  cubic.onPacketSent(packet);
  CongestionController::LossEvent loss;
  loss.addLostPacket(packet);
  cubic.onPacketAckOrLoss(folly::none, std::move(loss));
  auto packet1 = makeTestingWritePacket(1, 1, 2);
  cubic.onPacketSent(packet1);
  cubic.onPacketAckOrLoss(
      makeAck(1, 1, Clock::now(), packet1.time), folly::none);
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

TEST_F(CubicStateTest, RecoveryNoPace) {
  QuicConnectionStateBase conn(QuicNodeType::Client);
  conn.transportSettings.pacingEnabled = true;
  conn.lossState.srtt = 2000000us;
  TestingCubic cubic(conn);
  cubic.setStateForTest(CubicStates::FastRecovery);
  EXPECT_EQ(CubicStates::FastRecovery, cubic.state());
  EXPECT_FALSE(cubic.canBePaced());
}

// ======= Steady =======

TEST_F(CubicStateTest, SteadyAck) {
  QuicConnectionStateBase conn(QuicNodeType::Client);
  TestingCubic cubic(conn);
  cubic.setStateForTest(CubicStates::Steady);
  auto packet = makeTestingWritePacket(0, 0, 0);
  cubic.onPacketSent(packet);
  cubic.onPacketAckOrLoss(
      makeAck(0, 0, Clock::now(), packet.time), folly::none);
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

TEST_F(CubicStateTest, SteadyCanPace) {
  QuicConnectionStateBase conn(QuicNodeType::Client);
  auto qLogger = std::make_shared<FileQLogger>();
  conn.qLogger = qLogger;
  conn.transportSettings.pacingEnabled = true;
  conn.lossState.srtt = 2000000us;
  TestingCubic cubic(conn);
  cubic.setStateForTest(CubicStates::Steady);
  EXPECT_FALSE(cubic.canBePaced());
  cubic.setMinimalPacingInterval(15ms);
  EXPECT_TRUE(cubic.canBePaced());
  conn.lossState.srtt = 1ms;
  EXPECT_FALSE(cubic.canBePaced());
  std::vector<int> indices =
      getQLogEventIndices(QLogEventType::PacingMetricUpdate, qLogger);
  EXPECT_EQ(indices.size(), 1);
  auto tmp = std::move(qLogger->logs[indices[0]]);
  auto event = dynamic_cast<QLogPacingMetricUpdateEvent*>(tmp.get());
  EXPECT_EQ(event->pacingBurstSize, 1);
  EXPECT_EQ(event->pacingInterval, 15ms);
}

} // namespace test
} // namespace quic
