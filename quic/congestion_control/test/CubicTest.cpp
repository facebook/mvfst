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

class CubicTest : public Test {};

TEST_F(CubicTest, SentReduceWritable) {
  QuicConnectionStateBase conn(QuicNodeType::Client);
  Cubic cubic(conn);
  auto initCwnd = cubic.getWritableBytes();
  cubic.onPacketSent(makeTestingWritePacket(0, 100, 100));
  EXPECT_EQ(initCwnd - 100, cubic.getWritableBytes());
}

TEST_F(CubicTest, AckIncreaseWritable) {
  QuicConnectionStateBase conn(QuicNodeType::Client);
  Cubic cubic(conn);
  auto initCwnd = cubic.getWritableBytes();
  cubic.onPacketSent(makeTestingWritePacket(0, 100, 100));
  EXPECT_EQ(initCwnd - 100, cubic.getWritableBytes());

  // Acking 50, now inflight become 50. Cwnd is init + 50
  cubic.onPacketAckOrLoss(makeAck(0, 50, Clock::now()), folly::none);
  EXPECT_EQ(initCwnd, cubic.getWritableBytes());
}

TEST_F(CubicTest, PersistentCongestion) {
  QuicConnectionStateBase conn(QuicNodeType::Client);
  Cubic cubic(conn, std::numeric_limits<uint64_t>::max(), false);
  auto initCwnd = cubic.getWritableBytes();
  auto packet = makeTestingWritePacket(0, 1000, 1000);
  // Sent and lost, inflight = 0
  cubic.onPacketSent(packet);
  CongestionController::LossEvent loss;
  loss.addLostPacket(packet);
  loss.persistentCongestion = true;
  cubic.onPacketAckOrLoss(folly::none, std::move(loss));
  EXPECT_EQ(CubicStates::Hystart, cubic.state());
  // Cwnd should be dropped to minCwnd:
  EXPECT_EQ(
      conn.transportSettings.minCwndInMss * conn.udpSendPacketLen,
      cubic.getWritableBytes());

  // Verify ssthresh is at initCwnd / 2
  auto packet2 = makeTestingWritePacket(1, initCwnd / 2, initCwnd / 2 + 1000);
  cubic.onPacketSent(packet2);
  cubic.onPacketAckOrLoss(makeAck(1, initCwnd / 2, Clock::now()), folly::none);
  EXPECT_EQ(CubicStates::Steady, cubic.state());

  // Verify both lastMaxCwndBytes and lastReductionTime are also reset in
  // onPersistentCongestion. When they are both verified, the first ACK will
  // make both timeToOrigin and timeElapsed to be 0 in Ack handling in Steady
  // handler:
  auto currentCwnd = cubic.getWritableBytes(); // since nothing inflight
  auto packet3 = makeTestingWritePacket(2, 3000, initCwnd / 2 + 1000 + 3000);
  cubic.onPacketSent(packet3);
  cubic.onPacketAckOrLoss(makeAck(2, 3000, Clock::now()), folly::none);
  EXPECT_EQ(currentCwnd, cubic.getWritableBytes());
}

TEST_F(CubicTest, CwndIncreaseAfterReduction) {
  QuicConnectionStateBase conn(QuicNodeType::Client);
  conn.udpSendPacketLen = 200;
  // initCwnd > initSsthresh: an ack will immediately make the state machine
  // transit to Steady state:
  Cubic cubic(conn, 1000);
  cubic.setConnectionEmulation(1); // Easier to argue reduction this way

  // Send one and get acked, this moves the state machine to steady
  auto packet0 = makeTestingWritePacket(0, 1000, 1000);
  conn.lossState.largestSent = 0;
  cubic.onPacketSent(packet0);
  cubic.onPacketAckOrLoss(makeAck(0, 1000, Clock::now()), folly::none);
  // Cwnd increased by 1000, inflight = 0:
  EXPECT_EQ(3000, cubic.getWritableBytes());
  EXPECT_EQ(CubicStates::Steady, cubic.state());

  auto packet1 = makeTestingWritePacket(1, 1000, 2000);
  auto packet2 = makeTestingWritePacket(2, 1000, 3000);
  auto packet3 = makeTestingWritePacket(3, 1000, 4000);
  // This will set endOfRecovery to 3 when loss happens:
  conn.lossState.largestSent = 3;
  cubic.onPacketSent(packet1);
  cubic.onPacketSent(packet2);
  cubic.onPacketSent(packet3);
  // Cwnd = 3000, inflight = 3000:
  EXPECT_EQ(0, cubic.getWritableBytes());

  cubic.onPacketAckOrLoss(makeAck(1, 1000, Clock::now()), folly::none);
  // Cwnd >= 3000, inflight = 2000:
  EXPECT_GE(cubic.getWritableBytes(), 1000);
  CongestionController::LossEvent loss;
  loss.addLostPacket(packet2);
  cubic.onPacketAckOrLoss(folly::none, std::move(loss));
  // Cwnd >= 2400, inflight = 1000:
  EXPECT_GE(cubic.getWritableBytes(), 1400);
  // This won't bring state machine back to Steady since endOfRecovery = 3
  cubic.onPacketAckOrLoss(makeAck(3, 1000, Clock::now()), folly::none);
  // Cwnd no change, inflight = 0:
  EXPECT_GE(cubic.getWritableBytes(), 2400);
  EXPECT_EQ(CubicStates::FastRecovery, cubic.state());

  auto packet4 = makeTestingWritePacket(4, 1000, 5000);
  conn.lossState.largestSent = 4;
  cubic.onPacketSent(packet4);
  // This will bring state machine back to steady
  cubic.onPacketAckOrLoss(makeAck(4, 1000, Clock::now()), folly::none);
  EXPECT_GE(cubic.getWritableBytes(), 2400);
  EXPECT_EQ(CubicStates::Steady, cubic.state());
}

TEST_F(CubicTest, AppLimited) {
  QuicConnectionStateBase conn(QuicNodeType::Client);
  conn.udpSendPacketLen = 1500;
  TestingCubic cubic(conn);
  cubic.setStateForTest(CubicStates::Steady);

  auto packet = makeTestingWritePacket(0, 1000, 1000);
  cubic.onPacketSent(packet);
  auto reductionTime = Clock::now();
  auto maxCwnd = cubic.getCongestionWindow();
  CongestionController::LossEvent loss(reductionTime);
  loss.addLostPacket(packet);
  cubic.onPacketAckOrLoss(folly::none, std::move(loss));
  auto timeToOrigin = ::cbrt(
      (maxCwnd - cubic.getCongestionWindow()) * 1000 * 1000 /
      conn.udpSendPacketLen * 2500);

  auto cwnd = cubic.getCongestionWindow();
  auto packet1 = makeTestingWritePacket(1, 1000, 2000);
  cubic.onPacketSent(packet1);
  cubic.onPacketAckOrLoss(
      makeAck(1, 1000, reductionTime + std::chrono::milliseconds(1000)),
      folly::none);
  EXPECT_EQ(CubicStates::Steady, cubic.state());
  EXPECT_GT(cubic.getCongestionWindow(), cwnd);
  cwnd = cubic.getCongestionWindow();

  cubic.setAppLimited(true, reductionTime + std::chrono::milliseconds(1100));
  EXPECT_TRUE(cubic.isAppLimited());
  auto packet2 = makeTestingWritePacket(2, 1000, 3000);
  cubic.onPacketSent(packet2);
  cubic.onPacketAckOrLoss(
      makeAck(2, 1000, reductionTime + std::chrono::milliseconds(2000)),
      folly::none);
  EXPECT_EQ(cubic.getCongestionWindow(), cwnd);

  // 1 seconds of quiescence
  cubic.setAppLimited(false, reductionTime + std::chrono::milliseconds(2100));
  EXPECT_FALSE(cubic.isAppLimited());
  auto packet3 = makeTestingWritePacket(3, 1000, 4000);
  cubic.onPacketSent(packet3);
  cubic.onPacketAckOrLoss(
      makeAck(3, 1000, reductionTime + std::chrono::milliseconds(3000)),
      folly::none);
  EXPECT_GT(cubic.getCongestionWindow(), cwnd);

  auto expectedDelta = static_cast<int64_t>(std::floor(
      conn.udpSendPacketLen * kTimeScalingFactor *
      std::pow((2 * 1000 - timeToOrigin), 3.0) / 1000 / 1000 / 1000));
  EXPECT_EQ(maxCwnd + expectedDelta, cubic.getCongestionWindow());
}

TEST_F(CubicTest, PacingGain) {
  QuicConnectionStateBase conn(QuicNodeType::Client);
  conn.udpSendPacketLen = 1500;
  Cubic cubic(conn);
  cubic.setMinimalPacingInterval(std::chrono::milliseconds(1));
  conn.lossState.srtt = std::chrono::microseconds(3 * 1000);
  cubic.onPacketSent(makeTestingWritePacket(0, 1500, 1500));
  cubic.onPacketAckOrLoss(makeAck(0, 1500, Clock::now()), folly::none);
  EXPECT_EQ(CubicStates::Hystart, cubic.state());
  // 11 * 2 / (3 / 1), then take ceil
  EXPECT_EQ(std::chrono::milliseconds(1), cubic.getPacingInterval());
  EXPECT_EQ(8, cubic.getPacingRate(Clock::now()));

  auto packet = makeTestingWritePacket(1, 1500, 3000);
  cubic.onPacketSent(packet);
  CongestionController::LossEvent loss;
  loss.addLostPacket(packet);
  // reduce cwnd to 9 MSS
  cubic.onPacketAckOrLoss(folly::none, loss);
  EXPECT_EQ(CubicStates::FastRecovery, cubic.state());
  // 9 * 1.25 / (3 / 1) then take ceil
  EXPECT_EQ(std::chrono::milliseconds(1), cubic.getPacingInterval());
  EXPECT_EQ(4, cubic.getPacingRate(Clock::now()));

  cubic.onPacketSent(makeTestingWritePacket(2, 1500, 4500));
  cubic.onPacketAckOrLoss(makeAck(2, 1500, Clock::now()), folly::none);
  EXPECT_EQ(CubicStates::Steady, cubic.state());
  // Cwnd should still be very close to 9 mss
  // 9 / (3 / 1)
  EXPECT_EQ(std::chrono::milliseconds(1), cubic.getPacingInterval());
  EXPECT_NEAR(3, cubic.getPacingRate(Clock::now()), 1);
}

TEST_F(CubicTest, PacingSpread) {
  QuicConnectionStateBase conn(QuicNodeType::Client);
  conn.lossState.srtt = std::chrono::milliseconds(60);
  conn.udpSendPacketLen = 1500;
  Cubic::CubicBuilder builder;
  builder.setPacingSpreadAcrossRtt(true);
  auto cubic = builder.build(conn);
  cubic->setMinimalPacingInterval(std::chrono::milliseconds(1));

  for (size_t i = 0; i < 5; i++) {
    cubic->onPacketSent(makeTestingWritePacket(i, 1500, 4500 + 1500 * (1 + i)));
    cubic->onPacketAckOrLoss(makeAck(i, 1500, Clock::now()), folly::none);
  }
  ASSERT_EQ(1500 * 15, cubic->getCongestionWindow());
  EXPECT_EQ(2, cubic->getPacingRate(Clock::now()));
  EXPECT_EQ(std::chrono::milliseconds(4), cubic->getPacingInterval());
}

TEST_F(CubicTest, LatePacingTimer) {
  QuicConnectionStateBase conn(QuicNodeType::Client);
  conn.lossState.srtt = std::chrono::milliseconds(50);
  Cubic cubic(conn);
  cubic.setMinimalPacingInterval(std::chrono::milliseconds(1));
  cubic.onPacketSent(
      makeTestingWritePacket(0, conn.udpSendPacketLen, conn.udpSendPacketLen));
  cubic.onPacketAckOrLoss(
      makeAck(0, conn.udpSendPacketLen, Clock::now()), folly::none);

  auto currentTime = Clock::now();
  auto pacingRateWithoutCompensation = cubic.getPacingRate(currentTime);
  cubic.markPacerTimeoutScheduled(currentTime);
  auto pacingRateWithCompensation =
      cubic.getPacingRate(currentTime + std::chrono::milliseconds(50));
  EXPECT_GT(pacingRateWithCompensation, pacingRateWithoutCompensation);

  // No matter how late it comes, you cannot go beyond the max limit
  auto veryLatePacingRate =
      cubic.getPacingRate(currentTime + std::chrono::seconds(100));
  EXPECT_GE(conn.transportSettings.maxBurstPackets, veryLatePacingRate);

  // But if you call getPacingRate again, it won't have compensation
  auto pacingRateAgain =
      cubic.getPacingRate(currentTime + std::chrono::milliseconds(50));
  EXPECT_LT(pacingRateAgain, pacingRateWithCompensation);
}

TEST_F(CubicTest, RttSmallerThanInterval) {
  QuicConnectionStateBase conn(QuicNodeType::Client);
  conn.udpSendPacketLen = 1500;
  conn.lossState.srtt = std::chrono::microseconds(1);
  Cubic cubic(conn);
  cubic.onPacketSent(makeTestingWritePacket(0, 1500, 1500));
  cubic.onPacketAckOrLoss(makeAck(0, 1500, Clock::now()), folly::none);
  EXPECT_FALSE(cubic.canBePaced());
  EXPECT_EQ(std::chrono::milliseconds::zero(), cubic.getPacingInterval());
  EXPECT_EQ(
      conn.transportSettings.writeConnectionDataPacketsLimit,
      cubic.getPacingRate(Clock::now()));
}

TEST_F(CubicTest, NoLargestAckedPacketNoCrash) {
  QuicConnectionStateBase conn(QuicNodeType::Client);
  Cubic cubic(conn);
  CongestionController::LossEvent loss;
  loss.largestLostPacketNum = 0;
  CongestionController::AckEvent ack;
  cubic.onPacketAckOrLoss(ack, loss);
}

} // namespace test
} // namespace quic
