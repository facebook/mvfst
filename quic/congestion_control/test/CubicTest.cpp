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
  auto packet = makeTestingWritePacket(0, 100, 100);
  cubic.onPacketSent(packet);
  EXPECT_EQ(initCwnd - 100, cubic.getWritableBytes());

  // Acking 50, now inflight become 50. Cwnd is init + 50
  cubic.onPacketAckOrLoss(
      makeAck(0, 50, Clock::now(), packet.time), folly::none);
  EXPECT_EQ(initCwnd, cubic.getWritableBytes());
}

TEST_F(CubicTest, PersistentCongestion) {
  QuicConnectionStateBase conn(QuicNodeType::Client);
  auto qLogger = std::make_shared<FileQLogger>();
  conn.qLogger = qLogger;
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
  cubic.onPacketAckOrLoss(
      makeAck(1, initCwnd / 2, Clock::now(), packet2.time), folly::none);
  EXPECT_EQ(CubicStates::Steady, cubic.state());

  // Verify both lastMaxCwndBytes and lastReductionTime are also reset in
  // onPersistentCongestion. When they are both verified, the first ACK will
  // make both timeToOrigin and timeElapsed to be 0 in Ack handling in Steady
  // handler:
  auto currentCwnd = cubic.getWritableBytes(); // since nothing inflight
  auto packet3 = makeTestingWritePacket(2, 3000, initCwnd / 2 + 1000 + 3000);
  cubic.onPacketSent(packet3);
  cubic.onPacketAckOrLoss(
      makeAck(2, 3000, Clock::now(), packet3.time), folly::none);

  std::vector<int> indices =
      getQLogEventIndices(QLogEventType::CongestionMetricUpdate, qLogger);
  EXPECT_EQ(indices.size(), 9);

  auto tmp = std::move(qLogger->logs[indices[0]]);
  auto event = dynamic_cast<QLogCongestionMetricUpdateEvent*>(tmp.get());
  EXPECT_EQ(event->bytesInFlight, 0);
  EXPECT_EQ(event->currentCwnd, initCwnd);
  EXPECT_EQ(event->congestionEvent, kRemoveInflight.str());
  EXPECT_EQ(event->state, cubicStateToString(CubicStates::Hystart));
  EXPECT_EQ(event->recoveryState, "");

  auto tmp2 = std::move(qLogger->logs[indices[1]]);
  auto event2 = dynamic_cast<QLogCongestionMetricUpdateEvent*>(tmp2.get());
  EXPECT_EQ(event2->bytesInFlight, 0);
  EXPECT_EQ(event2->currentCwnd, 11088);
  EXPECT_EQ(event2->congestionEvent, kCubicLoss.str());
  EXPECT_EQ(event2->state, cubicStateToString(CubicStates::FastRecovery));
  EXPECT_EQ(event2->recoveryState, "");

  auto tmp3 = std::move(qLogger->logs[indices[2]]);
  auto event3 = dynamic_cast<QLogCongestionMetricUpdateEvent*>(tmp3.get());
  EXPECT_EQ(event3->bytesInFlight, 0);
  EXPECT_EQ(event3->currentCwnd, 2464);
  EXPECT_EQ(event3->congestionEvent, kPersistentCongestion.str());
  EXPECT_EQ(event3->state, cubicStateToString(CubicStates::Hystart));
  EXPECT_EQ(event3->recoveryState, "");

  auto tmp4 = std::move(qLogger->logs[indices[3]]);
  auto event4 = dynamic_cast<QLogCongestionMetricUpdateEvent*>(tmp4.get());
  EXPECT_EQ(event4->bytesInFlight, 0);
  EXPECT_EQ(event4->currentCwnd, cubic.getCongestionWindow());
  EXPECT_EQ(event4->congestionEvent, kCongestionPacketAck.str());
  EXPECT_EQ(event4->state, cubicStateToString(CubicStates::Steady));
  EXPECT_EQ(event4->recoveryState, "");

  auto tmp5 = std::move(qLogger->logs[indices[4]]);
  auto event5 = dynamic_cast<QLogCongestionMetricUpdateEvent*>(tmp5.get());
  EXPECT_EQ(event5->bytesInFlight, 0);
  EXPECT_EQ(event5->currentCwnd, cubic.getCongestionWindow());
  EXPECT_EQ(event5->congestionEvent, kResetTimeToOrigin.str());
  EXPECT_EQ(event5->state, cubicStateToString(CubicStates::Steady));
  EXPECT_EQ(event5->recoveryState, "");

  auto tmp6 = std::move(qLogger->logs[indices[5]]);
  auto event6 = dynamic_cast<QLogCongestionMetricUpdateEvent*>(tmp6.get());
  EXPECT_EQ(event6->bytesInFlight, 0);
  EXPECT_EQ(event6->currentCwnd, cubic.getCongestionWindow());
  EXPECT_EQ(event6->congestionEvent, kResetLastReductionTime.str());
  EXPECT_EQ(event6->state, cubicStateToString(CubicStates::Steady));
  EXPECT_EQ(event6->recoveryState, "");

  auto tmp7 = std::move(qLogger->logs[indices[6]]);
  auto event7 = dynamic_cast<QLogCongestionMetricUpdateEvent*>(tmp7.get());
  EXPECT_EQ(event7->bytesInFlight, 0);
  EXPECT_EQ(event7->currentCwnd, cubic.getCongestionWindow());
  EXPECT_EQ(event7->congestionEvent, kCubicSteadyCwnd.str());
  EXPECT_EQ(event7->state, cubicStateToString(CubicStates::Steady));
  EXPECT_EQ(event7->recoveryState, "");

  auto tmp8 = std::move(qLogger->logs[indices[7]]);
  auto event8 = dynamic_cast<QLogCongestionMetricUpdateEvent*>(tmp8.get());
  EXPECT_EQ(event8->bytesInFlight, 0);
  EXPECT_EQ(event8->currentCwnd, cubic.getCongestionWindow());
  EXPECT_EQ(event8->congestionEvent, kCwndNoChange.str());
  EXPECT_EQ(event8->state, cubicStateToString(CubicStates::Steady));
  EXPECT_EQ(event8->recoveryState, "");

  auto tmp9 = std::move(qLogger->logs[indices[8]]);
  auto event9 = dynamic_cast<QLogCongestionMetricUpdateEvent*>(tmp9.get());
  EXPECT_EQ(event9->bytesInFlight, 0);
  EXPECT_EQ(event9->currentCwnd, cubic.getCongestionWindow());
  EXPECT_EQ(event9->congestionEvent, kCongestionPacketAck.str());
  EXPECT_EQ(event9->state, cubicStateToString(CubicStates::Steady));
  EXPECT_EQ(event9->recoveryState, "");

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
  cubic.onPacketAckOrLoss(
      makeAck(0, 1000, Clock::now(), packet0.time), folly::none);
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

  cubic.onPacketAckOrLoss(
      makeAck(1, 1000, Clock::now(), packet1.time), folly::none);
  // Cwnd >= 3000, inflight = 2000:
  EXPECT_GE(cubic.getWritableBytes(), 1000);
  CongestionController::LossEvent loss;
  loss.addLostPacket(packet2);
  cubic.onPacketAckOrLoss(folly::none, std::move(loss));
  // Cwnd >= 2400, inflight = 1000:
  EXPECT_GE(cubic.getWritableBytes(), 1400);
  // This won't bring state machine back to Steady since endOfRecovery = 3
  cubic.onPacketAckOrLoss(
      makeAck(3, 1000, Clock::now(), packet3.time), folly::none);
  // Cwnd no change, inflight = 0:
  EXPECT_GE(cubic.getWritableBytes(), 2400);
  EXPECT_EQ(CubicStates::FastRecovery, cubic.state());

  auto packet4 = makeTestingWritePacket(4, 1000, 5000);
  conn.lossState.largestSent = 4;
  cubic.onPacketSent(packet4);
  // This will bring state machine back to steady
  cubic.onPacketAckOrLoss(
      makeAck(4, 1000, Clock::now(), packet4.time), folly::none);
  EXPECT_GE(cubic.getWritableBytes(), 2400);
  EXPECT_EQ(CubicStates::Steady, cubic.state());
}

TEST_F(CubicTest, AppIdle) {
  QuicConnectionStateBase conn(QuicNodeType::Client);
  auto qLogger = std::make_shared<FileQLogger>();
  conn.qLogger = qLogger;
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
      makeAck(1, 1000, reductionTime + 1000ms, packet1.time), folly::none);
  EXPECT_EQ(CubicStates::Steady, cubic.state());
  EXPECT_GT(cubic.getCongestionWindow(), cwnd);
  cwnd = cubic.getCongestionWindow();

  cubic.setAppIdle(true, reductionTime + 1100ms);
  EXPECT_TRUE(cubic.isAppLimited());
  auto packet2 = makeTestingWritePacket(2, 1000, 3000);
  cubic.onPacketSent(packet2);
  cubic.onPacketAckOrLoss(
      makeAck(2, 1000, reductionTime + 2000ms, packet2.time), folly::none);
  EXPECT_EQ(cubic.getCongestionWindow(), cwnd);

  // 1 seconds of quiescence
  cubic.setAppIdle(false, reductionTime + 2100ms);
  EXPECT_FALSE(cubic.isAppLimited());
  auto packet3 = makeTestingWritePacket(3, 1000, 4000);
  cubic.onPacketSent(packet3);
  cubic.onPacketAckOrLoss(
      makeAck(3, 1000, reductionTime + 3000ms, packet3.time), folly::none);
  EXPECT_GT(cubic.getCongestionWindow(), cwnd);

  auto expectedDelta = static_cast<int64_t>(std::floor(
      conn.udpSendPacketLen * kTimeScalingFactor *
      std::pow((2 * 1000 - timeToOrigin), 3.0) / 1000 / 1000 / 1000));
  EXPECT_EQ(maxCwnd + expectedDelta, cubic.getCongestionWindow());

  std::vector<int> indices =
      getQLogEventIndices(QLogEventType::AppIdleUpdate, qLogger);
  EXPECT_EQ(indices.size(), 2);

  auto tmp = std::move(qLogger->logs[indices[0]]);
  auto event = dynamic_cast<QLogAppIdleUpdateEvent*>(tmp.get());
  EXPECT_EQ(event->idleEvent, kAppIdle.str());
  EXPECT_TRUE(event->idle);

  auto tmp2 = std::move(qLogger->logs[indices[1]]);
  auto event2 = dynamic_cast<QLogAppIdleUpdateEvent*>(tmp2.get());
  EXPECT_EQ(event2->idleEvent, kAppIdle.str());
  EXPECT_FALSE(event2->idle);
}

TEST_F(CubicTest, PacingGain) {
  QuicConnectionStateBase conn(QuicNodeType::Client);
  conn.udpSendPacketLen = 1500;
  Cubic cubic(conn);
  cubic.setMinimalPacingInterval(1ms);
  conn.lossState.srtt = 3000us;
  auto packet = makeTestingWritePacket(0, 1500, 1500);
  cubic.onPacketSent(packet);
  cubic.onPacketAckOrLoss(
      makeAck(0, 1500, Clock::now(), packet.time), folly::none);
  EXPECT_EQ(CubicStates::Hystart, cubic.state());
  // 11 * 2 / (3 / 1), then take ceil
  EXPECT_EQ(1ms, cubic.getPacingInterval());
  EXPECT_EQ(8, cubic.getPacingRate(Clock::now()));

  auto packet1 = makeTestingWritePacket(1, 1500, 3000);
  cubic.onPacketSent(packet1);
  CongestionController::LossEvent loss;
  loss.addLostPacket(packet1);
  // reduce cwnd to 9 MSS
  cubic.onPacketAckOrLoss(folly::none, loss);
  EXPECT_EQ(CubicStates::FastRecovery, cubic.state());
  // 9 * 1.25 / (3 / 1) then take ceil
  EXPECT_EQ(1ms, cubic.getPacingInterval());
  EXPECT_EQ(4, cubic.getPacingRate(Clock::now()));

  auto packet2 = makeTestingWritePacket(2, 1500, 4500);
  cubic.onPacketSent(packet2);
  cubic.onPacketAckOrLoss(
      makeAck(2, 1500, Clock::now(), packet2.time), folly::none);
  EXPECT_EQ(CubicStates::Steady, cubic.state());
  // Cwnd should still be very close to 9 mss
  // 9 / (3 / 1)
  EXPECT_EQ(1ms, cubic.getPacingInterval());
  EXPECT_NEAR(3, cubic.getPacingRate(Clock::now()), 1);
}

TEST_F(CubicTest, PacingSpread) {
  QuicConnectionStateBase conn(QuicNodeType::Client);
  conn.lossState.srtt = 60ms;
  conn.udpSendPacketLen = 1500;
  Cubic::CubicBuilder builder;
  builder.setPacingSpreadAcrossRtt(true);
  auto cubic = builder.build(conn);
  cubic->setMinimalPacingInterval(1ms);

  for (size_t i = 0; i < 5; i++) {
    auto packet = makeTestingWritePacket(i, 1500, 4500 + 1500 * (1 + i));
    cubic->onPacketSent(packet);
    cubic->onPacketAckOrLoss(
        makeAck(i, 1500, Clock::now(), packet.time), folly::none);
  }
  ASSERT_EQ(1500 * 15, cubic->getCongestionWindow());
  EXPECT_EQ(1, cubic->getPacingRate(Clock::now()));
  EXPECT_EQ(2ms, cubic->getPacingInterval());
}

TEST_F(CubicTest, LatePacingTimer) {
  QuicConnectionStateBase conn(QuicNodeType::Client);
  conn.lossState.srtt = 50ms;
  Cubic cubic(conn);
  cubic.setMinimalPacingInterval(1ms);
  auto packet =
      makeTestingWritePacket(0, conn.udpSendPacketLen, conn.udpSendPacketLen);
  cubic.onPacketSent(packet);
  cubic.onPacketAckOrLoss(
      makeAck(0, conn.udpSendPacketLen, Clock::now(), packet.time),
      folly::none);

  auto currentTime = Clock::now();
  auto pacingRateWithoutCompensation = cubic.getPacingRate(currentTime);
  cubic.markPacerTimeoutScheduled(currentTime);
  auto pacingRateWithCompensation = cubic.getPacingRate(currentTime + 50ms);
  EXPECT_GT(pacingRateWithCompensation, pacingRateWithoutCompensation);

  // No matter how late it comes, you cannot go beyond the max limit
  auto veryLatePacingRate = cubic.getPacingRate(currentTime + 100s);
  EXPECT_GE(conn.transportSettings.maxBurstPackets, veryLatePacingRate);

  // But if you call getPacingRate again, it won't have compensation
  auto pacingRateAgain = cubic.getPacingRate(currentTime + 50ms);
  EXPECT_LT(pacingRateAgain, pacingRateWithCompensation);
}

TEST_F(CubicTest, RttSmallerThanInterval) {
  QuicConnectionStateBase conn(QuicNodeType::Client);
  conn.udpSendPacketLen = 1500;
  conn.lossState.srtt = 1us;
  Cubic cubic(conn);
  auto packet = makeTestingWritePacket(0, 1500, 1500);
  cubic.onPacketSent(packet);
  cubic.onPacketAckOrLoss(
      makeAck(0, 1500, Clock::now(), packet.time), folly::none);
  EXPECT_FALSE(cubic.canBePaced());
  EXPECT_EQ(std::chrono::milliseconds::zero(), cubic.getPacingInterval());
  EXPECT_EQ(
      conn.transportSettings.writeConnectionDataPacketsLimit,
      cubic.getPacingRate(Clock::now()));
}
} // namespace test
} // namespace quic
