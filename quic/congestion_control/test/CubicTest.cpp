/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <folly/portability/GTest.h>
#include <quic/common/test/TestUtils.h>
#include <quic/congestion_control/test/TestingCubic.h>
#include <quic/state/test/Mocks.h>

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
      makeAck(0, 50, Clock::now(), packet.metadata.time), folly::none);
  EXPECT_EQ(initCwnd, cubic.getWritableBytes());
}

TEST_F(CubicTest, PersistentCongestion) {
  QuicConnectionStateBase conn(QuicNodeType::Client);
  auto qLogger = std::make_shared<FileQLogger>(VantagePoint::Client);
  conn.qLogger = qLogger;
  Cubic cubic(conn, 0, Cubic::INIT_SSTHRESH, false);
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
      makeAck(1, initCwnd / 2, Clock::now(), packet2.metadata.time),
      folly::none);
  EXPECT_EQ(CubicStates::Steady, cubic.state());

  // Verify both lastMaxCwndBytes and lastReductionTime are also reset in
  // onPersistentCongestion. When they are both verified, the first ACK will
  // make both timeToOrigin and timeElapsed to be 0 in Ack handling in Steady
  // handler:
  auto currentCwnd = cubic.getWritableBytes(); // since nothing inflight
  auto packet3 = makeTestingWritePacket(2, 3000, initCwnd / 2 + 1000 + 3000);
  cubic.onPacketSent(packet3);
  cubic.onPacketAckOrLoss(
      makeAck(2, 3000, Clock::now(), packet3.metadata.time), folly::none);

  std::vector<int> indices =
      getQLogEventIndices(QLogEventType::CongestionMetricUpdate, qLogger);
  EXPECT_EQ(indices.size(), 10);
  std::array<std::string, 10> congestionEventArr = {
      kCubicInit,
      kRemoveInflight,
      kCubicLoss,
      kPersistentCongestion,
      kCongestionPacketAck,
      kResetTimeToOrigin,
      kResetLastReductionTime,
      kCubicSteadyCwnd,
      kCwndNoChange,
      kCongestionPacketAck};

  std::array<folly::StringPiece, 10> stateArr = {
      cubicStateToString(CubicStates::Hystart),
      cubicStateToString(CubicStates::Hystart),
      cubicStateToString(CubicStates::FastRecovery),
      cubicStateToString(CubicStates::Hystart),
      cubicStateToString(CubicStates::Steady),
      cubicStateToString(CubicStates::Steady),
      cubicStateToString(CubicStates::Steady),
      cubicStateToString(CubicStates::Steady),
      cubicStateToString(CubicStates::Steady),
      cubicStateToString(CubicStates::Steady)};

  for (int i = 0; i < 10; ++i) {
    auto tmp = std::move(qLogger->logs[indices[i]]);
    auto event = dynamic_cast<QLogCongestionMetricUpdateEvent*>(tmp.get());
    EXPECT_EQ(event->bytesInFlight, 0);
    EXPECT_EQ(event->congestionEvent, congestionEventArr[i]);
    EXPECT_EQ(event->state, stateArr[i]);
    EXPECT_EQ(event->recoveryState, "");
  }
  EXPECT_EQ(currentCwnd, cubic.getWritableBytes());
}

TEST_F(CubicTest, CwndIncreaseAfterReduction) {
  QuicConnectionStateBase conn(QuicNodeType::Client);
  auto qLogger = std::make_shared<FileQLogger>(VantagePoint::Client);
  conn.qLogger = qLogger;
  conn.udpSendPacketLen = 200;
  // initCwnd > initSsthresh: an ack will immediately make the state machine
  // transit to Steady state:
  Cubic cubic(conn, 0, 1000);

  // Send one and get acked, this moves the state machine to steady
  auto packet0 = makeTestingWritePacket(0, 1000, 1000);
  conn.lossState.largestSent = 0;
  cubic.onPacketSent(packet0);
  cubic.onPacketAckOrLoss(
      makeAck(0, 1000, Clock::now(), packet0.metadata.time), folly::none);
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
      makeAck(1, 1000, Clock::now(), packet1.metadata.time), folly::none);
  // Cwnd >= 3000, inflight = 2000:
  EXPECT_GE(cubic.getWritableBytes(), 1000);
  CongestionController::LossEvent loss;
  loss.addLostPacket(packet2);
  cubic.onPacketAckOrLoss(folly::none, std::move(loss));
  // Cwnd >= 2400, inflight = 1000:
  EXPECT_GE(cubic.getWritableBytes(), 1400);
  // This won't bring state machine back to Steady since endOfRecovery = 3
  cubic.onPacketAckOrLoss(
      makeAck(3, 1000, Clock::now(), packet3.metadata.time), folly::none);
  // Cwnd no change, inflight = 0:
  EXPECT_GE(cubic.getWritableBytes(), 2400);
  EXPECT_EQ(CubicStates::FastRecovery, cubic.state());

  auto packet4 = makeTestingWritePacket(4, 1000, 5000);
  conn.lossState.largestSent = 4;
  cubic.onPacketSent(packet4);
  // This will bring state machine back to steady
  cubic.onPacketAckOrLoss(
      makeAck(4, 1000, Clock::now(), packet4.metadata.time), folly::none);
  EXPECT_GE(cubic.getWritableBytes(), 2400);
  EXPECT_EQ(CubicStates::Steady, cubic.state());

  std::vector<int> indices =
      getQLogEventIndices(QLogEventType::TransportStateUpdate, qLogger);
  EXPECT_EQ(indices.size(), 1);
  auto tmp = std::move(qLogger->logs[indices[0]]);
  auto event = dynamic_cast<QLogTransportStateUpdateEvent*>(tmp.get());
  EXPECT_EQ(event->update, kRecalculateTimeToOrigin);
}

TEST_F(CubicTest, AppIdle) {
  QuicConnectionStateBase conn(QuicNodeType::Client);
  auto qLogger = std::make_shared<FileQLogger>(VantagePoint::Client);
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
      makeAck(1, 1000, reductionTime + 1000ms, packet1.metadata.time),
      folly::none);
  EXPECT_EQ(CubicStates::Steady, cubic.state());
  EXPECT_GT(cubic.getCongestionWindow(), cwnd);
  cwnd = cubic.getCongestionWindow();

  cubic.setAppIdle(true, reductionTime + 1100ms);
  EXPECT_TRUE(cubic.isAppLimited());
  auto packet2 = makeTestingWritePacket(2, 1000, 3000);
  cubic.onPacketSent(packet2);
  cubic.onPacketAckOrLoss(
      makeAck(2, 1000, reductionTime + 2000ms, packet2.metadata.time),
      folly::none);
  EXPECT_EQ(cubic.getCongestionWindow(), cwnd);

  // 1 seconds of quiescence
  cubic.setAppIdle(false, reductionTime + 2100ms);
  EXPECT_FALSE(cubic.isAppLimited());
  auto packet3 = makeTestingWritePacket(3, 1000, 4000);
  cubic.onPacketSent(packet3);
  cubic.onPacketAckOrLoss(
      makeAck(3, 1000, reductionTime + 3000ms, packet3.metadata.time),
      folly::none);
  EXPECT_GT(cubic.getCongestionWindow(), cwnd);

  auto expectedDelta = static_cast<int64_t>(std::floor(
      conn.udpSendPacketLen * kTimeScalingFactor *
      std::pow((2 * 1000 - timeToOrigin), 3.0) / 1000 / 1000 / 1000));
  EXPECT_EQ(maxCwnd + expectedDelta, cubic.getCongestionWindow());

  std::vector<int> indices =
      getQLogEventIndices(QLogEventType::AppIdleUpdate, qLogger);
  EXPECT_EQ(indices.size(), 2);
  std::array<bool, 2> idleArr = {true, false};
  for (int i = 0; i < 2; ++i) {
    auto tmp = std::move(qLogger->logs[indices[i]]);
    auto event = dynamic_cast<QLogAppIdleUpdateEvent*>(tmp.get());
    EXPECT_EQ(event->idleEvent, kAppIdle);
    EXPECT_EQ(event->idle, idleArr[i]);
  }
}

TEST_F(CubicTest, PacingGain) {
  QuicConnectionStateBase conn(QuicNodeType::Client);
  conn.transportSettings.pacingTimerTickInterval = 1ms;
  auto mockPacer = std::make_unique<MockPacer>();
  auto rawPacer = mockPacer.get();
  conn.pacer = std::move(mockPacer);
  auto qLogger = std::make_shared<FileQLogger>(VantagePoint::Client);
  conn.qLogger = qLogger;
  conn.udpSendPacketLen = 1500;
  Cubic cubic(conn);

  conn.lossState.srtt = 3000us;
  auto packet = makeTestingWritePacket(0, 1500, 1500);
  cubic.onPacketSent(packet);
  EXPECT_CALL(*rawPacer, refreshPacingRate(_, _, _))
      .Times(1)
      .WillOnce(
          Invoke([&](uint64_t cwndBytes, std::chrono::microseconds, auto) {
            EXPECT_EQ(cubic.getCongestionWindow() * 2, cwndBytes);
          }));
  cubic.onPacketAckOrLoss(
      makeAck(0, 1500, Clock::now(), packet.metadata.time), folly::none);
  EXPECT_EQ(CubicStates::Hystart, cubic.state());

  auto packet1 = makeTestingWritePacket(1, 1500, 3000);
  cubic.onPacketSent(packet1);
  CongestionController::LossEvent loss;
  loss.addLostPacket(packet1);
  // reduce cwnd to 9 MSS
  EXPECT_CALL(*rawPacer, refreshPacingRate(_, _, _))
      .Times(1)
      .WillOnce(
          Invoke([&](uint64_t cwndBytes, std::chrono::microseconds, auto) {
            EXPECT_EQ(
                static_cast<uint64_t>(cubic.getCongestionWindow() * 1.25),
                cwndBytes);
          }));
  cubic.onPacketAckOrLoss(folly::none, loss);
  EXPECT_EQ(CubicStates::FastRecovery, cubic.state());

  auto packet2 = makeTestingWritePacket(2, 1500, 4500);
  cubic.onPacketSent(packet2);
  EXPECT_CALL(*rawPacer, refreshPacingRate(_, _, _))
      .Times(1)
      .WillOnce(
          Invoke([&](uint64_t cwndBytes, std::chrono::microseconds, auto) {
            EXPECT_EQ(cubic.getCongestionWindow(), cwndBytes);
          }));
  cubic.onPacketAckOrLoss(
      makeAck(2, 1500, Clock::now(), packet2.metadata.time), folly::none);
  EXPECT_EQ(CubicStates::Steady, cubic.state());

  std::vector<int> indices =
      getQLogEventIndices(QLogEventType::TransportStateUpdate, qLogger);
  EXPECT_EQ(indices.size(), 1);
  auto tmp = std::move(qLogger->logs[indices[0]]);
  auto event = dynamic_cast<QLogTransportStateUpdateEvent*>(tmp.get());
  EXPECT_EQ(event->update, kRecalculateTimeToOrigin);
}

TEST_F(CubicTest, PacetLossInvokesPacer) {
  QuicConnectionStateBase conn(QuicNodeType::Client);
  auto mockPacer = std::make_unique<MockPacer>();
  auto rawPacer = mockPacer.get();
  conn.pacer = std::move(mockPacer);
  Cubic cubic(conn);

  auto packet = makeTestingWritePacket(0, 1000, 1000);
  cubic.onPacketSent(packet);
  EXPECT_CALL(*rawPacer, onPacketsLoss()).Times(1);
  CongestionController::LossEvent lossEvent;
  lossEvent.addLostPacket(packet);
  cubic.onPacketAckOrLoss(folly::none, lossEvent);
}

TEST_F(CubicTest, InitCwnd) {
  QuicConnectionStateBase conn(QuicNodeType::Client);
  Cubic cubic(conn, 123456);
  EXPECT_EQ(cubic.getWritableBytes(), 123456);
}

} // namespace test
} // namespace quic
