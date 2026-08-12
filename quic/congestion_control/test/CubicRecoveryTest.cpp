/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <folly/portability/GTest.h>
#include <quic/common/test/TestUtils.h>
#include <quic/congestion_control/QuicCubic.h>
#include <quic/congestion_control/test/Utils.h>

using namespace testing;

namespace quic::test {

namespace {

AckEvent makeSpuriousAck(uint64_t numPackets) {
  const auto ackTime = Clock::now();
  auto ack = AckEvent::Builder()
                 .setAckTime(ackTime)
                 .setAdjustedAckTime(ackTime)
                 .setAckDelay(0us)
                 .setPacketNumberSpace(PacketNumberSpace::AppData)
                 .setLargestAckedPacket(0)
                 .build();
  ack.numPacketsSpuriouslyAcked = numPackets;
  return ack;
}

void processCubicEvent(
    QuicConnectionStateBase& conn,
    Cubic& cubic,
    Optional<AckEvent> ack,
    Optional<LossEvent> loss) {
  const auto numPacketsSpuriouslyAcked =
      ack ? ack->numPacketsSpuriouslyAcked : 0;
  ASSERT_LE(numPacketsSpuriouslyAcked, conn.outstandings.declaredLostCount);
  conn.outstandings.declaredLostCount -= numPacketsSpuriouslyAcked;
  if (loss) {
    conn.outstandings.declaredLostCount += loss->lostPackets;
  }
  quic::test::onPacketAckOrLossWrapper(
      &conn, &cubic, std::move(ack), std::move(loss));
}

} // namespace

class CubicRecoveryTest : public Test {};

TEST_F(CubicRecoveryTest, SpuriousLossRecoveryDisabledByDefault) {
  QuicConnectionStateBase conn(QuicNodeType::Client);
  Cubic cubic(conn);
  const auto sentTime = Clock::now() - 1s;
  auto packet = makeTestingWritePacket(0, 1000, 1000, sentTime);
  quic::test::onPacketsSentWrapper(&conn, &cubic, packet);
  LossEvent loss;
  loss.addLostPacket(packet);
  processCubicEvent(conn, cubic, std::nullopt, std::move(loss));
  const auto cwndAfterLoss = cubic.getCongestionWindow();

  processCubicEvent(conn, cubic, makeSpuriousAck(1), std::nullopt);

  EXPECT_EQ(cwndAfterLoss, cubic.getCongestionWindow());
  EXPECT_EQ(CubicStates::FastRecovery, cubic.state());
}

TEST_F(CubicRecoveryTest, RecoversAfterEntireLossEpisodeIsSpurious) {
  QuicConnectionStateBase conn(QuicNodeType::Client);
  conn.transportSettings.ccaConfig.enableSpuriousLossRecovery = true;
  Cubic cubic(conn);
  const auto cwndBeforeLoss = cubic.getCongestionWindow();
  const auto sentTime = Clock::now() - 1s;
  auto packet0 = makeTestingWritePacket(0, 1000, 1000, sentTime);
  auto packet1 = makeTestingWritePacket(1, 1000, 2000, sentTime);
  quic::test::onPacketsSentWrapper(&conn, &cubic, packet0);
  quic::test::onPacketsSentWrapper(&conn, &cubic, packet1);
  LossEvent loss;
  loss.addLostPacket(packet0);
  loss.addLostPacket(packet1);
  processCubicEvent(conn, cubic, std::nullopt, std::move(loss));
  const auto cwndAfterLoss = cubic.getCongestionWindow();
  EXPECT_LT(cwndAfterLoss, cwndBeforeLoss);

  processCubicEvent(conn, cubic, makeSpuriousAck(1), std::nullopt);
  EXPECT_EQ(cwndAfterLoss, cubic.getCongestionWindow());
  EXPECT_EQ(CubicStates::FastRecovery, cubic.state());

  processCubicEvent(conn, cubic, makeSpuriousAck(1), std::nullopt);
  EXPECT_EQ(cwndBeforeLoss, cubic.getCongestionWindow());
  EXPECT_EQ(CubicStates::Hystart, cubic.state());
  CongestionControllerStats stats{};
  cubic.getStats(stats);
  EXPECT_EQ(Cubic::INIT_SSTHRESH, stats.cubicStats.ssthresh);
}

TEST_F(CubicRecoveryTest, LossesInRecoveryMustAlsoBeSpurious) {
  QuicConnectionStateBase conn(QuicNodeType::Client);
  conn.transportSettings.ccaConfig.enableSpuriousLossRecovery = true;
  Cubic cubic(conn);
  const auto cwndBeforeLoss = cubic.getCongestionWindow();
  const auto sentTime = Clock::now() - 1s;
  auto packet0 = makeTestingWritePacket(0, 1000, 1000, sentTime);
  auto packet1 = makeTestingWritePacket(1, 1000, 2000, sentTime);
  LossEvent firstLoss;
  firstLoss.addLostPacket(packet0);
  processCubicEvent(conn, cubic, std::nullopt, std::move(firstLoss));
  const auto cwndAfterLoss = cubic.getCongestionWindow();

  LossEvent lossInRecovery;
  lossInRecovery.addLostPacket(packet1);
  processCubicEvent(conn, cubic, std::nullopt, std::move(lossInRecovery));
  processCubicEvent(conn, cubic, makeSpuriousAck(1), std::nullopt);
  EXPECT_EQ(cwndAfterLoss, cubic.getCongestionWindow());

  processCubicEvent(conn, cubic, makeSpuriousAck(1), std::nullopt);
  EXPECT_EQ(cwndBeforeLoss, cubic.getCongestionWindow());
  EXPECT_EQ(CubicStates::Hystart, cubic.state());
}

TEST_F(CubicRecoveryTest, RetainedLossFromOlderEpisodePreventsUndo) {
  QuicConnectionStateBase conn(QuicNodeType::Client);
  conn.transportSettings.ccaConfig.enableSpuriousLossRecovery = true;
  Cubic cubic(conn);
  conn.outstandings.declaredLostCount = 1;
  auto packet = makeTestingWritePacket(0, 1000, 1000, Clock::now() - 1s);
  LossEvent loss;
  loss.addLostPacket(packet);
  processCubicEvent(conn, cubic, std::nullopt, std::move(loss));
  const auto cwndAfterLoss = cubic.getCongestionWindow();

  processCubicEvent(conn, cubic, makeSpuriousAck(2), std::nullopt);

  EXPECT_EQ(cwndAfterLoss, cubic.getCongestionWindow());
  EXPECT_EQ(CubicStates::FastRecovery, cubic.state());
}

TEST_F(CubicRecoveryTest, SpuriousLossIsProcessedBeforeNewLoss) {
  QuicConnectionStateBase conn(QuicNodeType::Client);
  conn.transportSettings.ccaConfig.enableSpuriousLossRecovery = true;
  Cubic cubic(conn);
  const auto cwndBeforeLoss = cubic.getCongestionWindow();
  auto packet0 = makeTestingWritePacket(0, 1000, 1000, Clock::now() - 1s);
  LossEvent firstLoss;
  firstLoss.addLostPacket(packet0);
  processCubicEvent(conn, cubic, std::nullopt, std::move(firstLoss));
  const auto cwndAfterOneReduction = cubic.getCongestionWindow();

  auto packet1 = makeTestingWritePacket(1, 1000, 2000, Clock::now() + 1s);
  LossEvent newLoss;
  newLoss.addLostPacket(packet1);
  processCubicEvent(conn, cubic, makeSpuriousAck(1), std::move(newLoss));

  EXPECT_EQ(cwndAfterOneReduction, cubic.getCongestionWindow());
  EXPECT_EQ(CubicStates::FastRecovery, cubic.state());
  processCubicEvent(conn, cubic, makeSpuriousAck(1), std::nullopt);
  EXPECT_EQ(cwndBeforeLoss, cubic.getCongestionWindow());
  EXPECT_EQ(CubicStates::Hystart, cubic.state());
}

TEST_F(CubicRecoveryTest, RecoversAfterFastRecoveryEnds) {
  QuicConnectionStateBase conn(QuicNodeType::Client);
  conn.transportSettings.ccaConfig.enableSpuriousLossRecovery = true;
  Cubic cubic(conn);
  const auto cwndBeforeLoss = cubic.getCongestionWindow();
  auto lostPacket = makeTestingWritePacket(0, 1000, 1000, Clock::now() - 1s);
  LossEvent loss;
  loss.addLostPacket(lostPacket);
  processCubicEvent(conn, cubic, std::nullopt, std::move(loss));

  auto ackedPacket = makeTestingWritePacket(1, 1000, 2000, Clock::now());
  processCubicEvent(
      conn,
      cubic,
      makeAck(1, 1000, Clock::now() + 1ms, ackedPacket.metadata.time),
      std::nullopt);
  ASSERT_EQ(CubicStates::Steady, cubic.state());
  const auto cwndAfterRecovery = cubic.getCongestionWindow();

  processCubicEvent(conn, cubic, makeSpuriousAck(1), std::nullopt);

  EXPECT_EQ(
      std::max(cwndBeforeLoss, cwndAfterRecovery), cubic.getCongestionWindow());
  EXPECT_EQ(CubicStates::Steady, cubic.state());
}

TEST_F(CubicRecoveryTest, CountMismatchInvalidatesUndo) {
  QuicConnectionStateBase conn(QuicNodeType::Client);
  conn.transportSettings.ccaConfig.enableSpuriousLossRecovery = true;
  Cubic cubic(conn);
  const auto sentTime = Clock::now() - 1s;
  auto packet0 = makeTestingWritePacket(0, 1000, 1000, sentTime);
  auto packet1 = makeTestingWritePacket(1, 1000, 2000, sentTime);
  LossEvent loss;
  loss.addLostPacket(packet0);
  loss.addLostPacket(packet1);
  processCubicEvent(conn, cubic, std::nullopt, std::move(loss));
  const auto cwndAfterLoss = cubic.getCongestionWindow();

  --conn.outstandings.declaredLostCount;
  processCubicEvent(conn, cubic, makeSpuriousAck(1), std::nullopt);

  EXPECT_EQ(cwndAfterLoss, cubic.getCongestionWindow());
  EXPECT_EQ(CubicStates::FastRecovery, cubic.state());
}

TEST_F(CubicRecoveryTest, PersistentCongestionInvalidatesRecovery) {
  QuicConnectionStateBase conn(QuicNodeType::Client);
  conn.transportSettings.ccaConfig.enableSpuriousLossRecovery = true;
  Cubic cubic(conn);
  auto packet0 = makeTestingWritePacket(0, 1000, 1000, Clock::now() - 1s);
  LossEvent firstLoss;
  firstLoss.addLostPacket(packet0);
  processCubicEvent(conn, cubic, std::nullopt, std::move(firstLoss));

  auto packet1 = makeTestingWritePacket(1, 1000, 2000, Clock::now() + 1s);
  LossEvent persistentLoss;
  persistentLoss.addLostPacket(packet1);
  persistentLoss.persistentCongestion = true;
  processCubicEvent(conn, cubic, std::nullopt, std::move(persistentLoss));
  const auto cwndAfterPersistentCongestion = cubic.getCongestionWindow();
  ASSERT_EQ(CubicStates::Hystart, cubic.state());

  processCubicEvent(conn, cubic, makeSpuriousAck(2), std::nullopt);
  EXPECT_EQ(cwndAfterPersistentCongestion, cubic.getCongestionWindow());
  EXPECT_EQ(CubicStates::Hystart, cubic.state());
}

TEST_F(CubicRecoveryTest, LossBurst) {
  QuicConnectionStateBase conn(QuicNodeType::Client);
  Cubic cubic(conn);
  uint64_t totalSent = 0;
  auto packet0 = makeTestingWritePacket(0, 1000, 1000 + totalSent);
  // Send and loss immediately
  quic::test::onPacketsSentWrapper(&conn, &cubic, packet0);
  totalSent += 1000;
  LossEvent loss;
  loss.addLostPacket(packet0);
  quic::test::onPacketAckOrLossWrapper(
      &conn, &cubic, std::nullopt, std::move(loss));
  EXPECT_EQ(CubicStates::FastRecovery, cubic.state());
  auto cwndAfterLoss = cubic.getCongestionWindow();

  // Then lose a few more:
  LossEvent loss2;
  for (size_t i = 1; i < 5; i++) {
    auto packet = makeTestingWritePacket(i, 1000, 1000 + totalSent);
    quic::test::onPacketsSentWrapper(&conn, &cubic, packet);
    totalSent += 1000;
    conn.lossState.largestSent = i;
    loss2.addLostPacket(packet);
  }
  quic::test::onPacketAckOrLossWrapper(
      &conn, &cubic, std::nullopt, std::move(loss2));
  // Still in recovery:
  EXPECT_EQ(CubicStates::FastRecovery, cubic.state());
  // Cwnd should be reduced.
  EXPECT_GT(cwndAfterLoss, cubic.getCongestionWindow());
}

TEST_F(CubicRecoveryTest, LossBeforeRecovery) {
  QuicConnectionStateBase conn(QuicNodeType::Client);
  Cubic cubic(conn);
  uint64_t totalSent = 0;

  // Send/ack one packet.
  auto packet = makeTestingWritePacket(0, 1000, 1000 + totalSent);
  quic::test::onPacketsSentWrapper(&conn, &cubic, packet);
  totalSent += 1000;
  quic::test::onPacketAckOrLossWrapper(
      &conn,
      &cubic,
      makeAck(0, 1000, Clock::now(), packet.metadata.time),
      std::nullopt);
  EXPECT_EQ(CubicStates::Hystart, cubic.state());

  // Send three packets, lose second immediately.
  auto packet1 = makeTestingWritePacket(1, 1000, 1000 + totalSent);
  totalSent += 1000;
  auto packet2 = makeTestingWritePacket(2, 1000, 1000 + totalSent);
  totalSent += 1000;
  auto packet3 = makeTestingWritePacket(3, 1000, 1000 + totalSent);
  totalSent += 1000;
  quic::test::onPacketsSentWrapper(&conn, &cubic, packet1);
  quic::test::onPacketsSentWrapper(&conn, &cubic, packet2);
  quic::test::onPacketsSentWrapper(&conn, &cubic, packet3);
  conn.lossState.largestSent = 3;
  LossEvent loss2;
  loss2.addLostPacket(packet2);
  quic::test::onPacketAckOrLossWrapper(
      &conn, &cubic, std::nullopt, std::move(loss2));

  // Should now be in recovery. Send packet4, receive acks for 3 and 4 which
  // should exit recovery with a certain cwnd.
  EXPECT_EQ(CubicStates::FastRecovery, cubic.state());
  auto packet4 = makeTestingWritePacket(4, 1000, 1000 + totalSent);
  quic::test::onPacketsSentWrapper(&conn, &cubic, packet4);
  totalSent += 1000;
  conn.lossState.largestSent = 4;
  quic::test::onPacketAckOrLossWrapper(
      &conn,
      &cubic,
      makeAck(3, 1000, Clock::now(), packet3.metadata.time),
      std::nullopt);
  quic::test::onPacketAckOrLossWrapper(
      &conn,
      &cubic,
      makeAck(4, 1000, Clock::now(), packet4.metadata.time),
      std::nullopt);
  auto cwndAfterRecovery = cubic.getCongestionWindow();
  EXPECT_EQ(CubicStates::Steady, cubic.state());

  // Now lose packet1, which should be ignored.
  LossEvent loss1;
  loss1.addLostPacket(packet1);
  quic::test::onPacketAckOrLossWrapper(
      &conn, &cubic, std::nullopt, std::move(loss1));
  EXPECT_EQ(CubicStates::Steady, cubic.state());
  EXPECT_EQ(cwndAfterRecovery, cubic.getCongestionWindow());
}

TEST_F(CubicRecoveryTest, LossAfterRecovery) {
  QuicConnectionStateBase conn(QuicNodeType::Client);
  Cubic cubic(conn);

  // Send/ack one packet.
  auto packet = makeTestingWritePacket(0, 1000, 1000);
  quic::test::onPacketsSentWrapper(&conn, &cubic, packet);
  quic::test::onPacketAckOrLossWrapper(
      &conn,
      &cubic,
      makeAck(0, 1000, Clock::now(), packet.metadata.time),
      std::nullopt);
  // Lose one packet.
  auto packet1 = makeTestingWritePacket(1, 1000, 2000);
  quic::test::onPacketsSentWrapper(&conn, &cubic, packet1);
  conn.lossState.largestSent = 1;
  LossEvent loss1;
  loss1.addLostPacket(packet1);
  quic::test::onPacketAckOrLossWrapper(
      &conn, &cubic, std::nullopt, std::move(loss1));
  EXPECT_EQ(CubicStates::FastRecovery, cubic.state());
  auto cwndAfterLoss = cubic.getCongestionWindow();

  // Lose another packet, cwnd should go down.
  auto packet2 = makeTestingWritePacket(2, 1000, 3000);
  quic::test::onPacketsSentWrapper(&conn, &cubic, packet1);
  conn.lossState.largestSent = 2;
  LossEvent loss2;
  loss2.addLostPacket(packet2);
  quic::test::onPacketAckOrLossWrapper(
      &conn, &cubic, std::nullopt, std::move(loss2));
  EXPECT_EQ(CubicStates::FastRecovery, cubic.state());
  EXPECT_TRUE(cwndAfterLoss > cubic.getCongestionWindow());
}

TEST_F(CubicRecoveryTest, AckNotLargestNotChangeCwnd) {
  QuicConnectionStateBase conn(QuicNodeType::Client);
  Cubic cubic(conn);
  auto packet1 = makeTestingWritePacket(0, 1000, 1000);
  auto packet2 = makeTestingWritePacket(1, 1000, 2000);
  auto packet3 = makeTestingWritePacket(2, 1000, 3000);
  auto packet4 = makeTestingWritePacket(3, 1000, 4000);
  auto packet5 = makeTestingWritePacket(4, 1000, 5000);

  LossEvent loss;
  quic::test::onPacketsSentWrapper(&conn, &cubic, packet1);
  quic::test::onPacketsSentWrapper(&conn, &cubic, packet2);
  quic::test::onPacketsSentWrapper(&conn, &cubic, packet3);
  quic::test::onPacketsSentWrapper(&conn, &cubic, packet4);
  quic::test::onPacketsSentWrapper(&conn, &cubic, packet5);
  conn.lossState.largestSent = 4;

  // packet5 is lost:
  loss.addLostPacket(packet5);
  quic::test::onPacketAckOrLossWrapper(
      &conn, &cubic, std::nullopt, std::move(loss));
  EXPECT_EQ(CubicStates::FastRecovery, cubic.state());
  auto cwndAfterLoss = cubic.getWritableBytes() + 4000; // 4k are in flight

  // the the rest are acked:
  quic::test::onPacketAckOrLossWrapper(
      &conn,
      &cubic,
      makeAck(0, 1000, Clock::now(), packet1.metadata.time),
      std::nullopt);
  quic::test::onPacketAckOrLossWrapper(
      &conn,
      &cubic,
      makeAck(1, 1000, Clock::now(), packet2.metadata.time),
      std::nullopt);
  quic::test::onPacketAckOrLossWrapper(
      &conn,
      &cubic,
      makeAck(2, 1000, Clock::now(), packet3.metadata.time),
      std::nullopt);
  quic::test::onPacketAckOrLossWrapper(
      &conn,
      &cubic,
      makeAck(3, 1000, Clock::now(), packet4.metadata.time),
      std::nullopt);

  // Still in recovery:
  EXPECT_EQ(CubicStates::FastRecovery, cubic.state());

  // Cwnd never changed during the whole time, and inflight is 0 at this point:
  EXPECT_EQ(cwndAfterLoss, cubic.getWritableBytes());
}
} // namespace quic::test
