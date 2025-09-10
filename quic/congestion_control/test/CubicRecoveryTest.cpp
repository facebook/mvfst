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

class CubicRecoveryTest : public Test {};

TEST_F(CubicRecoveryTest, LossBurst) {
  QuicConnectionStateBase conn(QuicNodeType::Client);
  Cubic cubic(conn);
  uint64_t totalSent = 0;
  auto packet0 = makeTestingWritePacket(0, 1000, 1000 + totalSent);
  // Send and loss immediately
  quic::test::onPacketsSentWrapper(&conn, &cubic, packet0);
  totalSent += 1000;
  CongestionController::LossEvent loss;
  loss.addLostPacket(packet0);
  quic::test::onPacketAckOrLossWrapper(
      &conn, &cubic, std::nullopt, std::move(loss));
  EXPECT_EQ(CubicStates::FastRecovery, cubic.state());
  auto cwndAfterLoss = cubic.getCongestionWindow();

  // Then lose a few more:
  CongestionController::LossEvent loss2;
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
  CongestionController::LossEvent loss2;
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
  CongestionController::LossEvent loss1;
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
  CongestionController::LossEvent loss1;
  loss1.addLostPacket(packet1);
  quic::test::onPacketAckOrLossWrapper(
      &conn, &cubic, std::nullopt, std::move(loss1));
  EXPECT_EQ(CubicStates::FastRecovery, cubic.state());
  auto cwndAfterLoss = cubic.getCongestionWindow();

  // Lose another packet, cwnd should go down.
  auto packet2 = makeTestingWritePacket(2, 1000, 3000);
  quic::test::onPacketsSentWrapper(&conn, &cubic, packet1);
  conn.lossState.largestSent = 2;
  CongestionController::LossEvent loss2;
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

  CongestionController::LossEvent loss;
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
