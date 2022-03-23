/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <quic/congestion_control/Bbr.h>

#include <folly/portability/GMock.h>
#include <folly/portability/GTest.h>
#include <quic/common/test/TestUtils.h>
#include <quic/congestion_control/StaticCwndCongestionController.h>
#include <quic/congestion_control/test/Mocks.h>
#include <quic/state/test/Mocks.h>

using namespace testing;

namespace quic::test {

class StaticCwndCongestionControllerTest : public Test {};

TEST_F(StaticCwndCongestionControllerTest, Basics) {
  const uint64_t cwndInBytes = 1000;
  StaticCwndCongestionController cca(
      (StaticCwndCongestionController::CwndInBytes(cwndInBytes)));

  EXPECT_EQ(cwndInBytes, cca.getWritableBytes());
  EXPECT_EQ(cwndInBytes, cca.getCongestionWindow());
  EXPECT_EQ(CongestionControlType::StaticCwnd, cca.type());
}

TEST_F(StaticCwndCongestionControllerTest, RemoveBytesFromInflight) {
  const auto pktSeqNum = 1;
  const uint64_t cwndInBytes = 1000;
  const uint64_t bytesSent = 1;

  StaticCwndCongestionController cca(
      (StaticCwndCongestionController::CwndInBytes(cwndInBytes)));
  cca.onPacketSent(makeTestingWritePacket(pktSeqNum, bytesSent, bytesSent));
  EXPECT_EQ(cwndInBytes - bytesSent, cca.getWritableBytes());
  EXPECT_EQ(cwndInBytes, cca.getCongestionWindow());

  // remove the bytes in flight
  cca.onRemoveBytesFromInflight(bytesSent);
  EXPECT_EQ(cwndInBytes, cca.getWritableBytes());
  EXPECT_EQ(cwndInBytes, cca.getCongestionWindow());
}

TEST_F(StaticCwndCongestionControllerTest, RemoveBytesFromInflightFullCwnd) {
  const auto pktSeqNum = 1;
  const uint64_t cwndInBytes = 1000;
  const uint64_t bytesSent = cwndInBytes; // full CWND

  StaticCwndCongestionController cca(
      (StaticCwndCongestionController::CwndInBytes(cwndInBytes)));
  cca.onPacketSent(makeTestingWritePacket(pktSeqNum, bytesSent, bytesSent));
  EXPECT_EQ(0, cca.getWritableBytes());
  EXPECT_EQ(cwndInBytes, cca.getCongestionWindow());

  // remove the bytes in flight
  cca.onRemoveBytesFromInflight(bytesSent);
  EXPECT_EQ(cwndInBytes, cca.getWritableBytes());
  EXPECT_EQ(cwndInBytes, cca.getCongestionWindow());
}

TEST_F(
    StaticCwndCongestionControllerTest,
    RemoveBytesFromInflightAfterOvershoot) {
  const auto pktSeqNum = 1;
  const uint64_t cwndInBytes = 1000;
  const uint64_t bytesSent = cwndInBytes + 1000; // overshoot

  StaticCwndCongestionController cca(
      (StaticCwndCongestionController::CwndInBytes(cwndInBytes)));

  cca.onPacketSent(makeTestingWritePacket(pktSeqNum, bytesSent, bytesSent));
  EXPECT_EQ(0, cca.getWritableBytes());
  EXPECT_EQ(cwndInBytes, cca.getCongestionWindow());

  // remove the bytes in flight
  cca.onRemoveBytesFromInflight(bytesSent);
  EXPECT_EQ(cwndInBytes, cca.getWritableBytes());
  EXPECT_EQ(cwndInBytes, cca.getCongestionWindow());
}

TEST_F(StaticCwndCongestionControllerTest, PacketSentThenAcked) {
  const auto pktSeqNum = 1;
  const uint64_t cwndInBytes = 1000;
  const uint64_t bytesSent = 1;

  StaticCwndCongestionController cca(
      (StaticCwndCongestionController::CwndInBytes(cwndInBytes)));

  cca.onPacketSent(makeTestingWritePacket(pktSeqNum, bytesSent, bytesSent));
  EXPECT_EQ(cwndInBytes - bytesSent, cca.getWritableBytes());
  EXPECT_EQ(cwndInBytes, cca.getCongestionWindow());

  // ack the packet
  const auto ack =
      makeAck(pktSeqNum, bytesSent, Clock::now(), Clock::now() - 5ms);
  cca.onPacketAckOrLoss(&ack, nullptr /* lossEvent */);
  EXPECT_EQ(cwndInBytes, cca.getWritableBytes());
  EXPECT_EQ(cwndInBytes, cca.getCongestionWindow());
}

TEST_F(StaticCwndCongestionControllerTest, PacketSentThenAckedFullCwnd) {
  const auto pktSeqNum = 1;
  const uint64_t cwndInBytes = 1000;
  const uint64_t bytesSent = cwndInBytes; // full CWND

  StaticCwndCongestionController cca(
      (StaticCwndCongestionController::CwndInBytes(cwndInBytes)));

  cca.onPacketSent(makeTestingWritePacket(pktSeqNum, bytesSent, bytesSent));
  EXPECT_EQ(0, cca.getWritableBytes());
  EXPECT_EQ(cwndInBytes, cca.getCongestionWindow());

  // ack the packet
  const auto ack =
      makeAck(pktSeqNum, bytesSent, Clock::now(), Clock::now() - 5ms);
  cca.onPacketAckOrLoss(&ack, nullptr /* lossEvent */);
  EXPECT_EQ(cwndInBytes, cca.getWritableBytes());
  EXPECT_EQ(cwndInBytes, cca.getCongestionWindow());
}

TEST_F(StaticCwndCongestionControllerTest, PacketSentThenAckedOvershoot) {
  const auto pktSeqNum = 1;
  const uint64_t cwndInBytes = 1000;
  const uint64_t bytesSent = cwndInBytes + 1000; // overshoot

  StaticCwndCongestionController cca(
      (StaticCwndCongestionController::CwndInBytes(cwndInBytes)));

  cca.onPacketSent(makeTestingWritePacket(pktSeqNum, bytesSent, bytesSent));
  EXPECT_EQ(0, cca.getWritableBytes());
  EXPECT_EQ(cwndInBytes, cca.getCongestionWindow());

  // ack the packet
  const auto ack =
      makeAck(pktSeqNum, bytesSent, Clock::now(), Clock::now() - 5ms);
  cca.onPacketAckOrLoss(&ack, nullptr /* lossEvent */);
  EXPECT_EQ(cwndInBytes, cca.getWritableBytes());
  EXPECT_EQ(cwndInBytes, cca.getCongestionWindow());
}

TEST_F(StaticCwndCongestionControllerTest, PacketsSentThenAcked) {
  const auto pktSeqNum = 1;
  const uint64_t cwndInBytes = 1000;
  const uint64_t bytesSentPkt1 = 1;
  const uint64_t bytesSentPkt2 = 1;

  StaticCwndCongestionController cca(
      (StaticCwndCongestionController::CwndInBytes(cwndInBytes)));

  cca.onPacketSent(
      makeTestingWritePacket(pktSeqNum, bytesSentPkt1, bytesSentPkt1));
  EXPECT_EQ(cwndInBytes - bytesSentPkt1, cca.getWritableBytes());
  EXPECT_EQ(cwndInBytes, cca.getCongestionWindow());

  cca.onPacketSent(makeTestingWritePacket(
      pktSeqNum, bytesSentPkt2, bytesSentPkt1 + bytesSentPkt2));
  EXPECT_EQ(
      cwndInBytes - bytesSentPkt1 - bytesSentPkt2, cca.getWritableBytes());
  EXPECT_EQ(cwndInBytes, cca.getCongestionWindow());

  // ack pkt1
  const auto ack1 =
      makeAck(pktSeqNum, bytesSentPkt1, Clock::now(), Clock::now() - 5ms);
  cca.onPacketAckOrLoss(&ack1, nullptr /* lossEvent */);
  EXPECT_EQ(cwndInBytes - bytesSentPkt2, cca.getWritableBytes());
  EXPECT_EQ(cwndInBytes, cca.getCongestionWindow());

  // ack pkt2
  const auto ack2 =
      makeAck(pktSeqNum, bytesSentPkt2, Clock::now(), Clock::now() - 5ms);
  cca.onPacketAckOrLoss(&ack2, nullptr /* lossEvent */);
  EXPECT_EQ(cwndInBytes, cca.getWritableBytes());
  EXPECT_EQ(cwndInBytes, cca.getCongestionWindow());
}

TEST_F(StaticCwndCongestionControllerTest, PacketsSentThenAckedOvershoot) {
  const auto pktSeqNum = 1;
  const uint64_t cwndInBytes = 1000;
  const uint64_t bytesSentPkt1 = 1;
  const uint64_t bytesSentPkt2 = cwndInBytes + 1;

  StaticCwndCongestionController cca(
      (StaticCwndCongestionController::CwndInBytes(cwndInBytes)));

  cca.onPacketSent(
      makeTestingWritePacket(pktSeqNum, bytesSentPkt1, bytesSentPkt1));
  EXPECT_EQ(cwndInBytes - bytesSentPkt1, cca.getWritableBytes());
  EXPECT_EQ(cwndInBytes, cca.getCongestionWindow());

  cca.onPacketSent(makeTestingWritePacket(
      pktSeqNum, bytesSentPkt2, bytesSentPkt1 + bytesSentPkt2));
  EXPECT_EQ(0, cca.getWritableBytes());
  EXPECT_EQ(cwndInBytes, cca.getCongestionWindow());

  // ack pkt1
  const auto ack1 =
      makeAck(pktSeqNum, bytesSentPkt1, Clock::now(), Clock::now() - 5ms);
  cca.onPacketAckOrLoss(&ack1, nullptr /* lossEvent */);
  EXPECT_EQ(0, cca.getWritableBytes());
  EXPECT_EQ(cwndInBytes, cca.getCongestionWindow());

  // ack pkt2
  const auto ack2 =
      makeAck(pktSeqNum, bytesSentPkt2, Clock::now(), Clock::now() - 5ms);
  cca.onPacketAckOrLoss(&ack2, nullptr /* lossEvent */);
  EXPECT_EQ(cwndInBytes, cca.getWritableBytes());
  EXPECT_EQ(cwndInBytes, cca.getCongestionWindow());
}

TEST_F(StaticCwndCongestionControllerTest, PacketSentThenLost) {
  const auto pktSeqNum = 1;
  const uint64_t cwndInBytes = 1000;
  const uint64_t bytesSent = 1;

  StaticCwndCongestionController cca(
      (StaticCwndCongestionController::CwndInBytes(cwndInBytes)));

  const auto pkt = makeTestingWritePacket(pktSeqNum, bytesSent, bytesSent);
  cca.onPacketSent(pkt);
  EXPECT_EQ(cwndInBytes - bytesSent, cca.getWritableBytes());
  EXPECT_EQ(cwndInBytes, cca.getCongestionWindow());

  // mark the packet lost
  CongestionController::LossEvent lossEvent;
  lossEvent.addLostPacket(pkt);
  cca.onPacketAckOrLoss(nullptr, &lossEvent);
  EXPECT_EQ(cwndInBytes, cca.getWritableBytes());
  EXPECT_EQ(cwndInBytes, cca.getCongestionWindow());
}

TEST_F(StaticCwndCongestionControllerTest, PacketSentThenLostFullCwnd) {
  const auto pktSeqNum = 1;
  const uint64_t cwndInBytes = 1000;
  const uint64_t bytesSent = cwndInBytes; // full CWND

  StaticCwndCongestionController cca(
      (StaticCwndCongestionController::CwndInBytes(cwndInBytes)));

  const auto pkt = makeTestingWritePacket(pktSeqNum, bytesSent, bytesSent);
  cca.onPacketSent(pkt);
  EXPECT_EQ(0, cca.getWritableBytes());
  EXPECT_EQ(cwndInBytes, cca.getCongestionWindow());

  // mark the packet lost
  CongestionController::LossEvent lossEvent;
  lossEvent.addLostPacket(pkt);
  cca.onPacketAckOrLoss(nullptr, &lossEvent);
  EXPECT_EQ(cwndInBytes, cca.getWritableBytes());
  EXPECT_EQ(cwndInBytes, cca.getCongestionWindow());
}

TEST_F(StaticCwndCongestionControllerTest, PacketSentThenLostOvershoot) {
  const auto pktSeqNum = 1;
  const uint64_t cwndInBytes = 1000;
  const uint64_t bytesSent = cwndInBytes + 1000; // overshoot

  StaticCwndCongestionController cca(
      (StaticCwndCongestionController::CwndInBytes(cwndInBytes)));

  const auto pkt = makeTestingWritePacket(pktSeqNum, bytesSent, bytesSent);
  cca.onPacketSent(pkt);
  EXPECT_EQ(0, cca.getWritableBytes());
  EXPECT_EQ(cwndInBytes, cca.getCongestionWindow());

  // mark the packet lost
  CongestionController::LossEvent lossEvent;
  lossEvent.addLostPacket(pkt);
  cca.onPacketAckOrLoss(nullptr, &lossEvent);
  EXPECT_EQ(cwndInBytes, cca.getWritableBytes());
  EXPECT_EQ(cwndInBytes, cca.getCongestionWindow());
}

TEST_F(StaticCwndCongestionControllerTest, PacketsSentThenLost) {
  const auto pktSeqNum = 1;
  const uint64_t cwndInBytes = 1000;
  const uint64_t bytesSentPkt1 = 1;
  const uint64_t bytesSentPkt2 = 1;

  StaticCwndCongestionController cca(
      (StaticCwndCongestionController::CwndInBytes(cwndInBytes)));

  const auto pkt1 =
      makeTestingWritePacket(pktSeqNum, bytesSentPkt1, bytesSentPkt1);
  cca.onPacketSent(pkt1);
  EXPECT_EQ(cwndInBytes - bytesSentPkt1, cca.getWritableBytes());
  EXPECT_EQ(cwndInBytes, cca.getCongestionWindow());

  const auto pkt2 = makeTestingWritePacket(
      pktSeqNum, bytesSentPkt2, bytesSentPkt1 + bytesSentPkt2);
  cca.onPacketSent(pkt2);
  EXPECT_EQ(
      cwndInBytes - bytesSentPkt1 - bytesSentPkt2, cca.getWritableBytes());
  EXPECT_EQ(cwndInBytes, cca.getCongestionWindow());

  // mark packet1 lost
  {
    CongestionController::LossEvent lossEvent;
    lossEvent.addLostPacket(pkt1);
    cca.onPacketAckOrLoss(nullptr, &lossEvent);
    EXPECT_EQ(cwndInBytes - bytesSentPkt2, cca.getWritableBytes());
    EXPECT_EQ(cwndInBytes, cca.getCongestionWindow());
  }

  // mark packet2 lost
  {
    CongestionController::LossEvent lossEvent;
    lossEvent.addLostPacket(pkt2);
    cca.onPacketAckOrLoss(nullptr, &lossEvent);
    EXPECT_EQ(cwndInBytes, cca.getWritableBytes());
    EXPECT_EQ(cwndInBytes, cca.getCongestionWindow());
  }
}

TEST_F(StaticCwndCongestionControllerTest, PacketsSentThenLostOvershoot) {
  const auto pktSeqNum = 1;
  const uint64_t cwndInBytes = 1000;
  const uint64_t bytesSentPkt1 = 1;
  const uint64_t bytesSentPkt2 = cwndInBytes + 1;

  StaticCwndCongestionController cca(
      (StaticCwndCongestionController::CwndInBytes(cwndInBytes)));

  const auto pkt1 =
      makeTestingWritePacket(pktSeqNum, bytesSentPkt1, bytesSentPkt1);
  cca.onPacketSent(pkt1);
  EXPECT_EQ(cwndInBytes - bytesSentPkt1, cca.getWritableBytes());
  EXPECT_EQ(cwndInBytes, cca.getCongestionWindow());

  const auto pkt2 = makeTestingWritePacket(
      pktSeqNum, bytesSentPkt2, bytesSentPkt1 + bytesSentPkt2);
  cca.onPacketSent(pkt2);
  EXPECT_EQ(0, cca.getWritableBytes());
  EXPECT_EQ(cwndInBytes, cca.getCongestionWindow());

  // mark packet1 lost
  {
    CongestionController::LossEvent lossEvent;
    lossEvent.addLostPacket(pkt1);
    cca.onPacketAckOrLoss(nullptr, &lossEvent);
    EXPECT_EQ(0, cca.getWritableBytes());
    EXPECT_EQ(cwndInBytes, cca.getCongestionWindow());
  }

  // mark packet2 lost
  {
    CongestionController::LossEvent lossEvent;
    lossEvent.addLostPacket(pkt2);
    cca.onPacketAckOrLoss(nullptr, &lossEvent);
    EXPECT_EQ(cwndInBytes, cca.getWritableBytes());
    EXPECT_EQ(cwndInBytes, cca.getCongestionWindow());
  }
}

} // namespace quic::test
