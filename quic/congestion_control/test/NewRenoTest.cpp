/*
 * Copyright (c) Facebook, Inc. and its affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 *
 */

#include <quic/congestion_control/NewReno.h>

#include <folly/portability/GTest.h>
#include <quic/common/test/TestUtils.h>

using namespace testing;

namespace quic {
namespace test {

class NewRenoTest : public Test {};

CongestionController::LossEvent createLossEvent(
    std::vector<std::pair<PacketNum, size_t>> lostPackets) {
  CongestionController::LossEvent loss;
  auto connId = getTestConnectionId();
  for (auto packetData : lostPackets) {
    RegularQuicWritePacket packet(
        ShortHeader(ProtectionType::KeyPhaseZero, connId, packetData.first));
    loss.addLostPacket(OutstandingPacket(
        std::move(packet), Clock::now(), 10, false, false, 10));
    loss.lostBytes = packetData.second;
  }
  loss.lostPackets = lostPackets.size();
  return loss;
}

CongestionController::AckEvent createAckEvent(
    PacketNum largestAcked,
    uint64_t ackedSize) {
  CongestionController::AckEvent ack;
  ack.largestAckedPacket = largestAcked;
  ack.ackTime = Clock::now();
  ack.ackedBytes = ackedSize;
  return ack;
}

OutstandingPacket createPacket(PacketNum packetNum, uint32_t size) {
  auto connId = getTestConnectionId();
  RegularQuicWritePacket packet(
      ShortHeader(ProtectionType::KeyPhaseZero, connId, packetNum));
  return OutstandingPacket(
      std::move(packet), Clock::now(), size, false, false, size);
}

TEST_F(NewRenoTest, TestLoss) {
  QuicServerConnectionState conn;
  NewReno reno(conn);
  EXPECT_TRUE(reno.inSlowStart());

  // Simulate largest sent.
  conn.lossState.largestSent = 5;
  PacketNum loss1 = 5;
  // Lose packet less than previous one now.
  PacketNum loss2 = 3;
  // Lose packet greater than previous loss.
  PacketNum loss3 = 11;
  reno.onPacketSent(createPacket(loss2, 10));
  reno.onPacketSent(createPacket(loss1, 11));
  reno.onPacketSent(createPacket(loss3, 20));
  EXPECT_EQ(reno.getBytesInFlight(), 41);
  auto originalWritableBytes = reno.getWritableBytes();

  reno.onPacketAckOrLoss(
      folly::none, createLossEvent({std::make_pair(loss1, 11)}));
  EXPECT_EQ(reno.getBytesInFlight(), 30);

  EXPECT_FALSE(reno.inSlowStart());
  auto newWritableBytes1 = reno.getWritableBytes();
  EXPECT_LE(newWritableBytes1, originalWritableBytes + 11);

  reno.onPacketAckOrLoss(
      folly::none, createLossEvent({std::make_pair(loss2, 10)}));
  auto newWritableBytes2 = reno.getWritableBytes();
  EXPECT_LE(newWritableBytes2, newWritableBytes1 + 10);
  EXPECT_EQ(reno.getBytesInFlight(), 20);

  reno.onPacketAckOrLoss(
      folly::none, createLossEvent({std::make_pair(loss3, 20)}));
  auto newWritableBytes3 = reno.getWritableBytes();
  EXPECT_LE(newWritableBytes3, newWritableBytes2 + 20);
  EXPECT_EQ(reno.getBytesInFlight(), 0);
}

TEST_F(NewRenoTest, SendMoreThanWritable) {
  QuicServerConnectionState conn;
  NewReno reno(conn);
  EXPECT_TRUE(reno.inSlowStart());

  PacketNum loss = 10;
  auto originalWritableBytes = reno.getWritableBytes();
  reno.onPacketSent(createPacket(loss, originalWritableBytes + 20));
  EXPECT_EQ(reno.getBytesInFlight(), originalWritableBytes + 20);
  EXPECT_EQ(reno.getWritableBytes(), 0);
  reno.onPacketAckOrLoss(
      folly::none,
      createLossEvent({std::make_pair(loss, originalWritableBytes + 20)}));
  EXPECT_LT(reno.getWritableBytes(), originalWritableBytes);
}

TEST_F(NewRenoTest, TestSlowStartAck) {
  QuicServerConnectionState conn;
  NewReno reno(conn);
  EXPECT_TRUE(reno.inSlowStart());

  auto originalWritableBytes = reno.getWritableBytes();
  PacketNum ackPacketNum1 = 10;
  uint64_t ackedSize = 10;

  reno.onPacketSent(createPacket(ackPacketNum1, ackedSize));
  EXPECT_EQ(reno.getBytesInFlight(), ackedSize);
  reno.onPacketAckOrLoss(createAckEvent(ackPacketNum1, ackedSize), folly::none);
  EXPECT_TRUE(reno.inSlowStart());
  auto newWritableBytes = reno.getWritableBytes();

  EXPECT_EQ(newWritableBytes, originalWritableBytes + ackedSize);
}

TEST_F(NewRenoTest, TestSteadyStateAck) {
  QuicServerConnectionState conn;
  NewReno reno(conn);
  EXPECT_TRUE(reno.inSlowStart());

  uint64_t inflightBytes = 0;

  conn.lossState.largestSent = 5;
  auto originalWritableBytes = reno.getWritableBytes();
  PacketNum loss1 = 5;
  reno.onPacketSent(createPacket(loss1, 10));
  reno.onPacketAckOrLoss(
      folly::none, createLossEvent({std::make_pair(loss1, 10)}));
  EXPECT_FALSE(reno.inSlowStart());
  auto newWritableBytes1 = reno.getWritableBytes();
  EXPECT_LT(newWritableBytes1, originalWritableBytes);

  PacketNum ackPacketNum1 = 4;
  uint64_t ackedSize = 10;
  inflightBytes += ackedSize;
  reno.onPacketSent(createPacket(ackPacketNum1, ackedSize));
  reno.onPacketAckOrLoss(createAckEvent(ackPacketNum1, ackedSize), folly::none);
  EXPECT_FALSE(reno.inSlowStart());

  auto newWritableBytes2 = reno.getWritableBytes();
  EXPECT_EQ(newWritableBytes2, newWritableBytes1);

  PacketNum ackPacketNum2 = 6;
  reno.onPacketSent(createPacket(ackPacketNum2, ackedSize));
  reno.onPacketAckOrLoss(createAckEvent(ackPacketNum2, ackedSize), folly::none);
  EXPECT_FALSE(reno.inSlowStart());

  auto newWritableBytes3 = reno.getWritableBytes();
  // TODO: see comments in NewReno::onPacketAcked
  EXPECT_EQ(
      newWritableBytes3,
      newWritableBytes2 +
          ((kDefaultUDPSendPacketLen * ackedSize) / newWritableBytes2));
}

TEST_F(NewRenoTest, TestWritableBytes) {
  QuicServerConnectionState conn;
  NewReno reno(conn);
  EXPECT_TRUE(reno.inSlowStart());

  conn.lossState.largestSent = 5;
  PacketNum ackPacketNum = 6;
  uint64_t writableBytes = reno.getWritableBytes();
  reno.onPacketSent(createPacket(ackPacketNum, writableBytes - 10));
  EXPECT_EQ(reno.getWritableBytes(), 10);
  reno.onPacketSent(createPacket(ackPacketNum, 20));
  EXPECT_EQ(reno.getWritableBytes(), 0);
}

TEST_F(NewRenoTest, RTOVerified) {
  QuicServerConnectionState conn;
  NewReno reno(conn);
  EXPECT_TRUE(reno.inSlowStart());

  conn.lossState.largestSent = 5;
  PacketNum ackPacketNum = 6;
  uint32_t ackedSize = 10;
  reno.onPacketSent(createPacket(ackPacketNum, ackedSize));
  reno.onRTOVerified();

  EXPECT_EQ(
      reno.getWritableBytes(),
      conn.transportSettings.minCwndInMss * conn.udpSendPacketLen - ackedSize);
  EXPECT_TRUE(reno.inSlowStart());
}

TEST_F(NewRenoTest, RemoveBytesWithoutLossOrAck) {
  QuicServerConnectionState conn;
  NewReno reno(conn);
  EXPECT_TRUE(reno.inSlowStart());

  auto originalWritableBytes = reno.getWritableBytes();
  conn.lossState.largestSent = 5;
  PacketNum ackPacketNum = 6;
  uint32_t ackedSize = 10;
  reno.onPacketSent(createPacket(ackPacketNum, ackedSize));
  reno.onRemoveBytesFromInflight(2);
  EXPECT_EQ(reno.getWritableBytes(), originalWritableBytes - ackedSize + 2);
}

TEST_F(NewRenoTest, NoLargestAckedPacketNoCrash) {
  QuicServerConnectionState conn;
  NewReno reno(conn);
  CongestionController::LossEvent loss;
  loss.largestLostPacketNum = 0;
  CongestionController::AckEvent ack;
  reno.onPacketAckOrLoss(ack, loss);
}
} // namespace test
} // namespace quic
