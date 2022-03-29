/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <quic/congestion_control/NewReno.h>

#include <folly/portability/GTest.h>
#include <quic/common/test/TestUtils.h>
#include <quic/fizz/server/handshake/FizzServerQuicHandshakeContext.h>

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
        std::move(packet),
        Clock::now(),
        10,
        0,
        false,
        10,
        0,
        0,
        0,
        LossState(),
        0,
        OutstandingPacketMetadata::DetailsPerStream()));
    loss.lostBytes = packetData.second;
  }
  loss.lostPackets = lostPackets.size();
  return loss;
}

CongestionController::AckEvent createAckEvent(
    PacketNum largestAcked,
    uint64_t ackedSize,
    TimePoint packetSentTime) {
  RegularQuicWritePacket packet(ShortHeader(
      ProtectionType::KeyPhaseZero, getTestConnectionId(), largestAcked));
  auto ackTime = Clock::now();
  auto ack = AckEvent::Builder()
                 .setAckTime(ackTime)
                 .setAdjustedAckTime(ackTime)
                 .setAckDelay(0us)
                 .setPacketNumberSpace(PacketNumberSpace::AppData)
                 .setLargestAckedPacket(largestAcked)
                 .build();
  ack.largestNewlyAckedPacket = largestAcked;
  ack.ackedBytes = ackedSize;
  ack.ackedPackets.push_back(
      makeAckPacketFromOutstandingPacket(OutstandingPacket(
          std::move(packet),
          packetSentTime,
          ackedSize,
          0,
          false,
          ackedSize,
          0,
          0,
          0,
          LossState(),
          0,
          OutstandingPacketMetadata::DetailsPerStream())));
  return ack;
}

OutstandingPacket createPacket(
    PacketNum packetNum,
    uint32_t size,
    TimePoint sendTime,
    uint64_t inflight = 0) {
  auto connId = getTestConnectionId();
  RegularQuicWritePacket packet(
      ShortHeader(ProtectionType::KeyPhaseZero, connId, packetNum));
  return OutstandingPacket(
      std::move(packet),
      sendTime,
      size,
      0,
      false,
      size,
      0,
      inflight,
      0,
      LossState(),
      0,
      OutstandingPacketMetadata::DetailsPerStream());
}

TEST_F(NewRenoTest, TestLoss) {
  QuicServerConnectionState conn(
      FizzServerQuicHandshakeContext::Builder().build());
  NewReno reno(conn);
  EXPECT_TRUE(reno.inSlowStart());

  // Simulate largest sent.
  conn.lossState.largestSent = 5;
  PacketNum loss1 = 5;
  // Lose packet less than previous one now.
  PacketNum loss2 = 3;
  // Lose packet greater than previous loss.
  PacketNum loss3 = 11;
  reno.onPacketSent(createPacket(loss2, 10, Clock::now()));
  reno.onPacketSent(createPacket(loss1, 11, Clock::now()));
  reno.onPacketSent(createPacket(loss3, 20, Clock::now()));
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
  QuicServerConnectionState conn(
      FizzServerQuicHandshakeContext::Builder().build());
  NewReno reno(conn);
  EXPECT_TRUE(reno.inSlowStart());

  PacketNum loss = 10;
  auto originalWritableBytes = reno.getWritableBytes();
  reno.onPacketSent(
      createPacket(loss, originalWritableBytes + 20, Clock::now()));
  EXPECT_EQ(reno.getBytesInFlight(), originalWritableBytes + 20);
  EXPECT_EQ(reno.getWritableBytes(), 0);
  reno.onPacketAckOrLoss(
      folly::none,
      createLossEvent({std::make_pair(loss, originalWritableBytes + 20)}));
  EXPECT_LT(reno.getWritableBytes(), originalWritableBytes);
}

TEST_F(NewRenoTest, TestSlowStartAck) {
  QuicServerConnectionState conn(
      FizzServerQuicHandshakeContext::Builder().build());
  NewReno reno(conn);
  EXPECT_TRUE(reno.inSlowStart());

  auto originalWritableBytes = reno.getWritableBytes();
  PacketNum ackPacketNum1 = 10;
  uint64_t ackedSize = 10;

  auto packet = createPacket(ackPacketNum1, ackedSize, Clock::now());
  reno.onPacketSent(packet);
  EXPECT_EQ(reno.getBytesInFlight(), ackedSize);
  reno.onPacketAckOrLoss(
      createAckEvent(ackPacketNum1, ackedSize, packet.metadata.time),
      folly::none);
  EXPECT_TRUE(reno.inSlowStart());
  auto newWritableBytes = reno.getWritableBytes();

  EXPECT_EQ(newWritableBytes, originalWritableBytes + ackedSize);
}

TEST_F(NewRenoTest, TestSteadyStateAck) {
  QuicServerConnectionState conn(
      FizzServerQuicHandshakeContext::Builder().build());
  NewReno reno(conn);
  EXPECT_TRUE(reno.inSlowStart());

  conn.lossState.largestSent = 5;
  auto originalWritableBytes = reno.getWritableBytes();
  PacketNum loss1 = 4;
  reno.onPacketSent(createPacket(loss1, 10, Clock::now()));
  reno.onPacketAckOrLoss(
      folly::none, createLossEvent({std::make_pair(loss1, 10)}));
  EXPECT_FALSE(reno.inSlowStart());
  auto newWritableBytes1 = reno.getWritableBytes();
  EXPECT_LT(newWritableBytes1, originalWritableBytes);

  PacketNum ackPacketNum1 = 4;
  uint64_t ackedSize = 10;
  auto packet1 = createPacket(
      ackPacketNum1, ackedSize, Clock::now() - std::chrono::milliseconds(10));
  reno.onPacketSent(packet1);
  reno.onPacketAckOrLoss(
      createAckEvent(ackPacketNum1, ackedSize, packet1.metadata.time),
      folly::none);
  EXPECT_FALSE(reno.inSlowStart());

  auto newWritableBytes2 = reno.getWritableBytes();
  EXPECT_EQ(newWritableBytes2, newWritableBytes1);

  PacketNum ackPacketNum2 = 6;
  auto packet2 = createPacket(ackPacketNum2, ackedSize, Clock::now());
  reno.onPacketSent(packet2);
  reno.onPacketAckOrLoss(
      createAckEvent(ackPacketNum2, ackedSize, packet2.metadata.time),
      folly::none);
  EXPECT_FALSE(reno.inSlowStart());

  auto newWritableBytes3 = reno.getWritableBytes();
  EXPECT_EQ(
      newWritableBytes3,
      newWritableBytes2 +
          ((kDefaultUDPSendPacketLen * ackedSize) / newWritableBytes2));
}

TEST_F(NewRenoTest, TestWritableBytes) {
  QuicServerConnectionState conn(
      FizzServerQuicHandshakeContext::Builder().build());
  NewReno reno(conn);
  EXPECT_TRUE(reno.inSlowStart());

  conn.lossState.largestSent = 5;
  PacketNum ackPacketNum = 6;
  uint64_t writableBytes = reno.getWritableBytes();
  reno.onPacketSent(
      createPacket(ackPacketNum, writableBytes - 10, Clock::now()));
  EXPECT_EQ(reno.getWritableBytes(), 10);
  reno.onPacketSent(createPacket(ackPacketNum, 20, Clock::now()));
  EXPECT_EQ(reno.getWritableBytes(), 0);
}

TEST_F(NewRenoTest, PersistentCongestion) {
  QuicServerConnectionState conn(
      FizzServerQuicHandshakeContext::Builder().build());
  NewReno reno(conn);
  EXPECT_TRUE(reno.inSlowStart());

  conn.lossState.largestSent = 5;
  PacketNum ackPacketNum = 6;
  uint32_t ackedSize = 10;
  auto pkt = createPacket(ackPacketNum, ackedSize, Clock::now());
  reno.onPacketSent(pkt);
  CongestionController::LossEvent loss;
  loss.persistentCongestion = true;
  loss.addLostPacket(pkt);
  reno.onPacketAckOrLoss(folly::none, loss);
  EXPECT_EQ(
      reno.getWritableBytes(),
      conn.transportSettings.minCwndInMss * conn.udpSendPacketLen);
  EXPECT_TRUE(reno.inSlowStart());
}

TEST_F(NewRenoTest, RemoveBytesWithoutLossOrAck) {
  QuicServerConnectionState conn(
      FizzServerQuicHandshakeContext::Builder().build());
  NewReno reno(conn);
  EXPECT_TRUE(reno.inSlowStart());

  auto originalWritableBytes = reno.getWritableBytes();
  conn.lossState.largestSent = 5;
  PacketNum ackPacketNum = 6;
  uint32_t ackedSize = 10;
  reno.onPacketSent(createPacket(ackPacketNum, ackedSize, Clock::now()));
  reno.onRemoveBytesFromInflight(2);
  EXPECT_EQ(reno.getWritableBytes(), originalWritableBytes - ackedSize + 2);
}
} // namespace test
} // namespace quic
