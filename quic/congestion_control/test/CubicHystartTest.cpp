/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <folly/portability/GTest.h>
#include <quic/common/test/TestUtils.h>
#include <quic/congestion_control/QuicCubic.h>

using namespace testing;

namespace quic {
namespace test {

class CubicHystartTest : public Test {};

TEST_F(CubicHystartTest, SendAndAck) {
  QuicConnectionStateBase conn(QuicNodeType::Client);
  conn.udpSendPacketLen = 100;
  Cubic cubic(conn);
  auto initCwnd = cubic.getWritableBytes();
  // Packet 0 is sent:
  conn.lossState.largestSent = 0;

  // Packet 0 is acked:
  conn.lossState.lrtt = 100us;
  auto packet = makeTestingWritePacket(0, 1000, 1000);
  cubic.onPacketSent(packet);
  cubic.onPacketAckOrLoss(
      makeAck(0, 1000, Clock::now(), packet.metadata.time), folly::none);

  EXPECT_EQ(initCwnd + 1000, cubic.getWritableBytes());
  EXPECT_EQ(CubicStates::Hystart, cubic.state());
}

TEST_F(CubicHystartTest, CwndLargerThanSSThresh) {
  QuicConnectionStateBase conn(QuicNodeType::Client);
  Cubic cubic(conn, 0, 0);
  auto initCwnd = cubic.getWritableBytes();
  // Packet 0 is sent:
  conn.lossState.largestSent = 0;

  // Packet 0 is acked:
  auto packet = makeTestingWritePacket(0, 1000, 1000);
  cubic.onPacketSent(packet);
  cubic.onPacketAckOrLoss(
      makeAck(0, 1000, Clock::now(), packet.metadata.time), folly::none);
  EXPECT_EQ(initCwnd + 1000, cubic.getWritableBytes());
  EXPECT_EQ(CubicStates::Steady, cubic.state());
}

TEST_F(CubicHystartTest, NoDelayIncrease) {
  QuicConnectionStateBase conn(QuicNodeType::Client);
  conn.udpSendPacketLen = 100;
  Cubic cubic(conn);
  auto initCwnd = cubic.getWritableBytes();
  // Packet 0 is sent:
  conn.lossState.largestSent = 0;

  // Packet 0 is acked:
  conn.lossState.lrtt = 2us;
  auto realNow = quic::Clock::now();
  // One onPacketAcked will not trigger DelayIncrease
  auto packet = makeTestingWritePacket(0, 1000, 1000, realNow);
  cubic.onPacketSent(packet);
  cubic.onPacketAckOrLoss(
      makeAck(0, 1000, realNow + 2us, packet.metadata.time), folly::none);
  EXPECT_EQ(initCwnd + 1000, cubic.getWritableBytes());
  EXPECT_EQ(CubicStates::Hystart, cubic.state());
}

TEST_F(CubicHystartTest, AckTrain) {
  QuicConnectionStateBase conn(QuicNodeType::Client);
  Cubic cubic(conn, 0, std::numeric_limits<uint64_t>::max(), true, true);
  auto initCwnd = cubic.getWritableBytes();
  // lrtt will be assigned to delayMin:
  conn.lossState.lrtt = 2us;
  auto realNow = quic::Clock::now();
  conn.lossState.largestSent = 0;
  // Packet 0 is sent:
  auto packetSize = kLowSsthreshInMss * conn.udpSendPacketLen;
  auto packet0 = makeTestingWritePacket(
      0, packetSize, packetSize, realNow - std::chrono::milliseconds(10));
  cubic.onPacketSent(packet0);
  // Packet 1 is sent:
  auto packet1 = makeTestingWritePacket(
      1, packetSize, packetSize * 2, realNow - std::chrono::milliseconds(5));
  cubic.onPacketSent(packet1);
  // Packet 0 is acked:
  cubic.onPacketAckOrLoss(
      makeAck(
          0,
          kLowSsthreshInMss * conn.udpSendPacketLen,
          realNow,
          packet0.metadata.time),
      folly::none);
  // Packet 1 is acked:
  cubic.onPacketAckOrLoss(
      makeAck(
          1,
          kLowSsthreshInMss * conn.udpSendPacketLen,
          realNow + 2us,
          packet1.metadata.time),
      folly::none);
  EXPECT_EQ(
      initCwnd + kLowSsthreshInMss * conn.udpSendPacketLen * 2,
      cubic.getWritableBytes());
  EXPECT_EQ(CubicStates::Steady, cubic.state());
}

TEST_F(CubicHystartTest, NoAckTrainNoDelayIncrease) {
  QuicConnectionStateBase conn(QuicNodeType::Client);
  Cubic cubic(conn, 0, std::numeric_limits<uint64_t>::max(), true, true);
  auto initCwnd = cubic.getWritableBytes();
  // Packet 0 is sent:
  conn.lossState.largestSent = 0;

  // Packet 0 is acked:
  // make sure AckTrain won't find it
  conn.lossState.lrtt = 10ms;
  auto realNow = quic::Clock::now();
  // One onPacketAcked will not trigger DelayIncrease
  auto packet = makeTestingWritePacket(0, 1000, 1000, realNow);
  cubic.onPacketSent(packet);
  cubic.onPacketAckOrLoss(
      makeAck(0, 1000, realNow + kAckCountingGap + 2us, packet.metadata.time),
      folly::none);
  EXPECT_EQ(initCwnd + 1000, cubic.getWritableBytes());
  EXPECT_EQ(CubicStates::Hystart, cubic.state());
}

TEST_F(CubicHystartTest, DelayIncrease) {
  QuicConnectionStateBase conn(QuicNodeType::Client);
  Cubic cubic(conn);
  PacketNum packetNum = 0;
  // get kLowSsthresh out of the way for exit condition
  uint64_t totalSent = 0;
  while (cubic.getWritableBytes() <=
         kLowSsthreshInMss * conn.udpSendPacketLen) {
    auto fullSize = cubic.getWritableBytes();
    auto packet =
        makeTestingWritePacket(packetNum, fullSize, fullSize + totalSent);
    cubic.onPacketSent(packet);
    cubic.onPacketAckOrLoss(
        makeAck(packetNum++, fullSize, Clock::now(), packet.metadata.time),
        folly::none);
    totalSent += fullSize;
  }

  auto packetsSentTime = Clock::now();
  auto firstPacketNum = packetNum++;
  auto packet0 = makeTestingWritePacket(
      packetNum, 1000, totalSent + 1000, packetsSentTime);
  totalSent += 1000;
  conn.lossState.largestSent = firstPacketNum;
  cubic.onPacketSent(packet0);

  auto secondPacketNum = packetNum++;
  auto packet1 = makeTestingWritePacket(
      secondPacketNum, 1000, totalSent + 1000, packetsSentTime);
  totalSent += 1000;
  // Packet 1 is sent:
  conn.lossState.largestSent = secondPacketNum;
  cubic.onPacketSent(packet1);

  conn.lossState.lrtt = 10ms;

  // First onPacketAcked will set up lastSampledRtt = 20ms for next round. It
  // will also set up rttRoundEndTarget = 1 since largestSent = 1.
  auto ackTime = packetsSentTime + 1us;
  auto ackTimeIncrease = 2ms;
  ackTime += ackTimeIncrease;
  cubic.onPacketAckOrLoss(
      makeAck(firstPacketNum, 1000, ackTime, packet0.metadata.time),
      folly::none);
  ackTime += ackTimeIncrease;
  cubic.onPacketAckOrLoss(
      makeAck(secondPacketNum, 1000, ackTime, packet1.metadata.time),
      folly::none);
  auto estimatedRttEndTarget = Clock::now();

  auto packet2 = makeTestingWritePacket(
      packetNum, 1000, totalSent + 1000, estimatedRttEndTarget + 1us);
  totalSent += 1000;
  conn.lossState.largestSent = packetNum;
  cubic.onPacketSent(packet2);
  // This will end current RTT round and start a new one next time Ack happens:
  ackTime = packet2.metadata.time + ackTimeIncrease;
  cubic.onPacketAckOrLoss(
      makeAck(packetNum, 1000, ackTime, packet2.metadata.time), folly::none);
  packetNum++;
  auto cwndEndRound = cubic.getWritableBytes();

  // New RTT round, give currSampledRtt a value larger than previous RTT:
  conn.lossState.lrtt = 20ms;
  // onPacketAcked kAckSampling - 1 times:
  std::vector<CongestionController::AckEvent> moreAcks;
  for (size_t i = 0; i < kAckSampling - 1; i++) {
    conn.lossState.largestSent = i + packetNum;
    auto packet = makeTestingWritePacket(
        i + packetNum, 1000, totalSent + 1000, packetsSentTime);
    cubic.onPacketSent(packet);
    totalSent += 1000;
    ackTime += ackTimeIncrease;
    moreAcks.push_back(
        makeAck(1 + packetNum, 1000, ackTime, packet.metadata.time));
    packetNum++;
  }
  for (auto& ack : moreAcks) {
    cubic.onPacketAckOrLoss(ack, folly::none);
  }
  // kAckSampling-th onPacketAcked in this round. This will trigger
  // DelayIncrease:
  conn.lossState.largestSent = packetNum;
  auto packetEnd = makeTestingWritePacket(
      packetNum, 1000, totalSent + 1000, packetsSentTime);
  cubic.onPacketSent(packetEnd);
  totalSent += 1000;
  ackTime += ackTimeIncrease;
  cubic.onPacketAckOrLoss(
      makeAck(packetNum, 1000, ackTime, packetEnd.metadata.time), folly::none);

  EXPECT_EQ(cwndEndRound + 1000 * kAckSampling, cubic.getWritableBytes());
  EXPECT_EQ(CubicStates::Steady, cubic.state());
}

TEST_F(CubicHystartTest, DelayIncreaseCwndTooSmall) {
  QuicConnectionStateBase conn(QuicNodeType::Client);
  Cubic cubic(conn);
  auto realNow = quic::Clock::now();

  uint64_t totalSent = 0;
  auto packet0 = makeTestingWritePacket(0, 1, totalSent + 1, realNow);
  // Packet 0 is sent:
  conn.lossState.largestSent = 0;
  cubic.onPacketSent(packet0);
  totalSent += 1;

  auto packet1 = makeTestingWritePacket(1, 1, totalSent + 1, realNow);
  conn.lossState.largestSent = 1;
  cubic.onPacketSent(packet1);
  totalSent += 1;

  conn.lossState.lrtt = 100us;

  // First onPacketAcked will set up lastSampledRtt = 200us for next round:
  auto ackTime = realNow;
  auto ackTimeIncrease = 2us;
  ackTime += ackTimeIncrease;
  cubic.onPacketAckOrLoss(
      makeAck(0, 1, ackTime, packet0.metadata.time), folly::none);
  ackTime += ackTimeIncrease;
  cubic.onPacketAckOrLoss(
      makeAck(1, 1, ackTime, packet1.metadata.time), folly::none);

  auto packet2 = makeTestingWritePacket(2, 10, 10 + totalSent, realNow);
  conn.lossState.largestSent = 2;
  cubic.onPacketSent(packet2);
  totalSent += 10;
  ackTime += ackTimeIncrease;
  cubic.onPacketAckOrLoss(
      makeAck(2, 1, ackTime, packet2.metadata.time), folly::none);
  auto cwndEndRound = cubic.getWritableBytes();

  // New RTT round, give currSampledRtt a value larger than previous RTT:
  conn.lossState.lrtt = 200us;
  // onPacketAcked kAckSampling - 1 times:
  std::vector<CongestionController::AckEvent> moreAcks;
  for (size_t i = 0; i < kAckSampling - 1; i++) {
    conn.lossState.largestSent = i + 3;
    auto packet = makeTestingWritePacket(i + 3, 1, 1 + totalSent, realNow);
    ackTime += ackTimeIncrease;
    moreAcks.push_back(makeAck(i + 3, 1, ackTime, packet.metadata.time));
    cubic.onPacketSent(packet);
    totalSent += 1;
  }
  for (auto& ack : moreAcks) {
    cubic.onPacketAckOrLoss(ack, folly::none);
  }
  // kAckSampling-th onPacketAcked in this round. This will trigger
  // DelayIncrease:
  conn.lossState.largestSent = kAckSampling;
  auto packetEnd =
      makeTestingWritePacket(kAckSampling, 1, 1 + totalSent, realNow);
  cubic.onPacketSent(packetEnd);
  totalSent += 1;
  ackTime += ackTimeIncrease;
  cubic.onPacketAckOrLoss(
      makeAck(kAckSampling, 1, ackTime, packetEnd.metadata.time), folly::none);
  auto expectedCwnd = cwndEndRound + 1 * kAckSampling;
  // Cwnd < kLowSsthresh, won't exit Hystart state:
  ASSERT_LT(expectedCwnd, kLowSsthreshInMss * conn.udpSendPacketLen);
  EXPECT_EQ(expectedCwnd, cubic.getWritableBytes());
  EXPECT_EQ(CubicStates::Hystart, cubic.state());
}

TEST_F(CubicHystartTest, ReduceByCubicReductionFactor) {
  QuicConnectionStateBase conn(QuicNodeType::Client);
  Cubic cubic(conn, 0, std::numeric_limits<uint64_t>::max());
  auto initCwnd = cubic.getWritableBytes();
  conn.lossState.largestSent = 0;
  auto packet = makeTestingWritePacket(0, 1000, 1000);
  // this increases inflight by 1000:
  cubic.onPacketSent(packet);
  EXPECT_EQ(initCwnd - 1000, cubic.getWritableBytes());
  // this decreases inflight by 1000, and then decreases cwnd by Cubic:
  CongestionController::LossEvent loss;
  loss.addLostPacket(packet);
  cubic.onPacketAckOrLoss(folly::none, std::move(loss));
  EXPECT_EQ(initCwnd * kDefaultCubicReductionFactor, cubic.getWritableBytes());
  EXPECT_EQ(CubicStates::FastRecovery, cubic.state());
}
} // namespace test
} // namespace quic
