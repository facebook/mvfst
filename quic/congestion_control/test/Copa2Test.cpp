/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <quic/congestion_control/Copa2.h>

#include <folly/portability/GTest.h>
#include <quic/common/test/TestUtils.h>
#include <quic/fizz/server/handshake/FizzServerQuicHandshakeContext.h>
#include <quic/state/test/Mocks.h>

using namespace testing;

namespace quic::test {

class Copa2Test : public Test {
 public:
  OutstandingPacket createPacket(
      PacketNum packetNum,
      uint32_t size,
      uint64_t totalSent,
      uint64_t inflight = 0) {
    auto connId = getTestConnectionId();
    RegularQuicWritePacket packet(
        ShortHeader(ProtectionType::KeyPhaseZero, connId, packetNum));
    return OutstandingPacket(
        std::move(packet),
        Clock::now(),
        size,
        false,
        totalSent,
        inflight,
        0,
        LossState());
  }

  CongestionController::AckEvent createAckEvent(
      PacketNum largestAcked,
      uint64_t ackedSize,
      TimePoint ackTime) {
    auto ackTime = Clock::now();
    auto ackEvent = AckEvent::Builder()
                        .setAckTime(ackTime)
                        .setAdjustedAckTime(ackTime)
                        .setAckDelay(0us)
                        .setImplicit(false)
                        .setPacketNumberSpace(PacketNumberSpace::AppData)
                        .setLargestAckedPacket(largestAcked)
                        .build();
    ack.largestNewlyAckedPacket = largestAcked;
    ack.ackedBytes = ackedSize;
    ack.ackedPackets.push_back(makeAckPacketFromOutstandingPacket(createPacket(
        largestAcked,
        ackedSize,
        ackedSize /* incorrect totalSent but works for this test */)));
    return ack;
  }
};

TEST_F(Copa2Test, TestWritableBytes) {
  QuicServerConnectionState conn(
      FizzServerQuicHandshakeContext::Builder().build());
  Copa2 copa2(conn);
  EXPECT_FALSE(copa2.inLossyMode());
  EXPECT_FALSE(copa2.inProbeRtt());

  conn.lossState.largestSent = 5;
  PacketNum ackPacketNum = 6;
  uint64_t writableBytes = copa2.getWritableBytes();
  copa2.onPacketSent(
      createPacket(ackPacketNum, writableBytes - 10, writableBytes - 10));
  EXPECT_EQ(copa2.getWritableBytes(), 10);
  copa2.onPacketSent(createPacket(ackPacketNum, 20, writableBytes + 10));
  EXPECT_EQ(copa2.getWritableBytes(), 0);
}

TEST_F(Copa2Test, PersistentCongestion) {
  QuicServerConnectionState conn(
      FizzServerQuicHandshakeContext::Builder().build());
  Copa2 copa2(conn);
  auto qLogger = std::make_shared<FileQLogger>(VantagePoint::Client);
  conn.qLogger = qLogger;
  EXPECT_FALSE(copa2.inLossyMode());
  EXPECT_FALSE(copa2.inProbeRtt());

  conn.lossState.largestSent = 5;
  PacketNum ackPacketNum = 6;
  uint32_t ackedSize = 10;
  uint64_t writableBytes = copa2.getWritableBytes();
  auto pkt = createPacket(ackPacketNum, ackedSize, ackedSize);
  copa2.onPacketSent(pkt);
  EXPECT_EQ(copa2.getWritableBytes(), writableBytes - ackedSize);

  CongestionController::LossEvent loss;
  loss.persistentCongestion = true;
  loss.addLostPacket(pkt);
  copa2.onPacketAckOrLoss(folly::none, loss);
  EXPECT_EQ(
      copa2.getCongestionWindow(),
      conn.transportSettings.minCwndInMss * conn.udpSendPacketLen);
  EXPECT_FALSE(copa2.inLossyMode());

  std::vector<int> indices =
      getQLogEventIndices(QLogEventType::CongestionMetricUpdate, qLogger);
  EXPECT_EQ(indices.size(), 3);
  auto tmp = std::move(qLogger->logs[indices[0]]);
  auto event = dynamic_cast<QLogCongestionMetricUpdateEvent*>(tmp.get());
  EXPECT_EQ(event->bytesInFlight, 10);
  EXPECT_EQ(event->currentCwnd, kDefaultCwnd);
  EXPECT_EQ(event->congestionEvent, kCongestionPacketSent);
}

TEST_F(Copa2Test, RemoveBytesWithoutLossOrAck) {
  QuicServerConnectionState conn(
      FizzServerQuicHandshakeContext::Builder().build());
  Copa2 copa2(conn);
  auto qLogger = std::make_shared<FileQLogger>(VantagePoint::Client);
  conn.qLogger = qLogger;

  auto originalWritableBytes = copa2.getWritableBytes();
  conn.lossState.largestSent = 5;
  PacketNum ackPacketNum = 6;
  uint32_t ackedSize = 10;
  copa2.onPacketSent(createPacket(ackPacketNum, ackedSize, ackedSize));
  copa2.onRemoveBytesFromInflight(2);
  EXPECT_EQ(copa2.getWritableBytes(), originalWritableBytes - ackedSize + 2);

  std::vector<int> indices =
      getQLogEventIndices(QLogEventType::CongestionMetricUpdate, qLogger);
  EXPECT_EQ(indices.size(), 2);
  auto tmp = std::move(qLogger->logs[indices[0]]);
  auto event = dynamic_cast<QLogCongestionMetricUpdateEvent*>(tmp.get());
  EXPECT_EQ(event->bytesInFlight, ackedSize);
  EXPECT_EQ(event->currentCwnd, kDefaultCwnd);
  EXPECT_EQ(event->congestionEvent, kCongestionPacketSent);

  auto tmp2 = std::move(qLogger->logs[indices[1]]);
  auto event2 = dynamic_cast<QLogCongestionMetricUpdateEvent*>(tmp2.get());
  EXPECT_EQ(event2->bytesInFlight, ackedSize - 2);
  EXPECT_EQ(event2->currentCwnd, kDefaultCwnd);
  EXPECT_EQ(event2->congestionEvent, kRemoveInflight);
}

TEST_F(Copa2Test, TestBwEstimate) {
  QuicServerConnectionState conn(
      FizzServerQuicHandshakeContext::Builder().build());
  // tests assume we sent at least 10 packets in the initial burst
  Copa2 copa2(conn);
  // initial cwnd = 10 packets
  EXPECT_EQ(
      copa2.getCongestionWindow(),
      conn.transportSettings.initCwndInMss * conn.udpSendPacketLen);

  auto numPacketsInFlight = 0;
  auto packetNumToSend = 1;
  auto packetSize = conn.udpSendPacketLen;
  auto alphaParam = 10;
  auto now = Clock::now();

  uint64_t totalSent = 0;
  // send one cwnd worth packets in a burst
  conn.lossState.lrtt = 100ms;
  while (copa2.getWritableBytes() > 0) {
    totalSent += packetSize;
    copa2.onPacketSent(createPacket(packetNumToSend, packetSize, totalSent));
    numPacketsInFlight++;
    EXPECT_EQ(copa2.getBytesInFlight(), numPacketsInFlight * packetSize);
  }

  // You get the ack for the first 5 packets after 100ms all at once
  conn.lossState.lrtt = 100ms;
  now += 100ms;
  copa2.onPacketAckOrLoss(createAckEvent(5, 5 * packetSize, now), folly::none);
  numPacketsInFlight -= 5;
  EXPECT_EQ(copa2.getBytesInFlight(), numPacketsInFlight * packetSize);
  // Not enough time has passed for cwnd to increase
  EXPECT_EQ(
      copa2.getCongestionWindow(),
      conn.transportSettings.initCwndInMss * conn.udpSendPacketLen);

  // We get one packet 210ms after that. Now cwnd will be updated
  now += 210ms;
  conn.lossState.lrtt = 500ms; // Large value should be ignored since
                               // only the min rtt should matter.
  copa2.onPacketAckOrLoss(createAckEvent(1, packetSize, now), folly::none);
  EXPECT_EQ(
      copa2.getCongestionWindow(), (6 + alphaParam) * conn.udpSendPacketLen);
  EXPECT_FALSE(copa2.inLossyMode());
  EXPECT_FALSE(copa2.inProbeRtt());
}

TEST_F(Copa2Test, NoLargestAckedPacketNoCrash) {
  QuicServerConnectionState conn(
      FizzServerQuicHandshakeContext::Builder().build());
  Copa2 copa2(conn);
  auto qLogger = std::make_shared<FileQLogger>(VantagePoint::Client);
  conn.qLogger = qLogger;
  CongestionController::LossEvent loss;
  loss.largestLostPacketNum = 0;
  CongestionController::AckEvent ack;
  copa2.onPacketAckOrLoss(ack, loss);

  std::vector<int> indices =
      getQLogEventIndices(QLogEventType::CongestionMetricUpdate, qLogger);
  EXPECT_EQ(indices.size(), 1);
  auto tmp = std::move(qLogger->logs[indices[0]]);
  auto event = dynamic_cast<QLogCongestionMetricUpdateEvent*>(tmp.get());
  EXPECT_EQ(event->bytesInFlight, copa2.getBytesInFlight());
  EXPECT_EQ(event->currentCwnd, kDefaultCwnd);
  EXPECT_EQ(event->congestionEvent, kCongestionPacketLoss);
}

TEST_F(Copa2Test, PacketLossInvokesPacer) {
  QuicServerConnectionState conn(
      FizzServerQuicHandshakeContext::Builder().build());
  Copa2 copa2(conn);
  auto mockPacer = std::make_unique<MockPacer>();
  auto rawPacer = mockPacer.get();
  conn.pacer = std::move(mockPacer);
  auto packet = createPacket(0, 1000, 1000);
  copa2.onPacketSent(packet);
  EXPECT_CALL(*rawPacer, onPacketsLoss()).Times(1);
  CongestionController::LossEvent lossEvent;
  lossEvent.addLostPacket(packet);
  copa2.onPacketAckOrLoss(folly::none, lossEvent);
  // Ack one packet to test how we set pacing rate
  copa2.onPacketSent(createPacket(1, 1000, 2000));
  copa2.onPacketAckOrLoss(createAckEvent(1, 1000, Clock::now()), folly::none);
}

TEST_F(Copa2Test, ProbeRttHappens) {
  QuicServerConnectionState conn(
      FizzServerQuicHandshakeContext::Builder().build());
  conn.transportSettings.initCwndInMss = 10;
  Copa2 copa2(conn);
  auto now = Clock::now();
  auto packetSize = conn.udpSendPacketLen;
  uint64_t totalSent = 0;
  auto packetNumToSend = 1;
  conn.lossState.lrtt = 100ms;
  while (copa2.getWritableBytes() > 0) {
    totalSent += packetSize;
    copa2.onPacketSent(createPacket(packetNumToSend, packetSize, totalSent));
  }

  now += 10ms;
  // Set the min rtt
  conn.lossState.lrtt = 100ms;
  copa2.onPacketAckOrLoss(createAckEvent(1, packetSize, now), folly::none);
  EXPECT_FALSE(copa2.inProbeRtt());

  now += kCopa2ProbeRttInterval / 2;
  conn.lossState.lrtt = 250ms;
  copa2.onPacketAckOrLoss(createAckEvent(1, packetSize, now), folly::none);
  EXPECT_FALSE(copa2.inProbeRtt());

  now += kCopa2ProbeRttInterval / 2;
  copa2.onPacketAckOrLoss(createAckEvent(1, packetSize, now), folly::none);
  EXPECT_TRUE(copa2.inProbeRtt());

  conn.lossState.lrtt = 150ms;
  now += kCopa2ProbeRttInterval / 2 - 50ms;
  copa2.onPacketAckOrLoss(createAckEvent(1, packetSize, now), folly::none);
  EXPECT_FALSE(copa2.inProbeRtt());

  // If delay is small enough, it will enter probe rtt after half the usual
  // period
  conn.lossState.lrtt = 150ms;
  now += 100ms;
  copa2.onPacketAckOrLoss(createAckEvent(1, packetSize, now), folly::none);
  EXPECT_TRUE(copa2.inProbeRtt());
}

TEST_F(Copa2Test, LossModeHappens) {
  QuicServerConnectionState conn(
      FizzServerQuicHandshakeContext::Builder().build());
  // Tests assume lossToleranceParam = 0.05;
  auto alphaParam = 10;
  conn.transportSettings.initCwndInMss = 10;

  Copa2 copa2(conn);
  auto now = Clock::now();
  auto packetSize = conn.udpSendPacketLen;
  uint64_t totalSent = 0;
  auto packetNumToSend = 1;
  conn.lossState.lrtt = 10ms;
  while (copa2.getWritableBytes() > 0) {
    totalSent += packetSize;
    copa2.onPacketSent(createPacket(packetNumToSend, packetSize, totalSent));
    packetNumToSend += 1;
  }

  // You get ack for the first 8 packets all at once and then 1 loss
  // followed by another loss. We should not shift to loss mode in the
  // first one but we should in the second one.
  CongestionController::LossEvent loss;
  loss.largestLostPacketNum = 9;
  loss.lostBytes = 1 * packetSize;
  loss.persistentCongestion = false;
  loss.lostPackets = 1;
  loss.largestLostSentTime = now;
  // Start the cycle
  copa2.onPacketAckOrLoss(createAckEvent(1, packetSize, now), folly::none);
  now += 21ms;
  // End it
  copa2.onPacketAckOrLoss(createAckEvent(8, 7 * packetSize, now), loss);
  EXPECT_FALSE(copa2.inLossyMode());
  EXPECT_EQ(
      copa2.getCongestionWindow(), (8 + alphaParam) * conn.udpSendPacketLen);

  // Should shift to loss mode now
  loss.largestLostPacketNum = 10;
  copa2.onPacketAckOrLoss(folly::none, loss);
  EXPECT_TRUE(copa2.inLossyMode());

  // Send the next cycle and ensure that we are sending fewer packets
  // as appropriate in lossy mode
  totalSent += packetSize;
  copa2.onPacketSent(createPacket(packetNumToSend, packetSize, totalSent));

  // Ack it at 10ms + 10ms * 2 * lossToleranceParam + 1ms
  now += 12ms;
  copa2.onPacketAckOrLoss(createAckEvent(1, packetSize, now), folly::none);
  EXPECT_EQ(
      copa2.getCongestionWindow(),
      packetSize + alphaParam * conn.udpSendPacketLen);
}

} // namespace quic::test
