/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <quic/congestion_control/Copa.h>

#include <folly/portability/GTest.h>
#include <quic/common/test/TestUtils.h>
#include <quic/fizz/server/handshake/FizzServerQuicHandshakeContext.h>
#include <quic/state/test/Mocks.h>

using namespace testing;

namespace quic {
namespace test {

// TODO: Add UT for different latency factor values
class CopaTest : public Test {
 public:
  CongestionController::LossEvent createLossEvent(
      std::vector<std::pair<PacketNum, size_t>> lostPackets) {
    CongestionController::LossEvent loss;
    auto connId = getTestConnectionId();
    uint64_t totalSentBytes = 0;
    for (auto packetData : lostPackets) {
      RegularQuicWritePacket packet(
          ShortHeader(ProtectionType::KeyPhaseZero, connId, packetData.first));
      totalSentBytes += 10;
      loss.addLostPacket(OutstandingPacketWrapper(
          std::move(packet),
          Clock::now(),
          10,
          0,
          false,
          totalSentBytes,
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

  OutstandingPacketWrapper createPacket(
      PacketNum packetNum,
      uint32_t size,
      uint64_t totalSent,
      uint64_t inflight = 0) {
    auto connId = getTestConnectionId();
    RegularQuicWritePacket packet(
        ShortHeader(ProtectionType::KeyPhaseZero, connId, packetNum));
    return OutstandingPacketWrapper(
        std::move(packet),
        Clock::now(),
        size,
        0,
        false,
        totalSent,
        0,
        inflight,
        0,
        LossState(),
        0,
        OutstandingPacketMetadata::DetailsPerStream());
  }

  CongestionController::AckEvent createAckEvent(
      PacketNum largestAcked,
      uint64_t ackedSize,
      TimePoint ackTime) {
    auto ack = AckEvent::Builder()
                   .setAckTime(ackTime)
                   .setAdjustedAckTime(ackTime)
                   .setAckDelay(0us)
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

  uint64_t cwndChangeSteadyState(
      uint64_t lastCwndBytes,
      uint64_t velocity,
      uint64_t packetSize,
      double deltaParam,
      QuicServerConnectionState& conn) {
    return 1.0 * packetSize * conn.udpSendPacketLen * velocity /
        (deltaParam * lastCwndBytes);
  }

  uint64_t
  exitSlowStart(Copa& copa, QuicServerConnectionState& conn, TimePoint& now) {
    auto numPacketsInFlight = 0;
    auto packetNumToSend = 1;
    auto packetSize = conn.udpSendPacketLen;

    EXPECT_TRUE(copa.inSlowStart());
    // send one cwnd worth packets in a burst
    auto totalSent = 0;
    while (copa.getWritableBytes() > 0) {
      totalSent += packetSize;
      copa.onPacketSent(createPacket(packetNumToSend, packetSize, totalSent));
      numPacketsInFlight++;
      EXPECT_EQ(copa.getBytesInFlight(), numPacketsInFlight * packetSize);
    }

    // Say you get ack for first packet after 50 ms
    now += 50ms;
    auto packetNumToAck = 1;
    // update rtt measurements
    conn.lossState.lrtt = 50ms;
    // Rttmin = 50ms
    conn.lossState.srtt = 50ms;

    // ack for first packet, lastCwndDoubleTime_ will be initialized now
    copa.onPacketAckOrLoss(
        createAckEvent(packetNumToAck, packetSize, now), folly::none);
    numPacketsInFlight--;
    EXPECT_EQ(copa.getBytesInFlight(), numPacketsInFlight * packetSize);

    now += 110ms;
    packetNumToAck++;

    EXPECT_TRUE(copa.inSlowStart());

    auto lastCwnd = copa.getCongestionWindow();
    // ack second packet
    // Since now - first_ack_time > srtt, rttStanding includes only the latest
    // measurement
    // update rtt measurements, current rate > target rate at this point, so it
    // exits slow start
    // target rate = 20 packets per sec, current rate = 10 packets / 100ms = 50
    // packets per second
    conn.lossState.lrtt = 150ms;
    // Rttmin = 50ms
    conn.lossState.srtt = 100ms;

    copa.onPacketAckOrLoss(
        createAckEvent(packetNumToAck, packetSize, now), folly::none);
    packetNumToAck++;
    EXPECT_FALSE(copa.inSlowStart());
    uint64_t cwndChange =
        cwndChangeSteadyState(lastCwnd, 1.0, packetSize, 0.5, conn);
    // cwnd = 10 - 1 / (0.5 * 10) = 9.8 packets
    EXPECT_EQ(copa.getCongestionWindow(), lastCwnd - cwndChange);
    return copa.getCongestionWindow();
  }
};

TEST_F(CopaTest, TestWritableBytes) {
  QuicServerConnectionState conn(
      FizzServerQuicHandshakeContext::Builder().build());
  conn.transportSettings.copaDeltaParam = 0.5;
  conn.transportSettings.copaUseRttStanding = true;
  Copa copa(conn);
  EXPECT_TRUE(copa.inSlowStart());

  conn.lossState.largestSent = 5;
  PacketNum ackPacketNum = 6;
  uint64_t writableBytes = copa.getWritableBytes();
  copa.onPacketSent(
      createPacket(ackPacketNum, writableBytes - 10, writableBytes - 10));
  EXPECT_EQ(copa.getWritableBytes(), 10);
  copa.onPacketSent(createPacket(ackPacketNum, 20, writableBytes + 10));
  EXPECT_EQ(copa.getWritableBytes(), 0);
}

TEST_F(CopaTest, PersistentCongestion) {
  QuicServerConnectionState conn(
      FizzServerQuicHandshakeContext::Builder().build());
  conn.transportSettings.copaDeltaParam = 0.5;
  conn.transportSettings.copaUseRttStanding = true;
  Copa copa(conn);
  auto qLogger = std::make_shared<FileQLogger>(VantagePoint::Client);
  conn.qLogger = qLogger;
  EXPECT_TRUE(copa.inSlowStart());

  conn.lossState.largestSent = 5;
  PacketNum ackPacketNum = 6;
  uint32_t ackedSize = 10;
  auto pkt = createPacket(ackPacketNum, ackedSize, ackedSize);
  copa.onPacketSent(pkt);

  std::vector<int> indices =
      getQLogEventIndices(QLogEventType::CongestionMetricUpdate, qLogger);
  EXPECT_EQ(indices.size(), 1);
  auto tmp = std::move(qLogger->logs[indices[0]]);
  auto event = dynamic_cast<QLogCongestionMetricUpdateEvent*>(tmp.get());
  EXPECT_EQ(event->bytesInFlight, 10);
  EXPECT_EQ(event->currentCwnd, kDefaultCwnd);
  EXPECT_EQ(event->congestionEvent, kCongestionPacketSent);

  CongestionController::LossEvent loss;
  loss.persistentCongestion = true;
  loss.addLostPacket(pkt);
  copa.onPacketAckOrLoss(folly::none, loss);
  EXPECT_EQ(
      copa.getWritableBytes(),
      conn.transportSettings.minCwndInMss * conn.udpSendPacketLen);
  EXPECT_TRUE(copa.inSlowStart());
}

TEST_F(CopaTest, RemoveBytesWithoutLossOrAck) {
  QuicServerConnectionState conn(
      FizzServerQuicHandshakeContext::Builder().build());
  conn.transportSettings.copaDeltaParam = 0.5;
  conn.transportSettings.copaUseRttStanding = true;
  Copa copa(conn);
  auto qLogger = std::make_shared<FileQLogger>(VantagePoint::Client);
  conn.qLogger = qLogger;
  EXPECT_TRUE(copa.inSlowStart());

  auto originalWritableBytes = copa.getWritableBytes();
  conn.lossState.largestSent = 5;
  PacketNum ackPacketNum = 6;
  uint32_t ackedSize = 10;
  copa.onPacketSent(createPacket(ackPacketNum, ackedSize, ackedSize));
  copa.onRemoveBytesFromInflight(2);
  EXPECT_EQ(copa.getWritableBytes(), originalWritableBytes - ackedSize + 2);

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

TEST_F(CopaTest, TestSlowStartAck) {
  QuicServerConnectionState conn(
      FizzServerQuicHandshakeContext::Builder().build());
  conn.transportSettings.copaDeltaParam = 0.5;
  // tests assume we sent at least 10 packets in the initial burst
  conn.transportSettings.initCwndInMss = 10;
  conn.transportSettings.copaUseRttStanding = true;
  Copa copa(conn);
  auto qLogger = std::make_shared<FileQLogger>(VantagePoint::Client);
  conn.qLogger = qLogger;
  EXPECT_TRUE(copa.inSlowStart());
  // initial cwnd = 10 packets
  EXPECT_EQ(
      copa.getCongestionWindow(),
      conn.transportSettings.initCwndInMss * conn.udpSendPacketLen);

  auto numPacketsInFlight = 0;
  auto packetNumToSend = 1;
  auto packetSize = conn.udpSendPacketLen;
  auto now = Clock::now();

  uint64_t totalSent = 0;
  // send one cwnd worth packets in a burst
  while (copa.getWritableBytes() > 0) {
    totalSent += packetSize;
    copa.onPacketSent(createPacket(packetNumToSend, packetSize, totalSent));
    numPacketsInFlight++;
    EXPECT_EQ(copa.getBytesInFlight(), numPacketsInFlight * packetSize);
  }

  // Say you get ack for first packet after 280 ms
  now += 280ms;
  auto packetNumToAck = 1;
  // update rtt measurements
  conn.lossState.lrtt = 280ms;
  // RTTmin = 280ms
  conn.lossState.srtt = 280ms;

  // ack for first packet, lastCwndDoubleTime_ will be initialized now
  copa.onPacketAckOrLoss(
      createAckEvent(packetNumToAck, packetSize, now), folly::none);
  numPacketsInFlight--;
  EXPECT_EQ(copa.getBytesInFlight(), numPacketsInFlight * packetSize);

  std::vector<int> indices =
      getQLogEventIndices(QLogEventType::CongestionMetricUpdate, qLogger);
  EXPECT_EQ(indices.size(), 11); // mostly congestionPacketSent logs
  auto tmp = std::move(qLogger->logs[indices[10]]);
  auto event = dynamic_cast<QLogCongestionMetricUpdateEvent*>(tmp.get());
  EXPECT_EQ(event->bytesInFlight, copa.getBytesInFlight());
  EXPECT_EQ(event->currentCwnd, kDefaultCwnd);
  EXPECT_EQ(event->congestionEvent, kCongestionPacketAck);

  now += 50ms;
  packetNumToAck++;

  EXPECT_TRUE(copa.inSlowStart());

  auto lastCwnd = copa.getCongestionWindow();
  // Say more time passed and some packets were acked meanwhile.
  copa.onPacketAckOrLoss(
      createAckEvent(packetNumToAck, packetSize, now), folly::none);
  packetNumToAck++;
  copa.onPacketAckOrLoss(
      createAckEvent(packetNumToAck, packetSize, now), folly::none);
  packetNumToAck++;
  now += 300ms;

  // update rtt measurements
  conn.lossState.lrtt = 300ms;
  // RTTmin = 280ms
  conn.lossState.srtt = 300ms;

  copa.onPacketAckOrLoss(
      createAckEvent(packetNumToAck, packetSize, now), folly::none);
  packetNumToAck++;
  now += 100ms;

  EXPECT_TRUE(copa.inSlowStart());
  // cwnd = 20 packets
  EXPECT_EQ(copa.getCongestionWindow(), 2 * lastCwnd);
  lastCwnd = copa.getCongestionWindow();

  // ack for 5th packet, at this point currentRate < targetRate, but not enough
  // time has passed for cwnd to double again in slow start
  copa.onPacketAckOrLoss(
      createAckEvent(packetNumToAck, packetSize, now), folly::none);
  EXPECT_TRUE(copa.inSlowStart());
  EXPECT_EQ(copa.getCongestionWindow(), lastCwnd);

  packetNumToAck++;
  now += 100ms;

  // update rtt measurements
  conn.lossState.lrtt = 350ms;
  // RTTmin = 280ms
  conn.lossState.srtt = 300ms;

  // ack for 6th packet, at this point even though lrtt has increased, standing
  // rtt hasn't. Hence it will still not exit slow start
  copa.onPacketAckOrLoss(
      createAckEvent(packetNumToAck, packetSize, now), folly::none);
  EXPECT_TRUE(copa.inSlowStart());
  // cwnd = 40 packets
  EXPECT_EQ(copa.getCongestionWindow(), lastCwnd);
  lastCwnd = copa.getCongestionWindow();

  now += 201ms;
  conn.lossState.lrtt = 400ms;
  conn.lossState.srtt = 300ms;

  // ack for 7th packet, at this point currentRate > targetRate, so it would
  // exit slow start and reduce cwnd
  copa.onPacketAckOrLoss(
      createAckEvent(packetNumToAck, packetSize, now), folly::none);
  EXPECT_FALSE(copa.inSlowStart());
  EXPECT_LE(copa.getCongestionWindow(), lastCwnd);
}

TEST_F(CopaTest, TestSteadyStateChanges) {
  QuicServerConnectionState conn(
      FizzServerQuicHandshakeContext::Builder().build());
  conn.transportSettings.copaDeltaParam = 0.5;
  conn.transportSettings.copaUseRttStanding = true;
  // Tests assume we have sent at least 10 packets in initial burst
  conn.transportSettings.initCwndInMss = 9;
  Copa copa(conn);
  auto now = Clock::now();
  auto lastCwnd = exitSlowStart(copa, conn, now);

  auto packetSize = conn.udpSendPacketLen;

  auto packetNumToAck = 10;
  now += 10ms;
  conn.lossState.lrtt = 100ms;
  // Rttmin = 100ms
  conn.lossState.srtt = 100ms;
  copa.onPacketAckOrLoss(
      createAckEvent(packetNumToAck, packetSize, now), folly::none);
  packetNumToAck++;
  uint64_t cwndChange =
      cwndChangeSteadyState(lastCwnd, 1.0, packetSize, 0.5, conn);
  // cwnd = 9.8 - 1 / (0.5 * 9.8) = 9.6 packets
  EXPECT_EQ(copa.getCongestionWindow(), lastCwnd - cwndChange);
  lastCwnd = copa.getCongestionWindow();

  now += 10ms;
  // target rate = 200 packets per sec, current rate = 9.6 packets / 100ms = ~50
  // packets per second
  conn.lossState.lrtt = 50ms;
  // Rttmin = 60ms
  conn.lossState.srtt = 100ms;
  copa.onPacketAckOrLoss(
      createAckEvent(packetNumToAck, packetSize, now), folly::none);
  packetNumToAck++;
  cwndChange = cwndChangeSteadyState(lastCwnd, 1.0, packetSize, 0.5, conn);
  // cwnd = 9.6 + 1 / (0.5 * 9.6) = 9.8 packets
  EXPECT_EQ(copa.getCongestionWindow(), lastCwnd + cwndChange);
  lastCwnd = copa.getCongestionWindow();

  now += 10ms;
  conn.lossState.lrtt = 100ms;
  // Rttmin = 60ms
  conn.lossState.srtt = 100ms;
  // Though lrtt has increased, rtt standing has not.  Will still increase
  copa.onPacketAckOrLoss(
      createAckEvent(packetNumToAck, packetSize, now), folly::none);
  packetNumToAck++;
  cwndChange = cwndChangeSteadyState(lastCwnd, 1.0, packetSize, 0.5, conn);
  // cwnd = 9.8 + 1 / (0.5 * 9.8) = 10.0 packets
  EXPECT_EQ(copa.getCongestionWindow(), lastCwnd + cwndChange);
  lastCwnd = copa.getCongestionWindow();

  // If sufficient time has elapsed, the increased rtt will be noted
  now += 110ms;
  copa.onPacketAckOrLoss(
      createAckEvent(packetNumToAck, packetSize, now), folly::none);
  packetNumToAck++;
  cwndChange = cwndChangeSteadyState(lastCwnd, 1.0, packetSize, 0.5, conn);
  // cwnd = 10 - 1 / (0.5 * 10) = 9.8
  EXPECT_EQ(copa.getCongestionWindow(), lastCwnd - cwndChange);
}

TEST_F(CopaTest, TestVelocity) {
  QuicServerConnectionState conn(
      FizzServerQuicHandshakeContext::Builder().build());
  conn.transportSettings.copaDeltaParam = 0.5;
  conn.transportSettings.copaUseRttStanding = true;
  conn.transportSettings.pacingTickInterval = 10ms;
  conn.transportSettings.initCwndInMss = 11;
  Copa copa(conn);
  auto qLogger = std::make_shared<FileQLogger>(VantagePoint::Client);
  conn.qLogger = qLogger;
  conn.transportSettings.pacingEnabled = true;

  // lastCwnd = 9.8 packets
  auto now = Clock::now();
  auto lastCwnd = exitSlowStart(copa, conn, now);
  uint64_t velocity = 1.0;
  auto packetSize = conn.udpSendPacketLen;

  // target rate = 200 packets per sec, current rate = 9.8 packets / 100ms = ~50
  // packets per second.
  conn.lossState.lrtt = 50ms;
  // Rttmin = 50ms
  conn.lossState.srtt = 100ms;
  now += 100ms;
  // velocity = 1, direction = 0
  copa.onPacketAckOrLoss(createAckEvent(30, packetSize, now), folly::none);

  uint64_t cwndChange =
      cwndChangeSteadyState(lastCwnd, velocity, packetSize, 0.5, conn);
  // cwnd = 9.8 + 1 / (0.5 * 9.8) = 10 packets
  EXPECT_EQ(copa.getCongestionWindow(), lastCwnd + cwndChange);
  lastCwnd = copa.getCongestionWindow();

  // another ack, velocity = 1, direction 0 -> 1
  now += 100ms;
  copa.onPacketAckOrLoss(createAckEvent(35, packetSize, now), folly::none);
  cwndChange = cwndChangeSteadyState(lastCwnd, velocity, packetSize, 0.5, conn);
  // cwnd = 10 + 1 / (0.5 * 10) = 10.2 packets
  EXPECT_EQ(copa.getCongestionWindow(), lastCwnd + cwndChange);
  lastCwnd = copa.getCongestionWindow();

  // another ack, velocity = 1, direction = 1
  now += 100ms;
  copa.onPacketAckOrLoss(createAckEvent(40, packetSize, now), folly::none);
  cwndChange = cwndChangeSteadyState(lastCwnd, velocity, packetSize, 0.5, conn);
  // cwnd = 10.2 + 1 / (0.5 * 10.2) = 10.4 packets
  EXPECT_EQ(copa.getCongestionWindow(), lastCwnd + cwndChange);
  lastCwnd = copa.getCongestionWindow();

  // another ack, velocity = 1, direction = 1
  now += 100ms;
  copa.onPacketAckOrLoss(createAckEvent(45, packetSize, now), folly::none);
  cwndChange = cwndChangeSteadyState(lastCwnd, velocity, packetSize, 0.5, conn);
  // cwnd = 10.4 + 1 / (0.5 * 10.4) = 10.6 packets
  EXPECT_EQ(copa.getCongestionWindow(), lastCwnd + cwndChange);
  lastCwnd = copa.getCongestionWindow();

  // another ack, velocity = 1, direction = 1
  now += 100ms;
  copa.onPacketAckOrLoss(createAckEvent(50, packetSize, now), folly::none);
  cwndChange = cwndChangeSteadyState(lastCwnd, velocity, packetSize, 0.5, conn);
  // cwnd = 10.4 + 1 / (0.5 * 10.4) = 10.6 packets
  EXPECT_EQ(copa.getCongestionWindow(), lastCwnd + cwndChange);
  lastCwnd = copa.getCongestionWindow();

  // another ack, velocity = 2, direction = 1
  velocity = 2 * velocity;
  now += 100ms;
  copa.onPacketAckOrLoss(createAckEvent(55, packetSize, now), folly::none);
  cwndChange = cwndChangeSteadyState(lastCwnd, velocity, packetSize, 0.5, conn);
  // cwnd = 10 + 2 / (0.5 * 10.6) = 11 packets
  EXPECT_EQ(copa.getCongestionWindow(), lastCwnd + cwndChange);
  lastCwnd = copa.getCongestionWindow();

  // another ack, velocity = 4, direction = 1
  velocity = 2 * velocity;
  now += 100ms;
  copa.onPacketAckOrLoss(createAckEvent(60, packetSize, now), folly::none);
  cwndChange = cwndChangeSteadyState(lastCwnd, velocity, packetSize, 0.5, conn);
  // cwnd = 11 + 4 / (0.5 * 11) = 11.8 packets
  EXPECT_EQ(copa.getCongestionWindow(), lastCwnd + cwndChange);
  lastCwnd = copa.getCongestionWindow();

  // another ack, velocity = 8, direction = 1
  velocity = 2 * velocity;
  now += 100ms;
  copa.onPacketAckOrLoss(createAckEvent(65, packetSize, now), folly::none);
  cwndChange = cwndChangeSteadyState(lastCwnd, velocity, packetSize, 0.5, conn);
  // cwnd = 11.8 + 8 / (0.5 * 11.8) = 13.4 packets
  EXPECT_EQ(copa.getCongestionWindow(), lastCwnd + cwndChange);
  lastCwnd = copa.getCongestionWindow();

  // drop target rate, verify that velocity resets
  conn.lossState.lrtt = 200ms;
  // Rttmin = 60ms
  conn.lossState.srtt = 100ms;

  velocity = 1;
  // give it some extra time for rtt standing to reset
  now += 110ms;
  copa.onPacketAckOrLoss(createAckEvent(50, packetSize, now), folly::none);
  cwndChange = cwndChangeSteadyState(lastCwnd, velocity, packetSize, 0.5, conn);
  // cwnd = 11.8 + 8 / (0.5 * 11.8) = 13.4 packets
  EXPECT_EQ(copa.getCongestionWindow(), lastCwnd - cwndChange);
  lastCwnd = copa.getCongestionWindow();
}

TEST_F(CopaTest, NoLargestAckedPacketNoCrash) {
  QuicServerConnectionState conn(
      FizzServerQuicHandshakeContext::Builder().build());
  conn.transportSettings.copaDeltaParam = 0.5;
  conn.transportSettings.copaUseRttStanding = true;
  Copa copa(conn);
  auto qLogger = std::make_shared<FileQLogger>(VantagePoint::Client);
  conn.qLogger = qLogger;
  CongestionController::LossEvent loss;
  loss.largestLostPacketNum = 0;
  const auto now = TimePoint::clock::now();
  auto ack = AckEvent::Builder()
                 .setAckTime(now)
                 .setAdjustedAckTime(now)
                 .setAckDelay(0us)
                 .setPacketNumberSpace(PacketNumberSpace::AppData)
                 .setLargestAckedPacket(1)
                 .build();
  copa.onPacketAckOrLoss(ack, loss);

  std::vector<int> indices =
      getQLogEventIndices(QLogEventType::CongestionMetricUpdate, qLogger);
  EXPECT_EQ(indices.size(), 1);
  auto tmp = std::move(qLogger->logs[indices[0]]);
  auto event = dynamic_cast<QLogCongestionMetricUpdateEvent*>(tmp.get());
  EXPECT_EQ(event->bytesInFlight, copa.getBytesInFlight());
  EXPECT_EQ(event->currentCwnd, kDefaultCwnd);
  EXPECT_EQ(event->congestionEvent, kCongestionPacketLoss);
}

TEST_F(CopaTest, PacketLossInvokesPacer) {
  QuicServerConnectionState conn(
      FizzServerQuicHandshakeContext::Builder().build());
  conn.transportSettings.copaDeltaParam = 0.5;
  conn.transportSettings.copaUseRttStanding = true;
  Copa copa(conn);
  auto mockPacer = std::make_unique<MockPacer>();
  auto rawPacer = mockPacer.get();
  conn.pacer = std::move(mockPacer);
  auto packet = createPacket(0 /* pacetNum */, 1000, 1000);
  copa.onPacketSent(packet);
  EXPECT_CALL(*rawPacer, onPacketsLoss()).Times(1);
  CongestionController::LossEvent lossEvent;
  lossEvent.addLostPacket(packet);
  copa.onPacketAckOrLoss(folly::none, lossEvent);
}

} // namespace test
} // namespace quic
