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
#include <quic/congestion_control/BbrBandwidthSampler.h>
#include <quic/congestion_control/test/Mocks.h>
#include <quic/state/test/Mocks.h>

using namespace testing;

namespace quic {
namespace test {

class BbrTest : public Test {};

TEST_F(BbrTest, InitStates) {
  QuicConnectionStateBase conn(QuicNodeType::Client);
  conn.udpSendPacketLen = 1000;
  BbrCongestionController bbr(conn);
  EXPECT_EQ(CongestionControlType::BBR, bbr.type());
  EXPECT_FALSE(bbr.inRecovery());
  EXPECT_EQ("Startup", bbrStateToString(bbr.state()));
  EXPECT_EQ(
      1000 * conn.transportSettings.initCwndInMss, bbr.getCongestionWindow());
  EXPECT_EQ(bbr.getWritableBytes(), bbr.getCongestionWindow());
}

TEST_F(BbrTest, InitWithCwndAndRtt) {
  QuicConnectionStateBase conn(QuicNodeType::Client);
  auto mockPacer = std::make_unique<MockPacer>();
  MockPacer* rawPacer = mockPacer.get();
  conn.pacer = std::move(mockPacer);

  auto cwnd = 123456;
  std::chrono::microseconds minRtt = 100ms;
  EXPECT_CALL(*rawPacer, refreshPacingRate(cwnd, minRtt, _));

  BbrCongestionController bbr(conn, cwnd, minRtt);

  EXPECT_EQ(CongestionControlType::BBR, bbr.type());
  EXPECT_EQ(bbr.getCongestionWindow(), cwnd);
  EXPECT_EQ(bbr.getWritableBytes(), bbr.getCongestionWindow());
}

TEST_F(BbrTest, Recovery) {
  QuicConnectionStateBase conn(QuicNodeType::Client);
  auto qLogger = std::make_shared<FileQLogger>(VantagePoint::Client);
  conn.qLogger = qLogger;
  conn.udpSendPacketLen = 1000;
  conn.transportSettings.initCwndInMss = 500; // Make a really large initCwnd
  BbrCongestionController bbr(conn);
  // Make a huge inflight so we don't underflow anything
  auto inflightBytes = 100 * 1000;
  bbr.onPacketSent(makeTestingWritePacket(9, inflightBytes, inflightBytes));

  // This also makes sure recoveryWindow_ is larger than inflightBytes
  uint64_t ackedBytes = 1000 * conn.transportSettings.minCwndInMss * 2;
  CongestionController::LossEvent loss;
  loss.lostBytes = 100;
  inflightBytes -= (loss.lostBytes + ackedBytes);
  uint64_t expectedRecoveryWindow = std::max(
      inflightBytes + ackedBytes - loss.lostBytes, inflightBytes + ackedBytes);
  // This sets the connectin to recovery state, also sets both the
  // endOfRoundTrip_ and endOfRecovery_ to Clock::now()
  bbr.onPacketAckOrLoss(
      makeAck(0, ackedBytes, Clock::now(), Clock::now() - 5ms), loss);
  auto estimatedEndOfRoundTrip = Clock::now();
  EXPECT_TRUE(bbr.inRecovery());
  EXPECT_EQ(expectedRecoveryWindow, bbr.getCongestionWindow());

  std::vector<int> indices =
      getQLogEventIndices(QLogEventType::CongestionMetricUpdate, qLogger);
  EXPECT_EQ(indices.size(), 1);
  auto tmp = std::move(qLogger->logs[indices[0]]);
  auto event = dynamic_cast<QLogCongestionMetricUpdateEvent*>(tmp.get());
  EXPECT_EQ(event->bytesInFlight, inflightBytes);
  EXPECT_EQ(event->currentCwnd, expectedRecoveryWindow);
  EXPECT_EQ(event->congestionEvent, kCongestionPacketAck);
  EXPECT_EQ(
      event->state,
      bbrStateToString(BbrCongestionController::BbrState::Startup));
  EXPECT_EQ(
      event->recoveryState,
      bbrRecoveryStateToString(
          BbrCongestionController::RecoveryState::CONSERVATIVE));

  // Sleep 1ms to make next now() a bit far from previous now().
  std::this_thread::sleep_for(1ms);

  CongestionController::LossEvent loss2;
  loss2.lostBytes = 100;
  inflightBytes -= loss2.lostBytes;
  expectedRecoveryWindow -= loss2.lostBytes;
  // This doesn't change endOfRoundTrip_, but move endOfRecovery to new
  // Clock::now()
  auto estimatedLossTime = Clock::now();
  bbr.onPacketAckOrLoss(folly::none, loss2);
  EXPECT_EQ(expectedRecoveryWindow, bbr.getCongestionWindow());

  ackedBytes = 500;
  expectedRecoveryWindow += ackedBytes; // GROWTH
  // This will move the Recovery to GROWTH
  bbr.onPacketAckOrLoss(
      makeAck(
          11,
          ackedBytes,
          estimatedLossTime - 1us,
          estimatedEndOfRoundTrip + 1us),
      folly::none);
  EXPECT_TRUE(bbr.inRecovery());
  // Since recoveryWindow_ is larger than inflightBytes + recoveryIncrase
  EXPECT_EQ(expectedRecoveryWindow, bbr.getCongestionWindow());
  inflightBytes -= ackedBytes;

  CongestionController::LossEvent loss3;
  loss3.persistentCongestion = true;
  loss3.lostBytes = inflightBytes / 2;
  expectedRecoveryWindow = conn.udpSendPacketLen * kMinCwndInMssForBbr;
  bbr.onPacketAckOrLoss(folly::none, loss3);
  EXPECT_EQ(expectedRecoveryWindow, bbr.getCongestionWindow());

  CongestionController::AckEvent ack3 = makeAck(
      12, inflightBytes / 2, estimatedLossTime + 10ms, estimatedLossTime + 5ms);
  // This will exit Recovery
  bbr.onPacketAckOrLoss(ack3, folly::none);
  EXPECT_FALSE(bbr.inRecovery());
}

TEST_F(BbrTest, StartupCwnd) {
  QuicConnectionStateBase conn(QuicNodeType::Client);
  conn.udpSendPacketLen = 1000;
  BbrCongestionController bbr(conn);
  auto mockRttSampler = std::make_unique<MockMinRttSampler>();
  auto mockBandwidthSampler = std::make_unique<MockBandwidthSampler>();
  auto rawRttSampler = mockRttSampler.get();
  auto rawBandwidthSampler = mockBandwidthSampler.get();
  bbr.setRttSampler(std::move(mockRttSampler));
  bbr.setBandwidthSampler(std::move(mockBandwidthSampler));

  auto packet = makeTestingWritePacket(0, 3000, 3000);
  bbr.onPacketSent(packet);
  auto startingCwnd = bbr.getCongestionWindow();
  conn.lossState.srtt = 100us;
  EXPECT_CALL(*rawRttSampler, minRtt()).WillRepeatedly(Return(100us));
  EXPECT_CALL(*rawBandwidthSampler, getBandwidth())
      .WillRepeatedly(Return(
          Bandwidth(5000ULL * 1000 * 1000, std::chrono::microseconds(1))));
  // Target cwnd will be 100 * 5000 * 2.885 = 1442500, but you haven't finished
  // STARTUP, too bad kiddo, you only grow a little today
  bbr.onPacketAckOrLoss(
      makeAck(0, 3000, Clock::now(), packet.metadata.time), folly::none);
  EXPECT_EQ(startingCwnd + 3000, bbr.getCongestionWindow());
}

TEST_F(BbrTest, StartupCwndImplicit) {
  QuicConnectionStateBase conn(QuicNodeType::Client);
  conn.udpSendPacketLen = 1000;
  BbrCongestionController bbr(conn);
  auto mockRttSampler = std::make_unique<MockMinRttSampler>();
  auto mockBandwidthSampler = std::make_unique<MockBandwidthSampler>();
  auto rawRttSampler = mockRttSampler.get();
  auto rawBandwidthSampler = mockBandwidthSampler.get();
  bbr.setRttSampler(std::move(mockRttSampler));
  bbr.setBandwidthSampler(std::move(mockBandwidthSampler));

  auto packet = makeTestingWritePacket(0, 3000, 3000);
  bbr.onPacketSent(packet);
  auto startingCwnd = bbr.getCongestionWindow();
  conn.lossState.srtt = 100us;
  EXPECT_CALL(*rawRttSampler, newRttSample(_, _)).Times(0);
  EXPECT_CALL(*rawRttSampler, minRtt()).WillRepeatedly(Return(100us));
  EXPECT_CALL(*rawBandwidthSampler, getBandwidth())
      .WillRepeatedly(Return(
          Bandwidth(5000ULL * 1000 * 1000, std::chrono::microseconds(1))));
  // Target cwnd will be 100 * 5000 * 2.885 = 1442500, but you haven't finished
  // STARTUP, too bad kiddo, you only grow a little today
  auto ack = makeAck(0, 3000, Clock::now(), packet.metadata.time);
  ack.implicit = true;
  bbr.onPacketAckOrLoss(ack, folly::none);
  EXPECT_EQ(startingCwnd + 3000, bbr.getCongestionWindow());
}

TEST_F(BbrTest, LeaveStartup) {
  QuicConnectionStateBase conn(QuicNodeType::Client);
  conn.udpSendPacketLen = 1000;
  BbrCongestionController bbr(conn);
  auto mockBandwidthSampler = std::make_unique<MockBandwidthSampler>();
  auto rawBandwidthSampler = mockBandwidthSampler.get();
  bbr.setBandwidthSampler(std::move(mockBandwidthSampler));

  PacketNum currentLatest = 0;
  conn.lossState.totalBytesAcked = 0;
  uint64_t totalSent = 0;
  Bandwidth mockedBandwidth(2000 * 1000, std::chrono::microseconds(1));
  // Helper lambda to send one packet, ack it, and control how fast the
  // bandwidth is growing
  auto sendAckGrow = [&](bool growFast) {
    conn.lossState.largestSent = currentLatest;
    auto packet = makeTestingWritePacket(
        conn.lossState.largestSent.value(), 1000, 1000 + totalSent);
    bbr.onPacketSent(packet);
    totalSent += 1000;
    EXPECT_CALL(*rawBandwidthSampler, getBandwidth())
        .WillRepeatedly(Return(
            mockedBandwidth * (growFast ? kExpectedStartupGrowth : 1.0)));
    bbr.onPacketAckOrLoss(
        makeAck(currentLatest, 1000, Clock::now(), packet.metadata.time),
        folly::none);
    conn.lossState.totalBytesAcked += 1000;
    if (growFast) {
      mockedBandwidth = mockedBandwidth * kExpectedStartupGrowth;
    }
    currentLatest++;
  };

  // Consecutive good growth, no exit startup:
  while (currentLatest < 10) {
    sendAckGrow(true);
  }
  EXPECT_EQ(BbrCongestionController::BbrState::Startup, bbr.state());

  // One slowed growth, follow by one good growth, then a few slowed growth just
  // one shy from kStartupSlowGrowRoundLimit, these won't exit startup:
  sendAckGrow(false);
  sendAckGrow(true);
  for (int i = 0; i < kStartupSlowGrowRoundLimit - 1; i++) {
    sendAckGrow(false);
  }
  EXPECT_EQ(BbrCongestionController::BbrState::Startup, bbr.state());

  sendAckGrow(true);
  // kStartupSlowGrowRoundLimit consecutive slow growth
  for (int i = 0; i < kStartupSlowGrowRoundLimit; i++) {
    EXPECT_EQ(BbrCongestionController::BbrState::Startup, bbr.state());
    sendAckGrow(false);
  }
  EXPECT_NE(BbrCongestionController::BbrState::Startup, bbr.state());
}

TEST_F(BbrTest, RemoveInflightBytes) {
  QuicConnectionStateBase conn(QuicNodeType::Client);
  conn.udpSendPacketLen = 1000;
  BbrCongestionController bbr(conn);
  auto writableBytesAfterInit = bbr.getWritableBytes();
  bbr.onPacketSent(makeTestingWritePacket(0, 1000, 1000));
  EXPECT_EQ(writableBytesAfterInit - 1000, bbr.getWritableBytes());
  bbr.onRemoveBytesFromInflight(1000);
  EXPECT_EQ(writableBytesAfterInit, bbr.getWritableBytes());
}

TEST_F(BbrTest, ProbeRtt) {
  QuicConnectionStateBase conn(QuicNodeType::Client);
  conn.udpSendPacketLen = 1000;
  BbrCongestionController bbr(conn);
  auto mockBandwidthSampler = std::make_unique<MockBandwidthSampler>();
  auto rawBandwidthSampler = mockBandwidthSampler.get();
  auto minRttSampler = std::make_unique<MockMinRttSampler>();
  auto rawRttSampler = minRttSampler.get();
  bbr.setBandwidthSampler(std::move(mockBandwidthSampler));
  bbr.setRttSampler(std::move(minRttSampler));
  EXPECT_CALL(*rawRttSampler, minRtt()).WillRepeatedly(Return(50us));

  PacketNum currentLatest = 0;
  std::deque<std::pair<PacketNum, TimePoint>> inflightPackets;
  uint64_t inflightBytes = 0, totalSent = 0;
  conn.lossState.totalBytesAcked = 0;
  auto sendFunc = [&]() {
    conn.lossState.largestSent = currentLatest;
    auto packet = makeTestingWritePacket(
        conn.lossState.largestSent.value(),
        conn.udpSendPacketLen,
        totalSent + conn.udpSendPacketLen);
    bbr.onPacketSent(packet);
    inflightPackets.push_back(
        std::make_pair(currentLatest, packet.metadata.time));
    inflightBytes += conn.udpSendPacketLen;
    currentLatest++;
    totalSent += conn.udpSendPacketLen;
  };
  // Send a few to make inflight big
  for (size_t i = 0; i < 10; i++) {
    sendFunc();
  }

  // Ack the first one without min rtt expiration.
  auto packetToAck = inflightPackets.front();
  EXPECT_CALL(*rawRttSampler, minRttExpired()).WillOnce(Return(false));
  bbr.onPacketAckOrLoss(
      makeAck(
          packetToAck.first,
          conn.udpSendPacketLen,
          Clock::now(),
          packetToAck.second),
      folly::none);
  conn.lossState.totalBytesAcked += conn.udpSendPacketLen;
  inflightBytes -= conn.udpSendPacketLen;
  inflightPackets.pop_front();
  EXPECT_NE(BbrCongestionController::BbrState::ProbeRtt, bbr.state());

  // Ack the second one, expire min rtt, enter ProbeRtt. This ack will also
  // ends the current RTT round. The new rtt round target will be the
  // largestSent of the conn
  packetToAck = inflightPackets.front();
  EXPECT_CALL(*rawRttSampler, minRttExpired()).WillOnce(Return(true));
  EXPECT_CALL(*rawBandwidthSampler, onAppLimited()).Times(AnyNumber());
  bbr.onPacketAckOrLoss(
      makeAck(
          packetToAck.first,
          conn.udpSendPacketLen,
          Clock::now(),
          packetToAck.second),
      folly::none);
  conn.lossState.totalBytesAcked += conn.udpSendPacketLen;
  inflightBytes -= conn.udpSendPacketLen;
  inflightPackets.pop_front();
  EXPECT_EQ(BbrCongestionController::BbrState::ProbeRtt, bbr.state());

  // Now we still have a inflight > ProbeRtt cwnd, count down won't happen.
  // Ack more packets until we reach the low inflight mark.
  // None of these acks will lead to a new RTT round
  while (inflightBytes >= bbr.getCongestionWindow() + conn.udpSendPacketLen) {
    packetToAck = inflightPackets.front();
    bbr.onPacketAckOrLoss(
        makeAck(
            packetToAck.first,
            conn.udpSendPacketLen,
            Clock::now(),
            packetToAck.second),
        folly::none);
    conn.lossState.totalBytesAcked += conn.udpSendPacketLen;
    inflightBytes -= conn.udpSendPacketLen;
    inflightPackets.pop_front();
  }
  EXPECT_EQ(BbrCongestionController::BbrState::ProbeRtt, bbr.state());

  // Now if we ack again, the ProbeRtt duration count down starts
  ASSERT_FALSE(inflightPackets.empty());
  packetToAck = inflightPackets.front();
  auto currentTime = Clock::now();
  bbr.onPacketAckOrLoss(
      makeAck(
          packetToAck.first,
          conn.udpSendPacketLen,
          currentTime,
          packetToAck.second),
      folly::none);
  conn.lossState.totalBytesAcked += conn.udpSendPacketLen;
  inflightBytes -= conn.udpSendPacketLen;
  inflightPackets.pop_front();
  EXPECT_EQ(BbrCongestionController::BbrState::ProbeRtt, bbr.state());

  // Ack everything still inflight
  while (inflightPackets.size()) {
    packetToAck = inflightPackets.front();
    bbr.onPacketAckOrLoss(
        makeAck(
            packetToAck.first,
            conn.udpSendPacketLen,
            packetToAck.second + 1ms,
            packetToAck.second),
        folly::none);
    inflightBytes -= conn.udpSendPacketLen;
    inflightPackets.pop_front();
    EXPECT_EQ(BbrCongestionController::BbrState::ProbeRtt, bbr.state());
    conn.lossState.totalBytesAcked += conn.udpSendPacketLen;
  }

  // Then sends a new one and ack it to end the previous RTT round. Now we are
  // counting down both time duration and has reached a new rtt round.
  sendFunc();
  packetToAck = inflightPackets.front();
  bbr.onPacketAckOrLoss(
      makeAck(
          packetToAck.first,
          conn.udpSendPacketLen,
          packetToAck.second + 2ms,
          packetToAck.second),
      folly::none);
  inflightBytes -= conn.udpSendPacketLen;
  inflightPackets.pop_front();
  EXPECT_EQ(BbrCongestionController::BbrState::ProbeRtt, bbr.state());
  conn.lossState.totalBytesAcked += conn.udpSendPacketLen;

  // finish the time duration count down
  sendFunc();
  packetToAck = inflightPackets.front();
  EXPECT_CALL(
      *rawRttSampler, timestampMinRtt(packetToAck.second + kProbeRttDuration))
      .Times(1);
  bbr.onPacketAckOrLoss(
      makeAck(
          packetToAck.first,
          conn.udpSendPacketLen,
          packetToAck.second + kProbeRttDuration,
          packetToAck.second),
      folly::none);
  conn.lossState.totalBytesAcked += conn.udpSendPacketLen;
  inflightBytes -= conn.udpSendPacketLen;
  inflightPackets.pop_front();
  EXPECT_EQ(BbrCongestionController::BbrState::Startup, bbr.state());
}

TEST_F(BbrTest, NoLargestAckedPacketInitialNoCrash) {
  QuicConnectionStateBase conn(QuicNodeType::Client);
  BbrCongestionController bbr(conn);
  CongestionController::LossEvent loss;
  loss.largestLostPacketNum = 0;
  const auto pn = 0;
  auto ackTime = Clock::now();
  auto ack = CongestionController::AckEvent::Builder()
                 .setAckTime(ackTime)
                 .setAdjustedAckTime(ackTime)
                 .setAckDelay(0us)
                 .setPacketNumberSpace(PacketNumberSpace::Initial)
                 .setLargestAckedPacket(pn)
                 .build();
  bbr.onPacketAckOrLoss(ack, loss);
}

TEST_F(BbrTest, NoLargestAckedPacketHandshakeNoCrash) {
  QuicConnectionStateBase conn(QuicNodeType::Client);
  BbrCongestionController bbr(conn);
  CongestionController::LossEvent loss;
  loss.largestLostPacketNum = 0;
  const auto pn = 0;
  auto ackTime = Clock::now();
  auto ack = CongestionController::AckEvent::Builder()
                 .setAckTime(ackTime)
                 .setAdjustedAckTime(ackTime)
                 .setAckDelay(0us)
                 .setPacketNumberSpace(PacketNumberSpace::Handshake)
                 .setLargestAckedPacket(pn)
                 .build();
  bbr.onPacketAckOrLoss(ack, loss);
}

TEST_F(BbrTest, NoLargestAckedPacketAppDataNoCrash) {
  QuicConnectionStateBase conn(QuicNodeType::Client);
  BbrCongestionController bbr(conn);
  CongestionController::LossEvent loss;
  loss.largestLostPacketNum = 0;
  const auto pn = 0;
  auto ackTime = Clock::now();
  auto ack = CongestionController::AckEvent::Builder()
                 .setAckTime(ackTime)
                 .setAdjustedAckTime(ackTime)
                 .setAckDelay(0us)
                 .setPacketNumberSpace(PacketNumberSpace::AppData)
                 .setLargestAckedPacket(pn)
                 .build();
  bbr.onPacketAckOrLoss(ack, loss);
}

TEST_F(BbrTest, NoLargestAckedPacketInitialNoCrashPn1) {
  QuicConnectionStateBase conn(QuicNodeType::Client);
  BbrCongestionController bbr(conn);
  CongestionController::LossEvent loss;
  loss.largestLostPacketNum = 0;
  const auto pn = 1;
  auto ackTime = Clock::now();
  auto ack = CongestionController::AckEvent::Builder()
                 .setAckTime(ackTime)
                 .setAdjustedAckTime(ackTime)
                 .setAckDelay(0us)
                 .setPacketNumberSpace(PacketNumberSpace::Initial)
                 .setLargestAckedPacket(pn)
                 .build();
  bbr.onPacketAckOrLoss(ack, loss);
}

TEST_F(BbrTest, NoLargestAckedPacketHandshakeNoCrashPn1) {
  QuicConnectionStateBase conn(QuicNodeType::Client);
  BbrCongestionController bbr(conn);
  CongestionController::LossEvent loss;
  loss.largestLostPacketNum = 0;
  const auto pn = 1;
  auto ackTime = Clock::now();
  auto ack = CongestionController::AckEvent::Builder()
                 .setAckTime(ackTime)
                 .setAdjustedAckTime(ackTime)
                 .setAckDelay(0us)
                 .setPacketNumberSpace(PacketNumberSpace::Handshake)
                 .setLargestAckedPacket(pn)
                 .build();
  bbr.onPacketAckOrLoss(ack, loss);
}

TEST_F(BbrTest, NoLargestAckedPacketAppDataNoCrashPn1) {
  QuicConnectionStateBase conn(QuicNodeType::Client);
  BbrCongestionController bbr(conn);
  CongestionController::LossEvent loss;
  loss.largestLostPacketNum = 0;
  const auto pn = 1;
  auto ackTime = Clock::now();
  auto ack = CongestionController::AckEvent::Builder()
                 .setAckTime(ackTime)
                 .setAdjustedAckTime(ackTime)
                 .setAckDelay(0us)
                 .setPacketNumberSpace(PacketNumberSpace::AppData)
                 .setLargestAckedPacket(pn)
                 .build();
  bbr.onPacketAckOrLoss(ack, loss);
}

TEST_F(BbrTest, AckAggregation) {
  QuicConnectionStateBase conn(QuicNodeType::Client);
  auto qLogger = std::make_shared<FileQLogger>(VantagePoint::Client);
  conn.qLogger = qLogger;
  conn.udpSendPacketLen = 1000;
  BbrCongestionController bbr(conn);
  auto mockBandwidthSampler = std::make_unique<MockBandwidthSampler>();
  auto mockRttSampler = std::make_unique<MockMinRttSampler>();
  auto rawRttSampler = mockRttSampler.get();
  auto rawBandwidthSampler = mockBandwidthSampler.get();
  bbr.setRttSampler(std::move(mockRttSampler));
  bbr.setBandwidthSampler(std::move(mockBandwidthSampler));
  conn.lossState.srtt = 50us;
  EXPECT_CALL(*rawRttSampler, minRtt()).WillRepeatedly(Return(50us));

  // The following part pretty much go through the LeaveStartup test case to
  // leave startup first. When BBR is still in startup, excessive bytes don't
  // get added to cwnd which make testing hard.
  PacketNum currentLatest = 0;
  uint64_t totalSent = 0;
  Bandwidth mockedBandwidth(2000 * 1000, std::chrono::microseconds(1));
  auto sendAckGrow = [&](bool growFast) {
    conn.lossState.largestSent = currentLatest;
    auto packet = makeTestingWritePacket(
        conn.lossState.largestSent.value(), 1000, 1000 + totalSent);
    bbr.onPacketSent(packet);
    totalSent += 1000;
    EXPECT_CALL(*rawBandwidthSampler, getBandwidth())
        .WillRepeatedly(Return(
            mockedBandwidth * (growFast ? kExpectedStartupGrowth : 1.0)));
    bbr.onPacketAckOrLoss(
        makeAck(
            currentLatest,
            1000,
            // force send time < ack time
            Clock::now() + std::chrono::milliseconds(10),
            packet.metadata.time),
        folly::none);
    conn.lossState.totalBytesAcked += 1000;
    if (growFast) {
      mockedBandwidth = mockedBandwidth * kExpectedStartupGrowth;
    }
    currentLatest++;
  };

  sendAckGrow(true);

  std::vector<int> indices =
      getQLogEventIndices(QLogEventType::CongestionMetricUpdate, qLogger);
  EXPECT_EQ(indices.size(), 1);
  auto tmp = std::move(qLogger->logs[indices[0]]);
  auto event = dynamic_cast<QLogCongestionMetricUpdateEvent*>(tmp.get());
  EXPECT_EQ(event->bytesInFlight, 0);
  EXPECT_EQ(event->currentCwnd, bbr.getCongestionWindow());
  EXPECT_EQ(event->congestionEvent, kCongestionPacketAck);
  EXPECT_EQ(
      event->state,
      bbrStateToString(BbrCongestionController::BbrState::Startup));
  EXPECT_EQ(
      event->recoveryState,
      bbrRecoveryStateToString(
          BbrCongestionController::RecoveryState::NOT_RECOVERY));

  // kStartupSlowGrowRoundLimit consecutive slow growth to leave Startup
  for (int i = 0; i <= kStartupSlowGrowRoundLimit; i++) {
    sendAckGrow(false);
  }
  EXPECT_NE(BbrCongestionController::BbrState::Startup, bbr.state());

  conn.lossState.largestSent = currentLatest;
  auto packet = makeTestingWritePacket(
      conn.lossState.largestSent.value(), 1000, 1000 + totalSent);
  bbr.onPacketSent(packet);
  totalSent += 1000;
  auto ackEvent = makeAck(
      currentLatest, 1000, packet.metadata.time + 10ms, packet.metadata.time);
  // use a real large bandwidth to clear accumulated ack aggregation during
  // startup
  auto currentCwnd = bbr.getCongestionWindow();
  EXPECT_CALL(*rawBandwidthSampler, getBandwidth())
      .WillRepeatedly(Return(mockedBandwidth * 10));
  auto expectedBdp =
      mockedBandwidth * 50 * std::chrono::microseconds(50) / 1000 / 1000;
  bbr.onPacketAckOrLoss(ackEvent, folly::none);
  auto newCwnd = bbr.getCongestionWindow();
  auto currentMaxAckHeight = 0;
  if (newCwnd != currentCwnd + 1000) {
    currentMaxAckHeight = newCwnd - expectedBdp * kProbeBwGain;
  }
  currentLatest++;

  // Another round, this time send something larger than currentMaxAckHeight:
  conn.lossState.largestSent = currentLatest;
  auto packet1 = makeTestingWritePacket(
      conn.lossState.largestSent.value(),
      currentMaxAckHeight * 2 + 100,
      currentMaxAckHeight * 2 + 100 + totalSent,
      packet.metadata.time + 1us);
  bbr.onPacketSent(packet1);
  totalSent += (currentMaxAckHeight * 2 + 100);
  auto ackEvent2 = makeAck(
      currentLatest,
      currentMaxAckHeight * 2 + 100,
      ackEvent.ackTime + 1ms,
      packet1.metadata.time);

  bbr.onPacketAckOrLoss(ackEvent2, folly::none);
  newCwnd = bbr.getCongestionWindow();
  EXPECT_GT(newCwnd, expectedBdp * kProbeBwGain + currentMaxAckHeight);
}

TEST_F(BbrTest, AppLimited) {
  QuicConnectionStateBase conn(QuicNodeType::Client);
  BbrCongestionController bbr(conn);
  auto mockBandwidthSampler = std::make_unique<MockBandwidthSampler>();
  auto rawBandwidthSampler = mockBandwidthSampler.get();
  bbr.setBandwidthSampler(std::move(mockBandwidthSampler));

  auto packet = makeTestingWritePacket(
      conn.lossState.largestSent.value_or(0), 1000, 1000);
  bbr.onPacketSent(packet);
  conn.lossState.largestSent = conn.lossState.largestSent.value_or(0) + 1;
  EXPECT_CALL(*rawBandwidthSampler, onAppLimited()).Times(1);
  bbr.setAppLimited();
  EXPECT_CALL(*rawBandwidthSampler, isAppLimited())
      .Times(1)
      .WillOnce(Return(true));
  EXPECT_TRUE(bbr.isAppLimited());
}

TEST_F(BbrTest, AppLimitedIgnored) {
  QuicConnectionStateBase conn(QuicNodeType::Client);
  BbrCongestionController bbr(conn);
  auto mockBandwidthSampler = std::make_unique<MockBandwidthSampler>();
  auto rawBandwidthSampler = mockBandwidthSampler.get();
  bbr.setBandwidthSampler(std::move(mockBandwidthSampler));
  auto cwnd = bbr.getCongestionWindow();
  uint64_t inflightBytes = 0;
  while (inflightBytes <= cwnd) {
    EXPECT_CALL(*rawBandwidthSampler, onAppLimited()).Times(1);
    bbr.setAppLimited();
    auto packet = makeTestingWritePacket(
        conn.lossState.largestSent.value_or(0), 1000, 1000 + inflightBytes);
    conn.lossState.largestSent = conn.lossState.largestSent.value_or(0) + 1;
    inflightBytes += 1000;
    bbr.onPacketSent(packet);
  }
  // setAppLimited will be ignored:
  EXPECT_CALL(*rawBandwidthSampler, onAppLimited()).Times(0);
  bbr.setAppLimited();
}

TEST_F(BbrTest, ExtendMinRttExpiration) {
  QuicConnectionStateBase conn(QuicNodeType::Client);
  conn.transportSettings.bbrConfig.probeRttDisabledIfAppLimited = true;
  BbrCongestionController bbr(conn);
  auto mockRttSampler = std::make_unique<MockMinRttSampler>();
  auto mockBandwidthSampler = std::make_unique<MockBandwidthSampler>();
  auto rawRttSampler = mockRttSampler.get();
  auto rawBandwidthSampler = mockBandwidthSampler.get();
  bbr.setRttSampler(std::move(mockRttSampler));
  bbr.setBandwidthSampler(std::move(mockBandwidthSampler));
  EXPECT_CALL(*rawBandwidthSampler, onAppLimited()).Times(1);
  bbr.setAppLimited();

  auto packet = makeTestingWritePacket(
      conn.lossState.largestSent.value_or(0), 1000, 1000);
  bbr.onPacketSent(packet);
  EXPECT_CALL(*rawRttSampler, timestampMinRtt(_)).Times(1);
  bbr.onPacketAckOrLoss(
      makeAck(
          conn.lossState.largestSent.value_or(0),
          1000,
          Clock::now(),
          packet.metadata.time),
      folly::none);
}

TEST_F(BbrTest, BytesCounting) {
  QuicConnectionStateBase conn(QuicNodeType::Client);
  BbrCongestionController bbr(conn);
  bbr.setBandwidthSampler(std::make_unique<BbrBandwidthSampler>(conn));

  PacketNum packetNum = 0;
  auto packet = makeTestingWritePacket(packetNum, 1200, 1200);
  conn.outstandings.packets.push_back(packet);
  conn.outstandings.packetCount[PacketNumberSpace::AppData]++;
  ReadAckFrame ackFrame;
  ackFrame.largestAcked = packetNum;
  ackFrame.ackBlocks.emplace_back(packetNum, packetNum);
  auto ackVisitor = [&](auto&, auto&, auto&) {};
  auto lossVisitor = [&](auto&, auto&, bool) {};
  processAckFrame(
      conn,
      PacketNumberSpace::AppData,
      ackFrame,
      ackVisitor,
      lossVisitor,
      Clock::now());
  EXPECT_EQ(1200, conn.lossState.totalBytesAcked);
}

TEST_F(BbrTest, AppIdle) {
  QuicConnectionStateBase conn(QuicNodeType::Client);
  auto qLogger = std::make_shared<FileQLogger>(VantagePoint::Client);
  conn.qLogger = qLogger;
  BbrCongestionController bbr(conn);

  bbr.setAppIdle(true, Clock::now());

  std::vector<int> indices =
      getQLogEventIndices(QLogEventType::AppIdleUpdate, qLogger);
  EXPECT_EQ(indices.size(), 1);
  auto tmp = std::move(qLogger->logs[indices[0]]);
  auto event = dynamic_cast<QLogAppIdleUpdateEvent*>(tmp.get());
  EXPECT_EQ(event->idleEvent, kAppIdle);
  EXPECT_TRUE(event->idle);
}

TEST_F(BbrTest, PacketLossInvokesPacer) {
  QuicConnectionStateBase conn(QuicNodeType::Client);
  BbrCongestionController bbr(conn);
  auto mockPacer = std::make_unique<MockPacer>();
  auto rawPacer = mockPacer.get();
  conn.pacer = std::move(mockPacer);

  auto packet = makeTestingWritePacket(0, 1000, 1000);
  bbr.onPacketSent(packet);
  EXPECT_CALL(*rawPacer, onPacketsLoss()).Times(1);
  CongestionController::LossEvent lossEvent;
  lossEvent.addLostPacket(packet);
  bbr.onPacketAckOrLoss(folly::none, lossEvent);
}

TEST_F(BbrTest, ProbeRttSetsAppLimited) {
  QuicConnectionStateBase conn(QuicNodeType::Client);
  BbrCongestionController bbr(conn);
  auto mockBandwidthSampler = std::make_unique<MockBandwidthSampler>();
  auto rawBandwidthSampler = mockBandwidthSampler.get();
  auto mockRttSampler = std::make_unique<MockMinRttSampler>();
  auto rawRttSampler = mockRttSampler.get();
  bbr.setBandwidthSampler(std::move(mockBandwidthSampler));
  bbr.setRttSampler(std::move(mockRttSampler));

  bbr.onPacketSent(makeTestingWritePacket(0, 1000, 1000));
  EXPECT_CALL(*rawRttSampler, minRttExpired()).Times(1).WillOnce(Return(true));
  EXPECT_CALL(*rawBandwidthSampler, onAppLimited()).Times(2);
  bbr.onPacketAckOrLoss(
      makeAck(0, 1000, Clock::now(), Clock::now() - 5ms), folly::none);
  EXPECT_EQ(BbrCongestionController::BbrState::ProbeRtt, bbr.state());

  bbr.onPacketSent(makeTestingWritePacket(1, 1000, 2000));
  EXPECT_CALL(*rawBandwidthSampler, onAppLimited()).Times(1);
  bbr.onPacketAckOrLoss(
      makeAck(1, 1000, Clock::now(), Clock::now() - 5ms), folly::none);
  EXPECT_EQ(BbrCongestionController::BbrState::ProbeRtt, bbr.state());
}

TEST_F(BbrTest, BackgroundMode) {
  QuicConnectionStateBase conn(QuicNodeType::Client);
  BbrCongestionController bbr(conn);
  auto mockBandwidthSampler = std::make_unique<MockBandwidthSampler>();
  auto rawBandwidthSampler = mockBandwidthSampler.get();
  auto mockRttSampler = std::make_unique<MockMinRttSampler>();
  bbr.setBandwidthSampler(std::move(mockBandwidthSampler));
  bbr.setRttSampler(std::move(mockRttSampler));

  EXPECT_FALSE(bbr.isInBackgroundMode());

  // Set bbr to background mode. The bandwidth sampler window should change to
  // use kBGNumOfCycles
  EXPECT_CALL(
      *rawBandwidthSampler,
      setWindowLength(bandwidthWindowLength(kBGNumOfCycles)))
      .Times(1)
      .RetiresOnSaturation();
  bbr.setBandwidthUtilizationFactor(0.75);
  EXPECT_TRUE(bbr.isInBackgroundMode());

  // Call to re-enable backdground mode should not change the window length
  // again.
  EXPECT_CALL(
      *rawBandwidthSampler,
      setWindowLength(bandwidthWindowLength(kBGNumOfCycles)))
      .Times(0);
  bbr.setBandwidthUtilizationFactor(0.75);
  EXPECT_TRUE(bbr.isInBackgroundMode());

  // Call to disable background mode should cause the bw sampler window
  // length to be restored to use kNumofCycles
  EXPECT_CALL(
      *rawBandwidthSampler,
      setWindowLength(bandwidthWindowLength(kNumOfCycles)))
      .Times(1)
      .RetiresOnSaturation();
  bbr.setBandwidthUtilizationFactor(1.0);
  EXPECT_FALSE(bbr.isInBackgroundMode());
}

} // namespace test
} // namespace quic
