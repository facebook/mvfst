/*
 * Copyright (c) Facebook, Inc. and its affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 *
 */

// Copyright 2004-present Facebook.  All rights reserved.

#include <quic/congestion_control/Bbr.h>
#include <folly/portability/GMock.h>
#include <folly/portability/GTest.h>
#include <quic/common/test/TestUtils.h>
#include <quic/congestion_control/BbrBandwidthSampler.h>

using namespace quic;
using namespace testing;

namespace quic {
namespace test {

// TODO: move these Mocks to a mock file
class MockMinRttSampler : public BbrCongestionController::MinRttSampler {
 public:
  ~MockMinRttSampler() override {}

  MOCK_CONST_METHOD0(minRtt, std::chrono::microseconds());
  MOCK_CONST_METHOD0(minRttExpired, bool());
  GMOCK_METHOD2_(
      ,
      noexcept,
      ,
      newRttSample,
      bool(std::chrono::microseconds, TimePoint));
  GMOCK_METHOD1_(, noexcept, , timestampMinRtt, void(TimePoint));
};

class MockBandwidthSampler : public BbrCongestionController::BandwidthSampler {
 public:
  ~MockBandwidthSampler() override {}

  MOCK_CONST_METHOD0(getBandwidth, Bandwidth());
  MOCK_CONST_METHOD0(isAppLimited, bool());

  MOCK_METHOD2(
      onPacketAcked,
      void(const CongestionController::AckEvent&, uint64_t));
  MOCK_METHOD0(onAppLimited, void());
};

class BbrTest : public Test {};

TEST_F(BbrTest, InitStates) {
  QuicConnectionStateBase conn(QuicNodeType::Client);
  conn.udpSendPacketLen = 1000;
  BbrCongestionController::BbrConfig config;
  BbrCongestionController bbr(conn, config);
  EXPECT_EQ(CongestionControlType::BBR, bbr.type());
  EXPECT_FALSE(bbr.inRecovery());
  EXPECT_EQ("Startup", bbrStateToString(bbr.state()));
  EXPECT_EQ(
      1000 * conn.transportSettings.initCwndInMss, bbr.getCongestionWindow());
  EXPECT_EQ(bbr.getWritableBytes(), bbr.getCongestionWindow());
}

TEST_F(BbrTest, Recovery) {
  QuicConnectionStateBase conn(QuicNodeType::Client);
  auto qLogger = std::make_shared<FileQLogger>();
  conn.qLogger = qLogger;
  conn.udpSendPacketLen = 1000;
  BbrCongestionController::BbrConfig config;
  conn.transportSettings.initCwndInMss = 500; // Make a really large initCwnd
  BbrCongestionController bbr(conn, config);
  // Make a huge inflight so we don't underflow anything
  auto inflightBytes = 100 * 1000;
  bbr.onPacketSent(makeTestingWritePacket(9, inflightBytes, inflightBytes));
  auto initCwnd = bbr.getCongestionWindow();

  // This also makes sure recoveryWindow_ is larger than inflightBytes
  uint64_t ackedBytes = 1000 * conn.transportSettings.minCwndInMss * 2;
  CongestionController::LossEvent loss;
  loss.lostBytes = 100;
  inflightBytes -= (loss.lostBytes + ackedBytes);
  uint64_t expectedRecoveryWindow = std::max(
      (uint64_t)(initCwnd * kBbrReductionFactor) - loss.lostBytes,
      inflightBytes + ackedBytes);
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
  EXPECT_EQ(event->currentCwnd, 449900);
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
  BbrCongestionController::BbrConfig config;
  BbrCongestionController bbr(conn, config);
  auto mockRttSampler = std::make_unique<MockMinRttSampler>();
  auto mockBandwidthSampler = std::make_unique<MockBandwidthSampler>();
  auto rawRttSampler = mockRttSampler.get();
  auto rawBandwidthSampler = mockBandwidthSampler.get();
  bbr.setRttSampler(std::move(mockRttSampler));
  bbr.setBandwidthSampler(std::move(mockBandwidthSampler));

  auto packet = makeTestingWritePacket(0, 3000, 3000, false);
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
      makeAck(0, 3000, Clock::now(), packet.time), folly::none);
  EXPECT_EQ(startingCwnd + 3000, bbr.getCongestionWindow());
}

TEST_F(BbrTest, LeaveStartup) {
  QuicConnectionStateBase conn(QuicNodeType::Client);
  conn.udpSendPacketLen = 1000;
  BbrCongestionController::BbrConfig config;
  BbrCongestionController bbr(conn, config);
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
        conn.lossState.largestSent, 1000, 1000 + totalSent, false);
    bbr.onPacketSent(packet);
    totalSent += 1000;
    EXPECT_CALL(*rawBandwidthSampler, getBandwidth())
        .WillRepeatedly(Return(
            mockedBandwidth * (growFast ? kExpectedStartupGrowth : 1.0)));
    bbr.onPacketAckOrLoss(
        makeAck(currentLatest, 1000, Clock::now(), packet.time), folly::none);
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
  BbrCongestionController::BbrConfig config;
  BbrCongestionController bbr(conn, config);
  auto writableBytesAfterInit = bbr.getWritableBytes();
  bbr.onPacketSent(makeTestingWritePacket(0, 1000, 1000, 0));
  EXPECT_EQ(writableBytesAfterInit - 1000, bbr.getWritableBytes());
  bbr.onRemoveBytesFromInflight(1000);
  EXPECT_EQ(writableBytesAfterInit, bbr.getWritableBytes());
}

TEST_F(BbrTest, ProbeRtt) {
  QuicConnectionStateBase conn(QuicNodeType::Client);
  conn.udpSendPacketLen = 1000;
  BbrCongestionController::BbrConfig config;
  BbrCongestionController bbr(conn, config);
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
        conn.lossState.largestSent,
        conn.udpSendPacketLen,
        totalSent + conn.udpSendPacketLen,
        false);
    bbr.onPacketSent(packet);
    inflightPackets.push_back(std::make_pair(currentLatest, packet.time));
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
  EXPECT_CALL(*rawBandwidthSampler, onAppLimited()).Times(1);
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
  // counting down both time duration and rtt round.
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

  // Then one more send-ack to end another rtt round.
  sendFunc();
  packetToAck = inflightPackets.front();
  bbr.onPacketAckOrLoss(
      makeAck(
          packetToAck.first,
          conn.udpSendPacketLen,
          packetToAck.second + 3ms,
          packetToAck.second),
      folly::none);
  inflightBytes -= conn.udpSendPacketLen;
  inflightPackets.pop_front();
  EXPECT_EQ(BbrCongestionController::BbrState::ProbeRtt, bbr.state());
  conn.lossState.totalBytesAcked += conn.udpSendPacketLen;

  // And finally, finish the time duration count down
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

TEST_F(BbrTest, NoLargestAckedPacketNoCrash) {
  QuicConnectionStateBase conn(QuicNodeType::Client);
  BbrCongestionController::BbrConfig config;
  BbrCongestionController bbr(conn, config);
  CongestionController::LossEvent loss;
  loss.largestLostPacketNum = 0;
  CongestionController::AckEvent ack;
  bbr.onPacketAckOrLoss(ack, loss);
}

TEST_F(BbrTest, AckAggregation) {
  QuicConnectionStateBase conn(QuicNodeType::Client);
  auto qLogger = std::make_shared<FileQLogger>();
  conn.qLogger = qLogger;
  conn.udpSendPacketLen = 1000;
  BbrCongestionController::BbrConfig config;
  BbrCongestionController bbr(conn, config);
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
        conn.lossState.largestSent, 1000, 1000 + totalSent, false);
    bbr.onPacketSent(packet);
    totalSent += 1000;
    EXPECT_CALL(*rawBandwidthSampler, getBandwidth())
        .WillRepeatedly(Return(
            mockedBandwidth * (growFast ? kExpectedStartupGrowth : 1.0)));
    bbr.onPacketAckOrLoss(
        makeAck(currentLatest, 1000, Clock::now(), packet.time), folly::none);
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
      conn.lossState.largestSent, 1000, 1000 + totalSent, false);
  bbr.onPacketSent(packet);
  totalSent += 1000;
  auto ackEvent = makeAck(currentLatest, 1000, Clock::now(), packet.time);
  ackEvent.ackTime = Clock::now();
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
      conn.lossState.largestSent,
      currentMaxAckHeight * 2 + 100,
      currentMaxAckHeight * 2 + 100 + totalSent,
      false);
  bbr.onPacketSent(packet1);
  totalSent += (currentMaxAckHeight * 2 + 100);
  auto ackEvent2 = makeAck(
      currentLatest, currentMaxAckHeight * 2 + 100, Clock::now(), packet1.time);
  // This will make the expected ack arrival rate very low:
  ackEvent2.ackTime = ackEvent.ackTime + 1us;
  bbr.onPacketAckOrLoss(ackEvent2, folly::none);
  newCwnd = bbr.getCongestionWindow();
  EXPECT_GT(newCwnd, expectedBdp * kProbeBwGain + currentMaxAckHeight);
}

TEST_F(BbrTest, AppLimited) {
  QuicConnectionStateBase conn(QuicNodeType::Client);
  BbrCongestionController::BbrConfig config;
  BbrCongestionController bbr(conn, config);
  auto mockBandwidthSampler = std::make_unique<MockBandwidthSampler>();
  auto rawBandwidthSampler = mockBandwidthSampler.get();
  bbr.setBandwidthSampler(std::move(mockBandwidthSampler));

  auto packet =
      makeTestingWritePacket(conn.lossState.largestSent, 1000, 1000, false);
  bbr.onPacketSent(packet);
  conn.lossState.largestSent++;
  EXPECT_CALL(*rawBandwidthSampler, onAppLimited()).Times(1);
  bbr.setAppLimited();
  EXPECT_CALL(*rawBandwidthSampler, isAppLimited())
      .Times(1)
      .WillOnce(Return(true));
  EXPECT_TRUE(bbr.isAppLimited());
}

TEST_F(BbrTest, AppLimitedIgnored) {
  QuicConnectionStateBase conn(QuicNodeType::Client);
  BbrCongestionController::BbrConfig config;
  BbrCongestionController bbr(conn, config);
  auto mockBandwidthSampler = std::make_unique<MockBandwidthSampler>();
  auto rawBandwidthSampler = mockBandwidthSampler.get();
  bbr.setBandwidthSampler(std::move(mockBandwidthSampler));
  auto cwnd = bbr.getCongestionWindow();
  uint64_t inflightBytes = 0;
  while (inflightBytes <= cwnd) {
    EXPECT_CALL(*rawBandwidthSampler, onAppLimited()).Times(1);
    bbr.setAppLimited();
    auto packet = makeTestingWritePacket(
        conn.lossState.largestSent++, 1000, 1000 + inflightBytes, 0);
    inflightBytes += 1000;
    bbr.onPacketSent(packet);
  }
  // setAppLimited will be ignored:
  EXPECT_CALL(*rawBandwidthSampler, onAppLimited()).Times(0);
  bbr.setAppLimited();
}

TEST_F(BbrTest, ExtendMinRttExpiration) {
  QuicConnectionStateBase conn(QuicNodeType::Client);
  BbrCongestionController::BbrConfig config;
  config.probeRttDisabledIfAppLimited = true;
  BbrCongestionController bbr(conn, config);
  auto mockRttSampler = std::make_unique<MockMinRttSampler>();
  auto mockBandwidthSampler = std::make_unique<MockBandwidthSampler>();
  auto rawRttSampler = mockRttSampler.get();
  auto rawBandwidthSampler = mockBandwidthSampler.get();
  bbr.setRttSampler(std::move(mockRttSampler));
  bbr.setBandwidthSampler(std::move(mockBandwidthSampler));
  EXPECT_CALL(*rawBandwidthSampler, onAppLimited()).Times(1);
  bbr.setAppLimited();

  auto packet =
      makeTestingWritePacket(conn.lossState.largestSent, 1000, 1000, 0);
  bbr.onPacketSent(packet);
  EXPECT_CALL(*rawRttSampler, timestampMinRtt(_)).Times(1);
  bbr.onPacketAckOrLoss(
      makeAck(conn.lossState.largestSent, 1000, Clock::now(), packet.time),
      folly::none);
}

TEST_F(BbrTest, Pacing) {
  QuicConnectionStateBase conn(QuicNodeType::Client);
  conn.lossState.srtt = 1ms;
  conn.udpSendPacketLen = 1000;
  conn.transportSettings.maxBurstPackets = std::numeric_limits<decltype(
      conn.transportSettings.maxBurstPackets)>::max();
  conn.transportSettings.pacingEnabled = true;
  auto qLogger = std::make_shared<FileQLogger>();
  conn.qLogger = qLogger;

  BbrCongestionController::BbrConfig config;
  BbrCongestionController bbr(conn, config);
  bbr.setMinimalPacingInterval(1ms);
  auto mockBandwidthSampler = std::make_unique<MockBandwidthSampler>();
  auto rawBandwidthSampler = mockBandwidthSampler.get();
  bbr.setBandwidthSampler(std::move(mockBandwidthSampler));
  auto mockRttSampler = std::make_unique<MockMinRttSampler>();
  auto rawRttSampler = mockRttSampler.get();
  bbr.setRttSampler(std::move(mockRttSampler));
  auto expectedMinRtt = 20ms;
  EXPECT_CALL(*rawRttSampler, minRtt()).WillRepeatedly(Return(expectedMinRtt));
  // Avoid ProbeRtt during this test case
  EXPECT_CALL(*rawRttSampler, minRttExpired()).WillRepeatedly(Return(false));

  PacketNum currentLatest = 0;
  uint64_t totalSent = 0;
  Bandwidth mockedBandwidth(2000 * 1000, 1ms);
  std::deque<std::pair<PacketNum, TimePoint>> inflightPackets;
  auto sendFunc = [&]() {
    conn.lossState.largestSent = currentLatest;
    auto packet = makeTestingWritePacket(
        conn.lossState.largestSent, 1000, totalSent + 1000, false);
    bbr.onPacketSent(packet);
    inflightPackets.push_back(std::make_pair(currentLatest, packet.time));
    totalSent += 1000;
    currentLatest++;
  };
  auto ackAndGrow = [&](PacketNum packetToAck, TimePoint sentTime) {
    EXPECT_CALL(*rawBandwidthSampler, getBandwidth())
        .WillRepeatedly(Return(mockedBandwidth));
    bbr.onPacketAckOrLoss(
        makeAck(packetToAck, 1000, Clock::now(), sentTime), folly::none);
    conn.lossState.totalBytesAcked += 1000;
  };

  auto sendAckGrow = [&](TimePoint ackTime) {
    conn.lossState.largestSent = currentLatest;
    auto packet = makeTestingWritePacket(
        conn.lossState.largestSent,
        1000,
        totalSent + 1000,
        false,
        ackTime - 1us);
    bbr.onPacketSent(packet);
    totalSent += 1000;
    EXPECT_CALL(*rawBandwidthSampler, getBandwidth())
        .WillRepeatedly(Return(mockedBandwidth));
    // Make sure when we take Clock::now() inside updateRoundTripCounter, it
    // will be later than ackTime - 1us when ackTime is Clock::now().
    std::this_thread::sleep_for(1us);
    bbr.onPacketAckOrLoss(
        makeAck(currentLatest, 1000, ackTime, packet.time), folly::none);
    conn.lossState.totalBytesAcked += 1000;
    currentLatest++;
  };

  // Take it to ProbeBw first
  std::vector<uint64_t> pacingRateVec;
  for (uint32_t i = 0; i < kStartupSlowGrowRoundLimit + 2; i++) {
    sendAckGrow(Clock::now());
    pacingRateVec.push_back(bbr.getPacingRate(Clock::now()));
  }

  std::vector<int> indices =
      getQLogEventIndices(QLogEventType::PacingMetricUpdate, qLogger);
  EXPECT_EQ(indices.size(), kStartupSlowGrowRoundLimit + 2);
  for (uint32_t i = 0; i < kStartupSlowGrowRoundLimit + 2; i++) {
    auto tmp = std::move(qLogger->logs[indices[i]]);
    auto event = dynamic_cast<QLogPacingMetricUpdateEvent*>(tmp.get());
    EXPECT_EQ(event->pacingBurstSize, pacingRateVec[i]);
    EXPECT_EQ(event->pacingInterval, bbr.getPacingInterval());
  }

  for (size_t i = 0; i < 5; i++) {
    sendFunc();
  }
  while (inflightPackets.size() &&
         bbr.state() != BbrCongestionController::BbrState::ProbeBw) {
    auto packetToAck = inflightPackets.back();
    ackAndGrow(packetToAck.first, packetToAck.second);
    inflightPackets.pop_back();
  }
  ASSERT_EQ(BbrCongestionController::BbrState::ProbeBw, bbr.state());
  auto currentTime = Clock::now(); // cycleStart_ is before this TimePoint

  // Throw out a big inflight bytes there. What a hack.
  for (size_t i = 0; i < 100000; i++) {
    sendFunc();
  }
  // Loop through kPacingGainCycles, we will collect 3 different burst sizes
  std::set<uint64_t> burstSizes;
  for (size_t i = 0; i < kNumOfCycles; i++) {
    auto nextAckTime = currentTime + expectedMinRtt + 50us;
    sendAckGrow(nextAckTime);
    burstSizes.insert(bbr.getPacingRate(Clock::now()));
    currentTime = nextAckTime;
  }
  EXPECT_EQ(3, burstSizes.size());
}

TEST_F(BbrTest, BytesCounting) {
  QuicConnectionStateBase conn(QuicNodeType::Client);
  BbrCongestionController::BbrConfig config;
  BbrCongestionController bbr(conn, config);
  bbr.setBandwidthSampler(std::make_unique<BbrBandwidthSampler>(conn));

  PacketNum packetNum = 0;
  auto packet = makeTestingWritePacket(packetNum, 1200, 1200, false);
  conn.outstandingPackets.push_back(packet);
  ReadAckFrame ackFrame;
  ackFrame.largestAcked = packetNum;
  ackFrame.ackBlocks.emplace_back(packetNum, packetNum);
  auto ackVisitor = [&](auto&, auto&, auto&) {};
  auto lossVisitor = [&](auto&, auto&, bool, PacketNum) {};
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
  auto qLogger = std::make_shared<FileQLogger>();
  conn.qLogger = qLogger;
  BbrCongestionController::BbrConfig config;
  BbrCongestionController bbr(conn, config);

  bbr.setAppIdle(true, Clock::now());

  std::vector<int> indices =
      getQLogEventIndices(QLogEventType::AppIdleUpdate, qLogger);
  EXPECT_EQ(indices.size(), 1);
  auto tmp = std::move(qLogger->logs[indices[0]]);
  auto event = dynamic_cast<QLogAppIdleUpdateEvent*>(tmp.get());
  EXPECT_EQ(event->idleEvent, kAppIdle.str());
  EXPECT_TRUE(event->idle);
}

} // namespace test
} // namespace quic
