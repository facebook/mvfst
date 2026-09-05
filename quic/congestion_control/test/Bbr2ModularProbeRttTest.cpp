/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <folly/portability/GMock.h>
#include <folly/portability/GTest.h>
#include <quic/common/test/TestUtils.h>
#include <quic/congestion_control/modular/Bbr2ProbeRtt.h>
#include <quic/congestion_control/modular/Bbr2Startup.h>
#include <quic/congestion_control/test/Utils.h>
#include <quic/state/test/Mocks.h>

using namespace testing;

namespace quic {

class Bbr2ModularTestPeer {
 public:
  static std::shared_ptr<Bbr2Shared> shared(const Bbr2Startup& controller) {
    return controller.shared_;
  }

  static void setMinRttState(
      Bbr2Shared& shared,
      std::chrono::microseconds minRtt,
      TimePoint timestamp) {
    shared.minRtt_ = minRtt;
    shared.minRttTimestamp_ = timestamp;
    shared.minRttExpired_ = false;
  }

  static std::chrono::microseconds minRtt(const Bbr2Shared& shared) {
    return shared.minRtt_;
  }

  static TimePoint minRttTimestamp(const Bbr2Shared& shared) {
    return shared.minRttTimestamp_.value();
  }

  static void setMinRttExpired(Bbr2Shared& shared, bool expired) {
    shared.minRttExpired_ = expired;
  }

  static void setIdleRestart(Bbr2Shared& shared, bool idleRestart) {
    shared.idleRestart_ = idleRestart;
  }

  static void setBandwidth(Bbr2Shared& shared, Bandwidth bandwidth) {
    shared.bandwidth_ = bandwidth;
  }

  static void setCwnd(Bbr2Shared& shared, uint64_t cwnd) {
    shared.cwndBytes_ = cwnd;
  }

  static Optional<uint64_t> probeRttCwnd(const Bbr2Shared& shared) {
    return shared.probeRttCwnd_;
  }

  static void setProbeRttCwnd(Bbr2Shared& shared, Optional<uint64_t> cwnd) {
    shared.probeRttCwnd_ = cwnd;
  }

  static bool returnedFromProbeRtt(const Bbr2Shared& shared) {
    return shared.returnedFromProbeRtt_;
  }

  static bool roundStarted(const Bbr2Shared& shared) {
    return shared.roundStart_;
  }

  static Optional<TimePoint> probeRttDoneTimestamp(
      const Bbr2ProbeRtt& probeRtt) {
    return probeRtt.probeRttDoneTimestamp_;
  }

  static void setProbeRttDoneTimestamp(
      Bbr2ProbeRtt& probeRtt,
      TimePoint timestamp) {
    probeRtt.probeRttDoneTimestamp_ = timestamp;
  }
};

namespace test {

namespace {

constexpr uint64_t kPacketSize = 1000;
const Bandwidth kBandwidth(100'000, 1s);

AckEvent makeAck(OptionalMicros rttSample = std::nullopt) {
  const auto ackTime = Clock::now();
  auto ack = AckEvent::Builder()
                 .setAckTime(ackTime)
                 .setAdjustedAckTime(ackTime)
                 .setAckDelay(0us)
                 .setPacketNumberSpace(PacketNumberSpace::AppData)
                 .setLargestAckedPacket(0)
                 .build();
  ack.rttSample = rttSample;
  return ack;
}

AckEvent makeRoundCompletingAck(
    OutstandingPacketWrapper packet,
    uint64_t totalBytesAcked) {
  const auto packetNum = packet.getPacketSequenceNum();
  const auto packetSize = packet.metadata.encodedSize;
  const auto sentTime = packet.metadata.time;
  const auto ackTime = Clock::now();
  auto ack = AckEvent::Builder()
                 .setAckTime(ackTime)
                 .setAdjustedAckTime(ackTime)
                 .setAckDelay(0us)
                 .setPacketNumberSpace(PacketNumberSpace::AppData)
                 .setLargestAckedPacket(packetNum)
                 .build();
  ack.ackedBytes = packetSize;
  ack.totalBytesAcked = totalBytesAcked;
  ack.largestNewlyAckedPacket = packetNum;
  ack.ackedPackets.emplace_back(
      makeAckPacketFromOutstandingPacket(std::move(packet)));
  ack.largestNewlyAckedPacketSentTime = sentTime;
  return ack;
}

} // namespace

class Bbr2ModularProbeRttTest : public Test {
 public:
  void SetUp() override {
    conn_ = std::make_unique<QuicConnectionStateBase>(QuicNodeType::Client);
    conn_->pacer = std::make_unique<NiceMock<MockPacer>>();
    conn_->udpSendPacketLen = kPacketSize;
    conn_->connectionTime = Clock::now() - 2s;
    conn_->transportSettings.ccaConfig.paceInitCwnd = true;
  }

 protected:
  std::unique_ptr<QuicConnectionStateBase> conn_;
};

TEST_F(Bbr2ModularProbeRttTest, InitialRttSampleDoesNotTriggerProbeRtt) {
  Bbr2Startup startup(*conn_);
  auto shared = Bbr2ModularTestPeer::shared(startup);
  const auto ack = makeAck(100ms);

  shared->updateMinRtt(ack);

  EXPECT_EQ(100ms, Bbr2ModularTestPeer::minRtt(*shared));
  EXPECT_FALSE(shared->shouldEnterProbeRtt());
  EXPECT_EQ(std::nullopt, Bbr2ModularTestPeer::probeRttCwnd(*shared));
}

TEST_F(Bbr2ModularProbeRttTest, MinRttExpiresOnlyAfterTenSecondWindow) {
  Bbr2Startup startup(*conn_);
  auto shared = Bbr2ModularTestPeer::shared(startup);
  Bbr2ModularTestPeer::setBandwidth(*shared, kBandwidth);
  Bbr2ModularTestPeer::setMinRttState(*shared, 200ms, Clock::now() - 9s);
  const auto ack = makeAck(300ms);

  shared->updateMinRtt(ack);

  EXPECT_FALSE(shared->shouldEnterProbeRtt());
  EXPECT_EQ(200ms, Bbr2ModularTestPeer::minRtt(*shared));
  EXPECT_EQ(std::nullopt, Bbr2ModularTestPeer::probeRttCwnd(*shared));

  Bbr2ModularTestPeer::setMinRttState(*shared, 200ms, Clock::now() - 11s);
  const auto updateStart = Clock::now();
  shared->updateMinRtt(ack);

  EXPECT_TRUE(shared->shouldEnterProbeRtt());
  EXPECT_EQ(300ms, Bbr2ModularTestPeer::minRtt(*shared));
  const auto probeRttCwnd = Bbr2ModularTestPeer::probeRttCwnd(*shared);
  ASSERT_TRUE(probeRttCwnd.has_value());
  EXPECT_EQ(10'000, *probeRttCwnd);
  EXPECT_GE(Bbr2ModularTestPeer::minRttTimestamp(*shared), updateStart);
}

TEST_F(
    Bbr2ModularProbeRttTest,
    ExpiredMinRttWithoutFreshSamplePreservesFilter) {
  Bbr2Startup startup(*conn_);
  auto shared = Bbr2ModularTestPeer::shared(startup);
  const auto oldTimestamp = Clock::now() - 11s;
  Bbr2ModularTestPeer::setBandwidth(*shared, kBandwidth);
  Bbr2ModularTestPeer::setMinRttState(*shared, 200ms, oldTimestamp);
  conn_->lossState.lrtt = 300ms;
  const auto ack = makeAck();

  shared->updateMinRtt(ack);

  EXPECT_TRUE(shared->shouldEnterProbeRtt());
  EXPECT_EQ(200ms, Bbr2ModularTestPeer::minRtt(*shared));
  EXPECT_EQ(oldTimestamp, Bbr2ModularTestPeer::minRttTimestamp(*shared));
  EXPECT_EQ(std::nullopt, Bbr2ModularTestPeer::probeRttCwnd(*shared));
}

TEST_F(Bbr2ModularProbeRttTest, EqualRttRefreshesMinRttTimestamp) {
  Bbr2Startup startup(*conn_);
  auto shared = Bbr2ModularTestPeer::shared(startup);
  const auto oldTimestamp = Clock::now() - 5s;
  Bbr2ModularTestPeer::setMinRttState(*shared, 100ms, oldTimestamp);
  conn_->lossState.lrtt = 50ms;
  const auto equalRttAck = makeAck(100ms);

  shared->updateMinRtt(equalRttAck);

  const auto refreshedTimestamp = Bbr2ModularTestPeer::minRttTimestamp(*shared);
  EXPECT_GT(refreshedTimestamp, oldTimestamp);
  EXPECT_FALSE(shared->shouldEnterProbeRtt());

  const auto largerRttAck = makeAck(101ms);
  shared->updateMinRtt(largerRttAck);

  EXPECT_EQ(100ms, Bbr2ModularTestPeer::minRtt(*shared));
  EXPECT_EQ(refreshedTimestamp, Bbr2ModularTestPeer::minRttTimestamp(*shared));

  const auto noRttAck = makeAck();
  shared->updateMinRtt(noRttAck);

  EXPECT_EQ(100ms, Bbr2ModularTestPeer::minRtt(*shared));
  EXPECT_EQ(refreshedTimestamp, Bbr2ModularTestPeer::minRttTimestamp(*shared));
}

TEST_F(Bbr2ModularProbeRttTest, IdleRestartRefreshesWithoutEnteringProbeRtt) {
  Bbr2Startup startup(*conn_);
  auto shared = Bbr2ModularTestPeer::shared(startup);
  Bbr2ModularTestPeer::setBandwidth(*shared, kBandwidth);
  Bbr2ModularTestPeer::setMinRttState(*shared, 200ms, Clock::now() - 11s);
  Bbr2ModularTestPeer::setIdleRestart(*shared, true);
  const auto freshRttAck = makeAck(300ms);

  shared->updateMinRtt(freshRttAck);

  EXPECT_FALSE(shared->shouldEnterProbeRtt());
  EXPECT_EQ(300ms, Bbr2ModularTestPeer::minRtt(*shared));
  const auto probeRttCwnd = Bbr2ModularTestPeer::probeRttCwnd(*shared);
  ASSERT_TRUE(probeRttCwnd.has_value());
  EXPECT_EQ(10'000, *probeRttCwnd);

  Bbr2ModularTestPeer::setIdleRestart(*shared, false);
  const auto noRttAck = makeAck();
  shared->updateMinRtt(noRttAck);
  EXPECT_FALSE(shared->shouldEnterProbeRtt());
}

TEST_F(Bbr2ModularProbeRttTest, ProbeRttCwndFallsBackToCurrentHalfBdp) {
  auto startup = std::make_unique<Bbr2Startup>(*conn_);
  auto shared = Bbr2ModularTestPeer::shared(*startup);
  Bbr2ModularTestPeer::setBandwidth(*shared, kBandwidth);
  Bbr2ModularTestPeer::setCwnd(*shared, 30'000);
  Bbr2ModularTestPeer::setMinRttState(*shared, 200ms, Clock::now() - 11s);
  conn_->lossState.lrtt = 300ms;
  const auto noRttAck = makeAck();
  shared->updateMinRtt(noRttAck);
  ASSERT_TRUE(shared->shouldEnterProbeRtt());
  ASSERT_EQ(std::nullopt, Bbr2ModularTestPeer::probeRttCwnd(*shared));

  conn_->lossState.inflightBytes = 20'000;
  Bbr2ProbeRtt probeRtt(*conn_, shared, std::move(startup));
  probeRtt.finishAckProcessing(noRttAck);

  EXPECT_EQ(10'000, probeRtt.getCongestionWindow());
}

TEST_F(Bbr2ModularProbeRttTest, ProbeRttCwndUsesSavedAndCurrentMinima) {
  auto startup = std::make_unique<Bbr2Startup>(*conn_);
  auto shared = Bbr2ModularTestPeer::shared(*startup);
  Bbr2ModularTestPeer::setBandwidth(*shared, kBandwidth);
  Bbr2ModularTestPeer::setCwnd(*shared, 30'000);
  Bbr2ModularTestPeer::setMinRttState(*shared, 200ms, Clock::now() - 11s);
  const auto initialAck = makeAck(300ms);
  shared->updateMinRtt(initialAck);
  ASSERT_TRUE(shared->shouldEnterProbeRtt());

  conn_->lossState.inflightBytes = 20'000;
  Bbr2ProbeRtt probeRtt(*conn_, shared, std::move(startup));
  probeRtt.finishAckProcessing(initialAck);
  EXPECT_EQ(10'000, probeRtt.getCongestionWindow());

  const auto lowerRttAck = makeAck(100ms);
  shared->updateMinRtt(lowerRttAck);
  probeRtt.finishAckProcessing(lowerRttAck);
  EXPECT_EQ(5'000, probeRtt.getCongestionWindow());

  const auto floorRttAck = makeAck(10ms);
  shared->updateMinRtt(floorRttAck);
  probeRtt.finishAckProcessing(floorRttAck);
  EXPECT_EQ(kMinCwndInMssForBbr * kPacketSize, probeRtt.getCongestionWindow());
}

TEST_F(Bbr2ModularProbeRttTest, ProbeRttExitRefreshesMinRttClock) {
  auto startup = std::make_unique<Bbr2Startup>(*conn_);
  auto* startupPtr = startup.get();
  auto shared = Bbr2ModularTestPeer::shared(*startup);
  Bbr2ModularTestPeer::setBandwidth(*shared, kBandwidth);
  Bbr2ModularTestPeer::setCwnd(*shared, 20'000);
  Bbr2ModularTestPeer::setMinRttState(*shared, 100ms, Clock::now() - 11s);
  const auto freshRttAck = makeAck(100ms);
  shared->updateMinRtt(freshRttAck);

  const auto sentTime = Clock::now() - 5ms;
  auto firstRoundPacket =
      makeTestingWritePacket(0, kPacketSize, kPacketSize, sentTime);
  firstRoundPacket.lastAckedPacketInfo.emplace(
      sentTime - 1ms, sentTime - 1ms, sentTime - 1ms, 0, 0);
  auto outstandingPacket =
      makeTestingWritePacket(1, kPacketSize, 2 * kPacketSize, sentTime);
  conn_->lossState.totalBytesSent = 2 * kPacketSize;
  onPacketsSentWrapper(conn_.get(), startup.get(), firstRoundPacket);
  onPacketsSentWrapper(conn_.get(), startup.get(), outstandingPacket);

  const auto probeRttStart = Clock::now();
  auto probeRtt =
      std::make_unique<Bbr2ProbeRtt>(*conn_, shared, std::move(startup));
  const auto probeRttStarted = Clock::now();
  auto* probeRttPtr = probeRtt.get();
  conn_->congestionController = std::move(probeRtt);

  const auto doneTimestamp =
      Bbr2ModularTestPeer::probeRttDoneTimestamp(*probeRttPtr);
  ASSERT_TRUE(doneTimestamp.has_value());
  EXPECT_GE(*doneTimestamp, probeRttStart + kBbr2ProbeRttDuration);
  EXPECT_LE(*doneTimestamp, probeRttStarted + kBbr2ProbeRttDuration);

  Bbr2ModularTestPeer::setMinRttState(*shared, 100ms, Clock::now() - 11s);
  Bbr2ModularTestPeer::setMinRttExpired(*shared, true);
  conn_->lossState.lrtt = 0us;
  Bbr2ModularTestPeer::setProbeRttDoneTimestamp(
      *probeRttPtr, Clock::now() + 1s);
  conn_->lossState.totalBytesAcked = kPacketSize;
  onPacketAckOrLossWrapper(
      conn_.get(),
      probeRttPtr,
      makeRoundCompletingAck(std::move(firstRoundPacket), kPacketSize),
      std::nullopt);

  EXPECT_EQ(probeRttPtr, conn_->congestionController.get());
  EXPECT_FALSE(Bbr2ModularTestPeer::returnedFromProbeRtt(*shared));
  EXPECT_TRUE(Bbr2ModularTestPeer::roundStarted(*shared));
  EXPECT_EQ(kPacketSize, conn_->lossState.inflightBytes);

  const auto secondRoundSentTime = Clock::now() - 1ms;
  auto secondRoundPacket = makeTestingWritePacket(
      2, kPacketSize, 3 * kPacketSize, secondRoundSentTime);
  secondRoundPacket.lastAckedPacketInfo.emplace(
      sentTime, sentTime, sentTime, 2 * kPacketSize, kPacketSize);
  conn_->lossState.totalBytesSent = 3 * kPacketSize;
  onPacketsSentWrapper(conn_.get(), probeRttPtr, secondRoundPacket);
  Bbr2ModularTestPeer::setProbeRttDoneTimestamp(
      *probeRttPtr, Clock::now() - 1us);
  const auto exitStart = Clock::now();
  conn_->lossState.totalBytesAcked = 2 * kPacketSize;
  auto exitAck =
      makeRoundCompletingAck(std::move(secondRoundPacket), 2 * kPacketSize);
  exitAck.rttSample = 100ms;
  onPacketAckOrLossWrapper(
      conn_.get(), probeRttPtr, std::move(exitAck), std::nullopt);

  EXPECT_EQ(startupPtr, conn_->congestionController.get());
  EXPECT_EQ(kPacketSize, conn_->lossState.inflightBytes);
  EXPECT_TRUE(Bbr2ModularTestPeer::roundStarted(*shared));
  EXPECT_TRUE(Bbr2ModularTestPeer::returnedFromProbeRtt(*shared));
  EXPECT_FALSE(shared->shouldEnterProbeRtt());
  EXPECT_GE(Bbr2ModularTestPeer::minRttTimestamp(*shared), exitStart);
  EXPECT_EQ(std::nullopt, Bbr2ModularTestPeer::probeRttCwnd(*shared));

  conn_->lossState.lrtt = 50ms;
  const auto noRttAck = makeAck();
  shared->updateMinRtt(noRttAck);
  EXPECT_FALSE(shared->shouldEnterProbeRtt());
}

} // namespace test
} // namespace quic
