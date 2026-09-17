/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <folly/portability/GMock.h>
#include <folly/portability/GTest.h>
#include <quic/common/test/TestUtils.h>
#include <quic/congestion_control/Bbr2.h>
#include <quic/congestion_control/test/Utils.h>
#include <quic/state/AckHandlers.h>
#include <quic/state/test/Mocks.h>

using namespace testing;

namespace quic {

class Bbr2TestPeer {
 public:
  using RecoveryState = Bbr2CongestionController::RecoveryState;

  static void setModelState(
      Bbr2CongestionController& controller,
      uint64_t cwndBytes,
      Optional<Bandwidth> bandwidthShortTerm,
      Optional<uint64_t> inflightShortTerm,
      Optional<uint64_t> inflightLongTerm) {
    controller.cwndBytes_ = cwndBytes;
    controller.bandwidthShortTerm_ = std::move(bandwidthShortTerm);
    controller.inflightShortTerm_ = inflightShortTerm;
    controller.inflightLongTerm_ = inflightLongTerm;
  }

  static uint64_t cwnd(const Bbr2CongestionController& controller) {
    return controller.cwndBytes_;
  }

  static Optional<Bandwidth> bandwidthShortTerm(
      const Bbr2CongestionController& controller) {
    return controller.bandwidthShortTerm_;
  }

  static Optional<uint64_t> inflightShortTerm(
      const Bbr2CongestionController& controller) {
    return controller.inflightShortTerm_;
  }

  static Optional<uint64_t> inflightLongTerm(
      const Bbr2CongestionController& controller) {
    return controller.inflightLongTerm_;
  }

  static RecoveryState recoveryState(
      const Bbr2CongestionController& controller) {
    return controller.recoveryState_;
  }

  static bool hasUndoState(const Bbr2CongestionController& controller) {
    return controller.spuriousLossUndoState_.has_value();
  }

  static uint64_t pendingLostPackets(
      const Bbr2CongestionController& controller) {
    return controller.spuriousLossUndoState_->pendingLostPackets;
  }

  static uint64_t undoPriorCwnd(const Bbr2CongestionController& controller) {
    return controller.spuriousLossUndoState_->priorCwndBytes;
  }

  static void setState(
      Bbr2CongestionController& controller,
      Bbr2CongestionController::State state) {
    controller.state_ = state;
    controller.updatePacingAndCwndGain();
  }

  static void enterProbeBw(Bbr2CongestionController& controller) {
    controller.fullBwReached_ = true;
    controller.enterProbeBW();
  }

  static void enterProbeRtt(Bbr2CongestionController& controller) {
    controller.enterProbeRtt();
  }

  static void exitProbeRtt(Bbr2CongestionController& controller) {
    controller.exitProbeRtt();
  }

  static void setBandwidthModel(
      Bbr2CongestionController& controller,
      Bandwidth bandwidth,
      std::chrono::microseconds minRtt) {
    controller.maxBwFilter_.Update(bandwidth, controller.cycleCount_);
    controller.bandwidth_ = bandwidth;
    controller.minRtt_ = minRtt;
  }

  static void setBandwidthSample(
      Bbr2CongestionController& controller,
      Bandwidth sample) {
    controller.currentBwSample_ = sample;
  }

  static Bandwidth bandwidthSample(const Bbr2CongestionController& controller) {
    return controller.currentBwSample_;
  }

  static uint64_t recoveryWindow(const Bbr2CongestionController& controller) {
    return controller.recoveryWindow_;
  }

  static uint64_t previousCwnd(const Bbr2CongestionController& controller) {
    return controller.previousCwndBytes_;
  }

  static bool fullBwReached(const Bbr2CongestionController& controller) {
    return controller.fullBwReached_;
  }

  static void setFullBwCount(
      Bbr2CongestionController& controller,
      uint64_t count) {
    controller.fullBwCount_ = count;
  }

  static uint64_t fullBwCount(const Bbr2CongestionController& controller) {
    return controller.fullBwCount_;
  }

  static bool fullBwNow(const Bbr2CongestionController& controller) {
    return controller.fullBwNow_;
  }

  static float lossPctInLastRound(const Bbr2CongestionController& controller) {
    return controller.lossPctInLastRound_;
  }

  static uint64_t lossEventsInLastRound(
      const Bbr2CongestionController& controller) {
    return controller.lossEventsInLastRound_;
  }

  static void finishProbeRtt(Bbr2CongestionController& controller) {
    controller.probeRttDoneTimestamp_ = Clock::now() - 1s;
  }

  static void enableLongTermLossUpdate(Bbr2CongestionController& controller) {
    controller.canUpdateLongtermLossModel_ = true;
  }

  static void setCurrentLossSignals(
      Bbr2CongestionController& controller,
      uint64_t lossBytes,
      uint64_t lossEvents,
      PacketNum largestLostPacket) {
    controller.lossBytesInRound_ = lossBytes;
    controller.lossEventsInRound_ = lossEvents;
    controller.largestLostPacketNumInRound_ = largestLostPacket;
  }

  static uint64_t lossBytesInRound(const Bbr2CongestionController& controller) {
    return controller.lossBytesInRound_;
  }

  static uint64_t lossEventsInRound(
      const Bbr2CongestionController& controller) {
    return controller.lossEventsInRound_;
  }

  static PacketNum largestLostPacketNumInRound(
      const Bbr2CongestionController& controller) {
    return controller.largestLostPacketNumInRound_;
  }
};

namespace test {

namespace {

constexpr uint64_t kPacketSize = 1000;
const Bandwidth kSavedBandwidth(12'000, 1s);
const Bandwidth kReducedBandwidth(6'000, 1s);
const Bandwidth kHigherBandwidth(18'000, 1s);

AckEvent makeSpuriousAck(uint64_t numPackets) {
  const auto ackTime = Clock::now();
  auto ack = AckEvent::Builder()
                 .setAckTime(ackTime)
                 .setAdjustedAckTime(ackTime)
                 .setAckDelay(0us)
                 .setPacketNumberSpace(PacketNumberSpace::AppData)
                 .setLargestAckedPacket(0)
                 .build();
  ack.numPacketsSpuriouslyAcked = numPackets;
  return ack;
}

} // namespace

class Bbr2SpuriousLossTest : public Test {
 public:
  void SetUp() override {
    conn_ = std::make_unique<QuicConnectionStateBase>(QuicNodeType::Client);
    auto pacer = std::make_unique<NiceMock<MockPacer>>();
    pacer_ = pacer.get();
    conn_->pacer = std::move(pacer);
    conn_->udpSendPacketLen = kPacketSize;
    conn_->connectionTime = Clock::now() - 2s;
    conn_->transportSettings.ccaConfig.paceInitCwnd = true;
  }

 protected:
  LossEvent makeLoss(
      CongestionController& controller,
      uint64_t numPackets,
      bool persistentCongestion = false,
      Optional<TimePoint> sentTime = std::nullopt) {
    LossEvent loss;
    for (uint64_t i = 0; i < numPackets; ++i) {
      totalBytesSent_ += kPacketSize;
      auto packet = makeTestingWritePacket(
          nextPacketNum_++,
          kPacketSize,
          totalBytesSent_,
          sentTime.value_or(Clock::now() - 1s));
      onPacketsSentWrapper(conn_.get(), &controller, packet);
      loss.addLostPacket(packet);
    }
    loss.persistentCongestion = persistentCongestion;
    return loss;
  }

  void processEvent(
      CongestionController& controller,
      Optional<AckEvent> ack,
      Optional<LossEvent> loss) {
    const auto numPacketsSpuriouslyAcked =
        ack ? ack->numPacketsSpuriouslyAcked : 0;
    ASSERT_LE(numPacketsSpuriouslyAcked, conn_->outstandings.declaredLostCount);
    conn_->outstandings.declaredLostCount -= numPacketsSpuriouslyAcked;
    if (loss) {
      conn_->outstandings.declaredLostCount += loss->lostPackets;
    }
    onPacketAckOrLossWrapper(
        conn_.get(), &controller, std::move(ack), std::move(loss));
  }

  void startLossEpisode(
      CongestionController& controller,
      uint64_t numPackets = 1,
      bool persistentCongestion = false,
      Optional<TimePoint> sentTime = std::nullopt) {
    processEvent(
        controller,
        std::nullopt,
        makeLoss(controller, numPackets, persistentCongestion, sentTime));
  }

  void expectRepace() {
    EXPECT_CALL(*pacer_, setRttFactor(_, _)).Times(1);
    EXPECT_CALL(*pacer_, refreshPacingRate(_, _, _)).Times(1);
  }

  void processRoundAck(
      Bbr2CongestionController& controller,
      Optional<LossEvent> loss = std::nullopt,
      uint64_t numPacketsSpuriouslyAcked = 0,
      bool startsLossRound = true,
      bool isAppLimited = false) {
    const auto previousTotalBytesAcked = conn_->lossState.totalBytesAcked;
    const auto sentTime = Clock::now() - 10ms;
    totalBytesSent_ += kPacketSize;
    auto packet = makeTestingWritePacket(
        nextPacketNum_++,
        kPacketSize,
        startsLossRound ? totalBytesSent_ : 0,
        sentTime);
    packet.isAppLimited = isAppLimited;
    packet.lastAckedPacketInfo.emplace(
        sentTime - 1ms,
        sentTime - 1ms,
        sentTime - 1ms,
        totalBytesSent_ - kPacketSize,
        previousTotalBytesAcked);
    onPacketsSentWrapper(conn_.get(), &controller, packet);

    auto ack = makeAck(
        packet.getPacketSequenceNum(), kPacketSize, Clock::now(), sentTime);
    ack.ackedPackets.front() =
        makeAckPacketFromOutstandingPacket(std::move(packet));
    ack.totalBytesAcked = previousTotalBytesAcked + kPacketSize;
    ack.numPacketsSpuriouslyAcked = numPacketsSpuriouslyAcked;
    conn_->lossState.totalBytesAcked = ack.totalBytesAcked;
    conn_->lossState.totalBytesSent = totalBytesSent_;
    processEvent(controller, std::move(ack), std::move(loss));
  }

  LossEvent makeNoncontiguousLoss(
      Bbr2CongestionController& controller,
      bool retainPackets = false) {
    LossEvent loss;
    for (uint64_t i = 0; i < 6; ++i) {
      nextPacketNum_ += 2;
      totalBytesSent_ += kPacketSize;
      auto packet = makeTestingWritePacket(
          nextPacketNum_, kPacketSize, totalBytesSent_, Clock::now() - 1s);
      onPacketsSentWrapper(conn_.get(), &controller, packet);
      loss.addLostPacket(packet);
      if (retainPackets) {
        packet.declaredLost = true;
        conn_->outstandings.packets.emplace_back(std::move(packet));
      }
    }
    ++nextPacketNum_;
    return loss;
  }

  void exitStartupOnLoss(Bbr2CongestionController& controller) {
    conn_->transportSettings.ccaConfig.exitStartupOnLoss = true;
    conn_->lossState.inflightBytes = 50 * kPacketSize;
    processRoundAck(controller, makeNoncontiguousLoss(controller), 0, false);
    ASSERT_EQ(Bbr2CongestionController::State::Startup, controller.getState());
    processRoundAck(controller);
    ASSERT_EQ(Bbr2CongestionController::State::Drain, controller.getState());
    ASSERT_TRUE(Bbr2TestPeer::fullBwReached(controller));
    ASSERT_FALSE(Bbr2TestPeer::fullBwNow(controller));
  }

  std::unique_ptr<QuicConnectionStateBase> conn_;
  MockPacer* pacer_{nullptr};
  PacketNum nextPacketNum_{0};
  uint64_t totalBytesSent_{0};
};

TEST_F(Bbr2SpuriousLossTest, DisabledByDefault) {
  Bbr2CongestionController controller(*conn_);
  Bbr2TestPeer::setModelState(
      controller, 20'000, kSavedBandwidth, 16'000, 18'000);
  startLossEpisode(controller);
  Bbr2TestPeer::setModelState(
      controller, 8'000, kReducedBandwidth, 7'000, 9'000);

  EXPECT_CALL(*pacer_, setRttFactor(_, _)).Times(0);
  EXPECT_CALL(*pacer_, refreshPacingRate(_, _, _)).Times(0);
  processEvent(controller, makeSpuriousAck(1), std::nullopt);

  EXPECT_EQ(8'000, Bbr2TestPeer::cwnd(controller));
  EXPECT_EQ(
      kReducedBandwidth, Bbr2TestPeer::bandwidthShortTerm(controller).value());
  EXPECT_EQ(7'000, Bbr2TestPeer::inflightShortTerm(controller).value());
  EXPECT_EQ(9'000, Bbr2TestPeer::inflightLongTerm(controller).value());
  EXPECT_FALSE(Bbr2TestPeer::hasUndoState(controller));
  EXPECT_NE(
      Bbr2TestPeer::RecoveryState::NOT_RECOVERY,
      Bbr2TestPeer::recoveryState(controller));
}

TEST_F(Bbr2SpuriousLossTest, UndoesRealLossResponse) {
  conn_->transportSettings.ccaConfig.enableSpuriousLossRecovery = true;
  Bbr2CongestionController controller(*conn_);
  const auto cwndBeforeLoss = controller.getCongestionWindow();

  const auto sentTime = Clock::now() - 10ms;
  const auto ackedPacketNum = nextPacketNum_++;
  totalBytesSent_ += kPacketSize;
  auto ackedPacket = makeTestingWritePacket(
      ackedPacketNum, kPacketSize, totalBytesSent_, sentTime);
  onPacketsSentWrapper(conn_.get(), &controller, ackedPacket);
  auto loss = makeLoss(controller, 1);

  processEvent(
      controller,
      makeAck(ackedPacketNum, kPacketSize, Clock::now(), sentTime),
      std::move(loss));
  const auto cwndAfterLoss = controller.getCongestionWindow();
  EXPECT_LT(cwndAfterLoss, cwndBeforeLoss);
  EXPECT_NE(
      Bbr2TestPeer::RecoveryState::NOT_RECOVERY,
      Bbr2TestPeer::recoveryState(controller));

  expectRepace();
  processEvent(controller, makeSpuriousAck(1), std::nullopt);
  EXPECT_EQ(cwndBeforeLoss, controller.getCongestionWindow());
  EXPECT_EQ(
      Bbr2TestPeer::RecoveryState::NOT_RECOVERY,
      Bbr2TestPeer::recoveryState(controller));
}

TEST_F(
    Bbr2SpuriousLossTest,
    CompleteEpisodeRestoresStateWithoutSamplingSpuriousAck) {
  conn_->transportSettings.ccaConfig.enableSpuriousLossRecovery = true;
  Bbr2CongestionController controller(*conn_);
  Bbr2TestPeer::setModelState(
      controller, 20'000, kSavedBandwidth, 16'000, 18'000);
  startLossEpisode(controller, 2);
  ASSERT_TRUE(Bbr2TestPeer::hasUndoState(controller));
  EXPECT_EQ(2, Bbr2TestPeer::pendingLostPackets(controller));

  Bbr2TestPeer::setModelState(
      controller, 8'000, kReducedBandwidth, 7'000, 9'000);
  processEvent(controller, makeSpuriousAck(1), std::nullopt);
  EXPECT_EQ(8'000, Bbr2TestPeer::cwnd(controller));
  EXPECT_EQ(1, Bbr2TestPeer::pendingLostPackets(controller));

  Bbr2TestPeer::setCurrentLossSignals(controller, 4'000, 3, 77);
  Bbr2TestPeer::setFullBwCount(controller, 2);
  Bbr2TestPeer::setBandwidthSample(controller, kHigherBandwidth);
  const auto previousCwnd = Bbr2TestPeer::previousCwnd(controller);
  expectRepace();

  processEvent(controller, makeSpuriousAck(1), std::nullopt);

  EXPECT_EQ(16'000, Bbr2TestPeer::cwnd(controller));
  EXPECT_EQ(
      kSavedBandwidth, Bbr2TestPeer::bandwidthShortTerm(controller).value());
  EXPECT_EQ(16'000, Bbr2TestPeer::inflightShortTerm(controller).value());
  EXPECT_EQ(18'000, Bbr2TestPeer::inflightLongTerm(controller).value());
  EXPECT_EQ(
      Bbr2TestPeer::RecoveryState::NOT_RECOVERY,
      Bbr2TestPeer::recoveryState(controller));
  EXPECT_FALSE(Bbr2TestPeer::hasUndoState(controller));
  EXPECT_EQ(0, Bbr2TestPeer::fullBwCount(controller));
  EXPECT_EQ(0, Bbr2TestPeer::lossBytesInRound(controller));
  EXPECT_EQ(0, Bbr2TestPeer::lossEventsInRound(controller));
  EXPECT_EQ(0, Bbr2TestPeer::largestLostPacketNumInRound(controller));
  EXPECT_EQ(kHigherBandwidth, Bbr2TestPeer::bandwidthSample(controller));
  EXPECT_EQ(previousCwnd, Bbr2TestPeer::previousCwnd(controller));
  EXPECT_EQ(20'000, Bbr2TestPeer::recoveryWindow(controller));
}

TEST_F(Bbr2SpuriousLossTest, OptionalBoundsTreatAbsentAsInfinity) {
  conn_->transportSettings.ccaConfig.enableSpuriousLossRecovery = true;
  Bbr2CongestionController controller(*conn_);

  Bbr2TestPeer::setModelState(
      controller, 20'000, std::nullopt, std::nullopt, std::nullopt);
  startLossEpisode(controller);
  Bbr2TestPeer::setModelState(
      controller, 8'000, kReducedBandwidth, 7'000, 9'000);
  processEvent(controller, makeSpuriousAck(1), std::nullopt);
  EXPECT_FALSE(Bbr2TestPeer::bandwidthShortTerm(controller));
  EXPECT_FALSE(Bbr2TestPeer::inflightShortTerm(controller));
  EXPECT_FALSE(Bbr2TestPeer::inflightLongTerm(controller));

  Bbr2TestPeer::setModelState(
      controller, 20'000, kSavedBandwidth, 16'000, 18'000);
  startLossEpisode(controller);
  Bbr2TestPeer::setModelState(
      controller, 8'000, std::nullopt, std::nullopt, std::nullopt);
  processEvent(controller, makeSpuriousAck(1), std::nullopt);
  EXPECT_FALSE(Bbr2TestPeer::bandwidthShortTerm(controller));
  EXPECT_FALSE(Bbr2TestPeer::inflightShortTerm(controller));
  EXPECT_FALSE(Bbr2TestPeer::inflightLongTerm(controller));

  Bbr2TestPeer::setModelState(
      controller, 20'000, kSavedBandwidth, 16'000, 18'000);
  startLossEpisode(controller);
  Bbr2TestPeer::setModelState(
      controller, 24'000, kHigherBandwidth, 26'000, 27'000);
  processEvent(controller, makeSpuriousAck(1), std::nullopt);
  EXPECT_EQ(24'000, Bbr2TestPeer::cwnd(controller));
  EXPECT_EQ(
      kHigherBandwidth, Bbr2TestPeer::bandwidthShortTerm(controller).value());
  EXPECT_EQ(26'000, Bbr2TestPeer::inflightShortTerm(controller).value());
  EXPECT_EQ(27'000, Bbr2TestPeer::inflightLongTerm(controller).value());
}

TEST_F(Bbr2SpuriousLossTest, LossDuringRecoveryExtendsEpisode) {
  conn_->transportSettings.ccaConfig.enableSpuriousLossRecovery = true;
  Bbr2CongestionController controller(*conn_);
  Bbr2TestPeer::setModelState(
      controller, 20'000, kSavedBandwidth, 16'000, 18'000);
  startLossEpisode(controller);
  startLossEpisode(controller);
  ASSERT_TRUE(Bbr2TestPeer::hasUndoState(controller));
  EXPECT_EQ(2, Bbr2TestPeer::pendingLostPackets(controller));
  Bbr2TestPeer::setModelState(
      controller, 8'000, kReducedBandwidth, 7'000, 9'000);

  processEvent(controller, makeSpuriousAck(1), std::nullopt);
  EXPECT_EQ(8'000, Bbr2TestPeer::cwnd(controller));
  EXPECT_EQ(1, Bbr2TestPeer::pendingLostPackets(controller));

  expectRepace();
  processEvent(controller, makeSpuriousAck(1), std::nullopt);
  EXPECT_EQ(16'000, Bbr2TestPeer::cwnd(controller));
}

TEST_F(Bbr2SpuriousLossTest, SpuriousAckIsResolvedBeforeNewLoss) {
  conn_->transportSettings.ccaConfig.enableSpuriousLossRecovery = true;
  Bbr2CongestionController controller(*conn_);
  Bbr2TestPeer::setModelState(
      controller, 20'000, kSavedBandwidth, 16'000, 18'000);
  startLossEpisode(controller);
  Bbr2TestPeer::setModelState(
      controller, 8'000, kReducedBandwidth, 7'000, 9'000);

  processEvent(controller, makeSpuriousAck(1), makeLoss(controller, 1, false));

  ASSERT_TRUE(Bbr2TestPeer::hasUndoState(controller));
  EXPECT_EQ(1, Bbr2TestPeer::pendingLostPackets(controller));
  EXPECT_EQ(16'000, Bbr2TestPeer::undoPriorCwnd(controller));

  Bbr2TestPeer::setModelState(
      controller, 7'000, kReducedBandwidth, 6'000, 8'000);
  expectRepace();
  processEvent(controller, makeSpuriousAck(1), std::nullopt);
  EXPECT_EQ(16'000, Bbr2TestPeer::cwnd(controller));
  EXPECT_EQ(
      kSavedBandwidth, Bbr2TestPeer::bandwidthShortTerm(controller).value());
  EXPECT_EQ(16'000, Bbr2TestPeer::inflightShortTerm(controller).value());
  EXPECT_EQ(18'000, Bbr2TestPeer::inflightLongTerm(controller).value());
}

TEST_F(Bbr2SpuriousLossTest, OlderRetainedLossPreventsUndo) {
  conn_->transportSettings.ccaConfig.enableSpuriousLossRecovery = true;
  Bbr2CongestionController controller(*conn_);
  conn_->outstandings.declaredLostCount = 1;
  Bbr2TestPeer::setModelState(
      controller, 20'000, kSavedBandwidth, 16'000, 18'000);
  startLossEpisode(controller);
  EXPECT_FALSE(Bbr2TestPeer::hasUndoState(controller));
  Bbr2TestPeer::setModelState(
      controller, 8'000, kReducedBandwidth, 7'000, 9'000);
  processEvent(controller, makeSpuriousAck(2), std::nullopt);
  EXPECT_EQ(8'000, Bbr2TestPeer::cwnd(controller));
}

TEST_F(Bbr2SpuriousLossTest, PersistentCongestionInvalidatesUndo) {
  conn_->transportSettings.ccaConfig.enableSpuriousLossRecovery = true;
  Bbr2CongestionController controller(*conn_);
  Bbr2TestPeer::setModelState(
      controller, 20'000, kSavedBandwidth, 16'000, 18'000);
  startLossEpisode(controller);
  ASSERT_TRUE(Bbr2TestPeer::hasUndoState(controller));
  startLossEpisode(controller, 1, true);
  EXPECT_FALSE(Bbr2TestPeer::hasUndoState(controller));
  Bbr2TestPeer::setModelState(
      controller, 6'000, kReducedBandwidth, 5'000, 7'000);
  processEvent(controller, makeSpuriousAck(2), std::nullopt);
  EXPECT_EQ(6'000, Bbr2TestPeer::cwnd(controller));
}

TEST_F(Bbr2SpuriousLossTest, CountMismatchInvalidatesUndo) {
  conn_->transportSettings.ccaConfig.enableSpuriousLossRecovery = true;
  Bbr2CongestionController controller(*conn_);
  Bbr2TestPeer::setModelState(
      controller, 20'000, kSavedBandwidth, 16'000, 18'000);
  startLossEpisode(controller, 2);
  Bbr2TestPeer::setModelState(
      controller, 8'000, kReducedBandwidth, 7'000, 9'000);

  --conn_->outstandings.declaredLostCount;
  processEvent(controller, makeSpuriousAck(1), std::nullopt);

  EXPECT_FALSE(Bbr2TestPeer::hasUndoState(controller));
  EXPECT_EQ(8'000, controller.getCongestionWindow());
}

TEST_F(Bbr2SpuriousLossTest, ExpiredLossEvidenceSurvivesNewSpuriousEpisode) {
  conn_->transportSettings.ccaConfig.enableSpuriousLossRecovery = true;
  conn_->transportSettings.ccaConfig.enableRecoveryInStartup = false;
  conn_->transportSettings.ccaConfig.exitStartupOnLoss = true;
  conn_->lossState.inflightBytes = 50 * kPacketSize;
  Bbr2CongestionController controller(*conn_);
  processRoundAck(
      controller, makeNoncontiguousLoss(controller, true), 0, false);
  ASSERT_EQ(Bbr2CongestionController::State::Startup, controller.getState());
  ASSERT_EQ(6, Bbr2TestPeer::lossEventsInRound(controller));

  clearOldOutstandingPackets(
      *conn_, Clock::now() + 10s, PacketNumberSpace::AppData);
  ASSERT_EQ(0, conn_->outstandings.declaredLostCount);
  startLossEpisode(controller);
  processEvent(controller, makeSpuriousAck(1), std::nullopt);
  processRoundAck(controller);

  EXPECT_EQ(Bbr2CongestionController::State::Drain, controller.getState());
  EXPECT_TRUE(Bbr2TestPeer::fullBwReached(controller));
  EXPECT_TRUE(Bbr2TestPeer::inflightLongTerm(controller));
}

TEST_F(
    Bbr2SpuriousLossTest,
    ImplicitAckLossEvidenceSurvivesNewSpuriousEpisode) {
  conn_->transportSettings.ccaConfig.enableSpuriousLossRecovery = true;
  conn_->transportSettings.ccaConfig.enableRecoveryInStartup = false;
  conn_->transportSettings.ccaConfig.exitStartupOnLoss = true;
  conn_->lossState.inflightBytes = 50 * kPacketSize;
  Bbr2CongestionController controller(*conn_);
  processRoundAck(
      controller, makeNoncontiguousLoss(controller, true), 0, false);
  processRoundAck(controller, std::nullopt, 0, true, true);
  ASSERT_EQ(Bbr2CongestionController::State::Startup, controller.getState());
  ASSERT_EQ(6, Bbr2TestPeer::lossEventsInLastRound(controller));

  ReadAckFrame frame;
  frame.largestAcked =
      conn_->outstandings.packets.back().getPacketSequenceNum();
  frame.ackBlocks.emplace_back(
      conn_->outstandings.packets.front().getPacketSequenceNum(),
      frame.largestAcked);
  frame.implicit = true;
  conn_->ackStates.appDataAckState.nextPacketNum = nextPacketNum_;
  auto result = processAckFrame(
      *conn_,
      PacketNumberSpace::AppData,
      frame,
      [](auto&) -> Expected<void, QuicError> { return {}; },
      [](const auto&, const auto&) -> Expected<void, QuicError> { return {}; },
      [](auto&, auto, auto&, bool) -> Expected<void, QuicError> { return {}; },
      Clock::now());
  ASSERT_FALSE(result.hasError());
  ASSERT_EQ(0, result.value().numPacketsSpuriouslyAcked);
  ASSERT_EQ(0, conn_->outstandings.declaredLostCount);

  processRoundAck(controller, makeLoss(controller, 1), 0, false);
  ASSERT_EQ(Bbr2CongestionController::State::Drain, controller.getState());
  const auto inflightLongTerm = Bbr2TestPeer::inflightLongTerm(controller);
  processEvent(controller, makeSpuriousAck(1), std::nullopt);

  EXPECT_EQ(Bbr2CongestionController::State::Drain, controller.getState());
  EXPECT_TRUE(Bbr2TestPeer::fullBwReached(controller));
  EXPECT_EQ(inflightLongTerm, Bbr2TestPeer::inflightLongTerm(controller));
}

TEST_F(Bbr2SpuriousLossTest, ExpiredLossRecoverySurvivesNewSpuriousEpisode) {
  conn_->transportSettings.ccaConfig.enableSpuriousLossRecovery = true;
  Bbr2CongestionController controller(*conn_);
  processRoundAck(
      controller, makeNoncontiguousLoss(controller, true), 0, false);
  processRoundAck(controller);
  processRoundAck(controller);
  ASSERT_EQ(0, Bbr2TestPeer::lossBytesInRound(controller));
  ASSERT_FLOAT_EQ(0, Bbr2TestPeer::lossPctInLastRound(controller));
  ASSERT_NE(
      Bbr2TestPeer::RecoveryState::NOT_RECOVERY,
      Bbr2TestPeer::recoveryState(controller));

  clearOldOutstandingPackets(
      *conn_, Clock::now() + 10s, PacketNumberSpace::AppData);
  ASSERT_EQ(0, conn_->outstandings.declaredLostCount);
  startLossEpisode(controller);
  processEvent(controller, makeSpuriousAck(1), std::nullopt);

  EXPECT_NE(
      Bbr2TestPeer::RecoveryState::NOT_RECOVERY,
      Bbr2TestPeer::recoveryState(controller));
}

TEST_F(Bbr2SpuriousLossTest, RecoversAfterOrdinaryRecoveryEnds) {
  conn_->transportSettings.ccaConfig.enableSpuriousLossRecovery = true;
  Bbr2CongestionController controller(*conn_);
  const auto cwndBeforeLoss = controller.getCongestionWindow();
  startLossEpisode(controller);

  const auto sentTime = Clock::now() + 1ms;
  const auto packetNum = nextPacketNum_++;
  totalBytesSent_ += kPacketSize;
  auto packet =
      makeTestingWritePacket(packetNum, kPacketSize, totalBytesSent_, sentTime);
  onPacketsSentWrapper(conn_.get(), &controller, packet);
  processEvent(
      controller,
      makeAck(packetNum, kPacketSize, sentTime + 1ms, sentTime),
      std::nullopt);
  const auto cwndAfterRecovery = controller.getCongestionWindow();
  EXPECT_EQ(
      Bbr2TestPeer::RecoveryState::NOT_RECOVERY,
      Bbr2TestPeer::recoveryState(controller));

  expectRepace();
  processEvent(controller, makeSpuriousAck(1), std::nullopt);
  EXPECT_EQ(
      std::max(cwndBeforeLoss, cwndAfterRecovery),
      controller.getCongestionWindow());
}

TEST_F(Bbr2SpuriousLossTest, NewRecoveryInvalidatesOlderEpisode) {
  conn_->transportSettings.ccaConfig.enableSpuriousLossRecovery = true;
  Bbr2CongestionController controller(*conn_);
  startLossEpisode(controller);

  const auto sentTime = Clock::now() + 1ms;
  const auto packetNum = nextPacketNum_++;
  totalBytesSent_ += kPacketSize;
  auto packet =
      makeTestingWritePacket(packetNum, kPacketSize, totalBytesSent_, sentTime);
  onPacketsSentWrapper(conn_.get(), &controller, packet);
  processEvent(
      controller,
      makeAck(packetNum, kPacketSize, sentTime + 1ms, sentTime),
      std::nullopt);
  ASSERT_EQ(
      Bbr2TestPeer::RecoveryState::NOT_RECOVERY,
      Bbr2TestPeer::recoveryState(controller));

  startLossEpisode(controller, 1, false, Clock::now() + 1ms);
  EXPECT_FALSE(Bbr2TestPeer::hasUndoState(controller));
  Bbr2TestPeer::setModelState(
      controller, 8'000, kReducedBandwidth, 7'000, 9'000);
  processEvent(controller, makeSpuriousAck(2), std::nullopt);
  EXPECT_EQ(8'000, controller.getCongestionWindow());
}

TEST_F(Bbr2SpuriousLossTest, RecoveryDisabledNewEpisodeInvalidatesOlderUndo) {
  conn_->transportSettings.ccaConfig.enableSpuriousLossRecovery = true;
  conn_->transportSettings.ccaConfig.enableRecoveryInStartup = false;
  Bbr2CongestionController controller(*conn_);
  Bbr2TestPeer::setModelState(
      controller, 20'000, kSavedBandwidth, 16'000, 18'000);
  startLossEpisode(controller);
  ASSERT_TRUE(Bbr2TestPeer::hasUndoState(controller));

  Bbr2TestPeer::setModelState(
      controller, 8'000, kReducedBandwidth, 7'000, 9'000);
  startLossEpisode(controller, 1, false, Clock::now() + 1ms);
  EXPECT_FALSE(Bbr2TestPeer::hasUndoState(controller));

  processEvent(controller, makeSpuriousAck(2), std::nullopt);
  EXPECT_EQ(8'000, controller.getCongestionWindow());
}

TEST_F(Bbr2SpuriousLossTest, IdleRestartInvalidatesUndo) {
  conn_->transportSettings.ccaConfig.enableSpuriousLossRecovery = true;
  Bbr2CongestionController controller(*conn_);
  Bbr2TestPeer::setModelState(
      controller, 20'000, kSavedBandwidth, 16'000, 18'000);
  startLossEpisode(controller);
  ASSERT_TRUE(Bbr2TestPeer::hasUndoState(controller));

  Bbr2TestPeer::setModelState(
      controller, 8'000, kReducedBandwidth, 7'000, 9'000);
  controller.setAppLimited();
  totalBytesSent_ += kPacketSize;
  auto packet = makeTestingWritePacket(
      nextPacketNum_++, kPacketSize, totalBytesSent_, Clock::now());
  onPacketsSentWrapper(conn_.get(), &controller, packet);
  EXPECT_FALSE(Bbr2TestPeer::hasUndoState(controller));

  processEvent(controller, makeSpuriousAck(1), std::nullopt);
  EXPECT_EQ(8'000, controller.getCongestionWindow());
}

TEST_F(Bbr2SpuriousLossTest, RecoveryGateDoesNotDisableModelUndo) {
  conn_->transportSettings.ccaConfig.enableSpuriousLossRecovery = true;
  conn_->transportSettings.ccaConfig.enableRecoveryInProbeStates = false;
  Bbr2CongestionController controller(*conn_);
  Bbr2TestPeer::enterProbeBw(controller);
  Bbr2TestPeer::setModelState(
      controller, 20'000, kSavedBandwidth, 16'000, 18'000);
  startLossEpisode(controller, 2);
  EXPECT_TRUE(Bbr2TestPeer::hasUndoState(controller));
  Bbr2TestPeer::setModelState(
      controller, 8'000, kReducedBandwidth, 7'000, 9'000);
  expectRepace();

  processEvent(controller, makeSpuriousAck(2), std::nullopt);

  EXPECT_EQ(16'000, Bbr2TestPeer::cwnd(controller));
  EXPECT_EQ(
      kSavedBandwidth, Bbr2TestPeer::bandwidthShortTerm(controller).value());
}

TEST_F(
    Bbr2SpuriousLossTest,
    RecoveryDisabledEpisodeCanEnterRecoveryAfterTransition) {
  conn_->transportSettings.ccaConfig.enableSpuriousLossRecovery = true;
  conn_->transportSettings.ccaConfig.enableRecoveryInStartup = false;
  Bbr2CongestionController controller(*conn_);
  Bbr2TestPeer::setModelState(
      controller, 20'000, kSavedBandwidth, 16'000, 18'000);
  startLossEpisode(controller);

  Bbr2TestPeer::enterProbeBw(controller);
  startLossEpisode(controller);
  ASSERT_TRUE(Bbr2TestPeer::hasUndoState(controller));
  EXPECT_EQ(2, Bbr2TestPeer::pendingLostPackets(controller));
  EXPECT_NE(
      Bbr2TestPeer::RecoveryState::NOT_RECOVERY,
      Bbr2TestPeer::recoveryState(controller));
  Bbr2TestPeer::setModelState(
      controller, 8'000, kReducedBandwidth, 7'000, 9'000);
  expectRepace();

  processEvent(controller, makeSpuriousAck(2), std::nullopt);

  EXPECT_EQ(16'000, controller.getCongestionWindow());
  EXPECT_EQ(
      kSavedBandwidth, Bbr2TestPeer::bandwidthShortTerm(controller).value());
}

TEST_F(Bbr2SpuriousLossTest, DrainReappliesRestoredModelBounds) {
  conn_->transportSettings.ccaConfig.enableSpuriousLossRecovery = true;
  Bbr2CongestionController controller(*conn_);
  Bbr2TestPeer::setState(controller, Bbr2CongestionController::State::Drain);
  Bbr2TestPeer::setModelState(
      controller, 20'000, kSavedBandwidth, 12'000, std::nullopt);
  startLossEpisode(controller);
  Bbr2TestPeer::setModelState(
      controller, 8'000, kReducedBandwidth, 6'000, std::nullopt);
  expectRepace();

  processEvent(controller, makeSpuriousAck(1), std::nullopt);

  EXPECT_EQ(12'000, controller.getCongestionWindow());
  EXPECT_EQ(12'000, Bbr2TestPeer::inflightShortTerm(controller).value());
  EXPECT_EQ(
      kSavedBandwidth, Bbr2TestPeer::bandwidthShortTerm(controller).value());
}

TEST_F(Bbr2SpuriousLossTest, ProbeBwReappliesRestoredModelBounds) {
  conn_->transportSettings.ccaConfig.enableSpuriousLossRecovery = true;
  Bbr2CongestionController controller(*conn_);
  Bbr2TestPeer::enterProbeBw(controller);
  Bbr2TestPeer::setModelState(
      controller, 30'000, kSavedBandwidth, 16'000, 18'000);
  startLossEpisode(controller);
  Bbr2TestPeer::setModelState(
      controller, 8'000, kReducedBandwidth, 7'000, 9'000);
  expectRepace();

  processEvent(controller, makeSpuriousAck(1), std::nullopt);

  EXPECT_EQ(16'000, controller.getCongestionWindow());
  EXPECT_EQ(16'000, Bbr2TestPeer::inflightShortTerm(controller).value());
  EXPECT_EQ(18'000, Bbr2TestPeer::inflightLongTerm(controller).value());
  EXPECT_EQ(30'000, Bbr2TestPeer::recoveryWindow(controller));
  EXPECT_TRUE(Bbr2TestPeer::fullBwReached(controller));
}

TEST_F(Bbr2SpuriousLossTest, UndoSurvivesStartupToProbeBwTransition) {
  conn_->transportSettings.ccaConfig.enableSpuriousLossRecovery = true;
  Bbr2CongestionController controller(*conn_);
  Bbr2TestPeer::setModelState(
      controller, 20'000, std::nullopt, std::nullopt, std::nullopt);
  startLossEpisode(controller);
  ASSERT_TRUE(Bbr2TestPeer::hasUndoState(controller));

  Bbr2TestPeer::enterProbeBw(controller);
  Bbr2TestPeer::setModelState(
      controller, 8'000, kReducedBandwidth, 7'000, 9'000);
  expectRepace();
  processEvent(controller, makeSpuriousAck(1), std::nullopt);

  EXPECT_EQ(20'000, controller.getCongestionWindow());
  EXPECT_FALSE(Bbr2TestPeer::bandwidthShortTerm(controller));
  EXPECT_FALSE(Bbr2TestPeer::inflightShortTerm(controller));
  EXPECT_FALSE(Bbr2TestPeer::inflightLongTerm(controller));
}

TEST_F(Bbr2SpuriousLossTest, UndoAfterProbeRttReturnUsesProbeBwState) {
  conn_->transportSettings.ccaConfig.enableSpuriousLossRecovery = true;
  Bbr2CongestionController controller(*conn_);
  Bbr2TestPeer::enterProbeBw(controller);
  Bbr2TestPeer::setModelState(
      controller, 20'000, kSavedBandwidth, 16'000, 18'000);
  startLossEpisode(controller);
  Bbr2TestPeer::enterProbeRtt(controller);
  Bbr2TestPeer::exitProbeRtt(controller);
  ASSERT_EQ(
      Bbr2CongestionController::State::ProbeBw_Cruise, controller.getState());
  Bbr2TestPeer::setModelState(
      controller, 8'000, kReducedBandwidth, 7'000, 9'000);
  expectRepace();

  processEvent(controller, makeSpuriousAck(1), std::nullopt);

  EXPECT_EQ(
      Bbr2CongestionController::State::ProbeBw_Cruise, controller.getState());
  EXPECT_GT(controller.getCongestionWindow(), 8'000);
}

TEST_F(Bbr2SpuriousLossTest, ProbeRttBoundsUndoAndResetsFullBwAfterTransition) {
  conn_->transportSettings.ccaConfig.enableSpuriousLossRecovery = true;
  Bbr2CongestionController controller(*conn_);
  Bbr2TestPeer::enterProbeBw(controller);
  Bbr2TestPeer::setModelState(
      controller, 20'000, kSavedBandwidth, 16'000, 18'000);
  startLossEpisode(controller);
  Bbr2TestPeer::setFullBwCount(controller, 3);
  ASSERT_TRUE(Bbr2TestPeer::hasUndoState(controller));

  const auto probeRttCwnd = std::max<uint64_t>(
      conn_->transportSettings.initCwndInMss * kPacketSize / 2,
      kMinCwndInMssForBbr * kPacketSize);
  Bbr2TestPeer::enterProbeRtt(controller);
  Bbr2TestPeer::setModelState(
      controller, 8'000, kReducedBandwidth, 7'000, 9'000);
  expectRepace();
  processEvent(controller, makeSpuriousAck(1), std::nullopt);

  EXPECT_EQ(
      std::min<uint64_t>(20'000, probeRttCwnd),
      controller.getCongestionWindow());
  EXPECT_EQ(0, Bbr2TestPeer::fullBwCount(controller));
  EXPECT_EQ(
      kSavedBandwidth, Bbr2TestPeer::bandwidthShortTerm(controller).value());
  EXPECT_EQ(16'000, Bbr2TestPeer::inflightShortTerm(controller).value());
  EXPECT_EQ(18'000, Bbr2TestPeer::inflightLongTerm(controller).value());
}

TEST_F(Bbr2SpuriousLossTest, PartialSpuriousAckKeepsGenuineLossInRecovery) {
  conn_->transportSettings.ccaConfig.enableSpuriousLossRecovery = true;
  Bbr2CongestionController controller(*conn_);
  const auto cwndBeforeLoss = controller.getCongestionWindow();
  const auto sentTime = Clock::now() - 10ms;
  const auto packetNum = nextPacketNum_++;
  totalBytesSent_ += kPacketSize;
  auto packet =
      makeTestingWritePacket(packetNum, kPacketSize, totalBytesSent_, sentTime);
  onPacketsSentWrapper(conn_.get(), &controller, packet);
  processEvent(
      controller,
      makeAck(packetNum, kPacketSize, Clock::now(), sentTime),
      makeLoss(controller, 2));
  const auto cwndAfterLoss = controller.getCongestionWindow();
  ASSERT_LT(cwndAfterLoss, cwndBeforeLoss);

  EXPECT_CALL(*pacer_, refreshPacingRate(_, _, _)).Times(0);
  processEvent(controller, makeSpuriousAck(1), std::nullopt);

  EXPECT_EQ(cwndAfterLoss, controller.getCongestionWindow());
  EXPECT_NE(
      Bbr2TestPeer::RecoveryState::NOT_RECOVERY,
      Bbr2TestPeer::recoveryState(controller));
  ASSERT_TRUE(Bbr2TestPeer::hasUndoState(controller));
  EXPECT_EQ(1, Bbr2TestPeer::pendingLostPackets(controller));
}

TEST_F(Bbr2SpuriousLossTest, DisablingGateInvalidatesPendingUndo) {
  conn_->transportSettings.ccaConfig.enableSpuriousLossRecovery = true;
  Bbr2CongestionController controller(*conn_);
  startLossEpisode(controller);
  ASSERT_TRUE(Bbr2TestPeer::hasUndoState(controller));
  Bbr2TestPeer::setModelState(
      controller, 8'000, kReducedBandwidth, 7'000, 9'000);
  conn_->transportSettings.ccaConfig.enableSpuriousLossRecovery = false;

  EXPECT_CALL(*pacer_, refreshPacingRate(_, _, _)).Times(0);
  processEvent(controller, makeSpuriousAck(1), std::nullopt);

  EXPECT_FALSE(Bbr2TestPeer::hasUndoState(controller));
  EXPECT_EQ(8'000, controller.getCongestionWindow());
  EXPECT_NE(
      Bbr2TestPeer::RecoveryState::NOT_RECOVERY,
      Bbr2TestPeer::recoveryState(controller));
}

TEST_F(Bbr2SpuriousLossTest, ProbeRttUndoReappliesBandwidthAndHeadroomBounds) {
  conn_->transportSettings.ccaConfig.enableSpuriousLossRecovery = true;
  Bbr2CongestionController controller(*conn_);
  Bbr2TestPeer::enterProbeBw(controller);
  Bbr2TestPeer::setBandwidthModel(controller, kHigherBandwidth, 1s);
  Bbr2TestPeer::setModelState(
      controller, 20'000, kSavedBandwidth, 6'000, 7'000);
  startLossEpisode(controller);
  Bbr2TestPeer::enterProbeRtt(controller);
  Bbr2TestPeer::setModelState(
      controller, 4'000, kReducedBandwidth, 4'000, 5'000);
  EXPECT_CALL(
      *pacer_,
      setRttFactor(
          conn_->transportSettings.defaultRttFactor.first,
          conn_->transportSettings.defaultRttFactor.second));
  EXPECT_CALL(*pacer_, refreshPacingRate(kSavedBandwidth * 1s, Eq(1s), _));

  processEvent(controller, makeSpuriousAck(1), std::nullopt);

  EXPECT_EQ(kSavedBandwidth, controller.getBandwidth().value());
  EXPECT_EQ(7'000 * 85 / 100, controller.getCongestionWindow());
  EXPECT_EQ(6'000, Bbr2TestPeer::inflightShortTerm(controller).value());
  EXPECT_EQ(7'000, Bbr2TestPeer::inflightLongTerm(controller).value());
  EXPECT_EQ(20'000, Bbr2TestPeer::recoveryWindow(controller));
  EXPECT_EQ(Bbr2CongestionController::State::ProbeRTT, controller.getState());
  EXPECT_TRUE(Bbr2TestPeer::fullBwReached(controller));
}

TEST_F(Bbr2SpuriousLossTest, ProbeRttUndoReappliesShortTermInflightBound) {
  conn_->transportSettings.ccaConfig.enableSpuriousLossRecovery = true;
  Bbr2CongestionController controller(*conn_);
  Bbr2TestPeer::enterProbeBw(controller);
  Bbr2TestPeer::setBandwidthModel(controller, kHigherBandwidth, 1s);
  Bbr2TestPeer::setModelState(
      controller, 20'000, kSavedBandwidth, 5'000, 9'000);
  startLossEpisode(controller);
  Bbr2TestPeer::enterProbeRtt(controller);
  Bbr2TestPeer::setModelState(
      controller, 4'000, kReducedBandwidth, 4'000, 5'000);

  processEvent(controller, makeSpuriousAck(1), std::nullopt);

  EXPECT_EQ(5'000, controller.getCongestionWindow());
  EXPECT_EQ(kSavedBandwidth, controller.getBandwidth().value());
  EXPECT_EQ(5'000, Bbr2TestPeer::inflightShortTerm(controller).value());
  EXPECT_EQ(9'000, Bbr2TestPeer::inflightLongTerm(controller).value());
  EXPECT_EQ(Bbr2CongestionController::State::ProbeRTT, controller.getState());
}

TEST_F(Bbr2SpuriousLossTest, CruiseUndoReappliesHeadroomAndBandwidthBound) {
  conn_->transportSettings.ccaConfig.enableSpuriousLossRecovery = true;
  Bbr2CongestionController controller(*conn_);
  Bbr2TestPeer::enterProbeBw(controller);
  Bbr2TestPeer::setState(
      controller, Bbr2CongestionController::State::ProbeBw_Cruise);
  Bbr2TestPeer::setBandwidthModel(controller, kHigherBandwidth, 1s);
  Bbr2TestPeer::setModelState(
      controller, 30'000, kSavedBandwidth, 16'000, 18'000);
  startLossEpisode(controller);
  Bbr2TestPeer::setModelState(
      controller, 8'000, kReducedBandwidth, 7'000, 9'000);
  EXPECT_CALL(*pacer_, refreshPacingRate(kSavedBandwidth * 1s, Eq(1s), _));

  processEvent(controller, makeSpuriousAck(1), std::nullopt);

  EXPECT_EQ(kSavedBandwidth, controller.getBandwidth().value());
  EXPECT_EQ(18'000 * 85 / 100, controller.getCongestionWindow());
}

TEST_F(Bbr2SpuriousLossTest, UndoHonorsIgnoredModelBoundsAndMaximumCwnd) {
  conn_->transportSettings.ccaConfig.enableSpuriousLossRecovery = true;
  conn_->transportSettings.ccaConfig.ignoreShortTerm = true;
  conn_->transportSettings.ccaConfig.ignoreInflightLongTerm = true;
  conn_->transportSettings.maxCwndInMss = 25;
  Bbr2CongestionController controller(*conn_);
  Bbr2TestPeer::enterProbeBw(controller);
  Bbr2TestPeer::setBandwidthModel(controller, kHigherBandwidth, 1s);
  Bbr2TestPeer::setModelState(
      controller, 30'000, kSavedBandwidth, 16'000, 18'000);
  startLossEpisode(controller);
  Bbr2TestPeer::setModelState(
      controller, 8'000, kReducedBandwidth, 7'000, 9'000);

  processEvent(controller, makeSpuriousAck(1), std::nullopt);

  EXPECT_EQ(kHigherBandwidth, controller.getBandwidth().value());
  EXPECT_EQ(25 * kPacketSize, controller.getCongestionWindow());
  EXPECT_EQ(16'000, Bbr2TestPeer::inflightShortTerm(controller).value());
  EXPECT_EQ(18'000, Bbr2TestPeer::inflightLongTerm(controller).value());
}

TEST_F(Bbr2SpuriousLossTest, StartupLossUndoRequiresCompleteEpisode) {
  conn_->transportSettings.ccaConfig.enableSpuriousLossRecovery = true;
  Bbr2CongestionController controller(*conn_);
  const auto initialCwnd = controller.getCongestionWindow();
  exitStartupOnLoss(controller);

  processEvent(controller, makeSpuriousAck(5), std::nullopt);
  EXPECT_EQ(Bbr2CongestionController::State::Drain, controller.getState());
  EXPECT_TRUE(Bbr2TestPeer::fullBwReached(controller));
  EXPECT_NE(
      Bbr2TestPeer::RecoveryState::NOT_RECOVERY,
      Bbr2TestPeer::recoveryState(controller));

  EXPECT_CALL(
      *pacer_,
      setRttFactor(
          conn_->transportSettings.startupRttFactor.first,
          conn_->transportSettings.startupRttFactor.second));
  EXPECT_CALL(*pacer_, refreshPacingRate(_, _, _));
  processEvent(controller, makeSpuriousAck(1), std::nullopt);

  EXPECT_EQ(Bbr2CongestionController::State::Startup, controller.getState());
  EXPECT_FALSE(Bbr2TestPeer::fullBwReached(controller));
  EXPECT_FALSE(Bbr2TestPeer::inflightLongTerm(controller));
  EXPECT_EQ(0, Bbr2TestPeer::lossEventsInLastRound(controller));
  EXPECT_FLOAT_EQ(0, Bbr2TestPeer::lossPctInLastRound(controller));
  EXPECT_GE(controller.getCongestionWindow(), initialCwnd);
  EXPECT_EQ(
      Bbr2TestPeer::RecoveryState::NOT_RECOVERY,
      Bbr2TestPeer::recoveryState(controller));
  Mock::VerifyAndClearExpectations(pacer_);

  processRoundAck(controller);
  EXPECT_EQ(Bbr2CongestionController::State::Startup, controller.getState());
}

TEST_F(Bbr2SpuriousLossTest, DisabledStartupUndoPreservesLossExit) {
  Bbr2CongestionController controller(*conn_);
  exitStartupOnLoss(controller);
  const auto cwnd = controller.getCongestionWindow();
  const auto inflightLongTerm = Bbr2TestPeer::inflightLongTerm(controller);
  EXPECT_CALL(*pacer_, setRttFactor(_, _)).Times(0);
  EXPECT_CALL(*pacer_, refreshPacingRate(_, _, _)).Times(0);

  processEvent(controller, makeSpuriousAck(6), std::nullopt);

  EXPECT_EQ(Bbr2CongestionController::State::Drain, controller.getState());
  EXPECT_TRUE(Bbr2TestPeer::fullBwReached(controller));
  EXPECT_EQ(cwnd, controller.getCongestionWindow());
  EXPECT_EQ(inflightLongTerm, Bbr2TestPeer::inflightLongTerm(controller));
  EXPECT_NE(
      Bbr2TestPeer::RecoveryState::NOT_RECOVERY,
      Bbr2TestPeer::recoveryState(controller));
}

TEST_F(Bbr2SpuriousLossTest, StartupLossUndoAfterDrainCompletes) {
  conn_->transportSettings.ccaConfig.enableSpuriousLossRecovery = true;
  Bbr2CongestionController controller(*conn_);
  exitStartupOnLoss(controller);
  conn_->lossState.inflightBytes = kPacketSize;
  processRoundAck(controller);
  ASSERT_EQ(
      Bbr2CongestionController::State::ProbeBw_Cruise, controller.getState());

  processEvent(controller, makeSpuriousAck(6), std::nullopt);

  EXPECT_EQ(Bbr2CongestionController::State::Startup, controller.getState());
  EXPECT_FALSE(Bbr2TestPeer::fullBwReached(controller));
}

TEST_F(Bbr2SpuriousLossTest, StartupUndoClearsProbeBwLossResponsePermission) {
  conn_->transportSettings.ccaConfig.enableSpuriousLossRecovery = true;
  Bbr2CongestionController controller(*conn_);
  exitStartupOnLoss(controller);
  Bbr2TestPeer::setState(
      controller, Bbr2CongestionController::State::ProbeBw_Refill);
  processRoundAck(controller);
  ASSERT_EQ(Bbr2CongestionController::State::ProbeBw_Up, controller.getState());

  processEvent(controller, makeSpuriousAck(6), std::nullopt);
  ASSERT_EQ(Bbr2CongestionController::State::Startup, controller.getState());
  for (uint64_t i = 0; i < 4; ++i) {
    processRoundAck(controller);
  }
  ASSERT_EQ(Bbr2CongestionController::State::Drain, controller.getState());
  ASSERT_TRUE(Bbr2TestPeer::fullBwNow(controller));
  ASSERT_FALSE(Bbr2TestPeer::inflightLongTerm(controller));

  processRoundAck(controller, makeLoss(controller, 1), 0, false);

  EXPECT_EQ(Bbr2CongestionController::State::Drain, controller.getState());
  EXPECT_FALSE(Bbr2TestPeer::inflightLongTerm(controller));

  Bbr2TestPeer::setState(
      controller, Bbr2CongestionController::State::ProbeBw_Refill);
  processRoundAck(controller);
  ASSERT_EQ(Bbr2CongestionController::State::ProbeBw_Up, controller.getState());
  processRoundAck(controller, makeLoss(controller, 1), 0, false);
  EXPECT_EQ(
      Bbr2CongestionController::State::ProbeBw_Down, controller.getState());
  EXPECT_TRUE(Bbr2TestPeer::inflightLongTerm(controller));
}

TEST_F(Bbr2SpuriousLossTest, StartupLossUndoDefersUntilProbeRttFinishes) {
  conn_->transportSettings.ccaConfig.enableSpuriousLossRecovery = true;
  Bbr2CongestionController controller(*conn_);
  exitStartupOnLoss(controller);
  Bbr2TestPeer::enterProbeRtt(controller);

  processEvent(controller, makeSpuriousAck(6), std::nullopt);

  EXPECT_EQ(Bbr2CongestionController::State::ProbeRTT, controller.getState());
  EXPECT_FALSE(Bbr2TestPeer::fullBwReached(controller));
  EXPECT_FALSE(Bbr2TestPeer::hasUndoState(controller));
  EXPECT_LE(
      controller.getCongestionWindow(),
      conn_->transportSettings.initCwndInMss * kPacketSize / 2);

  Bbr2TestPeer::finishProbeRtt(controller);
  processRoundAck(controller);
  EXPECT_EQ(Bbr2CongestionController::State::Startup, controller.getState());
}

TEST_F(Bbr2SpuriousLossTest, BandwidthPlateauExitIsNotUndone) {
  conn_->transportSettings.ccaConfig.enableSpuriousLossRecovery = true;
  Bbr2CongestionController controller(*conn_);
  conn_->lossState.inflightBytes = 50 * kPacketSize;
  startLossEpisode(controller);
  for (uint64_t i = 0; i < 4; ++i) {
    processRoundAck(controller);
  }
  ASSERT_EQ(Bbr2CongestionController::State::Drain, controller.getState());
  ASSERT_TRUE(Bbr2TestPeer::fullBwNow(controller));

  processEvent(controller, makeSpuriousAck(1), std::nullopt);

  EXPECT_EQ(Bbr2CongestionController::State::Drain, controller.getState());
  EXPECT_TRUE(Bbr2TestPeer::fullBwReached(controller));
  EXPECT_FALSE(Bbr2TestPeer::fullBwNow(controller));
}

TEST_F(Bbr2SpuriousLossTest, StartupUndoIsResolvedBeforeNewLossAndAck) {
  conn_->transportSettings.ccaConfig.enableSpuriousLossRecovery = true;
  Bbr2CongestionController controller(*conn_);
  exitStartupOnLoss(controller);

  processRoundAck(controller, makeLoss(controller, 1), 6);

  EXPECT_EQ(Bbr2CongestionController::State::Startup, controller.getState());
  EXPECT_FALSE(Bbr2TestPeer::fullBwReached(controller));
  ASSERT_TRUE(Bbr2TestPeer::hasUndoState(controller));
  EXPECT_EQ(1, Bbr2TestPeer::pendingLostPackets(controller));
  EXPECT_NE(
      Bbr2TestPeer::RecoveryState::NOT_RECOVERY,
      Bbr2TestPeer::recoveryState(controller));
  EXPECT_EQ(kPacketSize, Bbr2TestPeer::lossBytesInRound(controller));

  processEvent(controller, makeSpuriousAck(1), std::nullopt);
  EXPECT_EQ(Bbr2CongestionController::State::Startup, controller.getState());
  EXPECT_EQ(
      Bbr2TestPeer::RecoveryState::NOT_RECOVERY,
      Bbr2TestPeer::recoveryState(controller));
}

TEST_F(Bbr2SpuriousLossTest, ProbeBwLossSupersedesStartupUndo) {
  conn_->transportSettings.ccaConfig.enableSpuriousLossRecovery = true;
  Bbr2CongestionController controller(*conn_);
  exitStartupOnLoss(controller);
  Bbr2TestPeer::setState(
      controller, Bbr2CongestionController::State::ProbeBw_Up);
  Bbr2TestPeer::enableLongTermLossUpdate(controller);
  processRoundAck(controller, makeLoss(controller, 1), 0, false);
  ASSERT_EQ(
      Bbr2CongestionController::State::ProbeBw_Down, controller.getState());
  ASSERT_EQ(7, Bbr2TestPeer::pendingLostPackets(controller));

  processEvent(controller, makeSpuriousAck(7), std::nullopt);

  EXPECT_EQ(
      Bbr2CongestionController::State::ProbeBw_Down, controller.getState());
  EXPECT_TRUE(Bbr2TestPeer::fullBwReached(controller));
  EXPECT_FALSE(Bbr2TestPeer::hasUndoState(controller));
}

TEST_F(Bbr2SpuriousLossTest, NewLossEpisodeDiscardsStartupUndo) {
  conn_->transportSettings.ccaConfig.enableSpuriousLossRecovery = true;
  Bbr2CongestionController controller(*conn_);
  exitStartupOnLoss(controller);
  startLossEpisode(controller, 1, false, Clock::now() + 1ms);
  ASSERT_FALSE(Bbr2TestPeer::hasUndoState(controller));

  processEvent(controller, makeSpuriousAck(7), std::nullopt);

  EXPECT_EQ(Bbr2CongestionController::State::Drain, controller.getState());
  EXPECT_TRUE(Bbr2TestPeer::fullBwReached(controller));
}

TEST_F(Bbr2SpuriousLossTest, StartupUndoHonorsInitialPacingGate) {
  conn_->transportSettings.ccaConfig.enableSpuriousLossRecovery = true;
  Bbr2CongestionController controller(*conn_);
  conn_->transportSettings.ccaConfig.paceInitCwnd = false;
  startLossEpisode(controller);

  EXPECT_CALL(*pacer_, setRttFactor(_, _)).Times(0);
  EXPECT_CALL(*pacer_, refreshPacingRate(_, _, _)).Times(0);
  processEvent(controller, makeSpuriousAck(1), std::nullopt);

  EXPECT_FALSE(Bbr2TestPeer::hasUndoState(controller));
}

TEST_F(Bbr2SpuriousLossTest, ProbeBwUndoHonorsInitialPacingGate) {
  conn_->transportSettings.ccaConfig.enableSpuriousLossRecovery = true;
  Bbr2CongestionController controller(*conn_);
  conn_->transportSettings.ccaConfig.paceInitCwnd = false;
  Bbr2TestPeer::enterProbeBw(controller);
  startLossEpisode(controller);
  ASSERT_LT(
      conn_->lossState.totalBytesSent,
      conn_->transportSettings.initCwndInMss * kPacketSize);

  EXPECT_CALL(*pacer_, setRttFactor(_, _)).Times(0);
  EXPECT_CALL(*pacer_, refreshPacingRate(_, _, _)).Times(0);
  processEvent(controller, makeSpuriousAck(1), std::nullopt);
  EXPECT_FALSE(Bbr2TestPeer::hasUndoState(controller));
}

TEST_F(Bbr2SpuriousLossTest, ProbeRttUndoHonorsInitialPacingGate) {
  conn_->transportSettings.ccaConfig.enableSpuriousLossRecovery = true;
  Bbr2CongestionController controller(*conn_);
  conn_->transportSettings.ccaConfig.paceInitCwnd = false;
  Bbr2TestPeer::enterProbeRtt(controller);
  startLossEpisode(controller);
  ASSERT_LT(
      conn_->lossState.totalBytesSent,
      conn_->transportSettings.initCwndInMss * kPacketSize);

  EXPECT_CALL(*pacer_, setRttFactor(_, _)).Times(0);
  EXPECT_CALL(*pacer_, refreshPacingRate(_, _, _)).Times(0);
  processEvent(controller, makeSpuriousAck(1), std::nullopt);
  EXPECT_FALSE(Bbr2TestPeer::hasUndoState(controller));
}

} // namespace test
} // namespace quic
