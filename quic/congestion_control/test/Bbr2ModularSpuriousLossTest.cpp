/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <folly/portability/GMock.h>
#include <folly/portability/GTest.h>
#include <quic/common/test/TestUtils.h>
#include <quic/congestion_control/modular/Bbr2ProbeBw.h>
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

  static void setModelState(
      Bbr2Shared& shared,
      uint64_t cwndBytes,
      Optional<Bandwidth> bandwidthShortTerm,
      Optional<uint64_t> inflightShortTerm,
      Optional<uint64_t> inflightLongTerm) {
    shared.cwndBytes_ = cwndBytes;
    shared.bandwidthShortTerm_ = std::move(bandwidthShortTerm);
    shared.inflightShortTerm_ = inflightShortTerm;
    shared.inflightLongTerm_ = inflightLongTerm;
  }

  static uint64_t cwnd(const Bbr2Shared& shared) {
    return shared.cwndBytes_;
  }

  static Optional<Bandwidth> bandwidthShortTerm(const Bbr2Shared& shared) {
    return shared.bandwidthShortTerm_;
  }

  static Optional<uint64_t> inflightShortTerm(const Bbr2Shared& shared) {
    return shared.inflightShortTerm_;
  }

  static Optional<uint64_t> inflightLongTerm(const Bbr2Shared& shared) {
    return shared.inflightLongTerm_;
  }

  static Bbr2Shared::RecoveryState recoveryState(const Bbr2Shared& shared) {
    return shared.recoveryState_;
  }

  static bool hasUndoState(const Bbr2Shared& shared) {
    return shared.spuriousLossUndoState_.has_value();
  }

  static uint64_t pendingLostPackets(const Bbr2Shared& shared) {
    return shared.spuriousLossUndoState_->pendingLostPackets;
  }

  static uint64_t undoPriorCwnd(const Bbr2Shared& shared) {
    return shared.spuriousLossUndoState_->priorCwndBytes;
  }

  static void setState(Bbr2Shared& shared, Bbr2State state) {
    shared.state_ = state;
  }

  static Bbr2State state(const Bbr2Shared& shared) {
    return shared.state_;
  }

  static void setReturnedFromProbeRtt(Bbr2Shared& shared) {
    shared.returnedFromProbeRtt_ = true;
  }

  static void setProbeRttCwnd(Bbr2Shared& shared, uint64_t cwnd) {
    shared.probeRttCwnd_ = cwnd;
  }

  static void setFullBwCount(Bbr2Shared& shared, uint64_t count) {
    shared.fullBwCount_ = count;
  }

  static uint64_t fullBwCount(const Bbr2Shared& shared) {
    return shared.fullBwCount_;
  }

  static void setCurrentLossSignals(
      Bbr2Shared& shared,
      uint64_t lossBytes,
      uint64_t lossEvents,
      PacketNum largestLostPacket) {
    shared.lossBytesInRound_ = lossBytes;
    shared.lossEventsInRound_ = lossEvents;
    shared.largestLostPacketNumInRound_ = largestLostPacket;
  }

  static uint64_t lossBytesInRound(const Bbr2Shared& shared) {
    return shared.lossBytesInRound_;
  }

  static uint64_t lossEventsInRound(const Bbr2Shared& shared) {
    return shared.lossEventsInRound_;
  }

  static PacketNum largestLostPacketNumInRound(const Bbr2Shared& shared) {
    return shared.largestLostPacketNumInRound_;
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

class Bbr2ModularSpuriousLossTest : public Test {
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

  std::unique_ptr<QuicConnectionStateBase> conn_;
  MockPacer* pacer_{nullptr};
  PacketNum nextPacketNum_{0};
  uint64_t totalBytesSent_{0};
};

TEST_F(Bbr2ModularSpuriousLossTest, DisabledByDefault) {
  Bbr2Startup controller(*conn_);
  auto shared = Bbr2ModularTestPeer::shared(controller);
  Bbr2ModularTestPeer::setModelState(
      *shared, 20'000, kSavedBandwidth, 16'000, 18'000);
  startLossEpisode(controller);
  Bbr2ModularTestPeer::setModelState(
      *shared, 8'000, kReducedBandwidth, 7'000, 9'000);

  processEvent(controller, makeSpuriousAck(1), std::nullopt);

  EXPECT_EQ(8'000, Bbr2ModularTestPeer::cwnd(*shared));
  EXPECT_EQ(
      kReducedBandwidth,
      Bbr2ModularTestPeer::bandwidthShortTerm(*shared).value());
  EXPECT_EQ(7'000, Bbr2ModularTestPeer::inflightShortTerm(*shared).value());
  EXPECT_EQ(9'000, Bbr2ModularTestPeer::inflightLongTerm(*shared).value());
  EXPECT_FALSE(Bbr2ModularTestPeer::hasUndoState(*shared));
}

TEST_F(Bbr2ModularSpuriousLossTest, UndoesRealLossResponse) {
  conn_->transportSettings.ccaConfig.enableSpuriousLossRecovery = true;
  Bbr2Startup controller(*conn_);
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

  expectRepace();
  processEvent(controller, makeSpuriousAck(1), std::nullopt);
  EXPECT_EQ(cwndBeforeLoss, controller.getCongestionWindow());
}

TEST_F(
    Bbr2ModularSpuriousLossTest,
    CompleteEpisodeRestoresStateWithoutSamplingSpuriousAck) {
  conn_->transportSettings.ccaConfig.enableSpuriousLossRecovery = true;
  Bbr2Startup controller(*conn_);
  auto shared = Bbr2ModularTestPeer::shared(controller);
  Bbr2ModularTestPeer::setModelState(
      *shared, 20'000, kSavedBandwidth, 16'000, 18'000);
  startLossEpisode(controller, 2);
  ASSERT_TRUE(Bbr2ModularTestPeer::hasUndoState(*shared));
  EXPECT_EQ(2, Bbr2ModularTestPeer::pendingLostPackets(*shared));

  Bbr2ModularTestPeer::setModelState(
      *shared, 8'000, kReducedBandwidth, 7'000, 9'000);
  processEvent(controller, makeSpuriousAck(1), std::nullopt);
  EXPECT_EQ(8'000, Bbr2ModularTestPeer::cwnd(*shared));
  EXPECT_EQ(1, Bbr2ModularTestPeer::pendingLostPackets(*shared));

  Bbr2ModularTestPeer::setCurrentLossSignals(*shared, 4'000, 3, 77);
  Bbr2ModularTestPeer::setFullBwCount(*shared, 2);
  expectRepace();

  processEvent(controller, makeSpuriousAck(1), std::nullopt);

  EXPECT_EQ(20'000, Bbr2ModularTestPeer::cwnd(*shared));
  EXPECT_EQ(
      kSavedBandwidth,
      Bbr2ModularTestPeer::bandwidthShortTerm(*shared).value());
  EXPECT_EQ(16'000, Bbr2ModularTestPeer::inflightShortTerm(*shared).value());
  EXPECT_EQ(18'000, Bbr2ModularTestPeer::inflightLongTerm(*shared).value());
  EXPECT_EQ(
      Bbr2Shared::RecoveryState::NOT_RECOVERY,
      Bbr2ModularTestPeer::recoveryState(*shared));
  EXPECT_FALSE(Bbr2ModularTestPeer::hasUndoState(*shared));
  EXPECT_EQ(0, Bbr2ModularTestPeer::fullBwCount(*shared));
  EXPECT_EQ(0, Bbr2ModularTestPeer::lossBytesInRound(*shared));
  EXPECT_EQ(0, Bbr2ModularTestPeer::lossEventsInRound(*shared));
  EXPECT_EQ(0, Bbr2ModularTestPeer::largestLostPacketNumInRound(*shared));
}

TEST_F(Bbr2ModularSpuriousLossTest, OptionalBoundsTreatAbsentAsInfinity) {
  conn_->transportSettings.ccaConfig.enableSpuriousLossRecovery = true;
  Bbr2Startup controller(*conn_);
  auto shared = Bbr2ModularTestPeer::shared(controller);

  Bbr2ModularTestPeer::setModelState(
      *shared, 20'000, std::nullopt, std::nullopt, std::nullopt);
  startLossEpisode(controller);
  Bbr2ModularTestPeer::setModelState(
      *shared, 8'000, kReducedBandwidth, 7'000, 9'000);
  processEvent(controller, makeSpuriousAck(1), std::nullopt);
  EXPECT_FALSE(Bbr2ModularTestPeer::bandwidthShortTerm(*shared));
  EXPECT_FALSE(Bbr2ModularTestPeer::inflightShortTerm(*shared));
  EXPECT_FALSE(Bbr2ModularTestPeer::inflightLongTerm(*shared));

  Bbr2ModularTestPeer::setModelState(
      *shared, 20'000, kSavedBandwidth, 16'000, 18'000);
  startLossEpisode(controller);
  Bbr2ModularTestPeer::setModelState(
      *shared, 8'000, std::nullopt, std::nullopt, std::nullopt);
  processEvent(controller, makeSpuriousAck(1), std::nullopt);
  EXPECT_FALSE(Bbr2ModularTestPeer::bandwidthShortTerm(*shared));
  EXPECT_FALSE(Bbr2ModularTestPeer::inflightShortTerm(*shared));
  EXPECT_FALSE(Bbr2ModularTestPeer::inflightLongTerm(*shared));

  Bbr2ModularTestPeer::setModelState(
      *shared, 20'000, kSavedBandwidth, 16'000, 18'000);
  startLossEpisode(controller);
  Bbr2ModularTestPeer::setModelState(
      *shared, 24'000, kHigherBandwidth, 22'000, 23'000);
  processEvent(controller, makeSpuriousAck(1), std::nullopt);
  EXPECT_EQ(24'000, Bbr2ModularTestPeer::cwnd(*shared));
  EXPECT_EQ(
      kHigherBandwidth,
      Bbr2ModularTestPeer::bandwidthShortTerm(*shared).value());
  EXPECT_EQ(22'000, Bbr2ModularTestPeer::inflightShortTerm(*shared).value());
  EXPECT_EQ(23'000, Bbr2ModularTestPeer::inflightLongTerm(*shared).value());
}

TEST_F(Bbr2ModularSpuriousLossTest, LossDuringRecoveryExtendsEpisode) {
  conn_->transportSettings.ccaConfig.enableSpuriousLossRecovery = true;
  Bbr2Startup controller(*conn_);
  auto shared = Bbr2ModularTestPeer::shared(controller);
  Bbr2ModularTestPeer::setModelState(
      *shared, 20'000, kSavedBandwidth, 16'000, 18'000);
  startLossEpisode(controller);
  startLossEpisode(controller);
  ASSERT_TRUE(Bbr2ModularTestPeer::hasUndoState(*shared));
  EXPECT_EQ(2, Bbr2ModularTestPeer::pendingLostPackets(*shared));
  Bbr2ModularTestPeer::setModelState(
      *shared, 8'000, kReducedBandwidth, 7'000, 9'000);

  processEvent(controller, makeSpuriousAck(1), std::nullopt);
  EXPECT_EQ(8'000, Bbr2ModularTestPeer::cwnd(*shared));
  EXPECT_EQ(1, Bbr2ModularTestPeer::pendingLostPackets(*shared));

  expectRepace();
  processEvent(controller, makeSpuriousAck(1), std::nullopt);
  EXPECT_EQ(20'000, Bbr2ModularTestPeer::cwnd(*shared));
}

TEST_F(Bbr2ModularSpuriousLossTest, SpuriousAckIsResolvedBeforeNewLoss) {
  conn_->transportSettings.ccaConfig.enableSpuriousLossRecovery = true;
  Bbr2Startup controller(*conn_);
  auto shared = Bbr2ModularTestPeer::shared(controller);
  Bbr2ModularTestPeer::setModelState(
      *shared, 20'000, kSavedBandwidth, 16'000, 18'000);
  startLossEpisode(controller);
  Bbr2ModularTestPeer::setModelState(
      *shared, 8'000, kReducedBandwidth, 7'000, 9'000);

  processEvent(controller, makeSpuriousAck(1), makeLoss(controller, 1, false));

  ASSERT_TRUE(Bbr2ModularTestPeer::hasUndoState(*shared));
  EXPECT_EQ(1, Bbr2ModularTestPeer::pendingLostPackets(*shared));
  EXPECT_EQ(20'000, Bbr2ModularTestPeer::undoPriorCwnd(*shared));

  Bbr2ModularTestPeer::setModelState(
      *shared, 7'000, kReducedBandwidth, 6'000, 8'000);
  expectRepace();
  processEvent(controller, makeSpuriousAck(1), std::nullopt);
  EXPECT_EQ(20'000, Bbr2ModularTestPeer::cwnd(*shared));
  EXPECT_EQ(
      kSavedBandwidth,
      Bbr2ModularTestPeer::bandwidthShortTerm(*shared).value());
  EXPECT_EQ(16'000, Bbr2ModularTestPeer::inflightShortTerm(*shared).value());
  EXPECT_EQ(18'000, Bbr2ModularTestPeer::inflightLongTerm(*shared).value());
}

TEST_F(Bbr2ModularSpuriousLossTest, OlderRetainedLossPreventsUndo) {
  conn_->transportSettings.ccaConfig.enableSpuriousLossRecovery = true;
  Bbr2Startup controller(*conn_);
  auto shared = Bbr2ModularTestPeer::shared(controller);
  conn_->outstandings.declaredLostCount = 1;
  Bbr2ModularTestPeer::setModelState(
      *shared, 20'000, kSavedBandwidth, 16'000, 18'000);
  startLossEpisode(controller);
  EXPECT_FALSE(Bbr2ModularTestPeer::hasUndoState(*shared));
  Bbr2ModularTestPeer::setModelState(
      *shared, 8'000, kReducedBandwidth, 7'000, 9'000);
  processEvent(controller, makeSpuriousAck(2), std::nullopt);
  EXPECT_EQ(8'000, Bbr2ModularTestPeer::cwnd(*shared));
}

TEST_F(Bbr2ModularSpuriousLossTest, PersistentCongestionInvalidatesUndo) {
  conn_->transportSettings.ccaConfig.enableSpuriousLossRecovery = true;
  Bbr2Startup controller(*conn_);
  auto shared = Bbr2ModularTestPeer::shared(controller);
  Bbr2ModularTestPeer::setModelState(
      *shared, 20'000, kSavedBandwidth, 16'000, 18'000);
  startLossEpisode(controller);
  ASSERT_TRUE(Bbr2ModularTestPeer::hasUndoState(*shared));
  startLossEpisode(controller, 1, true);
  EXPECT_FALSE(Bbr2ModularTestPeer::hasUndoState(*shared));
  Bbr2ModularTestPeer::setModelState(
      *shared, 6'000, kReducedBandwidth, 5'000, 7'000);
  processEvent(controller, makeSpuriousAck(2), std::nullopt);
  EXPECT_EQ(6'000, Bbr2ModularTestPeer::cwnd(*shared));
}

TEST_F(Bbr2ModularSpuriousLossTest, CountMismatchInvalidatesUndo) {
  conn_->transportSettings.ccaConfig.enableSpuriousLossRecovery = true;
  Bbr2Startup controller(*conn_);
  auto shared = Bbr2ModularTestPeer::shared(controller);
  Bbr2ModularTestPeer::setModelState(
      *shared, 20'000, kSavedBandwidth, 16'000, 18'000);
  startLossEpisode(controller, 2);
  Bbr2ModularTestPeer::setModelState(
      *shared, 8'000, kReducedBandwidth, 7'000, 9'000);

  --conn_->outstandings.declaredLostCount;
  processEvent(controller, makeSpuriousAck(1), std::nullopt);

  EXPECT_FALSE(Bbr2ModularTestPeer::hasUndoState(*shared));
  EXPECT_EQ(8'000, controller.getCongestionWindow());
}

TEST_F(Bbr2ModularSpuriousLossTest, RecoversAfterOrdinaryRecoveryEnds) {
  conn_->transportSettings.ccaConfig.enableSpuriousLossRecovery = true;
  Bbr2Startup controller(*conn_);
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
      Bbr2Shared::RecoveryState::NOT_RECOVERY,
      Bbr2ModularTestPeer::recoveryState(
          *Bbr2ModularTestPeer::shared(controller)));

  expectRepace();
  processEvent(controller, makeSpuriousAck(1), std::nullopt);
  EXPECT_EQ(
      std::max(cwndBeforeLoss, cwndAfterRecovery),
      controller.getCongestionWindow());
}

TEST_F(Bbr2ModularSpuriousLossTest, NewRecoveryInvalidatesOlderEpisode) {
  conn_->transportSettings.ccaConfig.enableSpuriousLossRecovery = true;
  Bbr2Startup controller(*conn_);
  auto shared = Bbr2ModularTestPeer::shared(controller);
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
      Bbr2Shared::RecoveryState::NOT_RECOVERY,
      Bbr2ModularTestPeer::recoveryState(*shared));

  startLossEpisode(controller, 1, false, Clock::now() + 1ms);
  EXPECT_FALSE(Bbr2ModularTestPeer::hasUndoState(*shared));
  Bbr2ModularTestPeer::setModelState(
      *shared, 8'000, kReducedBandwidth, 7'000, 9'000);
  processEvent(controller, makeSpuriousAck(2), std::nullopt);
  EXPECT_EQ(8'000, controller.getCongestionWindow());
}

TEST_F(
    Bbr2ModularSpuriousLossTest,
    RecoveryDisabledNewEpisodeInvalidatesOlderUndo) {
  conn_->transportSettings.ccaConfig.enableSpuriousLossRecovery = true;
  conn_->transportSettings.ccaConfig.enableRecoveryInStartup = false;
  Bbr2Startup controller(*conn_);
  auto shared = Bbr2ModularTestPeer::shared(controller);
  Bbr2ModularTestPeer::setModelState(
      *shared, 20'000, kSavedBandwidth, 16'000, 18'000);
  startLossEpisode(controller);
  ASSERT_TRUE(Bbr2ModularTestPeer::hasUndoState(*shared));

  Bbr2ModularTestPeer::setModelState(
      *shared, 8'000, kReducedBandwidth, 7'000, 9'000);
  startLossEpisode(controller, 1, false, Clock::now() + 1ms);
  EXPECT_FALSE(Bbr2ModularTestPeer::hasUndoState(*shared));

  processEvent(controller, makeSpuriousAck(2), std::nullopt);
  EXPECT_EQ(8'000, controller.getCongestionWindow());
}

TEST_F(Bbr2ModularSpuriousLossTest, IdleRestartInvalidatesUndo) {
  conn_->transportSettings.ccaConfig.enableSpuriousLossRecovery = true;
  Bbr2Startup controller(*conn_);
  auto shared = Bbr2ModularTestPeer::shared(controller);
  Bbr2ModularTestPeer::setModelState(
      *shared, 20'000, kSavedBandwidth, 16'000, 18'000);
  startLossEpisode(controller);
  ASSERT_TRUE(Bbr2ModularTestPeer::hasUndoState(*shared));

  Bbr2ModularTestPeer::setModelState(
      *shared, 8'000, kReducedBandwidth, 7'000, 9'000);
  controller.setAppLimited();
  totalBytesSent_ += kPacketSize;
  auto packet = makeTestingWritePacket(
      nextPacketNum_++, kPacketSize, totalBytesSent_, Clock::now());
  onPacketsSentWrapper(conn_.get(), &controller, packet);
  EXPECT_FALSE(Bbr2ModularTestPeer::hasUndoState(*shared));

  processEvent(controller, makeSpuriousAck(1), std::nullopt);
  EXPECT_EQ(8'000, controller.getCongestionWindow());
}

TEST_F(Bbr2ModularSpuriousLossTest, RecoveryGateDoesNotDisableModelUndo) {
  conn_->transportSettings.ccaConfig.enableSpuriousLossRecovery = true;
  conn_->transportSettings.ccaConfig.enableRecoveryInProbeStates = false;
  Bbr2Startup startup(*conn_);
  auto shared = Bbr2ModularTestPeer::shared(startup);
  Bbr2ProbeBw controller(*conn_, shared);
  Bbr2ModularTestPeer::setModelState(
      *shared, 20'000, kSavedBandwidth, 16'000, 18'000);
  startLossEpisode(controller, 2);
  EXPECT_TRUE(Bbr2ModularTestPeer::hasUndoState(*shared));
  Bbr2ModularTestPeer::setModelState(
      *shared, 8'000, kReducedBandwidth, 7'000, 9'000);
  expectRepace();

  processEvent(controller, makeSpuriousAck(2), std::nullopt);

  EXPECT_EQ(16'000, Bbr2ModularTestPeer::cwnd(*shared));
  EXPECT_EQ(
      kSavedBandwidth,
      Bbr2ModularTestPeer::bandwidthShortTerm(*shared).value());
}

TEST_F(
    Bbr2ModularSpuriousLossTest,
    RecoveryDisabledEpisodeCanEnterRecoveryAfterTransition) {
  conn_->transportSettings.ccaConfig.enableSpuriousLossRecovery = true;
  conn_->transportSettings.ccaConfig.enableRecoveryInStartup = false;
  Bbr2Startup startup(*conn_);
  auto shared = Bbr2ModularTestPeer::shared(startup);
  Bbr2ModularTestPeer::setModelState(
      *shared, 20'000, kSavedBandwidth, 16'000, 18'000);
  startLossEpisode(startup);

  Bbr2ProbeBw probeBw(*conn_, shared);
  startLossEpisode(probeBw);
  ASSERT_TRUE(Bbr2ModularTestPeer::hasUndoState(*shared));
  EXPECT_EQ(2, Bbr2ModularTestPeer::pendingLostPackets(*shared));
  EXPECT_NE(
      Bbr2Shared::RecoveryState::NOT_RECOVERY,
      Bbr2ModularTestPeer::recoveryState(*shared));
  Bbr2ModularTestPeer::setModelState(
      *shared, 8'000, kReducedBandwidth, 7'000, 9'000);
  expectRepace();

  processEvent(probeBw, makeSpuriousAck(2), std::nullopt);

  EXPECT_EQ(16'000, probeBw.getCongestionWindow());
  EXPECT_EQ(
      kSavedBandwidth,
      Bbr2ModularTestPeer::bandwidthShortTerm(*shared).value());
}

TEST_F(Bbr2ModularSpuriousLossTest, DrainReappliesRestoredModelBounds) {
  conn_->transportSettings.ccaConfig.enableSpuriousLossRecovery = true;
  Bbr2Startup controller(*conn_);
  auto shared = Bbr2ModularTestPeer::shared(controller);
  Bbr2ModularTestPeer::setState(*shared, Bbr2State::Drain);
  Bbr2ModularTestPeer::setModelState(
      *shared, 20'000, kSavedBandwidth, 12'000, std::nullopt);
  startLossEpisode(controller);
  Bbr2ModularTestPeer::setModelState(
      *shared, 8'000, kReducedBandwidth, 6'000, std::nullopt);
  expectRepace();

  processEvent(controller, makeSpuriousAck(1), std::nullopt);

  EXPECT_EQ(12'000, controller.getCongestionWindow());
  EXPECT_EQ(12'000, Bbr2ModularTestPeer::inflightShortTerm(*shared).value());
  EXPECT_EQ(
      kSavedBandwidth,
      Bbr2ModularTestPeer::bandwidthShortTerm(*shared).value());
}

TEST_F(Bbr2ModularSpuriousLossTest, ProbeBwReappliesRestoredModelBounds) {
  conn_->transportSettings.ccaConfig.enableSpuriousLossRecovery = true;
  Bbr2Startup startup(*conn_);
  auto shared = Bbr2ModularTestPeer::shared(startup);
  Bbr2ProbeBw controller(*conn_, shared);
  Bbr2ModularTestPeer::setModelState(
      *shared, 30'000, kSavedBandwidth, 16'000, 18'000);
  startLossEpisode(controller);
  Bbr2ModularTestPeer::setModelState(
      *shared, 8'000, kReducedBandwidth, 7'000, 9'000);
  expectRepace();

  processEvent(controller, makeSpuriousAck(1), std::nullopt);

  EXPECT_EQ(16'000, controller.getCongestionWindow());
  EXPECT_EQ(16'000, Bbr2ModularTestPeer::inflightShortTerm(*shared).value());
  EXPECT_EQ(18'000, Bbr2ModularTestPeer::inflightLongTerm(*shared).value());
}

TEST_F(Bbr2ModularSpuriousLossTest, UndoSurvivesStartupToProbeBwTransition) {
  conn_->transportSettings.ccaConfig.enableSpuriousLossRecovery = true;
  Bbr2Startup startup(*conn_);
  auto shared = Bbr2ModularTestPeer::shared(startup);
  Bbr2ModularTestPeer::setModelState(
      *shared, 20'000, std::nullopt, std::nullopt, std::nullopt);
  startLossEpisode(startup);
  ASSERT_TRUE(Bbr2ModularTestPeer::hasUndoState(*shared));

  Bbr2ProbeBw probeBw(*conn_, shared);
  Bbr2ModularTestPeer::setModelState(
      *shared, 8'000, kReducedBandwidth, 7'000, 9'000);
  expectRepace();
  processEvent(probeBw, makeSpuriousAck(1), std::nullopt);

  EXPECT_EQ(20'000, probeBw.getCongestionWindow());
  EXPECT_FALSE(Bbr2ModularTestPeer::bandwidthShortTerm(*shared));
  EXPECT_FALSE(Bbr2ModularTestPeer::inflightShortTerm(*shared));
  EXPECT_FALSE(Bbr2ModularTestPeer::inflightLongTerm(*shared));
}

TEST_F(Bbr2ModularSpuriousLossTest, UndoAfterProbeRttReturnUsesProbeBwState) {
  conn_->transportSettings.ccaConfig.enableSpuriousLossRecovery = true;
  Bbr2Startup startup(*conn_);
  auto shared = Bbr2ModularTestPeer::shared(startup);
  Bbr2ProbeBw probeBw(*conn_, shared);
  Bbr2ModularTestPeer::setModelState(
      *shared, 20'000, kSavedBandwidth, 16'000, 18'000);
  startLossEpisode(probeBw);
  Bbr2ModularTestPeer::setState(*shared, Bbr2State::ProbeRtt);
  Bbr2ModularTestPeer::setReturnedFromProbeRtt(*shared);
  Bbr2ModularTestPeer::setModelState(
      *shared, 8'000, kReducedBandwidth, 7'000, 9'000);
  expectRepace();

  processEvent(probeBw, makeSpuriousAck(1), std::nullopt);

  EXPECT_EQ(Bbr2State::ProbeBw_Cruise, Bbr2ModularTestPeer::state(*shared));
  EXPECT_GT(probeBw.getCongestionWindow(), 8'000);
}

TEST_F(
    Bbr2ModularSpuriousLossTest,
    ProbeRttBoundsUndoAndResetsFullBwAfterTransition) {
  conn_->transportSettings.ccaConfig.enableSpuriousLossRecovery = true;
  auto startup = std::make_unique<Bbr2Startup>(*conn_);
  auto shared = Bbr2ModularTestPeer::shared(*startup);
  auto probeBw = std::make_unique<Bbr2ProbeBw>(*conn_, shared);
  Bbr2ModularTestPeer::setModelState(
      *shared, 20'000, kSavedBandwidth, 16'000, 18'000);
  startLossEpisode(*probeBw);
  Bbr2ModularTestPeer::setFullBwCount(*shared, 3);
  ASSERT_TRUE(Bbr2ModularTestPeer::hasUndoState(*shared));

  const auto probeRttCwnd = std::max<uint64_t>(
      conn_->transportSettings.initCwndInMss * kPacketSize / 2,
      kMinCwndInMssForBbr * kPacketSize);
  Bbr2ModularTestPeer::setProbeRttCwnd(*shared, probeRttCwnd);
  Bbr2ProbeRtt probeRtt(*conn_, shared, std::move(probeBw));
  Bbr2ModularTestPeer::setModelState(
      *shared, 8'000, kReducedBandwidth, 7'000, 9'000);
  expectRepace();
  processEvent(probeRtt, makeSpuriousAck(1), std::nullopt);

  EXPECT_EQ(
      std::min<uint64_t>(20'000, probeRttCwnd), probeRtt.getCongestionWindow());
  EXPECT_EQ(0, Bbr2ModularTestPeer::fullBwCount(*shared));
  EXPECT_EQ(
      kSavedBandwidth,
      Bbr2ModularTestPeer::bandwidthShortTerm(*shared).value());
  EXPECT_EQ(16'000, Bbr2ModularTestPeer::inflightShortTerm(*shared).value());
  EXPECT_EQ(18'000, Bbr2ModularTestPeer::inflightLongTerm(*shared).value());
}

} // namespace test
} // namespace quic
