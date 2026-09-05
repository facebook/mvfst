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
#include <quic/congestion_control/modular/Bbr2Startup.h>
#include <quic/congestion_control/test/Utils.h>
#include <quic/state/test/Mocks.h>
#include <limits>

using namespace testing;

namespace quic {

class Bbr2ModularTestPeer {
 public:
  static std::shared_ptr<Bbr2Shared> shared(const Bbr2Startup& controller) {
    return controller.shared_;
  }

  static void configureProbeBwUp(
      Bbr2ProbeBw& controller,
      Optional<uint64_t> inflightLongTerm,
      bool previousProbeTooHigh,
      bool previousProbePrecautionary,
      bool canUpdateLongtermLossModel = false) {
    controller.shared_->state_ = Bbr2State::ProbeBw_Up;
    controller.shared_->inflightLongTerm_ = inflightLongTerm;
    controller.shared_->lossBytesInRound_ = 0;
    controller.shared_->lossRoundEndBytesSent_ =
        std::numeric_limits<uint64_t>::max();
    controller.shared_->cwndLimitedInRound_ = false;
    controller.previousProbeTooHigh_ = previousProbeTooHigh;
    controller.previousProbePrecautionary_ = previousProbePrecautionary;
    controller.canUpdateLongtermLossModel_ = canUpdateLongtermLossModel;
    controller.fullBwNow_ = false;
    controller.fullBw_ = Bandwidth();
    controller.shared_->fullBwCount_ = 0;
    controller.shared_->startRound();
  }

  static Bbr2State state(const Bbr2ProbeBw& controller) {
    return controller.shared_->state_;
  }

  static bool previousProbeTooHigh(const Bbr2ProbeBw& controller) {
    return controller.previousProbeTooHigh_;
  }

  static bool previousProbePrecautionary(const Bbr2ProbeBw& controller) {
    return controller.previousProbePrecautionary_;
  }

  static Optional<uint64_t> inflightLongTerm(const Bbr2ProbeBw& controller) {
    return controller.shared_->inflightLongTerm_;
  }

  static void setLossBytesInRound(Bbr2ProbeBw& controller, uint64_t lossBytes) {
    controller.shared_->lossBytesInRound_ = lossBytes;
  }

  static void setFullBwNow(Bbr2ProbeBw& controller) {
    controller.fullBwNow_ = true;
  }

  static void expireProbeWait(Bbr2ProbeBw& controller) {
    controller.probeBWCycleStart_ = Clock::now() - 4s;
    controller.bwProbeWait_ = 2s;
  }

  static void preventRoundStart(Bbr2ProbeBw& controller) {
    controller.shared_->nextRoundDelivered_ =
        std::numeric_limits<uint64_t>::max();
  }

  static void configureProbeRttReturn(
      Bbr2ProbeBw& controller,
      bool previousProbeTooHigh,
      bool previousProbePrecautionary) {
    controller.shared_->state_ = Bbr2State::ProbeRtt;
    controller.shared_->returnedFromProbeRtt_ = true;
    controller.previousProbeTooHigh_ = previousProbeTooHigh;
    controller.previousProbePrecautionary_ = previousProbePrecautionary;
  }
};

namespace test {

namespace {

constexpr uint64_t kPacketSize = 1000;
constexpr uint64_t kInflightLongTerm = 10'000;

} // namespace

class Bbr2ModularProbeBwTest : public Test {
 public:
  void SetUp() override {
    conn_ = std::make_unique<QuicConnectionStateBase>(QuicNodeType::Client);
    conn_->pacer = std::make_unique<NiceMock<MockPacer>>();
    conn_->udpSendPacketLen = kPacketSize;
    conn_->connectionTime = Clock::now() - 2s;
    conn_->transportSettings.ccaConfig.paceInitCwnd = true;
    conn_->lossState.lrtt = 100ms;
  }

 protected:
  std::unique_ptr<Bbr2ProbeBw> makeController() {
    Bbr2Startup startup(*conn_);
    return std::make_unique<Bbr2ProbeBw>(
        *conn_, Bbr2ModularTestPeer::shared(startup));
  }

  void processAck(
      Bbr2ProbeBw& controller,
      uint64_t inflightAfterEvent,
      uint64_t sampledInflight,
      bool completesRound = true,
      uint64_t lostBytes = 0) {
    const auto previousTotalBytesAcked = conn_->lossState.totalBytesAcked;
    if (!completesRound) {
      ASSERT_GT(previousTotalBytesAcked, 0);
    }

    const auto sentTime = Clock::now() - 10ms;
    totalBytesSent_ += kPacketSize;
    auto packet = makeTestingWritePacket(
        nextPacketNum_++,
        kPacketSize,
        totalBytesSent_,
        sentTime,
        0,
        sampledInflight);
    const auto previousPacketTotalBytesAcked =
        completesRound ? previousTotalBytesAcked : previousTotalBytesAcked - 1;
    packet.lastAckedPacketInfo.emplace(
        sentTime - 1ms,
        sentTime - 1ms,
        sentTime - 1ms,
        totalBytesSent_ - kPacketSize,
        previousPacketTotalBytesAcked);

    const auto packetNum = packet.getPacketSequenceNum();
    const auto ackTime = Clock::now();
    auto ack = AckEvent::Builder()
                   .setAckTime(ackTime)
                   .setAdjustedAckTime(ackTime)
                   .setAckDelay(0us)
                   .setPacketNumberSpace(PacketNumberSpace::AppData)
                   .setLargestAckedPacket(packetNum)
                   .build();
    ack.ackedBytes = kPacketSize;
    ack.totalBytesAcked = previousTotalBytesAcked + kPacketSize;
    ack.largestNewlyAckedPacket = packetNum;
    ack.largestNewlyAckedPacketSentTime = sentTime;
    ack.ackedPackets.emplace_back(
        makeAckPacketFromOutstandingPacket(std::move(packet)));

    conn_->lossState.totalBytesAcked = ack.totalBytesAcked;
    conn_->lossState.inflightBytes =
        inflightAfterEvent + ack.ackedBytes + lostBytes;
    Optional<LossEvent> loss;
    if (lostBytes > 0) {
      totalBytesSent_ += lostBytes;
      auto lostPacket = makeTestingWritePacket(
          nextPacketNum_++,
          lostBytes,
          totalBytesSent_,
          sentTime,
          0,
          sampledInflight);
      loss.emplace();
      loss->addLostPacket(lostPacket);
    }
    conn_->lossState.totalBytesSent = totalBytesSent_;
    onPacketAckOrLossWrapper(
        conn_.get(), &controller, std::move(ack), std::move(loss));
    EXPECT_EQ(inflightAfterEvent, conn_->lossState.inflightBytes);
  }

  std::unique_ptr<QuicConnectionStateBase> conn_;
  PacketNum nextPacketNum_{0};
  uint64_t totalBytesSent_{0};
};

TEST_F(Bbr2ModularProbeBwTest, DisabledByDefaultPreservesProbeBwUp) {
  auto controller = makeController();
  Bbr2ModularTestPeer::configureProbeBwUp(
      *controller, kInflightLongTerm, true, false);

  processAck(
      *controller,
      kInflightLongTerm - kPacketSize,
      kInflightLongTerm - kPacketSize);

  EXPECT_EQ(Bbr2State::ProbeBw_Up, Bbr2ModularTestPeer::state(*controller));
  EXPECT_FALSE(Bbr2ModularTestPeer::previousProbeTooHigh(*controller));
  EXPECT_FALSE(Bbr2ModularTestPeer::previousProbePrecautionary(*controller));
}

TEST_F(Bbr2ModularProbeBwTest, OrdinaryProbeDoesNotStopAtInflightBound) {
  conn_->transportSettings.ccaConfig.enablePrecautionaryBandwidthProbing = true;
  auto controller = makeController();
  Bbr2ModularTestPeer::configureProbeBwUp(
      *controller, kInflightLongTerm, false, false);

  processAck(
      *controller,
      kInflightLongTerm - kPacketSize,
      kInflightLongTerm - kPacketSize);

  EXPECT_EQ(Bbr2State::ProbeBw_Up, Bbr2ModularTestPeer::state(*controller));
}

TEST_F(Bbr2ModularProbeBwTest, PrecautionaryProbeStopsAtInclusiveBound) {
  conn_->transportSettings.ccaConfig.enablePrecautionaryBandwidthProbing = true;
  auto controller = makeController();
  Bbr2ModularTestPeer::configureProbeBwUp(
      *controller, kInflightLongTerm, true, false);

  processAck(
      *controller,
      kInflightLongTerm - kPacketSize,
      kInflightLongTerm - kPacketSize);

  EXPECT_EQ(Bbr2State::ProbeBw_Down, Bbr2ModularTestPeer::state(*controller));
  EXPECT_FALSE(Bbr2ModularTestPeer::previousProbeTooHigh(*controller));
  EXPECT_TRUE(Bbr2ModularTestPeer::previousProbePrecautionary(*controller));
}

TEST_F(Bbr2ModularProbeBwTest, PrecautionaryProbeUsesInflightBeforeAckAndLoss) {
  conn_->transportSettings.ccaConfig.enablePrecautionaryBandwidthProbing = true;
  auto controller = makeController();
  Bbr2ModularTestPeer::configureProbeBwUp(
      *controller, kInflightLongTerm, true, false);

  constexpr uint64_t kLostBytes = 100;
  processAck(
      *controller,
      kInflightLongTerm - kPacketSize - kLostBytes,
      kInflightLongTerm - kPacketSize,
      true,
      kLostBytes);

  EXPECT_EQ(Bbr2State::ProbeBw_Down, Bbr2ModularTestPeer::state(*controller));
  EXPECT_FALSE(Bbr2ModularTestPeer::previousProbeTooHigh(*controller));
  EXPECT_TRUE(Bbr2ModularTestPeer::previousProbePrecautionary(*controller));
}

TEST_F(
    Bbr2ModularProbeBwTest,
    SendTimeInflightDoesNotTriggerPrecautionaryProbe) {
  conn_->transportSettings.ccaConfig.enablePrecautionaryBandwidthProbing = true;
  auto controller = makeController();
  Bbr2ModularTestPeer::configureProbeBwUp(
      *controller, kInflightLongTerm, true, false);

  processAck(
      *controller, kInflightLongTerm - kPacketSize - 1, kInflightLongTerm + 1);

  EXPECT_EQ(Bbr2State::ProbeBw_Up, Bbr2ModularTestPeer::state(*controller));
  EXPECT_EQ(
      kInflightLongTerm + 1,
      Bbr2ModularTestPeer::inflightLongTerm(*controller));
}

TEST_F(Bbr2ModularProbeBwTest, MissingInflightBoundDoesNotStopProbe) {
  conn_->transportSettings.ccaConfig.enablePrecautionaryBandwidthProbing = true;
  auto controller = makeController();
  Bbr2ModularTestPeer::configureProbeBwUp(
      *controller, std::nullopt, true, false);

  processAck(*controller, kInflightLongTerm, kInflightLongTerm);

  EXPECT_EQ(Bbr2State::ProbeBw_Up, Bbr2ModularTestPeer::state(*controller));
}

TEST_F(Bbr2ModularProbeBwTest, ExactLossThresholdDoesNotArmPrecaution) {
  conn_->transportSettings.ccaConfig.enablePrecautionaryBandwidthProbing = true;
  auto controller = makeController();
  Bbr2ModularTestPeer::configureProbeBwUp(
      *controller, kInflightLongTerm, false, false, true);
  Bbr2ModularTestPeer::setLossBytesInRound(*controller, 20);

  processAck(*controller, 0, kPacketSize);

  EXPECT_EQ(Bbr2State::ProbeBw_Up, Bbr2ModularTestPeer::state(*controller));
  EXPECT_FALSE(Bbr2ModularTestPeer::previousProbeTooHigh(*controller));
}

TEST_F(Bbr2ModularProbeBwTest, ExcessiveLossWinsOverPrecautionaryBoundary) {
  conn_->transportSettings.ccaConfig.enablePrecautionaryBandwidthProbing = true;
  auto controller = makeController();
  Bbr2ModularTestPeer::configureProbeBwUp(
      *controller, kInflightLongTerm, true, false, true);
  Bbr2ModularTestPeer::setLossBytesInRound(*controller, 21);

  processAck(*controller, kInflightLongTerm, kPacketSize);

  EXPECT_EQ(Bbr2State::ProbeBw_Down, Bbr2ModularTestPeer::state(*controller));
  EXPECT_TRUE(Bbr2ModularTestPeer::previousProbeTooHigh(*controller));
  EXPECT_FALSE(Bbr2ModularTestPeer::previousProbePrecautionary(*controller));
}

TEST_F(Bbr2ModularProbeBwTest, PrecautionaryProbeGetsOneRoundFastFollowup) {
  conn_->transportSettings.ccaConfig.enablePrecautionaryBandwidthProbing = true;
  auto controller = makeController();
  Bbr2ModularTestPeer::configureProbeBwUp(
      *controller, kInflightLongTerm, true, false);
  processAck(
      *controller,
      kInflightLongTerm - kPacketSize,
      kInflightLongTerm - kPacketSize);
  ASSERT_EQ(Bbr2State::ProbeBw_Down, Bbr2ModularTestPeer::state(*controller));

  processAck(
      *controller, kInflightLongTerm, kInflightLongTerm - kPacketSize, false);
  EXPECT_EQ(Bbr2State::ProbeBw_Down, Bbr2ModularTestPeer::state(*controller));

  processAck(*controller, kInflightLongTerm, kInflightLongTerm - kPacketSize);
  EXPECT_EQ(Bbr2State::ProbeBw_Refill, Bbr2ModularTestPeer::state(*controller));
  EXPECT_FALSE(Bbr2ModularTestPeer::previousProbePrecautionary(*controller));

  processAck(*controller, kInflightLongTerm, kInflightLongTerm - kPacketSize);
  ASSERT_EQ(Bbr2State::ProbeBw_Up, Bbr2ModularTestPeer::state(*controller));
  processAck(*controller, kInflightLongTerm, kInflightLongTerm - kPacketSize);
  EXPECT_EQ(Bbr2State::ProbeBw_Up, Bbr2ModularTestPeer::state(*controller));
}

TEST_F(
    Bbr2ModularProbeBwTest,
    PrecautionaryProbeGetsFastFollowupAfterEnteringCruise) {
  conn_->transportSettings.ccaConfig.enablePrecautionaryBandwidthProbing = true;
  auto controller = makeController();
  Bbr2ModularTestPeer::configureProbeBwUp(
      *controller, kInflightLongTerm, true, false);
  processAck(
      *controller,
      kInflightLongTerm - kPacketSize,
      kInflightLongTerm - kPacketSize);
  ASSERT_EQ(Bbr2State::ProbeBw_Down, Bbr2ModularTestPeer::state(*controller));

  processAck(*controller, 0, kInflightLongTerm - kPacketSize, false);
  ASSERT_EQ(Bbr2State::ProbeBw_Cruise, Bbr2ModularTestPeer::state(*controller));

  processAck(*controller, 0, kInflightLongTerm - kPacketSize);

  EXPECT_EQ(Bbr2State::ProbeBw_Refill, Bbr2ModularTestPeer::state(*controller));
  EXPECT_FALSE(Bbr2ModularTestPeer::previousProbePrecautionary(*controller));
}

TEST_F(Bbr2ModularProbeBwTest, ElapsedTimerStillEndsPrecautionaryDown) {
  conn_->transportSettings.ccaConfig.enablePrecautionaryBandwidthProbing = true;
  auto controller = makeController();
  Bbr2ModularTestPeer::configureProbeBwUp(
      *controller, kInflightLongTerm, true, false);
  processAck(*controller, kInflightLongTerm, kInflightLongTerm - kPacketSize);
  ASSERT_EQ(Bbr2State::ProbeBw_Down, Bbr2ModularTestPeer::state(*controller));
  Bbr2ModularTestPeer::expireProbeWait(*controller);
  Bbr2ModularTestPeer::preventRoundStart(*controller);

  processAck(
      *controller, kInflightLongTerm, kInflightLongTerm - kPacketSize, false);

  EXPECT_EQ(Bbr2State::ProbeBw_Refill, Bbr2ModularTestPeer::state(*controller));
  EXPECT_FALSE(Bbr2ModularTestPeer::previousProbePrecautionary(*controller));
}

TEST_F(Bbr2ModularProbeBwTest, OrdinaryFullBandwidthExitStillWorks) {
  conn_->transportSettings.ccaConfig.enablePrecautionaryBandwidthProbing = true;
  auto controller = makeController();
  Bbr2ModularTestPeer::configureProbeBwUp(
      *controller, kInflightLongTerm, false, false);
  Bbr2ModularTestPeer::setFullBwNow(*controller);

  processAck(*controller, 0, kPacketSize);

  EXPECT_EQ(Bbr2State::ProbeBw_Down, Bbr2ModularTestPeer::state(*controller));
  EXPECT_FALSE(Bbr2ModularTestPeer::previousProbeTooHigh(*controller));
  EXPECT_FALSE(Bbr2ModularTestPeer::previousProbePrecautionary(*controller));
}

TEST_F(Bbr2ModularProbeBwTest, ProbeRttReturnClearsPrecautionaryOutcome) {
  conn_->transportSettings.ccaConfig.enablePrecautionaryBandwidthProbing = true;
  auto controller = makeController();
  Bbr2ModularTestPeer::configureProbeRttReturn(*controller, false, true);

  processAck(*controller, 0, 0);

  EXPECT_EQ(Bbr2State::ProbeBw_Cruise, Bbr2ModularTestPeer::state(*controller));
  EXPECT_FALSE(Bbr2ModularTestPeer::previousProbePrecautionary(*controller));

  processAck(*controller, 0, 0);
  EXPECT_EQ(Bbr2State::ProbeBw_Cruise, Bbr2ModularTestPeer::state(*controller));
}

TEST_F(Bbr2ModularProbeBwTest, ProbeRttReturnPreservesTooHighOutcome) {
  conn_->transportSettings.ccaConfig.enablePrecautionaryBandwidthProbing = true;
  auto controller = makeController();
  Bbr2ModularTestPeer::configureProbeRttReturn(*controller, true, false);

  processAck(*controller, 0, 0);

  EXPECT_EQ(Bbr2State::ProbeBw_Cruise, Bbr2ModularTestPeer::state(*controller));
  EXPECT_TRUE(Bbr2ModularTestPeer::previousProbeTooHigh(*controller));
  EXPECT_FALSE(Bbr2ModularTestPeer::previousProbePrecautionary(*controller));
}

} // namespace test
} // namespace quic
