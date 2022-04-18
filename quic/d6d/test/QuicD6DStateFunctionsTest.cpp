/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <quic/api/test/MockQuicSocket.h>
#include <quic/api/test/Mocks.h>
#include <quic/common/test/TestUtils.h>
#include <quic/d6d/QuicD6DStateFunctions.h>
#include <quic/d6d/test/Mocks.h>
#include <quic/state/StateData.h>

using namespace testing;

namespace quic {
namespace test {

// timeLastNonSearchState can only increase
enum class TimeLastNonSearchStateEnd : uint8_t { EQ, GE };

struct D6DProbeLostTestFixture {
  D6DMachineState stateBegin;
  D6DMachineState stateEnd;
  bool sendProbeBegin;
  folly::Optional<std::chrono::milliseconds> sendProbeDelayEnd;
  // probe loss doesn't change outstanding probes, so a begin value
  // is enough
  uint64_t outstandingProbes;
  uint32_t currentProbeSizeBegin;
  uint32_t currentProbeSizeEnd;
  D6DProbePacket lastProbe;
  D6DMachineState lastNonSearchStateBegin;
  D6DMachineState lastNonSearchStateEnd;
  TimePoint timeLastNonSearchStateBegin;
  TimeLastNonSearchStateEnd timeLastNonSearchStateEndE;
};

RegularQuicWritePacket makeTestShortPacket() {
  ShortHeader header(
      ProtectionType::KeyPhaseZero, getTestConnectionId(), 2 /* packetNum */);
  RegularQuicWritePacket packet(std::move(header));
  return packet;
}

class QuicD6DStateFunctionsTest : public Test {
 public:
  void runD6DProbeLostTest(
      QuicConnectionStateBase& conn,
      D6DProbeLostTestFixture fixture) {
    conn.d6d.state = fixture.stateBegin;
    conn.d6d.outstandingProbes = fixture.outstandingProbes;
    conn.d6d.currentProbeSize = fixture.currentProbeSizeBegin;
    conn.d6d.lastProbe = fixture.lastProbe;
    conn.pendingEvents.d6d.sendProbePacket = fixture.sendProbeBegin;
    conn.d6d.meta.lastNonSearchState = fixture.lastNonSearchStateBegin;
    conn.d6d.meta.timeLastNonSearchState = fixture.timeLastNonSearchStateBegin;
    onD6DLastProbeLost(conn);
    EXPECT_EQ(conn.d6d.state, fixture.stateEnd);
    EXPECT_EQ(conn.d6d.currentProbeSize, fixture.currentProbeSizeEnd);
    if (fixture.sendProbeDelayEnd.hasValue()) {
      ASSERT_TRUE(conn.pendingEvents.d6d.sendProbeDelay.hasValue());
      EXPECT_EQ(
          *conn.pendingEvents.d6d.sendProbeDelay, *fixture.sendProbeDelayEnd);
    } else {
      ASSERT_FALSE(conn.pendingEvents.d6d.sendProbeDelay.hasValue());
    }
    EXPECT_EQ(conn.d6d.meta.lastNonSearchState, fixture.lastNonSearchStateEnd);
    switch (fixture.timeLastNonSearchStateEndE) {
      case TimeLastNonSearchStateEnd::EQ:
        EXPECT_EQ(
            conn.d6d.meta.timeLastNonSearchState,
            fixture.timeLastNonSearchStateBegin);
        break;
      default:
        EXPECT_GE(
            conn.d6d.meta.timeLastNonSearchState,
            fixture.timeLastNonSearchStateBegin);
    }
  }
};

TEST_F(QuicD6DStateFunctionsTest, D6DProbeTimeoutExpiredOneInBase) {
  QuicConnectionStateBase conn(QuicNodeType::Server);
  auto now = Clock::now();
  // One probe lost in BASE state
  D6DProbeLostTestFixture oneProbeLostInBase = {
      D6DMachineState::BASE, // stateBegin
      D6DMachineState::BASE, // stateEnd
      false, // sendProbeBegin
      kDefaultD6DProbeDelayWhenLost, // sendProbeEnd
      1, // outstandingProbes
      conn.d6d.basePMTU, // currentProbeSizeBegin
      conn.d6d.basePMTU, // currentProbeSizeEnd
      D6DProbePacket(0, conn.d6d.basePMTU + 10),
      D6DMachineState::DISABLED, // lastNonSearchStateBegin
      D6DMachineState::DISABLED, // lastNonSearchStateEnd
      now, // timeLastNonSearchStateBegin
      TimeLastNonSearchStateEnd::EQ // timeLastNonSearchStateEndE
  };
  runD6DProbeLostTest(conn, oneProbeLostInBase);
}

TEST_F(QuicD6DStateFunctionsTest, D6DProbeTimeoutExpiredMaxInBase) {
  QuicConnectionStateBase conn(QuicNodeType::Server);
  auto now = Clock::now();
  // max number of probes lost in BASE state
  D6DProbeLostTestFixture maxNumProbesLostInBase = {
      D6DMachineState::BASE,
      D6DMachineState::ERROR,
      false,
      kDefaultD6DProbeDelayWhenLost,
      kDefaultD6DMaxOutstandingProbes,
      conn.d6d.basePMTU,
      kMinMaxUDPPayload,
      D6DProbePacket(0, conn.d6d.basePMTU + 10),
      D6DMachineState::DISABLED,
      D6DMachineState::BASE,
      now,
      TimeLastNonSearchStateEnd::GE};
  runD6DProbeLostTest(conn, maxNumProbesLostInBase);
}

TEST_F(QuicD6DStateFunctionsTest, D6DProbeTimeoutExpiredOneInSearching) {
  QuicConnectionStateBase conn(QuicNodeType::Server);
  auto now = Clock::now();
  // One probe lots in SEARCHING state
  D6DProbeLostTestFixture oneProbeLostInSearching = {
      D6DMachineState::SEARCHING,
      D6DMachineState::SEARCHING,
      false,
      kDefaultD6DProbeDelayWhenLost,
      1,
      static_cast<uint32_t>(conn.d6d.basePMTU + 10),
      static_cast<uint32_t>(conn.d6d.basePMTU + 10),
      D6DProbePacket(0, conn.d6d.basePMTU + 10),
      D6DMachineState::BASE,
      D6DMachineState::BASE,
      now,
      TimeLastNonSearchStateEnd::EQ};
  runD6DProbeLostTest(conn, oneProbeLostInSearching);
}

TEST_F(QuicD6DStateFunctionsTest, D6DProbeTimeoutExpiredMaxInSearching) {
  QuicConnectionStateBase conn(QuicNodeType::Server);
  auto now = Clock::now();
  // Max number of probes lost in SEARCHING state
  D6DProbeLostTestFixture maxProbesLostInSearching = {
      D6DMachineState::SEARCHING,
      D6DMachineState::SEARCH_COMPLETE,
      false,
      folly::none,
      kDefaultD6DMaxOutstandingProbes,
      static_cast<uint32_t>(conn.d6d.basePMTU + 10),
      static_cast<uint32_t>(conn.d6d.basePMTU + 10),
      D6DProbePacket(0, conn.d6d.basePMTU + 10),
      D6DMachineState::BASE,
      D6DMachineState::BASE,
      now,
      TimeLastNonSearchStateEnd::EQ};
  runD6DProbeLostTest(conn, maxProbesLostInSearching);
}

TEST_F(QuicD6DStateFunctionsTest, D6DProbeTimeoutExpiredOneInError) {
  QuicConnectionStateBase conn(QuicNodeType::Server);
  auto now = Clock::now();
  // Probe lost in ERROR state
  D6DProbeLostTestFixture probeLostInError = {
      D6DMachineState::ERROR,
      D6DMachineState::ERROR,
      false,
      kDefaultD6DProbeDelayWhenLost,
      kDefaultD6DMaxOutstandingProbes + 1,
      kMinMaxUDPPayload,
      kMinMaxUDPPayload,
      D6DProbePacket(0, conn.d6d.basePMTU + 10),
      D6DMachineState::BASE,
      D6DMachineState::BASE,
      now,
      TimeLastNonSearchStateEnd::EQ};
  runD6DProbeLostTest(conn, probeLostInError);
}

TEST_F(QuicD6DStateFunctionsTest, D6DProbeAckedInBase) {
  auto socket = std::make_shared<MockQuicSocket>();
  const auto observerContainer =
      std::make_shared<SocketObserverContainer>(socket.get());

  QuicConnectionStateBase conn(QuicNodeType::Server);
  conn.observerContainer = observerContainer;

  LegacyObserver::EventSet eventSet;
  eventSet.enable(SocketObserverInterface::Events::pmtuEvents);
  auto obs1 = std::make_unique<NiceMock<MockLegacyObserver>>(eventSet);
  observerContainer->addObserver(obs1.get());

  const uint16_t expectPMTU = 1400;
  auto& d6d = conn.d6d;
  const auto now = Clock::now();
  d6d.state = D6DMachineState::BASE;
  d6d.outstandingProbes = 1;
  d6d.currentProbeSize = d6d.basePMTU;
  d6d.meta.lastNonSearchState = D6DMachineState::DISABLED;
  d6d.meta.timeLastNonSearchState = now;
  auto pkt = OutstandingPacket(
      makeTestShortPacket(),
      Clock::now(),
      d6d.currentProbeSize,
      0,
      false,
      true,
      d6d.currentProbeSize,
      d6d.currentProbeSize,
      0,
      LossState(),
      0,
      OutstandingPacketMetadata::DetailsPerStream());
  d6d.lastProbe = D6DProbePacket(
      pkt.packet.header.getPacketSequenceNum(), pkt.metadata.encodedSize);
  d6d.raiser = std::make_unique<MockProbeSizeRaiser>();
  auto mockRaiser = dynamic_cast<MockProbeSizeRaiser*>(d6d.raiser.get());
  EXPECT_CALL(*mockRaiser, raiseProbeSize(d6d.currentProbeSize))
      .Times(1)
      .WillOnce(Return(expectPMTU));
  EXPECT_CALL(*obs1, pmtuUpperBoundDetected(_, _)).Times(0);
  onD6DLastProbeAcked(conn);

  EXPECT_EQ(d6d.state, D6DMachineState::SEARCHING);
  EXPECT_EQ(d6d.currentProbeSize, expectPMTU);
  EXPECT_EQ(conn.udpSendPacketLen, d6d.basePMTU);
  EXPECT_EQ(d6d.meta.lastNonSearchState, D6DMachineState::BASE);
  EXPECT_GE(d6d.meta.timeLastNonSearchState, now);

  observerContainer->removeObserver(obs1.get());
}

TEST_F(QuicD6DStateFunctionsTest, D6DProbeAckedInSearchingOne) {
  auto socket = std::make_shared<MockQuicSocket>();
  const auto observerContainer =
      std::make_shared<SocketObserverContainer>(socket.get());

  QuicConnectionStateBase conn(QuicNodeType::Server);
  conn.observerContainer = observerContainer;

  LegacyObserver::EventSet eventSet;
  eventSet.enable(SocketObserverInterface::Events::pmtuEvents);
  auto obs1 = std::make_unique<NiceMock<MockLegacyObserver>>(eventSet);
  observerContainer->addObserver(obs1.get());

  const uint16_t expectPMTU = 1400;
  auto& d6d = conn.d6d;
  const auto now = Clock::now();
  d6d.state = D6DMachineState::SEARCHING;
  d6d.outstandingProbes = 1;
  conn.udpSendPacketLen = 1250;
  d6d.currentProbeSize = 1300;
  d6d.meta.lastNonSearchState = D6DMachineState::BASE;
  d6d.meta.timeLastNonSearchState = now;
  auto pkt = OutstandingPacket(
      makeTestShortPacket(),
      Clock::now(),
      d6d.currentProbeSize,
      0,
      false,
      true,
      d6d.currentProbeSize,
      d6d.currentProbeSize,
      0,
      LossState(),
      0,
      OutstandingPacketMetadata::DetailsPerStream());
  d6d.lastProbe = D6DProbePacket(
      pkt.packet.header.getPacketSequenceNum(), pkt.metadata.encodedSize);
  d6d.raiser = std::make_unique<MockProbeSizeRaiser>();
  auto mockRaiser = dynamic_cast<MockProbeSizeRaiser*>(d6d.raiser.get());
  EXPECT_CALL(*mockRaiser, raiseProbeSize(d6d.currentProbeSize))
      .Times(1)
      .WillOnce(Return(expectPMTU));
  EXPECT_CALL(*obs1, pmtuUpperBoundDetected(_, _)).Times(0);
  onD6DLastProbeAcked(conn);

  EXPECT_EQ(d6d.state, D6DMachineState::SEARCHING);
  EXPECT_EQ(d6d.currentProbeSize, expectPMTU);
  EXPECT_EQ(conn.udpSendPacketLen, 1300);
  EXPECT_EQ(d6d.meta.lastNonSearchState, D6DMachineState::BASE);
  EXPECT_EQ(d6d.meta.timeLastNonSearchState, now);

  observerContainer->removeObserver(obs1.get());
}

TEST_F(QuicD6DStateFunctionsTest, D6DProbeAckedInSearchingMax) {
  auto socket = std::make_shared<MockQuicSocket>();
  const auto observerContainer =
      std::make_shared<SocketObserverContainer>(socket.get());

  QuicConnectionStateBase conn(QuicNodeType::Server);
  conn.observerContainer = observerContainer;

  LegacyObserver::EventSet eventSet;
  eventSet.enable(SocketObserverInterface::Events::pmtuEvents);
  auto obs1 = std::make_unique<NiceMock<MockLegacyObserver>>(eventSet);
  observerContainer->addObserver(obs1.get());

  const uint16_t oversize = 1500;
  auto& d6d = conn.d6d;
  const auto now = Clock::now();
  d6d.state = D6DMachineState::SEARCHING;
  d6d.outstandingProbes = 3;
  conn.udpSendPacketLen = 1400;
  d6d.currentProbeSize = 1450;
  d6d.meta.lastNonSearchState = D6DMachineState::BASE;
  d6d.meta.timeLastNonSearchState = now;
  d6d.meta.totalTxedProbes = 10;
  auto pkt = OutstandingPacket(
      makeTestShortPacket(),
      Clock::now(),
      d6d.currentProbeSize,
      0,
      false,
      true,
      d6d.currentProbeSize,
      d6d.currentProbeSize,
      0,
      LossState(),
      0,
      OutstandingPacketMetadata::DetailsPerStream());
  d6d.lastProbe = D6DProbePacket(
      pkt.packet.header.getPacketSequenceNum(), pkt.metadata.encodedSize);
  d6d.raiser = std::make_unique<MockProbeSizeRaiser>();
  auto mockRaiser = dynamic_cast<MockProbeSizeRaiser*>(d6d.raiser.get());
  EXPECT_CALL(*mockRaiser, raiseProbeSize(d6d.currentProbeSize))
      .Times(1)
      .WillOnce(Return(oversize));
  EXPECT_CALL(*obs1, pmtuUpperBoundDetected(_, _))
      .Times(1)
      .WillOnce(Invoke(
          [&](QuicSocket* /* qSocket */,
              const SocketObserverInterface::PMTUUpperBoundEvent& event) {
            EXPECT_LT(now, event.upperBoundTime);
            EXPECT_LT(0us, event.timeSinceLastNonSearchState);
            EXPECT_EQ(D6DMachineState::BASE, event.lastNonSearchState);
            EXPECT_EQ(1450, event.upperBoundPMTU);
            EXPECT_EQ(10, event.cumulativeProbesSent);
            EXPECT_EQ(
                ProbeSizeRaiserType::ConstantStep, event.probeSizeRaiserType);
          }));
  onD6DLastProbeAcked(conn);

  EXPECT_EQ(d6d.state, D6DMachineState::SEARCH_COMPLETE);
  EXPECT_EQ(d6d.currentProbeSize, 1450);
  EXPECT_EQ(conn.udpSendPacketLen, 1450);
  EXPECT_EQ(d6d.meta.lastNonSearchState, D6DMachineState::BASE);
  EXPECT_EQ(d6d.meta.timeLastNonSearchState, now);

  observerContainer->removeObserver(obs1.get());
}

TEST_F(QuicD6DStateFunctionsTest, D6DProbeAckedInError) {
  auto socket = std::make_shared<MockQuicSocket>();
  const auto observerContainer =
      std::make_shared<SocketObserverContainer>(socket.get());

  QuicConnectionStateBase conn(QuicNodeType::Server);
  conn.observerContainer = observerContainer;

  LegacyObserver::EventSet eventSet;
  eventSet.enable(SocketObserverInterface::Events::pmtuEvents);
  auto obs1 = std::make_unique<NiceMock<MockLegacyObserver>>(eventSet);
  observerContainer->addObserver(obs1.get());

  auto& d6d = conn.d6d;
  const auto now = Clock::now();
  d6d.state = D6DMachineState::ERROR;
  d6d.outstandingProbes = 3;
  conn.udpSendPacketLen = d6d.basePMTU;
  d6d.currentProbeSize = d6d.basePMTU - 20;
  d6d.meta.lastNonSearchState = D6DMachineState::BASE;
  d6d.meta.timeLastNonSearchState = now;
  auto pkt = OutstandingPacket(
      makeTestShortPacket(),
      Clock::now(),
      d6d.currentProbeSize,
      0,
      false,
      true,
      d6d.currentProbeSize,
      d6d.currentProbeSize,
      0,
      LossState(),
      0,
      OutstandingPacketMetadata::DetailsPerStream());
  d6d.lastProbe = D6DProbePacket(
      pkt.packet.header.getPacketSequenceNum(), pkt.metadata.encodedSize);
  d6d.raiser = std::make_unique<MockProbeSizeRaiser>();
  auto mockRaiser = dynamic_cast<MockProbeSizeRaiser*>(d6d.raiser.get());
  EXPECT_CALL(*mockRaiser, raiseProbeSize(d6d.currentProbeSize))
      .Times(1)
      .WillOnce(Return(1300)); // Won't be used
  EXPECT_CALL(*obs1, pmtuUpperBoundDetected(_, _)).Times(0);
  onD6DLastProbeAcked(conn);

  EXPECT_EQ(d6d.state, D6DMachineState::BASE);
  EXPECT_EQ(d6d.currentProbeSize, d6d.basePMTU);
  EXPECT_EQ(conn.udpSendPacketLen, d6d.basePMTU);
  EXPECT_EQ(d6d.meta.lastNonSearchState, D6DMachineState::ERROR);
  EXPECT_GE(d6d.meta.timeLastNonSearchState, now);

  observerContainer->removeObserver(obs1.get());
}

TEST_F(QuicD6DStateFunctionsTest, BlackholeInSearching) {
  auto socket = std::make_shared<MockQuicSocket>();
  const auto observerContainer =
      std::make_shared<SocketObserverContainer>(socket.get());

  QuicConnectionStateBase conn(QuicNodeType::Server);
  conn.observerContainer = observerContainer;

  LegacyObserver::EventSet eventSet;
  eventSet.enable(SocketObserverInterface::Events::pmtuEvents);
  auto obs1 = std::make_unique<NiceMock<MockLegacyObserver>>(eventSet);
  observerContainer->addObserver(obs1.get());

  auto& d6d = conn.d6d;
  const auto now = Clock::now();
  d6d.state = D6DMachineState::SEARCHING;
  d6d.outstandingProbes = 2;
  conn.udpSendPacketLen = d6d.basePMTU + 20;
  d6d.currentProbeSize = d6d.basePMTU + 30;
  d6d.meta.lastNonSearchState = D6DMachineState::BASE;
  d6d.meta.timeLastNonSearchState = now;
  auto pkt = OutstandingPacket(
      makeTestShortPacket(),
      now + 10s,
      d6d.currentProbeSize,
      0,
      false,
      true,
      d6d.currentProbeSize,
      d6d.currentProbeSize,
      0,
      LossState(),
      0,
      OutstandingPacketMetadata::DetailsPerStream());
  d6d.lastProbe = D6DProbePacket(
      pkt.packet.header.getPacketSequenceNum(), pkt.metadata.encodedSize);

  auto lostPacket = OutstandingPacket(
      makeTestShortPacket(),
      now + 8s,
      conn.udpSendPacketLen,
      0,
      false,
      conn.udpSendPacketLen + d6d.currentProbeSize,
      0,
      conn.udpSendPacketLen + d6d.currentProbeSize,
      0,
      LossState(),
      0,
      OutstandingPacketMetadata::DetailsPerStream());

  d6d.thresholdCounter = std::make_unique<WindowedCounter<uint64_t, uint64_t>>(
      std::chrono::microseconds(kDefaultD6DBlackholeDetectionWindow).count(),
      1); // Threshold of 1 will cause window to be set to 0

  EXPECT_CALL(*obs1, pmtuBlackholeDetected(_, _))
      .Times(1)
      .WillOnce(
          Invoke([&](QuicSocket* /* qSocket */,
                     const SocketObserverInterface::PMTUBlackholeEvent& event) {
            EXPECT_LE(d6d.meta.timeLastNonSearchState, event.blackholeTime);
            EXPECT_EQ(D6DMachineState::BASE, event.lastNonSearchState);
            EXPECT_EQ(D6DMachineState::SEARCHING, event.currentState);
            EXPECT_EQ(d6d.basePMTU + 20, event.udpSendPacketLen);
            EXPECT_EQ(d6d.basePMTU + 30, event.lastProbeSize);
            EXPECT_EQ(0, event.blackholeDetectionWindow);
            EXPECT_EQ(1, event.blackholeDetectionThreshold);
            EXPECT_EQ(
                d6d.basePMTU + 20, event.triggeringPacketMetadata.encodedSize);
          }));
  detectPMTUBlackhole(conn, lostPacket);

  EXPECT_EQ(d6d.state, D6DMachineState::BASE);
  EXPECT_EQ(d6d.currentProbeSize, d6d.basePMTU);
  EXPECT_EQ(conn.udpSendPacketLen, d6d.basePMTU);
  EXPECT_EQ(d6d.meta.lastNonSearchState, D6DMachineState::BASE);
  EXPECT_GE(d6d.meta.timeLastNonSearchState, now);

  observerContainer->removeObserver(obs1.get());
}

TEST_F(QuicD6DStateFunctionsTest, BlackholeInSearchComplete) {
  auto socket = std::make_shared<MockQuicSocket>();
  const auto observerContainer =
      std::make_shared<SocketObserverContainer>(socket.get());

  QuicConnectionStateBase conn(QuicNodeType::Server);
  conn.observerContainer = observerContainer;

  LegacyObserver::EventSet eventSet;
  eventSet.enable(SocketObserverInterface::Events::pmtuEvents);
  auto obs1 = std::make_unique<NiceMock<MockLegacyObserver>>(eventSet);
  observerContainer->addObserver(obs1.get());

  auto& d6d = conn.d6d;
  auto now = Clock::now();
  d6d.state = D6DMachineState::SEARCH_COMPLETE;
  conn.udpSendPacketLen = d6d.basePMTU + 20;
  d6d.currentProbeSize = d6d.basePMTU + 20;
  d6d.meta.lastNonSearchState = D6DMachineState::BASE;
  d6d.meta.timeLastNonSearchState = now;
  auto pkt = OutstandingPacket(
      makeTestShortPacket(),
      now + 10s,
      d6d.currentProbeSize,
      0,
      false,
      true,
      d6d.currentProbeSize,
      d6d.currentProbeSize,
      0,
      LossState(),
      0,
      OutstandingPacketMetadata::DetailsPerStream());

  d6d.lastProbe = D6DProbePacket(
      pkt.packet.header.getPacketSequenceNum(), pkt.metadata.encodedSize);

  auto lostPacket = OutstandingPacket(
      makeTestShortPacket(),
      now + 12s,
      conn.udpSendPacketLen,
      0,
      false,
      conn.udpSendPacketLen + d6d.currentProbeSize,
      0,
      conn.udpSendPacketLen + d6d.currentProbeSize,
      0,
      LossState(),
      0,
      OutstandingPacketMetadata::DetailsPerStream());

  d6d.thresholdCounter = std::make_unique<WindowedCounter<uint64_t, uint64_t>>(
      std::chrono::microseconds(kDefaultD6DBlackholeDetectionWindow).count(),
      1); // Threshold of 1 will cause window to be set to 0

  EXPECT_CALL(*obs1, pmtuBlackholeDetected(_, _))
      .Times(1)
      .WillOnce(
          Invoke([&](QuicSocket* /* qSocket */,
                     const SocketObserverInterface::PMTUBlackholeEvent& event) {
            EXPECT_LE(d6d.meta.timeLastNonSearchState, event.blackholeTime);
            EXPECT_EQ(D6DMachineState::BASE, event.lastNonSearchState);
            EXPECT_EQ(D6DMachineState::SEARCH_COMPLETE, event.currentState);
            EXPECT_EQ(d6d.basePMTU + 20, event.udpSendPacketLen);
            EXPECT_EQ(d6d.basePMTU + 20, event.lastProbeSize);
            EXPECT_EQ(0, event.blackholeDetectionWindow);
            EXPECT_EQ(1, event.blackholeDetectionThreshold);
            EXPECT_EQ(
                d6d.basePMTU + 20, event.triggeringPacketMetadata.encodedSize);
          }));
  detectPMTUBlackhole(conn, lostPacket);

  EXPECT_EQ(d6d.state, D6DMachineState::BASE);
  EXPECT_EQ(d6d.currentProbeSize, d6d.basePMTU);
  EXPECT_EQ(conn.udpSendPacketLen, d6d.basePMTU);
  EXPECT_EQ(d6d.meta.lastNonSearchState, D6DMachineState::SEARCH_COMPLETE);
  EXPECT_GE(d6d.meta.timeLastNonSearchState, now);

  observerContainer->removeObserver(obs1.get());
}

TEST_F(QuicD6DStateFunctionsTest, ReachMaxPMTU) {
  auto socket = std::make_shared<MockQuicSocket>();
  const auto observerContainer =
      std::make_shared<SocketObserverContainer>(socket.get());

  QuicConnectionStateBase conn(QuicNodeType::Server);
  conn.observerContainer = observerContainer;

  LegacyObserver::EventSet eventSet;
  eventSet.enable(SocketObserverInterface::Events::pmtuEvents);
  auto obs1 = std::make_unique<NiceMock<MockLegacyObserver>>(eventSet);
  observerContainer->addObserver(obs1.get());

  auto& d6d = conn.d6d;
  const auto now = Clock::now();
  d6d.state = D6DMachineState::SEARCHING;
  d6d.maxPMTU = 1452;
  d6d.outstandingProbes = 1;
  conn.udpSendPacketLen = 1400;
  d6d.currentProbeSize = 1442;
  d6d.meta.lastNonSearchState = D6DMachineState::BASE;
  d6d.meta.timeLastNonSearchState = now;
  d6d.meta.totalTxedProbes = 10;
  auto pkt = OutstandingPacket(
      makeTestShortPacket(),
      Clock::now(),
      d6d.currentProbeSize,
      0,
      false,
      true,
      d6d.currentProbeSize,
      d6d.currentProbeSize,
      0,
      LossState(),
      0,
      OutstandingPacketMetadata::DetailsPerStream());
  d6d.lastProbe = D6DProbePacket(
      pkt.packet.header.getPacketSequenceNum(), pkt.metadata.encodedSize);
  d6d.raiser = std::make_unique<MockProbeSizeRaiser>();
  auto mockRaiser = dynamic_cast<MockProbeSizeRaiser*>(d6d.raiser.get());
  EXPECT_CALL(*mockRaiser, raiseProbeSize(d6d.currentProbeSize))
      .Times(1)
      .WillOnce(Return(1452));
  onD6DLastProbeAcked(conn);
  EXPECT_EQ(d6d.state, D6DMachineState::SEARCHING);
  EXPECT_EQ(d6d.currentProbeSize, 1452);
  EXPECT_EQ(conn.udpSendPacketLen, 1442);
  EXPECT_EQ(d6d.meta.lastNonSearchState, D6DMachineState::BASE);
  EXPECT_EQ(d6d.meta.timeLastNonSearchState, now);

  observerContainer->removeObserver(obs1.get());
}

TEST_F(
    QuicD6DStateFunctionsTest,
    MaintainStateWhenFalsePositiveBlackholeDetected) {
  QuicConnectionStateBase conn(QuicNodeType::Server);
  auto& d6d = conn.d6d;
  auto now = Clock::now();
  d6d.state = D6DMachineState::SEARCHING;
  d6d.maxPMTU = 1452;
  d6d.outstandingProbes = 1;
  conn.udpSendPacketLen = 1400;
  d6d.currentProbeSize = 1442;
  d6d.meta.lastNonSearchState = D6DMachineState::BASE;
  d6d.meta.timeLastNonSearchState = now;
  d6d.meta.totalTxedProbes = 10;
  auto pkt = OutstandingPacket(
      makeTestShortPacket(),
      Clock::now(),
      d6d.currentProbeSize,
      0,
      false,
      true,
      d6d.currentProbeSize,
      d6d.currentProbeSize,
      0,
      LossState(),
      0,
      OutstandingPacketMetadata::DetailsPerStream());
  d6d.lastProbe = D6DProbePacket(
      pkt.packet.header.getPacketSequenceNum(), pkt.metadata.encodedSize);
  d6d.raiser = std::make_unique<MockProbeSizeRaiser>();
  auto mockRaiser = dynamic_cast<MockProbeSizeRaiser*>(d6d.raiser.get());
  EXPECT_CALL(*mockRaiser, raiseProbeSize(d6d.currentProbeSize))
      .Times(1)
      .WillOnce(Return(1452));
  d6d.thresholdCounter = std::make_unique<WindowedCounter<uint64_t, uint64_t>>(
      std::chrono::microseconds(kDefaultD6DBlackholeDetectionWindow).count(),
      1); // Threshold of 1 will cause window to be set to 0

  auto lostPacket = OutstandingPacket(
      makeTestShortPacket(),
      Clock::now(),
      d6d.currentProbeSize,
      0,
      false,
      false,
      d6d.currentProbeSize,
      d6d.currentProbeSize,
      0,
      LossState(),
      0,
      OutstandingPacketMetadata::DetailsPerStream());
  // Generate a false positive blackhole signal
  detectPMTUBlackhole(conn, lostPacket);
  EXPECT_EQ(d6d.state, D6DMachineState::BASE);
  EXPECT_EQ(conn.udpSendPacketLen, d6d.basePMTU);

  // The ack of a non-stale probe should bring us back to SEARCHING state and
  // correct probe size
  onD6DLastProbeAcked(conn);
  EXPECT_EQ(d6d.state, D6DMachineState::SEARCHING);
  EXPECT_EQ(d6d.currentProbeSize, 1452);
  EXPECT_EQ(conn.udpSendPacketLen, 1442);
  EXPECT_EQ(d6d.meta.lastNonSearchState, D6DMachineState::BASE);
  EXPECT_EQ(d6d.meta.timeLastNonSearchState, now);
}

TEST_F(QuicD6DStateFunctionsTest, UpperboundIsBase) {
  QuicConnectionStateBase conn(QuicNodeType::Server);
  auto& d6d = conn.d6d;
  auto now = Clock::now();
  d6d.state = D6DMachineState::BASE;
  d6d.basePMTU = 1400;
  d6d.maxPMTU = 1400;
  d6d.outstandingProbes = 1;
  conn.udpSendPacketLen = 1400;
  d6d.currentProbeSize = 1400;
  d6d.meta.lastNonSearchState = D6DMachineState::DISABLED;
  d6d.meta.timeLastNonSearchState = now;
  d6d.meta.totalTxedProbes = 10;
  auto pkt = OutstandingPacket(
      makeTestShortPacket(),
      Clock::now(),
      d6d.currentProbeSize,
      0,
      false,
      true,
      d6d.currentProbeSize,
      d6d.currentProbeSize,
      0,
      LossState(),
      0,
      OutstandingPacketMetadata::DetailsPerStream());
  d6d.lastProbe = D6DProbePacket(
      pkt.packet.header.getPacketSequenceNum(), pkt.metadata.encodedSize);
  d6d.raiser = std::make_unique<MockProbeSizeRaiser>();
  auto mockRaiser = dynamic_cast<MockProbeSizeRaiser*>(d6d.raiser.get());
  EXPECT_CALL(*mockRaiser, raiseProbeSize(d6d.currentProbeSize))
      .Times(1)
      .WillOnce(Return(1452));

  // The ack of a non-stale probe should bring us back to SEARCHING state and
  // correct probe size
  onD6DLastProbeAcked(conn);
  EXPECT_EQ(d6d.state, D6DMachineState::SEARCH_COMPLETE);
  EXPECT_EQ(d6d.currentProbeSize, 1400);
  EXPECT_EQ(conn.udpSendPacketLen, 1400);
  EXPECT_EQ(d6d.meta.lastNonSearchState, D6DMachineState::BASE);
  EXPECT_GT(d6d.meta.timeLastNonSearchState, now);
}

} // namespace test
} // namespace quic
