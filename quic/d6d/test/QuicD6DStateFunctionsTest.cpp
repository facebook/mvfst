/*
 * Copyright (c) Facebook, Inc. and its affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 *
 */

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <quic/common/test/TestUtils.h>
#include <quic/d6d/QuicD6DStateFunctions.h>
#include <quic/d6d/test/Mocks.h>
#include <quic/state/StateData.h>

using namespace testing;

namespace quic {
namespace test {

namespace {
using D6DMachineState = QuicConnectionStateBase::D6DMachineState;
} // namespace

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
    conn.pendingEvents.d6d.sendProbePacket = fixture.sendProbeBegin;
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
  }
};

TEST_F(QuicD6DStateFunctionsTest, D6DProbeTimeoutExpiredOneInBase) {
  QuicConnectionStateBase conn(QuicNodeType::Server);
  // One probe lost in BASE state
  D6DProbeLostTestFixture oneProbeLostInBase = {
      D6DMachineState::BASE, // stateBegin
      D6DMachineState::BASE, // stateEnd
      false, // sendProbeBegin
      kDefaultD6DProbeDelayWhenLost, // sendProbeEnd
      1, // outstandingProbes
      conn.d6d.basePMTU, // currentProbeSizeBegin
      conn.d6d.basePMTU // currentProbeSizeEnd
  };
  runD6DProbeLostTest(conn, oneProbeLostInBase);
}

TEST_F(QuicD6DStateFunctionsTest, D6DProbeTimeoutExpiredMaxInBase) {
  QuicConnectionStateBase conn(QuicNodeType::Server);
  // max number of probes lost in BASE state
  D6DProbeLostTestFixture maxNumProbesLostInBase = {
      D6DMachineState::BASE,
      D6DMachineState::ERROR,
      false,
      kDefaultD6DProbeDelayWhenLost,
      kDefaultD6DMaxOutstandingProbes,
      conn.d6d.basePMTU,
      kMinMaxUDPPayload};
  runD6DProbeLostTest(conn, maxNumProbesLostInBase);
}

TEST_F(QuicD6DStateFunctionsTest, D6DProbeTimeoutExpiredOneInSearching) {
  QuicConnectionStateBase conn(QuicNodeType::Server);
  // One probe lots in SEARCHING state
  D6DProbeLostTestFixture oneProbeLostInSearching = {
      D6DMachineState::SEARCHING,
      D6DMachineState::SEARCHING,
      false,
      kDefaultD6DProbeDelayWhenLost,
      1,
      static_cast<uint32_t>(conn.d6d.basePMTU + 10),
      static_cast<uint32_t>(conn.d6d.basePMTU + 10)};
  runD6DProbeLostTest(conn, oneProbeLostInSearching);
}

TEST_F(QuicD6DStateFunctionsTest, D6DProbeTimeoutExpiredMaxInSearching) {
  QuicConnectionStateBase conn(QuicNodeType::Server);
  // Max number of probes lost in SEARCHING state
  D6DProbeLostTestFixture maxProbesLostInSearching = {
      D6DMachineState::SEARCHING,
      D6DMachineState::SEARCH_COMPLETE,
      false,
      folly::none,
      kDefaultD6DMaxOutstandingProbes,
      static_cast<uint32_t>(conn.d6d.basePMTU + 10),
      static_cast<uint32_t>(conn.d6d.basePMTU + 10)};
  runD6DProbeLostTest(conn, maxProbesLostInSearching);
}

TEST_F(QuicD6DStateFunctionsTest, D6DProbeTimeoutExpiredOneInError) {
  QuicConnectionStateBase conn(QuicNodeType::Server);
  // Probe lost in ERROR state
  D6DProbeLostTestFixture probeLostInError = {
      D6DMachineState::ERROR,
      D6DMachineState::ERROR,
      false,
      kDefaultD6DProbeDelayWhenLost,
      kDefaultD6DMaxOutstandingProbes + 1,
      kMinMaxUDPPayload,
      kMinMaxUDPPayload};
  runD6DProbeLostTest(conn, probeLostInError);
}

TEST_F(QuicD6DStateFunctionsTest, D6DProbeAckedInBase) {
  QuicConnectionStateBase conn(QuicNodeType::Server);
  const uint16_t expectPMTU = 1400;
  auto& d6d = conn.d6d;
  d6d.state = D6DMachineState::BASE;
  d6d.outstandingProbes = 1;
  d6d.currentProbeSize = d6d.basePMTU;
  auto pkt = OutstandingPacket(
      makeTestShortPacket(),
      Clock::now(),
      d6d.currentProbeSize,
      false,
      true,
      d6d.currentProbeSize);
  d6d.lastProbe = QuicConnectionStateBase::D6DProbePacket(
      pkt.packet.header.getPacketSequenceNum(), pkt.metadata.encodedSize);
  d6d.raiser = std::make_unique<MockProbeSizeRaiser>();
  auto mockRaiser = dynamic_cast<MockProbeSizeRaiser*>(d6d.raiser.get());
  EXPECT_CALL(*mockRaiser, raiseProbeSize(d6d.currentProbeSize))
      .Times(1)
      .WillOnce(Return(expectPMTU));
  onD6DLastProbeAcked(conn);
  EXPECT_EQ(d6d.state, D6DMachineState::SEARCHING);
  EXPECT_EQ(d6d.currentProbeSize, expectPMTU);
  EXPECT_EQ(conn.udpSendPacketLen, d6d.basePMTU);
}

TEST_F(QuicD6DStateFunctionsTest, D6DProbeAckedInSearchingOne) {
  QuicConnectionStateBase conn(QuicNodeType::Server);
  const uint16_t expectPMTU = 1400;
  auto& d6d = conn.d6d;
  d6d.state = D6DMachineState::SEARCHING;
  d6d.outstandingProbes = 1;
  conn.udpSendPacketLen = 1250;
  d6d.currentProbeSize = 1300;
  auto pkt = OutstandingPacket(
      makeTestShortPacket(),
      Clock::now(),
      d6d.currentProbeSize,
      false,
      true,
      d6d.currentProbeSize);
  d6d.lastProbe = QuicConnectionStateBase::D6DProbePacket(
      pkt.packet.header.getPacketSequenceNum(), pkt.metadata.encodedSize);
  d6d.raiser = std::make_unique<MockProbeSizeRaiser>();
  auto mockRaiser = dynamic_cast<MockProbeSizeRaiser*>(d6d.raiser.get());
  EXPECT_CALL(*mockRaiser, raiseProbeSize(d6d.currentProbeSize))
      .Times(1)
      .WillOnce(Return(expectPMTU));
  onD6DLastProbeAcked(conn);
  EXPECT_EQ(d6d.state, D6DMachineState::SEARCHING);
  EXPECT_EQ(d6d.currentProbeSize, expectPMTU);
  EXPECT_EQ(conn.udpSendPacketLen, 1300);
}

TEST_F(QuicD6DStateFunctionsTest, D6DProbeAckedInSearchingMax) {
  QuicConnectionStateBase conn(QuicNodeType::Server);
  const uint16_t oversize = 1500;
  auto& d6d = conn.d6d;
  d6d.state = D6DMachineState::SEARCHING;
  d6d.outstandingProbes = 3;
  conn.udpSendPacketLen = 1400;
  d6d.currentProbeSize = 1450;
  auto pkt = OutstandingPacket(
      makeTestShortPacket(),
      Clock::now(),
      d6d.currentProbeSize,
      false,
      true,
      d6d.currentProbeSize);
  d6d.lastProbe = QuicConnectionStateBase::D6DProbePacket(
      pkt.packet.header.getPacketSequenceNum(), pkt.metadata.encodedSize);
  d6d.raiser = std::make_unique<MockProbeSizeRaiser>();
  auto mockRaiser = dynamic_cast<MockProbeSizeRaiser*>(d6d.raiser.get());
  EXPECT_CALL(*mockRaiser, raiseProbeSize(d6d.currentProbeSize))
      .Times(1)
      .WillOnce(Return(oversize));
  onD6DLastProbeAcked(conn);
  EXPECT_EQ(d6d.state, D6DMachineState::SEARCH_COMPLETE);
  EXPECT_EQ(d6d.currentProbeSize, 1450);
  EXPECT_EQ(conn.udpSendPacketLen, 1450);
}

TEST_F(QuicD6DStateFunctionsTest, D6DProbeAckedInError) {
  QuicConnectionStateBase conn(QuicNodeType::Server);
  auto& d6d = conn.d6d;
  d6d.state = D6DMachineState::ERROR;
  d6d.outstandingProbes = 3;
  conn.udpSendPacketLen = d6d.basePMTU;
  d6d.currentProbeSize = d6d.basePMTU - 20;
  auto pkt = OutstandingPacket(
      makeTestShortPacket(),
      Clock::now(),
      d6d.currentProbeSize,
      false,
      true,
      d6d.currentProbeSize);
  d6d.lastProbe = QuicConnectionStateBase::D6DProbePacket(
      pkt.packet.header.getPacketSequenceNum(), pkt.metadata.encodedSize);
  d6d.raiser = std::make_unique<MockProbeSizeRaiser>();
  auto mockRaiser = dynamic_cast<MockProbeSizeRaiser*>(d6d.raiser.get());
  EXPECT_CALL(*mockRaiser, raiseProbeSize(d6d.currentProbeSize))
      .Times(1)
      .WillOnce(Return(1300)); // Won't be used
  onD6DLastProbeAcked(conn);
  EXPECT_EQ(d6d.state, D6DMachineState::BASE);
  EXPECT_EQ(d6d.currentProbeSize, d6d.basePMTU);
  EXPECT_EQ(conn.udpSendPacketLen, d6d.basePMTU);
}

} // namespace test
} // namespace quic
