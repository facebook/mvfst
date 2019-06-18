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
#include <quic/server/state/ServerStateMachine.h>
#include <quic/state/QuicStateFunctions.h>
#include <quic/state/test/Mocks.h>

using namespace folly;
using namespace testing;

namespace quic {
namespace test {

bool verifyToAckImmediately(
    const QuicConnectionStateBase& conn,
    const AckState& ackState) {
  return !conn.pendingEvents.scheduleAckTimeout &&
      ackState.needsToSendAckImmediately && ackState.numRxPacketsRecvd == 0 &&
      ackState.numNonRxPacketsRecvd == 0;
}

bool verifyToScheduleAckTimeout(const QuicConnectionStateBase& conn) {
  return conn.pendingEvents.scheduleAckTimeout;
}

RegularQuicWritePacket makeTestShortPacket() {
  ShortHeader header(
      ProtectionType::KeyPhaseZero, getTestConnectionId(), 2 /* packetNum */);
  RegularQuicWritePacket packet(std::move(header));
  return packet;
}

RegularQuicWritePacket makeTestLongPacket(LongHeader::Types type) {
  LongHeader header(
      type,
      getTestConnectionId(0),
      getTestConnectionId(1),
      2 /* packetNum */,
      QuicVersion::QUIC_DRAFT);
  RegularQuicWritePacket packet(std::move(header));
  return packet;
}

class UpdateLargestReceivedPacketNumTest
    : public TestWithParam<PacketNumberSpace> {};

TEST_P(UpdateLargestReceivedPacketNumTest, ReceiveNew) {
  QuicServerConnectionState conn;
  getAckState(conn, GetParam()).largestReceivedPacketNum = 100;
  auto currentLargestReceived =
      *getAckState(conn, GetParam()).largestReceivedPacketNum;
  PacketNum newReceived = currentLargestReceived + 1;
  updateLargestReceivedPacketNum(
      getAckState(conn, GetParam()), newReceived, Clock::now());
  EXPECT_GT(
      *getAckState(conn, GetParam()).largestReceivedPacketNum,
      currentLargestReceived);
}

TEST_P(UpdateLargestReceivedPacketNumTest, ReceiveOld) {
  QuicServerConnectionState conn;
  getAckState(conn, GetParam()).largestReceivedPacketNum = 100;
  auto currentLargestReceived =
      *getAckState(conn, GetParam()).largestReceivedPacketNum;
  PacketNum newReceived = currentLargestReceived - 1;
  updateLargestReceivedPacketNum(
      getAckState(conn, GetParam()), newReceived, Clock::now());
  EXPECT_EQ(
      *getAckState(conn, GetParam()).largestReceivedPacketNum,
      currentLargestReceived);
}

INSTANTIATE_TEST_CASE_P(
    UpdateLargestReceivedPacketNumTests,
    UpdateLargestReceivedPacketNumTest,
    Values(
        PacketNumberSpace::Initial,
        PacketNumberSpace::Handshake,
        PacketNumberSpace::AppData));

class UpdateAckStateTest : public TestWithParam<PacketNumberSpace> {};

TEST_P(UpdateAckStateTest, TestUpdateAckState) {
  QuicServerConnectionState conn;
  PacketNum nextPacketNum = 0;
  auto& ackState = getAckState(conn, GetParam());
  updateAckState(conn, GetParam(), nextPacketNum++, true, false, Clock::now());
  EXPECT_EQ(ackState.acks.size(), 1);
  EXPECT_EQ(ackState.acks.front().start, 0);
  EXPECT_EQ(ackState.acks.front().end, 0);
  EXPECT_FALSE(ackState.needsToSendAckImmediately);
  EXPECT_EQ(ackState.numRxPacketsRecvd, 1);
  EXPECT_TRUE(conn.pendingEvents.scheduleAckTimeout);

  conn.pendingEvents.scheduleAckTimeout = false;
  updateAckState(conn, GetParam(), nextPacketNum++, true, false, Clock::now());
  EXPECT_EQ(ackState.acks.size(), 1);
  EXPECT_EQ(ackState.acks.front().start, 0);
  EXPECT_EQ(ackState.acks.front().end, 1);
  EXPECT_FALSE(ackState.needsToSendAckImmediately);
  EXPECT_EQ(ackState.numRxPacketsRecvd, 2);
  EXPECT_TRUE(conn.pendingEvents.scheduleAckTimeout);

  // Have a gap for next packet
  nextPacketNum += 2;
  conn.pendingEvents.scheduleAckTimeout = false;
  updateAckState(conn, GetParam(), nextPacketNum++, true, false, Clock::now());
  EXPECT_EQ(ackState.acks.size(), 2);
  EXPECT_EQ(ackState.acks.front().start, 0);
  EXPECT_EQ(ackState.acks.front().end, 1);
  EXPECT_EQ(ackState.acks.back().start, 4);
  EXPECT_EQ(ackState.acks.back().end, 4);
  EXPECT_TRUE(ackState.needsToSendAckImmediately);
  EXPECT_EQ(0, ackState.numRxPacketsRecvd);
  EXPECT_FALSE(conn.pendingEvents.scheduleAckTimeout);
  ackState.needsToSendAckImmediately = false;
  conn.pendingEvents.scheduleAckTimeout = false;

  // Reaching retx limit
  for (uint8_t i = 0; i < kRxPacketsPendingBeforeAckThresh - 1; ++i) {
    updateAckState(
        conn, GetParam(), nextPacketNum++, true, false, Clock::now());
    EXPECT_FALSE(ackState.needsToSendAckImmediately);
    EXPECT_TRUE(conn.pendingEvents.scheduleAckTimeout);
    EXPECT_EQ(ackState.numRxPacketsRecvd, i + 1);
  }
  // Hit the limit
  updateAckState(conn, GetParam(), nextPacketNum++, true, false, Clock::now());
  // Should send ack immediately once we have kRxPacketsPendingBeforeAckThresh
  // retransmittable packets
  EXPECT_TRUE(ackState.needsToSendAckImmediately);
  EXPECT_FALSE(conn.pendingEvents.scheduleAckTimeout);

  ackState.needsToSendAckImmediately = false;
  conn.pendingEvents.scheduleAckTimeout = false;

  // Nonrx limit
  for (uint64_t i = 0; i < kNonRxPacketsPendingBeforeAckThresh; ++i) {
    EXPECT_FALSE(ackState.needsToSendAckImmediately);
    EXPECT_EQ(ackState.numNonRxPacketsRecvd, i);
    updateAckState(
        conn, GetParam(), nextPacketNum++, false, false, Clock::now());
  }
  // Should send ack immediately once we have
  // kNonRxPacketsPendingBeforeAckThresh non retransmittable packets
  EXPECT_TRUE(ackState.needsToSendAckImmediately);
  // Non-rx packets don't turn on Ack timer:
  EXPECT_FALSE(conn.pendingEvents.scheduleAckTimeout);

  ackState.needsToSendAckImmediately = false;

  // Crypto always triggers immediately ack:
  updateAckState(conn, GetParam(), nextPacketNum++, true, true, Clock::now());
  EXPECT_TRUE(ackState.needsToSendAckImmediately);
  EXPECT_FALSE(conn.pendingEvents.scheduleAckTimeout);
}

TEST_F(UpdateAckStateTest, UpdateAckStateOnAckTimeout) {
  QuicConnectionStateBase conn(QuicNodeType::Client);
  auto& initialAckState = getAckState(conn, PacketNumberSpace::Initial);
  auto& handshakeAckState = getAckState(conn, PacketNumberSpace::Handshake);
  auto& appDataAckState = getAckState(conn, PacketNumberSpace::AppData);
  initialAckState.numRxPacketsRecvd = 1;
  handshakeAckState.numRxPacketsRecvd = 2;
  appDataAckState.numRxPacketsRecvd = 3;
  initialAckState.numNonRxPacketsRecvd = 4;
  handshakeAckState.numNonRxPacketsRecvd = 5;
  appDataAckState.numNonRxPacketsRecvd = 6;

  updateAckStateOnAckTimeout(conn);

  EXPECT_TRUE(appDataAckState.needsToSendAckImmediately);
  EXPECT_FALSE(conn.pendingEvents.scheduleAckTimeout);
  EXPECT_EQ(0, appDataAckState.numRxPacketsRecvd);
  EXPECT_EQ(0, appDataAckState.numNonRxPacketsRecvd);

  EXPECT_FALSE(initialAckState.needsToSendAckImmediately);
  EXPECT_EQ(1, initialAckState.numRxPacketsRecvd);
  EXPECT_EQ(4, initialAckState.numNonRxPacketsRecvd);

  EXPECT_FALSE(handshakeAckState.needsToSendAckImmediately);
  EXPECT_FALSE(conn.pendingEvents.scheduleAckTimeout);
  EXPECT_EQ(2, handshakeAckState.numRxPacketsRecvd);
  EXPECT_EQ(5, handshakeAckState.numNonRxPacketsRecvd);
}

TEST_P(UpdateAckStateTest, UpdateAckSendStateOnRecvPacketsCrypto) {
  // Crypto always leads to immediate ack
  QuicConnectionStateBase conn(QuicNodeType::Client);
  auto& ackState = getAckState(conn, GetParam());
  updateAckSendStateOnRecvPacket(conn, ackState, false, true, true);
  EXPECT_TRUE(verifyToAckImmediately(conn, ackState));
  EXPECT_FALSE(verifyToScheduleAckTimeout(conn));
}

TEST_P(UpdateAckStateTest, UpdateAckSendStateOnRecvPacketsRxLimit) {
  // Retx packets reach thresh
  QuicConnectionStateBase conn(QuicNodeType::Client);
  auto& ackState = getAckState(conn, GetParam());
  for (size_t i = 0; i < kRxPacketsPendingBeforeAckThresh - 1; i++) {
    updateAckSendStateOnRecvPacket(conn, ackState, false, true, false);
    EXPECT_FALSE(verifyToAckImmediately(conn, ackState));
    EXPECT_TRUE(verifyToScheduleAckTimeout(conn));
  }
  updateAckSendStateOnRecvPacket(conn, ackState, false, true, false);
  EXPECT_TRUE(verifyToAckImmediately(conn, ackState));
  EXPECT_FALSE(verifyToScheduleAckTimeout(conn));
  // Ack one more, we will start counting again
  updateAckSendStateOnRecvPacket(conn, ackState, false, true, false);
  EXPECT_FALSE(verifyToAckImmediately(conn, ackState));
  EXPECT_TRUE(verifyToScheduleAckTimeout(conn));
}

TEST_P(UpdateAckStateTest, UpdateAckSendStateOnRecvPacketsNonRxLimit) {
  // Non-rx packets reach thresh
  QuicConnectionStateBase conn(QuicNodeType::Client);
  auto& ackState = getAckState(conn, GetParam());
  for (size_t i = 0; i < kNonRxPacketsPendingBeforeAckThresh - 1; i++) {
    updateAckSendStateOnRecvPacket(conn, ackState, false, false, false);
    EXPECT_FALSE(verifyToAckImmediately(conn, ackState));
    EXPECT_FALSE(verifyToScheduleAckTimeout(conn));
  }
  updateAckSendStateOnRecvPacket(conn, ackState, false, false, false);
  EXPECT_TRUE(verifyToAckImmediately(conn, ackState));
  EXPECT_FALSE(verifyToScheduleAckTimeout(conn));
  // Ack one more, we will start counting again
  updateAckSendStateOnRecvPacket(conn, ackState, false, false, false);
  EXPECT_FALSE(verifyToAckImmediately(conn, ackState));
  EXPECT_FALSE(verifyToScheduleAckTimeout(conn));
}

TEST_P(
    UpdateAckStateTest,
    UpdateAckSendStateOnRecvPacketsNonRxLimitWithRxPackets) {
  // Non-rx packets reach thresh
  QuicConnectionStateBase conn(QuicNodeType::Client);
  auto& ackState = getAckState(conn, GetParam());
  // use 1 rx packet
  updateAckSendStateOnRecvPacket(conn, ackState, false, true, false);
  for (size_t i = 0; i < kRxPacketsPendingBeforeAckThresh - 2; i++) {
    updateAckSendStateOnRecvPacket(conn, ackState, false, false, false);
    EXPECT_FALSE(verifyToAckImmediately(conn, ackState));
    EXPECT_TRUE(verifyToScheduleAckTimeout(conn));
  }
  updateAckSendStateOnRecvPacket(conn, ackState, false, false, false);
  EXPECT_TRUE(verifyToAckImmediately(conn, ackState));
  EXPECT_FALSE(verifyToScheduleAckTimeout(conn));
  // Ack one more, we will start counting again
  updateAckSendStateOnRecvPacket(conn, ackState, false, false, false);
  EXPECT_FALSE(verifyToAckImmediately(conn, ackState));
  EXPECT_FALSE(verifyToScheduleAckTimeout(conn));
}

TEST_P(UpdateAckStateTest, UpdateAckSendStateOnRecvPacketsRxAndNonRxMixed) {
  // Rx and non-rx mixed together. We should still just need
  // kRxPacketsPendingBeforeAckThresh to trigger an ack
  QuicConnectionStateBase conn(QuicNodeType::Client);
  auto& ackState = getAckState(conn, GetParam());
  for (size_t i = 0; i < kRxPacketsPendingBeforeAckThresh - 1; i++) {
    bool isRetransmittable = i % 2;
    updateAckSendStateOnRecvPacket(
        conn, ackState, false, isRetransmittable, false);
    EXPECT_FALSE(verifyToAckImmediately(conn, ackState));
    EXPECT_EQ(i >= 1, verifyToScheduleAckTimeout(conn));
  }
  updateAckSendStateOnRecvPacket(conn, ackState, false, true, false);
  EXPECT_TRUE(verifyToAckImmediately(conn, ackState));
  EXPECT_FALSE(verifyToScheduleAckTimeout(conn));
  // Ack one more, we will start counting again
  updateAckSendStateOnRecvPacket(conn, ackState, false, true, false);
  EXPECT_FALSE(verifyToAckImmediately(conn, ackState));
  EXPECT_TRUE(verifyToScheduleAckTimeout(conn));
}

TEST_P(UpdateAckStateTest, UpdateAckSendStateOnRecvPacketsRxOutOfOrder) {
  // Retransmittable & out of order: ack immediately
  QuicConnectionStateBase conn(QuicNodeType::Client);
  auto& ackState = getAckState(conn, GetParam());
  updateAckSendStateOnRecvPacket(conn, ackState, true, true, false);
  EXPECT_TRUE(verifyToAckImmediately(conn, ackState));
  EXPECT_FALSE(verifyToScheduleAckTimeout(conn));
}

TEST_P(UpdateAckStateTest, UpdateAckSendStateOnRecvPacketsNonRxOutOfOrder) {
  // Non-retransmittable & out of order: not ack immediately
  QuicConnectionStateBase conn(QuicNodeType::Client);
  auto& ackState = getAckState(conn, GetParam());
  updateAckSendStateOnRecvPacket(conn, ackState, true, false, false);
  EXPECT_FALSE(verifyToAckImmediately(conn, ackState));
  EXPECT_FALSE(verifyToScheduleAckTimeout(conn));
}

INSTANTIATE_TEST_CASE_P(
    UpdateAckStateTests,
    UpdateAckStateTest,
    Values(
        PacketNumberSpace::Initial,
        PacketNumberSpace::Handshake,
        PacketNumberSpace::AppData));

class QuicStateFunctionsTest : public TestWithParam<PacketNumberSpace> {};

TEST_F(QuicStateFunctionsTest, RttCalculationNoAckDelay) {
  QuicServerConnectionState conn;
  auto rttSample = 1100us;
  updateRtt(conn, rttSample, 0us);
  EXPECT_EQ(1100, conn.lossState.srtt.count());
  EXPECT_EQ(1100 / 2, conn.lossState.rttvar.count());
  EXPECT_EQ(0us, conn.lossState.maxAckDelay);
}

TEST_F(QuicStateFunctionsTest, RttCalculationWithAckDelay) {
  QuicServerConnectionState conn;
  auto rttSample = 1000us;
  updateRtt(conn, rttSample, 300us);
  EXPECT_EQ(1000, conn.lossState.srtt.count());
  EXPECT_EQ(500, conn.lossState.rttvar.count());
  EXPECT_EQ(300us, conn.lossState.maxAckDelay);
}

TEST_F(QuicStateFunctionsTest, RttCalculationWithMrttAckDelay) {
  QuicServerConnectionState conn;
  conn.lossState.mrtt = 100us;
  auto rttSample = 1000us;
  updateRtt(conn, rttSample, 300us);
  EXPECT_EQ(700, conn.lossState.srtt.count());
  EXPECT_EQ(350, conn.lossState.rttvar.count());
  EXPECT_EQ(300us, conn.lossState.maxAckDelay);
}

TEST_F(QuicStateFunctionsTest, TestInvokeStreamStateMachineConnectionError) {
  QuicServerConnectionState conn;
  QuicStreamState stream(1, conn);
  RstStreamFrame rst(1, GenericApplicationErrorCode::UNKNOWN, 100);
  stream.finalReadOffset = 1024;
  EXPECT_THROW(
      invokeStreamReceiveStateMachine(conn, stream, std::move(rst)),
      QuicTransportException);
  // This doesn't change the send state machine implicitly anymore
  bool matches = matchesStates<StreamSendStateData, StreamSendStates::Open>(
      stream.send.state);
  EXPECT_TRUE(matches);
}

TEST_F(QuicStateFunctionsTest, InvokeResetDoesNotSendFlowControl) {
  QuicServerConnectionState conn;
  QuicStreamState stream(1, conn);
  RstStreamFrame rst(1, GenericApplicationErrorCode::UNKNOWN, 90);
  // this would normally trigger a flow control update.
  stream.flowControlState.advertisedMaxOffset = 100;
  stream.flowControlState.windowSize = 100;
  conn.flowControlState.advertisedMaxOffset = 100;
  conn.flowControlState.windowSize = 100;
  invokeStreamReceiveStateMachine(conn, stream, std::move(rst));
  bool matches =
      matchesStates<StreamReceiveStateData, StreamReceiveStates::Closed>(
          stream.recv.state);
  EXPECT_TRUE(matches);
  EXPECT_FALSE(conn.streamManager->hasWindowUpdates());
  EXPECT_TRUE(conn.pendingEvents.connWindowUpdate);
}

TEST_F(QuicStateFunctionsTest, TestInvokeStreamStateMachineStreamError) {
  // We isolate invalid events on streams to affect only the streams. Is that
  // a good idea? We'll find out.
  QuicServerConnectionState conn;
  QuicStreamState stream(1, conn);
  RstStreamFrame rst(1, GenericApplicationErrorCode::UNKNOWN, 100);
  try {
    invokeStreamSendStateMachine(conn, stream, StreamEvents::RstAck(rst));
    ADD_FAILURE();
  } catch (QuicTransportException& ex) {
    EXPECT_EQ(ex.errorCode(), TransportErrorCode::STREAM_STATE_ERROR);
  }
  bool matches = matchesStates<StreamSendStateData, StreamSendStates::Open>(
      stream.send.state);
  EXPECT_TRUE(matches);
}

TEST_F(QuicStateFunctionsTest, UpdateMinRtt) {
  QuicServerConnectionState conn;
  // First rtt sample, will be assign to both srtt and mrtt
  auto rttSample = 100us;
  updateRtt(conn, rttSample, 0us);
  EXPECT_EQ(100us, conn.lossState.lrtt);
  EXPECT_EQ(conn.lossState.lrtt, conn.lossState.mrtt);
  EXPECT_EQ(conn.lossState.lrtt, conn.lossState.srtt);
  auto oldMrtt = conn.lossState.mrtt;

  // Slower packet
  rttSample = 550us;
  updateRtt(conn, rttSample, 0us);
  EXPECT_EQ(oldMrtt, conn.lossState.mrtt);

  // Faster packet
  rttSample = 20us;
  updateRtt(conn, rttSample, 0us);
  EXPECT_EQ(20us, conn.lossState.mrtt);
}

TEST_F(QuicStateFunctionsTest, UpdateMaxAckDelay) {
  QuicServerConnectionState conn;
  EXPECT_EQ(0us, conn.lossState.maxAckDelay);
  auto rttSample = 100us;

  // update maxAckDelay
  updateRtt(conn, rttSample, 30us);
  EXPECT_EQ(30us, conn.lossState.maxAckDelay);

  // smaller ackDelay
  updateRtt(conn, rttSample, 3us);
  EXPECT_EQ(30us, conn.lossState.maxAckDelay);
}

TEST_F(QuicStateFunctionsTest, IsConnectionPaced) {
  QuicConnectionStateBase state(QuicNodeType::Client);
  EXPECT_FALSE(isConnectionPaced(state));

  state.canBePaced = true;
  EXPECT_FALSE(isConnectionPaced(state));

  state.transportSettings.pacingEnabled = true;
  EXPECT_FALSE(isConnectionPaced(state));

  auto mockCongestionController = std::make_unique<MockCongestionController>();
  auto rawCongestionController = mockCongestionController.get();
  state.congestionController = std::move(mockCongestionController);
  EXPECT_CALL(*rawCongestionController, canBePaced()).WillOnce(Return(false));
  EXPECT_FALSE(isConnectionPaced(state));
  EXPECT_CALL(*rawCongestionController, canBePaced()).WillOnce(Return(true));
  EXPECT_TRUE(isConnectionPaced(state));
}

TEST_F(QuicStateFunctionsTest, GetOutstandingPackets) {
  QuicConnectionStateBase conn(QuicNodeType::Client);
  conn.outstandingPackets.emplace_back(
      makeTestLongPacket(LongHeader::Types::Initial),
      Clock::now(),
      135,
      false,
      false,
      0);
  conn.outstandingPackets.emplace_back(
      makeTestLongPacket(LongHeader::Types::Handshake),
      Clock::now(),
      1217,
      false,
      false,
      0);
  conn.outstandingPackets.emplace_back(
      makeTestShortPacket(), Clock::now(), 5556, false, false, 0);
  conn.outstandingPackets.emplace_back(
      makeTestLongPacket(LongHeader::Types::Initial),
      Clock::now(),
      56,
      false,
      false,
      0);
  conn.outstandingPackets.emplace_back(
      makeTestShortPacket(), Clock::now(), 6665, false, false, 0);
  EXPECT_EQ(
      135,
      getFirstOutstandingPacket(conn, PacketNumberSpace::Initial)->encodedSize);
  EXPECT_EQ(
      56,
      getLastOutstandingPacket(conn, PacketNumberSpace::Initial)->encodedSize);
  EXPECT_EQ(
      1217,
      getFirstOutstandingPacket(conn, PacketNumberSpace::Handshake)
          ->encodedSize);
  EXPECT_EQ(
      1217,
      getFirstOutstandingPacket(conn, PacketNumberSpace::Handshake)
          ->encodedSize);
  EXPECT_EQ(
      5556,
      getFirstOutstandingPacket(conn, PacketNumberSpace::AppData)->encodedSize);
  EXPECT_EQ(
      6665,
      getLastOutstandingPacket(conn, PacketNumberSpace::AppData)->encodedSize);
}

TEST_F(QuicStateFunctionsTest, UpdateLargestReceivePacketsAtLatCloseSent) {
  QuicConnectionStateBase conn(QuicNodeType::Client);
  EXPECT_FALSE(conn.ackStates.initialAckState.largestReceivedAtLastCloseSent);
  EXPECT_FALSE(conn.ackStates.handshakeAckState.largestReceivedAtLastCloseSent);
  EXPECT_FALSE(conn.ackStates.appDataAckState.largestReceivedAtLastCloseSent);
  conn.ackStates.initialAckState.largestReceivedPacketNum = 123;
  conn.ackStates.handshakeAckState.largestReceivedPacketNum = 654;
  conn.ackStates.appDataAckState.largestReceivedPacketNum = 789;
  updateLargestReceivedPacketsAtLastCloseSent(conn);
  EXPECT_EQ(
      123, *conn.ackStates.initialAckState.largestReceivedAtLastCloseSent);
  EXPECT_EQ(
      654, *conn.ackStates.handshakeAckState.largestReceivedAtLastCloseSent);
  EXPECT_EQ(
      789, *conn.ackStates.appDataAckState.largestReceivedAtLastCloseSent);
}

TEST_P(QuicStateFunctionsTest, HasReceivedPackets) {
  QuicConnectionStateBase conn(QuicNodeType::Server);
  EXPECT_FALSE(hasReceivedPackets(conn));
  getAckState(conn, GetParam()).largestReceivedPacketNum = 123;
  EXPECT_TRUE(hasReceivedPackets(conn));
}

TEST_P(QuicStateFunctionsTest, HasReceivedPacketsAtLastCloseSent) {
  QuicConnectionStateBase conn(QuicNodeType::Server);
  EXPECT_FALSE(hasReceivedPacketsAtLastCloseSent(conn));
  getAckState(conn, GetParam()).largestReceivedAtLastCloseSent = 1;
  EXPECT_TRUE(hasReceivedPacketsAtLastCloseSent(conn));
}

TEST_P(QuicStateFunctionsTest, HasNotReceivedNewPacketsSinceLastClose) {
  QuicConnectionStateBase conn(QuicNodeType::Server);
  EXPECT_TRUE(hasNotReceivedNewPacketsSinceLastCloseSent(conn));
  getAckState(conn, GetParam()).largestReceivedPacketNum = 1;
  EXPECT_FALSE(hasNotReceivedNewPacketsSinceLastCloseSent(conn));
  getAckState(conn, GetParam()).largestReceivedAtLastCloseSent = 1;
  EXPECT_TRUE(hasReceivedPacketsAtLastCloseSent(conn));
}

TEST_F(QuicStateFunctionsTest, EarliestLossTimer) {
  QuicConnectionStateBase conn(QuicNodeType::Server);
  EXPECT_FALSE(earliestLossTimer(conn).first.hasValue());
  auto currentTime = Clock::now();
  conn.lossState.initialLossTime = currentTime;
  EXPECT_EQ(PacketNumberSpace::Initial, earliestLossTimer(conn).second);
  EXPECT_EQ(currentTime, earliestLossTimer(conn).first.value());
  conn.lossState.appDataLossTime = currentTime - 1s;
  EXPECT_EQ(PacketNumberSpace::AppData, earliestLossTimer(conn).second);
  EXPECT_EQ(currentTime - 1s, earliestLossTimer(conn).first.value());
  conn.lossState.handshakeLossTime = currentTime + 1s;
  EXPECT_EQ(PacketNumberSpace::AppData, earliestLossTimer(conn).second);
  EXPECT_EQ(currentTime - 1s, earliestLossTimer(conn).first.value());
  conn.lossState.appDataLossTime= currentTime + 1s;
  EXPECT_EQ(PacketNumberSpace::Initial, earliestLossTimer(conn).second);
  EXPECT_EQ(currentTime, earliestLossTimer(conn).first.value());
}

INSTANTIATE_TEST_CASE_P(
    QuicStateFunctionsTests,
    QuicStateFunctionsTest,
    Values(
        PacketNumberSpace::Initial,
        PacketNumberSpace::Handshake,
        PacketNumberSpace::AppData));

} // namespace test
} // namespace quic
