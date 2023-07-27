/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <quic/state/OutstandingPacket.h>

#include <quic/codec/Types.h>
#include <quic/common/test/TestUtils.h>
#include <quic/fizz/server/handshake/FizzServerQuicHandshakeContext.h>
#include <quic/server/state/ServerStateMachine.h>
#include <quic/state/QuicStateFunctions.h>
#include <quic/state/stream/StreamReceiveHandlers.h>
#include <quic/state/stream/StreamSendHandlers.h>
#include <quic/state/test/Mocks.h>
#include <chrono>
#include <cstdint>
#include <deque>

using namespace testing;

namespace quic::test {

bool verifyToAckImmediatelyAndZeroPacketsReceived(
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

TEST_P(UpdateLargestReceivedPacketNumTest, FirstPacketNotOutOfOrder) {
  QuicServerConnectionState conn(
      FizzServerQuicHandshakeContext::Builder().build());
  /**
   * We skip setting the getAckState(conn, GetParam()).largestReceivedPacketNum
   * to simulate that we haven't received any packets yet.
   * `updateLargestReceivedPacketNum()` should return false for the first packet
   * received.
   */
  PacketNum firstPacket = folly::Random::rand32(1, 100);
  EXPECT_FALSE(updateLargestReceivedPacketNum(
      conn, getAckState(conn, GetParam()), firstPacket, Clock::now()));
}

TEST_P(UpdateLargestReceivedPacketNumTest, ReceiveNew) {
  QuicServerConnectionState conn(
      FizzServerQuicHandshakeContext::Builder().build());
  getAckState(conn, GetParam()).largestRecvdPacketNum = 100;
  auto currentLargestReceived =
      *getAckState(conn, GetParam()).largestRecvdPacketNum;
  PacketNum newReceived = currentLargestReceived + 1;
  auto distance = updateLargestReceivedPacketNum(
      conn, getAckState(conn, GetParam()), newReceived, Clock::now());
  EXPECT_EQ(distance, 0);
  EXPECT_GT(
      *getAckState(conn, GetParam()).largestRecvdPacketNum,
      currentLargestReceived);
}

TEST_P(UpdateLargestReceivedPacketNumTest, ReceiveNewWithGap) {
  QuicServerConnectionState conn(
      FizzServerQuicHandshakeContext::Builder().build());
  getAckState(conn, GetParam()).largestRecvdPacketNum = 100;
  auto currentLargestReceived =
      *getAckState(conn, GetParam()).largestRecvdPacketNum;
  PacketNum newReceived = currentLargestReceived + 3;
  auto distance = updateLargestReceivedPacketNum(
      conn, getAckState(conn, GetParam()), newReceived, Clock::now());
  EXPECT_EQ(distance, 2); // newReceived is 2 after the expected pkt num
  EXPECT_GT(
      *getAckState(conn, GetParam()).largestRecvdPacketNum,
      currentLargestReceived);
}

TEST_P(UpdateLargestReceivedPacketNumTest, ReceiveOld) {
  QuicServerConnectionState conn(
      FizzServerQuicHandshakeContext::Builder().build());
  getAckState(conn, GetParam()).largestRecvdPacketNum = 100;
  auto currentLargestReceived =
      *getAckState(conn, GetParam()).largestRecvdPacketNum;
  PacketNum newReceived = currentLargestReceived - 1;
  auto distance = updateLargestReceivedPacketNum(
      conn, getAckState(conn, GetParam()), newReceived, Clock::now());
  EXPECT_EQ(distance, 2); // newReceived is 2 before the expected pkt num
  EXPECT_EQ(
      *getAckState(conn, GetParam()).largestRecvdPacketNum,
      currentLargestReceived);
}

TEST_P(UpdateLargestReceivedPacketNumTest, ReceiveOldWithGap) {
  QuicServerConnectionState conn(
      FizzServerQuicHandshakeContext::Builder().build());
  getAckState(conn, GetParam()).largestRecvdPacketNum = 100;
  auto currentLargestReceived =
      *getAckState(conn, GetParam()).largestRecvdPacketNum;
  PacketNum newReceived = currentLargestReceived - 5;
  auto distance = updateLargestReceivedPacketNum(
      conn, getAckState(conn, GetParam()), newReceived, Clock::now());
  EXPECT_EQ(distance, 6); // newReceived is 6 before the expected pkt num
  EXPECT_EQ(
      *getAckState(conn, GetParam()).largestRecvdPacketNum,
      currentLargestReceived);
}

INSTANTIATE_TEST_SUITE_P(
    UpdateLargestReceivedPacketNumTests,
    UpdateLargestReceivedPacketNumTest,
    Values(
        PacketNumberSpace::Initial,
        PacketNumberSpace::Handshake,
        PacketNumberSpace::AppData));

class UpdateReceivedPacketTimestampsTest
    : public TestWithParam<PacketNumberSpace> {};

TEST_P(UpdateReceivedPacketTimestampsTest, TestUpdatePktReceiveTimestamps) {
  QuicServerConnectionState conn(
      FizzServerQuicHandshakeContext::Builder().build());

  PacketNum nextPacketNum = 0;
  TimePoint latestTimeStamp = Clock::now();
  conn.ackStates = AckStates(nextPacketNum);
  for (uint64_t i = 0;
       i < conn.transportSettings.maxReceiveTimestampsPerAckStored + 2;
       i++) {
    updateAckState(
        conn,
        PacketNumberSpace::AppData,
        nextPacketNum++,
        true /* pktHasRetransmattableData */,
        false /* pktHasCryptoData */,
        latestTimeStamp);
    latestTimeStamp += 1ms;
  }
  auto& ackState = getAckState(conn, PacketNumberSpace::AppData);
  EXPECT_EQ(
      ackState.recvdPacketInfos.size(),
      conn.transportSettings.maxReceiveTimestampsPerAckStored);
  // First 2 packets (0, 1) should be popped.
  EXPECT_EQ(ackState.recvdPacketInfos.front().pktNum, 2);
  EXPECT_TRUE(ackState.largestRecvdPacketNum.has_value());
  EXPECT_TRUE(ackState.lastRecvdPacketInfo.has_value());

  EXPECT_EQ(
      ackState.largestRecvdPacketNum.value(),
      conn.transportSettings.maxReceiveTimestampsPerAckStored + 1);
  EXPECT_EQ(
      ackState.lastRecvdPacketInfo.value().pktNum,
      conn.transportSettings.maxReceiveTimestampsPerAckStored + 1);
}

TEST_P(
    UpdateReceivedPacketTimestampsTest,
    TestUpdateOutOfOrderPktReceiveTimestamps) {
  QuicServerConnectionState conn(
      FizzServerQuicHandshakeContext::Builder().build());

  std::vector<PacketNum> receivedPkts = {0, 2, 3, 1, 4, 6, 5};
  conn.ackStates = AckStates(receivedPkts.front());
  auto recvdTs = Clock::now();
  for (auto pktNum : receivedPkts) {
    updateAckState(
        conn,
        PacketNumberSpace::AppData,
        pktNum,
        true /* pktHasRetransmattableData */,
        false /* pktHasCryptoData */,
        recvdTs);
  }
  // Packets 1 and 5 are out of order and will not be stored.
  auto& ackState = getAckState(conn, PacketNumberSpace::AppData);
  std::deque<RecvdPacketInfo> expectedPktsInfo = {
      {0, recvdTs}, {2, recvdTs}, {3, recvdTs}, {4, recvdTs}, {6, recvdTs}};
  EXPECT_EQ(expectedPktsInfo.size(), ackState.recvdPacketInfos.size());
  for (unsigned long i = 0; i < expectedPktsInfo.size(); i++) {
    EXPECT_EQ(expectedPktsInfo[i].pktNum, ackState.recvdPacketInfos[i].pktNum);
    EXPECT_EQ(
        expectedPktsInfo[i].timeStamp, ackState.recvdPacketInfos[i].timeStamp);
  }
  EXPECT_EQ(ackState.lastRecvdPacketInfo.value().pktNum, 5);
  EXPECT_EQ(ackState.lastRecvdPacketInfo.value().timeStamp, recvdTs);
}

INSTANTIATE_TEST_SUITE_P(
    UpdateReceivedPacketTimestampsTests,
    UpdateReceivedPacketTimestampsTest,
    Values(PacketNumberSpace::AppData));

class UpdateAckStateTest : public TestWithParam<PacketNumberSpace> {};

TEST_P(UpdateAckStateTest, TestUpdateAckState) {
  QuicServerConnectionState conn(
      FizzServerQuicHandshakeContext::Builder().build());
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
  for (uint8_t i = 0;
       i < conn.transportSettings.rxPacketsBeforeAckBeforeInit - 1;
       ++i) {
    updateAckState(
        conn, GetParam(), nextPacketNum++, true, false, Clock::now());
    EXPECT_FALSE(ackState.needsToSendAckImmediately);
    EXPECT_TRUE(conn.pendingEvents.scheduleAckTimeout);
    EXPECT_EQ(ackState.numRxPacketsRecvd, i + 1);
  }
  // Hit the limit
  updateAckState(conn, GetParam(), nextPacketNum++, true, false, Clock::now());
  // Should send ack immediately once we have
  // conn.transportSettings.rxPacketsBeforeAckBeforeInit retransmittable packets
  EXPECT_TRUE(ackState.needsToSendAckImmediately);
  EXPECT_FALSE(conn.pendingEvents.scheduleAckTimeout);

  ackState.needsToSendAckImmediately = false;
  conn.pendingEvents.scheduleAckTimeout = false;

  // Nonrx limit
  for (uint64_t i = 0; i < kNonRtxRxPacketsPendingBeforeAck; ++i) {
    EXPECT_FALSE(ackState.needsToSendAckImmediately);
    EXPECT_EQ(ackState.numNonRxPacketsRecvd, i);
    updateAckState(
        conn, GetParam(), nextPacketNum++, false, false, Clock::now());
  }
  // Should send ack immediately once we have
  // kNonRtxRxPacketsPendingBeforeAck non retransmittable packets
  EXPECT_TRUE(ackState.needsToSendAckImmediately);
  // Non-rx packets don't turn on Ack timer:
  EXPECT_FALSE(conn.pendingEvents.scheduleAckTimeout);

  ackState.needsToSendAckImmediately = false;

  // Crypto always triggers immediately ack:
  updateAckState(conn, GetParam(), nextPacketNum++, true, true, Clock::now());
  EXPECT_TRUE(ackState.needsToSendAckImmediately);
  EXPECT_FALSE(conn.pendingEvents.scheduleAckTimeout);
}

TEST_P(UpdateAckStateTest, TestUpdateAckStateFrequency) {
  QuicServerConnectionState conn(
      FizzServerQuicHandshakeContext::Builder().build());
  conn.transportSettings.rxPacketsBeforeAckInitThreshold = 20;
  conn.transportSettings.rxPacketsBeforeAckBeforeInit = 2;
  conn.transportSettings.rxPacketsBeforeAckAfterInit = 10;
  PacketNum nextPacketNum = 0;
  auto& ackState = getAckState(conn, GetParam());

  for (uint8_t i = 0;
       i < conn.transportSettings.rxPacketsBeforeAckBeforeInit - 1;
       ++i) {
    updateAckState(
        conn, GetParam(), nextPacketNum++, true, false, Clock::now());
    EXPECT_FALSE(ackState.needsToSendAckImmediately);
    EXPECT_TRUE(conn.pendingEvents.scheduleAckTimeout);
    EXPECT_EQ(ackState.numRxPacketsRecvd, i + 1);
  }
  updateAckState(conn, GetParam(), nextPacketNum++, true, false, Clock::now());
  EXPECT_TRUE(ackState.needsToSendAckImmediately);
  EXPECT_FALSE(conn.pendingEvents.scheduleAckTimeout);
  ackState.needsToSendAckImmediately = false;
  conn.pendingEvents.scheduleAckTimeout = false;

  for (;
       nextPacketNum <= conn.transportSettings.rxPacketsBeforeAckInitThreshold;
       nextPacketNum++) {
    updateAckState(conn, GetParam(), nextPacketNum, true, false, Clock::now());
  }
  ASSERT_EQ(
      ackState.largestRecvdPacketNum.value(),
      conn.transportSettings.rxPacketsBeforeAckInitThreshold);
  ackState.needsToSendAckImmediately = false;
  conn.pendingEvents.scheduleAckTimeout = false;
  ackState.numRxPacketsRecvd = 0;
  for (uint8_t i = 0;
       i < conn.transportSettings.rxPacketsBeforeAckAfterInit - 1;
       ++i) {
    updateAckState(
        conn, GetParam(), nextPacketNum++, true, false, Clock::now());
    EXPECT_FALSE(ackState.needsToSendAckImmediately);
    EXPECT_TRUE(conn.pendingEvents.scheduleAckTimeout);
    EXPECT_EQ(ackState.numRxPacketsRecvd, i + 1);
  }
  updateAckState(conn, GetParam(), nextPacketNum++, true, false, Clock::now());
  EXPECT_TRUE(ackState.needsToSendAckImmediately);
  EXPECT_FALSE(conn.pendingEvents.scheduleAckTimeout);
}

TEST_P(UpdateAckStateTest, TestUpdateAckStateFrequencyFromTolerance) {
  QuicServerConnectionState conn(
      FizzServerQuicHandshakeContext::Builder().build());
  PacketNum nextPacketNum = 1;
  auto& ackState = getAckState(conn, GetParam());
  ackState.largestRecvdPacketNum = nextPacketNum - 1;
  ackState.tolerance = 2;
  for (; nextPacketNum <= 10; nextPacketNum++) {
    updateAckState(conn, GetParam(), nextPacketNum, true, false, Clock::now());
    if (nextPacketNum < 2) {
      EXPECT_FALSE(ackState.needsToSendAckImmediately);
      EXPECT_TRUE(conn.pendingEvents.scheduleAckTimeout);
      EXPECT_EQ(nextPacketNum, ackState.numRxPacketsRecvd);
    } else {
      EXPECT_TRUE(ackState.needsToSendAckImmediately);
      EXPECT_FALSE(conn.pendingEvents.scheduleAckTimeout);
      EXPECT_EQ(0, ackState.numRxPacketsRecvd);
    }
    EXPECT_EQ(0, ackState.numNonRxPacketsRecvd);
  }
  ackState.tolerance = 10;
  for (; nextPacketNum <= 40; nextPacketNum++) {
    updateAckState(conn, GetParam(), nextPacketNum, true, false, Clock::now());
    if (nextPacketNum < 10) {
      EXPECT_FALSE(ackState.needsToSendAckImmediately);
      EXPECT_TRUE(conn.pendingEvents.scheduleAckTimeout);
      EXPECT_EQ(nextPacketNum, ackState.numRxPacketsRecvd);
    } else {
      EXPECT_TRUE(ackState.needsToSendAckImmediately);
      EXPECT_FALSE(conn.pendingEvents.scheduleAckTimeout);
      EXPECT_EQ(0, ackState.numRxPacketsRecvd);
    }
    EXPECT_EQ(0, ackState.numRxPacketsRecvd);
  }
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
  updateAckSendStateOnRecvPacket(conn, ackState, 0, true, true);
  EXPECT_TRUE(verifyToAckImmediatelyAndZeroPacketsReceived(conn, ackState));
  EXPECT_FALSE(verifyToScheduleAckTimeout(conn));
}

TEST_P(
    UpdateAckStateTest,
    UpdateAckSendStateOnRecvPacketsInitCryptoExperimental) {
  // Crypto data leads to immediate ack unless init packet space.
  QuicConnectionStateBase conn(QuicNodeType::Server);

  bool isInitPktNumSpace = GetParam() == PacketNumberSpace::Initial;

  auto& ackState = getAckState(conn, GetParam());
  updateAckSendStateOnRecvPacket(
      conn, ackState, false, true, true, isInitPktNumSpace);

  EXPECT_EQ(
      verifyToAckImmediatelyAndZeroPacketsReceived(conn, ackState),
      !isInitPktNumSpace);
  EXPECT_EQ(verifyToScheduleAckTimeout(conn), isInitPktNumSpace);
}

TEST_P(UpdateAckStateTest, UpdateAckSendStateOnRecvPacketsRxLimit) {
  // Retx packets reach thresh
  QuicConnectionStateBase conn(QuicNodeType::Client);
  auto& ackState = getAckState(conn, GetParam());
  for (size_t i = 0;
       i < conn.transportSettings.rxPacketsBeforeAckBeforeInit - 1;
       i++) {
    updateAckSendStateOnRecvPacket(conn, ackState, 0, true, false);
    EXPECT_FALSE(verifyToAckImmediatelyAndZeroPacketsReceived(conn, ackState));
    EXPECT_TRUE(verifyToScheduleAckTimeout(conn));
  }
  updateAckSendStateOnRecvPacket(conn, ackState, 0, true, false);
  EXPECT_TRUE(verifyToAckImmediatelyAndZeroPacketsReceived(conn, ackState));
  EXPECT_FALSE(verifyToScheduleAckTimeout(conn));

  // Followed by a retx packet, we will still need to ack immediately
  updateAckSendStateOnRecvPacket(conn, ackState, 0, true, false);
  EXPECT_TRUE(verifyToAckImmediatelyAndZeroPacketsReceived(conn, ackState));
  EXPECT_FALSE(verifyToScheduleAckTimeout(conn));
}

TEST_P(UpdateAckStateTest, UpdateAckSendStateOnRecvPacketsNonRxLimit) {
  // Non-rx packets reach thresh
  QuicConnectionStateBase conn(QuicNodeType::Client);
  auto& ackState = getAckState(conn, GetParam());
  for (size_t i = 0; i < kNonRtxRxPacketsPendingBeforeAck - 1; i++) {
    updateAckSendStateOnRecvPacket(conn, ackState, 0, false, false);
    EXPECT_FALSE(verifyToAckImmediatelyAndZeroPacketsReceived(conn, ackState));
    EXPECT_FALSE(verifyToScheduleAckTimeout(conn));
  }
  updateAckSendStateOnRecvPacket(conn, ackState, 0, false, false);
  EXPECT_TRUE(verifyToAckImmediatelyAndZeroPacketsReceived(conn, ackState));
  EXPECT_FALSE(verifyToScheduleAckTimeout(conn));

  // Followed by a non-rx packet, we will still need to ack immediately
  updateAckSendStateOnRecvPacket(conn, ackState, 0, false, false);
  EXPECT_TRUE(verifyToAckImmediatelyAndZeroPacketsReceived(conn, ackState));
  EXPECT_FALSE(verifyToScheduleAckTimeout(conn));
}

TEST_P(
    UpdateAckStateTest,
    UpdateAckSendStateOnRecvPacketsNonRxLimitWithRxPackets) {
  // Non-rx packets reach thresh
  QuicConnectionStateBase conn(QuicNodeType::Client);
  auto& ackState = getAckState(conn, GetParam());
  // use 1 rx packet
  updateAckSendStateOnRecvPacket(conn, ackState, 0, true, false);
  for (size_t i = 0;
       i < conn.transportSettings.rxPacketsBeforeAckBeforeInit - 2;
       i++) {
    updateAckSendStateOnRecvPacket(conn, ackState, 0, false, false);
    EXPECT_FALSE(verifyToAckImmediatelyAndZeroPacketsReceived(conn, ackState));
    EXPECT_TRUE(verifyToScheduleAckTimeout(conn));
  }
  updateAckSendStateOnRecvPacket(conn, ackState, 0, false, false);
  EXPECT_TRUE(verifyToAckImmediatelyAndZeroPacketsReceived(conn, ackState));
  EXPECT_FALSE(verifyToScheduleAckTimeout(conn));

  // Followed by a non-rx packet, we will still need to ack immediately
  updateAckSendStateOnRecvPacket(conn, ackState, 0, false, false);
  EXPECT_TRUE(verifyToAckImmediatelyAndZeroPacketsReceived(conn, ackState));
  EXPECT_FALSE(verifyToScheduleAckTimeout(conn));
}

TEST_P(
    UpdateAckStateTest,
    UpdateAckSendStateOnRecvPacketsRxLimitFollowedByNonRx) {
  // Retx packets reach thresh
  QuicConnectionStateBase conn(QuicNodeType::Client);
  auto& ackState = getAckState(conn, GetParam());
  for (size_t i = 0;
       i < conn.transportSettings.rxPacketsBeforeAckBeforeInit - 1;
       i++) {
    updateAckSendStateOnRecvPacket(conn, ackState, 0, true, false);
    EXPECT_FALSE(verifyToAckImmediatelyAndZeroPacketsReceived(conn, ackState));
    EXPECT_TRUE(verifyToScheduleAckTimeout(conn));
  }
  updateAckSendStateOnRecvPacket(conn, ackState, 0, true, false);
  EXPECT_TRUE(verifyToAckImmediatelyAndZeroPacketsReceived(conn, ackState));
  EXPECT_FALSE(verifyToScheduleAckTimeout(conn));

  // Followed by a non-retx packet, we will still need to ack immediately
  updateAckSendStateOnRecvPacket(conn, ackState, 0, false, false);
  EXPECT_TRUE(verifyToAckImmediatelyAndZeroPacketsReceived(conn, ackState));
  EXPECT_FALSE(verifyToScheduleAckTimeout(conn));
}

TEST_P(
    UpdateAckStateTest,
    UpdateAckSendStateOnRecvPacketsNonRxLimitFollowedByRx) {
  // Non-rx packets reach thresh
  QuicConnectionStateBase conn(QuicNodeType::Client);
  auto& ackState = getAckState(conn, GetParam());
  for (size_t i = 0; i < kNonRtxRxPacketsPendingBeforeAck - 1; i++) {
    updateAckSendStateOnRecvPacket(conn, ackState, 0, false, false);
    EXPECT_FALSE(verifyToAckImmediatelyAndZeroPacketsReceived(conn, ackState));
    EXPECT_FALSE(verifyToScheduleAckTimeout(conn));
  }
  updateAckSendStateOnRecvPacket(conn, ackState, 0, false, false);
  EXPECT_TRUE(verifyToAckImmediatelyAndZeroPacketsReceived(conn, ackState));
  EXPECT_FALSE(verifyToScheduleAckTimeout(conn));

  // Followed by a retx packet, we will still need to ack immediately
  updateAckSendStateOnRecvPacket(conn, ackState, 0, true, false);
  EXPECT_TRUE(verifyToAckImmediatelyAndZeroPacketsReceived(conn, ackState));
  EXPECT_FALSE(verifyToScheduleAckTimeout(conn));
}

TEST_P(UpdateAckStateTest, UpdateAckSendStateOnRecvPacketsRxAndNonRxMixed) {
  // Rx and non-rx mixed together. We should still just need
  // conn.transportSettings.rxPacketsBeforeAckBeforeInit to trigger an ack
  QuicConnectionStateBase conn(QuicNodeType::Client);
  auto& ackState = getAckState(conn, GetParam());
  for (size_t i = 0;
       i < conn.transportSettings.rxPacketsBeforeAckBeforeInit - 1;
       i++) {
    bool isRetransmittable = i % 2;
    updateAckSendStateOnRecvPacket(conn, ackState, 0, isRetransmittable, false);
    EXPECT_FALSE(verifyToAckImmediatelyAndZeroPacketsReceived(conn, ackState));
    EXPECT_EQ(i >= 1, verifyToScheduleAckTimeout(conn));
  }
  updateAckSendStateOnRecvPacket(conn, ackState, 0, true, false);
  EXPECT_TRUE(verifyToAckImmediatelyAndZeroPacketsReceived(conn, ackState));
  EXPECT_FALSE(verifyToScheduleAckTimeout(conn));

  // Followed by a retx packet, we will still need to ack immediately
  updateAckSendStateOnRecvPacket(conn, ackState, 0, true, false);
  EXPECT_TRUE(verifyToAckImmediatelyAndZeroPacketsReceived(conn, ackState));
  EXPECT_FALSE(verifyToScheduleAckTimeout(conn));
}

TEST_P(UpdateAckStateTest, UpdateAckSendStateOnRecvPacketsRxOutOfOrder) {
  // Retransmittable & out of order: ack immediately
  QuicConnectionStateBase conn(QuicNodeType::Client);
  auto& ackState = getAckState(conn, GetParam());
  updateAckSendStateOnRecvPacket(conn, ackState, 1, true, false);
  EXPECT_TRUE(verifyToAckImmediatelyAndZeroPacketsReceived(conn, ackState));
  EXPECT_FALSE(verifyToScheduleAckTimeout(conn));
}

TEST_P(
    UpdateAckStateTest,
    UpdateAckSendStateOnRecvPacketsRxOutOfOrderThresholdNotExceeded) {
  // Retransmittable & out of order: don't ack immediately if threshold not
  // exceeded.
  QuicConnectionStateBase conn(QuicNodeType::Client);
  auto& ackState = getAckState(conn, GetParam());
  ackState.reorderThreshold = 3;
  updateAckSendStateOnRecvPacket(conn, ackState, 3, true, false);
  EXPECT_FALSE(verifyToAckImmediatelyAndZeroPacketsReceived(conn, ackState));
  EXPECT_TRUE(verifyToScheduleAckTimeout(conn));
}

TEST_P(UpdateAckStateTest, UpdateAckSendStateOnRecvPacketsNonRxOutOfOrder) {
  // Non-retransmittable & out of order: not ack immediately
  QuicConnectionStateBase conn(QuicNodeType::Client);
  auto& ackState = getAckState(conn, GetParam());
  updateAckSendStateOnRecvPacket(conn, ackState, 3, false, false);
  EXPECT_FALSE(verifyToAckImmediatelyAndZeroPacketsReceived(conn, ackState));
  EXPECT_FALSE(verifyToScheduleAckTimeout(conn));
}

TEST_P(
    UpdateAckStateTest,
    UpdateAckSendStateOnRecvPacketsRxOutOfOrderFollowedByInOrder) {
  // Retransmittable & out of order: ack immediately
  QuicConnectionStateBase conn(QuicNodeType::Client);
  auto& ackState = getAckState(conn, GetParam());
  updateAckSendStateOnRecvPacket(conn, ackState, 1, true, false);
  EXPECT_TRUE(verifyToAckImmediatelyAndZeroPacketsReceived(conn, ackState));
  EXPECT_FALSE(verifyToScheduleAckTimeout(conn));

  // Followed by a retransmittable & in order: still ack immediately
  updateAckSendStateOnRecvPacket(conn, ackState, 0, true, false);
  EXPECT_TRUE(verifyToAckImmediatelyAndZeroPacketsReceived(conn, ackState));
  EXPECT_FALSE(verifyToScheduleAckTimeout(conn));
}

TEST_P(
    UpdateAckStateTest,
    UpdateAckSendStateOnRecvPacketsCryptoFollowedByNonCrypto) {
  // Retransmittable & Crypto: ack immediately
  QuicConnectionStateBase conn(QuicNodeType::Client);
  auto& ackState = getAckState(conn, GetParam());
  updateAckSendStateOnRecvPacket(conn, ackState, 0, true, true);
  EXPECT_TRUE(verifyToAckImmediatelyAndZeroPacketsReceived(conn, ackState));
  EXPECT_FALSE(verifyToScheduleAckTimeout(conn));

  // Followed by a retransmittable & non Crypo: still ack immediately
  updateAckSendStateOnRecvPacket(conn, ackState, 0, true, false);
  EXPECT_TRUE(verifyToAckImmediatelyAndZeroPacketsReceived(conn, ackState));
  EXPECT_FALSE(verifyToScheduleAckTimeout(conn));
}

INSTANTIATE_TEST_SUITE_P(
    UpdateAckStateTests,
    UpdateAckStateTest,
    Values(
        PacketNumberSpace::Initial,
        PacketNumberSpace::Handshake,
        PacketNumberSpace::AppData));

class QuicStateFunctionsTest : public TestWithParam<PacketNumberSpace> {};

TEST_F(QuicStateFunctionsTest, RttCalculationZeroAckDelayFirstRtt) {
  QuicServerConnectionState conn(
      FizzServerQuicHandshakeContext::Builder().build());
  const auto rttSample = 1100us;
  const auto ackDelay = 0us;
  updateRtt(conn, rttSample, ackDelay);
  EXPECT_EQ(1100, conn.lossState.srtt.count());
  EXPECT_EQ(1100, conn.lossState.lrtt.count());
  EXPECT_EQ(1100 / 2, conn.lossState.rttvar.count());
  EXPECT_EQ(1100, conn.lossState.mrtt.count());
  EXPECT_EQ(0us, conn.lossState.maxAckDelay);
}

TEST_F(QuicStateFunctionsTest, RttCalculationWithAckDelayFirstRtt) {
  QuicServerConnectionState conn(
      FizzServerQuicHandshakeContext::Builder().build());
  const auto rttSample = 1000us;
  const auto ackDelay = 300us;
  updateRtt(conn, rttSample, ackDelay);
  EXPECT_EQ(1000, conn.lossState.srtt.count());
  EXPECT_EQ(1000, conn.lossState.lrtt.count());
  EXPECT_EQ(1000, conn.lossState.mrtt.count());
  EXPECT_EQ(1000 / 2, conn.lossState.rttvar.count());
  EXPECT_EQ(300us, conn.lossState.maxAckDelay);
}

TEST_F(QuicStateFunctionsTest, RttCalculationWithExistingMrttNewLower) {
  QuicServerConnectionState conn(
      FizzServerQuicHandshakeContext::Builder().build());
  conn.lossState.mrtt = 100us;
  const auto rttSample = 50us;
  const auto ackDelay = 100us;
  updateRtt(conn, rttSample, ackDelay);
  EXPECT_EQ(50, conn.lossState.srtt.count());
  EXPECT_EQ(50, conn.lossState.lrtt.count());
  EXPECT_EQ(50, conn.lossState.mrtt.count());
  EXPECT_EQ(50 / 2, conn.lossState.rttvar.count());
}

TEST_F(QuicStateFunctionsTest, RttCalculationWithExistingMrttStaysSame) {
  QuicServerConnectionState conn(
      FizzServerQuicHandshakeContext::Builder().build());
  conn.lossState.mrtt = 25us;
  const auto rttSample = 50us;
  const auto ackDelay = 100us;
  updateRtt(conn, rttSample, ackDelay);
  EXPECT_EQ(50, conn.lossState.srtt.count());
  EXPECT_EQ(50, conn.lossState.lrtt.count());
  EXPECT_EQ(25, conn.lossState.mrtt.count());
  EXPECT_EQ(50 / 2, conn.lossState.rttvar.count());
}

TEST_F(QuicStateFunctionsTest, RttCalculationWithExistingMrttZeroAckDelay) {
  QuicServerConnectionState conn(
      FizzServerQuicHandshakeContext::Builder().build());
  conn.lossState.mrtt = 100us;
  conn.lossState.maxAckDelay = 500us;
  const auto rttSample = 1100us;
  const auto ackDelay = 0us;
  updateRtt(conn, rttSample, ackDelay);
  EXPECT_EQ(1100, conn.lossState.srtt.count());
  EXPECT_EQ(1100, conn.lossState.lrtt.count());
  EXPECT_EQ(100, conn.lossState.mrtt.count());
  EXPECT_EQ(1100 / 2, conn.lossState.rttvar.count());
  EXPECT_EQ(500us, conn.lossState.maxAckDelay);
}

TEST_F(QuicStateFunctionsTest, RttCalculationWithExistingMrttSubtractAckDelay) {
  QuicServerConnectionState conn(
      FizzServerQuicHandshakeContext::Builder().build());
  conn.lossState.mrtt = 100us;
  const auto rttSample = 1000us;
  const auto ackDelay = 300us;
  updateRtt(conn, rttSample, ackDelay);
  EXPECT_EQ(700, conn.lossState.srtt.count()); // 700 as ack delay subtracted
  EXPECT_EQ(1000, conn.lossState.lrtt.count()); // 1000 as lrtt = rttSample
  EXPECT_EQ(100, conn.lossState.mrtt.count());
  EXPECT_EQ(
      700 / 2, conn.lossState.rttvar.count()); // 700 as ack delay subtracted
  EXPECT_EQ(300us, conn.lossState.maxAckDelay);
}

TEST_F(QuicStateFunctionsTest, RttCalculationWithExistingMrttIgnoreAckDelay) {
  QuicServerConnectionState conn(
      FizzServerQuicHandshakeContext::Builder().build());
  conn.lossState.mrtt = 700us;
  const auto rttSample = 900us;
  const auto ackDelay = 300us;
  updateRtt(conn, rttSample, ackDelay);
  EXPECT_EQ(900, conn.lossState.srtt.count());
  EXPECT_EQ(900, conn.lossState.lrtt.count());
  EXPECT_EQ(700, conn.lossState.mrtt.count());
  EXPECT_EQ(450, conn.lossState.rttvar.count());
  EXPECT_EQ(300us, conn.lossState.maxAckDelay);
}

TEST_F(QuicStateFunctionsTest, RttCalculationWithNewLowerMrttZeroAckDelay) {
  QuicServerConnectionState conn(
      FizzServerQuicHandshakeContext::Builder().build());
  conn.lossState.mrtt = 100us;
  conn.lossState.maxAckDelay = 500us;
  const auto rttSample = 50us;
  const auto ackDelay = 0us;
  updateRtt(conn, rttSample, ackDelay);
  EXPECT_EQ(50, conn.lossState.srtt.count());
  EXPECT_EQ(50, conn.lossState.lrtt.count());
  EXPECT_EQ(50, conn.lossState.mrtt.count());
  EXPECT_EQ(50 / 2, conn.lossState.rttvar.count());
  EXPECT_EQ(500us, conn.lossState.maxAckDelay);
}

TEST_F(QuicStateFunctionsTest, RttCalculationWithNewLowerMrttIgnoreAckDelay) {
  QuicServerConnectionState conn(
      FizzServerQuicHandshakeContext::Builder().build());
  conn.lossState.mrtt = 100us;
  const auto rttSample = 50us;
  const auto ackDelay = 25us;
  updateRtt(conn, rttSample, ackDelay);
  EXPECT_EQ(50, conn.lossState.srtt.count());
  EXPECT_EQ(50, conn.lossState.lrtt.count());
  EXPECT_EQ(50, conn.lossState.mrtt.count());
  EXPECT_EQ(50 / 2, conn.lossState.rttvar.count());
  EXPECT_EQ(25us, conn.lossState.maxAckDelay);
}

TEST_F(QuicStateFunctionsTest, RttCalculationMaxAckDelayIncreases) {
  QuicServerConnectionState conn(
      FizzServerQuicHandshakeContext::Builder().build());
  conn.lossState.mrtt = 100us;
  conn.lossState.maxAckDelay = 50us;
  const auto rttSample = 500us;
  const auto ackDelay = 100us;
  updateRtt(conn, rttSample, ackDelay);
  EXPECT_EQ(400, conn.lossState.srtt.count()); // 400 as ack delay subtracted
  EXPECT_EQ(500, conn.lossState.lrtt.count()); // 500 as lrtt = rttSample
  EXPECT_EQ(100, conn.lossState.mrtt.count());
  EXPECT_EQ(400 / 2, conn.lossState.rttvar.count());
  EXPECT_EQ(100us, conn.lossState.maxAckDelay);
}

TEST_F(QuicStateFunctionsTest, RttCalculationMaxAckDelayStaysSame) {
  QuicServerConnectionState conn(
      FizzServerQuicHandshakeContext::Builder().build());
  conn.lossState.mrtt = 100us;
  conn.lossState.maxAckDelay = 5000us;
  const auto rttSample = 500us;
  const auto ackDelay = 100us;
  updateRtt(conn, rttSample, ackDelay);
  EXPECT_EQ(400, conn.lossState.srtt.count()); // 400 as ack delay subtracted
  EXPECT_EQ(500, conn.lossState.lrtt.count()); // 500 as lrtt = rttSample
  EXPECT_EQ(100, conn.lossState.mrtt.count());
  EXPECT_EQ(400 / 2, conn.lossState.rttvar.count());
  EXPECT_EQ(5000us, conn.lossState.maxAckDelay);
}

TEST_F(QuicStateFunctionsTest, RttCalculationNewLowerMrttMaxAckDelayIncreases) {
  QuicServerConnectionState conn(
      FizzServerQuicHandshakeContext::Builder().build());
  conn.lossState.mrtt = 100us;
  conn.lossState.maxAckDelay = 50us;
  const auto rttSample = 50us;
  const auto ackDelay = 100us;
  updateRtt(conn, rttSample, ackDelay);
  EXPECT_EQ(50, conn.lossState.srtt.count());
  EXPECT_EQ(50, conn.lossState.lrtt.count());
  EXPECT_EQ(50, conn.lossState.mrtt.count());
  EXPECT_EQ(50 / 2, conn.lossState.rttvar.count());
  EXPECT_EQ(100us, conn.lossState.maxAckDelay);
}

TEST_F(QuicStateFunctionsTest, RttCalculationNewLowerMrttMaxAckDelayStaysSame) {
  QuicServerConnectionState conn(
      FizzServerQuicHandshakeContext::Builder().build());
  conn.lossState.mrtt = 100us;
  conn.lossState.maxAckDelay = 5000us;
  const auto rttSample = 50us;
  const auto ackDelay = 10us;
  updateRtt(conn, rttSample, ackDelay);
  EXPECT_EQ(50, conn.lossState.srtt.count());
  EXPECT_EQ(50, conn.lossState.lrtt.count());
  EXPECT_EQ(50, conn.lossState.mrtt.count());
  EXPECT_EQ(50 / 2, conn.lossState.rttvar.count());
  EXPECT_EQ(5000us, conn.lossState.maxAckDelay);
}

TEST_F(QuicStateFunctionsTest, RttCalculationAckDelayLargerThanSample) {
  QuicServerConnectionState conn(
      FizzServerQuicHandshakeContext::Builder().build());
  const auto rttSample = 10us;
  const auto ackDelay = 300us;
  updateRtt(conn, rttSample, ackDelay);
  EXPECT_EQ(10, conn.lossState.srtt.count());
  EXPECT_EQ(10, conn.lossState.lrtt.count());
  EXPECT_EQ(10, conn.lossState.mrtt.count());
  EXPECT_EQ(5, conn.lossState.rttvar.count());
  EXPECT_EQ(300us, conn.lossState.maxAckDelay);
}

TEST_F(
    QuicStateFunctionsTest,
    RttCalculationWithNewLowerMrttAckDelayLargerThanSample) {
  QuicServerConnectionState conn(
      FizzServerQuicHandshakeContext::Builder().build());
  conn.lossState.mrtt = 100us;
  const auto rttSample = 10us;
  const auto ackDelay = 300us;
  updateRtt(conn, rttSample, ackDelay);
  EXPECT_EQ(10, conn.lossState.srtt.count());
  EXPECT_EQ(10, conn.lossState.lrtt.count());
  EXPECT_EQ(10, conn.lossState.mrtt.count());
  EXPECT_EQ(5, conn.lossState.rttvar.count());
  EXPECT_EQ(300us, conn.lossState.maxAckDelay);
}

TEST_F(QuicStateFunctionsTest, RttCalculationExtraRttMetricsStoredInLossState) {
  QuicServerConnectionState conn(
      FizzServerQuicHandshakeContext::Builder().build());

  // Test cases
  //
  //                                     ||   [ Value Expected ]   |
  //  Case | RTT (delay) | RTT w/o delay ||  mRTT  |  w/o ACK delay | Updated
  //  -----|-------------|---------------||------- |----------------|----------
  //    1  | 31ms (5 ms) |     26ms      ||   31   |       26       | (both)
  //    2  | 30ms (3 ms) |     27ms      ||   30   |       26       | (1)
  //    3  | 30ms (8 ms) |     22ms      ||   30   |       22       | (2)
  //    4  | 37ms (8 ms) |     29ms      ||   30   |       22       | (none)
  //    5  | 25ms (0 ms) |     29ms      ||   25   |       22       | (1)
  //    6  | 25ms (4 ms) |     29ms      ||   25   |       21       | (2)
  //    7  | 20ms (0 ms) |     29ms      ||   20   |       20       | (both)
  //    8  | 0ms (0 ms)  |     0ms       ||   0    |       0        | (both)
  //    9  | 0ms (10 ms) |     0ms       ||   0    |       0        | (none)

  // case 1
  updateRtt(conn, 31ms /* RTT sample */, 5ms /* ack delay */);
  EXPECT_EQ(31ms, conn.lossState.mrtt);
  EXPECT_EQ(26ms, conn.lossState.maybeMrttNoAckDelay);
  EXPECT_EQ(31ms, conn.lossState.maybeLrtt);
  EXPECT_EQ(5ms, conn.lossState.maybeLrttAckDelay);

  // case 2
  updateRtt(conn, 30ms /* RTT sample */, 3ms /* ack delay */);
  EXPECT_EQ(30ms, conn.lossState.mrtt);
  EXPECT_EQ(26ms, conn.lossState.maybeMrttNoAckDelay);
  EXPECT_EQ(30ms, conn.lossState.maybeLrtt);
  EXPECT_EQ(3ms, conn.lossState.maybeLrttAckDelay);

  // case 3
  updateRtt(conn, 30ms /* RTT sample */, 8ms /* ack delay */);
  EXPECT_EQ(30ms, conn.lossState.mrtt);
  EXPECT_EQ(22ms, conn.lossState.maybeMrttNoAckDelay);
  EXPECT_EQ(30ms, conn.lossState.maybeLrtt);
  EXPECT_EQ(8ms, conn.lossState.maybeLrttAckDelay);

  // case 4
  updateRtt(conn, 37ms /* RTT sample */, 8ms /* ack delay */);
  EXPECT_EQ(30ms, conn.lossState.mrtt);
  EXPECT_EQ(22ms, conn.lossState.maybeMrttNoAckDelay);
  EXPECT_EQ(37ms, conn.lossState.maybeLrtt);
  EXPECT_EQ(8ms, conn.lossState.maybeLrttAckDelay);

  // case 5
  updateRtt(conn, 25ms /* RTT sample */, 0ms /* ack delay */);
  EXPECT_EQ(25ms, conn.lossState.mrtt);
  EXPECT_EQ(22ms, conn.lossState.maybeMrttNoAckDelay);
  EXPECT_EQ(25ms, conn.lossState.maybeLrtt);
  EXPECT_EQ(0ms, conn.lossState.maybeLrttAckDelay);

  // case 6
  updateRtt(conn, 25ms /* RTT sample */, 4ms /* ack delay */);
  EXPECT_EQ(25ms, conn.lossState.mrtt);
  EXPECT_EQ(21ms, conn.lossState.maybeMrttNoAckDelay);
  EXPECT_EQ(25ms, conn.lossState.maybeLrtt);
  EXPECT_EQ(4ms, conn.lossState.maybeLrttAckDelay);

  // case 7
  updateRtt(conn, 20ms /* RTT sample */, 0ms /* ack delay */);
  EXPECT_EQ(20ms, conn.lossState.mrtt);
  EXPECT_EQ(20ms, conn.lossState.maybeMrttNoAckDelay);
  EXPECT_EQ(20ms, conn.lossState.maybeLrtt);
  EXPECT_EQ(0ms, conn.lossState.maybeLrttAckDelay);

  // case 8
  updateRtt(conn, 0ms /* RTT sample */, 0ms /* ack delay */);
  EXPECT_EQ(0ms, conn.lossState.mrtt);
  EXPECT_EQ(0ms, conn.lossState.maybeMrttNoAckDelay);
  EXPECT_EQ(0ms, conn.lossState.maybeLrtt);
  EXPECT_EQ(0ms, conn.lossState.maybeLrttAckDelay);

  // case 9
  updateRtt(conn, 0ms /* RTT sample */, 10ms /* ack delay */);
  EXPECT_EQ(0ms, conn.lossState.mrtt);
  EXPECT_EQ(0ms, conn.lossState.maybeMrttNoAckDelay);
  EXPECT_EQ(0ms, conn.lossState.maybeLrtt);
  EXPECT_EQ(10ms, conn.lossState.maybeLrttAckDelay);
}

TEST_F(QuicStateFunctionsTest, TestInvokeStreamStateMachineConnectionError) {
  QuicServerConnectionState conn(
      FizzServerQuicHandshakeContext::Builder().build());
  QuicStreamState stream(1, conn);
  RstStreamFrame rst(1, GenericApplicationErrorCode::UNKNOWN, 100);
  stream.finalReadOffset = 1024;
  EXPECT_THROW(
      receiveRstStreamSMHandler(stream, std::move(rst)),
      QuicTransportException);
  // This doesn't change the send state machine implicitly anymore
  bool matches = (stream.sendState == StreamSendState::Open);
  EXPECT_TRUE(matches);
}

TEST_F(QuicStateFunctionsTest, InvokeResetDoesNotSendFlowControl) {
  QuicServerConnectionState conn(
      FizzServerQuicHandshakeContext::Builder().build());
  QuicStreamState stream(1, conn);
  RstStreamFrame rst(1, GenericApplicationErrorCode::UNKNOWN, 90);
  // this would normally trigger a flow control update.
  stream.flowControlState.advertisedMaxOffset = 100;
  stream.flowControlState.windowSize = 100;
  conn.flowControlState.advertisedMaxOffset = 100;
  conn.flowControlState.windowSize = 100;
  receiveRstStreamSMHandler(stream, std::move(rst));
  bool matches = (stream.recvState == StreamRecvState::Closed);
  EXPECT_TRUE(matches);
  EXPECT_FALSE(conn.streamManager->hasWindowUpdates());
  EXPECT_TRUE(conn.pendingEvents.connWindowUpdate);
}

TEST_F(QuicStateFunctionsTest, TestInvokeStreamStateMachineStreamError) {
  // We isolate invalid events on streams to affect only the streams. Is that
  // a good idea? We'll find out.
  QuicServerConnectionState conn(
      FizzServerQuicHandshakeContext::Builder().build());
  QuicStreamState stream(1, conn);
  RstStreamFrame rst(1, GenericApplicationErrorCode::UNKNOWN, 100);
  try {
    sendRstAckSMHandler(stream);
    ADD_FAILURE();
  } catch (QuicTransportException& ex) {
    EXPECT_EQ(ex.errorCode(), TransportErrorCode::STREAM_STATE_ERROR);
  }
  bool matches = (stream.sendState == StreamSendState::Open);
  EXPECT_TRUE(matches);
}

TEST_F(QuicStateFunctionsTest, UpdateMinRtt) {
  QuicServerConnectionState conn(
      FizzServerQuicHandshakeContext::Builder().build());
  auto qLogger = std::make_shared<FileQLogger>(VantagePoint::Server);
  conn.qLogger = qLogger;

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

  std::vector<int> indices =
      getQLogEventIndices(QLogEventType::MetricUpdate, qLogger);
  EXPECT_EQ(indices.size(), 3);
  std::array<std::chrono::microseconds, 3> rttSampleArr = {100us, 550us, 20us};
  std::array<std::chrono::microseconds, 3> mrttArr = {oldMrtt, oldMrtt, 20us};
  std::array<std::chrono::microseconds, 3> srttArr = {100us, 155us, 137us};

  for (int i = 0; i < 3; ++i) {
    auto tmp = std::move(qLogger->logs[indices[i]]);
    auto event = dynamic_cast<QLogMetricUpdateEvent*>(tmp.get());
    EXPECT_EQ(event->latestRtt, rttSampleArr[i]);
    EXPECT_EQ(event->mrtt, mrttArr[i]);
    EXPECT_EQ(event->srtt, srttArr[i]);
    EXPECT_EQ(event->ackDelay, 0us);
  }
}

TEST_F(QuicStateFunctionsTest, UpdateMaxAckDelay) {
  QuicServerConnectionState conn(
      FizzServerQuicHandshakeContext::Builder().build());
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
}

TEST_F(QuicStateFunctionsTest, GetOutstandingPackets) {
  QuicConnectionStateBase conn(QuicNodeType::Client);
  conn.outstandings.packets.emplace_back(
      makeTestLongPacket(LongHeader::Types::Initial),
      Clock::now(),
      135,
      0,
      false,
      0,
      0,
      0,
      0,
      LossState(),
      0,
      OutstandingPacketMetadata::DetailsPerStream());
  conn.outstandings.packets.emplace_back(
      makeTestLongPacket(LongHeader::Types::Handshake),
      Clock::now(),
      1217,
      0,
      false,
      0,
      0,
      0,
      0,
      LossState(),
      0,
      OutstandingPacketMetadata::DetailsPerStream());
  conn.outstandings.packets.emplace_back(
      makeTestShortPacket(),
      Clock::now(),
      5556,
      5000,
      false,
      0,
      0,
      0,
      0,
      LossState(),
      0,
      OutstandingPacketMetadata::DetailsPerStream());
  conn.outstandings.packets.emplace_back(
      makeTestLongPacket(LongHeader::Types::Initial),
      Clock::now(),
      56,
      0,
      false,
      0,
      0,
      0,
      0,
      LossState(),
      0,
      OutstandingPacketMetadata::DetailsPerStream());
  conn.outstandings.packets.emplace_back(
      makeTestShortPacket(),
      Clock::now(),
      6665,
      6000,
      false,
      0,
      0,
      0,
      0,
      LossState(),
      0,
      OutstandingPacketMetadata::DetailsPerStream());
  EXPECT_EQ(
      135,
      getFirstOutstandingPacket(conn, PacketNumberSpace::Initial)
          ->metadata.encodedSize);
  EXPECT_EQ(
      0,
      getFirstOutstandingPacket(conn, PacketNumberSpace::Initial)
          ->metadata.encodedBodySize);
  EXPECT_EQ(
      56,
      getLastOutstandingPacket(conn, PacketNumberSpace::Initial)
          ->metadata.encodedSize);
  EXPECT_EQ(
      0,
      getLastOutstandingPacket(conn, PacketNumberSpace::Initial)
          ->metadata.encodedBodySize);
  EXPECT_EQ(
      1217,
      getFirstOutstandingPacket(conn, PacketNumberSpace::Handshake)
          ->metadata.encodedSize);
  EXPECT_EQ(
      0,
      getFirstOutstandingPacket(conn, PacketNumberSpace::Handshake)
          ->metadata.encodedBodySize);
  EXPECT_EQ(
      5556,
      getFirstOutstandingPacket(conn, PacketNumberSpace::AppData)
          ->metadata.encodedSize);
  EXPECT_EQ(
      5000,
      getFirstOutstandingPacket(conn, PacketNumberSpace::AppData)
          ->metadata.encodedBodySize);
  EXPECT_EQ(
      6665,
      getLastOutstandingPacket(conn, PacketNumberSpace::AppData)
          ->metadata.encodedSize);
  EXPECT_EQ(
      6000,
      getLastOutstandingPacket(conn, PacketNumberSpace::AppData)
          ->metadata.encodedBodySize);
}

TEST_F(QuicStateFunctionsTest, UpdateLargestReceivePacketsAtLatCloseSent) {
  QuicConnectionStateBase conn(QuicNodeType::Client);
  EXPECT_FALSE(conn.ackStates.initialAckState->largestReceivedAtLastCloseSent);
  EXPECT_FALSE(
      conn.ackStates.handshakeAckState->largestReceivedAtLastCloseSent);
  EXPECT_FALSE(conn.ackStates.appDataAckState.largestReceivedAtLastCloseSent);
  conn.ackStates.initialAckState->largestRecvdPacketNum = 123;
  conn.ackStates.handshakeAckState->largestRecvdPacketNum = 654;
  conn.ackStates.appDataAckState.largestRecvdPacketNum = 789;
  updateLargestReceivedPacketsAtLastCloseSent(conn);
  EXPECT_EQ(
      123, *conn.ackStates.initialAckState->largestReceivedAtLastCloseSent);
  EXPECT_EQ(
      654, *conn.ackStates.handshakeAckState->largestReceivedAtLastCloseSent);
  EXPECT_EQ(
      789, *conn.ackStates.appDataAckState.largestReceivedAtLastCloseSent);
}

TEST_P(QuicStateFunctionsTest, HasReceivedPackets) {
  QuicConnectionStateBase conn(QuicNodeType::Server);
  EXPECT_FALSE(hasReceivedPackets(conn));
  getAckState(conn, GetParam()).largestRecvdPacketNum = 123;
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
  getAckState(conn, GetParam()).largestRecvdPacketNum = 1;
  EXPECT_FALSE(hasNotReceivedNewPacketsSinceLastCloseSent(conn));
  getAckState(conn, GetParam()).largestReceivedAtLastCloseSent = 1;
  EXPECT_TRUE(hasReceivedPacketsAtLastCloseSent(conn));
}

TEST_F(QuicStateFunctionsTest, EarliestLossTimer) {
  QuicConnectionStateBase conn(QuicNodeType::Server);
  EXPECT_FALSE(earliestLossTimer(conn).first.has_value());
  auto currentTime = Clock::now();

  // Before handshake completed
  conn.lossState.lossTimes[PacketNumberSpace::Initial] = currentTime;
  EXPECT_EQ(PacketNumberSpace::Initial, earliestLossTimer(conn).second);
  EXPECT_EQ(currentTime, earliestLossTimer(conn).first.value());
  conn.lossState.lossTimes[PacketNumberSpace::AppData] = currentTime - 2s;
  EXPECT_EQ(PacketNumberSpace::Initial, earliestLossTimer(conn).second);
  EXPECT_EQ(currentTime, earliestLossTimer(conn).first.value());
  conn.lossState.lossTimes[PacketNumberSpace::Handshake] = currentTime - 1s;
  EXPECT_EQ(PacketNumberSpace::Handshake, earliestLossTimer(conn).second);
  EXPECT_EQ(currentTime - 1s, earliestLossTimer(conn).first.value());

  conn.oneRttWriteCipher = createNoOpAead();

  // After one-rtt cipher is available
  EXPECT_EQ(PacketNumberSpace::AppData, earliestLossTimer(conn).second);
  EXPECT_EQ(currentTime - 2s, earliestLossTimer(conn).first.value());
  conn.lossState.lossTimes[PacketNumberSpace::AppData] = currentTime + 1s;
  EXPECT_EQ(PacketNumberSpace::Handshake, earliestLossTimer(conn).second);
  EXPECT_EQ(currentTime - 1s, earliestLossTimer(conn).first.value());
}

TEST_P(QuicStateFunctionsTest, CloseTranportStateChange) {
  QuicConnectionStateBase conn(QuicNodeType::Server);
  getAckState(conn, GetParam()).nextPacketNum = kMaxPacketNumber - 1;
  EXPECT_FALSE(conn.pendingEvents.closeTransport);
  increaseNextPacketNum(conn, GetParam());
  EXPECT_TRUE(conn.pendingEvents.closeTransport);
}

INSTANTIATE_TEST_SUITE_P(
    QuicStateFunctionsTests,
    QuicStateFunctionsTest,
    Values(
        PacketNumberSpace::Initial,
        PacketNumberSpace::Handshake,
        PacketNumberSpace::AppData));

} // namespace quic::test
