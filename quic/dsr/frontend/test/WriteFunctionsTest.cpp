/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <folly/portability/GTest.h>
#include <quic/dsr/frontend/WriteFunctions.h>
#include <quic/dsr/test/TestCommon.h>
#include <quic/state/test/Mocks.h>

using namespace testing;

namespace quic::test {

class WriteFunctionsTest : public DSRCommonTestFixture {};

TEST_F(WriteFunctionsTest, SchedulerNoData) {
  prepareFlowControlAndStreamLimit();
  auto cid = getTestConnectionId();
  size_t packetLimit = 20;
  EXPECT_EQ(0, writePacketizationRequest(conn_, cid, packetLimit, *aead_));
}

TEST_F(WriteFunctionsTest, CwndBlockd) {
  prepareOneStream();
  auto mockCongestionController =
      std::make_unique<NiceMock<MockCongestionController>>();
  auto rawCongestionController = mockCongestionController.get();
  conn_.congestionController = std::move(mockCongestionController);
  EXPECT_CALL(*rawCongestionController, getWritableBytes())
      .WillRepeatedly(Return(0));
  auto cid = getTestConnectionId();
  size_t packetLimit = 20;
  EXPECT_EQ(0, writePacketizationRequest(conn_, cid, packetLimit, *aead_));
}

TEST_F(WriteFunctionsTest, FlowControlBlockded) {
  prepareOneStream();
  auto mockCongestionController =
      std::make_unique<NiceMock<MockCongestionController>>();
  auto rawCongestionController = mockCongestionController.get();
  conn_.congestionController = std::move(mockCongestionController);
  EXPECT_CALL(*rawCongestionController, getWritableBytes())
      .WillRepeatedly(Return(0));
  auto cid = getTestConnectionId();
  size_t packetLimit = 20;
  EXPECT_EQ(0, writePacketizationRequest(conn_, cid, packetLimit, *aead_));
}

TEST_F(WriteFunctionsTest, WriteOne) {
  prepareFlowControlAndStreamLimit();
  auto streamId = prepareOneStream();
  auto cid = getTestConnectionId();
  auto stream = conn_.streamManager->findStream(streamId);
  auto currentBufMetaOffset = stream->writeBufMeta.offset;
  size_t packetLimit = 20;
  EXPECT_EQ(1, writePacketizationRequest(conn_, cid, packetLimit, *aead_));
  EXPECT_GT(stream->writeBufMeta.offset, currentBufMetaOffset);
  EXPECT_EQ(1, stream->retransmissionBufMetas.size());
  EXPECT_EQ(1, countInstructions(streamId));
  EXPECT_EQ(1, conn_.outstandings.packets.size());
  EXPECT_TRUE(verifyAllOutstandingsAreDSR());
}

TEST_F(WriteFunctionsTest, WriteLoopTimeLimit) {
  prepareFlowControlAndStreamLimit();
  auto streamId = prepareOneStream(3000);
  auto cid = getTestConnectionId();
  auto stream = conn_.streamManager->findStream(streamId);
  auto currentBufMetaOffset = stream->writeBufMeta.offset;
  size_t packetLimit = 2;
  conn_.lossState.srtt = 100ms;
  EXPECT_EQ(2, writePacketizationRequest(conn_, cid, packetLimit, *aead_));
  EXPECT_GT(stream->writeBufMeta.offset, currentBufMetaOffset);
  EXPECT_EQ(2, stream->retransmissionBufMetas.size());
  EXPECT_EQ(2, countInstructions(streamId));
  EXPECT_EQ(2, conn_.outstandings.packets.size());
  EXPECT_TRUE(verifyAllOutstandingsAreDSR());

  // Fake the time so it's in the past.
  auto writeLoopBeginTime = Clock::now() - 200ms;
  EXPECT_EQ(
      0,
      writePacketizationRequest(
          conn_, cid, packetLimit, *aead_, writeLoopBeginTime));
  EXPECT_EQ(2, stream->retransmissionBufMetas.size());
  EXPECT_EQ(2, countInstructions(streamId));
  EXPECT_EQ(2, conn_.outstandings.packets.size());
  EXPECT_TRUE(verifyAllOutstandingsAreDSR());
}

TEST_F(WriteFunctionsTest, WriteTwoInstructions) {
  prepareFlowControlAndStreamLimit();
  auto streamId = prepareOneStream(2000);
  auto stream = conn_.streamManager->findStream(streamId);
  auto cid = getTestConnectionId();
  size_t packetLimit = 20;
  EXPECT_EQ(2, writePacketizationRequest(conn_, cid, packetLimit, *aead_));
  EXPECT_EQ(2, stream->retransmissionBufMetas.size());
  EXPECT_EQ(2, countInstructions(streamId));
  EXPECT_EQ(2, conn_.outstandings.packets.size());
  EXPECT_TRUE(verifyAllOutstandingsAreDSR());
}

TEST_F(WriteFunctionsTest, PacketLimit) {
  prepareFlowControlAndStreamLimit();
  auto streamId = prepareOneStream(2000 * 100);
  auto stream = conn_.streamManager->findStream(streamId);
  auto mockCongestionController =
      std::make_unique<NiceMock<MockCongestionController>>();
  auto rawCongestionController = mockCongestionController.get();
  conn_.congestionController = std::move(mockCongestionController);
  EXPECT_CALL(*rawCongestionController, getWritableBytes())
      .WillRepeatedly(Return(1000));
  auto cid = getTestConnectionId();
  size_t packetLimit = 20;
  EXPECT_EQ(20, writePacketizationRequest(conn_, cid, packetLimit, *aead_));
  EXPECT_EQ(20, stream->retransmissionBufMetas.size());
  EXPECT_EQ(20, countInstructions(streamId));
  EXPECT_EQ(20, conn_.outstandings.packets.size());
  EXPECT_TRUE(verifyAllOutstandingsAreDSR());
}

TEST_F(WriteFunctionsTest, WriteTwoStreams) {
  prepareFlowControlAndStreamLimit();
  auto streamId1 = prepareOneStream(1000);
  auto streamId2 = prepareOneStream(1000);
  auto stream1 = conn_.streamManager->findStream(streamId1);
  auto stream2 = conn_.streamManager->findStream(streamId2);
  auto cid = getTestConnectionId();
  size_t packetLimit = 20;
  EXPECT_EQ(2, writePacketizationRequest(conn_, cid, packetLimit, *aead_));
  EXPECT_EQ(1, stream1->retransmissionBufMetas.size());
  EXPECT_EQ(1, stream2->retransmissionBufMetas.size());
  // TODO: This needs to be fixed later: The stream and the sender needs to be
  // 1:1 in the future. Then there will be two senders for this test case and
  // each of them will send out one instruction.
  EXPECT_EQ(1, countInstructions(streamId1));
  EXPECT_EQ(1, countInstructions(streamId2));
  EXPECT_EQ(2, conn_.outstandings.packets.size());
  EXPECT_TRUE(verifyAllOutstandingsAreDSR());
}

TEST_F(WriteFunctionsTest, LossAndFreshTwoInstructionsInTwoPackets) {
  prepareFlowControlAndStreamLimit();
  auto streamId = prepareOneStream(1000);
  auto stream = conn_.streamManager->findStream(streamId);
  auto bufMetaStartingOffset = stream->writeBufMeta.offset;
  // Move part of the BufMetas to lossBufMetas
  auto split = stream->writeBufMeta.split(500);
  stream->lossBufMetas.push_back(split);
  size_t packetLimit = 10;
  EXPECT_EQ(
      2,
      writePacketizationRequest(
          conn_, getTestConnectionId(), packetLimit, *aead_));
  EXPECT_EQ(2, countInstructions(streamId));
  EXPECT_EQ(2, conn_.outstandings.packets.size());
  auto& packet1 = conn_.outstandings.packets.front().packet;
  auto& packet2 = conn_.outstandings.packets.back().packet;
  EXPECT_EQ(1, packet1.frames.size());
  EXPECT_EQ(1, packet2.frames.size());
  WriteStreamFrame expectedFirstFrame(
      streamId, bufMetaStartingOffset, 500, false, true);
  WriteStreamFrame expectedSecondFrame(
      streamId, 500 + bufMetaStartingOffset, 500, true, true);
  EXPECT_EQ(expectedFirstFrame, *packet1.frames[0].asWriteStreamFrame());
  EXPECT_EQ(expectedSecondFrame, *packet2.frames[0].asWriteStreamFrame());
}

} // namespace quic::test
