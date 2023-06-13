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

class WriteFunctionsTest : public DSRCommonTestFixture {
  void SetUp() override {
    aead_ = createNoOpAead(16);
  }
};

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
  // Pretend we sent the non DSR data
  stream->ackedIntervals.insert(0, stream->writeBuffer.chainLength() - 1);
  stream->currentWriteOffset = stream->writeBuffer.chainLength();
  stream->writeBuffer.move();
  conn_.streamManager->updateWritableStreams(*stream);
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

TEST_F(WriteFunctionsTest, WriteLoopTimeLimitNoLimit) {
  prepareFlowControlAndStreamLimit();
  auto streamId = prepareOneStream(3000);
  auto cid = getTestConnectionId();
  auto stream = conn_.streamManager->findStream(streamId);
  // Pretend we sent the non DSR data
  stream->ackedIntervals.insert(0, stream->writeBuffer.chainLength() - 1);
  stream->currentWriteOffset = stream->writeBuffer.chainLength();
  stream->writeBuffer.move();
  conn_.streamManager->updateWritableStreams(*stream);
  auto currentBufMetaOffset = stream->writeBufMeta.offset;
  size_t packetLimit = 2;
  conn_.lossState.srtt = 100ms;
  conn_.transportSettings.writeLimitRttFraction = 0;
  EXPECT_EQ(2, writePacketizationRequest(conn_, cid, packetLimit, *aead_));
  EXPECT_GT(stream->writeBufMeta.offset, currentBufMetaOffset);
  EXPECT_EQ(2, stream->retransmissionBufMetas.size());
  EXPECT_EQ(2, countInstructions(streamId));
  EXPECT_EQ(2, conn_.outstandings.packets.size());
  EXPECT_TRUE(verifyAllOutstandingsAreDSR());

  // Fake the time so it's in the past.
  auto writeLoopBeginTime = Clock::now() - 200ms;
  EXPECT_EQ(
      1,
      writePacketizationRequest(
          conn_, cid, packetLimit, *aead_, writeLoopBeginTime));
  EXPECT_EQ(3, stream->retransmissionBufMetas.size());
  EXPECT_EQ(3, countInstructions(streamId));
  EXPECT_EQ(3, conn_.outstandings.packets.size());
  EXPECT_TRUE(verifyAllOutstandingsAreDSR());
}

TEST_F(WriteFunctionsTest, WriteTwoInstructions) {
  prepareFlowControlAndStreamLimit();
  auto streamId = prepareOneStream(2000);
  auto stream = conn_.streamManager->findStream(streamId);
  // Pretend we sent the non DSR data
  stream->ackedIntervals.insert(0, stream->writeBuffer.chainLength() - 1);
  stream->currentWriteOffset = stream->writeBuffer.chainLength();
  stream->writeBuffer.move();
  conn_.streamManager->updateWritableStreams(*stream);
  auto cid = getTestConnectionId();
  size_t packetLimit = 20;
  EXPECT_EQ(2, writePacketizationRequest(conn_, cid, packetLimit, *aead_));
  EXPECT_EQ(2, stream->retransmissionBufMetas.size());
  EXPECT_EQ(2, countInstructions(streamId));
  EXPECT_EQ(2, conn_.outstandings.packets.size());
  EXPECT_TRUE(verifyAllOutstandingsAreDSR());
  // Check the packet size is full.
  EXPECT_EQ(
      conn_.outstandings.packets[0].metadata.encodedSize,
      conn_.udpSendPacketLen);
}

TEST_F(WriteFunctionsTest, PacketLimit) {
  prepareFlowControlAndStreamLimit();
  auto streamId = prepareOneStream(2000 * 100);
  auto stream = conn_.streamManager->findStream(streamId);
  // Pretend we sent the non DSR data
  stream->ackedIntervals.insert(0, stream->writeBuffer.chainLength() - 1);
  stream->currentWriteOffset = stream->writeBuffer.chainLength();
  stream->writeBuffer.move();
  conn_.streamManager->updateWritableStreams(*stream);
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
  // All packets should be full.
  for (auto& outstanding : conn_.outstandings.packets) {
    EXPECT_EQ(outstanding.metadata.encodedSize, conn_.udpSendPacketLen);
  }
}

TEST_F(WriteFunctionsTest, WriteTwoStreams) {
  prepareFlowControlAndStreamLimit();
  auto streamId1 = prepareOneStream(1000);
  auto streamId2 = prepareOneStream(1000);
  auto stream1 = conn_.streamManager->findStream(streamId1);
  auto stream2 = conn_.streamManager->findStream(streamId2);
  // Pretend we sent the non DSR data on second stream
  stream2->ackedIntervals.insert(0, stream2->writeBuffer.chainLength() - 1);
  stream2->currentWriteOffset = stream2->writeBuffer.chainLength();
  stream2->writeBuffer.move();
  conn_.streamManager->updateWritableStreams(*stream2);
  auto cid = getTestConnectionId();
  size_t packetLimit = 20;
  EXPECT_EQ(2, writePacketizationRequest(conn_, cid, packetLimit, *aead_));
  EXPECT_EQ(1, stream1->retransmissionBufMetas.size());
  EXPECT_EQ(1, stream2->retransmissionBufMetas.size());
  EXPECT_EQ(1, countInstructions(streamId1));
  EXPECT_EQ(1, countInstructions(streamId2));
  EXPECT_EQ(2, conn_.outstandings.packets.size());
  EXPECT_TRUE(verifyAllOutstandingsAreDSR());
}

TEST_F(WriteFunctionsTest, WriteThreeStreamsNonDsrAndDsr) {
  prepareFlowControlAndStreamLimit();
  auto streamId1 = prepareOneStream(1000);
  auto streamId2 = prepareOneStream(1000);
  auto streamId3 = prepareOneStream(1000);
  auto stream1 = conn_.streamManager->findStream(streamId1);
  auto stream2 = conn_.streamManager->findStream(streamId2);
  auto stream3 = conn_.streamManager->findStream(streamId3);
  auto cid = getTestConnectionId();
  size_t packetLimit = 20;
  // First loop only write a single packet because it will find there's non-DSR
  // data to write on the next stream.
  EXPECT_EQ(1, writePacketizationRequest(conn_, cid, packetLimit, *aead_));
  // Pretend we sent the non DSR data for last stream
  stream3->ackedIntervals.insert(0, stream3->writeBuffer.chainLength() - 1);
  stream3->currentWriteOffset = stream3->writeBuffer.chainLength();
  stream3->writeBuffer.move();
  conn_.streamManager->updateWritableStreams(*stream3);
  EXPECT_EQ(2, writePacketizationRequest(conn_, cid, packetLimit, *aead_));
  EXPECT_EQ(1, stream1->retransmissionBufMetas.size());
  EXPECT_EQ(1, stream2->retransmissionBufMetas.size());
  EXPECT_EQ(1, stream3->retransmissionBufMetas.size());
  EXPECT_EQ(1, countInstructions(streamId1));
  EXPECT_EQ(1, countInstructions(streamId2));
  EXPECT_EQ(1, countInstructions(streamId3));
  EXPECT_EQ(3, conn_.outstandings.packets.size());
  EXPECT_TRUE(verifyAllOutstandingsAreDSR());
}

TEST_F(WriteFunctionsTest, WriteTwoStreamsNonIncremental) {
  prepareFlowControlAndStreamLimit();
  auto streamId1 = prepareOneStream(2000);
  auto streamId2 = prepareOneStream(1000);
  auto stream1 = conn_.streamManager->findStream(streamId1);
  auto stream2 = conn_.streamManager->findStream(streamId2);
  conn_.streamManager->setStreamPriority(streamId1, Priority{3, false});
  conn_.streamManager->setStreamPriority(streamId2, Priority{3, false});
  // Pretend we sent the non DSR data on first stream
  stream1->ackedIntervals.insert(0, stream1->writeBuffer.chainLength() - 1);
  stream1->currentWriteOffset = stream1->writeBuffer.chainLength();
  stream1->writeBuffer.move();
  conn_.streamManager->updateWritableStreams(*stream1);
  auto cid = getTestConnectionId();
  size_t packetLimit = 2;
  EXPECT_EQ(2, writePacketizationRequest(conn_, cid, packetLimit, *aead_));
  EXPECT_EQ(2, stream1->retransmissionBufMetas.size());
  EXPECT_EQ(0, stream2->retransmissionBufMetas.size());
  EXPECT_EQ(2, countInstructions(streamId1));
  EXPECT_EQ(0, countInstructions(streamId2));
  EXPECT_EQ(2, conn_.outstandings.packets.size());
  EXPECT_TRUE(verifyAllOutstandingsAreDSR());
}

TEST_F(WriteFunctionsTest, WriteTwoStreamsIncremental) {
  prepareFlowControlAndStreamLimit();
  auto streamId1 = prepareOneStream(2000);
  auto streamId2 = prepareOneStream(1000);
  auto stream1 = conn_.streamManager->findStream(streamId1);
  auto stream2 = conn_.streamManager->findStream(streamId2);
  conn_.streamManager->setStreamPriority(streamId1, Priority{3, true});
  conn_.streamManager->setStreamPriority(streamId2, Priority{3, true});
  // Pretend we sent the non DSR data on second stream
  stream2->ackedIntervals.insert(0, stream2->writeBuffer.chainLength() - 1);
  stream2->currentWriteOffset = stream2->writeBuffer.chainLength();
  stream2->writeBuffer.move();
  conn_.streamManager->updateWritableStreams(*stream2);
  auto cid = getTestConnectionId();
  size_t packetLimit = 2;
  EXPECT_EQ(2, writePacketizationRequest(conn_, cid, packetLimit, *aead_));
  EXPECT_EQ(1, stream1->retransmissionBufMetas.size());
  EXPECT_EQ(1, stream2->retransmissionBufMetas.size());
  EXPECT_EQ(1, countInstructions(streamId1));
  EXPECT_EQ(1, countInstructions(streamId2));
  EXPECT_EQ(2, conn_.outstandings.packets.size());
  EXPECT_TRUE(verifyAllOutstandingsAreDSR());
}

TEST_F(WriteFunctionsTest, LossAndFreshTwoInstructionsInTwoPackets) {
  prepareFlowControlAndStreamLimit();
  auto streamId = prepareOneStream(1000);
  auto stream = conn_.streamManager->findStream(streamId);
  // Pretend we sent the non DSR data
  stream->ackedIntervals.insert(0, stream->writeBuffer.chainLength() - 1);
  stream->currentWriteOffset = stream->writeBuffer.chainLength();
  stream->writeBuffer.move();
  conn_.streamManager->updateWritableStreams(*stream);
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
      streamId, bufMetaStartingOffset, 500, false, true, folly::none, 0);
  WriteStreamFrame expectedSecondFrame(
      streamId, 500 + bufMetaStartingOffset, 500, true, true, folly::none, 1);
  EXPECT_EQ(expectedFirstFrame, *packet1.frames[0].asWriteStreamFrame());
  EXPECT_EQ(expectedSecondFrame, *packet2.frames[0].asWriteStreamFrame());
}

TEST_F(
    WriteFunctionsTest,
    LossAndFreshTwoInstructionsInTwoPacketsNoFlowControl) {
  prepareFlowControlAndStreamLimit();
  auto streamId = prepareOneStream(1000);
  auto stream = conn_.streamManager->findStream(streamId);
  auto bufMetaStartingOffset = stream->writeBufMeta.offset;
  // Move part of the BufMetas to lossBufMetas
  auto split = stream->writeBufMeta.split(500);
  stream->lossBufMetas.push_back(split);
  conn_.streamManager->updateWritableStreams(*stream);
  // Zero out conn flow control.
  conn_.flowControlState.sumCurWriteOffset =
      conn_.flowControlState.peerAdvertisedMaxOffset;
  size_t packetLimit = 10;
  // Should only write lost data
  EXPECT_EQ(
      1,
      writePacketizationRequest(
          conn_, getTestConnectionId(), packetLimit, *aead_));
  EXPECT_EQ(1, countInstructions(streamId));
  ASSERT_EQ(1, conn_.outstandings.packets.size());
  auto& packet1 = conn_.outstandings.packets.front().packet;
  EXPECT_EQ(1, packet1.frames.size());
  WriteStreamFrame expectedFirstFrame(
      streamId, bufMetaStartingOffset, 500, false, true);
  EXPECT_EQ(expectedFirstFrame, *packet1.frames[0].asWriteStreamFrame());
}

} // namespace quic::test
