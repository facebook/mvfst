/*
 * Copyright (c) Facebook, Inc. and its affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 *
 */

#include <folly/portability/GTest.h>
#include <quic/common/test/TestUtils.h>
#include <quic/dsr/WriteFunctions.h>
#include <quic/dsr/test/Mocks.h>
#include <quic/fizz/server/handshake/FizzServerQuicHandshakeContext.h>
#include <quic/server/state/ServerStateMachine.h>
#include <quic/state/test/Mocks.h>

using namespace testing;

namespace quic::test {

class WriteFunctionsTest : public Test {
 public:
  WriteFunctionsTest()
      : conn_(FizzServerQuicHandshakeContext::Builder().build()),
        scheduler_(conn_),
        aead_(createNoOpAead()) {
    ON_CALL(sender_, addSendInstruction(_))
        .WillByDefault(Invoke([&](const SendInstruction&) {
          instructionCounter_++;
          return true;
        }));
    ON_CALL(sender_, flush()).WillByDefault(Return(true));
  }

 protected:
  void prepareFlowControlAndStreamLimit() {
    conn_.flowControlState.peerAdvertisedInitialMaxStreamOffsetBidiLocal =
        kDefaultStreamWindowSize;
    conn_.flowControlState.peerAdvertisedInitialMaxStreamOffsetBidiRemote =
        kDefaultStreamWindowSize;
    conn_.flowControlState.peerAdvertisedInitialMaxStreamOffsetUni =
        kDefaultStreamWindowSize;
    conn_.flowControlState.peerAdvertisedMaxOffset =
        kDefaultConnectionWindowSize;
    conn_.streamManager->setMaxLocalBidirectionalStreams(
        kDefaultMaxStreamsBidirectional);
    conn_.streamManager->setMaxLocalUnidirectionalStreams(
        kDefaultMaxStreamsUnidirectional);
  }

  StreamId prepareOneStream(size_t bufMetaLength = 1000) {
    conn_.streamManager->setMaxLocalBidirectionalStreams(
        kDefaultMaxStreamsBidirectional);
    conn_.streamManager->setMaxLocalUnidirectionalStreams(
        kDefaultMaxStreamsUnidirectional);
    auto id = conn_.streamManager->createNextBidirectionalStream().value()->id;
    auto stream = conn_.streamManager->findStream(id);
    writeDataToQuicStream(
        *stream,
        folly::IOBuf::copyBuffer("MetroCard Customer Claims"),
        false /* eof */);
    BufferMeta bufMeta(bufMetaLength);
    writeBufMetaToQuicStream(*stream, bufMeta, true /* eof */);
    return id;
  }

 protected:
  QuicServerConnectionState conn_;
  DSRStreamFrameScheduler scheduler_;
  std::unique_ptr<Aead> aead_;
  MockDSRPacketizationRequestSender sender_;
  size_t instructionCounter_{0};
};

TEST_F(WriteFunctionsTest, SchedulerNoData) {
  prepareFlowControlAndStreamLimit();
  ASSERT_FALSE(scheduler_.hasPendingData());
  auto cid = getTestConnectionId();
  size_t packetLimit = 20;
  EXPECT_EQ(
      0,
      writePacketizationRequest(
          conn_, scheduler_, cid, packetLimit, *aead_, sender_));
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
  EXPECT_EQ(
      0,
      writePacketizationRequest(
          conn_, scheduler_, cid, packetLimit, *aead_, sender_));
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
  EXPECT_EQ(
      0,
      writePacketizationRequest(
          conn_, scheduler_, cid, packetLimit, *aead_, sender_));
}

TEST_F(WriteFunctionsTest, WriteOne) {
  prepareFlowControlAndStreamLimit();
  auto streamId = prepareOneStream();
  auto cid = getTestConnectionId();
  auto stream = conn_.streamManager->findStream(streamId);
  auto currentBufMetaOffset = stream->writeBufMeta.offset;
  size_t packetLimit = 20;
  EXPECT_EQ(
      1,
      writePacketizationRequest(
          conn_, scheduler_, cid, packetLimit, *aead_, sender_));
  EXPECT_GT(stream->writeBufMeta.offset, currentBufMetaOffset);
  EXPECT_EQ(1, stream->retransmissionBufMetas.size());
  EXPECT_EQ(1, instructionCounter_);
}

TEST_F(WriteFunctionsTest, WriteTwoInstructions) {
  prepareFlowControlAndStreamLimit();
  auto streamId = prepareOneStream(2000);
  auto stream = conn_.streamManager->findStream(streamId);
  auto cid = getTestConnectionId();
  size_t packetLimit = 20;
  EXPECT_EQ(
      2,
      writePacketizationRequest(
          conn_, scheduler_, cid, packetLimit, *aead_, sender_));
  EXPECT_EQ(2, stream->retransmissionBufMetas.size());
  EXPECT_EQ(2, instructionCounter_);
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
  EXPECT_EQ(
      20,
      writePacketizationRequest(
          conn_, scheduler_, cid, packetLimit, *aead_, sender_));
  EXPECT_EQ(20, stream->retransmissionBufMetas.size());
  EXPECT_EQ(20, instructionCounter_);
}

TEST_F(WriteFunctionsTest, WriteTwoStreams) {
  prepareFlowControlAndStreamLimit();
  auto streamId1 = prepareOneStream(1000);
  auto streamId2 = prepareOneStream(1000);
  auto stream1 = conn_.streamManager->findStream(streamId1);
  auto stream2 = conn_.streamManager->findStream(streamId2);
  auto cid = getTestConnectionId();
  size_t packetLimit = 20;
  EXPECT_EQ(
      2,
      writePacketizationRequest(
          conn_, scheduler_, cid, packetLimit, *aead_, sender_));
  EXPECT_EQ(1, stream1->retransmissionBufMetas.size());
  EXPECT_EQ(1, stream2->retransmissionBufMetas.size());
  // TODO: This needs to be fixed later: The stream and the sender needs to be
  // 1:1 in the future. Then there will be two senders for this test case and
  // each of them will send out one instruction.
  EXPECT_EQ(2, instructionCounter_);
}} // namespace quic::test
