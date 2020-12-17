/*
 * Copyright (c) Facebook, Inc. and its affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 *
 */

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <quic/fizz/server/handshake/FizzServerQuicHandshakeContext.h>
#include <quic/server/state/ServerStateMachine.h>
#include <quic/state/QPRFunctions.h>

using namespace folly;
using namespace testing;

namespace quic {
namespace test {

class QPRFunctionsTest : public Test {
 public:
  QPRFunctionsTest()
      : conn(FizzServerQuicHandshakeContext::Builder().build()) {}

  void SetUp() override {
    conn.flowControlState.peerAdvertisedInitialMaxStreamOffsetBidiLocal =
        kDefaultStreamWindowSize;
    conn.flowControlState.peerAdvertisedInitialMaxStreamOffsetBidiRemote =
        kDefaultStreamWindowSize;
    conn.flowControlState.peerAdvertisedInitialMaxStreamOffsetUni =
        kDefaultStreamWindowSize;
    conn.flowControlState.peerAdvertisedMaxOffset =
        kDefaultConnectionWindowSize;
    conn.streamManager->setMaxLocalBidirectionalStreams(
        kDefaultMaxStreamsBidirectional);
    conn.streamManager->setMaxLocalUnidirectionalStreams(
        kDefaultMaxStreamsUnidirectional);
    conn.partialReliabilityEnabled = true;
  }

  QuicServerConnectionState conn;
};

TEST_F(QPRFunctionsTest, RecvExpiredStreamDataFrame) {
  // case1. sending only stream
  auto sendingOnlyStream =
      conn.streamManager->createNextUnidirectionalStream().value();
  ExpiredStreamDataFrame expiredStreamDataFrame(sendingOnlyStream->id, 10);
  EXPECT_THROW(
      onRecvExpiredStreamDataFrame(sendingOnlyStream, expiredStreamDataFrame),
      QuicTransportException);

  auto stream = conn.streamManager->createNextBidirectionalStream().value();
  stream->currentReceiveOffset = 100;
  expiredStreamDataFrame.streamId = stream->id;

  // case2. loss reordering
  expiredStreamDataFrame.minimumStreamOffset = 10;
  onRecvExpiredStreamDataFrame(stream, expiredStreamDataFrame);
  EXPECT_EQ(stream->currentReceiveOffset, 100);

  // case3. normal case
  stream->currentReadOffset = 100;
  stream->conn.flowControlState.sumCurReadOffset = 100;
  auto buf1 = IOBuf::copyBuffer("XXXXXXXXXX"); // 140-149
  StreamBuffer buffer{buf1->clone(), 140, false};
  stream->readBuffer.emplace_back(std::move(buffer));
  expiredStreamDataFrame.minimumStreamOffset = 145;
  onRecvExpiredStreamDataFrame(stream, expiredStreamDataFrame);
  EXPECT_EQ(stream->currentReceiveOffset, 145);
  EXPECT_EQ(stream->currentReadOffset, 145);
  EXPECT_FALSE(stream->readBuffer.empty());
  EXPECT_EQ(stream->readBuffer.front().offset, 145);
  EXPECT_EQ(stream->readBuffer.front().data.chainLength(), 5);
  EXPECT_EQ(stream->conn.flowControlState.sumCurReadOffset, 145);
}

TEST_F(QPRFunctionsTest, AdvanceMinimumRetransmittableOffset) {
  auto stream = conn.streamManager->createNextBidirectionalStream().value();

  // case 0. currentWriteOffset = 0, must be moved to 4.
  stream->currentWriteOffset = 0;
  auto result = advanceMinimumRetransmittableOffset(stream, 4);
  EXPECT_EQ(stream->currentWriteOffset, 4);
  EXPECT_TRUE(result.has_value());
  EXPECT_EQ(stream->minimumRetransmittableOffset, 4);

  // case1. minimumRetransmittableOffset to set is too small
  stream->minimumRetransmittableOffset = 10;
  result = advanceMinimumRetransmittableOffset(stream, 1);
  EXPECT_FALSE(result.has_value());
  EXPECT_EQ(stream->minimumRetransmittableOffset, 10);

  auto buf = folly::IOBuf::copyBuffer("aaaaaaaaaa");
  // case2. has no unacked data below 139
  stream->currentWriteOffset = 150;
  stream->retransmissionBuffer.emplace(
      140, std::make_unique<StreamBuffer>(buf->clone(), 140));
  result = advanceMinimumRetransmittableOffset(stream, 139);
  EXPECT_TRUE(result.has_value());
  EXPECT_EQ(*result, 139);
  EXPECT_EQ(stream->minimumRetransmittableOffset, 139);
  EXPECT_EQ(stream->conn.pendingEvents.frames.size(), 1);

  // case3. ExpiredStreamDataFrame is wired
  stream->minimumRetransmittableOffset = 139;
  stream->retransmissionBuffer.emplace(
      140, std::make_unique<StreamBuffer>(buf->clone(), 140));
  result = advanceMinimumRetransmittableOffset(stream, 150);
  EXPECT_TRUE(result.has_value());
  EXPECT_EQ(*result, 150);
  EXPECT_EQ(stream->conn.pendingEvents.frames.size(), 1);
  {
    ExpiredStreamDataFrame* expiredFrame =
        stream->conn.pendingEvents.frames[0].asExpiredStreamDataFrame();
    if (expiredFrame) {
      EXPECT_EQ(expiredFrame->minimumStreamOffset, 150);
    }
  }
  EXPECT_TRUE(stream->retransmissionBuffer.empty());

  // case4. update existing pending event.
  stream->minimumRetransmittableOffset = 150;
  stream->retransmissionBuffer.emplace(
      150, std::make_unique<StreamBuffer>(buf->clone(), 150));
  stream->conn.pendingEvents.frames.clear();
  stream->conn.pendingEvents.frames.emplace_back(
      ExpiredStreamDataFrame(stream->id, 160));
  result = advanceMinimumRetransmittableOffset(stream, 200);
  EXPECT_TRUE(result.has_value());
  EXPECT_EQ(*result, 200);
  EXPECT_EQ(stream->conn.pendingEvents.frames.size(), 1);
  {
    ExpiredStreamDataFrame* expiredFrame =
        stream->conn.pendingEvents.frames[0].asExpiredStreamDataFrame();
    if (expiredFrame) {
      EXPECT_EQ(expiredFrame->minimumStreamOffset, 200);
    }
  }
}

TEST_F(QPRFunctionsTest, RecvMinStreamDataFrame) {
  auto stream = conn.streamManager->createNextBidirectionalStream().value();

  // case1. invalid frame data
  MinStreamDataFrame maximumDataLessThanMinimumStreamOffset(stream->id, 5, 10);
  PacketNum packetNum(10);
  EXPECT_THROW(
      onRecvMinStreamDataFrame(
          stream, maximumDataLessThanMinimumStreamOffset, packetNum),
      QuicTransportException);

  // case2. offset is less than currentMinimumRetransmittableOffset
  MinStreamDataFrame offsetLessThanMinimumRetransmittableOffset(
      stream->id, 1000, 100);
  stream->minimumRetransmittableOffset = 1000;
  onRecvMinStreamDataFrame(
      stream, offsetLessThanMinimumRetransmittableOffset, packetNum);
  EXPECT_EQ(stream->minimumRetransmittableOffset, 1000);

  // case3. normal case
  stream->minimumRetransmittableOffset = 100;
  MinStreamDataFrame okMinStreamDataFrame(
      stream->id, stream->flowControlState.peerAdvertisedMaxOffset, 200);
  onRecvMinStreamDataFrame(stream, okMinStreamDataFrame, packetNum);
  EXPECT_EQ(stream->minimumRetransmittableOffset, 200);
}

TEST_F(QPRFunctionsTest, RecvMinStreamDataFrameShrinkBuffer) {
  // case 1. where we have enough bytes in writeBuffer to shrink
  auto stream = conn.streamManager->createNextBidirectionalStream().value();
  PacketNum packetNum(10);
  stream->minimumRetransmittableOffset = 100;
  stream->currentWriteOffset = 100;
  auto buf = folly::IOBuf::copyBuffer("aaaaaaaaaabbbbbbbbbb");
  stream->writeBuffer.append(std::move(buf));
  stream->conn.flowControlState.sumCurStreamBufferLen = 20;
  auto writtenBuffer = folly::IOBuf::copyBuffer("cccccccccc");
  stream->retransmissionBuffer.emplace(
      90, std::make_unique<StreamBuffer>(std::move(writtenBuffer), 90, false));
  MinStreamDataFrame shrinkMinStreamDataFrame(
      stream->id, stream->flowControlState.peerAdvertisedMaxOffset, 110);
  onRecvMinStreamDataFrame(stream, shrinkMinStreamDataFrame, packetNum);
  EXPECT_EQ(stream->minimumRetransmittableOffset, 110);
  EXPECT_EQ(stream->currentWriteOffset, 110);
  EXPECT_FALSE(stream->writeBuffer.empty());
  EXPECT_EQ(stream->writeBuffer.chainLength(), 10);
  EXPECT_TRUE(stream->retransmissionBuffer.empty());
  EXPECT_EQ(stream->conn.flowControlState.sumCurStreamBufferLen, 10);

  // case 2. where we skip beyond what we have in writeBuffer
  stream->minimumRetransmittableOffset = 100;
  stream->currentWriteOffset = 100;
  stream->writeBuffer.move();
  stream->conn.flowControlState.sumCurStreamBufferLen = 0;
  onRecvMinStreamDataFrame(stream, shrinkMinStreamDataFrame, packetNum);
  EXPECT_EQ(stream->minimumRetransmittableOffset, 110);
  EXPECT_EQ(stream->currentWriteOffset, 110);
  EXPECT_EQ(stream->conn.flowControlState.sumCurStreamBufferLen, 0);
}

TEST_F(QPRFunctionsTest, RecvMinStreamDataFrameOnUnidirectionalStream) {
  auto stream = conn.streamManager->createNextUnidirectionalStream().value();
  stream->sendState = StreamSendState::Closed;
  stream->recvState = StreamRecvState::Closed;
  PacketNum packetNum(10);
  MinStreamDataFrame frame(
      stream->id, stream->flowControlState.peerAdvertisedMaxOffset + 100, 100);
  EXPECT_THROW(
      onRecvMinStreamDataFrame(stream, frame, packetNum),
      QuicTransportException);
}

TEST_F(QPRFunctionsTest, AdvanceCurrentReceiveOffset) {
  auto stream = conn.streamManager->createNextBidirectionalStream().value();

  // case1. nothing happend
  stream->currentReadOffset = 10;
  stream->currentReceiveOffset = 10;
  auto result = advanceCurrentReceiveOffset(stream, 1);
  EXPECT_EQ(stream->currentReceiveOffset, 10);
  EXPECT_FALSE(result.has_value());

  // case2. MinStreamDataFrame is put on the wire
  stream->currentReadOffset = 10;
  stream->currentReceiveOffset = 10;
  result = advanceCurrentReceiveOffset(stream, 100);
  EXPECT_EQ(stream->conn.pendingEvents.frames.size(), 1);
  {
    MinStreamDataFrame* minStreamDataFrame =
        stream->conn.pendingEvents.frames[0].asMinStreamDataFrame();
    if (minStreamDataFrame) {
      EXPECT_EQ(minStreamDataFrame->minimumStreamOffset, 100);
    }
  }
  EXPECT_TRUE(result.has_value());
  EXPECT_EQ(*result, 100);

  // case3. update existing pending event
  stream->currentReadOffset = 100;
  stream->currentReceiveOffset = 100;
  stream->conn.pendingEvents.frames.clear();
  stream->conn.pendingEvents.frames.emplace_back(
      MinStreamDataFrame(stream->id, 100, 120));
  result = advanceCurrentReceiveOffset(stream, 150);
  EXPECT_EQ(stream->conn.pendingEvents.frames.size(), 1);
  {
    MinStreamDataFrame* minStreamDataFrame =
        stream->conn.pendingEvents.frames[0].asMinStreamDataFrame();
    if (minStreamDataFrame) {
      EXPECT_EQ(minStreamDataFrame->minimumStreamOffset, 150);
    }
  }
  EXPECT_TRUE(result.has_value());
  EXPECT_EQ(*result, 150);

  // case4. where offset was adjusted
  stream->currentReadOffset = 100;
  stream->currentReceiveOffset = 100;
  stream->finalReadOffset = folly::make_optional((uint64_t)120);
  result = advanceCurrentReceiveOffset(stream, 150);
  EXPECT_EQ(stream->conn.pendingEvents.frames.size(), 1);
  {
    MinStreamDataFrame* minStreamDataFrame =
        stream->conn.pendingEvents.frames[0].asMinStreamDataFrame();
    if (minStreamDataFrame) {
      EXPECT_EQ(minStreamDataFrame->minimumStreamOffset, 120);
    }
  }
  EXPECT_TRUE(result.has_value());
  EXPECT_EQ(*result, 120);
}

} // namespace test
} // namespace quic
