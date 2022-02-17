/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <quic/client/state/ClientStateMachine.h>
#include <quic/common/test/TestUtils.h>
#include <quic/flowcontrol/QuicFlowController.h>
#include <quic/state/test/MockQuicStats.h>

#include <gmock/gmock.h>
#include <gtest/gtest.h>

using namespace folly;
using namespace testing;

namespace quic {
namespace test {

class QuicFlowControlTest : public Test {
 public:
  void SetUp() override {
    quicStats_ = std::make_unique<MockQuicStats>();
    conn_.streamManager = std::make_unique<QuicStreamManager>(
        conn_, conn_.nodeType, conn_.transportSettings);
    conn_.statsCallback = quicStats_.get();
  }
  std::unique_ptr<MockQuicStats> quicStats_;
  QuicConnectionStateBase conn_{QuicNodeType::Client};
};

TEST_F(QuicFlowControlTest, MaybeSendConnWindowUpdate) {
  conn_.flowControlState.windowSize = 500;
  conn_.flowControlState.advertisedMaxOffset = 400;
  conn_.flowControlState.sumCurReadOffset = 100;

  // Should not send window update
  EXPECT_CALL(*quicStats_, onConnFlowControlUpdate()).Times(0);
  maybeSendConnWindowUpdate(conn_, Clock::now());
  EXPECT_FALSE(conn_.pendingEvents.connWindowUpdate);

  conn_.flowControlState.sumCurReadOffset += 200;
  // Should send window update
  EXPECT_CALL(*quicStats_, onConnFlowControlUpdate()).Times(1);
  maybeSendConnWindowUpdate(conn_, Clock::now());
  EXPECT_TRUE(conn_.pendingEvents.connWindowUpdate);
}

TEST_F(QuicFlowControlTest, MaybeSendConnWindowUpdateAndIncrease) {
  conn_.flowControlState.windowSize = 500;
  conn_.flowControlState.advertisedMaxOffset = 400;
  conn_.flowControlState.sumCurReadOffset = 100;
  conn_.transportSettings.autotuneReceiveConnFlowControl = true;

  conn_.lossState.srtt = 100us;
  conn_.flowControlState.timeOfLastFlowControlUpdate = Clock::now();

  // Should not send window update
  EXPECT_CALL(*quicStats_, onConnFlowControlUpdate()).Times(0);
  maybeSendConnWindowUpdate(
      conn_, *conn_.flowControlState.timeOfLastFlowControlUpdate + 10us);
  EXPECT_FALSE(conn_.pendingEvents.connWindowUpdate);
  EXPECT_EQ(conn_.flowControlState.windowSize, 500);

  conn_.flowControlState.sumCurReadOffset += 200;
  // Should send window update
  EXPECT_CALL(*quicStats_, onConnFlowControlUpdate()).Times(1);
  maybeSendConnWindowUpdate(
      conn_, *conn_.flowControlState.timeOfLastFlowControlUpdate + 10us);
  EXPECT_TRUE(conn_.pendingEvents.connWindowUpdate);
  EXPECT_EQ(conn_.flowControlState.windowSize, 1000);
}

TEST_F(QuicFlowControlTest, MaybeSendConnWindowUpdateAndNoIncrease) {
  conn_.flowControlState.windowSize = 500;
  conn_.flowControlState.advertisedMaxOffset = 400;
  conn_.flowControlState.sumCurReadOffset = 100;
  conn_.transportSettings.autotuneReceiveConnFlowControl = true;

  conn_.lossState.srtt = 100us;
  conn_.flowControlState.timeOfLastFlowControlUpdate = Clock::now();

  // Should not send window update
  EXPECT_CALL(*quicStats_, onConnFlowControlUpdate()).Times(0);
  maybeSendConnWindowUpdate(
      conn_, *conn_.flowControlState.timeOfLastFlowControlUpdate + 201us);
  EXPECT_FALSE(conn_.pendingEvents.connWindowUpdate);
  EXPECT_EQ(conn_.flowControlState.windowSize, 500);

  conn_.flowControlState.sumCurReadOffset += 200;
  // Should send window update
  EXPECT_CALL(*quicStats_, onConnFlowControlUpdate()).Times(1);
  maybeSendConnWindowUpdate(
      conn_, *conn_.flowControlState.timeOfLastFlowControlUpdate + 10us);
  EXPECT_TRUE(conn_.pendingEvents.connWindowUpdate);
  EXPECT_EQ(conn_.flowControlState.windowSize, 1000);
}

TEST_F(QuicFlowControlTest, MaybeSendConnWindowUpdateTimeElapsed) {
  conn_.flowControlState.windowSize = 500;
  conn_.flowControlState.advertisedMaxOffset = 400;
  conn_.flowControlState.sumCurReadOffset = 100;

  conn_.lossState.srtt = 100us;
  conn_.flowControlState.timeOfLastFlowControlUpdate = Clock::now();
  // Should not send window update
  EXPECT_CALL(*quicStats_, onConnFlowControlUpdate()).Times(0);
  // less than 2rtt passes
  maybeSendConnWindowUpdate(
      conn_, *conn_.flowControlState.timeOfLastFlowControlUpdate + 100us);
  EXPECT_FALSE(conn_.pendingEvents.connWindowUpdate);
  EXPECT_EQ(conn_.flowControlState.windowSize, 500);

  // Should send window update
  EXPECT_CALL(*quicStats_, onConnFlowControlUpdate()).Times(1);

  maybeSendConnWindowUpdate(
      conn_, *conn_.flowControlState.timeOfLastFlowControlUpdate + 300us);
  EXPECT_TRUE(conn_.pendingEvents.connWindowUpdate);
  EXPECT_EQ(conn_.flowControlState.windowSize, 500);
}

TEST_F(QuicFlowControlTest, DontSendConnFlowControlTwice) {
  conn_.flowControlState.windowSize = 500;
  conn_.flowControlState.advertisedMaxOffset = 400;
  conn_.flowControlState.sumCurReadOffset = 100;

  conn_.lossState.srtt = 100us;
  conn_.flowControlState.timeOfLastFlowControlUpdate = Clock::now();

  // Should send window update
  EXPECT_CALL(*quicStats_, onConnFlowControlUpdate()).Times(1);
  maybeSendConnWindowUpdate(
      conn_, *conn_.flowControlState.timeOfLastFlowControlUpdate + 300us);
  EXPECT_TRUE(conn_.pendingEvents.connWindowUpdate);
  maybeSendConnWindowUpdate(
      conn_, *conn_.flowControlState.timeOfLastFlowControlUpdate + 300us);
}

TEST_F(QuicFlowControlTest, NoStreamFlowControlUpdateOnTimeFlowUnchanged) {
  conn_.flowControlState.windowSize = 500;
  conn_.flowControlState.advertisedMaxOffset = 600;
  conn_.flowControlState.sumCurReadOffset = 100;

  conn_.lossState.srtt = 100us;
  conn_.flowControlState.timeOfLastFlowControlUpdate = Clock::now();
  EXPECT_CALL(*quicStats_, onConnFlowControlUpdate()).Times(0);

  maybeSendConnWindowUpdate(
      conn_, *conn_.flowControlState.timeOfLastFlowControlUpdate + 300us);
  EXPECT_FALSE(conn_.pendingEvents.connWindowUpdate);
}

TEST_F(QuicFlowControlTest, NoConnFlowControlUpdateOnTimeExpiredIfNotChanged) {
  conn_.flowControlState.windowSize = 500;
  conn_.flowControlState.advertisedMaxOffset = 600;
  conn_.flowControlState.sumCurReadOffset = 100;

  conn_.lossState.srtt = 100us;
  conn_.flowControlState.timeOfLastFlowControlUpdate = Clock::now();
  EXPECT_CALL(*quicStats_, onConnFlowControlUpdate()).Times(0);

  maybeSendConnWindowUpdate(
      conn_, *conn_.flowControlState.timeOfLastFlowControlUpdate + 300us);
  EXPECT_FALSE(conn_.pendingEvents.connWindowUpdate);
}

TEST_F(QuicFlowControlTest, MaybeSendConnWindowUpdateEnqueuesPendingEvent) {
  conn_.flowControlState.windowSize = 100;
  conn_.flowControlState.advertisedMaxOffset = 400;
  conn_.flowControlState.sumCurReadOffset = 301;

  EXPECT_CALL(*quicStats_, onConnFlowControlUpdate()).Times(0);
  maybeSendConnWindowUpdate(conn_, Clock::now());
  EXPECT_FALSE(conn_.pendingEvents.connWindowUpdate);

  conn_.flowControlState.windowSize = 500;
  EXPECT_CALL(*quicStats_, onConnFlowControlUpdate()).Times(1);
  maybeSendConnWindowUpdate(conn_, Clock::now());
  EXPECT_TRUE(conn_.pendingEvents.connWindowUpdate);
}

TEST_F(QuicFlowControlTest, GenerateMaxDataFrameChangeWindowSmaller) {
  conn_.flowControlState.windowSize = 500;
  conn_.flowControlState.advertisedMaxOffset = 400;
  conn_.flowControlState.sumCurReadOffset = 300;
  auto frame = generateMaxDataFrame(conn_);
  EXPECT_EQ(800, frame.maximumData);

  conn_.flowControlState.windowSize = 10;
  // change the read bytes to be within the maybeSendUpdate size of the previous
  // window
  conn_.flowControlState.sumCurReadOffset =
      conn_.flowControlState.advertisedMaxOffset - 15;

  // put within current window
  conn_.flowControlState.sumCurReadOffset =
      conn_.flowControlState.advertisedMaxOffset - 4;
  auto frame2 = generateMaxDataFrame(conn_);
  EXPECT_EQ(frame2.maximumData, conn_.flowControlState.sumCurReadOffset + 10);
}

TEST_F(QuicFlowControlTest, GenerateMaxDataFrameChangeWindowLarger) {
  conn_.flowControlState.windowSize = 500;
  conn_.flowControlState.advertisedMaxOffset = 400;
  conn_.flowControlState.sumCurReadOffset = 301;
  auto frame = generateMaxDataFrame(conn_);
  EXPECT_EQ(801, frame.maximumData);
  onConnWindowUpdateSent(conn_, frame.maximumData, Clock::now());
  EXPECT_EQ(801, conn_.flowControlState.advertisedMaxOffset);

  conn_.flowControlState.windowSize = 1001;
  auto frame2 = generateMaxDataFrame(conn_);
  EXPECT_EQ(1302, frame2.maximumData);
  onConnWindowUpdateSent(conn_, frame2.maximumData, Clock::now());
  EXPECT_EQ(
      frame2.maximumData,
      conn_.flowControlState.sumCurReadOffset +
          conn_.flowControlState.windowSize);
}

TEST_F(QuicFlowControlTest, MaybeSendStreamWindowUpdate) {
  StreamId id = 3;
  QuicStreamState stream(id, conn_);
  stream.currentReadOffset = 100;
  stream.flowControlState.windowSize = 500;
  stream.flowControlState.advertisedMaxOffset = 400;

  // Should not send window update
  EXPECT_CALL(*quicStats_, onStreamFlowControlUpdate()).Times(0);
  maybeSendStreamWindowUpdate(stream, Clock::now());
  EXPECT_FALSE(conn_.streamManager->pendingWindowUpdate(stream.id));

  EXPECT_CALL(*quicStats_, onStreamFlowControlUpdate()).Times(0);
  maybeSendStreamWindowUpdate(stream, Clock::now());
  stream.currentReadOffset += 200;
  // Should send window update
  EXPECT_CALL(*quicStats_, onStreamFlowControlUpdate()).Times(1);
  maybeSendStreamWindowUpdate(stream, Clock::now());
  EXPECT_TRUE(conn_.streamManager->pendingWindowUpdate(stream.id));
}

TEST_F(QuicFlowControlTest, MaybeSendStreamWindowUpdateTimeElapsed) {
  StreamId id = 3;
  QuicStreamState stream(id, conn_);
  stream.currentReadOffset = 100;
  stream.flowControlState.windowSize = 500;
  stream.flowControlState.advertisedMaxOffset = 400;

  conn_.lossState.srtt = 100us;
  stream.flowControlState.timeOfLastFlowControlUpdate = Clock::now();

  // Should not send window update
  EXPECT_CALL(*quicStats_, onStreamFlowControlUpdate()).Times(0);
  maybeSendStreamWindowUpdate(
      stream, *stream.flowControlState.timeOfLastFlowControlUpdate + 100us);
  EXPECT_FALSE(conn_.streamManager->pendingWindowUpdate(stream.id));

  EXPECT_CALL(*quicStats_, onStreamFlowControlUpdate()).Times(1);
  maybeSendStreamWindowUpdate(
      stream, *stream.flowControlState.timeOfLastFlowControlUpdate + 300us);
  EXPECT_TRUE(conn_.streamManager->pendingWindowUpdate(stream.id));
}

TEST_F(QuicFlowControlTest, DontSendStreamWindowUpdateTwice) {
  StreamId id = 3;
  QuicStreamState stream(id, conn_);
  stream.currentReadOffset = 100;
  stream.flowControlState.windowSize = 500;
  stream.flowControlState.advertisedMaxOffset = 400;

  conn_.lossState.srtt = 100us;
  stream.flowControlState.timeOfLastFlowControlUpdate = Clock::now();

  EXPECT_CALL(*quicStats_, onStreamFlowControlUpdate()).Times(1);
  maybeSendStreamWindowUpdate(
      stream, *stream.flowControlState.timeOfLastFlowControlUpdate + 300us);
  EXPECT_TRUE(conn_.streamManager->pendingWindowUpdate(stream.id));
  maybeSendStreamWindowUpdate(
      stream, *stream.flowControlState.timeOfLastFlowControlUpdate + 300us);
}

TEST_F(QuicFlowControlTest, DontSendStreamWindowUpdateOnRemoteHalfClosed) {
  StreamId id = 3;
  QuicStreamState stream(id, conn_);
  stream.sendState = StreamSendState::Open;
  stream.recvState = StreamRecvState::Closed;
  // Should not send window update
  maybeSendStreamWindowUpdate(stream, Clock::now());
  EXPECT_FALSE(conn_.streamManager->pendingWindowUpdate(stream.id));
}

TEST_F(QuicFlowControlTest, MaybeSendStreamWindowUpdateChangeWindowSmaller) {
  StreamId id = 3;
  QuicStreamState stream(id, conn_);
  stream.currentReadOffset = 300;
  stream.flowControlState.windowSize = 500;
  stream.flowControlState.advertisedMaxOffset = 400;

  // Should not send window update
  EXPECT_CALL(*quicStats_, onStreamFlowControlUpdate()).Times(1);
  maybeSendStreamWindowUpdate(stream, Clock::now());
  ASSERT_TRUE(conn_.streamManager->pendingWindowUpdate(stream.id));
  auto sendTime = Clock::now();
  onStreamWindowUpdateSent(
      stream, generateMaxStreamDataFrame(stream).maximumData, sendTime);

  stream.flowControlState.windowSize = 10;
  // change the read bytes to be within the maybeSendUpdate size of the previous
  // window
  stream.currentReadOffset = stream.flowControlState.advertisedMaxOffset - 15;
  // Should send window update
  EXPECT_CALL(*quicStats_, onStreamFlowControlUpdate()).Times(1);
  maybeSendStreamWindowUpdate(stream, sendTime);
  EXPECT_FALSE(conn_.streamManager->pendingWindowUpdate(stream.id));

  // put within current window
  stream.currentReadOffset = stream.flowControlState.advertisedMaxOffset - 4;
  maybeSendStreamWindowUpdate(stream, sendTime);
  EXPECT_EQ(
      generateMaxStreamDataFrame(stream).maximumData,
      stream.currentReadOffset + 10);
}

TEST_F(QuicFlowControlTest, MaybeWriteBlockedAfterAPIWrite) {
  StreamId id = 3;
  QuicStreamState stream(id, conn_);
  stream.currentWriteOffset = 200;
  stream.flowControlState.peerAdvertisedMaxOffset = 400;

  EXPECT_CALL(*quicStats_, onStreamFlowControlBlocked()).Times(0);
  maybeWriteBlockAfterAPIWrite(stream);
  EXPECT_FALSE(conn_.streamManager->hasBlocked());

  stream.currentWriteOffset = 400;
  stream.writeBuffer.append(IOBuf::copyBuffer("1234"));
  EXPECT_CALL(*quicStats_, onStreamFlowControlBlocked()).Times(0);
  maybeWriteBlockAfterAPIWrite(stream);
  EXPECT_FALSE(conn_.streamManager->hasBlocked());

  stream.writeBuffer.move();
  stream.currentWriteOffset = 600;
  stream.flowControlState.peerAdvertisedMaxOffset = 600;
  EXPECT_CALL(*quicStats_, onStreamFlowControlBlocked()).Times(1);
  maybeWriteBlockAfterAPIWrite(stream);
  EXPECT_TRUE(conn_.streamManager->hasBlocked());
}

TEST_F(QuicFlowControlTest, MaybeWriteBlockedAfterSocketWrite) {
  StreamId id = 3;
  QuicStreamState stream(id, conn_);
  stream.currentWriteOffset = 200;
  stream.flowControlState.peerAdvertisedMaxOffset = 400;

  maybeWriteBlockAfterSocketWrite(stream);
  EXPECT_FALSE(conn_.streamManager->hasBlocked());

  // Don't add a blocked if there is nothing to write even the stream is
  // flow control limited.
  stream.currentWriteOffset = 400;
  maybeWriteBlockAfterSocketWrite(stream);
  EXPECT_CALL(*quicStats_, onStreamFlowControlBlocked()).Times(0);
  EXPECT_FALSE(conn_.streamManager->hasBlocked());

  // Now write something
  stream.writeBuffer.append(IOBuf::copyBuffer("1234"));
  EXPECT_CALL(*quicStats_, onStreamFlowControlBlocked()).Times(1);
  maybeWriteBlockAfterSocketWrite(stream);
  EXPECT_TRUE(conn_.streamManager->hasBlocked());

  // No block if everything till FIN has been sent
  conn_.streamManager->removeBlocked(id);
  EXPECT_FALSE(conn_.streamManager->hasBlocked());
  stream.finalWriteOffset =
      stream.currentWriteOffset + stream.writeBuffer.chainLength();
  stream.currentWriteOffset = *stream.finalWriteOffset + 1;
  maybeWriteBlockAfterSocketWrite(stream);
  EXPECT_FALSE(conn_.streamManager->hasBlocked());
}

TEST_F(QuicFlowControlTest, MaybeSendStreamWindowUpdateChangeWindowLarger) {
  StreamId id = 3;
  QuicStreamState stream(id, conn_);
  stream.currentReadOffset = 301;
  stream.flowControlState.windowSize = 500;
  stream.flowControlState.advertisedMaxOffset = 400;

  // Should not send window update
  EXPECT_CALL(*quicStats_, onStreamFlowControlUpdate()).Times(1);
  maybeSendStreamWindowUpdate(stream, Clock::now());
  EXPECT_TRUE(conn_.streamManager->pendingWindowUpdate(stream.id));
  onStreamWindowUpdateSent(
      stream, generateMaxStreamDataFrame(stream).maximumData, Clock::now());
  EXPECT_FALSE(conn_.streamManager->pendingWindowUpdate(stream.id));

  stream.flowControlState.windowSize = 1001;
  // Should send window update
  EXPECT_CALL(*quicStats_, onStreamFlowControlUpdate()).Times(1);
  maybeSendStreamWindowUpdate(stream, Clock::now());
  EXPECT_EQ(
      generateMaxStreamDataFrame(stream).maximumData,
      stream.currentReadOffset + stream.flowControlState.windowSize);
}

TEST_F(QuicFlowControlTest, SendingConnectionWindowUpdate) {
  conn_.flowControlState.windowSize = 500;
  conn_.flowControlState.advertisedMaxOffset = 400;
  conn_.flowControlState.sumCurReadOffset = 300;

  // Should send window update
  EXPECT_CALL(*quicStats_, onConnFlowControlUpdate()).Times(1);
  maybeSendConnWindowUpdate(conn_, Clock::now());
  EXPECT_TRUE(conn_.pendingEvents.connWindowUpdate);
  auto frameOffset = generateMaxDataFrame(conn_).maximumData;
  EXPECT_EQ(800, frameOffset);

  // Clear out the window update.
  auto sendTime = Clock::now();
  onConnWindowUpdateSent(conn_, frameOffset, sendTime);
  EXPECT_FALSE(conn_.pendingEvents.connWindowUpdate);
  EXPECT_EQ(conn_.flowControlState.advertisedMaxOffset, frameOffset);
  EXPECT_EQ(*conn_.flowControlState.timeOfLastFlowControlUpdate, sendTime);
}

TEST_F(QuicFlowControlTest, SendingStreamWindowUpdate) {
  StreamId id = 3;
  QuicStreamState stream(id, conn_);
  stream.currentReadOffset = 300;
  stream.flowControlState.windowSize = 500;
  stream.flowControlState.advertisedMaxOffset = 400;

  // Should send window update
  EXPECT_CALL(*quicStats_, onStreamFlowControlUpdate()).Times(1);
  maybeSendStreamWindowUpdate(stream, Clock::now());
  EXPECT_TRUE(conn_.streamManager->pendingWindowUpdate(stream.id));
  auto frameOffset = generateMaxStreamDataFrame(stream).maximumData;
  EXPECT_EQ(800, frameOffset);

  auto sendTime = Clock::now();
  onStreamWindowUpdateSent(stream, frameOffset, sendTime);
  EXPECT_FALSE(conn_.streamManager->pendingWindowUpdate(stream.id));
  EXPECT_EQ(stream.flowControlState.advertisedMaxOffset, frameOffset);
  EXPECT_EQ(*stream.flowControlState.timeOfLastFlowControlUpdate, sendTime);
}

TEST_F(QuicFlowControlTest, LostConnectionWindowUpdate) {
  conn_.flowControlState.windowSize = 500;
  conn_.flowControlState.advertisedMaxOffset = 400;
  conn_.flowControlState.sumCurReadOffset = 300;

  onConnWindowUpdateLost(conn_);
  EXPECT_TRUE(conn_.pendingEvents.connWindowUpdate);
  EXPECT_EQ(generateMaxDataFrame(conn_).maximumData, 500 + 300);
}

TEST_F(QuicFlowControlTest, LostConnectionWindowUpdateSmallerWindow) {
  conn_.flowControlState.windowSize = 10;
  conn_.flowControlState.advertisedMaxOffset = 400;
  conn_.flowControlState.sumCurReadOffset = 300;

  onConnWindowUpdateLost(conn_);
  ASSERT_TRUE(conn_.pendingEvents.connWindowUpdate);
  EXPECT_EQ(generateMaxDataFrame(conn_).maximumData, 400);
}

TEST_F(QuicFlowControlTest, LostStreamWindowUpdate) {
  StreamId id = 3;
  QuicStreamState stream(id, conn_);
  stream.currentReadOffset = 300;
  stream.flowControlState.windowSize = 500;
  stream.flowControlState.advertisedMaxOffset = 400;

  // Should send window update
  onStreamWindowUpdateLost(stream);
  EXPECT_EQ(generateMaxStreamDataFrame(stream).maximumData, 500 + 300);
}

TEST_F(QuicFlowControlTest, LostStreamWindowUpdateHalfClosedRemote) {
  StreamId id = 3;
  QuicStreamState stream(id, conn_);
  stream.currentReadOffset = 300;
  stream.flowControlState.windowSize = 500;
  stream.flowControlState.advertisedMaxOffset = 400;
  stream.sendState = StreamSendState::Open;
  stream.recvState = StreamRecvState::Closed;

  // Should not send window update
  onStreamWindowUpdateLost(stream);
  EXPECT_FALSE(conn_.streamManager->pendingWindowUpdate(stream.id));
}

TEST_F(QuicFlowControlTest, LostStreamWindowUpdateSmallerWindow) {
  StreamId id = 3;
  QuicStreamState stream(id, conn_);
  stream.currentReadOffset = 300;
  stream.flowControlState.windowSize = 10;
  stream.flowControlState.advertisedMaxOffset = 400;

  // Should send window update
  onStreamWindowUpdateLost(stream);
  EXPECT_EQ(generateMaxStreamDataFrame(stream).maximumData, 400);
}

TEST_F(QuicFlowControlTest, HandleConnBlocked) {
  conn_.flowControlState.windowSize = 500;
  conn_.flowControlState.advertisedMaxOffset = 400;
  conn_.flowControlState.sumCurReadOffset = 300;

  handleConnBlocked(conn_);
  EXPECT_TRUE(conn_.pendingEvents.connWindowUpdate);
  EXPECT_EQ(generateMaxDataFrame(conn_).maximumData, 500 + 300);
}

TEST_F(QuicFlowControlTest, HandleConnBlockedSmallerWindow) {
  conn_.flowControlState.windowSize = 10;
  conn_.flowControlState.advertisedMaxOffset = 400;
  conn_.flowControlState.sumCurReadOffset = 300;

  handleConnBlocked(conn_);
  EXPECT_TRUE(conn_.pendingEvents.connWindowUpdate);
  EXPECT_EQ(generateMaxDataFrame(conn_).maximumData, 400);
}

TEST_F(QuicFlowControlTest, HandleStreamBlocked) {
  StreamId id = 3;
  QuicStreamState stream(id, conn_);
  stream.currentReadOffset = 300;
  stream.flowControlState.windowSize = 500;
  stream.flowControlState.advertisedMaxOffset = 400;

  handleStreamBlocked(stream);
  EXPECT_EQ(generateMaxStreamDataFrame(stream).maximumData, 500 + 300);
}

TEST_F(QuicFlowControlTest, HandleStreamBlockedSmallerWindow) {
  StreamId id = 3;
  QuicStreamState stream(id, conn_);
  stream.currentReadOffset = 300;
  stream.flowControlState.windowSize = 10;
  stream.flowControlState.advertisedMaxOffset = 400;

  handleStreamBlocked(stream);
  EXPECT_EQ(generateMaxStreamDataFrame(stream).maximumData, 400);
}

TEST_F(QuicFlowControlTest, UpdateFlowControlOnStreamData) {
  conn_.flowControlState.sumMaxObservedOffset = 550;
  conn_.flowControlState.sumCurReadOffset = 200;
  conn_.flowControlState.windowSize = 400;
  conn_.flowControlState.advertisedMaxOffset = 600;
  StreamId id = 3;
  QuicStreamState stream(id, conn_);
  stream.currentReadOffset = 150;
  stream.maxOffsetObserved = 200;
  stream.flowControlState.windowSize = 100;
  stream.flowControlState.advertisedMaxOffset = 250;

  auto data1 = buildRandomInputData(10);
  uint64_t buffer1EndOffset = 200 + data1->computeChainDataLength();
  updateFlowControlOnStreamData(
      stream, stream.maxOffsetObserved, buffer1EndOffset);
  EXPECT_EQ(conn_.flowControlState.sumMaxObservedOffset, 560);
}

TEST_F(QuicFlowControlTest, UpdateFlowControlOnStreamDataUnchangedOffset) {
  conn_.flowControlState.sumMaxObservedOffset = 550;
  conn_.flowControlState.sumCurReadOffset = 200;
  conn_.flowControlState.windowSize = 400;
  conn_.flowControlState.advertisedMaxOffset = 600;
  StreamId id = 3;
  QuicStreamState stream(id, conn_);
  stream.currentReadOffset = 150;
  stream.maxOffsetObserved = 200;
  stream.flowControlState.windowSize = 100;
  stream.flowControlState.advertisedMaxOffset = 250;

  uint64_t buffer1EndOffset = 100;
  updateFlowControlOnStreamData(
      stream, stream.maxOffsetObserved, buffer1EndOffset);
  EXPECT_EQ(stream.maxOffsetObserved, 200);
  EXPECT_EQ(conn_.flowControlState.sumMaxObservedOffset, 550);
}

TEST_F(QuicFlowControlTest, UpdateBadFlowControlOnStreamData) {
  conn_.flowControlState.sumMaxObservedOffset = 550;
  conn_.flowControlState.sumCurReadOffset = 200;
  conn_.flowControlState.windowSize = 400;
  conn_.flowControlState.advertisedMaxOffset = 600;
  StreamId id = 3;
  QuicStreamState stream(id, conn_);
  stream.currentReadOffset = 150;
  stream.maxOffsetObserved = 200;
  stream.flowControlState.windowSize = 100;
  stream.flowControlState.advertisedMaxOffset = 250;

  auto data1 = buildRandomInputData(100);
  uint64_t buffer1EndOffset = 200 + data1->computeChainDataLength();
  // Stream flow control violation
  EXPECT_THROW(
      updateFlowControlOnStreamData(
          stream, stream.maxOffsetObserved, buffer1EndOffset),
      QuicTransportException);

  stream.currentReadOffset = 200;
  // Connection flow control violation
  EXPECT_THROW(
      updateFlowControlOnStreamData(
          stream, stream.maxOffsetObserved, buffer1EndOffset),
      QuicTransportException);

  auto data2 = buildRandomInputData(50);
  uint64_t buffer2EndOffset = 200 + data2->computeChainDataLength();
  EXPECT_NO_THROW(updateFlowControlOnStreamData(
      stream, stream.maxOffsetObserved, buffer2EndOffset));
  EXPECT_EQ(conn_.flowControlState.sumMaxObservedOffset, 600);
}

TEST_F(QuicFlowControlTest, UpdateFlowControlOnRead) {
  auto qLogger = std::make_shared<FileQLogger>(VantagePoint::Client);
  conn_.qLogger = qLogger;

  StreamId id = 3;
  QuicStreamState stream(id, conn_);
  stream.currentReadOffset = 200;
  stream.flowControlState.windowSize = 200;
  stream.flowControlState.advertisedMaxOffset = 250;

  conn_.flowControlState.windowSize = 500;
  conn_.flowControlState.advertisedMaxOffset = 400;
  conn_.flowControlState.sumCurReadOffset = 100;
  EXPECT_CALL(*quicStats_, onConnFlowControlUpdate());
  EXPECT_CALL(*quicStats_, onStreamFlowControlUpdate());
  updateFlowControlOnRead(stream, 100, Clock::now());
  EXPECT_EQ(conn_.flowControlState.sumCurReadOffset, 200);

  EXPECT_TRUE(conn_.streamManager->pendingWindowUpdate(stream.id));
  EXPECT_EQ(generateMaxStreamDataFrame(stream).maximumData, 400);

  std::vector<int> indices =
      getQLogEventIndices(QLogEventType::TransportStateUpdate, qLogger);
  EXPECT_EQ(indices.size(), 1);
  auto tmp = std::move(qLogger->logs[indices[0]]);
  auto event = dynamic_cast<QLogTransportStateUpdateEvent*>(tmp.get());
  EXPECT_EQ(event->update, getFlowControlEvent(700));
}

TEST_F(QuicFlowControlTest, UpdateFlowControlOnWrite) {
  StreamId id = 3;
  QuicStreamState stream(id, conn_);
  stream.currentWriteOffset = 200;
  stream.flowControlState.peerAdvertisedMaxOffset = 300;

  conn_.flowControlState.sumCurWriteOffset = 200;
  EXPECT_CALL(*quicStats_, onConnFlowControlBlocked()).Times(0);
  updateFlowControlOnWriteToStream(stream, 100);
  EXPECT_EQ(conn_.flowControlState.sumCurStreamBufferLen, 100);
  EXPECT_CALL(*quicStats_, onConnFlowControlBlocked()).Times(0);
  updateFlowControlOnWriteToSocket(stream, 100);
  EXPECT_EQ(conn_.flowControlState.sumCurWriteOffset, 300);
  EXPECT_EQ(conn_.flowControlState.sumCurStreamBufferLen, 0);

  EXPECT_FALSE(conn_.streamManager->flowControlUpdatedContains(id));

  stream.currentWriteOffset = 300;
  EXPECT_CALL(*quicStats_, onConnFlowControlBlocked()).Times(0);
  updateFlowControlOnWriteToStream(stream, 100);
  EXPECT_EQ(conn_.flowControlState.sumCurStreamBufferLen, 100);

  EXPECT_CALL(*quicStats_, onConnFlowControlBlocked()).Times(0);
  updateFlowControlOnWriteToSocket(stream, 100);
  EXPECT_EQ(conn_.flowControlState.sumCurStreamBufferLen, 0);
  EXPECT_EQ(conn_.flowControlState.sumCurWriteOffset, 400);
  EXPECT_FALSE(conn_.streamManager->flowControlUpdatedContains(id));

  conn_.flowControlState.peerAdvertisedMaxOffset = 500;
  conn_.flowControlState.sumCurStreamBufferLen = 100;
  stream.flowControlState.peerAdvertisedMaxOffset = 600;
  EXPECT_CALL(*quicStats_, onConnFlowControlBlocked()).Times(1);
  updateFlowControlOnWriteToSocket(stream, 100);
}

TEST_F(QuicFlowControlTest, UpdateFlowControlOnWriteToStream) {
  StreamId id = 3;
  QuicStreamState stream(id, conn_);

  stream.currentWriteOffset = 200;
  conn_.flowControlState.sumCurStreamBufferLen = 100;
  stream.flowControlState.peerAdvertisedMaxOffset = 300;

  updateFlowControlOnWriteToStream(stream, 100);
  EXPECT_EQ(conn_.flowControlState.sumCurStreamBufferLen, 200);

  updateFlowControlOnWriteToSocket(stream, 150);
  EXPECT_EQ(conn_.flowControlState.sumCurStreamBufferLen, 50);

  updateFlowControlOnWriteToStream(stream, 100);
  EXPECT_EQ(conn_.flowControlState.sumCurStreamBufferLen, 150);
}

TEST_F(QuicFlowControlTest, HandleStreamWindowUpdate) {
  StreamId id = 3;
  QuicStreamState stream(id, conn_);
  stream.flowControlState.peerAdvertisedMaxOffset = 200;
  auto qLogger = std::make_shared<FileQLogger>(VantagePoint::Client);
  conn_.qLogger = qLogger;

  handleStreamWindowUpdate(stream, 300, 2);
  EXPECT_EQ(stream.flowControlState.peerAdvertisedMaxOffset, 300);
  ASSERT_TRUE(conn_.streamManager->flowControlUpdatedContains(stream.id));

  conn_.streamManager->removeFlowControlUpdated(stream.id);

  handleStreamWindowUpdate(stream, 200, 1);
  EXPECT_EQ(stream.flowControlState.peerAdvertisedMaxOffset, 300);
  ASSERT_FALSE(conn_.streamManager->flowControlUpdatedContains(stream.id));

  EXPECT_NO_THROW(handleStreamWindowUpdate(stream, 200, 3));
  EXPECT_EQ(stream.flowControlState.peerAdvertisedMaxOffset, 300);

  std::vector<int> indices =
      getQLogEventIndices(QLogEventType::TransportStateUpdate, qLogger);
  EXPECT_EQ(indices.size(), 1);
  auto tmp = std::move(qLogger->logs[indices[0]]);
  auto event = dynamic_cast<QLogTransportStateUpdateEvent*>(tmp.get());
  EXPECT_EQ(event->update, getRxStreamWU(id, 2, 300));
}

TEST_F(QuicFlowControlTest, HandleConnWindowUpdate) {
  conn_.flowControlState.peerAdvertisedMaxOffset = 200;
  MaxDataFrame update1(300);
  handleConnWindowUpdate(conn_, update1, 2);
  EXPECT_EQ(conn_.flowControlState.peerAdvertisedMaxOffset, 300);

  MaxDataFrame update2(200);
  handleConnWindowUpdate(conn_, update2, 1);
  EXPECT_EQ(conn_.flowControlState.peerAdvertisedMaxOffset, 300);

  MaxDataFrame update3(200);
  EXPECT_NO_THROW(handleConnWindowUpdate(conn_, update3, 3));
  EXPECT_EQ(conn_.flowControlState.peerAdvertisedMaxOffset, 300);
}

TEST_F(QuicFlowControlTest, WritableList) {
  StreamId id = 3;
  QuicStreamState stream(id, conn_);
  stream.currentWriteOffset = 100;
  stream.flowControlState.peerAdvertisedMaxOffset = 200;

  conn_.streamManager->updateWritableStreams(stream);
  EXPECT_FALSE(writableContains(*conn_.streamManager, id));

  auto buf = IOBuf::create(100);
  buf->append(100);
  writeDataToQuicStream(stream, std::move(buf), false);
  conn_.streamManager->updateWritableStreams(stream);
  EXPECT_TRUE(writableContains(*conn_.streamManager, id));

  // Flow control
  stream.flowControlState.peerAdvertisedMaxOffset = stream.currentWriteOffset;
  conn_.streamManager->updateWritableStreams(stream);
  EXPECT_FALSE(writableContains(*conn_.streamManager, id));

  // Fin
  writeDataToQuicStream(stream, nullptr, true);
  stream.writeBuffer.move();
  stream.currentWriteOffset += 100;
  stream.flowControlState.peerAdvertisedMaxOffset = stream.currentWriteOffset;
  conn_.streamManager->updateWritableStreams(stream);
  EXPECT_TRUE(writableContains(*conn_.streamManager, id));

  // After Fin
  stream.currentWriteOffset++;
  conn_.streamManager->updateWritableStreams(stream);
  EXPECT_FALSE(writableContains(*conn_.streamManager, id));
}

TEST_F(QuicFlowControlTest, GetSendStreamFlowControlBytes) {
  StreamId id = 3;
  QuicStreamState stream(id, conn_);
  stream.flowControlState.peerAdvertisedMaxOffset = 300;
  stream.currentWriteOffset = 200;
  EXPECT_EQ(100, getSendStreamFlowControlBytesWire(stream));
}

TEST_F(QuicFlowControlTest, GetSendStreamFlowControlBytesAPIEmpty) {
  StreamId id = 3;
  QuicStreamState stream(id, conn_);
  auto buf = IOBuf::create(200);
  buf->append(200);

  stream.writeBuffer.append(std::move(buf));

  stream.flowControlState.peerAdvertisedMaxOffset = 300;
  stream.currentWriteOffset = 200;
  EXPECT_EQ(getSendStreamFlowControlBytesAPI(stream), 0);
}

TEST_F(QuicFlowControlTest, GetSendStreamFlowControlBytesAPIPartial) {
  StreamId id = 3;
  QuicStreamState stream(id, conn_);
  auto buf = IOBuf::create(200);
  buf->append(200);

  stream.writeBuffer.append(std::move(buf));

  stream.flowControlState.peerAdvertisedMaxOffset = 500;
  stream.currentWriteOffset = 200;
  EXPECT_EQ(getSendStreamFlowControlBytesAPI(stream), 100);
}

TEST_F(QuicFlowControlTest, GetSendConnFlowControlBytes) {
  conn_.flowControlState.sumCurWriteOffset = 200;
  conn_.flowControlState.peerAdvertisedMaxOffset = 200;
  EXPECT_EQ(0, getSendConnFlowControlBytesWire(conn_));

  conn_.flowControlState.sumCurWriteOffset = 100;
  conn_.flowControlState.peerAdvertisedMaxOffset = 200;
  EXPECT_EQ(100, getSendConnFlowControlBytesWire(conn_));
}

TEST_F(QuicFlowControlTest, GetSendConnFlowControlBytesAPI) {
  StreamId id = 3;
  QuicStreamState stream(id, conn_);

  conn_.flowControlState.sumCurWriteOffset = 200;
  conn_.flowControlState.peerAdvertisedMaxOffset = 400;
  conn_.flowControlState.sumCurStreamBufferLen = 200;

  EXPECT_EQ(getSendConnFlowControlBytesAPI(conn_), 0);

  conn_.flowControlState.sumCurStreamBufferLen = 300;
  EXPECT_EQ(getSendConnFlowControlBytesAPI(conn_), 0);

  conn_.flowControlState.sumCurStreamBufferLen = 100;
  EXPECT_EQ(getSendConnFlowControlBytesAPI(conn_), 100);
}

TEST_F(QuicFlowControlTest, GetRecvConnFlowControlBytes) {
  conn_.flowControlState.sumCurReadOffset = 200;
  conn_.flowControlState.advertisedMaxOffset = 300;
  EXPECT_EQ(100, getRecvConnFlowControlBytes(conn_));

  conn_.flowControlState.sumCurReadOffset = 200;
  conn_.flowControlState.advertisedMaxOffset = 200;
  EXPECT_EQ(0, getRecvConnFlowControlBytes(conn_));
}

TEST_F(QuicFlowControlTest, GetRecvStreamFlowControlBytes) {
  StreamId id = 3;
  QuicStreamState stream(id, conn_);
  stream.currentReadOffset = 200;
  stream.flowControlState.advertisedMaxOffset = 300;
  EXPECT_EQ(100, getRecvStreamFlowControlBytes(stream));

  stream.currentReadOffset = 200;
  stream.flowControlState.advertisedMaxOffset = 200;
  EXPECT_EQ(0, getRecvStreamFlowControlBytes(stream));

  // Current read offset can be greater than advertised max offset, since
  // that's how we account for whether or not we read the eof.
  stream.currentReadOffset = 201;
  stream.flowControlState.advertisedMaxOffset = 200;
  EXPECT_EQ(0, getRecvStreamFlowControlBytes(stream));
}

TEST_F(QuicFlowControlTest, OnConnWindowUpdateSentWithoutPendingEvent) {
  EXPECT_FALSE(conn_.pendingEvents.connWindowUpdate);
  conn_.flowControlState.windowSize = 1000;
  conn_.flowControlState.advertisedMaxOffset = 0;
  conn_.flowControlState.sumCurReadOffset = 0;
  onConnWindowUpdateSent(conn_, 1000, Clock::now());
  EXPECT_EQ(1000, conn_.flowControlState.advertisedMaxOffset);
  EXPECT_FALSE(conn_.pendingEvents.connWindowUpdate);
}

TEST_F(QuicFlowControlTest, OnStreamWindowUpdateSentWithoutPendingEvent) {
  StreamId id = 4;
  QuicStreamState stream(id, conn_);
  stream.currentReadOffset = 0;
  stream.flowControlState.advertisedMaxOffset = 0;
  stream.flowControlState.windowSize = 1000;
  onStreamWindowUpdateSent(stream, 1000, Clock::now());
  EXPECT_EQ(1000, stream.flowControlState.advertisedMaxOffset);
  EXPECT_FALSE(conn_.streamManager->pendingWindowUpdate(id));
}

TEST_F(QuicFlowControlTest, StreamFlowControlWithBufMeta) {
  StreamId id = 0;
  QuicStreamState stream(id, conn_);
  stream.flowControlState.peerAdvertisedMaxOffset = 1000;
  stream.currentWriteOffset = 200;
  stream.writeBuffer.append(buildRandomInputData(100));
  EXPECT_EQ(800, getSendStreamFlowControlBytesWire(stream));
  EXPECT_EQ(700, getSendStreamFlowControlBytesAPI(stream));

  stream.writeBufMeta.offset =
      stream.currentWriteOffset + stream.writeBuffer.chainLength();
  stream.writeBufMeta.length = 300;
  EXPECT_EQ(800, getSendStreamFlowControlBytesWire(stream));
  EXPECT_EQ(400, getSendStreamFlowControlBytesAPI(stream));

  stream.currentWriteOffset += stream.writeBuffer.chainLength();
  stream.writeBuffer.move();
  EXPECT_EQ(700, getSendStreamFlowControlBytesWire(stream));
  EXPECT_EQ(400, getSendStreamFlowControlBytesAPI(stream));
}

} // namespace test
} // namespace quic
