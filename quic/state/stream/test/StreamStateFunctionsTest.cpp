/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <quic/state/stream/StreamStateFunctions.h>

#include <gtest/gtest.h>
#include <quic/common/test/TestUtils.h>
#include <quic/dsr/Types.h>
#include <quic/dsr/test/Mocks.h>
#include <quic/fizz/server/handshake/FizzServerQuicHandshakeContext.h>
#include <quic/logging/FileQLogger.h>
#include <quic/server/state/ServerStateMachine.h>
#include <quic/state/QuicStreamFunctions.h>
#include <quic/state/stream/StreamSendHandlers.h>

using namespace ::testing;

namespace quic::test {

class StreamStateFunctionsTests : public Test {};

TEST_F(StreamStateFunctionsTests, BasicResetTest) {
  QuicServerConnectionState conn(
      FizzServerQuicHandshakeContext::Builder().build());
  StreamId streamId = 0xbaad;
  QuicStreamState stream(streamId, conn);
  appendDataToReadBuffer(
      stream, StreamBuffer(folly::IOBuf::copyBuffer("It is a hotdog!"), 0));
  appendDataToReadBuffer(
      stream,
      StreamBuffer(folly::IOBuf::copyBuffer(" It is not a hotdog."), 15));
  writeDataToQuicStream(
      stream, folly::IOBuf::copyBuffer("What is it then?"), false);

  std::string retxBufData = "How would I know?";
  Buf retxBuf = folly::IOBuf::copyBuffer(retxBufData);
  stream.retransmissionBuffer.emplace(
      34,
      std::make_unique<WriteStreamBuffer>(ChainedByteRangeHead(retxBuf), 34));
  auto currentWriteOffset = stream.currentWriteOffset;
  auto currentReadOffset = stream.currentReadOffset;
  EXPECT_TRUE(stream.writable());

  sendRstSMHandler(stream, GenericApplicationErrorCode::UNKNOWN);

  // Something are cleared:
  EXPECT_TRUE(stream.writeBuffer.empty());
  EXPECT_TRUE(stream.retransmissionBuffer.empty());
  EXPECT_FALSE(stream.readBuffer.empty());

  // The rest are untouched:
  EXPECT_EQ(stream.id, streamId);
  EXPECT_EQ(currentReadOffset, stream.currentReadOffset);
  EXPECT_EQ(currentWriteOffset, stream.currentWriteOffset);
  EXPECT_FALSE(stream.writable());
}

TEST_F(StreamStateFunctionsTests, BasicReliableResetTest) {
  QuicServerConnectionState conn(
      FizzServerQuicHandshakeContext::Builder().build());
  StreamId streamId = 0xbaad;
  QuicStreamState stream(streamId, conn);
  appendDataToReadBuffer(
      stream, StreamBuffer(folly::IOBuf::copyBuffer("It is a hotdog!"), 0));
  appendDataToReadBuffer(
      stream,
      StreamBuffer(folly::IOBuf::copyBuffer(" It is not a hotdog."), 15));
  writeDataToQuicStream(
      stream, folly::IOBuf::copyBuffer("What is it then?"), false);

  std::string retxBufData = "How would I know?";
  Buf retxBuf = folly::IOBuf::copyBuffer(retxBufData);
  stream.retransmissionBuffer.emplace(
      34,
      std::make_unique<WriteStreamBuffer>(ChainedByteRangeHead(retxBuf), 34));
  auto currentWriteOffset = stream.currentWriteOffset;
  auto currentReadOffset = stream.currentReadOffset;
  EXPECT_TRUE(stream.writable());

  sendRstSMHandler(stream, GenericApplicationErrorCode::UNKNOWN, 5);

  // The writeBuffer is going to have bytes 0-4 because the reliableSize is 5.
  EXPECT_EQ(stream.writeBuffer.chainLength(), 5);
  EXPECT_TRUE(stream.retransmissionBuffer.empty());
  EXPECT_FALSE(stream.readBuffer.empty());

  EXPECT_EQ(stream.id, streamId);
  EXPECT_EQ(currentReadOffset, stream.currentReadOffset);
  EXPECT_EQ(currentWriteOffset, stream.currentWriteOffset);
  EXPECT_FALSE(stream.writable());

  // We set the finalWriteOffset to the maximum of the reliableSize (5) and the
  // amount of data we have written to the wire (0).
  EXPECT_EQ(conn.pendingEvents.resets.at(stream.id).finalSize, 5);

  EXPECT_EQ(*stream.reliableSizeToPeer, 5);
  EXPECT_EQ(*stream.appErrorCodeToPeer, GenericApplicationErrorCode::UNKNOWN);
}

TEST_F(StreamStateFunctionsTests, IsAllDataReceivedEmptyStream) {
  QuicServerConnectionState conn(
      FizzServerQuicHandshakeContext::Builder().build());
  StreamId id = 3;
  QuicStreamState stream(id, conn);
  EXPECT_FALSE(isAllDataReceived(stream));
}

TEST_F(StreamStateFunctionsTests, IsAllDataReceivedReadBufferHasHole) {
  QuicServerConnectionState conn(
      FizzServerQuicHandshakeContext::Builder().build());
  StreamId id = 3;
  QuicStreamState stream(id, conn);
  stream.currentReadOffset = 100;
  appendDataToReadBuffer(
      stream,
      StreamBuffer(
          folly::IOBuf::copyBuffer("Your read buffer has a hole"), 150, true));
  EXPECT_FALSE(isAllDataReceived(stream));
}

TEST_F(StreamStateFunctionsTests, IsAllDataReceivedReadBufferNoHoleNoFin) {
  QuicServerConnectionState conn(
      FizzServerQuicHandshakeContext::Builder().build());
  StreamId id = 3;
  QuicStreamState stream(id, conn);
  stream.currentReadOffset = 100;
  appendDataToReadBuffer(
      stream,
      StreamBuffer(folly::IOBuf::copyBuffer("Your haven't seen FIN yet"), 100));
  EXPECT_FALSE(isAllDataReceived(stream));
}

TEST_F(StreamStateFunctionsTests, IsAllDataReceivedReadBufferEmptyBufferFin) {
  QuicServerConnectionState conn(
      FizzServerQuicHandshakeContext::Builder().build());
  StreamId id = 3;
  QuicStreamState stream(id, conn);
  stream.currentReadOffset = 100;
  appendDataToReadBuffer(
      stream, StreamBuffer(folly::IOBuf::create(0), 100, true));
  EXPECT_TRUE(isAllDataReceived(stream));
}

TEST_F(StreamStateFunctionsTests, IsAllDataReceivedReadBufferBufferFin) {
  QuicServerConnectionState conn(
      FizzServerQuicHandshakeContext::Builder().build());
  StreamId id = 3;
  QuicStreamState stream(id, conn);
  stream.currentReadOffset = 100;
  appendDataToReadBuffer(
      stream,
      StreamBuffer(
          folly::IOBuf::copyBuffer("you may say im a dreamer"), 100, true));
  EXPECT_TRUE(isAllDataReceived(stream));
}

TEST_F(StreamStateFunctionsTests, IsAllDataReceivedMultipleStreamDataNoHole) {
  QuicServerConnectionState conn(
      FizzServerQuicHandshakeContext::Builder().build());
  StreamId id = 3;
  QuicStreamState stream(id, conn);
  stream.currentReadOffset = 100;
  appendDataToReadBuffer(
      stream, StreamBuffer(folly::IOBuf::copyBuffer("0123456789"), 100));
  appendDataToReadBuffer(
      stream,
      StreamBuffer(folly::IOBuf::copyBuffer("01234567890123456789"), 110));
  appendDataToReadBuffer(
      stream,
      StreamBuffer(folly::IOBuf::copyBuffer("Counting is hard"), 130, true));
  EXPECT_TRUE(isAllDataReceived(stream));
}

TEST_F(StreamStateFunctionsTests, IsAllDataReceivedMultipleStreamDataHasHole) {
  QuicServerConnectionState conn(
      FizzServerQuicHandshakeContext::Builder().build());
  StreamId id = 3;
  QuicStreamState stream(id, conn);
  stream.currentReadOffset = 100;
  appendDataToReadBuffer(
      stream, StreamBuffer(folly::IOBuf::copyBuffer("0123456789"), 100));
  appendDataToReadBuffer(
      stream,
      StreamBuffer(folly::IOBuf::copyBuffer("01234567890123456789"), 115));
  appendDataToReadBuffer(
      stream,
      StreamBuffer(folly::IOBuf::copyBuffer("Counting is hard"), 130, true));
  EXPECT_FALSE(isAllDataReceived(stream));
}

TEST_F(StreamStateFunctionsTests, IsAllDataReceivedAllDataRead) {
  QuicServerConnectionState conn(
      FizzServerQuicHandshakeContext::Builder().build());
  StreamId id = 3;
  QuicStreamState stream(id, conn);
  stream.currentReadOffset = 101;
  stream.finalReadOffset = 100;
  EXPECT_TRUE(isAllDataReceived(stream));
}

TEST_F(StreamStateFunctionsTests, SendReset) {
  QuicServerConnectionState conn(
      FizzServerQuicHandshakeContext::Builder().build());
  // Set an initial flow control.
  conn.flowControlState.peerAdvertisedMaxOffset = 1024;
  StreamId id = 1;
  QuicStreamState stream(id, conn);
  auto initialConnWindow = getSendConnFlowControlBytesAPI(conn);
  EXPECT_EQ(initialConnWindow, 1024);
  writeDataToQuicStream(stream, folly::IOBuf::copyBuffer("hello"), true);
  EXPECT_EQ(conn.flowControlState.sumCurStreamBufferLen, 5);
  EXPECT_EQ(getSendConnFlowControlBytesAPI(conn), initialConnWindow - 5);
  appendDataToReadBuffer(
      stream, StreamBuffer(folly::IOBuf::copyBuffer("hi"), 0));
  EXPECT_FALSE(stream.writeBuffer.empty());
  EXPECT_FALSE(stream.readBuffer.empty());
  resetQuicStream(stream, GenericApplicationErrorCode::UNKNOWN);
  EXPECT_EQ(getSendConnFlowControlBytesAPI(conn), initialConnWindow);
  EXPECT_TRUE(stream.writeBuffer.empty());
}

TEST_F(StreamStateFunctionsTests, SendResetDSRStream) {
  QuicServerConnectionState conn(
      FizzServerQuicHandshakeContext::Builder().build());
  conn.flowControlState.peerAdvertisedMaxOffset = 5000;
  StreamId id = 1;
  QuicStreamState stream(id, conn);
  auto initialConnWindow = getSendConnFlowControlBytesAPI(conn);
  writeDataToQuicStream(stream, folly::IOBuf::copyBuffer("aloha"), false);
  auto mockDSRSender = std::make_unique<MockDSRPacketizationRequestSender>();
  EXPECT_CALL(*mockDSRSender, release()).Times(1);
  stream.flowControlState.peerAdvertisedMaxOffset =
      std::numeric_limits<uint64_t>::max();
  stream.dsrSender = std::move(mockDSRSender);
  BufferMeta bufMeta(2000);
  writeBufMetaToQuicStream(stream, bufMeta, true);
  EXPECT_EQ(conn.flowControlState.sumCurStreamBufferLen, 5 + 2000);
  EXPECT_EQ(getSendConnFlowControlBytesAPI(conn), initialConnWindow - 5 - 2000);
  appendDataToReadBuffer(
      stream, StreamBuffer(folly::IOBuf::copyBuffer("hi"), 0));
  EXPECT_FALSE(stream.writeBuffer.empty());
  EXPECT_FALSE(stream.readBuffer.empty());
  resetQuicStream(stream, GenericApplicationErrorCode::UNKNOWN);
  EXPECT_EQ(getSendConnFlowControlBytesAPI(conn), initialConnWindow);
  EXPECT_TRUE(stream.streamWriteError.hasValue());
  EXPECT_TRUE(stream.writeBuffer.empty());
  EXPECT_EQ(0, stream.writeBufMeta.length);
  EXPECT_TRUE(stream.lossBufMetas.empty());
}

TEST_F(StreamStateFunctionsTests, ResetNoFlowControlGenerated) {
  QuicServerConnectionState conn(
      FizzServerQuicHandshakeContext::Builder().build());
  StreamId id = 1;
  QuicStreamState stream(id, conn);
  writeDataToQuicStream(stream, folly::IOBuf::copyBuffer("hello"), true);
  EXPECT_GT(conn.flowControlState.sumCurStreamBufferLen, 0);
  RstStreamFrame rst(id, GenericApplicationErrorCode::UNKNOWN, 90);

  stream.currentReadOffset = 80;
  stream.maxOffsetObserved = 90;
  stream.flowControlState.advertisedMaxOffset = 100;

  conn.flowControlState.advertisedMaxOffset = 10000;
  conn.flowControlState.sumMaxObservedOffset = 90;
  conn.flowControlState.sumCurReadOffset = 80;
  conn.flowControlState.windowSize = 10000;

  onResetQuicStream(stream, std::move(rst));
  EXPECT_EQ(stream.currentReadOffset, 90);
  EXPECT_EQ(conn.flowControlState.sumCurReadOffset, 90);
  EXPECT_FALSE(conn.pendingEvents.connWindowUpdate);
}

TEST_F(StreamStateFunctionsTests, ResetFlowControlGenerated) {
  QuicServerConnectionState conn(
      FizzServerQuicHandshakeContext::Builder().build());
  auto qLogger = std::make_shared<FileQLogger>(VantagePoint::Client);
  conn.qLogger = qLogger;

  StreamId id = 1;
  QuicStreamState stream(id, conn);
  writeDataToQuicStream(stream, folly::IOBuf::copyBuffer("hello"), true);
  EXPECT_GT(conn.flowControlState.sumCurStreamBufferLen, 0);
  RstStreamFrame rst(id, GenericApplicationErrorCode::UNKNOWN, 100);
  stream.currentReadOffset = 80;
  stream.maxOffsetObserved = 90;
  stream.flowControlState.advertisedMaxOffset = 100;

  conn.flowControlState.advertisedMaxOffset = 100;
  conn.flowControlState.sumMaxObservedOffset = 90;
  conn.flowControlState.sumCurReadOffset = 80;
  conn.flowControlState.windowSize = 100;

  onResetQuicStream(stream, std::move(rst));
  EXPECT_EQ(stream.currentReadOffset, 100);
  EXPECT_EQ(conn.flowControlState.sumCurReadOffset, 100);
  EXPECT_TRUE(conn.pendingEvents.connWindowUpdate);

  std::vector<int> indices =
      getQLogEventIndices(QLogEventType::TransportStateUpdate, qLogger);
  EXPECT_EQ(indices.size(), 2);
  std::array<int, 2> offsets = {0, 200};
  for (int i = 0; i < 2; ++i) {
    auto tmp = std::move(qLogger->logs[indices[i]]);
    auto event = dynamic_cast<QLogTransportStateUpdateEvent*>(tmp.get());
    EXPECT_EQ(event->update, getFlowControlEvent(offsets[i]));
  }
}

TEST_F(StreamStateFunctionsTests, ResetOffsetNotMatch) {
  QuicServerConnectionState conn(
      FizzServerQuicHandshakeContext::Builder().build());
  StreamId id = 1;
  QuicStreamState stream(id, conn);
  RstStreamFrame rst(id, GenericApplicationErrorCode::UNKNOWN, 10);
  stream.currentReadOffset = 20;
  stream.maxOffsetObserved = 100;
  stream.finalReadOffset = 100;
  stream.flowControlState.advertisedMaxOffset = 300;
  EXPECT_THROW(
      onResetQuicStream(stream, std::move(rst)), QuicTransportException);
}

TEST_F(StreamStateFunctionsTests, ResetFinalSizeChange) {
  QuicServerConnectionState conn(
      FizzServerQuicHandshakeContext::Builder().build());
  StreamId id = 1;
  QuicStreamState stream(id, conn);
  stream.finalReadOffset = 11;
  stream.streamReadError = GenericApplicationErrorCode::UNKNOWN;
  RstStreamFrame rst(id, GenericApplicationErrorCode::UNKNOWN, 10);
  try {
    onResetQuicStream(stream, rst);
    FAIL() << "Should throw QuicTransportException";
  } catch (QuicTransportException& exc) {
    EXPECT_EQ(exc.errorCode(), TransportErrorCode::STREAM_STATE_ERROR);
  }
}

TEST_F(StreamStateFunctionsTests, ResetErrorCodeChange) {
  QuicServerConnectionState conn(
      FizzServerQuicHandshakeContext::Builder().build());
  StreamId id = 1;
  QuicStreamState stream(id, conn);
  stream.finalReadOffset = 10;
  stream.streamReadError = GenericApplicationErrorCode::UNKNOWN + 1;
  RstStreamFrame rst(id, GenericApplicationErrorCode::UNKNOWN, 10);
  try {
    onResetQuicStream(stream, rst);
    FAIL() << "Should throw QuicTransportException";
  } catch (QuicTransportException& exc) {
    EXPECT_EQ(exc.errorCode(), TransportErrorCode::STREAM_STATE_ERROR);
  }
}

TEST_F(StreamStateFunctionsTests, ResetOffsetLessThanMaxObserved) {
  QuicServerConnectionState conn(
      FizzServerQuicHandshakeContext::Builder().build());
  StreamId id = 1;
  QuicStreamState stream(id, conn);
  RstStreamFrame rst(id, GenericApplicationErrorCode::UNKNOWN, 30);
  stream.currentReadOffset = 20;
  stream.maxOffsetObserved = 100;
  stream.flowControlState.advertisedMaxOffset = 300;
  EXPECT_THROW(
      onResetQuicStream(stream, std::move(rst)), QuicTransportException);
}

TEST_F(StreamStateFunctionsTests, ResetOffsetGreaterThanStreamFlowControl) {
  QuicServerConnectionState conn(
      FizzServerQuicHandshakeContext::Builder().build());
  StreamId id = 1;
  QuicStreamState stream(id, conn);
  RstStreamFrame rst(id, GenericApplicationErrorCode::UNKNOWN, 200);
  stream.currentReadOffset = 20;
  stream.maxOffsetObserved = 30;
  stream.flowControlState.advertisedMaxOffset = 100;
  EXPECT_THROW(
      onResetQuicStream(stream, std::move(rst)), QuicTransportException);
}

TEST_F(StreamStateFunctionsTests, ResetOffsetGreaterThanConnFlowControl) {
  QuicServerConnectionState conn(
      FizzServerQuicHandshakeContext::Builder().build());
  StreamId id = 1;
  QuicStreamState stream(id, conn);
  RstStreamFrame rst(id, GenericApplicationErrorCode::UNKNOWN, 200);

  stream.currentReadOffset = 20;
  stream.maxOffsetObserved = 30;
  stream.flowControlState.advertisedMaxOffset = 300;
  stream.flowControlState.windowSize = 100;

  conn.flowControlState.sumCurReadOffset = 20;
  conn.flowControlState.sumMaxObservedOffset = 30;
  conn.flowControlState.advertisedMaxOffset = 100;
  conn.flowControlState.windowSize = 100;
  EXPECT_THROW(
      onResetQuicStream(stream, std::move(rst)), QuicTransportException);
}

TEST_F(StreamStateFunctionsTests, ResetAfterReadingAllBytesTillFin) {
  QuicServerConnectionState conn(
      FizzServerQuicHandshakeContext::Builder().build());
  StreamId id = 1;
  QuicStreamState stream(id, conn);
  RstStreamFrame rst(id, GenericApplicationErrorCode::UNKNOWN, 100);
  stream.currentReadOffset = 101;
  stream.finalReadOffset = 100;
  stream.maxOffsetObserved = 100;
  stream.flowControlState.advertisedMaxOffset = 300;
  onResetQuicStream(stream, std::move(rst));
  EXPECT_EQ(stream.currentReadOffset, 101);
  EXPECT_FALSE(conn.streamManager->hasWindowUpdates());
  EXPECT_FALSE(conn.pendingEvents.connWindowUpdate);
}

// The application has already read all data until the specified
// offset.
TEST_F(StreamStateFunctionsTests, isAllDataReceivedUntil1) {
  QuicServerConnectionState conn(
      FizzServerQuicHandshakeContext::Builder().build());
  StreamId id = 1;
  QuicStreamState stream(id, conn);
  stream.currentReadOffset = 1;
  EXPECT_TRUE(isAllDataReceivedUntil(stream, 0));
}

// The application has not read all data until the specified
// offset, and the data isn't available in the read buffer either.
TEST_F(StreamStateFunctionsTests, isAllDataReceivedUntil2) {
  QuicServerConnectionState conn(
      FizzServerQuicHandshakeContext::Builder().build());
  StreamId id = 1;
  QuicStreamState stream(id, conn);
  stream.currentReadOffset = 1;
  stream.readBuffer.emplace_back(
      StreamBuffer(folly::IOBuf::copyBuffer("1"), 1, false));
  EXPECT_FALSE(isAllDataReceivedUntil(stream, 2));
}

// The application has not read all data until the specified
// offset, but the data is available in the read buffer.
TEST_F(StreamStateFunctionsTests, isAllDataReceivedUntil3) {
  QuicServerConnectionState conn(
      FizzServerQuicHandshakeContext::Builder().build());
  StreamId id = 1;
  QuicStreamState stream(id, conn);
  stream.currentReadOffset = 1;
  stream.readBuffer.emplace_back(
      StreamBuffer(folly::IOBuf::copyBuffer("1"), 1, false));
  EXPECT_TRUE(isAllDataReceivedUntil(stream, 1));
}

// There's a "hole" in the data received.
TEST_F(StreamStateFunctionsTests, isAllDataReceivedUntil4) {
  QuicServerConnectionState conn(
      FizzServerQuicHandshakeContext::Builder().build());
  StreamId id = 1;
  QuicStreamState stream(id, conn);
  stream.currentReadOffset = 1;
  stream.readBuffer.emplace_back(
      StreamBuffer(folly::IOBuf::copyBuffer("1"), 2, false));
  EXPECT_FALSE(isAllDataReceivedUntil(stream, 2));
}
} // namespace quic::test
