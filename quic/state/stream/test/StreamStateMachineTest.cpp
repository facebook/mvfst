/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <quic/api/QuicTransportFunctions.h>
#include <quic/codec/DefaultConnectionIdAlgo.h>
#include <quic/common/test/TestUtils.h>
#include <quic/fizz/server/handshake/FizzServerQuicHandshakeContext.h>
#include <quic/state/QuicStreamFunctions.h>
#include <quic/state/stream/StreamReceiveHandlers.h>
#include <quic/state/stream/StreamSendHandlers.h>

using namespace folly;
using namespace testing;

namespace quic {
namespace test {

void verifyStreamReset(
    const QuicStreamState& stream,
    uint64_t readOffsetExpected) {
  EXPECT_TRUE(stream.readBuffer.empty());
  EXPECT_TRUE(stream.finalReadOffset.has_value());
  EXPECT_EQ(readOffsetExpected, stream.finalReadOffset.value());
}

std::unique_ptr<QuicServerConnectionState> createConn() {
  auto conn = std::make_unique<QuicServerConnectionState>(
      FizzServerQuicHandshakeContext::Builder().build());
  conn->clientConnectionId = getTestConnectionId();
  conn->version = QuicVersion::MVFST;
  conn->ackStates.initialAckState.nextPacketNum = 1;
  conn->ackStates.handshakeAckState.nextPacketNum = 1;
  conn->ackStates.appDataAckState.nextPacketNum = 1;
  conn->flowControlState.peerAdvertisedInitialMaxStreamOffsetBidiLocal =
      kDefaultStreamWindowSize;
  conn->flowControlState.peerAdvertisedInitialMaxStreamOffsetBidiRemote =
      kDefaultStreamWindowSize;
  conn->flowControlState.peerAdvertisedInitialMaxStreamOffsetUni =
      kDefaultStreamWindowSize;
  conn->flowControlState.peerAdvertisedMaxOffset = kDefaultConnectionWindowSize;
  conn->streamManager->setMaxLocalBidirectionalStreams(
      kDefaultMaxStreamsBidirectional);
  conn->streamManager->setMaxLocalUnidirectionalStreams(
      kDefaultMaxStreamsUnidirectional);
  return conn;
}

class QuicOpenStateTest : public Test {};

TEST_F(QuicOpenStateTest, ReadStreamDataNotFin) {
  auto conn = createConn();
  StreamId id = 5;
  QuicStreamState stream(id, *conn);
  uint64_t offset = 0;
  bool fin = false;
  ReadStreamFrame frame(id, offset, fin);
  frame.data = IOBuf::copyBuffer("hey");
  receiveReadStreamFrameSMHandler(stream, std::move(frame));
  EXPECT_TRUE(stream.hasReadableData());
  EXPECT_TRUE(stream.hasPeekableData());
  EXPECT_EQ(stream.recvState, StreamRecvState::Open);
}

TEST_F(QuicOpenStateTest, ReadInvalidData) {
  auto conn = createConn();
  StreamId id = 5;
  QuicStreamState stream(id, *conn);
  uint64_t offset1 = 0;
  bool fin1 = false;

  // EOF in middle of stream
  ReadStreamFrame frame1(id, offset1, fin1);
  frame1.data = IOBuf::copyBuffer("hey");
  receiveReadStreamFrameSMHandler(stream, std::move(frame1));
  EXPECT_EQ(stream.recvState, StreamRecvState::Open);

  uint64_t offset2 = 1;
  bool fin2 = true;
  ReadStreamFrame frame2(id, offset2, fin2);
  frame2.data = IOBuf::copyBuffer("e");
  EXPECT_THROW(
      receiveReadStreamFrameSMHandler(stream, std::move(frame2)),
      QuicTransportException);
}

TEST_F(QuicOpenStateTest, InvalidEvent) {
  auto conn = createConn();
  StreamId id = 5;
  QuicStreamState stream(id, *conn);
  RstStreamFrame frame(1, GenericApplicationErrorCode::UNKNOWN, 0);
  EXPECT_THROW(sendRstAckSMHandler(stream), QuicTransportException);
}

TEST_F(QuicOpenStateTest, ReceiveStreamFrameWithFIN) {
  auto conn = createConn();

  auto stream = conn->streamManager->createNextBidirectionalStream().value();
  stream->currentReadOffset = 100;

  // We received FIN and everything:
  ReadStreamFrame receivedStreamFrame(stream->id, 100, true);
  receivedStreamFrame.data = folly::IOBuf::create(10);
  receivedStreamFrame.data->append(10);
  receiveReadStreamFrameSMHandler(*stream, std::move(receivedStreamFrame));
  ASSERT_EQ(stream->recvState, StreamRecvState::Closed);
}

TEST_F(QuicOpenStateTest, ReceiveStreamFrameWithFINReadbuffHole) {
  auto conn = createConn();

  auto stream = conn->streamManager->createNextBidirectionalStream().value();
  stream->currentReadOffset = 100;

  // We received FIN, but we havn't received anything between 100 and 200:
  ReadStreamFrame receivedStreamFrame(stream->id, 200, true);
  receivedStreamFrame.data = folly::IOBuf::create(10);
  receivedStreamFrame.data->append(10);
  receiveReadStreamFrameSMHandler(*stream, std::move(receivedStreamFrame));
  ASSERT_EQ(stream->recvState, StreamRecvState::Open);
}

TEST_F(QuicOpenStateTest, ReceiveStreamFrameWithoutFIN) {
  auto conn = createConn();

  auto stream = conn->streamManager->createNextBidirectionalStream().value();
  stream->currentReadOffset = 100;

  // We haven't received FIN:
  ReadStreamFrame receivedStreamFrame(stream->id, 100, false);
  receivedStreamFrame.data = folly::IOBuf::create(10);
  receivedStreamFrame.data->append(10);
  receiveReadStreamFrameSMHandler(*stream, std::move(receivedStreamFrame));
  ASSERT_EQ(stream->recvState, StreamRecvState::Open);
}

TEST_F(QuicOpenStateTest, AckStream) {
  auto conn = createConn();

  auto stream = conn->streamManager->createNextBidirectionalStream().value();
  folly::Optional<ConnectionId> serverChosenConnId = *conn->clientConnectionId;
  serverChosenConnId.value().data()[0] ^= 0x01;
  EventBase evb;
  auto sock = std::make_unique<folly::test::MockAsyncUDPSocket>(&evb);

  auto buf = IOBuf::copyBuffer("hello");
  writeQuicPacket(
      *conn,
      *conn->clientConnectionId,
      *serverChosenConnId,
      *sock,
      *stream,
      *buf,
      true);

  EXPECT_EQ(stream->retransmissionBuffer.size(), 1);
  EXPECT_EQ(1, conn->outstandings.packets.size());

  auto& streamFrame =
      *getFirstOutstandingPacket(*conn, PacketNumberSpace::AppData)
           ->packet.frames.front()
           .asWriteStreamFrame();

  sendAckSMHandler(*stream, streamFrame);
  ASSERT_EQ(stream->sendState, StreamSendState::Closed);

  sendAckSMHandler(*stream, streamFrame);
  ASSERT_EQ(stream->sendState, StreamSendState::Closed);
}

TEST_F(QuicOpenStateTest, AckStreamMulti) {
  auto conn = createConn();

  auto stream = conn->streamManager->createNextBidirectionalStream().value();
  folly::Optional<ConnectionId> serverChosenConnId = *conn->clientConnectionId;
  serverChosenConnId.value().data()[0] ^= 0x01;
  EventBase evb;
  auto sock = std::make_unique<folly::test::MockAsyncUDPSocket>(&evb);

  auto buf = IOBuf::copyBuffer("hello");
  writeQuicPacket(
      *conn,
      *conn->clientConnectionId,
      *serverChosenConnId,
      *sock,
      *stream,
      *buf,
      false);
  writeQuicPacket(
      *conn,
      *conn->clientConnectionId,
      *serverChosenConnId,
      *sock,
      *stream,
      *IOBuf::copyBuffer("world"),
      false);
  writeQuicPacket(
      *conn,
      *conn->clientConnectionId,
      *serverChosenConnId,
      *sock,
      *stream,
      *IOBuf::copyBuffer("this is bob"),
      false);

  EXPECT_EQ(stream->retransmissionBuffer.size(), 3);
  EXPECT_EQ(3, conn->outstandings.packets.size());

  auto& streamFrame3 =
      *conn->outstandings.packets[2].packet.frames[0].asWriteStreamFrame();

  sendAckSMHandler(*stream, streamFrame3);
  ASSERT_EQ(stream->sendState, StreamSendState::Open);
  ASSERT_EQ(stream->ackedIntervals.front().start, 10);
  ASSERT_EQ(stream->ackedIntervals.front().end, 21);

  auto& streamFrame2 =
      *conn->outstandings.packets[1].packet.frames[0].asWriteStreamFrame();

  sendAckSMHandler(*stream, streamFrame2);
  ASSERT_EQ(stream->sendState, StreamSendState::Open);
  ASSERT_EQ(stream->ackedIntervals.front().start, 5);
  ASSERT_EQ(stream->ackedIntervals.front().end, 21);

  auto& streamFrame1 =
      *conn->outstandings.packets[0].packet.frames[0].asWriteStreamFrame();

  sendAckSMHandler(*stream, streamFrame1);
  ASSERT_EQ(stream->sendState, StreamSendState::Open);
  ASSERT_EQ(stream->ackedIntervals.front().start, 0);
  ASSERT_EQ(stream->ackedIntervals.front().end, 21);
}

TEST_F(QuicOpenStateTest, RetxBufferSortedAfterAck) {
  auto conn = createConn();
  auto stream = conn->streamManager->createNextBidirectionalStream().value();
  EventBase evb;
  folly::test::MockAsyncUDPSocket socket(&evb);
  folly::Optional<ConnectionId> serverChosenConnId = *conn->clientConnectionId;
  serverChosenConnId.value().data()[0] ^= 0x01;

  auto buf1 = IOBuf::copyBuffer("Alice");
  auto buf2 = IOBuf::copyBuffer("Bob");
  auto buf3 = IOBuf::copyBuffer("NSA");
  writeQuicPacket(
      *conn,
      *conn->clientConnectionId,
      *serverChosenConnId,
      socket,
      *stream,
      *buf1,
      false);
  writeQuicPacket(
      *conn,
      *conn->clientConnectionId,
      *serverChosenConnId,
      socket,
      *stream,
      *buf2,
      false);
  writeQuicPacket(
      *conn,
      *conn->clientConnectionId,
      *serverChosenConnId,
      socket,
      *stream,
      *buf3,
      false);

  EXPECT_EQ(3, stream->retransmissionBuffer.size());
  EXPECT_EQ(3, conn->outstandings.packets.size());
  auto packet = conn->outstandings.packets[folly::Random::rand32() % 3];
  auto streamFrame = *conn->outstandings.packets[std::rand() % 3]
                          .packet.frames.front()
                          .asWriteStreamFrame();
  sendAckSMHandler(*stream, streamFrame);
  EXPECT_EQ(2, stream->retransmissionBuffer.size());
}

class QuicResetSentStateTest : public Test {};

TEST_F(QuicResetSentStateTest, RstAck) {
  auto conn = createConn();
  StreamId id = 5;

  QuicStreamState stream(id, *conn);
  stream.sendState = StreamSendState::ResetSent;
  stream.currentReadOffset = 0xABCD;
  stream.finalWriteOffset = 0xACDC;
  stream.readBuffer.emplace_back(
      folly::IOBuf::copyBuffer("One more thing"), 0xABCD, false);
  RstStreamFrame frame(id, GenericApplicationErrorCode::UNKNOWN, 0);
  sendRstAckSMHandler(stream);

  EXPECT_EQ(stream.sendState, StreamSendState::Closed);
  EXPECT_FALSE(stream.finalReadOffset);
  EXPECT_FALSE(stream.readBuffer.empty());
}

class QuicClosedStateTest : public Test {};

TEST_F(QuicClosedStateTest, RstAck) {
  auto conn = createConn();
  StreamId id = 5;
  QuicStreamState stream(id, *conn);
  stream.sendState = StreamSendState::Closed;
  RstStreamFrame frame(id, GenericApplicationErrorCode::UNKNOWN, 0);
  sendRstAckSMHandler(stream);
  EXPECT_EQ(stream.sendState, StreamSendState::Closed);
}

class QuicHalfClosedLocalStateTest : public Test {};

TEST_F(QuicHalfClosedLocalStateTest, ReceiveStreamFrameWithFIN) {
  auto conn = createConn();

  auto stream = conn->streamManager->createNextBidirectionalStream().value();
  stream->sendState = StreamSendState::Closed;
  stream->recvState = StreamRecvState::Open;
  stream->currentReadOffset = 100;

  // We received FIN and everything:
  ReadStreamFrame receivedStreamFrame(stream->id, 100, true);
  receivedStreamFrame.data = folly::IOBuf::create(10);
  receivedStreamFrame.data->append(10);
  receiveReadStreamFrameSMHandler(*stream, std::move(receivedStreamFrame));
  ASSERT_EQ(stream->sendState, StreamSendState::Closed);
  ASSERT_EQ(stream->recvState, StreamRecvState::Closed);
}

TEST_F(QuicHalfClosedLocalStateTest, ReceiveStreamFrameWithFINReadbuffHole) {
  auto conn = createConn();

  auto stream = conn->streamManager->createNextBidirectionalStream().value();
  stream->sendState = StreamSendState::Closed;
  stream->recvState = StreamRecvState::Open;
  stream->currentReadOffset = 100;

  // We received FIN, but we havn't received anything between 100 and 200:
  ReadStreamFrame receivedStreamFrame(stream->id, 200, true);
  receivedStreamFrame.data = folly::IOBuf::create(10);
  receivedStreamFrame.data->append(10);
  receiveReadStreamFrameSMHandler(*stream, std::move(receivedStreamFrame));
  ASSERT_EQ(stream->sendState, StreamSendState::Closed);
  ASSERT_EQ(stream->recvState, StreamRecvState::Open);
}

TEST_F(QuicHalfClosedLocalStateTest, ReceiveStreamFrameWithoutFIN) {
  auto conn = createConn();

  auto stream = conn->streamManager->createNextBidirectionalStream().value();
  stream->sendState = StreamSendState::Closed;
  stream->recvState = StreamRecvState::Open;
  stream->currentReadOffset = 100;

  // We haven't received FIN:
  ReadStreamFrame receivedStreamFrame(stream->id, 100, false);
  receivedStreamFrame.data = folly::IOBuf::create(10);
  receivedStreamFrame.data->append(10);
  receiveReadStreamFrameSMHandler(*stream, std::move(receivedStreamFrame));

  ASSERT_EQ(stream->sendState, StreamSendState::Closed);
  ASSERT_EQ(stream->recvState, StreamRecvState::Open);
}

class QuicHalfClosedRemoteStateTest : public Test {};

TEST_F(QuicHalfClosedRemoteStateTest, AckStream) {
  auto conn = createConn();
  // create server chosen connId with processId = 0 and workerId = 0
  ServerConnectionIdParams params(0, 0, 0);
  auto connIdAlgo = std::make_unique<DefaultConnectionIdAlgo>();
  auto serverChosenConnId = connIdAlgo->encodeConnectionId(params);
  auto stream = conn->streamManager->createNextBidirectionalStream().value();
  stream->sendState = StreamSendState::Open;
  stream->recvState = StreamRecvState::Closed;

  EventBase evb;
  auto sock = std::make_unique<folly::test::MockAsyncUDPSocket>(&evb);

  auto buf = IOBuf::copyBuffer("hello");
  writeQuicPacket(
      *conn,
      *conn->clientConnectionId,
      *serverChosenConnId,
      *sock,
      *stream,
      *buf,
      true);

  EXPECT_EQ(stream->retransmissionBuffer.size(), 1);
  EXPECT_EQ(1, conn->outstandings.packets.size());

  auto& streamFrame =
      *getFirstOutstandingPacket(*conn, PacketNumberSpace::AppData)
           ->packet.frames.front()
           .asWriteStreamFrame();

  sendAckSMHandler(*stream, streamFrame);
  ASSERT_EQ(stream->sendState, StreamSendState::Closed);

  sendAckSMHandler(*stream, streamFrame);
  ASSERT_EQ(stream->sendState, StreamSendState::Closed);
}

class QuicSendResetTest : public Test {};

TEST_F(QuicSendResetTest, FromOpen) {
  auto conn = createConn();
  StreamId id = 5;
  QuicStreamState stream(id, *conn);
  sendRstSMHandler(stream, GenericApplicationErrorCode::UNKNOWN);
  EXPECT_EQ(stream.sendState, StreamSendState::ResetSent);
}

TEST_F(QuicSendResetTest, FromHalfCloseRemote) {
  auto conn = createConn();
  StreamId id = 5;
  QuicStreamState stream(id, *conn);
  stream.sendState = StreamSendState::Open;
  stream.recvState = StreamRecvState::Closed;

  sendRstSMHandler(stream, GenericApplicationErrorCode::UNKNOWN);
  EXPECT_EQ(stream.sendState, StreamSendState::ResetSent);
}

TEST_F(QuicSendResetTest, FromHalfCloseLocal) {
  auto conn = createConn();
  StreamId id = 5;
  QuicStreamState stream(id, *conn);
  stream.sendState = StreamSendState::Closed;
  stream.recvState = StreamRecvState::Open;
  sendRstSMHandler(stream, GenericApplicationErrorCode::UNKNOWN);

  // You cannot send a reset after FIN has been acked
  EXPECT_EQ(stream.sendState, StreamSendState::Closed);
}

TEST_F(QuicSendResetTest, FromClosed) {
  auto conn = createConn();
  StreamId id = 5;
  QuicStreamState stream(id, *conn);
  stream.sendState = StreamSendState::Closed;

  sendRstSMHandler(stream, GenericApplicationErrorCode::UNKNOWN);
}

TEST_F(QuicSendResetTest, FromResetSent) {
  auto conn = createConn();
  StreamId id = 5;
  QuicStreamState stream(id, *conn);
  stream.sendState = StreamSendState::ResetSent;
  sendRstSMHandler(stream, GenericApplicationErrorCode::UNKNOWN);
}

class QuicRecvResetTest : public Test {};

TEST_F(QuicRecvResetTest, FromOpen) {
  auto conn = createConn();
  StreamId id = 5;
  StreamId rstStream = 1;
  QuicStreamState stream(id, *conn);
  RstStreamFrame rst(rstStream, GenericApplicationErrorCode::UNKNOWN, 100);
  receiveRstStreamSMHandler(stream, std::move(rst));

  EXPECT_EQ(stream.sendState, StreamSendState::Open);
  EXPECT_EQ(stream.recvState, StreamRecvState::Closed);
  verifyStreamReset(stream, 100);
}

TEST_F(QuicRecvResetTest, FromOpenReadEOFMismatch) {
  auto conn = createConn();
  StreamId id = 5;

  QuicStreamState stream(id, *conn);
  RstStreamFrame rst(1, GenericApplicationErrorCode::UNKNOWN, 100);
  stream.finalReadOffset = 1024;
  EXPECT_THROW(
      receiveRstStreamSMHandler(stream, std::move(rst)),
      QuicTransportException);
}

TEST_F(QuicRecvResetTest, FromHalfClosedRemoteNoReadOffsetYet) {
  StreamId id = 5;
  auto conn = createConn();
  QuicStreamState stream(id, *conn);
  stream.sendState = StreamSendState::Open;
  stream.recvState = StreamRecvState::Closed;
  receiveRstStreamSMHandler(
      stream, RstStreamFrame(1, GenericApplicationErrorCode::UNKNOWN, 100));

  EXPECT_EQ(stream.sendState, StreamSendState::Open);
  EXPECT_EQ(stream.recvState, StreamRecvState::Closed);
  verifyStreamReset(stream, 100);
}

TEST_F(QuicRecvResetTest, FromHalfClosedRemoteReadOffsetMatch) {
  auto conn = createConn();
  StreamId id = 5;
  QuicStreamState stream(id, *conn);
  stream.sendState = StreamSendState::Open;
  stream.recvState = StreamRecvState::Closed;
  stream.finalReadOffset = 1024;

  receiveRstStreamSMHandler(
      stream, RstStreamFrame(1, GenericApplicationErrorCode::UNKNOWN, 1024));
  EXPECT_EQ(stream.sendState, StreamSendState::Open);
  EXPECT_EQ(stream.recvState, StreamRecvState::Closed);
  verifyStreamReset(stream, 1024);
}

TEST_F(QuicRecvResetTest, FromHalfClosedRemoteReadOffsetMismatch) {
  auto conn = createConn();
  StreamId id = 5;
  QuicStreamState stream(id, *conn);
  stream.sendState = StreamSendState::Open;
  stream.recvState = StreamRecvState::Closed;
  stream.finalReadOffset = 1024;
  EXPECT_THROW(
      receiveRstStreamSMHandler(
          stream, RstStreamFrame(1, GenericApplicationErrorCode::UNKNOWN, 100)),
      QuicTransportException);
}

TEST_F(QuicRecvResetTest, FromHalfClosedLocal) {
  auto conn = createConn();
  StreamId id = 5;
  QuicStreamState stream(id, *conn);
  stream.sendState = StreamSendState::Closed;
  stream.recvState = StreamRecvState::Open;
  receiveRstStreamSMHandler(
      stream, RstStreamFrame(1, GenericApplicationErrorCode::UNKNOWN, 200));
  EXPECT_EQ(stream.sendState, StreamSendState::Closed);
  EXPECT_EQ(stream.recvState, StreamRecvState::Closed);
  verifyStreamReset(stream, 200);
}

TEST_F(QuicRecvResetTest, FromHalfClosedLocalReadEOFMismatch) {
  auto conn = createConn();
  StreamId id = 5;
  QuicStreamState stream(id, *conn);
  stream.sendState = StreamSendState::Closed;
  stream.recvState = StreamRecvState::Open;
  stream.finalReadOffset = 2014;
  EXPECT_THROW(
      receiveRstStreamSMHandler(
          stream, RstStreamFrame(1, GenericApplicationErrorCode::UNKNOWN, 200)),
      QuicTransportException);
}

TEST_F(QuicRecvResetTest, FromResetSentNoReadOffsetYet) {
  auto conn = createConn();
  StreamId id = 5;
  QuicStreamState stream(id, *conn);
  stream.sendState = StreamSendState::ResetSent;
  stream.recvState = StreamRecvState::Open;

  receiveRstStreamSMHandler(
      stream, RstStreamFrame(1, GenericApplicationErrorCode::UNKNOWN, 200));
  EXPECT_EQ(stream.sendState, StreamSendState::ResetSent);
  EXPECT_EQ(stream.recvState, StreamRecvState::Closed);
  verifyStreamReset(stream, 200);
}

TEST_F(QuicRecvResetTest, FromResetSentOffsetMatch) {
  auto conn = createConn();
  StreamId id = 5;
  QuicStreamState stream(id, *conn);
  stream.sendState = StreamSendState::ResetSent;
  stream.recvState = StreamRecvState::Open;
  stream.finalReadOffset = 200;

  receiveRstStreamSMHandler(
      stream, RstStreamFrame(1, GenericApplicationErrorCode::UNKNOWN, 200));
  EXPECT_EQ(stream.sendState, StreamSendState::ResetSent);
  EXPECT_EQ(stream.recvState, StreamRecvState::Closed);
  verifyStreamReset(stream, 200);
}

TEST_F(QuicRecvResetTest, FromResetSentOffsetMismatch) {
  auto conn = createConn();
  StreamId id = 5;
  QuicStreamState stream(id, *conn);
  stream.sendState = StreamSendState::ResetSent;
  stream.recvState = StreamRecvState::Open;
  stream.finalReadOffset = 300;
  EXPECT_THROW(
      receiveRstStreamSMHandler(
          stream, RstStreamFrame(1, GenericApplicationErrorCode::UNKNOWN, 200)),
      QuicTransportException);
}

TEST_F(QuicRecvResetTest, FromClosedNoReadOffsetYet) {
  auto conn = createConn();
  StreamId id = 5;
  QuicStreamState stream(id, *conn);
  stream.sendState = StreamSendState::Closed;
  stream.recvState = StreamRecvState::Closed;
  receiveRstStreamSMHandler(
      stream, RstStreamFrame(1, GenericApplicationErrorCode::UNKNOWN, 200));
  EXPECT_EQ(stream.sendState, StreamSendState::Closed);
  EXPECT_EQ(stream.recvState, StreamRecvState::Closed);
  verifyStreamReset(stream, 200);
}

TEST_F(QuicRecvResetTest, FromClosedOffsetMatch) {
  auto conn = createConn();
  StreamId id = 5;
  QuicStreamState stream(id, *conn);
  stream.sendState = StreamSendState::Closed;
  stream.recvState = StreamRecvState::Closed;
  stream.finalReadOffset = 1234;
  receiveRstStreamSMHandler(
      stream, RstStreamFrame(1, GenericApplicationErrorCode::UNKNOWN, 1234));
  EXPECT_EQ(stream.sendState, StreamSendState::Closed);
  EXPECT_EQ(stream.recvState, StreamRecvState::Closed);
  verifyStreamReset(stream, 1234);
}

TEST_F(QuicRecvResetTest, FromClosedOffsetMismatch) {
  auto conn = createConn();
  StreamId id = 5;
  QuicStreamState stream(id, *conn);
  stream.sendState = StreamSendState::Closed;
  stream.recvState = StreamRecvState::Closed;
  stream.finalReadOffset = 123;
  EXPECT_THROW(
      receiveRstStreamSMHandler(
          stream,
          RstStreamFrame(1, GenericApplicationErrorCode::UNKNOWN, 1234)),
      QuicTransportException);
}

class QuicUnidirectionalStreamTest : public Test {};

TEST_F(QuicUnidirectionalStreamTest, OpenInvalidReadStream) {
  auto conn = createConn();
  StreamId id = 0b111;
  QuicStreamState stream(id, *conn);
  stream.sendState = StreamSendState::Open;
  stream.recvState = StreamRecvState::Invalid;
  EXPECT_THROW(
      receiveReadStreamFrameSMHandler(stream, ReadStreamFrame(id, 1, false)),
      QuicTransportException);
}

TEST_F(QuicUnidirectionalStreamTest, OpenInvalidRstStream) {
  auto conn = createConn();
  StreamId id = 0b111;
  QuicStreamState stream(id, *conn);
  stream.sendState = StreamSendState::Open;
  stream.recvState = StreamRecvState::Invalid;
  EXPECT_THROW(
      receiveRstStreamSMHandler(
          stream,
          RstStreamFrame(1, GenericApplicationErrorCode::UNKNOWN, 1234)),
      QuicTransportException);
}

TEST_F(QuicUnidirectionalStreamTest, OpenInvalidSendReset) {
  auto conn = createConn();
  StreamId id = 0b110;
  QuicStreamState stream(id, *conn);
  stream.sendState = StreamSendState::Invalid;
  stream.recvState = StreamRecvState::Open;

  EXPECT_THROW(
      sendRstSMHandler(stream, GenericApplicationErrorCode::UNKNOWN),
      QuicTransportException);
}

TEST_F(QuicUnidirectionalStreamTest, OpenInvalidAckStreamFrame) {
  auto conn = createConn();
  StreamId id = 0b110;
  QuicStreamState stream(id, *conn);
  stream.sendState = StreamSendState::Invalid;
  stream.recvState = StreamRecvState::Open;
  WriteStreamFrame ackedFrame(id, 0, 0, false);
  EXPECT_THROW(sendAckSMHandler(stream, ackedFrame), QuicTransportException);
}

TEST_F(QuicUnidirectionalStreamTest, OpenInvalidStopSending) {
  auto conn = createConn();
  StreamId id = 0b110;
  QuicStreamState stream(id, *conn);
  stream.sendState = StreamSendState::Invalid;
  stream.recvState = StreamRecvState::Open;
  EXPECT_THROW(
      sendStopSendingSMHandler(
          stream, StopSendingFrame(id, GenericApplicationErrorCode::UNKNOWN)),
      QuicTransportException);
}

TEST_F(QuicUnidirectionalStreamTest, ClosedInvalidReadStream) {
  auto conn = createConn();
  StreamId id = 0b111;
  QuicStreamState stream(id, *conn);
  stream.sendState = StreamSendState::Open;
  stream.recvState = StreamRecvState::Invalid;
  EXPECT_THROW(
      receiveReadStreamFrameSMHandler(stream, ReadStreamFrame(id, 1, false)),
      QuicTransportException);
}

TEST_F(QuicUnidirectionalStreamTest, ClosedInvalidRstStream) {
  auto conn = createConn();
  StreamId id = 0b111;
  QuicStreamState stream(id, *conn);
  stream.sendState = StreamSendState::Open;
  stream.recvState = StreamRecvState::Invalid;
  EXPECT_THROW(
      receiveRstStreamSMHandler(
          stream,
          RstStreamFrame(1, GenericApplicationErrorCode::UNKNOWN, 1234)),
      QuicTransportException);
}

TEST_F(QuicUnidirectionalStreamTest, ClosedInvalidSendReset) {
  auto conn = createConn();
  StreamId id = 0b110;
  QuicStreamState stream(id, *conn);
  stream.sendState = StreamSendState::Invalid;
  stream.recvState = StreamRecvState::Closed;
  EXPECT_THROW(
      sendRstSMHandler(stream, GenericApplicationErrorCode::UNKNOWN),
      QuicTransportException);
}

TEST_F(QuicUnidirectionalStreamTest, ClosedInvalidAckStreamFrame) {
  auto conn = createConn();
  StreamId id = 0b110;
  QuicStreamState stream(id, *conn);
  stream.sendState = StreamSendState::Invalid;
  stream.recvState = StreamRecvState::Closed;

  WriteStreamFrame ackedFrame(id, 0, 0, false);
  EXPECT_THROW(sendAckSMHandler(stream, ackedFrame), QuicTransportException);
}

TEST_F(QuicUnidirectionalStreamTest, ClosedInvalidStopSending) {
  auto conn = createConn();
  StreamId id = 0b110;
  QuicStreamState stream(id, *conn);
  stream.sendState = StreamSendState::Invalid;
  stream.recvState = StreamRecvState::Closed;
  EXPECT_THROW(
      sendStopSendingSMHandler(
          stream, StopSendingFrame(id, GenericApplicationErrorCode::UNKNOWN)),
      QuicTransportException);
}

TEST_F(QuicUnidirectionalStreamTest, OpenReadStreamFin) {
  auto conn = createConn();
  StreamId id = 0b110;
  QuicStreamState stream(id, *conn);
  stream.sendState = StreamSendState::Invalid;
  stream.recvState = StreamRecvState::Open;
  stream.currentReadOffset = 100;
  ReadStreamFrame receivedStreamFrame(stream.id, 100, true);
  receivedStreamFrame.data = folly::IOBuf::create(10);
  receivedStreamFrame.data->append(10);
  receiveReadStreamFrameSMHandler(stream, std::move(receivedStreamFrame));
  EXPECT_EQ(stream.sendState, StreamSendState::Invalid);
  EXPECT_EQ(stream.recvState, StreamRecvState::Closed);
}

TEST_F(QuicUnidirectionalStreamTest, OpenRstStream) {
  auto conn = createConn();
  StreamId id = 0b110;
  QuicStreamState stream(id, *conn);
  stream.sendState = StreamSendState::Invalid;
  stream.recvState = StreamRecvState::Open;

  receiveRstStreamSMHandler(
      stream, RstStreamFrame(1, GenericApplicationErrorCode::UNKNOWN, 1234));
  EXPECT_EQ(stream.sendState, StreamSendState::Invalid);
  EXPECT_EQ(stream.recvState, StreamRecvState::Closed);
}

TEST_F(QuicUnidirectionalStreamTest, OpenFinalAckStreamFrame) {
  auto conn = createConn();
  StreamId id = 0b111;
  QuicStreamState stream(id, *conn);
  WriteStreamFrame streamFrame(id, 1, 1, false);
  stream.sendState = StreamSendState::Open;
  stream.recvState = StreamRecvState::Invalid;
  stream.finalWriteOffset = 1;
  stream.currentWriteOffset = 2;
  auto buf = folly::IOBuf::create(1);
  buf->append(1);
  stream.retransmissionBuffer.emplace(
      std::piecewise_construct,
      std::forward_as_tuple(1),
      std::forward_as_tuple(
          std::make_unique<StreamBuffer>(std::move(buf), 1, false)));
  sendAckSMHandler(stream, streamFrame);
  EXPECT_EQ(stream.sendState, StreamSendState::Closed);
  EXPECT_EQ(stream.recvState, StreamRecvState::Invalid);
}

TEST_F(QuicUnidirectionalStreamTest, ResetSentInvalidReadStream) {
  auto conn = createConn();
  StreamId id = 0b111;
  QuicStreamState stream(id, *conn);
  stream.sendState = StreamSendState::ResetSent;
  stream.recvState = StreamRecvState::Invalid;
  EXPECT_THROW(
      receiveReadStreamFrameSMHandler(stream, ReadStreamFrame(id, 1, false)),
      QuicTransportException);
}

TEST_F(QuicUnidirectionalStreamTest, ResetSentInvalidRstStream) {
  auto conn = createConn();
  StreamId id = 0b111;
  QuicStreamState stream(id, *conn);
  stream.sendState = StreamSendState::ResetSent;
  stream.recvState = StreamRecvState::Invalid;
  EXPECT_THROW(
      receiveRstStreamSMHandler(
          stream,
          RstStreamFrame(1, GenericApplicationErrorCode::UNKNOWN, 1234)),
      QuicTransportException);
}

TEST_F(QuicOpenStateTest, DSRStreamAcked) {
  auto conn = createConn();
  conn->clientConnectionId = getTestConnectionId(0);
  conn->serverConnectionId = getTestConnectionId(1);
  auto stream = conn->streamManager->createNextBidirectionalStream().value();
  writeDataToQuicStream(
      *stream,
      folly::IOBuf::copyBuffer("Big ship stucks in small water"),
      false);
  writeBufMetaToQuicStream(*stream, BufferMeta(1000), true);
  auto bufMetaStartingOffset = stream->writeBufMeta.offset;
  handleStreamBufMetaWritten(
      *conn,
      *stream,
      bufMetaStartingOffset,
      300,
      false,
      1,
      PacketNumberSpace::AppData);
  ASSERT_NE(
      stream->retransmissionBufMetas.end(),
      stream->retransmissionBufMetas.find(bufMetaStartingOffset));
  WriteStreamFrame frame(stream->id, bufMetaStartingOffset, 300, false);
  frame.fromBufMeta = true;
  sendAckSMHandler(*stream, frame);
  EXPECT_TRUE(stream->retransmissionBufMetas.empty());
  EXPECT_EQ(stream->sendState, StreamSendState::Open);
}

TEST_F(QuicOpenStateTest, DSRFullStreamAcked) {
  auto conn = createConn();
  conn->clientConnectionId = getTestConnectionId(0);
  conn->serverConnectionId = getTestConnectionId(1);
  auto stream = conn->streamManager->createNextBidirectionalStream().value();
  auto buf = folly::IOBuf::copyBuffer("Big ship stucks in small water");
  size_t len = buf->computeChainDataLength();
  writeDataToQuicStream(*stream, std::move(buf), false);
  handleStreamWritten(
      *conn, *stream, 0, len, false, 1, PacketNumberSpace::AppData);
  ASSERT_EQ(stream->retransmissionBuffer.size(), 1);
  writeBufMetaToQuicStream(*stream, BufferMeta(1000), true);
  auto bufMetaStartingOffset = stream->writeBufMeta.offset;
  handleStreamBufMetaWritten(
      *conn,
      *stream,
      bufMetaStartingOffset,
      1000,
      true,
      1,
      PacketNumberSpace::AppData);
  ASSERT_EQ(stream->writeBuffer.chainLength(), 0);
  ASSERT_NE(
      stream->retransmissionBufMetas.end(),
      stream->retransmissionBufMetas.find(bufMetaStartingOffset));
  WriteStreamFrame frame(stream->id, bufMetaStartingOffset, 1000, true);
  frame.fromBufMeta = true;
  sendAckSMHandler(*stream, frame);
  frame.offset = 0;
  frame.len = len;
  frame.fin = false;
  frame.fromBufMeta = false;
  sendAckSMHandler(*stream, frame);
  EXPECT_TRUE(stream->retransmissionBuffer.empty());
  EXPECT_TRUE(stream->retransmissionBufMetas.empty());
  EXPECT_EQ(stream->sendState, StreamSendState::Closed);
}

} // namespace test
} // namespace quic
