/*
 * Copyright (c) Facebook, Inc. and its affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 *
 */

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <folly/Overload.h>

#include <quic/api/QuicTransportFunctions.h>
#include <quic/codec/DefaultConnectionIdAlgo.h>
#include <quic/common/test/TestUtils.h>
#include <quic/state/QuicStreamFunctions.h>
#include <quic/state/stream/StreamStateMachine.h>

using namespace folly;
using namespace testing;

namespace quic {
namespace test {

void verifyStreamReset(
    const QuicStreamState& stream,
    uint64_t readOffsetExpected) {
  EXPECT_TRUE(stream.readBuffer.empty());
  EXPECT_TRUE(stream.finalReadOffset.hasValue());
  EXPECT_EQ(readOffsetExpected, stream.finalReadOffset.value());
}

std::unique_ptr<QuicServerConnectionState> createConn() {
  auto conn = std::make_unique<QuicServerConnectionState>();
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
  invokeHandler<StreamReceiveStateMachine>(
      stream.recv, std::move(frame), stream);
  EXPECT_TRUE(stream.hasReadableData());
  EXPECT_TRUE(stream.hasPeekableData());
  EXPECT_TRUE(isState<StreamReceiveStates::Open>(stream.recv));
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
  invokeHandler<StreamReceiveStateMachine>(
      stream.recv, std::move(frame1), stream);
  EXPECT_TRUE(isState<StreamReceiveStates::Open>(stream.recv));

  uint64_t offset2 = 1;
  bool fin2 = true;
  ReadStreamFrame frame2(id, offset2, fin2);
  frame2.data = IOBuf::copyBuffer("e");
  EXPECT_THROW(
      invokeHandler<StreamReceiveStateMachine>(
          stream.recv, std::move(frame2), stream),
      QuicTransportException);
}

TEST_F(QuicOpenStateTest, InvalidEvent) {
  auto conn = createConn();
  StreamId id = 5;
  QuicStreamState stream(id, *conn);
  RstStreamFrame frame(1, GenericApplicationErrorCode::UNKNOWN, 0);
  EXPECT_THROW(
      invokeHandler<StreamSendStateMachine>(
          stream.send, StreamEvents::RstAck(frame), stream),
      QuicTransportException);
}

TEST_F(QuicOpenStateTest, ReceiveStreamFrameWithFIN) {
  auto conn = createConn();

  auto stream = conn->streamManager->createNextBidirectionalStream().value();
  stream->currentReadOffset = 100;

  // We received FIN and everything:
  ReadStreamFrame receivedStreamFrame(stream->id, 100, true);
  receivedStreamFrame.data = folly::IOBuf::create(10);
  receivedStreamFrame.data->append(10);
  invokeHandler<StreamReceiveStateMachine>(
      stream->recv, std::move(receivedStreamFrame), *stream);
  ASSERT_TRUE(isState<StreamReceiveStates::Closed>(stream->recv));
}

TEST_F(QuicOpenStateTest, ReceiveStreamFrameWithFINReadbuffHole) {
  auto conn = createConn();

  auto stream = conn->streamManager->createNextBidirectionalStream().value();
  stream->currentReadOffset = 100;

  // We received FIN, but we havn't received anything between 100 and 200:
  ReadStreamFrame receivedStreamFrame(stream->id, 200, true);
  receivedStreamFrame.data = folly::IOBuf::create(10);
  receivedStreamFrame.data->append(10);
  invokeHandler<StreamReceiveStateMachine>(
      stream->recv, std::move(receivedStreamFrame), *stream);
  ASSERT_TRUE(isState<StreamReceiveStates::Open>(stream->recv));
}

TEST_F(QuicOpenStateTest, ReceiveStreamFrameWithoutFIN) {
  auto conn = createConn();

  auto stream = conn->streamManager->createNextBidirectionalStream().value();
  stream->currentReadOffset = 100;

  // We haven't received FIN:
  ReadStreamFrame receivedStreamFrame(stream->id, 100, false);
  receivedStreamFrame.data = folly::IOBuf::create(10);
  receivedStreamFrame.data->append(10);
  invokeHandler<StreamReceiveStateMachine>(
      stream->recv, std::move(receivedStreamFrame), *stream);
  ASSERT_TRUE(isState<StreamReceiveStates::Open>(stream->recv));
}

class QuicResetSentStateTest : public Test {};

TEST_F(QuicResetSentStateTest, RstAck) {
  auto conn = createConn();
  StreamId id = 5;

  QuicStreamState stream(id, *conn);
  stream.send.state = StreamSendStates::ResetSent();
  stream.currentReadOffset = 0xABCD;
  stream.finalWriteOffset = 0xACDC;
  stream.readBuffer.emplace_back(
      folly::IOBuf::copyBuffer("One more thing"), 0xABCD, false);
  RstStreamFrame frame(id, GenericApplicationErrorCode::UNKNOWN, 0);
  invokeHandler<StreamSendStateMachine>(
      stream.send, StreamEvents::RstAck(frame), stream);

  EXPECT_TRUE(isState<StreamSendStates::Closed>(stream.send));
  EXPECT_FALSE(stream.finalReadOffset);
  EXPECT_FALSE(stream.readBuffer.empty());
}

class QuicClosedStateTest : public Test {};

TEST_F(QuicClosedStateTest, RstAck) {
  auto conn = createConn();
  StreamId id = 5;
  QuicStreamState stream(id, *conn);
  stream.send.state = StreamSendStates::Closed();
  RstStreamFrame frame(id, GenericApplicationErrorCode::UNKNOWN, 0);
  invokeHandler<StreamSendStateMachine>(
      stream.send, StreamEvents::RstAck(frame), stream);
  EXPECT_TRUE(isState<StreamSendStates::Closed>(stream.send));
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
  EXPECT_EQ(1, conn->outstandingPackets.size());

  auto& streamFrame = boost::get<WriteStreamFrame>(
      getFirstOutstandingPacket(*conn, PacketNumberSpace::AppData)
          ->packet.frames.front());

  StreamEvents::AckStreamFrame ack(streamFrame);
  invokeHandler<StreamSendStateMachine>(stream->send, ack, *stream);
  ASSERT_TRUE(isState<StreamSendStates::Closed>(stream->send));

  invokeHandler<StreamSendStateMachine>(stream->send, ack, *stream);
  ASSERT_TRUE(isState<StreamSendStates::Closed>(stream->send));
}

TEST_F(QuicOpenStateTest, AckStreamAfterSkip) {
  auto conn = createConn();
  conn->partialReliabilityEnabled = true;

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
  EXPECT_EQ(1, conn->outstandingPackets.size());

  auto& streamFrame = boost::get<WriteStreamFrame>(
      getFirstOutstandingPacket(*conn, PacketNumberSpace::AppData)
          ->packet.frames.front());

  PacketNum packetNum(1);
  MinStreamDataFrame minDataFrame(stream->id, 1000, 100);
  onRecvMinStreamDataFrame(stream, minDataFrame, packetNum);
  EXPECT_EQ(stream->minimumRetransmittableOffset, buf->length());

  EXPECT_TRUE(stream->retransmissionBuffer.empty());

  StreamEvents::AckStreamFrame ack(streamFrame);
  invokeHandler<StreamSendStateMachine>(stream->send, ack, *stream);
  ASSERT_TRUE(isState<StreamSendStates::Closed>(stream->send));
  ASSERT_TRUE(isState<StreamReceiveStates::Open>(stream->recv));

  invokeHandler<StreamSendStateMachine>(stream->send, ack, *stream);
  ASSERT_TRUE(isState<StreamSendStates::Closed>(stream->send));
  ASSERT_TRUE(isState<StreamReceiveStates::Open>(stream->recv));
}

TEST_F(QuicOpenStateTest, AckStreamAfterSkipHalfBuf) {
  auto conn = createConn();
  conn->partialReliabilityEnabled = true;

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
  EXPECT_EQ(1, conn->outstandingPackets.size());

  auto& streamFrame = boost::get<WriteStreamFrame>(
      getFirstOutstandingPacket(*conn, PacketNumberSpace::AppData)
          ->packet.frames.front());

  PacketNum packetNum(1);
  // Skip ~0.5 buffers.
  MinStreamDataFrame minDataFrame(stream->id, 1000, 3);
  onRecvMinStreamDataFrame(stream, minDataFrame, packetNum);
  EXPECT_EQ(stream->minimumRetransmittableOffset, 3);

  EXPECT_EQ(stream->retransmissionBuffer.size(), 1);

  StreamEvents::AckStreamFrame ack(streamFrame);
  invokeHandler<StreamSendStateMachine>(stream->send, ack, *stream);
  ASSERT_TRUE(isState<StreamSendStates::Closed>(stream->send));
  ASSERT_TRUE(isState<StreamReceiveStates::Open>(stream->recv));
}

TEST_F(QuicOpenStateTest, AckStreamAfterSkipOneAndAHalfBuf) {
  auto conn = createConn();
  conn->partialReliabilityEnabled = true;

  auto stream = conn->streamManager->createNextBidirectionalStream().value();
  folly::Optional<ConnectionId> serverChosenConnId = *conn->clientConnectionId;
  serverChosenConnId.value().data()[0] ^= 0x01;
  EventBase evb;
  auto sock = std::make_unique<folly::test::MockAsyncUDPSocket>(&evb);

  // Write two buffers.
  auto buf = IOBuf::copyBuffer("hello");
  writeQuicPacket(
      *conn,
      *conn->clientConnectionId,
      *serverChosenConnId,
      *sock,
      *stream,
      *buf,
      false);
  auto buf2 = IOBuf::copyBuffer("hello again");
  writeQuicPacket(
      *conn,
      *conn->clientConnectionId,
      *serverChosenConnId,
      *sock,
      *stream,
      *buf,
      true);

  EXPECT_EQ(stream->retransmissionBuffer.size(), 2);
  EXPECT_EQ(2, conn->outstandingPackets.size());

  auto streamFrameIt =
      getFirstOutstandingPacket(*conn, PacketNumberSpace::AppData);
  auto& streamFrame1 =
      boost::get<WriteStreamFrame>(streamFrameIt->packet.frames.front());
  auto& streamFrame2 = boost::get<WriteStreamFrame>(
      getNextOutstandingPacket(
          *conn, PacketNumberSpace::AppData, ++streamFrameIt)
          ->packet.frames.front());

  PacketNum packetNum(1);
  // Skip ~1.5 buffers.
  MinStreamDataFrame minDataFrame(stream->id, 1000, 7);
  onRecvMinStreamDataFrame(stream, minDataFrame, packetNum);
  EXPECT_EQ(stream->minimumRetransmittableOffset, 7);
  EXPECT_EQ(stream->retransmissionBuffer.size(), 1);

  // Send ack for the first buffer, should be ignored since that buffer was
  // discarded after the skip.
  StreamEvents::AckStreamFrame ack1(streamFrame1);
  invokeHandler<StreamSendStateMachine>(stream->send, ack1, *stream);
  EXPECT_EQ(stream->retransmissionBuffer.size(), 1);
  ASSERT_TRUE(isState<StreamSendStates::Open>(stream->send));
  ASSERT_TRUE(isState<StreamReceiveStates::Open>(stream->recv));

  // Send ack for the second buffer, should clear out the retransmit queue after
  // correctly identifying adjusted offset.
  StreamEvents::AckStreamFrame ack2(streamFrame2);
  invokeHandler<StreamSendStateMachine>(stream->send, ack2, *stream);
  EXPECT_TRUE(stream->retransmissionBuffer.empty());
  ASSERT_TRUE(isState<StreamSendStates::Closed>(stream->send));
  ASSERT_TRUE(isState<StreamReceiveStates::Open>(stream->recv));
}

class QuicHalfClosedLocalStateTest : public Test {};

TEST_F(QuicHalfClosedLocalStateTest, ReceiveStreamFrameWithFIN) {
  auto conn = createConn();

  auto stream = conn->streamManager->createNextBidirectionalStream().value();
  stream->send.state = StreamSendStates::Closed();
  stream->recv.state = StreamReceiveStates::Open();
  stream->currentReadOffset = 100;

  // We received FIN and everything:
  ReadStreamFrame receivedStreamFrame(stream->id, 100, true);
  receivedStreamFrame.data = folly::IOBuf::create(10);
  receivedStreamFrame.data->append(10);
  invokeHandler<StreamReceiveStateMachine>(
      stream->recv, std::move(receivedStreamFrame), *stream);
  ASSERT_TRUE(isState<StreamSendStates::Closed>(stream->send));
  ASSERT_TRUE(isState<StreamReceiveStates::Closed>(stream->recv));
}

TEST_F(QuicHalfClosedLocalStateTest, ReceiveStreamFrameWithFINReadbuffHole) {
  auto conn = createConn();

  auto stream = conn->streamManager->createNextBidirectionalStream().value();
  stream->send.state = StreamSendStates::Closed();
  stream->recv.state = StreamReceiveStates::Open();
  stream->currentReadOffset = 100;

  // We received FIN, but we havn't received anything between 100 and 200:
  ReadStreamFrame receivedStreamFrame(stream->id, 200, true);
  receivedStreamFrame.data = folly::IOBuf::create(10);
  receivedStreamFrame.data->append(10);
  invokeHandler<StreamReceiveStateMachine>(
      stream->recv, std::move(receivedStreamFrame), *stream);
  ASSERT_TRUE(isState<StreamSendStates::Closed>(stream->send));
  ASSERT_TRUE(isState<StreamReceiveStates::Open>(stream->recv));
}

TEST_F(QuicHalfClosedLocalStateTest, ReceiveStreamFrameWithoutFIN) {
  auto conn = createConn();

  auto stream = conn->streamManager->createNextBidirectionalStream().value();
  stream->send.state = StreamSendStates::Closed();
  stream->recv.state = StreamReceiveStates::Open();
  stream->currentReadOffset = 100;

  // We haven't received FIN:
  ReadStreamFrame receivedStreamFrame(stream->id, 100, false);
  receivedStreamFrame.data = folly::IOBuf::create(10);
  receivedStreamFrame.data->append(10);
  invokeHandler<StreamReceiveStateMachine>(
      stream->recv, std::move(receivedStreamFrame), *stream);
  ASSERT_TRUE(isState<StreamSendStates::Closed>(stream->send));
  ASSERT_TRUE(isState<StreamReceiveStates::Open>(stream->recv));
}

class QuicHalfClosedRemoteStateTest : public Test {};

TEST_F(QuicHalfClosedRemoteStateTest, AckStream) {
  auto conn = createConn();
  // create server chosen connId with processId = 0 and workerId = 0
  ServerConnectionIdParams params(0, 0, 0);
  params.clientConnId = *conn->clientConnectionId;
  auto connIdAlgo = std::make_unique<DefaultConnectionIdAlgo>();
  folly::Optional<ConnectionId> serverChosenConnId =
      connIdAlgo->encodeConnectionId(params);
  auto stream = conn->streamManager->createNextBidirectionalStream().value();
  stream->send.state = StreamSendStates::Open();
  stream->recv.state = StreamReceiveStates::Closed();

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
  EXPECT_EQ(1, conn->outstandingPackets.size());

  auto& streamFrame = boost::get<WriteStreamFrame>(
      getFirstOutstandingPacket(*conn, PacketNumberSpace::AppData)
          ->packet.frames.front());

  StreamEvents::AckStreamFrame ack(streamFrame);
  invokeHandler<StreamSendStateMachine>(stream->send, ack, *stream);
  ASSERT_TRUE(isState<StreamSendStates::Closed>(stream->send));

  invokeHandler<StreamSendStateMachine>(stream->send, ack, *stream);
  ASSERT_TRUE(isState<StreamSendStates::Closed>(stream->send));
}

TEST_F(QuicHalfClosedRemoteStateTest, AckStreamAfterSkip) {
  auto conn = createConn();
  // create server chosen connId with processId = 0 and workerId = 0
  ServerConnectionIdParams params(0, 0, 0);
  params.clientConnId = *conn->clientConnectionId;
  auto connIdAlgo = std::make_unique<DefaultConnectionIdAlgo>();
  folly::Optional<ConnectionId> serverChosenConnId =
      connIdAlgo->encodeConnectionId(params);
  auto stream = conn->streamManager->createNextBidirectionalStream().value();
  stream->send.state = StreamSendStates::Open();
  stream->recv.state = StreamReceiveStates::Closed();

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
  EXPECT_EQ(1, conn->outstandingPackets.size());

  auto& streamFrame = boost::get<WriteStreamFrame>(
      getFirstOutstandingPacket(*conn, PacketNumberSpace::AppData)
          ->packet.frames.front());

  PacketNum packetNum(1);
  MinStreamDataFrame minDataFrame(stream->id, 1000, 100);
  onRecvMinStreamDataFrame(stream, minDataFrame, packetNum);
  EXPECT_EQ(stream->minimumRetransmittableOffset, buf->length());

  EXPECT_TRUE(stream->retransmissionBuffer.empty());

  StreamEvents::AckStreamFrame ack(streamFrame);
  invokeHandler<StreamSendStateMachine>(stream->send, ack, *stream);
  ASSERT_TRUE(isState<StreamSendStates::Closed>(stream->send));
  ASSERT_TRUE(isState<StreamReceiveStates::Closed>(stream->recv));

  invokeHandler<StreamSendStateMachine>(stream->send, ack, *stream);
  ASSERT_TRUE(isState<StreamSendStates::Closed>(stream->send));
  ASSERT_TRUE(isState<StreamReceiveStates::Closed>(stream->recv));
}

class QuicSendResetTest : public Test {};

TEST_F(QuicSendResetTest, FromOpen) {
  auto conn = createConn();
  StreamId id = 5;
  QuicStreamState stream(id, *conn);
  invokeHandler<StreamSendStateMachine>(
      stream.send,
      StreamEvents::SendReset(GenericApplicationErrorCode::UNKNOWN),
      stream);
  EXPECT_TRUE(isState<StreamSendStates::ResetSent>(stream.send));
}

TEST_F(QuicSendResetTest, FromHalfCloseRemote) {
  auto conn = createConn();
  StreamId id = 5;
  QuicStreamState stream(id, *conn);
  stream.send.state = StreamSendStates::Open();
  stream.recv.state = StreamReceiveStates::Closed();
  invokeHandler<StreamSendStateMachine>(
      stream.send,
      StreamEvents::SendReset(GenericApplicationErrorCode::UNKNOWN),
      stream);
  EXPECT_TRUE(isState<StreamSendStates::ResetSent>(stream.send));
}

TEST_F(QuicSendResetTest, FromHalfCloseLocal) {
  auto conn = createConn();
  StreamId id = 5;
  QuicStreamState stream(id, *conn);
  stream.send.state = StreamSendStates::Closed();
  stream.recv.state = StreamReceiveStates::Open();
  invokeHandler<StreamSendStateMachine>(
      stream.send,
      StreamEvents::SendReset(GenericApplicationErrorCode::UNKNOWN),
      stream);

  // You cannot send a reset after FIN has been acked
  EXPECT_TRUE(isState<StreamSendStates::Closed>(stream.send));
}

TEST_F(QuicSendResetTest, FromClosed) {
  auto conn = createConn();
  StreamId id = 5;
  QuicStreamState stream(id, *conn);
  stream.send.state = StreamSendStates::Closed();
  invokeHandler<StreamSendStateMachine>(
      stream.send,
      StreamEvents::SendReset(GenericApplicationErrorCode::UNKNOWN),
      stream);
}

TEST_F(QuicSendResetTest, FromResetSent) {
  auto conn = createConn();
  StreamId id = 5;
  QuicStreamState stream(id, *conn);
  stream.send.state = StreamSendStates::ResetSent();
  invokeHandler<StreamSendStateMachine>(
      stream.send,
      StreamEvents::SendReset(GenericApplicationErrorCode::UNKNOWN),
      stream);
}

class QuicRecvResetTest : public Test {};

TEST_F(QuicRecvResetTest, FromOpen) {
  auto conn = createConn();
  StreamId id = 5;
  StreamId rstStream = 1;
  QuicStreamState stream(id, *conn);
  RstStreamFrame rst(rstStream, GenericApplicationErrorCode::UNKNOWN, 100);
  invokeHandler<StreamReceiveStateMachine>(stream.recv, std::move(rst), stream);
  EXPECT_TRUE(isState<StreamSendStates::Open>(stream.send));
  EXPECT_TRUE(isState<StreamReceiveStates::Closed>(stream.recv));
  verifyStreamReset(stream, 100);
}

TEST_F(QuicRecvResetTest, FromOpenReadEOFMismatch) {
  auto conn = createConn();
  StreamId id = 5;

  QuicStreamState stream(id, *conn);
  RstStreamFrame rst(1, GenericApplicationErrorCode::UNKNOWN, 100);
  stream.finalReadOffset = 1024;
  EXPECT_THROW(
      invokeHandler<StreamReceiveStateMachine>(
          stream.recv, std::move(rst), stream),
      QuicTransportException);
}

TEST_F(QuicRecvResetTest, FromHalfClosedRemoteNoReadOffsetYet) {
  StreamId id = 5;
  auto conn = createConn();
  QuicStreamState stream(id, *conn);
  stream.send.state = StreamSendStates::Open();
  stream.recv.state = StreamReceiveStates::Closed();
  invokeHandler<StreamReceiveStateMachine>(
      stream.recv,
      RstStreamFrame(1, GenericApplicationErrorCode::UNKNOWN, 100),
      stream);
  EXPECT_TRUE(isState<StreamSendStates::Open>(stream.send));
  EXPECT_TRUE(isState<StreamReceiveStates::Closed>(stream.recv));
  verifyStreamReset(stream, 100);
}

TEST_F(QuicRecvResetTest, FromHalfClosedRemoteReadOffsetMatch) {
  auto conn = createConn();
  StreamId id = 5;
  QuicStreamState stream(id, *conn);
  stream.send.state = StreamSendStates::Open();
  stream.recv.state = StreamReceiveStates::Closed();
  stream.finalReadOffset = 1024;
  invokeHandler<StreamReceiveStateMachine>(
      stream.recv,
      RstStreamFrame(1, GenericApplicationErrorCode::UNKNOWN, 1024),
      stream);
  EXPECT_TRUE(isState<StreamSendStates::Open>(stream.send));
  EXPECT_TRUE(isState<StreamReceiveStates::Closed>(stream.recv));
  verifyStreamReset(stream, 1024);
}

TEST_F(QuicRecvResetTest, FromHalfClosedRemoteReadOffsetMismatch) {
  auto conn = createConn();
  StreamId id = 5;
  QuicStreamState stream(id, *conn);
  stream.send.state = StreamSendStates::Open();
  stream.recv.state = StreamReceiveStates::Closed();
  stream.finalReadOffset = 1024;
  EXPECT_THROW(
      invokeHandler<StreamReceiveStateMachine>(
          stream.recv,
          RstStreamFrame(1, GenericApplicationErrorCode::UNKNOWN, 100),
          stream),
      QuicTransportException);
}

TEST_F(QuicRecvResetTest, FromHalfClosedLocal) {
  auto conn = createConn();
  StreamId id = 5;
  QuicStreamState stream(id, *conn);
  stream.send.state = StreamSendStates::Closed();
  stream.recv.state = StreamReceiveStates::Open();
  invokeHandler<StreamReceiveStateMachine>(
      stream.recv,
      RstStreamFrame(1, GenericApplicationErrorCode::UNKNOWN, 200),
      stream);
  EXPECT_TRUE(isState<StreamSendStates::Closed>(stream.send));
  EXPECT_TRUE(isState<StreamReceiveStates::Closed>(stream.recv));
  verifyStreamReset(stream, 200);
}

TEST_F(QuicRecvResetTest, FromHalfClosedLocalReadEOFMismatch) {
  auto conn = createConn();
  StreamId id = 5;
  QuicStreamState stream(id, *conn);
  stream.send.state = StreamSendStates::Closed();
  stream.recv.state = StreamReceiveStates::Open();
  stream.finalReadOffset = 2014;
  EXPECT_THROW(
      invokeHandler<StreamReceiveStateMachine>(
          stream.recv,
          RstStreamFrame(1, GenericApplicationErrorCode::UNKNOWN, 200),
          stream),
      QuicTransportException);
}

TEST_F(QuicRecvResetTest, FromResetSentNoReadOffsetYet) {
  auto conn = createConn();
  StreamId id = 5;
  QuicStreamState stream(id, *conn);
  stream.send.state = StreamSendStates::ResetSent();
  stream.recv.state = StreamReceiveStates::Open();
  invokeHandler<StreamReceiveStateMachine>(
      stream.recv,
      RstStreamFrame(1, GenericApplicationErrorCode::UNKNOWN, 200),
      stream);
  EXPECT_TRUE(isState<StreamSendStates::ResetSent>(stream.send));
  EXPECT_TRUE(isState<StreamReceiveStates::Closed>(stream.recv));
  verifyStreamReset(stream, 200);
}

TEST_F(QuicRecvResetTest, FromResetSentOffsetMatch) {
  auto conn = createConn();
  StreamId id = 5;
  QuicStreamState stream(id, *conn);
  stream.send.state = StreamSendStates::ResetSent();
  stream.recv.state = StreamReceiveStates::Open();
  stream.finalReadOffset = 200;
  invokeHandler<StreamReceiveStateMachine>(
      stream.recv,
      RstStreamFrame(1, GenericApplicationErrorCode::UNKNOWN, 200),
      stream);
  EXPECT_TRUE(isState<StreamSendStates::ResetSent>(stream.send));
  EXPECT_TRUE(isState<StreamReceiveStates::Closed>(stream.recv));
  verifyStreamReset(stream, 200);
}

TEST_F(QuicRecvResetTest, FromResetSentOffsetMismatch) {
  auto conn = createConn();
  StreamId id = 5;
  QuicStreamState stream(id, *conn);
  stream.send.state = StreamSendStates::ResetSent();
  stream.recv.state = StreamReceiveStates::Open();
  stream.finalReadOffset = 300;
  EXPECT_THROW(
      invokeHandler<StreamReceiveStateMachine>(
          stream.recv,
          RstStreamFrame(1, GenericApplicationErrorCode::UNKNOWN, 200),
          stream),
      QuicTransportException);
}

TEST_F(QuicRecvResetTest, FromClosedNoReadOffsetYet) {
  auto conn = createConn();
  StreamId id = 5;
  QuicStreamState stream(id, *conn);
  stream.send.state = StreamSendStates::Closed();
  stream.recv.state = StreamReceiveStates::Closed();
  invokeHandler<StreamReceiveStateMachine>(
      stream.recv,
      RstStreamFrame(1, GenericApplicationErrorCode::UNKNOWN, 200),
      stream);
  EXPECT_TRUE(isState<StreamSendStates::Closed>(stream.send));
  EXPECT_TRUE(isState<StreamReceiveStates::Closed>(stream.recv));
  verifyStreamReset(stream, 200);
}

TEST_F(QuicRecvResetTest, FromClosedOffsetMatch) {
  auto conn = createConn();
  StreamId id = 5;
  QuicStreamState stream(id, *conn);
  stream.send.state = StreamSendStates::Closed();
  stream.recv.state = StreamReceiveStates::Closed();
  stream.finalReadOffset = 1234;
  invokeHandler<StreamReceiveStateMachine>(
      stream.recv,
      RstStreamFrame(1, GenericApplicationErrorCode::UNKNOWN, 1234),
      stream);
  EXPECT_TRUE(isState<StreamSendStates::Closed>(stream.send));
  EXPECT_TRUE(isState<StreamReceiveStates::Closed>(stream.recv));
  verifyStreamReset(stream, 1234);
}

TEST_F(QuicRecvResetTest, FromClosedOffsetMismatch) {
  auto conn = createConn();
  StreamId id = 5;
  QuicStreamState stream(id, *conn);
  stream.send.state = StreamSendStates::Closed();
  stream.recv.state = StreamReceiveStates::Closed();
  stream.finalReadOffset = 123;
  EXPECT_THROW(
      invokeHandler<StreamReceiveStateMachine>(
          stream.recv,
          RstStreamFrame(1, GenericApplicationErrorCode::UNKNOWN, 1234),
          stream),
      QuicTransportException);
}

class QuicUnidirectionalStreamTest : public Test {};

TEST_F(QuicUnidirectionalStreamTest, OpenInvalidReadStream) {
  auto conn = createConn();
  StreamId id = 0b111;
  QuicStreamState stream(id, *conn);
  stream.send.state = StreamSendStates::Open();
  stream.recv.state = StreamReceiveStates::Invalid();
  EXPECT_THROW(
      invokeHandler<StreamReceiveStateMachine>(
          stream.recv, ReadStreamFrame(id, 1, false), stream),
      QuicTransportException);
}

TEST_F(QuicUnidirectionalStreamTest, OpenInvalidRstStream) {
  auto conn = createConn();
  StreamId id = 0b111;
  QuicStreamState stream(id, *conn);
  stream.send.state = StreamSendStates::Open();
  stream.recv.state = StreamReceiveStates::Invalid();
  EXPECT_THROW(
      invokeHandler<StreamReceiveStateMachine>(
          stream.recv,
          RstStreamFrame(1, GenericApplicationErrorCode::UNKNOWN, 1234),
          stream),
      QuicTransportException);
}

TEST_F(QuicUnidirectionalStreamTest, OpenInvalidSendReset) {
  auto conn = createConn();
  StreamId id = 0b110;
  QuicStreamState stream(id, *conn);
  stream.send.state = StreamSendStates::Invalid();
  stream.recv.state = StreamReceiveStates::Open();
  EXPECT_THROW(
      invokeHandler<StreamSendStateMachine>(
          stream.send,
          StreamEvents::SendReset(GenericApplicationErrorCode::UNKNOWN),
          stream),
      QuicTransportException);
}

TEST_F(QuicUnidirectionalStreamTest, OpenInvalidAckStreamFrame) {
  auto conn = createConn();
  StreamId id = 0b110;
  QuicStreamState stream(id, *conn);
  stream.send.state = StreamSendStates::Invalid();
  stream.recv.state = StreamReceiveStates::Open();
  StreamEvents::AckStreamFrame ack(WriteStreamFrame(id, 0, 0, false));
  EXPECT_THROW(
      invokeHandler<StreamSendStateMachine>(stream.send, ack, stream),
      QuicTransportException);
}

TEST_F(QuicUnidirectionalStreamTest, OpenInvalidStopSending) {
  auto conn = createConn();
  StreamId id = 0b110;
  QuicStreamState stream(id, *conn);
  stream.send.state = StreamSendStates::Invalid();
  stream.recv.state = StreamReceiveStates::Open();
  EXPECT_THROW(
      invokeHandler<StreamSendStateMachine>(
          stream.send,
          StopSendingFrame(id, GenericApplicationErrorCode::UNKNOWN),
          stream),
      QuicTransportException);
}

TEST_F(QuicUnidirectionalStreamTest, ClosedInvalidReadStream) {
  auto conn = createConn();
  StreamId id = 0b111;
  QuicStreamState stream(id, *conn);
  stream.send.state = StreamSendStates::Open();
  stream.recv.state = StreamReceiveStates::Invalid();
  EXPECT_THROW(
      invokeHandler<StreamReceiveStateMachine>(
          stream.recv, ReadStreamFrame(id, 1, false), stream),
      QuicTransportException);
}

TEST_F(QuicUnidirectionalStreamTest, ClosedInvalidRstStream) {
  auto conn = createConn();
  StreamId id = 0b111;
  QuicStreamState stream(id, *conn);
  stream.send.state = StreamSendStates::Open();
  stream.recv.state = StreamReceiveStates::Invalid();
  EXPECT_THROW(
      invokeHandler<StreamReceiveStateMachine>(
          stream.recv,
          RstStreamFrame(1, GenericApplicationErrorCode::UNKNOWN, 1234),
          stream),
      QuicTransportException);
}

TEST_F(QuicUnidirectionalStreamTest, ClosedInvalidSendReset) {
  auto conn = createConn();
  StreamId id = 0b110;
  QuicStreamState stream(id, *conn);
  stream.send.state = StreamSendStates::Invalid();
  stream.recv.state = StreamReceiveStates::Closed();
  EXPECT_THROW(
      invokeHandler<StreamSendStateMachine>(
          stream.send,
          StreamEvents::SendReset(GenericApplicationErrorCode::UNKNOWN),
          stream),
      QuicTransportException);
}

TEST_F(QuicUnidirectionalStreamTest, ClosedInvalidAckStreamFrame) {
  auto conn = createConn();
  StreamId id = 0b110;
  QuicStreamState stream(id, *conn);
  stream.send.state = StreamSendStates::Invalid();
  stream.recv.state = StreamReceiveStates::Closed();
  StreamEvents::AckStreamFrame ack(WriteStreamFrame(id, 0, 0, false));
  EXPECT_THROW(
      invokeHandler<StreamSendStateMachine>(stream.send, ack, stream),
      QuicTransportException);
}

TEST_F(QuicUnidirectionalStreamTest, ClosedInvalidStopSending) {
  auto conn = createConn();
  StreamId id = 0b110;
  QuicStreamState stream(id, *conn);
  stream.send.state = StreamSendStates::Invalid();
  stream.recv.state = StreamReceiveStates::Closed();
  EXPECT_THROW(
      invokeHandler<StreamSendStateMachine>(
          stream.send,
          StopSendingFrame(id, GenericApplicationErrorCode::UNKNOWN),
          stream),
      QuicTransportException);
}

TEST_F(QuicUnidirectionalStreamTest, OpenReadStreamFin) {
  auto conn = createConn();
  StreamId id = 0b110;
  QuicStreamState stream(id, *conn);
  stream.send.state = StreamSendStates::Invalid();
  stream.recv.state = StreamReceiveStates::Open();
  stream.currentReadOffset = 100;
  ReadStreamFrame receivedStreamFrame(stream.id, 100, true);
  receivedStreamFrame.data = folly::IOBuf::create(10);
  receivedStreamFrame.data->append(10);
  invokeHandler<StreamReceiveStateMachine>(
      stream.recv, std::move(receivedStreamFrame), stream);
  EXPECT_TRUE(isState<StreamSendStates::Invalid>(stream.send));
  EXPECT_TRUE(isState<StreamReceiveStates::Closed>(stream.recv));
}

TEST_F(QuicUnidirectionalStreamTest, OpenRstStream) {
  auto conn = createConn();
  StreamId id = 0b110;
  QuicStreamState stream(id, *conn);
  stream.send.state = StreamSendStates::Invalid();
  stream.recv.state = StreamReceiveStates::Open();
  invokeHandler<StreamReceiveStateMachine>(
      stream.recv,
      RstStreamFrame(1, GenericApplicationErrorCode::UNKNOWN, 1234),
      stream);
  EXPECT_TRUE(isState<StreamSendStates::Invalid>(stream.send));
  EXPECT_TRUE(isState<StreamReceiveStates::Closed>(stream.recv));
}

TEST_F(QuicUnidirectionalStreamTest, OpenFinalAckStreamFrame) {
  auto conn = createConn();
  StreamId id = 0b111;
  QuicStreamState stream(id, *conn);
  WriteStreamFrame streamFrame(id, 1, 1, false);
  stream.send.state = StreamSendStates::Open();
  stream.recv.state = StreamReceiveStates::Invalid();
  stream.finalWriteOffset = 1;
  stream.currentWriteOffset = 2;
  auto buf = folly::IOBuf::create(1);
  buf->append(1);
  stream.retransmissionBuffer.emplace_back(std::move(buf), 1, false);
  StreamEvents::AckStreamFrame ack(streamFrame);
  invokeHandler<StreamSendStateMachine>(stream.send, ack, stream);
  EXPECT_TRUE(isState<StreamSendStates::Closed>(stream.send));
  EXPECT_TRUE(isState<StreamReceiveStates::Invalid>(stream.recv));
}

TEST_F(QuicUnidirectionalStreamTest, ResetSentInvalidReadStream) {
  auto conn = createConn();
  StreamId id = 0b111;
  QuicStreamState stream(id, *conn);
  stream.send.state = StreamSendStates::ResetSent();
  stream.recv.state = StreamReceiveStates::Invalid();
  EXPECT_THROW(
      invokeHandler<StreamReceiveStateMachine>(
          stream.recv, ReadStreamFrame(id, 1, false), stream),
      QuicTransportException);
}

TEST_F(QuicUnidirectionalStreamTest, ResetSentInvalidRstStream) {
  auto conn = createConn();
  StreamId id = 0b111;
  QuicStreamState stream(id, *conn);
  stream.send.state = StreamSendStates::ResetSent();
  stream.recv.state = StreamReceiveStates::Invalid();
  EXPECT_THROW(
      invokeHandler<StreamReceiveStateMachine>(
          stream.recv,
          RstStreamFrame(1, GenericApplicationErrorCode::UNKNOWN, 1234),
          stream),
      QuicTransportException);
}

} // namespace test
} // namespace quic
