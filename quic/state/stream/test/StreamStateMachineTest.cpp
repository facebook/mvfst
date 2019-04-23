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
  EXPECT_TRUE(stream.retransmissionBuffer.empty());
  EXPECT_TRUE(stream.writeBuffer.empty());
  EXPECT_TRUE(stream.finalReadOffset.hasValue());
  EXPECT_EQ(readOffsetExpected, stream.finalReadOffset.value());
  EXPECT_FALSE(stream.writable());
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
  invokeHandler<StreamStateMachine>(stream, std::move(frame));
  EXPECT_TRUE(stream.hasReadableData());
  EXPECT_TRUE(stream.hasPeekableData());
  EXPECT_TRUE(isState<StreamStates::Open>(stream));
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
  invokeHandler<StreamStateMachine>(stream, std::move(frame1));
  EXPECT_TRUE(isState<StreamStates::Open>(stream));

  uint64_t offset2 = 1;
  bool fin2 = true;
  ReadStreamFrame frame2(id, offset2, fin2);
  frame2.data = IOBuf::copyBuffer("e");
  EXPECT_THROW(
      invokeHandler<StreamStateMachine>(stream, std::move(frame2)),
      QuicTransportException);
}

TEST_F(QuicOpenStateTest, InvalidEvent) {
  auto conn = createConn();
  StreamId id = 5;
  QuicStreamState stream(id, *conn);
  RstStreamFrame frame(1, ApplicationErrorCode::STOPPING, 0);
  EXPECT_THROW(
      invokeHandler<StreamStateMachine>(stream, StreamEvents::RstAck(frame)),
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
  invokeHandler<StreamStateMachine>(*stream, std::move(receivedStreamFrame));
  ASSERT_TRUE(isState<StreamStates::HalfClosedRemote>(*stream));
}

TEST_F(QuicOpenStateTest, ReceiveStreamFrameWithFINReadbuffHole) {
  auto conn = createConn();

  auto stream = conn->streamManager->createNextBidirectionalStream().value();
  stream->currentReadOffset = 100;

  // We received FIN, but we havn't received anything between 100 and 200:
  ReadStreamFrame receivedStreamFrame(stream->id, 200, true);
  receivedStreamFrame.data = folly::IOBuf::create(10);
  receivedStreamFrame.data->append(10);
  invokeHandler<StreamStateMachine>(*stream, std::move(receivedStreamFrame));
  ASSERT_TRUE(isState<StreamStates::Open>(*stream));
}

TEST_F(QuicOpenStateTest, ReceiveStreamFrameWithoutFIN) {
  auto conn = createConn();

  auto stream = conn->streamManager->createNextBidirectionalStream().value();
  stream->currentReadOffset = 100;

  // We haven't received FIN:
  ReadStreamFrame receivedStreamFrame(stream->id, 100, false);
  receivedStreamFrame.data = folly::IOBuf::create(10);
  receivedStreamFrame.data->append(10);
  invokeHandler<StreamStateMachine>(*stream, std::move(receivedStreamFrame));
  ASSERT_TRUE(isState<StreamStates::Open>(*stream));
}

class QuicWaitingForRstAckStateTest : public Test {};

TEST_F(QuicWaitingForRstAckStateTest, RstAck) {
  auto conn = createConn();
  StreamId id = 5;

  QuicStreamState stream(id, *conn);
  stream.state = StreamStates::WaitingForRstAck();
  stream.currentReadOffset = 0xABCD;
  stream.finalWriteOffset = 0xACDC;
  stream.readBuffer.emplace_back(
      folly::IOBuf::copyBuffer("One more thing"), 0xABCD, false);
  RstStreamFrame frame(id, ApplicationErrorCode::STOPPING, 0);
  invokeHandler<StreamStateMachine>(stream, StreamEvents::RstAck(frame));

  EXPECT_TRUE(isState<StreamStates::Closed>(stream));
  EXPECT_FALSE(stream.finalReadOffset);
  EXPECT_FALSE(stream.readBuffer.empty());
}

class QuicClosedStateTest : public Test {};

TEST_F(QuicClosedStateTest, RstAck) {
  auto conn = createConn();
  StreamId id = 5;
  QuicStreamState stream(id, *conn);
  stream.state = StreamStates::Closed();
  RstStreamFrame frame(id, ApplicationErrorCode::STOPPING, 0);
  invokeHandler<StreamStateMachine>(stream, StreamEvents::RstAck(frame));
  EXPECT_TRUE(isState<StreamStates::Closed>(stream));
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
  invokeHandler<StreamStateMachine>(*stream, ack);
  ASSERT_TRUE(isState<StreamStates::HalfClosedLocal>(*stream));

  invokeHandler<StreamStateMachine>(*stream, ack);
  ASSERT_TRUE(isState<StreamStates::HalfClosedLocal>(*stream));
}

class QuicHalfClosedLocalStateTest : public Test {};

TEST_F(QuicHalfClosedLocalStateTest, ReceiveStreamFrameWithFIN) {
  auto conn = createConn();

  auto stream = conn->streamManager->createNextBidirectionalStream().value();
  stream->state = StreamStates::HalfClosedLocal();
  stream->currentReadOffset = 100;

  // We received FIN and everything:
  ReadStreamFrame receivedStreamFrame(stream->id, 100, true);
  receivedStreamFrame.data = folly::IOBuf::create(10);
  receivedStreamFrame.data->append(10);
  invokeHandler<StreamStateMachine>(*stream, std::move(receivedStreamFrame));
  ASSERT_TRUE(isState<StreamStates::Closed>(*stream));
}

TEST_F(QuicHalfClosedLocalStateTest, ReceiveStreamFrameWithFINReadbuffHole) {
  auto conn = createConn();

  auto stream = conn->streamManager->createNextBidirectionalStream().value();
  stream->state = StreamStates::HalfClosedLocal();
  stream->currentReadOffset = 100;

  // We received FIN, but we havn't received anything between 100 and 200:
  ReadStreamFrame receivedStreamFrame(stream->id, 200, true);
  receivedStreamFrame.data = folly::IOBuf::create(10);
  receivedStreamFrame.data->append(10);
  invokeHandler<StreamStateMachine>(*stream, std::move(receivedStreamFrame));
  ASSERT_TRUE(isState<StreamStates::HalfClosedLocal>(*stream));
}

TEST_F(QuicHalfClosedLocalStateTest, ReceiveStreamFrameWithoutFIN) {
  auto conn = createConn();

  auto stream = conn->streamManager->createNextBidirectionalStream().value();
  stream->state = StreamStates::HalfClosedLocal();
  stream->currentReadOffset = 100;

  // We haven't received FIN:
  ReadStreamFrame receivedStreamFrame(stream->id, 100, false);
  receivedStreamFrame.data = folly::IOBuf::create(10);
  receivedStreamFrame.data->append(10);
  invokeHandler<StreamStateMachine>(*stream, std::move(receivedStreamFrame));
  ASSERT_TRUE(isState<StreamStates::HalfClosedLocal>(*stream));
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
  stream->state = StreamStates::HalfClosedRemote();

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
  invokeHandler<StreamStateMachine>(*stream, ack);
  ASSERT_TRUE(isState<StreamStates::Closed>(*stream));

  invokeHandler<StreamStateMachine>(*stream, ack);
  ASSERT_TRUE(isState<StreamStates::Closed>(*stream));
}

class QuicSendResetTest : public Test {};

TEST_F(QuicSendResetTest, FromOpen) {
  auto conn = createConn();
  StreamId id = 5;
  QuicStreamState stream(id, *conn);
  invokeHandler<StreamStateMachine>(
      stream, StreamEvents::SendReset(ApplicationErrorCode::STOPPING));
  EXPECT_TRUE(isState<StreamStates::WaitingForRstAck>(stream));
}

TEST_F(QuicSendResetTest, FromHalfCloseRemote) {
  auto conn = createConn();
  StreamId id = 5;
  QuicStreamState stream(id, *conn);
  stream.state = StreamStates::HalfClosedRemote();
  invokeHandler<StreamStateMachine>(
      stream, StreamEvents::SendReset(ApplicationErrorCode::STOPPING));
  EXPECT_TRUE(isState<StreamStates::WaitingForRstAck>(stream));
}

TEST_F(QuicSendResetTest, FromHalfCloseLocal) {
  auto conn = createConn();
  StreamId id = 5;
  QuicStreamState stream(id, *conn);
  stream.state = StreamStates::HalfClosedLocal();
  invokeHandler<StreamStateMachine>(
      stream, StreamEvents::SendReset(ApplicationErrorCode::STOPPING));
  EXPECT_TRUE(isState<StreamStates::WaitingForRstAck>(stream));
}

TEST_F(QuicSendResetTest, FromClosed) {
  auto conn = createConn();
  StreamId id = 5;
  QuicStreamState stream(id, *conn);
  stream.state = StreamStates::Closed();
  invokeHandler<StreamStateMachine>(
      stream, StreamEvents::SendReset(ApplicationErrorCode::STOPPING));
}

TEST_F(QuicSendResetTest, FromWaitingForRstAck) {
  auto conn = createConn();
  StreamId id = 5;
  QuicStreamState stream(id, *conn);
  stream.state = StreamStates::WaitingForRstAck();
  invokeHandler<StreamStateMachine>(
      stream, StreamEvents::SendReset(ApplicationErrorCode::STOPPING));
}

class QuicRecvResetTest : public Test {};

TEST_F(QuicRecvResetTest, FromOpen) {
  auto conn = createConn();
  StreamId id = 5;
  StreamId rstStream = 1;
  QuicStreamState stream(id, *conn);
  RstStreamFrame rst(rstStream, ApplicationErrorCode::STOPPING, 100);
  invokeHandler<StreamStateMachine>(stream, std::move(rst));
  EXPECT_TRUE(isState<StreamStates::WaitingForRstAck>(stream));
  verifyStreamReset(stream, 100);
}

TEST_F(QuicRecvResetTest, FromOpenReadEOFMismatch) {
  auto conn = createConn();
  StreamId id = 5;

  QuicStreamState stream(id, *conn);
  RstStreamFrame rst(1, ApplicationErrorCode::STOPPING, 100);
  stream.finalReadOffset = 1024;
  EXPECT_THROW(
      invokeHandler<StreamStateMachine>(stream, std::move(rst)),
      QuicTransportException);
}

TEST_F(QuicRecvResetTest, FromHalfClosedRemoteNoReadOffsetYet) {
  StreamId id = 5;
  auto conn = createConn();
  QuicStreamState stream(id, *conn);
  stream.state = StreamStates::HalfClosedRemote();
  invokeHandler<StreamStateMachine>(
      stream, RstStreamFrame(1, ApplicationErrorCode::STOPPING, 100));
  EXPECT_TRUE(isState<StreamStates::WaitingForRstAck>(stream));
  verifyStreamReset(stream, 100);
}

TEST_F(QuicRecvResetTest, FromHalfClosedRemoteReadOffsetMatch) {
  auto conn = createConn();
  StreamId id = 5;
  QuicStreamState stream(id, *conn);
  stream.state = StreamStates::HalfClosedRemote();
  stream.finalReadOffset = 1024;
  invokeHandler<StreamStateMachine>(
      stream, RstStreamFrame(1, ApplicationErrorCode::STOPPING, 1024));
  EXPECT_TRUE(isState<StreamStates::WaitingForRstAck>(stream));
  verifyStreamReset(stream, 1024);
}

TEST_F(QuicRecvResetTest, FromHalfClosedRemoteReadOffsetMismatch) {
  auto conn = createConn();
  StreamId id = 5;
  QuicStreamState stream(id, *conn);
  stream.state = StreamStates::HalfClosedRemote();
  stream.finalReadOffset = 1024;
  EXPECT_THROW(
      invokeHandler<StreamStateMachine>(
          stream, RstStreamFrame(1, ApplicationErrorCode::STOPPING, 100)),
      QuicTransportException);
}

TEST_F(QuicRecvResetTest, FromHalfClosedLocal) {
  auto conn = createConn();
  StreamId id = 5;
  QuicStreamState stream(id, *conn);
  stream.state = StreamStates::HalfClosedLocal();
  invokeHandler<StreamStateMachine>(
      stream, RstStreamFrame(1, ApplicationErrorCode::STOPPING, 200));
  EXPECT_TRUE(isState<StreamStates::Closed>(stream));
  verifyStreamReset(stream, 200);
}

TEST_F(QuicRecvResetTest, FromHalfClosedLocalReadEOFMismatch) {
  auto conn = createConn();
  StreamId id = 5;
  QuicStreamState stream(id, *conn);
  stream.state = StreamStates::HalfClosedLocal();
  stream.finalReadOffset = 2014;
  EXPECT_THROW(
      invokeHandler<StreamStateMachine>(
          stream, RstStreamFrame(1, ApplicationErrorCode::STOPPING, 200)),
      QuicTransportException);
}

TEST_F(QuicRecvResetTest, FromWaitingForRstAckNoReadOffsetYet) {
  auto conn = createConn();
  StreamId id = 5;
  QuicStreamState stream(id, *conn);
  stream.state = StreamStates::WaitingForRstAck();
  invokeHandler<StreamStateMachine>(
      stream, RstStreamFrame(1, ApplicationErrorCode::STOPPING, 200));
  EXPECT_TRUE(isState<StreamStates::WaitingForRstAck>(stream));
  verifyStreamReset(stream, 200);
}

TEST_F(QuicRecvResetTest, FromWaitingForRstAckOffsetMatch) {
  auto conn = createConn();
  StreamId id = 5;
  QuicStreamState stream(id, *conn);
  stream.state = StreamStates::WaitingForRstAck();
  stream.finalReadOffset = 200;
  invokeHandler<StreamStateMachine>(
      stream, RstStreamFrame(1, ApplicationErrorCode::STOPPING, 200));
  EXPECT_TRUE(isState<StreamStates::WaitingForRstAck>(stream));
  verifyStreamReset(stream, 200);
}

TEST_F(QuicRecvResetTest, FromWaitingForRstAckOffsetMismatch) {
  auto conn = createConn();
  StreamId id = 5;
  QuicStreamState stream(id, *conn);
  stream.state = StreamStates::WaitingForRstAck();
  stream.finalReadOffset = 300;
  EXPECT_THROW(
      invokeHandler<StreamStateMachine>(
          stream, RstStreamFrame(1, ApplicationErrorCode::STOPPING, 200)),
      QuicTransportException);
}

TEST_F(QuicRecvResetTest, FromClosedNoReadOffsetYet) {
  auto conn = createConn();
  StreamId id = 5;
  QuicStreamState stream(id, *conn);
  stream.state = StreamStates::Closed();
  invokeHandler<StreamStateMachine>(
      stream, RstStreamFrame(1, ApplicationErrorCode::STOPPING, 200));
  EXPECT_TRUE(isState<StreamStates::Closed>(stream));
  verifyStreamReset(stream, 200);
}

TEST_F(QuicRecvResetTest, FromClosedOffsetMatch) {
  auto conn = createConn();
  StreamId id = 5;
  QuicStreamState stream(id, *conn);
  stream.state = StreamStates::Closed();
  stream.finalReadOffset = 1234;
  invokeHandler<StreamStateMachine>(
      stream, RstStreamFrame(1, ApplicationErrorCode::STOPPING, 1234));
  EXPECT_TRUE(isState<StreamStates::Closed>(stream));
  verifyStreamReset(stream, 1234);
}

TEST_F(QuicRecvResetTest, FromClosedOffsetMismatch) {
  auto conn = createConn();
  StreamId id = 5;
  QuicStreamState stream(id, *conn);
  stream.state = StreamStates::Closed();
  stream.finalReadOffset = 123;
  EXPECT_THROW(
      invokeHandler<StreamStateMachine>(
          stream, RstStreamFrame(1, ApplicationErrorCode::STOPPING, 1234)),
      QuicTransportException);
}

class QuicUnidirectionalStreamTest : public Test {};

TEST_F(QuicUnidirectionalStreamTest, OpenInvalidReadStream) {
  auto conn = createConn();
  StreamId id = 0b111;
  QuicStreamState stream(id, *conn);
  stream.state = StreamStates::Open();
  EXPECT_THROW(
      invokeHandler<StreamStateMachine>(stream, ReadStreamFrame(id, 1, false)),
      QuicTransportException);
}

TEST_F(QuicUnidirectionalStreamTest, OpenInvalidRstStream) {
  auto conn = createConn();
  StreamId id = 0b111;
  QuicStreamState stream(id, *conn);
  stream.state = StreamStates::Open();
  EXPECT_THROW(
      invokeHandler<StreamStateMachine>(
          stream, RstStreamFrame(1, ApplicationErrorCode::STOPPING, 1234)),
      QuicTransportException);
}

TEST_F(QuicUnidirectionalStreamTest, OpenInvalidSendReset) {
  auto conn = createConn();
  StreamId id = 0b110;
  QuicStreamState stream(id, *conn);
  stream.state = StreamStates::Open();
  EXPECT_THROW(
      invokeHandler<StreamStateMachine>(
          stream, StreamEvents::SendReset(ApplicationErrorCode::STOPPING)),
      QuicTransportException);
}

TEST_F(QuicUnidirectionalStreamTest, OpenInvalidAckStreamFrame) {
  auto conn = createConn();
  StreamId id = 0b110;
  QuicStreamState stream(id, *conn);
  stream.state = StreamStates::Open();
  StreamEvents::AckStreamFrame ack(WriteStreamFrame(id, 0, 0, false));
  EXPECT_THROW(
      invokeHandler<StreamStateMachine>(stream, ack), QuicTransportException);
}

TEST_F(QuicUnidirectionalStreamTest, OpenInvalidStopSending) {
  auto conn = createConn();
  StreamId id = 0b110;
  QuicStreamState stream(id, *conn);
  stream.state = StreamStates::Open();
  EXPECT_THROW(
      invokeHandler<StreamStateMachine>(
          stream, StopSendingFrame(id, ApplicationErrorCode::STOPPING)),
      QuicTransportException);
}

TEST_F(QuicUnidirectionalStreamTest, ClosedInvalidReadStream) {
  auto conn = createConn();
  StreamId id = 0b111;
  QuicStreamState stream(id, *conn);
  stream.state = StreamStates::Closed();
  EXPECT_THROW(
      invokeHandler<StreamStateMachine>(stream, ReadStreamFrame(id, 1, false)),
      QuicTransportException);
}

TEST_F(QuicUnidirectionalStreamTest, ClosedInvalidRstStream) {
  auto conn = createConn();
  StreamId id = 0b111;
  QuicStreamState stream(id, *conn);
  stream.state = StreamStates::Closed();
  EXPECT_THROW(
      invokeHandler<StreamStateMachine>(
          stream, RstStreamFrame(1, ApplicationErrorCode::STOPPING, 1234)),
      QuicTransportException);
}

TEST_F(QuicUnidirectionalStreamTest, ClosedInvalidSendReset) {
  auto conn = createConn();
  StreamId id = 0b110;
  QuicStreamState stream(id, *conn);
  stream.state = StreamStates::Closed();
  EXPECT_THROW(
      invokeHandler<StreamStateMachine>(
          stream, StreamEvents::SendReset(ApplicationErrorCode::STOPPING)),
      QuicTransportException);
}

TEST_F(QuicUnidirectionalStreamTest, ClosedInvalidAckStreamFrame) {
  auto conn = createConn();
  StreamId id = 0b110;
  QuicStreamState stream(id, *conn);
  stream.state = StreamStates::Closed();
  StreamEvents::AckStreamFrame ack(WriteStreamFrame(id, 0, 0, false));
  EXPECT_THROW(
      invokeHandler<StreamStateMachine>(stream, ack), QuicTransportException);
}

TEST_F(QuicUnidirectionalStreamTest, ClosedInvalidStopSending) {
  auto conn = createConn();
  StreamId id = 0b110;
  QuicStreamState stream(id, *conn);
  stream.state = StreamStates::Closed();
  EXPECT_THROW(
      invokeHandler<StreamStateMachine>(
          stream, StopSendingFrame(id, ApplicationErrorCode::STOPPING)),
      QuicTransportException);
}

TEST_F(QuicUnidirectionalStreamTest, OpenReadStreamFin) {
  auto conn = createConn();
  StreamId id = 0b110;
  QuicStreamState stream(id, *conn);
  stream.state = StreamStates::Open();
  stream.currentReadOffset = 100;
  ReadStreamFrame receivedStreamFrame(stream.id, 100, true);
  receivedStreamFrame.data = folly::IOBuf::create(10);
  receivedStreamFrame.data->append(10);
  invokeHandler<StreamStateMachine>(stream, std::move(receivedStreamFrame));
  EXPECT_TRUE(isState<StreamStates::Closed>(stream));
}

TEST_F(QuicUnidirectionalStreamTest, OpenRstStream) {
  auto conn = createConn();
  StreamId id = 0b110;
  QuicStreamState stream(id, *conn);
  stream.state = StreamStates::Open();
  invokeHandler<StreamStateMachine>(
      stream, RstStreamFrame(1, ApplicationErrorCode::STOPPING, 1234));
  EXPECT_TRUE(isState<StreamStates::Closed>(stream));
}

TEST_F(QuicUnidirectionalStreamTest, OpenFinalAckStreamFrame) {
  auto conn = createConn();
  StreamId id = 0b111;
  QuicStreamState stream(id, *conn);
  WriteStreamFrame streamFrame(id, 1, 1, false);
  stream.state = StreamStates::Open();
  stream.finalWriteOffset = 1;
  stream.currentWriteOffset = 2;
  auto buf = folly::IOBuf::create(1);
  buf->append(1);
  stream.retransmissionBuffer.emplace_back(std::move(buf), 1, false);
  StreamEvents::AckStreamFrame ack(streamFrame);
  invokeHandler<StreamStateMachine>(stream, ack);
  EXPECT_TRUE(isState<StreamStates::Closed>(stream));
}

TEST_F(QuicUnidirectionalStreamTest, WaitingForRstAckInvalidReadStream) {
  auto conn = createConn();
  StreamId id = 0b111;
  QuicStreamState stream(id, *conn);
  stream.state = StreamStates::WaitingForRstAck();
  EXPECT_THROW(
      invokeHandler<StreamStateMachine>(stream, ReadStreamFrame(id, 1, false)),
      QuicTransportException);
}

TEST_F(QuicUnidirectionalStreamTest, WaitingForRstAckInvalidRstStream) {
  auto conn = createConn();
  StreamId id = 0b111;
  QuicStreamState stream(id, *conn);
  stream.state = StreamStates::WaitingForRstAck();
  EXPECT_THROW(
      invokeHandler<StreamStateMachine>(
          stream, RstStreamFrame(1, ApplicationErrorCode::STOPPING, 1234)),
      QuicTransportException);
}

TEST_F(QuicUnidirectionalStreamTest, WaitingForRstAckInvalidStopSending) {
  auto conn = createConn();
  StreamId id = 0b110;
  QuicStreamState stream(id, *conn);
  stream.state = StreamStates::WaitingForRstAck();
  EXPECT_THROW(
      invokeHandler<StreamStateMachine>(
          stream, StopSendingFrame(id, ApplicationErrorCode::STOPPING)),
      QuicTransportException);
}
} // namespace test
} // namespace quic
