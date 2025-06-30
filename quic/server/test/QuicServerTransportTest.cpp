/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <quic/server/test/QuicServerTransportTestUtil.h>

#include <quic/QuicConstants.h>
#include <quic/codec/QuicPacketBuilder.h>
#include <quic/common/TransportKnobs.h>
#include <quic/dsr/Types.h>
#include <quic/dsr/test/Mocks.h>
#include <quic/fizz/handshake/FizzCryptoFactory.h>
#include <quic/logging/FileQLogger.h>
#include <quic/priority/HTTPPriorityQueue.h>
#include <quic/server/handshake/ServerHandshake.h>
#include <quic/state/QuicStreamFunctions.h>
#include <quic/state/test/Mocks.h>

using namespace testing;
using namespace folly;

namespace quic::test {

namespace {
auto constexpr kTestMaxPacingRate = std::numeric_limits<uint64_t>::max();
} // namespace

Optional<QuicFrame> getFrameIfPresent(
    std::vector<std::unique_ptr<folly::IOBuf>>& socketWrites,
    QuicReadCodec& readCodec,
    QuicFrame::Type frameType) {
  AckStates ackStates;
  for (auto& write : socketWrites) {
    auto packetQueue = bufToQueue(write->clone());
    auto result = readCodec.parsePacket(packetQueue, ackStates);
    auto regularPacket = result.regularPacket();
    if (!regularPacket) {
      continue;
    }
    for ([[maybe_unused]] auto& frame : regularPacket->frames) {
      if (frame.type() != frameType) {
        continue;
      }
      return frame;
    }
  }
  return std::nullopt;
}

bool verifyFramePresent(
    std::vector<std::unique_ptr<folly::IOBuf>>& socketWrites,
    QuicReadCodec& readCodec,
    QuicFrame::Type frameType) {
  return getFrameIfPresent(socketWrites, readCodec, frameType).has_value();
}

struct MigrationParam {
  Optional<uint64_t> clientSentActiveConnIdTransportParam;
};

class QuicServerTransportTest : public QuicServerTransportAfterStartTestBase {
 public:
  void SetUp() override {
    QuicServerTransportAfterStartTestBase::SetUp();
  }

  auto getTxMatcher(StreamId id, uint64_t offset) {
    return MockByteEventCallback::getTxMatcher(id, offset);
  }
};

TEST_F(QuicServerTransportTest, TestReadMultipleStreams) {
  PacketNum clientPacketNum = clientNextAppDataPacketNum++;
  ShortHeader header(
      ProtectionType::KeyPhaseZero,
      *server->getConn().serverConnectionId,
      clientPacketNum);
  RegularQuicPacketBuilder builder(
      server->getConn().udpSendPacketLen,
      std::move(header),
      0 /* largestAcked */);
  auto encodeResult = builder.encodePacketHeader();
  ASSERT_FALSE(encodeResult.hasError());
  ASSERT_TRUE(builder.canBuildPacket());

  auto buf1 = IOBuf::copyBuffer("Aloha");
  auto buf2 = IOBuf::copyBuffer("Hello");

  auto res = writeStreamFrameHeader(
      builder,
      0x08,
      0,
      buf1->computeChainDataLength(),
      buf1->computeChainDataLength(),
      true,
      std::nullopt /* skipLenHint */);
  ASSERT_TRUE(res.hasValue());
  auto dataLen = *res;
  ASSERT_TRUE(dataLen);
  ASSERT_EQ(*dataLen, buf1->computeChainDataLength());
  writeStreamFrameData(builder, buf1->clone(), buf1->computeChainDataLength());

  res = writeStreamFrameHeader(
      builder,
      0x0C,
      0,
      buf1->computeChainDataLength(),
      buf1->computeChainDataLength(),
      true,
      std::nullopt /* skipLenHint */);
  ASSERT_TRUE(res.hasValue());
  dataLen = *res;
  ASSERT_TRUE(dataLen);
  ASSERT_EQ(*dataLen, buf1->computeChainDataLength());
  writeStreamFrameData(builder, buf2->clone(), buf2->computeChainDataLength());

  auto packet = std::move(builder).buildPacket();

  // Clear out the existing acks to make sure that we are the cause of the acks.
  server->getNonConstConn().ackStates.initialAckState->acks.clear();
  server->getNonConstConn().ackStates.initialAckState->largestRecvdPacketTime =
      std::nullopt;
  server->getNonConstConn().ackStates.handshakeAckState->acks.clear();
  server->getNonConstConn()
      .ackStates.handshakeAckState->largestRecvdPacketTime = std::nullopt;
  server->getNonConstConn().ackStates.appDataAckState.acks.clear();
  server->getNonConstConn().ackStates.appDataAckState.largestRecvdPacketTime =
      std::nullopt;

  EXPECT_CALL(*quicStats_, onNewQuicStream()).Times(2); // for x08, x0C
  deliverData(packetToBuf(packet));

  EXPECT_TRUE(
      server->getConn()
          .ackStates.appDataAckState.largestRecvdPacketTime.has_value());
  EXPECT_EQ(server->getConn().ackStates.appDataAckState.acks.size(), 1);
  EXPECT_EQ(
      server->getConn().ackStates.appDataAckState.acks.front().start,
      clientPacketNum);
  EXPECT_EQ(
      server->getConn().ackStates.appDataAckState.acks.front().end,
      clientPacketNum);
  ASSERT_EQ(server->getConn().streamManager->streamCount(), 2);
  IOBufEqualTo eq;
  auto stream = server->getNonConstConn().streamManager->findStream(0x08);
  ASSERT_TRUE(stream);
  auto streamData = readDataFromQuicStream(*stream);
  ASSERT_FALSE(streamData.hasError());
  EXPECT_TRUE(eq(buf1, streamData->first));
  EXPECT_TRUE(streamData->second);

  auto stream2 = server->getNonConstConn().streamManager->findStream(0x0C);
  ASSERT_TRUE(stream2);
  auto streamData2 = readDataFromQuicStream(*stream2);
  ASSERT_FALSE(streamData2.hasError());
  EXPECT_TRUE(eq(buf2, streamData2->first));
  EXPECT_TRUE(streamData2->second);
  EXPECT_CALL(*quicStats_, onQuicStreamClosed()).Times(2);
}

TEST_F(QuicServerTransportTest, TestInvalidServerStream) {
  EXPECT_CALL(*quicStats_, onNewQuicStream()).Times(0);
  StreamId streamId = 0x01;
  auto data = IOBuf::copyBuffer("Aloha");
  EXPECT_THROW(recvEncryptedStream(streamId, *data), std::runtime_error);
  auto packetData = packetToBuf(createStreamPacket(
      *clientConnectionId,
      *server->getConn().serverConnectionId,
      clientNextAppDataPacketNum++,
      streamId,
      *data,
      0 /* cipherOverhead */,
      0 /* largestAckled */));
  EXPECT_THROW(deliverData(std::move(packetData)), std::runtime_error);
  ASSERT_EQ(server->getConn().streamManager->streamCount(), 0);
}

TEST_F(QuicServerTransportTest, IdleTimerResetOnRecvNewData) {
  EXPECT_CALL(*quicStats_, onNewQuicStream()).Times(1);
  StreamId streamId = server->createBidirectionalStream().value();
  auto expected = IOBuf::copyBuffer("hello");
  auto packet = packetToBuf(createStreamPacket(
      *clientConnectionId,
      *server->getConn().serverConnectionId,
      clientNextAppDataPacketNum++,
      streamId,
      *expected,
      0 /* cipherOverhead */,
      0 /* largestAcked */));

  server->idleTimeout().cancelTimerCallback();
  ASSERT_FALSE(server->idleTimeout().isTimerCallbackScheduled());
  recvEncryptedStream(streamId, *expected);
  ASSERT_TRUE(server->idleTimeout().isTimerCallbackScheduled());
  ASSERT_TRUE(server->keepaliveTimeout().isTimerCallbackScheduled());
  EXPECT_CALL(*quicStats_, onQuicStreamClosed());
}

TEST_F(QuicServerTransportTest, MaxBatchPacketsKnobOnlyUpdatesPacketLimit) {
  // Capture initial maxBatchSize.
  auto& conn = server->getNonConstConn();
  uint32_t initialBatchSize = conn.transportSettings.maxBatchSize;

  // Build knob param to set packet limit to 25.
  TransportKnobParams params;
  params.push_back(
      {static_cast<uint64_t>(TransportKnobParamId::MAX_BATCH_PACKETS),
       uint64_t{25}});

  server->handleKnobParams(params);

  // writeConnectionDataPacketsLimit should reflect the new value (bounded).
  EXPECT_EQ(
      conn.transportSettings.writeConnectionDataPacketsLimit,
      std::min<uint64_t>(25, kMaxWriteConnectionDataPacketLimit));

  // maxBatchSize should remain unchanged.
  EXPECT_EQ(conn.transportSettings.maxBatchSize, initialBatchSize);
}

TEST_F(QuicServerTransportTest, IdleTimerNotResetOnDuplicatePacket) {
  EXPECT_CALL(*quicStats_, onNewQuicStream()).Times(1);
  StreamId streamId = server->createBidirectionalStream().value();

  auto expected = IOBuf::copyBuffer("hello");
  auto packet = recvEncryptedStream(streamId, *expected);
  ASSERT_TRUE(server->idleTimeout().isTimerCallbackScheduled());
  ASSERT_TRUE(server->keepaliveTimeout().isTimerCallbackScheduled());

  server->idleTimeout().cancelTimerCallback();
  server->keepaliveTimeout().cancelTimerCallback();
  ASSERT_FALSE(server->idleTimeout().isTimerCallbackScheduled());
  ASSERT_FALSE(server->keepaliveTimeout().isTimerCallbackScheduled());
  // Try delivering the same packet again
  deliverData(packet->clone(), false);
  ASSERT_FALSE(server->idleTimeout().isTimerCallbackScheduled());
  ASSERT_FALSE(server->keepaliveTimeout().isTimerCallbackScheduled());
  EXPECT_CALL(*quicStats_, onQuicStreamClosed());
}

TEST_F(QuicServerTransportTest, IdleTimerNotResetWhenDataOutstanding) {
  // Clear the receivedNewPacketBeforeWrite flag, since we may reveice from
  // client during the SetUp of the test case.
  server->getNonConstConn().outstandings.reset();
  server->getNonConstConn().receivedNewPacketBeforeWrite = false;
  StreamId streamId = server->createBidirectionalStream().value();

  server->idleTimeout().cancelTimerCallback();
  server->keepaliveTimeout().cancelTimerCallback();
  ASSERT_FALSE(server->idleTimeout().isTimerCallbackScheduled());
  server->writeChain(
      streamId,
      IOBuf::copyBuffer("And if the darkness is to keep us apart"),
      false);
  loopForWrites();
  // It was the first packet
  EXPECT_TRUE(server->idleTimeout().isTimerCallbackScheduled());
  EXPECT_TRUE(server->keepaliveTimeout().isTimerCallbackScheduled());

  // cancel it and write something else. This time idle timer shouldn't set.
  server->idleTimeout().cancelTimerCallback();
  server->keepaliveTimeout().cancelTimerCallback();
  EXPECT_FALSE(server->idleTimeout().isTimerCallbackScheduled());
  server->writeChain(
      streamId,
      IOBuf::copyBuffer("And if the daylight feels like it's a long way off"),
      false);
  loopForWrites();
  EXPECT_FALSE(server->idleTimeout().isTimerCallbackScheduled());
  EXPECT_FALSE(server->keepaliveTimeout().isTimerCallbackScheduled());
}

TEST_F(QuicServerTransportTest, TimeoutsNotSetAfterClose) {
  StreamId streamId = server->createBidirectionalStream().value();

  auto expected = IOBuf::copyBuffer("hello");
  auto packet = packetToBuf(createStreamPacket(
      *clientConnectionId,
      *server->getConn().serverConnectionId,
      clientNextAppDataPacketNum++,
      streamId,
      *expected,
      0 /* cipherOverhead */,
      0 /* largestAcked */));
  server->close(QuicError(
      QuicErrorCode(TransportErrorCode::INTERNAL_ERROR),
      std::string("how about no")));
  server->idleTimeout().cancelTimerCallback();
  server->keepaliveTimeout().cancelTimerCallback();
  ASSERT_FALSE(server->idleTimeout().isTimerCallbackScheduled());

  deliverDataWithoutErrorCheck(packet->clone());
  ASSERT_FALSE(server->idleTimeout().isTimerCallbackScheduled());
  ASSERT_FALSE(server->keepaliveTimeout().isTimerCallbackScheduled());
  ASSERT_FALSE(server->lossTimeout().isTimerCallbackScheduled());
  ASSERT_FALSE(server->ackTimeout().isTimerCallbackScheduled());
  ASSERT_TRUE(server->drainTimeout().isTimerCallbackScheduled());
}

TEST_F(QuicServerTransportTest, InvalidMigrationNoDrain) {
  StreamId streamId = server->createBidirectionalStream().value();

  auto expected = IOBuf::copyBuffer("hello");
  auto packet = packetToBuf(createStreamPacket(
      *clientConnectionId,
      *server->getConn().serverConnectionId,
      clientNextAppDataPacketNum++,
      streamId,
      *expected,
      0 /* cipherOverhead */,
      0 /* largestAcked */));
  server->close(QuicError(
      QuicErrorCode(TransportErrorCode::INVALID_MIGRATION),
      std::string("migration disabled")));
  server->idleTimeout().cancelTimerCallback();
  server->keepaliveTimeout().cancelTimerCallback();
  ASSERT_FALSE(server->idleTimeout().isTimerCallbackScheduled());

  deliverDataWithoutErrorCheck(packet->clone());
  ASSERT_FALSE(server->idleTimeout().isTimerCallbackScheduled());
  ASSERT_FALSE(server->keepaliveTimeout().isTimerCallbackScheduled());
  ASSERT_FALSE(server->lossTimeout().isTimerCallbackScheduled());
  ASSERT_FALSE(server->ackTimeout().isTimerCallbackScheduled());
  ASSERT_FALSE(server->drainTimeout().isTimerCallbackScheduled());
}

TEST_F(QuicServerTransportTest, IdleTimeoutExpired) {
  server->idleTimeout().timeoutExpired();

  EXPECT_FALSE(server->idleTimeout().isTimerCallbackScheduled());
  EXPECT_TRUE(server->isDraining());
  EXPECT_TRUE(server->isClosed());
  auto serverReadCodec = makeClientEncryptedCodec();
  EXPECT_FALSE(verifyFramePresent(
      serverWrites, *serverReadCodec, QuicFrame::Type::ConnectionCloseFrame));
  EXPECT_FALSE(verifyFramePresent(
      serverWrites, *serverReadCodec, QuicFrame::Type::ConnectionCloseFrame));
}

TEST_F(QuicServerTransportTest, KeepaliveTimeoutExpired) {
  server->keepaliveTimeout().timeoutExpired();

  EXPECT_FALSE(server->isDraining());
  EXPECT_FALSE(server->isClosed());
  server->idleTimeout().cancelTimerCallback();
  server->keepaliveTimeout().cancelTimerCallback();
  server->getNonConstConn().receivedNewPacketBeforeWrite = true;
  // After we write, the idletimout and keepalive timeout should be
  // scheduled and there should be a ping written.
  loopForWrites();
  EXPECT_TRUE(server->idleTimeout().isTimerCallbackScheduled());
  EXPECT_TRUE(server->keepaliveTimeout().isTimerCallbackScheduled());
  auto serverReadCodec = makeClientEncryptedCodec();
  EXPECT_TRUE(verifyFramePresent(
      serverWrites, *serverReadCodec, QuicFrame::Type::PingFrame));
}

TEST_F(QuicServerTransportTest, RecvDataAfterIdleTimeout) {
  server->idleTimeout().timeoutExpired();

  EXPECT_FALSE(server->idleTimeout().isTimerCallbackScheduled());
  EXPECT_FALSE(server->keepaliveTimeout().isTimerCallbackScheduled());
  EXPECT_TRUE(server->isDraining());
  EXPECT_TRUE(server->isClosed());

  serverWrites.clear();
  StreamId streamId = 11;
  auto expected = IOBuf::copyBuffer("hello");
  recvEncryptedStream(streamId, *expected);
  EXPECT_TRUE(verifyFramePresent(
      serverWrites,
      *makeClientEncryptedCodec(true),
      QuicFrame::Type::ConnectionCloseFrame));
}

TEST_F(QuicServerTransportTest, TestCloseConnectionWithError) {
  server->close(QuicError(
      QuicErrorCode(GenericApplicationErrorCode::UNKNOWN),
      std::string("stopping")));
  EXPECT_TRUE(verifyFramePresent(
      serverWrites,
      *makeClientEncryptedCodec(),
      QuicFrame::Type::ConnectionCloseFrame));
}

TEST_F(QuicServerTransportTest, TestCloseConnectionWithNoError) {
  server->close(QuicError(
      QuicErrorCode(GenericApplicationErrorCode::UNKNOWN),
      std::string("stopping")));
  EXPECT_TRUE(verifyFramePresent(
      serverWrites,
      *makeClientEncryptedCodec(),
      QuicFrame::Type::ConnectionCloseFrame));
}

TEST_F(QuicServerTransportTest, TestClientAddressChanges) {
  auto qLogger = std::make_shared<FileQLogger>(VantagePoint::Server);
  server->getNonConstConn().qLogger = qLogger;
  StreamId streamId = 4;
  clientAddr = folly::SocketAddress("127.0.0.1", 2000);
  auto data = IOBuf::copyBuffer("data");
  EXPECT_THROW(
      recvEncryptedStream(streamId, *data, 0, true), std::runtime_error);
  EXPECT_TRUE(verifyFramePresent(
      serverWrites,
      *makeClientEncryptedCodec(),
      QuicFrame::Type::ConnectionCloseFrame));

  std::vector<int> indices =
      getQLogEventIndices(QLogEventType::PacketDrop, qLogger);
  EXPECT_EQ(indices.size(), 1);
  auto tmp = std::move(qLogger->logs[indices[0]]);
  auto event = dynamic_cast<QLogPacketDropEvent*>(tmp.get());
  EXPECT_EQ(event->packetSize, 29);
  EXPECT_EQ(
      event->dropReason,
      PacketDropReason(PacketDropReason::PEER_ADDRESS_CHANGE)._to_string());
}

TEST_F(QuicServerTransportTest, TestCloseConnectionWithNoErrorPendingStreams) {
  auto streamId = server->createBidirectionalStream().value();

  server->writeChain(streamId, IOBuf::copyBuffer("hello"), true);
  loopForWrites();

  AckBlocks acks;
  auto start = getFirstOutstandingPacket(
                   server->getNonConstConn(), PacketNumberSpace::AppData)
                   ->packet.header.getPacketSequenceNum();
  auto end = getLastOutstandingPacket(
                 server->getNonConstConn(), PacketNumberSpace::AppData)
                 ->packet.header.getPacketSequenceNum();
  acks.insert(start, end);
  deliverData(packetToBuf(createAckPacket(
      server->getNonConstConn(),
      ++clientNextAppDataPacketNum,
      acks,
      PacketNumberSpace::AppData)));
  server->close(QuicError(
      QuicErrorCode(GenericApplicationErrorCode::UNKNOWN),
      std::string("stopping")));

  EXPECT_THROW(
      recvEncryptedStream(streamId, *IOBuf::copyBuffer("hello")),
      std::runtime_error);
  EXPECT_TRUE(verifyFramePresent(
      serverWrites,
      *makeClientEncryptedCodec(),
      QuicFrame::Type::ConnectionCloseFrame));
}

TEST_F(QuicServerTransportTest, ReceivePacketAfterLocalError) {
  ShortHeader header(
      ProtectionType::KeyPhaseZero,
      *server->getConn().serverConnectionId,
      clientNextAppDataPacketNum++);
  RegularQuicPacketBuilder builder(
      server->getConn().udpSendPacketLen,
      std::move(header),
      0 /* largestAcked */);
  ASSERT_FALSE(builder.encodePacketHeader().hasError());
  ASSERT_TRUE(builder.canBuildPacket());

  // Deliver a reset to non existent stream to trigger a local conn error
  StreamId streamId = 0x01;
  RstStreamFrame rstFrame(streamId, GenericApplicationErrorCode::UNKNOWN, 0);
  ASSERT_FALSE(writeFrame(std::move(rstFrame), builder).hasError());
  auto packet = std::move(builder).buildPacket();
  deliverDataWithoutErrorCheck(packetToBuf(packet));
  EXPECT_TRUE(verifyFramePresent(
      serverWrites,
      *makeClientEncryptedCodec(),
      QuicFrame::Type::ConnectionCloseFrame));
  serverWrites.clear();

  ShortHeader header2(
      ProtectionType::KeyPhaseZero,
      *server->getConn().serverConnectionId,
      clientNextAppDataPacketNum++);
  RegularQuicPacketBuilder builder2(
      server->getConn().udpSendPacketLen,
      std::move(header2),
      0 /* largestAcked */);
  ASSERT_FALSE(builder2.encodePacketHeader().hasError());
  RstStreamFrame rstFrame2(streamId, GenericApplicationErrorCode::UNKNOWN, 0);
  ASSERT_FALSE(writeFrame(std::move(rstFrame2), builder2).hasError());
  auto packet2 = std::move(builder2).buildPacket();
  deliverDataWithoutErrorCheck(packetToBuf(packet2));
  EXPECT_TRUE(hasNotReceivedNewPacketsSinceLastCloseSent(server->getConn()));
  EXPECT_TRUE(verifyFramePresent(
      serverWrites,
      *makeClientEncryptedCodec(),
      QuicFrame::Type::ConnectionCloseFrame));
}

TEST_F(QuicServerTransportTest, ReceiveCloseAfterLocalError) {
  auto qLogger = std::make_shared<FileQLogger>(VantagePoint::Server);
  server->getNonConstConn().qLogger = qLogger;

  ShortHeader header(
      ProtectionType::KeyPhaseZero,
      *server->getConn().serverConnectionId,
      clientNextAppDataPacketNum++);
  RegularQuicPacketBuilder builder(
      server->getConn().udpSendPacketLen,
      std::move(header),
      0 /* largestAcked */);
  ASSERT_FALSE(builder.encodePacketHeader().hasError());
  ASSERT_TRUE(builder.canBuildPacket());

  // Deliver a reset to non existent stream to trigger a local conn error
  StreamId streamId = 0x01;
  RstStreamFrame rstFrame(streamId, GenericApplicationErrorCode::UNKNOWN, 0);
  ASSERT_FALSE(writeFrame(std::move(rstFrame), builder).hasError());
  auto packet = std::move(builder).buildPacket();
  deliverDataWithoutErrorCheck(packetToBuf(packet));
  EXPECT_TRUE(verifyFramePresent(
      serverWrites,
      *makeClientEncryptedCodec(),
      QuicFrame::Type::ConnectionCloseFrame));
  serverWrites.clear();

  auto currLargestReceivedUdpPacketNum =
      server->getConn().ackStates.appDataAckState.largestRecvdPacketNum;
  EXPECT_TRUE(hasNotReceivedNewPacketsSinceLastCloseSent(server->getConn()));

  ShortHeader header2(
      ProtectionType::KeyPhaseZero,
      *server->getConn().serverConnectionId,
      clientNextAppDataPacketNum++);
  RegularQuicPacketBuilder builder2(
      server->getConn().udpSendPacketLen,
      std::move(header2),
      0 /* largestAcked */);
  ASSERT_FALSE(builder2.encodePacketHeader().hasError());
  std::string errMsg = "Mind the gap";
  ConnectionCloseFrame connClose(
      QuicErrorCode(TransportErrorCode::NO_ERROR), errMsg);
  ASSERT_FALSE(writeFrame(std::move(connClose), builder2).hasError());

  auto packet2 = std::move(builder2).buildPacket();
  deliverDataWithoutErrorCheck(packetToBuf(packet2));
  EXPECT_FALSE(verifyFramePresent(
      serverWrites,
      *makeClientEncryptedCodec(),
      QuicFrame::Type::ConnectionCloseFrame));
  EXPECT_GT(
      server->getConn().ackStates.appDataAckState.largestRecvdPacketNum,
      currLargestReceivedUdpPacketNum);

  // Deliver the same bad data again
  EXPECT_CALL(*quicStats_, onPacketDropped(_));
  deliverDataWithoutErrorCheck(packetToBuf(packet));
  EXPECT_LT(
      server->getConn()
          .ackStates.appDataAckState.largestReceivedAtLastCloseSent,
      server->getConn().ackStates.appDataAckState.largestRecvdPacketNum);
  EXPECT_FALSE(verifyFramePresent(
      serverWrites,
      *makeClientEncryptedCodec(),
      QuicFrame::Type::ConnectionCloseFrame));
  checkTransportStateUpdate(
      qLogger, "Server closed by peer reason=Mind the gap");
}

TEST_F(QuicServerTransportTest, NoDataExceptCloseProcessedAfterClosing) {
  auto packetNum = clientNextAppDataPacketNum++;
  ShortHeader header(
      ProtectionType::KeyPhaseZero,
      *server->getConn().serverConnectionId,
      packetNum);
  RegularQuicPacketBuilder builder(
      server->getConn().udpSendPacketLen,
      std::move(header),
      0 /* largestAcked */);
  ASSERT_FALSE(builder.encodePacketHeader().hasError());
  ASSERT_TRUE(builder.canBuildPacket());

  auto buf = folly::IOBuf::copyBuffer("hello");
  ASSERT_FALSE(writeStreamFrameHeader(
                   builder,
                   4,
                   0,
                   buf->computeChainDataLength(),
                   buf->computeChainDataLength(),
                   true,
                   std::nullopt /* skipLenHint */)
                   .hasError());
  writeStreamFrameData(builder, buf->clone(), buf->computeChainDataLength());
  std::string errMsg = "Mind the gap";
  ConnectionCloseFrame connClose(
      QuicErrorCode(TransportErrorCode::NO_ERROR), errMsg);
  ASSERT_FALSE(writeFrame(std::move(connClose), builder).hasError());

  auto packet = std::move(builder).buildPacket();

  server->close(QuicError(
      QuicErrorCode(GenericApplicationErrorCode::UNKNOWN),
      std::string("hello")));
  EXPECT_TRUE(verifyFramePresent(
      serverWrites,
      *makeClientEncryptedCodec(),
      QuicFrame::Type::ConnectionCloseFrame));
  EXPECT_TRUE(hasNotReceivedNewPacketsSinceLastCloseSent(server->getConn()));
  serverWrites.clear();

  // largestRecvdPacketNum won't be accurate because we will throw
  // before updating the ack state.
  deliverDataWithoutErrorCheck(packetToBuf(packet));
  EXPECT_EQ(
      server->getConn().ackStates.appDataAckState.largestRecvdPacketNum,
      packetNum);
  EXPECT_FALSE(verifyFramePresent(
      serverWrites,
      *makeClientEncryptedCodec(),
      QuicFrame::Type::ConnectionCloseFrame));
  EXPECT_FALSE(verifyFramePresent(
      serverWrites,
      *makeClientEncryptedCodec(),
      QuicFrame::Type::ConnectionCloseFrame));
  EXPECT_EQ(server->getConn().streamManager->streamCount(), 0);
}

TEST_F(QuicServerTransportTest, TestOpenAckStreamFrame) {
  StreamId streamId = server->createBidirectionalStream().value();

  auto data = IOBuf::copyBuffer("Aloha");

  // Remove any packets that might have been queued.
  server->getNonConstConn().outstandings.reset();
  server->writeChain(streamId, data->clone(), false);
  loopForWrites();
  server->writeChain(streamId, data->clone(), false);
  server->writeChain(streamId, data->clone(), false);
  loopForWrites();

  auto streamResult =
      server->getNonConstConn().streamManager->getStream(streamId);
  ASSERT_FALSE(streamResult.hasError());
  auto stream = streamResult.value();
  ASSERT_FALSE(server->getConn().outstandings.packets.empty());
  ASSERT_FALSE(stream->retransmissionBuffer.empty());
  // We need more than one packet for this test.
  ASSERT_FALSE(server->getConn().outstandings.packets.empty());

  PacketNum packetNum1 =
      getFirstOutstandingPacket(
          server->getNonConstConn(), PacketNumberSpace::AppData)
          ->packet.header.getPacketSequenceNum();

  PacketNum lastPacketNum =
      getLastOutstandingPacket(
          server->getNonConstConn(), PacketNumberSpace::AppData)
          ->packet.header.getPacketSequenceNum();

  uint32_t buffersInPacket1 = 0;
  for (size_t i = 0; i < server->getNonConstConn().outstandings.packets.size();
       ++i) {
    auto& packet = server->getNonConstConn().outstandings.packets[i];
    if (packet.packet.header.getPacketNumberSpace() !=
        PacketNumberSpace::AppData) {
      continue;
    }
    PacketNum currentPacket = packet.packet.header.getPacketSequenceNum();
    ASSERT_FALSE(packet.packet.frames.empty());
    for (auto& quicFrame : packet.packet.frames) {
      auto frame = quicFrame.asWriteStreamFrame();
      if (!frame) {
        continue;
      }
      auto it = stream->retransmissionBuffer.find(frame->offset);
      ASSERT_TRUE(it != stream->retransmissionBuffer.end());
      if (currentPacket == packetNum1 && frame->streamId == streamId) {
        buffersInPacket1++;
      }
    }
  }

  auto originalRetransSize = stream->retransmissionBuffer.size();
  AckBlocks acks = {{packetNum1, packetNum1}};
  auto packet1 = createAckPacket(
      server->getNonConstConn(),
      ++clientNextAppDataPacketNum,
      acks,
      PacketNumberSpace::AppData);
  deliverData(packetToBuf(packet1));
  EXPECT_EQ(
      stream->retransmissionBuffer.size(),
      originalRetransSize - buffersInPacket1);
  EXPECT_EQ(stream->sendState, StreamSendState::Open);
  EXPECT_EQ(stream->recvState, StreamRecvState::Open);

  // Dup ack
  auto packet2 = createAckPacket(
      server->getNonConstConn(),
      ++clientNextAppDataPacketNum,
      acks,
      PacketNumberSpace::AppData);
  deliverData(packetToBuf(packet2));

  EXPECT_EQ(
      stream->retransmissionBuffer.size(),
      originalRetransSize - buffersInPacket1);
  EXPECT_EQ(stream->sendState, StreamSendState::Open);
  EXPECT_EQ(stream->recvState, StreamRecvState::Open);

  AckBlocks acks2 = {{packetNum1, lastPacketNum}};
  auto packet3 = createAckPacket(
      server->getNonConstConn(),
      ++clientNextAppDataPacketNum,
      acks2,
      PacketNumberSpace::AppData);
  deliverData(packetToBuf(packet3));

  EXPECT_EQ(stream->retransmissionBuffer.size(), 0);
  EXPECT_EQ(stream->sendState, StreamSendState::Open);
  EXPECT_EQ(stream->recvState, StreamRecvState::Open);

  auto empty = IOBuf::create(0);
  server->writeChain(streamId, std::move(empty), true);
  loopForWrites();
  ASSERT_FALSE(server->getConn().outstandings.packets.empty());

  PacketNum finPacketNum =
      getFirstOutstandingPacket(
          server->getNonConstConn(), PacketNumberSpace::AppData)
          ->packet.header.getPacketSequenceNum();

  AckBlocks acks3 = {{lastPacketNum, finPacketNum}};
  auto packet4 = createAckPacket(
      server->getNonConstConn(),
      ++clientNextAppDataPacketNum,
      acks3,
      PacketNumberSpace::AppData);
  deliverData(packetToBuf(packet4));
  EXPECT_EQ(stream->sendState, StreamSendState::Closed);
  EXPECT_EQ(stream->recvState, StreamRecvState::Open);
}

TEST_F(QuicServerTransportTest, RecvRstStreamFrameNonexistClientStream) {
  StreamId streamId = 0x00;
  ShortHeader header(
      ProtectionType::KeyPhaseZero,
      *server->getConn().serverConnectionId,
      clientNextAppDataPacketNum++);
  RegularQuicPacketBuilder builder(
      server->getConn().udpSendPacketLen,
      std::move(header),
      0 /* largestAcked */);
  ASSERT_FALSE(builder.encodePacketHeader().hasError());
  ASSERT_TRUE(builder.canBuildPacket());

  RstStreamFrame rstFrame(streamId, GenericApplicationErrorCode::UNKNOWN, 0);
  ASSERT_FALSE(writeFrame(std::move(rstFrame), builder).hasError());
  auto packet = std::move(builder).buildPacket();
  deliverData(packetToBuf(packet));

  auto streamResult =
      server->getNonConstConn().streamManager->getStream(streamId);
  ASSERT_FALSE(streamResult.hasError());
  auto stream = streamResult.value();
  ASSERT_TRUE(stream->streamReadError.has_value());
}

TEST_F(QuicServerTransportTest, ReceiveRstStreamNonExistentAndOtherFrame) {
  StreamId clientUnidirectional = 0x02;

  // Deliver reset on peer unidirectional stream to close the stream.
  RstStreamFrame rstFrame(
      clientUnidirectional, GenericApplicationErrorCode::UNKNOWN, 0);
  ShortHeader header(
      ProtectionType::KeyPhaseZero,
      *server->getConn().serverConnectionId,
      clientNextAppDataPacketNum++);
  RegularQuicPacketBuilder builder(
      server->getConn().udpSendPacketLen,
      std::move(header),
      0 /* largestAcked */);
  ASSERT_FALSE(builder.encodePacketHeader().hasError());
  ASSERT_FALSE(writeFrame(rstFrame, builder).hasError());
  auto packet = packetToBuf(std::move(builder).buildPacket());
  deliverData(std::move(packet));

  auto streamId =
      server->createBidirectionalStream(false /* replaySafe */).value();

  ShortHeader header2(
      ProtectionType::KeyPhaseZero,
      *server->getConn().serverConnectionId,
      clientNextAppDataPacketNum++);
  RegularQuicPacketBuilder builder2(
      server->getConn().udpSendPacketLen,
      std::move(header2),
      0 /* largestAcked */);
  ASSERT_FALSE(builder2.encodePacketHeader().hasError());
  ASSERT_FALSE(writeFrame(rstFrame, builder2).hasError());

  auto data = folly::IOBuf::copyBuffer("hello");
  ASSERT_FALSE(writeStreamFrameHeader(
                   builder2,
                   streamId,
                   0,
                   data->computeChainDataLength(),
                   data->computeChainDataLength(),
                   false,
                   std::nullopt /* skipLenHint */)
                   .hasError());
  writeStreamFrameData(builder2, data->clone(), data->computeChainDataLength());
  auto packetObject = std::move(builder2).buildPacket();
  auto packet2 = packetToBuf(std::move(packetObject));
  deliverData(std::move(packet2));

  auto readData = server->read(streamId, 0);
  ASSERT_TRUE(readData.hasValue());
  ASSERT_NE(readData.value().first, nullptr);
  EXPECT_TRUE(folly::IOBufEqualTo()(*readData.value().first, *data));
}

TEST_F(QuicServerTransportTest, RecvRstStreamFrameNonexistServerStream) {
  ShortHeader header(
      ProtectionType::KeyPhaseZero,
      *server->getConn().serverConnectionId,
      clientNextAppDataPacketNum++);
  RegularQuicPacketBuilder builder(
      server->getConn().udpSendPacketLen,
      std::move(header),
      0 /* largestAcked */);
  ASSERT_FALSE(builder.encodePacketHeader().hasError());
  ASSERT_TRUE(builder.canBuildPacket());

  StreamId streamId = 0x01;
  RstStreamFrame rstFrame(streamId, GenericApplicationErrorCode::UNKNOWN, 0);
  ASSERT_FALSE(writeFrame(std::move(rstFrame), builder).hasError());
  auto packet = std::move(builder).buildPacket();
  EXPECT_THROW(deliverData(packetToBuf(packet)), std::runtime_error);
}

TEST_F(QuicServerTransportTest, RecvRstStreamFrame) {
  clientNextAppDataPacketNum = 3;
  std::array<std::string, 4> words = {
      "Hey Bob, this is Alice, for real.",
      "What message did I send you last time?",
      "You don't sound like Alice",
      "You are a liar!",
  };

  StreamId streamId = 0x00;
  auto streamResult =
      server->getNonConstConn().streamManager->getStream(streamId);
  ASSERT_FALSE(streamResult.hasError());
  auto stream = streamResult.value();
  stream->readBuffer.emplace_back(IOBuf::copyBuffer(words.at(0)), 0, false);
  stream->readBuffer.emplace_back(
      IOBuf::copyBuffer(words.at(1)), words.at(0).length(), false);

  auto wordsBuf2 = IOBuf::copyBuffer(words.at(2));
  stream->retransmissionBuffer.emplace(
      std::piecewise_construct,
      std::forward_as_tuple(0),
      std::forward_as_tuple(std::make_unique<WriteStreamBuffer>(
          ChainedByteRangeHead(wordsBuf2), 0, false)));
  ASSERT_FALSE(
      writeDataToQuicStream(*stream, IOBuf::copyBuffer(words.at(3)), false)
          .hasError());
  stream->currentWriteOffset = words.at(2).length() + words.at(3).length();
  stream->currentReadOffset = words.at(0).length() + words.at(1).length();

  server->getNonConstConn().ackStates.appDataAckState.nextPacketNum = 5;
  ShortHeader header(
      ProtectionType::KeyPhaseZero,
      *server->getConn().serverConnectionId,
      clientNextAppDataPacketNum++);
  RegularQuicPacketBuilder builder(
      server->getConn().udpSendPacketLen,
      std::move(header),
      0 /* largestAcked */);
  ASSERT_FALSE(builder.encodePacketHeader().hasError());

  RstStreamFrame rstFrame(
      streamId,
      GenericApplicationErrorCode::UNKNOWN,
      words.at(0).length() + words.at(1).length());
  ASSERT_TRUE(builder.canBuildPacket());
  ASSERT_FALSE(writeFrame(std::move(rstFrame), builder).hasError());
  auto packet = std::move(builder).buildPacket();
  deliverData(packetToBuf(packet));

  // Verify stream receive state is cleaned up but send state isn't:
  auto updatedStream =
      server->getNonConstConn().streamManager->findStream(streamId);
  ASSERT_TRUE(updatedStream);
  EXPECT_TRUE(updatedStream->readBuffer.empty());
  // We can verify retx buffer isn't empty here. The writeBuffer though could be
  // empty since deliverData can cause a write synchrously.
  EXPECT_FALSE(updatedStream->retransmissionBuffer.empty());
  EXPECT_EQ(
      words.at(0).length() + words.at(1).length(),
      updatedStream->finalReadOffset.value());
  // updatedStream still writable since receiving rst has no impact on egress
  EXPECT_TRUE(updatedStream->writable());
}

TEST_F(QuicServerTransportTest, RecvReliableRstStreamFrame) {
  clientNextAppDataPacketNum = 3;

  StreamId streamId = 0x00;
  auto streamResult =
      server->getNonConstConn().streamManager->getStream(streamId);
  ASSERT_FALSE(streamResult.hasError());
  ShortHeader header(
      ProtectionType::KeyPhaseZero,
      *server->getConn().serverConnectionId,
      clientNextAppDataPacketNum++);
  RegularQuicPacketBuilder builder(
      server->getConn().udpSendPacketLen,
      std::move(header),
      0 /* largestAcked */);
  ASSERT_FALSE(builder.encodePacketHeader().hasError());

  RstStreamFrame rstFrame(streamId, GenericApplicationErrorCode::UNKNOWN, 5, 5);
  ASSERT_TRUE(builder.canBuildPacket());
  ASSERT_FALSE(writeFrame(std::move(rstFrame), builder).hasError());
  auto packet = std::move(builder).buildPacket();
  deliverDataWithoutErrorCheck(packetToBuf(packet));
  EXPECT_EQ(
      server->getConn().localConnectionError->code,
      QuicErrorCode(TransportErrorCode::PROTOCOL_VIOLATION));
}

TEST_F(QuicServerTransportTest, RecvStopSendingFrame) {
  server->getNonConstConn().ackStates.appDataAckState.nextPacketNum = 3;
  std::array<std::string, 4> words = {
      "Hey Bob, this is Alice, for real.",
      "What message did I send you last time?",
      "You don't sound like Alice",
      "You are a liar!",
  };

  StreamId streamId = 0x00;
  auto streamResult =
      server->getNonConstConn().streamManager->getStream(streamId);
  ASSERT_FALSE(streamResult.hasError());
  auto stream = streamResult.value();
  stream->readBuffer.emplace_back(IOBuf::copyBuffer(words.at(0)), 0, false);
  stream->readBuffer.emplace_back(
      IOBuf::copyBuffer(words.at(1)), words.at(0).length(), false);
  auto wordsBuf2 = IOBuf::copyBuffer(words.at(2));
  stream->retransmissionBuffer.emplace(
      std::piecewise_construct,
      std::forward_as_tuple(0),
      std::forward_as_tuple(std::make_unique<WriteStreamBuffer>(
          ChainedByteRangeHead(wordsBuf2), 0, false)));
  stream->writeBuffer.append(IOBuf::copyBuffer(words.at(3)));
  stream->currentWriteOffset = words.at(2).length() + words.at(3).length();
  stream->currentReadOffset = words.at(0).length() + words.at(1).length();

  server->getNonConstConn().ackStates.appDataAckState.nextPacketNum = 5;
  ShortHeader header(
      ProtectionType::KeyPhaseZero,
      *server->getConn().serverConnectionId,
      clientNextAppDataPacketNum++);
  RegularQuicPacketBuilder builder(
      server->getConn().udpSendPacketLen,
      std::move(header),
      0 /* largestAcked */);
  ASSERT_FALSE(builder.encodePacketHeader().hasError());
  StopSendingFrame stopSendingFrame(
      streamId, GenericApplicationErrorCode::UNKNOWN);
  ASSERT_TRUE(builder.canBuildPacket());
  ASSERT_FALSE(
      writeFrame(QuicSimpleFrame(stopSendingFrame), builder).hasError());
  auto packet = std::move(builder).buildPacket();
  EXPECT_CALL(
      connCallback,
      onStopSending(streamId, GenericApplicationErrorCode::UNKNOWN));
  deliverData(packetToBuf(packet));
}

TEST_F(QuicServerTransportTest, RecvStopSendingFrameAfterCloseStream) {
  server->getNonConstConn().ackStates.appDataAckState.nextPacketNum = 3;
  std::array<std::string, 4> words = {
      "Hey Bob, this is Alice, for real.",
      "What message did I send you last time?",
      "You don't sound like Alice",
      "You are a liar!",
  };

  StreamId streamId = 0x00;
  auto streamResult =
      server->getNonConstConn().streamManager->getStream(streamId);
  ASSERT_FALSE(streamResult.hasError());
  auto stream = streamResult.value();
  stream->readBuffer.emplace_back(IOBuf::copyBuffer(words.at(0)), 0, false);
  stream->readBuffer.emplace_back(
      IOBuf::copyBuffer(words.at(1)), words.at(0).length(), false);
  auto wordsBuf2 = IOBuf::copyBuffer(words.at(2));
  stream->retransmissionBuffer.emplace(
      std::piecewise_construct,
      std::forward_as_tuple(0),
      std::forward_as_tuple(std::make_unique<WriteStreamBuffer>(
          ChainedByteRangeHead(wordsBuf2), 0, false)));
  stream->writeBuffer.append(IOBuf::copyBuffer(words.at(3)));
  stream->currentWriteOffset = words.at(2).length() + words.at(3).length();
  stream->currentReadOffset = words.at(0).length() + words.at(1).length();
  server->getNonConstConn().flowControlState.sumCurStreamBufferLen = 100;

  server->getNonConstConn().ackStates.appDataAckState.nextPacketNum = 5;
  ShortHeader header(
      ProtectionType::KeyPhaseZero,
      *server->getConn().serverConnectionId,
      clientNextAppDataPacketNum++);
  RegularQuicPacketBuilder builder(
      server->getConn().udpSendPacketLen,
      std::move(header),
      0 /* largestAcked */);
  ASSERT_FALSE(builder.encodePacketHeader().hasError());

  StopSendingFrame stopSendingFrame(
      streamId, GenericApplicationErrorCode::UNKNOWN);
  ASSERT_TRUE(builder.canBuildPacket());
  ASSERT_FALSE(
      writeFrame(QuicSimpleFrame(stopSendingFrame), builder).hasError());
  auto packet = std::move(builder).buildPacket();
  server->resetStream(streamId, GenericApplicationErrorCode::UNKNOWN);
  EXPECT_CALL(connCallback, onStopSending(_, _)).Times(0);
  deliverData(packetToBuf(packet));
}

TEST_F(QuicServerTransportTest, RecvInvalidMaxStreamData) {
  server->getNonConstConn().ackStates.appDataAckState.nextPacketNum = 3;
  std::array<std::string, 4> words = {
      "Hey Bob, this is Alice, for real.",
      "What message did I send you last time?",
      "You don't sound like Alice",
      "You are a liar!",
  };

  StreamId streamId = 0x02;
  auto streamResult =
      server->getNonConstConn().streamManager->getStream(streamId);
  ASSERT_FALSE(streamResult.hasError());
  auto stream = streamResult.value();
  stream->readBuffer.emplace_back(IOBuf::copyBuffer(words.at(0)), 0, false);
  stream->readBuffer.emplace_back(
      IOBuf::copyBuffer(words.at(1)), words.at(0).length(), false);
  auto wordsBuf2 = IOBuf::copyBuffer(words.at(2));
  stream->retransmissionBuffer.emplace(
      std::piecewise_construct,
      std::forward_as_tuple(0),
      std::forward_as_tuple(std::make_unique<WriteStreamBuffer>(
          ChainedByteRangeHead(wordsBuf2), 0, false)));
  stream->writeBuffer.append(IOBuf::copyBuffer(words.at(3)));
  stream->currentWriteOffset = words.at(2).length() + words.at(3).length();
  stream->currentReadOffset = words.at(0).length() + words.at(1).length();
  server->getNonConstConn().flowControlState.sumCurStreamBufferLen = 100;

  server->getNonConstConn().ackStates.appDataAckState.nextPacketNum = 5;
  ShortHeader header(
      ProtectionType::KeyPhaseZero,
      *server->getConn().serverConnectionId,
      clientNextAppDataPacketNum++);
  RegularQuicPacketBuilder builder(
      server->getConn().udpSendPacketLen,
      std::move(header),
      0 /* largestAcked */);
  ASSERT_FALSE(builder.encodePacketHeader().hasError());

  MaxStreamDataFrame maxStreamDataFrame(streamId, 100);
  ASSERT_TRUE(builder.canBuildPacket());
  ASSERT_FALSE(writeFrame(std::move(maxStreamDataFrame), builder).hasError());
  auto packet = std::move(builder).buildPacket();
  EXPECT_THROW(deliverData(packetToBuf(packet)), std::runtime_error);
}

TEST_F(QuicServerTransportTest, RecvStopSendingFrameAfterHalfCloseRemote) {
  server->getNonConstConn().ackStates.appDataAckState.nextPacketNum = 3;
  std::array<std::string, 4> words = {
      "Hey Bob, this is Alice, for real.",
      "What message did I send you last time?",
      "You don't sound like Alice",
      "You are a liar!",
  };

  StreamId streamId = 0x00;
  auto streamResult =
      server->getNonConstConn().streamManager->getStream(streamId);
  ASSERT_FALSE(streamResult.hasError());
  auto stream = streamResult.value();
  stream->readBuffer.emplace_back(IOBuf::copyBuffer(words.at(0)), 0, false);
  stream->readBuffer.emplace_back(
      IOBuf::copyBuffer(words.at(1)), words.at(0).length(), false);
  auto wordsBuf2 = IOBuf::copyBuffer(words.at(2));
  stream->retransmissionBuffer.emplace(
      std::piecewise_construct,
      std::forward_as_tuple(0),
      std::forward_as_tuple(std::make_unique<WriteStreamBuffer>(
          ChainedByteRangeHead(wordsBuf2), 0, false)));
  stream->writeBuffer.append(IOBuf::copyBuffer(words.at(3)));
  stream->currentWriteOffset = words.at(2).length() + words.at(3).length();
  stream->currentReadOffset = words.at(0).length() + words.at(1).length();

  server->getNonConstConn().ackStates.appDataAckState.nextPacketNum = 5;
  ShortHeader header(
      ProtectionType::KeyPhaseZero,
      *server->getConn().serverConnectionId,
      clientNextAppDataPacketNum++);
  RegularQuicPacketBuilder builder(
      server->getConn().udpSendPacketLen,
      std::move(header),
      0 /* largestAcked */);
  ASSERT_FALSE(builder.encodePacketHeader().hasError());

  StopSendingFrame stopSendingFrame(
      streamId, GenericApplicationErrorCode::UNKNOWN);
  ASSERT_TRUE(builder.canBuildPacket());
  auto res = writeStreamFrameHeader(
      builder,
      0x00,
      stream->currentReadOffset,
      0,
      10,
      true,
      std::nullopt /* skipLenHint */);
  ASSERT_TRUE(res.hasValue());
  auto dataLen = *res;
  ASSERT_TRUE(dataLen.has_value());
  ASSERT_EQ(*dataLen, 0);
  ASSERT_FALSE(
      writeFrame(QuicSimpleFrame(stopSendingFrame), builder).hasError());
  auto packet = std::move(builder).buildPacket();
  EXPECT_CALL(
      connCallback,
      onStopSending(streamId, GenericApplicationErrorCode::UNKNOWN));
  deliverData(packetToBuf(packet));
}

TEST_F(QuicServerTransportTest, RecvStopSendingBeforeStream) {
  StreamId streamId = 0x00;
  server->getNonConstConn().ackStates.appDataAckState.nextPacketNum = 3;
  ShortHeader header(
      ProtectionType::KeyPhaseZero,
      *server->getConn().serverConnectionId,
      clientNextAppDataPacketNum++);
  RegularQuicPacketBuilder builder(
      server->getConn().udpSendPacketLen,
      std::move(header),
      0 /* largestAcked */);
  ASSERT_FALSE(builder.encodePacketHeader().hasError());

  StopSendingFrame stopSendingFrame(
      streamId, GenericApplicationErrorCode::UNKNOWN);
  ASSERT_TRUE(builder.canBuildPacket());
  ASSERT_FALSE(
      writeFrame(QuicSimpleFrame(stopSendingFrame), builder).hasError());
  auto packet = std::move(builder).buildPacket();
  EXPECT_CALL(connCallback, onNewBidirectionalStream(streamId));
  EXPECT_CALL(
      connCallback,
      onStopSending(streamId, GenericApplicationErrorCode::UNKNOWN));
  deliverData(packetToBuf(packet));
}

TEST_F(QuicServerTransportTest, RecvStopSendingFrameAfterReset) {
  server->getNonConstConn().ackStates.appDataAckState.nextPacketNum = 3;
  std::array<std::string, 4> words = {
      "Hey Bob, this is Alice, for real.",
      "What message did I send you last time?",
      "You don't sound like Alice",
      "You are a liar!",
  };

  StreamId streamId1 = 0x00;
  StreamId streamId2 = 0x04;
  auto stream1Result =
      server->getNonConstConn().streamManager->getStream(streamId1);
  ASSERT_FALSE(stream1Result.hasError());
  auto stream1 = stream1Result.value();
  stream1->readBuffer.emplace_back(IOBuf::copyBuffer(words.at(0)), 0, false);
  stream1->readBuffer.emplace_back(
      IOBuf::copyBuffer(words.at(1)), words.at(0).length(), false);
  auto wordsBuf2 = IOBuf::copyBuffer(words.at(2));
  stream1->retransmissionBuffer.emplace(
      std::piecewise_construct,
      std::forward_as_tuple(0),
      std::forward_as_tuple(std::make_unique<WriteStreamBuffer>(
          ChainedByteRangeHead(wordsBuf2), 0, false)));
  stream1->writeBuffer.append(IOBuf::copyBuffer(words.at(3)));
  stream1->currentWriteOffset = words.at(2).length() + words.at(3).length();
  stream1->currentReadOffset = words.at(0).length() + words.at(1).length();
  auto stream2Result =
      server->getNonConstConn().streamManager->getStream(streamId2);
  ASSERT_FALSE(stream2Result.hasError());
  auto stream2 = stream2Result.value();
  stream2->readBuffer.emplace_back(IOBuf::copyBuffer(words.at(0)), 0, false);
  stream2->readBuffer.emplace_back(
      IOBuf::copyBuffer(words.at(1)), words.at(0).length(), false);
  stream2->retransmissionBuffer.emplace(
      std::piecewise_construct,
      std::forward_as_tuple(0),
      std::forward_as_tuple(std::make_unique<WriteStreamBuffer>(
          ChainedByteRangeHead(wordsBuf2), 0, false)));
  stream2->writeBuffer.append(IOBuf::copyBuffer(words.at(3)));
  stream2->currentWriteOffset = words.at(2).length() + words.at(3).length();
  stream2->currentReadOffset = words.at(0).length() + words.at(1).length();

  server->getNonConstConn().ackStates.appDataAckState.nextPacketNum = 5;
  ShortHeader header(
      ProtectionType::KeyPhaseZero,
      *server->getConn().serverConnectionId,
      clientNextAppDataPacketNum++);
  RegularQuicPacketBuilder builder(
      server->getConn().udpSendPacketLen,
      std::move(header),
      0 /* largestAcked */);
  ASSERT_FALSE(builder.encodePacketHeader().hasError());

  StopSendingFrame stopSendingFrame1(
      streamId1, GenericApplicationErrorCode::UNKNOWN);
  StopSendingFrame stopSendingFrame2(
      streamId2, GenericApplicationErrorCode::UNKNOWN);
  ASSERT_TRUE(builder.canBuildPacket());
  ASSERT_FALSE(
      writeFrame(QuicSimpleFrame(stopSendingFrame1), builder).hasError());
  ASSERT_FALSE(
      writeFrame(QuicSimpleFrame(stopSendingFrame2), builder).hasError());
  auto packet = std::move(builder).buildPacket();
  EXPECT_CALL(
      connCallback, onStopSending(_, GenericApplicationErrorCode::UNKNOWN))
      .WillOnce(Invoke([&](StreamId /*sid*/, ApplicationErrorCode /*e*/) {
        server->close(std::nullopt);
      }));
  EXPECT_THROW(deliverData(packetToBuf(packet)), std::runtime_error);
}

TEST_F(QuicServerTransportTest, StopSendingLoss) {
  server->getNonConstConn().ackStates.appDataAckState.nextPacketNum = 3;
  auto streamId = server->createBidirectionalStream().value();
  auto streamResult =
      server->getNonConstConn().streamManager->getStream(streamId);
  ASSERT_FALSE(streamResult.hasError());
  ShortHeader header(
      ProtectionType::KeyPhaseZero,
      *server->getConn().serverConnectionId,
      server->getNonConstConn().ackStates.appDataAckState.nextPacketNum++);
  RegularQuicPacketBuilder builder(
      server->getConn().udpSendPacketLen,
      std::move(header),
      server->getConn().ackStates.appDataAckState.largestAckedByPeer.value_or(
          0));
  ASSERT_FALSE(builder.encodePacketHeader().hasError());
  StopSendingFrame stopSendingFrame(
      streamId, GenericApplicationErrorCode::UNKNOWN);
  ASSERT_TRUE(builder.canBuildPacket());
  ASSERT_FALSE(
      writeFrame(QuicSimpleFrame(stopSendingFrame), builder).hasError());
  auto packet = std::move(builder).buildPacket();
  ASSERT_FALSE(markPacketLoss(server->getNonConstConn(), packet.packet, false)
                   .hasError());
  EXPECT_EQ(server->getNonConstConn().pendingEvents.frames.size(), 1);
  StopSendingFrame* stopFrame = server->getNonConstConn()
                                    .pendingEvents.frames.front()
                                    .asStopSendingFrame();
  ASSERT_NE(stopFrame, nullptr);
  EXPECT_EQ(*stopFrame, stopSendingFrame);
}

TEST_F(QuicServerTransportTest, StopSendingLossAfterStreamClosed) {
  server->getNonConstConn().ackStates.appDataAckState.nextPacketNum = 3;
  auto streamId = server->createBidirectionalStream().value();
  auto streamResult =
      server->getNonConstConn().streamManager->getStream(streamId);
  ASSERT_FALSE(streamResult.hasError());
  ShortHeader header(
      ProtectionType::KeyPhaseZero,
      *server->getConn().serverConnectionId,
      clientNextAppDataPacketNum++);
  RegularQuicPacketBuilder builder(
      server->getConn().udpSendPacketLen,
      std::move(header),
      server->getConn().ackStates.appDataAckState.largestAckedByPeer.value_or(
          0));
  ASSERT_FALSE(builder.encodePacketHeader().hasError());
  StopSendingFrame stopSendingFrame(
      streamId, GenericApplicationErrorCode::UNKNOWN);
  ASSERT_TRUE(builder.canBuildPacket());
  ASSERT_FALSE(
      writeFrame(QuicSimpleFrame(stopSendingFrame), builder).hasError());
  auto packet = std::move(builder).buildPacket();

  // clear out all the streams, this is not a great way to simulate closed
  // streams, but good enough for this test.
  server->getNonConstConn().streamManager->clearOpenStreams();
  ASSERT_FALSE(markPacketLoss(server->getNonConstConn(), packet.packet, false)
                   .hasError());
  EXPECT_EQ(server->getNonConstConn().pendingEvents.frames.size(), 0);
}

TEST_F(QuicServerTransportTest, TestCloneStopSending) {
  auto streamId = server->createBidirectionalStream().value();
  auto qLogger = std::make_shared<quic::FileQLogger>(VantagePoint::Server);
  server->getNonConstConn().qLogger = qLogger;
  auto streamResult =
      server->getNonConstConn().streamManager->getStream(streamId);
  ASSERT_FALSE(streamResult.hasError());
  // knock every handshake outstanding packets out
  server->getNonConstConn().outstandings.reset();
  for (auto& t : server->getNonConstConn().lossState.lossTimes) {
    t.reset();
  }

  server->stopSending(streamId, GenericApplicationErrorCode::UNKNOWN);
  loopForWrites();
  // Find the outstanding StopSending.
  auto packetItr = std::find_if(
      server->getNonConstConn().outstandings.packets.begin(),
      server->getNonConstConn().outstandings.packets.end(),
      findFrameInPacketFunc<QuicSimpleFrame::Type::StopSendingFrame>());

  ASSERT_TRUE(
      packetItr != server->getNonConstConn().outstandings.packets.end());
  // Force a timeout with no data so that it clones the packet
  server->lossTimeout().timeoutExpired();
  loopForWrites();
  auto numStopSendingPackets = std::count_if(
      server->getNonConstConn().outstandings.packets.begin(),
      server->getNonConstConn().outstandings.packets.end(),
      findFrameInPacketFunc<QuicSimpleFrame::Type::StopSendingFrame>());

  EXPECT_GT(numStopSendingPackets, 1);

  std::vector<int> indices =
      getQLogEventIndices(QLogEventType::TransportStateUpdate, qLogger);
  EXPECT_EQ(indices.size(), 1);
  auto tmp = std::move(qLogger->logs[indices[0]]);
  auto event = dynamic_cast<QLogTransportStateUpdateEvent*>(tmp.get());
  EXPECT_EQ(event->update, kLossTimeoutExpired);
}

TEST_F(QuicServerTransportTest, TestAckStopSending) {
  auto streamId = server->createBidirectionalStream().value();
  auto streamResult =
      server->getNonConstConn().streamManager->getStream(streamId);
  ASSERT_FALSE(streamResult.hasError());
  server->stopSending(streamId, GenericApplicationErrorCode::UNKNOWN);
  loopForWrites();
  auto match = findFrameInPacketFunc<QuicSimpleFrame::Type::StopSendingFrame>();

  auto op = findOutstandingPacket(server->getNonConstConn(), match);
  ASSERT_TRUE(op != nullptr);
  PacketNum packetNum = op->packet.header.getPacketSequenceNum();
  AckBlocks acks = {{packetNum, packetNum}};
  auto packet1 = createAckPacket(
      server->getNonConstConn(),
      ++clientNextAppDataPacketNum,
      acks,
      PacketNumberSpace::AppData);
  deliverData(packetToBuf(packet1));
  op = findOutstandingPacket(server->getNonConstConn(), match);
  EXPECT_TRUE(op == nullptr);
}

TEST_F(QuicServerTransportTest, RecvPathChallenge) {
  auto& conn = server->getNonConstConn();

  // Add additional peer id so PathResponse completes.
  conn.peerConnectionIds.emplace_back(
      ConnectionId::createAndMaybeCrash({1, 2, 3, 4}), 1);

  ShortHeader header(
      ProtectionType::KeyPhaseZero, *conn.serverConnectionId, 10);
  RegularQuicPacketBuilder builder(
      conn.udpSendPacketLen, std::move(header), 0 /* largestAcked */);
  ASSERT_FALSE(builder.encodePacketHeader().hasError());
  PathChallengeFrame pathChallenge(123);
  ASSERT_TRUE(builder.canBuildPacket());
  ASSERT_FALSE(
      writeSimpleFrame(QuicSimpleFrame(pathChallenge), builder).hasError());

  auto packet = std::move(builder).buildPacket();

  EXPECT_TRUE(conn.pendingEvents.frames.empty());
  deliverData(packetToBuf(packet), false);
  EXPECT_EQ(conn.pendingEvents.frames.size(), 2);
  // The RetireConnectionId frame will be enqueued before the PathResponse.
  auto retireFrame = conn.pendingEvents.frames[0].asRetireConnectionIdFrame();
  EXPECT_EQ(retireFrame->sequenceNumber, 0);

  PathResponseFrame& pathResponse =
      *conn.pendingEvents.frames[1].asPathResponseFrame();
  EXPECT_EQ(pathResponse.pathData, pathChallenge.pathData);
}

TEST_F(QuicServerTransportTest, TestAckRstStream) {
  auto streamId = server->createUnidirectionalStream().value();
  auto streamResult =
      server->getNonConstConn().streamManager->getStream(streamId);
  ASSERT_FALSE(streamResult.hasError());
  auto stream = streamResult.value();

  auto packetNum = rstStreamAndSendPacket(
      server->getNonConstConn(),
      server->getSocket(),
      *stream,
      GenericApplicationErrorCode::UNKNOWN);

  AckBlocks acks = {{packetNum, packetNum}};
  auto packet1 = createAckPacket(
      server->getNonConstConn(),
      ++clientNextAppDataPacketNum,
      acks,
      PacketNumberSpace::AppData);
  deliverData(packetToBuf(packet1));
  // Closed streams should be deleted.
  EXPECT_EQ(server->getConn().streamManager->streamCount(), 0);
}

TEST_F(QuicServerTransportTest, ReceiveConnectionClose) {
  auto qLogger = std::make_shared<FileQLogger>(VantagePoint::Server);
  server->getNonConstConn().qLogger = qLogger;

  ShortHeader header(
      ProtectionType::KeyPhaseZero,
      *server->getConn().serverConnectionId,
      clientNextAppDataPacketNum++);
  RegularQuicPacketBuilder builder(
      server->getConn().udpSendPacketLen,
      std::move(header),
      0 /* largestAcked */);
  ASSERT_FALSE(builder.encodePacketHeader().hasError());
  std::string errMsg = "Stand clear of the closing doors, please";
  ConnectionCloseFrame connClose(
      QuicErrorCode(TransportErrorCode::NO_ERROR), errMsg);
  ASSERT_FALSE(writeFrame(std::move(connClose), builder).hasError());
  auto packet = std::move(builder).buildPacket();
  EXPECT_CALL(connCallback, onConnectionEnd());
  deliverDataWithoutErrorCheck(packetToBuf(packet));
  // Now the transport should be closed
  EXPECT_EQ(
      server->getConn().localConnectionError->code,
      QuicErrorCode(TransportErrorCode::NO_ERROR));
  EXPECT_EQ(
      server->getConn().peerConnectionError->code,
      QuicErrorCode(TransportErrorCode::NO_ERROR));
  auto closedMsg = fmt::format("Server closed by peer reason={}", errMsg);
  EXPECT_EQ(server->getConn().peerConnectionError->message, closedMsg);
  EXPECT_TRUE(server->isClosed());
  EXPECT_TRUE(verifyFramePresent(
      serverWrites,
      *makeClientEncryptedCodec(),
      QuicFrame::Type::ConnectionCloseFrame));
  checkTransportStateUpdate(qLogger, std::move(closedMsg));
}

TEST_F(QuicServerTransportTest, ReceiveConnectionCloseBeforeDatagram) {
  auto& conn = server->getNonConstConn();
  conn.datagramState.maxReadFrameSize = std::numeric_limits<uint16_t>::max();
  conn.datagramState.maxReadBufferSize = 10;

  auto qLogger = std::make_shared<FileQLogger>(VantagePoint::Server);
  server->getNonConstConn().qLogger = qLogger;

  {
    // Deliver a datagram.
    // Should be received just fine.
    ShortHeader header(
        ProtectionType::KeyPhaseZero,
        *server->getConn().serverConnectionId,
        clientNextAppDataPacketNum++);
    RegularQuicPacketBuilder builder(
        server->getConn().udpSendPacketLen,
        std::move(header),
        0 /* largestAcked */);
    ASSERT_FALSE(builder.encodePacketHeader().hasError());
    StringPiece datagramPayload = "do not rely on me. I am unreliable";
    DatagramFrame datagramFrame(
        datagramPayload.size(), IOBuf::copyBuffer(datagramPayload));
    ASSERT_FALSE(writeFrame(datagramFrame, builder).hasError());
    auto packet = std::move(builder).buildPacket();

    EXPECT_CALL(*quicStats_, onDatagramRead(_)).Times(1);
    deliverDataWithoutErrorCheck(packetToBuf(packet));
    ASSERT_EQ(server->getConn().datagramState.readBuffer.size(), 1);
  }

  auto lateDgPktNum = clientNextAppDataPacketNum++;
  auto connClosePktNum = clientNextAppDataPacketNum++;

  {
    // Deliver conn close followed by another datagram.
    // Conn should close and clean up, the late datagram should be ignored and
    // dropped on the floor.

    // Build conn close frame.
    ShortHeader header(
        ProtectionType::KeyPhaseZero,
        *server->getConn().serverConnectionId,
        connClosePktNum);
    RegularQuicPacketBuilder builder(
        server->getConn().udpSendPacketLen,
        std::move(header),
        0 /* largestAcked */);
    ASSERT_FALSE(builder.encodePacketHeader().hasError());
    std::string errMsg = "Stand clear of the closing doors, please";
    ConnectionCloseFrame connClose(
        QuicErrorCode(TransportErrorCode::NO_ERROR), errMsg);
    ASSERT_FALSE(writeFrame(std::move(connClose), builder).hasError());
    auto packet = std::move(builder).buildPacket();

    // Build late datagram.
    ShortHeader header2(
        ProtectionType::KeyPhaseZero,
        *server->getConn().serverConnectionId,
        lateDgPktNum);
    RegularQuicPacketBuilder builder2(
        server->getConn().udpSendPacketLen,
        std::move(header2),
        0 /* largestAcked */);
    ASSERT_FALSE(builder2.encodePacketHeader().hasError());
    StringPiece datagramPayload = "do not rely on me. I am unreliable";
    DatagramFrame datagramFrame(
        datagramPayload.size(), IOBuf::copyBuffer(datagramPayload));
    ASSERT_FALSE(writeFrame(datagramFrame, builder2).hasError());
    auto packet2 = std::move(builder2).buildPacket();

    // Deliver conn close followed by late datagram.
    EXPECT_CALL(*quicStats_, onDatagramRead(_)).Times(0);
    EXPECT_CALL(connCallback, onConnectionEnd()).Times(1);
    deliverDataWithoutErrorCheck(packetToBuf(packet));
    deliverDataWithoutErrorCheck(packetToBuf(packet2));

    // Now the transport should be closed
    EXPECT_EQ(
        server->getConn().localConnectionError->code,
        QuicErrorCode(TransportErrorCode::NO_ERROR));
    EXPECT_EQ(
        server->getConn().peerConnectionError->code,
        QuicErrorCode(TransportErrorCode::NO_ERROR));
    auto closedMsg = fmt::format("Server closed by peer reason={}", errMsg);
    EXPECT_EQ(server->getConn().peerConnectionError->message, closedMsg);
    EXPECT_TRUE(server->isClosed());
    EXPECT_TRUE(verifyFramePresent(
        serverWrites,
        *makeClientEncryptedCodec(),
        QuicFrame::Type::ConnectionCloseFrame));
    ASSERT_EQ(server->getConn().datagramState.readBuffer.size(), 0);
    checkTransportStateUpdate(qLogger, std::move(closedMsg));
  }
}

TEST_F(QuicServerTransportTest, ReceiveApplicationClose) {
  auto qLogger = std::make_shared<FileQLogger>(VantagePoint::Server);
  server->getNonConstConn().qLogger = qLogger;

  ShortHeader header(
      ProtectionType::KeyPhaseZero,
      *server->getConn().serverConnectionId,
      clientNextAppDataPacketNum++);
  RegularQuicPacketBuilder builder(
      server->getConn().udpSendPacketLen,
      std::move(header),
      0 /* largestAcked */);
  ASSERT_FALSE(builder.encodePacketHeader().hasError());

  std::string errMsg = "Stand clear of the closing doors, please";
  ConnectionCloseFrame appClose(
      QuicErrorCode(GenericApplicationErrorCode::UNKNOWN), errMsg);
  ASSERT_FALSE(writeFrame(std::move(appClose), builder).hasError());
  auto packet = std::move(builder).buildPacket();

  EXPECT_CALL(
      connCallback,
      onConnectionError(IsAppError(GenericApplicationErrorCode::UNKNOWN)));
  deliverDataWithoutErrorCheck(packetToBuf(packet));
  // Now the transport should be closed
  EXPECT_EQ(
      QuicErrorCode(TransportErrorCode::NO_ERROR),
      server->getConn().localConnectionError->code);
  EXPECT_EQ(
      server->getConn().peerConnectionError->code,
      QuicErrorCode(GenericApplicationErrorCode::UNKNOWN));
  auto closedMsg = fmt::format("Server closed by peer reason={}", errMsg);
  EXPECT_EQ(server->getConn().peerConnectionError->message, closedMsg);
  EXPECT_TRUE(server->isClosed());
  EXPECT_TRUE(verifyFramePresent(
      serverWrites,
      *makeClientEncryptedCodec(),
      QuicFrame::Type::ConnectionCloseFrame));
  checkTransportStateUpdate(qLogger, std::move(closedMsg));
}

TEST_F(QuicServerTransportTest, ReceiveConnectionCloseTwice) {
  auto qLogger = std::make_shared<FileQLogger>(VantagePoint::Server);
  server->getNonConstConn().qLogger = qLogger;
  ShortHeader header(
      ProtectionType::KeyPhaseZero,
      *server->getConn().serverConnectionId,
      clientNextAppDataPacketNum++);
  RegularQuicPacketBuilder builder(
      server->getConn().udpSendPacketLen,
      std::move(header),
      0 /* largestAcked */);
  ASSERT_FALSE(builder.encodePacketHeader().hasError());
  std::string errMsg = "Mind the gap";
  ConnectionCloseFrame connClose(
      QuicErrorCode(TransportErrorCode::NO_ERROR), errMsg);
  ASSERT_FALSE(writeFrame(std::move(connClose), builder).hasError());
  auto packet = std::move(builder).buildPacket();
  EXPECT_CALL(connCallback, onConnectionEnd());
  deliverDataWithoutErrorCheck(packetToBuf(packet));
  // Now the transport should be closed
  EXPECT_EQ(
      QuicErrorCode(TransportErrorCode::NO_ERROR),
      server->getConn().localConnectionError->code);
  EXPECT_EQ(
      server->getConn().peerConnectionError->code,
      QuicErrorCode(TransportErrorCode::NO_ERROR));
  auto closedMsg = fmt::format("Server closed by peer reason={}", errMsg);
  EXPECT_EQ(server->getConn().peerConnectionError->message, closedMsg);
  EXPECT_TRUE(server->isClosed());
  EXPECT_TRUE(verifyFramePresent(
      serverWrites,
      *makeClientEncryptedCodec(),
      QuicFrame::Type::ConnectionCloseFrame));
  serverWrites.clear();
  deliverDataWithoutErrorCheck(packetToBuf(packet));
  EXPECT_FALSE(verifyFramePresent(
      serverWrites,
      *makeClientEncryptedCodec(),
      QuicFrame::Type::ConnectionCloseFrame));
  std::vector<int> indices =
      getQLogEventIndices(QLogEventType::PacketDrop, qLogger);
  EXPECT_EQ(indices.size(), 1);
  auto tmp = std::move(qLogger->logs[indices[0]]);
  auto event = dynamic_cast<QLogPacketDropEvent*>(tmp.get());
  EXPECT_EQ(event->packetSize, 29);
  EXPECT_EQ(
      event->dropReason,
      PacketDropReason(PacketDropReason::SERVER_STATE_CLOSED)._to_string());
}

TEST_F(QuicServerTransportTest, CloseTransportWontUnbound) {
  EXPECT_CALL(routingCallback, onConnectionUnbound(_, _, _)).Times(0);
  server->closeTransport();
  // Need to do this otherwise server transport destructor will still call
  // onConnectionUnbound
  server->setRoutingCallback(nullptr);
}

TEST_F(QuicServerTransportTest, UnboundConnection) {
  EXPECT_CALL(routingCallback, onConnectionUnbound(_, _, _)).Times(1);
  server->unbindConnection();
  // Need to do this otherwise server transport destructor will still call
  // onConnectionUnbound
  server->setRoutingCallback(nullptr);
}

TEST_F(
    QuicServerTransportTest,
    CallbackParametersAccessibleAfterTransportDestruction) {
  // Ensures callbacks cannot access destructed objects in case the underlying
  // transport is destroyed.
  auto* serverPtr = server.get();
  std::set<std::string> possibleLocalhostQual{"127.0.0.1", "::1"};
  auto onConnectionUnboundCallback =
      [serverOwner = std::move(server), &possibleLocalhostQual](
          QuicServerTransport* /*transport*/,
          const QuicServerTransport::SourceIdentity& source,
          const std::vector<ConnectionIdData>&
              connectionIdData) mutable noexcept {
        serverOwner.reset(); // Destroy the transport.
        EXPECT_EQ(connectionIdData.size(), 1);
        EXPECT_TRUE(
            possibleLocalhostQual.find(source.first.getFullyQualified()) !=
            possibleLocalhostQual.end());
      };
  server = nullptr;

  {
    EXPECT_CALL(routingCallback, onConnectionUnbound(_, _, _))
        .Times(1)
        .WillOnce(onConnectionUnboundCallback);
    serverPtr->unbindConnection();
  }
}

TEST_F(QuicServerTransportTest, DestroyWithoutClosing) {
  StreamId streamId = server->createBidirectionalStream().value();

  MockReadCallback readCb;
  server->setReadCallback(streamId, &readCb);

  EXPECT_CALL(connCallback, onConnectionError(_)).Times(0);
  EXPECT_CALL(connCallback, onConnectionEnd()).Times(0);
  MockDeliveryCallback deliveryCallback;
  auto write = IOBuf::copyBuffer("no");
  server->writeChain(streamId, write->clone(), true, &deliveryCallback);

  EXPECT_CALL(deliveryCallback, onCanceled(_, _));
  EXPECT_CALL(readCb, readError(_, _));

  server.reset();
}

TEST_F(QuicServerTransportTest, DestroyWithoutClosingCancelByteEvents) {
  StreamId streamId = server->createBidirectionalStream().value();

  MockReadCallback readCb;
  server->setReadCallback(streamId, &readCb);

  EXPECT_CALL(connCallback, onConnectionError(_)).Times(0);
  EXPECT_CALL(connCallback, onConnectionEnd()).Times(0);
  auto write = IOBuf::copyBuffer("no");
  server->writeChain(streamId, write->clone(), true);

  MockByteEventCallback txCallback;
  MockByteEventCallback deliveryCallback;

  server->registerByteEventCallback(
      ByteEvent::Type::TX, streamId, 0, &txCallback);
  server->registerByteEventCallback(
      ByteEvent::Type::ACK, streamId, 0, &deliveryCallback);

  EXPECT_CALL(txCallback, onByteEventCanceled(_));
  EXPECT_CALL(deliveryCallback, onByteEventCanceled(_));
  EXPECT_CALL(readCb, readError(_, _));

  server.reset();
}

TEST_F(QuicServerTransportTest, SetCongestionControl) {
  // Default: Cubic
  auto cc = server->getConn().congestionController.get();
  EXPECT_EQ(CongestionControlType::Cubic, cc->type());

  // Change to Reno
  server->setCongestionControl(CongestionControlType::NewReno);
  cc = server->getConn().congestionController.get();
  EXPECT_EQ(CongestionControlType::NewReno, cc->type());

  // Change back to Cubic:
  server->setCongestionControl(CongestionControlType::Cubic);
  cc = server->getConn().congestionController.get();
  EXPECT_EQ(CongestionControlType::Cubic, cc->type());
}

TEST_F(QuicServerTransportTest, TestServerNotDetachable) {
  EXPECT_FALSE(server->isDetachable());
}

TEST_F(
    QuicServerTransportTest,
    ReceiveDataFromChangedPeerAddressWhileMigrationIsDisabled) {
  auto data = IOBuf::copyBuffer("bad data");
  StreamId streamId = 2;
  auto packetData = packetToBuf(createStreamPacket(
      *clientConnectionId,
      *server->getConn().serverConnectionId,
      clientNextAppDataPacketNum++,
      streamId,
      *data,
      0 /* cipherOverhead */,
      0 /* largestAcked */));
  folly::SocketAddress newPeer("100.101.102.103", 23456);
  try {
    deliverData(std::move(packetData), true, &newPeer);
    FAIL();
  } catch (const std::runtime_error& ex) {
    EXPECT_EQ(std::string(ex.what()), "Invalid migration");
  }
  EXPECT_TRUE(server->getConn().localConnectionError);
  EXPECT_EQ(
      server->getConn().localConnectionError->message, "Migration disabled");
  EXPECT_EQ(server->getConn().streamManager->streamCount(), 0);
}

TEST_F(QuicServerTransportTest, SwitchServerCidsNoOtherIds) {
  auto& conn = server->getNonConstConn();

  EXPECT_EQ(conn.retireAndSwitchPeerConnectionIds(), false);
  EXPECT_EQ(conn.pendingEvents.frames.size(), 0);
  EXPECT_EQ(conn.peerConnectionIds.size(), 1);
}

TEST_F(QuicServerTransportTest, SwitchServerCidsOneOtherCid) {
  auto& conn = server->getNonConstConn();
  auto originalCid = conn.clientConnectionId;
  auto secondCid = ConnectionIdData(
      ConnectionId::createAndMaybeCrash(std::vector<uint8_t>{5, 6, 7, 8}), 2);
  conn.peerConnectionIds.push_back(secondCid);

  EXPECT_EQ(conn.retireAndSwitchPeerConnectionIds(), true);
  EXPECT_EQ(conn.peerConnectionIds.size(), 1);

  EXPECT_EQ(conn.pendingEvents.frames.size(), 1);
  auto retireFrame = conn.pendingEvents.frames[0].asRetireConnectionIdFrame();
  EXPECT_EQ(retireFrame->sequenceNumber, 0);

  auto replacedCid = conn.clientConnectionId;
  EXPECT_NE(originalCid, *replacedCid);
  EXPECT_EQ(secondCid.connId, *replacedCid);
}

TEST_F(QuicServerTransportTest, SwitchServerCidsMultipleCids) {
  auto& conn = server->getNonConstConn();
  auto originalCid = conn.clientConnectionId;
  auto secondCid = ConnectionIdData(
      ConnectionId::createAndMaybeCrash(std::vector<uint8_t>{5, 6, 7, 8}), 2);
  auto thirdCid = ConnectionIdData(
      ConnectionId::createAndMaybeCrash(std::vector<uint8_t>{3, 3, 3, 3}), 3);

  conn.peerConnectionIds.push_back(secondCid);
  conn.peerConnectionIds.push_back(thirdCid);

  EXPECT_EQ(conn.retireAndSwitchPeerConnectionIds(), true);
  EXPECT_EQ(conn.peerConnectionIds.size(), 2);

  EXPECT_EQ(conn.pendingEvents.frames.size(), 1);
  auto retireFrame = conn.pendingEvents.frames[0].asRetireConnectionIdFrame();
  EXPECT_EQ(retireFrame->sequenceNumber, 0);

  // Uses the first unused connection id.
  auto replacedCid = conn.clientConnectionId;
  EXPECT_NE(originalCid, *replacedCid);
  EXPECT_EQ(secondCid.connId, *replacedCid);
}

TEST_F(
    QuicServerTransportTest,
    TestRetireAndSwitchPeerConnectionIdsEmptyPeerCid) {
  auto& conn = server->getNonConstConn();

  conn.clientConnectionId = ConnectionId::createZeroLength();
  EXPECT_EQ(conn.peerConnectionIds.size(), 1);

  EXPECT_EQ(conn.retireAndSwitchPeerConnectionIds(), true);
  EXPECT_EQ(conn.pendingEvents.frames.size(), 0);
  EXPECT_EQ(conn.peerConnectionIds.size(), 1);
}

TEST_F(QuicServerTransportTest, ShortHeaderPacketWithNoFrames) {
  auto qLogger = std::make_shared<FileQLogger>(VantagePoint::Server);
  server->getNonConstConn().qLogger = qLogger;
  // Use large packet number to make sure packet is long enough to parse
  PacketNum nextPacket = 0x11111111;
  // Add some dummy data to make body parseable
  auto dummyDataLen = 20;
  server->getNonConstConn().serverConnectionId = getTestConnectionId();
  auto aead = dynamic_cast<const MockAead*>(
      server->getNonConstConn().readCodec->getOneRttReadCipher());
  // Override the Aead mock to remove the 20 bytes of dummy data added below
  ON_CALL(*aead, _tryDecrypt(_, _, _))
      .WillByDefault(Invoke([&](auto& buf, auto, auto) {
        buf->trimEnd(20);
        return buf->clone();
      }));
  ShortHeader header(
      ProtectionType::KeyPhaseZero,
      *server->getConn().serverConnectionId,
      nextPacket);
  RegularQuicPacketBuilder builder(
      server->getConn().udpSendPacketLen,
      std::move(header),
      0 /* largestAcked */);
  ASSERT_FALSE(builder.encodePacketHeader().hasError());
  ASSERT_TRUE(builder.canBuildPacket());
  BufPtr buf = packetToBuf(std::move(builder).buildPacket());

  buf->coalesce();
  buf->reserve(0, 200);
  buf->append(dummyDataLen);
  EXPECT_THROW(deliverData(std::move(buf)), std::runtime_error);
  std::vector<int> indices =
      getQLogEventIndices(QLogEventType::PacketDrop, qLogger);
  EXPECT_EQ(indices.size(), 1);

  auto tmp = std::move(qLogger->logs[indices[0]]);
  auto event = dynamic_cast<QLogPacketDropEvent*>(tmp.get());
  EXPECT_EQ(
      event->dropReason,
      PacketDropReason(PacketDropReason::PROTOCOL_VIOLATION)._to_string());
}

TEST_F(QuicServerTransportTest, ShortHeaderPacketWithNoFramesAfterClose) {
  auto qLogger = std::make_shared<FileQLogger>(VantagePoint::Server);
  server->getNonConstConn().qLogger = qLogger;
  // Use large packet number to make sure packet is long enough to parse
  PacketNum nextPacket = 0x11111111;
  // Add some dummy data to make body parseable
  auto dummyDataLen = 20;
  server->getNonConstConn().serverConnectionId = getTestConnectionId();
  auto aead = dynamic_cast<const MockAead*>(
      server->getNonConstConn().readCodec->getOneRttReadCipher());
  // Override the Aead mock to remove the 20 bytes of dummy data added below
  ON_CALL(*aead, _tryDecrypt(_, _, _))
      .WillByDefault(Invoke([&](auto& buf, auto, auto) {
        buf->trimEnd(20);
        return buf->clone();
      }));

  // Close the connection
  server->close(QuicError(
      QuicErrorCode(TransportErrorCode::INTERNAL_ERROR),
      std::string("test close")));
  server->idleTimeout().cancelTimerCallback();
  ASSERT_FALSE(server->idleTimeout().isTimerCallbackScheduled());

  ShortHeader header(
      ProtectionType::KeyPhaseZero,
      *server->getConn().serverConnectionId,
      nextPacket);
  RegularQuicPacketBuilder builder(
      server->getConn().udpSendPacketLen,
      std::move(header),
      0 /* largestAcked */);
  ASSERT_FALSE(builder.encodePacketHeader().hasError());
  ASSERT_TRUE(builder.canBuildPacket());
  BufPtr buf = packetToBuf(std::move(builder).buildPacket());
  buf->coalesce();
  buf->reserve(0, 200);
  buf->append(dummyDataLen);
  EXPECT_THROW(deliverData(std::move(buf)), std::runtime_error);
  std::vector<int> indices =
      getQLogEventIndices(QLogEventType::PacketDrop, qLogger);
  EXPECT_EQ(indices.size(), 1);

  auto tmp = std::move(qLogger->logs[indices[0]]);
  auto event = dynamic_cast<QLogPacketDropEvent*>(tmp.get());
  EXPECT_EQ(
      event->dropReason,
      PacketDropReason(PacketDropReason::PROTOCOL_VIOLATION)._to_string());
}

class QuicServerTransportAllowMigrationTest
    : public QuicServerTransportTest,
      public WithParamInterface<MigrationParam> {
 public:
  bool getDisableMigration() override {
    return false;
  }

  virtual void initializeServerHandshake() override {
    fakeHandshake = new FakeServerHandshake(
        server->getNonConstConn(),
        FizzServerQuicHandshakeContext::Builder().build(),
        false,
        false,
        GetParam().clientSentActiveConnIdTransportParam);
    ON_CALL(*fakeHandshake, writeNewSessionTicket)
        .WillByDefault(Return(folly::unit));
  }
};

INSTANTIATE_TEST_SUITE_P(
    QuicServerTransportMigrationTests,
    QuicServerTransportAllowMigrationTest,
    Values(
        MigrationParam{std::nullopt},
        MigrationParam{2},
        MigrationParam{4},
        MigrationParam{9},
        MigrationParam{50}));

TEST_P(
    QuicServerTransportAllowMigrationTest,
    ReceiveProbingPacketFromChangedPeerAddress) {
  auto qLogger = std::make_shared<FileQLogger>(VantagePoint::Server);
  server->getNonConstConn().qLogger = qLogger;
  server->getNonConstConn().transportSettings.disableMigration = false;

  EXPECT_CALL(*quicStats_, onPeerAddressChanged).Times(1);
  // Add additional peer id so PathResponse completes.
  server->getNonConstConn().peerConnectionIds.emplace_back(
      ConnectionId::createAndMaybeCrash({1, 2, 3, 4}), 1);

  ShortHeader header(
      ProtectionType::KeyPhaseZero,
      *server->getConn().serverConnectionId,
      clientNextAppDataPacketNum++);
  RegularQuicPacketBuilder builder(
      server->getConn().udpSendPacketLen,
      std::move(header),
      0 /* largestAcked */);
  ASSERT_FALSE(builder.encodePacketHeader().hasError());
  ASSERT_TRUE(builder.canBuildPacket());

  ASSERT_FALSE(writeSimpleFrame(PathChallengeFrame(123), builder).hasError());
  auto packet = std::move(builder).buildPacket();
  auto packetData = packetToBuf(packet);
  folly::SocketAddress newPeer("100.101.102.103", 23456);
  try {
    deliverData(std::move(packetData), true, &newPeer);
    FAIL();
  } catch (const std::runtime_error& ex) {
    EXPECT_EQ(std::string(ex.what()), "Invalid migration");
  }
  EXPECT_TRUE(server->getConn().localConnectionError);
  EXPECT_EQ(
      server->getConn().localConnectionError->message,
      "Probing not supported yet");

  std::vector<int> indices =
      getQLogEventIndices(QLogEventType::PacketDrop, qLogger);
  EXPECT_EQ(indices.size(), 1);
  auto tmp = std::move(qLogger->logs[indices[0]]);
  auto event = dynamic_cast<QLogPacketDropEvent*>(tmp.get());
  EXPECT_EQ(event->packetSize, 29);
  EXPECT_EQ(
      event->dropReason,
      PacketDropReason(PacketDropReason::PEER_ADDRESS_CHANGE)._to_string());
  EXPECT_EQ(server->getConn().migrationState.numMigrations, 0);
}

TEST_P(
    QuicServerTransportAllowMigrationTest,
    ReceiveReorderedDataFromChangedPeerAddress) {
  auto data = IOBuf::copyBuffer("bad data");
  auto firstPacket = packetToBuf(createStreamPacket(
      *clientConnectionId,
      *server->getConn().serverConnectionId,
      clientNextAppDataPacketNum++,
      2,
      *data,
      0 /* cipherOverhead */,
      0 /* largestAcked */));
  auto secondPacket = packetToBuf(createStreamPacket(
      *clientConnectionId,
      *server->getConn().serverConnectionId,
      clientNextAppDataPacketNum++,
      6,
      *data,
      0 /* cipherOverhead */,
      0 /* largestAcked */));

  EXPECT_EQ(server->getConn().migrationState.numMigrations, 0);

  // Receive second packet first
  deliverData(std::move(secondPacket));

  auto peerAddress = server->getConn().peerAddress;

  // Receive first packet later from a different address
  folly::SocketAddress newPeer("100.101.102.103", 23456);
  EXPECT_CALL(*quicStats_, onPeerAddressChanged).Times(1);
  deliverData(std::move(firstPacket), true, &newPeer);

  // No migration for reordered packet
  EXPECT_EQ(server->getConn().peerAddress, peerAddress);
  EXPECT_EQ(server->getConn().migrationState.numMigrations, 0);
}

TEST_P(QuicServerTransportAllowMigrationTest, MigrateToUnvalidatedPeer) {
  auto data = IOBuf::copyBuffer("bad data");
  auto packetData = packetToBuf(createStreamPacket(
      *clientConnectionId,
      *server->getConn().serverConnectionId,
      clientNextAppDataPacketNum++,
      2,
      *data,
      0 /* cipherOverhead */,
      0 /* largestAcked */));

  EXPECT_EQ(server->getConn().migrationState.previousPeerAddresses.size(), 0);
  EXPECT_EQ(server->getConn().migrationState.numMigrations, 0);

  auto peerAddress = server->getConn().peerAddress;
  auto congestionController = server->getConn().congestionController.get();
  auto srtt = server->getConn().lossState.srtt;
  auto lrtt = server->getConn().lossState.lrtt;
  auto rttvar = server->getConn().lossState.rttvar;
  auto mrtt = server->getConn().lossState.mrtt;

  folly::SocketAddress newPeer("100.101.102.103", 23456);
  EXPECT_CALL(*quicStats_, onPeerAddressChanged).Times(1);
  deliverData(std::move(packetData), false, &newPeer);

  EXPECT_TRUE(server->getConn().pendingEvents.pathChallenge);
  EXPECT_EQ(server->getConn().peerAddress, newPeer);
  EXPECT_EQ(server->getConn().migrationState.numMigrations, 1);
  EXPECT_EQ(server->getConn().migrationState.previousPeerAddresses.size(), 1);
  EXPECT_EQ(
      server->getConn().migrationState.previousPeerAddresses.back(),
      peerAddress);
  EXPECT_EQ(server->getConn().lossState.srtt, 0us);
  EXPECT_EQ(server->getConn().lossState.lrtt, 0us);
  EXPECT_EQ(server->getConn().lossState.rttvar, 0us);
  EXPECT_EQ(server->getConn().lossState.mrtt, kDefaultMinRtt);
  EXPECT_NE(server->getConn().congestionController.get(), nullptr);
  EXPECT_NE(server->getConn().congestionController.get(), congestionController);
  EXPECT_EQ(
      server->getConn().migrationState.lastCongestionAndRtt->peerAddress,
      clientAddr);
  EXPECT_EQ(
      server->getConn()
          .migrationState.lastCongestionAndRtt->congestionController.get(),
      congestionController);
  EXPECT_EQ(server->getConn().migrationState.lastCongestionAndRtt->srtt, srtt);
  EXPECT_EQ(server->getConn().migrationState.lastCongestionAndRtt->lrtt, lrtt);
  EXPECT_EQ(
      server->getConn().migrationState.lastCongestionAndRtt->rttvar, rttvar);
  EXPECT_EQ(server->getConn().migrationState.lastCongestionAndRtt->mrtt, mrtt);

  loopForWrites();
  EXPECT_FALSE(server->getConn().pendingEvents.pathChallenge);
  EXPECT_TRUE(server->getConn().outstandingPathValidation);
  EXPECT_TRUE(server->getConn().pendingEvents.schedulePathValidationTimeout);
  EXPECT_TRUE(server->pathValidationTimeout().isTimerCallbackScheduled());

  EXPECT_TRUE(server->getConn().pathValidationLimiter != nullptr);

  ShortHeader header(
      ProtectionType::KeyPhaseZero,
      *server->getConn().serverConnectionId,
      clientNextAppDataPacketNum++);
  RegularQuicPacketBuilder builder(
      server->getConn().udpSendPacketLen,
      std::move(header),
      0 /* largestAcked */);
  ASSERT_FALSE(builder.encodePacketHeader().hasError());
  ASSERT_TRUE(builder.canBuildPacket());

  ASSERT_FALSE(writeSimpleFrame(
                   PathResponseFrame(
                       server->getConn().outstandingPathValidation->pathData),
                   builder)
                   .hasError());
  auto packet = std::move(builder).buildPacket();
  deliverData(packetToBuf(packet), false, &newPeer);
  EXPECT_FALSE(server->getConn().outstandingPathValidation);
  EXPECT_FALSE(server->getConn().pendingEvents.schedulePathValidationTimeout);
  EXPECT_FALSE(server->pathValidationTimeout().isTimerCallbackScheduled());

  // receiving data from the original peer address should not increment
  // numMigrations counter
  EXPECT_CALL(*quicStats_, onPeerAddressChanged).Times(1);
  auto nextPacketData = packetToBuf(createStreamPacket(
      *clientConnectionId,
      *server->getConn().serverConnectionId,
      clientNextAppDataPacketNum++,
      6,
      *data,
      0 /* cipherOverhead */,
      0 /* largestAcked */));

  deliverData(std::move(nextPacketData), false);
  EXPECT_EQ(server->getConn().migrationState.numMigrations, 1);
}

TEST_P(QuicServerTransportAllowMigrationTest, ResetPathRttPathResponse) {
  auto data = IOBuf::copyBuffer("bad data");
  auto packetData = packetToBuf(createStreamPacket(
      *clientConnectionId,
      *server->getConn().serverConnectionId,
      clientNextAppDataPacketNum++,
      2,
      *data,
      0 /* cipherOverhead */,
      0 /* largestAcked */));

  EXPECT_EQ(server->getConn().migrationState.numMigrations, 0);
  EXPECT_EQ(server->getConn().migrationState.previousPeerAddresses.size(), 0);

  auto peerAddress = server->getConn().peerAddress;
  auto srtt = server->getConn().lossState.srtt;
  auto lrtt = server->getConn().lossState.lrtt;
  auto rttvar = server->getConn().lossState.rttvar;

  folly::SocketAddress newPeer("100.101.102.103", 23456);
  EXPECT_CALL(*quicStats_, onPeerAddressChanged).Times(1);
  deliverData(std::move(packetData), false, &newPeer);

  EXPECT_TRUE(server->getConn().pendingEvents.pathChallenge);
  EXPECT_EQ(server->getConn().peerAddress, newPeer);
  EXPECT_EQ(server->getConn().migrationState.previousPeerAddresses.size(), 1);
  EXPECT_EQ(server->getConn().migrationState.numMigrations, 1);
  EXPECT_EQ(
      server->getConn().migrationState.previousPeerAddresses.back(),
      peerAddress);
  EXPECT_EQ(server->getConn().lossState.srtt, 0us);
  EXPECT_EQ(server->getConn().lossState.lrtt, 0us);
  EXPECT_EQ(server->getConn().lossState.rttvar, 0us);
  EXPECT_EQ(
      server->getConn().migrationState.lastCongestionAndRtt->peerAddress,
      clientAddr);
  EXPECT_EQ(server->getConn().migrationState.lastCongestionAndRtt->srtt, srtt);
  EXPECT_EQ(server->getConn().migrationState.lastCongestionAndRtt->lrtt, lrtt);
  EXPECT_EQ(
      server->getConn().migrationState.lastCongestionAndRtt->rttvar, rttvar);

  loopForWrites();
  EXPECT_FALSE(server->getConn().pendingEvents.pathChallenge);
  EXPECT_TRUE(server->getConn().outstandingPathValidation);
  EXPECT_TRUE(server->getConn().pendingEvents.schedulePathValidationTimeout);
  EXPECT_TRUE(server->pathValidationTimeout().isTimerCallbackScheduled());

  ShortHeader header(
      ProtectionType::KeyPhaseZero,
      *server->getConn().serverConnectionId,
      clientNextAppDataPacketNum++);
  RegularQuicPacketBuilder builder(
      server->getConn().udpSendPacketLen,
      std::move(header),
      0 /* largestAcked */);
  ASSERT_FALSE(builder.encodePacketHeader().hasError());
  ASSERT_TRUE(builder.canBuildPacket());

  ASSERT_FALSE(writeSimpleFrame(
                   PathResponseFrame(
                       server->getConn().outstandingPathValidation->pathData),
                   builder)
                   .hasError());
  auto packet = std::move(builder).buildPacket();
  deliverData(packetToBuf(packet), false, &newPeer);
  EXPECT_FALSE(server->getConn().outstandingPathValidation);
  EXPECT_FALSE(server->getConn().pendingEvents.schedulePathValidationTimeout);
  EXPECT_FALSE(server->pathValidationTimeout().isTimerCallbackScheduled());
  EXPECT_FALSE(server->getConn().writableBytesLimit);

  // After Pathresponse frame is received, srtt,lrtt = sampleRtt;
  // sampleRtt = time from send of PathChallenge to receiving PathResponse
  EXPECT_NE(server->getConn().lossState.srtt, 0us);
  EXPECT_NE(server->getConn().lossState.lrtt, 0us);
  EXPECT_NE(server->getConn().lossState.rttvar, 0us);

  EXPECT_EQ(server->getConn().migrationState.lastCongestionAndRtt->srtt, srtt);
  EXPECT_EQ(server->getConn().migrationState.lastCongestionAndRtt->lrtt, lrtt);
  EXPECT_EQ(
      server->getConn().migrationState.lastCongestionAndRtt->rttvar, rttvar);
}

TEST_P(QuicServerTransportAllowMigrationTest, IgnoreInvalidPathResponse) {
  auto data = IOBuf::copyBuffer("bad data");
  auto packetData = packetToBuf(createStreamPacket(
      *clientConnectionId,
      *server->getConn().serverConnectionId,
      clientNextAppDataPacketNum++,
      2,
      *data,
      0 /* cipherOverhead */,
      0 /* largestAcked */));

  EXPECT_EQ(server->getConn().migrationState.previousPeerAddresses.size(), 0);

  auto peerAddress = server->getConn().peerAddress;

  folly::SocketAddress newPeer("100.101.102.103", 23456);

  EXPECT_CALL(*quicStats_, onPeerAddressChanged).Times(1);
  deliverData(std::move(packetData), false, &newPeer);

  EXPECT_TRUE(server->getConn().pendingEvents.pathChallenge);

  EXPECT_TRUE(server->getConn().pathValidationLimiter != nullptr);
  EXPECT_EQ(server->getConn().peerAddress, newPeer);
  EXPECT_EQ(server->getConn().migrationState.previousPeerAddresses.size(), 1);
  EXPECT_EQ(
      server->getConn().migrationState.previousPeerAddresses.back(),
      peerAddress);

  loopForWrites();
  EXPECT_FALSE(server->getConn().pendingEvents.pathChallenge);
  EXPECT_TRUE(server->getConn().outstandingPathValidation);
  EXPECT_TRUE(server->getConn().pendingEvents.schedulePathValidationTimeout);
  EXPECT_TRUE(server->pathValidationTimeout().isTimerCallbackScheduled());

  ShortHeader header(
      ProtectionType::KeyPhaseZero,
      *server->getConn().serverConnectionId,
      clientNextAppDataPacketNum++);
  RegularQuicPacketBuilder builder(
      server->getConn().udpSendPacketLen,
      std::move(header),
      0 /* largestAcked */);
  ASSERT_FALSE(builder.encodePacketHeader().hasError());
  ASSERT_TRUE(builder.canBuildPacket());

  ASSERT_FALSE(
      writeSimpleFrame(
          PathResponseFrame(
              server->getConn().outstandingPathValidation->pathData ^ 1),
          builder)
          .hasError());
  auto packet = std::move(builder).buildPacket();
  deliverData(packetToBuf(packet), false, &newPeer);
  EXPECT_TRUE(server->getConn().outstandingPathValidation);
  EXPECT_TRUE(server->getConn().pendingEvents.schedulePathValidationTimeout);
  EXPECT_TRUE(server->pathValidationTimeout().isTimerCallbackScheduled());
}

TEST_P(
    QuicServerTransportAllowMigrationTest,
    ReceivePathResponseFromDifferentPeerAddress) {
  auto data = IOBuf::copyBuffer("bad data");
  auto packetData = packetToBuf(createStreamPacket(
      *clientConnectionId,
      *server->getConn().serverConnectionId,
      clientNextAppDataPacketNum++,
      2,
      *data,
      0 /* cipherOverhead */,
      0 /* largestAcked */));

  EXPECT_EQ(server->getConn().migrationState.previousPeerAddresses.size(), 0);

  auto peerAddress = server->getConn().peerAddress;

  folly::SocketAddress newPeer("100.101.102.103", 23456);
  EXPECT_CALL(*quicStats_, onPeerAddressChanged).Times(1);
  deliverData(std::move(packetData), false, &newPeer);

  EXPECT_TRUE(server->getConn().pendingEvents.pathChallenge);
  EXPECT_EQ(server->getConn().peerAddress, newPeer);
  EXPECT_EQ(server->getConn().migrationState.previousPeerAddresses.size(), 1);
  EXPECT_EQ(
      server->getConn().migrationState.previousPeerAddresses.back(),
      peerAddress);

  loopForWrites();
  EXPECT_FALSE(server->getConn().pendingEvents.pathChallenge);
  EXPECT_TRUE(server->getConn().outstandingPathValidation);
  EXPECT_TRUE(server->getConn().pendingEvents.schedulePathValidationTimeout);
  EXPECT_TRUE(server->pathValidationTimeout().isTimerCallbackScheduled());

  EXPECT_TRUE(server->getConn().pathValidationLimiter != nullptr);

  ShortHeader header(
      ProtectionType::KeyPhaseZero,
      *server->getConn().serverConnectionId,
      clientNextAppDataPacketNum++);
  RegularQuicPacketBuilder builder(
      server->getConn().udpSendPacketLen,
      std::move(header),
      0 /* largestAcked */);
  ASSERT_FALSE(builder.encodePacketHeader().hasError());
  ASSERT_TRUE(builder.canBuildPacket());
  ASSERT_FALSE(writeSimpleFrame(
                   PathResponseFrame(
                       server->getConn().outstandingPathValidation->pathData),
                   builder)
                   .hasError());
  auto packet = std::move(builder).buildPacket();
  folly::SocketAddress newPeer2("200.101.102.103", 23456);
  try {
    EXPECT_CALL(*quicStats_, onPeerAddressChanged).Times(1);
    deliverData(packetToBuf(packet), false, &newPeer2);
    FAIL();
  } catch (const std::runtime_error& ex) {
    EXPECT_EQ(std::string(ex.what()), "Invalid migration");
  }
  EXPECT_TRUE(server->isClosed());
  EXPECT_TRUE(server->getConn().outstandingPathValidation);
  EXPECT_FALSE(server->getConn().pendingEvents.schedulePathValidationTimeout);
  EXPECT_FALSE(server->pathValidationTimeout().isTimerCallbackScheduled());

  EXPECT_TRUE(server->getConn().localConnectionError);
  EXPECT_EQ(
      server->getConn().localConnectionError->message,
      "Probing not supported yet");
}

TEST_F(QuicServerTransportTest, TooManyMigrations) {
  auto qLogger = std::make_shared<FileQLogger>(VantagePoint::Server);
  server->getNonConstConn().qLogger = qLogger;
  server->getNonConstConn().transportSettings.disableMigration = false;

  auto data = IOBuf::copyBuffer("bad data");
  auto packetData = packetToBuf(createStreamPacket(
      *clientConnectionId,
      *server->getConn().serverConnectionId,
      clientNextAppDataPacketNum++,
      2,
      *data,
      0 /* cipherOverhead */,
      0 /* largestAcked */));

  uint16_t maxNumMigrationsAllowed =
      server->getConn().transportSettings.maxNumMigrationsAllowed;
  for (uint16_t i = 0; i < maxNumMigrationsAllowed; ++i) {
    folly::SocketAddress newPeer("100.101.102.103", 23456 + i);
    EXPECT_CALL(*quicStats_, onPeerAddressChanged).Times(1);
    deliverData(packetData->clone(), false, &newPeer);
  }
  EXPECT_EQ(
      server->getConn().migrationState.numMigrations, maxNumMigrationsAllowed);

  folly::SocketAddress newPeer("200.101.102.103", 23456);
  try {
    EXPECT_CALL(*quicStats_, onPeerAddressChanged).Times(1);
    deliverData(packetData->clone(), false, &newPeer);
  } catch (const std::runtime_error& ex) {
    EXPECT_EQ(std::string(ex.what()), "Invalid migration");
  }
  EXPECT_TRUE(server->getConn().localConnectionError);
  EXPECT_EQ(
      server->getConn().localConnectionError->message, "Too many migrations");
  EXPECT_TRUE(server->isClosed());
  std::vector<int> indices =
      getQLogEventIndices(QLogEventType::PacketDrop, qLogger);
  EXPECT_EQ(indices.size(), 1);
  auto tmp = std::move(qLogger->logs[indices[0]]);
  auto event = dynamic_cast<QLogPacketDropEvent*>(tmp.get());
  EXPECT_EQ(event->packetSize, 0);
  EXPECT_EQ(
      event->dropReason,
      PacketDropReason(PacketDropReason::PEER_ADDRESS_CHANGE)._to_string());
}

TEST_P(QuicServerTransportAllowMigrationTest, RetiringConnIdIssuesNewIds) {
  auto& conn = server->getNonConstConn();
  // reset queued packets
  conn.outstandings.reset();
  auto initialServerConnId = conn.selfConnectionIds[0];
  auto nextConnId = conn.selfConnectionIds[1].connId;
  EXPECT_EQ(initialServerConnId.sequenceNumber, 0);

  auto data = IOBuf::copyBuffer("hi there!");
  auto packetStreamData = packetToBuf(createStreamPacket(
      *clientConnectionId,
      *serverConnectionId,
      clientNextAppDataPacketNum++,
      2,
      *data,
      0 /* cipherOverhead */,
      0 /* largestAcked */));

  ShortHeader header(
      ProtectionType::KeyPhaseZero, nextConnId, clientNextAppDataPacketNum++);
  RegularQuicPacketBuilder builder(
      conn.udpSendPacketLen, std::move(header), 0 /* largestAcked */);
  ASSERT_FALSE(builder.encodePacketHeader().hasError());

  // build packet containing a frame retiring the initial server conn id
  ASSERT_TRUE(builder.canBuildPacket());
  RetireConnectionIdFrame retireConnIdFrame(initialServerConnId.sequenceNumber);
  ASSERT_FALSE(
      writeSimpleFrame(QuicSimpleFrame(retireConnIdFrame), builder).hasError());
  auto retireConnIdPacket = std::move(builder).buildPacket();

  /**
   * Deliver both packets (one containing stream data and the other containing a
   * RETIRE_CONNECTION_ID frame). The RETIRE_CONNECTION_ID frame should result
   * in invoking onConnectionIdRetired().
   */
  EXPECT_CALL(
      routingCallback, onConnectionIdRetired(_, initialServerConnId.connId));
  deliverData(std::move(packetStreamData), false);
  deliverData(packetToBuf(retireConnIdPacket));
  // received a RETIRE_CONN_ID frame for seq no 0, expect next seq to be 1
  EXPECT_EQ(conn.selfConnectionIds[0].sequenceNumber, 1);

  // server should have written NEW_CONNECTION_ID frame since we've retired one
  auto numNewConnIdFrames = std::count_if(
      conn.outstandings.packets.begin(),
      conn.outstandings.packets.end(),
      findFrameInPacketFunc<QuicSimpleFrame::Type::NewConnectionIdFrame>());
  EXPECT_EQ(numNewConnIdFrames, 1);
}

TEST_P(QuicServerTransportAllowMigrationTest, RetiringInvalidConnId) {
  auto& conn = server->getNonConstConn();
  // reset queued packets
  conn.outstandings.reset();

  ShortHeader header(
      ProtectionType::KeyPhaseZero,
      *serverConnectionId,
      clientNextAppDataPacketNum++);
  RegularQuicPacketBuilder builder(
      conn.udpSendPacketLen, std::move(header), 0 /* largestAcked */);
  ASSERT_FALSE(builder.encodePacketHeader().hasError());

  // build packet containing a frame retiring an invalid conn id / seq no
  ASSERT_TRUE(builder.canBuildPacket());
  RetireConnectionIdFrame retireConnIdFrame(conn.nextSelfConnectionIdSequence);
  ASSERT_FALSE(
      writeSimpleFrame(QuicSimpleFrame(retireConnIdFrame), builder).hasError());
  auto retireConnIdPacket = std::move(builder).buildPacket();

  // retiring invalid conn id should not invoke onConnectionIdRetired()
  EXPECT_CALL(routingCallback, onConnectionIdRetired(_, _)).Times(0);
  deliverData(packetToBuf(retireConnIdPacket));
  // no changes should have been made to selfConnectionIds
  EXPECT_EQ(conn.selfConnectionIds[0].sequenceNumber, 0);
  EXPECT_TRUE(conn.connIdsRetiringSoon->empty());

  // verify that we don't issue a new conn id
  auto numNewConnIdFrames = std::count_if(
      conn.outstandings.packets.begin(),
      conn.outstandings.packets.end(),
      findFrameInPacketFunc<QuicSimpleFrame::Type::NewConnectionIdFrame>());
  EXPECT_EQ(numNewConnIdFrames, 0);
}

TEST_P(QuicServerTransportAllowMigrationTest, RetireConnIdOfContainingPacket) {
  /**
   * From RFC9000:
   * The sequence number specified in a RETIRE_CONNECTION_ID frame MUST NOT
   * refer to the Destination Connection ID field of the packet in which the
   * frame is contained.  The peer MAY treat this as a connection error of type
   * PROTOCOL_VIOLATION.
   */

  auto& conn = server->getNonConstConn();
  // reset queued packets
  conn.outstandings.reset();

  ShortHeader header(
      ProtectionType::KeyPhaseZero,
      *serverConnectionId,
      clientNextAppDataPacketNum++);
  RegularQuicPacketBuilder builder(
      conn.udpSendPacketLen, std::move(header), 0 /* largestAcked */);
  ASSERT_FALSE(builder.encodePacketHeader().hasError());

  // build packet containing a frame retiring conn id of containing packet
  ASSERT_TRUE(builder.canBuildPacket());
  RetireConnectionIdFrame retireConnIdFrame(0);
  ASSERT_FALSE(
      writeSimpleFrame(QuicSimpleFrame(retireConnIdFrame), builder).hasError());
  auto retireConnIdPacket = std::move(builder).buildPacket();

  // parsing packet should throw an error
  EXPECT_THROW(
      deliverData(packetToBuf(retireConnIdPacket)), std::runtime_error);
}

TEST_P(
    QuicServerTransportAllowMigrationTest,
    RetireConnIdFrameZeroLengthSrcConnId) {
  /**
   * From RFC9000:
   * An endpoint cannot send this frame if it was provided with a zero-length
   * connection ID by its peer. An endpoint that provides a zero- length
   * connection ID MUST treat receipt of a RETIRE_CONNECTION_ID frame as a
   * connection error of type PROTOCOL_VIOLATION.
   */
  auto& conn = server->getNonConstConn();
  // reset queued packets
  conn.outstandings.reset();
  // simulate that the client has a zero-length conn id
  conn.clientConnectionId = ConnectionId::createZeroLength();

  ShortHeader header(
      ProtectionType::KeyPhaseZero,
      *serverConnectionId,
      clientNextAppDataPacketNum++);
  RegularQuicPacketBuilder builder(
      conn.udpSendPacketLen, std::move(header), 0 /* largestAcked */);
  ASSERT_FALSE(builder.encodePacketHeader().hasError());

  // build packet containing a RETIRE_CONNECTION_ID frame
  ASSERT_TRUE(builder.canBuildPacket());
  RetireConnectionIdFrame retireConnIdFrame(0);
  ASSERT_FALSE(
      writeSimpleFrame(QuicSimpleFrame(retireConnIdFrame), builder).hasError());
  auto retireConnIdPacket = std::move(builder).buildPacket();

  // parsing packet should throw an error
  EXPECT_THROW(
      deliverData(packetToBuf(retireConnIdPacket)), std::runtime_error);
}

TEST_P(QuicServerTransportAllowMigrationTest, MigrateToValidatedPeer) {
  folly::SocketAddress newPeer("100.101.102.103", 23456);
  server->getNonConstConn().migrationState.previousPeerAddresses.push_back(
      newPeer);
  CongestionAndRttState state;
  state.peerAddress = newPeer;
  state.recordTime = Clock::now();
  state.congestionController = ccFactory_->makeCongestionController(
      server->getNonConstConn(),
      server->getNonConstConn().transportSettings.defaultCongestionController);
  state.srtt = 1000us;
  state.lrtt = 2000us;
  state.rttvar = 3000us;
  state.mrtt = 800us;
  server->getNonConstConn().migrationState.lastCongestionAndRtt =
      std::move(state);

  auto data = IOBuf::copyBuffer("bad data");
  auto packetData = packetToBuf(createStreamPacket(
      *clientConnectionId,
      *server->getConn().serverConnectionId,
      clientNextAppDataPacketNum++,
      2,
      *data,
      0 /* cipherOverhead */,
      0 /* largestAcked */));

  EXPECT_EQ(server->getConn().migrationState.previousPeerAddresses.size(), 1);

  auto peerAddress = server->getConn().peerAddress;
  auto lastCongestionController =
      server->getConn()
          .migrationState.lastCongestionAndRtt->congestionController.get();
  auto lastSrtt = server->getConn().migrationState.lastCongestionAndRtt->srtt;
  auto lastLrtt = server->getConn().migrationState.lastCongestionAndRtt->lrtt;
  auto lastRttvar =
      server->getConn().migrationState.lastCongestionAndRtt->rttvar;
  auto lastMrtt = server->getConn().migrationState.lastCongestionAndRtt->mrtt;
  auto congestionController = server->getConn().congestionController.get();
  auto srtt = server->getConn().lossState.srtt;
  auto lrtt = server->getConn().lossState.lrtt;
  auto rttvar = server->getConn().lossState.rttvar;
  auto mrtt = server->getConn().lossState.mrtt;

  deliverData(std::move(packetData), false, &newPeer);

  EXPECT_FALSE(server->getConn().pendingEvents.pathChallenge);
  EXPECT_EQ(server->getConn().peerAddress, newPeer);
  EXPECT_EQ(server->getConn().migrationState.previousPeerAddresses.size(), 1);
  EXPECT_EQ(
      server->getConn().migrationState.previousPeerAddresses.back(),
      peerAddress);
  EXPECT_EQ(server->getConn().lossState.srtt, lastSrtt);
  EXPECT_EQ(server->getConn().lossState.lrtt, lastLrtt);
  EXPECT_EQ(server->getConn().lossState.rttvar, lastRttvar);
  EXPECT_EQ(server->getConn().lossState.mrtt, lastMrtt);
  EXPECT_EQ(
      server->getConn().congestionController.get(), lastCongestionController);
  EXPECT_EQ(
      server->getConn().migrationState.lastCongestionAndRtt->peerAddress,
      clientAddr);
  EXPECT_EQ(
      server->getConn()
          .migrationState.lastCongestionAndRtt->congestionController.get(),
      congestionController);
  EXPECT_EQ(server->getConn().migrationState.lastCongestionAndRtt->srtt, srtt);
  EXPECT_EQ(server->getConn().migrationState.lastCongestionAndRtt->lrtt, lrtt);
  EXPECT_EQ(
      server->getConn().migrationState.lastCongestionAndRtt->rttvar, rttvar);
  EXPECT_EQ(server->getConn().migrationState.lastCongestionAndRtt->mrtt, mrtt);
}

TEST_P(
    QuicServerTransportAllowMigrationTest,
    MigrateToUnvalidatedPeerOverwritesCachedRttState) {
  folly::SocketAddress newPeer("100.101.102.103", 23456);
  server->getNonConstConn().migrationState.previousPeerAddresses.push_back(
      newPeer);
  CongestionAndRttState state;
  state.peerAddress = newPeer;
  state.recordTime = Clock::now();
  state.congestionController = ccFactory_->makeCongestionController(
      server->getNonConstConn(),
      server->getNonConstConn().transportSettings.defaultCongestionController);
  state.srtt = 1000us;
  state.lrtt = 2000us;
  state.rttvar = 3000us;
  state.mrtt = 800us;
  server->getNonConstConn().migrationState.lastCongestionAndRtt =
      std::move(state);

  auto data = IOBuf::copyBuffer("bad data");
  auto packetData = packetToBuf(createStreamPacket(
      *clientConnectionId,
      *server->getConn().serverConnectionId,
      clientNextAppDataPacketNum++,
      2,
      *data,
      0 /* cipherOverhead */,
      0 /* largestAcked */));

  EXPECT_EQ(server->getConn().migrationState.previousPeerAddresses.size(), 1);

  auto peerAddress = server->getConn().peerAddress;
  auto congestionController = server->getConn().congestionController.get();
  auto srtt = server->getConn().lossState.srtt;
  auto lrtt = server->getConn().lossState.lrtt;
  auto rttvar = server->getConn().lossState.rttvar;
  auto mrtt = server->getConn().lossState.mrtt;

  folly::SocketAddress newPeer2("200.101.102.103", 2345);
  deliverData(std::move(packetData), false, &newPeer2);

  EXPECT_TRUE(server->getConn().pendingEvents.pathChallenge);

  EXPECT_EQ(server->getConn().peerAddress, newPeer2);
  EXPECT_EQ(server->getConn().migrationState.previousPeerAddresses.size(), 2);
  EXPECT_EQ(
      server->getConn().migrationState.previousPeerAddresses.front(), newPeer);
  EXPECT_EQ(
      server->getConn().migrationState.previousPeerAddresses.back(),
      peerAddress);
  EXPECT_EQ(server->getConn().lossState.srtt, 0us);
  EXPECT_EQ(server->getConn().lossState.lrtt, 0us);
  EXPECT_EQ(server->getConn().lossState.rttvar, 0us);
  EXPECT_EQ(server->getConn().lossState.mrtt, kDefaultMinRtt);
  EXPECT_NE(server->getConn().congestionController.get(), nullptr);
  EXPECT_NE(server->getConn().congestionController.get(), congestionController);
  EXPECT_EQ(
      server->getConn().migrationState.lastCongestionAndRtt->peerAddress,
      clientAddr);
  EXPECT_EQ(
      server->getConn()
          .migrationState.lastCongestionAndRtt->congestionController.get(),
      congestionController);
  EXPECT_EQ(server->getConn().migrationState.lastCongestionAndRtt->srtt, srtt);
  EXPECT_EQ(server->getConn().migrationState.lastCongestionAndRtt->lrtt, lrtt);
  EXPECT_EQ(
      server->getConn().migrationState.lastCongestionAndRtt->rttvar, rttvar);
  EXPECT_EQ(server->getConn().migrationState.lastCongestionAndRtt->mrtt, mrtt);
}

TEST_P(QuicServerTransportAllowMigrationTest, MigrateToStaleValidatedPeer) {
  folly::SocketAddress newPeer("100.101.102.103", 23456);
  server->getNonConstConn().migrationState.previousPeerAddresses.push_back(
      newPeer);
  CongestionAndRttState state;
  state.peerAddress = newPeer;
  state.recordTime = Clock::now() - 2 * kTimeToRetainLastCongestionAndRttState;
  state.congestionController = ccFactory_->makeCongestionController(
      server->getNonConstConn(),
      server->getNonConstConn().transportSettings.defaultCongestionController);
  state.srtt = 1000us;
  state.lrtt = 2000us;
  state.rttvar = 3000us;
  state.srtt = 800us;
  server->getNonConstConn().migrationState.lastCongestionAndRtt =
      std::move(state);

  auto data = IOBuf::copyBuffer("bad data");
  auto packetData = packetToBuf(createStreamPacket(
      *clientConnectionId,
      *server->getConn().serverConnectionId,
      clientNextAppDataPacketNum++,
      2,
      *data,
      0 /* cipherOverhead */,
      0 /* largestAcked */));

  EXPECT_EQ(server->getConn().migrationState.previousPeerAddresses.size(), 1);

  auto peerAddress = server->getConn().peerAddress;
  auto congestionController = server->getConn().congestionController.get();
  auto srtt = server->getConn().lossState.srtt;
  auto lrtt = server->getConn().lossState.lrtt;
  auto rttvar = server->getConn().lossState.rttvar;
  auto mrtt = server->getConn().lossState.mrtt;

  deliverData(std::move(packetData), false, &newPeer);

  EXPECT_FALSE(server->getConn().pendingEvents.pathChallenge);
  EXPECT_EQ(server->getConn().peerAddress, newPeer);
  EXPECT_EQ(server->getConn().migrationState.previousPeerAddresses.size(), 1);
  EXPECT_EQ(
      server->getConn().migrationState.previousPeerAddresses.back(),
      peerAddress);
  EXPECT_EQ(server->getConn().lossState.srtt, 0us);
  EXPECT_EQ(server->getConn().lossState.lrtt, 0us);
  EXPECT_EQ(server->getConn().lossState.rttvar, 0us);
  EXPECT_EQ(server->getConn().lossState.mrtt, kDefaultMinRtt);
  EXPECT_NE(server->getConn().congestionController.get(), nullptr);
  EXPECT_NE(server->getConn().congestionController.get(), congestionController);
  EXPECT_EQ(
      server->getConn().migrationState.lastCongestionAndRtt->peerAddress,
      clientAddr);
  EXPECT_EQ(
      server->getConn()
          .migrationState.lastCongestionAndRtt->congestionController.get(),
      congestionController);
  EXPECT_EQ(server->getConn().migrationState.lastCongestionAndRtt->srtt, srtt);
  EXPECT_EQ(server->getConn().migrationState.lastCongestionAndRtt->lrtt, lrtt);
  EXPECT_EQ(
      server->getConn().migrationState.lastCongestionAndRtt->rttvar, rttvar);
  EXPECT_EQ(server->getConn().migrationState.lastCongestionAndRtt->mrtt, mrtt);
}

TEST_F(
    QuicServerTransportTest,
    MigrateToValidatePeerCancelsPendingPathChallenge) {
  server->getNonConstConn().transportSettings.disableMigration = false;
  auto data = IOBuf::copyBuffer("bad data");
  auto packetData = packetToBuf(createStreamPacket(
      *clientConnectionId,
      *server->getConn().serverConnectionId,
      clientNextAppDataPacketNum++,
      2,
      *data,
      0 /* cipherOverhead */,
      0 /* largestAcked */));

  auto peerAddress = server->getConn().peerAddress;
  auto congestionController = server->getConn().congestionController.get();
  auto srtt = server->getConn().lossState.srtt;
  auto lrtt = server->getConn().lossState.lrtt;
  auto rttvar = server->getConn().lossState.rttvar;
  auto mrtt = server->getConn().lossState.mrtt;

  EXPECT_CALL(*quicStats_, onPeerAddressChanged).Times(1);
  folly::SocketAddress newPeer("100.101.102.103", 23456);
  deliverData(std::move(packetData), false, &newPeer);
  EXPECT_EQ(server->getConn().peerAddress, newPeer);
  EXPECT_TRUE(server->getConn().pendingEvents.pathChallenge);
  EXPECT_FALSE(server->getConn().outstandingPathValidation);
  EXPECT_FALSE(server->getConn().pendingEvents.schedulePathValidationTimeout);
  EXPECT_FALSE(server->pathValidationTimeout().isTimerCallbackScheduled());

  EXPECT_EQ(server->getConn().migrationState.previousPeerAddresses.size(), 1);
  EXPECT_EQ(
      server->getConn().migrationState.previousPeerAddresses.back(),
      peerAddress);
  EXPECT_EQ(server->getConn().lossState.srtt, 0us);
  EXPECT_EQ(server->getConn().lossState.lrtt, 0us);
  EXPECT_EQ(server->getConn().lossState.rttvar, 0us);
  EXPECT_EQ(server->getConn().lossState.mrtt, kDefaultMinRtt);
  EXPECT_NE(server->getConn().congestionController.get(), nullptr);
  EXPECT_NE(server->getConn().congestionController.get(), congestionController);
  EXPECT_EQ(
      server->getConn().migrationState.lastCongestionAndRtt->peerAddress,
      clientAddr);
  EXPECT_EQ(
      server->getConn()
          .migrationState.lastCongestionAndRtt->congestionController.get(),
      congestionController);
  EXPECT_EQ(server->getConn().migrationState.lastCongestionAndRtt->srtt, srtt);
  EXPECT_EQ(server->getConn().migrationState.lastCongestionAndRtt->lrtt, lrtt);
  EXPECT_EQ(
      server->getConn().migrationState.lastCongestionAndRtt->rttvar, rttvar);
  EXPECT_EQ(server->getConn().migrationState.lastCongestionAndRtt->mrtt, mrtt);

  auto packetData2 = packetToBuf(createStreamPacket(
      *clientConnectionId,
      *server->getConn().serverConnectionId,
      clientNextAppDataPacketNum++,
      6,
      *data,
      0 /* cipherOverhead */,
      0 /* largestAcked */));
  EXPECT_CALL(*quicStats_, onPeerAddressChanged).Times(1);
  deliverData(std::move(packetData2), false);
  EXPECT_FALSE(server->getConn().pendingEvents.pathChallenge);
  EXPECT_FALSE(server->getConn().outstandingPathValidation);
  EXPECT_FALSE(server->getConn().pendingEvents.schedulePathValidationTimeout);
  EXPECT_FALSE(server->pathValidationTimeout().isTimerCallbackScheduled());

  EXPECT_EQ(server->getConn().migrationState.previousPeerAddresses.size(), 0);
  EXPECT_EQ(server->getConn().lossState.srtt, srtt);
  EXPECT_EQ(server->getConn().lossState.lrtt, lrtt);
  EXPECT_EQ(server->getConn().lossState.rttvar, rttvar);
  EXPECT_EQ(server->getConn().lossState.mrtt, mrtt);
  EXPECT_EQ(server->getConn().congestionController.get(), congestionController);
  EXPECT_FALSE(server->getConn().migrationState.lastCongestionAndRtt);
}

TEST_F(
    QuicServerTransportTest,
    MigrateToUnvalidatePeerCancelsOutstandingPathChallenge) {
  server->getNonConstConn().transportSettings.disableMigration = false;
  auto data = IOBuf::copyBuffer("bad data");
  auto packetData = packetToBuf(createStreamPacket(
      *clientConnectionId,
      *server->getConn().serverConnectionId,
      clientNextAppDataPacketNum++,
      2,
      *data,
      0 /* cipherOverhead */,
      0 /* largestAcked */));

  auto peerAddress = server->getConn().peerAddress;
  auto congestionController = server->getConn().congestionController.get();
  auto srtt = server->getConn().lossState.srtt;
  auto lrtt = server->getConn().lossState.lrtt;
  auto rttvar = server->getConn().lossState.rttvar;
  auto mrtt = server->getConn().lossState.mrtt;

  folly::SocketAddress newPeer("100.101.102.103", 23456);
  deliverData(std::move(packetData), true, &newPeer);
  EXPECT_EQ(server->getConn().peerAddress, newPeer);
  EXPECT_TRUE(server->getConn().outstandingPathValidation);
  EXPECT_TRUE(server->getConn().pendingEvents.schedulePathValidationTimeout);
  EXPECT_TRUE(server->pathValidationTimeout().isTimerCallbackScheduled());

  EXPECT_EQ(server->getConn().migrationState.previousPeerAddresses.size(), 1);
  EXPECT_EQ(
      server->getConn().migrationState.previousPeerAddresses.back(),
      peerAddress);
  EXPECT_EQ(server->getConn().lossState.srtt, 0us);
  EXPECT_EQ(server->getConn().lossState.lrtt, 0us);
  EXPECT_EQ(server->getConn().lossState.rttvar, 0us);
  EXPECT_EQ(server->getConn().lossState.mrtt, kDefaultMinRtt);
  EXPECT_NE(server->getConn().congestionController.get(), nullptr);
  EXPECT_NE(server->getConn().congestionController.get(), congestionController);
  EXPECT_EQ(
      server->getConn().migrationState.lastCongestionAndRtt->peerAddress,
      clientAddr);
  EXPECT_EQ(
      server->getConn()
          .migrationState.lastCongestionAndRtt->congestionController.get(),
      congestionController);
  EXPECT_EQ(server->getConn().migrationState.lastCongestionAndRtt->srtt, srtt);
  EXPECT_EQ(server->getConn().migrationState.lastCongestionAndRtt->lrtt, lrtt);
  EXPECT_EQ(
      server->getConn().migrationState.lastCongestionAndRtt->rttvar, rttvar);
  EXPECT_EQ(server->getConn().migrationState.lastCongestionAndRtt->mrtt, mrtt);

  auto packetData2 = packetToBuf(createStreamPacket(
      *clientConnectionId,
      *server->getConn().serverConnectionId,
      clientNextAppDataPacketNum++,
      6,
      *data,
      0 /* cipherOverhead */,
      0 /* largestAcked */));
  folly::SocketAddress newPeer2("200.101.102.103", 23456);
  deliverData(std::move(packetData2), false, &newPeer2);
  EXPECT_FALSE(server->getConn().outstandingPathValidation);
  EXPECT_FALSE(server->getConn().pendingEvents.schedulePathValidationTimeout);
  EXPECT_FALSE(server->pathValidationTimeout().isTimerCallbackScheduled());

  EXPECT_EQ(server->getConn().migrationState.previousPeerAddresses.size(), 1);
  EXPECT_EQ(
      server->getConn().migrationState.previousPeerAddresses.back(),
      peerAddress);
  EXPECT_EQ(server->getConn().lossState.srtt, 0us);
  EXPECT_EQ(server->getConn().lossState.lrtt, 0us);
  EXPECT_EQ(server->getConn().lossState.rttvar, 0us);
  EXPECT_EQ(server->getConn().lossState.mrtt, kDefaultMinRtt);
  EXPECT_NE(server->getConn().congestionController.get(), nullptr);
  EXPECT_NE(server->getConn().congestionController.get(), congestionController);
  EXPECT_EQ(
      server->getConn().migrationState.lastCongestionAndRtt->peerAddress,
      clientAddr);
  EXPECT_EQ(
      server->getConn()
          .migrationState.lastCongestionAndRtt->congestionController.get(),
      congestionController);
  EXPECT_EQ(server->getConn().migrationState.lastCongestionAndRtt->srtt, srtt);
  EXPECT_EQ(server->getConn().migrationState.lastCongestionAndRtt->lrtt, lrtt);
  EXPECT_EQ(
      server->getConn().migrationState.lastCongestionAndRtt->rttvar, rttvar);
  EXPECT_EQ(server->getConn().migrationState.lastCongestionAndRtt->mrtt, mrtt);
}

TEST_F(
    QuicServerTransportTest,
    MigrateToValidatePeerCancelsOutstandingPathChallenge) {
  server->getNonConstConn().transportSettings.disableMigration = false;
  auto data = IOBuf::copyBuffer("bad data");
  auto packetData = packetToBuf(createStreamPacket(
      *clientConnectionId,
      *server->getConn().serverConnectionId,
      clientNextAppDataPacketNum++,
      2,
      *data,
      0 /* cipherOverhead */,
      0 /* largestAcked */));

  auto peerAddress = server->getConn().peerAddress;
  auto congestionController = server->getConn().congestionController.get();
  auto srtt = server->getConn().lossState.srtt;
  auto lrtt = server->getConn().lossState.lrtt;
  auto rttvar = server->getConn().lossState.rttvar;
  auto mrtt = server->getConn().lossState.mrtt;

  folly::SocketAddress newPeer("100.101.102.103", 23456);
  deliverData(std::move(packetData), true, &newPeer);
  EXPECT_EQ(server->getConn().peerAddress, newPeer);
  EXPECT_TRUE(server->getConn().outstandingPathValidation);
  EXPECT_TRUE(server->getConn().pendingEvents.schedulePathValidationTimeout);
  EXPECT_TRUE(server->pathValidationTimeout().isTimerCallbackScheduled());

  EXPECT_EQ(server->getConn().migrationState.previousPeerAddresses.size(), 1);
  EXPECT_EQ(
      server->getConn().migrationState.previousPeerAddresses.back(),
      peerAddress);
  EXPECT_EQ(server->getConn().lossState.srtt, 0us);
  EXPECT_EQ(server->getConn().lossState.lrtt, 0us);
  EXPECT_EQ(server->getConn().lossState.rttvar, 0us);
  EXPECT_EQ(server->getConn().lossState.mrtt, kDefaultMinRtt);
  EXPECT_NE(server->getConn().congestionController.get(), nullptr);
  EXPECT_NE(server->getConn().congestionController.get(), congestionController);
  EXPECT_EQ(
      server->getConn().migrationState.lastCongestionAndRtt->peerAddress,
      clientAddr);
  EXPECT_EQ(
      server->getConn()
          .migrationState.lastCongestionAndRtt->congestionController.get(),
      congestionController);
  EXPECT_EQ(server->getConn().migrationState.lastCongestionAndRtt->srtt, srtt);
  EXPECT_EQ(server->getConn().migrationState.lastCongestionAndRtt->lrtt, lrtt);
  EXPECT_EQ(
      server->getConn().migrationState.lastCongestionAndRtt->rttvar, rttvar);
  EXPECT_EQ(server->getConn().migrationState.lastCongestionAndRtt->mrtt, mrtt);

  auto packetData2 = packetToBuf(createStreamPacket(
      *clientConnectionId,
      *server->getConn().serverConnectionId,
      clientNextAppDataPacketNum++,
      6,
      *data,
      0 /* cipherOverhead */,
      0 /* largestAcked */));
  deliverData(std::move(packetData2));
  EXPECT_FALSE(server->getConn().outstandingPathValidation);
  EXPECT_FALSE(server->getConn().pendingEvents.schedulePathValidationTimeout);
  EXPECT_FALSE(server->pathValidationTimeout().isTimerCallbackScheduled());

  EXPECT_EQ(server->getConn().migrationState.previousPeerAddresses.size(), 0);
  EXPECT_EQ(server->getConn().lossState.srtt, srtt);
  EXPECT_EQ(server->getConn().lossState.lrtt, lrtt);
  EXPECT_EQ(server->getConn().lossState.rttvar, rttvar);
  EXPECT_EQ(server->getConn().lossState.mrtt, mrtt);
  EXPECT_EQ(server->getConn().congestionController.get(), congestionController);
  EXPECT_FALSE(server->getConn().migrationState.lastCongestionAndRtt);
}

TEST_F(QuicServerTransportTest, ClientPortChangeNATRebinding) {
  server->getNonConstConn().transportSettings.disableMigration = false;

  StreamId streamId = server->createBidirectionalStream().value();
  auto data1 = IOBuf::copyBuffer("Aloha");
  server->writeChain(streamId, data1->clone(), false);
  loopForWrites();
  PacketNum packetNum1 =
      getFirstOutstandingPacket(
          server->getNonConstConn(), PacketNumberSpace::AppData)
          ->packet.header.getPacketSequenceNum();
  AckBlocks acks = {{packetNum1, packetNum1}};
  auto packet1 = createAckPacket(
      server->getNonConstConn(),
      ++clientNextAppDataPacketNum,
      acks,
      PacketNumberSpace::AppData);
  deliverData(packetToBuf(packet1));

  auto data = IOBuf::copyBuffer("bad data");
  auto packetData = packetToBuf(createStreamPacket(
      *clientConnectionId,
      *server->getConn().serverConnectionId,
      clientNextAppDataPacketNum++,
      2,
      *data,
      0 /* cipherOverhead */,
      0 /* largestAcked */));

  auto congestionController = server->getConn().congestionController.get();

  folly::SocketAddress newPeer(clientAddr.getIPAddress(), 23456);
  deliverData(std::move(packetData), true, &newPeer);

  EXPECT_TRUE(server->getConn().outstandingPathValidation);
  EXPECT_EQ(server->getConn().peerAddress, newPeer);
  EXPECT_EQ(server->getConn().migrationState.previousPeerAddresses.size(), 1);
  EXPECT_NE(
      server->getConn().lossState.srtt, std::chrono::microseconds::zero());
  EXPECT_NE(
      server->getConn().lossState.lrtt, std::chrono::microseconds::zero());
  EXPECT_NE(
      server->getConn().lossState.rttvar, std::chrono::microseconds::zero());
  EXPECT_NE(server->getConn().lossState.mrtt, kDefaultMinRtt);
  EXPECT_EQ(server->getConn().congestionController.get(), congestionController);
  EXPECT_FALSE(server->getConn().migrationState.lastCongestionAndRtt);
}

TEST_F(QuicServerTransportTest, ClientAddressChangeNATRebinding) {
  server->getNonConstConn().transportSettings.disableMigration = false;
  StreamId streamId = server->createBidirectionalStream().value();
  auto data1 = IOBuf::copyBuffer("Aloha");
  server->writeChain(streamId, data1->clone(), false);
  loopForWrites();
  PacketNum packetNum1 =
      getFirstOutstandingPacket(
          server->getNonConstConn(), PacketNumberSpace::AppData)
          ->packet.header.getPacketSequenceNum();
  AckBlocks acks = {{packetNum1, packetNum1}};
  auto packet1 = createAckPacket(
      server->getNonConstConn(),
      ++clientNextAppDataPacketNum,
      acks,
      PacketNumberSpace::AppData);
  deliverData(packetToBuf(packet1));

  auto data = IOBuf::copyBuffer("bad data");
  auto packetData = packetToBuf(createStreamPacket(
      *clientConnectionId,
      *server->getConn().serverConnectionId,
      clientNextAppDataPacketNum++,
      2,
      *data,
      0 /* cipherOverhead */,
      0 /* largestAcked */));

  auto congestionController = server->getConn().congestionController.get();

  folly::SocketAddress newPeer("127.0.0.100", 23456);
  deliverData(std::move(packetData), true, &newPeer);

  EXPECT_TRUE(server->getConn().outstandingPathValidation);

  EXPECT_EQ(server->getConn().peerAddress, newPeer);
  EXPECT_EQ(server->getConn().migrationState.previousPeerAddresses.size(), 1);
  EXPECT_NE(server->getConn().lossState.srtt, 0us);
  EXPECT_NE(server->getConn().lossState.lrtt, 0us);
  EXPECT_NE(server->getConn().lossState.rttvar, 0us);
  EXPECT_NE(server->getConn().lossState.mrtt, kDefaultMinRtt);
  EXPECT_EQ(server->getConn().congestionController.get(), congestionController);
  EXPECT_FALSE(server->getConn().migrationState.lastCongestionAndRtt);
}

TEST_F(
    QuicServerTransportTest,
    ClientNATRebindingWhilePathValidationOutstanding) {
  server->getNonConstConn().transportSettings.disableMigration = false;

  auto data = IOBuf::copyBuffer("bad data");
  auto packetData = packetToBuf(createStreamPacket(
      *clientConnectionId,
      *server->getConn().serverConnectionId,
      clientNextAppDataPacketNum++,
      2,
      *data,
      0 /* cipherOverhead */,
      0 /* largestAcked */));

  auto congestionController = server->getConn().congestionController.get();

  folly::SocketAddress newPeer("200.0.0.100", 23456);
  deliverData(std::move(packetData), true, &newPeer);

  EXPECT_TRUE(server->getConn().outstandingPathValidation);

  EXPECT_EQ(server->getConn().peerAddress, newPeer);
  EXPECT_EQ(server->getConn().migrationState.previousPeerAddresses.size(), 1);
  EXPECT_EQ(
      server->getConn().lossState.srtt, std::chrono::microseconds::zero());
  EXPECT_EQ(
      server->getConn().lossState.lrtt, std::chrono::microseconds::zero());
  EXPECT_EQ(
      server->getConn().lossState.rttvar, std::chrono::microseconds::zero());
  EXPECT_EQ(server->getConn().lossState.mrtt, kDefaultMinRtt);
  EXPECT_NE(server->getConn().congestionController.get(), nullptr);
  EXPECT_NE(server->getConn().congestionController.get(), congestionController);
  EXPECT_TRUE(server->getConn().migrationState.lastCongestionAndRtt);

  auto newCC = server->getConn().congestionController.get();
  folly::SocketAddress newPeer2("200.0.0.200", 12345);
  auto data2 = IOBuf::copyBuffer("bad data");
  auto packetData2 = packetToBuf(createStreamPacket(
      *clientConnectionId,
      *server->getConn().serverConnectionId,
      clientNextAppDataPacketNum++,
      2,
      *data,
      0 /* cipherOverhead */,
      0 /* largestAcked */));
  deliverData(std::move(packetData2), true, &newPeer2);

  EXPECT_TRUE(server->getConn().outstandingPathValidation);

  EXPECT_EQ(server->getConn().peerAddress, newPeer2);
  EXPECT_EQ(server->getConn().migrationState.previousPeerAddresses.size(), 1);
  EXPECT_EQ(
      server->getConn().lossState.srtt, std::chrono::microseconds::zero());
  EXPECT_EQ(
      server->getConn().lossState.lrtt, std::chrono::microseconds::zero());
  EXPECT_EQ(
      server->getConn().lossState.rttvar, std::chrono::microseconds::zero());
  EXPECT_EQ(server->getConn().lossState.mrtt, kDefaultMinRtt);
  EXPECT_EQ(server->getConn().congestionController.get(), newCC);
  EXPECT_TRUE(server->getConn().migrationState.lastCongestionAndRtt);
}

TEST_F(QuicServerTransportTest, PingIsTreatedAsRetransmittable) {
  PingFrame pingFrame;
  ShortHeader header(
      ProtectionType::KeyPhaseZero,
      *server->getConn().serverConnectionId,
      clientNextAppDataPacketNum++);
  RegularQuicPacketBuilder builder(
      server->getConn().udpSendPacketLen,
      std::move(header),
      0 /* largestAcked */);
  ASSERT_FALSE(builder.encodePacketHeader().hasError());
  ASSERT_FALSE(writeFrame(pingFrame, builder).hasError());
  auto packet = std::move(builder).buildPacket();
  deliverData(packetToBuf(packet));
  EXPECT_TRUE(server->getConn().pendingEvents.scheduleAckTimeout);
}

TEST_F(QuicServerTransportTest, ImmediateAckValid) {
  // Verify that an incoming IMMEDIATE_ACK frame flags all
  // packet number spaces to generate ACKs immediately.
  ImmediateAckFrame immediateAckFrame;
  // We support receiving IMMEDIATE_ACK
  server->getNonConstConn().transportSettings.minAckDelay = 1ms;

  auto packetNum = clientNextAppDataPacketNum++;
  ShortHeader header(
      ProtectionType::KeyPhaseZero,
      *server->getConn().serverConnectionId,
      packetNum);
  RegularQuicPacketBuilder builder(
      server->getConn().udpSendPacketLen,
      std::move(header),
      0 /* largestAcked */);
  ASSERT_FALSE(builder.encodePacketHeader().hasError());
  ASSERT_FALSE(writeFrame(immediateAckFrame, builder).hasError());
  auto packet = std::move(builder).buildPacket();
  ASSERT_NO_THROW(deliverData(packetToBuf(packet)));
  // An ACK has been scheduled for AppData number space.
  EXPECT_TRUE(server->getConn()
                  .ackStates.appDataAckState.largestAckScheduled.has_value());
  EXPECT_EQ(
      server->getConn().ackStates.appDataAckState.largestAckScheduled.value_or(
          packetNum + 1),
      packetNum);
}

TEST_F(QuicServerTransportTest, ImmediateAckProtocolViolation) {
  // Verify that an incoming IMMEDIATE_ACK frame flags all
  // packet number spaces to generate ACKs immediately.
  ImmediateAckFrame immediateAckFrame;
  // We do not support IMMEDIATE_ACK frames
  server->getNonConstConn().transportSettings.minAckDelay.reset();

  auto packetNum = clientNextAppDataPacketNum++;
  ShortHeader header(
      ProtectionType::KeyPhaseZero,
      *server->getConn().serverConnectionId,
      packetNum);
  RegularQuicPacketBuilder builder(
      server->getConn().udpSendPacketLen,
      std::move(header),
      0 /* largestAcked */);
  ASSERT_FALSE(builder.encodePacketHeader().hasError());
  ASSERT_FALSE(writeFrame(immediateAckFrame, builder).hasError());
  auto packet = std::move(builder).buildPacket();
  // This should throw a protocol violation error
  ASSERT_THROW(deliverData(packetToBuf(packet)), std::runtime_error);
  // Verify that std::nullopt of the ack states have changed
  EXPECT_FALSE(
      server->getConn().ackStates.initialAckState->needsToSendAckImmediately);
  EXPECT_FALSE(
      server->getConn().ackStates.handshakeAckState->needsToSendAckImmediately);
  EXPECT_FALSE(
      server->getConn().ackStates.appDataAckState.needsToSendAckImmediately);
}

TEST_F(QuicServerTransportTest, ReceiveDatagramFrameAndDiscard) {
  ShortHeader header(
      ProtectionType::KeyPhaseZero,
      *server->getConn().serverConnectionId,
      clientNextAppDataPacketNum++);
  RegularQuicPacketBuilder builder(
      server->getConn().udpSendPacketLen,
      std::move(header),
      0 /* largestAcked */);
  ASSERT_FALSE(builder.encodePacketHeader().hasError());
  StringPiece datagramPayload = "do not rely on me. I am unreliable";
  DatagramFrame datagramFrame(
      datagramPayload.size(), IOBuf::copyBuffer(datagramPayload));
  ASSERT_FALSE(writeFrame(datagramFrame, builder).hasError());
  auto packet = std::move(builder).buildPacket();
  EXPECT_CALL(*quicStats_, onDatagramDroppedOnRead()).Times(1);
  deliverData(packetToBuf(packet));
  ASSERT_EQ(server->getConn().datagramState.readBuffer.size(), 0);
}

TEST_F(QuicServerTransportTest, ReceiveDatagramFrameAndStore) {
  auto& conn = server->getNonConstConn();
  conn.datagramState.maxReadFrameSize = std::numeric_limits<uint16_t>::max();
  conn.datagramState.maxReadBufferSize = 10;

  EXPECT_CALL(*quicStats_, onDatagramRead(_))
      .Times(conn.datagramState.maxReadBufferSize)
      .WillRepeatedly(Invoke([](uint64_t bytes) { EXPECT_GT(bytes, 0); }));
  EXPECT_CALL(*quicStats_, onDatagramDroppedOnRead())
      .Times(conn.datagramState.maxReadBufferSize);
  for (uint64_t i = 0; i < conn.datagramState.maxReadBufferSize * 2; i++) {
    ShortHeader header(
        ProtectionType::KeyPhaseZero,
        *server->getConn().serverConnectionId,
        clientNextAppDataPacketNum++);
    RegularQuicPacketBuilder builder(
        server->getConn().udpSendPacketLen,
        std::move(header),
        0 /* largestAcked */);
    ASSERT_FALSE(builder.encodePacketHeader().hasError());
    StringPiece datagramPayload = "do not rely on me. I am unreliable";
    DatagramFrame datagramFrame(
        datagramPayload.size(), IOBuf::copyBuffer(datagramPayload));
    ASSERT_FALSE(writeFrame(datagramFrame, builder).hasError());
    auto packet = std::move(builder).buildPacket();
    deliverData(packetToBuf(packet));
    if (i < conn.datagramState.maxReadBufferSize) {
      ASSERT_EQ(server->getConn().datagramState.readBuffer.size(), i + 1);
    }
  }
  ASSERT_EQ(
      server->getConn().datagramState.readBuffer.size(),
      conn.datagramState.maxReadBufferSize);
}

TEST_F(QuicServerTransportTest, RecvNewConnectionIdValid) {
  auto& conn = server->getNonConstConn();
  conn.transportSettings.selfActiveConnectionIdLimit = 2;

  ShortHeader header(ProtectionType::KeyPhaseZero, *conn.clientConnectionId, 1);
  RegularQuicPacketBuilder builder(
      conn.udpSendPacketLen, std::move(header), 0 /* largestAcked */);
  ASSERT_FALSE(builder.encodePacketHeader().hasError());
  ASSERT_TRUE(builder.canBuildPacket());
  NewConnectionIdFrame newConnId(
      1,
      0,
      ConnectionId::createAndMaybeCrash({2, 4, 2, 3}),
      StatelessResetToken{9, 8, 7, 6});
  ASSERT_FALSE(
      writeSimpleFrame(QuicSimpleFrame(newConnId), builder).hasError());

  auto packet = std::move(builder).buildPacket();

  EXPECT_EQ(conn.peerConnectionIds.size(), 1);
  deliverData(packetToBuf(packet), false);
  EXPECT_EQ(conn.peerConnectionIds.size(), 2);
  EXPECT_EQ(conn.peerConnectionIds[1].connId, newConnId.connectionId);
  EXPECT_EQ(conn.peerConnectionIds[1].sequenceNumber, newConnId.sequenceNumber);
  EXPECT_EQ(conn.peerConnectionIds[1].token, newConnId.token);
}

TEST_F(QuicServerTransportTest, RecvNewConnectionIdTooManyReceivedIds) {
  auto& conn = server->getNonConstConn();
  conn.transportSettings.selfActiveConnectionIdLimit = 0;

  ShortHeader header(ProtectionType::KeyPhaseZero, *conn.clientConnectionId, 1);
  RegularQuicPacketBuilder builder(
      conn.udpSendPacketLen, std::move(header), 0 /* largestAcked */);
  ASSERT_FALSE(builder.encodePacketHeader().hasError());
  ASSERT_TRUE(builder.canBuildPacket());
  NewConnectionIdFrame newConnId(
      1,
      0,
      ConnectionId::createAndMaybeCrash({2, 4, 2, 3}),
      StatelessResetToken());
  ASSERT_FALSE(
      writeSimpleFrame(QuicSimpleFrame(newConnId), builder).hasError());

  auto packet = std::move(builder).buildPacket();

  EXPECT_EQ(conn.peerConnectionIds.size(), 1);
  deliverData(packetToBuf(packet), false);
  EXPECT_EQ(conn.peerConnectionIds.size(), 1);
}

TEST_F(QuicServerTransportTest, RecvNewConnectionIdInvalidRetire) {
  auto& conn = server->getNonConstConn();
  conn.transportSettings.selfActiveConnectionIdLimit = 1;

  ShortHeader header(ProtectionType::KeyPhaseZero, *conn.clientConnectionId, 1);
  RegularQuicPacketBuilder builder(
      conn.udpSendPacketLen, std::move(header), 0 /* largestAcked */);
  ASSERT_FALSE(builder.encodePacketHeader().hasError());
  ASSERT_TRUE(builder.canBuildPacket());
  NewConnectionIdFrame newConnId(
      1,
      3,
      ConnectionId::createAndMaybeCrash({2, 4, 2, 3}),
      StatelessResetToken());
  ASSERT_FALSE(
      writeSimpleFrame(QuicSimpleFrame(newConnId), builder).hasError());

  auto packet = std::move(builder).buildPacket();

  EXPECT_EQ(conn.peerConnectionIds.size(), 1);
  EXPECT_THROW(deliverData(packetToBuf(packet), false), std::runtime_error);
}

TEST_F(QuicServerTransportTest, RecvNewConnectionIdNoopValidDuplicate) {
  auto& conn = server->getNonConstConn();
  conn.transportSettings.selfActiveConnectionIdLimit = 1;

  ConnectionId connId2 = ConnectionId::createAndMaybeCrash({5, 5, 5, 5});
  conn.peerConnectionIds.emplace_back(connId2, 1);

  ShortHeader header(ProtectionType::KeyPhaseZero, *conn.clientConnectionId, 1);
  RegularQuicPacketBuilder builder(
      conn.udpSendPacketLen, std::move(header), 0 /* largestAcked */);
  ASSERT_FALSE(builder.encodePacketHeader().hasError());
  ASSERT_TRUE(builder.canBuildPacket());
  NewConnectionIdFrame newConnId(1, 0, connId2, StatelessResetToken());
  ASSERT_FALSE(
      writeSimpleFrame(QuicSimpleFrame(newConnId), builder).hasError());

  auto packet = std::move(builder).buildPacket();

  EXPECT_EQ(conn.peerConnectionIds.size(), 2);
  deliverData(packetToBuf(packet), false);
  EXPECT_EQ(conn.peerConnectionIds.size(), 2);
}

TEST_F(QuicServerTransportTest, RecvNewConnectionIdExceptionInvalidDuplicate) {
  auto& conn = server->getNonConstConn();

  ConnectionId connId2 = ConnectionId::createAndMaybeCrash({5, 5, 5, 5});
  conn.peerConnectionIds.emplace_back(connId2, 1);

  ShortHeader header(ProtectionType::KeyPhaseZero, *conn.clientConnectionId, 1);
  RegularQuicPacketBuilder builder(
      conn.udpSendPacketLen, std::move(header), 0 /* largestAcked */);
  ASSERT_FALSE(builder.encodePacketHeader().hasError());
  ASSERT_TRUE(builder.canBuildPacket());
  NewConnectionIdFrame newConnId(2, 0, connId2, StatelessResetToken());
  ASSERT_FALSE(
      writeSimpleFrame(QuicSimpleFrame(newConnId), builder).hasError());

  auto packet = std::move(builder).buildPacket();

  EXPECT_EQ(conn.peerConnectionIds.size(), 2);
  EXPECT_THROW(deliverData(packetToBuf(packet)), std::runtime_error);
}

TEST_F(QuicServerTransportTest, WriteBufMetaWithoutRealData) {
  auto streamId = server->createBidirectionalStream().value();
  size_t bufferLength = 2000;
  BufferMeta meta(bufferLength);
  auto result = server->writeBufMeta(streamId, meta, true);
  EXPECT_TRUE(result.hasError());
}

TEST_F(QuicServerTransportTest, ResetDSRStream) {
  auto& conn = server->getConnectionState();
  server->getNonConstConn().transportSettings.writeConnectionDataPacketsLimit =
      1;
  auto streamId = server->createBidirectionalStream().value();
  BufferMeta meta(conn.udpSendPacketLen * 5);
  auto buf = buildRandomInputData(200);
  auto dsrSender = std::make_unique<MockDSRPacketizationRequestSender>();
  EXPECT_CALL(*dsrSender, release()).Times(1);
  server->setDSRPacketizationRequestSender(streamId, std::move(dsrSender));
  EXPECT_TRUE(server->writeChain(streamId, std::move(buf), false).hasValue());
  auto streamResult = conn.streamManager->getStream(streamId);
  ASSERT_FALSE(streamResult.hasError());
  auto stream = streamResult.value();
  EXPECT_TRUE(server->writeBufMeta(streamId, meta, false).hasValue());
  loopForWrites();
  ASSERT_NE(stream, nullptr);
  stream->writeBufMeta.split(conn.udpSendPacketLen - 200);

  server->resetStream(streamId, GenericApplicationErrorCode::UNKNOWN);
  loopForWrites();
  auto packet = getLastOutstandingPacket(
                    server->getConnectionState(), PacketNumberSpace::AppData)
                    ->packet;
  EXPECT_GE(packet.frames.size(), 1);

  bool foundReset = false;
  for (auto& frame : packet.frames) {
    auto rstStream = frame.asRstStreamFrame();
    if (!rstStream) {
      continue;
    }
    EXPECT_EQ(streamId, rstStream->streamId);
    EXPECT_GT(rstStream->finalSize, 200);
    EXPECT_EQ(GenericApplicationErrorCode::UNKNOWN, rstStream->errorCode);
    foundReset = true;
  }
  EXPECT_TRUE(foundReset);
}

TEST_F(QuicServerTransportTest, SetDSRSenderAndWriteBufMetaIntoStream) {
  auto streamId = server->createBidirectionalStream().value();
  size_t bufferLength = 2000;
  BufferMeta meta(bufferLength);
  auto buf = buildRandomInputData(20);
  auto dsrSender = std::make_unique<MockDSRPacketizationRequestSender>();
  server->setDSRPacketizationRequestSender(streamId, std::move(dsrSender));
  // Some amount of real data needs to be written first:
  server->writeChain(streamId, std::move(buf), false);
  server->writeBufMeta(streamId, meta, true);
  auto& stream =
      *server->getConnectionState().streamManager->findStream(streamId);
  EXPECT_GE(stream.writeBufMeta.offset, 20);
  EXPECT_EQ(stream.writeBufMeta.length, bufferLength);
  EXPECT_TRUE(stream.writeBufMeta.eof);
  EXPECT_EQ(
      *stream.finalWriteOffset,
      stream.writeBufMeta.offset + stream.writeBufMeta.length);
}

TEST_F(QuicServerTransportTest, InvokeTxCallbacksSingleByteDSR) {
  StrictMock<MockByteEventCallback> firstByteTxCb;
  StrictMock<MockByteEventCallback> dsrByteTxCb;
  StrictMock<MockByteEventCallback> lastByteTxCb;
  StrictMock<MockByteEventCallback> pastlastByteTxCb;
  auto stream = server->createBidirectionalStream().value();
  auto dsrSender = std::make_unique<MockDSRPacketizationRequestSender>();
  server->setDSRPacketizationRequestSender(stream, std::move(dsrSender));

  auto buf = buildRandomInputData(1);
  server->writeChain(stream, buf->clone(), false /* eof */);
  server->writeBufMeta(stream, BufferMeta(1), false);
  EXPECT_CALL(firstByteTxCb, onByteEventRegistered(getTxMatcher(stream, 0)))
      .Times(1);
  EXPECT_CALL(dsrByteTxCb, onByteEventRegistered(getTxMatcher(stream, 1)))
      .Times(1);
  EXPECT_CALL(lastByteTxCb, onByteEventRegistered(getTxMatcher(stream, 1)))
      .Times(1);
  EXPECT_CALL(pastlastByteTxCb, onByteEventRegistered(getTxMatcher(stream, 2)))
      .Times(1);
  server->registerTxCallback(stream, 0, &firstByteTxCb);
  server->registerTxCallback(stream, 1, &dsrByteTxCb);
  server->registerTxCallback(stream, 1, &lastByteTxCb);
  server->registerTxCallback(stream, 2, &pastlastByteTxCb);
  Mock::VerifyAndClearExpectations(&firstByteTxCb);
  Mock::VerifyAndClearExpectations(&dsrByteTxCb);
  Mock::VerifyAndClearExpectations(&lastByteTxCb);
  Mock::VerifyAndClearExpectations(&pastlastByteTxCb);

  // first and last byte TX callbacks should be triggered immediately
  EXPECT_CALL(firstByteTxCb, onByteEvent(getTxMatcher(stream, 0))).Times(1);
  EXPECT_CALL(dsrByteTxCb, onByteEvent(getTxMatcher(stream, 1))).Times(1);
  EXPECT_CALL(lastByteTxCb, onByteEvent(getTxMatcher(stream, 1))).Times(1);
  server->getConnectionState().oneRttWriteCipher = test::createNoOpAead();
  auto temp = test::createNoOpHeaderCipher().value();
  temp->setDefaultKey();
  server->getConnectionState().oneRttWriteHeaderCipher = std::move(temp);
  CHECK(server->getConnectionState().oneRttWriteCipher->getKey().has_value());
  CHECK(server->getConnectionState().oneRttWriteHeaderCipher);
  loopForWrites();
  Mock::VerifyAndClearExpectations(&firstByteTxCb);
  Mock::VerifyAndClearExpectations(&lastByteTxCb);
  Mock::VerifyAndClearExpectations(&pastlastByteTxCb);

  // try to set the first and last byte offsets again
  // callbacks should be triggered immediately
  EXPECT_CALL(firstByteTxCb, onByteEventRegistered(getTxMatcher(stream, 0)))
      .Times(1);
  EXPECT_CALL(dsrByteTxCb, onByteEventRegistered(getTxMatcher(stream, 1)))
      .Times(1);
  EXPECT_CALL(lastByteTxCb, onByteEventRegistered(getTxMatcher(stream, 1)))
      .Times(1);
  server->registerTxCallback(stream, 0, &firstByteTxCb);
  server->registerTxCallback(stream, 1, &dsrByteTxCb);
  server->registerTxCallback(stream, 1, &lastByteTxCb);
  Mock::VerifyAndClearExpectations(&firstByteTxCb);
  Mock::VerifyAndClearExpectations(&dsrByteTxCb);
  Mock::VerifyAndClearExpectations(&lastByteTxCb);
  EXPECT_CALL(firstByteTxCb, onByteEvent(getTxMatcher(stream, 0))).Times(1);
  EXPECT_CALL(dsrByteTxCb, onByteEvent(getTxMatcher(stream, 1))).Times(1);
  EXPECT_CALL(lastByteTxCb, onByteEvent(getTxMatcher(stream, 1))).Times(1);
  loopForWrites(); // have to loop since processed async
  Mock::VerifyAndClearExpectations(&firstByteTxCb);
  Mock::VerifyAndClearExpectations(&dsrByteTxCb);
  Mock::VerifyAndClearExpectations(&lastByteTxCb);

  // Even if we register pastlastByte again, it shouldn't trigger
  // onByteEventRegistered because this is a duplicate registration.
  EXPECT_CALL(pastlastByteTxCb, onByteEventRegistered(getTxMatcher(stream, 2)))
      .Times(0);
  auto ret = server->registerTxCallback(stream, 2, &pastlastByteTxCb);
  EXPECT_EQ(LocalErrorCode::INVALID_OPERATION, ret.error());
  Mock::VerifyAndClearExpectations(&pastlastByteTxCb);

  // pastlastByteTxCb::onByteEvent will never get called
  // cancel gets called instead
  // Even though we attempted to register the ByteEvent twice,  it resulted in
  // an error. So, onByteEventCanceled should be called only once.
  EXPECT_CALL(pastlastByteTxCb, onByteEventCanceled(getTxMatcher(stream, 2)))
      .Times(1);
  server->close(std::nullopt);
  Mock::VerifyAndClearExpectations(&pastlastByteTxCb);
}

TEST_F(QuicServerTransportTest, InvokeDeliveryCallbacksSingleByteWithDSR) {
  // register all possible ways to get a DeliveryCb
  //
  // applications built atop QUIC may capture both first and last byte timings,
  // which in this test are the same byte
  StrictMock<MockDeliveryCallback> writeChainDeliveryCb;
  StrictMock<MockDeliveryCallback> writeBufMetaDeliveryCb;
  StrictMock<MockDeliveryCallback> firstByteDeliveryCb;
  StrictMock<MockDeliveryCallback> lastByteDeliveryCb;
  StrictMock<MockDeliveryCallback> unsentByteDeliveryCb;
  auto stream = server->createBidirectionalStream().value();
  auto dsrSender = std::make_unique<MockDSRPacketizationRequestSender>();
  server->setDSRPacketizationRequestSender(stream, std::move(dsrSender));

  auto buf = buildRandomInputData(1);
  server->writeChain(
      stream, buf->clone(), false /* eof */, &writeChainDeliveryCb);
  server->writeBufMeta(stream, BufferMeta(1), false, &writeBufMetaDeliveryCb);
  server->registerDeliveryCallback(stream, 0, &firstByteDeliveryCb);
  server->registerDeliveryCallback(stream, 1, &lastByteDeliveryCb);
  server->registerDeliveryCallback(stream, 2, &unsentByteDeliveryCb);

  // writeChain, first, last byte callbacks triggered after delivery
  auto& conn = server->getConnectionState();
  folly::SocketAddress addr;
  conn.streamManager->addDeliverable(stream);
  conn.lossState.srtt = 100us;
  NetworkData networkData;
  auto streamState = conn.streamManager->getStream(stream);
  ASSERT_FALSE(streamState.hasError());
  streamState.value()->ackedIntervals.insert(0, 1);
  EXPECT_CALL(writeChainDeliveryCb, onDeliveryAck(stream, 0, 100us)).Times(1);
  EXPECT_CALL(writeBufMetaDeliveryCb, onDeliveryAck(stream, 1, 100us)).Times(1);
  EXPECT_CALL(firstByteDeliveryCb, onDeliveryAck(stream, 0, 100us)).Times(1);
  EXPECT_CALL(lastByteDeliveryCb, onDeliveryAck(stream, 1, 100us)).Times(1);
  server->onNetworkData(addr, std::move(networkData));
  Mock::VerifyAndClearExpectations(&writeChainDeliveryCb);
  Mock::VerifyAndClearExpectations(&writeBufMetaDeliveryCb);
  Mock::VerifyAndClearExpectations(&firstByteDeliveryCb);
  Mock::VerifyAndClearExpectations(&lastByteDeliveryCb);

  // try to set both offsets again
  // callbacks should be triggered immediately
  EXPECT_CALL(firstByteDeliveryCb, onDeliveryAck(stream, 0, _)).Times(1);
  EXPECT_CALL(lastByteDeliveryCb, onDeliveryAck(stream, 1, _)).Times(1);
  server->registerDeliveryCallback(stream, 0, &firstByteDeliveryCb);
  server->registerDeliveryCallback(stream, 1, &lastByteDeliveryCb);
  loopForWrites();
  Mock::VerifyAndClearExpectations(&firstByteDeliveryCb);
  Mock::VerifyAndClearExpectations(&lastByteDeliveryCb);

  // unsentByteDeliveryCb::onByteEvent will never get called
  // cancel gets called instead
  EXPECT_CALL(unsentByteDeliveryCb, onCanceled(stream, 2)).Times(1);
  server->close(std::nullopt);
  Mock::VerifyAndClearExpectations(&unsentByteDeliveryCb);
}

class QuicUnencryptedServerTransportTest : public QuicServerTransportTest {
 public:
  void setupConnection() override {}
};

TEST_F(QuicUnencryptedServerTransportTest, FirstPacketProcessedCallback) {
  getFakeHandshakeLayer()->allowZeroRttKeys();
  EXPECT_CALL(connSetupCallback, onFirstPeerPacketProcessed()).Times(1);
  recvClientHello();
  loopForWrites();
  AckBlocks acks;
  acks.insert(0);
  auto aead = getInitialCipher();
  auto headerCipher = getInitialHeaderCipher();
  EXPECT_CALL(connSetupCallback, onFirstPeerPacketProcessed()).Times(0);
  deliverData(packetToBufCleartext(
      createAckPacket(
          server->getNonConstConn(),
          clientNextInitialPacketNum,
          acks,
          PacketNumberSpace::Initial,
          aead.get()),
      *aead,
      *headerCipher,
      clientNextInitialPacketNum));
}

TEST_F(QuicUnencryptedServerTransportTest, TestUnencryptedStream) {
  auto data = IOBuf::copyBuffer("bad data");
  PacketNum nextPacket = clientNextInitialPacketNum++;
  StreamId streamId = 3;
  auto initialCipher = getInitialCipher();
  auto headerCipher = getInitialHeaderCipher();
  auto packetData = packetToBufCleartext(
      createStreamPacket(
          *clientConnectionId,
          *initialDestinationConnectionId,
          nextPacket,
          streamId,
          *data,
          initialCipher->getCipherOverhead(),
          0 /* largestAcked */,
          std::make_pair(LongHeader::Types::Initial, QuicVersion::MVFST)),
      *initialCipher,
      *headerCipher,
      nextPacket);
  EXPECT_THROW(deliverData(std::move(packetData)), std::runtime_error);
  EXPECT_EQ(server->getConn().streamManager->streamCount(), 0);
}

TEST_F(QuicUnencryptedServerTransportTest, TestUnencryptedAck) {
  auto qLogger = std::make_shared<FileQLogger>(VantagePoint::Server);
  server->getNonConstConn().qLogger = qLogger;
  AckBlocks acks = {{1, 2}};
  PacketNum nextPacketNum = clientNextInitialPacketNum++;
  LongHeader header(
      LongHeader::Types::Initial,
      *clientConnectionId,
      *initialDestinationConnectionId,
      nextPacketNum,
      QuicVersion::MVFST);
  RegularQuicPacketBuilder builder(
      kDefaultUDPSendPacketLen, std::move(header), 0 /* largestAcked */);
  ASSERT_FALSE(builder.encodePacketHeader().hasError());
  DCHECK(builder.canBuildPacket());
  WriteAckFrameState writeAckState = {.acks = acks};
  WriteAckFrameMetaData ackData = {
      .ackState = writeAckState,
      .ackDelay = 0us,
      .ackDelayExponent = static_cast<uint8_t>(kDefaultAckDelayExponent)};
  ASSERT_FALSE(writeAckFrame(ackData, builder).hasError());
  auto packet = packetToBufCleartext(
      std::move(builder).buildPacket(),
      *getInitialCipher(),
      *getInitialHeaderCipher(),
      nextPacketNum);
  EXPECT_THROW(deliverData(std::move(packet)), std::runtime_error);
  std::vector<int> indices =
      getQLogEventIndices(QLogEventType::PacketDrop, qLogger);
  EXPECT_EQ(indices.size(), 1);

  auto tmp = std::move(qLogger->logs[indices[0]]);
  auto event = dynamic_cast<QLogPacketDropEvent*>(tmp.get());
  EXPECT_EQ(event->packetSize, 45);
  EXPECT_EQ(event->dropReason, "DECRYPTION_ERROR_INITIAL");
}

TEST_F(QuicUnencryptedServerTransportTest, TestBadPacketProtectionLevel) {
  // Version negotiation has no protection level.
  auto packet = VersionNegotiationPacketBuilder(
                    *clientConnectionId /* src */,
                    getTestConnectionId(1) /* dest */,
                    {QuicVersion::MVFST})
                    .buildPacket();
  EXPECT_CALL(*quicStats_, onPacketDropped(_));
  deliverData(packet.second->clone());
}

TEST_F(QuicUnencryptedServerTransportTest, TestBadCleartextEncryption) {
  FizzCryptoFactory cryptoFactory;
  PacketNum nextPacket = clientNextInitialPacketNum++;
  auto aead =
      cryptoFactory
          .getServerInitialCipher(*clientConnectionId, QuicVersion::MVFST)
          .value();
  auto chloBuf = IOBuf::copyBuffer("CHLO");
  ChainedByteRangeHead chloRch(chloBuf);
  auto packetData = packetToBufCleartext(
      createInitialCryptoPacket(
          *clientConnectionId,
          *initialDestinationConnectionId,
          nextPacket,
          QuicVersion::MVFST,
          chloRch,
          *aead,
          0 /* largestAcked */),
      *aead,
      *getInitialHeaderCipher(),
      nextPacket);
  EXPECT_THROW(deliverData(std::move(packetData)), std::runtime_error);
  // If crypto data was processed, we would have generated some writes.
  EXPECT_NE(server->getConn().readCodec, nullptr);
  EXPECT_TRUE(server->getConn().cryptoState->initialStream.writeBuffer.empty());
  EXPECT_TRUE(server->getConn()
                  .cryptoState->initialStream.retransmissionBuffer.empty());
}

TEST_F(QuicUnencryptedServerTransportTest, TestPendingZeroRttData) {
  auto data = IOBuf::copyBuffer("bad data");
  size_t expectedPendingLen =
      server->getConn().transportSettings.maxPacketsToBuffer;
  for (size_t i = 0; i < expectedPendingLen + 10; ++i) {
    StreamId streamId = static_cast<StreamId>(i);
    auto packetData = packetToBuf(createStreamPacket(
        *clientConnectionId,
        server->getConn().serverConnectionId.value_or(getTestConnectionId(1)),
        clientNextAppDataPacketNum++,
        streamId,
        *data,
        0 /* cipherOverhead */,
        0 /* largestAcked */,
        std::make_pair(LongHeader::Types::ZeroRtt, QuicVersion::MVFST)));
    EXPECT_CALL(*quicStats_, onPacketDropped(_));
    deliverData(std::move(packetData));
  }
  EXPECT_EQ(server->getConn().streamManager->streamCount(), 0);
  EXPECT_EQ(server->getConn().pendingZeroRttData->size(), expectedPendingLen);

  server->getNonConstConn().pendingZeroRttData->clear();
  deliverData(IOBuf::create(0));
  EXPECT_TRUE(server->getConn().pendingZeroRttData->empty());
}

TEST_F(QuicUnencryptedServerTransportTest, TestPendingOneRttData) {
  recvClientHello();
  auto data = IOBuf::copyBuffer("bad data");
  size_t expectedPendingLen =
      server->getConn().transportSettings.maxPacketsToBuffer;
  for (size_t i = 0; i < expectedPendingLen + 10; ++i) {
    StreamId streamId = static_cast<StreamId>(i);
    auto packetData = packetToBuf(createStreamPacket(
        *clientConnectionId,
        *server->getConn().serverConnectionId,
        clientNextAppDataPacketNum++,
        streamId,
        *data,
        0 /* cipherOverhead */,
        0 /* largestAcked */));
    EXPECT_CALL(*quicStats_, onPacketDropped(_));
    deliverData(std::move(packetData));
  }
  EXPECT_EQ(server->getConn().streamManager->streamCount(), 0);
  EXPECT_EQ(server->getConn().pendingOneRttData->size(), expectedPendingLen);

  server->getNonConstConn().pendingOneRttData->clear();
  deliverData(IOBuf::create(0));
  EXPECT_TRUE(server->getConn().pendingOneRttData->empty());
}

TEST_F(
    QuicUnencryptedServerTransportTest,
    TestReceiveClientFinishedFromChangedPeerAddress) {
  auto qLogger = std::make_shared<FileQLogger>(VantagePoint::Server);
  server->getNonConstConn().qLogger = qLogger;
  recvClientHello();

  folly::SocketAddress newPeer("100.101.102.103", 23456);

  EXPECT_CALL(handshakeFinishedCallback, onHandshakeUnfinished());
  try {
    recvClientFinished(true, &newPeer);
  } catch (const std::runtime_error& ex) {
    EXPECT_EQ(std::string(ex.what()), "Invalid migration");
  }
  EXPECT_TRUE(server->getConn().localConnectionError);
  EXPECT_EQ(
      server->getConn().localConnectionError->message,
      "Migration not allowed during handshake");
  EXPECT_TRUE(server->isClosed());

  std::vector<int> indices =
      getQLogEventIndices(QLogEventType::PacketDrop, qLogger);
  EXPECT_EQ(indices.size(), 1);
  auto tmp = std::move(qLogger->logs[indices[0]]);
  auto event = dynamic_cast<QLogPacketDropEvent*>(tmp.get());
  EXPECT_EQ(event->packetSize, 44);
  EXPECT_EQ(
      event->dropReason,
      PacketDropReason(PacketDropReason::PEER_ADDRESS_CHANGE)._to_string());
}

TEST_F(
    QuicUnencryptedServerTransportTest,
    TestReceiveClientFinishedFromChangedPeerAddressNoClose) {
  auto qLogger = std::make_shared<FileQLogger>(VantagePoint::Server);
  server->getNonConstConn().qLogger = qLogger;
  server->getNonConstConn().transportSettings.closeIfMigrationDuringHandshake =
      false;
  recvClientHello();

  folly::SocketAddress newPeer("100.101.102.103", 23456);

  EXPECT_CALL(handshakeFinishedCallback, onHandshakeUnfinished());
  recvClientFinished(true, &newPeer);
  EXPECT_FALSE(server->getConn().localConnectionError);
  EXPECT_FALSE(server->isClosed());

  std::vector<int> indices =
      getQLogEventIndices(QLogEventType::PacketDrop, qLogger);
  EXPECT_EQ(indices.size(), 1);
  auto tmp = std::move(qLogger->logs[indices[0]]);
  auto event = dynamic_cast<QLogPacketDropEvent*>(tmp.get());
  EXPECT_EQ(event->packetSize, 44);
  EXPECT_EQ(
      event->dropReason,
      PacketDropReason(PacketDropReason::PEER_ADDRESS_CHANGE)._to_string());
}

TEST_F(
    QuicUnencryptedServerTransportTest,
    ReceiveHandshakePacketFromChangedPeerAddress) {
  server->getNonConstConn().transportSettings.disableMigration = false;

  recvClientHello();

  auto data = IOBuf::copyBuffer("bad data");
  folly::SocketAddress newPeer("100.101.102.103", 23456);

  EXPECT_CALL(handshakeFinishedCallback, onHandshakeUnfinished());
  try {
    recvClientFinished(true, &newPeer);
  } catch (const std::runtime_error& ex) {
    EXPECT_EQ(std::string(ex.what()), "Invalid migration");
  }
  EXPECT_TRUE(server->getConn().localConnectionError);
  EXPECT_EQ(
      server->getConn().localConnectionError->message,
      "Migration not allowed during handshake");
}

TEST_F(
    QuicUnencryptedServerTransportTest,
    ReceiveRetireConnIdFrameInZeroRttPacket) {
  server->getNonConstConn().transportSettings.disableMigration = false;
  fakeHandshake->allowZeroRttKeys();
  recvClientHello();

  // create 0-rtt packet with some stream data and a retire_conn_id frame
  LongHeader header(
      LongHeader::Types::ZeroRtt,
      *clientConnectionId,
      *initialDestinationConnectionId,
      clientNextAppDataPacketNum++,
      server->getConn().supportedVersions[0]);
  RegularQuicPacketBuilder builder(
      kDefaultUDPSendPacketLen, std::move(header), /*largestAckedPacketNum=*/0);
  RetireConnectionIdFrame retireConnIdFrame(0);
  ASSERT_FALSE(
      writeSimpleFrame(QuicSimpleFrame(retireConnIdFrame), builder).hasError());

  // add some data
  auto data = IOBuf::copyBuffer("hello!");
  auto res = *writeStreamFrameHeader(
      builder,
      /*id=*/4,
      /*offset=*/0,
      data->computeChainDataLength(),
      data->computeChainDataLength(),
      /*fin=*/true,
      /*skipLenHint=*/std::nullopt);
  ASSERT_TRUE(res.has_value());
  auto dataLen = *res;
  writeStreamFrameData(
      builder,
      data->clone(),
      std::min(static_cast<size_t>(dataLen), data->computeChainDataLength()));

  ASSERT_FALSE(builder.encodePacketHeader().hasError());
  builder.accountForCipherOverhead(0);

  auto packet = std::move(builder).buildPacket();
  EXPECT_THROW(deliverData(packetToBuf(packet), true), std::runtime_error);
  EXPECT_TRUE(server->getConn().localConnectionError);
}

TEST_F(
    QuicUnencryptedServerTransportTest,
    ReceivePathResponseFrameInZeroRttPacket) {
  server->getNonConstConn().transportSettings.disableMigration = false;
  fakeHandshake->allowZeroRttKeys();
  recvClientHello();

  // create 0-rtt packet with some stream data and a path response frame
  LongHeader header(
      LongHeader::Types::ZeroRtt,
      *clientConnectionId,
      *initialDestinationConnectionId,
      clientNextAppDataPacketNum++,
      server->getConn().supportedVersions[0]);
  RegularQuicPacketBuilder builder(
      kDefaultUDPSendPacketLen, std::move(header), /*largestAcked=*/0);
  ASSERT_FALSE(
      writeSimpleFrame(PathResponseFrame(0xaabbccddeeff), builder).hasError());

  // add some data
  auto data = IOBuf::copyBuffer("hello!");
  auto res = *writeStreamFrameHeader(
      builder,
      /*id=*/4,
      /*offset=*/0,
      data->computeChainDataLength(),
      data->computeChainDataLength(),
      /*eof=*/true,
      /*skipLenHint=*/std::nullopt);
  ASSERT_TRUE(res.has_value());
  auto dataLen = *res;
  writeStreamFrameData(
      builder,
      data->clone(),
      std::min(static_cast<size_t>(dataLen), data->computeChainDataLength()));

  ASSERT_FALSE(builder.encodePacketHeader().hasError());
  builder.accountForCipherOverhead(0);

  auto packet = std::move(builder).buildPacket();
  EXPECT_THROW(deliverData(packetToBuf(packet), true), std::runtime_error);
  EXPECT_TRUE(server->getConn().localConnectionError);
}

TEST_F(
    QuicUnencryptedServerTransportTest,
    ReceiveNewTokenFrameInZeroRttPacket) {
  server->getNonConstConn().transportSettings.disableMigration = false;
  fakeHandshake->allowZeroRttKeys();
  recvClientHello();

  // create 0-rtt packet with some stream data and a new token frame
  LongHeader header(
      LongHeader::Types::ZeroRtt,
      *clientConnectionId,
      *initialDestinationConnectionId,
      clientNextAppDataPacketNum++,
      server->getConn().supportedVersions[0]);
  RegularQuicPacketBuilder builder(
      kDefaultUDPSendPacketLen, std::move(header), /*largestAcked=*/0);
  ASSERT_FALSE(
      writeSimpleFrame(NewTokenFrame(IOBuf::copyBuffer("token!")), builder)
          .hasError());

  // add some data
  auto data = IOBuf::copyBuffer("hello!");
  auto res = *writeStreamFrameHeader(
      builder,
      /*id=*/4,
      /*offset=*/0,
      data->computeChainDataLength(),
      data->computeChainDataLength(),
      /*eof=*/true,
      /*skipLenHint=*/std::nullopt);
  ASSERT_TRUE(res.has_value());
  auto dataLen = *res;
  writeStreamFrameData(
      builder,
      data->clone(),
      std::min(static_cast<size_t>(dataLen), data->computeChainDataLength()));

  ASSERT_FALSE(builder.encodePacketHeader().hasError());
  builder.accountForCipherOverhead(0);

  auto packet = std::move(builder).buildPacket();
  EXPECT_THROW(deliverData(packetToBuf(packet), true), std::runtime_error);
  EXPECT_TRUE(server->getConn().localConnectionError);
}

TEST_F(
    QuicUnencryptedServerTransportTest,
    ReceiveZeroRttPacketFromChangedPeerAddress) {
  server->getNonConstConn().transportSettings.disableMigration = false;
  fakeHandshake->allowZeroRttKeys();

  recvClientHello();

  auto data = IOBuf::copyBuffer("bad data");
  StreamId streamId = 2;
  auto packetData = packetToBuf(createStreamPacket(
      *clientConnectionId,
      *server->getConn().serverConnectionId,
      clientNextAppDataPacketNum++,
      streamId,
      *data,
      0 /* cipherOverhead */,
      0 /* largestAcked */,
      std::make_pair(
          LongHeader::Types::ZeroRtt, server->getConn().supportedVersions[0]),
      false));
  folly::SocketAddress newPeer("100.101.102.103", 23456);
  try {
    deliverData(std::move(packetData), true, &newPeer);
  } catch (const std::runtime_error& ex) {
    EXPECT_EQ(std::string(ex.what()), "Invalid migration");
  }
  EXPECT_TRUE(server->getConn().localConnectionError);
  EXPECT_EQ(
      server->getConn().localConnectionError->message,
      "Migration not allowed during handshake");
}

TEST_F(
    QuicUnencryptedServerTransportTest,
    TestNoCipherProcessPendingOneRttDataFromChangedAddress) {
  recvClientHello();

  auto data = IOBuf::copyBuffer("bad data");
  StreamId streamId = 2;
  auto packetData = packetToBuf(createStreamPacket(
      *clientConnectionId,
      *server->getConn().serverConnectionId,
      clientNextAppDataPacketNum++,
      streamId,
      *data,
      0 /* cipherOverhead */,
      0 /* largestAcked */));
  folly::SocketAddress newPeer("100.101.102.103", 23456);
  deliverData(std::move(packetData), true, &newPeer);
  EXPECT_EQ(server->getConn().streamManager->streamCount(), 0);
  EXPECT_EQ(server->getConn().pendingOneRttData->size(), 1);

  try {
    recvClientFinished();
  } catch (const std::runtime_error& ex) {
    EXPECT_EQ(std::string(ex.what()), "Invalid migration");
  }
  EXPECT_TRUE(server->getConn().localConnectionError);
  EXPECT_EQ(
      server->getConn().localConnectionError->message, "Migration disabled");
  EXPECT_EQ(server->getConn().streamManager->streamCount(), 0);
  EXPECT_EQ(server->getConn().pendingZeroRttData, nullptr);
  EXPECT_EQ(server->getConn().pendingOneRttData, nullptr);
}

class QuicServerTransportSendAckOnlyInitialTest
    : public QuicUnencryptedServerTransportTest,
      public testing::WithParamInterface<bool> {};

TEST_P(
    QuicServerTransportSendAckOnlyInitialTest,
    TestSkipAckOnlyCryptoInitial) {
  auto transportSettings = server->getTransportSettings();
  transportSettings.sendAckOnlyInitial = GetParam();
  server->setTransportSettings(transportSettings);
  // start at some random packet number that isn't zero
  clientNextInitialPacketNum = folly::Random::rand32(1, 100);

  // bypass doHandshake() in fakeServerHandshake by sending something other than
  // "CHLO"
  recvClientHello(true, QuicVersion::MVFST, "hello :)");

  // we expect nothing to be written as we're skipping the initial ack-only
  // packet
  EXPECT_EQ(serverWrites.size(), (size_t)transportSettings.sendAckOnlyInitial);
}

TEST_F(QuicUnencryptedServerTransportTest, TestNoAckOnlyCryptoInitial) {
  recvClientHello();

  EXPECT_GE(serverWrites.size(), 1);

  AckStates ackStates;

  auto clientCodec = makeClientEncryptedCodec(true);
  for (auto& write : serverWrites) {
    auto packetQueue = bufToQueue(write->clone());
    auto result = clientCodec->parsePacket(packetQueue, ackStates);
    auto& regularPacket = *result.regularPacket();
    ProtectionType protectionType = regularPacket.header.getProtectionType();
    bool handshakePacket = protectionType == ProtectionType::Initial ||
        protectionType == ProtectionType::Handshake;
    EXPECT_GE(regularPacket.frames.size(), 1);
    bool hasCryptoFrame = false;
    bool hasAckFrame = false;
    for (auto& frame : regularPacket.frames) {
      hasCryptoFrame |= frame.asReadCryptoFrame() != nullptr;
      hasAckFrame |= frame.asReadAckFrame() != nullptr;
    }

    // The packet sent by the server shouldn't be a pure ack (i.e. contains some
    // crypto data as well)
    if (handshakePacket) {
      EXPECT_TRUE(hasCryptoFrame);
      EXPECT_TRUE(hasAckFrame);
    }
  }
}

INSTANTIATE_TEST_SUITE_P(
    QuicServerTransportSendAckOnlyInitialTests,
    QuicServerTransportSendAckOnlyInitialTest,
    Bool());

TEST_F(QuicUnencryptedServerTransportTest, TestDuplicateCryptoInitialLogging) {
  auto transportSettings = server->getTransportSettings();
  server->setTransportSettings(transportSettings);

  recvClientHello();
  recvClientHello();
  recvClientHello();

  EXPECT_GE(serverWrites.size(), 1);
  EXPECT_EQ(getConn().initialPacketsReceived, 3);
  EXPECT_EQ(getConn().uniqueInitialCryptoFramesReceived, 1);
}

TEST_F(
    QuicUnencryptedServerTransportTest,
    TestHandshakeNotWritableBytesLimited) {
  /**
   * Set the WritableBytes limit to 5x (~ 5 * 1200 = 6,000). This will be enough
   * for the handshake to fit (1200 initial + 3000 handshake = 4,200 < 6,000).
   */
  auto transportSettings = server->getTransportSettings();
  transportSettings.limitedCwndInMss = 5;
  transportSettings.enableWritableBytesLimit = true;
  server->setTransportSettings(transportSettings);
  EXPECT_CALL(*quicStats_, onConnectionWritableBytesLimited()).Times(0);

  recvClientHello(true, QuicVersion::MVFST, "CHLO_CERT");

  EXPECT_GE(serverWrites.size(), 3);

  AckStates ackStates;

  auto clientCodec = makeClientEncryptedCodec(true);
  bool hasCryptoInitialFrame = false;
  bool hasCryptoHandshakeFrame = false;
  bool hasAckFrame = false;

  /**
   * Verify that we've written some cypto frames (initial, handshake packet
   * spaces) and some acks.
   */
  for (auto& write : serverWrites) {
    auto packetQueue = bufToQueue(write->clone());
    auto result = clientCodec->parsePacket(packetQueue, ackStates);
    auto& regularPacket = *result.regularPacket();
    // EXPECT_TRUE(regularPacket);
    ProtectionType protectionType = regularPacket.header.getProtectionType();
    EXPECT_GE(regularPacket.frames.size(), 1);
    bool hasCryptoFrame = false;
    for (auto& frame : regularPacket.frames) {
      hasCryptoFrame |= frame.asReadCryptoFrame() != nullptr;
      hasAckFrame |= frame.asReadAckFrame() != nullptr;
    }

    hasCryptoInitialFrame |=
        (protectionType == ProtectionType::Initial && hasCryptoFrame);
    hasCryptoHandshakeFrame |=
        (protectionType == ProtectionType::Handshake && hasCryptoFrame);
  }

  EXPECT_TRUE(hasCryptoInitialFrame);
  EXPECT_TRUE(hasCryptoHandshakeFrame);
  // skipping ack-only initial should not kick in here since we also have crypto
  // data to write.
  EXPECT_TRUE(hasAckFrame);
}

TEST_F(
    QuicUnencryptedServerTransportTest,
    TestHandshakeWritableBytesLimitedWithCFinNewToken) {
  /**
   * Exact same test case as above, but let's make the transport assume that the
   * address was verified (we received a valid new token). This should bypass
   * the writableBytesLimit and proceed as usual.
   */
  EXPECT_CALL(*quicStats_, onConnectionWritableBytesLimited())
      .Times(AtLeast(0));
  /**
   * Set the WritableBytes limit to 3x (~ 3 * 1200 = 3,600). This will not be
   * enough for the handshake to fit (1200 initial + 4000 handshake = 5,200 >
   * 3,600), however the valid new token should bypass the limit and not be
   * blocked.
   */
  auto transportSettings = server->getTransportSettings();
  transportSettings.limitedCwndInMss = 3;
  transportSettings.enableWritableBytesLimit = true;
  server->setTransportSettings(transportSettings);

  // make the server think we've received a valid new token
  server->verifiedClientAddress();

  recvClientHello(true, QuicVersion::MVFST, "CHLO_CERT");

  EXPECT_GE(serverWrites.size(), 3);

  AckStates ackStates;
}

TEST_F(
    QuicUnencryptedServerTransportTest,
    TestHandshakeWritableBytesLimitedWithCFin) {
  EXPECT_CALL(*quicStats_, onConnectionWritableBytesLimited())
      .Times(AtLeast(1));
  /**
   * Set the WritableBytes limit to 3x (~ 3 * 1200 = 3,600). This will not be
   * enough for the handshake to fit (1200 initial + 4000 handshake = 5,200 >
   * 3,600). We expect to be WritableBytes limited. After receiving an ack/cfin
   * from the client, the limit should increase and we're now unblocked.
   */
  auto transportSettings = server->getTransportSettings();
  transportSettings.limitedCwndInMss = 3;
  transportSettings.enableWritableBytesLimit = true;
  server->setTransportSettings(transportSettings);

  recvClientHello(true, QuicVersion::MVFST, "CHLO_CERT");

  // basically the maximum we can write is three packets before we hit the limit
  EXPECT_EQ(serverWrites.size(), 3);

  AckStates ackStates;

  auto clientCodec = makeClientEncryptedCodec(true);
  bool hasCryptoInitialFrame, hasCryptoHandshakeFrame, hasAckFrame;
  hasCryptoInitialFrame = hasCryptoHandshakeFrame = hasAckFrame = false;

  for (auto& write : serverWrites) {
    auto packetQueue = bufToQueue(write->clone());
    auto result = clientCodec->parsePacket(packetQueue, ackStates);
    auto& regularPacket = *result.regularPacket();
    // EXPECT_TRUE(regularPacket);
    ProtectionType protectionType = regularPacket.header.getProtectionType();
    EXPECT_GE(regularPacket.frames.size(), 1);
    bool hasCryptoFrame = false;
    for (auto& frame : regularPacket.frames) {
      hasCryptoFrame |= frame.asReadCryptoFrame() != nullptr;
      hasAckFrame |= frame.asReadAckFrame() != nullptr;
    }

    hasCryptoInitialFrame |=
        (protectionType == ProtectionType::Initial && hasCryptoFrame);
    hasCryptoHandshakeFrame |=
        (protectionType == ProtectionType::Handshake && hasCryptoFrame);
  }

  EXPECT_TRUE(hasCryptoInitialFrame);
  EXPECT_TRUE(hasCryptoHandshakeFrame);
  EXPECT_TRUE(hasAckFrame);
  /**
   * Let's now send an ack/cfin to the server which will unblock and let us
   * finish the handshake. The packets written by the server at this point are
   * expected to have crypto data and acks only in the handshake pn space, not
   * initial.
   */
  EXPECT_CALL(*quicStats_, onConnectionWritableBytesLimited()).Times(0);
  serverWrites.clear();
  recvClientFinished();
  EXPECT_TRUE(server->getConn().isClientAddrVerified);
  EXPECT_FALSE(server->getConn().writableBytesLimit);
  EXPECT_GT(serverWrites.size(), 0);

  hasCryptoInitialFrame = hasCryptoHandshakeFrame = hasAckFrame = false;

  for (auto& write : serverWrites) {
    auto packetQueue = bufToQueue(write->clone());
    auto result = clientCodec->parsePacket(packetQueue, ackStates);
    auto& regularPacket = *result.regularPacket();
    ProtectionType protectionType = regularPacket.header.getProtectionType();
    EXPECT_GE(regularPacket.frames.size(), 1);
    bool hasCryptoFrame = false;
    for (auto& frame : regularPacket.frames) {
      hasCryptoFrame |= frame.asReadCryptoFrame() != nullptr;
      hasAckFrame |= frame.asReadAckFrame() != nullptr;
    }

    hasCryptoHandshakeFrame |=
        (protectionType == ProtectionType::Handshake && hasCryptoFrame);
  }

  // We don't expect crypto frame in initial pnspace since we're done
  EXPECT_FALSE(hasCryptoInitialFrame);
  EXPECT_TRUE(hasCryptoHandshakeFrame);
  EXPECT_TRUE(hasAckFrame);
}

TEST_F(
    QuicUnencryptedServerTransportTest,
    TestHandshakeWritableBytesLimitedPartialAck) {
  /**
   * Set the WritableBytes limit to 3x (~ 3 * 1200 = 3,600). This will not be
   * enough for the handshake to fit (1200 initial + 4000 handshake = 5,200 >
   * 3,600). We expect to be WritableBytes limited. After receiving an ack
   * from the client acking only the initial crypto data, the pto should fire
   * immediately to resend the handshake crypto data.
   */
  auto transportSettings = server->getTransportSettings();
  transportSettings.limitedCwndInMss = 3;
  transportSettings.enableWritableBytesLimit = true;
  server->setTransportSettings(transportSettings);
  EXPECT_CALL(*quicStats_, onConnectionWritableBytesLimited())
      .Times(AtLeast(1));

  recvClientHello(true, QuicVersion::MVFST, "CHLO_CERT");

  // basically the maximum we can write is three packets before we hit the limit
  EXPECT_EQ(serverWrites.size(), 3);

  AckStates ackStates;

  auto clientCodec = makeClientEncryptedCodec(true);

  for (auto& write : serverWrites) {
    auto packetQueue = bufToQueue(write->clone());
    auto result = clientCodec->parsePacket(packetQueue, ackStates);
    EXPECT_TRUE(result.regularPacket());
  }

  /**
   * Let's now send an partial ack to the server, acking only the initial pn
   * space, which will unblock and let us finish the handshake. Since we've
   * already sent the handshake data, we expect a pto to fire immediately and
   */

  serverWrites.clear();
  auto nextPacketNum = clientNextInitialPacketNum++;
  auto aead = getInitialCipher();
  auto headerCipher = getInitialHeaderCipher();
  AckBlocks acks;
  auto start = getFirstOutstandingPacket(
                   server->getNonConstConn(), PacketNumberSpace::Initial)
                   ->packet.header.getPacketSequenceNum();
  auto end = getLastOutstandingPacket(
                 server->getNonConstConn(), PacketNumberSpace::Initial)
                 ->packet.header.getPacketSequenceNum();
  acks.insert(start, end);
  EXPECT_CALL(*quicStats_, onConnectionWritableBytesLimited()).Times(0);
  deliverData(packetToBufCleartext(
      createAckPacket(
          server->getNonConstConn(),
          nextPacketNum,
          acks,
          PacketNumberSpace::Initial,
          aead.get()),
      *aead,
      *headerCipher,
      nextPacketNum));

  // The server is unblocked and should now be able to finish the handshake
  EXPECT_GE(serverWrites.size(), 1);
}

TEST_F(QuicUnencryptedServerTransportTest, TestCorruptedDstCidInitialTest) {
  auto chlo = folly::IOBuf::copyBuffer("CHLO");
  auto nextPacketNum = clientNextInitialPacketNum++;

  /*
   * generate ciphers based off of initialDestinationConnectionId and include a
   * different DstCid in the packet header.
   */
  auto aead = getInitialCipher();
  auto headerCipher = getInitialHeaderCipher();
  auto corruptedDstCid = getTestConnectionId(1);

  EXPECT_TRUE(initialDestinationConnectionId);
  EXPECT_TRUE(clientConnectionId);
  EXPECT_NE(*initialDestinationConnectionId, corruptedDstCid);

  ChainedByteRangeHead chloRch(chlo);
  auto initialPacket = packetToBufCleartext(
      createInitialCryptoPacket(
          *clientConnectionId,
          corruptedDstCid,
          nextPacketNum,
          QuicVersion::MVFST,
          chloRch,
          *aead,
          0 /* largestAcked */),
      *aead,
      *headerCipher,
      nextPacketNum);

  EXPECT_CALL(routingCallback, onConnectionUnbound(_, _, _)).Times(1);

  EXPECT_THROW(deliverData(initialPacket->clone(), true), std::runtime_error);
}

TEST_F(QuicUnencryptedServerTransportTest, TestWriteHandshakeAndZeroRtt) {
  getFakeHandshakeLayer()->allowZeroRttKeys();
  // This should trigger derivation of keys.
  recvClientHello();

  auto streamId = server->createBidirectionalStream().value();
  server->writeChain(streamId, IOBuf::copyBuffer("hello"), true);
  loopForWrites();
  auto clientCodec = makeClientEncryptedCodec(true);

  size_t numCryptoFrames = 0;
  size_t numNonCryptoFrames = 0;
  EXPECT_GT(serverWrites.size(), 1);
  AckStates ackStates;
  for (auto& write : serverWrites) {
    auto packetQueue = bufToQueue(write->clone());
    auto result = clientCodec->parsePacket(packetQueue, ackStates);
    auto& regularPacket = *result.regularPacket();
    ProtectionType protectionType = regularPacket.header.getProtectionType();
    bool handshakePacket = protectionType == ProtectionType::Initial ||
        protectionType == ProtectionType::Handshake;
    EXPECT_GE(regularPacket.frames.size(), 1);
    bool hasCryptoFrame = false;
    bool hasNonCryptoStream = false;
    for (auto& frame : regularPacket.frames) {
      hasCryptoFrame |= frame.asReadCryptoFrame() != nullptr;
      hasNonCryptoStream |= frame.asReadStreamFrame() != nullptr;
    }
    if (hasCryptoFrame) {
      EXPECT_TRUE(handshakePacket);
      numCryptoFrames++;
    }
    if (hasNonCryptoStream) {
      EXPECT_FALSE(handshakePacket);
      numNonCryptoFrames++;
    }
  }
  EXPECT_GE(numCryptoFrames, 1);
  EXPECT_GE(numNonCryptoFrames, 1);
}

TEST_F(QuicUnencryptedServerTransportTest, TestEncryptedDataBeforeCFIN) {
  getFakeHandshakeLayer()->allowZeroRttKeys();
  // This should trigger derivation of keys.
  recvClientHello();

  StreamId streamId = 4;
  recvEncryptedStream(streamId, *IOBuf::copyBuffer("hello"));

  auto streamResult =
      server->getNonConstConn().streamManager->getStream(streamId);
  ASSERT_FALSE(streamResult.hasError());
  auto stream = streamResult.value();
  ASSERT_TRUE(stream->readBuffer.empty());
}

TEST_F(
    QuicUnencryptedServerTransportTest,
    TestClearInFlightBytesLimitationAfterCFIN) {
  auto qLogger = std::make_shared<FileQLogger>(VantagePoint::Server);
  server->getNonConstConn().qLogger = qLogger;
  server->getNonConstConn().transportSettings.zeroRttSourceTokenMatchingPolicy =
      ZeroRttSourceTokenMatchingPolicy::LIMIT_IF_NO_EXACT_MATCH;
  getFakeHandshakeLayer()->allowZeroRttKeys();
  auto originalUdpSize = server->getConn().udpSendPacketLen;

  setupClientReadCodec();

  recvClientHello();
  ASSERT_TRUE(server->getNonConstConn().writableBytesLimit.has_value());
  EXPECT_EQ(
      *server->getNonConstConn().writableBytesLimit,
      server->getConn().transportSettings.limitedCwndInMss * originalUdpSize);

  EXPECT_CALL(handshakeFinishedCallback, onHandshakeFinished());
  recvClientFinished();
  loopForWrites();
  EXPECT_EQ(server->getConn().writableBytesLimit, std::nullopt);

  std::vector<int> indices =
      getQLogEventIndices(QLogEventType::TransportStateUpdate, qLogger);
  EXPECT_EQ(indices.size(), 5);
  std::array<::std::string, 5> updateArray = {
      kDerivedZeroRttReadCipher,
      kDerivedOneRttWriteCipher,
      kTransportReady,
      kDerivedOneRttReadCipher,
      kWriteNst};
  for (int i = 0; i < 5; ++i) {
    auto tmp = std::move(qLogger->logs[indices[i]]);
    auto event = dynamic_cast<QLogTransportStateUpdateEvent*>(tmp.get());
    EXPECT_EQ(event->update, updateArray[i]);
  }
}

TEST_F(QuicUnencryptedServerTransportTest, TestSendHandshakeDone) {
  EXPECT_CALL(*quicStats_, onConnectionWritableBytesLimited()).Times(0);
  EXPECT_CALL(handshakeFinishedCallback, onHandshakeFinished());
  getFakeHandshakeLayer()->allowZeroRttKeys();
  setupClientReadCodec();
  recvClientHello(true, QuicVersion::MVFST);
  recvClientFinished(true, nullptr, QuicVersion::MVFST);
  auto& packets = server->getConn().outstandings.packets;
  ASSERT_FALSE(packets.empty());
  int numHandshakeDone = 0;
  for (auto& p : packets) {
    for (auto& f : p.packet.frames) {
      auto s = f.asQuicSimpleFrame();
      if (s) {
        if (s->asHandshakeDoneFrame()) {
          numHandshakeDone++;
        }
      }
    }
  }
  EXPECT_EQ(numHandshakeDone, 1);
}

/**
 * Returns the number of new token frames (should either be zero or one).
 */
std::pair<int, std::vector<const NewTokenFrame*>> getNewTokenFrame(
    const std::deque<OutstandingPacketWrapper>& packets) {
  int numNewTokens = 0;
  std::vector<const NewTokenFrame*> frames;

  for (auto& p : packets) {
    for (auto& f : p.packet.frames) {
      auto s = f.asQuicSimpleFrame();
      if (s && s->asNewTokenFrame()) {
        numNewTokens++;
        frames.push_back(s->asNewTokenFrame());
      }
    }
  }

  return std::make_pair(numNewTokens, std::move(frames));
}

TEST_F(QuicUnencryptedServerTransportTest, TestSendHandshakeDoneNewTokenFrame) {
  EXPECT_CALL(*quicStats_, onConnectionWritableBytesLimited()).Times(0);
  std::array<uint8_t, kRetryTokenSecretLength> secret;
  folly::Random::secureRandom(secret.data(), secret.size());
  server->getNonConstConn().transportSettings.retryTokenSecret = secret;

  getFakeHandshakeLayer()->allowZeroRttKeys();
  setupClientReadCodec();
  recvClientHello(true, QuicVersion::MVFST);

  /**
   * Receiving just the chlo should not issue a NewTokenFrame.
   */
  EXPECT_EQ(getNewTokenFrame(server->getConn().outstandings.packets).first, 0);

  EXPECT_CALL(*quicStats_, onNewTokenIssued());
  recvClientFinished(true, nullptr, QuicVersion::MVFST);

  /**
   * After the handshake is complete, we expect only one NewTokenFrame to be
   * issued.
   */
  auto serverWriteNewTokenFrame =
      getNewTokenFrame(server->getConn().outstandings.packets);
  EXPECT_EQ(serverWriteNewTokenFrame.first, 1);

  // Verify that the client parses the same token as what was written
  auto clientParsedFrame = getFrameIfPresent(
      serverWrites,
      *makeClientEncryptedCodec(true),
      QuicFrame::Type::ReadNewTokenFrame);

  EXPECT_TRUE(
      clientParsedFrame.has_value() &&
      clientParsedFrame->asReadNewTokenFrame());

  auto clientReadNewTokenFrame = clientParsedFrame->asReadNewTokenFrame();

  auto serverToken =
      serverWriteNewTokenFrame.second[0]->token->to<std::string>();
  auto clientToken = clientReadNewTokenFrame->token->to<std::string>();

  EXPECT_EQ(clientToken, serverToken);
  loopForWrites();

  /**
   * Receiving client data post-handshake should not issue any NewTokenFrames.
   */

  // Remove any packets that might have been queued.
  server->getNonConstConn().outstandings.reset();

  StreamId streamId = server->createBidirectionalStream().value();
  auto data = IOBuf::copyBuffer("data");
  auto packet = packetToBuf(createStreamPacket(
      *clientConnectionId,
      *server->getConn().serverConnectionId,
      clientNextAppDataPacketNum++,
      streamId,
      *data,
      0 /* cipherOverhead */,
      0 /* largestAcked */));
  deliverData(std::move(packet));

  EXPECT_EQ(server->getConn().streamManager->streamCount(), 1);
  EXPECT_EQ(getNewTokenFrame(server->getConn().outstandings.packets).first, 0);
}

TEST_F(
    QuicUnencryptedServerTransportTest,
    IncreaseLimitAfterReceivingNewPacket) {
  auto qLogger = std::make_shared<FileQLogger>(VantagePoint::Server);
  server->getNonConstConn().qLogger = qLogger;
  getFakeHandshakeLayer()->allowZeroRttKeys();
  server->getNonConstConn().transportSettings.zeroRttSourceTokenMatchingPolicy =
      ZeroRttSourceTokenMatchingPolicy::LIMIT_IF_NO_EXACT_MATCH;

  auto originalUdpSize = server->getConn().udpSendPacketLen;
  setupClientReadCodec();

  recvClientHello();
  EXPECT_EQ(
      *server->getNonConstConn().writableBytesLimit,
      server->getConn().transportSettings.limitedCwndInMss * originalUdpSize);

  recvClientHello();

  // in tests the udp packet length changes
  auto expectedLen =
      server->getConn().transportSettings.limitedCwndInMss * originalUdpSize +
      server->getConn().transportSettings.limitedCwndInMss *
          server->getConn().udpSendPacketLen;
  EXPECT_NE(originalUdpSize, server->getConn().udpSendPacketLen);
  EXPECT_EQ(*server->getNonConstConn().writableBytesLimit, expectedLen);
  std::vector<int> indices =
      getQLogEventIndices(QLogEventType::TransportStateUpdate, qLogger);
  EXPECT_EQ(indices.size(), 3);
  std::array<::std::string, 3> updateArray = {
      kDerivedZeroRttReadCipher, kDerivedOneRttWriteCipher, kTransportReady};
  for (int i = 0; i < 3; ++i) {
    auto tmp = std::move(qLogger->logs[indices[i]]);
    auto event = dynamic_cast<QLogTransportStateUpdateEvent*>(tmp.get());
    EXPECT_EQ(event->update, updateArray[i]);
  }
}

TEST_F(QuicUnencryptedServerTransportTest, MaxReceivePacketSizeTooLarge) {
  getFakeHandshakeLayer()->allowZeroRttKeys();
  fakeHandshake->maxRecvPacketSize = 4096;
  setupClientReadCodec();
  recvClientHello();
  EXPECT_EQ(server->getConn().udpSendPacketLen, kDefaultMaxUDPPayload);
}

TEST_F(QuicUnencryptedServerTransportTest, TestGarbageData) {
  auto qLogger = std::make_shared<FileQLogger>(VantagePoint::Server);
  server->getNonConstConn().qLogger = qLogger;

  auto data = IOBuf::copyBuffer("bad data");
  PacketNum nextPacket = clientNextInitialPacketNum++;
  auto aead = getInitialCipher();
  auto headerCipher = getInitialHeaderCipher();
  auto chloBuf = IOBuf::copyBuffer("CHLO");
  ChainedByteRangeHead chloRch(chloBuf);
  auto packet = createCryptoPacket(
      *clientConnectionId,
      *initialDestinationConnectionId,
      nextPacket,
      QuicVersion::MVFST,
      ProtectionType::Initial,
      chloRch,
      *aead,
      0 /* largestAcked */);
  auto packetData =
      packetToBufCleartext(packet, *aead, *headerCipher, nextPacket);
  packetData->appendToChain(IOBuf::copyBuffer("garbage in"));
  deliverData(std::move(packetData));
  EXPECT_NE(server->getConn().readCodec, nullptr);
  EXPECT_NE(server->getConn().initialWriteCipher, nullptr);

  std::vector<int> indices =
      getQLogEventIndices(QLogEventType::PacketBuffered, qLogger);
  EXPECT_EQ(indices.size(), 1);
  auto tmp = std::move(qLogger->logs[indices[0]]);
  auto event = dynamic_cast<QLogPacketBufferedEvent*>(tmp.get());
  EXPECT_EQ(event->protectionType, ProtectionType::KeyPhaseZero);
  EXPECT_EQ(event->packetSize, 10);
}

BufPtr getHandshakePacketWithFrame(
    QuicWriteFrame frame,
    ConnectionId connId,
    Aead& clientWriteCipher,
    PacketNumberCipher& headerCipher) {
  PacketNum clientPacketNum = folly::Random::rand32();
  LongHeader header(
      LongHeader::Types::Handshake,
      connId,
      connId,
      clientPacketNum,
      QuicVersion::MVFST);
  RegularQuicPacketBuilder builder(
      kDefaultUDPSendPacketLen,
      std::move(header),
      clientPacketNum / 2 /* largestAcked */);
  CHECK(!builder.encodePacketHeader().hasError());
  builder.accountForCipherOverhead(clientWriteCipher.getCipherOverhead());
  CHECK(!writeFrame(std::move(frame), builder).hasError());
  return packetToBufCleartext(
      std::move(builder).buildPacket(),
      clientWriteCipher,
      headerCipher,
      clientPacketNum);
}

TEST_F(QuicUnencryptedServerTransportTest, TestNotAllowedInUnencryptedPacket) {
  // This should trigger derivation of keys.
  recvClientHello();

  StreamId streamId = 4;
  auto data = IOBuf::copyBuffer("data");

  EXPECT_THROW(
      deliverData(getHandshakePacketWithFrame(
          MaxStreamDataFrame(streamId, 100),
          *clientConnectionId,
          *getInitialCipher(),
          *getInitialHeaderCipher())),
      std::runtime_error);
  EXPECT_TRUE(server->error());
}

TEST_F(QuicUnencryptedServerTransportTest, TestCloseWhileAsyncPending) {
  folly::EventBase testLooper;
  setupClientReadCodec();
  getFakeHandshakeLayer()->initialize(&testLooper, server.get());

  recvClientHello();
  testLooper.loop();

  // Make sure the test looper worked.
  IOBufEqualTo eq;
  EXPECT_TRUE(eq(getCryptoStreamData(), IOBuf::copyBuffer("SHLO")));

  EXPECT_CALL(handshakeFinishedCallback, onHandshakeUnfinished());
  recvClientFinished();

  server->close(QuicError(
      QuicErrorCode(GenericApplicationErrorCode::UNKNOWN),
      std::string("hello")));
  EXPECT_TRUE(server->isClosed());
  testLooper.loop();

  EXPECT_EQ(server->getConn().oneRttWriteCipher, nullptr);

  StreamId streamId = 4;
  auto data = IOBuf::copyBuffer("data");

  EXPECT_THROW(
      deliverData(getHandshakePacketWithFrame(
          MaxStreamDataFrame(streamId, 100),
          *clientConnectionId,
          *getInitialCipher(),
          *getInitialHeaderCipher())),
      std::runtime_error);
}

struct FizzHandshakeParam {
  FizzHandshakeParam(bool argCHLOSync, bool argCFINSync, bool argAcceptZeroRtt)
      : chloSync(argCHLOSync),
        cfinSync(argCFINSync),
        acceptZeroRtt(argAcceptZeroRtt) {}

  bool chloSync;
  bool cfinSync;
  bool acceptZeroRtt;
};

class QuicServerTransportPendingDataTest
    : public QuicUnencryptedServerTransportTest,
      public WithParamInterface<FizzHandshakeParam> {
 public:
  ~QuicServerTransportPendingDataTest() override {
    loopForWrites();
  }

  void initializeServerHandshake() override {
    fakeHandshake = new FakeServerHandshake(
        server->getNonConstConn(),
        FizzServerQuicHandshakeContext::Builder().build(),
        GetParam().chloSync,
        GetParam().cfinSync);
    ON_CALL(*fakeHandshake, writeNewSessionTicket)
        .WillByDefault(testing::Return(folly::unit));
    if (GetParam().acceptZeroRtt) {
      fakeHandshake->allowZeroRttKeys();
    }
  }
};

INSTANTIATE_TEST_SUITE_P(
    QuicServerTransportPendingDataTests,
    QuicServerTransportPendingDataTest,
    Values(
        FizzHandshakeParam(false, false, false),
        FizzHandshakeParam(false, false, true),
        FizzHandshakeParam(false, true, false),
        FizzHandshakeParam(false, true, true),
        FizzHandshakeParam(true, false, false),
        FizzHandshakeParam(true, false, true),
        FizzHandshakeParam(true, true, false),
        FizzHandshakeParam(true, true, true)));

TEST_P(
    QuicServerTransportPendingDataTest,
    TestNoCipherProcessPendingZeroRttData) {
  server->getNonConstConn().qLogger =
      std::make_shared<quic::FileQLogger>(VantagePoint::Server);
  recvClientHello(false);
  auto data = IOBuf::copyBuffer("bad data");
  StreamId streamId = 2;
  // Write packet with zero rtt keys
  auto packetData = packetToBuf(createStreamPacket(
      *clientConnectionId,
      *server->getConn().serverConnectionId,
      clientNextAppDataPacketNum++,
      streamId,
      *data,
      0 /* cipherOverhead */,
      0 /* largestAcked */,
      std::make_pair(
          LongHeader::Types::ZeroRtt, server->getConn().supportedVersions[0]),
      false));
  deliverData(std::move(packetData), false);
  if (GetParam().acceptZeroRtt) {
    if (!GetParam().chloSync) {
      EXPECT_EQ(server->getConn().streamManager->streamCount(), 0);
      EXPECT_EQ(server->getConn().pendingZeroRttData->size(), 1);
      loopForWrites();
    }
    EXPECT_EQ(server->getConn().streamManager->streamCount(), 1);
    EXPECT_EQ(server->getConn().pendingZeroRttData, nullptr);
  } else {
    EXPECT_EQ(server->getConn().streamManager->streamCount(), 0);
    EXPECT_EQ(server->getConn().pendingZeroRttData->size(), 1);
  }
  EXPECT_EQ(
      server->getConn().qLogger->scid, server->getConn().serverConnectionId);
}

TEST_P(
    QuicServerTransportPendingDataTest,
    TestNoCipherProcessPendingOneRttData) {
  server->getNonConstConn().qLogger =
      std::make_shared<quic::FileQLogger>(VantagePoint::Server);
  recvClientHello();
  auto data = IOBuf::copyBuffer("bad data");
  StreamId streamId = 2;
  // Write packet with zero rtt keys
  auto packetData = packetToBuf(createStreamPacket(
      *clientConnectionId,
      *server->getConn().serverConnectionId,
      clientNextAppDataPacketNum++,
      streamId,
      *data,
      0 /* cipherOverhead */,
      0 /* largestAcked */,
      std::nullopt,
      false));
  deliverData(std::move(packetData));
  EXPECT_EQ(server->getConn().streamManager->streamCount(), 0);
  EXPECT_EQ(server->getConn().pendingOneRttData->size(), 1);

  EXPECT_CALL(handshakeFinishedCallback, onHandshakeFinished());
  recvClientFinished();
  EXPECT_EQ(server->getConn().streamManager->streamCount(), 1);
  EXPECT_EQ(server->getConn().pendingZeroRttData, nullptr);
  EXPECT_EQ(server->getConn().pendingOneRttData, nullptr);
  EXPECT_EQ(
      server->getConn().qLogger->scid, server->getConn().serverConnectionId);
}

TEST_P(
    QuicServerTransportPendingDataTest,
    TestNoCipherProcessingZeroAndOneRttData) {
  server->getNonConstConn().qLogger =
      std::make_shared<quic::FileQLogger>(VantagePoint::Server);
  recvClientHello(false);
  auto data = IOBuf::copyBuffer("bad data");
  StreamId streamId = 2;
  // Write packet with zero rtt keys
  auto packetData = packetToBuf(createStreamPacket(
      *clientConnectionId,
      *server->getConn().serverConnectionId,
      clientNextAppDataPacketNum++,
      streamId,
      *data,
      0 /* cipherOverhead */,
      0 /* largestAcked */,
      std::make_pair(
          LongHeader::Types::ZeroRtt, server->getConn().supportedVersions[0]),
      false));
  deliverData(std::move(packetData), false);
  if (GetParam().acceptZeroRtt) {
    if (!GetParam().chloSync) {
      EXPECT_EQ(server->getConn().streamManager->streamCount(), 0);
      EXPECT_EQ(server->getConn().pendingZeroRttData->size(), 1);
      loopForWrites();
    }
    EXPECT_EQ(server->getConn().streamManager->streamCount(), 1);
    EXPECT_EQ(server->getConn().pendingZeroRttData, nullptr);
  } else {
    EXPECT_EQ(server->getConn().streamManager->streamCount(), 0);
    EXPECT_EQ(server->getConn().pendingZeroRttData->size(), 1);
  }
  loopForWrites();

  StreamId streamId2 = 4;
  // Write packet with zero rtt keys
  auto packetData2 = packetToBuf(createStreamPacket(
      *clientConnectionId,
      *server->getConn().serverConnectionId,
      clientNextAppDataPacketNum++,
      streamId2,
      *data,
      0 /* cipherOverhead */,
      0 /* largestAcked */));
  deliverData(std::move(packetData2));
  EXPECT_EQ(
      server->getConn().streamManager->streamCount(),
      GetParam().acceptZeroRtt ? 1 : 0);
  EXPECT_EQ(server->getConn().pendingOneRttData->size(), 1);

  EXPECT_CALL(handshakeFinishedCallback, onHandshakeFinished());
  recvClientFinished();
  EXPECT_EQ(
      server->getConn().streamManager->streamCount(),
      GetParam().acceptZeroRtt ? 2 : 1);
  EXPECT_EQ(server->getConn().pendingZeroRttData, nullptr);
  EXPECT_EQ(server->getConn().pendingOneRttData, nullptr);
  EXPECT_EQ(
      server->getConn().qLogger->scid, server->getConn().serverConnectionId);
}

/**
 * Test handshake process with different parameters:
 * sync CHLO processing, sync CFIN processing, accept 0-rtt
 */
class QuicServerTransportHandshakeTest
    : public QuicUnencryptedServerTransportTest,
      public WithParamInterface<FizzHandshakeParam> {
 public:
  ~QuicServerTransportHandshakeTest() override {
    // We need an extra pump here for some reason.
    loopForWrites();
  }

  void initializeServerHandshake() override {
    fakeHandshake = new FakeServerHandshake(
        server->getNonConstConn(),
        FizzServerQuicHandshakeContext::Builder().build(),
        GetParam().chloSync,
        GetParam().cfinSync);
    if (GetParam().acceptZeroRtt) {
      fakeHandshake->allowZeroRttKeys();
    }
  }

  void expectWriteNewSessionTicket() override {
    std::string appParams("APP params");
    server->setEarlyDataAppParamsFunctions(
        [](const Optional<std::string>&, const BufPtr&) { return false; },
        [=]() -> BufPtr { return folly::IOBuf::copyBuffer(appParams); });
    EXPECT_CALL(*getFakeHandshakeLayer(), writeNewSessionTicket(_))
        .WillOnce(Invoke([=](const AppToken& appToken) {
          auto& params = appToken.transportParams.parameters;

          auto initialMaxDataResult = getIntegerParameter(
              TransportParameterId::initial_max_data, params);
          EXPECT_FALSE(initialMaxDataResult.hasError());
          auto initialMaxData = *initialMaxDataResult.value();
          EXPECT_EQ(
              initialMaxData,
              server->getConn()
                  .transportSettings
                  .advertisedInitialConnectionFlowControlWindow);

          auto initialMaxStreamDataBidiLocalResult = getIntegerParameter(
              TransportParameterId::initial_max_stream_data_bidi_local, params);
          EXPECT_FALSE(initialMaxStreamDataBidiLocalResult.hasError());
          auto initialMaxStreamDataBidiLocal =
              *initialMaxStreamDataBidiLocalResult.value();

          auto initialMaxStreamDataBidiRemoteResult = getIntegerParameter(
              TransportParameterId::initial_max_stream_data_bidi_remote,
              params);
          EXPECT_FALSE(initialMaxStreamDataBidiRemoteResult.hasError());
          auto initialMaxStreamDataBidiRemote =
              *initialMaxStreamDataBidiRemoteResult.value();

          auto initialMaxStreamDataUniResult = getIntegerParameter(
              TransportParameterId::initial_max_stream_data_bidi_remote,
              params);
          EXPECT_FALSE(initialMaxStreamDataUniResult.hasError());
          auto initialMaxStreamDataUni = *initialMaxStreamDataUniResult.value();
          EXPECT_EQ(
              initialMaxStreamDataBidiLocal,
              server->getConn()
                  .transportSettings
                  .advertisedInitialBidiLocalStreamFlowControlWindow);
          EXPECT_EQ(
              initialMaxStreamDataBidiRemote,
              server->getConn()
                  .transportSettings
                  .advertisedInitialBidiRemoteStreamFlowControlWindow);
          EXPECT_EQ(
              initialMaxStreamDataUni,
              server->getConn()
                  .transportSettings
                  .advertisedInitialUniStreamFlowControlWindow);

          auto initialMaxStreamsBidiResult = getIntegerParameter(
              TransportParameterId::initial_max_streams_bidi, params);
          EXPECT_FALSE(initialMaxStreamsBidiResult.hasError());
          auto initialMaxStreamsBidi = *initialMaxStreamsBidiResult.value();

          auto initialMaxStreamsUniResult = getIntegerParameter(
              TransportParameterId::initial_max_streams_uni, params);
          EXPECT_FALSE(initialMaxStreamsUniResult.hasError());
          auto initialMaxStreamsUni = *initialMaxStreamsUniResult.value();
          EXPECT_EQ(
              initialMaxStreamsBidi,
              server->getConn()
                  .transportSettings.advertisedInitialMaxStreamsBidi);
          EXPECT_EQ(
              initialMaxStreamsUni,
              server->getConn()
                  .transportSettings.advertisedInitialMaxStreamsUni);

          auto maxRecvPacketSizeResult = getIntegerParameter(
              TransportParameterId::max_packet_size, params);
          EXPECT_FALSE(maxRecvPacketSizeResult.hasError());
          auto maxRecvPacketSize = *maxRecvPacketSizeResult.value();
          EXPECT_EQ(
              maxRecvPacketSize,
              server->getConn().transportSettings.maxRecvPacketSize);

          EXPECT_THAT(
              appToken.sourceAddresses, ContainerEq(expectedSourceToken_));

          EXPECT_TRUE(folly::IOBufEqualTo()(
              appToken.appParams, folly::IOBuf::copyBuffer(appParams)));
          return folly::unit;
        }));
  }

  void testSetupConnection() {
    // If 0-rtt is accepted, one rtt write cipher will be available after CHLO
    // is processed
    if (GetParam().acceptZeroRtt) {
      EXPECT_CALL(*quicStats_, onNewConnection());
      EXPECT_CALL(connSetupCallback, onTransportReady());
      EXPECT_CALL(connSetupCallback, onFullHandshakeDone()).Times(0);
    }
    recvClientHello();

    EXPECT_CALL(connSetupCallback, onFullHandshakeDone()).Times(1);

    // If 0-rtt is disabled, one rtt write cipher will be available after CFIN
    // is processed
    if (!GetParam().acceptZeroRtt) {
      EXPECT_CALL(*quicStats_, onNewConnection());
      EXPECT_CALL(connSetupCallback, onTransportReady());
    }
    // onConnectionIdBound is always invoked after CFIN is processed
    EXPECT_CALL(routingCallback, onConnectionIdBound(_));
    // NST is always written after CFIN is processed
    expectWriteNewSessionTicket();
    EXPECT_CALL(handshakeFinishedCallback, onHandshakeFinished());
    recvClientFinished();
  }

 protected:
  std::vector<folly::IPAddress> expectedSourceToken_;
};

INSTANTIATE_TEST_SUITE_P(
    QuicServerTransportHandshakeTests,
    QuicServerTransportHandshakeTest,
    Values(
        FizzHandshakeParam(false, false, false),
        FizzHandshakeParam(false, false, true),
        FizzHandshakeParam(false, true, false),
        FizzHandshakeParam(false, true, true),
        FizzHandshakeParam(true, false, false),
        FizzHandshakeParam(true, false, true),
        FizzHandshakeParam(true, true, false),
        FizzHandshakeParam(true, true, true)));

TEST_P(
    QuicServerTransportHandshakeTest,
    TestConnectionSetupWithoutSourceTokenInPsk) {
  serverCtx->setSendNewSessionTicket(false);
  expectedSourceToken_ = {clientAddr.getIPAddress()};
  testSetupConnection();
}

TEST_P(
    QuicServerTransportHandshakeTest,
    TestConnectionSetupWithSourceTokenInPsk) {
  serverCtx->setSendNewSessionTicket(false);
  auto ipAddr = folly::IPAddress("1.2.3.4");
  getFakeHandshakeLayer()->setSourceTokens({ipAddr});
  if (GetParam().acceptZeroRtt) {
    expectedSourceToken_ = {ipAddr, clientAddr.getIPAddress()};
  } else {
    expectedSourceToken_ = {clientAddr.getIPAddress()};
  }
  testSetupConnection();
}

TEST_F(QuicUnencryptedServerTransportTest, DuplicateOneRttWriteCipher) {
  setupClientReadCodec();
  recvClientHello();
  EXPECT_CALL(handshakeFinishedCallback, onHandshakeFinished());
  recvClientFinished();
  loopForWrites();
  try {
    recvClientHello();
    recvClientFinished();
    FAIL();
  } catch (const std::runtime_error& ex) {
    EXPECT_THAT(ex.what(), HasSubstr("Crypto error"));
  }
  EXPECT_TRUE(server->isClosed());
}

TEST_F(QuicServerTransportTest, TestRegisterAndHandleTransportKnobParams) {
  int flag = 0;
  server->registerKnobParamHandler(
      199,
      [&](QuicServerTransport* /* server_conn */, TransportKnobParam::Val val) {
        EXPECT_EQ(std::get<uint64_t>(val), 10);
        flag = 1;
        return folly::unit;
      });
  server->registerKnobParamHandler(
      200,
      [&](QuicServerTransport* /* server_conn */,
          const TransportKnobParam::Val& /* val */) {
        flag = 2;
        return folly::unit;
      });
  server->handleKnobParams({
      {199, uint64_t{10}},
      {201, uint64_t{20}},
  });

  EXPECT_EQ(flag, 1);

  // overwrite will fail, the new handler won't be called
  server->registerKnobParamHandler(
      199,
      [&](QuicServerTransport* /* server_conn */, TransportKnobParam::Val val) {
        EXPECT_EQ(std::get<uint64_t>(val), 30);
        flag = 3;
        return folly::unit;
      });

  server->handleKnobParams({
      {199, uint64_t{10}},
      {201, uint64_t{20}},
  });
  EXPECT_EQ(flag, 1);
}

TEST_F(
    QuicServerTransportTest,
    TestHandleTransportKnobParamWithUnexpectedValTypes) {
  // expect an uint64_t but string value provided
  auto knobParamId =
      static_cast<uint64_t>(TransportKnobParamId::MAX_PACING_RATE_KNOB);
  EXPECT_CALL(*quicStats_, onTransportKnobError(Eq(knobParamId))).Times(1);
  server->handleKnobParams({{knobParamId, "not-uint64_t"}});

  // expect a string but uint64_t value provided
  knobParamId = static_cast<uint64_t>(
      TransportKnobParamId::MAX_PACING_RATE_KNOB_SEQUENCED);
  EXPECT_CALL(*quicStats_, onTransportKnobError(Eq(knobParamId))).Times(1);
  server->handleKnobParams({{knobParamId, uint64_t{1234}}});
}

TEST_F(QuicServerTransportTest, TestSkipKnobsWhenNotAdvertisingSupport) {
  auto& conn = server->getNonConstConn();
  auto& transportSettings = conn.transportSettings;
  EXPECT_EQ(transportSettings.ccaConfig.conservativeRecovery, false);

  transportSettings.advertisedKnobFrameSupport = true;

  // Start with advertising knob support to make sure the knob works
  conn.pendingEvents.knobs.emplace_back(
      quic::kDefaultQuicTransportKnobSpace,
      TransportKnobParamId::CC_CONFIG,
      folly::IOBuf::copyBuffer(
          R"({"52397": "{ \"conservativeRecovery\": true}"})"));

  server->triggerKnobCallbacks();

  // The value should change.
  ASSERT_EQ(transportSettings.ccaConfig.conservativeRecovery, true);
  // The pending knobs should be cleared
  ASSERT_TRUE(server->getConn().pendingEvents.knobs.empty());

  // Reset the config and disable advertising knob support, then retry

  transportSettings.ccaConfig.conservativeRecovery = false;
  transportSettings.advertisedKnobFrameSupport = false;

  // Start with advertising knob support to make sure the knob works
  conn.pendingEvents.knobs.emplace_back(
      quic::kDefaultQuicTransportKnobSpace,
      TransportKnobParamId::CC_CONFIG,
      folly::IOBuf::copyBuffer(
          R"({"52397": "{ \"conservativeRecovery\": true}"})"));

  server->triggerKnobCallbacks();

  // The value should not change.
  EXPECT_EQ(transportSettings.ccaConfig.conservativeRecovery, false);
  // The pending knobs should be cleared
  EXPECT_TRUE(server->getConn().pendingEvents.knobs.empty());
}

TEST_F(QuicServerTransportTest, TestCCExperimentalKnobHandler) {
  auto mockCongestionController =
      std::make_unique<NiceMock<MockCongestionController>>();
  auto rawCongestionController = mockCongestionController.get();
  server->getNonConstConn().congestionController =
      std::move(mockCongestionController);

  EXPECT_CALL(*rawCongestionController, setExperimental(true)).Times(2);
  server->handleKnobParams(
      {{static_cast<uint64_t>(TransportKnobParamId::CC_EXPERIMENTAL),
        uint64_t{1}}});
  server->handleKnobParams(
      {{static_cast<uint64_t>(TransportKnobParamId::CC_EXPERIMENTAL),
        uint64_t{2}}});

  EXPECT_CALL(*rawCongestionController, setExperimental(false)).Times(1);
  server->handleKnobParams(
      {{static_cast<uint64_t>(TransportKnobParamId::CC_EXPERIMENTAL),
        uint64_t{0}}});
}

TEST_F(QuicServerTransportTest, TestCCConfigKnobHandler) {
  auto& transportSettings = server->getNonConstConn().transportSettings;

  EXPECT_EQ(transportSettings.ccaConfig.conservativeRecovery, false);

  server->handleKnobParams(
      {{static_cast<uint64_t>(TransportKnobParamId::CC_CONFIG),
        std::string("{\"conservativeRecovery\": true}")}});
  EXPECT_EQ(transportSettings.ccaConfig.conservativeRecovery, true);
  EXPECT_EQ(transportSettings.ccaConfig.ackFrequencyConfig.has_value(), false);

  server->handleKnobParams(
      {{static_cast<uint64_t>(TransportKnobParamId::CC_CONFIG),
        std::string(
            R"({"drainToTarget": true, "ackFrequencyConfig":{"minRttDivisor": 77}})")}});

  EXPECT_EQ(transportSettings.ccaConfig.conservativeRecovery, false);
  EXPECT_EQ(transportSettings.ccaConfig.drainToTarget, true);
  ASSERT_EQ(transportSettings.ccaConfig.ackFrequencyConfig.has_value(), true);
  EXPECT_EQ(transportSettings.ccaConfig.ackFrequencyConfig->minRttDivisor, 77);
}

TEST_F(QuicServerTransportTest, TestCCConfigKnobHandlerInvalidJSON) {
  auto& transportSettings = server->getNonConstConn().transportSettings;

  EXPECT_EQ(transportSettings.ccaConfig.conservativeRecovery, false);

  server->handleKnobParams(
      {{static_cast<uint64_t>(TransportKnobParamId::CC_CONFIG),
        std::string(R"({"conservativeRecovery": "blabla"})")}});
  EXPECT_EQ(transportSettings.ccaConfig.conservativeRecovery, false);
}

TEST_F(QuicServerTransportTest, TestConnMigrationKnobHandler) {
  auto& transportSettings = server->getNonConstConn().transportSettings;

  // Migration is disabled by default
  ASSERT_EQ(transportSettings.disableMigration, true);

  server->handleKnobParams(
      {{static_cast<uint64_t>(TransportKnobParamId::CONNECTION_MIGRATION),
        uint64_t(1)}});
  EXPECT_EQ(transportSettings.disableMigration, false);

  server->handleKnobParams(
      {{static_cast<uint64_t>(TransportKnobParamId::CONNECTION_MIGRATION),
        uint64_t(0)}});
  EXPECT_EQ(transportSettings.disableMigration, true);
}

TEST_F(QuicServerTransportTest, TestNewStreamBlockedConditionKnobHandler) {
  auto& transportSettings = server->getNonConstConn().transportSettings;

  // useNewStreamBlockedCondition is disabled by default
  ASSERT_FALSE(transportSettings.useNewStreamBlockedCondition);

  server->handleKnobParams(
      {{static_cast<uint64_t>(
            TransportKnobParamId::USE_NEW_STREAM_BLOCKED_CONDITION),
        uint64_t(1)}});
  EXPECT_TRUE(transportSettings.useNewStreamBlockedCondition);

  server->handleKnobParams(
      {{static_cast<uint64_t>(
            TransportKnobParamId::USE_NEW_STREAM_BLOCKED_CONDITION),
        uint64_t(0)}});
  EXPECT_FALSE(transportSettings.useNewStreamBlockedCondition);
}

TEST_F(QuicServerTransportTest, TestAutotuneStreamFlowControlKnobHandler) {
  auto& transportSettings = server->getNonConstConn().transportSettings;

  // autotuneReceiveStreamFlowControl is disabled by default
  ASSERT_FALSE(transportSettings.autotuneReceiveStreamFlowControl);

  server->handleKnobParams(
      {{static_cast<uint64_t>(
            TransportKnobParamId::AUTOTUNE_RECV_STREAM_FLOW_CONTROL),
        uint64_t(1)}});
  EXPECT_TRUE(transportSettings.autotuneReceiveStreamFlowControl);

  server->handleKnobParams(
      {{static_cast<uint64_t>(
            TransportKnobParamId::AUTOTUNE_RECV_STREAM_FLOW_CONTROL),
        uint64_t(0)}});
  EXPECT_FALSE(transportSettings.autotuneReceiveStreamFlowControl);
}

TEST_F(QuicServerTransportTest, TestInflightReorderingThreshold) {
  auto& transportSettings = server->getNonConstConn().transportSettings;

  // autotuneReceiveStreamFlowControl is disabled by default
  ASSERT_FALSE(transportSettings.useInflightReorderingThreshold);

  server->handleKnobParams(
      {{static_cast<uint64_t>(
            TransportKnobParamId::INFLIGHT_REORDERING_THRESHOLD),
        uint64_t(1)}});
  EXPECT_TRUE(transportSettings.useInflightReorderingThreshold);

  server->handleKnobParams(
      {{static_cast<uint64_t>(
            TransportKnobParamId::INFLIGHT_REORDERING_THRESHOLD),
        uint64_t(0)}});
  EXPECT_FALSE(transportSettings.useInflightReorderingThreshold);
}

TEST_F(QuicServerTransportTest, TestPacerExperimentalKnobHandler) {
  auto mockPacer = std::make_unique<NiceMock<MockPacer>>();
  auto rawPacer = mockPacer.get();
  server->getNonConstConn().pacer = std::move(mockPacer);

  EXPECT_CALL(*rawPacer, setExperimental(true)).Times(2);
  server->handleKnobParams(
      {{static_cast<uint64_t>(TransportKnobParamId::PACER_EXPERIMENTAL),
        uint64_t{1}}});
  server->handleKnobParams(
      {{static_cast<uint64_t>(TransportKnobParamId::PACER_EXPERIMENTAL),
        uint64_t{2}}});

  EXPECT_CALL(*rawPacer, setExperimental(false)).Times(1);
  server->handleKnobParams(
      {{static_cast<uint64_t>(TransportKnobParamId::PACER_EXPERIMENTAL),
        uint64_t{0}}});
}

TEST_F(QuicServerTransportTest, TestAckFrequencyPolicyKnobHandler) {
  server->handleKnobParams(
      {{static_cast<uint64_t>(TransportKnobParamId::ACK_FREQUENCY_POLICY),
        uint64_t{1}}});
  EXPECT_FALSE(server->getTransportSettings().ccaConfig.ackFrequencyConfig);
  server->handleKnobParams(
      {{static_cast<uint64_t>(TransportKnobParamId::ACK_FREQUENCY_POLICY),
        "blah,blah,blah"}});
  EXPECT_FALSE(server->getTransportSettings().ccaConfig.ackFrequencyConfig);
  server->handleKnobParams(
      {{static_cast<uint64_t>(TransportKnobParamId::ACK_FREQUENCY_POLICY),
        "1,1,"}});
  EXPECT_FALSE(server->getTransportSettings().ccaConfig.ackFrequencyConfig);
  server->handleKnobParams(
      {{static_cast<uint64_t>(TransportKnobParamId::ACK_FREQUENCY_POLICY),
        "1,1,1,1"}});
  EXPECT_FALSE(server->getTransportSettings().ccaConfig.ackFrequencyConfig);
  server->handleKnobParams(
      {{static_cast<uint64_t>(TransportKnobParamId::ACK_FREQUENCY_POLICY),
        "10,3,1,1"}});
  ASSERT_TRUE(server->getTransportSettings().ccaConfig.ackFrequencyConfig);
  EXPECT_EQ(
      server->getTransportSettings()
          .ccaConfig.ackFrequencyConfig->ackElicitingThreshold,
      10);
  EXPECT_EQ(
      server->getTransportSettings()
          .ccaConfig.ackFrequencyConfig->reorderingThreshold,
      3);
  EXPECT_EQ(
      server->getTransportSettings()
          .ccaConfig.ackFrequencyConfig->minRttDivisor,
      1);
  EXPECT_EQ(
      server->getTransportSettings()
          .ccaConfig.ackFrequencyConfig->useSmallThresholdDuringStartup,
      true);
  server->getNonConstConn()
      .transportSettings.ccaConfig.ackFrequencyConfig.reset();
  server->handleKnobParams(
      {{static_cast<uint64_t>(TransportKnobParamId::ACK_FREQUENCY_POLICY),
        "10,3,-1,1"}});
  EXPECT_FALSE(server->getTransportSettings().ccaConfig.ackFrequencyConfig);
  server->handleKnobParams(
      {{static_cast<uint64_t>(TransportKnobParamId::ACK_FREQUENCY_POLICY),
        "10,-1,1,1"}});
  EXPECT_FALSE(server->getTransportSettings().ccaConfig.ackFrequencyConfig);
  server->handleKnobParams(
      {{static_cast<uint64_t>(TransportKnobParamId::ACK_FREQUENCY_POLICY),
        "-1,3,1,1"}});
  EXPECT_FALSE(server->getTransportSettings().ccaConfig.ackFrequencyConfig);
  server->handleKnobParams(
      {{static_cast<uint64_t>(TransportKnobParamId::ACK_FREQUENCY_POLICY),
        "10,3,0,1"}});
  EXPECT_FALSE(server->getTransportSettings().ccaConfig.ackFrequencyConfig);
  server->handleKnobParams(
      {{static_cast<uint64_t>(TransportKnobParamId::ACK_FREQUENCY_POLICY),
        "10,1,1,1"}});
  EXPECT_FALSE(server->getTransportSettings().ccaConfig.ackFrequencyConfig);
  server->handleKnobParams(
      {{static_cast<uint64_t>(TransportKnobParamId::ACK_FREQUENCY_POLICY),
        "1,3,1,1"}});
  server->handleKnobParams(
      {{static_cast<uint64_t>(TransportKnobParamId::DEFAULT_STREAM_PRIORITY),
        "1,1"}});
  EXPECT_EQ(
      HTTPPriorityQueue::Priority(
          server->getTransportSettings().defaultPriority),
      HTTPPriorityQueue::Priority(1, true));
  server->handleKnobParams(
      {{static_cast<uint64_t>(TransportKnobParamId::DEFAULT_STREAM_PRIORITY),
        "4,0"}});
  EXPECT_EQ(
      HTTPPriorityQueue::Priority(
          server->getTransportSettings().defaultPriority),
      HTTPPriorityQueue::Priority(4, false));
  server->handleKnobParams(
      {{static_cast<uint64_t>(TransportKnobParamId::DEFAULT_STREAM_PRIORITY),
        "4,0,10"}});
  EXPECT_EQ(
      HTTPPriorityQueue::Priority(
          server->getTransportSettings().defaultPriority),
      HTTPPriorityQueue::Priority(4, false));
  // level too large, unchanged
  server->handleKnobParams(
      {{static_cast<uint64_t>(TransportKnobParamId::DEFAULT_STREAM_PRIORITY),
        "20,0"}});
  EXPECT_EQ(
      HTTPPriorityQueue::Priority(
          server->getTransportSettings().defaultPriority),
      HTTPPriorityQueue::Priority(4, false));
  server->handleKnobParams(
      {{static_cast<uint64_t>(TransportKnobParamId::WRITE_LOOP_TIME_FRACTION),
        uint64_t(2)}});
  EXPECT_EQ(server->getTransportSettings().writeLimitRttFraction, 2);
  server->handleKnobParams(
      {{static_cast<uint64_t>(TransportKnobParamId::WRITES_PER_STREAM),
        uint64_t(5)}});
  EXPECT_EQ(server->getTransportSettings().priorityQueueWritesPerStream, 5);
}

TEST_F(QuicServerTransportTest, TestSetMaxPacingRateLifecycle) {
  auto mockPacer = std::make_unique<NiceMock<MockPacer>>();
  auto rawPacer = mockPacer.get();
  server->getNonConstConn().pacer = std::move(mockPacer);

  // verify init state NO_PACING
  auto maxPacingRateKnobState = server->getConn().maxPacingRateKnobState;
  EXPECT_FALSE(maxPacingRateKnobState.frameOutOfOrderDetected);
  EXPECT_EQ(kTestMaxPacingRate, maxPacingRateKnobState.lastMaxRateBytesPerSec);

  // set max pacing rate
  uint64_t pacingRate = 1234;
  EXPECT_CALL(*rawPacer, setMaxPacingRate(pacingRate)).Times(1);
  server->handleKnobParams(
      {{static_cast<uint64_t>(TransportKnobParamId::MAX_PACING_RATE_KNOB),
        pacingRate}});
  maxPacingRateKnobState = server->getConn().maxPacingRateKnobState;
  EXPECT_FALSE(maxPacingRateKnobState.frameOutOfOrderDetected);
  EXPECT_EQ(pacingRate, maxPacingRateKnobState.lastMaxRateBytesPerSec);

  // disable pacing
  EXPECT_CALL(*rawPacer, setMaxPacingRate(kTestMaxPacingRate)).Times(1);
  server->handleKnobParams(
      {{static_cast<uint64_t>(TransportKnobParamId::MAX_PACING_RATE_KNOB),
        kTestMaxPacingRate}});
  maxPacingRateKnobState = server->getConn().maxPacingRateKnobState;
  EXPECT_FALSE(maxPacingRateKnobState.frameOutOfOrderDetected);
  EXPECT_EQ(kTestMaxPacingRate, maxPacingRateKnobState.lastMaxRateBytesPerSec);

  // set max pacing rate again
  pacingRate = 5678;
  EXPECT_CALL(*rawPacer, setMaxPacingRate(pacingRate)).Times(1);
  server->handleKnobParams(
      {{static_cast<uint64_t>(TransportKnobParamId::MAX_PACING_RATE_KNOB),
        pacingRate}});
  maxPacingRateKnobState = server->getConn().maxPacingRateKnobState;
  EXPECT_FALSE(maxPacingRateKnobState.frameOutOfOrderDetected);
  EXPECT_EQ(pacingRate, maxPacingRateKnobState.lastMaxRateBytesPerSec);

  // another pacing rate should still work
  pacingRate = 9999;
  EXPECT_CALL(*rawPacer, setMaxPacingRate(pacingRate)).Times(1);
  server->handleKnobParams(
      {{static_cast<uint64_t>(TransportKnobParamId::MAX_PACING_RATE_KNOB),
        pacingRate}});
  maxPacingRateKnobState = server->getConn().maxPacingRateKnobState;
  EXPECT_FALSE(maxPacingRateKnobState.frameOutOfOrderDetected);
  EXPECT_EQ(pacingRate, maxPacingRateKnobState.lastMaxRateBytesPerSec);

  // disable pacing
  EXPECT_CALL(*rawPacer, setMaxPacingRate(kTestMaxPacingRate)).Times(1);
  server->handleKnobParams(
      {{static_cast<uint64_t>(TransportKnobParamId::MAX_PACING_RATE_KNOB),
        kTestMaxPacingRate}});
  maxPacingRateKnobState = server->getConn().maxPacingRateKnobState;
  EXPECT_FALSE(maxPacingRateKnobState.frameOutOfOrderDetected);
  EXPECT_EQ(kTestMaxPacingRate, maxPacingRateKnobState.lastMaxRateBytesPerSec);
}

TEST_F(
    QuicServerTransportTest,
    TestMaxPacingRateKnobSequencedWithInvalidFrameValues) {
  auto mockPacer = std::make_unique<NiceMock<MockPacer>>();
  auto rawPacer = mockPacer.get();
  server->getNonConstConn().pacer = std::move(mockPacer);

  // expect pacer never gets called
  EXPECT_CALL(*rawPacer, setMaxPacingRate(_)).Times(0);

  // only pacing provided
  server->handleKnobParams(
      {{static_cast<uint64_t>(
            TransportKnobParamId::MAX_PACING_RATE_KNOB_SEQUENCED),
        "1234"}});

  // extra field beside pacing rate & sequence number
  server->handleKnobParams(
      {{static_cast<uint64_t>(
            TransportKnobParamId::MAX_PACING_RATE_KNOB_SEQUENCED),
        "1234,5678,9999"}});

  // non uint64_t provided as pacing rate
  server->handleKnobParams(
      {{static_cast<uint64_t>(
            TransportKnobParamId::MAX_PACING_RATE_KNOB_SEQUENCED),
        "abc,1"}});
  server->handleKnobParams(
      {{static_cast<uint64_t>(
            TransportKnobParamId::MAX_PACING_RATE_KNOB_SEQUENCED),
        "2a,1"}});

  // non uint64_t provided as sequence number
  server->handleKnobParams(
      {{static_cast<uint64_t>(
            TransportKnobParamId::MAX_PACING_RATE_KNOB_SEQUENCED),
        "1234,def"}});
  server->handleKnobParams(
      {{static_cast<uint64_t>(
            TransportKnobParamId::MAX_PACING_RATE_KNOB_SEQUENCED),
        "1234,2a"}});

  // negative integer provided
  server->handleKnobParams(
      {{static_cast<uint64_t>(
            TransportKnobParamId::MAX_PACING_RATE_KNOB_SEQUENCED),
        "-1000,1"}});
  server->handleKnobParams(
      {{static_cast<uint64_t>(
            TransportKnobParamId::MAX_PACING_RATE_KNOB_SEQUENCED),
        "1000,-2"}});

  // now, expect pacer to get called as we pass valid params
  uint64_t rate = 1000;
  uint64_t seqNum = 1;
  auto knobVal = [&rate, &seqNum]() {
    return fmt::format("{},{}", rate, seqNum);
  };
  EXPECT_CALL(*rawPacer, setMaxPacingRate(rate)).Times(1);
  server->handleKnobParams(
      {{static_cast<uint64_t>(
            TransportKnobParamId::MAX_PACING_RATE_KNOB_SEQUENCED),
        knobVal()}});

  rate = 9999;
  seqNum = 100;
  EXPECT_CALL(*rawPacer, setMaxPacingRate(rate)).Times(1);
  server->handleKnobParams(
      {{static_cast<uint64_t>(
            TransportKnobParamId::MAX_PACING_RATE_KNOB_SEQUENCED),
        knobVal()}});
}

class OutOfOrderMaxPacingRateKnobSequencedFrameTest
    : public QuicServerTransportTest,
      public testing::WithParamInterface<uint64_t> {};

TEST_P(
    OutOfOrderMaxPacingRateKnobSequencedFrameTest,
    TestMaxPacingRateKnobSequencedWithOutOfOrderFrames) {
  auto mockPacer = std::make_unique<NiceMock<MockPacer>>();
  auto rawPacer = mockPacer.get();
  server->getNonConstConn().pacer = std::move(mockPacer);

  // first frame received with seqNum
  uint64_t rate = 5678;
  uint64_t seqNum = GetParam();
  auto serializedKnobVal = [&rate, &seqNum]() {
    return fmt::format("{},{}", rate, seqNum);
  };
  EXPECT_CALL(*rawPacer, setMaxPacingRate(rate)).Times(1);
  server->handleKnobParams(
      {{static_cast<uint64_t>(
            TransportKnobParamId::MAX_PACING_RATE_KNOB_SEQUENCED),
        serializedKnobVal()}});

  // second frame received with the same seqNum, should be rejected regardless
  // of pacing rate being different
  rate = 1234;
  EXPECT_CALL(*rawPacer, setMaxPacingRate(_)).Times(0);
  server->handleKnobParams(
      {{static_cast<uint64_t>(
            TransportKnobParamId::MAX_PACING_RATE_KNOB_SEQUENCED),
        serializedKnobVal()}});

  // second frame received with sequence number being less than seqNum, should
  // be rejected
  if (seqNum > 0) {
    rate = 8888;
    seqNum = GetParam() - 1;
    EXPECT_CALL(*rawPacer, setMaxPacingRate(_)).Times(0);
    server->handleKnobParams(
        {{static_cast<uint64_t>(
              TransportKnobParamId::MAX_PACING_RATE_KNOB_SEQUENCED),
          serializedKnobVal()}});
  }

  // third frame received with sequence number = seqNum + 1, should be accepted
  rate = 9999;
  seqNum = GetParam() + 1;
  EXPECT_CALL(*rawPacer, setMaxPacingRate(rate)).Times(1);
  server->handleKnobParams(
      {{static_cast<uint64_t>(
            TransportKnobParamId::MAX_PACING_RATE_KNOB_SEQUENCED),
        serializedKnobVal()}});

  // forth frame received with larger sequence number should be accepted
  rate = 1111;
  seqNum = GetParam() + 1000;
  EXPECT_CALL(*rawPacer, setMaxPacingRate(rate)).Times(1);
  server->handleKnobParams(
      {{static_cast<uint64_t>(
            TransportKnobParamId::MAX_PACING_RATE_KNOB_SEQUENCED),
        serializedKnobVal()}});
}

INSTANTIATE_TEST_SUITE_P(
    OutOfOrderMaxPacingRateKnobSequencedFrameTests,
    OutOfOrderMaxPacingRateKnobSequencedFrameTest,
    ::testing::Values(0, 1, 7, 42));

/*
 * Verify that if the transport receives a request to set max pacing rate after
 * out of order frame detected, then the request to set max pacing will not be
 * processed.
 *
 *   NO_PACING --> NO_PACING --> PACING
 */
TEST_F(QuicServerTransportTest, TestSetMaxPacingRateFrameOutOfOrder) {
  auto mockPacer = std::make_unique<NiceMock<MockPacer>>();
  auto rawPacer = mockPacer.get();
  server->getNonConstConn().pacer = std::move(mockPacer);

  // verify init state NO_PACING
  auto maxPacingRateKnobState = server->getConn().maxPacingRateKnobState;
  EXPECT_FALSE(maxPacingRateKnobState.frameOutOfOrderDetected);
  EXPECT_EQ(kTestMaxPacingRate, maxPacingRateKnobState.lastMaxRateBytesPerSec);

  // disable pacing while the current pacing state is still NO_PACING, should
  // detect out of order frame
  EXPECT_CALL(*rawPacer, setMaxPacingRate(kTestMaxPacingRate)).Times(0);
  server->handleKnobParams(
      {{static_cast<uint64_t>(TransportKnobParamId::MAX_PACING_RATE_KNOB),
        kTestMaxPacingRate}});
  maxPacingRateKnobState = server->getConn().maxPacingRateKnobState;
  EXPECT_TRUE(maxPacingRateKnobState.frameOutOfOrderDetected);

  // any attempt to set max pacing rate from now on should fail
  uint64_t pacingRate = 1234;
  EXPECT_CALL(*rawPacer, setMaxPacingRate(pacingRate)).Times(0);
  server->handleKnobParams(
      {{static_cast<uint64_t>(TransportKnobParamId::MAX_PACING_RATE_KNOB),
        pacingRate}});
  maxPacingRateKnobState = server->getConn().maxPacingRateKnobState;
  EXPECT_TRUE(maxPacingRateKnobState.frameOutOfOrderDetected);

  EXPECT_CALL(*rawPacer, setMaxPacingRate(kTestMaxPacingRate)).Times(0);
  server->handleKnobParams(
      {{static_cast<uint64_t>(TransportKnobParamId::MAX_PACING_RATE_KNOB),
        kTestMaxPacingRate}});
  maxPacingRateKnobState = server->getConn().maxPacingRateKnobState;
  EXPECT_TRUE(maxPacingRateKnobState.frameOutOfOrderDetected);

  pacingRate = 5678;
  EXPECT_CALL(*rawPacer, setMaxPacingRate(pacingRate)).Times(0);
  server->handleKnobParams(
      {{static_cast<uint64_t>(TransportKnobParamId::MAX_PACING_RATE_KNOB),
        pacingRate}});
  maxPacingRateKnobState = server->getConn().maxPacingRateKnobState;
  EXPECT_TRUE(maxPacingRateKnobState.frameOutOfOrderDetected);
}

class QuicServerTransportForciblySetUDUPayloadSizeTest
    : public QuicServerTransportTest {
 public:
  bool getCanIgnorePathMTU() override {
    return false;
  }
};

TEST_F(
    QuicServerTransportForciblySetUDUPayloadSizeTest,
    TestHandleTransportKnobParamForciblySetUDPPayloadSize) {
  EXPECT_LT(server->getConn().udpSendPacketLen, 1452);
  server->handleKnobParams(
      {{static_cast<uint64_t>(
            TransportKnobParamId::FORCIBLY_SET_UDP_PAYLOAD_SIZE),
        uint64_t{1}}});
  EXPECT_EQ(server->getConn().udpSendPacketLen, 1452);
}

TEST_F(
    QuicServerTransportTest,
    TestHandleTransportKnobParamFixedShortHeaderPadding) {
  EXPECT_EQ(server->getConn().transportSettings.fixedShortHeaderPadding, 0);
  server->handleKnobParams(
      {{static_cast<uint64_t>(
            TransportKnobParamId::FIXED_SHORT_HEADER_PADDING_KNOB),
        uint64_t{42}}});
  EXPECT_EQ(server->getConn().transportSettings.fixedShortHeaderPadding, 42);
}

TEST_F(QuicServerTransportTest, TestBurstSizeKnobHandlers) {
  auto& transportSettings = server->getNonConstConn().transportSettings;

  ASSERT_EQ(transportSettings.minBurstPackets, kDefaultMinBurstPackets);
  server->handleKnobParams(
      {{static_cast<uint64_t>(TransportKnobParamId::PACER_MIN_BURST_PACKETS),
        uint64_t(25)}});
  EXPECT_EQ(transportSettings.minBurstPackets, 25);

  ASSERT_EQ(
      transportSettings.writeConnectionDataPacketsLimit,
      kDefaultWriteConnectionDataPacketLimit);
  ASSERT_EQ(transportSettings.maxBatchSize, kDefaultQuicMaxBatchSize);
  server->handleKnobParams(
      {{static_cast<uint64_t>(TransportKnobParamId::MAX_BATCH_PACKETS),
        uint64_t(25)}});
  EXPECT_EQ(transportSettings.writeConnectionDataPacketsLimit, 25);
  // maxBatchSize should remain unchanged
  EXPECT_EQ(transportSettings.maxBatchSize, kDefaultQuicMaxBatchSize);
  server->handleKnobParams(
      {{static_cast<uint64_t>(TransportKnobParamId::MAX_BATCH_PACKETS),
        uint64_t(kQuicMaxBatchSizeLimit) + 1}});
  // maxBatchSize should still remain unchanged
  EXPECT_EQ(transportSettings.maxBatchSize, kDefaultQuicMaxBatchSize);
  server->handleKnobParams(
      {{static_cast<uint64_t>(TransportKnobParamId::MAX_BATCH_PACKETS),
        uint64_t(kMaxWriteConnectionDataPacketLimit) + 1}});
  EXPECT_EQ(
      transportSettings.writeConnectionDataPacketsLimit,
      kMaxWriteConnectionDataPacketLimit);
}

TEST_F(QuicServerTransportTest, TestUseNewPriorityQueueKnobHandler) {
  auto& transportSettings = server->getNonConstConn().transportSettings;
  transportSettings.advertisedInitialMaxStreamsBidi = 2;
  auto tsres = server->getConn().streamManager->refreshTransportSettings(
      transportSettings);
  server->handleKnobParams(
      {{static_cast<uint64_t>(TransportKnobParamId::USE_NEW_PRIORITY_QUEUE),
        uint64_t(1)}});
  EXPECT_TRUE(transportSettings.useNewPriorityQueue);
  EXPECT_EQ(server->getConn().streamManager->oldWriteQueue(), nullptr);

  server->handleKnobParams(
      {{static_cast<uint64_t>(TransportKnobParamId::USE_NEW_PRIORITY_QUEUE),
        uint64_t(0)}});
  EXPECT_FALSE(transportSettings.useNewPriorityQueue);
  EXPECT_NE(server->getConn().streamManager->oldWriteQueue(), nullptr);

  EXPECT_EQ(
      server->getConn().streamManager->openableRemoteBidirectionalStreams(), 2);
  // updating knob with writable streams fails
  auto peerStream = server->getConn().streamManager->getStream(0);
  EXPECT_EQ(
      server->getConn().streamManager->openableRemoteBidirectionalStreams(), 1);
  auto streamId = server->createBidirectionalStream().value();

  auto buf = folly::IOBuf::create(1100);
  buf->append(1100);
  server->writeChain(streamId, std::move(buf), false);

  server->handleKnobParams(
      {{static_cast<uint64_t>(TransportKnobParamId::USE_NEW_PRIORITY_QUEUE),
        uint64_t(1)}});
  EXPECT_FALSE(transportSettings.useNewPriorityQueue);
  EXPECT_NE(server->getConn().streamManager->oldWriteQueue(), nullptr);
  EXPECT_EQ(
      server->getConn().streamManager->openableRemoteBidirectionalStreams(), 1);

  // updating the knob now should not reset the openable streams
  peerStream = server->getConn().streamManager->getStream(0);
  (*peerStream)->sendState = StreamSendState::Closed;
  (*peerStream)->recvState = StreamRecvState::Closed;
  auto res =
      server->getConn().streamManager->removeClosedStream((*peerStream)->id);
  EXPECT_EQ(
      server->getConn().streamManager->openableRemoteBidirectionalStreams(), 2);

  // The switch back works
  server->handleKnobParams(
      {{static_cast<uint64_t>(TransportKnobParamId::USE_NEW_PRIORITY_QUEUE),
        uint64_t(0)}});
  EXPECT_FALSE(transportSettings.useNewPriorityQueue);

  // Peer openable streams unchanged
  EXPECT_EQ(
      server->getConn().streamManager->openableRemoteBidirectionalStreams(), 2);
}

TEST_F(QuicServerTransportTest, WriteDSR) {
  EXPECT_EQ(server->getConn().dsrPacketCount, 0);
  // Make sure we are post-handshake
  ASSERT_NE(nullptr, server->getConn().oneRttWriteCipher);
  // Rinse anything pending
  server->writeData();
  loopForWrites();
  server->getNonConstConn().outstandings.reset();
  getFakeHandshakeLayer()->setCipherSuite(
      fizz::CipherSuite::TLS_AES_128_GCM_SHA256);
  auto streamId = server->createBidirectionalStream().value();
  // Large-ish non-DSR data but not a full packet's worth.
  auto buf = folly::IOBuf::create(1100);
  buf->append(1100);
  server->writeChain(streamId, std::move(buf), false);
  auto mockDSRSender = std::make_unique<MockDSRPacketizationRequestSender>();
  auto rawDSRSender = mockDSRSender.get();
  server->setDSRPacketizationRequestSender(streamId, std::move(mockDSRSender));
  // Explicitly control how many packets we expect.
  server->getNonConstConn().transportSettings.writeConnectionDataPacketsLimit =
      6;
  // Ensure we have plenty of data.
  BufferMeta bufMeta(server->getConn().udpSendPacketLen * 50);
  server->writeBufMeta(streamId, bufMeta, true);
  server->writeData();
  int numDsr = 0;
  int numNonDsr = 0;
  for (auto& p : server->getConn().outstandings.packets) {
    if (p.isDSRPacket) {
      numDsr++;
    } else {
      numNonDsr++;
    }
  }
  EXPECT_EQ(server->getConn().outstandings.packets.size(), 7);
  // Since there's only a small non-DSR packet, we should have 6 DSR and 1
  // non-DSR.
  EXPECT_EQ(numDsr, 6);
  EXPECT_EQ(numNonDsr, 1);
  EXPECT_CALL(*rawDSRSender, release()).Times(1);
  server->resetStream(streamId, GenericApplicationErrorCode::NO_ERROR);
  EXPECT_EQ(server->getConn().dsrPacketCount, 6);
}

class QuicServerTransportCertTest : public QuicServerTransportTest {
 protected:
  class MockCert : public fizz::Cert {
    std::string getIdentity() const override {
      return "";
    }

    std::optional<std::string> getDER() const override {
      return std::nullopt;
    }
  };
};

TEST_F(QuicServerTransportCertTest, TestGetPeerCertificate) {
  auto& conn = getFakeHandshakeLayer()->conn_;

  // have handshake layer, but no client cert
  EXPECT_NE(conn.serverHandshakeLayer, nullptr);
  EXPECT_EQ(server->getPeerCertificate(), nullptr);

  // have client cert
  auto mockCert = std::make_shared<MockCert>();
  const_cast<fizz::server::State&>(conn.serverHandshakeLayer->getState())
      .clientCert() = mockCert;
  EXPECT_EQ(server->getPeerCertificate(), mockCert);

  // no handshake layer
  auto* serverHandshakeLayer = conn.serverHandshakeLayer;
  conn.serverHandshakeLayer = nullptr;
  EXPECT_EQ(server->getPeerCertificate(), nullptr);

  // to prevent crash
  conn.serverHandshakeLayer = serverHandshakeLayer;
}

TEST_F(QuicServerTransportCertTest, TestGetSelfCertificate) {
  auto& conn = getFakeHandshakeLayer()->conn_;

  // have handshake layer, but no server cert
  EXPECT_NE(conn.serverHandshakeLayer, nullptr);
  EXPECT_EQ(server->getSelfCertificate(), nullptr);

  // have server cert
  auto mockCert = std::make_shared<MockCert>();
  const_cast<fizz::server::State&>(conn.serverHandshakeLayer->getState())
      .serverCert() = mockCert;
  EXPECT_EQ(server->getSelfCertificate(), mockCert);

  // no handshake layer
  auto* serverHandshakeLayer = conn.serverHandshakeLayer;
  conn.serverHandshakeLayer = nullptr;
  EXPECT_EQ(server->getSelfCertificate(), nullptr);

  // to prevent crash
  conn.serverHandshakeLayer = serverHandshakeLayer;
}

} // namespace quic::test
