/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <quic/api/QuicTransportFunctions.h>

#include <folly/io/async/test/MockAsyncUDPSocket.h>
#include <quic/api/test/Mocks.h>
#include <quic/common/test/TestUtils.h>
#include <quic/fizz/server/handshake/FizzServerQuicHandshakeContext.h>
#include <quic/logging/FileQLogger.h>
#include <quic/logging/QLoggerConstants.h>
#include <quic/server/state/ServerStateMachine.h>
#include <quic/state/test/MockQuicStats.h>
#include <quic/state/test/Mocks.h>

#include <gtest/gtest.h>

using namespace folly;
using namespace testing;

namespace quic {
namespace test {

using PacketStreamDetails = OutstandingPacketMetadata::StreamDetails;

uint64_t writeProbingDataToSocketForTest(
    folly::AsyncUDPSocket& sock,
    QuicConnectionStateBase& conn,
    uint8_t probesToSend,
    const Aead& aead,
    const PacketNumberCipher& headerCipher,
    QuicVersion version) {
  FrameScheduler scheduler = std::move(FrameScheduler::Builder(
                                           conn,
                                           EncryptionLevel::AppData,
                                           PacketNumberSpace::AppData,
                                           "test")
                                           .streamFrames()
                                           .cryptoFrames())
                                 .build();
  return writeProbingDataToSocket(
      sock,
      conn,
      *conn.clientConnectionId,
      *conn.serverConnectionId,
      ShortHeaderBuilder(),
      EncryptionLevel::AppData,
      PacketNumberSpace::AppData,
      scheduler,
      probesToSend,
      aead,
      headerCipher,
      version);
}

void writeCryptoDataProbesToSocketForTest(
    folly::AsyncUDPSocket& sock,
    QuicConnectionStateBase& conn,
    uint8_t probesToSend,
    const Aead& aead,
    const PacketNumberCipher& headerCipher,
    QuicVersion version,
    LongHeader::Types type = LongHeader::Types::Initial) {
  auto encryptionLevel =
      protectionTypeToEncryptionLevel(longHeaderTypeToProtectionType(type));
  auto pnSpace = LongHeader::typeToPacketNumberSpace(type);
  auto scheduler = std::move(FrameScheduler::Builder(
                                 conn, encryptionLevel, pnSpace, "Crypto")
                                 .cryptoFrames())
                       .build();
  writeProbingDataToSocket(
      sock,
      conn,
      *conn.clientConnectionId,
      *conn.serverConnectionId,
      LongHeaderBuilder(type),
      protectionTypeToEncryptionLevel(longHeaderTypeToProtectionType(type)),
      LongHeader::typeToPacketNumberSpace(type),
      scheduler,
      probesToSend,
      aead,
      headerCipher,
      version);
}

RegularQuicWritePacket stripPaddingFrames(RegularQuicWritePacket packet) {
  RegularQuicWritePacket::Vec trimmedFrames{};
  for (auto frame : packet.frames) {
    if (!frame.asPaddingFrame()) {
      trimmedFrames.push_back(frame);
    }
  }
  packet.frames = trimmedFrames;
  return packet;
}

auto buildEmptyPacket(
    QuicServerConnectionState& conn,
    PacketNumberSpace pnSpace,
    bool shortHeader = false) {
  folly::Optional<PacketHeader> header;
  if (shortHeader) {
    header = ShortHeader(
        ProtectionType::KeyPhaseZero,
        *conn.clientConnectionId,
        conn.ackStates.appDataAckState.nextPacketNum);
  } else {
    if (pnSpace == PacketNumberSpace::Initial) {
      header = LongHeader(
          LongHeader::Types::Initial,
          *conn.clientConnectionId,
          *conn.serverConnectionId,
          conn.ackStates.initialAckState.nextPacketNum,
          *conn.version);
    } else if (pnSpace == PacketNumberSpace::Handshake) {
      header = LongHeader(
          LongHeader::Types::Handshake,
          *conn.clientConnectionId,
          *conn.serverConnectionId,
          conn.ackStates.handshakeAckState.nextPacketNum,
          *conn.version);
    } else if (pnSpace == PacketNumberSpace::AppData) {
      header = LongHeader(
          LongHeader::Types::ZeroRtt,
          *conn.clientConnectionId,
          *conn.serverConnectionId,
          conn.ackStates.appDataAckState.nextPacketNum,
          *conn.version);
    }
  }
  RegularQuicPacketBuilder builder(
      conn.udpSendPacketLen,
      std::move(*header),
      getAckState(conn, pnSpace).largestAckedByPeer.value_or(0));
  builder.encodePacketHeader();
  DCHECK(builder.canBuildPacket());
  return std::move(builder).buildPacket();
}

uint64_t getEncodedSize(const RegularQuicPacketBuilder::Packet& packet) {
  // calculate size as the plaintext size
  uint32_t encodedSize = 0;
  if (packet.header) {
    encodedSize += packet.header->computeChainDataLength();
  }
  if (packet.body) {
    encodedSize += packet.body->computeChainDataLength();
  }
  return encodedSize;
}

uint64_t getEncodedBodySize(const RegularQuicPacketBuilder::Packet& packet) {
  // calculate size as the plaintext size
  uint32_t encodedBodySize = 0;
  if (packet.body) {
    encodedBodySize += packet.body->computeChainDataLength();
  }
  return encodedBodySize;
}

class QuicTransportFunctionsTest : public Test {
 public:
  void SetUp() override {
    aead = test::createNoOpAead();
    headerCipher = test::createNoOpHeaderCipher();
    quicStats_ = std::make_unique<NiceMock<MockQuicStats>>();
  }

  std::unique_ptr<QuicServerConnectionState> createConn() {
    auto conn = std::make_unique<QuicServerConnectionState>(
        FizzServerQuicHandshakeContext::Builder().build());
    conn->serverConnectionId = getTestConnectionId();
    conn->clientConnectionId = getTestConnectionId();
    conn->version = QuicVersion::MVFST;
    conn->flowControlState.peerAdvertisedInitialMaxStreamOffsetBidiLocal =
        kDefaultStreamWindowSize * 1000;
    conn->flowControlState.peerAdvertisedInitialMaxStreamOffsetBidiRemote =
        kDefaultStreamWindowSize * 1000;
    conn->flowControlState.peerAdvertisedInitialMaxStreamOffsetUni =
        kDefaultStreamWindowSize * 1000;
    conn->flowControlState.peerAdvertisedMaxOffset =
        kDefaultConnectionWindowSize * 1000;
    conn->statsCallback = quicStats_.get();
    conn->initialWriteCipher = createNoOpAead();
    conn->initialHeaderCipher = createNoOpHeaderCipher();
    conn->streamManager->setMaxLocalBidirectionalStreams(
        kDefaultMaxStreamsBidirectional);
    conn->streamManager->setMaxLocalUnidirectionalStreams(
        kDefaultMaxStreamsUnidirectional);
    return conn;
  }

  QuicVersion getVersion(QuicServerConnectionState& conn) {
    return conn.version.value_or(*conn.originalVersion);
  }

  std::unique_ptr<Aead> aead;
  std::unique_ptr<PacketNumberCipher> headerCipher;
  std::unique_ptr<MockQuicStats> quicStats_;
};

TEST_F(QuicTransportFunctionsTest, PingPacketGoesToOPList) {
  auto conn = createConn();
  auto packet = buildEmptyPacket(*conn, PacketNumberSpace::AppData);
  packet.packet.frames.push_back(PingFrame());
  EXPECT_EQ(0, conn->outstandings.packets.size());
  updateConnection(
      *conn,
      folly::none,
      packet.packet,
      Clock::now(),
      50,
      0,
      false /* isDSRPacket */);
  EXPECT_EQ(1, conn->outstandings.packets.size());
  // But it won't set loss detection alarm
  EXPECT_FALSE(conn->pendingEvents.setLossDetectionAlarm);
}

TEST_F(QuicTransportFunctionsTest, TestUpdateConnection) {
  auto conn = createConn();
  auto mockCongestionController =
      std::make_unique<NiceMock<MockCongestionController>>();
  auto rawCongestionController = mockCongestionController.get();
  conn->congestionController = std::move(mockCongestionController);
  conn->qLogger = std::make_shared<quic::FileQLogger>(VantagePoint::Client);
  // Builds a fake packet to test with.
  auto packet = buildEmptyPacket(*conn, PacketNumberSpace::Handshake);

  auto stream1Id =
      conn->streamManager->createNextBidirectionalStream().value()->id;
  auto stream2Id =
      conn->streamManager->createNextBidirectionalStream().value()->id;
  auto stream1 = conn->streamManager->findStream(stream1Id);
  auto stream2 = conn->streamManager->findStream(stream2Id);

  auto buf = IOBuf::copyBuffer("hey whats up");
  EXPECT_CALL(*quicStats_, onPacketRetransmission()).Times(2);
  writeDataToQuicStream(*stream1, buf->clone(), true);
  writeDataToQuicStream(*stream2, buf->clone(), true);

  WriteStreamFrame writeStreamFrame1(stream1->id, 0, 5, false);
  WriteStreamFrame writeStreamFrame2(stream2->id, 0, 12, true);
  packet.packet.frames.push_back(std::move(writeStreamFrame1));
  packet.packet.frames.push_back(std::move(writeStreamFrame2));

  auto currentNextInitialPacketNum =
      conn->ackStates.initialAckState.nextPacketNum;
  auto currentNextHandshakePacketNum =
      conn->ackStates.handshakeAckState.nextPacketNum;
  auto currentNextAppDataPacketNum =
      conn->ackStates.appDataAckState.nextPacketNum;
  EXPECT_CALL(*rawCongestionController, onPacketSent(_)).Times(1);
  EXPECT_CALL(*rawCongestionController, isAppLimited())
      .Times(1)
      .WillOnce(Return(true));
  updateConnection(
      *conn,
      folly::none,
      packet.packet,
      TimePoint{},
      getEncodedSize(packet),
      getEncodedBodySize(packet),
      false /* isDSRPacket */);

  EXPECT_EQ(
      conn->ackStates.initialAckState.nextPacketNum,
      currentNextInitialPacketNum);
  EXPECT_GT(
      conn->ackStates.handshakeAckState.nextPacketNum,
      currentNextHandshakePacketNum);
  EXPECT_EQ(
      conn->ackStates.appDataAckState.nextPacketNum,
      currentNextAppDataPacketNum);
  EXPECT_TRUE(conn->outstandings.packets.back().isAppLimited);

  EXPECT_EQ(stream1->currentWriteOffset, 5);
  EXPECT_EQ(stream2->currentWriteOffset, 13);
  EXPECT_EQ(conn->flowControlState.sumCurWriteOffset, 17);

  IOBufEqualTo eq;

  EXPECT_EQ(stream1->retransmissionBuffer.size(), 1);
  auto& rt1 = *stream1->retransmissionBuffer.at(0);
  EXPECT_EQ(rt1.offset, 0);
  EXPECT_TRUE(eq(*IOBuf::copyBuffer("hey w"), *rt1.data.front()));

  EXPECT_EQ(stream2->retransmissionBuffer.size(), 1);
  auto& rt2 = *stream2->retransmissionBuffer.at(0);
  EXPECT_EQ(rt2.offset, 0);
  EXPECT_TRUE(eq(*buf, *rt2.data.front()));
  EXPECT_TRUE(rt2.eof);

  // Testing retransmission
  stream1->lossBuffer.push_back(std::move(rt1));
  stream1->retransmissionBuffer.clear();
  stream2->lossBuffer.push_back(std::move(rt2));
  stream2->retransmissionBuffer.clear();
  conn->streamManager->addLoss(stream1->id);
  conn->streamManager->addLoss(stream2->id);

  // Write the remainder of the data with retransmission
  auto packet2 = buildEmptyPacket(*conn, PacketNumberSpace::Handshake);
  WriteStreamFrame writeStreamFrame3(stream1->id, 5, 7, true);
  WriteStreamFrame writeStreamFrame4(stream1->id, 0, 5, false);
  WriteStreamFrame writeStreamFrame5(stream2->id, 0, 6, false);
  packet2.packet.frames.push_back(std::move(writeStreamFrame3));
  packet2.packet.frames.push_back(std::move(writeStreamFrame4));
  packet2.packet.frames.push_back(std::move(writeStreamFrame5));

  EXPECT_CALL(*rawCongestionController, onPacketSent(_)).Times(1);
  currentNextInitialPacketNum = conn->ackStates.initialAckState.nextPacketNum;
  currentNextHandshakePacketNum =
      conn->ackStates.handshakeAckState.nextPacketNum;
  currentNextAppDataPacketNum = conn->ackStates.appDataAckState.nextPacketNum;
  EXPECT_CALL(*rawCongestionController, isAppLimited())
      .Times(1)
      .WillOnce(Return(false));
  updateConnection(
      *conn,
      folly::none,
      packet2.packet,
      TimePoint(),
      getEncodedSize(packet2),
      getEncodedBodySize(packet2),
      false /* isDSRPacket */);
  EXPECT_EQ(
      conn->ackStates.initialAckState.nextPacketNum,
      currentNextInitialPacketNum);
  EXPECT_GT(
      conn->ackStates.handshakeAckState.nextPacketNum,
      currentNextHandshakePacketNum);
  EXPECT_EQ(
      conn->ackStates.appDataAckState.nextPacketNum,
      currentNextAppDataPacketNum);
  EXPECT_FALSE(conn->outstandings.packets.back().isAppLimited);

  EXPECT_EQ(stream1->currentWriteOffset, 13);
  EXPECT_EQ(stream2->currentWriteOffset, 13);
  EXPECT_EQ(conn->flowControlState.sumCurWriteOffset, 24);

  EXPECT_EQ(stream1->lossBuffer.size(), 0);
  EXPECT_EQ(stream1->retransmissionBuffer.size(), 2);
  auto& rt3 = *stream1->retransmissionBuffer.at(5);
  EXPECT_TRUE(eq(IOBuf::copyBuffer("hats up"), rt3.data.move()));

  auto& rt4 = *stream1->retransmissionBuffer.at(0);
  EXPECT_TRUE(eq(*IOBuf::copyBuffer("hey w"), *rt4.data.front()));

  // loss buffer should be split into 2. Part in retransmission buffer and
  // part remains in loss buffer.
  EXPECT_EQ(stream2->lossBuffer.size(), 1);
  EXPECT_EQ(stream2->retransmissionBuffer.size(), 1);
  auto& rt5 = *stream2->retransmissionBuffer.at(0);
  EXPECT_TRUE(eq(*IOBuf::copyBuffer("hey wh"), *rt5.data.front()));
  EXPECT_EQ(rt5.offset, 0);
  EXPECT_EQ(rt5.eof, 0);

  auto& rt6 = stream2->lossBuffer.front();
  EXPECT_TRUE(eq(*IOBuf::copyBuffer("ats up"), *rt6.data.front()));
  EXPECT_EQ(rt6.offset, 6);
  EXPECT_EQ(rt6.eof, 1);

  // verify handshake packets stored in QLogger
  std::shared_ptr<quic::FileQLogger> qLogger =
      std::dynamic_pointer_cast<quic::FileQLogger>(conn->qLogger);
  std::vector<int> indices =
      getQLogEventIndices(QLogEventType::PacketSent, qLogger);
  EXPECT_EQ(indices.size(), 2);

  for (int i = 0; i < 2; ++i) {
    auto p1 = std::move(qLogger->logs[indices[i]]);
    auto event = dynamic_cast<QLogPacketEvent*>(p1.get());
    EXPECT_EQ(event->packetType, toQlogString(LongHeader::Types::Handshake));
    EXPECT_EQ(event->packetSize, getEncodedSize(packet));
    EXPECT_EQ(event->eventType, QLogEventType::PacketSent);

    if (i == 0) {
      EXPECT_EQ(event->frames.size(), 2);
      auto frame = static_cast<StreamFrameLog*>(event->frames[0].get());
      EXPECT_EQ(frame->streamId, stream1->id);
      EXPECT_EQ(frame->offset, 0);
      EXPECT_EQ(frame->len, 5);
      EXPECT_FALSE(frame->fin);
    } else if (i == 1) {
      EXPECT_EQ(event->frames.size(), 3);
      auto frame = static_cast<StreamFrameLog*>(event->frames[0].get());
      EXPECT_EQ(frame->streamId, stream1->id);
      EXPECT_EQ(frame->offset, 5);
      EXPECT_EQ(frame->len, 7);
      EXPECT_TRUE(frame->fin);
    }
  }
}

TEST_F(QuicTransportFunctionsTest, TestUpdateConnectionPacketRetrans) {
  const IOBufEqualTo eq;

  auto conn = createConn();
  auto mockCongestionController =
      std::make_unique<NiceMock<MockCongestionController>>();
  auto rawCongestionController = mockCongestionController.get();
  conn->congestionController = std::move(mockCongestionController);
  conn->qLogger = std::make_shared<quic::FileQLogger>(VantagePoint::Client);

  // two streams, both writing "hey whats up"
  auto stream1Id =
      conn->streamManager->createNextBidirectionalStream().value()->id;
  auto stream2Id =
      conn->streamManager->createNextBidirectionalStream().value()->id;
  auto stream1 = conn->streamManager->findStream(stream1Id);
  auto stream2 = conn->streamManager->findStream(stream2Id);
  auto buf = IOBuf::copyBuffer("hey whats up");
  writeDataToQuicStream(*stream1, buf->clone(), true /* eof */);
  writeDataToQuicStream(*stream2, buf->clone(), true /* eof */);
  WriteStreamFrame writeStreamFrame1(stream1->id, 0, 12, true /* eom */);
  WriteStreamFrame writeStreamFrame2(stream2->id, 0, 12, true /* eom */);
  EXPECT_EQ(stream1->currentWriteOffset, 0);
  EXPECT_EQ(stream2->currentWriteOffset, 0);
  EXPECT_EQ(conn->flowControlState.sumCurWriteOffset, 0);

  // add both stream frames into AppData packet1
  auto packet1 = buildEmptyPacket(*conn, PacketNumberSpace::AppData);
  packet1.packet.frames.push_back(writeStreamFrame1);
  packet1.packet.frames.push_back(writeStreamFrame2);

  // mimic send, call updateConnection
  auto currentNextInitialPacketNum =
      conn->ackStates.initialAckState.nextPacketNum;
  auto currentNextHandshakePacketNum =
      conn->ackStates.handshakeAckState.nextPacketNum;
  auto currentNextAppDataPacketNum =
      conn->ackStates.appDataAckState.nextPacketNum;
  EXPECT_CALL(*rawCongestionController, onPacketSent(_)).Times(1);
  EXPECT_CALL(*rawCongestionController, isAppLimited())
      .Times(1)
      .WillOnce(Return(true));
  updateConnection(
      *conn,
      folly::none,
      packet1.packet,
      TimePoint{},
      getEncodedSize(packet1),
      getEncodedBodySize(packet1),
      false /* isDSRPacket */);

  // appData packet number should increase
  EXPECT_EQ(
      conn->ackStates.initialAckState.nextPacketNum,
      currentNextInitialPacketNum); // no change
  EXPECT_EQ(
      conn->ackStates.handshakeAckState.nextPacketNum,
      currentNextHandshakePacketNum); // no change
  EXPECT_GT(
      conn->ackStates.appDataAckState.nextPacketNum,
      currentNextAppDataPacketNum); // increased
  EXPECT_TRUE(conn->outstandings.packets.back().isAppLimited);

  // offsets should be 13 (len + EOF) and 24 (bytes without EOF)
  EXPECT_EQ(stream1->currentWriteOffset, 13); // len (12) + EOF (1)
  EXPECT_EQ(stream2->currentWriteOffset, 13); // len (12) + EOF (1)
  EXPECT_EQ(conn->flowControlState.sumCurWriteOffset, 24); // sum(len)

  // verify retransmission buffer and mark stream bytes in packet1 lost
  {
    ASSERT_EQ(stream1->retransmissionBuffer.size(), 1);
    auto& rt = *stream1->retransmissionBuffer.at(0);
    EXPECT_EQ(rt.offset, 0);
    EXPECT_TRUE(eq(*buf, *rt.data.front()));
    EXPECT_TRUE(rt.eof);
    stream1->lossBuffer.push_back(std::move(rt));
  }
  {
    ASSERT_EQ(stream2->retransmissionBuffer.size(), 1);
    auto& rt = *stream2->retransmissionBuffer.at(0);
    EXPECT_EQ(rt.offset, 0);
    EXPECT_TRUE(eq(*buf, *rt.data.front()));
    EXPECT_TRUE(rt.eof);
    stream2->lossBuffer.push_back(std::move(rt));
  }
  stream1->retransmissionBuffer.clear();
  stream2->retransmissionBuffer.clear();
  conn->streamManager->addLoss(stream1->id);
  conn->streamManager->addLoss(stream2->id);

  // retransmit the lost frames in AppData packet2
  auto packet2 = buildEmptyPacket(*conn, PacketNumberSpace::AppData);
  packet2.packet.frames.push_back(writeStreamFrame1);
  packet2.packet.frames.push_back(writeStreamFrame2);

  // mimic send, call updateConnection
  EXPECT_CALL(*rawCongestionController, onPacketSent(_)).Times(1);
  currentNextInitialPacketNum = conn->ackStates.initialAckState.nextPacketNum;
  currentNextHandshakePacketNum =
      conn->ackStates.handshakeAckState.nextPacketNum;
  currentNextAppDataPacketNum = conn->ackStates.appDataAckState.nextPacketNum;
  EXPECT_CALL(*rawCongestionController, isAppLimited())
      .Times(1)
      .WillOnce(Return(false));
  updateConnection(
      *conn,
      folly::none,
      packet2.packet,
      TimePoint(),
      getEncodedSize(packet2),
      getEncodedBodySize(packet2),
      false /* isDSRPacket */);
  EXPECT_EQ(
      conn->ackStates.initialAckState.nextPacketNum,
      currentNextInitialPacketNum); // no change
  EXPECT_EQ(
      conn->ackStates.handshakeAckState.nextPacketNum,
      currentNextHandshakePacketNum); // no change
  EXPECT_GT(
      conn->ackStates.appDataAckState.nextPacketNum,
      currentNextAppDataPacketNum); // increased
  EXPECT_FALSE(conn->outstandings.packets.back().isAppLimited);

  // since retransmission with no new data, no change in offsets
  EXPECT_EQ(stream1->currentWriteOffset, 13); // len (12) + EOF (1)
  EXPECT_EQ(stream2->currentWriteOffset, 13); // len (12) + EOF (1)
  EXPECT_EQ(conn->flowControlState.sumCurWriteOffset, 24); // sum(len)

  // check loss state
  CHECK_EQ(
      conn->lossState.totalBytesSent,
      getEncodedSize(packet1) + getEncodedSize(packet2));
  CHECK_EQ(
      conn->lossState.totalBodyBytesSent,
      getEncodedBodySize(packet1) + getEncodedBodySize(packet2));
  CHECK_EQ(conn->lossState.totalPacketsSent, 2);

  // totalStreamBytesSent:
  //   the first packet contained 12 + 12
  //   the second packet contained 12 + 12
  //   total = 48
  EXPECT_EQ(conn->lossState.totalStreamBytesSent, 48); // sum(len)

  // totalNewStreamBytesSent: just sum(len)
  EXPECT_EQ(conn->lossState.totalNewStreamBytesSent, 24);
  EXPECT_EQ(
      conn->lossState.totalNewStreamBytesSent,
      conn->flowControlState.sumCurWriteOffset);
}

TEST_F(
    QuicTransportFunctionsTest,
    TestUpdateConnectionPacketRetransWithNewData) {
  const IOBufEqualTo eq;

  auto conn = createConn();
  auto mockCongestionController =
      std::make_unique<NiceMock<MockCongestionController>>();
  auto rawCongestionController = mockCongestionController.get();
  conn->congestionController = std::move(mockCongestionController);
  conn->qLogger = std::make_shared<quic::FileQLogger>(VantagePoint::Client);

  // three streams, all writing "hey whats up"
  //
  // streams1 and 2 EOF after writing buffer, stream3 does not
  //
  // frames:
  //   stream1,frame1 contains the entire string with EOM
  //   stream2,frame1 contains "hey w", and thus no EOM
  //   stream3,frame1 contains the entire string, but no EOM given no EOF yet
  //
  // we'll write additional data to stream3 later
  auto stream1Id =
      conn->streamManager->createNextBidirectionalStream().value()->id;
  auto stream2Id =
      conn->streamManager->createNextBidirectionalStream().value()->id;
  auto stream3Id =
      conn->streamManager->createNextBidirectionalStream().value()->id;
  auto stream1 = conn->streamManager->findStream(stream1Id);
  auto stream2 = conn->streamManager->findStream(stream2Id);
  auto stream3 = conn->streamManager->findStream(stream3Id);
  auto buf = IOBuf::copyBuffer("hey whats up");
  writeDataToQuicStream(*stream1, buf->clone(), true /* eof */);
  writeDataToQuicStream(*stream2, buf->clone(), true /* eof */);
  writeDataToQuicStream(*stream3, buf->clone(), false /* eof */);
  WriteStreamFrame writeStreamFrame1(stream1->id, 0, 12, true /* eom */);
  WriteStreamFrame writeStreamFrame2(stream2->id, 0, 5, false /* eom */);
  WriteStreamFrame writeStreamFrame3(stream3->id, 0, 12, false /* eom */);
  EXPECT_EQ(stream1->currentWriteOffset, 0);
  EXPECT_EQ(stream2->currentWriteOffset, 0);
  EXPECT_EQ(stream3->currentWriteOffset, 0);
  EXPECT_EQ(conn->flowControlState.sumCurWriteOffset, 0);

  // add all stream frames into AppData packet1
  auto packet1 = buildEmptyPacket(*conn, PacketNumberSpace::AppData);
  packet1.packet.frames.push_back(writeStreamFrame1);
  packet1.packet.frames.push_back(writeStreamFrame2);
  packet1.packet.frames.push_back(writeStreamFrame3);

  // mimic send, call updateConnection
  auto currentNextInitialPacketNum =
      conn->ackStates.initialAckState.nextPacketNum;
  auto currentNextHandshakePacketNum =
      conn->ackStates.handshakeAckState.nextPacketNum;
  auto currentNextAppDataPacketNum =
      conn->ackStates.appDataAckState.nextPacketNum;
  EXPECT_CALL(*rawCongestionController, onPacketSent(_)).Times(1);
  EXPECT_CALL(*rawCongestionController, isAppLimited())
      .Times(1)
      .WillOnce(Return(true));
  updateConnection(
      *conn,
      folly::none,
      packet1.packet,
      TimePoint{},
      getEncodedSize(packet1),
      getEncodedBodySize(packet1),
      false /* isDSRPacket */);

  // appData packet number should increase
  EXPECT_EQ(
      conn->ackStates.initialAckState.nextPacketNum,
      currentNextInitialPacketNum); // no change
  EXPECT_EQ(
      conn->ackStates.handshakeAckState.nextPacketNum,
      currentNextHandshakePacketNum); // no change
  EXPECT_GT(
      conn->ackStates.appDataAckState.nextPacketNum,
      currentNextAppDataPacketNum); // increased
  EXPECT_TRUE(conn->outstandings.packets.back().isAppLimited);

  // check offsets
  EXPECT_EQ(stream1->currentWriteOffset, 13); // len (12) + EOF (1)
  EXPECT_EQ(stream2->currentWriteOffset, 5); // len (5)
  EXPECT_EQ(stream3->currentWriteOffset, 12); // len (12)
  EXPECT_EQ(conn->flowControlState.sumCurWriteOffset, 29); // sum(len)

  // verify retransmission buffer and mark stream bytes in packet1 lost
  {
    ASSERT_EQ(stream1->retransmissionBuffer.size(), 1);
    auto& rt = *stream1->retransmissionBuffer.at(0);
    EXPECT_EQ(rt.offset, 0);
    EXPECT_TRUE(eq(*buf, *rt.data.front()));
    EXPECT_TRUE(rt.eof);
    stream1->lossBuffer.push_back(std::move(rt));
  }
  {
    ASSERT_EQ(stream2->retransmissionBuffer.size(), 1);
    auto& rt = *stream2->retransmissionBuffer.at(0);
    EXPECT_EQ(rt.offset, 0);
    EXPECT_TRUE(eq(*IOBuf::copyBuffer("hey w"), *rt.data.front()));
    EXPECT_FALSE(rt.eof);
    stream2->lossBuffer.push_back(std::move(rt));
  }
  {
    ASSERT_EQ(stream3->retransmissionBuffer.size(), 1);
    auto& rt = *stream3->retransmissionBuffer.at(0);
    EXPECT_EQ(rt.offset, 0);
    EXPECT_TRUE(eq(*buf, *rt.data.front()));
    EXPECT_FALSE(rt.eof);
    stream3->lossBuffer.push_back(std::move(rt));
  }
  stream1->retransmissionBuffer.clear();
  stream2->retransmissionBuffer.clear();
  stream3->retransmissionBuffer.clear();
  conn->streamManager->addLoss(stream1->id);
  conn->streamManager->addLoss(stream2->id);
  conn->streamManager->addLoss(stream3->id);

  // add some additional data
  // write a "?" to stream3 and set eof
  auto buf2 = IOBuf::copyBuffer("?");
  writeDataToQuicStream(*stream3, buf->clone(), true /* eof */);

  // packet2 contains orignally transmitted frames + new data frames
  auto packet2 = buildEmptyPacket(*conn, PacketNumberSpace::AppData);
  packet2.packet.frames.push_back(writeStreamFrame1);
  packet2.packet.frames.push_back(writeStreamFrame2);
  packet2.packet.frames.push_back(writeStreamFrame3);
  packet2.packet.frames.push_back(WriteStreamFrame(
      stream2->id, 5 /* offset */, 7 /* len */, true /* eom */));
  packet2.packet.frames.push_back(WriteStreamFrame(
      stream3->id, 12 /* offset */, 1 /* len */, true /* eom */));

  // mimic send, call updateConnection
  EXPECT_CALL(*rawCongestionController, onPacketSent(_)).Times(1);
  currentNextInitialPacketNum = conn->ackStates.initialAckState.nextPacketNum;
  currentNextHandshakePacketNum =
      conn->ackStates.handshakeAckState.nextPacketNum;
  currentNextAppDataPacketNum = conn->ackStates.appDataAckState.nextPacketNum;
  EXPECT_CALL(*rawCongestionController, isAppLimited())
      .Times(1)
      .WillOnce(Return(false));
  updateConnection(
      *conn,
      folly::none,
      packet2.packet,
      TimePoint(),
      getEncodedSize(packet2),
      getEncodedBodySize(packet2),
      false /* isDSRPacket */);
  EXPECT_EQ(
      conn->ackStates.initialAckState.nextPacketNum,
      currentNextInitialPacketNum); // no change
  EXPECT_EQ(
      conn->ackStates.handshakeAckState.nextPacketNum,
      currentNextHandshakePacketNum); // no change
  EXPECT_GT(
      conn->ackStates.appDataAckState.nextPacketNum,
      currentNextAppDataPacketNum); // increased
  EXPECT_FALSE(conn->outstandings.packets.back().isAppLimited);

  // check offsets
  EXPECT_EQ(stream1->currentWriteOffset, 13); // len (12) + EOF (1)
  EXPECT_EQ(stream2->currentWriteOffset, 13); // len (12) + EOF (1)
  EXPECT_EQ(stream3->currentWriteOffset, 14); // len (13) + EOF (1)
  EXPECT_EQ(conn->flowControlState.sumCurWriteOffset, 37); // sum(len)

  // check loss state
  CHECK_EQ(
      conn->lossState.totalBytesSent,
      getEncodedSize(packet1) + getEncodedSize(packet2));
  CHECK_EQ(
      conn->lossState.totalBodyBytesSent,
      getEncodedBodySize(packet1) + getEncodedBodySize(packet2));
  CHECK_EQ(conn->lossState.totalPacketsSent, 2);

  // totalStreamBytesSent:
  //   the first packet contained 12 + 5 + 12 stream bytes
  //   the second packet contained 12 + 12 + 13 stream bytes
  //   total = 66
  EXPECT_EQ(conn->lossState.totalStreamBytesSent, 66); // sum(len)

  // totalNewStreamBytesSent: just sum(len)
  EXPECT_EQ(conn->lossState.totalNewStreamBytesSent, 37);
  EXPECT_EQ(
      conn->lossState.totalNewStreamBytesSent,
      conn->flowControlState.sumCurWriteOffset);
}

TEST_F(QuicTransportFunctionsTest, TestUpdateConnectionD6DNotConsumeSendPing) {
  auto conn = createConn();
  conn->pendingEvents.sendPing = true; // Simulate application sendPing()
  auto packet = buildEmptyPacket(*conn, PacketNumberSpace::AppData);
  packet.packet.frames.push_back(PingFrame());
  auto packetNum = packet.packet.header.getPacketSequenceNum();
  conn->d6d.lastProbe = D6DProbePacket(packetNum, 50);
  updateConnection(
      *conn,
      folly::none,
      packet.packet,
      Clock::now(),
      50,
      0,
      false /* isDSRPacket */);
  EXPECT_EQ(1, conn->outstandings.packets.size());
  EXPECT_TRUE(conn->outstandings.packets.front().metadata.isD6DProbe);
  EXPECT_EQ(1, conn->d6d.outstandingProbes);
  // sendPing should still be active since d6d probe should be "hidden" from
  // application
  EXPECT_TRUE(conn->pendingEvents.sendPing);
}

TEST_F(QuicTransportFunctionsTest, TestUpdateConnectionD6DNeedsAppDataPNSpace) {
  auto conn = createConn();
  auto packet = buildEmptyPacket(*conn, PacketNumberSpace::Handshake);
  packet.packet.frames.push_back(PingFrame());
  auto packetNum = packet.packet.header.getPacketSequenceNum();
  conn->d6d.lastProbe = D6DProbePacket(packetNum, 50);
  updateConnection(
      *conn,
      folly::none,
      packet.packet,
      Clock::now(),
      50,
      0,
      false /* isDSRPacket */);
  EXPECT_EQ(1, conn->outstandings.packets.size());
  EXPECT_FALSE(conn->outstandings.packets.front().metadata.isD6DProbe);
  EXPECT_EQ(0, conn->d6d.outstandingProbes);
}

TEST_F(QuicTransportFunctionsTest, TestUpdateConnectionPacketSorting) {
  auto conn = createConn();
  conn->qLogger = std::make_shared<quic::FileQLogger>(VantagePoint::Client);
  conn->ackStates.initialAckState.nextPacketNum = 0;
  conn->ackStates.handshakeAckState.nextPacketNum = 1;
  conn->ackStates.appDataAckState.nextPacketNum = 2;
  auto initialPacket = buildEmptyPacket(*conn, PacketNumberSpace::Initial);
  auto handshakePacket = buildEmptyPacket(*conn, PacketNumberSpace::Handshake);
  auto appDataPacket = buildEmptyPacket(*conn, PacketNumberSpace::AppData);

  auto stream = conn->streamManager->createNextBidirectionalStream().value();
  writeDataToQuicStream(
      *stream,
      folly::IOBuf::copyBuffer("The sun is cold and the rain is hard."),
      true);
  WriteStreamFrame writeStreamFrame(stream->id, 0, 5, false);
  initialPacket.packet.frames.push_back(writeStreamFrame);
  handshakePacket.packet.frames.push_back(writeStreamFrame);
  appDataPacket.packet.frames.push_back(writeStreamFrame);

  updateConnection(
      *conn,
      folly::none,
      handshakePacket.packet,
      TimePoint{},
      getEncodedSize(handshakePacket),
      getEncodedBodySize(handshakePacket),
      false /* isDSRPacket */);
  updateConnection(
      *conn,
      folly::none,
      initialPacket.packet,
      TimePoint{},
      getEncodedSize(initialPacket),
      getEncodedBodySize(initialPacket),
      false /* isDSRPacket */);
  updateConnection(
      *conn,
      folly::none,
      appDataPacket.packet,
      TimePoint{},
      getEncodedSize(appDataPacket),
      getEncodedBodySize(appDataPacket),
      false /* isDSRPacket */);
  // verify qLogger added correct logs
  std::shared_ptr<quic::FileQLogger> qLogger =
      std::dynamic_pointer_cast<quic::FileQLogger>(conn->qLogger);
  std::vector<int> indices =
      getQLogEventIndices(QLogEventType::PacketSent, qLogger);
  EXPECT_EQ(indices.size(), 3);

  auto l1 = std::move(qLogger->logs[indices[0]]);
  auto l2 = std::move(qLogger->logs[indices[1]]);
  auto l3 = std::move(qLogger->logs[indices[2]]);
  auto event1 = dynamic_cast<QLogPacketEvent*>(l1.get());
  auto event2 = dynamic_cast<QLogPacketEvent*>(l2.get());
  auto event3 = dynamic_cast<QLogPacketEvent*>(l3.get());

  EXPECT_EQ(event1->packetType, toQlogString(LongHeader::Types::Handshake));
  EXPECT_EQ(event2->packetType, toQlogString(LongHeader::Types::Initial));
  EXPECT_EQ(event3->packetType, toQlogString(LongHeader::Types::ZeroRtt));

  EXPECT_EQ(3, conn->outstandings.packets.size());
  auto& firstHeader = conn->outstandings.packets.front().packet.header;
  auto firstPacketNum = firstHeader.getPacketSequenceNum();
  EXPECT_EQ(0, firstPacketNum);
  EXPECT_EQ(1, event1->packetNum);

  EXPECT_EQ(PacketNumberSpace::Initial, firstHeader.getPacketNumberSpace());

  auto& lastHeader = conn->outstandings.packets.back().packet.header;

  auto lastPacketNum = lastHeader.getPacketSequenceNum();

  EXPECT_EQ(2, lastPacketNum);
  EXPECT_EQ(2, event3->packetNum);

  EXPECT_EQ(PacketNumberSpace::AppData, lastHeader.getPacketNumberSpace());
}

TEST_F(QuicTransportFunctionsTest, TestUpdateConnectionFinOnly) {
  auto conn = createConn();
  conn->qLogger = std::make_shared<quic::FileQLogger>(VantagePoint::Client);
  auto packet = buildEmptyPacket(*conn, PacketNumberSpace::Handshake);
  auto stream1 = conn->streamManager->createNextBidirectionalStream().value();

  writeDataToQuicStream(*stream1, nullptr, true);
  packet.packet.frames.push_back(WriteStreamFrame(stream1->id, 0, 0, true));
  updateConnection(
      *conn,
      folly::none,
      packet.packet,
      TimePoint(),
      getEncodedSize(packet),
      getEncodedBodySize(packet),
      false /* isDSRPacket */);

  // verify QLogger contains correct packet information
  std::shared_ptr<quic::FileQLogger> qLogger =
      std::dynamic_pointer_cast<quic::FileQLogger>(conn->qLogger);
  std::vector<int> indices =
      getQLogEventIndices(QLogEventType::PacketSent, qLogger);
  EXPECT_EQ(indices.size(), 1);
  auto tmp = std::move(qLogger->logs[indices[0]]);

  auto event = dynamic_cast<QLogPacketEvent*>(tmp.get());
  EXPECT_EQ(event->packetType, toQlogString(LongHeader::Types::Handshake));
  EXPECT_EQ(event->packetSize, getEncodedSize(packet));
  EXPECT_EQ(event->eventType, QLogEventType::PacketSent);

  // verify QLogger contains correct frame information
  EXPECT_EQ(event->frames.size(), 1);
  auto frame = static_cast<StreamFrameLog*>(event->frames[0].get());
  EXPECT_EQ(frame->streamId, stream1->id);
  EXPECT_EQ(frame->offset, 0);
  EXPECT_EQ(frame->len, 0);
  EXPECT_TRUE(frame->fin);

  EXPECT_EQ(stream1->retransmissionBuffer.size(), 1);
  auto& rt1 = *stream1->retransmissionBuffer.at(0);

  EXPECT_EQ(stream1->currentWriteOffset, 1);
  EXPECT_EQ(rt1.offset, 0);
  EXPECT_EQ(rt1.data.front()->computeChainDataLength(), 0);
  EXPECT_TRUE(rt1.eof);
}

TEST_F(QuicTransportFunctionsTest, TestUpdateConnectionAllBytesExceptFin) {
  auto conn = createConn();
  conn->qLogger = std::make_shared<quic::FileQLogger>(VantagePoint::Client);
  auto packet = buildEmptyPacket(*conn, PacketNumberSpace::Handshake);

  auto stream1 = conn->streamManager->createNextUnidirectionalStream().value();

  auto buf = IOBuf::copyBuffer("Bluberries are purple");
  writeDataToQuicStream(*stream1, buf->clone(), true);

  packet.packet.frames.push_back(
      WriteStreamFrame(stream1->id, 0, buf->computeChainDataLength(), false));
  updateConnection(
      *conn,
      folly::none,
      packet.packet,
      TimePoint(),
      getEncodedSize(packet),
      getEncodedBodySize(packet),
      false /* isDSRPacket */);

  // verify QLogger contains correct packet information
  std::shared_ptr<quic::FileQLogger> qLogger =
      std::dynamic_pointer_cast<quic::FileQLogger>(conn->qLogger);
  std::vector<int> indices =
      getQLogEventIndices(QLogEventType::PacketSent, qLogger);
  EXPECT_EQ(indices.size(), 1);
  auto tmp = std::move(qLogger->logs[indices[0]]);
  auto event = dynamic_cast<QLogPacketEvent*>(tmp.get());

  EXPECT_EQ(event->packetType, toQlogString(LongHeader::Types::Handshake));
  EXPECT_EQ(event->packetSize, getEncodedSize(packet));
  EXPECT_EQ(event->eventType, QLogEventType::PacketSent);

  // verify QLogger contains correct frame information
  EXPECT_EQ(event->frames.size(), 1);
  auto frame = static_cast<StreamFrameLog*>(event->frames[0].get());
  EXPECT_EQ(frame->streamId, stream1->id);
  EXPECT_EQ(frame->offset, 0);
  EXPECT_EQ(frame->len, buf->computeChainDataLength());
  EXPECT_FALSE(frame->fin);

  EXPECT_EQ(stream1->currentWriteOffset, buf->computeChainDataLength());

  EXPECT_EQ(stream1->retransmissionBuffer.size(), 1);
  auto& rt1 = *stream1->retransmissionBuffer.at(0);
  EXPECT_EQ(rt1.offset, 0);
  EXPECT_EQ(
      rt1.data.front()->computeChainDataLength(),
      buf->computeChainDataLength());
  EXPECT_FALSE(rt1.eof);
}

TEST_F(QuicTransportFunctionsTest, TestUpdateConnectionEmptyAckWriteResult) {
  auto conn = createConn();
  conn->qLogger = std::make_shared<quic::FileQLogger>(VantagePoint::Client);
  auto packet = buildEmptyPacket(*conn, PacketNumberSpace::Handshake);
  // None of the largestAckScheduled should be changed. But since
  // buildEmptyPacket() builds a Handshake packet, we use handshakeAckState to
  // verify.
  auto currentPendingLargestAckScheduled =
      conn->ackStates.handshakeAckState.largestAckScheduled;
  updateConnection(
      *conn,
      folly::none,
      packet.packet,
      TimePoint(),
      getEncodedSize(packet),
      getEncodedBodySize(packet),
      false /* isDSRPacket */);

  // verify QLogger contains correct packet information
  std::shared_ptr<quic::FileQLogger> qLogger =
      std::dynamic_pointer_cast<quic::FileQLogger>(conn->qLogger);
  std::vector<int> indices =
      getQLogEventIndices(QLogEventType::PacketSent, qLogger);
  EXPECT_EQ(indices.size(), 1);
  auto tmp = std::move(qLogger->logs[indices[0]]);
  auto event = dynamic_cast<QLogPacketEvent*>(tmp.get());
  EXPECT_EQ(event->packetType, toQlogString(LongHeader::Types::Handshake));
  EXPECT_EQ(event->packetSize, getEncodedSize(packet));
  EXPECT_EQ(event->eventType, QLogEventType::PacketSent);

  EXPECT_EQ(
      currentPendingLargestAckScheduled,
      conn->ackStates.handshakeAckState.largestAckScheduled);
}

TEST_F(QuicTransportFunctionsTest, TestUpdateConnectionPureAckCounter) {
  auto conn = createConn();
  conn->qLogger = std::make_shared<quic::FileQLogger>(VantagePoint::Client);
  auto stream = conn->streamManager->createNextBidirectionalStream().value();
  writeDataToQuicStream(*stream, nullptr, true);
  EXPECT_EQ(0, conn->outstandings.packetCount[PacketNumberSpace::Handshake]);

  auto packet = buildEmptyPacket(*conn, PacketNumberSpace::Handshake);
  auto packetEncodedSize =
      packet.header ? packet.header->computeChainDataLength() : 0;
  packetEncodedSize += packet.body ? packet.body->computeChainDataLength() : 0;

  WriteAckFrame ackFrame;
  ackFrame.ackBlocks.emplace_back(0, 100);
  packet.packet.frames.push_back(std::move(ackFrame));
  updateConnection(
      *conn,
      folly::none,
      packet.packet,
      TimePoint(),
      getEncodedSize(packet),
      getEncodedBodySize(packet),
      false /* isDSRPacket */);

  auto nonHandshake = buildEmptyPacket(*conn, PacketNumberSpace::Handshake);
  packetEncodedSize =
      nonHandshake.header ? nonHandshake.header->computeChainDataLength() : 0;
  packetEncodedSize +=
      nonHandshake.body ? nonHandshake.body->computeChainDataLength() : 0;
  auto stream1 = conn->streamManager->createNextBidirectionalStream().value();
  writeDataToQuicStream(*stream1, nullptr, true);

  conn->pendingEvents.resets.emplace(
      1, RstStreamFrame(1, GenericApplicationErrorCode::UNKNOWN, 0));
  auto packet2 = buildEmptyPacket(*conn, PacketNumberSpace::Handshake);
  RstStreamFrame rstFrame(1, GenericApplicationErrorCode::UNKNOWN, 0);
  packet2.packet.frames.push_back(std::move(rstFrame));

  updateConnection(
      *conn,
      folly::none,
      packet2.packet,
      TimePoint(),
      getEncodedSize(packet),
      getEncodedBodySize(packet),
      false /* isDSRPacket */);

  //  verify QLogger contains correct packet and frame information
  std::shared_ptr<quic::FileQLogger> qLogger =
      std::dynamic_pointer_cast<quic::FileQLogger>(conn->qLogger);
  std::vector<int> indices =
      getQLogEventIndices(QLogEventType::PacketSent, qLogger);
  EXPECT_EQ(indices.size(), 2);
  for (int i = 0; i < 2; ++i) {
    auto tmp = std::move(qLogger->logs[indices[i]]);
    auto event = dynamic_cast<QLogPacketEvent*>(tmp.get());
    EXPECT_EQ(event->packetType, toQlogString(LongHeader::Types::Handshake));
    EXPECT_EQ(event->packetSize, getEncodedSize(packet));
    EXPECT_EQ(event->frames.size(), 1);
  }
}

TEST_F(QuicTransportFunctionsTest, TestPaddingPureAckPacketIsStillPureAck) {
  auto conn = createConn();
  conn->qLogger = std::make_shared<quic::FileQLogger>(VantagePoint::Client);
  auto packet = buildEmptyPacket(*conn, PacketNumberSpace::Handshake);
  auto packetEncodedSize =
      packet.header ? packet.header->computeChainDataLength() : 0;
  packetEncodedSize += packet.body ? packet.body->computeChainDataLength() : 0;

  WriteAckFrame ackFrame;
  ackFrame.ackBlocks.emplace_back(0, 100);
  packet.packet.frames.push_back(std::move(ackFrame));
  packet.packet.frames.push_back(PaddingFrame());
  updateConnection(
      *conn,
      folly::none,
      packet.packet,
      TimePoint(),
      getEncodedSize(packet),
      getEncodedBodySize(packet),
      false /* isDSRPacket */);

  // verify QLogger contains correct packet and frames information
  std::shared_ptr<quic::FileQLogger> qLogger =
      std::dynamic_pointer_cast<quic::FileQLogger>(conn->qLogger);
  std::vector<int> indices =
      getQLogEventIndices(QLogEventType::PacketSent, qLogger);
  EXPECT_EQ(indices.size(), 1);
  auto tmp = std::move(qLogger->logs[indices[0]]);

  auto event = dynamic_cast<QLogPacketEvent*>(tmp.get());
  EXPECT_EQ(event->packetType, toQlogString(LongHeader::Types::Handshake));
  EXPECT_EQ(event->packetSize, getEncodedSize(packet));
  EXPECT_EQ(event->eventType, QLogEventType::PacketSent);
  EXPECT_EQ(event->frames.size(), 2);
}

TEST_F(QuicTransportFunctionsTest, TestImplicitAck) {
  auto conn = createConn();
  auto data = IOBuf::copyBuffer("totally real crypto data");
  data->coalesce();

  auto initialStream =
      getCryptoStream(*conn->cryptoState, EncryptionLevel::Initial);
  ASSERT_TRUE(initialStream->writeBuffer.empty());
  ASSERT_TRUE(initialStream->retransmissionBuffer.empty());
  ASSERT_TRUE(initialStream->lossBuffer.empty());
  auto packet = buildEmptyPacket(*conn, PacketNumberSpace::Initial);
  packet.packet.frames.push_back(WriteCryptoFrame(0, data->length()));
  initialStream->writeBuffer.append(data->clone());
  updateConnection(
      *conn,
      folly::none,
      packet.packet,
      TimePoint(),
      getEncodedSize(packet),
      getEncodedBodySize(packet),
      false /* isDSRPacket */);
  EXPECT_EQ(1, conn->outstandings.packetCount[PacketNumberSpace::Initial]);
  EXPECT_EQ(0, conn->outstandings.packetCount[PacketNumberSpace::Handshake]);
  EXPECT_EQ(1, conn->outstandings.packets.size());
  EXPECT_EQ(1, initialStream->retransmissionBuffer.size());

  packet = buildEmptyPacket(*conn, PacketNumberSpace::Initial);
  packet.packet.frames.push_back(
      WriteCryptoFrame(data->length(), data->length()));
  packet.packet.frames.push_back(
      WriteCryptoFrame(data->length() * 2, data->length()));
  initialStream->writeBuffer.append(data->clone());
  initialStream->writeBuffer.append(data->clone());
  updateConnection(
      *conn,
      folly::none,
      packet.packet,
      TimePoint(),
      getEncodedSize(packet),
      getEncodedBodySize(packet),
      false /* isDSRPacket */);
  EXPECT_EQ(2, conn->outstandings.packetCount[PacketNumberSpace::Initial]);
  EXPECT_EQ(0, conn->outstandings.packetCount[PacketNumberSpace::Handshake]);
  EXPECT_EQ(2, conn->outstandings.packets.size());
  EXPECT_EQ(3, initialStream->retransmissionBuffer.size());
  EXPECT_TRUE(initialStream->writeBuffer.empty());
  EXPECT_TRUE(initialStream->lossBuffer.empty());

  // Fake loss.
  Buf firstBuf =
      initialStream->retransmissionBuffer.find(0)->second->data.move();
  initialStream->retransmissionBuffer.erase(0);
  initialStream->lossBuffer.emplace_back(std::move(firstBuf), 0, false);
  conn->outstandings.packets.pop_front();
  conn->outstandings.packetCount[PacketNumberSpace::Initial]--;

  auto handshakeStream =
      getCryptoStream(*conn->cryptoState, EncryptionLevel::Handshake);
  ASSERT_TRUE(handshakeStream->writeBuffer.empty());
  ASSERT_TRUE(handshakeStream->retransmissionBuffer.empty());
  ASSERT_TRUE(handshakeStream->lossBuffer.empty());
  packet = buildEmptyPacket(*conn, PacketNumberSpace::Handshake);
  packet.packet.frames.push_back(WriteCryptoFrame(0, data->length()));
  handshakeStream->writeBuffer.append(data->clone());
  updateConnection(
      *conn,
      folly::none,
      packet.packet,
      TimePoint(),
      getEncodedSize(packet),
      getEncodedBodySize(packet),
      false /* isDSRPacket */);
  EXPECT_EQ(1, conn->outstandings.packetCount[PacketNumberSpace::Initial]);
  EXPECT_EQ(1, conn->outstandings.packetCount[PacketNumberSpace::Handshake]);
  EXPECT_EQ(2, conn->outstandings.packets.size());
  EXPECT_EQ(1, handshakeStream->retransmissionBuffer.size());

  packet = buildEmptyPacket(*conn, PacketNumberSpace::Handshake);
  packet.packet.frames.push_back(
      WriteCryptoFrame(data->length(), data->length()));
  handshakeStream->writeBuffer.append(data->clone());
  updateConnection(
      *conn,
      folly::none,
      packet.packet,
      TimePoint(),
      getEncodedSize(packet),
      getEncodedBodySize(packet),
      false /* isDSRPacket */);
  EXPECT_EQ(1, conn->outstandings.packetCount[PacketNumberSpace::Initial]);
  EXPECT_EQ(2, conn->outstandings.packetCount[PacketNumberSpace::Handshake]);
  EXPECT_EQ(3, conn->outstandings.packets.size());
  EXPECT_EQ(2, handshakeStream->retransmissionBuffer.size());
  EXPECT_TRUE(handshakeStream->writeBuffer.empty());
  EXPECT_TRUE(handshakeStream->lossBuffer.empty());

  // Fake loss.
  firstBuf = handshakeStream->retransmissionBuffer.find(0)->second->data.move();
  handshakeStream->retransmissionBuffer.erase(0);
  handshakeStream->lossBuffer.emplace_back(std::move(firstBuf), 0, false);
  auto& op = conn->outstandings.packets.front();
  ASSERT_EQ(
      op.packet.header.getPacketNumberSpace(), PacketNumberSpace::Handshake);
  auto frame = op.packet.frames[0].asWriteCryptoFrame();
  EXPECT_EQ(frame->offset, 0);
  conn->outstandings.packets.pop_front();
  conn->outstandings.packetCount[PacketNumberSpace::Handshake]--;

  implicitAckCryptoStream(*conn, EncryptionLevel::Initial);
  EXPECT_EQ(0, conn->outstandings.packetCount[PacketNumberSpace::Initial]);
  EXPECT_EQ(1, conn->outstandings.packetCount[PacketNumberSpace::Handshake]);
  EXPECT_EQ(1, conn->outstandings.packets.size());
  EXPECT_TRUE(initialStream->retransmissionBuffer.empty());
  EXPECT_TRUE(initialStream->writeBuffer.empty());
  EXPECT_TRUE(initialStream->lossBuffer.empty());

  implicitAckCryptoStream(*conn, EncryptionLevel::Handshake);
  EXPECT_EQ(0, conn->outstandings.packetCount[PacketNumberSpace::Initial]);
  EXPECT_EQ(0, conn->outstandings.packetCount[PacketNumberSpace::Handshake]);
  EXPECT_TRUE(conn->outstandings.packets.empty());
  EXPECT_TRUE(handshakeStream->retransmissionBuffer.empty());
  EXPECT_TRUE(handshakeStream->writeBuffer.empty());
  EXPECT_TRUE(handshakeStream->lossBuffer.empty());
}

TEST_F(QuicTransportFunctionsTest, TestUpdateConnectionHandshakeCounter) {
  auto conn = createConn();
  conn->qLogger = std::make_shared<quic::FileQLogger>(VantagePoint::Client);
  auto stream = conn->streamManager->createNextBidirectionalStream().value();
  writeDataToQuicStream(*stream, nullptr, true);
  EXPECT_EQ(0, conn->outstandings.packetCount[PacketNumberSpace::Handshake]);

  auto packet = buildEmptyPacket(*conn, PacketNumberSpace::Handshake);
  auto packetEncodedSize =
      packet.header ? packet.header->computeChainDataLength() : 0;
  packetEncodedSize += packet.body ? packet.body->computeChainDataLength() : 0;

  packet.packet.frames.push_back(WriteCryptoFrame(0, 0));
  updateConnection(
      *conn,
      folly::none,
      packet.packet,
      TimePoint(),
      getEncodedSize(packet),
      getEncodedBodySize(packet),
      false /* isDSRPacket */);
  EXPECT_EQ(1, conn->outstandings.packetCount[PacketNumberSpace::Handshake]);

  auto nonHandshake = buildEmptyPacket(*conn, PacketNumberSpace::AppData);
  packetEncodedSize =
      nonHandshake.header ? nonHandshake.header->computeChainDataLength() : 0;
  packetEncodedSize +=
      nonHandshake.body ? nonHandshake.body->computeChainDataLength() : 0;
  auto stream1 = conn->streamManager->createNextBidirectionalStream().value();
  writeDataToQuicStream(*stream1, nullptr, true);

  nonHandshake.packet.frames.push_back(
      WriteStreamFrame(stream1->id, 0, 0, true));
  updateConnection(
      *conn,
      folly::none,
      nonHandshake.packet,
      TimePoint(),
      getEncodedSize(packet),
      getEncodedBodySize(packet),
      false /* isDSRPacket */);

  // verify QLogger contains correct packet information
  std::shared_ptr<quic::FileQLogger> qLogger =
      std::dynamic_pointer_cast<quic::FileQLogger>(conn->qLogger);
  std::vector<int> indices =
      getQLogEventIndices(QLogEventType::PacketSent, qLogger);
  EXPECT_EQ(indices.size(), 2);
  std::vector<std::string> packetTypes = {
      std::string(toQlogString(LongHeader::Types::Handshake)),
      std::string(toQlogString(LongHeader::Types::ZeroRtt))};
  for (int i = 0; i < 2; ++i) {
    auto tmp = std::move(qLogger->logs[indices[i]]);
    auto event = dynamic_cast<QLogPacketEvent*>(tmp.get());
    EXPECT_EQ(event->packetType, packetTypes[i]);
    EXPECT_EQ(event->packetSize, packetEncodedSize);
    EXPECT_EQ(event->eventType, QLogEventType::PacketSent);

    if (i == 0) {
      EXPECT_EQ(event->frames.size(), 1);
      auto gotFrame = static_cast<CryptoFrameLog*>(event->frames[0].get());
      gotFrame->offset = 0;
      gotFrame->len = 0;
    } else if (i == 1) {
      EXPECT_EQ(event->frames.size(), 1);
      auto gotFrame = static_cast<StreamFrameLog*>(event->frames[0].get());
      EXPECT_EQ(gotFrame->streamId, stream1->id);
      EXPECT_EQ(gotFrame->offset, 0);
      EXPECT_EQ(gotFrame->len, 0);
      EXPECT_TRUE(gotFrame->fin);
      EXPECT_EQ(
          1, conn->outstandings.packetCount[PacketNumberSpace::Handshake]);
    }
  }
}

TEST_F(QuicTransportFunctionsTest, TestUpdateConnectionForOneRttCryptoData) {
  auto conn = createConn();
  conn->qLogger = std::make_shared<quic::FileQLogger>(VantagePoint::Client);
  auto stream = conn->streamManager->createNextBidirectionalStream().value();
  writeDataToQuicStream(*stream, nullptr, true);
  EXPECT_EQ(0, conn->outstandings.packetCount[PacketNumberSpace::Handshake]);

  // Packet with CryptoFrame in AppData pn space
  auto packet = buildEmptyPacket(*conn, PacketNumberSpace::AppData, true);
  auto packetEncodedSize =
      packet.header ? packet.header->computeChainDataLength() : 0;
  packetEncodedSize += packet.body ? packet.body->computeChainDataLength() : 0;

  packet.packet.frames.push_back(WriteCryptoFrame(0, 0));
  updateConnection(
      *conn,
      folly::none,
      packet.packet,
      TimePoint(),
      getEncodedSize(packet),
      getEncodedBodySize(packet),
      false /* isDSRPacket */);

  EXPECT_EQ(0, conn->outstandings.packetCount[PacketNumberSpace::Handshake]);
  EXPECT_EQ(1, conn->outstandings.packets.size());

  auto nonHandshake = buildEmptyPacket(*conn, PacketNumberSpace::AppData);
  packetEncodedSize =
      nonHandshake.header ? nonHandshake.header->computeChainDataLength() : 0;
  packetEncodedSize +=
      nonHandshake.body ? nonHandshake.body->computeChainDataLength() : 0;
  auto stream1 = conn->streamManager->createNextBidirectionalStream().value();
  writeDataToQuicStream(*stream1, nullptr, true);

  nonHandshake.packet.frames.push_back(
      WriteStreamFrame(stream1->id, 0, 0, true));
  updateConnection(
      *conn,
      folly::none,
      nonHandshake.packet,
      TimePoint(),
      getEncodedSize(packet),
      getEncodedBodySize(packet),
      false /* isDSRPacket */);

  // verify QLogger contains correct packet information
  std::shared_ptr<quic::FileQLogger> qLogger =
      std::dynamic_pointer_cast<quic::FileQLogger>(conn->qLogger);
  std::vector<int> indices =
      getQLogEventIndices(QLogEventType::PacketSent, qLogger);
  EXPECT_EQ(indices.size(), 2);
  std::vector<std::string> packetTypes = {
      kShortHeaderPacketType.str(),
      std::string(toQlogString(LongHeader::Types::ZeroRtt))};
  for (int i = 0; i < 2; ++i) {
    auto tmp = std::move(qLogger->logs[indices[i]]);
    auto event = dynamic_cast<QLogPacketEvent*>(tmp.get());
    EXPECT_EQ(event->packetType, packetTypes[i]);
    EXPECT_EQ(event->packetSize, getEncodedSize(packet));
    EXPECT_EQ(event->eventType, QLogEventType::PacketSent);

    if (i == 0) {
      EXPECT_EQ(event->frames.size(), 1);
      auto frame = static_cast<CryptoFrameLog*>(event->frames[0].get());
      EXPECT_EQ(frame->offset, 0);
      EXPECT_EQ(frame->len, 0);
    } else if (i == 1) {
      EXPECT_EQ(event->frames.size(), 1);
      auto frame = static_cast<StreamFrameLog*>(event->frames[0].get());
      EXPECT_EQ(frame->streamId, stream1->id);
      EXPECT_EQ(frame->offset, 0);
      EXPECT_EQ(frame->len, 0);
      EXPECT_TRUE(frame->fin);
    }
  }

  EXPECT_EQ(0, conn->outstandings.packetCount[PacketNumberSpace::Handshake]);
  EXPECT_EQ(2, conn->outstandings.packets.size());
}

TEST_F(QuicTransportFunctionsTest, TestUpdateConnectionWithPureAck) {
  auto conn = createConn();
  conn->qLogger = std::make_shared<quic::FileQLogger>(VantagePoint::Client);
  auto packet = buildEmptyPacket(*conn, PacketNumberSpace::Handshake);
  auto mockPacer = std::make_unique<NiceMock<MockPacer>>();
  auto rawPacer = mockPacer.get();
  conn->pacer = std::move(mockPacer);
  auto mockCongestionController =
      std::make_unique<NiceMock<MockCongestionController>>();
  auto rawController = mockCongestionController.get();
  conn->congestionController = std::move(mockCongestionController);
  EXPECT_EQ(0, conn->lossState.totalPacketsSent);
  EXPECT_EQ(0, conn->lossState.totalAckElicitingPacketsSent);
  EXPECT_EQ(0, conn->outstandings.packets.size());
  ASSERT_EQ(0, conn->lossState.totalBytesAcked);
  WriteAckFrame ackFrame;
  ackFrame.ackBlocks.emplace_back(0, 10);
  packet.packet.frames.push_back(std::move(ackFrame));
  EXPECT_CALL(*rawController, onPacketSent(_)).Times(0);
  EXPECT_CALL(*rawPacer, onPacketSent()).Times(0);
  updateConnection(
      *conn,
      folly::none,
      packet.packet,
      TimePoint(),
      getEncodedSize(packet),
      getEncodedBodySize(packet),
      false /* isDSRPacket */);
  EXPECT_EQ(1, conn->lossState.totalPacketsSent);
  EXPECT_EQ(0, conn->lossState.totalAckElicitingPacketsSent);
  EXPECT_EQ(0, conn->outstandings.packets.size());
  EXPECT_EQ(0, conn->lossState.totalBytesAcked);
  std::shared_ptr<quic::FileQLogger> qLogger =
      std::dynamic_pointer_cast<quic::FileQLogger>(conn->qLogger);
  // verify QLogger contains correct packet information
  std::vector<int> indices =
      getQLogEventIndices(QLogEventType::PacketSent, qLogger);
  EXPECT_EQ(indices.size(), 1);
  auto tmp = std::move(qLogger->logs[indices[0]]);
  auto event = dynamic_cast<QLogPacketEvent*>(tmp.get());
  EXPECT_EQ(event->packetType, toQlogString(LongHeader::Types::Handshake));
  EXPECT_EQ(event->packetSize, getEncodedSize(packet));
  EXPECT_EQ(event->eventType, QLogEventType::PacketSent);
  // verify QLogger contains correct frame information
  EXPECT_EQ(event->frames.size(), 1);
  auto frame = static_cast<WriteAckFrameLog*>(event->frames[0].get());
  EXPECT_EQ(frame->ackBlocks.size(), 1);
}

TEST_F(QuicTransportFunctionsTest, TestUpdateConnectionWithBytesStats) {
  auto conn = createConn();
  conn->qLogger = std::make_shared<quic::FileQLogger>(VantagePoint::Client);
  auto stream = conn->streamManager->createNextBidirectionalStream().value();
  auto packet = buildEmptyPacket(*conn, PacketNumberSpace::Handshake);
  // This is clearly not 555 bytes. I just need some data inside the packet.
  writeDataToQuicStream(
      *stream, folly::IOBuf::copyBuffer("Im gonna cut your hair."), true);
  WriteStreamFrame writeStreamFrame(stream->id, 0, 5, false);
  packet.packet.frames.push_back(std::move(writeStreamFrame));
  conn->lossState.totalBytesSent = 13579;
  conn->lossState.totalBodyBytesSent = 13000;
  conn->lossState.inflightBytes = 16000;
  auto currentTime = Clock::now();
  conn->lossState.lastAckedTime = currentTime - 123s;
  conn->lossState.adjustedLastAckedTime = currentTime - 123s;
  conn->lossState.lastAckedPacketSentTime = currentTime - 234s;
  conn->lossState.totalBytesSentAtLastAck = 10000;
  conn->lossState.totalBytesAckedAtLastAck = 5000;
  conn->lossState.totalPacketsSent = 20;
  conn->lossState.totalAckElicitingPacketsSent = 15;
  updateConnection(
      *conn,
      folly::none,
      packet.packet,
      TimePoint(),
      555,
      500,
      false /* isDSRPacket */);
  EXPECT_EQ(21, conn->lossState.totalPacketsSent);
  EXPECT_EQ(16, conn->lossState.totalAckElicitingPacketsSent);

  // verify QLogger contains correct packet information
  std::shared_ptr<quic::FileQLogger> qLogger =
      std::dynamic_pointer_cast<quic::FileQLogger>(conn->qLogger);
  std::vector<int> indices =
      getQLogEventIndices(QLogEventType::PacketSent, qLogger);
  EXPECT_EQ(indices.size(), 1);
  auto tmp = std::move(qLogger->logs[indices[0]]);
  auto event = dynamic_cast<QLogPacketEvent*>(tmp.get());

  EXPECT_EQ(event->packetType, toQlogString(LongHeader::Types::Handshake));
  EXPECT_EQ(event->packetSize, 555);
  EXPECT_EQ(event->eventType, QLogEventType::PacketSent);

  EXPECT_EQ(
      13579 + 555,
      getFirstOutstandingPacket(*conn, PacketNumberSpace::Handshake)
          ->metadata.totalBytesSent);
  EXPECT_EQ(
      13000 + 500,
      getFirstOutstandingPacket(*conn, PacketNumberSpace::Handshake)
          ->metadata.totalBodyBytesSent);
  EXPECT_EQ(
      16000 + 555,
      getFirstOutstandingPacket(*conn, PacketNumberSpace::Handshake)
          ->metadata.inflightBytes);
  EXPECT_EQ(
      1,
      getFirstOutstandingPacket(*conn, PacketNumberSpace::Handshake)
          ->metadata.packetsInflight);
  EXPECT_EQ(
      555,
      getFirstOutstandingPacket(*conn, PacketNumberSpace::Handshake)
          ->metadata.encodedSize);
  EXPECT_EQ(
      500,
      getFirstOutstandingPacket(*conn, PacketNumberSpace::Handshake)
          ->metadata.encodedBodySize);
  EXPECT_EQ(
      20 + 1,
      getFirstOutstandingPacket(*conn, PacketNumberSpace::Handshake)
          ->metadata.totalPacketsSent);
  EXPECT_EQ(
      15 + 1,
      getFirstOutstandingPacket(*conn, PacketNumberSpace::Handshake)
          ->metadata.totalAckElicitingPacketsSent);

  EXPECT_TRUE(getFirstOutstandingPacket(*conn, PacketNumberSpace::Handshake)
                  ->lastAckedPacketInfo.has_value());
  EXPECT_EQ(
      currentTime - 123s,
      getFirstOutstandingPacket(*conn, PacketNumberSpace::Handshake)
          ->lastAckedPacketInfo->ackTime);
  EXPECT_EQ(
      currentTime -= 234s,
      getFirstOutstandingPacket(*conn, PacketNumberSpace::Handshake)
          ->lastAckedPacketInfo->sentTime);
  EXPECT_EQ(
      10000,
      getFirstOutstandingPacket(*conn, PacketNumberSpace::Handshake)
          ->lastAckedPacketInfo->totalBytesSent);
  EXPECT_EQ(
      5000,
      getFirstOutstandingPacket(*conn, PacketNumberSpace::Handshake)
          ->lastAckedPacketInfo->totalBytesAcked);
}

TEST_F(QuicTransportFunctionsTest, TestUpdateConnectionWithCloneResult) {
  auto conn = createConn();
  conn->qLogger = std::make_shared<quic::FileQLogger>(VantagePoint::Client);
  auto mockCongestionController =
      std::make_unique<NiceMock<MockCongestionController>>();
  auto rawCongestionController = mockCongestionController.get();
  conn->congestionController = std::move(mockCongestionController);
  ShortHeader shortHeader(
      ProtectionType::KeyPhaseZero,
      *conn->clientConnectionId,
      conn->ackStates.appDataAckState.nextPacketNum);
  auto thisMoment = Clock::now();
  MockClock::mockNow = [=]() { return thisMoment; };
  RegularQuicWritePacket writePacket(std::move(shortHeader));
  // Add a dummy frame into the packet so we don't treat it as pureAck
  auto maxDataAmt = 1000 + conn->flowControlState.advertisedMaxOffset;
  MaxDataFrame maxDataFrame(maxDataAmt);
  conn->pendingEvents.connWindowUpdate = true;
  writePacket.frames.push_back(std::move(maxDataFrame));
  PacketEvent event(PacketNumberSpace::AppData, 1);
  conn->outstandings.packetEvents.insert(event);
  auto futureMoment = thisMoment + 50ms;
  MockClock::mockNow = [=]() { return futureMoment; };
  EXPECT_CALL(*rawCongestionController, onPacketSent(_)).Times(1);
  updateConnection(
      *conn,
      event,
      std::move(writePacket),
      MockClock::now(),
      1500,
      1400,
      false /* isDSRPacket */);
  // verify QLogger contains correct packet information
  std::shared_ptr<quic::FileQLogger> qLogger =
      std::dynamic_pointer_cast<quic::FileQLogger>(conn->qLogger);

  std::vector<int> indices =
      getQLogEventIndices(QLogEventType::PacketSent, qLogger);
  EXPECT_EQ(indices.size(), 1);
  auto tmp = std::move(qLogger->logs[indices[0]]);
  auto qLogEvent = dynamic_cast<QLogPacketEvent*>(tmp.get());
  EXPECT_EQ(qLogEvent->packetType, kShortHeaderPacketType.str());
  EXPECT_EQ(qLogEvent->packetSize, 1500);
  EXPECT_EQ(qLogEvent->eventType, QLogEventType::PacketSent);

  // verify QLogger contains correct frame information
  EXPECT_EQ(qLogEvent->frames.size(), 1);
  auto frame = static_cast<MaxDataFrameLog*>(qLogEvent->frames[0].get());
  EXPECT_EQ(frame->maximumData, maxDataAmt);
  EXPECT_EQ(
      futureMoment,
      getLastOutstandingPacket(*conn, PacketNumberSpace::AppData)
          ->metadata.time);
  EXPECT_EQ(
      1500,
      getLastOutstandingPacket(*conn, PacketNumberSpace::AppData)
          ->metadata.encodedSize);
  EXPECT_EQ(
      1400,
      getLastOutstandingPacket(*conn, PacketNumberSpace::AppData)
          ->metadata.encodedBodySize);
  EXPECT_EQ(
      event,
      *getLastOutstandingPacket(*conn, PacketNumberSpace::AppData)
           ->associatedEvent);
  EXPECT_TRUE(conn->pendingEvents.setLossDetectionAlarm);
}

TEST_F(QuicTransportFunctionsTest, TestUpdateConnectionStreamWindowUpdate) {
  auto conn = createConn();
  conn->qLogger = std::make_shared<quic::FileQLogger>(VantagePoint::Client);
  auto packet = buildEmptyPacket(*conn, PacketNumberSpace::Handshake);
  auto stream = conn->streamManager->createNextBidirectionalStream().value();
  MaxStreamDataFrame streamWindowUpdate(stream->id, 0);
  conn->streamManager->queueWindowUpdate(stream->id);
  packet.packet.frames.push_back(std::move(streamWindowUpdate));
  updateConnection(
      *conn,
      folly::none,
      packet.packet,
      TimePoint(),
      getEncodedSize(packet),
      getEncodedBodySize(packet),
      false /* isDSRPacket */);

  // verify QLogger contains correct packet information
  std::shared_ptr<quic::FileQLogger> qLogger =
      std::dynamic_pointer_cast<quic::FileQLogger>(conn->qLogger);
  std::vector<int> indices =
      getQLogEventIndices(QLogEventType::PacketSent, qLogger);
  EXPECT_EQ(indices.size(), 1);
  auto tmp = std::move(qLogger->logs[indices[0]]);
  auto event = dynamic_cast<QLogPacketEvent*>(tmp.get());

  EXPECT_EQ(event->packetType, toQlogString(LongHeader::Types::Handshake));
  EXPECT_EQ(event->packetSize, getEncodedSize(packet));
  EXPECT_EQ(event->eventType, QLogEventType::PacketSent);

  // verify QLogger contains correct frame information
  EXPECT_EQ(event->frames.size(), 1);
  auto frame = static_cast<MaxStreamDataFrameLog*>(event->frames[0].get());
  EXPECT_EQ(frame->streamId, stream->id);
  EXPECT_EQ(frame->maximumData, 0);
}

TEST_F(QuicTransportFunctionsTest, TestUpdateConnectionConnWindowUpdate) {
  auto conn = createConn();
  conn->qLogger = std::make_shared<quic::FileQLogger>(VantagePoint::Client);
  auto packet = buildEmptyPacket(*conn, PacketNumberSpace::Handshake);
  conn->pendingEvents.connWindowUpdate = true;
  MaxDataFrame connWindowUpdate(conn->flowControlState.advertisedMaxOffset);
  packet.packet.frames.push_back(std::move(connWindowUpdate));
  updateConnection(
      *conn,
      folly::none,
      packet.packet,
      TimePoint(),
      getEncodedSize(packet),
      getEncodedBodySize(packet),
      false /* isDSRPacket */);

  // verify QLogger contains correct packet information
  std::shared_ptr<quic::FileQLogger> qLogger =
      std::dynamic_pointer_cast<quic::FileQLogger>(conn->qLogger);
  std::vector<int> indices =
      getQLogEventIndices(QLogEventType::PacketSent, qLogger);
  EXPECT_EQ(indices.size(), 1);
  auto tmp = std::move(qLogger->logs[indices[0]]);
  auto event = dynamic_cast<QLogPacketEvent*>(tmp.get());

  EXPECT_EQ(event->packetType, toQlogString(LongHeader::Types::Handshake));
  EXPECT_EQ(event->packetSize, getEncodedSize(packet));
  EXPECT_EQ(event->eventType, QLogEventType::PacketSent);
  // verify QLogger contains correct frame information
  EXPECT_EQ(event->frames.size(), 1);
  auto frame = static_cast<MaxDataFrameLog*>(event->frames[0].get());
  EXPECT_EQ(frame->maximumData, conn->flowControlState.advertisedMaxOffset);
}

TEST_F(QuicTransportFunctionsTest, StreamDetailsEmptyPacket) {
  auto conn = createConn();
  auto packet = buildEmptyPacket(*conn, PacketNumberSpace::AppData);
  updateConnection(
      *conn,
      folly::none,
      packet.packet,
      TimePoint(),
      getEncodedSize(packet),
      getEncodedBodySize(packet),
      false /* isDSRPacket */);
  // Since there is no ACK eliciting frame in this packet,
  // it is not included as an outstanding packet, and there's no StreamDetails
  EXPECT_EQ(0, conn->outstandings.packets.size());
}

TEST_F(QuicTransportFunctionsTest, StreamDetailsNoStreamsInPacket) {
  auto conn = createConn();
  auto packet = buildEmptyPacket(*conn, PacketNumberSpace::AppData);
  auto stream = conn->streamManager->createNextBidirectionalStream().value();
  StreamDataBlockedFrame blockedFrame(stream->id, 1000);
  packet.packet.frames.push_back(blockedFrame);
  packet.packet.frames.push_back(PingFrame());
  updateConnection(
      *conn,
      folly::none,
      packet.packet,
      TimePoint(),
      getEncodedSize(packet),
      getEncodedBodySize(packet),
      false /* isDSRPacket */);
  // If we have only control frames sent, there should be no stream data in the
  // outstanding packet.
  ASSERT_EQ(1, conn->outstandings.packets.size());
  const auto& detailsPerStream =
      getFirstOutstandingPacket(*conn, PacketNumberSpace::AppData)
          ->metadata.detailsPerStream;
  EXPECT_THAT(detailsPerStream, IsEmpty());
}

TEST_F(QuicTransportFunctionsTest, StreamDetailsSingleStream) {
  uint64_t frameOffset = 0;
  uint64_t frameLen = 10;

  auto conn = createConn();
  auto packet = buildEmptyPacket(*conn, PacketNumberSpace::AppData);
  auto stream = conn->streamManager->createNextBidirectionalStream().value();
  writeDataToQuicStream(*stream, folly::IOBuf::copyBuffer("abcdefghij"), true);
  WriteStreamFrame writeStreamFrame(
      stream->id, frameOffset, frameLen, false /* fin */);
  packet.packet.frames.push_back(writeStreamFrame);
  updateConnection(
      *conn,
      folly::none,
      packet.packet,
      TimePoint(),
      getEncodedSize(packet),
      getEncodedBodySize(packet),
      false /* isDSRPacket */);

  const auto streamMatcher = testing::Pair(
      stream->id,
      testing::AllOf(
          testing::Field(&PacketStreamDetails::finObserved, false),
          testing::Field(&PacketStreamDetails::streamBytesSent, frameLen),
          testing::Field(&PacketStreamDetails::newStreamBytesSent, frameLen),
          testing::Field(
              &PacketStreamDetails::maybeFirstNewStreamByteOffset,
              folly::Optional<uint64_t>(frameOffset)),
          testing::Field(
              &PacketStreamDetails::streamIntervals,
              testing::ElementsAre(Interval<uint64_t>(
                  frameOffset, frameOffset + frameLen - 1)))));
  const auto pktMatcher = testing::Field(
      &OutstandingPacket::metadata,
      testing::AllOf(
          testing::Field(
              &OutstandingPacketMetadata::totalPacketsSent, testing::Eq(1)),
          testing::Field(
              &OutstandingPacketMetadata::detailsPerStream,
              testing::UnorderedElementsAre(streamMatcher))));
  EXPECT_THAT(conn->outstandings.packets, ElementsAre(pktMatcher));
}

TEST_F(QuicTransportFunctionsTest, StreamDetailsSingleStreamMultipleFrames) {
  auto conn = createConn();
  auto packet = buildEmptyPacket(*conn, PacketNumberSpace::AppData);
  auto stream = conn->streamManager->createNextBidirectionalStream().value();
  writeDataToQuicStream(
      *stream, folly::IOBuf::copyBuffer("abcdefghijklmno"), true);
  WriteStreamFrame writeStreamFrame1(
      stream->id, 0 /* offset */, 10 /* length */, false /* fin */);
  WriteStreamFrame writeStreamFrame2(
      stream->id, 10 /* offset */, 5 /* length */, true /* fin */);
  packet.packet.frames.push_back(writeStreamFrame1);
  packet.packet.frames.push_back(writeStreamFrame2);
  updateConnection(
      *conn,
      folly::none,
      packet.packet,
      TimePoint(),
      getEncodedSize(packet),
      getEncodedBodySize(packet),
      false /* isDSRPacket */);

  const auto streamMatcher = testing::Pair(
      stream->id,
      testing::AllOf(
          testing::Field(&PacketStreamDetails::finObserved, true),
          testing::Field(&PacketStreamDetails::streamBytesSent, 15),
          testing::Field(&PacketStreamDetails::newStreamBytesSent, 15),
          testing::Field(
              &PacketStreamDetails::maybeFirstNewStreamByteOffset,
              folly::Optional<uint64_t>(0)),
          testing::Field(
              &PacketStreamDetails::streamIntervals,
              testing::ElementsAre(Interval<uint64_t>(0, 14)))));
  const auto pktMatcher = testing::Field(
      &OutstandingPacket::metadata,
      testing::AllOf(
          testing::Field(
              &OutstandingPacketMetadata::totalPacketsSent, testing::Eq(1)),
          testing::Field(
              &OutstandingPacketMetadata::detailsPerStream,
              testing::UnorderedElementsAre(streamMatcher))));
  EXPECT_THAT(conn->outstandings.packets, ElementsAre(pktMatcher));
}

TEST_F(QuicTransportFunctionsTest, StreamDetailsSingleStreamRetransmit) {
  auto conn = createConn();
  auto stream = conn->streamManager->createNextBidirectionalStream().value();

  writeDataToQuicStream(
      *stream, folly::IOBuf::copyBuffer("abcdefghij"), false /* eof */);
  uint64_t frame1Offset = 0;
  uint64_t frame1Len = 10;
  auto packet = buildEmptyPacket(*conn, PacketNumberSpace::AppData);
  WriteStreamFrame frame1(stream->id, frame1Offset, frame1Len, false /* fin */);
  packet.packet.frames.push_back(frame1);
  updateConnection(
      *conn,
      folly::none,
      packet.packet,
      TimePoint(),
      getEncodedSize(packet),
      getEncodedBodySize(packet),
      false /* isDSRPacket */);

  ASSERT_EQ(1, conn->outstandings.packets.size());

  // The first outstanding packet is the one with new data
  {
    const auto streamMatcher = testing::Pair(
        stream->id,
        testing::AllOf(
            testing::Field(&PacketStreamDetails::finObserved, false),
            testing::Field(&PacketStreamDetails::streamBytesSent, frame1Len),
            testing::Field(&PacketStreamDetails::newStreamBytesSent, frame1Len),
            testing::Field(
                &PacketStreamDetails::maybeFirstNewStreamByteOffset,
                folly::Optional<uint64_t>(frame1Offset)),
            testing::Field(
                &PacketStreamDetails::streamIntervals,
                testing::ElementsAre(Interval<uint64_t>(
                    frame1Offset, frame1Offset + frame1Len - 1)))));
    const auto pktMatcher = testing::Field(
        &OutstandingPacket::metadata,
        testing::AllOf(
            testing::Field(
                &OutstandingPacketMetadata::totalPacketsSent, testing::Eq(1)),
            testing::Field(
                &OutstandingPacketMetadata::detailsPerStream,
                testing::UnorderedElementsAre(streamMatcher))));
    EXPECT_THAT(conn->outstandings.packets, Contains(pktMatcher));
  }

  // retransmit the same frame1 again.
  packet = buildEmptyPacket(*conn, PacketNumberSpace::AppData);
  packet.packet.frames.push_back(frame1);
  updateConnection(
      *conn,
      folly::none,
      packet.packet,
      TimePoint(),
      getEncodedSize(packet),
      getEncodedBodySize(packet),
      false /* isDSRPacket */);

  ASSERT_EQ(2, conn->outstandings.packets.size());

  // The second outstanding packet is the one with retransmit data
  {
    const auto streamMatcher = testing::Pair(
        stream->id,
        testing::AllOf(
            testing::Field(&PacketStreamDetails::finObserved, false),
            testing::Field(&PacketStreamDetails::streamBytesSent, frame1Len),
            testing::Field(&PacketStreamDetails::newStreamBytesSent, 0),
            testing::Field(
                &PacketStreamDetails::maybeFirstNewStreamByteOffset,
                folly::Optional<uint64_t>(/* empty */)),
            testing::Field(
                &PacketStreamDetails::streamIntervals,
                testing::ElementsAre(Interval<uint64_t>(
                    frame1Offset, frame1Offset + frame1Len - 1)))));
    const auto pktMatcher = testing::Field(
        &OutstandingPacket::metadata,
        testing::AllOf(
            testing::Field(
                &OutstandingPacketMetadata::totalPacketsSent, testing::Eq(2)),
            testing::Field(
                &OutstandingPacketMetadata::detailsPerStream,
                testing::UnorderedElementsAre(streamMatcher))));
    EXPECT_THAT(conn->outstandings.packets, Contains(pktMatcher));
  }

  // Retransmit frame1 and send new data in frame2.
  writeDataToQuicStream(
      *stream, folly::IOBuf::copyBuffer("klmnopqrstuvwxy"), false /* eof */);
  uint64_t frame2Offset = 10;
  uint64_t frame2Len = 15;
  packet = buildEmptyPacket(*conn, PacketNumberSpace::AppData);
  WriteStreamFrame frame2(stream->id, frame2Offset, frame2Len, false /* fin */);
  packet.packet.frames.push_back(frame1);
  packet.packet.frames.push_back(frame2);
  updateConnection(
      *conn,
      folly::none,
      packet.packet,
      TimePoint(),
      getEncodedSize(packet),
      getEncodedBodySize(packet),
      false /* isDSRPacket */);

  ASSERT_EQ(3, conn->outstandings.packets.size());

  // The third outstanding packet will have both new and retransmitted data.
  {
    const auto streamMatcher = testing::Pair(
        stream->id,
        testing::AllOf(
            testing::Field(&PacketStreamDetails::finObserved, false),
            testing::Field(
                &PacketStreamDetails::streamBytesSent, frame1Len + frame2Len),
            testing::Field(&PacketStreamDetails::newStreamBytesSent, frame2Len),
            testing::Field(
                &PacketStreamDetails::maybeFirstNewStreamByteOffset,
                folly::Optional<uint64_t>(frame2Offset)),
            testing::Field(
                &PacketStreamDetails::streamIntervals,
                testing::ElementsAre(Interval<uint64_t>(
                    frame1Offset, frame2Offset + frame2Len - 1)))));
    const auto pktMatcher = testing::Field(
        &OutstandingPacket::metadata,
        testing::AllOf(
            testing::Field(
                &OutstandingPacketMetadata::totalPacketsSent, testing::Eq(3)),
            testing::Field(
                &OutstandingPacketMetadata::detailsPerStream,
                testing::UnorderedElementsAre(streamMatcher))));
    EXPECT_THAT(conn->outstandings.packets, Contains(pktMatcher));
  }

  // Retransmit frame1 aand frame2.
  packet = buildEmptyPacket(*conn, PacketNumberSpace::AppData);
  packet.packet.frames.push_back(frame1);
  packet.packet.frames.push_back(frame2);
  updateConnection(
      *conn,
      folly::none,
      packet.packet,
      TimePoint(),
      getEncodedSize(packet),
      getEncodedBodySize(packet),
      false /* isDSRPacket */);

  ASSERT_EQ(4, conn->outstandings.packets.size());

  // The forth outstanding packet will have only retransmit data.
  {
    const auto streamMatcher = testing::Pair(
        stream->id,
        testing::AllOf(
            testing::Field(&PacketStreamDetails::finObserved, false),
            testing::Field(
                &PacketStreamDetails::streamBytesSent, frame1Len + frame2Len),
            testing::Field(&PacketStreamDetails::newStreamBytesSent, 0),
            testing::Field(
                &PacketStreamDetails::maybeFirstNewStreamByteOffset,
                folly::Optional<uint64_t>(/* empty */)),
            testing::Field(
                &PacketStreamDetails::streamIntervals,
                testing::ElementsAre(Interval<uint64_t>(
                    frame1Offset, frame2Offset + frame2Len - 1)))));
    const auto pktMatcher = testing::Field(
        &OutstandingPacket::metadata,
        testing::AllOf(
            testing::Field(
                &OutstandingPacketMetadata::totalPacketsSent, testing::Eq(4)),
            testing::Field(
                &OutstandingPacketMetadata::detailsPerStream,
                testing::UnorderedElementsAre(streamMatcher))));
    EXPECT_THAT(conn->outstandings.packets, Contains(pktMatcher));
  }
}

TEST_F(QuicTransportFunctionsTest, StreamDetailsSingleStreamFinWithRetransmit) {
  auto conn = createConn();
  auto stream = conn->streamManager->createNextBidirectionalStream().value();
  const uint64_t frameLen = 1;

  // write two packets, each containing one byte of frame data
  // second packet contains FIN
  writeDataToQuicStream(
      *stream, folly::IOBuf::copyBuffer("a"), false /* eof */);
  uint64_t frame1Offset = 0;
  auto packet1 = buildEmptyPacket(*conn, PacketNumberSpace::AppData);
  WriteStreamFrame frame1(stream->id, frame1Offset, frameLen, false /* fin */);
  packet1.packet.frames.push_back(frame1);
  updateConnection(
      *conn,
      folly::none,
      packet1.packet,
      TimePoint(),
      getEncodedSize(packet1),
      getEncodedBodySize(packet1),
      false /* isDSRPacket */);

  writeDataToQuicStream(*stream, folly::IOBuf::copyBuffer("b"), true /* eof */);
  uint64_t frame2Offset = (frameLen * 2) - 1;
  auto packet2 = buildEmptyPacket(*conn, PacketNumberSpace::AppData);
  WriteStreamFrame frame2(stream->id, frame2Offset, frameLen, true /* fin */);
  packet2.packet.frames.push_back(frame2);
  updateConnection(
      *conn,
      folly::none,
      packet2.packet,
      TimePoint(),
      getEncodedSize(packet2),
      getEncodedBodySize(packet2),
      false /* isDSRPacket */);

  // Should be two packets at this point, each with 1 frame of data
  EXPECT_THAT(conn->outstandings.packets, SizeIs(2));
  {
    auto getStreamDetailsMatcher = [&stream, &frameLen](
                                       auto frameOffset, bool finObserved) {
      return testing::Pair(
          stream->id,
          testing::AllOf(
              testing::Field(&PacketStreamDetails::finObserved, finObserved),
              testing::Field(&PacketStreamDetails::streamBytesSent, frameLen),
              testing::Field(
                  &PacketStreamDetails::newStreamBytesSent, frameLen),
              testing::Field(
                  &PacketStreamDetails::maybeFirstNewStreamByteOffset,
                  folly::Optional<uint64_t>(frameOffset)),
              testing::Field(
                  &PacketStreamDetails::streamIntervals,
                  testing::ElementsAre(Interval<uint64_t>(
                      frameOffset, frameOffset + frameLen - 1)))));
    };

    const auto pkt1Matcher = testing::Field(
        &OutstandingPacket::metadata,
        testing::AllOf(
            testing::Field(
                &OutstandingPacketMetadata::totalPacketsSent, testing::Eq(1)),
            testing::Field(
                &OutstandingPacketMetadata::detailsPerStream,
                testing::UnorderedElementsAre(getStreamDetailsMatcher(
                    frame1Offset, false /* finObserved */)))));
    const auto pkt2Matcher = testing::Field(
        &OutstandingPacket::metadata,
        testing::AllOf(
            testing::Field(
                &OutstandingPacketMetadata::totalPacketsSent, testing::Eq(2)),
            testing::Field(
                &OutstandingPacketMetadata::detailsPerStream,
                testing::UnorderedElementsAre(getStreamDetailsMatcher(
                    frame2Offset, true /* finObserved */)))));
    EXPECT_THAT(
        conn->outstandings.packets, ElementsAre(pkt1Matcher, pkt2Matcher));
  }

  // retransmit both frames in packet3
  auto packet3 = buildEmptyPacket(*conn, PacketNumberSpace::AppData);
  packet3.packet.frames.push_back(frame1);
  packet3.packet.frames.push_back(frame2);
  updateConnection(
      *conn,
      folly::none,
      packet3.packet,
      TimePoint(),
      getEncodedSize(packet3),
      getEncodedBodySize(packet3),
      false /* isDSRPacket */);

  // Should be three packets at this point
  //
  // StreamDetails should report fin since frame2 is in packet3
  EXPECT_THAT(conn->outstandings.packets, SizeIs(3));
  {
    auto streamDetailsMatcher = testing::Pair(
        stream->id,
        testing::AllOf(
            testing::Field(&PacketStreamDetails::finObserved, true),
            testing::Field(&PacketStreamDetails::streamBytesSent, frameLen * 2),
            testing::Field(&PacketStreamDetails::newStreamBytesSent, 0),
            testing::Field(
                &PacketStreamDetails::maybeFirstNewStreamByteOffset,
                folly::Optional<uint64_t>(/* empty */)),
            testing::Field(
                &PacketStreamDetails::streamIntervals,
                // contains frame1 and frame2
                testing::ElementsAre(Interval<uint64_t>(
                    frame1Offset, frame2Offset + frameLen - 1)))));

    const auto pkt3Matcher = testing::Field(
        &OutstandingPacket::metadata,
        testing::AllOf(
            testing::Field(
                &OutstandingPacketMetadata::totalPacketsSent, testing::Eq(3)),
            testing::Field(
                &OutstandingPacketMetadata::detailsPerStream,
                testing::UnorderedElementsAre(streamDetailsMatcher))));
    EXPECT_THAT(conn->outstandings.packets, Contains(pkt3Matcher));
  }
}

TEST_F(
    QuicTransportFunctionsTest,
    StreamDetailsSingleStreamSingleBytePktsPartialAckRetransmit) {
  auto conn = createConn();
  auto stream = conn->streamManager->createNextBidirectionalStream().value();
  const uint64_t frameLen = 1;

  // write three packets, each containing one byte of frame data
  writeDataToQuicStream(
      *stream, folly::IOBuf::copyBuffer("a"), false /* eof */);
  uint64_t frame1Offset = 0;
  auto packet1 = buildEmptyPacket(*conn, PacketNumberSpace::AppData);
  WriteStreamFrame frame1(stream->id, frame1Offset, frameLen, false /* fin */);
  packet1.packet.frames.push_back(frame1);
  updateConnection(
      *conn,
      folly::none,
      packet1.packet,
      TimePoint(),
      getEncodedSize(packet1),
      getEncodedBodySize(packet1),
      false /* isDSRPacket */);

  writeDataToQuicStream(
      *stream, folly::IOBuf::copyBuffer("b"), false /* eof */);
  uint64_t frame2Offset = frameLen;
  auto packet2 = buildEmptyPacket(*conn, PacketNumberSpace::AppData);
  WriteStreamFrame frame2(stream->id, frame2Offset, frameLen, false /* fin */);
  packet2.packet.frames.push_back(frame2);
  updateConnection(
      *conn,
      folly::none,
      packet2.packet,
      TimePoint(),
      getEncodedSize(packet2),
      getEncodedBodySize(packet2),
      false /* isDSRPacket */);

  writeDataToQuicStream(
      *stream, folly::IOBuf::copyBuffer("c"), false /* eof */);
  uint64_t frame3Offset = frameLen * 2;
  auto packet3 = buildEmptyPacket(*conn, PacketNumberSpace::AppData);
  WriteStreamFrame frame3(stream->id, frame3Offset, frameLen, false /* fin */);
  packet3.packet.frames.push_back(frame3);
  updateConnection(
      *conn,
      folly::none,
      packet3.packet,
      TimePoint(),
      getEncodedSize(packet3),
      getEncodedBodySize(packet3),
      false /* isDSRPacket */);

  // Should be three packets at this point, each with 1 frame of data
  EXPECT_THAT(conn->outstandings.packets, SizeIs(3));
  {
    auto getStreamDetailsMatcher = [&stream, &frameLen](auto frameOffset) {
      return testing::Pair(
          stream->id,
          testing::AllOf(
              testing::Field(&PacketStreamDetails::finObserved, false),
              testing::Field(&PacketStreamDetails::streamBytesSent, frameLen),
              testing::Field(
                  &PacketStreamDetails::newStreamBytesSent, frameLen),
              testing::Field(
                  &PacketStreamDetails::maybeFirstNewStreamByteOffset,
                  folly::Optional<uint64_t>(frameOffset)),
              testing::Field(
                  &PacketStreamDetails::streamIntervals,
                  testing::ElementsAre(Interval<uint64_t>(
                      frameOffset, frameOffset + frameLen - 1)))));
    };

    const auto pkt1Matcher = testing::Field(
        &OutstandingPacket::metadata,
        testing::AllOf(
            testing::Field(
                &OutstandingPacketMetadata::totalPacketsSent, testing::Eq(1)),
            testing::Field(
                &OutstandingPacketMetadata::detailsPerStream,
                testing::UnorderedElementsAre(
                    getStreamDetailsMatcher(frame1Offset)))));
    const auto pkt2Matcher = testing::Field(
        &OutstandingPacket::metadata,
        testing::AllOf(
            testing::Field(
                &OutstandingPacketMetadata::totalPacketsSent, testing::Eq(2)),
            testing::Field(
                &OutstandingPacketMetadata::detailsPerStream,
                testing::UnorderedElementsAre(
                    getStreamDetailsMatcher(frame2Offset)))));
    const auto pkt3Matcher = testing::Field(
        &OutstandingPacket::metadata,
        testing::AllOf(
            testing::Field(
                &OutstandingPacketMetadata::totalPacketsSent, testing::Eq(3)),
            testing::Field(
                &OutstandingPacketMetadata::detailsPerStream,
                testing::UnorderedElementsAre(
                    getStreamDetailsMatcher(frame3Offset)))));
    EXPECT_THAT(
        conn->outstandings.packets,
        ElementsAre(pkt1Matcher, pkt2Matcher, pkt3Matcher));
  }

  // retransmit contents of packet1 and packet3 (frame1 and frame3) in packet4
  // simulates ACK of packet2 and loss of packet1 and packet3
  auto packet4 = buildEmptyPacket(*conn, PacketNumberSpace::AppData);
  packet4.packet.frames.push_back(frame1);
  packet4.packet.frames.push_back(frame3);
  updateConnection(
      *conn,
      folly::none,
      packet4.packet,
      TimePoint(),
      getEncodedSize(packet4),
      getEncodedBodySize(packet4),
      false /* isDSRPacket */);

  // Should be four packets at this point
  EXPECT_THAT(conn->outstandings.packets, SizeIs(4));
  {
    auto streamDetailsMatcher = testing::Pair(
        stream->id,
        testing::AllOf(
            testing::Field(&PacketStreamDetails::finObserved, false),
            testing::Field(&PacketStreamDetails::streamBytesSent, frameLen * 2),
            testing::Field(&PacketStreamDetails::newStreamBytesSent, 0),
            testing::Field(
                &PacketStreamDetails::maybeFirstNewStreamByteOffset,
                folly::Optional<uint64_t>(/* empty */)),
            testing::Field(
                &PacketStreamDetails::streamIntervals,
                // contains frame1 and frame 3
                testing::ElementsAre(
                    Interval<uint64_t>(
                        frame1Offset, frame1Offset + frameLen - 1),
                    Interval<uint64_t>(
                        frame3Offset, frame3Offset + frameLen - 1)))));

    const auto pkt4Matcher = testing::Field(
        &OutstandingPacket::metadata,
        testing::AllOf(
            testing::Field(
                &OutstandingPacketMetadata::totalPacketsSent, testing::Eq(4)),
            testing::Field(
                &OutstandingPacketMetadata::detailsPerStream,
                testing::UnorderedElementsAre(streamDetailsMatcher))));
    EXPECT_THAT(conn->outstandings.packets, Contains(pkt4Matcher));
  }
}

TEST_F(
    QuicTransportFunctionsTest,
    StreamDetailsSingleStreamTwoBytePktsPartialAckRetransmit) {
  auto conn = createConn();
  auto stream = conn->streamManager->createNextBidirectionalStream().value();
  const uint64_t frameLen = 2;

  // write three packets, each containing two bytes of frame data
  writeDataToQuicStream(
      *stream, folly::IOBuf::copyBuffer("ab"), false /* eof */);
  uint64_t frame1Offset = 0;
  auto packet1 = buildEmptyPacket(*conn, PacketNumberSpace::AppData);
  WriteStreamFrame frame1(stream->id, frame1Offset, frameLen, false /* fin */);
  packet1.packet.frames.push_back(frame1);
  updateConnection(
      *conn,
      folly::none,
      packet1.packet,
      TimePoint(),
      getEncodedSize(packet1),
      getEncodedBodySize(packet1),
      false /* isDSRPacket */);

  writeDataToQuicStream(
      *stream, folly::IOBuf::copyBuffer("cd"), false /* eof */);
  uint64_t frame2Offset = frameLen;
  LOG(INFO) << "frame2Offset = " << frame2Offset;
  auto packet2 = buildEmptyPacket(*conn, PacketNumberSpace::AppData);
  WriteStreamFrame frame2(stream->id, frame2Offset, frameLen, false /* fin */);
  packet2.packet.frames.push_back(frame2);
  updateConnection(
      *conn,
      folly::none,
      packet2.packet,
      TimePoint(),
      getEncodedSize(packet2),
      getEncodedBodySize(packet2),
      false /* isDSRPacket */);

  writeDataToQuicStream(
      *stream, folly::IOBuf::copyBuffer("ef"), false /* eof */);
  uint64_t frame3Offset = (frameLen * 2);
  LOG(INFO) << "frame3Offset = " << frame3Offset;
  auto packet3 = buildEmptyPacket(*conn, PacketNumberSpace::AppData);
  WriteStreamFrame frame3(stream->id, frame3Offset, frameLen, false /* fin */);
  packet3.packet.frames.push_back(frame3);
  updateConnection(
      *conn,
      folly::none,
      packet3.packet,
      TimePoint(),
      getEncodedSize(packet3),
      getEncodedBodySize(packet3),
      false /* isDSRPacket */);

  // Should be three packets at this point, each with 1 frame of data
  EXPECT_THAT(conn->outstandings.packets, SizeIs(3));
  {
    auto getStreamDetailsMatcher = [&stream, &frameLen](auto frameOffset) {
      return testing::Pair(
          stream->id,
          testing::AllOf(
              testing::Field(&PacketStreamDetails::finObserved, false),
              testing::Field(&PacketStreamDetails::streamBytesSent, frameLen),
              testing::Field(
                  &PacketStreamDetails::newStreamBytesSent, frameLen),
              testing::Field(
                  &PacketStreamDetails::maybeFirstNewStreamByteOffset,
                  folly::Optional<uint64_t>(frameOffset)),
              testing::Field(
                  &PacketStreamDetails::streamIntervals,
                  testing::ElementsAre(Interval<uint64_t>(
                      frameOffset, frameOffset + frameLen - 1)))));
    };

    const auto pkt1Matcher = testing::Field(
        &OutstandingPacket::metadata,
        testing::AllOf(
            testing::Field(
                &OutstandingPacketMetadata::totalPacketsSent, testing::Eq(1)),
            testing::Field(
                &OutstandingPacketMetadata::detailsPerStream,
                testing::UnorderedElementsAre(
                    getStreamDetailsMatcher(frame1Offset)))));
    const auto pkt2Matcher = testing::Field(
        &OutstandingPacket::metadata,
        testing::AllOf(
            testing::Field(
                &OutstandingPacketMetadata::totalPacketsSent, testing::Eq(2)),
            testing::Field(
                &OutstandingPacketMetadata::detailsPerStream,
                testing::UnorderedElementsAre(
                    getStreamDetailsMatcher(frame2Offset)))));
    const auto pkt3Matcher = testing::Field(
        &OutstandingPacket::metadata,
        testing::AllOf(
            testing::Field(
                &OutstandingPacketMetadata::totalPacketsSent, testing::Eq(3)),
            testing::Field(
                &OutstandingPacketMetadata::detailsPerStream,
                testing::UnorderedElementsAre(
                    getStreamDetailsMatcher(frame3Offset)))));
    EXPECT_THAT(
        conn->outstandings.packets,
        ElementsAre(pkt1Matcher, pkt2Matcher, pkt3Matcher));
  }

  // retransmit contents of packet1 and packet3 (frame1 and frame3) in packet4
  // simulates ACK of packet2 and loss of packet1 and packet3
  auto packet4 = buildEmptyPacket(*conn, PacketNumberSpace::AppData);
  packet4.packet.frames.push_back(frame1);
  packet4.packet.frames.push_back(frame3);
  updateConnection(
      *conn,
      folly::none,
      packet4.packet,
      TimePoint(),
      getEncodedSize(packet4),
      getEncodedBodySize(packet4),
      false /* isDSRPacket */);

  // Should be four packets at this point
  EXPECT_THAT(conn->outstandings.packets, SizeIs(4));
  {
    auto streamDetailsMatcher = testing::Pair(
        stream->id,
        testing::AllOf(
            testing::Field(&PacketStreamDetails::finObserved, false),
            testing::Field(&PacketStreamDetails::streamBytesSent, frameLen * 2),
            testing::Field(&PacketStreamDetails::newStreamBytesSent, 0),
            testing::Field(
                &PacketStreamDetails::maybeFirstNewStreamByteOffset,
                folly::Optional<uint64_t>(/* empty */)),
            testing::Field(
                &PacketStreamDetails::streamIntervals,
                // contains frame1 and frame 3
                testing::ElementsAre(
                    Interval<uint64_t>(
                        frame1Offset, frame1Offset + frameLen - 1),
                    Interval<uint64_t>(
                        frame3Offset, frame3Offset + frameLen - 1)))));

    const auto pkt4Matcher = testing::Field(
        &OutstandingPacket::metadata,
        testing::AllOf(
            testing::Field(
                &OutstandingPacketMetadata::totalPacketsSent, testing::Eq(4)),
            testing::Field(
                &OutstandingPacketMetadata::detailsPerStream,
                testing::UnorderedElementsAre(streamDetailsMatcher))));
    EXPECT_THAT(conn->outstandings.packets, Contains(pkt4Matcher));
  }
}

TEST_F(QuicTransportFunctionsTest, StreamDetailsMultipleStreams) {
  auto conn = createConn();
  auto stream1Id =
      conn->streamManager->createNextBidirectionalStream().value()->id;
  auto stream2Id =
      conn->streamManager->createNextBidirectionalStream().value()->id;
  auto stream3Id =
      conn->streamManager->createNextBidirectionalStream().value()->id;
  auto stream1 = conn->streamManager->findStream(stream1Id);
  auto stream2 = conn->streamManager->findStream(stream2Id);
  auto stream3 = conn->streamManager->findStream(stream3Id);
  ASSERT_NE(nullptr, stream1);
  ASSERT_NE(nullptr, stream2);
  ASSERT_NE(nullptr, stream3);

  auto buf = IOBuf::copyBuffer("hey whats up");
  writeDataToQuicStream(*stream1, buf->clone(), true);
  writeDataToQuicStream(*stream2, buf->clone(), true);
  writeDataToQuicStream(*stream3, buf->clone(), true);

  uint64_t stream1Offset = 0;
  uint64_t stream2Offset = 0;
  uint64_t stream3Offset = 0;
  uint64_t stream1Len = 5;
  uint64_t stream2Len = 12;
  uint64_t stream3Len = 5;

  auto packet1 = buildEmptyPacket(*conn, PacketNumberSpace::AppData);
  WriteStreamFrame writeStreamFrame1(
      stream1->id, stream1Offset, stream1Len, false);
  WriteStreamFrame writeStreamFrame2(
      stream2->id, stream2Offset, stream2Len, true);
  WriteStreamFrame writeStreamFrame3(
      stream3->id, stream3Offset, stream3Len, true);
  packet1.packet.frames.push_back(writeStreamFrame1);
  packet1.packet.frames.push_back(writeStreamFrame2);
  packet1.packet.frames.push_back(writeStreamFrame3);

  updateConnection(
      *conn,
      folly::none,
      packet1.packet,
      TimePoint(),
      getEncodedSize(packet1),
      getEncodedBodySize(packet1),
      false /* isDSRPacket */);

  // check stream details for the sent packet
  {
    auto stream1DetailsMatcher = testing::Pair(
        stream1Id,
        testing::AllOf(
            testing::Field(&PacketStreamDetails::finObserved, false),
            testing::Field(&PacketStreamDetails::streamBytesSent, stream1Len),
            testing::Field(
                &PacketStreamDetails::newStreamBytesSent, stream1Len),
            testing::Field(
                &PacketStreamDetails::maybeFirstNewStreamByteOffset,
                folly::Optional<uint64_t>(stream1Offset)),
            testing::Field(
                &PacketStreamDetails::streamIntervals,
                testing::ElementsAre(Interval<uint64_t>(
                    stream1Offset, stream1Offset + stream1Len - 1)))));
    auto stream2DetailsMatcher = testing::Pair(
        stream2Id,
        testing::AllOf(
            testing::Field(&PacketStreamDetails::finObserved, true),
            testing::Field(&PacketStreamDetails::streamBytesSent, stream2Len),
            testing::Field(
                &PacketStreamDetails::newStreamBytesSent, stream2Len),
            testing::Field(
                &PacketStreamDetails::maybeFirstNewStreamByteOffset,
                folly::Optional<uint64_t>(stream2Offset)),
            testing::Field(
                &PacketStreamDetails::streamIntervals,
                testing::ElementsAre(Interval<uint64_t>(
                    stream2Offset, stream2Offset + stream2Len - 1)))));
    auto stream3DetailsMatcher = testing::Pair(
        stream3Id,
        testing::AllOf(
            testing::Field(&PacketStreamDetails::finObserved, true),
            testing::Field(&PacketStreamDetails::streamBytesSent, stream3Len),
            testing::Field(
                &PacketStreamDetails::newStreamBytesSent, stream3Len),
            testing::Field(
                &PacketStreamDetails::maybeFirstNewStreamByteOffset,
                folly::Optional<uint64_t>(stream3Offset)),
            testing::Field(
                &PacketStreamDetails::streamIntervals,
                testing::ElementsAre(Interval<uint64_t>(
                    stream3Offset, stream3Offset + stream3Len - 1)))));

    const auto pktMatcher = testing::Field(
        &OutstandingPacket::metadata,
        testing::AllOf(
            testing::Field(
                &OutstandingPacketMetadata::totalPacketsSent, testing::Eq(1)),
            testing::Field(
                &OutstandingPacketMetadata::detailsPerStream,
                testing::UnorderedElementsAre(
                    stream1DetailsMatcher,
                    stream2DetailsMatcher,
                    stream3DetailsMatcher))));
    EXPECT_THAT(conn->outstandings.packets, ElementsAre(pktMatcher));
  }

  // retransmit the packet
  auto packet2 = buildEmptyPacket(*conn, PacketNumberSpace::AppData);
  packet2.packet.frames.push_back(writeStreamFrame1);
  packet2.packet.frames.push_back(writeStreamFrame2);
  packet2.packet.frames.push_back(writeStreamFrame3);

  updateConnection(
      *conn,
      folly::none,
      packet2.packet,
      TimePoint(),
      getEncodedSize(packet1),
      getEncodedBodySize(packet1),
      false /* isDSRPacket */);

  // check stream details for the retransmitted packet
  EXPECT_THAT(conn->outstandings.packets, SizeIs(2));
  {
    auto stream1DetailsMatcher = testing::Pair(
        stream1Id,
        testing::AllOf(
            testing::Field(&PacketStreamDetails::finObserved, false),
            testing::Field(&PacketStreamDetails::streamBytesSent, stream1Len),
            testing::Field(&PacketStreamDetails::newStreamBytesSent, 0),
            testing::Field(
                &PacketStreamDetails::maybeFirstNewStreamByteOffset,
                folly::Optional<uint64_t>(/* empty */)),
            testing::Field(
                &PacketStreamDetails::streamIntervals,
                testing::ElementsAre(Interval<uint64_t>(
                    stream1Offset, stream1Offset + stream1Len - 1)))));
    auto stream2DetailsMatcher = testing::Pair(
        stream2Id,
        testing::AllOf(
            testing::Field(&PacketStreamDetails::finObserved, true),
            testing::Field(&PacketStreamDetails::streamBytesSent, stream2Len),
            testing::Field(&PacketStreamDetails::newStreamBytesSent, 0),
            testing::Field(
                &PacketStreamDetails::maybeFirstNewStreamByteOffset,
                folly::Optional<uint64_t>(/* empty */)),
            testing::Field(
                &PacketStreamDetails::streamIntervals,
                testing::ElementsAre(Interval<uint64_t>(
                    stream2Offset, stream2Offset + stream2Len - 1)))));
    auto stream3DetailsMatcher = testing::Pair(
        stream3Id,
        testing::AllOf(
            testing::Field(&PacketStreamDetails::finObserved, true),
            testing::Field(&PacketStreamDetails::streamBytesSent, stream3Len),
            testing::Field(&PacketStreamDetails::newStreamBytesSent, 0),
            testing::Field(
                &PacketStreamDetails::maybeFirstNewStreamByteOffset,
                folly::Optional<uint64_t>(/* empty */)),
            testing::Field(
                &PacketStreamDetails::streamIntervals,
                testing::ElementsAre(Interval<uint64_t>(
                    stream3Offset, stream3Offset + stream3Len - 1)))));

    const auto pktMatcher = testing::Field(
        &OutstandingPacket::metadata,
        testing::AllOf(
            testing::Field(
                &OutstandingPacketMetadata::totalPacketsSent, testing::Eq(2)),
            testing::Field(
                &OutstandingPacketMetadata::detailsPerStream,
                testing::UnorderedElementsAre(
                    stream1DetailsMatcher,
                    stream2DetailsMatcher,
                    stream3DetailsMatcher))));
    EXPECT_THAT(conn->outstandings.packets, Contains(pktMatcher));
  }
}

TEST_F(QuicTransportFunctionsTest, WriteQuicDataToSocketWithCC) {
  auto conn = createConn();
  conn->udpSendPacketLen = 30;
  auto mockCongestionController =
      std::make_unique<NiceMock<MockCongestionController>>();
  auto rawCongestionController = mockCongestionController.get();
  conn->congestionController = std::move(mockCongestionController);

  EventBase evb;
  auto socket =
      std::make_unique<NiceMock<folly::test::MockAsyncUDPSocket>>(&evb);
  auto rawSocket = socket.get();

  auto stream1 = conn->streamManager->createNextBidirectionalStream().value();
  auto buf =
      IOBuf::copyBuffer("0123456789012012345678901201234567890120123456789012");
  writeDataToQuicStream(*stream1, buf->clone(), true);

  uint64_t writableBytes = 30;
  EXPECT_CALL(*rawCongestionController, getWritableBytes())
      .WillRepeatedly(
          InvokeWithoutArgs([&writableBytes]() { return writableBytes; }));
  EXPECT_CALL(*rawSocket, write(_, _))
      .WillRepeatedly(Invoke([&](const SocketAddress&,
                                 const std::unique_ptr<folly::IOBuf>& iobuf) {
        EXPECT_LE(iobuf->computeChainDataLength(), 30);
        writableBytes -= iobuf->computeChainDataLength();
        return iobuf->computeChainDataLength();
      }));
  EXPECT_CALL(*rawCongestionController, onPacketSent(_)).Times(1);
  EXPECT_CALL(*quicStats_, onWrite(_));
  writeQuicDataToSocket(
      *rawSocket,
      *conn,
      *conn->clientConnectionId,
      *conn->serverConnectionId,
      *aead,
      *headerCipher,
      getVersion(*conn),
      conn->transportSettings.writeConnectionDataPacketsLimit);
}

TEST_F(QuicTransportFunctionsTest, WriteQuicdataToSocketWithPacer) {
  auto conn = createConn();
  auto mockPacer = std::make_unique<NiceMock<MockPacer>>();
  auto rawPacer = mockPacer.get();
  conn->pacer = std::move(mockPacer);

  EventBase evb;
  auto socket =
      std::make_unique<NiceMock<folly::test::MockAsyncUDPSocket>>(&evb);
  auto rawSocket = socket.get();

  auto stream1 = conn->streamManager->createNextBidirectionalStream().value();
  auto buf =
      IOBuf::copyBuffer("0123456789012012345678901201234567890120123456789012");
  writeDataToQuicStream(*stream1, buf->clone(), true);

  EXPECT_CALL(*rawPacer, onPacketSent()).Times(1);
  EXPECT_CALL(*quicStats_, onWrite(_));
  writeQuicDataToSocket(
      *rawSocket,
      *conn,
      *conn->clientConnectionId,
      *conn->serverConnectionId,
      *aead,
      *headerCipher,
      getVersion(*conn),
      conn->transportSettings.writeConnectionDataPacketsLimit);
}

TEST_F(QuicTransportFunctionsTest, WriteQuicDataToSocketLimitTest) {
  auto conn = createConn();
  auto mockCongestionController =
      std::make_unique<NiceMock<MockCongestionController>>();
  auto rawCongestionController = mockCongestionController.get();
  conn->congestionController = std::move(mockCongestionController);
  conn->udpSendPacketLen = aead->getCipherOverhead() + 50;

  EventBase evb;
  auto socket =
      std::make_unique<NiceMock<folly::test::MockAsyncUDPSocket>>(&evb);
  auto rawSocket = socket.get();
  auto stream1 = conn->streamManager->createNextBidirectionalStream().value();
  // ~50 bytes
  auto buf =
      IOBuf::copyBuffer("0123456789012012345678901201234567890120123456789012");
  writeDataToQuicStream(*stream1, buf->clone(), false);
  uint64_t writableBytes = 30;
  EXPECT_CALL(*rawCongestionController, getWritableBytes())
      .WillRepeatedly(
          InvokeWithoutArgs([&writableBytes]() { return writableBytes; }));

  // Limit to zero
  conn->transportSettings.writeConnectionDataPacketsLimit = 0;
  EXPECT_CALL(*rawSocket, write(_, _)).Times(0);
  EXPECT_CALL(*rawCongestionController, onPacketSent(_)).Times(0);
  EXPECT_CALL(*quicStats_, onWrite(_)).Times(0);
  auto res = writeQuicDataToSocket(
      *rawSocket,
      *conn,
      *conn->clientConnectionId,
      *conn->serverConnectionId,
      *aead,
      *headerCipher,
      getVersion(*conn),
      conn->transportSettings.writeConnectionDataPacketsLimit);
  EXPECT_EQ(0, res.packetsWritten);
  EXPECT_EQ(0, res.probesWritten);

  // Normal limit
  conn->pendingEvents.numProbePackets[PacketNumberSpace::Initial] = 0;
  conn->pendingEvents.numProbePackets[PacketNumberSpace::Handshake] = 0;
  conn->pendingEvents.numProbePackets[PacketNumberSpace::AppData] = 0;
  conn->transportSettings.writeConnectionDataPacketsLimit =
      kDefaultWriteConnectionDataPacketLimit;
  EXPECT_CALL(*rawSocket, write(_, _))
      .Times(1)
      .WillOnce(Invoke([&](const SocketAddress&,
                           const std::unique_ptr<folly::IOBuf>& iobuf) {
        writableBytes -= iobuf->computeChainDataLength();
        return iobuf->computeChainDataLength();
      }));
  EXPECT_CALL(*rawCongestionController, onPacketSent(_)).Times(1);
  EXPECT_CALL(*quicStats_, onWrite(_)).Times(1);
  res = writeQuicDataToSocket(
      *rawSocket,
      *conn,
      *conn->clientConnectionId,
      *conn->serverConnectionId,
      *aead,
      *headerCipher,
      getVersion(*conn),
      conn->transportSettings.writeConnectionDataPacketsLimit);

  EXPECT_EQ(1, res.packetsWritten);
  EXPECT_EQ(0, res.probesWritten);

  // Probing can exceed packet limit. In practice we limit it to
  // kPacketToSendForPTO
  conn->pendingEvents.numProbePackets[PacketNumberSpace::AppData] =
      kDefaultWriteConnectionDataPacketLimit * 2;
  writeDataToQuicStream(*stream1, buf->clone(), true);
  writableBytes = 10000;
  EXPECT_CALL(*rawCongestionController, getWritableBytes())
      .WillRepeatedly(
          InvokeWithoutArgs([&writableBytes]() { return writableBytes; }));
  EXPECT_CALL(*rawSocket, write(_, _))
      .Times(kDefaultWriteConnectionDataPacketLimit * 2)
      .WillRepeatedly(Invoke([&](const SocketAddress&,
                                 const std::unique_ptr<folly::IOBuf>& iobuf) {
        return iobuf->computeChainDataLength();
      }));
  EXPECT_CALL(*rawCongestionController, onPacketSent(_))
      .Times(kDefaultWriteConnectionDataPacketLimit * 2);
  EXPECT_CALL(*quicStats_, onWrite(_))
      .Times(kDefaultWriteConnectionDataPacketLimit * 2);
  res = writeQuicDataToSocket(
      *rawSocket,
      *conn,
      *conn->clientConnectionId,
      *conn->serverConnectionId,
      *aead,
      *headerCipher,
      getVersion(*conn),
      conn->transportSettings.writeConnectionDataPacketsLimit);

  EXPECT_EQ(0, res.packetsWritten);
  EXPECT_EQ(kDefaultWriteConnectionDataPacketLimit * 2, res.probesWritten);
}

TEST_F(
    QuicTransportFunctionsTest,
    WriteQuicDataToSocketWhenInFlightBytesAreLimited) {
  auto conn = createConn();
  conn->oneRttWriteCipher = test::createNoOpAead();
  auto mockCongestionController =
      std::make_unique<NiceMock<MockCongestionController>>();
  auto rawCongestionController = mockCongestionController.get();
  conn->congestionController = std::move(mockCongestionController);

  EventBase evb;
  auto socket =
      std::make_unique<NiceMock<folly::test::MockAsyncUDPSocket>>(&evb);
  auto rawSocket = socket.get();

  auto stream1 = conn->streamManager->createNextBidirectionalStream().value();
  auto buf =
      IOBuf::copyBuffer("0123456789012012345678901201234567890120123456789012");
  writeDataToQuicStream(*stream1, buf->clone(), true);

  conn->writableBytesLimit = 100;
  uint64_t writableBytes = 5 * *conn->writableBytesLimit;

  EXPECT_CALL(*rawCongestionController, getWritableBytes())
      .WillRepeatedly(
          InvokeWithoutArgs([&writableBytes]() { return writableBytes; }));
  EXPECT_CALL(*rawSocket, write(_, _))
      .WillRepeatedly(Invoke([&](const SocketAddress&,
                                 const std::unique_ptr<folly::IOBuf>& iobuf) {
        EXPECT_LE(
            iobuf->computeChainDataLength(),
            *conn->writableBytesLimit - conn->lossState.totalBytesSent);
        writableBytes -= iobuf->computeChainDataLength();
        return iobuf->computeChainDataLength();
      }));
  EXPECT_NE(WriteDataReason::NO_WRITE, shouldWriteData(*conn));
  writeQuicDataToSocket(
      *rawSocket,
      *conn,
      *conn->clientConnectionId,
      *conn->serverConnectionId,
      *aead,
      *headerCipher,
      getVersion(*conn),
      conn->transportSettings.writeConnectionDataPacketsLimit);
  EXPECT_EQ(WriteDataReason::NO_WRITE, shouldWriteData(*conn));
}

TEST_F(QuicTransportFunctionsTest, WriteQuicDataToSocketWithNoBytesForHeader) {
  auto conn = createConn();
  auto mockCongestionController =
      std::make_unique<NiceMock<MockCongestionController>>();
  auto rawCongestionController = mockCongestionController.get();
  conn->congestionController = std::move(mockCongestionController);

  EventBase evb;
  auto socket =
      std::make_unique<NiceMock<folly::test::MockAsyncUDPSocket>>(&evb);
  auto rawSocket = socket.get();

  auto stream1 = conn->streamManager->createNextBidirectionalStream().value();
  auto buf = IOBuf::copyBuffer("0123456789012");
  writeDataToQuicStream(*stream1, buf->clone(), true);

  EXPECT_CALL(*rawCongestionController, getWritableBytes())
      .WillRepeatedly(Return(0));
  EXPECT_CALL(*rawCongestionController, onPacketSent(_)).Times(0);
  writeQuicDataToSocket(
      *rawSocket,
      *conn,
      *conn->clientConnectionId,
      *conn->serverConnectionId,
      *aead,
      *headerCipher,
      getVersion(*conn),
      conn->transportSettings.writeConnectionDataPacketsLimit);
  // No header space left. Should send nothing.
  EXPECT_TRUE(conn->outstandings.packets.empty());
}

TEST_F(QuicTransportFunctionsTest, WriteQuicDataToSocketRetxBufferSorted) {
  EventBase evb;
  NiceMock<folly::test::MockAsyncUDPSocket> socket(&evb);
  auto conn = createConn();
  auto stream = conn->streamManager->createNextBidirectionalStream().value();
  auto buf1 = IOBuf::copyBuffer("Whatsapp");
  writeDataToQuicStream(*stream, std::move(buf1), false);
  writeQuicDataToSocket(
      socket,
      *conn,
      *conn->clientConnectionId,
      *conn->serverConnectionId,
      *aead,
      *headerCipher,
      getVersion(*conn),
      conn->transportSettings.writeConnectionDataPacketsLimit);
  EXPECT_EQ(1, stream->retransmissionBuffer.size());

  auto buf2 = IOBuf::copyBuffer("Google Buzz");
  writeDataToQuicStream(*stream, std::move(buf2), false);
  writeQuicDataToSocket(
      socket,
      *conn,
      *conn->clientConnectionId,
      *conn->serverConnectionId,
      *aead,
      *headerCipher,
      getVersion(*conn),
      conn->transportSettings.writeConnectionDataPacketsLimit);
  EXPECT_EQ(2, stream->retransmissionBuffer.size());
}

TEST_F(QuicTransportFunctionsTest, NothingWritten) {
  auto conn = createConn();
  auto mockCongestionController =
      std::make_unique<NiceMock<MockCongestionController>>();
  auto rawCongestionController = mockCongestionController.get();
  conn->congestionController = std::move(mockCongestionController);

  EventBase evb;
  auto socket =
      std::make_unique<NiceMock<folly::test::MockAsyncUDPSocket>>(&evb);
  auto rawSocket = socket.get();

  // 18 isn't enough to write 3 ack blocks, but is enough to write a pure
  // header packet, which we shouldn't write
  EXPECT_CALL(*rawCongestionController, getWritableBytes())
      .WillRepeatedly(Return(18));

  addAckStatesWithCurrentTimestamps(conn->ackStates.initialAckState, 0, 1000);
  addAckStatesWithCurrentTimestamps(
      conn->ackStates.initialAckState, 1500, 2000);
  addAckStatesWithCurrentTimestamps(
      conn->ackStates.initialAckState, 2500, 3000);
  auto res = writeQuicDataToSocket(
      *rawSocket,
      *conn,
      *conn->clientConnectionId,
      *conn->serverConnectionId,
      *aead,
      *headerCipher,
      getVersion(*conn),
      conn->transportSettings.writeConnectionDataPacketsLimit);
  EXPECT_EQ(0, res.packetsWritten);
  EXPECT_EQ(0, res.probesWritten);
}

const QuicWriteFrame& getFirstFrameInOutstandingPackets(
    const std::deque<OutstandingPacket>& outstandingPackets,
    QuicWriteFrame::Type frameType) {
  for (const auto& packet : outstandingPackets) {
    for (const auto& frame : packet.packet.frames) {
      if (frame.type() == frameType) {
        return frame;
      }
    }
  }
  throw std::runtime_error("Frame not present");
}

TEST_F(QuicTransportFunctionsTest, WriteBlockedFrameWhenBlocked) {
  auto conn = createConn();
  EventBase evb;
  auto socket =
      std::make_unique<NiceMock<folly::test::MockAsyncUDPSocket>>(&evb);
  auto rawSocket = socket.get();
  auto stream1 = conn->streamManager->createNextBidirectionalStream().value();
  auto buf = buildRandomInputData(200);
  writeDataToQuicStream(*stream1, buf->clone(), true);

  auto originalNextSeq = conn->ackStates.appDataAckState.nextPacketNum;
  uint64_t sentBytes = 0;
  EXPECT_CALL(*rawSocket, write(_, _))
      .WillRepeatedly(Invoke([&](const SocketAddress&,
                                 const std::unique_ptr<folly::IOBuf>& iobuf) {
        auto len = iobuf->computeChainDataLength();
        sentBytes += len;
        return len;
      }));

  // Artificially Block the stream
  stream1->flowControlState.peerAdvertisedMaxOffset = 10;
  // writes blocked frame in additionally
  EXPECT_CALL(*quicStats_, onWrite(_)).Times(2);
  writeQuicDataToSocket(
      *rawSocket,
      *conn,
      *conn->clientConnectionId,
      *conn->serverConnectionId,
      *aead,
      *headerCipher,
      getVersion(*conn),
      conn->transportSettings.writeConnectionDataPacketsLimit);
  EXPECT_LT(sentBytes, 200);

  EXPECT_GT(conn->ackStates.appDataAckState.nextPacketNum, originalNextSeq);
  auto blocked = *getFirstFrameInOutstandingPackets(
                      conn->outstandings.packets,
                      QuicWriteFrame::Type::StreamDataBlockedFrame)
                      .asStreamDataBlockedFrame();
  EXPECT_EQ(blocked.streamId, stream1->id);

  // Since everything is blocked, we shouldn't write a blocked again, so we
  // won't have any new packets to write if we trigger a write.
  auto previousPackets = conn->outstandings.packets.size();
  EXPECT_CALL(*quicStats_, onWrite(_)).Times(0);
  writeQuicDataToSocket(
      *rawSocket,
      *conn,
      *conn->clientConnectionId,
      *conn->serverConnectionId,
      *aead,
      *headerCipher,
      getVersion(*conn),
      conn->transportSettings.writeConnectionDataPacketsLimit);
  EXPECT_EQ(previousPackets, conn->outstandings.packets.size());
}

TEST_F(QuicTransportFunctionsTest, WriteProbingNewData) {
  auto conn = createConn();
  // writeProbingDataToSocketForTest writes ShortHeader, thus it writes at
  // AppTraffic level
  auto currentPacketSeqNum = conn->ackStates.appDataAckState.nextPacketNum;
  auto mockCongestionController =
      std::make_unique<NiceMock<MockCongestionController>>();
  // Probing data is not limited by congestion control, this should not affect
  // anything
  EXPECT_CALL(*mockCongestionController, getWritableBytes())
      .WillRepeatedly(Return(0));
  auto rawCongestionController = mockCongestionController.get();
  conn->congestionController = std::move(mockCongestionController);
  EventBase evb;
  auto socket =
      std::make_unique<NiceMock<folly::test::MockAsyncUDPSocket>>(&evb);
  auto rawSocket = socket.get();
  auto stream1 = conn->streamManager->createNextBidirectionalStream().value();
  auto buf = buildRandomInputData(conn->udpSendPacketLen * 2);
  writeDataToQuicStream(*stream1, buf->clone(), true /* eof */);

  auto currentStreamWriteOffset = stream1->currentWriteOffset;
  EXPECT_CALL(*rawCongestionController, onPacketSent(_)).Times(1);
  EXPECT_CALL(*rawSocket, write(_, _))
      .WillOnce(Invoke([&](const SocketAddress&,
                           const std::unique_ptr<folly::IOBuf>& iobuf) {
        auto len = iobuf->computeChainDataLength();
        EXPECT_EQ(conn->udpSendPacketLen - aead->getCipherOverhead(), len);
        return len;
      }));
  writeProbingDataToSocketForTest(
      *rawSocket, *conn, 1, *aead, *headerCipher, getVersion(*conn));
  EXPECT_LT(currentPacketSeqNum, conn->ackStates.appDataAckState.nextPacketNum);
  EXPECT_FALSE(conn->outstandings.packets.empty());
  EXPECT_EQ(
      conn->outstandings.packets.back().packet.header.getPacketSequenceNum(),
      currentPacketSeqNum + 1);
  EXPECT_TRUE(conn->pendingEvents.setLossDetectionAlarm);
  EXPECT_GT(stream1->currentWriteOffset, currentStreamWriteOffset);
  EXPECT_FALSE(stream1->retransmissionBuffer.empty());
}

TEST_F(QuicTransportFunctionsTest, WriteProbingOldData) {
  auto conn = createConn();
  conn->congestionController.reset();
  EventBase evb;
  auto socket =
      std::make_unique<NiceMock<folly::test::MockAsyncUDPSocket>>(&evb);
  auto rawSocket = socket.get();
  EXPECT_CALL(*rawSocket, write(_, _)).WillRepeatedly(Return(100));
  auto capturingAead = std::make_unique<MockAead>();
  auto stream = conn->streamManager->createNextBidirectionalStream().value();
  auto buf = folly::IOBuf::copyBuffer("Where you wanna go");
  writeDataToQuicStream(*stream, buf->clone(), true);

  folly::IOBuf pktBodyCaptured;
  EXPECT_CALL(*capturingAead, _inplaceEncrypt(_, _, _))
      .WillRepeatedly(Invoke([&](auto& buf, auto, auto) {
        if (buf) {
          pktBodyCaptured.prependChain(buf->clone());
          return buf->clone();
        } else {
          return folly::IOBuf::create(0);
        }
      }));
  EXPECT_EQ(
      1,
      writeProbingDataToSocketForTest(
          *rawSocket, *conn, 1, *aead, *headerCipher, getVersion(*conn)));
  // Now we have no new data, let's probe again, and verify the same old data
  // is sent.
  folly::IOBuf secondBodyCaptured;
  EXPECT_CALL(*capturingAead, _inplaceEncrypt(_, _, _))
      .WillRepeatedly(Invoke([&](auto& buf, auto, auto) {
        if (buf) {
          secondBodyCaptured.prependChain(buf->clone());
          return buf->clone();
        } else {
          return folly::IOBuf::create(0);
        }
      }));
  EXPECT_EQ(
      1,
      writeProbingDataToSocketForTest(
          *rawSocket, *conn, 1, *aead, *headerCipher, getVersion(*conn)));
  // Verify two pacekts have the same body
  EXPECT_TRUE(folly::IOBufEqualTo()(pktBodyCaptured, secondBodyCaptured));
}

TEST_F(QuicTransportFunctionsTest, WriteProbingCryptoData) {
  QuicServerConnectionState conn(
      FizzServerQuicHandshakeContext::Builder().build());
  conn.serverConnectionId = getTestConnectionId();
  conn.clientConnectionId = getTestConnectionId();
  // writeCryptoDataProbesToSocketForTest writes Initial LongHeader, thus it
  // writes at Initial level.
  auto currentPacketSeqNum = conn.ackStates.initialAckState.nextPacketNum;
  // Replace real congestionController with MockCongestionController:
  auto mockCongestionController =
      std::make_unique<NiceMock<MockCongestionController>>();
  // Probing data is not limited by congestion control, this should not affect
  // anything
  EXPECT_CALL(*mockCongestionController, getWritableBytes())
      .WillRepeatedly(Return(0));
  auto rawCongestionController = mockCongestionController.get();
  conn.congestionController = std::move(mockCongestionController);
  EventBase evb;
  auto socket =
      std::make_unique<NiceMock<folly::test::MockAsyncUDPSocket>>(&evb);
  auto rawSocket = socket.get();
  auto cryptoStream = &conn.cryptoState->initialStream;
  auto buf = buildRandomInputData(conn.udpSendPacketLen * 2);
  writeDataToQuicStream(*cryptoStream, buf->clone());

  auto currentStreamWriteOffset = cryptoStream->currentWriteOffset;
  EXPECT_CALL(*rawCongestionController, onPacketSent(_)).Times(1);
  EXPECT_CALL(*rawSocket, write(_, _))
      .WillOnce(Invoke([&](const SocketAddress&,
                           const std::unique_ptr<folly::IOBuf>& iobuf) {
        auto len = iobuf->computeChainDataLength();
        EXPECT_EQ(conn.udpSendPacketLen - aead->getCipherOverhead(), len);
        return len;
      }));
  writeCryptoDataProbesToSocketForTest(
      *rawSocket, conn, 1, *aead, *headerCipher, getVersion(conn));
  EXPECT_LT(currentPacketSeqNum, conn.ackStates.initialAckState.nextPacketNum);
  EXPECT_FALSE(conn.outstandings.packets.empty());
  EXPECT_TRUE(conn.pendingEvents.setLossDetectionAlarm);
  EXPECT_GT(cryptoStream->currentWriteOffset, currentStreamWriteOffset);
  EXPECT_FALSE(cryptoStream->retransmissionBuffer.empty());
}

TEST_F(QuicTransportFunctionsTest, WriteableBytesLimitedProbingCryptoData) {
  QuicServerConnectionState conn(
      FizzServerQuicHandshakeContext::Builder().build());
  conn.statsCallback = quicStats_.get();
  conn.transportSettings.enableWritableBytesLimit = true;
  conn.writableBytesLimit = 2 * conn.udpSendPacketLen;

  conn.serverConnectionId = getTestConnectionId();
  conn.clientConnectionId = getTestConnectionId();
  // writeCryptoDataProbesToSocketForTest writes Initial LongHeader, thus it
  // writes at Initial level.
  auto currentPacketSeqNum = conn.ackStates.initialAckState.nextPacketNum;
  // Replace real congestionController with MockCongestionController:
  auto mockCongestionController =
      std::make_unique<NiceMock<MockCongestionController>>();
  auto rawCongestionController = mockCongestionController.get();
  conn.congestionController = std::move(mockCongestionController);
  EventBase evb;
  auto socket =
      std::make_unique<NiceMock<folly::test::MockAsyncUDPSocket>>(&evb);
  auto rawSocket = socket.get();
  auto cryptoStream = &conn.cryptoState->initialStream;
  uint8_t probesToSend = 4;
  auto buf = buildRandomInputData(conn.udpSendPacketLen * probesToSend);
  EXPECT_CALL(*quicStats_, onConnectionWritableBytesLimited())
      .Times(AtLeast(1));
  writeDataToQuicStream(*cryptoStream, buf->clone());

  auto currentStreamWriteOffset = cryptoStream->currentWriteOffset;
  EXPECT_CALL(*rawCongestionController, onPacketSent(_)).Times(2);
  EXPECT_CALL(*rawSocket, write(_, _))
      .WillRepeatedly(Invoke([&](const SocketAddress&,
                                 const std::unique_ptr<folly::IOBuf>& iobuf) {
        auto len = iobuf->computeChainDataLength();
        EXPECT_EQ(conn.udpSendPacketLen - aead->getCipherOverhead(), len);
        return len;
      }));
  writeCryptoDataProbesToSocketForTest(
      *rawSocket, conn, probesToSend, *aead, *headerCipher, getVersion(conn));

  EXPECT_EQ(conn.numProbesWritableBytesLimited, 1);
  EXPECT_LT(currentPacketSeqNum, conn.ackStates.initialAckState.nextPacketNum);
  EXPECT_FALSE(conn.outstandings.packets.empty());
  EXPECT_TRUE(conn.pendingEvents.setLossDetectionAlarm);
  EXPECT_GT(cryptoStream->currentWriteOffset, currentStreamWriteOffset);
  EXPECT_FALSE(cryptoStream->retransmissionBuffer.empty());
}

TEST_F(QuicTransportFunctionsTest, ProbingNotFallbackToPingWhenNoQuota) {
  auto conn = createConn();
  auto mockCongestionController =
      std::make_unique<NiceMock<MockCongestionController>>();
  auto rawCongestionController = mockCongestionController.get();
  conn->congestionController = std::move(mockCongestionController);
  EventBase evb;
  auto socket =
      std::make_unique<NiceMock<folly::test::MockAsyncUDPSocket>>(&evb);
  auto rawSocket = socket.get();
  EXPECT_CALL(*rawCongestionController, onPacketSent(_)).Times(0);
  EXPECT_CALL(*rawSocket, write(_, _)).Times(0);
  uint8_t probesToSend = 0;
  EXPECT_EQ(
      0,
      writeProbingDataToSocketForTest(
          *rawSocket,
          *conn,
          probesToSend,
          *aead,
          *headerCipher,
          getVersion(*conn)));
}

TEST_F(QuicTransportFunctionsTest, ProbingFallbackToPing) {
  auto conn = createConn();
  EventBase evb;
  auto socket =
      std::make_unique<NiceMock<folly::test::MockAsyncUDPSocket>>(&evb);
  auto rawSocket = socket.get();
  EXPECT_CALL(*rawSocket, write(_, _))
      .Times(1)
      .WillOnce(Invoke([&](const SocketAddress&,
                           const std::unique_ptr<folly::IOBuf>& iobuf) {
        return iobuf->computeChainDataLength();
      }));
  uint8_t probesToSend = 1;
  EXPECT_EQ(
      1,
      writeProbingDataToSocketForTest(
          *rawSocket,
          *conn,
          probesToSend,
          *aead,
          *headerCipher,
          getVersion(*conn)));
  // Ping is the only non-retransmittable packet that will go into OP list
  EXPECT_EQ(1, conn->outstandings.packets.size());
}

TEST_F(QuicTransportFunctionsTest, TestCryptoWritingIsHandshakeInOutstanding) {
  auto conn = createConn();
  auto cryptoStream = &conn->cryptoState->initialStream;
  auto buf = buildRandomInputData(200);
  writeDataToQuicStream(*cryptoStream, buf->clone());
  EventBase evb;
  auto socket =
      std::make_unique<NiceMock<folly::test::MockAsyncUDPSocket>>(&evb);
  auto rawSocket = socket.get();
  auto res = writeCryptoAndAckDataToSocket(
      *rawSocket,
      *conn,
      *conn->clientConnectionId,
      *conn->serverConnectionId,
      LongHeader::Types::Initial,
      *conn->initialWriteCipher,
      *conn->initialHeaderCipher,
      getVersion(*conn),
      conn->transportSettings.writeConnectionDataPacketsLimit);

  EXPECT_EQ(1, res.packetsWritten);
  EXPECT_EQ(0, res.probesWritten);
  EXPECT_GE(res.bytesWritten, buf->computeChainDataLength());
  ASSERT_EQ(1, conn->outstandings.packets.size());
  EXPECT_TRUE(getFirstOutstandingPacket(*conn, PacketNumberSpace::Initial)
                  ->metadata.isHandshake);
}

TEST_F(QuicTransportFunctionsTest, NoCryptoProbeWriteIfNoProbeCredit) {
  auto conn = createConn();
  auto cryptoStream = &conn->cryptoState->initialStream;
  auto buf = buildRandomInputData(200);
  writeDataToQuicStream(*cryptoStream, buf->clone());
  EventBase evb;
  auto socket =
      std::make_unique<NiceMock<folly::test::MockAsyncUDPSocket>>(&evb);
  auto rawSocket = socket.get();
  auto res = writeCryptoAndAckDataToSocket(
      *rawSocket,
      *conn,
      *conn->clientConnectionId,
      *conn->serverConnectionId,
      LongHeader::Types::Initial,
      *conn->initialWriteCipher,
      *conn->initialHeaderCipher,
      getVersion(*conn),
      conn->transportSettings.writeConnectionDataPacketsLimit);
  EXPECT_GE(res.bytesWritten, buf->computeChainDataLength());

  EXPECT_EQ(1, res.packetsWritten);
  EXPECT_EQ(0, res.probesWritten);
  ASSERT_EQ(1, conn->outstandings.packets.size());
  EXPECT_TRUE(getFirstOutstandingPacket(*conn, PacketNumberSpace::Initial)
                  ->metadata.isHandshake);
  ASSERT_EQ(1, cryptoStream->retransmissionBuffer.size());
  ASSERT_TRUE(cryptoStream->writeBuffer.empty());

  conn->pendingEvents.numProbePackets[PacketNumberSpace::Initial] = 0;
  conn->pendingEvents.numProbePackets[PacketNumberSpace::Handshake] = 0;
  conn->pendingEvents.numProbePackets[PacketNumberSpace::AppData] = 0;
  res = writeCryptoAndAckDataToSocket(
      *rawSocket,
      *conn,
      *conn->clientConnectionId,
      *conn->serverConnectionId,
      LongHeader::Types::Initial,
      *conn->initialWriteCipher,
      *conn->initialHeaderCipher,
      getVersion(*conn),
      conn->transportSettings.writeConnectionDataPacketsLimit);
  EXPECT_EQ(0, res.bytesWritten);
  EXPECT_EQ(0, res.packetsWritten);
  EXPECT_EQ(0, res.probesWritten);
}

TEST_F(QuicTransportFunctionsTest, ResetNumProbePackets) {
  auto conn = createConn();
  EventBase evb;
  auto socket =
      std::make_unique<NiceMock<folly::test::MockAsyncUDPSocket>>(&evb);
  auto rawSocket = socket.get();

  conn->pendingEvents.numProbePackets[PacketNumberSpace::Initial] = 2;
  auto writeRes1 = writeCryptoAndAckDataToSocket(
      *rawSocket,
      *conn,
      *conn->clientConnectionId,
      *conn->serverConnectionId,
      LongHeader::Types::Initial,
      *conn->initialWriteCipher,
      *conn->initialHeaderCipher,
      getVersion(*conn),
      conn->transportSettings.writeConnectionDataPacketsLimit);
  EXPECT_FALSE(conn->pendingEvents.anyProbePackets());
  EXPECT_EQ(0, writeRes1.bytesWritten);

  conn->handshakeWriteCipher = createNoOpAead();
  conn->handshakeWriteHeaderCipher = createNoOpHeaderCipher();
  conn->pendingEvents.numProbePackets[PacketNumberSpace::Handshake] = 2;
  auto writeRes2 = writeCryptoAndAckDataToSocket(
      *rawSocket,
      *conn,
      *conn->clientConnectionId,
      *conn->serverConnectionId,
      LongHeader::Types::Handshake,
      *conn->handshakeWriteCipher,
      *conn->handshakeWriteHeaderCipher,
      getVersion(*conn),
      conn->transportSettings.writeConnectionDataPacketsLimit);
  EXPECT_FALSE(conn->pendingEvents.anyProbePackets());
  EXPECT_EQ(0, writeRes2.bytesWritten);

  conn->oneRttWriteCipher = createNoOpAead();
  conn->oneRttWriteHeaderCipher = createNoOpHeaderCipher();
  conn->pendingEvents.numProbePackets[PacketNumberSpace::AppData] = 2;
  writeQuicDataToSocket(
      *rawSocket,
      *conn,
      *conn->clientConnectionId,
      *conn->serverConnectionId,
      *conn->oneRttWriteCipher,
      *conn->oneRttWriteHeaderCipher,
      getVersion(*conn),
      conn->transportSettings.writeConnectionDataPacketsLimit);
  EXPECT_FALSE(conn->pendingEvents.anyProbePackets());
}

TEST_F(QuicTransportFunctionsTest, WritePureAckWhenNoWritableBytes) {
  auto conn = createConn();
  auto mockCongestionController =
      std::make_unique<NiceMock<MockCongestionController>>();
  auto rawCongestionController = mockCongestionController.get();
  conn->congestionController = std::move(mockCongestionController);

  EventBase evb;
  auto socket =
      std::make_unique<NiceMock<folly::test::MockAsyncUDPSocket>>(&evb);
  auto rawSocket = socket.get();

  auto stream1 = conn->streamManager->createNextBidirectionalStream().value();
  auto buf = IOBuf::copyBuffer("0123456789012");
  writeDataToQuicStream(*stream1, buf->clone(), true);

  addAckStatesWithCurrentTimestamps(conn->ackStates.appDataAckState, 0, 100);
  conn->ackStates.appDataAckState.needsToSendAckImmediately = true;
  conn->ackStates.appDataAckState.largestAckScheduled = 50;

  EXPECT_CALL(*rawCongestionController, getWritableBytes())
      .WillRepeatedly(Return(0));

  EXPECT_CALL(*rawSocket, write(_, _))
      .WillRepeatedly(Invoke([&](const SocketAddress&,
                                 const std::unique_ptr<folly::IOBuf>& iobuf) {
        EXPECT_LE(iobuf->computeChainDataLength(), 30);
        return iobuf->computeChainDataLength();
      }));
  EXPECT_CALL(*rawCongestionController, onPacketSent(_)).Times(0);
  auto res = writeQuicDataToSocket(
      *rawSocket,
      *conn,
      *conn->clientConnectionId,
      *conn->serverConnectionId,
      *aead,
      *headerCipher,
      getVersion(*conn),
      conn->transportSettings.writeConnectionDataPacketsLimit);
  EXPECT_GT(res.packetsWritten, 0);
  EXPECT_EQ(0, conn->outstandings.packets.size());
}

TEST_F(QuicTransportFunctionsTest, ShouldWriteDataTest) {
  auto conn = createConn();

  auto mockCongestionController =
      std::make_unique<NiceMock<MockCongestionController>>();
  auto rawCongestionController = mockCongestionController.get();
  EXPECT_CALL(*rawCongestionController, getWritableBytes())
      .WillRepeatedly(Return(1500));
  conn->congestionController = std::move(mockCongestionController);

  EventBase evb;
  auto socket =
      std::make_unique<NiceMock<folly::test::MockAsyncUDPSocket>>(&evb);
  auto rawSocket = socket.get();

  // Pure acks without an oneRttCipher
  CHECK(!conn->oneRttWriteCipher);
  conn->ackStates.appDataAckState.needsToSendAckImmediately = true;
  addAckStatesWithCurrentTimestamps(conn->ackStates.appDataAckState, 1, 20);
  EXPECT_EQ(WriteDataReason::NO_WRITE, shouldWriteData(*conn));

  conn->oneRttWriteCipher = test::createNoOpAead();
  EXPECT_CALL(*quicStats_, onCwndBlocked()).Times(0);
  EXPECT_NE(WriteDataReason::NO_WRITE, shouldWriteData(*conn));

  auto stream1 = conn->streamManager->createNextBidirectionalStream().value();
  auto buf = IOBuf::copyBuffer("0123456789");
  writeDataToQuicStream(*stream1, buf->clone(), false);
  EXPECT_NE(WriteDataReason::NO_WRITE, shouldWriteData(*conn));

  writeQuicDataToSocket(
      *rawSocket,
      *conn,
      *conn->clientConnectionId,
      *conn->serverConnectionId,
      *aead,
      *headerCipher,
      getVersion(*conn),
      conn->transportSettings.writeConnectionDataPacketsLimit);
  EXPECT_EQ(WriteDataReason::NO_WRITE, shouldWriteData(*conn));

  // Congestion control
  EXPECT_CALL(*rawCongestionController, getWritableBytes())
      .WillRepeatedly(Return(0));
  EXPECT_CALL(*quicStats_, onCwndBlocked());
  writeDataToQuicStream(*stream1, buf->clone(), true);
  EXPECT_EQ(WriteDataReason::NO_WRITE, shouldWriteData(*conn));

  EXPECT_CALL(*quicStats_, onCwndBlocked());
  writeQuicDataToSocket(
      *rawSocket,
      *conn,
      *conn->clientConnectionId,
      *conn->serverConnectionId,
      *aead,
      *headerCipher,
      getVersion(*conn),
      conn->transportSettings.writeConnectionDataPacketsLimit);
  EXPECT_EQ(WriteDataReason::NO_WRITE, shouldWriteData(*conn));
}

TEST_F(QuicTransportFunctionsTest, ShouldWriteDataTestDuringPathValidation) {
  auto conn = createConn();

  // Create the CC.
  auto mockCongestionController =
      std::make_unique<NiceMock<MockCongestionController>>();
  auto rawCongestionController = mockCongestionController.get();
  conn->congestionController = std::move(mockCongestionController);
  conn->oneRttWriteCipher = test::createNoOpAead();

  // Create an outstandingPathValidation + limiter so this will be applied.
  auto pathValidationLimiter = std::make_unique<MockPendingPathRateLimiter>();
  MockPendingPathRateLimiter* rawLimiter = pathValidationLimiter.get();
  conn->pathValidationLimiter = std::move(pathValidationLimiter);
  conn->outstandingPathValidation = PathChallengeFrame(1000);

  // Have stream data queued up during the test so there's something TO write.
  auto stream1 = conn->streamManager->createNextBidirectionalStream().value();
  auto buf = IOBuf::copyBuffer("0123456789");
  writeDataToQuicStream(*stream1, buf->clone(), false);

  // Only case that we allow the write; both CC / PathLimiter have
  // writablebytes
  EXPECT_CALL(*rawCongestionController, getWritableBytes()).WillOnce(Return(1));
  EXPECT_CALL(*rawLimiter, currentCredit(_, _)).WillOnce(Return(1));

  EXPECT_CALL(*quicStats_, onCwndBlocked()).Times(0);
  EXPECT_NE(WriteDataReason::NO_WRITE, shouldWriteData(*conn));

  // CC has writableBytes, but PathLimiter doesn't.
  EXPECT_CALL(*rawCongestionController, getWritableBytes()).WillOnce(Return(1));
  EXPECT_CALL(*rawLimiter, currentCredit(_, _)).WillOnce(Return(0));

  EXPECT_CALL(*quicStats_, onCwndBlocked());
  EXPECT_EQ(WriteDataReason::NO_WRITE, shouldWriteData(*conn));

  // PathLimiter has writableBytes, CC doesn't
  EXPECT_CALL(*rawCongestionController, getWritableBytes()).WillOnce(Return(0));
  EXPECT_CALL(*rawLimiter, currentCredit(_, _)).WillOnce(Return(1));

  EXPECT_CALL(*quicStats_, onCwndBlocked());
  EXPECT_EQ(WriteDataReason::NO_WRITE, shouldWriteData(*conn));

  // Neither PathLimiter or CC have writablebytes
  EXPECT_CALL(*rawCongestionController, getWritableBytes()).WillOnce(Return(0));
  EXPECT_CALL(*rawLimiter, currentCredit(_, _)).WillOnce(Return(0));

  EXPECT_CALL(*quicStats_, onCwndBlocked());
  EXPECT_EQ(WriteDataReason::NO_WRITE, shouldWriteData(*conn));
}

TEST_F(QuicTransportFunctionsTest, ShouldWriteStreamsNoCipher) {
  auto conn = createConn();
  auto mockCongestionController =
      std::make_unique<NiceMock<MockCongestionController>>();
  auto rawCongestionController = mockCongestionController.get();
  EXPECT_CALL(*rawCongestionController, getWritableBytes())
      .WillRepeatedly(Return(1500));
  conn->congestionController = std::move(mockCongestionController);

  auto stream1 = conn->streamManager->createNextBidirectionalStream().value();
  auto buf = IOBuf::copyBuffer("0123456789");
  writeDataToQuicStream(*stream1, buf->clone(), false);
  EXPECT_EQ(WriteDataReason::NO_WRITE, shouldWriteData(*conn));
}

TEST_F(QuicTransportFunctionsTest, ShouldWritePureAcksNoCipher) {
  auto conn = createConn();
  auto mockCongestionController =
      std::make_unique<NiceMock<MockCongestionController>>();
  auto rawCongestionController = mockCongestionController.get();
  EXPECT_CALL(*rawCongestionController, getWritableBytes())
      .WillRepeatedly(Return(1500));
  conn->congestionController = std::move(mockCongestionController);

  conn->ackStates.appDataAckState.needsToSendAckImmediately = true;
  addAckStatesWithCurrentTimestamps(conn->ackStates.appDataAckState, 1, 20);
  EXPECT_EQ(WriteDataReason::NO_WRITE, shouldWriteData(*conn));
}

TEST_F(QuicTransportFunctionsTest, ShouldWriteDataNoConnFlowControl) {
  auto conn = createConn();
  conn->oneRttWriteCipher = test::createNoOpAead();
  auto mockCongestionController =
      std::make_unique<NiceMock<MockCongestionController>>();
  auto rawCongestionController = mockCongestionController.get();
  EXPECT_CALL(*rawCongestionController, getWritableBytes())
      .WillRepeatedly(Return(1500));
  auto stream1 = conn->streamManager->createNextBidirectionalStream().value();
  auto buf = IOBuf::copyBuffer("0123456789");
  writeDataToQuicStream(*stream1, buf->clone(), false);
  EXPECT_NE(WriteDataReason::NO_WRITE, shouldWriteData(*conn));
  // Artificially limit the connection flow control.
  conn->flowControlState.peerAdvertisedMaxOffset = 0;
  EXPECT_EQ(WriteDataReason::NO_WRITE, shouldWriteData(*conn));
}

TEST_F(QuicTransportFunctionsTest, ShouldWriteDataNoConnFlowControlLoss) {
  auto conn = createConn();
  conn->oneRttWriteCipher = test::createNoOpAead();
  auto mockCongestionController =
      std::make_unique<NiceMock<MockCongestionController>>();
  auto rawCongestionController = mockCongestionController.get();
  EXPECT_CALL(*rawCongestionController, getWritableBytes())
      .WillRepeatedly(Return(1500));
  auto stream1 = conn->streamManager->createNextBidirectionalStream().value();
  auto buf = IOBuf::copyBuffer("0123456789");
  writeDataToQuicStream(*stream1, buf->clone(), false);
  EXPECT_NE(WriteDataReason::NO_WRITE, shouldWriteData(*conn));
  // Artificially limit the connection flow control.
  conn->streamManager->addLoss(stream1->id);
  conn->flowControlState.peerAdvertisedMaxOffset = 0;
  EXPECT_NE(WriteDataReason::NO_WRITE, shouldWriteData(*conn));
}

TEST_F(QuicTransportFunctionsTest, HasAckDataToWriteCipherAndAckStateMatch) {
  auto conn = createConn();
  EXPECT_FALSE(hasAckDataToWrite(*conn));
  conn->initialWriteCipher = test::createNoOpAead();
  EXPECT_FALSE(hasAckDataToWrite(*conn));
  conn->ackStates.appDataAckState.needsToSendAckImmediately = true;
  conn->ackStates.appDataAckState.acks.insert(0, 100);
  EXPECT_FALSE(hasAckDataToWrite(*conn));
  conn->ackStates.initialAckState.needsToSendAckImmediately = true;
  conn->ackStates.initialAckState.acks.insert(0, 100);
  EXPECT_TRUE(hasAckDataToWrite(*conn));
}

TEST_F(QuicTransportFunctionsTest, HasAckDataToWriteNoImmediateAcks) {
  auto conn = createConn();
  conn->oneRttWriteCipher = test::createNoOpAead();
  conn->ackStates.appDataAckState.acks.insert(0, 100);
  conn->ackStates.appDataAckState.needsToSendAckImmediately = false;
  EXPECT_FALSE(hasAckDataToWrite(*conn));
  conn->ackStates.appDataAckState.needsToSendAckImmediately = true;
  EXPECT_TRUE(hasAckDataToWrite(*conn));
}

TEST_F(QuicTransportFunctionsTest, HasAckDataToWriteNoAcksScheduled) {
  auto conn = createConn();
  conn->oneRttWriteCipher = test::createNoOpAead();
  conn->ackStates.initialAckState.needsToSendAckImmediately = true;
  EXPECT_FALSE(hasAckDataToWrite(*conn));
}

TEST_F(QuicTransportFunctionsTest, HasAckDataToWrite) {
  auto conn = createConn();
  conn->oneRttWriteCipher = test::createNoOpAead();
  conn->ackStates.initialAckState.needsToSendAckImmediately = true;
  conn->ackStates.initialAckState.acks.insert(0);
  EXPECT_TRUE(hasAckDataToWrite(*conn));
}

TEST_F(QuicTransportFunctionsTest, HasAckDataToWriteMismatch) {
  // When one ack space has needsToSendAckImmediately = true and another has
  // hasAckToSchedule = true, but no ack space has both of them to true, we
  // should not send.
  auto conn = createConn();
  EXPECT_FALSE(hasAckDataToWrite(*conn));
  conn->ackStates.initialAckState.needsToSendAckImmediately = true;
  EXPECT_FALSE(hasAckDataToWrite(*conn));
  conn->ackStates.handshakeAckState.acks.insert(0, 10);
  conn->handshakeWriteCipher = test::createNoOpAead();
  EXPECT_FALSE(hasAckDataToWrite(*conn));
}

TEST_F(QuicTransportFunctionsTest, HasCryptoDataToWrite) {
  auto conn = createConn();
  conn->cryptoState->initialStream.lossBuffer.emplace_back(
      folly::IOBuf::copyBuffer("Grab your coat and get your hat"), 0, false);
  EXPECT_EQ(WriteDataReason::CRYPTO_STREAM, hasNonAckDataToWrite(*conn));
  conn->initialWriteCipher.reset();
  EXPECT_EQ(WriteDataReason::NO_WRITE, hasNonAckDataToWrite(*conn));
}

TEST_F(QuicTransportFunctionsTest, HasControlFramesToWrite) {
  auto conn = createConn();
  conn->streamManager->queueBlocked(1, 100);
  EXPECT_EQ(WriteDataReason::NO_WRITE, hasNonAckDataToWrite(*conn));

  conn->oneRttWriteCipher = test::createNoOpAead();
  EXPECT_EQ(WriteDataReason::BLOCKED, hasNonAckDataToWrite(*conn));
}

TEST_F(QuicTransportFunctionsTest, FlowControlBlocked) {
  auto conn = createConn();
  conn->flowControlState.peerAdvertisedMaxOffset = 1000;
  conn->flowControlState.sumCurWriteOffset = 1000;
  EXPECT_EQ(WriteDataReason::NO_WRITE, hasNonAckDataToWrite(*conn));
}

TEST_F(QuicTransportFunctionsTest, HasAppDataToWrite) {
  auto conn = createConn();
  conn->flowControlState.peerAdvertisedMaxOffset = 1000;
  conn->flowControlState.sumCurWriteOffset = 800;
  QuicStreamState stream(0, *conn);
  writeDataToQuicStream(stream, folly::IOBuf::copyBuffer("I'm a devil"), true);
  conn->streamManager->addWritable(stream);
  EXPECT_EQ(WriteDataReason::NO_WRITE, hasNonAckDataToWrite(*conn));

  conn->oneRttWriteCipher = test::createNoOpAead();
  EXPECT_EQ(WriteDataReason::STREAM, hasNonAckDataToWrite(*conn));
}

TEST_F(QuicTransportFunctionsTest, HasDatagramsToWrite) {
  auto conn = createConn();
  conn->oneRttWriteCipher = test::createNoOpAead();
  EXPECT_EQ(WriteDataReason::NO_WRITE, hasNonAckDataToWrite(*conn));
  conn->datagramState.writeBuffer.emplace_back(
      folly::IOBuf::copyBuffer("I'm an unreliable Datagram"));
  EXPECT_EQ(WriteDataReason::DATAGRAM, hasNonAckDataToWrite(*conn));
}

TEST_F(QuicTransportFunctionsTest, UpdateConnectionCloneCounterAppData) {
  auto conn = createConn();
  ASSERT_EQ(
      0, conn->outstandings.clonedPacketCount[PacketNumberSpace::AppData]);
  auto packet = buildEmptyPacket(*conn, PacketNumberSpace::AppData);
  auto connWindowUpdate =
      MaxDataFrame(conn->flowControlState.advertisedMaxOffset);
  conn->pendingEvents.connWindowUpdate = true;
  packet.packet.frames.emplace_back(connWindowUpdate);
  PacketEvent packetEvent(PacketNumberSpace::AppData, 100);
  conn->outstandings.packetEvents.insert(packetEvent);
  updateConnection(
      *conn,
      packetEvent,
      packet.packet,
      TimePoint(),
      123,
      100,
      false /* isDSRPacket */);
  EXPECT_EQ(
      0, conn->outstandings.clonedPacketCount[PacketNumberSpace::Initial]);
  EXPECT_EQ(
      0, conn->outstandings.clonedPacketCount[PacketNumberSpace::Handshake]);
  EXPECT_EQ(
      1, conn->outstandings.clonedPacketCount[PacketNumberSpace::AppData]);
}

TEST_F(QuicTransportFunctionsTest, UpdateConnectionCloneCounterHandshake) {
  auto conn = createConn();
  ASSERT_EQ(
      0, conn->outstandings.clonedPacketCount[PacketNumberSpace::Handshake]);
  auto packet = buildEmptyPacket(*conn, PacketNumberSpace::Handshake);
  auto connWindowUpdate =
      MaxDataFrame(conn->flowControlState.advertisedMaxOffset);
  conn->pendingEvents.connWindowUpdate = true;
  packet.packet.frames.emplace_back(connWindowUpdate);
  PacketEvent packetEvent(PacketNumberSpace::AppData, 100);
  conn->outstandings.packetEvents.insert(packetEvent);
  updateConnection(
      *conn,
      packetEvent,
      packet.packet,
      TimePoint(),
      123,
      123,
      false /* isDSRPacket */);
  EXPECT_EQ(
      0, conn->outstandings.clonedPacketCount[PacketNumberSpace::Initial]);
  EXPECT_EQ(
      1, conn->outstandings.clonedPacketCount[PacketNumberSpace::Handshake]);
  EXPECT_EQ(
      0, conn->outstandings.clonedPacketCount[PacketNumberSpace::AppData]);
}

TEST_F(QuicTransportFunctionsTest, UpdateConnectionCloneCounterInitial) {
  auto conn = createConn();
  ASSERT_EQ(
      0, conn->outstandings.clonedPacketCount[PacketNumberSpace::Initial]);
  auto packet = buildEmptyPacket(*conn, PacketNumberSpace::Initial);
  auto connWindowUpdate =
      MaxDataFrame(conn->flowControlState.advertisedMaxOffset);
  conn->pendingEvents.connWindowUpdate = true;
  packet.packet.frames.emplace_back(connWindowUpdate);
  PacketEvent packetEvent(PacketNumberSpace::AppData, 100);
  conn->outstandings.packetEvents.insert(packetEvent);
  updateConnection(
      *conn,
      packetEvent,
      packet.packet,
      TimePoint(),
      123,
      123,
      false /* isDSRPacket */);
  EXPECT_EQ(
      1, conn->outstandings.clonedPacketCount[PacketNumberSpace::Initial]);
  EXPECT_EQ(
      0, conn->outstandings.clonedPacketCount[PacketNumberSpace::Handshake]);
  EXPECT_EQ(
      0, conn->outstandings.clonedPacketCount[PacketNumberSpace::AppData]);
}

TEST_F(QuicTransportFunctionsTest, ClearBlockedFromPendingEvents) {
  auto conn = createConn();
  auto packet = buildEmptyPacket(*conn, PacketNumberSpace::Handshake);
  auto stream = conn->streamManager->createNextBidirectionalStream().value();
  StreamDataBlockedFrame blockedFrame(stream->id, 1000);
  packet.packet.frames.push_back(blockedFrame);
  conn->streamManager->queueBlocked(stream->id, 1000);
  updateConnection(
      *conn,
      folly::none,
      packet.packet,
      TimePoint(),
      getEncodedSize(packet),
      getEncodedBodySize(packet),
      false /* isDSRPacket */);
  EXPECT_FALSE(conn->streamManager->hasBlocked());
  EXPECT_FALSE(conn->outstandings.packets.empty());
  EXPECT_EQ(0, conn->outstandings.numClonedPackets());
}

TEST_F(QuicTransportFunctionsTest, ClonedBlocked) {
  auto conn = createConn();
  PacketEvent packetEvent(
      PacketNumberSpace::AppData,
      conn->ackStates.appDataAckState.nextPacketNum);
  auto packet = buildEmptyPacket(*conn, PacketNumberSpace::AppData);
  auto stream = conn->streamManager->createNextBidirectionalStream().value();
  StreamDataBlockedFrame blockedFrame(stream->id, 1000);
  packet.packet.frames.emplace_back(blockedFrame);
  conn->outstandings.packetEvents.insert(packetEvent);
  // This shall not crash
  updateConnection(
      *conn,
      packetEvent,
      packet.packet,
      TimePoint(),
      getEncodedSize(packet),
      getEncodedBodySize(packet),
      false /* isDSRPacket */);
  EXPECT_FALSE(conn->outstandings.packets.empty());
  EXPECT_EQ(
      1, conn->outstandings.clonedPacketCount[PacketNumberSpace::AppData]);
}

TEST_F(QuicTransportFunctionsTest, TwoConnWindowUpdateWillCrash) {
  auto conn = createConn();
  auto packet = buildEmptyPacket(*conn, PacketNumberSpace::Handshake);
  MaxDataFrame connWindowUpdate(
      1000 + conn->flowControlState.advertisedMaxOffset);
  packet.packet.frames.emplace_back(connWindowUpdate);
  packet.packet.frames.emplace_back(connWindowUpdate);
  conn->pendingEvents.connWindowUpdate = true;
  EXPECT_DEATH(
      updateConnection(
          *conn,
          folly::none,
          packet.packet,
          TimePoint(),
          getEncodedSize(packet),
          getEncodedBodySize(packet),
          false /* isDSRPacket */),
      ".*Send more than one connection window update.*");
}

TEST_F(QuicTransportFunctionsTest, WriteStreamFrameIsNotPureAck) {
  auto conn = createConn();
  auto stream = conn->streamManager->createNextBidirectionalStream().value();
  auto packet = buildEmptyPacket(*conn, PacketNumberSpace::Handshake);
  writeDataToQuicStream(
      *stream, folly::IOBuf::copyBuffer("I feel like a million bucks."), true);
  WriteStreamFrame writeStreamFrame(stream->id, 0, 5, false);
  packet.packet.frames.push_back(std::move(writeStreamFrame));
  updateConnection(
      *conn,
      folly::none,
      packet.packet,
      TimePoint(),
      getEncodedSize(packet),
      getEncodedBodySize(packet),
      false /* isDSRPacket */);
  EXPECT_FALSE(conn->outstandings.packets.empty());
}

TEST_F(QuicTransportFunctionsTest, ClearRstFromPendingEvents) {
  auto conn = createConn();
  auto stream = conn->streamManager->createNextBidirectionalStream().value();
  auto packet = buildEmptyPacket(*conn, PacketNumberSpace::Handshake);
  RstStreamFrame rstStreamFrame(
      stream->id, GenericApplicationErrorCode::UNKNOWN, 0);
  packet.packet.frames.push_back(rstStreamFrame);
  conn->pendingEvents.resets.emplace(stream->id, rstStreamFrame);
  updateConnection(
      *conn,
      folly::none,
      packet.packet,
      TimePoint(),
      getEncodedSize(packet),
      getEncodedBodySize(packet),
      false /* isDSRPacket */);
  EXPECT_TRUE(conn->pendingEvents.resets.empty());
  EXPECT_FALSE(conn->outstandings.packets.empty());
  EXPECT_EQ(0, conn->outstandings.numClonedPackets());
}

TEST_F(QuicTransportFunctionsTest, ClonedRst) {
  auto conn = createConn();
  PacketEvent packetEvent(
      PacketNumberSpace::AppData,
      conn->ackStates.appDataAckState.nextPacketNum);
  auto stream = conn->streamManager->createNextBidirectionalStream().value();
  auto packet = buildEmptyPacket(*conn, PacketNumberSpace::AppData);
  RstStreamFrame rstStreamFrame(
      stream->id, GenericApplicationErrorCode::UNKNOWN, 0);
  packet.packet.frames.emplace_back(std::move(rstStreamFrame));
  conn->outstandings.packetEvents.insert(packetEvent);
  // This shall not crash
  updateConnection(
      *conn,
      packetEvent,
      packet.packet,
      TimePoint(),
      getEncodedSize(packet),
      getEncodedBodySize(packet),
      false /* isDSRPacket */);
  EXPECT_FALSE(conn->outstandings.packets.empty());
  EXPECT_EQ(1, conn->outstandings.numClonedPackets());
}

TEST_F(QuicTransportFunctionsTest, TotalBytesSentUpdate) {
  auto conn = createConn();
  conn->lossState.totalBytesSent = 1234;
  conn->lossState.totalBodyBytesSent = 1000;
  auto packet = buildEmptyPacket(*conn, PacketNumberSpace::Handshake);
  updateConnection(
      *conn,
      folly::none,
      packet.packet,
      TimePoint{},
      4321,
      4000,
      false /* isDSRPacket */);
  EXPECT_EQ(5555, conn->lossState.totalBytesSent);
  EXPECT_EQ(5000, conn->lossState.totalBodyBytesSent);
}

TEST_F(QuicTransportFunctionsTest, TotalPacketsSentUpdate) {
  const auto startTotalPacketsSent = 1234;
  auto conn = createConn();
  conn->lossState.totalPacketsSent = startTotalPacketsSent;
  auto packet = buildEmptyPacket(*conn, PacketNumberSpace::Handshake);
  updateConnection(
      *conn,
      folly::none,
      packet.packet,
      TimePoint{},
      4321,
      0,
      false /* isDSRPacket */);
  EXPECT_EQ(startTotalPacketsSent + 1, conn->lossState.totalPacketsSent);
}

TEST_F(QuicTransportFunctionsTest, TimeoutBasedRetxCountUpdate) {
  auto conn = createConn();
  auto stream = conn->streamManager->createNextBidirectionalStream().value();
  conn->lossState.timeoutBasedRtxCount = 246;
  auto packet = buildEmptyPacket(*conn, PacketNumberSpace::AppData);
  RstStreamFrame rstStreamFrame(
      stream->id, GenericApplicationErrorCode::UNKNOWN, 0);
  packet.packet.frames.push_back(rstStreamFrame);
  PacketEvent packetEvent(PacketNumberSpace::AppData, 100);
  conn->outstandings.packetEvents.insert(packetEvent);
  updateConnection(
      *conn,
      packetEvent,
      packet.packet,
      TimePoint(),
      0,
      0,
      false /* isDSRPacket */);
  EXPECT_EQ(247, conn->lossState.timeoutBasedRtxCount);
}

TEST_F(QuicTransportFunctionsTest, WriteLimitBytRttFraction) {
  auto conn = createConn();
  conn->lossState.srtt = 50ms;
  auto mockCongestionController =
      std::make_unique<NiceMock<MockCongestionController>>();
  auto rawCongestionController = mockCongestionController.get();
  conn->congestionController = std::move(mockCongestionController);
  conn->transportSettings.batchingMode = QuicBatchingMode::BATCHING_MODE_NONE;

  EventBase evb;
  auto socket =
      std::make_unique<NiceMock<folly::test::MockAsyncUDPSocket>>(&evb);
  auto rawSocket = socket.get();

  auto stream1 = conn->streamManager->createNextBidirectionalStream().value();
  auto buf = buildRandomInputData(2048 * 2048);
  writeDataToQuicStream(*stream1, buf->clone(), true);

  EXPECT_CALL(*rawSocket, write(_, _)).WillRepeatedly(Return(1));
  EXPECT_CALL(*rawCongestionController, getWritableBytes())
      .WillRepeatedly(Return(50));
  auto writeLoopBeginTime = Clock::now();
  auto res = writeQuicDataToSocket(
      *rawSocket,
      *conn,
      *conn->clientConnectionId,
      *conn->serverConnectionId,
      *aead,
      *headerCipher,
      getVersion(*conn),
      1000 /* packetLimit */,
      writeLoopBeginTime);

  EXPECT_GT(1000, res.packetsWritten);
  EXPECT_EQ(res.probesWritten, 0);

  res = writeQuicDataToSocket(
      *rawSocket,
      *conn,
      *conn->clientConnectionId,
      *conn->serverConnectionId,
      *aead,
      *headerCipher,
      getVersion(*conn),
      1000 /* packetLimit */,
      writeLoopBeginTime);
  EXPECT_EQ(
      conn->transportSettings.writeConnectionDataPacketsLimit,
      res.packetsWritten);
}

TEST_F(QuicTransportFunctionsTest, CongestionControlWritableBytesRoundUp) {
  auto conn = createConn();
  conn->udpSendPacketLen = 2000;
  auto mockCongestionController =
      std::make_unique<NiceMock<MockCongestionController>>();
  auto rawCongestionController = mockCongestionController.get();
  conn->congestionController = std::move(mockCongestionController);

  EXPECT_CALL(*rawCongestionController, getWritableBytes()).WillOnce(Return(1));
  EXPECT_EQ(conn->udpSendPacketLen, congestionControlWritableBytes(*conn));

  EXPECT_CALL(*rawCongestionController, getWritableBytes())
      .WillOnce(Return(1000));
  EXPECT_EQ(conn->udpSendPacketLen, congestionControlWritableBytes(*conn));

  EXPECT_CALL(*rawCongestionController, getWritableBytes()).WillOnce(Return(0));
  EXPECT_EQ(0, congestionControlWritableBytes(*conn));

  EXPECT_CALL(*rawCongestionController, getWritableBytes())
      .WillOnce(Return(2000));
  EXPECT_EQ(conn->udpSendPacketLen, congestionControlWritableBytes(*conn));

  EXPECT_CALL(*rawCongestionController, getWritableBytes())
      .WillOnce(Return(2001));
  EXPECT_EQ(conn->udpSendPacketLen * 2, congestionControlWritableBytes(*conn));
}

TEST_F(QuicTransportFunctionsTest, HandshakeConfirmedDropCipher) {
  auto conn = createConn();
  conn->readCodec = std::make_unique<QuicReadCodec>(QuicNodeType::Server);
  EventBase evb;
  auto socket =
      std::make_unique<NiceMock<folly::test::MockAsyncUDPSocket>>(&evb);
  auto initialStream =
      getCryptoStream(*conn->cryptoState, EncryptionLevel::Initial);
  auto handshakeStream =
      getCryptoStream(*conn->cryptoState, EncryptionLevel::Handshake);
  writeDataToQuicStream(
      *initialStream, folly::IOBuf::copyBuffer("LittleRemedies"));
  writeDataToQuicStream(
      *handshakeStream,
      folly::IOBuf::copyBuffer("Where should I join the meeting"));
  ASSERT_NE(nullptr, conn->initialWriteCipher);
  conn->handshakeWriteCipher = createNoOpAead();
  conn->readCodec->setInitialReadCipher(createNoOpAead());
  conn->readCodec->setInitialHeaderCipher(createNoOpHeaderCipher());
  conn->readCodec->setHandshakeReadCipher(createNoOpAead());
  conn->readCodec->setHandshakeHeaderCipher(createNoOpHeaderCipher());
  conn->oneRttWriteCipher = createNoOpAead();
  conn->oneRttWriteHeaderCipher = createNoOpHeaderCipher();
  conn->readCodec->setOneRttReadCipher(createNoOpAead());
  conn->readCodec->setOneRttHeaderCipher(createNoOpHeaderCipher());
  writeCryptoDataProbesToSocketForTest(
      *socket,
      *conn,
      1,
      *aead,
      *headerCipher,
      getVersion(*conn),
      LongHeader::Types::Initial);
  writeCryptoDataProbesToSocketForTest(
      *socket,
      *conn,
      1,
      *aead,
      *headerCipher,
      getVersion(*conn),
      LongHeader::Types::Handshake);
  ASSERT_FALSE(initialStream->retransmissionBuffer.empty());
  ASSERT_FALSE(handshakeStream->retransmissionBuffer.empty());
  initialStream->insertIntoLossBuffer(std::make_unique<StreamBuffer>(
      folly::IOBuf::copyBuffer(
          "I don't see the dialup info in the meeting invite"),
      0,
      false));
  handshakeStream->insertIntoLossBuffer(std::make_unique<StreamBuffer>(
      folly::IOBuf::copyBuffer("Traffic Protocol Weekly Sync"), 0, false));

  handshakeConfirmed(*conn);
  EXPECT_TRUE(initialStream->writeBuffer.empty());
  EXPECT_TRUE(initialStream->retransmissionBuffer.empty());
  EXPECT_TRUE(initialStream->lossBuffer.empty());
  EXPECT_TRUE(handshakeStream->writeBuffer.empty());
  EXPECT_TRUE(handshakeStream->retransmissionBuffer.empty());
  EXPECT_TRUE(handshakeStream->lossBuffer.empty());
  EXPECT_EQ(nullptr, conn->initialWriteCipher);
  EXPECT_EQ(nullptr, conn->handshakeWriteCipher);
  EXPECT_EQ(nullptr, conn->readCodec->getInitialCipher());
  EXPECT_EQ(nullptr, conn->readCodec->getInitialHeaderCipher());
  EXPECT_EQ(nullptr, conn->readCodec->getHandshakeReadCipher());
  EXPECT_EQ(nullptr, conn->readCodec->getHandshakeHeaderCipher());
}

TEST_F(QuicTransportFunctionsTest, ProbeWriteNewFunctionalFrames) {
  auto conn = createConn();
  conn->udpSendPacketLen = 1200;
  EventBase evb;
  auto sock = std::make_unique<NiceMock<folly::test::MockAsyncUDPSocket>>(&evb);
  auto rawSocket = sock.get();

  EXPECT_CALL(*rawSocket, write(_, _))
      .WillRepeatedly(Invoke([&](const SocketAddress&,
                                 const std::unique_ptr<folly::IOBuf>& iobuf) {
        return iobuf->computeChainDataLength();
      }));

  auto stream = conn->streamManager->createNextBidirectionalStream().value();
  auto buf = folly::IOBuf::copyBuffer("Drug facts");
  writeDataToQuicStream(*stream, buf->clone(), true);
  writeQuicDataToSocket(
      *rawSocket,
      *conn,
      *conn->clientConnectionId,
      *conn->serverConnectionId,
      *aead,
      *headerCipher,
      getVersion(*conn),
      conn->transportSettings.writeConnectionDataPacketsLimit);
  ASSERT_EQ(1, stream->retransmissionBuffer.size());

  conn->pendingEvents.numProbePackets[PacketNumberSpace::AppData] = 1;
  conn->flowControlState.windowSize *= 2;
  conn->flowControlState.timeOfLastFlowControlUpdate = Clock::now() - 20s;
  maybeSendConnWindowUpdate(*conn, Clock::now());
  writeQuicDataToSocket(
      *rawSocket,
      *conn,
      *conn->clientConnectionId,
      *conn->serverConnectionId,
      *aead,
      *headerCipher,
      getVersion(*conn),
      1 /* limit to 1 packet */);
  EXPECT_EQ(2, conn->outstandings.packets.size());
  auto packet = stripPaddingFrames(conn->outstandings.packets[1].packet);
  EXPECT_EQ(1, packet.frames.size());
  EXPECT_EQ(
      QuicWriteFrame::Type::MaxDataFrame,
      conn->outstandings.packets[1].packet.frames[0].type());
}

TEST_F(QuicTransportFunctionsTest, WriteWithInplaceBuilder) {
  auto conn = createConn();
  conn->transportSettings.dataPathType = DataPathType::ContinuousMemory;
  auto simpleBufAccessor =
      std::make_unique<SimpleBufAccessor>(conn->udpSendPacketLen * 16);
  auto outputBuf = simpleBufAccessor->obtain();
  auto bufPtr = outputBuf.get();
  simpleBufAccessor->release(std::move(outputBuf));
  conn->bufAccessor = simpleBufAccessor.get();
  conn->transportSettings.batchingMode = QuicBatchingMode::BATCHING_MODE_GSO;
  EventBase evb;
  folly::test::MockAsyncUDPSocket mockSock(&evb);
  EXPECT_CALL(mockSock, getGSO()).WillRepeatedly(Return(true));
  auto stream = conn->streamManager->createNextBidirectionalStream().value();
  auto buf = folly::IOBuf::copyBuffer("Andante in C minor");
  writeDataToQuicStream(*stream, buf->clone(), true);
  EXPECT_CALL(mockSock, write(_, _))
      .Times(1)
      .WillOnce(Invoke([&](const SocketAddress&,
                           const std::unique_ptr<folly::IOBuf>& sockBuf) {
        EXPECT_GT(bufPtr->length(), 0);
        EXPECT_GE(sockBuf->length(), buf->length());
        EXPECT_EQ(sockBuf.get(), bufPtr);
        EXPECT_TRUE(folly::IOBufEqualTo()(*sockBuf, *bufPtr));
        EXPECT_FALSE(sockBuf->isChained());
        return sockBuf->computeChainDataLength();
      }));
  writeQuicDataToSocket(
      mockSock,
      *conn,
      *conn->clientConnectionId,
      *conn->serverConnectionId,
      *aead,
      *headerCipher,
      getVersion(*conn),
      conn->transportSettings.writeConnectionDataPacketsLimit);
  EXPECT_EQ(0, bufPtr->length());
  EXPECT_EQ(0, bufPtr->headroom());
}

TEST_F(QuicTransportFunctionsTest, WriteWithInplaceBuilderRollbackBuf) {
  auto conn = createConn();
  conn->transportSettings.dataPathType = DataPathType::ContinuousMemory;
  auto simpleBufAccessor =
      std::make_unique<SimpleBufAccessor>(conn->udpSendPacketLen * 16);
  auto outputBuf = simpleBufAccessor->obtain();
  auto bufPtr = outputBuf.get();
  simpleBufAccessor->release(std::move(outputBuf));
  conn->bufAccessor = simpleBufAccessor.get();
  conn->transportSettings.batchingMode = QuicBatchingMode::BATCHING_MODE_GSO;
  EventBase evb;
  folly::test::MockAsyncUDPSocket mockSock(&evb);
  EXPECT_CALL(mockSock, getGSO()).WillRepeatedly(Return(true));
  EXPECT_CALL(mockSock, write(_, _)).Times(0);
  writeQuicDataToSocket(
      mockSock,
      *conn,
      *conn->clientConnectionId,
      *conn->serverConnectionId,
      *aead,
      *headerCipher,
      getVersion(*conn),
      conn->transportSettings.writeConnectionDataPacketsLimit);
  EXPECT_EQ(0, bufPtr->length());
  EXPECT_EQ(0, bufPtr->headroom());
}

TEST_F(QuicTransportFunctionsTest, WriteWithInplaceBuilderGSOMultiplePackets) {
  auto conn = createConn();
  conn->transportSettings.dataPathType = DataPathType::ContinuousMemory;
  auto simpleBufAccessor =
      std::make_unique<SimpleBufAccessor>(conn->udpSendPacketLen * 16);
  auto outputBuf = simpleBufAccessor->obtain();
  auto bufPtr = outputBuf.get();
  simpleBufAccessor->release(std::move(outputBuf));
  conn->bufAccessor = simpleBufAccessor.get();
  conn->transportSettings.batchingMode = QuicBatchingMode::BATCHING_MODE_GSO;
  EventBase evb;
  folly::test::MockAsyncUDPSocket mockSock(&evb);
  EXPECT_CALL(mockSock, getGSO()).WillRepeatedly(Return(true));
  auto stream = conn->streamManager->createNextBidirectionalStream().value();
  auto buf = buildRandomInputData(conn->udpSendPacketLen * 10);
  writeDataToQuicStream(*stream, buf->clone(), true);
  EXPECT_CALL(mockSock, writeGSO(_, _, _))
      .Times(1)
      .WillOnce(Invoke([&](const folly::SocketAddress&,
                           const std::unique_ptr<folly::IOBuf>& sockBuf,
                           int gso) {
        EXPECT_LE(gso, conn->udpSendPacketLen);
        EXPECT_GT(bufPtr->length(), 0);
        EXPECT_EQ(sockBuf.get(), bufPtr);
        EXPECT_TRUE(folly::IOBufEqualTo()(*sockBuf, *bufPtr));
        EXPECT_FALSE(sockBuf->isChained());
        return sockBuf->length();
      }));
  writeQuicDataToSocket(
      mockSock,
      *conn,
      *conn->clientConnectionId,
      *conn->serverConnectionId,
      *aead,
      *headerCipher,
      getVersion(*conn),
      conn->transportSettings.writeConnectionDataPacketsLimit);
  EXPECT_EQ(0, bufPtr->length());
  EXPECT_EQ(0, bufPtr->headroom());
}

TEST_F(QuicTransportFunctionsTest, WriteProbingWithInplaceBuilder) {
  auto conn = createConn();
  conn->transportSettings.dataPathType = DataPathType::ContinuousMemory;
  conn->transportSettings.batchingMode = QuicBatchingMode::BATCHING_MODE_GSO;
  EventBase evb;
  folly::test::MockAsyncUDPSocket mockSock(&evb);
  EXPECT_CALL(mockSock, getGSO()).WillRepeatedly(Return(true));

  SimpleBufAccessor bufAccessor(
      conn->udpSendPacketLen * conn->transportSettings.maxBatchSize);
  conn->bufAccessor = &bufAccessor;
  auto buf = bufAccessor.obtain();
  auto bufPtr = buf.get();
  bufAccessor.release(std::move(buf));

  auto stream = conn->streamManager->createNextBidirectionalStream().value();
  auto inputBuf = buildRandomInputData(
      conn->udpSendPacketLen *
      conn->transportSettings.writeConnectionDataPacketsLimit);
  writeDataToQuicStream(*stream, inputBuf->clone(), true);
  EXPECT_CALL(mockSock, writeGSO(_, _, _))
      .Times(1)
      .WillOnce(Invoke([&](const folly::SocketAddress&,
                           const std::unique_ptr<folly::IOBuf>& sockBuf,
                           int gso) {
        EXPECT_LE(gso, conn->udpSendPacketLen);
        EXPECT_GE(
            bufPtr->length(),
            conn->udpSendPacketLen *
                conn->transportSettings.writeConnectionDataPacketsLimit);
        EXPECT_EQ(sockBuf.get(), bufPtr);
        EXPECT_TRUE(folly::IOBufEqualTo()(*sockBuf, *bufPtr));
        EXPECT_FALSE(sockBuf->isChained());
        return sockBuf->length();
      }));
  writeQuicDataToSocket(
      mockSock,
      *conn,
      *conn->clientConnectionId,
      *conn->serverConnectionId,
      *aead,
      *headerCipher,
      getVersion(*conn),
      conn->transportSettings.writeConnectionDataPacketsLimit + 1);
  ASSERT_EQ(0, bufPtr->length());
  ASSERT_EQ(0, bufPtr->headroom());
  EXPECT_GE(conn->outstandings.packets.size(), 5);
  // Make sure there no more new data to write:
  StreamFrameScheduler streamScheduler(*conn);
  ASSERT_FALSE(streamScheduler.hasPendingData());

  // The first packet has be a full packet
  auto firstPacketSize =
      conn->outstandings.packets.front().metadata.encodedSize;
  auto outstandingPacketsCount = conn->outstandings.packets.size();
  ASSERT_EQ(firstPacketSize, conn->udpSendPacketLen);
  EXPECT_CALL(mockSock, write(_, _))
      .Times(1)
      .WillOnce(Invoke([&](const folly::SocketAddress&,
                           const std::unique_ptr<folly::IOBuf>& buf) {
        EXPECT_FALSE(buf->isChained());
        EXPECT_EQ(buf->length(), firstPacketSize);
        return buf->length();
      }));
  writeProbingDataToSocketForTest(
      mockSock,
      *conn,
      1 /* probesToSend */,
      *aead,
      *headerCipher,
      getVersion(*conn));
  EXPECT_EQ(conn->outstandings.packets.size(), outstandingPacketsCount + 1);
  EXPECT_EQ(0, bufPtr->length());
  EXPECT_EQ(0, bufPtr->headroom());

  // Clone again, this time 2 pacckets.
  EXPECT_CALL(mockSock, writeGSO(_, _, _))
      .Times(1)
      .WillOnce(Invoke([&](const folly::SocketAddress&,
                           const std::unique_ptr<folly::IOBuf>& buf,
                           int gso) {
        EXPECT_FALSE(buf->isChained());
        EXPECT_EQ(conn->udpSendPacketLen, gso);
        EXPECT_EQ(buf->length(), conn->udpSendPacketLen * 2);
        return buf->length();
      }));
  writeProbingDataToSocketForTest(
      mockSock,
      *conn,
      2 /* probesToSend */,
      *aead,
      *headerCipher,
      getVersion(*conn));
  EXPECT_EQ(0, bufPtr->length());
  EXPECT_EQ(0, bufPtr->headroom());
  EXPECT_EQ(conn->outstandings.packets.size(), outstandingPacketsCount + 3);
}

TEST_F(QuicTransportFunctionsTest, WriteD6DProbesWithInplaceBuilder) {
  auto conn = createConn();
  conn->transportSettings.dataPathType = DataPathType::ContinuousMemory;
  conn->d6d.currentProbeSize = 1450;
  conn->pendingEvents.d6d.sendProbePacket = true;
  auto simpleBufAccessor =
      std::make_unique<SimpleBufAccessor>(kDefaultMaxUDPPayload * 16);
  auto outputBuf = simpleBufAccessor->obtain();
  auto bufPtr = outputBuf.get();
  simpleBufAccessor->release(std::move(outputBuf));
  conn->bufAccessor = simpleBufAccessor.get();
  conn->transportSettings.batchingMode = QuicBatchingMode::BATCHING_MODE_GSO;
  EventBase evb;
  folly::test::MockAsyncUDPSocket mockSock(&evb);
  EXPECT_CALL(mockSock, getGSO()).WillRepeatedly(Return(true));
  EXPECT_CALL(mockSock, write(_, _))
      .Times(1)
      .WillOnce(Invoke([&](const SocketAddress&,
                           const std::unique_ptr<folly::IOBuf>& sockBuf) {
        EXPECT_EQ(sockBuf->length(), conn->d6d.currentProbeSize);
        EXPECT_EQ(sockBuf.get(), bufPtr);
        EXPECT_TRUE(folly::IOBufEqualTo()(*sockBuf, *bufPtr));
        EXPECT_FALSE(sockBuf->isChained());
        return sockBuf->computeChainDataLength();
      }));
  writeD6DProbeToSocket(
      mockSock,
      *conn,
      *conn->clientConnectionId,
      *conn->serverConnectionId,
      *aead,
      *headerCipher,
      getVersion(*conn));
  EXPECT_EQ(0, bufPtr->length());
  EXPECT_EQ(0, bufPtr->headroom());
}

TEST_F(QuicTransportFunctionsTest, UpdateConnectionWithBufferMeta) {
  auto conn = createConn();
  // Builds a fake packet to test with.
  auto packet = buildEmptyPacket(*conn, PacketNumberSpace::AppData);

  auto streamId =
      conn->streamManager->createNextBidirectionalStream().value()->id;
  auto stream = conn->streamManager->findStream(streamId);
  EXPECT_TRUE(stream->retransmissionBufMetas.empty());
  writeDataToQuicStream(
      *stream, IOBuf::copyBuffer("Wear a face mask please!"), false /* eof */);
  BufferMeta bufMeta(2000);
  writeBufMetaToQuicStream(*stream, bufMeta, true /* eof */);
  EXPECT_TRUE(stream->writeBufMeta.eof);
  EXPECT_EQ(2000, stream->writeBufMeta.length);
  auto bufMetaStartingOffset = stream->writeBufMeta.offset;
  WriteStreamFrame writeStreamFrame(
      streamId, bufMetaStartingOffset, 1000, false /* fin */);
  writeStreamFrame.fromBufMeta = true;
  packet.packet.frames.push_back(writeStreamFrame);

  updateConnection(
      *conn,
      folly::none,
      packet.packet,
      TimePoint(),
      getEncodedSize(packet),
      getEncodedBodySize(packet),
      true /* dsr */);
  EXPECT_EQ(1000 + bufMetaStartingOffset, stream->writeBufMeta.offset);
  EXPECT_EQ(1000, stream->writeBufMeta.length);
  EXPECT_FALSE(stream->retransmissionBufMetas.empty());
  auto retxBufMetaIter =
      stream->retransmissionBufMetas.find(bufMetaStartingOffset);
  EXPECT_NE(retxBufMetaIter, stream->retransmissionBufMetas.end());
  EXPECT_EQ(bufMetaStartingOffset, retxBufMetaIter->second.offset);
  EXPECT_EQ(1000, retxBufMetaIter->second.length);
  EXPECT_FALSE(retxBufMetaIter->second.eof);
  EXPECT_TRUE(conn->outstandings.packets.back().isDSRPacket);

  // Manually lose this packet:
  stream->lossBufMetas.push_back(retxBufMetaIter->second);
  stream->retransmissionBufMetas.erase(retxBufMetaIter);
  ASSERT_FALSE(stream->lossBufMetas.empty());
  ASSERT_TRUE(stream->retransmissionBufMetas.empty());

  // Retransmit it:
  auto retxPacket = buildEmptyPacket(*conn, PacketNumberSpace::AppData);
  // Retx of the stream looks exactly the same
  retxPacket.packet.frames.push_back(writeStreamFrame);
  updateConnection(
      *conn,
      folly::none,
      retxPacket.packet,
      TimePoint(),
      getEncodedSize(retxPacket),
      getEncodedBodySize(packet),
      true /* dsr */);
  EXPECT_TRUE(stream->lossBufMetas.empty());
  retxBufMetaIter = stream->retransmissionBufMetas.find(bufMetaStartingOffset);
  EXPECT_NE(retxBufMetaIter, stream->retransmissionBufMetas.end());
  EXPECT_EQ(bufMetaStartingOffset, retxBufMetaIter->second.offset);
  EXPECT_EQ(1000, retxBufMetaIter->second.length);
  EXPECT_FALSE(retxBufMetaIter->second.eof);
  EXPECT_TRUE(conn->outstandings.packets.back().isDSRPacket);
}

TEST_F(QuicTransportFunctionsTest, MissingStreamFrameBytes) {
  auto conn = createConn();
  auto packet = buildEmptyPacket(*conn, PacketNumberSpace::AppData);
  auto stream = conn->streamManager->createNextBidirectionalStream().value();
  writeDataToQuicStream(*stream, folly::IOBuf::copyBuffer("abcdefghij"), true);

  // write frame with bytes 0 -> 3 (start at offset 0, write 4 bytes)
  {
    WriteStreamFrame writeStreamFrame(
        stream->id, 0 /* offset */, 4 /* len */, false /* fin */);
    packet.packet.frames.push_back(writeStreamFrame);
    updateConnection(
        *conn,
        folly::none,
        packet.packet,
        TimePoint(),
        getEncodedSize(packet),
        getEncodedBodySize(packet),
        false /* isDSRPacket */);
  }

  // write frame with bytes 5 -> 6 (start at offset 5, write 2 bytes)
  // should throw since we never wrote byte offset 4
  {
    WriteStreamFrame writeStreamFrame(
        stream->id, 5 /* offset */, 2 /* len */, false /* fin */);
    packet.packet.frames.push_back(writeStreamFrame);
    EXPECT_ANY_THROW(updateConnection(
        *conn,
        folly::none,
        packet.packet,
        TimePoint(),
        getEncodedSize(packet),
        getEncodedBodySize(packet),
        false /* isDSRPacket */));
  }
}

TEST_F(QuicTransportFunctionsTest, MissingStreamFrameBytesEof) {
  auto conn = createConn();
  auto packet = buildEmptyPacket(*conn, PacketNumberSpace::AppData);
  auto stream = conn->streamManager->createNextBidirectionalStream().value();
  const std::string str = "abcdefg";
  writeDataToQuicStream(*stream, folly::IOBuf::copyBuffer(str), true);

  // write frame with bytes 0 -> 3 (start at offset 0, write 4 bytes)
  {
    WriteStreamFrame writeStreamFrame(
        stream->id, 0 /* offset */, 4 /* len */, false /* fin */);
    packet.packet.frames.push_back(writeStreamFrame);
    updateConnection(
        *conn,
        folly::none,
        packet.packet,
        TimePoint(),
        getEncodedSize(packet),
        getEncodedBodySize(packet),
        false /* isDSRPacket */);
  }

  // write frame with bytes 5 -> 6 (start at offset 5, write 2 bytes)
  // offset 6 should be last byte in original stream, so we'll mark fin
  //
  // should throw since we never wrote byte offset 4
  {
    const auto offset = 5;
    const auto len = 2;
    EXPECT_EQ(str.length(), offset + len); // should be end of string
    WriteStreamFrame writeStreamFrame(
        stream->id, offset /* offset */, len /* len */, true /* fin */);
    packet.packet.frames.push_back(writeStreamFrame);
    EXPECT_ANY_THROW(updateConnection(
        *conn,
        folly::none,
        packet.packet,
        TimePoint(),
        getEncodedSize(packet),
        getEncodedBodySize(packet),
        false /* isDSRPacket */));
  }
}

TEST_F(QuicTransportFunctionsTest, MissingStreamFrameBytesSingleByteWrite) {
  auto conn = createConn();
  auto packet = buildEmptyPacket(*conn, PacketNumberSpace::AppData);
  auto stream = conn->streamManager->createNextBidirectionalStream().value();
  const std::string str = "abcdefg";
  writeDataToQuicStream(*stream, folly::IOBuf::copyBuffer(str), true);

  // write frame with bytes 0 -> 3 (start at offset 0, write 4 bytes)
  {
    WriteStreamFrame writeStreamFrame(
        stream->id, 0 /* offset */, 4 /* len */, false /* fin */);
    packet.packet.frames.push_back(writeStreamFrame);
    updateConnection(
        *conn,
        folly::none,
        packet.packet,
        TimePoint(),
        getEncodedSize(packet),
        getEncodedBodySize(packet),
        false /* isDSRPacket */);
  }

  // write frame with bytes 5 -> 5 (start at offset 5, write 1 byte)
  // should throw since we never wrote byte offset 4
  {
    WriteStreamFrame writeStreamFrame(
        stream->id, 5 /* offset */, 1 /* len */, false /* fin */);
    packet.packet.frames.push_back(writeStreamFrame);
    EXPECT_ANY_THROW(updateConnection(
        *conn,
        folly::none,
        packet.packet,
        TimePoint(),
        getEncodedSize(packet),
        getEncodedBodySize(packet),
        false /* isDSRPacket */));
  }
}

} // namespace test
} // namespace quic
