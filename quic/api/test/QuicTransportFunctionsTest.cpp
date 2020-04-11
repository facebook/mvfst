/*
 * Copyright (c) Facebook, Inc. and its affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 *
 */

#include <quic/api/QuicTransportFunctions.h>

#include <folly/io/async/test/MockAsyncUDPSocket.h>
#include <quic/api/test/Mocks.h>
#include <quic/common/test/TestUtils.h>
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
      LongHeader::typeToPacketNumberSpace(type),
      scheduler,
      probesToSend,
      aead,
      headerCipher,
      version);
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
      getAckState(conn, pnSpace).largestAckedByPeer);
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

class QuicTransportFunctionsTest : public Test {
 public:
  void SetUp() override {
    aead = test::createNoOpAead();
    headerCipher = test::createNoOpHeaderCipher();
    transportInfoCb_ = std::make_unique<NiceMock<MockQuicStats>>();
  }

  std::unique_ptr<QuicServerConnectionState> createConn() {
    auto conn = std::make_unique<QuicServerConnectionState>();
    conn->serverConnectionId = getTestConnectionId();
    conn->clientConnectionId = getTestConnectionId();
    conn->version = QuicVersion::MVFST;
    conn->flowControlState.peerAdvertisedInitialMaxStreamOffsetBidiLocal =
        kDefaultStreamWindowSize;
    conn->flowControlState.peerAdvertisedInitialMaxStreamOffsetBidiRemote =
        kDefaultStreamWindowSize;
    conn->flowControlState.peerAdvertisedInitialMaxStreamOffsetUni =
        kDefaultStreamWindowSize;
    conn->flowControlState.peerAdvertisedMaxOffset =
        kDefaultConnectionWindowSize;
    conn->statsCallback = transportInfoCb_.get();
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
  std::unique_ptr<MockQuicStats> transportInfoCb_;
};

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
  EXPECT_CALL(*transportInfoCb_, onPacketRetransmission()).Times(2);
  writeDataToQuicStream(*stream1, buf->clone(), true);
  writeDataToQuicStream(*stream2, buf->clone(), true);

  WriteStreamFrame writeStreamFrame1(stream1->id, 0, 5, false),
      writeStreamFrame2(stream2->id, 0, 12, true);
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
      *conn, folly::none, packet.packet, TimePoint{}, getEncodedSize(packet));

  EXPECT_EQ(
      conn->ackStates.initialAckState.nextPacketNum,
      currentNextInitialPacketNum);
  EXPECT_GT(
      conn->ackStates.handshakeAckState.nextPacketNum,
      currentNextHandshakePacketNum);
  EXPECT_EQ(
      conn->ackStates.appDataAckState.nextPacketNum,
      currentNextAppDataPacketNum);
  EXPECT_TRUE(conn->outstandingPackets.back().isAppLimited);

  EXPECT_EQ(stream1->retransmissionBuffer.size(), 1);
  auto& rt1 = *stream1->retransmissionBuffer.at(0);

  EXPECT_EQ(stream1->currentWriteOffset, 5);
  EXPECT_EQ(stream2->currentWriteOffset, 13);

  IOBufEqualTo eq;
  EXPECT_EQ(rt1.offset, 0);
  EXPECT_TRUE(eq(*IOBuf::copyBuffer("hey w"), *rt1.data.front()));

  EXPECT_EQ(stream2->retransmissionBuffer.size(), 1);
  auto& rt2 = *stream2->retransmissionBuffer.at(0);

  EXPECT_EQ(rt2.offset, 0);
  EXPECT_TRUE(eq(*buf, *rt2.data.front()));
  EXPECT_TRUE(rt2.eof);

  EXPECT_EQ(conn->flowControlState.sumCurWriteOffset, 17);

  // Testing retransmission
  stream1->lossBuffer.push_back(std::move(rt1));
  stream1->retransmissionBuffer.clear();
  stream2->lossBuffer.push_back(std::move(rt2));
  stream2->retransmissionBuffer.clear();
  conn->streamManager->addLoss(stream1->id);
  conn->streamManager->addLoss(stream2->id);

  // Write the remainder of the data
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
      *conn, folly::none, packet2.packet, TimePoint(), getEncodedSize(packet));
  EXPECT_EQ(
      conn->ackStates.initialAckState.nextPacketNum,
      currentNextInitialPacketNum);
  EXPECT_GT(
      conn->ackStates.handshakeAckState.nextPacketNum,
      currentNextHandshakePacketNum);
  EXPECT_EQ(
      conn->ackStates.appDataAckState.nextPacketNum,
      currentNextAppDataPacketNum);
  EXPECT_FALSE(conn->outstandingPackets.back().isAppLimited);

  EXPECT_EQ(stream1->currentWriteOffset, 13);
  EXPECT_EQ(stream1->currentWriteOffset, 13);

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
    EXPECT_EQ(event->packetType, toString(LongHeader::Types::Handshake));
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
      getEncodedSize(handshakePacket));
  updateConnection(
      *conn,
      folly::none,
      initialPacket.packet,
      TimePoint{},
      getEncodedSize(initialPacket));
  updateConnection(
      *conn,
      folly::none,
      appDataPacket.packet,
      TimePoint{},
      getEncodedSize(appDataPacket));
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

  EXPECT_EQ(event1->packetType, toString(LongHeader::Types::Handshake));
  EXPECT_EQ(event2->packetType, toString(LongHeader::Types::Initial));
  EXPECT_EQ(event3->packetType, toString(LongHeader::Types::ZeroRtt));

  EXPECT_EQ(3, conn->outstandingPackets.size());
  auto& firstHeader = conn->outstandingPackets.front().packet.header;
  auto firstPacketNum = firstHeader.getPacketSequenceNum();
  EXPECT_EQ(0, firstPacketNum);
  EXPECT_EQ(1, event1->packetNum);

  EXPECT_EQ(PacketNumberSpace::Initial, firstHeader.getPacketNumberSpace());

  auto& lastHeader = conn->outstandingPackets.back().packet.header;

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
      *conn, folly::none, packet.packet, TimePoint(), getEncodedSize(packet));

  // verify QLogger contains correct packet information
  std::shared_ptr<quic::FileQLogger> qLogger =
      std::dynamic_pointer_cast<quic::FileQLogger>(conn->qLogger);
  std::vector<int> indices =
      getQLogEventIndices(QLogEventType::PacketSent, qLogger);
  EXPECT_EQ(indices.size(), 1);
  auto tmp = std::move(qLogger->logs[indices[0]]);

  auto event = dynamic_cast<QLogPacketEvent*>(tmp.get());
  EXPECT_EQ(event->packetType, toString(LongHeader::Types::Handshake));
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
      *conn, folly::none, packet.packet, TimePoint(), getEncodedSize(packet));

  // verify QLogger contains correct packet information
  std::shared_ptr<quic::FileQLogger> qLogger =
      std::dynamic_pointer_cast<quic::FileQLogger>(conn->qLogger);
  std::vector<int> indices =
      getQLogEventIndices(QLogEventType::PacketSent, qLogger);
  EXPECT_EQ(indices.size(), 1);
  auto tmp = std::move(qLogger->logs[indices[0]]);
  auto event = dynamic_cast<QLogPacketEvent*>(tmp.get());

  EXPECT_EQ(event->packetType, toString(LongHeader::Types::Handshake));
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
      *conn, folly::none, packet.packet, TimePoint(), getEncodedSize(packet));

  // verify QLogger contains correct packet information
  std::shared_ptr<quic::FileQLogger> qLogger =
      std::dynamic_pointer_cast<quic::FileQLogger>(conn->qLogger);
  std::vector<int> indices =
      getQLogEventIndices(QLogEventType::PacketSent, qLogger);
  EXPECT_EQ(indices.size(), 1);
  auto tmp = std::move(qLogger->logs[indices[0]]);
  auto event = dynamic_cast<QLogPacketEvent*>(tmp.get());
  EXPECT_EQ(event->packetType, toString(LongHeader::Types::Handshake));
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
  EXPECT_EQ(0, conn->outstandingHandshakePacketsCount);

  auto packet = buildEmptyPacket(*conn, PacketNumberSpace::Handshake);
  auto packetEncodedSize =
      packet.header ? packet.header->computeChainDataLength() : 0;
  packetEncodedSize += packet.body ? packet.body->computeChainDataLength() : 0;

  WriteAckFrame ackFrame;
  ackFrame.ackBlocks.emplace_back(0, 100);
  packet.packet.frames.push_back(std::move(ackFrame));
  updateConnection(
      *conn, folly::none, packet.packet, TimePoint(), getEncodedSize(packet));

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
      *conn, folly::none, packet2.packet, TimePoint(), getEncodedSize(packet));

  //  verify QLogger contains correct packet and frame information
  std::shared_ptr<quic::FileQLogger> qLogger =
      std::dynamic_pointer_cast<quic::FileQLogger>(conn->qLogger);
  std::vector<int> indices =
      getQLogEventIndices(QLogEventType::PacketSent, qLogger);
  EXPECT_EQ(indices.size(), 2);
  for (int i = 0; i < 2; ++i) {
    auto tmp = std::move(qLogger->logs[indices[i]]);
    auto event = dynamic_cast<QLogPacketEvent*>(tmp.get());
    EXPECT_EQ(event->packetType, toString(LongHeader::Types::Handshake));
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
      *conn, folly::none, packet.packet, TimePoint(), getEncodedSize(packet));

  // verify QLogger contains correct packet and frames information
  std::shared_ptr<quic::FileQLogger> qLogger =
      std::dynamic_pointer_cast<quic::FileQLogger>(conn->qLogger);
  std::vector<int> indices =
      getQLogEventIndices(QLogEventType::PacketSent, qLogger);
  EXPECT_EQ(indices.size(), 1);
  auto tmp = std::move(qLogger->logs[indices[0]]);

  auto event = dynamic_cast<QLogPacketEvent*>(tmp.get());
  EXPECT_EQ(event->packetType, toString(LongHeader::Types::Handshake));
  EXPECT_EQ(event->packetSize, getEncodedSize(packet));
  EXPECT_EQ(event->eventType, QLogEventType::PacketSent);
  EXPECT_EQ(event->frames.size(), 2);
}

TEST_F(QuicTransportFunctionsTest, TestUpdateConnectionHandshakeCounter) {
  auto conn = createConn();
  conn->qLogger = std::make_shared<quic::FileQLogger>(VantagePoint::Client);
  auto stream = conn->streamManager->createNextBidirectionalStream().value();
  writeDataToQuicStream(*stream, nullptr, true);
  EXPECT_EQ(0, conn->outstandingHandshakePacketsCount);

  auto packet = buildEmptyPacket(*conn, PacketNumberSpace::Handshake);
  auto packetEncodedSize =
      packet.header ? packet.header->computeChainDataLength() : 0;
  packetEncodedSize += packet.body ? packet.body->computeChainDataLength() : 0;

  packet.packet.frames.push_back(WriteCryptoFrame(0, 0));
  updateConnection(
      *conn, folly::none, packet.packet, TimePoint(), getEncodedSize(packet));
  EXPECT_EQ(1, conn->outstandingHandshakePacketsCount);

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
      getEncodedSize(packet));

  // verify QLogger contains correct packet information
  std::shared_ptr<quic::FileQLogger> qLogger =
      std::dynamic_pointer_cast<quic::FileQLogger>(conn->qLogger);
  std::vector<int> indices =
      getQLogEventIndices(QLogEventType::PacketSent, qLogger);
  EXPECT_EQ(indices.size(), 2);
  std::vector<std::string> packetTypes = {
      toString(LongHeader::Types::Handshake),
      toString(LongHeader::Types::ZeroRtt)};
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
      EXPECT_EQ(1, conn->outstandingHandshakePacketsCount);
    }
  }
}

TEST_F(QuicTransportFunctionsTest, TestUpdateConnectionForOneRttCryptoData) {
  auto conn = createConn();
  conn->qLogger = std::make_shared<quic::FileQLogger>(VantagePoint::Client);
  auto stream = conn->streamManager->createNextBidirectionalStream().value();
  writeDataToQuicStream(*stream, nullptr, true);
  EXPECT_EQ(0, conn->outstandingHandshakePacketsCount);

  // Packet with CryptoFrame in AppData pn space
  auto packet = buildEmptyPacket(*conn, PacketNumberSpace::AppData, true);
  auto packetEncodedSize =
      packet.header ? packet.header->computeChainDataLength() : 0;
  packetEncodedSize += packet.body ? packet.body->computeChainDataLength() : 0;

  packet.packet.frames.push_back(WriteCryptoFrame(0, 0));
  updateConnection(
      *conn, folly::none, packet.packet, TimePoint(), getEncodedSize(packet));

  EXPECT_EQ(0, conn->outstandingHandshakePacketsCount);
  EXPECT_EQ(1, conn->outstandingPackets.size());

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
      getEncodedSize(packet));

  // verify QLogger contains correct packet information
  std::shared_ptr<quic::FileQLogger> qLogger =
      std::dynamic_pointer_cast<quic::FileQLogger>(conn->qLogger);
  std::vector<int> indices =
      getQLogEventIndices(QLogEventType::PacketSent, qLogger);
  EXPECT_EQ(indices.size(), 2);
  std::vector<std::string> packetTypes = {kShortHeaderPacketType.str(),
                                          toString(LongHeader::Types::ZeroRtt)};
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

  EXPECT_EQ(0, conn->outstandingHandshakePacketsCount);
  EXPECT_EQ(2, conn->outstandingPackets.size());
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
  ASSERT_EQ(0, conn->lossState.totalBytesAcked);
  WriteAckFrame ackFrame;
  ackFrame.ackBlocks.emplace_back(0, 10);
  packet.packet.frames.push_back(std::move(ackFrame));
  EXPECT_CALL(*rawController, onPacketSent(_)).Times(0);
  EXPECT_CALL(*rawPacer, onPacketSent()).Times(0);
  updateConnection(
      *conn, folly::none, packet.packet, TimePoint(), getEncodedSize(packet));
  EXPECT_EQ(0, conn->outstandingPackets.size());
  EXPECT_EQ(0, conn->lossState.totalBytesAcked);
  std::shared_ptr<quic::FileQLogger> qLogger =
      std::dynamic_pointer_cast<quic::FileQLogger>(conn->qLogger);
  // verify QLogger contains correct packet information
  std::vector<int> indices =
      getQLogEventIndices(QLogEventType::PacketSent, qLogger);
  EXPECT_EQ(indices.size(), 1);
  auto tmp = std::move(qLogger->logs[indices[0]]);
  auto event = dynamic_cast<QLogPacketEvent*>(tmp.get());
  EXPECT_EQ(event->packetType, toString(LongHeader::Types::Handshake));
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
  conn->lossState.totalBytesAcked = 8642;
  auto currentTime = Clock::now();
  conn->lossState.lastAckedTime = currentTime - 123s;
  conn->lossState.lastAckedPacketSentTime = currentTime - 234s;
  conn->lossState.totalBytesSentAtLastAck = 10000;
  conn->lossState.totalBytesAckedAtLastAck = 5000;
  updateConnection(*conn, folly::none, packet.packet, TimePoint(), 555);

  // verify QLogger contains correct packet information
  std::shared_ptr<quic::FileQLogger> qLogger =
      std::dynamic_pointer_cast<quic::FileQLogger>(conn->qLogger);
  std::vector<int> indices =
      getQLogEventIndices(QLogEventType::PacketSent, qLogger);
  EXPECT_EQ(indices.size(), 1);
  auto tmp = std::move(qLogger->logs[indices[0]]);
  auto event = dynamic_cast<QLogPacketEvent*>(tmp.get());

  EXPECT_EQ(event->packetType, toString(LongHeader::Types::Handshake));
  EXPECT_EQ(event->packetSize, 555);
  EXPECT_EQ(event->eventType, QLogEventType::PacketSent);

  EXPECT_EQ(
      13579 + 555,
      getFirstOutstandingPacket(*conn, PacketNumberSpace::Handshake)
          ->totalBytesSent);
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
  PacketEvent event = 1;
  conn->outstandingPacketEvents.insert(event);
  auto futureMoment = thisMoment + 50ms;
  MockClock::mockNow = [=]() { return futureMoment; };
  EXPECT_CALL(*rawCongestionController, onPacketSent(_)).Times(1);
  updateConnection(
      *conn, event, std::move(writePacket), MockClock::now(), 1500);
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
      getLastOutstandingPacket(*conn, PacketNumberSpace::AppData)->time);
  EXPECT_EQ(
      1500,
      getLastOutstandingPacket(*conn, PacketNumberSpace::AppData)->encodedSize);
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
  auto packetNum = packet.packet.header.getPacketSequenceNum();
  auto stream = conn->streamManager->createNextBidirectionalStream().value();
  MaxStreamDataFrame streamWindowUpdate(stream->id, 0);
  conn->streamManager->queueWindowUpdate(stream->id);
  packet.packet.frames.push_back(std::move(streamWindowUpdate));
  updateConnection(
      *conn, folly::none, packet.packet, TimePoint(), getEncodedSize(packet));

  // verify QLogger contains correct packet information
  std::shared_ptr<quic::FileQLogger> qLogger =
      std::dynamic_pointer_cast<quic::FileQLogger>(conn->qLogger);
  std::vector<int> indices =
      getQLogEventIndices(QLogEventType::PacketSent, qLogger);
  EXPECT_EQ(indices.size(), 1);
  auto tmp = std::move(qLogger->logs[indices[0]]);
  auto event = dynamic_cast<QLogPacketEvent*>(tmp.get());

  EXPECT_EQ(event->packetType, toString(LongHeader::Types::Handshake));
  EXPECT_EQ(event->packetSize, getEncodedSize(packet));
  EXPECT_EQ(event->eventType, QLogEventType::PacketSent);

  // verify QLogger contains correct frame information
  EXPECT_EQ(event->frames.size(), 1);
  auto frame = static_cast<MaxStreamDataFrameLog*>(event->frames[0].get());
  EXPECT_EQ(frame->streamId, stream->id);
  EXPECT_EQ(frame->maximumData, 0);

  EXPECT_EQ(packetNum, *stream->latestMaxStreamDataPacket);
  EXPECT_FALSE(conn->latestMaxDataPacket.has_value());
}

TEST_F(QuicTransportFunctionsTest, TestUpdateConnectionConnWindowUpdate) {
  auto conn = createConn();
  conn->qLogger = std::make_shared<quic::FileQLogger>(VantagePoint::Client);
  auto packet = buildEmptyPacket(*conn, PacketNumberSpace::Handshake);
  auto packetNum = packet.packet.header.getPacketSequenceNum();
  conn->pendingEvents.connWindowUpdate = true;
  auto stream = conn->streamManager->createNextBidirectionalStream().value();
  MaxDataFrame connWindowUpdate(conn->flowControlState.advertisedMaxOffset);
  packet.packet.frames.push_back(std::move(connWindowUpdate));
  updateConnection(
      *conn, folly::none, packet.packet, TimePoint(), getEncodedSize(packet));

  // verify QLogger contains correct packet information
  std::shared_ptr<quic::FileQLogger> qLogger =
      std::dynamic_pointer_cast<quic::FileQLogger>(conn->qLogger);
  std::vector<int> indices =
      getQLogEventIndices(QLogEventType::PacketSent, qLogger);
  EXPECT_EQ(indices.size(), 1);
  auto tmp = std::move(qLogger->logs[indices[0]]);
  auto event = dynamic_cast<QLogPacketEvent*>(tmp.get());

  EXPECT_EQ(event->packetType, toString(LongHeader::Types::Handshake));
  EXPECT_EQ(event->packetSize, getEncodedSize(packet));
  EXPECT_EQ(event->eventType, QLogEventType::PacketSent);
  // verify QLogger contains correct frame information
  EXPECT_EQ(event->frames.size(), 1);
  auto frame = static_cast<MaxDataFrameLog*>(event->frames[0].get());
  EXPECT_EQ(frame->maximumData, conn->flowControlState.advertisedMaxOffset);

  EXPECT_FALSE(stream->latestMaxStreamDataPacket.has_value());
  EXPECT_EQ(packetNum, *conn->latestMaxDataPacket);
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
  EXPECT_CALL(*transportInfoCb_, onWrite(_));
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
  EXPECT_CALL(*transportInfoCb_, onWrite(_));
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
  EXPECT_CALL(*transportInfoCb_, onWrite(_)).Times(0);
  EXPECT_EQ(
      0,
      writeQuicDataToSocket(
          *rawSocket,
          *conn,
          *conn->clientConnectionId,
          *conn->serverConnectionId,
          *aead,
          *headerCipher,
          getVersion(*conn),
          conn->transportSettings.writeConnectionDataPacketsLimit));

  // Normal limit
  conn->pendingEvents.numProbePackets = 0;
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
  EXPECT_CALL(*transportInfoCb_, onWrite(_)).Times(1);
  EXPECT_EQ(
      1,
      writeQuicDataToSocket(
          *rawSocket,
          *conn,
          *conn->clientConnectionId,
          *conn->serverConnectionId,
          *aead,
          *headerCipher,
          getVersion(*conn),
          conn->transportSettings.writeConnectionDataPacketsLimit));

  // Probing can be limited by packet limit too
  conn->pendingEvents.numProbePackets =
      kDefaultWriteConnectionDataPacketLimit * 2;
  writeDataToQuicStream(*stream1, buf->clone(), true);
  writableBytes = 10000;
  EXPECT_CALL(*rawCongestionController, getWritableBytes())
      .WillRepeatedly(
          InvokeWithoutArgs([&writableBytes]() { return writableBytes; }));
  EXPECT_CALL(*rawSocket, write(_, _))
      .Times(kDefaultWriteConnectionDataPacketLimit)
      .WillRepeatedly(Invoke([&](const SocketAddress&,
                                 const std::unique_ptr<folly::IOBuf>& iobuf) {
        return iobuf->computeChainDataLength();
      }));
  EXPECT_CALL(*rawCongestionController, onPacketSent(_))
      .Times(kDefaultWriteConnectionDataPacketLimit);
  EXPECT_CALL(*transportInfoCb_, onWrite(_))
      .Times(kDefaultWriteConnectionDataPacketLimit);
  EXPECT_EQ(
      kDefaultWriteConnectionDataPacketLimit,
      writeQuicDataToSocket(
          *rawSocket,
          *conn,
          *conn->clientConnectionId,
          *conn->serverConnectionId,
          *aead,
          *headerCipher,
          getVersion(*conn),
          conn->transportSettings.writeConnectionDataPacketsLimit));
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
  EXPECT_TRUE(conn->outstandingPackets.empty());
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
  EXPECT_EQ(
      writeQuicDataToSocket(
          *rawSocket,
          *conn,
          *conn->clientConnectionId,
          *conn->serverConnectionId,
          *aead,
          *headerCipher,
          getVersion(*conn),
          conn->transportSettings.writeConnectionDataPacketsLimit),
      0);
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
  EXPECT_CALL(*transportInfoCb_, onWrite(_)).Times(2);
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
                      conn->outstandingPackets,
                      QuicWriteFrame::Type::StreamDataBlockedFrame_E)
                      .asStreamDataBlockedFrame();
  EXPECT_EQ(blocked.streamId, stream1->id);

  // Since everything is blocked, we shouldn't write a blocked again, so we
  // won't have any new packets to write if we trigger a write.
  auto previousPackets = conn->outstandingPackets.size();
  EXPECT_CALL(*transportInfoCb_, onWrite(_)).Times(0);
  writeQuicDataToSocket(
      *rawSocket,
      *conn,
      *conn->clientConnectionId,
      *conn->serverConnectionId,
      *aead,
      *headerCipher,
      getVersion(*conn),
      conn->transportSettings.writeConnectionDataPacketsLimit);
  EXPECT_EQ(previousPackets, conn->outstandingPackets.size());
}

TEST_F(QuicTransportFunctionsTest, WriteProbingNewData) {
  auto conn = createConn();
  // writeProbingDataToSocketForTest writes ShortHeader, thus it writes at
  // AppTraffic level
  auto currentPacketSeqNum = conn->ackStates.appDataAckState.nextPacketNum;
  auto mockCongestionController =
      std::make_unique<NiceMock<MockCongestionController>>();
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
  EXPECT_FALSE(conn->outstandingPackets.empty());
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
  EXPECT_CALL(*capturingAead, _encrypt(_, _, _))
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
  // Now we have no new data, let's probe again, and verify the same old data is
  // sent.
  folly::IOBuf secondBodyCaptured;
  EXPECT_CALL(*capturingAead, _encrypt(_, _, _))
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
  QuicServerConnectionState conn;
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
  EXPECT_FALSE(conn.outstandingPackets.empty());
  EXPECT_TRUE(conn.pendingEvents.setLossDetectionAlarm);
  EXPECT_GT(cryptoStream->currentWriteOffset, currentStreamWriteOffset);
  EXPECT_FALSE(cryptoStream->retransmissionBuffer.empty());
}

TEST_F(QuicTransportFunctionsTest, WriteProbesNoNewDataNoCryptoDataNoOldData) {
  auto conn = createConn();
  // writeProbingDataToSocketForTest uses ShortHeader, thus it writes at
  // AppTraffic level
  auto currentPacketSeqNum = conn->ackStates.appDataAckState.nextPacketNum;
  auto mockCongestionController =
      std::make_unique<NiceMock<MockCongestionController>>();
  auto rawCongestionController = mockCongestionController.get();
  conn->congestionController = std::move(mockCongestionController);
  EventBase evb;
  auto socket =
      std::make_unique<NiceMock<folly::test::MockAsyncUDPSocket>>(&evb);
  auto rawSocket = socket.get();
  auto stream1 = conn->streamManager->createNextBidirectionalStream().value();
  auto buf = buildRandomInputData(0);
  writeDataToQuicStream(*stream1, buf->clone(), false /* eof */);

  auto currentStreamWriteOffset = stream1->currentWriteOffset;
  EXPECT_CALL(*rawCongestionController, onPacketSent(_)).Times(0);
  EXPECT_CALL(*rawSocket, write(_, _)).Times(0);
  uint8_t probesToSend = 1;
  EXPECT_EQ(
      0,
      writeProbingDataToSocketForTest(
          *rawSocket,
          *conn,
          probesToSend,
          *aead,
          *headerCipher,
          getVersion(*conn)));
  EXPECT_EQ(1, probesToSend);
  EXPECT_EQ(currentPacketSeqNum, conn->ackStates.appDataAckState.nextPacketNum);
  EXPECT_TRUE(conn->outstandingPackets.empty());
  EXPECT_FALSE(conn->pendingEvents.setLossDetectionAlarm);
  EXPECT_EQ(stream1->currentWriteOffset, currentStreamWriteOffset);
  EXPECT_TRUE(stream1->retransmissionBuffer.empty());
}

TEST_F(QuicTransportFunctionsTest, ProbingNotWriteOtherFrames) {
  auto conn = createConn();
  // writeProbingDataToSocketForTest uses ShortHeader, thus it writes at
  // AppTraffic level
  auto currentPacketSeqNum = conn->ackStates.appDataAckState.nextPacketNum;
  auto mockCongestionController =
      std::make_unique<NiceMock<MockCongestionController>>();
  auto rawCongestionController = mockCongestionController.get();
  conn->congestionController = std::move(mockCongestionController);
  EventBase evb;
  auto socket =
      std::make_unique<NiceMock<folly::test::MockAsyncUDPSocket>>(&evb);
  auto rawSocket = socket.get();
  auto stream1 = conn->streamManager->createNextBidirectionalStream().value();
  RstStreamFrame rstFrame(stream1->id, GenericApplicationErrorCode::UNKNOWN, 0);
  conn->pendingEvents.resets.emplace(stream1->id, rstFrame);
  conn->pendingEvents.connWindowUpdate = true;
  conn->streamManager->queueWindowUpdate(stream1->id);

  auto currentStreamWriteOffset = stream1->currentWriteOffset;
  auto currentStreamWindow = stream1->flowControlState.advertisedMaxOffset;
  EXPECT_CALL(*rawCongestionController, onPacketSent(_)).Times(0);
  EXPECT_CALL(*rawSocket, write(_, _)).Times(0);
  uint8_t probesToSend = 1;
  EXPECT_EQ(
      0,
      writeProbingDataToSocketForTest(
          *rawSocket,
          *conn,
          probesToSend,
          *aead,
          *headerCipher,
          getVersion(*conn)));
  EXPECT_EQ(1, probesToSend);
  EXPECT_EQ(currentPacketSeqNum, conn->ackStates.appDataAckState.nextPacketNum);
  EXPECT_TRUE(conn->outstandingPackets.empty());
  EXPECT_FALSE(conn->pendingEvents.setLossDetectionAlarm);
  EXPECT_EQ(stream1->currentWriteOffset, currentStreamWriteOffset);
  EXPECT_TRUE(stream1->retransmissionBuffer.empty());
  // No Ack scheduled:
  EXPECT_FALSE(conn->ackStates.initialAckState.largestAckScheduled.has_value());
  EXPECT_FALSE(
      conn->ackStates.handshakeAckState.largestAckScheduled.has_value());
  EXPECT_FALSE(conn->ackStates.appDataAckState.largestAckScheduled.has_value());
  // Pending resets are still here:
  EXPECT_NE(
      conn->pendingEvents.resets.end(),
      conn->pendingEvents.resets.find(stream1->id));
  // Pending connWindowUpdate is still here:
  EXPECT_TRUE(conn->pendingEvents.connWindowUpdate);
  // Stream window update ain't changed:
  EXPECT_EQ(currentStreamWindow, stream1->flowControlState.advertisedMaxOffset);
  // Pending streamWindowUpdates are still here:
  EXPECT_TRUE(conn->streamManager->pendingWindowUpdate(stream1->id));
}

TEST_F(QuicTransportFunctionsTest, TestCryptoWritingIsHandshakeInOutstanding) {
  auto conn = createConn();
  // TODO: use handshake write cipher with draft-14.
  auto cryptoStream = &conn->cryptoState->initialStream;
  auto buf = buildRandomInputData(200);
  writeDataToQuicStream(*cryptoStream, buf->clone());
  EventBase evb;
  auto socket =
      std::make_unique<NiceMock<folly::test::MockAsyncUDPSocket>>(&evb);
  auto rawSocket = socket.get();
  EXPECT_EQ(
      1,
      writeCryptoAndAckDataToSocket(
          *rawSocket,
          *conn,
          *conn->clientConnectionId,
          *conn->serverConnectionId,
          LongHeader::Types::Initial,
          *conn->initialWriteCipher,
          *conn->initialHeaderCipher,
          getVersion(*conn),
          conn->transportSettings.writeConnectionDataPacketsLimit));
  ASSERT_EQ(1, conn->outstandingPackets.size());
  EXPECT_TRUE(getFirstOutstandingPacket(*conn, PacketNumberSpace::Initial)
                  ->isHandshake);
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
  EXPECT_GT(
      writeQuicDataToSocket(
          *rawSocket,
          *conn,
          *conn->clientConnectionId,
          *conn->serverConnectionId,
          *aead,
          *headerCipher,
          getVersion(*conn),
          conn->transportSettings.writeConnectionDataPacketsLimit),
      0);
  EXPECT_EQ(0, conn->outstandingPackets.size());
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
  EXPECT_CALL(*transportInfoCb_, onCwndBlocked()).Times(0);
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
  EXPECT_CALL(*transportInfoCb_, onCwndBlocked());
  writeDataToQuicStream(*stream1, buf->clone(), true);
  EXPECT_EQ(WriteDataReason::NO_WRITE, shouldWriteData(*conn));

  EXPECT_CALL(*transportInfoCb_, onCwndBlocked());
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

  // Only case that we allow the write; both CC / PathLimiter have writablebytes
  EXPECT_CALL(*rawCongestionController, getWritableBytes()).WillOnce(Return(1));
  EXPECT_CALL(*rawLimiter, currentCredit(_, _)).WillOnce(Return(1));

  EXPECT_CALL(*transportInfoCb_, onCwndBlocked()).Times(0);
  EXPECT_NE(WriteDataReason::NO_WRITE, shouldWriteData(*conn));

  // CC has writableBytes, but PathLimiter doesn't.
  EXPECT_CALL(*rawCongestionController, getWritableBytes()).WillOnce(Return(1));
  EXPECT_CALL(*rawLimiter, currentCredit(_, _)).WillOnce(Return(0));

  EXPECT_CALL(*transportInfoCb_, onCwndBlocked());
  EXPECT_EQ(WriteDataReason::NO_WRITE, shouldWriteData(*conn));

  // PathLimiter has writableBytes, CC doesn't
  EXPECT_CALL(*rawCongestionController, getWritableBytes()).WillOnce(Return(0));
  EXPECT_CALL(*rawLimiter, currentCredit(_, _)).WillOnce(Return(1));

  EXPECT_CALL(*transportInfoCb_, onCwndBlocked());
  EXPECT_EQ(WriteDataReason::NO_WRITE, shouldWriteData(*conn));

  // Neither PathLimiter or CC have writablebytes
  EXPECT_CALL(*rawCongestionController, getWritableBytes()).WillOnce(Return(0));
  EXPECT_CALL(*rawLimiter, currentCredit(_, _)).WillOnce(Return(0));

  EXPECT_CALL(*transportInfoCb_, onCwndBlocked());
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
  conn->ackStates.initialAckState.needsToSendAckImmediately = false;
  conn->ackStates.handshakeAckState.needsToSendAckImmediately = false;
  conn->ackStates.appDataAckState.needsToSendAckImmediately = false;
  EXPECT_FALSE(hasAckDataToWrite(*conn));
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
  conn->streamManager->addWritable(stream);
  EXPECT_EQ(WriteDataReason::NO_WRITE, hasNonAckDataToWrite(*conn));

  conn->oneRttWriteCipher = test::createNoOpAead();
  EXPECT_EQ(WriteDataReason::STREAM, hasNonAckDataToWrite(*conn));
}

TEST_F(QuicTransportFunctionsTest, UpdateConnectionCloneCounter) {
  auto conn = createConn();
  ASSERT_EQ(0, conn->outstandingClonedPacketsCount);
  auto packet = buildEmptyPacket(*conn, PacketNumberSpace::AppData);
  auto connWindowUpdate =
      MaxDataFrame(conn->flowControlState.advertisedMaxOffset);
  conn->pendingEvents.connWindowUpdate = true;
  packet.packet.frames.emplace_back(connWindowUpdate);
  PacketEvent packetEvent = 100;
  conn->outstandingPacketEvents.insert(packetEvent);
  updateConnection(*conn, packetEvent, packet.packet, TimePoint(), 123);
  EXPECT_EQ(1, conn->outstandingClonedPacketsCount);
}

TEST_F(QuicTransportFunctionsTest, ClearBlockedFromPendingEvents) {
  auto conn = createConn();
  auto packet = buildEmptyPacket(*conn, PacketNumberSpace::Handshake);
  auto stream = conn->streamManager->createNextBidirectionalStream().value();
  StreamDataBlockedFrame blockedFrame(stream->id, 1000);
  packet.packet.frames.push_back(blockedFrame);
  conn->streamManager->queueBlocked(stream->id, 1000);
  updateConnection(
      *conn, folly::none, packet.packet, TimePoint(), getEncodedSize(packet));
  EXPECT_FALSE(conn->streamManager->hasBlocked());
  EXPECT_FALSE(conn->outstandingPackets.empty());
  EXPECT_EQ(0, conn->outstandingClonedPacketsCount);
}

TEST_F(QuicTransportFunctionsTest, ClonedBlocked) {
  auto conn = createConn();
  auto packetEvent = conn->ackStates.appDataAckState.nextPacketNum;
  auto packet = buildEmptyPacket(*conn, PacketNumberSpace::AppData);
  auto stream = conn->streamManager->createNextBidirectionalStream().value();
  StreamDataBlockedFrame blockedFrame(stream->id, 1000);
  packet.packet.frames.emplace_back(blockedFrame);
  conn->outstandingPacketEvents.insert(packetEvent);
  // This shall not crash
  updateConnection(
      *conn, packetEvent, packet.packet, TimePoint(), getEncodedSize(packet));
  EXPECT_FALSE(conn->outstandingPackets.empty());
  EXPECT_EQ(1, conn->outstandingClonedPacketsCount);
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
          getEncodedSize(packet)),
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
      *conn, folly::none, packet.packet, TimePoint(), getEncodedSize(packet));
  EXPECT_FALSE(conn->outstandingPackets.empty());
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
      *conn, folly::none, packet.packet, TimePoint(), getEncodedSize(packet));
  EXPECT_TRUE(conn->pendingEvents.resets.empty());
  EXPECT_FALSE(conn->outstandingPackets.empty());
  EXPECT_EQ(0, conn->outstandingClonedPacketsCount);
}

TEST_F(QuicTransportFunctionsTest, ClonedRst) {
  auto conn = createConn();
  auto packetEvent = conn->ackStates.appDataAckState.nextPacketNum;
  auto stream = conn->streamManager->createNextBidirectionalStream().value();
  auto packet = buildEmptyPacket(*conn, PacketNumberSpace::AppData);
  RstStreamFrame rstStreamFrame(
      stream->id, GenericApplicationErrorCode::UNKNOWN, 0);
  packet.packet.frames.emplace_back(std::move(rstStreamFrame));
  conn->outstandingPacketEvents.insert(packetEvent);
  // This shall not crash
  updateConnection(
      *conn, packetEvent, packet.packet, TimePoint(), getEncodedSize(packet));
  EXPECT_FALSE(conn->outstandingPackets.empty());
  EXPECT_EQ(1, conn->outstandingClonedPacketsCount);
}

TEST_F(QuicTransportFunctionsTest, TotalBytesSentUpdate) {
  auto conn = createConn();
  conn->lossState.totalBytesSent = 1234;
  auto packet = buildEmptyPacket(*conn, PacketNumberSpace::Handshake);
  updateConnection(*conn, folly::none, packet.packet, TimePoint{}, 4321);
  EXPECT_EQ(5555, conn->lossState.totalBytesSent);
}

TEST_F(QuicTransportFunctionsTest, TimeoutBasedRetxCountUpdate) {
  auto conn = createConn();
  auto stream = conn->streamManager->createNextBidirectionalStream().value();
  conn->lossState.timeoutBasedRtxCount = 246;
  auto packet = buildEmptyPacket(*conn, PacketNumberSpace::AppData);
  RstStreamFrame rstStreamFrame(
      stream->id, GenericApplicationErrorCode::UNKNOWN, 0);
  packet.packet.frames.push_back(rstStreamFrame);
  PacketEvent packetEvent = 100;
  conn->outstandingPacketEvents.insert(packetEvent);
  updateConnection(*conn, packetEvent, packet.packet, TimePoint(), 500);
  EXPECT_EQ(247, conn->lossState.timeoutBasedRtxCount);
}

TEST_F(QuicTransportFunctionsTest, WriteLimitBytRttFraction) {
  auto conn = createConn();
  conn->lossState.srtt = 50ms;
  auto mockCongestionController =
      std::make_unique<NiceMock<MockCongestionController>>();
  auto rawCongestionController = mockCongestionController.get();
  conn->congestionController = std::move(mockCongestionController);

  EventBase evb;
  auto socket =
      std::make_unique<NiceMock<folly::test::MockAsyncUDPSocket>>(&evb);
  auto rawSocket = socket.get();

  auto stream1 = conn->streamManager->createNextBidirectionalStream().value();
  auto buf = buildRandomInputData(2048 * 1024);
  writeDataToQuicStream(*stream1, buf->clone(), true);

  EXPECT_CALL(*rawSocket, write(_, _)).WillRepeatedly(Return(1));
  EXPECT_CALL(*rawCongestionController, getWritableBytes())
      .WillRepeatedly(Return(50));
  EXPECT_GT(
      500,
      writeQuicDataToSocket(
          *rawSocket,
          *conn,
          *conn->clientConnectionId,
          *conn->serverConnectionId,
          *aead,
          *headerCipher,
          getVersion(*conn),
          500 /* packetLimit */));
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

} // namespace test
} // namespace quic
