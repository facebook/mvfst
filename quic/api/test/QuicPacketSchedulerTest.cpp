/*
 * Copyright (c) Facebook, Inc. and its affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 *
 */

#include <quic/api/QuicPacketScheduler.h>

#include <folly/portability/GTest.h>

#include <quic/api/test/Mocks.h>
#include <quic/client/state/ClientStateMachine.h>
#include <quic/codec/QuicPacketBuilder.h>
#include <quic/codec/test/Mocks.h>
#include <quic/common/test/TestUtils.h>
#include <quic/server/state/ServerStateMachine.h>
#include <quic/state/QuicStreamFunctions.h>

using namespace quic;
using namespace testing;

namespace {

PacketNum addInitialOutstandingPacket(QuicConnectionStateBase& conn) {
  PacketNum nextPacketNum =
      getNextPacketNum(conn, PacketNumberSpace::Handshake);
  std::vector<uint8_t> zeroConnIdData(quic::kDefaultConnectionIdSize, 0);
  ConnectionId srcConnId(zeroConnIdData);
  LongHeader header(
      LongHeader::Types::Initial,
      srcConnId,
      conn.clientConnectionId.value_or(quic::test::getTestConnectionId()),
      nextPacketNum,
      QuicVersion::QUIC_DRAFT);
  RegularQuicWritePacket packet(std::move(header));
  conn.outstandingPackets.emplace_back(packet, Clock::now(), 0, true, false, 0);
  conn.outstandingHandshakePacketsCount++;
  increaseNextPacketNum(conn, PacketNumberSpace::Handshake);
  return nextPacketNum;
}

PacketNum addHandshakeOutstandingPacket(QuicConnectionStateBase& conn) {
  PacketNum nextPacketNum =
      getNextPacketNum(conn, PacketNumberSpace::Handshake);
  std::vector<uint8_t> zeroConnIdData(quic::kDefaultConnectionIdSize, 0);
  ConnectionId srcConnId(zeroConnIdData);
  LongHeader header(
      LongHeader::Types::Handshake,
      srcConnId,
      conn.clientConnectionId.value_or(quic::test::getTestConnectionId()),
      nextPacketNum,
      QuicVersion::QUIC_DRAFT);
  RegularQuicWritePacket packet(std::move(header));
  conn.outstandingPackets.emplace_back(packet, Clock::now(), 0, true, false, 0);
  conn.outstandingHandshakePacketsCount++;
  increaseNextPacketNum(conn, PacketNumberSpace::Handshake);
  return nextPacketNum;
}

PacketNum addPureAckOutstandingPacket(QuicConnectionStateBase& conn) {
  PacketNum nextPacketNum = getNextPacketNum(conn, PacketNumberSpace::AppData);
  ShortHeader header(
      ProtectionType::KeyPhaseOne,
      conn.clientConnectionId.value_or(quic::test::getTestConnectionId()),
      nextPacketNum);
  RegularQuicWritePacket packet(std::move(header));
  conn.outstandingPackets.emplace_back(packet, Clock::now(), 0, false, true, 0);
  increaseNextPacketNum(conn, PacketNumberSpace::AppData);
  return nextPacketNum;
}

PacketNum addOutstandingPacket(QuicConnectionStateBase& conn) {
  PacketNum nextPacketNum = getNextPacketNum(conn, PacketNumberSpace::AppData);
  ShortHeader header(
      ProtectionType::KeyPhaseOne,
      conn.clientConnectionId.value_or(quic::test::getTestConnectionId()),
      nextPacketNum);
  RegularQuicWritePacket packet(std::move(header));
  conn.outstandingPackets.emplace_back(
      packet, Clock::now(), 0, false, false, 0);
  increaseNextPacketNum(conn, PacketNumberSpace::AppData);
  return nextPacketNum;
}

} // namespace

namespace quic {
namespace test {

class QuicPacketSchedulerTest : public Test {
 public:
  QuicVersion version{QuicVersion::MVFST};
};

TEST_F(QuicPacketSchedulerTest, NoopScheduler) {
  QuicConnectionStateBase conn(QuicNodeType::Client);
  FrameScheduler scheduler("frame");
  EXPECT_FALSE(scheduler.hasData());

  LongHeader header(
      LongHeader::Types::Initial,
      getTestConnectionId(1),
      getTestConnectionId(),
      0x1356,
      version);
  RegularQuicPacketBuilder builder(
      conn.udpSendPacketLen,
      std::move(header),
      conn.ackStates.initialAckState.largestAckedByPeer);

  auto builtPacket = std::move(builder).buildPacket();
  EXPECT_TRUE(builtPacket.packet.frames.empty());
}

TEST_F(QuicPacketSchedulerTest, CryptoPaddingInitialPacket) {
  QuicClientConnectionState conn;
  auto connId = getTestConnectionId();
  LongHeader longHeader1(
      LongHeader::Types::Initial,
      getTestConnectionId(1),
      connId,
      getNextPacketNum(conn, PacketNumberSpace::Initial),
      QuicVersion::MVFST);
  increaseNextPacketNum(conn, PacketNumberSpace::Initial);
  RegularQuicPacketBuilder builder1(
      conn.udpSendPacketLen,
      std::move(longHeader1),
      conn.ackStates.initialAckState.largestAckedByPeer);
  CryptoStreamScheduler scheduler(
      conn, *getCryptoStream(*conn.cryptoState, EncryptionLevel::Initial));
  writeDataToQuicStream(
      conn.cryptoState->initialStream, folly::IOBuf::copyBuffer("chlo"));
  scheduler.writeCryptoData(builder1);
  EXPECT_EQ(builder1.remainingSpaceInPkt(), 0);

  LongHeader longHeader2(
      LongHeader::Types::Handshake,
      connId,
      connId,
      getNextPacketNum(conn, PacketNumberSpace::Handshake),
      QuicVersion::MVFST);
  RegularQuicPacketBuilder builder2(
      conn.udpSendPacketLen,
      std::move(longHeader2),
      conn.ackStates.handshakeAckState.largestAckedByPeer);
  writeDataToQuicStream(
      conn.cryptoState->initialStream, folly::IOBuf::copyBuffer("finished"));
  scheduler.writeCryptoData(builder2);
  EXPECT_GT(builder2.remainingSpaceInPkt(), 0);
}

TEST_F(QuicPacketSchedulerTest, CryptoServerInitialNotPadded) {
  QuicServerConnectionState conn;
  auto connId = getTestConnectionId();
  PacketNum nextPacketNum = getNextPacketNum(conn, PacketNumberSpace::Initial);
  LongHeader longHeader1(
      LongHeader::Types::Initial,
      getTestConnectionId(1),
      connId,
      nextPacketNum,
      QuicVersion::MVFST);
  RegularQuicPacketBuilder builder1(
      conn.udpSendPacketLen,
      std::move(longHeader1),
      conn.ackStates.initialAckState.largestAckedByPeer);
  CryptoStreamScheduler scheduler(
      conn, *getCryptoStream(*conn.cryptoState, EncryptionLevel::Initial));
  writeDataToQuicStream(
      conn.cryptoState->initialStream, folly::IOBuf::copyBuffer("shlo"));
  scheduler.writeCryptoData(builder1);
  EXPECT_GT(builder1.remainingSpaceInPkt(), 0);
}

TEST_F(QuicPacketSchedulerTest, CryptoPaddingRetransmissionClientInitial) {
  QuicClientConnectionState conn;
  auto connId = getTestConnectionId();
  LongHeader longHeader(
      LongHeader::Types::Initial,
      getTestConnectionId(1),
      connId,
      getNextPacketNum(conn, PacketNumberSpace::Initial),
      QuicVersion::MVFST);
  RegularQuicPacketBuilder builder(
      conn.udpSendPacketLen,
      std::move(longHeader),
      conn.ackStates.initialAckState.largestAckedByPeer);
  CryptoStreamScheduler scheduler(
      conn, *getCryptoStream(*conn.cryptoState, EncryptionLevel::Initial));
  conn.cryptoState->initialStream.lossBuffer.push_back(
      StreamBuffer{folly::IOBuf::copyBuffer("chlo"), 0, false});
  scheduler.writeCryptoData(builder);
  EXPECT_EQ(builder.remainingSpaceInPkt(), 0);
}

TEST_F(QuicPacketSchedulerTest, CryptoSchedulerOnlySingleLossFits) {
  QuicServerConnectionState conn;
  auto connId = getTestConnectionId();
  LongHeader longHeader(
      LongHeader::Types::Handshake,
      connId,
      connId,
      getNextPacketNum(conn, PacketNumberSpace::Handshake),
      QuicVersion::MVFST);
  RegularQuicPacketBuilder builder(
      conn.udpSendPacketLen,
      std::move(longHeader),
      conn.ackStates.handshakeAckState.largestAckedByPeer);
  PacketBuilderWrapper builderWrapper(builder, 13);
  CryptoStreamScheduler scheduler(
      conn, *getCryptoStream(*conn.cryptoState, EncryptionLevel::Handshake));
  conn.cryptoState->handshakeStream.lossBuffer.push_back(
      StreamBuffer{folly::IOBuf::copyBuffer("shlo"), 0, false});
  conn.cryptoState->handshakeStream.lossBuffer.push_back(StreamBuffer{
      folly::IOBuf::copyBuffer(
          "certificatethatisverylongseriouslythisisextremelylongandcannotfitintoapacket"),
      7,
      false});
  EXPECT_TRUE(scheduler.writeCryptoData(builderWrapper));
}

TEST_F(QuicPacketSchedulerTest, CryptoWritePartialLossBuffer) {
  QuicClientConnectionState conn;
  auto connId = getTestConnectionId();
  LongHeader longHeader(
      LongHeader::Types::Initial,
      ConnectionId(std::vector<uint8_t>()),
      connId,
      getNextPacketNum(conn, PacketNumberSpace::Initial),
      QuicVersion::MVFST);
  RegularQuicPacketBuilder builder(
      25,
      std::move(longHeader),
      conn.ackStates.initialAckState.largestAckedByPeer);
  CryptoStreamScheduler scheduler(
      conn, *getCryptoStream(*conn.cryptoState, EncryptionLevel::Initial));
  conn.cryptoState->initialStream.lossBuffer.push_back(StreamBuffer{
      folly::IOBuf::copyBuffer("return the special duration value max"),
      0,
      false});
  EXPECT_TRUE(scheduler.writeCryptoData(builder));
  EXPECT_EQ(builder.remainingSpaceInPkt(), 0);
  EXPECT_FALSE(conn.cryptoState->initialStream.lossBuffer.empty());
}

TEST_F(QuicPacketSchedulerTest, StreamFrameSchedulerExists) {
  QuicServerConnectionState conn;
  conn.streamManager->setMaxLocalBidirectionalStreams(10);
  auto connId = getTestConnectionId();
  auto stream = conn.streamManager->createNextBidirectionalStream().value();

  WindowUpdateScheduler scheduler(conn);
  ShortHeader shortHeader(
      ProtectionType::KeyPhaseZero,
      connId,
      getNextPacketNum(conn, PacketNumberSpace::AppData));
  RegularQuicPacketBuilder builder(
      conn.udpSendPacketLen,
      std::move(shortHeader),
      conn.ackStates.appDataAckState.largestAckedByPeer);
  auto originalSpace = builder.remainingSpaceInPkt();
  conn.streamManager->queueWindowUpdate(stream->id);
  scheduler.writeWindowUpdates(builder);
  EXPECT_LT(builder.remainingSpaceInPkt(), originalSpace);
}

TEST_F(QuicPacketSchedulerTest, StreamFrameNoSpace) {
  QuicServerConnectionState conn;
  conn.streamManager->setMaxLocalBidirectionalStreams(10);
  auto connId = getTestConnectionId();
  auto stream = conn.streamManager->createNextBidirectionalStream().value();

  WindowUpdateScheduler scheduler(conn);
  ShortHeader shortHeader(
      ProtectionType::KeyPhaseZero,
      connId,
      getNextPacketNum(conn, PacketNumberSpace::AppData));
  RegularQuicPacketBuilder builder(
      conn.udpSendPacketLen,
      std::move(shortHeader),
      conn.ackStates.appDataAckState.largestAckedByPeer);
  PacketBuilderWrapper builderWrapper(builder, 2);
  auto originalSpace = builder.remainingSpaceInPkt();
  conn.streamManager->queueWindowUpdate(stream->id);
  scheduler.writeWindowUpdates(builderWrapper);
  EXPECT_EQ(builder.remainingSpaceInPkt(), originalSpace);
}

TEST_F(QuicPacketSchedulerTest, StreamFrameSchedulerStreamNotExists) {
  QuicServerConnectionState conn;
  auto connId = getTestConnectionId();
  StreamId nonExistentStream = 11;

  WindowUpdateScheduler scheduler(conn);
  ShortHeader shortHeader(
      ProtectionType::KeyPhaseZero,
      connId,
      getNextPacketNum(conn, PacketNumberSpace::AppData));
  RegularQuicPacketBuilder builder(
      conn.udpSendPacketLen,
      std::move(shortHeader),
      conn.ackStates.appDataAckState.largestAckedByPeer);
  auto originalSpace = builder.remainingSpaceInPkt();
  conn.streamManager->queueWindowUpdate(nonExistentStream);
  scheduler.writeWindowUpdates(builder);
  EXPECT_EQ(builder.remainingSpaceInPkt(), originalSpace);
}

TEST_F(QuicPacketSchedulerTest, CloningSchedulerTest) {
  QuicClientConnectionState conn;
  FrameScheduler noopScheduler("frame");
  ASSERT_FALSE(noopScheduler.hasData());
  CloningScheduler cloningScheduler(noopScheduler, conn, "CopyCat", 0);
  EXPECT_FALSE(cloningScheduler.hasData());
  auto packetNum = addOutstandingPacket(conn);
  // There needs to have retransmittable frame for the rebuilder to work
  conn.outstandingPackets.back().packet.frames.push_back(
      MaxDataFrame(conn.flowControlState.advertisedMaxOffset));
  EXPECT_TRUE(cloningScheduler.hasData());

  ASSERT_FALSE(noopScheduler.hasData());
  ShortHeader header(
      ProtectionType::KeyPhaseOne,
      conn.clientConnectionId.value_or(getTestConnectionId()),
      getNextPacketNum(conn, PacketNumberSpace::AppData));
  RegularQuicPacketBuilder builder(
      conn.udpSendPacketLen,
      std::move(header),
      conn.ackStates.appDataAckState.largestAckedByPeer);
  auto result = cloningScheduler.scheduleFramesForPacket(
      std::move(builder), kDefaultUDPSendPacketLen);
  EXPECT_TRUE(result.first.hasValue() && result.second.hasValue());
  EXPECT_EQ(packetNum, *result.first);
}

TEST_F(QuicPacketSchedulerTest, WriteOnlyOutstandingPacketsTest) {
  QuicClientConnectionState conn;
  FrameScheduler noopScheduler("frame");
  ASSERT_FALSE(noopScheduler.hasData());
  CloningScheduler cloningScheduler(noopScheduler, conn, "CopyCat", 0);
  EXPECT_FALSE(cloningScheduler.hasData());
  auto packetNum = addOutstandingPacket(conn);
  // There needs to have retransmittable frame for the rebuilder to work
  conn.outstandingPackets.back().packet.frames.push_back(
      MaxDataFrame(conn.flowControlState.advertisedMaxOffset));
  EXPECT_TRUE(cloningScheduler.hasData());

  ASSERT_FALSE(noopScheduler.hasData());
  ShortHeader header(
      ProtectionType::KeyPhaseOne,
      conn.clientConnectionId.value_or(getTestConnectionId()),
      getNextPacketNum(conn, PacketNumberSpace::AppData));
  RegularQuicPacketBuilder regularBuilder(
      conn.udpSendPacketLen,
      std::move(header),
      conn.ackStates.appDataAckState.largestAckedByPeer);

  // Create few frames
  ConnectionCloseFrame connCloseFrame(
      TransportErrorCode::FRAME_ENCODING_ERROR, "The sun is in the sky.");
  MaxStreamsFrame maxStreamFrame(999, true);
  PingFrame pingFrame;
  IntervalSet<PacketNum> ackBlocks;
  ackBlocks.insert(10, 100);
  ackBlocks.insert(200, 1000);
  AckFrameMetaData ackMeta(ackBlocks, 0us, kDefaultAckDelayExponent);

  // Write those framses with a regular builder
  writeFrame(connCloseFrame, regularBuilder);
  writeFrame(QuicSimpleFrame(maxStreamFrame), regularBuilder);
  writeFrame(QuicSimpleFrame(pingFrame), regularBuilder);
  writeAckFrame(ackMeta, regularBuilder);

  auto result = cloningScheduler.scheduleFramesForPacket(
      std::move(regularBuilder), kDefaultUDPSendPacketLen);
  EXPECT_TRUE(result.first.hasValue() && result.second.hasValue());
  EXPECT_EQ(packetNum, *result.first);
  // written packet (result.second) should not have any frame in the builder
  auto& writtenPacket = *result.second;
  auto shortHeader = writtenPacket.packet.header.asShort();
  CHECK(shortHeader);
  EXPECT_EQ(ProtectionType::KeyPhaseOne, shortHeader->getProtectionType());
  EXPECT_EQ(
      conn.ackStates.appDataAckState.nextPacketNum,
      shortHeader->getPacketSequenceNum());

  // Test that the only frame that's written is maxdataframe
  EXPECT_GE(writtenPacket.packet.frames.size(), 1);
  auto& writtenFrame = writtenPacket.packet.frames.at(0);
  auto maxDataFrame = writtenFrame.asMaxDataFrame();
  CHECK(maxDataFrame);
  for (auto& frame : writtenPacket.packet.frames) {
    bool present = false;
    /* the next four frames should not be written */
    present |= frame.asConnectionCloseFrame() ? true : false;
    present |= frame.asQuicSimpleFrame() ? true : false;
    present |= frame.asQuicSimpleFrame() ? true : false;
    present |= frame.asWriteAckFrame() ? true : false;
    ASSERT_FALSE(present);
  }
}

TEST_F(QuicPacketSchedulerTest, DoNotCloneProcessedClonedPacket) {
  QuicClientConnectionState conn;
  FrameScheduler noopScheduler("frame");
  CloningScheduler cloningScheduler(noopScheduler, conn, "CopyCat", 0);
  // Add two outstanding packets, but then mark the second one processed by
  // adding a PacketEvent that's missing from the outstandingPacketEvents set
  PacketNum expected = addOutstandingPacket(conn);
  // There needs to have retransmittable frame for the rebuilder to work
  conn.outstandingPackets.back().packet.frames.push_back(
      MaxDataFrame(conn.flowControlState.advertisedMaxOffset));
  addOutstandingPacket(conn);
  conn.outstandingPackets.back().associatedEvent = 1;
  // There needs to have retransmittable frame for the rebuilder to work
  conn.outstandingPackets.back().packet.frames.push_back(
      MaxDataFrame(conn.flowControlState.advertisedMaxOffset));

  ShortHeader header(
      ProtectionType::KeyPhaseOne,
      conn.clientConnectionId.value_or(getTestConnectionId()),
      getNextPacketNum(conn, PacketNumberSpace::AppData));
  RegularQuicPacketBuilder builder(
      conn.udpSendPacketLen,
      std::move(header),
      conn.ackStates.initialAckState.largestAckedByPeer);
  auto result = cloningScheduler.scheduleFramesForPacket(
      std::move(builder), kDefaultUDPSendPacketLen);
  EXPECT_TRUE(result.first.hasValue() && result.second.hasValue());
  EXPECT_EQ(expected, *result.first);
}

TEST_F(QuicPacketSchedulerTest, DoNotClonePureAck) {
  QuicClientConnectionState conn;
  FrameScheduler noopScheduler("frame");
  CloningScheduler cloningScheduler(noopScheduler, conn, "CopyCat", 0);
  // Add two outstanding packets, with second one being pureAck
  auto expected = addOutstandingPacket(conn);
  // There needs to have retransmittable frame for the rebuilder to work
  conn.outstandingPackets.back().packet.frames.push_back(
      MaxDataFrame(conn.flowControlState.advertisedMaxOffset));
  addPureAckOutstandingPacket(conn);
  conn.outstandingPackets.back().packet.frames.push_back(WriteAckFrame());

  ShortHeader header(
      ProtectionType::KeyPhaseOne,
      conn.clientConnectionId.value_or(getTestConnectionId()),
      getNextPacketNum(conn, PacketNumberSpace::AppData));
  RegularQuicPacketBuilder builder(
      conn.udpSendPacketLen,
      std::move(header),
      conn.ackStates.appDataAckState.largestAckedByPeer);
  auto result = cloningScheduler.scheduleFramesForPacket(
      std::move(builder), kDefaultUDPSendPacketLen);
  EXPECT_TRUE(result.first.hasValue() && result.second.hasValue());
  EXPECT_EQ(expected, *result.first);
}

TEST_F(QuicPacketSchedulerTest, CloneSchedulerHasDataIgnoresNonAppData) {
  QuicClientConnectionState conn;
  FrameScheduler noopScheduler("frame");
  CloningScheduler cloningScheduler(noopScheduler, conn, "CopyCat", 0);
  EXPECT_FALSE(cloningScheduler.hasData());

  addHandshakeOutstandingPacket(conn);
  EXPECT_FALSE(cloningScheduler.hasData());

  addInitialOutstandingPacket(conn);
  EXPECT_FALSE(cloningScheduler.hasData());

  addOutstandingPacket(conn);
  EXPECT_TRUE(cloningScheduler.hasData());
}

TEST_F(QuicPacketSchedulerTest, DoNotCloneHandshake) {
  QuicClientConnectionState conn;
  FrameScheduler noopScheduler("frame");
  CloningScheduler cloningScheduler(noopScheduler, conn, "CopyCat", 0);
  // Add two outstanding packets, with second one being handshake
  auto expected = addOutstandingPacket(conn);
  // There needs to have retransmittable frame for the rebuilder to work
  conn.outstandingPackets.back().packet.frames.push_back(
      MaxDataFrame(conn.flowControlState.advertisedMaxOffset));
  addHandshakeOutstandingPacket(conn);
  conn.outstandingPackets.back().packet.frames.push_back(
      MaxDataFrame(conn.flowControlState.advertisedMaxOffset));

  ShortHeader header(
      ProtectionType::KeyPhaseOne,
      conn.clientConnectionId.value_or(getTestConnectionId()),
      getNextPacketNum(conn, PacketNumberSpace::AppData));
  RegularQuicPacketBuilder builder(
      conn.udpSendPacketLen,
      std::move(header),
      conn.ackStates.appDataAckState.largestAckedByPeer);
  auto result = cloningScheduler.scheduleFramesForPacket(
      std::move(builder), kDefaultUDPSendPacketLen);
  EXPECT_TRUE(result.first.hasValue() && result.second.hasValue());
  EXPECT_EQ(expected, *result.first);
}

TEST_F(QuicPacketSchedulerTest, CloneSchedulerUseNormalSchedulerFirst) {
  QuicClientConnectionState conn;
  MockFrameScheduler mockScheduler;
  CloningScheduler cloningScheduler(mockScheduler, conn, "Mocker", 0);
  ShortHeader header(
      ProtectionType::KeyPhaseOne,
      conn.clientConnectionId.value_or(getTestConnectionId()),
      getNextPacketNum(conn, PacketNumberSpace::AppData));
  EXPECT_CALL(mockScheduler, hasData()).Times(1).WillOnce(Return(true));

  EXPECT_CALL(mockScheduler, _scheduleFramesForPacket(_, _))
      .Times(1)
      .WillOnce(Invoke(
          [&, headerCopy = header](
              std::unique_ptr<RegularQuicPacketBuilder>&, uint32_t) mutable {
            RegularQuicWritePacket packet(std::move(headerCopy));
            packet.frames.push_back(MaxDataFrame(2832));
            RegularQuicPacketBuilder::Packet builtPacket(
                std::move(packet),
                folly::IOBuf::copyBuffer("if you are the dealer"),
                folly::IOBuf::copyBuffer("I'm out of the game"));
            return std::make_pair(folly::none, std::move(builtPacket));
          }));
  RegularQuicPacketBuilder builder(
      conn.udpSendPacketLen,
      std::move(header),
      conn.ackStates.appDataAckState.largestAckedByPeer);
  auto result = cloningScheduler.scheduleFramesForPacket(
      std::move(builder), kDefaultUDPSendPacketLen);
  EXPECT_EQ(folly::none, result.first);
  EXPECT_EQ(result.second->packet.header.getHeaderForm(), HeaderForm::Short);
  ShortHeader& shortHeader = *result.second->packet.header.asShort();
  EXPECT_EQ(ProtectionType::KeyPhaseOne, shortHeader.getProtectionType());
  EXPECT_EQ(
      conn.ackStates.appDataAckState.nextPacketNum,
      shortHeader.getPacketSequenceNum());
  EXPECT_EQ(1, result.second->packet.frames.size());
  MaxDataFrame* maxDataFrame =
      result.second->packet.frames.front().asMaxDataFrame();
  ASSERT_NE(maxDataFrame, nullptr);
  EXPECT_EQ(2832, maxDataFrame->maximumData);
  EXPECT_TRUE(folly::IOBufEqualTo{}(
      *folly::IOBuf::copyBuffer("if you are the dealer"),
      *result.second->header));
  EXPECT_TRUE(folly::IOBufEqualTo{}(
      *folly::IOBuf::copyBuffer("I'm out of the game"), *result.second->body));
}

TEST_F(QuicPacketSchedulerTest, CloneWillGenerateNewWindowUpdate) {
  QuicClientConnectionState conn;
  conn.streamManager->setMaxLocalBidirectionalStreams(10);
  auto stream = conn.streamManager->createNextBidirectionalStream().value();
  FrameScheduler noopScheduler("frame");
  CloningScheduler cloningScheduler(noopScheduler, conn, "GiantsShoulder", 0);
  auto expectedPacketEvent = addOutstandingPacket(conn);
  ASSERT_EQ(1, conn.outstandingPackets.size());
  conn.outstandingPackets.back().packet.frames.push_back(MaxDataFrame(1000));
  conn.outstandingPackets.back().packet.frames.push_back(
      MaxStreamDataFrame(stream->id, 1000));
  conn.flowControlState.advertisedMaxOffset = 1000;
  stream->flowControlState.advertisedMaxOffset = 1000;

  conn.flowControlState.sumCurReadOffset = 300;
  conn.flowControlState.windowSize = 3000;
  stream->currentReadOffset = 200;
  stream->flowControlState.windowSize = 1500;

  ShortHeader header(
      ProtectionType::KeyPhaseOne,
      conn.clientConnectionId.value_or(getTestConnectionId()),
      getNextPacketNum(conn, PacketNumberSpace::AppData));
  RegularQuicPacketBuilder builder(
      conn.udpSendPacketLen,
      std::move(header),
      conn.ackStates.appDataAckState.largestAckedByPeer);
  auto packetResult = cloningScheduler.scheduleFramesForPacket(
      std::move(builder), conn.udpSendPacketLen);
  EXPECT_EQ(expectedPacketEvent, *packetResult.first);
  int32_t verifyConnWindowUpdate = 1, verifyStreamWindowUpdate = 1;
  for (const auto& frame : packetResult.second->packet.frames) {
    switch (frame.type()) {
      case QuicWriteFrame::Type::MaxStreamDataFrame_E: {
        const MaxStreamDataFrame& maxStreamDataFrame =
            *frame.asMaxStreamDataFrame();
        EXPECT_EQ(stream->id, maxStreamDataFrame.streamId);
        verifyStreamWindowUpdate--;
        break;
      }
      case QuicWriteFrame::Type::MaxDataFrame_E: {
        verifyConnWindowUpdate--;
        break;
      }
      case QuicWriteFrame::Type::PaddingFrame_E: {
        break;
      }
      default:
        // should never happen
        EXPECT_TRUE(false);
    }
  }
  EXPECT_EQ(0, verifyStreamWindowUpdate);
  EXPECT_EQ(0, verifyConnWindowUpdate);

  // Verify the built out packet has refreshed window update values
  EXPECT_GE(packetResult.second->packet.frames.size(), 2);
  uint32_t streamWindowUpdateCounter = 0;
  uint32_t connWindowUpdateCounter = 0;
  for (auto& frame : packetResult.second->packet.frames) {
    auto streamFlowControl = frame.asMaxStreamDataFrame();
    if (!streamFlowControl) {
      continue;
    }
    streamWindowUpdateCounter++;
    EXPECT_EQ(1700, streamFlowControl->maximumData);
  }
  for (auto& frame : packetResult.second->packet.frames) {
    auto connFlowControl = frame.asMaxDataFrame();
    if (!connFlowControl) {
      continue;
    }
    connWindowUpdateCounter++;
    EXPECT_EQ(3300, connFlowControl->maximumData);
  }
  EXPECT_EQ(1, connWindowUpdateCounter);
  EXPECT_EQ(1, streamWindowUpdateCounter);
}

class AckSchedulingTest : public TestWithParam<PacketNumberSpace> {};

TEST_F(QuicPacketSchedulerTest, AckStateHasAcksToSchedule) {
  QuicClientConnectionState conn;
  EXPECT_FALSE(hasAcksToSchedule(conn.ackStates.initialAckState));
  EXPECT_FALSE(hasAcksToSchedule(conn.ackStates.handshakeAckState));
  EXPECT_FALSE(hasAcksToSchedule(conn.ackStates.appDataAckState));

  conn.ackStates.initialAckState.acks.insert(0, 100);
  EXPECT_TRUE(hasAcksToSchedule(conn.ackStates.initialAckState));

  conn.ackStates.handshakeAckState.acks.insert(0, 100);
  conn.ackStates.handshakeAckState.largestAckScheduled = 200;
  EXPECT_FALSE(hasAcksToSchedule(conn.ackStates.handshakeAckState));

  conn.ackStates.handshakeAckState.largestAckScheduled = folly::none;
  EXPECT_TRUE(hasAcksToSchedule(conn.ackStates.handshakeAckState));
}

TEST_F(QuicPacketSchedulerTest, AckSchedulerHasAcksToSchedule) {
  QuicClientConnectionState conn;
  AckScheduler initialAckScheduler(
      conn, getAckState(conn, PacketNumberSpace::Initial));
  AckScheduler handshakeAckScheduler(
      conn, getAckState(conn, PacketNumberSpace::Handshake));
  AckScheduler appDataAckScheduler(
      conn, getAckState(conn, PacketNumberSpace::AppData));
  EXPECT_FALSE(initialAckScheduler.hasPendingAcks());
  EXPECT_FALSE(handshakeAckScheduler.hasPendingAcks());
  EXPECT_FALSE(appDataAckScheduler.hasPendingAcks());

  conn.ackStates.initialAckState.acks.insert(0, 100);
  EXPECT_TRUE(initialAckScheduler.hasPendingAcks());

  conn.ackStates.handshakeAckState.acks.insert(0, 100);
  conn.ackStates.handshakeAckState.largestAckScheduled = 200;
  EXPECT_FALSE(handshakeAckScheduler.hasPendingAcks());

  conn.ackStates.handshakeAckState.largestAckScheduled = folly::none;
  EXPECT_TRUE(handshakeAckScheduler.hasPendingAcks());
}

TEST_F(QuicPacketSchedulerTest, LargestAckToSend) {
  QuicClientConnectionState conn;
  EXPECT_EQ(folly::none, largestAckToSend(conn.ackStates.initialAckState));
  EXPECT_EQ(folly::none, largestAckToSend(conn.ackStates.handshakeAckState));
  EXPECT_EQ(folly::none, largestAckToSend(conn.ackStates.appDataAckState));

  conn.ackStates.initialAckState.acks.insert(0, 50);
  conn.ackStates.handshakeAckState.acks.insert(0, 50);
  conn.ackStates.handshakeAckState.acks.insert(75, 150);

  EXPECT_EQ(50, *largestAckToSend(conn.ackStates.initialAckState));
  EXPECT_EQ(150, *largestAckToSend(conn.ackStates.handshakeAckState));
  EXPECT_EQ(folly::none, largestAckToSend(conn.ackStates.appDataAckState));
}

TEST_F(QuicPacketSchedulerTest, StreamFrameSchedulerAllFit) {
  QuicClientConnectionState conn;
  conn.streamManager->setMaxLocalBidirectionalStreams(10);
  conn.flowControlState.peerAdvertisedMaxOffset = 100000;
  conn.flowControlState.peerAdvertisedInitialMaxStreamOffsetBidiRemote = 100000;
  auto connId = getTestConnectionId();
  StreamFrameScheduler scheduler(conn);
  ShortHeader shortHeader(
      ProtectionType::KeyPhaseZero,
      connId,
      getNextPacketNum(conn, PacketNumberSpace::AppData));
  RegularQuicPacketBuilder builder(
      conn.udpSendPacketLen,
      std::move(shortHeader),
      conn.ackStates.appDataAckState.largestAckedByPeer);
  auto stream1 = conn.streamManager->createNextBidirectionalStream().value();
  auto stream2 = conn.streamManager->createNextBidirectionalStream().value();
  auto stream3 = conn.streamManager->createNextBidirectionalStream().value();
  writeDataToQuicStream(*stream1, folly::IOBuf::copyBuffer("some data"), false);
  writeDataToQuicStream(*stream2, folly::IOBuf::copyBuffer("some data"), false);
  writeDataToQuicStream(*stream3, folly::IOBuf::copyBuffer("some data"), false);
  scheduler.writeStreams(builder);
  EXPECT_EQ(conn.schedulingState.nextScheduledStream, 0);
}

TEST_F(QuicPacketSchedulerTest, StreamFrameSchedulerRoundRobin) {
  QuicClientConnectionState conn;
  conn.streamManager->setMaxLocalBidirectionalStreams(10);
  conn.flowControlState.peerAdvertisedMaxOffset = 100000;
  conn.flowControlState.peerAdvertisedInitialMaxStreamOffsetBidiRemote = 100000;
  auto connId = getTestConnectionId();
  StreamFrameScheduler scheduler(conn);
  ShortHeader shortHeader1(
      ProtectionType::KeyPhaseZero,
      connId,
      getNextPacketNum(conn, PacketNumberSpace::AppData));
  RegularQuicPacketBuilder builder1(
      conn.udpSendPacketLen,
      std::move(shortHeader1),
      conn.ackStates.appDataAckState.largestAckedByPeer);
  auto stream1 = conn.streamManager->createNextBidirectionalStream().value();
  auto stream2 = conn.streamManager->createNextBidirectionalStream().value();
  auto stream3 = conn.streamManager->createNextBidirectionalStream().value();
  auto largeBuf = folly::IOBuf::createChain(conn.udpSendPacketLen * 2, 4096);
  auto curBuf = largeBuf.get();
  do {
    curBuf->append(curBuf->capacity());
    curBuf = curBuf->next();
  } while (curBuf != largeBuf.get());
  auto chainLen = largeBuf->computeChainDataLength();
  writeDataToQuicStream(*stream1, std::move(largeBuf), false);
  writeDataToQuicStream(*stream2, folly::IOBuf::copyBuffer("some data"), false);
  writeDataToQuicStream(*stream3, folly::IOBuf::copyBuffer("some data"), false);
  // Force the wraparound initially.
  conn.schedulingState.nextScheduledStream = stream3->id + 8;
  scheduler.writeStreams(builder1);
  EXPECT_EQ(conn.schedulingState.nextScheduledStream, 4);

  // Should write frames for stream2, stream3, followed by stream1 again.
  MockQuicPacketBuilder builder2;
  EXPECT_CALL(builder2, remainingSpaceInPkt()).WillRepeatedly(Return(4096));
  EXPECT_CALL(builder2, appendFrame(_)).WillRepeatedly(Invoke([&](auto f) {
    builder2.frames_.push_back(f);
  }));
  scheduler.writeStreams(builder2);
  auto& frames = builder2.frames_;
  ASSERT_EQ(frames.size(), 3);
  WriteStreamFrame f1(stream2->id, 0, 9, false);
  WriteStreamFrame f2(stream3->id, 0, 9, false);
  WriteStreamFrame f3(stream1->id, 0, chainLen, false);
  ASSERT_TRUE(frames[0].asWriteStreamFrame());
  EXPECT_EQ(*frames[0].asWriteStreamFrame(), f1);
  ASSERT_TRUE(frames[1].asWriteStreamFrame());
  EXPECT_EQ(*frames[1].asWriteStreamFrame(), f2);
  ASSERT_TRUE(frames[2].asWriteStreamFrame());
  EXPECT_EQ(*frames[2].asWriteStreamFrame(), f3);
}

TEST_F(QuicPacketSchedulerTest, StreamFrameSchedulerOneStream) {
  QuicClientConnectionState conn;
  conn.streamManager->setMaxLocalBidirectionalStreams(10);
  conn.flowControlState.peerAdvertisedMaxOffset = 100000;
  conn.flowControlState.peerAdvertisedInitialMaxStreamOffsetBidiRemote = 100000;
  auto connId = getTestConnectionId();
  StreamFrameScheduler scheduler(conn);
  ShortHeader shortHeader(
      ProtectionType::KeyPhaseZero,
      connId,
      getNextPacketNum(conn, PacketNumberSpace::AppData));
  RegularQuicPacketBuilder builder(
      conn.udpSendPacketLen,
      std::move(shortHeader),
      conn.ackStates.appDataAckState.largestAckedByPeer);
  auto stream1 = conn.streamManager->createNextBidirectionalStream().value();
  writeDataToQuicStream(*stream1, folly::IOBuf::copyBuffer("some data"), false);
  scheduler.writeStreams(builder);
  EXPECT_EQ(conn.schedulingState.nextScheduledStream, 0);
}

TEST_F(QuicPacketSchedulerTest, StreamFrameSchedulerRemoveOne) {
  QuicClientConnectionState conn;
  conn.streamManager->setMaxLocalBidirectionalStreams(10);
  conn.flowControlState.peerAdvertisedMaxOffset = 100000;
  conn.flowControlState.peerAdvertisedInitialMaxStreamOffsetBidiRemote = 100000;
  StreamFrameScheduler scheduler(conn);
  MockQuicPacketBuilder builder;
  auto stream1 = conn.streamManager->createNextBidirectionalStream().value();
  auto stream2 = conn.streamManager->createNextBidirectionalStream().value();
  writeDataToQuicStream(*stream1, folly::IOBuf::copyBuffer("some data"), false);
  writeDataToQuicStream(*stream2, folly::IOBuf::copyBuffer("some data"), false);
  EXPECT_CALL(builder, remainingSpaceInPkt()).WillRepeatedly(Return(4096));
  EXPECT_CALL(builder, appendFrame(_)).WillRepeatedly(Invoke([&](auto f) {
    builder.frames_.push_back(f);
  }));
  scheduler.writeStreams(builder);
  WriteStreamFrame f1(stream1->id, 0, 9, false);
  WriteStreamFrame f2(stream2->id, 0, 9, false);
  ASSERT_TRUE(builder.frames_[0].asWriteStreamFrame());
  EXPECT_EQ(*builder.frames_[0].asWriteStreamFrame(), f1);
  ASSERT_TRUE(builder.frames_[1].asWriteStreamFrame());
  EXPECT_EQ(*builder.frames_[1].asWriteStreamFrame(), f2);

  // Manually remove a stream and set the next scheduled to that stream.
  builder.frames_.clear();
  conn.streamManager->removeWritable(stream2->id);
  conn.schedulingState.nextScheduledStream = stream2->id;
  scheduler.writeStreams(builder);
  ASSERT_EQ(builder.frames_.size(), 1);
  ASSERT_TRUE(builder.frames_[0].asWriteStreamFrame());
  EXPECT_EQ(*builder.frames_[0].asWriteStreamFrame(), f1);
}

} // namespace test
} // namespace quic
