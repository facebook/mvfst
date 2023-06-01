/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <folly/portability/GTest.h>

#include <quic/api/QuicPacketScheduler.h>
#include <quic/api/QuicTransportFunctions.h>
#include <quic/api/test/Mocks.h>
#include <quic/client/state/ClientStateMachine.h>
#include <quic/codec/QuicPacketBuilder.h>
#include <quic/codec/test/Mocks.h>
#include <quic/common/test/TestUtils.h>
#include <quic/dsr/Types.h>
#include <quic/dsr/test/Mocks.h>
#include <quic/fizz/client/handshake/FizzClientQuicHandshakeContext.h>
#include <quic/fizz/server/handshake/FizzServerQuicHandshakeContext.h>
#include <quic/server/state/ServerStateMachine.h>
#include <quic/state/QuicStreamFunctions.h>
#include <quic/state/test/MockQuicStats.h>

using namespace quic;
using namespace testing;

enum PacketBuilderType { Regular, Inplace };

namespace {

PacketNum addInitialOutstandingPacket(QuicConnectionStateBase& conn) {
  PacketNum nextPacketNum = getNextPacketNum(conn, PacketNumberSpace::Initial);
  std::vector<uint8_t> zeroConnIdData(quic::kDefaultConnectionIdSize, 0);
  ConnectionId srcConnId(zeroConnIdData);
  LongHeader header(
      LongHeader::Types::Initial,
      srcConnId,
      conn.clientConnectionId.value_or(quic::test::getTestConnectionId()),
      nextPacketNum,
      QuicVersion::QUIC_DRAFT);
  RegularQuicWritePacket packet(std::move(header));
  conn.outstandings.packets.emplace_back(
      packet,
      Clock::now(),
      0,
      0,
      true,
      0,
      0,
      0,
      0,
      LossState(),
      0,
      OutstandingPacketMetadata::DetailsPerStream());
  conn.outstandings.packetCount[PacketNumberSpace::Initial]++;
  increaseNextPacketNum(conn, PacketNumberSpace::Initial);
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
  conn.outstandings.packets.emplace_back(
      packet,
      Clock::now(),
      0,
      0,
      true,
      0,
      0,
      0,
      0,
      LossState(),
      0,
      OutstandingPacketMetadata::DetailsPerStream());
  conn.outstandings.packetCount[PacketNumberSpace::Handshake]++;
  increaseNextPacketNum(conn, PacketNumberSpace::Handshake);
  return nextPacketNum;
}

PacketNum addOutstandingPacket(QuicConnectionStateBase& conn) {
  PacketNum nextPacketNum = getNextPacketNum(conn, PacketNumberSpace::AppData);
  ShortHeader header(
      ProtectionType::KeyPhaseOne,
      conn.clientConnectionId.value_or(quic::test::getTestConnectionId()),
      nextPacketNum);
  RegularQuicWritePacket packet(std::move(header));
  conn.outstandings.packets.emplace_back(
      packet,
      Clock::now(),
      0,
      0,
      false,
      0,
      0,
      0,
      0,
      LossState(),
      0,
      OutstandingPacketMetadata::DetailsPerStream());
  increaseNextPacketNum(conn, PacketNumberSpace::AppData);
  return nextPacketNum;
}

} // namespace

namespace quic {
namespace test {

class QuicPacketSchedulerTest : public TestWithParam<PacketBuilderType> {
 public:
  QuicVersion version{QuicVersion::MVFST};
};

TEST_F(QuicPacketSchedulerTest, CryptoPaddingInitialPacket) {
  QuicClientConnectionState conn(
      FizzClientQuicHandshakeContext::Builder().build());
  auto connId = getTestConnectionId();
  LongHeader longHeader(
      LongHeader::Types::Initial,
      getTestConnectionId(1),
      connId,
      getNextPacketNum(conn, PacketNumberSpace::Initial),
      QuicVersion::MVFST);
  increaseNextPacketNum(conn, PacketNumberSpace::Initial);
  RegularQuicPacketBuilder builder(
      conn.udpSendPacketLen,
      std::move(longHeader),
      conn.ackStates.initialAckState->largestAckedByPeer.value_or(0));
  FrameScheduler cryptoOnlyScheduler =
      std::move(
          FrameScheduler::Builder(
              conn,
              EncryptionLevel::Initial,
              LongHeader::typeToPacketNumberSpace(LongHeader::Types::Initial),
              "CryptoOnlyScheduler")
              .cryptoFrames())
          .build();
  writeDataToQuicStream(
      conn.cryptoState->initialStream, folly::IOBuf::copyBuffer("chlo"));
  auto result = cryptoOnlyScheduler.scheduleFramesForPacket(
      std::move(builder), conn.udpSendPacketLen);
  auto packetLength = result.packet->header->computeChainDataLength() +
      result.packet->body->computeChainDataLength();
  EXPECT_EQ(conn.udpSendPacketLen, packetLength);
}

TEST_F(QuicPacketSchedulerTest, PaddingInitialPureAcks) {
  QuicClientConnectionState conn(
      FizzClientQuicHandshakeContext::Builder().build());
  auto connId = getTestConnectionId();
  LongHeader longHeader(
      LongHeader::Types::Initial,
      connId,
      connId,
      getNextPacketNum(conn, PacketNumberSpace::Initial),
      QuicVersion::MVFST);
  RegularQuicPacketBuilder builder(
      conn.udpSendPacketLen,
      std::move(longHeader),
      conn.ackStates.handshakeAckState->largestAckedByPeer.value_or(0));
  conn.ackStates.initialAckState->largestRecvdPacketTime = Clock::now();
  conn.ackStates.initialAckState->needsToSendAckImmediately = true;
  conn.ackStates.initialAckState->acks.insert(10);
  FrameScheduler acksOnlyScheduler =
      std::move(
          FrameScheduler::Builder(
              conn,
              EncryptionLevel::Initial,
              LongHeader::typeToPacketNumberSpace(LongHeader::Types::Initial),
              "AcksOnlyScheduler")
              .ackFrames())
          .build();
  auto result = acksOnlyScheduler.scheduleFramesForPacket(
      std::move(builder), conn.udpSendPacketLen);
  auto packetLength = result.packet->header->computeChainDataLength() +
      result.packet->body->computeChainDataLength();
  EXPECT_EQ(conn.udpSendPacketLen, packetLength);
}

TEST_F(QuicPacketSchedulerTest, InitialPaddingDoesNotUseWrapper) {
  QuicClientConnectionState conn(
      FizzClientQuicHandshakeContext::Builder().build());
  auto connId = getTestConnectionId();
  size_t cipherOverhead = 30;
  LongHeader longHeader(
      LongHeader::Types::Initial,
      connId,
      connId,
      getNextPacketNum(conn, PacketNumberSpace::Initial),
      QuicVersion::MVFST);
  RegularQuicPacketBuilder builder(
      conn.udpSendPacketLen,
      std::move(longHeader),
      conn.ackStates.handshakeAckState->largestAckedByPeer.value_or(0));
  conn.ackStates.initialAckState->largestRecvdPacketTime = Clock::now();
  conn.ackStates.initialAckState->needsToSendAckImmediately = true;
  conn.ackStates.initialAckState->acks.insert(10);
  FrameScheduler acksOnlyScheduler =
      std::move(
          FrameScheduler::Builder(
              conn,
              EncryptionLevel::Initial,
              LongHeader::typeToPacketNumberSpace(LongHeader::Types::Initial),
              "AcksOnlyScheduler")
              .ackFrames())
          .build();
  auto result = acksOnlyScheduler.scheduleFramesForPacket(
      std::move(builder), conn.udpSendPacketLen - cipherOverhead);
  auto packetLength = result.packet->header->computeChainDataLength() +
      result.packet->body->computeChainDataLength();
  EXPECT_EQ(conn.udpSendPacketLen, packetLength);
}

TEST_F(QuicPacketSchedulerTest, CryptoServerInitialPadded) {
  QuicServerConnectionState conn(
      FizzServerQuicHandshakeContext::Builder().build());
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
      conn.ackStates.initialAckState->largestAckedByPeer.value_or(0));
  FrameScheduler scheduler =
      std::move(
          FrameScheduler::Builder(
              conn,
              EncryptionLevel::Initial,
              LongHeader::typeToPacketNumberSpace(LongHeader::Types::Initial),
              "CryptoOnlyScheduler")
              .cryptoFrames())
          .build();
  writeDataToQuicStream(
      conn.cryptoState->initialStream, folly::IOBuf::copyBuffer("shlo"));
  auto result = scheduler.scheduleFramesForPacket(
      std::move(builder1), conn.udpSendPacketLen);
  auto packetLength = result.packet->header->computeChainDataLength() +
      result.packet->body->computeChainDataLength();
  EXPECT_EQ(conn.udpSendPacketLen, packetLength);
}

TEST_F(QuicPacketSchedulerTest, PadTwoInitialPackets) {
  QuicServerConnectionState conn(
      FizzServerQuicHandshakeContext::Builder().build());
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
      conn.ackStates.initialAckState->largestAckedByPeer.value_or(0));
  FrameScheduler scheduler =
      std::move(
          FrameScheduler::Builder(
              conn,
              EncryptionLevel::Initial,
              LongHeader::typeToPacketNumberSpace(LongHeader::Types::Initial),
              "CryptoOnlyScheduler")
              .cryptoFrames())
          .build();
  writeDataToQuicStream(
      conn.cryptoState->initialStream, folly::IOBuf::copyBuffer("shlo"));
  auto result = scheduler.scheduleFramesForPacket(
      std::move(builder1), conn.udpSendPacketLen);
  auto packetLength = result.packet->header->computeChainDataLength() +
      result.packet->body->computeChainDataLength();
  EXPECT_EQ(conn.udpSendPacketLen, packetLength);

  increaseNextPacketNum(conn, PacketNumberSpace::Initial);
  LongHeader longHeader2(
      LongHeader::Types::Initial,
      getTestConnectionId(1),
      connId,
      nextPacketNum,
      QuicVersion::MVFST);
  RegularQuicPacketBuilder builder2(
      conn.udpSendPacketLen,
      std::move(longHeader2),
      conn.ackStates.initialAckState->largestAckedByPeer.value_or(0));
  writeDataToQuicStream(
      conn.cryptoState->initialStream, folly::IOBuf::copyBuffer("shlo again"));
  auto result2 = scheduler.scheduleFramesForPacket(
      std::move(builder2), conn.udpSendPacketLen);
  packetLength = result2.packet->header->computeChainDataLength() +
      result2.packet->body->computeChainDataLength();
  EXPECT_EQ(conn.udpSendPacketLen, packetLength);
}

TEST_F(QuicPacketSchedulerTest, CryptoPaddingRetransmissionClientInitial) {
  QuicClientConnectionState conn(
      FizzClientQuicHandshakeContext::Builder().build());
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
      conn.ackStates.initialAckState->largestAckedByPeer.value_or(0));
  FrameScheduler scheduler =
      std::move(
          FrameScheduler::Builder(
              conn,
              EncryptionLevel::Initial,
              LongHeader::typeToPacketNumberSpace(LongHeader::Types::Initial),
              "CryptoOnlyScheduler")
              .cryptoFrames())
          .build();
  conn.cryptoState->initialStream.lossBuffer.push_back(
      StreamBuffer{folly::IOBuf::copyBuffer("chlo"), 0, false});
  auto result = scheduler.scheduleFramesForPacket(
      std::move(builder), conn.udpSendPacketLen);
  auto packetLength = result.packet->header->computeChainDataLength() +
      result.packet->body->computeChainDataLength();
  EXPECT_EQ(conn.udpSendPacketLen, packetLength);
}

TEST_F(QuicPacketSchedulerTest, CryptoSchedulerOnlySingleLossFits) {
  QuicServerConnectionState conn(
      FizzServerQuicHandshakeContext::Builder().build());
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
      conn.ackStates.handshakeAckState->largestAckedByPeer.value_or(0));
  builder.encodePacketHeader();
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
  QuicClientConnectionState conn(
      FizzClientQuicHandshakeContext::Builder().build());
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
      conn.ackStates.initialAckState->largestAckedByPeer.value_or(
          conn.ackStates.initialAckState->nextPacketNum));
  FrameScheduler cryptoOnlyScheduler =
      std::move(
          FrameScheduler::Builder(
              conn,
              EncryptionLevel::Initial,
              LongHeader::typeToPacketNumberSpace(LongHeader::Types::Initial),
              "CryptoOnlyScheduler")
              .cryptoFrames())
          .build();
  conn.cryptoState->initialStream.lossBuffer.push_back(StreamBuffer{
      folly::IOBuf::copyBuffer("return the special duration value max"),
      0,
      false});
  auto result = cryptoOnlyScheduler.scheduleFramesForPacket(
      std::move(builder), conn.udpSendPacketLen);
  auto packetLength = result.packet->header->computeChainDataLength() +
      result.packet->body->computeChainDataLength();
  EXPECT_LE(packetLength, 25);
  EXPECT_TRUE(result.packet->packet.frames[0].asWriteCryptoFrame() != nullptr);
  EXPECT_FALSE(conn.cryptoState->initialStream.lossBuffer.empty());
}

TEST_F(QuicPacketSchedulerTest, StreamFrameSchedulerExists) {
  QuicServerConnectionState conn(
      FizzServerQuicHandshakeContext::Builder().build());
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
      conn.ackStates.appDataAckState.largestAckedByPeer.value_or(0));
  builder.encodePacketHeader();
  auto originalSpace = builder.remainingSpaceInPkt();
  conn.streamManager->queueWindowUpdate(stream->id);
  scheduler.writeWindowUpdates(builder);
  EXPECT_LT(builder.remainingSpaceInPkt(), originalSpace);
}

TEST_F(QuicPacketSchedulerTest, StreamFrameNoSpace) {
  QuicServerConnectionState conn(
      FizzServerQuicHandshakeContext::Builder().build());
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
      conn.ackStates.appDataAckState.largestAckedByPeer.value_or(0));
  builder.encodePacketHeader();
  PacketBuilderWrapper builderWrapper(builder, 2);
  auto originalSpace = builder.remainingSpaceInPkt();
  conn.streamManager->queueWindowUpdate(stream->id);
  scheduler.writeWindowUpdates(builderWrapper);
  EXPECT_EQ(builder.remainingSpaceInPkt(), originalSpace);
}

TEST_F(QuicPacketSchedulerTest, StreamFrameSchedulerStreamNotExists) {
  QuicServerConnectionState conn(
      FizzServerQuicHandshakeContext::Builder().build());
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
      conn.ackStates.appDataAckState.largestAckedByPeer.value_or(0));
  builder.encodePacketHeader();
  auto originalSpace = builder.remainingSpaceInPkt();
  conn.streamManager->queueWindowUpdate(nonExistentStream);
  scheduler.writeWindowUpdates(builder);
  EXPECT_EQ(builder.remainingSpaceInPkt(), originalSpace);
}

TEST_F(QuicPacketSchedulerTest, NoCloningForDSR) {
  QuicClientConnectionState conn(
      FizzClientQuicHandshakeContext::Builder().build());
  FrameScheduler noopScheduler("frame", conn);
  ASSERT_FALSE(noopScheduler.hasData());
  CloningScheduler cloningScheduler(noopScheduler, conn, "Juice WRLD", 0);
  EXPECT_FALSE(cloningScheduler.hasData());
  addOutstandingPacket(conn);
  EXPECT_TRUE(cloningScheduler.hasData());
  conn.outstandings.packets.back().isDSRPacket = true;
  conn.outstandings.dsrCount++;
  EXPECT_FALSE(cloningScheduler.hasData());
  ShortHeader header(
      ProtectionType::KeyPhaseOne,
      conn.clientConnectionId.value_or(getTestConnectionId()),
      getNextPacketNum(conn, PacketNumberSpace::AppData));
  RegularQuicPacketBuilder builder(
      conn.udpSendPacketLen,
      std::move(header),
      conn.ackStates.appDataAckState.largestAckedByPeer.value_or(0));
  auto result = cloningScheduler.scheduleFramesForPacket(
      std::move(builder), kDefaultUDPSendPacketLen);
  EXPECT_FALSE(result.packetEvent.hasValue());
  EXPECT_FALSE(result.packet.hasValue());
}

TEST_F(QuicPacketSchedulerTest, CloningSchedulerTest) {
  QuicClientConnectionState conn(
      FizzClientQuicHandshakeContext::Builder().build());
  FrameScheduler noopScheduler("frame", conn);
  ASSERT_FALSE(noopScheduler.hasData());
  CloningScheduler cloningScheduler(noopScheduler, conn, "CopyCat", 0);
  EXPECT_FALSE(cloningScheduler.hasData());
  auto packetNum = addOutstandingPacket(conn);
  // There needs to have retransmittable frame for the rebuilder to work
  conn.outstandings.packets.back().packet.frames.push_back(
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
      conn.ackStates.appDataAckState.largestAckedByPeer.value_or(0));
  auto result = cloningScheduler.scheduleFramesForPacket(
      std::move(builder), kDefaultUDPSendPacketLen);
  EXPECT_TRUE(result.packetEvent.has_value() && result.packet.has_value());
  EXPECT_EQ(packetNum, result.packetEvent->packetNumber);
}

TEST_F(QuicPacketSchedulerTest, WriteOnlyOutstandingPacketsTest) {
  QuicClientConnectionState conn(
      FizzClientQuicHandshakeContext::Builder().build());
  FrameScheduler noopScheduler("frame", conn);
  ASSERT_FALSE(noopScheduler.hasData());
  CloningScheduler cloningScheduler(noopScheduler, conn, "CopyCat", 0);
  EXPECT_FALSE(cloningScheduler.hasData());
  auto packetNum = addOutstandingPacket(conn);
  // There needs to have retransmittable frame for the rebuilder to work
  conn.outstandings.packets.back().packet.frames.push_back(
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
      conn.ackStates.appDataAckState.largestAckedByPeer.value_or(0));

  // Create few frames
  ConnectionCloseFrame connCloseFrame(
      QuicErrorCode(TransportErrorCode::FRAME_ENCODING_ERROR),
      "The sun is in the sky.");
  MaxStreamsFrame maxStreamFrame(999, true);
  PingFrame pingFrame;
  AckBlocks ackBlocks;
  ackBlocks.insert(10, 100);
  ackBlocks.insert(200, 1000);
  WriteAckFrameState writeAckState = {.acks = ackBlocks};
  WriteAckFrameMetaData ackMeta = {
      .ackState = writeAckState,
      .ackDelay = 0us,
      .ackDelayExponent = static_cast<uint8_t>(kDefaultAckDelayExponent)};

  // Write those framses with a regular builder
  writeFrame(connCloseFrame, regularBuilder);
  writeFrame(QuicSimpleFrame(maxStreamFrame), regularBuilder);
  writeFrame(pingFrame, regularBuilder);
  writeAckFrame(ackMeta, regularBuilder);

  auto result = cloningScheduler.scheduleFramesForPacket(
      std::move(regularBuilder), kDefaultUDPSendPacketLen);
  EXPECT_TRUE(result.packetEvent.hasValue() && result.packet.hasValue());
  EXPECT_EQ(packetNum, result.packetEvent->packetNumber);
  // written packet should not have any frame in the builder
  auto& writtenPacket = *result.packet;
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
  QuicClientConnectionState conn(
      FizzClientQuicHandshakeContext::Builder().build());
  FrameScheduler noopScheduler("frame", conn);
  CloningScheduler cloningScheduler(noopScheduler, conn, "CopyCat", 0);
  // Add two outstanding packets, but then mark the second one processed by
  // adding a PacketEvent that's missing from the outstandings.packetEvents set
  PacketNum expected = addOutstandingPacket(conn);
  // There needs to have retransmittable frame for the rebuilder to work
  conn.outstandings.packets.back().packet.frames.push_back(
      MaxDataFrame(conn.flowControlState.advertisedMaxOffset));
  addOutstandingPacket(conn);
  conn.outstandings.packets.back().associatedEvent =
      PacketEvent(PacketNumberSpace::AppData, 1);
  // There needs to have retransmittable frame for the rebuilder to work
  conn.outstandings.packets.back().packet.frames.push_back(
      MaxDataFrame(conn.flowControlState.advertisedMaxOffset));

  ShortHeader header(
      ProtectionType::KeyPhaseOne,
      conn.clientConnectionId.value_or(getTestConnectionId()),
      getNextPacketNum(conn, PacketNumberSpace::AppData));
  RegularQuicPacketBuilder builder(
      conn.udpSendPacketLen,
      std::move(header),
      conn.ackStates.initialAckState->largestAckedByPeer.value_or(0));
  auto result = cloningScheduler.scheduleFramesForPacket(
      std::move(builder), kDefaultUDPSendPacketLen);
  EXPECT_TRUE(result.packetEvent.has_value() && result.packet.has_value());
  EXPECT_EQ(expected, result.packetEvent->packetNumber);
}

TEST_F(QuicPacketSchedulerTest, CloneSchedulerHasHandshakeData) {
  QuicClientConnectionState conn(
      FizzClientQuicHandshakeContext::Builder().build());
  FrameScheduler noopScheduler("frame", conn);
  CloningScheduler cloningScheduler(noopScheduler, conn, "CopyCat", 0);
  EXPECT_FALSE(cloningScheduler.hasData());

  addHandshakeOutstandingPacket(conn);
  EXPECT_TRUE(cloningScheduler.hasData());
}

/**
 * This test case covers the following scenario:
   1) conn sent out a handshake packet that did not get acked yet
   2) conn received some handshake data that needs to be acked
   3) imitate that we're emitting a PTO packet (that is generated via cloning
      scheduler)
   4) emitted cloned packet MUST have both cloned crypto data AND ack
      frame(s)

    There was a bug that would result in mvfst emit a "empty" PTO packet with
    acks; this is the test case to cover that scenario.
 */
TEST_F(QuicPacketSchedulerTest, CloneSchedulerHasHandshakeDataAndAcks) {
  QuicServerConnectionState conn(
      FizzServerQuicHandshakeContext::Builder().build());
  conn.version = QuicVersion::MVFST_EXPERIMENTAL2;

  FrameScheduler noopScheduler = std::move(FrameScheduler::Builder(
                                               conn,
                                               EncryptionLevel::Handshake,
                                               PacketNumberSpace::Handshake,
                                               "testScheduler")
                                               .ackFrames())
                                     .build();
  addHandshakeOutstandingPacket(conn);

  // Add some crypto data for the outstanding packet to make it look legit.
  // This is so cloning scheduler can actually copy something.
  getCryptoStream(*conn.cryptoState, EncryptionLevel::Handshake)
      ->retransmissionBuffer.emplace(
          0,
          std::make_unique<StreamBuffer>(
              folly::IOBuf::copyBuffer("test"), 0, false));
  conn.outstandings.packets.back().packet.frames.push_back(
      WriteCryptoFrame(0, 4));

  // Make it look like we received some acks from the peer.
  conn.ackStates.handshakeAckState->acks.insert(10);
  conn.ackStates.handshakeAckState->largestRecvdPacketTime = Clock::now();

  // Create cloning scheduler.
  CloningScheduler cloningScheduler(noopScheduler, conn, "CopyCat", 0);
  EXPECT_TRUE(cloningScheduler.hasData());

  // Get the packet builder going for the clone packet.
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
  RegularQuicPacketBuilder builder(
      conn.udpSendPacketLen,
      std::move(header),
      conn.ackStates.appDataAckState.largestAckedByPeer.value_or(0));

  // Clone the packet.
  auto result = cloningScheduler.scheduleFramesForPacket(
      std::move(builder), kDefaultUDPSendPacketLen);
  EXPECT_TRUE(result.packetEvent.has_value());
  EXPECT_TRUE(result.packet.has_value());

  // Cloned packet has to have crypto data and no acks.
  bool hasAckFrame = false;
  bool hasCryptoFrame = false;
  for (auto iter = result.packet->packet.frames.cbegin();
       iter != result.packet->packet.frames.cend();
       iter++) {
    const QuicWriteFrame& frame = *iter;
    switch (frame.type()) {
      case QuicWriteFrame::Type::WriteAckFrame:
        hasAckFrame = true;
        break;
      case QuicWriteFrame::Type::WriteCryptoFrame:
        hasCryptoFrame = true;
        break;
      default:
        break;
    }
  }
  EXPECT_FALSE(hasAckFrame);
  EXPECT_TRUE(hasCryptoFrame);
}

TEST_F(QuicPacketSchedulerTest, CloneSchedulerHasInitialData) {
  QuicClientConnectionState conn(
      FizzClientQuicHandshakeContext::Builder().build());
  FrameScheduler noopScheduler("frame", conn);
  CloningScheduler cloningScheduler(noopScheduler, conn, "CopyCat", 0);
  EXPECT_FALSE(cloningScheduler.hasData());

  addInitialOutstandingPacket(conn);
  EXPECT_TRUE(cloningScheduler.hasData());
}

TEST_F(QuicPacketSchedulerTest, CloneSchedulerHasAppDataData) {
  QuicClientConnectionState conn(
      FizzClientQuicHandshakeContext::Builder().build());
  FrameScheduler noopScheduler("frame", conn);
  CloningScheduler cloningScheduler(noopScheduler, conn, "CopyCat", 0);
  EXPECT_FALSE(cloningScheduler.hasData());

  addOutstandingPacket(conn);
  EXPECT_TRUE(cloningScheduler.hasData());
}

TEST_F(QuicPacketSchedulerTest, DoNotCloneHandshake) {
  QuicClientConnectionState conn(
      FizzClientQuicHandshakeContext::Builder().build());
  FrameScheduler noopScheduler("frame", conn);
  CloningScheduler cloningScheduler(noopScheduler, conn, "CopyCat", 0);
  // Add two outstanding packets, with second one being handshake
  auto expected = addOutstandingPacket(conn);
  // There needs to have retransmittable frame for the rebuilder to work
  conn.outstandings.packets.back().packet.frames.push_back(
      MaxDataFrame(conn.flowControlState.advertisedMaxOffset));
  addHandshakeOutstandingPacket(conn);
  conn.outstandings.packets.back().packet.frames.push_back(
      MaxDataFrame(conn.flowControlState.advertisedMaxOffset));

  ShortHeader header(
      ProtectionType::KeyPhaseOne,
      conn.clientConnectionId.value_or(getTestConnectionId()),
      getNextPacketNum(conn, PacketNumberSpace::AppData));
  RegularQuicPacketBuilder builder(
      conn.udpSendPacketLen,
      std::move(header),
      conn.ackStates.appDataAckState.largestAckedByPeer.value_or(0));
  auto result = cloningScheduler.scheduleFramesForPacket(
      std::move(builder), kDefaultUDPSendPacketLen);
  EXPECT_TRUE(result.packetEvent.has_value() && result.packet.has_value());
  EXPECT_EQ(expected, result.packetEvent->packetNumber);
}

TEST_F(QuicPacketSchedulerTest, CloneSchedulerUseNormalSchedulerFirst) {
  QuicClientConnectionState conn(
      FizzClientQuicHandshakeContext::Builder().build());
  conn.version = QuicVersion::MVFST_EXPERIMENTAL2;
  NiceMock<MockFrameScheduler> mockScheduler(&conn);
  CloningScheduler cloningScheduler(mockScheduler, conn, "Mocker", 0);
  ShortHeader header(
      ProtectionType::KeyPhaseOne,
      conn.clientConnectionId.value_or(getTestConnectionId()),
      getNextPacketNum(conn, PacketNumberSpace::AppData));
  EXPECT_CALL(mockScheduler, hasImmediateData())
      .Times(1)
      .WillOnce(Return(true));

  EXPECT_CALL(mockScheduler, _scheduleFramesForPacket(_, _))
      .Times(1)
      .WillOnce(Invoke(
          [&, headerCopy = header](PacketBuilderInterface*, uint32_t) mutable {
            RegularQuicWritePacket packet(std::move(headerCopy));
            packet.frames.push_back(MaxDataFrame(2832));
            RegularQuicPacketBuilder::Packet builtPacket(
                std::move(packet),
                folly::IOBuf::copyBuffer("if you are the dealer"),
                folly::IOBuf::copyBuffer("I'm out of the game"));
            return SchedulingResult(folly::none, std::move(builtPacket));
          }));
  RegularQuicPacketBuilder builder(
      conn.udpSendPacketLen,
      std::move(header),
      conn.ackStates.appDataAckState.largestAckedByPeer.value_or(0));
  auto result = cloningScheduler.scheduleFramesForPacket(
      std::move(builder), kDefaultUDPSendPacketLen);
  EXPECT_EQ(folly::none, result.packetEvent);
  EXPECT_EQ(result.packet->packet.header.getHeaderForm(), HeaderForm::Short);
  ShortHeader& shortHeader = *result.packet->packet.header.asShort();
  EXPECT_EQ(ProtectionType::KeyPhaseOne, shortHeader.getProtectionType());
  EXPECT_EQ(
      conn.ackStates.appDataAckState.nextPacketNum,
      shortHeader.getPacketSequenceNum());
  EXPECT_EQ(1, result.packet->packet.frames.size());
  MaxDataFrame* maxDataFrame =
      result.packet->packet.frames.front().asMaxDataFrame();
  ASSERT_NE(maxDataFrame, nullptr);
  EXPECT_EQ(2832, maxDataFrame->maximumData);
  EXPECT_TRUE(folly::IOBufEqualTo{}(
      *folly::IOBuf::copyBuffer("if you are the dealer"),
      *result.packet->header));
  EXPECT_TRUE(folly::IOBufEqualTo{}(
      *folly::IOBuf::copyBuffer("I'm out of the game"), *result.packet->body));
}

TEST_F(QuicPacketSchedulerTest, CloneWillGenerateNewWindowUpdate) {
  QuicClientConnectionState conn(
      FizzClientQuicHandshakeContext::Builder().build());
  conn.streamManager->setMaxLocalBidirectionalStreams(10);
  auto stream = conn.streamManager->createNextBidirectionalStream().value();
  FrameScheduler noopScheduler("frame", conn);
  CloningScheduler cloningScheduler(noopScheduler, conn, "GiantsShoulder", 0);
  PacketEvent expectedPacketEvent(
      PacketNumberSpace::AppData, addOutstandingPacket(conn));
  ASSERT_EQ(1, conn.outstandings.packets.size());
  conn.outstandings.packets.back().packet.frames.push_back(MaxDataFrame(1000));
  conn.outstandings.packets.back().packet.frames.push_back(
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
      conn.ackStates.appDataAckState.largestAckedByPeer.value_or(0));
  auto packetResult = cloningScheduler.scheduleFramesForPacket(
      std::move(builder), conn.udpSendPacketLen);
  EXPECT_EQ(expectedPacketEvent, *packetResult.packetEvent);
  int32_t verifyConnWindowUpdate = 1, verifyStreamWindowUpdate = 1;
  for (const auto& frame : packetResult.packet->packet.frames) {
    switch (frame.type()) {
      case QuicWriteFrame::Type::MaxStreamDataFrame: {
        const MaxStreamDataFrame& maxStreamDataFrame =
            *frame.asMaxStreamDataFrame();
        EXPECT_EQ(stream->id, maxStreamDataFrame.streamId);
        verifyStreamWindowUpdate--;
        break;
      }
      case QuicWriteFrame::Type::MaxDataFrame: {
        verifyConnWindowUpdate--;
        break;
      }
      case QuicWriteFrame::Type::PaddingFrame: {
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
  EXPECT_GE(packetResult.packet->packet.frames.size(), 2);
  uint32_t streamWindowUpdateCounter = 0;
  uint32_t connWindowUpdateCounter = 0;
  for (auto& frame : packetResult.packet->packet.frames) {
    auto streamFlowControl = frame.asMaxStreamDataFrame();
    if (!streamFlowControl) {
      continue;
    }
    streamWindowUpdateCounter++;
    EXPECT_EQ(1700, streamFlowControl->maximumData);
  }
  for (auto& frame : packetResult.packet->packet.frames) {
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

TEST_F(QuicPacketSchedulerTest, CloningSchedulerWithInplaceBuilder) {
  QuicClientConnectionState conn(
      FizzClientQuicHandshakeContext::Builder().build());
  conn.transportSettings.dataPathType = DataPathType::ContinuousMemory;
  SimpleBufAccessor bufAccessor(2000);
  auto buf = bufAccessor.obtain();
  EXPECT_EQ(buf->length(), 0);
  bufAccessor.release(std::move(buf));
  conn.bufAccessor = &bufAccessor;

  FrameScheduler noopScheduler("frame", conn);
  ASSERT_FALSE(noopScheduler.hasData());
  CloningScheduler cloningScheduler(noopScheduler, conn, "93MillionMiles", 0);
  auto packetNum = addOutstandingPacket(conn);
  // There needs to have retransmittable frame for the rebuilder to work
  conn.outstandings.packets.back().packet.frames.push_back(
      MaxDataFrame(conn.flowControlState.advertisedMaxOffset));
  EXPECT_TRUE(cloningScheduler.hasData());

  ASSERT_FALSE(noopScheduler.hasData());
  ShortHeader header(
      ProtectionType::KeyPhaseOne,
      conn.clientConnectionId.value_or(getTestConnectionId()),
      getNextPacketNum(conn, PacketNumberSpace::AppData));
  InplaceQuicPacketBuilder builder(
      bufAccessor,
      conn.udpSendPacketLen,
      std::move(header),
      conn.ackStates.appDataAckState.largestAckedByPeer.value_or(0));
  auto result = cloningScheduler.scheduleFramesForPacket(
      std::move(builder), kDefaultUDPSendPacketLen);
  EXPECT_TRUE(result.packetEvent.has_value() && result.packet.has_value());
  EXPECT_EQ(packetNum, result.packetEvent->packetNumber);

  // Something was written into the buffer:
  EXPECT_TRUE(bufAccessor.ownsBuffer());
  buf = bufAccessor.obtain();
  EXPECT_GT(buf->length(), 10);
}

TEST_F(QuicPacketSchedulerTest, CloningSchedulerWithInplaceBuilderFullPacket) {
  QuicClientConnectionState conn(
      FizzClientQuicHandshakeContext::Builder().build());
  conn.streamManager->setMaxLocalBidirectionalStreams(10);
  conn.flowControlState.peerAdvertisedMaxOffset = 100000;
  conn.flowControlState.peerAdvertisedInitialMaxStreamOffsetBidiRemote = 100000;
  conn.transportSettings.dataPathType = DataPathType::ContinuousMemory;
  SimpleBufAccessor bufAccessor(2000);
  auto buf = bufAccessor.obtain();
  EXPECT_EQ(buf->length(), 0);
  bufAccessor.release(std::move(buf));
  conn.bufAccessor = &bufAccessor;
  auto stream = *conn.streamManager->createNextBidirectionalStream();
  auto inBuf = buildRandomInputData(conn.udpSendPacketLen * 10);
  writeDataToQuicStream(*stream, inBuf->clone(), false);

  FrameScheduler scheduler = std::move(FrameScheduler::Builder(
                                           conn,
                                           EncryptionLevel::AppData,
                                           PacketNumberSpace::AppData,
                                           "streamScheduler")
                                           .streamFrames())
                                 .build();
  auto packetNum = getNextPacketNum(conn, PacketNumberSpace::AppData);
  ShortHeader header(
      ProtectionType::KeyPhaseOne,
      conn.clientConnectionId.value_or(getTestConnectionId()),
      packetNum);
  InplaceQuicPacketBuilder builder(
      bufAccessor,
      conn.udpSendPacketLen,
      std::move(header),
      conn.ackStates.appDataAckState.largestAckedByPeer.value_or(0));
  ASSERT_TRUE(scheduler.hasData());
  auto result = scheduler.scheduleFramesForPacket(
      std::move(builder), conn.udpSendPacketLen);
  auto bufferLength = result.packet->header->computeChainDataLength() +
      result.packet->body->computeChainDataLength();
  EXPECT_EQ(conn.udpSendPacketLen, bufferLength);
  updateConnection(
      conn,
      folly::none,
      result.packet->packet,
      Clock::now(),
      bufferLength,
      0,
      false /* isDSRPacket */);
  buf = bufAccessor.obtain();
  ASSERT_EQ(conn.udpSendPacketLen, buf->length());
  buf->clear();
  bufAccessor.release(std::move(buf));

  FrameScheduler noopScheduler("noopScheduler", conn);
  ASSERT_FALSE(noopScheduler.hasData());
  CloningScheduler cloningScheduler(noopScheduler, conn, "93MillionMiles", 0);
  EXPECT_TRUE(cloningScheduler.hasData());
  ASSERT_FALSE(noopScheduler.hasData());
  // Exact same header, so header encoding should be the same
  ShortHeader dupHeader(
      ProtectionType::KeyPhaseOne,
      conn.clientConnectionId.value_or(getTestConnectionId()),
      packetNum);
  InplaceQuicPacketBuilder internalBuilder(
      bufAccessor,
      conn.udpSendPacketLen,
      std::move(dupHeader),
      conn.ackStates.appDataAckState.largestAckedByPeer.value_or(0));
  auto cloneResult = cloningScheduler.scheduleFramesForPacket(
      std::move(internalBuilder), conn.udpSendPacketLen);
  EXPECT_TRUE(
      cloneResult.packetEvent.has_value() && cloneResult.packet.has_value());
  EXPECT_EQ(packetNum, cloneResult.packetEvent->packetNumber);

  // Something was written into the buffer:
  EXPECT_TRUE(bufAccessor.ownsBuffer());
  buf = bufAccessor.obtain();
  EXPECT_EQ(buf->length(), conn.udpSendPacketLen);
}

TEST_F(QuicPacketSchedulerTest, CloneLargerThanOriginalPacket) {
  QuicClientConnectionState conn(
      FizzClientQuicHandshakeContext::Builder().build());
  conn.udpSendPacketLen = 1000;
  conn.streamManager->setMaxLocalBidirectionalStreams(10);
  conn.flowControlState.peerAdvertisedMaxOffset = 100000;
  conn.flowControlState.peerAdvertisedInitialMaxStreamOffsetBidiRemote = 100000;
  auto stream = conn.streamManager->createNextBidirectionalStream().value();
  auto inputData = buildRandomInputData(conn.udpSendPacketLen * 10);
  writeDataToQuicStream(*stream, inputData->clone(), false);
  FrameScheduler scheduler = std::move(FrameScheduler::Builder(
                                           conn,
                                           EncryptionLevel::AppData,
                                           PacketNumberSpace::AppData,
                                           "streamScheduler")
                                           .streamFrames())
                                 .build();
  auto cipherOverhead = 16;
  PacketNum packetNum = 0;
  ShortHeader header(
      ProtectionType::KeyPhaseOne,
      conn.clientConnectionId.value_or(getTestConnectionId()),
      packetNum);
  RegularQuicPacketBuilder builder(
      conn.udpSendPacketLen,
      std::move(header),
      conn.ackStates.appDataAckState.largestAckedByPeer.value_or(0));
  auto packetResult = scheduler.scheduleFramesForPacket(
      std::move(builder), conn.udpSendPacketLen - cipherOverhead);
  auto encodedSize = packetResult.packet->body->computeChainDataLength() +
      packetResult.packet->header->computeChainDataLength() + cipherOverhead;
  EXPECT_EQ(encodedSize, conn.udpSendPacketLen);
  updateConnection(
      conn,
      folly::none,
      packetResult.packet->packet,
      Clock::now(),
      encodedSize,
      0,
      false /* isDSRPacket */);

  // make packetNum too larger to be encoded into the same size:
  packetNum += 0xFF;
  ShortHeader cloneHeader(
      ProtectionType::KeyPhaseOne,
      conn.clientConnectionId.value_or(getTestConnectionId()),
      packetNum);
  RegularQuicPacketBuilder throwawayBuilder(
      conn.udpSendPacketLen,
      std::move(cloneHeader),
      conn.ackStates.appDataAckState.largestAckedByPeer.value_or(0));
  FrameScheduler noopScheduler("noopScheduler", conn);
  CloningScheduler cloningScheduler(
      noopScheduler, conn, "CopyCat", cipherOverhead);
  auto cloneResult = cloningScheduler.scheduleFramesForPacket(
      std::move(throwawayBuilder), kDefaultUDPSendPacketLen);
  EXPECT_FALSE(cloneResult.packet.hasValue());
  EXPECT_FALSE(cloneResult.packetEvent.hasValue());
}

class AckSchedulingTest : public TestWithParam<PacketNumberSpace> {};

TEST_F(QuicPacketSchedulerTest, AckStateHasAcksToSchedule) {
  QuicClientConnectionState conn(
      FizzClientQuicHandshakeContext::Builder().build());
  EXPECT_FALSE(hasAcksToSchedule(*conn.ackStates.initialAckState));
  EXPECT_FALSE(hasAcksToSchedule(*conn.ackStates.handshakeAckState));
  EXPECT_FALSE(hasAcksToSchedule(conn.ackStates.appDataAckState));

  conn.ackStates.initialAckState->acks.insert(0, 100);
  EXPECT_TRUE(hasAcksToSchedule(*conn.ackStates.initialAckState));

  conn.ackStates.handshakeAckState->acks.insert(0, 100);
  conn.ackStates.handshakeAckState->largestAckScheduled = 200;
  EXPECT_FALSE(hasAcksToSchedule(*conn.ackStates.handshakeAckState));

  conn.ackStates.handshakeAckState->largestAckScheduled = folly::none;
  EXPECT_TRUE(hasAcksToSchedule(*conn.ackStates.handshakeAckState));
}

TEST_F(QuicPacketSchedulerTest, AckSchedulerHasAcksToSchedule) {
  QuicClientConnectionState conn(
      FizzClientQuicHandshakeContext::Builder().build());
  AckScheduler initialAckScheduler(
      conn, getAckState(conn, PacketNumberSpace::Initial));
  AckScheduler handshakeAckScheduler(
      conn, getAckState(conn, PacketNumberSpace::Handshake));
  AckScheduler appDataAckScheduler(
      conn, getAckState(conn, PacketNumberSpace::AppData));
  EXPECT_FALSE(initialAckScheduler.hasPendingAcks());
  EXPECT_FALSE(handshakeAckScheduler.hasPendingAcks());
  EXPECT_FALSE(appDataAckScheduler.hasPendingAcks());

  conn.ackStates.initialAckState->acks.insert(0, 100);
  EXPECT_TRUE(initialAckScheduler.hasPendingAcks());

  conn.ackStates.handshakeAckState->acks.insert(0, 100);
  conn.ackStates.handshakeAckState->largestAckScheduled = 200;
  EXPECT_FALSE(handshakeAckScheduler.hasPendingAcks());

  conn.ackStates.handshakeAckState->largestAckScheduled = folly::none;
  EXPECT_TRUE(handshakeAckScheduler.hasPendingAcks());
}

TEST_F(QuicPacketSchedulerTest, LargestAckToSend) {
  QuicClientConnectionState conn(
      FizzClientQuicHandshakeContext::Builder().build());
  EXPECT_EQ(folly::none, largestAckToSend(*conn.ackStates.initialAckState));
  EXPECT_EQ(folly::none, largestAckToSend(*conn.ackStates.handshakeAckState));
  EXPECT_EQ(folly::none, largestAckToSend(conn.ackStates.appDataAckState));

  conn.ackStates.initialAckState->acks.insert(0, 50);
  conn.ackStates.handshakeAckState->acks.insert(0, 50);
  conn.ackStates.handshakeAckState->acks.insert(75, 150);

  EXPECT_EQ(50, *largestAckToSend(*conn.ackStates.initialAckState));
  EXPECT_EQ(150, *largestAckToSend(*conn.ackStates.handshakeAckState));
  EXPECT_EQ(folly::none, largestAckToSend(conn.ackStates.appDataAckState));
}

TEST_F(QuicPacketSchedulerTest, NeedsToSendAckWithoutAcksAvailable) {
  // This covers the scheduler behavior when an IMMEDIATE_ACK frame is received.
  QuicClientConnectionState conn(
      FizzClientQuicHandshakeContext::Builder().build());
  AckScheduler initialAckScheduler(
      conn, getAckState(conn, PacketNumberSpace::Initial));
  AckScheduler handshakeAckScheduler(
      conn, getAckState(conn, PacketNumberSpace::Handshake));
  AckScheduler appDataAckScheduler(
      conn, getAckState(conn, PacketNumberSpace::AppData));
  EXPECT_FALSE(initialAckScheduler.hasPendingAcks());
  EXPECT_FALSE(handshakeAckScheduler.hasPendingAcks());
  EXPECT_FALSE(appDataAckScheduler.hasPendingAcks());

  conn.ackStates.initialAckState->needsToSendAckImmediately = true;
  conn.ackStates.handshakeAckState->needsToSendAckImmediately = true;
  conn.ackStates.appDataAckState.needsToSendAckImmediately = true;

  conn.ackStates.initialAckState->acks.insert(0, 100);
  EXPECT_TRUE(initialAckScheduler.hasPendingAcks());

  conn.ackStates.handshakeAckState->acks.insert(0, 100);
  conn.ackStates.handshakeAckState->largestAckScheduled = 200;
  EXPECT_FALSE(handshakeAckScheduler.hasPendingAcks());

  conn.ackStates.handshakeAckState->largestAckScheduled = folly::none;
  EXPECT_TRUE(handshakeAckScheduler.hasPendingAcks());
}

TEST_F(QuicPacketSchedulerTest, StreamFrameSchedulerAllFit) {
  QuicClientConnectionState conn(
      FizzClientQuicHandshakeContext::Builder().build());
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
      conn.ackStates.appDataAckState.largestAckedByPeer.value_or(0));
  builder.encodePacketHeader();
  auto stream1 =
      conn.streamManager->createNextBidirectionalStream().value()->id;
  auto stream2 =
      conn.streamManager->createNextBidirectionalStream().value()->id;
  auto stream3 =
      conn.streamManager->createNextBidirectionalStream().value()->id;
  writeDataToQuicStream(
      *conn.streamManager->findStream(stream1),
      folly::IOBuf::copyBuffer("some data"),
      false);
  writeDataToQuicStream(
      *conn.streamManager->findStream(stream2),
      folly::IOBuf::copyBuffer("some data"),
      false);
  writeDataToQuicStream(
      *conn.streamManager->findStream(stream3),
      folly::IOBuf::copyBuffer("some data"),
      false);
  scheduler.writeStreams(builder);
  EXPECT_EQ(
      conn.streamManager->writeQueue().getNextScheduledStream(kDefaultPriority),
      0);
}

TEST_F(QuicPacketSchedulerTest, StreamFrameSchedulerRoundRobin) {
  QuicClientConnectionState conn(
      FizzClientQuicHandshakeContext::Builder().build());
  conn.streamManager->setMaxLocalBidirectionalStreams(10);
  conn.flowControlState.peerAdvertisedMaxOffset = 100000;
  conn.flowControlState.peerAdvertisedInitialMaxStreamOffsetBidiRemote = 100000;
  auto connId = getTestConnectionId();
  StreamFrameScheduler scheduler(conn);
  ShortHeader shortHeader1(
      ProtectionType::KeyPhaseZero,
      connId,
      getNextPacketNum(conn, PacketNumberSpace::AppData));
  RegularQuicPacketBuilder builder(
      conn.udpSendPacketLen,
      std::move(shortHeader1),
      conn.ackStates.appDataAckState.largestAckedByPeer.value_or(0));
  builder.encodePacketHeader();
  auto stream1 =
      conn.streamManager->createNextBidirectionalStream().value()->id;
  auto stream2 =
      conn.streamManager->createNextBidirectionalStream().value()->id;
  auto stream3 =
      conn.streamManager->createNextBidirectionalStream().value()->id;
  auto largeBuf = folly::IOBuf::createChain(conn.udpSendPacketLen * 2, 4096);
  auto curBuf = largeBuf.get();
  do {
    curBuf->append(curBuf->capacity());
    curBuf = curBuf->next();
  } while (curBuf != largeBuf.get());
  auto chainLen = largeBuf->computeChainDataLength();
  writeDataToQuicStream(
      *conn.streamManager->findStream(stream1), std::move(largeBuf), false);
  writeDataToQuicStream(
      *conn.streamManager->findStream(stream2),
      folly::IOBuf::copyBuffer("some data"),
      false);
  writeDataToQuicStream(
      *conn.streamManager->findStream(stream3),
      folly::IOBuf::copyBuffer("some data"),
      false);
  // Force the wraparound initially.
  scheduler.writeStreams(builder);
  EXPECT_EQ(
      conn.streamManager->writeQueue().getNextScheduledStream(kDefaultPriority),
      4);

  // Should write frames for stream2, stream3, followed by stream1 again.
  NiceMock<MockQuicPacketBuilder> builder2;
  EXPECT_CALL(builder2, remainingSpaceInPkt()).WillRepeatedly(Return(4096));
  EXPECT_CALL(builder2, appendFrame(_)).WillRepeatedly(Invoke([&](auto f) {
    builder2.frames_.push_back(f);
  }));
  scheduler.writeStreams(builder2);
  auto& frames = builder2.frames_;
  ASSERT_EQ(frames.size(), 3);
  WriteStreamFrame f1(stream2, 0, 9, false);
  WriteStreamFrame f2(stream3, 0, 9, false);
  WriteStreamFrame f3(stream1, 0, chainLen, false);
  ASSERT_TRUE(frames[0].asWriteStreamFrame());
  EXPECT_EQ(*frames[0].asWriteStreamFrame(), f1);
  ASSERT_TRUE(frames[1].asWriteStreamFrame());
  EXPECT_EQ(*frames[1].asWriteStreamFrame(), f2);
  ASSERT_TRUE(frames[2].asWriteStreamFrame());
  EXPECT_EQ(*frames[2].asWriteStreamFrame(), f3);
}

TEST_F(QuicPacketSchedulerTest, StreamFrameSchedulerRoundRobinNextsPer) {
  QuicClientConnectionState conn(
      FizzClientQuicHandshakeContext::Builder().build());
  conn.streamManager->setMaxLocalBidirectionalStreams(10);
  conn.streamManager->writeQueue().setMaxNextsPerStream(2);
  conn.transportSettings.defaultPriority = Priority(0, true);
  conn.flowControlState.peerAdvertisedMaxOffset = 100000;
  conn.flowControlState.peerAdvertisedInitialMaxStreamOffsetBidiRemote = 100000;
  auto connId = getTestConnectionId();
  StreamFrameScheduler scheduler(conn);
  ShortHeader shortHeader1(
      ProtectionType::KeyPhaseZero,
      connId,
      getNextPacketNum(conn, PacketNumberSpace::AppData));
  RegularQuicPacketBuilder builder(
      conn.udpSendPacketLen,
      std::move(shortHeader1),
      conn.ackStates.appDataAckState.largestAckedByPeer.value_or(0));
  builder.encodePacketHeader();
  auto stream1 =
      conn.streamManager->createNextBidirectionalStream().value()->id;
  auto stream2 =
      conn.streamManager->createNextBidirectionalStream().value()->id;
  auto stream3 =
      conn.streamManager->createNextBidirectionalStream().value()->id;
  auto largeBuf = folly::IOBuf::createChain(conn.udpSendPacketLen * 2, 4096);
  auto curBuf = largeBuf.get();
  do {
    curBuf->append(curBuf->capacity());
    curBuf = curBuf->next();
  } while (curBuf != largeBuf.get());
  writeDataToQuicStream(
      *conn.streamManager->findStream(stream1), std::move(largeBuf), false);
  writeDataToQuicStream(
      *conn.streamManager->findStream(stream2),
      folly::IOBuf::copyBuffer("some data"),
      false);
  writeDataToQuicStream(
      *conn.streamManager->findStream(stream3),
      folly::IOBuf::copyBuffer("some data"),
      false);
  // Should write frames for stream1, stream1, stream2, stream3, followed by
  // stream1 again.
  NiceMock<MockQuicPacketBuilder> builder2;
  std::vector<uint64_t> remainingRet = {1500, 0, 1400, 0, 1300, 1100, 1000, 0};
  auto remainingItr = remainingRet.begin();

  EXPECT_CALL(builder2, appendFrame(_)).WillRepeatedly(Invoke([&](auto f) {
    builder2.frames_.push_back(f);
    remainingItr++;
  }));
  EXPECT_CALL(builder2, remainingSpaceInPkt()).WillRepeatedly(Invoke([&]() {
    return *remainingItr;
  }));
  scheduler.writeStreams(builder2);
  remainingItr++;
  ASSERT_EQ(conn.streamManager->writeQueue().getNextScheduledStream(), stream1);
  ASSERT_EQ(builder2.frames_.size(), 1);
  ASSERT_EQ(*remainingItr, 1400);
  scheduler.writeStreams(builder2);
  ASSERT_EQ(builder2.frames_.size(), 2);
  ASSERT_EQ(conn.streamManager->writeQueue().getNextScheduledStream(), stream2);
  ASSERT_EQ(*remainingItr, 0);
  remainingItr++;
  scheduler.writeStreams(builder2);
  scheduler.writeStreams(builder2);
  auto& frames = builder2.frames_;
  ASSERT_EQ(frames.size(), 5);
  ASSERT_TRUE(frames[0].asWriteStreamFrame());
  EXPECT_EQ(frames[0].asWriteStreamFrame()->streamId, stream1);
  ASSERT_TRUE(frames[1].asWriteStreamFrame());
  EXPECT_EQ(frames[1].asWriteStreamFrame()->streamId, stream1);
  ASSERT_TRUE(frames[2].asWriteStreamFrame());
  EXPECT_EQ(frames[2].asWriteStreamFrame()->streamId, stream2);
  ASSERT_TRUE(frames[3].asWriteStreamFrame());
  EXPECT_EQ(frames[3].asWriteStreamFrame()->streamId, stream3);
  ASSERT_TRUE(frames[4].asWriteStreamFrame());
  EXPECT_EQ(frames[4].asWriteStreamFrame()->streamId, stream1);
}

TEST_F(QuicPacketSchedulerTest, StreamFrameSchedulerRoundRobinStreamPerPacket) {
  QuicClientConnectionState conn(
      FizzClientQuicHandshakeContext::Builder().build());
  conn.streamManager->setMaxLocalBidirectionalStreams(10);
  conn.flowControlState.peerAdvertisedMaxOffset = 100000;
  conn.flowControlState.peerAdvertisedInitialMaxStreamOffsetBidiRemote = 100000;
  conn.transportSettings.streamFramePerPacket = true;
  auto connId = getTestConnectionId();
  StreamFrameScheduler scheduler(conn);
  ShortHeader shortHeader1(
      ProtectionType::KeyPhaseZero,
      connId,
      getNextPacketNum(conn, PacketNumberSpace::AppData));
  RegularQuicPacketBuilder builder1(
      conn.udpSendPacketLen,
      std::move(shortHeader1),
      conn.ackStates.appDataAckState.largestAckedByPeer.value_or(0));
  auto stream1 =
      conn.streamManager->createNextBidirectionalStream().value()->id;
  auto stream2 =
      conn.streamManager->createNextBidirectionalStream().value()->id;
  auto stream3 =
      conn.streamManager->createNextBidirectionalStream().value()->id;
  auto largeBuf = folly::IOBuf::createChain(conn.udpSendPacketLen * 2, 4096);
  auto curBuf = largeBuf.get();
  do {
    curBuf->append(curBuf->capacity());
    curBuf = curBuf->next();
  } while (curBuf != largeBuf.get());
  auto chainLen = largeBuf->computeChainDataLength();
  writeDataToQuicStream(
      *conn.streamManager->findStream(stream1), std::move(largeBuf), false);
  writeDataToQuicStream(
      *conn.streamManager->findStream(stream2),
      folly::IOBuf::copyBuffer("some data"),
      false);
  writeDataToQuicStream(
      *conn.streamManager->findStream(stream3),
      folly::IOBuf::copyBuffer("some data"),
      false);
  // The default is to wraparound initially.
  scheduler.writeStreams(builder1);
  EXPECT_EQ(
      conn.streamManager->writeQueue().getNextScheduledStream(kDefaultPriority),
      stream2);

  // Should write frames for stream2, stream3, followed by stream1 again.
  NiceMock<MockQuicPacketBuilder> builder2;
  EXPECT_CALL(builder2, remainingSpaceInPkt()).WillRepeatedly(Return(4096));
  EXPECT_CALL(builder2, appendFrame(_)).WillRepeatedly(Invoke([&](auto f) {
    builder2.frames_.push_back(f);
  }));
  auto& frames = builder2.frames_;
  scheduler.writeStreams(builder2);
  ASSERT_EQ(frames.size(), 1);
  scheduler.writeStreams(builder2);
  ASSERT_EQ(frames.size(), 2);
  scheduler.writeStreams(builder2);
  ASSERT_EQ(frames.size(), 3);
  WriteStreamFrame f1(stream2, 0, 9, false);
  WriteStreamFrame f2(stream3, 0, 9, false);
  WriteStreamFrame f3(stream1, 0, chainLen, false);
  ASSERT_TRUE(frames[0].asWriteStreamFrame());
  EXPECT_EQ(*frames[0].asWriteStreamFrame(), f1);
  ASSERT_TRUE(frames[1].asWriteStreamFrame());
  EXPECT_EQ(*frames[1].asWriteStreamFrame(), f2);
  ASSERT_TRUE(frames[2].asWriteStreamFrame());
  EXPECT_EQ(*frames[2].asWriteStreamFrame(), f3);
}

TEST_F(
    QuicPacketSchedulerTest,
    StreamFrameSchedulerRoundRobinStreamPerPacketHitsDsr) {
  QuicClientConnectionState conn(
      FizzClientQuicHandshakeContext::Builder().build());
  conn.streamManager->setMaxLocalBidirectionalStreams(10);
  conn.flowControlState.peerAdvertisedMaxOffset = 100000;
  conn.flowControlState.peerAdvertisedInitialMaxStreamOffsetBidiRemote = 100000;
  conn.transportSettings.streamFramePerPacket = true;
  auto connId = getTestConnectionId();
  StreamFrameScheduler scheduler(conn);
  ShortHeader shortHeader1(
      ProtectionType::KeyPhaseZero,
      connId,
      getNextPacketNum(conn, PacketNumberSpace::AppData));
  RegularQuicPacketBuilder builder1(
      conn.udpSendPacketLen,
      std::move(shortHeader1),
      conn.ackStates.appDataAckState.largestAckedByPeer.value_or(0));
  auto stream1 =
      conn.streamManager->createNextBidirectionalStream().value()->id;
  auto stream2 =
      conn.streamManager->createNextBidirectionalStream().value()->id;
  auto stream3 =
      conn.streamManager->createNextBidirectionalStream().value()->id;
  auto stream4 =
      conn.streamManager->createNextBidirectionalStream().value()->id;
  auto largeBuf = folly::IOBuf::createChain(conn.udpSendPacketLen * 2, 4096);
  auto curBuf = largeBuf.get();
  do {
    curBuf->append(curBuf->capacity());
    curBuf = curBuf->next();
  } while (curBuf != largeBuf.get());
  writeDataToQuicStream(
      *conn.streamManager->findStream(stream1), std::move(largeBuf), false);
  writeDataToQuicStream(
      *conn.streamManager->findStream(stream2),
      folly::IOBuf::copyBuffer("some data"),
      false);
  writeDataToQuicStream(
      *conn.streamManager->findStream(stream3),
      folly::IOBuf::copyBuffer("some data"),
      false);
  auto sender = std::make_unique<MockDSRPacketizationRequestSender>();
  ON_CALL(*sender, addSendInstruction(testing::_))
      .WillByDefault(testing::Return(true));
  ON_CALL(*sender, flush()).WillByDefault(testing::Return(true));
  auto dsrStream = conn.streamManager->findStream(stream4);
  dsrStream->dsrSender = std::move(sender);
  BufferMeta bufMeta(20);
  writeDataToQuicStream(
      *conn.streamManager->findStream(stream4),
      folly::IOBuf::copyBuffer("some data"),
      false);
  writeBufMetaToQuicStream(
      *conn.streamManager->findStream(stream4), bufMeta, true /* eof */);
  // Pretend we sent the non DSR data
  dsrStream->ackedIntervals.insert(0, dsrStream->writeBuffer.chainLength() - 1);
  dsrStream->currentWriteOffset = dsrStream->writeBuffer.chainLength();
  dsrStream->writeBuffer.move();
  conn.streamManager->updateWritableStreams(*dsrStream);

  // The default is to wraparound initially.
  scheduler.writeStreams(builder1);
  EXPECT_EQ(
      conn.streamManager->writeQueue().getNextScheduledStream(kDefaultPriority),
      stream2);

  // Should write frames for stream2, stream3, followed by an empty write.
  NiceMock<MockQuicPacketBuilder> builder2;
  EXPECT_CALL(builder2, remainingSpaceInPkt()).WillRepeatedly(Return(4096));
  EXPECT_CALL(builder2, appendFrame(_)).WillRepeatedly(Invoke([&](auto f) {
    builder2.frames_.push_back(f);
  }));
  auto& frames = builder2.frames_;
  ASSERT_TRUE(scheduler.hasPendingData());
  scheduler.writeStreams(builder2);
  ASSERT_EQ(frames.size(), 1);
  ASSERT_TRUE(scheduler.hasPendingData());
  scheduler.writeStreams(builder2);
  ASSERT_EQ(frames.size(), 2);
  EXPECT_FALSE(scheduler.hasPendingData());
  scheduler.writeStreams(builder2);
  WriteStreamFrame f1(stream2, 0, 9, false);
  WriteStreamFrame f2(stream3, 0, 9, false);
  ASSERT_TRUE(frames[0].asWriteStreamFrame());
  EXPECT_EQ(*frames[0].asWriteStreamFrame(), f1);
  ASSERT_TRUE(frames[1].asWriteStreamFrame());
  EXPECT_EQ(*frames[1].asWriteStreamFrame(), f2);
}

TEST_F(QuicPacketSchedulerTest, StreamFrameSchedulerSequential) {
  QuicClientConnectionState conn(
      FizzClientQuicHandshakeContext::Builder().build());
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
      conn.ackStates.appDataAckState.largestAckedByPeer.value_or(0));
  auto stream1 =
      conn.streamManager->createNextBidirectionalStream().value()->id;
  auto stream2 =
      conn.streamManager->createNextBidirectionalStream().value()->id;
  auto stream3 =
      conn.streamManager->createNextBidirectionalStream().value()->id;
  conn.streamManager->findStream(stream1)->priority = Priority(0, false);
  conn.streamManager->findStream(stream2)->priority = Priority(0, false);
  conn.streamManager->findStream(stream3)->priority = Priority(0, false);
  auto largeBuf = folly::IOBuf::createChain(conn.udpSendPacketLen * 2, 4096);
  auto curBuf = largeBuf.get();
  do {
    curBuf->append(curBuf->capacity());
    curBuf = curBuf->next();
  } while (curBuf != largeBuf.get());
  auto chainLen = largeBuf->computeChainDataLength();
  writeDataToQuicStream(
      *conn.streamManager->findStream(stream1), std::move(largeBuf), false);
  writeDataToQuicStream(
      *conn.streamManager->findStream(stream2),
      folly::IOBuf::copyBuffer("some data"),
      false);
  writeDataToQuicStream(
      *conn.streamManager->findStream(stream3),
      folly::IOBuf::copyBuffer("some data"),
      false);
  // The default is to wraparound initially.
  scheduler.writeStreams(builder1);
  EXPECT_EQ(
      conn.streamManager->writeQueue().getNextScheduledStream(
          Priority(0, false)),
      stream1);

  // Should write frames for stream1, stream2, stream3, in that order.
  NiceMock<MockQuicPacketBuilder> builder2;
  EXPECT_CALL(builder2, remainingSpaceInPkt()).WillRepeatedly(Return(4096));
  EXPECT_CALL(builder2, appendFrame(_)).WillRepeatedly(Invoke([&](auto f) {
    builder2.frames_.push_back(f);
  }));
  scheduler.writeStreams(builder2);
  auto& frames = builder2.frames_;
  ASSERT_EQ(frames.size(), 3);
  WriteStreamFrame f1(stream1, 0, chainLen, false);
  WriteStreamFrame f2(stream2, 0, 9, false);
  WriteStreamFrame f3(stream3, 0, 9, false);
  ASSERT_TRUE(frames[0].asWriteStreamFrame());
  EXPECT_EQ(*frames[0].asWriteStreamFrame(), f1);
  ASSERT_TRUE(frames[1].asWriteStreamFrame());
  EXPECT_EQ(*frames[1].asWriteStreamFrame(), f2);
  ASSERT_TRUE(frames[2].asWriteStreamFrame());
  EXPECT_EQ(*frames[2].asWriteStreamFrame(), f3);
}

TEST_F(QuicPacketSchedulerTest, StreamFrameSchedulerSequentialDefault) {
  QuicClientConnectionState conn(
      FizzClientQuicHandshakeContext::Builder().build());
  conn.streamManager->setMaxLocalBidirectionalStreams(10);
  conn.flowControlState.peerAdvertisedMaxOffset = 100000;
  conn.flowControlState.peerAdvertisedInitialMaxStreamOffsetBidiRemote = 100000;
  conn.transportSettings.defaultPriority = Priority(0, false);
  auto connId = getTestConnectionId();
  StreamFrameScheduler scheduler(conn);
  ShortHeader shortHeader1(
      ProtectionType::KeyPhaseZero,
      connId,
      getNextPacketNum(conn, PacketNumberSpace::AppData));
  RegularQuicPacketBuilder builder1(
      conn.udpSendPacketLen,
      std::move(shortHeader1),
      conn.ackStates.appDataAckState.largestAckedByPeer.value_or(0));
  auto stream1 =
      conn.streamManager->createNextBidirectionalStream().value()->id;
  auto stream2 =
      conn.streamManager->createNextBidirectionalStream().value()->id;
  auto stream3 =
      conn.streamManager->createNextBidirectionalStream().value()->id;
  auto largeBuf = folly::IOBuf::createChain(conn.udpSendPacketLen * 2, 4096);
  auto curBuf = largeBuf.get();
  do {
    curBuf->append(curBuf->capacity());
    curBuf = curBuf->next();
  } while (curBuf != largeBuf.get());
  auto chainLen = largeBuf->computeChainDataLength();
  writeDataToQuicStream(
      *conn.streamManager->findStream(stream1), std::move(largeBuf), false);
  writeDataToQuicStream(
      *conn.streamManager->findStream(stream2),
      folly::IOBuf::copyBuffer("some data"),
      false);
  writeDataToQuicStream(
      *conn.streamManager->findStream(stream3),
      folly::IOBuf::copyBuffer("some data"),
      false);
  // The default is to wraparound initially.
  scheduler.writeStreams(builder1);
  EXPECT_EQ(
      conn.streamManager->writeQueue().getNextScheduledStream(
          Priority(0, false)),
      stream1);

  // Should write frames for stream1, stream2, stream3, in that order.
  NiceMock<MockQuicPacketBuilder> builder2;
  EXPECT_CALL(builder2, remainingSpaceInPkt()).WillRepeatedly(Return(4096));
  EXPECT_CALL(builder2, appendFrame(_)).WillRepeatedly(Invoke([&](auto f) {
    builder2.frames_.push_back(f);
  }));
  scheduler.writeStreams(builder2);
  auto& frames = builder2.frames_;
  ASSERT_EQ(frames.size(), 3);
  WriteStreamFrame f1(stream1, 0, chainLen, false);
  WriteStreamFrame f2(stream2, 0, 9, false);
  WriteStreamFrame f3(stream3, 0, 9, false);
  ASSERT_TRUE(frames[0].asWriteStreamFrame());
  EXPECT_EQ(*frames[0].asWriteStreamFrame(), f1);
  ASSERT_TRUE(frames[1].asWriteStreamFrame());
  EXPECT_EQ(*frames[1].asWriteStreamFrame(), f2);
  ASSERT_TRUE(frames[2].asWriteStreamFrame());
  EXPECT_EQ(*frames[2].asWriteStreamFrame(), f3);
}

TEST_F(QuicPacketSchedulerTest, StreamFrameSchedulerRoundRobinControl) {
  QuicClientConnectionState conn(
      FizzClientQuicHandshakeContext::Builder().build());
  conn.streamManager->setMaxLocalBidirectionalStreams(10);
  conn.flowControlState.peerAdvertisedMaxOffset = 100000;
  conn.flowControlState.peerAdvertisedInitialMaxStreamOffsetBidiRemote = 100000;
  auto connId = getTestConnectionId();
  StreamFrameScheduler scheduler(conn);
  ShortHeader shortHeader1(
      ProtectionType::KeyPhaseZero,
      connId,
      getNextPacketNum(conn, PacketNumberSpace::AppData));
  RegularQuicPacketBuilder builder(
      conn.udpSendPacketLen,
      std::move(shortHeader1),
      conn.ackStates.appDataAckState.largestAckedByPeer.value_or(0));
  builder.encodePacketHeader();
  auto stream1 =
      conn.streamManager->createNextBidirectionalStream().value()->id;
  auto stream2 =
      conn.streamManager->createNextBidirectionalStream().value()->id;
  auto stream3 =
      conn.streamManager->createNextBidirectionalStream().value()->id;
  auto stream4 =
      conn.streamManager->createNextBidirectionalStream().value()->id;
  conn.streamManager->setStreamAsControl(
      *conn.streamManager->findStream(stream2));
  conn.streamManager->setStreamAsControl(
      *conn.streamManager->findStream(stream4));
  auto largeBuf = folly::IOBuf::createChain(conn.udpSendPacketLen * 2, 4096);
  auto curBuf = largeBuf.get();
  do {
    curBuf->append(curBuf->capacity());
    curBuf = curBuf->next();
  } while (curBuf != largeBuf.get());
  auto chainLen = largeBuf->computeChainDataLength();
  writeDataToQuicStream(
      *conn.streamManager->findStream(stream1), std::move(largeBuf), false);
  writeDataToQuicStream(
      *conn.streamManager->findStream(stream2),
      folly::IOBuf::copyBuffer("some data"),
      false);
  writeDataToQuicStream(
      *conn.streamManager->findStream(stream3),
      folly::IOBuf::copyBuffer("some data"),
      false);
  writeDataToQuicStream(
      *conn.streamManager->findStream(stream4),
      folly::IOBuf::copyBuffer("some data"),
      false);
  // The default is to wraparound initially.
  scheduler.writeStreams(builder);
  EXPECT_EQ(
      conn.streamManager->writeQueue().getNextScheduledStream(kDefaultPriority),
      stream3);
  EXPECT_EQ(conn.schedulingState.nextScheduledControlStream, stream2);

  // Should write frames for stream2, stream4, followed by stream 3 then 1.
  NiceMock<MockQuicPacketBuilder> builder2;
  EXPECT_CALL(builder2, remainingSpaceInPkt()).WillRepeatedly(Return(4096));
  EXPECT_CALL(builder2, appendFrame(_)).WillRepeatedly(Invoke([&](auto f) {
    builder2.frames_.push_back(f);
  }));
  scheduler.writeStreams(builder2);
  auto& frames = builder2.frames_;
  ASSERT_EQ(frames.size(), 4);
  WriteStreamFrame f1(stream2, 0, 9, false);
  WriteStreamFrame f2(stream4, 0, 9, false);
  WriteStreamFrame f3(stream3, 0, 9, false);
  WriteStreamFrame f4(stream1, 0, chainLen, false);
  ASSERT_TRUE(frames[0].asWriteStreamFrame());
  EXPECT_EQ(*frames[0].asWriteStreamFrame(), f1);
  ASSERT_TRUE(frames[1].asWriteStreamFrame());
  EXPECT_EQ(*frames[1].asWriteStreamFrame(), f2);
  ASSERT_TRUE(frames[2].asWriteStreamFrame());
  EXPECT_EQ(*frames[2].asWriteStreamFrame(), f3);
  ASSERT_TRUE(frames[3].asWriteStreamFrame());
  EXPECT_EQ(*frames[3].asWriteStreamFrame(), f4);

  EXPECT_EQ(
      conn.streamManager->writeQueue().getNextScheduledStream(kDefaultPriority),
      stream3);
  EXPECT_EQ(conn.schedulingState.nextScheduledControlStream, stream2);
}

TEST_F(QuicPacketSchedulerTest, StreamFrameSchedulerOneStream) {
  QuicClientConnectionState conn(
      FizzClientQuicHandshakeContext::Builder().build());
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
      conn.ackStates.appDataAckState.largestAckedByPeer.value_or(0));
  builder.encodePacketHeader();
  auto stream1 = conn.streamManager->createNextBidirectionalStream().value();
  writeDataToQuicStream(*stream1, folly::IOBuf::copyBuffer("some data"), false);
  scheduler.writeStreams(builder);
  EXPECT_EQ(
      conn.streamManager->writeQueue().getNextScheduledStream(kDefaultPriority),
      0);
}

TEST_F(QuicPacketSchedulerTest, StreamFrameSchedulerRemoveOne) {
  QuicClientConnectionState conn(
      FizzClientQuicHandshakeContext::Builder().build());
  conn.streamManager->setMaxLocalBidirectionalStreams(10);
  conn.flowControlState.peerAdvertisedMaxOffset = 100000;
  conn.flowControlState.peerAdvertisedInitialMaxStreamOffsetBidiRemote = 100000;
  StreamFrameScheduler scheduler(conn);
  NiceMock<MockQuicPacketBuilder> builder;
  auto stream1 =
      conn.streamManager->createNextBidirectionalStream().value()->id;
  auto stream2 =
      conn.streamManager->createNextBidirectionalStream().value()->id;
  writeDataToQuicStream(
      *conn.streamManager->findStream(stream1),
      folly::IOBuf::copyBuffer("some data"),
      false);
  writeDataToQuicStream(
      *conn.streamManager->findStream(stream2),
      folly::IOBuf::copyBuffer("some data"),
      false);
  EXPECT_CALL(builder, remainingSpaceInPkt()).WillRepeatedly(Return(4096));
  EXPECT_CALL(builder, appendFrame(_)).WillRepeatedly(Invoke([&](auto f) {
    builder.frames_.push_back(f);
  }));
  scheduler.writeStreams(builder);
  WriteStreamFrame f1(stream1, 0, 9, false);
  WriteStreamFrame f2(stream2, 0, 9, false);
  ASSERT_TRUE(builder.frames_[0].asWriteStreamFrame());
  EXPECT_EQ(*builder.frames_[0].asWriteStreamFrame(), f1);
  ASSERT_TRUE(builder.frames_[1].asWriteStreamFrame());
  EXPECT_EQ(*builder.frames_[1].asWriteStreamFrame(), f2);

  // Manually remove a stream and set the next scheduled to that stream.
  builder.frames_.clear();
  conn.streamManager->writeQueue().setNextScheduledStream(stream2);
  conn.streamManager->removeWritable(*conn.streamManager->findStream(stream2));
  scheduler.writeStreams(builder);
  ASSERT_EQ(builder.frames_.size(), 1);
  ASSERT_TRUE(builder.frames_[0].asWriteStreamFrame());
  EXPECT_EQ(*builder.frames_[0].asWriteStreamFrame(), f1);
}

TEST_F(
    QuicPacketSchedulerTest,
    CloningSchedulerWithInplaceBuilderDoNotEncodeHeaderWithoutBuild) {
  QuicClientConnectionState conn(
      FizzClientQuicHandshakeContext::Builder().build());
  conn.transportSettings.dataPathType = DataPathType::ContinuousMemory;
  SimpleBufAccessor bufAccessor(2000);
  auto buf = bufAccessor.obtain();
  EXPECT_EQ(buf->length(), 0);
  bufAccessor.release(std::move(buf));
  conn.bufAccessor = &bufAccessor;

  FrameScheduler noopScheduler("frame", conn);
  ASSERT_FALSE(noopScheduler.hasData());
  CloningScheduler cloningScheduler(noopScheduler, conn, "Little Hurry", 0);
  addOutstandingPacket(conn);
  // There needs to have retransmittable frame for the rebuilder to work
  conn.outstandings.packets.back().packet.frames.push_back(
      MaxDataFrame(conn.flowControlState.advertisedMaxOffset));
  // Lie about the encodedSize to let the Cloner skip it:
  conn.outstandings.packets.back().metadata.encodedSize =
      kDefaultUDPSendPacketLen * 2;
  EXPECT_TRUE(cloningScheduler.hasData());

  ASSERT_FALSE(noopScheduler.hasData());
  ShortHeader header(
      ProtectionType::KeyPhaseOne,
      conn.clientConnectionId.value_or(getTestConnectionId()),
      getNextPacketNum(conn, PacketNumberSpace::AppData));
  InplaceQuicPacketBuilder builder(
      bufAccessor,
      conn.udpSendPacketLen,
      std::move(header),
      conn.ackStates.appDataAckState.largestAckedByPeer.value_or(0));
  auto result = cloningScheduler.scheduleFramesForPacket(
      std::move(builder), kDefaultUDPSendPacketLen);
  EXPECT_FALSE(result.packetEvent.has_value());

  // Nothing was written into the buffer:
  EXPECT_TRUE(bufAccessor.ownsBuffer());
  buf = bufAccessor.obtain();
  EXPECT_EQ(buf->length(), 0);
}

TEST_F(
    QuicPacketSchedulerTest,
    CloningSchedulerWithInplaceBuilderRollbackBufWhenFailToRebuild) {
  QuicClientConnectionState conn(
      FizzClientQuicHandshakeContext::Builder().build());
  conn.transportSettings.dataPathType = DataPathType::ContinuousMemory;
  SimpleBufAccessor bufAccessor(2000);
  auto buf = bufAccessor.obtain();
  EXPECT_EQ(buf->length(), 0);
  bufAccessor.release(std::move(buf));
  conn.bufAccessor = &bufAccessor;

  FrameScheduler noopScheduler("frame", conn);
  ASSERT_FALSE(noopScheduler.hasData());
  CloningScheduler cloningScheduler(noopScheduler, conn, "HotPot", 0);
  addOutstandingPacket(conn);
  // Not adding frame to this outstanding packet so that rebuild will fail:
  ASSERT_TRUE(conn.outstandings.packets.back().packet.frames.empty());
  EXPECT_TRUE(cloningScheduler.hasData());

  ASSERT_FALSE(noopScheduler.hasData());
  ShortHeader header(
      ProtectionType::KeyPhaseOne,
      conn.clientConnectionId.value_or(getTestConnectionId()),
      getNextPacketNum(conn, PacketNumberSpace::AppData));
  InplaceQuicPacketBuilder builder(
      bufAccessor,
      conn.udpSendPacketLen,
      std::move(header),
      conn.ackStates.appDataAckState.largestAckedByPeer.value_or(0));
  auto result = cloningScheduler.scheduleFramesForPacket(
      std::move(builder), kDefaultUDPSendPacketLen);
  EXPECT_FALSE(result.packetEvent.has_value());

  // Nothing was written into the buffer:
  EXPECT_TRUE(bufAccessor.ownsBuffer());
  buf = bufAccessor.obtain();
  EXPECT_EQ(buf->length(), 0);
}

TEST_F(QuicPacketSchedulerTest, HighPriNewDataBeforeLowPriLossData) {
  QuicServerConnectionState conn(
      FizzServerQuicHandshakeContext::Builder().build());
  conn.streamManager->setMaxLocalBidirectionalStreams(10);
  conn.flowControlState.peerAdvertisedMaxOffset = 100000;
  conn.flowControlState.peerAdvertisedInitialMaxStreamOffsetBidiRemote = 100000;
  auto lowPriStreamId =
      (*conn.streamManager->createNextBidirectionalStream())->id;
  auto highPriStreamId =
      (*conn.streamManager->createNextBidirectionalStream())->id;
  auto lowPriStream = conn.streamManager->findStream(lowPriStreamId);
  auto highPriStream = conn.streamManager->findStream(highPriStreamId);

  lowPriStream->lossBuffer.push_back(
      StreamBuffer(folly::IOBuf::copyBuffer("Onegin"), 0, false));
  conn.streamManager->updateWritableStreams(*lowPriStream);
  conn.streamManager->setStreamPriority(lowPriStream->id, Priority(5, false));

  auto inBuf = buildRandomInputData(conn.udpSendPacketLen * 10);
  writeDataToQuicStream(*highPriStream, inBuf->clone(), false);
  conn.streamManager->updateWritableStreams(*highPriStream);
  conn.streamManager->setStreamPriority(highPriStream->id, Priority(0, false));

  StreamFrameScheduler scheduler(conn);
  ShortHeader shortHeader(
      ProtectionType::KeyPhaseZero,
      getTestConnectionId(),
      getNextPacketNum(conn, PacketNumberSpace::AppData));
  RegularQuicPacketBuilder builder(
      conn.udpSendPacketLen,
      std::move(shortHeader),
      conn.ackStates.appDataAckState.largestAckedByPeer.value_or(0));
  builder.encodePacketHeader();
  scheduler.writeStreams(builder);
  auto packet = std::move(builder).buildPacket().packet;
  EXPECT_EQ(1, packet.frames.size());
  auto& writeStreamFrame = *packet.frames[0].asWriteStreamFrame();
  EXPECT_EQ(highPriStream->id, writeStreamFrame.streamId);
  EXPECT_FALSE(lowPriStream->lossBuffer.empty());
}

TEST_F(QuicPacketSchedulerTest, WriteLossWithoutFlowControl) {
  QuicServerConnectionState conn(
      FizzServerQuicHandshakeContext::Builder().build());
  conn.streamManager->setMaxLocalBidirectionalStreams(10);
  conn.flowControlState.peerAdvertisedMaxOffset = 1000;
  conn.flowControlState.peerAdvertisedInitialMaxStreamOffsetBidiRemote = 1000;

  auto streamId = (*conn.streamManager->createNextBidirectionalStream())->id;
  auto stream = conn.streamManager->findStream(streamId);
  auto data = buildRandomInputData(1000);
  writeDataToQuicStream(*stream, std::move(data), true);
  conn.streamManager->updateWritableStreams(*stream);

  StreamFrameScheduler scheduler(conn);
  EXPECT_TRUE(scheduler.hasPendingData());
  ShortHeader shortHeader1(
      ProtectionType::KeyPhaseZero,
      getTestConnectionId(),
      getNextPacketNum(conn, PacketNumberSpace::AppData));
  RegularQuicPacketBuilder builder1(
      conn.udpSendPacketLen,
      std::move(shortHeader1),
      conn.ackStates.appDataAckState.largestAckedByPeer.value_or(0));
  builder1.encodePacketHeader();
  scheduler.writeStreams(builder1);
  auto packet1 = std::move(builder1).buildPacket().packet;
  updateConnection(
      conn, folly::none, packet1, Clock::now(), 1000, 0, false /* isDSR */);
  EXPECT_EQ(1, packet1.frames.size());
  auto& writeStreamFrame1 = *packet1.frames[0].asWriteStreamFrame();
  EXPECT_EQ(streamId, writeStreamFrame1.streamId);
  EXPECT_EQ(0, getSendConnFlowControlBytesWire(conn));
  EXPECT_EQ(0, stream->writeBuffer.chainLength());
  EXPECT_EQ(1, stream->retransmissionBuffer.size());
  EXPECT_EQ(1000, stream->retransmissionBuffer[0]->data.chainLength());

  // Move the bytes to loss buffer:
  stream->lossBuffer.emplace_back(std::move(*stream->retransmissionBuffer[0]));
  stream->retransmissionBuffer.clear();
  conn.streamManager->updateWritableStreams(*stream);
  EXPECT_TRUE(scheduler.hasPendingData());

  // Write again
  ShortHeader shortHeader2(
      ProtectionType::KeyPhaseZero,
      getTestConnectionId(),
      getNextPacketNum(conn, PacketNumberSpace::AppData));
  RegularQuicPacketBuilder builder2(
      conn.udpSendPacketLen,
      std::move(shortHeader2),
      conn.ackStates.appDataAckState.largestAckedByPeer.value_or(0));
  builder2.encodePacketHeader();
  scheduler.writeStreams(builder2);
  auto packet2 = std::move(builder2).buildPacket().packet;
  updateConnection(
      conn, folly::none, packet2, Clock::now(), 1000, 0, false /* isDSR */);
  EXPECT_EQ(1, packet2.frames.size());
  auto& writeStreamFrame2 = *packet2.frames[0].asWriteStreamFrame();
  EXPECT_EQ(streamId, writeStreamFrame2.streamId);
  EXPECT_EQ(0, getSendConnFlowControlBytesWire(conn));
  EXPECT_TRUE(stream->lossBuffer.empty());
  EXPECT_EQ(1, stream->retransmissionBuffer.size());
  EXPECT_EQ(1000, stream->retransmissionBuffer[0]->data.chainLength());
}

TEST_F(QuicPacketSchedulerTest, WriteLossWithoutFlowControlIgnoreDSR) {
  QuicServerConnectionState conn(
      FizzServerQuicHandshakeContext::Builder().build());
  conn.streamManager->setMaxLocalBidirectionalStreams(10);
  conn.flowControlState.peerAdvertisedMaxOffset = 1000;
  conn.flowControlState.peerAdvertisedInitialMaxStreamOffsetBidiRemote = 1000;

  auto streamId = (*conn.streamManager->createNextBidirectionalStream())->id;
  auto dsrStream = conn.streamManager->createNextBidirectionalStream().value();
  auto stream = conn.streamManager->findStream(streamId);
  auto data = buildRandomInputData(1000);
  writeDataToQuicStream(*stream, std::move(data), true);
  WriteBufferMeta bufMeta{};
  bufMeta.offset = 0;
  bufMeta.length = 100;
  bufMeta.eof = false;
  dsrStream->insertIntoLossBufMeta(bufMeta);
  conn.streamManager->updateWritableStreams(*stream);
  conn.streamManager->updateWritableStreams(*dsrStream);

  StreamFrameScheduler scheduler(conn);
  EXPECT_TRUE(scheduler.hasPendingData());
  ShortHeader shortHeader1(
      ProtectionType::KeyPhaseZero,
      getTestConnectionId(),
      getNextPacketNum(conn, PacketNumberSpace::AppData));
  RegularQuicPacketBuilder builder1(
      conn.udpSendPacketLen,
      std::move(shortHeader1),
      conn.ackStates.appDataAckState.largestAckedByPeer.value_or(0));
  builder1.encodePacketHeader();
  scheduler.writeStreams(builder1);
  auto packet1 = std::move(builder1).buildPacket().packet;
  updateConnection(
      conn, folly::none, packet1, Clock::now(), 1000, 0, false /* isDSR */);
  EXPECT_EQ(1, packet1.frames.size());
  auto& writeStreamFrame1 = *packet1.frames[0].asWriteStreamFrame();
  EXPECT_EQ(streamId, writeStreamFrame1.streamId);
  EXPECT_EQ(0, getSendConnFlowControlBytesWire(conn));
  EXPECT_EQ(0, stream->writeBuffer.chainLength());
  EXPECT_EQ(1, stream->retransmissionBuffer.size());
  EXPECT_EQ(1000, stream->retransmissionBuffer[0]->data.chainLength());

  EXPECT_FALSE(scheduler.hasPendingData());
}

TEST_F(QuicPacketSchedulerTest, WriteLossWithoutFlowControlSequential) {
  QuicServerConnectionState conn(
      FizzServerQuicHandshakeContext::Builder().build());
  conn.streamManager->setMaxLocalBidirectionalStreams(10);
  conn.flowControlState.peerAdvertisedMaxOffset = 1000;
  conn.flowControlState.peerAdvertisedInitialMaxStreamOffsetBidiRemote = 1000;

  auto streamId = (*conn.streamManager->createNextBidirectionalStream())->id;
  conn.streamManager->setStreamPriority(streamId, Priority(0, false));
  auto stream = conn.streamManager->findStream(streamId);
  auto data = buildRandomInputData(1000);
  writeDataToQuicStream(*stream, std::move(data), true);
  conn.streamManager->updateWritableStreams(*stream);

  StreamFrameScheduler scheduler(conn);
  EXPECT_TRUE(scheduler.hasPendingData());
  ShortHeader shortHeader1(
      ProtectionType::KeyPhaseZero,
      getTestConnectionId(),
      getNextPacketNum(conn, PacketNumberSpace::AppData));
  RegularQuicPacketBuilder builder1(
      conn.udpSendPacketLen,
      std::move(shortHeader1),
      conn.ackStates.appDataAckState.largestAckedByPeer.value_or(0));
  builder1.encodePacketHeader();
  scheduler.writeStreams(builder1);
  auto packet1 = std::move(builder1).buildPacket().packet;
  updateConnection(
      conn, folly::none, packet1, Clock::now(), 1000, 0, false /* isDSR */);
  EXPECT_EQ(1, packet1.frames.size());
  auto& writeStreamFrame1 = *packet1.frames[0].asWriteStreamFrame();
  EXPECT_EQ(streamId, writeStreamFrame1.streamId);
  EXPECT_EQ(0, getSendConnFlowControlBytesWire(conn));
  EXPECT_EQ(0, stream->writeBuffer.chainLength());
  EXPECT_EQ(1, stream->retransmissionBuffer.size());
  EXPECT_EQ(1000, stream->retransmissionBuffer[0]->data.chainLength());

  // Move the bytes to loss buffer:
  stream->lossBuffer.emplace_back(std::move(*stream->retransmissionBuffer[0]));
  stream->retransmissionBuffer.clear();
  conn.streamManager->updateWritableStreams(*stream);
  EXPECT_TRUE(scheduler.hasPendingData());

  // Write again
  ShortHeader shortHeader2(
      ProtectionType::KeyPhaseZero,
      getTestConnectionId(),
      getNextPacketNum(conn, PacketNumberSpace::AppData));
  RegularQuicPacketBuilder builder2(
      conn.udpSendPacketLen,
      std::move(shortHeader2),
      conn.ackStates.appDataAckState.largestAckedByPeer.value_or(0));
  builder2.encodePacketHeader();
  scheduler.writeStreams(builder2);
  auto packet2 = std::move(builder2).buildPacket().packet;
  updateConnection(
      conn, folly::none, packet2, Clock::now(), 1000, 0, false /* isDSR */);
  EXPECT_EQ(1, packet2.frames.size());
  auto& writeStreamFrame2 = *packet2.frames[0].asWriteStreamFrame();
  EXPECT_EQ(streamId, writeStreamFrame2.streamId);
  EXPECT_EQ(0, getSendConnFlowControlBytesWire(conn));
  EXPECT_TRUE(stream->lossBuffer.empty());
  EXPECT_EQ(1, stream->retransmissionBuffer.size());
  EXPECT_EQ(1000, stream->retransmissionBuffer[0]->data.chainLength());
}

TEST_F(QuicPacketSchedulerTest, RunOutFlowControlDuringStreamWrite) {
  QuicServerConnectionState conn(
      FizzServerQuicHandshakeContext::Builder().build());
  conn.streamManager->setMaxLocalBidirectionalStreams(10);
  conn.flowControlState.peerAdvertisedMaxOffset = 1000;
  conn.flowControlState.peerAdvertisedInitialMaxStreamOffsetBidiRemote = 1000;
  conn.udpSendPacketLen = 2000;

  auto streamId1 = (*conn.streamManager->createNextBidirectionalStream())->id;
  auto streamId2 = (*conn.streamManager->createNextBidirectionalStream())->id;
  auto stream1 = conn.streamManager->findStream(streamId1);
  auto stream2 = conn.streamManager->findStream(streamId2);
  auto newData = buildRandomInputData(1000);
  writeDataToQuicStream(*stream1, std::move(newData), true);
  conn.streamManager->updateWritableStreams(*stream1);

  // Fake a loss data for stream2:
  stream2->currentWriteOffset = 201;
  auto lossData = buildRandomInputData(200);
  stream2->lossBuffer.emplace_back(std::move(lossData), 0, true);
  conn.streamManager->updateWritableStreams(*stream2);

  StreamFrameScheduler scheduler(conn);
  ShortHeader shortHeader1(
      ProtectionType::KeyPhaseZero,
      getTestConnectionId(),
      getNextPacketNum(conn, PacketNumberSpace::AppData));
  RegularQuicPacketBuilder builder1(
      conn.udpSendPacketLen,
      std::move(shortHeader1),
      conn.ackStates.appDataAckState.largestAckedByPeer.value_or(0));
  builder1.encodePacketHeader();
  scheduler.writeStreams(builder1);
  auto packet1 = std::move(builder1).buildPacket().packet;
  updateConnection(
      conn, folly::none, packet1, Clock::now(), 1200, 0, false /* isDSR */);
  ASSERT_EQ(2, packet1.frames.size());
  auto& writeStreamFrame1 = *packet1.frames[0].asWriteStreamFrame();
  EXPECT_EQ(streamId1, writeStreamFrame1.streamId);
  EXPECT_EQ(0, getSendConnFlowControlBytesWire(conn));
  EXPECT_EQ(0, stream1->writeBuffer.chainLength());
  EXPECT_EQ(1, stream1->retransmissionBuffer.size());
  EXPECT_EQ(1000, stream1->retransmissionBuffer[0]->data.chainLength());

  auto& writeStreamFrame2 = *packet1.frames[1].asWriteStreamFrame();
  EXPECT_EQ(streamId2, writeStreamFrame2.streamId);
  EXPECT_EQ(200, writeStreamFrame2.len);
  EXPECT_TRUE(stream2->lossBuffer.empty());
  EXPECT_EQ(1, stream2->retransmissionBuffer.size());
  EXPECT_EQ(200, stream2->retransmissionBuffer[0]->data.chainLength());
}

TEST_F(QuicPacketSchedulerTest, WritingFINFromBufWithBufMetaFirst) {
  QuicServerConnectionState conn(
      FizzServerQuicHandshakeContext::Builder().build());
  conn.streamManager->setMaxLocalBidirectionalStreams(10);
  conn.flowControlState.peerAdvertisedMaxOffset = 100000;
  auto* stream = *(conn.streamManager->createNextBidirectionalStream());
  stream->flowControlState.peerAdvertisedMaxOffset = 100000;

  writeDataToQuicStream(*stream, folly::IOBuf::copyBuffer("Ascent"), false);
  stream->dsrSender = std::make_unique<MockDSRPacketizationRequestSender>();
  BufferMeta bufferMeta(5000);
  writeBufMetaToQuicStream(*stream, bufferMeta, true);
  EXPECT_TRUE(stream->finalWriteOffset.hasValue());

  stream->writeBufMeta.split(5000);
  ASSERT_EQ(0, stream->writeBufMeta.length);
  ASSERT_GT(stream->writeBufMeta.offset, 0);
  conn.streamManager->updateWritableStreams(*stream);

  PacketNum packetNum = 0;
  ShortHeader header(
      ProtectionType::KeyPhaseOne,
      conn.clientConnectionId.value_or(getTestConnectionId()),
      packetNum);
  RegularQuicPacketBuilder builder(
      conn.udpSendPacketLen,
      std::move(header),
      conn.ackStates.appDataAckState.largestAckedByPeer.value_or(0));
  builder.encodePacketHeader();
  StreamFrameScheduler scheduler(conn);
  scheduler.writeStreams(builder);
  auto packet = std::move(builder).buildPacket().packet;
  ASSERT_EQ(1, packet.frames.size());
  auto streamFrame = *packet.frames[0].asWriteStreamFrame();
  EXPECT_EQ(streamFrame.len, 6);
  EXPECT_EQ(streamFrame.offset, 0);
  EXPECT_FALSE(streamFrame.fin);
  handleNewStreamDataWritten(*stream, streamFrame.len, streamFrame.fin);
  EXPECT_EQ(stream->currentWriteOffset, 6);
}

TEST_F(QuicPacketSchedulerTest, NoFINWriteWhenBufMetaWrittenFIN) {
  QuicServerConnectionState conn(
      FizzServerQuicHandshakeContext::Builder().build());
  conn.streamManager->setMaxLocalBidirectionalStreams(10);
  conn.flowControlState.peerAdvertisedMaxOffset = 100000;
  auto* stream = *(conn.streamManager->createNextBidirectionalStream());
  stream->flowControlState.peerAdvertisedMaxOffset = 100000;

  writeDataToQuicStream(*stream, folly::IOBuf::copyBuffer("Ascent"), false);
  stream->dsrSender = std::make_unique<MockDSRPacketizationRequestSender>();
  BufferMeta bufferMeta(5000);
  writeBufMetaToQuicStream(*stream, bufferMeta, true);
  EXPECT_TRUE(stream->finalWriteOffset.hasValue());
  PacketNum packetNum = 0;
  ShortHeader header(
      ProtectionType::KeyPhaseOne,
      conn.clientConnectionId.value_or(getTestConnectionId()),
      packetNum);
  RegularQuicPacketBuilder builder(
      conn.udpSendPacketLen,
      std::move(header),
      conn.ackStates.appDataAckState.largestAckedByPeer.value_or(0));
  builder.encodePacketHeader();
  StreamFrameScheduler scheduler(conn);
  scheduler.writeStreams(builder);
  auto packet = std::move(builder).buildPacket().packet;
  EXPECT_EQ(1, packet.frames.size());
  auto streamFrame = *packet.frames[0].asWriteStreamFrame();
  EXPECT_EQ(streamFrame.len, 6);
  EXPECT_EQ(streamFrame.offset, 0);
  EXPECT_FALSE(streamFrame.fin);
  handleNewStreamDataWritten(*stream, streamFrame.len, streamFrame.fin);

  // Pretent all the bufMetas were sent, without FIN bit
  stream->writeBufMeta.split(5000);
  stream->writeBufMeta.offset++;
  ASSERT_EQ(0, stream->writeBufMeta.length);
  ASSERT_GT(stream->writeBufMeta.offset, 0);
  conn.streamManager->updateWritableStreams(*stream);
  StreamFrameScheduler scheduler2(conn);
  EXPECT_FALSE(scheduler2.hasPendingData());
}

TEST_F(QuicPacketSchedulerTest, DatagramFrameSchedulerMultipleFramesPerPacket) {
  QuicClientConnectionState conn(
      FizzClientQuicHandshakeContext::Builder().build());
  conn.datagramState.maxReadFrameSize = std::numeric_limits<uint16_t>::max();
  conn.datagramState.maxReadBufferSize = 10;
  conn.transportSettings.datagramConfig.framePerPacket = false;
  DatagramFrameScheduler scheduler(conn);
  // Add datagrams
  std::string s1(conn.udpSendPacketLen / 3, '*');
  conn.datagramState.writeBuffer.emplace_back(folly::IOBuf::copyBuffer(s1));
  std::string s2(conn.udpSendPacketLen / 3, '%');
  conn.datagramState.writeBuffer.emplace_back(folly::IOBuf::copyBuffer(s2));
  NiceMock<MockQuicPacketBuilder> builder;
  EXPECT_CALL(builder, remainingSpaceInPkt()).WillRepeatedly(Return(4096));
  EXPECT_CALL(builder, appendFrame(_)).WillRepeatedly(Invoke([&](auto f) {
    builder.frames_.push_back(f);
  }));
  NiceMock<MockQuicStats> quicStats;
  conn.statsCallback = &quicStats;
  EXPECT_CALL(quicStats, onDatagramWrite(_))
      .Times(2)
      .WillRepeatedly(Invoke([](uint64_t bytes) { EXPECT_GT(bytes, 0); }));
  // Call scheduler
  auto& frames = builder.frames_;
  scheduler.writeDatagramFrames(builder);
  ASSERT_EQ(frames.size(), 2);
}

TEST_F(QuicPacketSchedulerTest, DatagramFrameSchedulerOneFramePerPacket) {
  QuicClientConnectionState conn(
      FizzClientQuicHandshakeContext::Builder().build());
  conn.datagramState.maxReadFrameSize = std::numeric_limits<uint16_t>::max();
  conn.datagramState.maxReadBufferSize = 10;
  conn.transportSettings.datagramConfig.framePerPacket = true;
  DatagramFrameScheduler scheduler(conn);
  // Add datagrams
  std::string s1(conn.udpSendPacketLen / 3, '*');
  conn.datagramState.writeBuffer.emplace_back(folly::IOBuf::copyBuffer(s1));
  std::string s2(conn.udpSendPacketLen / 3, '%');
  conn.datagramState.writeBuffer.emplace_back(folly::IOBuf::copyBuffer(s2));
  NiceMock<MockQuicPacketBuilder> builder;
  EXPECT_CALL(builder, remainingSpaceInPkt()).WillRepeatedly(Return(4096));
  EXPECT_CALL(builder, appendFrame(_)).WillRepeatedly(Invoke([&](auto f) {
    builder.frames_.push_back(f);
  }));
  NiceMock<MockQuicStats> quicStats;
  conn.statsCallback = &quicStats;
  // Call scheduler
  auto& frames = builder.frames_;
  EXPECT_CALL(quicStats, onDatagramWrite(_))
      .Times(1)
      .WillRepeatedly(Invoke([](uint64_t bytes) { EXPECT_GT(bytes, 0); }));
  scheduler.writeDatagramFrames(builder);
  ASSERT_EQ(frames.size(), 1);
  EXPECT_CALL(quicStats, onDatagramWrite(_))
      .Times(1)
      .WillRepeatedly(Invoke([](uint64_t bytes) { EXPECT_GT(bytes, 0); }));
  scheduler.writeDatagramFrames(builder);
  ASSERT_EQ(frames.size(), 2);
}

TEST_F(QuicPacketSchedulerTest, DatagramFrameWriteWhenRoomAvailable) {
  QuicClientConnectionState conn(
      FizzClientQuicHandshakeContext::Builder().build());
  conn.datagramState.maxReadFrameSize = std::numeric_limits<uint16_t>::max();
  conn.datagramState.maxReadBufferSize = 10;
  conn.transportSettings.datagramConfig.framePerPacket = true;
  DatagramFrameScheduler scheduler(conn);
  // Add datagram
  std::string s(conn.udpSendPacketLen / 3, '*');
  conn.datagramState.writeBuffer.emplace_back(folly::IOBuf::copyBuffer(s));
  NiceMock<MockQuicPacketBuilder> builder;
  EXPECT_CALL(builder, remainingSpaceInPkt())
      .WillRepeatedly(Return(conn.udpSendPacketLen / 4));
  EXPECT_CALL(builder, appendFrame(_)).WillRepeatedly(Invoke([&](auto f) {
    builder.frames_.push_back(f);
  }));
  NiceMock<MockQuicStats> quicStats;
  conn.statsCallback = &quicStats;
  // Call scheduler
  auto& frames = builder.frames_;
  scheduler.writeDatagramFrames(builder);
  ASSERT_EQ(frames.size(), 0);
  EXPECT_CALL(builder, remainingSpaceInPkt())
      .WillRepeatedly(Return(conn.udpSendPacketLen / 2));
  EXPECT_CALL(quicStats, onDatagramWrite(_))
      .Times(1)
      .WillRepeatedly(Invoke([](uint64_t bytes) { EXPECT_GT(bytes, 0); }));
  scheduler.writeDatagramFrames(builder);
  ASSERT_EQ(frames.size(), 1);
}

TEST_F(QuicPacketSchedulerTest, ShortHeaderPaddingWithSpaceForPadding) {
  QuicServerConnectionState conn(
      FizzServerQuicHandshakeContext::Builder().build());
  size_t paddingModulo = 16;
  conn.transportSettings.paddingModulo = paddingModulo;
  // create enough input data to partially fill packet
  size_t inputDataLength1 = conn.udpSendPacketLen / 2;
  size_t inputDataLength2 = inputDataLength1 + 1;
  auto inputData1 = buildRandomInputData(inputDataLength1);
  auto inputData2 = buildRandomInputData(inputDataLength2);

  FrameScheduler scheduler = std::move(FrameScheduler::Builder(
                                           conn,
                                           EncryptionLevel::AppData,
                                           PacketNumberSpace::AppData,
                                           "streamScheduler")
                                           .streamFrames())
                                 .build();

  ShortHeader shortHeader1(
      ProtectionType::KeyPhaseOne,
      conn.clientConnectionId.value_or(getTestConnectionId()),
      getNextPacketNum(conn, PacketNumberSpace::AppData));
  ShortHeader shortHeader2(
      ProtectionType::KeyPhaseOne,
      conn.clientConnectionId.value_or(getTestConnectionId()),
      getNextPacketNum(conn, PacketNumberSpace::AppData));

  RegularQuicPacketBuilder builder1(
      conn.udpSendPacketLen,
      std::move(shortHeader1),
      conn.ackStates.appDataAckState.largestAckedByPeer.value_or(0));
  RegularQuicPacketBuilder builder2(
      conn.udpSendPacketLen,
      std::move(shortHeader2),
      conn.ackStates.appDataAckState.largestAckedByPeer.value_or(0));

  DatagramFrame frame1(inputDataLength1, std::move(inputData1));
  DatagramFrame frame2(inputDataLength2, std::move(inputData2));
  writeFrame(frame1, builder1);
  writeFrame(frame2, builder2);

  NiceMock<MockQuicStats> quicStats;
  conn.statsCallback = &quicStats;

  EXPECT_CALL(quicStats, onShortHeaderPadding(_)).Times(1);
  auto result1 = scheduler.scheduleFramesForPacket(
      std::move(builder1), conn.udpSendPacketLen);
  EXPECT_CALL(quicStats, onShortHeaderPadding(_)).Times(1);
  auto result2 = scheduler.scheduleFramesForPacket(
      std::move(builder2), conn.udpSendPacketLen);

  auto headerLength1 = result1.packet->header->computeChainDataLength();
  auto bodyLength1 = result1.packet->body->computeChainDataLength();
  auto packetLength1 = headerLength1 + bodyLength1;
  auto expectedPadding1 =
      (conn.udpSendPacketLen - (inputDataLength1 + headerLength1)) %
      paddingModulo;

  auto headerLength2 = result2.packet->header->computeChainDataLength();
  auto bodyLength2 = result2.packet->body->computeChainDataLength();
  auto packetLength2 = headerLength2 + bodyLength2;
  auto expectedPadding2 =
      (conn.udpSendPacketLen - (inputDataLength2 + headerLength2)) %
      paddingModulo;

  EXPECT_EQ(packetLength1, headerLength1 + inputDataLength1 + expectedPadding1);
  EXPECT_EQ(packetLength2, headerLength2 + inputDataLength2 + expectedPadding2);
  // ensure two similar size input data get padded up to same length
  EXPECT_EQ(packetLength1, packetLength2);
}

TEST_F(QuicPacketSchedulerTest, ShortHeaderPaddingNearMaxPacketLength) {
  QuicServerConnectionState conn(
      FizzServerQuicHandshakeContext::Builder().build());
  conn.udpSendPacketLen = 1000;
  size_t paddingModulo = 50;
  conn.transportSettings.paddingModulo = paddingModulo;
  // create enough input data to almost fill packet
  size_t inputDataLength = conn.udpSendPacketLen - 20;
  auto inputData = buildRandomInputData(inputDataLength);

  FrameScheduler scheduler = std::move(FrameScheduler::Builder(
                                           conn,
                                           EncryptionLevel::AppData,
                                           PacketNumberSpace::AppData,
                                           "streamScheduler")
                                           .streamFrames())
                                 .build();

  ShortHeader shortHeader(
      ProtectionType::KeyPhaseOne,
      conn.clientConnectionId.value_or(getTestConnectionId()),
      getNextPacketNum(conn, PacketNumberSpace::AppData));

  RegularQuicPacketBuilder builder(
      conn.udpSendPacketLen,
      std::move(shortHeader),
      conn.ackStates.appDataAckState.largestAckedByPeer.value_or(0));

  DatagramFrame frame(inputDataLength, std::move(inputData));
  writeFrame(frame, builder);

  NiceMock<MockQuicStats> quicStats;
  conn.statsCallback = &quicStats;

  EXPECT_CALL(quicStats, onShortHeaderPadding(_)).Times(1);
  auto result = scheduler.scheduleFramesForPacket(
      std::move(builder), conn.udpSendPacketLen);

  auto headerLength = result.packet->header->computeChainDataLength();
  auto bodyLength = result.packet->body->computeChainDataLength();

  auto packetLength = headerLength + bodyLength;

  auto expectedPadding =
      (conn.udpSendPacketLen - (inputDataLength + headerLength)) %
      paddingModulo;

  EXPECT_EQ(packetLength, headerLength + inputDataLength + expectedPadding);
  EXPECT_EQ(packetLength, conn.udpSendPacketLen);
}

TEST_F(QuicPacketSchedulerTest, ShortHeaderPaddingMaxPacketLength) {
  QuicServerConnectionState conn(
      FizzServerQuicHandshakeContext::Builder().build());
  conn.udpSendPacketLen = 1000;
  size_t paddingModulo = 50;
  conn.transportSettings.paddingModulo = paddingModulo;

  FrameScheduler scheduler = std::move(FrameScheduler::Builder(
                                           conn,
                                           EncryptionLevel::AppData,
                                           PacketNumberSpace::AppData,
                                           "streamScheduler")
                                           .streamFrames())
                                 .build();

  ShortHeader shortHeader(
      ProtectionType::KeyPhaseOne,
      conn.clientConnectionId.value_or(getTestConnectionId()),
      getNextPacketNum(conn, PacketNumberSpace::AppData));

  size_t largestAckedPacketNum =
      conn.ackStates.appDataAckState.largestAckedByPeer.value_or(0);
  auto packetNumberEncoding = encodePacketNumber(
      shortHeader.getPacketSequenceNum(), largestAckedPacketNum);
  auto connectionIdSize = shortHeader.getConnectionId().size();

  RegularQuicPacketBuilder builder(
      conn.udpSendPacketLen, std::move(shortHeader), largestAckedPacketNum);

  // create enough input data to fully fill packet
  while (builder.remainingSpaceInPkt() >
         connectionIdSize + packetNumberEncoding.length + 1) {
    writeFrame(PaddingFrame(), builder);
  }

  NiceMock<MockQuicStats> quicStats;
  conn.statsCallback = &quicStats;

  EXPECT_CALL(quicStats, onShortHeaderPadding(_)).Times(1);
  auto result = scheduler.scheduleFramesForPacket(
      std::move(builder), conn.udpSendPacketLen);

  auto headerLength = result.packet->header->computeChainDataLength();
  auto bodyLength = result.packet->body->computeChainDataLength();

  auto packetLength = headerLength + bodyLength;

  EXPECT_EQ(packetLength, conn.udpSendPacketLen);
}

TEST_F(QuicPacketSchedulerTest, ImmediateAckFrameSchedulerOnRequest) {
  QuicClientConnectionState conn(
      FizzClientQuicHandshakeContext::Builder().build());
  conn.pendingEvents.requestImmediateAck = true;
  auto connId = getTestConnectionId();

  LongHeader longHeader(
      LongHeader::Types::Initial,
      getTestConnectionId(1),
      connId,
      getNextPacketNum(conn, PacketNumberSpace::Initial),
      QuicVersion::MVFST);
  increaseNextPacketNum(conn, PacketNumberSpace::Initial);

  RegularQuicPacketBuilder builder(
      conn.udpSendPacketLen,
      std::move(longHeader),
      conn.ackStates.initialAckState->largestAckedByPeer.value_or(0));

  FrameScheduler immediateAckOnlyScheduler =
      std::move(
          FrameScheduler::Builder(
              conn,
              EncryptionLevel::Initial,
              LongHeader::typeToPacketNumberSpace(LongHeader::Types::Initial),
              "ImmediateAckOnlyScheduler")
              .immediateAckFrames())
          .build();

  auto result = immediateAckOnlyScheduler.scheduleFramesForPacket(
      std::move(builder), conn.udpSendPacketLen);
  auto packetLength = result.packet->header->computeChainDataLength() +
      result.packet->body->computeChainDataLength();
  EXPECT_EQ(conn.udpSendPacketLen, packetLength);
}

TEST_F(QuicPacketSchedulerTest, ImmediateAckFrameSchedulerNotRequested) {
  QuicClientConnectionState conn(
      FizzClientQuicHandshakeContext::Builder().build());
  conn.pendingEvents.requestImmediateAck = false;
  auto connId = getTestConnectionId();

  LongHeader longHeader(
      LongHeader::Types::Initial,
      getTestConnectionId(1),
      connId,
      getNextPacketNum(conn, PacketNumberSpace::Initial),
      QuicVersion::MVFST);
  increaseNextPacketNum(conn, PacketNumberSpace::Initial);

  RegularQuicPacketBuilder builder(
      conn.udpSendPacketLen,
      std::move(longHeader),
      conn.ackStates.initialAckState->largestAckedByPeer.value_or(0));

  FrameScheduler immediateAckOnlyScheduler =
      std::move(
          FrameScheduler::Builder(
              conn,
              EncryptionLevel::Initial,
              LongHeader::typeToPacketNumberSpace(LongHeader::Types::Initial),
              "ImmediateAckOnlyScheduler")
              .immediateAckFrames())
          .build();

  auto result = immediateAckOnlyScheduler.scheduleFramesForPacket(
      std::move(builder), conn.udpSendPacketLen);
  auto packetLength = result.packet->header->computeChainDataLength() +
      result.packet->body->computeChainDataLength();
  // The immediate ACK scheduler was not triggered. This packet has no frames
  // and it shouldn't get padded.
  EXPECT_LT(packetLength, conn.udpSendPacketLen);
}

} // namespace test
} // namespace quic
