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
#include <quic/priority/HTTPPriorityQueue.h>
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
      QuicVersion::MVFST);
  RegularQuicWritePacket packet(std::move(header));
  conn.outstandings.packets.emplace_back(
      packet,
      Clock::now(),
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
      QuicVersion::MVFST);
  RegularQuicWritePacket packet(std::move(header));
  conn.outstandings.packets.emplace_back(
      packet,
      Clock::now(),
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
      0,
      0,
      LossState(),
      0,
      OutstandingPacketMetadata::DetailsPerStream());
  increaseNextPacketNum(conn, PacketNumberSpace::AppData);
  return nextPacketNum;
}

using namespace quic::test;

auto createStream(
    QuicClientConnectionState& conn,
    std::optional<HTTPPriorityQueue::Priority> priority = std::nullopt) {
  auto stream = conn.streamManager->createNextBidirectionalStream().value();
  if (priority) {
    stream->priority = *priority;
  }
  return stream->id;
}

RegularQuicPacketBuilder createPacketBuilder(QuicClientConnectionState& conn) {
  auto connId = getTestConnectionId();
  ShortHeader shortHeader(
      ProtectionType::KeyPhaseZero,
      connId,
      getNextPacketNum(conn, PacketNumberSpace::AppData));
  RegularQuicPacketBuilder builder(
      conn.udpSendPacketLen,
      std::move(shortHeader),
      conn.ackStates.appDataAckState.largestAckedByPeer.value_or(0));
  CHECK(!builder.encodePacketHeader().hasError());
  return builder;
}

std::unique_ptr<folly::IOBuf> createLargeBuffer(size_t size) {
  auto largeBuf = folly::IOBuf::createChain(size, 4096);
  auto curBuf = largeBuf.get();
  do {
    curBuf->append(curBuf->capacity());
    curBuf = curBuf->next();
  } while (curBuf != largeBuf.get());
  return largeBuf;
}

WriteStreamFrame writeDataToStream(
    QuicClientConnectionState& conn,
    StreamId streamId,
    const std::string& data) {
  auto stream = conn.streamManager->findStream(streamId);
  auto length = data.size();
  CHECK(stream);
  auto result =
      writeDataToQuicStream(*stream, folly::IOBuf::copyBuffer(data), false);
  CHECK(!result.hasError());
  return {streamId, 0, length, false};
}

// Helper function to write data to a stream
WriteStreamFrame writeDataToStream(
    QuicClientConnectionState& conn,
    StreamId streamId,
    std::unique_ptr<folly::IOBuf> buf) {
  auto stream = conn.streamManager->findStream(streamId);
  auto length = buf->computeChainDataLength();
  auto result = writeDataToQuicStream(*stream, std::move(buf), false);
  CHECK(!result.hasError());
  return {streamId, 0, length, false};
}

std::unique_ptr<MockQuicPacketBuilder> setupMockPacketBuilder() {
  auto builder = std::make_unique<NiceMock<MockQuicPacketBuilder>>();
  EXPECT_CALL(*builder, remainingSpaceInPkt()).WillRepeatedly(Return(4096));
  EXPECT_CALL(*builder, appendFrame(_))
      .WillRepeatedly(Invoke([builder = builder.get()](auto f) {
        builder->frames_.push_back(f);
      }));
  return builder;
}

std::unique_ptr<MockQuicPacketBuilder> setupMockPacketBuilder(
    std::vector<size_t> expectedRemaining) {
  auto builder = std::make_unique<NiceMock<MockQuicPacketBuilder>>();
  builder->setExpectedSpaceRemaining(std::move(expectedRemaining));
  return builder;
}

void verifyStreamFrames(
    MockQuicPacketBuilder& builder,
    const std::vector<WriteStreamFrame>& expectedFrames) {
  ASSERT_EQ(builder.frames_.size(), expectedFrames.size());
  for (size_t i = 0; i < expectedFrames.size(); ++i) {
    ASSERT_TRUE(builder.frames_[i].asWriteStreamFrame());
    EXPECT_EQ(*builder.frames_[i].asWriteStreamFrame(), expectedFrames[i]);
  }
  if (expectedFrames.size() == builder.frames_.size()) {
    builder.frames_.clear();
  } else {
    builder.frames_.erase(
        builder.frames_.begin(),
        builder.frames_.begin() + expectedFrames.size());
  }
}

void verifyStreamFrames(
    MockQuicPacketBuilder& builder,
    const std::vector<StreamId>& expectedIds) {
  ASSERT_EQ(builder.frames_.size(), expectedIds.size());
  for (size_t i = 0; i < expectedIds.size(); ++i) {
    ASSERT_TRUE(builder.frames_[i].asWriteStreamFrame());
    EXPECT_EQ(
        builder.frames_[i].asWriteStreamFrame()->streamId, expectedIds[i]);
  }
  if (expectedIds.size() == builder.frames_.size()) {
    builder.frames_.clear();
  } else {
    builder.frames_.erase(
        builder.frames_.begin(), builder.frames_.begin() + expectedIds.size());
  }
}

} // namespace

namespace quic::test {

class QuicPacketSchedulerTestBase {
 public:
  QuicVersion version{QuicVersion::MVFST};

  std::unique_ptr<QuicClientConnectionState> createConn(
      uint32_t maxStreams,
      uint64_t maxOffset,
      uint64_t initialMaxOffset,
      bool useNewPriorityQueue = false) {
    auto conn = std::make_unique<QuicClientConnectionState>(
        FizzClientQuicHandshakeContext::Builder().build());
    transportSettings.useNewPriorityQueue = useNewPriorityQueue;
    auto result =
        conn->streamManager->refreshTransportSettings(transportSettings);
    CHECK(!result.hasError()) << "Failed to refresh transport settings";
    result = conn->streamManager->setMaxLocalBidirectionalStreams(maxStreams);
    CHECK(!result.hasError())
        << "Failed to set max local bidirectional streams";
    conn->flowControlState.peerAdvertisedMaxOffset = maxOffset;
    conn->flowControlState.peerAdvertisedInitialMaxStreamOffsetBidiRemote =
        initialMaxOffset;
    return conn;
  }

  TransportSettings transportSettings;
};

class QuicPacketSchedulerTest : public QuicPacketSchedulerTestBase,
                                public testing::TestWithParam<bool> {
 public:
  StreamId nextScheduledStreamID(QuicConnectionStateBase& conn) {
    auto oldWriteQueue = conn.streamManager->oldWriteQueue();
    CHECK(oldWriteQueue || GetParam()) << "why old queue when using new";
    if (oldWriteQueue) {
      return oldWriteQueue->getNextScheduledStream();
    }
    return conn.streamManager->writeQueue().peekNextScheduledID().asStreamID();
  }
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
  ASSERT_FALSE(result.hasError());
  auto packetLength = result.value().packet->header.computeChainDataLength() +
      result.value().packet->body.computeChainDataLength();
  EXPECT_EQ(conn.udpSendPacketLen, packetLength);
}

TEST_P(QuicPacketSchedulerTest, PaddingInitialPureAcks) {
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
  ASSERT_FALSE(result.hasError());
  auto packetLength = result.value().packet->header.computeChainDataLength() +
      result.value().packet->body.computeChainDataLength();
  EXPECT_EQ(conn.udpSendPacketLen, packetLength);
}

TEST_P(QuicPacketSchedulerTest, InitialPaddingDoesNotUseWrapper) {
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
  ASSERT_FALSE(result.hasError());
  auto packetLength = result.value().packet->header.computeChainDataLength() +
      result.value().packet->body.computeChainDataLength();
  EXPECT_EQ(conn.udpSendPacketLen, packetLength);
}

TEST_P(QuicPacketSchedulerTest, CryptoServerInitialPadded) {
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
  ASSERT_FALSE(result.hasError());
  auto packetLength = result.value().packet->header.computeChainDataLength() +
      result.value().packet->body.computeChainDataLength();
  EXPECT_EQ(conn.udpSendPacketLen, packetLength);
}

TEST_P(QuicPacketSchedulerTest, PadTwoInitialPackets) {
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
  ASSERT_FALSE(result.hasError());
  auto packetLength = result.value().packet->header.computeChainDataLength() +
      result.value().packet->body.computeChainDataLength();
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
  ASSERT_FALSE(result2.hasError());
  packetLength = result2.value().packet->header.computeChainDataLength() +
      result2.value().packet->body.computeChainDataLength();
  EXPECT_EQ(conn.udpSendPacketLen, packetLength);
}

TEST_P(QuicPacketSchedulerTest, CryptoPaddingRetransmissionClientInitial) {
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
  Buf helloBuf = folly::IOBuf::copyBuffer("chlo");
  ChainedByteRangeHead clientHelloData(helloBuf);
  conn.cryptoState->initialStream.lossBuffer.push_back(
      WriteStreamBuffer{std::move(clientHelloData), 0, false});
  auto result = std::move(scheduler).scheduleFramesForPacket(
      std::move(builder), conn.udpSendPacketLen);
  ASSERT_FALSE(result.hasError());
  auto packetLength = result.value().packet->header.computeChainDataLength() +
      result.value().packet->body.computeChainDataLength();
  EXPECT_EQ(conn.udpSendPacketLen, packetLength);
}

TEST_P(QuicPacketSchedulerTest, CryptoSchedulerOnlySingleLossFits) {
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
  ASSERT_FALSE(builder.encodePacketHeader().hasError());
  PacketBuilderWrapper builderWrapper(builder, 13);
  CryptoStreamScheduler scheduler(
      conn, *getCryptoStream(*conn.cryptoState, EncryptionLevel::Handshake));

  Buf helloBuf = folly::IOBuf::copyBuffer("shlo");
  Buf certBuf = folly::IOBuf::copyBuffer(
      "certificatethatisverylongseriouslythisisextremelylongandcannotfitintoapacket");

  conn.cryptoState->handshakeStream.lossBuffer.emplace_back(
      ChainedByteRangeHead(helloBuf), 0, false);
  conn.cryptoState->handshakeStream.lossBuffer.emplace_back(
      ChainedByteRangeHead(certBuf), 7, false);
  EXPECT_TRUE(scheduler.writeCryptoData(builderWrapper));
}

TEST_P(QuicPacketSchedulerTest, CryptoWritePartialLossBuffer) {
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
  Buf lossBuffer =
      folly::IOBuf::copyBuffer("return the special duration value max");
  conn.cryptoState->initialStream.lossBuffer.emplace_back(
      ChainedByteRangeHead(lossBuffer), 0, false);
  auto result = cryptoOnlyScheduler.scheduleFramesForPacket(
      std::move(builder), conn.udpSendPacketLen);
  ASSERT_FALSE(result.hasError());
  auto packetLength = result->packet->header.computeChainDataLength() +
      result->packet->body.computeChainDataLength();
  EXPECT_LE(packetLength, 25);
  EXPECT_TRUE(result->packet->packet.frames[0].asWriteCryptoFrame() != nullptr);
  EXPECT_FALSE(conn.cryptoState->initialStream.lossBuffer.empty());
}

TEST_P(QuicPacketSchedulerTest, StreamFrameSchedulerExists) {
  QuicServerConnectionState conn(
      FizzServerQuicHandshakeContext::Builder().build());
  ASSERT_FALSE(
      conn.streamManager->setMaxLocalBidirectionalStreams(10).hasError());
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
  ASSERT_FALSE(builder.encodePacketHeader().hasError());
  auto originalSpace = builder.remainingSpaceInPkt();
  conn.streamManager->queueWindowUpdate(stream->id);
  ASSERT_FALSE(scheduler.writeWindowUpdates(builder).hasError());
  EXPECT_LT(builder.remainingSpaceInPkt(), originalSpace);
}

TEST_P(QuicPacketSchedulerTest, StreamFrameNoSpace) {
  QuicServerConnectionState conn(
      FizzServerQuicHandshakeContext::Builder().build());
  ASSERT_FALSE(
      conn.streamManager->setMaxLocalBidirectionalStreams(10).hasError());
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
  ASSERT_FALSE(builder.encodePacketHeader().hasError());
  PacketBuilderWrapper builderWrapper(builder, 2);
  auto originalSpace = builder.remainingSpaceInPkt();
  conn.streamManager->queueWindowUpdate(stream->id);
  ASSERT_FALSE(scheduler.writeWindowUpdates(builderWrapper).hasError());
  EXPECT_EQ(builder.remainingSpaceInPkt(), originalSpace);
}

TEST_P(QuicPacketSchedulerTest, StreamFrameSchedulerStreamNotExists) {
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
  ASSERT_FALSE(builder.encodePacketHeader().hasError());
  auto originalSpace = builder.remainingSpaceInPkt();
  conn.streamManager->queueWindowUpdate(nonExistentStream);
  ASSERT_FALSE(scheduler.writeWindowUpdates(builder).hasError());
  EXPECT_EQ(builder.remainingSpaceInPkt(), originalSpace);
}

TEST_P(QuicPacketSchedulerTest, NoCloningForDSR) {
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
  ASSERT_FALSE(result.hasError());
  EXPECT_FALSE(result->clonedPacketIdentifier.hasValue());
  EXPECT_FALSE(result->packet.hasValue());
}

TEST_P(QuicPacketSchedulerTest, CloningSchedulerTest) {
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
  ASSERT_FALSE(result.hasError());
  EXPECT_TRUE(
      result->clonedPacketIdentifier.has_value() && result->packet.has_value());
  EXPECT_EQ(packetNum, result->clonedPacketIdentifier->packetNumber);
}

TEST_P(QuicPacketSchedulerTest, WriteOnlyOutstandingPacketsTest) {
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
  ASSERT_FALSE(writeFrame(connCloseFrame, regularBuilder).hasError());
  ASSERT_FALSE(
      writeFrame(QuicSimpleFrame(maxStreamFrame), regularBuilder).hasError());
  ASSERT_FALSE(writeFrame(pingFrame, regularBuilder).hasError());
  ASSERT_FALSE(writeAckFrame(ackMeta, regularBuilder).hasError());

  auto result = cloningScheduler.scheduleFramesForPacket(
      std::move(regularBuilder), kDefaultUDPSendPacketLen);
  ASSERT_FALSE(result.hasError());
  EXPECT_TRUE(
      result->clonedPacketIdentifier.hasValue() && result->packet.hasValue());
  EXPECT_EQ(packetNum, result->clonedPacketIdentifier->packetNumber);
  // written packet should not have any frame in the builder
  auto& writtenPacket = *result->packet;
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

TEST_P(QuicPacketSchedulerTest, DoNotCloneProcessedClonedPacket) {
  QuicClientConnectionState conn(
      FizzClientQuicHandshakeContext::Builder().build());
  FrameScheduler noopScheduler("frame", conn);
  CloningScheduler cloningScheduler(noopScheduler, conn, "CopyCat", 0);
  // Add two outstanding packets, but then mark the first one processed by
  // adding a ClonedPacketIdentifier that's missing from the
  // outstandings.clonedPacketIdentifiers set
  addOutstandingPacket(conn);
  conn.outstandings.packets.back().maybeClonedPacketIdentifier =
      ClonedPacketIdentifier(PacketNumberSpace::AppData, 1);
  // There needs to have retransmittable frame for the rebuilder to work
  conn.outstandings.packets.back().packet.frames.push_back(
      MaxDataFrame(conn.flowControlState.advertisedMaxOffset));
  PacketNum expected = addOutstandingPacket(conn);
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
  ASSERT_FALSE(result.hasError());
  EXPECT_TRUE(
      result->clonedPacketIdentifier.has_value() && result->packet.has_value());
  EXPECT_EQ(expected, result->clonedPacketIdentifier->packetNumber);
}

class CloneAllPacketsWithCryptoFrameTest
    : public QuicPacketSchedulerTestBase,
      public TestWithParam<std::tuple<bool, bool>> {};

TEST_P(
    CloneAllPacketsWithCryptoFrameTest,
    TestCloneAllPacketsWithCryptoFrameTrueFalse) {
  QuicClientConnectionState conn(
      FizzClientQuicHandshakeContext::Builder().build());
  auto testParams = GetParam();
  conn.transportSettings.cloneAllPacketsWithCryptoFrame =
      std::get<0>(testParams);
  conn.transportSettings.cloneCryptoPacketsAtMostOnce = std::get<1>(testParams);
  FrameScheduler noopScheduler("frame", conn);
  CloningScheduler cloningScheduler(noopScheduler, conn, "cryptoClone", 0);

  PacketNum firstPacketNum = addInitialOutstandingPacket(conn);
  {
    conn.outstandings.packets.back().packet.frames.push_back(
        WriteCryptoFrame(0, 1));
    ClonedPacketIdentifier clonedPacketIdentifier(
        PacketNumberSpace::Initial, firstPacketNum);
    conn.outstandings.packets.back().maybeClonedPacketIdentifier =
        clonedPacketIdentifier;
    // It is not processed yet
    conn.outstandings.clonedPacketIdentifiers.insert(clonedPacketIdentifier);
    // There needs to have retransmittable frame for the rebuilder to work
    conn.outstandings.packets.back().packet.frames.push_back(
        MaxDataFrame(conn.flowControlState.advertisedMaxOffset));
  }

  PacketNum secondPacketNum = addInitialOutstandingPacket(conn);
  {
    conn.outstandings.packets.back().packet.frames.push_back(
        WriteCryptoFrame(0, 1));
    ClonedPacketIdentifier clonedPacketIdentifier(
        PacketNumberSpace::Initial, secondPacketNum);
    conn.outstandings.packets.back().maybeClonedPacketIdentifier =
        clonedPacketIdentifier;
    // It is not processed yet
    conn.outstandings.clonedPacketIdentifiers.insert(clonedPacketIdentifier);
    // There needs to have retransmittable frame for the rebuilder to work
    conn.outstandings.packets.back().packet.frames.push_back(
        MaxDataFrame(conn.flowControlState.advertisedMaxOffset));
  }

  // Add a third outstanding packet, which is a re-clone of the first packet
  {
    addInitialOutstandingPacket(conn);
    conn.outstandings.packets.back().packet.frames.push_back(
        WriteCryptoFrame(0, 1));
    ClonedPacketIdentifier clonedPacketIdentifier(
        PacketNumberSpace::Initial, firstPacketNum);
    conn.outstandings.packets.back().maybeClonedPacketIdentifier =
        clonedPacketIdentifier;
    // It is not processed yet
    conn.outstandings.clonedPacketIdentifiers.insert(clonedPacketIdentifier);
    // There needs to have retransmittable frame for the rebuilder to work
    conn.outstandings.packets.back().packet.frames.push_back(
        MaxDataFrame(conn.flowControlState.advertisedMaxOffset));
  }

  // Schedule a fourth packet
  std::vector<uint8_t> zeroConnIdData(quic::kDefaultConnectionIdSize, 0);
  ConnectionId srcConnId(zeroConnIdData);
  LongHeader header(
      LongHeader::Types::Initial,
      srcConnId,
      conn.clientConnectionId.value_or(getTestConnectionId()),
      getNextPacketNum(conn, PacketNumberSpace::Initial),
      QuicVersion::MVFST);
  RegularQuicPacketBuilder builder(
      conn.udpSendPacketLen,
      std::move(header),
      conn.ackStates.initialAckState->largestAckedByPeer.value_or(0));
  auto result = cloningScheduler.scheduleFramesForPacket(
      std::move(builder), kDefaultUDPSendPacketLen);
  ASSERT_FALSE(result.hasError());
  if (conn.transportSettings.cloneAllPacketsWithCryptoFrame &&
      conn.transportSettings.cloneCryptoPacketsAtMostOnce) {
    // First and second packets already cloned, skip all and schedule no packet
    EXPECT_FALSE(result->clonedPacketIdentifier.has_value());
    EXPECT_FALSE(result->packet.has_value());
  } else {
    EXPECT_TRUE(
        result->clonedPacketIdentifier.has_value() &&
        result->packet.has_value());
    EXPECT_EQ(
        conn.transportSettings.cloneAllPacketsWithCryptoFrame ? secondPacketNum
                                                              : firstPacketNum,
        result->clonedPacketIdentifier->packetNumber);
  }
}

INSTANTIATE_TEST_SUITE_P(
    CloneAllPacketsWithCryptoFrameTest,
    CloneAllPacketsWithCryptoFrameTest,
    Combine(Bool(), Bool()));

TEST_P(QuicPacketSchedulerTest, DoNotSkipUnclonedCryptoPacket) {
  QuicClientConnectionState conn(
      FizzClientQuicHandshakeContext::Builder().build());
  conn.transportSettings.cloneAllPacketsWithCryptoFrame = true;
  FrameScheduler noopScheduler("frame", conn);
  CloningScheduler cloningScheduler(noopScheduler, conn, "cryptoClone", 0);

  // First packet has a crypto frame
  PacketNum firstPacketNum = addInitialOutstandingPacket(conn);
  conn.outstandings.packets.back().packet.frames.push_back(
      WriteCryptoFrame(0, 1));
  // There needs to have retransmittable frame for the rebuilder to work
  conn.outstandings.packets.back().packet.frames.push_back(
      MaxDataFrame(conn.flowControlState.advertisedMaxOffset));

  addInitialOutstandingPacket(conn);
  // There needs to have retransmittable frame for the rebuilder to work
  conn.outstandings.packets.back().packet.frames.push_back(
      MaxDataFrame(conn.flowControlState.advertisedMaxOffset));

  std::vector<uint8_t> zeroConnIdData(quic::kDefaultConnectionIdSize, 0);
  ConnectionId srcConnId(zeroConnIdData);
  LongHeader header(
      LongHeader::Types::Initial,
      srcConnId,
      conn.clientConnectionId.value_or(getTestConnectionId()),
      getNextPacketNum(conn, PacketNumberSpace::Initial),
      QuicVersion::MVFST);
  RegularQuicPacketBuilder builder(
      conn.udpSendPacketLen,
      std::move(header),
      conn.ackStates.initialAckState->largestAckedByPeer.value_or(0));
  auto result = cloningScheduler.scheduleFramesForPacket(
      std::move(builder), kDefaultUDPSendPacketLen);
  ASSERT_FALSE(result.hasError());
  EXPECT_TRUE(
      result->clonedPacketIdentifier.has_value() && result->packet.has_value());
  EXPECT_EQ(firstPacketNum, result->clonedPacketIdentifier->packetNumber);
}

TEST_P(QuicPacketSchedulerTest, CloneSchedulerHasHandshakeData) {
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
TEST_P(QuicPacketSchedulerTest, CloneSchedulerHasHandshakeDataAndAcks) {
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
  Buf cryptoBuf = folly::IOBuf::copyBuffer("test");
  ChainedByteRangeHead cryptoRch(cryptoBuf);
  getCryptoStream(*conn.cryptoState, EncryptionLevel::Handshake)
      ->retransmissionBuffer.emplace(
          0,
          std::make_unique<WriteStreamBuffer>(std::move(cryptoRch), 0, false));
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
      QuicVersion::MVFST);
  RegularQuicPacketBuilder builder(
      conn.udpSendPacketLen,
      std::move(header),
      conn.ackStates.appDataAckState.largestAckedByPeer.value_or(0));

  // Clone the packet.
  auto result = cloningScheduler.scheduleFramesForPacket(
      std::move(builder), kDefaultUDPSendPacketLen);
  ASSERT_FALSE(result.hasError());
  EXPECT_TRUE(result->clonedPacketIdentifier.has_value());
  EXPECT_TRUE(result->packet.has_value());

  // Cloned packet has to have crypto data and no acks.
  bool hasAckFrame = false;
  bool hasCryptoFrame = false;
  for (auto iter = result->packet->packet.frames.cbegin();
       iter != result->packet->packet.frames.cend();
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

TEST_P(QuicPacketSchedulerTest, CloneSchedulerHasInitialData) {
  QuicClientConnectionState conn(
      FizzClientQuicHandshakeContext::Builder().build());
  FrameScheduler noopScheduler("frame", conn);
  CloningScheduler cloningScheduler(noopScheduler, conn, "CopyCat", 0);
  EXPECT_FALSE(cloningScheduler.hasData());

  addInitialOutstandingPacket(conn);
  EXPECT_TRUE(cloningScheduler.hasData());
}

TEST_P(QuicPacketSchedulerTest, CloneSchedulerHasAppDataData) {
  QuicClientConnectionState conn(
      FizzClientQuicHandshakeContext::Builder().build());
  FrameScheduler noopScheduler("frame", conn);
  CloningScheduler cloningScheduler(noopScheduler, conn, "CopyCat", 0);
  EXPECT_FALSE(cloningScheduler.hasData());

  addOutstandingPacket(conn);
  EXPECT_TRUE(cloningScheduler.hasData());
}

TEST_P(QuicPacketSchedulerTest, DoNotCloneHandshake) {
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
  ASSERT_FALSE(result.hasError());
  EXPECT_TRUE(
      result->clonedPacketIdentifier.has_value() && result->packet.has_value());
  EXPECT_EQ(expected, result->clonedPacketIdentifier->packetNumber);
}

TEST_P(QuicPacketSchedulerTest, CloneSchedulerUseNormalSchedulerFirst) {
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
                folly::IOBuf(
                    folly::IOBuf::CopyBufferOp::COPY_BUFFER,
                    "if you are the dealer"),
                folly::IOBuf(
                    folly::IOBuf::CopyBufferOp::COPY_BUFFER,
                    "I'm out of the game"));
            return SchedulingResult(none, std::move(builtPacket));
          }));
  RegularQuicPacketBuilder builder(
      conn.udpSendPacketLen,
      std::move(header),
      conn.ackStates.appDataAckState.largestAckedByPeer.value_or(0));
  auto result = cloningScheduler.scheduleFramesForPacket(
      std::move(builder), kDefaultUDPSendPacketLen);
  ASSERT_FALSE(result.hasError());
  EXPECT_EQ(none, result->clonedPacketIdentifier);
  EXPECT_EQ(result->packet->packet.header.getHeaderForm(), HeaderForm::Short);
  ShortHeader& shortHeader = *result->packet->packet.header.asShort();
  EXPECT_EQ(ProtectionType::KeyPhaseOne, shortHeader.getProtectionType());
  EXPECT_EQ(
      conn.ackStates.appDataAckState.nextPacketNum,
      shortHeader.getPacketSequenceNum());
  EXPECT_EQ(1, result->packet->packet.frames.size());
  MaxDataFrame* maxDataFrame =
      result->packet->packet.frames.front().asMaxDataFrame();
  ASSERT_NE(maxDataFrame, nullptr);
  EXPECT_EQ(2832, maxDataFrame->maximumData);
  EXPECT_TRUE(folly::IOBufEqualTo{}(
      *folly::IOBuf::copyBuffer("if you are the dealer"),
      result->packet->header));
  EXPECT_TRUE(folly::IOBufEqualTo{}(
      *folly::IOBuf::copyBuffer("I'm out of the game"), result->packet->body));
}

TEST_P(QuicPacketSchedulerTest, CloneWillGenerateNewWindowUpdate) {
  QuicClientConnectionState conn(
      FizzClientQuicHandshakeContext::Builder().build());
  auto result = conn.streamManager->setMaxLocalBidirectionalStreams(10);
  ASSERT_FALSE(result.hasError());
  auto stream = conn.streamManager->createNextBidirectionalStream().value();
  FrameScheduler noopScheduler("frame", conn);
  CloningScheduler cloningScheduler(noopScheduler, conn, "GiantsShoulder", 0);
  ClonedPacketIdentifier expectedClonedPacketIdentifier(
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
  ASSERT_FALSE(packetResult.hasError());
  EXPECT_EQ(
      expectedClonedPacketIdentifier, *packetResult->clonedPacketIdentifier);
  int32_t verifyConnWindowUpdate = 1, verifyStreamWindowUpdate = 1;
  for (const auto& frame : packetResult->packet->packet.frames) {
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
  EXPECT_GE(packetResult->packet->packet.frames.size(), 2);
  uint32_t streamWindowUpdateCounter = 0;
  uint32_t connWindowUpdateCounter = 0;
  for (auto& frame : packetResult->packet->packet.frames) {
    auto streamFlowControl = frame.asMaxStreamDataFrame();
    if (!streamFlowControl) {
      continue;
    }
    streamWindowUpdateCounter++;
    EXPECT_EQ(1700, streamFlowControl->maximumData);
  }
  for (auto& frame : packetResult->packet->packet.frames) {
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

TEST_P(QuicPacketSchedulerTest, CloningSchedulerWithInplaceBuilder) {
  QuicClientConnectionState conn(
      FizzClientQuicHandshakeContext::Builder().build());
  conn.transportSettings.dataPathType = DataPathType::ContinuousMemory;
  BufAccessor bufAccessor(2000);
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
  ASSERT_FALSE(result.hasError());
  EXPECT_TRUE(
      result.value().clonedPacketIdentifier.has_value() &&
      result.value().packet.has_value());
  EXPECT_EQ(packetNum, result.value().clonedPacketIdentifier->packetNumber);

  // Something was written into the buffer:
  EXPECT_TRUE(bufAccessor.ownsBuffer());
  buf = bufAccessor.obtain();
  EXPECT_GT(buf->length(), 10);
}

TEST_P(QuicPacketSchedulerTest, CloningSchedulerWithInplaceBuilderFullPacket) {
  QuicClientConnectionState conn(
      FizzClientQuicHandshakeContext::Builder().build());
  auto streamResult = conn.streamManager->setMaxLocalBidirectionalStreams(10);
  ASSERT_FALSE(streamResult.hasError());
  conn.flowControlState.peerAdvertisedMaxOffset = 100000;
  conn.flowControlState.peerAdvertisedInitialMaxStreamOffsetBidiRemote = 100000;
  conn.transportSettings.dataPathType = DataPathType::ContinuousMemory;
  BufAccessor bufAccessor(2000);
  auto buf = bufAccessor.obtain();
  EXPECT_EQ(buf->length(), 0);
  bufAccessor.release(std::move(buf));
  conn.bufAccessor = &bufAccessor;
  auto stream = *conn.streamManager->createNextBidirectionalStream();
  auto inBuf = buildRandomInputData(conn.udpSendPacketLen * 10);
  auto writeResult = writeDataToQuicStream(*stream, inBuf->clone(), false);
  ASSERT_FALSE(writeResult.hasError());

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
  ASSERT_FALSE(result.hasError());
  auto bufferLength = result->packet->header.computeChainDataLength() +
      result->packet->body.computeChainDataLength();
  EXPECT_EQ(conn.udpSendPacketLen, bufferLength);
  auto updateResult = updateConnection(
      conn,
      none,
      result->packet->packet,
      Clock::now(),
      bufferLength,
      0,
      false /* isDSRPacket */);
  ASSERT_FALSE(updateResult.hasError());
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
  ASSERT_FALSE(cloneResult.hasError());
  EXPECT_TRUE(
      cloneResult->clonedPacketIdentifier.has_value() &&
      cloneResult->packet.has_value());
  EXPECT_EQ(packetNum, cloneResult->clonedPacketIdentifier->packetNumber);

  // Something was written into the buffer:
  EXPECT_TRUE(bufAccessor.ownsBuffer());
  buf = bufAccessor.obtain();
  EXPECT_EQ(buf->length(), conn.udpSendPacketLen);
}

TEST_P(QuicPacketSchedulerTest, CloneLargerThanOriginalPacket) {
  QuicClientConnectionState conn(
      FizzClientQuicHandshakeContext::Builder().build());
  conn.udpSendPacketLen = 1000;
  auto result = conn.streamManager->setMaxLocalBidirectionalStreams(10);
  ASSERT_FALSE(result.hasError());
  conn.flowControlState.peerAdvertisedMaxOffset = 100000;
  conn.flowControlState.peerAdvertisedInitialMaxStreamOffsetBidiRemote = 100000;
  auto stream = conn.streamManager->createNextBidirectionalStream().value();
  auto inputData = buildRandomInputData(conn.udpSendPacketLen * 10);
  auto writeResult = writeDataToQuicStream(*stream, inputData->clone(), false);
  ASSERT_FALSE(writeResult.hasError());
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
  ASSERT_FALSE(packetResult.hasError());
  auto encodedSize = packetResult->packet->body.computeChainDataLength() +
      packetResult->packet->header.computeChainDataLength() + cipherOverhead;
  EXPECT_EQ(encodedSize, conn.udpSendPacketLen);
  auto updateResult = updateConnection(
      conn,
      none,
      packetResult->packet->packet,
      Clock::now(),
      encodedSize,
      0,
      false /* isDSRPacket */);
  ASSERT_FALSE(updateResult.hasError());

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
  ASSERT_FALSE(cloneResult.hasError());
  EXPECT_FALSE(cloneResult->packet.hasValue());
  EXPECT_FALSE(cloneResult->clonedPacketIdentifier.hasValue());
}

class AckSchedulingTest : public TestWithParam<PacketNumberSpace> {};

TEST_P(QuicPacketSchedulerTest, AckStateHasAcksToSchedule) {
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

  conn.ackStates.handshakeAckState->largestAckScheduled = none;
  EXPECT_TRUE(hasAcksToSchedule(*conn.ackStates.handshakeAckState));
}

TEST_P(QuicPacketSchedulerTest, AckSchedulerHasAcksToSchedule) {
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

  conn.ackStates.handshakeAckState->largestAckScheduled = none;
  EXPECT_TRUE(handshakeAckScheduler.hasPendingAcks());
}

TEST_P(QuicPacketSchedulerTest, LargestAckToSend) {
  QuicClientConnectionState conn(
      FizzClientQuicHandshakeContext::Builder().build());
  EXPECT_EQ(none, largestAckToSend(*conn.ackStates.initialAckState));
  EXPECT_EQ(none, largestAckToSend(*conn.ackStates.handshakeAckState));
  EXPECT_EQ(none, largestAckToSend(conn.ackStates.appDataAckState));

  conn.ackStates.initialAckState->acks.insert(0, 50);
  conn.ackStates.handshakeAckState->acks.insert(0, 50);
  conn.ackStates.handshakeAckState->acks.insert(75, 150);

  EXPECT_EQ(50, *largestAckToSend(*conn.ackStates.initialAckState));
  EXPECT_EQ(150, *largestAckToSend(*conn.ackStates.handshakeAckState));
  EXPECT_EQ(none, largestAckToSend(conn.ackStates.appDataAckState));
}

TEST_P(QuicPacketSchedulerTest, NeedsToSendAckWithoutAcksAvailable) {
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

  conn.ackStates.handshakeAckState->largestAckScheduled = none;
  EXPECT_TRUE(handshakeAckScheduler.hasPendingAcks());
}

TEST_P(QuicPacketSchedulerTest, StreamFrameSchedulerAllFit) {
  auto connPtr = createConn(10, 100000, 100000, GetParam());
  auto& conn = *connPtr;
  StreamFrameScheduler scheduler(conn);

  auto stream1 = createStream(conn);
  auto stream2 = createStream(conn);
  auto stream3 = createStream(conn);

  auto f1 = writeDataToStream(conn, stream1, "some data");
  auto f2 = writeDataToStream(conn, stream2, "some data");
  auto f3 = writeDataToStream(conn, stream3, "some data");

  auto builder = setupMockPacketBuilder();
  scheduler.writeStreams(*builder);
  verifyStreamFrames(*builder, {f1, f2, f3});
  if (GetParam()) {
    EXPECT_TRUE(conn.streamManager->writeQueue().empty());
  } else {
    EXPECT_EQ(nextScheduledStreamID(conn), 0);
  }
}

TEST_P(QuicPacketSchedulerTest, StreamFrameSchedulerRoundRobin) {
  auto connPtr = createConn(10, 100000, 100000, GetParam());
  auto& conn = *connPtr;
  StreamFrameScheduler scheduler(conn);

  auto stream1 = createStream(conn);
  auto stream2 = createStream(conn);
  auto stream3 = createStream(conn);

  auto largeBuf = createLargeBuffer(conn.udpSendPacketLen * 2);
  auto f1 = writeDataToStream(conn, stream1, std::move(largeBuf));
  auto f2 = writeDataToStream(conn, stream2, "some data");
  auto f3 = writeDataToStream(conn, stream3, "some data");

  // write a normal size packet from stream1
  auto builder = createPacketBuilder(conn);
  scheduler.writeStreams(builder);

  // Should write frames for stream2, stream3, followed by stream1 again.
  auto builder2 = setupMockPacketBuilder();
  scheduler.writeStreams(*builder2);
  verifyStreamFrames(*builder2, {f2, f3, f1});
}

TEST_P(QuicPacketSchedulerTest, StreamFrameSchedulerRoundRobinNextsPer) {
  auto connPtr = createConn(10, 100000, 100000, GetParam());
  auto& conn = *connPtr;
  conn.streamManager->setWriteQueueMaxNextsPerStream(2);
  StreamFrameScheduler scheduler(conn);

  auto stream1 = createStream(conn);
  auto stream2 = createStream(conn);
  auto stream3 = createStream(conn);

  auto largeBuf = createLargeBuffer(conn.udpSendPacketLen * 2);
  auto f1 = writeDataToStream(conn, stream1, std::move(largeBuf));
  auto f2 = writeDataToStream(conn, stream2, "some data");
  auto f3 = writeDataToStream(conn, stream3, "some data");

  // Should write frames for stream1, stream1, stream2, stream3, followed >
  // stream1 again.
  auto builder2 =
      setupMockPacketBuilder({1500, 0, 1400, 0, 1300, 1100, 1000, 0});
  scheduler.writeStreams(*builder2);
  builder2->advanceRemaining();
  ASSERT_EQ(nextScheduledStreamID(conn), stream1);
  ASSERT_EQ(builder2->frames_.size(), 1);
  scheduler.writeStreams(*builder2);
  ASSERT_EQ(builder2->frames_.size(), 2);
  ASSERT_EQ(nextScheduledStreamID(conn), stream2);
  builder2->advanceRemaining();
  scheduler.writeStreams(*builder2);
  scheduler.writeStreams(*builder2);
  verifyStreamFrames(*builder2, {stream1, stream1, stream2, stream3, stream1});
}

TEST_P(QuicPacketSchedulerTest, StreamFrameSchedulerRoundRobinStreamPerPacket) {
  auto connPtr = createConn(10, 100000, 100000, GetParam());
  auto& conn = *connPtr;
  conn.transportSettings.streamFramePerPacket = true;
  StreamFrameScheduler scheduler(conn);

  auto stream1 = createStream(conn);
  auto stream2 = createStream(conn);
  auto stream3 = createStream(conn);

  auto largeBuf = createLargeBuffer(conn.udpSendPacketLen * 2);
  auto f1 = writeDataToStream(conn, stream1, std::move(largeBuf));
  auto f2 = writeDataToStream(conn, stream2, "some data");
  auto f3 = writeDataToStream(conn, stream3, "some data");

  // Write a normal size packet from stream1
  auto builder = createPacketBuilder(conn);
  scheduler.writeStreams(builder);
  EXPECT_EQ(nextScheduledStreamID(conn), stream2);

  // Should write frames for stream2, stream3, followed by stream1 again.
  auto builder2 = setupMockPacketBuilder();
  scheduler.writeStreams(*builder2);
  verifyStreamFrames(*builder2, {f2});
  scheduler.writeStreams(*builder2);
  verifyStreamFrames(*builder2, {f3});
  scheduler.writeStreams(*builder2);
  verifyStreamFrames(*builder2, {f1});
}

TEST_P(
    QuicPacketSchedulerTest,
    StreamFrameSchedulerRoundRobinStreamPerPacketHitsDsr) {
  auto connPtr = createConn(10, 100000, 100000, GetParam());
  auto& conn = *connPtr;
  conn.transportSettings.streamFramePerPacket = true;
  StreamFrameScheduler scheduler(conn);

  auto stream1 = createStream(conn);
  auto stream2 = createStream(conn);
  auto stream3 = createStream(conn);
  auto stream4 = createStream(conn);

  auto largeBuf = createLargeBuffer(conn.udpSendPacketLen * 2);
  writeDataToStream(conn, stream1, std::move(largeBuf));
  auto f2 = writeDataToStream(conn, stream2, "some data");
  auto f3 = writeDataToStream(conn, stream3, "some data");

  // Set up DSR
  auto sender = std::make_unique<MockDSRPacketizationRequestSender>();
  ON_CALL(*sender, addSendInstruction(testing::_))
      .WillByDefault(testing::Return(true));
  ON_CALL(*sender, flush()).WillByDefault(testing::Return(true));
  auto dsrStream = conn.streamManager->findStream(stream4);
  dsrStream->dsrSender = std::move(sender);

  BufferMeta bufMeta(20);
  writeDataToStream(conn, stream4, "some data");
  ASSERT_FALSE(writeBufMetaToQuicStream(
                   *conn.streamManager->findStream(stream4), bufMeta, true)
                   .hasError());

  // Pretend we sent the non DSR data
  dsrStream->ackedIntervals.insert(0, dsrStream->writeBuffer.chainLength() - 1);
  dsrStream->currentWriteOffset = dsrStream->writeBuffer.chainLength();
  dsrStream->writeBuffer.move();
  ChainedByteRangeHead(std::move(
      dsrStream->pendingWrites)); // Move and destruct the pending writes
  conn.streamManager->updateWritableStreams(*dsrStream);

  // Write a normal size packet from stream1
  auto builder1 = createPacketBuilder(conn);
  scheduler.writeStreams(builder1);

  EXPECT_EQ(nextScheduledStreamID(conn), stream2);

  // Should write frames for stream2, stream3, followed by an empty write.
  auto builder2 = setupMockPacketBuilder();
  ASSERT_TRUE(scheduler.hasPendingData());
  scheduler.writeStreams(*builder2);
  ASSERT_EQ(builder2->frames_.size(), 1);
  ASSERT_TRUE(scheduler.hasPendingData());
  scheduler.writeStreams(*builder2);
  ASSERT_EQ(builder2->frames_.size(), 2);
  EXPECT_FALSE(scheduler.hasPendingData());
  scheduler.writeStreams(*builder2);

  verifyStreamFrames(*builder2, {f2, f3});
}

TEST_P(QuicPacketSchedulerTest, StreamFrameSchedulerSequential) {
  auto connPtr = createConn(10, 100000, 100000, GetParam());
  auto& conn = *connPtr;
  StreamFrameScheduler scheduler(conn);

  auto stream1 = createStream(conn, HTTPPriorityQueue::Priority(0, false));
  auto stream2 = createStream(conn, HTTPPriorityQueue::Priority(0, false));
  auto stream3 = createStream(conn, HTTPPriorityQueue::Priority(0, false));

  auto largeBuf = createLargeBuffer(conn.udpSendPacketLen * 2);
  auto f1 = writeDataToStream(conn, stream1, std::move(largeBuf));
  auto f2 = writeDataToStream(conn, stream2, "some data");
  auto f3 = writeDataToStream(conn, stream3, "some data");

  // Write a normal size packet from stream1
  auto builder1 = createPacketBuilder(conn);
  scheduler.writeStreams(builder1);

  EXPECT_EQ(nextScheduledStreamID(conn), stream1);

  // Should write frames for stream1, stream2, stream3, in that order.
  auto builder2 = setupMockPacketBuilder();
  scheduler.writeStreams(*builder2);

  verifyStreamFrames(*builder2, {f1, f2, f3});
}

TEST_P(QuicPacketSchedulerTest, StreamFrameSchedulerSequentialDefault) {
  auto connPtr = createConn(10, 100000, 100000, GetParam());
  auto& conn = *connPtr;
  conn.transportSettings.defaultPriority =
      HTTPPriorityQueue::Priority(0, false);
  StreamFrameScheduler scheduler(conn);

  auto stream1 = createStream(conn);
  auto stream2 = createStream(conn);
  auto stream3 = createStream(conn);

  auto largeBuf = createLargeBuffer(conn.udpSendPacketLen * 2);
  auto f1 = writeDataToStream(conn, stream1, std::move(largeBuf));
  auto f2 = writeDataToStream(conn, stream2, "some data");
  auto f3 = writeDataToStream(conn, stream3, "some data");

  // Write a normal size packet from stream1
  auto builder1 = createPacketBuilder(conn);
  scheduler.writeStreams(builder1);

  EXPECT_EQ(nextScheduledStreamID(conn), stream1);

  // Should write frames for stream1, stream2, stream3, in that order.
  auto builder2 = setupMockPacketBuilder();
  scheduler.writeStreams(*builder2);

  verifyStreamFrames(*builder2, {f1, f2, f3});
}

TEST_P(QuicPacketSchedulerTest, StreamFrameSchedulerRoundRobinControl) {
  auto connPtr = createConn(10, 100000, 100000, GetParam());
  auto& conn = *connPtr;
  StreamFrameScheduler scheduler(conn);

  auto stream1 = createStream(conn);
  auto stream2 = createStream(conn);
  auto stream3 = createStream(conn);
  auto stream4 = createStream(conn);

  conn.streamManager->setStreamAsControl(
      *conn.streamManager->findStream(stream2));
  conn.streamManager->setStreamAsControl(
      *conn.streamManager->findStream(stream4));

  auto largeBuf = createLargeBuffer(conn.udpSendPacketLen * 2);
  auto f1 = writeDataToStream(conn, stream1, std::move(largeBuf));
  auto f2 = writeDataToStream(conn, stream2, "some data");
  auto f3 = writeDataToStream(conn, stream3, "some data");
  auto f4 = writeDataToStream(conn, stream4, "some data");

  // This writes a normal size packet with 2, 4, 1
  auto builder1 = createPacketBuilder(conn);
  scheduler.writeStreams(builder1);

  EXPECT_EQ(nextScheduledStreamID(conn), stream3);
  EXPECT_EQ(conn.schedulingState.nextScheduledControlStream, stream2);

  // 2 and 4 did not get removed from writable, so they get repeated here
  // Should write frames for stream2, stream4, followed by stream 3 then 1.
  auto builder2 = setupMockPacketBuilder();
  scheduler.writeStreams(*builder2);

  verifyStreamFrames(*builder2, {f2, f4, f3, f1});

  EXPECT_EQ(conn.schedulingState.nextScheduledControlStream, stream2);
  if (GetParam()) {
    EXPECT_TRUE(conn.streamManager->writeQueue().empty());
  } else {
    EXPECT_EQ(nextScheduledStreamID(conn), stream3);
  }
}

TEST_P(QuicPacketSchedulerTest, StreamFrameSchedulerOneStream) {
  auto connPtr = createConn(10, 100000, 100000, GetParam());
  auto& conn = *connPtr;
  StreamFrameScheduler scheduler(conn);

  auto stream1 = createStream(conn);
  writeDataToStream(conn, stream1, "some data");

  auto builder1 = createPacketBuilder(conn);
  scheduler.writeStreams(builder1);

  if (GetParam()) {
    EXPECT_TRUE(conn.streamManager->writeQueue().empty());
  } else {
    EXPECT_EQ(nextScheduledStreamID(conn), 0);
  }
}

TEST_P(QuicPacketSchedulerTest, StreamFrameSchedulerRemoveOne) {
  auto connPtr = createConn(10, 100000, 100000, GetParam());
  auto& conn = *connPtr;
  StreamFrameScheduler scheduler(conn);

  auto stream1 = createStream(conn);
  auto stream2 = createStream(conn);

  auto f1 = writeDataToStream(conn, stream1, "some data");
  auto f2 = writeDataToStream(conn, stream2, "some data");

  auto builder = setupMockPacketBuilder();
  scheduler.writeStreams(*builder);
  verifyStreamFrames(*builder, {f1, f2});

  // Manually remove a stream and set the next scheduled to that stream.
  conn.streamManager->removeWritable(*conn.streamManager->findStream(stream1));
  // the queue is empty, reload it
  conn.streamManager->updateWritableStreams(
      *conn.streamManager->findStream(stream2));

  scheduler.writeStreams(*builder);
  ASSERT_EQ(builder->frames_.size(), 1);
  verifyStreamFrames(*builder, {f2});
}

TEST_P(
    QuicPacketSchedulerTest,
    CloningSchedulerWithInplaceBuilderDoNotEncodeHeaderWithoutBuild) {
  QuicClientConnectionState conn(
      FizzClientQuicHandshakeContext::Builder().build());
  conn.transportSettings.dataPathType = DataPathType::ContinuousMemory;
  BufAccessor bufAccessor(2000);
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
  ASSERT_FALSE(result.hasError());
  EXPECT_FALSE(result.value().clonedPacketIdentifier.has_value());

  // Nothing was written into the buffer:
  EXPECT_TRUE(bufAccessor.ownsBuffer());
  buf = bufAccessor.obtain();
  EXPECT_EQ(buf->length(), 0);
}

TEST_P(
    QuicPacketSchedulerTest,
    CloningSchedulerWithInplaceBuilderRollbackBufWhenFailToRebuild) {
  QuicClientConnectionState conn(
      FizzClientQuicHandshakeContext::Builder().build());
  conn.transportSettings.dataPathType = DataPathType::ContinuousMemory;
  BufAccessor bufAccessor(2000);
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
  ASSERT_FALSE(result.hasError());
  EXPECT_FALSE(result.value().clonedPacketIdentifier.has_value());

  // Nothing was written into the buffer:
  EXPECT_TRUE(bufAccessor.ownsBuffer());
  buf = bufAccessor.obtain();
  EXPECT_EQ(buf->length(), 0);
}

TEST_P(QuicPacketSchedulerTest, HighPriNewDataBeforeLowPriLossData) {
  auto connPtr = createConn(10, 100000, 100000, GetParam());
  auto& conn = *connPtr;
  StreamFrameScheduler scheduler(conn);

  auto lowPriStreamId =
      createStream(conn, HTTPPriorityQueue::Priority(5, false));
  auto highPriStreamId =
      createStream(conn, HTTPPriorityQueue::Priority(0, false));

  writeDataToStream(conn, lowPriStreamId, "Onegin");
  writeDataToStream(
      conn, highPriStreamId, buildRandomInputData(conn.udpSendPacketLen * 10));

  auto builder1 = createPacketBuilder(conn);
  scheduler.writeStreams(builder1);

  auto packet = std::move(builder1).buildPacket().packet;
  EXPECT_EQ(1, packet.frames.size());
  auto& writeStreamFrame = *packet.frames[0].asWriteStreamFrame();
  EXPECT_EQ(highPriStreamId, writeStreamFrame.streamId);
}

TEST_P(QuicPacketSchedulerTest, WriteLossWithoutFlowControl) {
  QuicServerConnectionState conn(
      FizzServerQuicHandshakeContext::Builder().build());
  ASSERT_FALSE(
      conn.streamManager->setMaxLocalBidirectionalStreams(10).hasError());
  conn.flowControlState.peerAdvertisedMaxOffset = 1000;
  conn.flowControlState.peerAdvertisedInitialMaxStreamOffsetBidiRemote = 1000;

  auto streamId = (*conn.streamManager->createNextBidirectionalStream())->id;
  auto stream = conn.streamManager->findStream(streamId);
  auto data = buildRandomInputData(1000);
  ASSERT_FALSE(
      writeDataToQuicStream(*stream, std::move(data), true).hasError());
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
  ASSERT_FALSE(builder1.encodePacketHeader().hasError());
  scheduler.writeStreams(builder1);
  auto packet1 = std::move(builder1).buildPacket().packet;
  ASSERT_FALSE(
      updateConnection(
          conn, none, packet1, Clock::now(), 1000, 0, false /* isDSR */)
          .hasError());
  EXPECT_EQ(1, packet1.frames.size());
  auto& writeStreamFrame1 = *packet1.frames[0].asWriteStreamFrame();
  EXPECT_EQ(streamId, writeStreamFrame1.streamId);
  EXPECT_EQ(0, getSendConnFlowControlBytesWire(conn));
  EXPECT_EQ(0, stream->pendingWrites.chainLength());
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
  ASSERT_FALSE(builder2.encodePacketHeader().hasError());
  scheduler.writeStreams(builder2);
  auto packet2 = std::move(builder2).buildPacket().packet;
  ASSERT_FALSE(
      updateConnection(
          conn, none, packet2, Clock::now(), 1000, 0, false /* isDSR */)
          .hasError());
  EXPECT_EQ(1, packet2.frames.size());
  auto& writeStreamFrame2 = *packet2.frames[0].asWriteStreamFrame();
  EXPECT_EQ(streamId, writeStreamFrame2.streamId);
  EXPECT_EQ(0, getSendConnFlowControlBytesWire(conn));
  EXPECT_TRUE(stream->lossBuffer.empty());
  EXPECT_EQ(1, stream->retransmissionBuffer.size());
  EXPECT_EQ(1000, stream->retransmissionBuffer[0]->data.chainLength());
}

TEST_P(QuicPacketSchedulerTest, WriteLossWithoutFlowControlIgnoreDSR) {
  QuicServerConnectionState conn(
      FizzServerQuicHandshakeContext::Builder().build());
  ASSERT_FALSE(
      conn.streamManager->setMaxLocalBidirectionalStreams(10).hasError());
  conn.flowControlState.peerAdvertisedMaxOffset = 1000;
  conn.flowControlState.peerAdvertisedInitialMaxStreamOffsetBidiRemote = 1000;

  auto streamId = (*conn.streamManager->createNextBidirectionalStream())->id;
  auto dsrStream = conn.streamManager->createNextBidirectionalStream().value();
  auto stream = conn.streamManager->findStream(streamId);
  auto data = buildRandomInputData(1000);
  ASSERT_FALSE(
      writeDataToQuicStream(*stream, std::move(data), true).hasError());
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
  ASSERT_FALSE(builder1.encodePacketHeader().hasError());
  scheduler.writeStreams(builder1);
  auto packet1 = std::move(builder1).buildPacket().packet;
  ASSERT_FALSE(
      updateConnection(
          conn, none, packet1, Clock::now(), 1000, 0, false /* isDSR */)
          .hasError());
  EXPECT_EQ(1, packet1.frames.size());
  auto& writeStreamFrame1 = *packet1.frames[0].asWriteStreamFrame();
  EXPECT_EQ(streamId, writeStreamFrame1.streamId);
  EXPECT_EQ(0, getSendConnFlowControlBytesWire(conn));
  EXPECT_EQ(0, stream->pendingWrites.chainLength());
  EXPECT_EQ(1, stream->retransmissionBuffer.size());
  EXPECT_EQ(1000, stream->retransmissionBuffer[0]->data.chainLength());

  EXPECT_FALSE(scheduler.hasPendingData());
}

TEST_P(QuicPacketSchedulerTest, WriteLossWithoutFlowControlSequential) {
  QuicServerConnectionState conn(
      FizzServerQuicHandshakeContext::Builder().build());
  ASSERT_FALSE(
      conn.streamManager->setMaxLocalBidirectionalStreams(10).hasError());
  conn.flowControlState.peerAdvertisedMaxOffset = 1000;
  conn.flowControlState.peerAdvertisedInitialMaxStreamOffsetBidiRemote = 1000;

  auto streamId = (*conn.streamManager->createNextBidirectionalStream())->id;
  conn.streamManager->setStreamPriority(
      streamId, HTTPPriorityQueue::Priority(0, false));
  auto stream = conn.streamManager->findStream(streamId);
  auto data = buildRandomInputData(1000);
  ASSERT_FALSE(
      writeDataToQuicStream(*stream, std::move(data), true).hasError());
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
  ASSERT_FALSE(builder1.encodePacketHeader().hasError());
  scheduler.writeStreams(builder1);
  auto packet1 = std::move(builder1).buildPacket().packet;
  ASSERT_FALSE(
      updateConnection(
          conn, none, packet1, Clock::now(), 1000, 0, false /* isDSR */)
          .hasError());
  EXPECT_EQ(1, packet1.frames.size());
  auto& writeStreamFrame1 = *packet1.frames[0].asWriteStreamFrame();
  EXPECT_EQ(streamId, writeStreamFrame1.streamId);
  EXPECT_EQ(0, getSendConnFlowControlBytesWire(conn));
  EXPECT_EQ(0, stream->pendingWrites.chainLength());
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
  ASSERT_FALSE(builder2.encodePacketHeader().hasError());
  scheduler.writeStreams(builder2);
  auto packet2 = std::move(builder2).buildPacket().packet;
  ASSERT_FALSE(
      updateConnection(
          conn, none, packet2, Clock::now(), 1000, 0, false /* isDSR */)
          .hasError());
  EXPECT_EQ(1, packet2.frames.size());
  auto& writeStreamFrame2 = *packet2.frames[0].asWriteStreamFrame();
  EXPECT_EQ(streamId, writeStreamFrame2.streamId);
  EXPECT_EQ(0, getSendConnFlowControlBytesWire(conn));
  EXPECT_TRUE(stream->lossBuffer.empty());
  EXPECT_EQ(1, stream->retransmissionBuffer.size());
  EXPECT_EQ(1000, stream->retransmissionBuffer[0]->data.chainLength());
}

TEST_P(QuicPacketSchedulerTest, MultipleStreamsRunOutOfFlowControl) {
  auto connPtr = createConn(10, 1000, 2000, GetParam());
  auto& conn = *connPtr;
  conn.udpSendPacketLen = 2000;

  auto highPriStreamId =
      (*conn.streamManager->createNextBidirectionalStream())->id;
  auto lowPriStreamId =
      (*conn.streamManager->createNextBidirectionalStream())->id;
  auto highPriStream = conn.streamManager->findStream(highPriStreamId);
  auto lowPriStream = conn.streamManager->findStream(lowPriStreamId);

  // Write new data to high priority stream in excess of max data
  auto newData = buildRandomInputData(2000);
  ASSERT_TRUE(writeDataToQuicStream(*highPriStream, std::move(newData), true));
  conn.streamManager->updateWritableStreams(
      *highPriStream, /*connFlowControlOpen=*/true);

  // Fake a loss data for low priority stream
  lowPriStream->currentWriteOffset = 201;
  auto lossData = buildRandomInputData(200);
  lowPriStream->lossBuffer.emplace_back(
      ChainedByteRangeHead(lossData), 0, true);
  conn.streamManager->updateWritableStreams(
      *lowPriStream, /*connFlowControlOpen=*/true);

  StreamFrameScheduler scheduler(conn);
  ShortHeader shortHeader1(
      ProtectionType::KeyPhaseZero,
      getTestConnectionId(),
      getNextPacketNum(conn, PacketNumberSpace::AppData));
  RegularQuicPacketBuilder builder1(
      conn.udpSendPacketLen,
      std::move(shortHeader1),
      conn.ackStates.appDataAckState.largestAckedByPeer.value_or(0));
  ASSERT_TRUE(builder1.encodePacketHeader());
  scheduler.writeStreams(builder1);
  auto packet1 = std::move(builder1).buildPacket().packet;
  ASSERT_TRUE(updateConnection(
      conn, none, packet1, Clock::now(), 1200, 0, false /* isDSR */));
  ASSERT_EQ(2, packet1.frames.size());
  auto& writeStreamFrame1 = *packet1.frames[0].asWriteStreamFrame();
  EXPECT_EQ(highPriStreamId, writeStreamFrame1.streamId);
  EXPECT_EQ(0, getSendConnFlowControlBytesWire(conn));
  EXPECT_EQ(1000, highPriStream->pendingWrites.chainLength());
  EXPECT_EQ(1, highPriStream->retransmissionBuffer.size());
  EXPECT_EQ(1000, highPriStream->retransmissionBuffer[0]->data.chainLength());

  auto& writeStreamFrame2 = *packet1.frames[1].asWriteStreamFrame();
  EXPECT_EQ(lowPriStreamId, writeStreamFrame2.streamId);
  EXPECT_EQ(200, writeStreamFrame2.len);
  EXPECT_TRUE(lowPriStream->lossBuffer.empty());
  EXPECT_EQ(1, lowPriStream->retransmissionBuffer.size());
  EXPECT_EQ(200, lowPriStream->retransmissionBuffer[0]->data.chainLength());

  // Simulate additional flow control granted
  conn.flowControlState.peerAdvertisedMaxOffset = 2000;
  conn.streamManager->onMaxData();
  // Don't need to call updateWritableStreams, onMaxData updates the state for
  // any stream blocked on conn flow control

  // Write remaining data for high priority stream
  ShortHeader shortHeader2(
      ProtectionType::KeyPhaseZero,
      getTestConnectionId(),
      getNextPacketNum(conn, PacketNumberSpace::AppData));
  RegularQuicPacketBuilder builder2(
      conn.udpSendPacketLen,
      std::move(shortHeader2),
      conn.ackStates.appDataAckState.largestAckedByPeer.value_or(0));
  ASSERT_TRUE(builder2.encodePacketHeader());
  scheduler.writeStreams(builder2);
  auto packet2 = std::move(builder2).buildPacket().packet;
  ASSERT_TRUE(updateConnection(
      conn, none, packet2, Clock::now(), 1000, 0, false /* isDSR */));
  ASSERT_EQ(1, packet2.frames.size());
  auto& writeStreamFrame3 = *packet2.frames[0].asWriteStreamFrame();
  EXPECT_EQ(highPriStreamId, writeStreamFrame3.streamId);
  EXPECT_EQ(0, getSendConnFlowControlBytesWire(conn));
  EXPECT_EQ(
      1000, highPriStream->retransmissionBuffer[1000]->data.chainLength());
  EXPECT_EQ(1000, writeStreamFrame3.len);
}

TEST_P(QuicPacketSchedulerTest, RunOutFlowControlDuringStreamWrite) {
  QuicServerConnectionState conn(
      FizzServerQuicHandshakeContext::Builder().build());
  ASSERT_FALSE(
      conn.streamManager->setMaxLocalBidirectionalStreams(10).hasError());
  conn.flowControlState.peerAdvertisedMaxOffset = 1000;
  conn.flowControlState.peerAdvertisedInitialMaxStreamOffsetBidiRemote = 1000;
  conn.udpSendPacketLen = 2000;

  auto streamId1 = (*conn.streamManager->createNextBidirectionalStream())->id;
  auto streamId2 = (*conn.streamManager->createNextBidirectionalStream())->id;
  auto stream1 = conn.streamManager->findStream(streamId1);
  auto stream2 = conn.streamManager->findStream(streamId2);
  auto newData = buildRandomInputData(1000);
  ASSERT_FALSE(
      writeDataToQuicStream(*stream1, std::move(newData), true).hasError());
  conn.streamManager->updateWritableStreams(*stream1);

  // Fake a loss data for stream2:
  stream2->currentWriteOffset = 201;
  auto lossData = buildRandomInputData(200);
  stream2->lossBuffer.emplace_back(ChainedByteRangeHead(lossData), 0, true);
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
  ASSERT_FALSE(builder1.encodePacketHeader().hasError());
  scheduler.writeStreams(builder1);
  auto packet1 = std::move(builder1).buildPacket().packet;
  ASSERT_FALSE(
      updateConnection(
          conn, none, packet1, Clock::now(), 1200, 0, false /* isDSR */)
          .hasError());
  ASSERT_EQ(2, packet1.frames.size());
  auto& writeStreamFrame1 = *packet1.frames[0].asWriteStreamFrame();
  EXPECT_EQ(streamId1, writeStreamFrame1.streamId);
  EXPECT_EQ(0, getSendConnFlowControlBytesWire(conn));
  EXPECT_EQ(0, stream1->pendingWrites.chainLength());
  EXPECT_EQ(1, stream1->retransmissionBuffer.size());
  EXPECT_EQ(1000, stream1->retransmissionBuffer[0]->data.chainLength());

  auto& writeStreamFrame2 = *packet1.frames[1].asWriteStreamFrame();
  EXPECT_EQ(streamId2, writeStreamFrame2.streamId);
  EXPECT_EQ(200, writeStreamFrame2.len);
  EXPECT_TRUE(stream2->lossBuffer.empty());
  EXPECT_EQ(1, stream2->retransmissionBuffer.size());
  EXPECT_EQ(200, stream2->retransmissionBuffer[0]->data.chainLength());
}

TEST_P(QuicPacketSchedulerTest, WritingFINFromBufWithBufMetaFirst) {
  QuicServerConnectionState conn(
      FizzServerQuicHandshakeContext::Builder().build());
  ASSERT_FALSE(
      conn.streamManager->setMaxLocalBidirectionalStreams(10).hasError());
  conn.flowControlState.peerAdvertisedMaxOffset = 100000;
  auto* stream = *(conn.streamManager->createNextBidirectionalStream());
  stream->flowControlState.peerAdvertisedMaxOffset = 100000;

  ASSERT_FALSE(
      writeDataToQuicStream(*stream, folly::IOBuf::copyBuffer("Ascent"), false)
          .hasError());
  stream->dsrSender = std::make_unique<MockDSRPacketizationRequestSender>();
  BufferMeta bufferMeta(5000);
  ASSERT_FALSE(writeBufMetaToQuicStream(*stream, bufferMeta, true).hasError());
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
  ASSERT_FALSE(builder.encodePacketHeader().hasError());
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

TEST_P(QuicPacketSchedulerTest, NoFINWriteWhenBufMetaWrittenFIN) {
  QuicServerConnectionState conn(
      FizzServerQuicHandshakeContext::Builder().build());
  ASSERT_FALSE(
      conn.streamManager->setMaxLocalBidirectionalStreams(10).hasError());
  conn.flowControlState.peerAdvertisedMaxOffset = 100000;
  auto* stream = *(conn.streamManager->createNextBidirectionalStream());
  stream->flowControlState.peerAdvertisedMaxOffset = 100000;

  ASSERT_FALSE(
      writeDataToQuicStream(*stream, folly::IOBuf::copyBuffer("Ascent"), false)
          .hasError());
  stream->dsrSender = std::make_unique<MockDSRPacketizationRequestSender>();
  BufferMeta bufferMeta(5000);
  ASSERT_FALSE(writeBufMetaToQuicStream(*stream, bufferMeta, true).hasError());
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
  ASSERT_FALSE(builder.encodePacketHeader().hasError());
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

TEST_P(QuicPacketSchedulerTest, DatagramFrameSchedulerMultipleFramesPerPacket) {
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
  ASSERT_FALSE(scheduler.writeDatagramFrames(builder).hasError());
  ASSERT_EQ(frames.size(), 2);
}

TEST_P(QuicPacketSchedulerTest, DatagramFrameSchedulerOneFramePerPacket) {
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
  ASSERT_FALSE(scheduler.writeDatagramFrames(builder).hasError());
  ASSERT_EQ(frames.size(), 1);
  EXPECT_CALL(quicStats, onDatagramWrite(_))
      .Times(1)
      .WillRepeatedly(Invoke([](uint64_t bytes) { EXPECT_GT(bytes, 0); }));
  ASSERT_FALSE(scheduler.writeDatagramFrames(builder).hasError());
  ASSERT_EQ(frames.size(), 2);
}

TEST_P(QuicPacketSchedulerTest, DatagramFrameWriteWhenRoomAvailable) {
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
  ASSERT_FALSE(scheduler.writeDatagramFrames(builder).hasError());
  ASSERT_EQ(frames.size(), 0);
  EXPECT_CALL(builder, remainingSpaceInPkt())
      .WillRepeatedly(Return(conn.udpSendPacketLen / 2));
  EXPECT_CALL(quicStats, onDatagramWrite(_))
      .Times(1)
      .WillRepeatedly(Invoke([](uint64_t bytes) { EXPECT_GT(bytes, 0); }));
  ASSERT_FALSE(scheduler.writeDatagramFrames(builder).hasError());
  ASSERT_EQ(frames.size(), 1);
}

TEST_P(QuicPacketSchedulerTest, ShortHeaderPaddingWithSpaceForPadding) {
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
  ASSERT_FALSE(writeFrame(frame1, builder1).hasError());
  ASSERT_FALSE(writeFrame(frame2, builder2).hasError());

  NiceMock<MockQuicStats> quicStats;
  conn.statsCallback = &quicStats;

  auto result1 = scheduler.scheduleFramesForPacket(
      std::move(builder1), conn.udpSendPacketLen);
  ASSERT_FALSE(result1.hasError());
  EXPECT_GT(result1.value().shortHeaderPadding, 0);
  auto result2 = scheduler.scheduleFramesForPacket(
      std::move(builder2), conn.udpSendPacketLen);
  ASSERT_FALSE(result2.hasError());
  EXPECT_GT(result2.value().shortHeaderPadding, 0);

  auto headerLength1 = result1.value().packet->header.computeChainDataLength();
  auto bodyLength1 = result1.value().packet->body.computeChainDataLength();
  auto packetLength1 = headerLength1 + bodyLength1;
  auto expectedPadding1 =
      (conn.udpSendPacketLen - (inputDataLength1 + headerLength1)) %
      paddingModulo;

  auto headerLength2 = result2.value().packet->header.computeChainDataLength();
  auto bodyLength2 = result2.value().packet->body.computeChainDataLength();
  auto packetLength2 = headerLength2 + bodyLength2;
  auto expectedPadding2 =
      (conn.udpSendPacketLen - (inputDataLength2 + headerLength2)) %
      paddingModulo;

  EXPECT_EQ(packetLength1, headerLength1 + inputDataLength1 + expectedPadding1);
  EXPECT_EQ(packetLength2, headerLength2 + inputDataLength2 + expectedPadding2);
  // ensure two similar size input data get padded up to same length
  EXPECT_EQ(packetLength1, packetLength2);
}

TEST_P(QuicPacketSchedulerTest, ShortHeaderFixedPaddingAtStart) {
  QuicServerConnectionState conn(
      FizzServerQuicHandshakeContext::Builder().build());
  conn.transportSettings.fixedShortHeaderPadding = 2;
  conn.transportSettings.paddingModulo = 16;
  conn.flowControlState.peerAdvertisedMaxOffset = 1000000;
  conn.flowControlState.peerAdvertisedInitialMaxStreamOffsetBidiRemote =
      1000000;

  // Create stream and write data
  ASSERT_FALSE(
      conn.streamManager->setMaxLocalBidirectionalStreams(10).hasError());
  auto stream = conn.streamManager->createNextBidirectionalStream().value();
  auto data = buildRandomInputData(50); // Small enough to fit in one packet
  ASSERT_FALSE(
      writeDataToQuicStream(*stream, std::move(data), false).hasError());

  // Set up scheduler and builder
  FrameScheduler scheduler = std::move(FrameScheduler::Builder(
                                           conn,
                                           EncryptionLevel::AppData,
                                           PacketNumberSpace::AppData,
                                           "streamScheduler")
                                           .streamFrames())
                                 .build();

  ShortHeader header(
      ProtectionType::KeyPhaseOne,
      conn.clientConnectionId.value_or(getTestConnectionId()),
      getNextPacketNum(conn, PacketNumberSpace::AppData));

  RegularQuicPacketBuilder builder(
      conn.udpSendPacketLen,
      std::move(header),
      conn.ackStates.appDataAckState.largestAckedByPeer.value_or(0));

  // Schedule frames
  auto result = scheduler.scheduleFramesForPacket(
      std::move(builder), conn.udpSendPacketLen);
  ASSERT_FALSE(result.hasError());

  // Verify padding frames were added at start
  EXPECT_TRUE(result.value().packet.hasValue());
  const auto& frames = result.value().packet->packet.frames;
  ASSERT_EQ(frames.size(), 3);
  EXPECT_TRUE(frames[0].asPaddingFrame());
  EXPECT_TRUE(frames[1].asWriteStreamFrame());
  EXPECT_TRUE(frames[2].asPaddingFrame());
}

TEST_P(QuicPacketSchedulerTest, ShortHeaderPaddingNearMaxPacketLength) {
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
  ASSERT_FALSE(writeFrame(frame, builder).hasError());

  NiceMock<MockQuicStats> quicStats;
  conn.statsCallback = &quicStats;

  auto result = scheduler.scheduleFramesForPacket(
      std::move(builder), conn.udpSendPacketLen);
  ASSERT_FALSE(result.hasError());
  EXPECT_GT(result.value().shortHeaderPadding, 0);

  auto headerLength = result.value().packet->header.computeChainDataLength();
  auto bodyLength = result.value().packet->body.computeChainDataLength();

  auto packetLength = headerLength + bodyLength;

  auto expectedPadding =
      (conn.udpSendPacketLen - (inputDataLength + headerLength)) %
      paddingModulo;

  EXPECT_EQ(packetLength, headerLength + inputDataLength + expectedPadding);
  EXPECT_EQ(packetLength, conn.udpSendPacketLen);
}

TEST_P(QuicPacketSchedulerTest, ShortHeaderPaddingMaxPacketLength) {
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
    ASSERT_FALSE(writeFrame(PaddingFrame(), builder).hasError());
  }

  NiceMock<MockQuicStats> quicStats;
  conn.statsCallback = &quicStats;

  auto result = scheduler.scheduleFramesForPacket(
      std::move(builder), conn.udpSendPacketLen);
  ASSERT_FALSE(result.hasError());
  EXPECT_EQ(result.value().shortHeaderPadding, 0);

  auto headerLength = result.value().packet->header.computeChainDataLength();
  auto bodyLength = result.value().packet->body.computeChainDataLength();

  auto packetLength = headerLength + bodyLength;

  EXPECT_EQ(packetLength, conn.udpSendPacketLen);
}

TEST_P(QuicPacketSchedulerTest, ImmediateAckFrameSchedulerOnRequest) {
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

  auto result =
      std::move(immediateAckOnlyScheduler)
          .scheduleFramesForPacket(std::move(builder), conn.udpSendPacketLen);
  ASSERT_FALSE(result.hasError());
  auto packetLength = result.value().packet->header.computeChainDataLength() +
      result.value().packet->body.computeChainDataLength();
  EXPECT_EQ(conn.udpSendPacketLen, packetLength);
}

TEST_P(QuicPacketSchedulerTest, ImmediateAckFrameSchedulerNotRequested) {
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

  auto result =
      std::move(immediateAckOnlyScheduler)
          .scheduleFramesForPacket(std::move(builder), conn.udpSendPacketLen);
  ASSERT_FALSE(result.hasError());
  auto packetLength = result.value().packet->header.computeChainDataLength() +
      result.value().packet->body.computeChainDataLength();
  // The immediate ACK scheduler was not triggered. This packet has no
  // frames and it shouldn't get padded.
  EXPECT_LT(packetLength, conn.udpSendPacketLen);
}

TEST_P(QuicPacketSchedulerTest, RstStreamSchedulerReliableReset) {
  QuicClientConnectionState conn(
      FizzClientQuicHandshakeContext::Builder().build());
  ASSERT_FALSE(
      conn.streamManager->setMaxLocalBidirectionalStreams(10).hasError());
  conn.flowControlState.peerAdvertisedMaxOffset = 100000;
  conn.flowControlState.peerAdvertisedInitialMaxStreamOffsetBidiRemote = 100000;
  auto stream = conn.streamManager->createNextBidirectionalStream().value();
  auto buf = folly::IOBuf::copyBuffer("cupcake");
  auto bufLen = buf->computeChainDataLength();
  ASSERT_FALSE(writeDataToQuicStream(*stream, buf->clone(), false).hasError());

  // Reliable reset with reliableSize = bufLen
  conn.pendingEvents.resets.emplace(
      stream->id, RstStreamFrame(stream->id, 0, bufLen, bufLen));

  FrameScheduler scheduler = std::move(FrameScheduler::Builder(
                                           conn,
                                           EncryptionLevel::AppData,
                                           PacketNumberSpace::AppData,
                                           "streamScheduler")
                                           .streamFrames()
                                           .resetFrames())
                                 .build();
  auto cipherOverhead = 16;
  PacketNum packetNum1 = 0;
  ShortHeader header1(
      ProtectionType::KeyPhaseOne,
      conn.clientConnectionId.value_or(getTestConnectionId()),
      packetNum1);
  RegularQuicPacketBuilder builder1(
      conn.udpSendPacketLen,
      std::move(header1),
      conn.ackStates.appDataAckState.largestAckedByPeer.value_or(0));
  auto packetResult1 = scheduler.scheduleFramesForPacket(
      std::move(builder1), conn.udpSendPacketLen - cipherOverhead);
  ASSERT_FALSE(packetResult1.hasError());
  auto encodedSize1 =
      packetResult1.value().packet->body.computeChainDataLength() +
      packetResult1.value().packet->header.computeChainDataLength() +
      cipherOverhead;
  ASSERT_FALSE(updateConnection(
                   conn,
                   none,
                   packetResult1.value().packet->packet,
                   Clock::now(),
                   encodedSize1,
                   0,
                   false /* isDSRPacket */)
                   .hasError());

  // We shouldn't send the reliable reset just yet, because we haven't yet
  // egressed all the stream data upto the reliable offset.
  EXPECT_TRUE(conn.pendingEvents.resets.contains(stream->id));

  PacketNum packetNum2 = 1;
  ShortHeader header2(
      ProtectionType::KeyPhaseOne,
      conn.clientConnectionId.value_or(getTestConnectionId()),
      packetNum2);
  RegularQuicPacketBuilder builder2(
      conn.udpSendPacketLen,
      std::move(header2),
      conn.ackStates.appDataAckState.largestAckedByPeer.value_or(0));
  auto packetResult2 = scheduler.scheduleFramesForPacket(
      std::move(builder2), conn.udpSendPacketLen - cipherOverhead);
  ASSERT_FALSE(packetResult2.hasError());
  auto encodedSize2 =
      packetResult1.value().packet->body.computeChainDataLength() +
      packetResult2.value().packet->header.computeChainDataLength() +
      cipherOverhead;
  ASSERT_FALSE(updateConnection(
                   conn,
                   none,
                   packetResult2.value().packet->packet,
                   Clock::now(),
                   encodedSize2,
                   0,
                   false /* isDSRPacket */)
                   .hasError());

  // Now we should have egressed all the stream data upto the reliable offset,
  // so we should have sent the reliable reset.
  EXPECT_FALSE(conn.pendingEvents.resets.contains(stream->id));
}

TEST_P(QuicPacketSchedulerTest, PausedPriorityEnabled) {
  static const auto kSequentialPriority = HTTPPriorityQueue::Priority(3, false);
  static const HTTPPriorityQueue::Priority kPausedPriority =
      HTTPPriorityQueue::Priority::PAUSED;

  auto connPtr = createConn(10, 100000, 100000, GetParam());
  auto& conn = *connPtr;
  StreamFrameScheduler scheduler(conn);

  auto pausedStreamId = createStream(conn, kPausedPriority);
  auto regularStreamId = createStream(conn, kSequentialPriority);

  auto pausedFrame = writeDataToStream(conn, pausedStreamId, "paused_data");
  auto regularFrame = writeDataToStream(conn, regularStreamId, "regular_data");

  // Should write frames for only regular stream.
  auto builder = setupMockPacketBuilder();
  scheduler.writeStreams(*builder);

  verifyStreamFrames(*builder, {regularFrame});

  conn.streamManager->removeWritable(
      *conn.streamManager->findStream(regularStreamId));

  // Unpause the stream. Expect the scheduleor to write the data.
  conn.streamManager->setStreamPriority(pausedStreamId, kSequentialPriority);
  scheduler.writeStreams(*builder);

  verifyStreamFrames(*builder, {pausedFrame});

  // Pause the stream again. Expect no more data writable.
  conn.streamManager->setStreamPriority(pausedStreamId, kPausedPriority);
  ASSERT_FALSE(conn.streamManager->hasWritable());
}

TEST_P(QuicPacketSchedulerTest, PausedPriorityDisabled) {
  static const auto kSequentialPriority = HTTPPriorityQueue::Priority(3, false);
  static const HTTPPriorityQueue::Priority kPausedPriority =
      HTTPPriorityQueue::Priority::PAUSED;

  auto connPtr = createConn(10, 100000, 100000, GetParam());
  auto& conn = *connPtr;
  transportSettings.disablePausedPriority = true;
  StreamFrameScheduler scheduler(conn);

  auto pausedStreamId = createStream(conn, kPausedPriority);
  auto regularStreamId = createStream(conn, kSequentialPriority);

  auto pausedFrame = writeDataToStream(conn, pausedStreamId, "paused_data");
  auto regularFrame = writeDataToStream(conn, regularStreamId, "regular_data");

  auto builder = setupMockPacketBuilder();
  scheduler.writeStreams(*builder);
  verifyStreamFrames(*builder, {regularFrame, pausedFrame});
}

TEST_P(QuicPacketSchedulerTest, FixedShortHeaderPadding) {
  QuicServerConnectionState conn(
      FizzServerQuicHandshakeContext::Builder().build());
  conn.transportSettings.fixedShortHeaderPadding = 2;
  conn.transportSettings.paddingModulo = 0;
  conn.flowControlState.peerAdvertisedMaxOffset = 1000000;
  conn.flowControlState.peerAdvertisedInitialMaxStreamOffsetBidiRemote =
      1000000;

  // Create stream and write data
  ASSERT_FALSE(
      conn.streamManager->setMaxLocalBidirectionalStreams(10).hasError());
  auto stream = conn.streamManager->createNextBidirectionalStream().value();
  auto data = buildRandomInputData(50); // Small enough to fit in one packet
  ASSERT_FALSE(
      writeDataToQuicStream(*stream, std::move(data), false).hasError());
  conn.streamManager->updateWritableStreams(*stream);

  // Set up scheduler and builder
  FrameScheduler scheduler = std::move(FrameScheduler::Builder(
                                           conn,
                                           EncryptionLevel::AppData,
                                           PacketNumberSpace::AppData,
                                           "streamScheduler")
                                           .streamFrames())
                                 .build();

  ShortHeader header(
      ProtectionType::KeyPhaseOne,
      conn.clientConnectionId.value_or(getTestConnectionId()),
      getNextPacketNum(conn, PacketNumberSpace::AppData));

  RegularQuicPacketBuilder builder(
      conn.udpSendPacketLen,
      std::move(header),
      conn.ackStates.appDataAckState.largestAckedByPeer.value_or(0));

  // Schedule frames
  auto result = scheduler.scheduleFramesForPacket(
      std::move(builder), conn.udpSendPacketLen);
  ASSERT_FALSE(result.hasError());

  // Verify padding frames were added
  // at start
  EXPECT_TRUE(result.value().packet.hasValue());
  const auto& frames = result.value().packet->packet.frames;
  ASSERT_EQ(frames.size(), 2);
  EXPECT_TRUE(frames[0].asPaddingFrame());
  EXPECT_TRUE(frames[1].asWriteStreamFrame());
}

// This test class sets up a connection with all the fields that can be included
// in an ACK. The fixtures for this class confirm that the scheduler writes the
// correct frame type and fields enabled by the connection state.
class QuicAckSchedulerTest : public QuicPacketSchedulerTestBase, public Test {
 protected:
  QuicAckSchedulerTest()
      : conn_(createConn(10, 100000, 100000)),
        ackState_(getAckState(*conn_, PacketNumberSpace::AppData)),
        builder_(setupMockPacketBuilder()) {}

  void SetUp() override {
    // One ack block
    ackState_.acks.insert(1, 10);

    // One receive timestamps
    WriteAckFrameState::ReceivedPacket rpi;
    rpi.pktNum = 10;
    rpi.timings.receiveTimePoint = Clock::now();
    ackState_.recvdPacketInfos.emplace_back(rpi);
    ackState_.largestRecvdPacketNum = 10;
    ackState_.largestRecvdPacketTime = rpi.timings.receiveTimePoint;

    // Non-zero ECN values
    ackState_.ecnECT0CountReceived = 1;
    ackState_.ecnECT1CountReceived = 2;
    ackState_.ecnCECountReceived = 3;

    auto connId = getTestConnectionId();
    mockPacketHeader_ = std::make_unique<PacketHeader>(ShortHeader(
        ProtectionType::KeyPhaseZero,
        connId,
        getNextPacketNum(*conn_, PacketNumberSpace::AppData)));

    EXPECT_CALL(*builder_, getPacketHeader())
        .WillRepeatedly(ReturnRef(*mockPacketHeader_));
  }

  std::unique_ptr<QuicClientConnectionState> conn_;
  AckState ackState_;
  std::unique_ptr<MockQuicPacketBuilder> builder_;
  std::unique_ptr<PacketHeader> mockPacketHeader_;
};

TEST_F(QuicAckSchedulerTest, DefaultAckFrame) {
  // Default config writes ACK frame.
  AckScheduler ackScheduler(*conn_, ackState_);
  ASSERT_TRUE(ackScheduler.hasPendingAcks());

  auto writeResult = ackScheduler.writeNextAcks(*builder_);
  ASSERT_FALSE(writeResult.hasError());
  ASSERT_TRUE(writeResult.value() != none);
  ASSERT_EQ(builder_->frames_.size(), 1);

  auto ackFrame = builder_->frames_[0].asWriteAckFrame();
  ASSERT_TRUE(ackFrame != nullptr);

  EXPECT_EQ(ackFrame->frameType, FrameType::ACK);

  EXPECT_EQ(ackFrame->ackBlocks.size(), 1);
  EXPECT_EQ(ackFrame->ackBlocks[0].start, 1);
  EXPECT_EQ(ackFrame->ackBlocks[0].end, 10);

  EXPECT_TRUE(ackFrame->recvdPacketsTimestampRanges.empty());

  EXPECT_EQ(ackFrame->ecnECT0Count, 0);
  EXPECT_EQ(ackFrame->ecnECT1Count, 0);
  EXPECT_EQ(ackFrame->ecnCECount, 0);
}

TEST_F(QuicAckSchedulerTest, WriteAckEcnWhenReadingEcnOnEgress) {
  conn_->transportSettings.readEcnOnIngress = true;

  AckScheduler ackScheduler(*conn_, ackState_);
  ASSERT_TRUE(ackScheduler.hasPendingAcks());

  auto writeResult = ackScheduler.writeNextAcks(*builder_);
  ASSERT_FALSE(writeResult.hasError());
  ASSERT_TRUE(writeResult.value() != none);
  ASSERT_EQ(builder_->frames_.size(), 1);

  auto ackFrame = builder_->frames_[0].asWriteAckFrame();
  ASSERT_TRUE(ackFrame != nullptr);

  EXPECT_EQ(ackFrame->frameType, FrameType::ACK_ECN);

  EXPECT_EQ(ackFrame->ackBlocks.size(), 1);
  EXPECT_EQ(ackFrame->ackBlocks[0].start, 1);
  EXPECT_EQ(ackFrame->ackBlocks[0].end, 10);

  EXPECT_TRUE(ackFrame->recvdPacketsTimestampRanges.empty());

  EXPECT_EQ(ackFrame->ecnECT0Count, 1);
  EXPECT_EQ(ackFrame->ecnECT1Count, 2);
  EXPECT_EQ(ackFrame->ecnCECount, 3);
}

TEST_F(QuicAckSchedulerTest, WriteAckReceiveTimestampsWhenEnabled) {
  conn_->transportSettings.readEcnOnIngress = false;

  conn_->maybePeerAckReceiveTimestampsConfig = AckReceiveTimestampsConfig();
  conn_->transportSettings.maybeAckReceiveTimestampsConfigSentToPeer =
      AckReceiveTimestampsConfig();

  updateNegotiatedAckFeatures(*conn_);
  AckScheduler ackScheduler(*conn_, ackState_);
  ASSERT_TRUE(ackScheduler.hasPendingAcks());

  auto writeResult = ackScheduler.writeNextAcks(*builder_);
  ASSERT_FALSE(writeResult.hasError());
  ASSERT_TRUE(writeResult.value() != none);
  ASSERT_EQ(builder_->frames_.size(), 1);

  auto ackFrame = builder_->frames_[0].asWriteAckFrame();
  ASSERT_TRUE(ackFrame != nullptr);

  EXPECT_EQ(ackFrame->frameType, FrameType::ACK_RECEIVE_TIMESTAMPS);

  EXPECT_EQ(ackFrame->ackBlocks.size(), 1);
  EXPECT_EQ(ackFrame->ackBlocks[0].start, 1);
  EXPECT_EQ(ackFrame->ackBlocks[0].end, 10);

  ASSERT_EQ(ackFrame->recvdPacketsTimestampRanges.size(), 1);
  EXPECT_EQ(ackFrame->recvdPacketsTimestampRanges[0].timestamp_delta_count, 1);

  EXPECT_EQ(ackFrame->ecnECT0Count, 0);
  EXPECT_EQ(ackFrame->ecnECT1Count, 0);
  EXPECT_EQ(ackFrame->ecnCECount, 0);
}

TEST_F(QuicAckSchedulerTest, AckEcnTakesPrecedenceOverReceiveTimestamps) {
  conn_->transportSettings.readEcnOnIngress = true;

  conn_->maybePeerAckReceiveTimestampsConfig = AckReceiveTimestampsConfig();
  conn_->transportSettings.maybeAckReceiveTimestampsConfigSentToPeer =
      AckReceiveTimestampsConfig();

  AckScheduler ackScheduler(*conn_, ackState_);
  ASSERT_TRUE(ackScheduler.hasPendingAcks());

  auto writeResult = ackScheduler.writeNextAcks(*builder_);
  ASSERT_FALSE(writeResult.hasError());
  ASSERT_TRUE(writeResult.value() != none);
  ASSERT_EQ(builder_->frames_.size(), 1);

  auto ackFrame = builder_->frames_[0].asWriteAckFrame();
  ASSERT_TRUE(ackFrame != nullptr);

  EXPECT_EQ(ackFrame->frameType, FrameType::ACK_ECN);

  EXPECT_EQ(ackFrame->ackBlocks.size(), 1);
  EXPECT_EQ(ackFrame->ackBlocks[0].start, 1);
  EXPECT_EQ(ackFrame->ackBlocks[0].end, 10);

  EXPECT_TRUE(ackFrame->recvdPacketsTimestampRanges.empty());

  EXPECT_EQ(ackFrame->ecnECT0Count, 1);
  EXPECT_EQ(ackFrame->ecnECT1Count, 2);
  EXPECT_EQ(ackFrame->ecnCECount, 3);
}

TEST_F(QuicAckSchedulerTest, AckExtendedNotSentIfNotSupported) {
  conn_->transportSettings.readEcnOnIngress = true;

  conn_->transportSettings.enableExtendedAckFeatures =
      3; // ECN + ReceiveTimestamps
  conn_->peerAdvertisedExtendedAckFeatures = 0;
  updateNegotiatedAckFeatures(*conn_);

  AckScheduler ackScheduler(*conn_, ackState_);
  ASSERT_TRUE(ackScheduler.hasPendingAcks());

  auto writeResult = ackScheduler.writeNextAcks(*builder_);
  ASSERT_FALSE(writeResult.hasError());
  ASSERT_TRUE(writeResult.value() != none);
  ASSERT_EQ(builder_->frames_.size(), 1);

  auto ackFrame = builder_->frames_[0].asWriteAckFrame();
  ASSERT_TRUE(ackFrame != nullptr);

  EXPECT_EQ(ackFrame->frameType, FrameType::ACK_ECN);

  EXPECT_EQ(ackFrame->ackBlocks.size(), 1);
  EXPECT_EQ(ackFrame->ackBlocks[0].start, 1);
  EXPECT_EQ(ackFrame->ackBlocks[0].end, 10);

  EXPECT_TRUE(ackFrame->recvdPacketsTimestampRanges.empty());

  EXPECT_EQ(ackFrame->ecnECT0Count, 1);
  EXPECT_EQ(ackFrame->ecnECT1Count, 2);
  EXPECT_EQ(ackFrame->ecnCECount, 3);
}

TEST_F(QuicAckSchedulerTest, AckExtendedNotSentIfNotEnabled) {
  conn_->transportSettings.readEcnOnIngress = true;

  conn_->transportSettings.enableExtendedAckFeatures = 0;
  conn_->peerAdvertisedExtendedAckFeatures = 3; // ECN + ReceiveTimestamps;
  updateNegotiatedAckFeatures(*conn_);

  AckScheduler ackScheduler(*conn_, ackState_);
  ASSERT_TRUE(ackScheduler.hasPendingAcks());

  auto writeResult = ackScheduler.writeNextAcks(*builder_);
  ASSERT_FALSE(writeResult.hasError());
  ASSERT_TRUE(writeResult.value() != none);
  ASSERT_EQ(builder_->frames_.size(), 1);

  auto ackFrame = builder_->frames_[0].asWriteAckFrame();
  ASSERT_TRUE(ackFrame != nullptr);

  EXPECT_EQ(ackFrame->frameType, FrameType::ACK_ECN);

  EXPECT_EQ(ackFrame->ackBlocks.size(), 1);
  EXPECT_EQ(ackFrame->ackBlocks[0].start, 1);
  EXPECT_EQ(ackFrame->ackBlocks[0].end, 10);

  EXPECT_TRUE(ackFrame->recvdPacketsTimestampRanges.empty());

  EXPECT_EQ(ackFrame->ecnECT0Count, 1);
  EXPECT_EQ(ackFrame->ecnECT1Count, 2);
  EXPECT_EQ(ackFrame->ecnCECount, 3);
}

TEST_F(
    QuicAckSchedulerTest,
    AckExtendedNotSentIfReceiveTimestampFeatureNotSupported) {
  conn_->transportSettings.readEcnOnIngress = true;

  conn_->transportSettings.enableExtendedAckFeatures =
      3; // We support ECN + ReceiveTimestamps
  conn_->peerAdvertisedExtendedAckFeatures =
      2; // Peer supports ReceiveTimestamps but not ECN in extended ack
  // Peer sent ART config
  conn_->maybePeerAckReceiveTimestampsConfig = AckReceiveTimestampsConfig();
  // We don't have an ART config (i.e. we can't sent ART)
  conn_->transportSettings.maybeAckReceiveTimestampsConfigSentToPeer = none;
  updateNegotiatedAckFeatures(*conn_);

  AckScheduler ackScheduler(*conn_, ackState_);
  ASSERT_TRUE(ackScheduler.hasPendingAcks());

  auto writeResult = ackScheduler.writeNextAcks(*builder_);
  ASSERT_FALSE(writeResult.hasError());
  ASSERT_TRUE(writeResult.value() != none);
  ASSERT_EQ(builder_->frames_.size(), 1);

  auto ackFrame = builder_->frames_[0].asWriteAckFrame();
  ASSERT_TRUE(ackFrame != nullptr);

  EXPECT_EQ(ackFrame->frameType, FrameType::ACK_ECN);

  EXPECT_EQ(ackFrame->ackBlocks.size(), 1);
  EXPECT_EQ(ackFrame->ackBlocks[0].start, 1);
  EXPECT_EQ(ackFrame->ackBlocks[0].end, 10);

  EXPECT_TRUE(ackFrame->recvdPacketsTimestampRanges.empty());

  EXPECT_EQ(ackFrame->ecnECT0Count, 1);
  EXPECT_EQ(ackFrame->ecnECT1Count, 2);
  EXPECT_EQ(ackFrame->ecnCECount, 3);
}

TEST_F(QuicAckSchedulerTest, AckExtendedNotSentIfECNFeatureNotSupported) {
  conn_->transportSettings.enableExtendedAckFeatures =
      3; // We support ECN + ReceiveTimestamps
  conn_->peerAdvertisedExtendedAckFeatures =
      1; // Peer supports ECN but not ReceiveTimestamps in extended ack

  // ART support negotiated
  conn_->maybePeerAckReceiveTimestampsConfig = AckReceiveTimestampsConfig();
  conn_->transportSettings.maybeAckReceiveTimestampsConfigSentToPeer =
      AckReceiveTimestampsConfig();

  updateNegotiatedAckFeatures(*conn_);

  AckScheduler ackScheduler(*conn_, ackState_);
  ASSERT_TRUE(ackScheduler.hasPendingAcks());

  auto writeResult = ackScheduler.writeNextAcks(*builder_);
  ASSERT_FALSE(writeResult.hasError());
  ASSERT_TRUE(writeResult.value() != none);
  ASSERT_EQ(builder_->frames_.size(), 1);

  auto ackFrame = builder_->frames_[0].asWriteAckFrame();
  ASSERT_TRUE(ackFrame != nullptr);

  EXPECT_EQ(ackFrame->frameType, FrameType::ACK_RECEIVE_TIMESTAMPS);

  EXPECT_EQ(ackFrame->ackBlocks.size(), 1);
  EXPECT_EQ(ackFrame->ackBlocks[0].start, 1);
  EXPECT_EQ(ackFrame->ackBlocks[0].end, 10);

  ASSERT_EQ(ackFrame->recvdPacketsTimestampRanges.size(), 1);
  EXPECT_EQ(ackFrame->recvdPacketsTimestampRanges[0].timestamp_delta_count, 1);

  EXPECT_EQ(ackFrame->ecnECT0Count, 0);
  EXPECT_EQ(ackFrame->ecnECT1Count, 0);
  EXPECT_EQ(ackFrame->ecnCECount, 0);
}

TEST_F(QuicAckSchedulerTest, AckExtendedWithAllFeatures) {
  conn_->transportSettings.enableExtendedAckFeatures =
      3; // We support ECN + ReceiveTimestamps
  conn_->peerAdvertisedExtendedAckFeatures =
      3; // Peer supports ECN + ReceiveTimestamps

  // ART support negotiated
  conn_->maybePeerAckReceiveTimestampsConfig = AckReceiveTimestampsConfig();
  conn_->transportSettings.maybeAckReceiveTimestampsConfigSentToPeer =
      AckReceiveTimestampsConfig();

  // We can read ECN
  conn_->transportSettings.readEcnOnIngress = true;

  updateNegotiatedAckFeatures(*conn_);

  AckScheduler ackScheduler(*conn_, ackState_);
  ASSERT_TRUE(ackScheduler.hasPendingAcks());

  auto writeResult = ackScheduler.writeNextAcks(*builder_);
  ASSERT_FALSE(writeResult.hasError());
  ASSERT_TRUE(writeResult.value() != none);
  ASSERT_EQ(builder_->frames_.size(), 1);

  auto ackFrame = builder_->frames_[0].asWriteAckFrame();
  ASSERT_TRUE(ackFrame != nullptr);

  EXPECT_EQ(ackFrame->frameType, FrameType::ACK_EXTENDED);

  EXPECT_EQ(ackFrame->ackBlocks.size(), 1);
  EXPECT_EQ(ackFrame->ackBlocks[0].start, 1);
  EXPECT_EQ(ackFrame->ackBlocks[0].end, 10);

  ASSERT_EQ(ackFrame->recvdPacketsTimestampRanges.size(), 1);
  EXPECT_EQ(ackFrame->recvdPacketsTimestampRanges[0].timestamp_delta_count, 1);

  EXPECT_EQ(ackFrame->ecnECT0Count, 1);
  EXPECT_EQ(ackFrame->ecnECT1Count, 2);
  EXPECT_EQ(ackFrame->ecnCECount, 3);
}

TEST_F(QuicAckSchedulerTest, AckExtendedTakesPrecedenceOverECN) {
  conn_->transportSettings.enableExtendedAckFeatures =
      3; // We support ECN + ReceiveTimestamps
  conn_->peerAdvertisedExtendedAckFeatures =
      2; // Peer supports extended ack with only ReceiveTimestamps

  // ART support negotiated
  conn_->maybePeerAckReceiveTimestampsConfig = AckReceiveTimestampsConfig();
  conn_->transportSettings.maybeAckReceiveTimestampsConfigSentToPeer =
      AckReceiveTimestampsConfig();

  // We can read ECN
  conn_->transportSettings.readEcnOnIngress = true;

  updateNegotiatedAckFeatures(*conn_);

  AckScheduler ackScheduler(*conn_, ackState_);
  ASSERT_TRUE(ackScheduler.hasPendingAcks());

  auto writeResult = ackScheduler.writeNextAcks(*builder_);
  ASSERT_FALSE(writeResult.hasError());
  ASSERT_TRUE(writeResult.value() != none);
  ASSERT_EQ(builder_->frames_.size(), 1);

  auto ackFrame = builder_->frames_[0].asWriteAckFrame();
  ASSERT_TRUE(ackFrame != nullptr);

  EXPECT_EQ(ackFrame->frameType, FrameType::ACK_EXTENDED);

  EXPECT_EQ(ackFrame->ackBlocks.size(), 1);
  EXPECT_EQ(ackFrame->ackBlocks[0].start, 1);
  EXPECT_EQ(ackFrame->ackBlocks[0].end, 10);

  ASSERT_EQ(ackFrame->recvdPacketsTimestampRanges.size(), 1);
  EXPECT_EQ(ackFrame->recvdPacketsTimestampRanges[0].timestamp_delta_count, 1);

  EXPECT_EQ(ackFrame->ecnECT0Count, 0);
  EXPECT_EQ(ackFrame->ecnECT1Count, 0);
  EXPECT_EQ(ackFrame->ecnCECount, 0);
}

TEST_F(QuicAckSchedulerTest, AckExtendedTakesPrecedenceOverReceiveTimestamps) {
  conn_->transportSettings.enableExtendedAckFeatures =
      3; // We support ECN + ReceiveTimestamps
  conn_->peerAdvertisedExtendedAckFeatures =
      1; // Peer supports extended ack with only ECN

  // ART support negotiated
  conn_->maybePeerAckReceiveTimestampsConfig = AckReceiveTimestampsConfig();
  conn_->transportSettings.maybeAckReceiveTimestampsConfigSentToPeer =
      AckReceiveTimestampsConfig();

  // We can read ECN
  conn_->transportSettings.readEcnOnIngress = true;

  updateNegotiatedAckFeatures(*conn_);

  AckScheduler ackScheduler(*conn_, ackState_);
  ASSERT_TRUE(ackScheduler.hasPendingAcks());

  auto writeResult = ackScheduler.writeNextAcks(*builder_);
  ASSERT_FALSE(writeResult.hasError());
  ASSERT_TRUE(writeResult.value() != none);
  ASSERT_EQ(builder_->frames_.size(), 1);

  auto ackFrame = builder_->frames_[0].asWriteAckFrame();
  ASSERT_TRUE(ackFrame != nullptr);

  EXPECT_EQ(ackFrame->frameType, FrameType::ACK_EXTENDED);

  EXPECT_EQ(ackFrame->ackBlocks.size(), 1);
  EXPECT_EQ(ackFrame->ackBlocks[0].start, 1);
  EXPECT_EQ(ackFrame->ackBlocks[0].end, 10);

  EXPECT_TRUE(ackFrame->recvdPacketsTimestampRanges.empty());

  EXPECT_EQ(ackFrame->ecnECT0Count, 1);
  EXPECT_EQ(ackFrame->ecnECT1Count, 2);
  EXPECT_EQ(ackFrame->ecnCECount, 3);
}

INSTANTIATE_TEST_SUITE_P(
    QuicPacketSchedulerTest,
    QuicPacketSchedulerTest,
    ::testing::Values(false, true));

} // namespace quic::test
