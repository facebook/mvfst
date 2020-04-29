/*
 * Copyright (c) Facebook, Inc. and its affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 *
 */

#include <folly/portability/GTest.h>

#include <quic/codec/QuicPacketBuilder.h>
#include <quic/codec/QuicPacketRebuilder.h>
#include <quic/common/test/TestUtils.h>
#include <quic/server/state/ServerStateMachine.h>
#include <quic/state/QuicStateFunctions.h>
#include <quic/state/QuicStreamFunctions.h>
#include <quic/state/StateData.h>
#include <quic/state/stream/StreamSendHandlers.h>
#include <quic/state/stream/StreamStateFunctions.h>

using namespace testing;

namespace quic {
namespace test {

OutstandingPacket makeDummyOutstandingPacket(
    const RegularQuicWritePacket& writePacket,
    uint64_t totalBytesSentOnConnection) {
  OutstandingPacket packet(
      writePacket, Clock::now(), 1000, false, totalBytesSentOnConnection);
  return packet;
}

class QuicPacketRebuilderTest : public Test {};

TEST_F(QuicPacketRebuilderTest, RebuildEmpty) {
  RegularQuicPacketBuilder regularBuilder(
      kDefaultUDPSendPacketLen,
      ShortHeader(ProtectionType::KeyPhaseZero, getTestConnectionId(), 0),
      0 /* largestAcked */);
  regularBuilder.encodePacketHeader();
  QuicConnectionStateBase conn(QuicNodeType::Client);
  PacketRebuilder rebuilder(regularBuilder, conn);
  auto packet = std::move(regularBuilder).buildPacket();
  EXPECT_TRUE(packet.packet.frames.empty());
  EXPECT_FALSE(packet.header->empty());
  EXPECT_TRUE(packet.body->empty());
}

TEST_F(QuicPacketRebuilderTest, RebuildPacket) {
  ShortHeader shortHeader1(
      ProtectionType::KeyPhaseZero, getTestConnectionId(), 0);
  RegularQuicPacketBuilder regularBuilder1(
      kDefaultUDPSendPacketLen, std::move(shortHeader1), 0 /* largestAcked */);
  regularBuilder1.encodePacketHeader();
  // Get a bunch frames
  ConnectionCloseFrame connCloseFrame(
      QuicErrorCode(TransportErrorCode::FRAME_ENCODING_ERROR),
      "The sun is in the sky.",
      FrameType::ACK);
  MaxStreamsFrame maxStreamsFrame(4321, true);
  AckBlocks ackBlocks;
  ackBlocks.insert(10, 100);
  ackBlocks.insert(200, 1000);
  AckFrameMetaData ackMeta(ackBlocks, 0us, kDefaultAckDelayExponent);
  QuicServerConnectionState conn;
  conn.streamManager->setMaxLocalBidirectionalStreams(10);
  auto stream = conn.streamManager->createNextBidirectionalStream().value();
  auto streamId = stream->id;
  auto buf =
      folly::IOBuf::copyBuffer("You can't deny you are looking for the sunset");
  MaxDataFrame maxDataFrame(1000);
  MaxStreamDataFrame maxStreamDataFrame(streamId, 2000);
  uint64_t cryptoOffset = 0;
  auto cryptoBuf = folly::IOBuf::copyBuffer("NewSessionTicket");

  PingFrame pingFrame{};
  // Write them with a regular builder
  writeFrame(connCloseFrame, regularBuilder1);
  writeFrame(QuicSimpleFrame(maxStreamsFrame), regularBuilder1);
  writeFrame(QuicSimpleFrame(pingFrame), regularBuilder1);
  writeAckFrame(ackMeta, regularBuilder1);
  writeStreamFrameHeader(
      regularBuilder1,
      streamId,
      0,
      buf->computeChainDataLength(),
      buf->computeChainDataLength(),
      true);
  writeStreamFrameData(
      regularBuilder1, buf->clone(), buf->computeChainDataLength());
  writeFrame(maxDataFrame, regularBuilder1);
  writeFrame(maxStreamDataFrame, regularBuilder1);
  writeCryptoFrame(cryptoOffset, cryptoBuf->clone(), regularBuilder1);
  auto packet1 = std::move(regularBuilder1).buildPacket();
  ASSERT_EQ(8, packet1.packet.frames.size());
  stream->retransmissionBuffer.emplace(
      std::piecewise_construct,
      std::forward_as_tuple(0),
      std::forward_as_tuple(
          std::make_unique<StreamBuffer>(buf->clone(), 0, true)));
  conn.cryptoState->oneRttStream.retransmissionBuffer.emplace(
      std::piecewise_construct,
      std::forward_as_tuple(0),
      std::forward_as_tuple(
          std::make_unique<StreamBuffer>(cryptoBuf->clone(), 0, true)));

  // rebuild a packet from the built out packet
  ShortHeader shortHeader2(
      ProtectionType::KeyPhaseZero, getTestConnectionId(), 0);
  RegularQuicPacketBuilder regularBuilder2(
      kDefaultUDPSendPacketLen, std::move(shortHeader2), 0 /* largestAcked */);
  regularBuilder2.encodePacketHeader();
  PacketRebuilder rebuilder(regularBuilder2, conn);
  auto outstanding = makeDummyOutstandingPacket(packet1.packet, 1000);
  EXPECT_TRUE(rebuilder.rebuildFromPacket(outstanding).has_value());
  auto packet2 = std::move(regularBuilder2).buildPacket();
  // rebuilder writes frames to regularBuilder2
  EXPECT_EQ(packet1.packet.frames.size(), packet2.packet.frames.size());
  auto expectedConnFlowControlValue = std::max(
      conn.flowControlState.sumCurReadOffset + conn.flowControlState.windowSize,
      conn.flowControlState.advertisedMaxOffset);
  auto expectedStreamFlowControlValue = std::max(
      stream->currentReadOffset + stream->flowControlState.windowSize,
      stream->flowControlState.advertisedMaxOffset);
  for (const auto& frame : packet2.packet.frames) {
    switch (frame.type()) {
      case QuicWriteFrame::Type::ConnectionCloseFrame_E: {
        const ConnectionCloseFrame& closeFrame =
            *frame.asConnectionCloseFrame();
        const TransportErrorCode* transportErrorCode =
            closeFrame.errorCode.asTransportErrorCode();
        EXPECT_EQ(
            TransportErrorCode::FRAME_ENCODING_ERROR, *transportErrorCode);
        EXPECT_EQ("The sun is in the sky.", closeFrame.reasonPhrase);
        EXPECT_EQ(FrameType::ACK, closeFrame.closingFrameType);
        break;
      }
      case QuicWriteFrame::Type::QuicSimpleFrame_E: {
        const QuicSimpleFrame& simpleFrame = *frame.asQuicSimpleFrame();
        switch (simpleFrame.type()) {
          case QuicSimpleFrame::Type::MaxStreamsFrame_E: {
            const MaxStreamsFrame* maxStreamFrame =
                simpleFrame.asMaxStreamsFrame();
            EXPECT_NE(maxStreamFrame, nullptr);
            EXPECT_EQ(4321, maxStreamFrame->maxStreams);
            break;
          }
          case QuicSimpleFrame::Type::PingFrame_E: {
            const PingFrame* simplePingFrame = simpleFrame.asPingFrame();
            EXPECT_NE(simplePingFrame, nullptr);
            break;
          }
          default:
            EXPECT_TRUE(false); /* fail if this happens */
        }
        break;
      }
      case QuicWriteFrame::Type::WriteAckFrame_E: {
        const WriteAckFrame& ack = *frame.asWriteAckFrame();
        EXPECT_EQ(Interval<PacketNum>(10, 100), ack.ackBlocks.back());
        EXPECT_EQ(Interval<PacketNum>(200, 1000), ack.ackBlocks.front());
        break;
      }
      case QuicWriteFrame::Type::WriteStreamFrame_E: {
        const WriteStreamFrame& streamFrame = *frame.asWriteStreamFrame();
        EXPECT_EQ(streamId, streamFrame.streamId);
        EXPECT_EQ(0, streamFrame.offset);
        EXPECT_EQ(buf->computeChainDataLength(), streamFrame.len);
        EXPECT_EQ(true, streamFrame.fin);
        break;
      }
      case QuicWriteFrame::Type::WriteCryptoFrame_E: {
        const WriteCryptoFrame& cryptoFrame = *frame.asWriteCryptoFrame();
        EXPECT_EQ(cryptoFrame.offset, cryptoOffset);
        EXPECT_EQ(cryptoFrame.len, cryptoBuf->computeChainDataLength());
        break;
      }
      case QuicWriteFrame::Type::MaxDataFrame_E: {
        const MaxDataFrame& maxData = *frame.asMaxDataFrame();
        EXPECT_EQ(expectedConnFlowControlValue, maxData.maximumData);
        break;
      }
      case QuicWriteFrame::Type::MaxStreamDataFrame_E: {
        const MaxStreamDataFrame& maxStreamData = *frame.asMaxStreamDataFrame();
        EXPECT_EQ(streamId, maxStreamData.streamId);
        EXPECT_EQ(expectedStreamFlowControlValue, maxStreamData.maximumData);
        break;
      }
      default:
        EXPECT_TRUE(false); /* should never happen*/
    }
  }
  EXPECT_TRUE(folly::IOBufEqualTo()(*packet1.header, *packet2.header));
  // TODO: I don't have a good way to verify body without decode them
}

TEST_F(QuicPacketRebuilderTest, RebuildAfterResetStream) {
  ShortHeader shortHeader1(
      ProtectionType::KeyPhaseZero, getTestConnectionId(), 0);
  RegularQuicPacketBuilder regularBuilder1(
      kDefaultUDPSendPacketLen, std::move(shortHeader1), 0 /* largestAcked */);
  regularBuilder1.encodePacketHeader();
  QuicServerConnectionState conn;
  conn.streamManager->setMaxLocalBidirectionalStreams(10);
  auto stream = conn.streamManager->createNextBidirectionalStream().value();
  auto streamId = stream->id;
  auto buf = folly::IOBuf::copyBuffer("A million miles away.");
  writeStreamFrameHeader(
      regularBuilder1,
      streamId,
      0,
      buf->computeChainDataLength(),
      buf->computeChainDataLength(),
      true);
  writeStreamFrameData(
      regularBuilder1, buf->clone(), buf->computeChainDataLength());
  auto packet1 = std::move(regularBuilder1).buildPacket();
  ASSERT_EQ(1, packet1.packet.frames.size());

  // Then we reset the stream
  sendRstSMHandler(*stream, GenericApplicationErrorCode::UNKNOWN);
  ShortHeader shortHeader2(
      ProtectionType::KeyPhaseZero, getTestConnectionId(), 0);
  RegularQuicPacketBuilder regularBuilder2(
      kDefaultUDPSendPacketLen, std::move(shortHeader2), 0 /* largestAcked */);
  regularBuilder2.encodePacketHeader();
  PacketRebuilder rebuilder(regularBuilder2, conn);
  auto outstanding = makeDummyOutstandingPacket(packet1.packet, 1000);
  EXPECT_FALSE(rebuilder.rebuildFromPacket(outstanding).has_value());
}

TEST_F(QuicPacketRebuilderTest, FinOnlyStreamRebuild) {
  ShortHeader shortHeader1(
      ProtectionType::KeyPhaseZero, getTestConnectionId(), 0);
  RegularQuicPacketBuilder regularBuilder1(
      kDefaultUDPSendPacketLen, std::move(shortHeader1), 0 /* largestAcked */);
  regularBuilder1.encodePacketHeader();
  QuicServerConnectionState conn;
  conn.streamManager->setMaxLocalBidirectionalStreams(10);
  auto stream = conn.streamManager->createNextBidirectionalStream().value();
  auto streamId = stream->id;

  // Write them with a regular builder
  writeStreamFrameHeader(regularBuilder1, streamId, 0, 0, 0, true);
  auto packet1 = std::move(regularBuilder1).buildPacket();
  stream->retransmissionBuffer.emplace(
      std::piecewise_construct,
      std::forward_as_tuple(0),
      std::forward_as_tuple(std::make_unique<StreamBuffer>(nullptr, 0, true)));

  // rebuild a packet from the built out packet
  ShortHeader shortHeader2(
      ProtectionType::KeyPhaseZero, getTestConnectionId(), 0);
  RegularQuicPacketBuilder regularBuilder2(
      kDefaultUDPSendPacketLen, std::move(shortHeader2), 0 /* largestAcked */);
  regularBuilder2.encodePacketHeader();
  PacketRebuilder rebuilder(regularBuilder2, conn);
  auto outstanding = makeDummyOutstandingPacket(packet1.packet, 2000);
  EXPECT_TRUE(rebuilder.rebuildFromPacket(outstanding).has_value());
  auto packet2 = std::move(regularBuilder2).buildPacket();
  EXPECT_EQ(packet1.packet.frames.size(), packet2.packet.frames.size());
  EXPECT_TRUE(
      0 ==
      memcmp(
          packet1.packet.frames.data(),
          packet2.packet.frames.data(),
          packet1.packet.frames.size()));
  EXPECT_TRUE(folly::IOBufEqualTo()(*packet1.header, *packet2.header));
  // Once we start to use the correct ack delay value in AckFrames, this needs
  // to be changed:
  EXPECT_TRUE(folly::IOBufEqualTo()(*packet1.body, *packet2.body));
}

TEST_F(QuicPacketRebuilderTest, RebuildDataStreamAndEmptyCryptoStream) {
  ShortHeader shortHeader1(
      ProtectionType::KeyPhaseZero, getTestConnectionId(), 0);
  RegularQuicPacketBuilder regularBuilder1(
      kDefaultUDPSendPacketLen, std::move(shortHeader1), 0 /* largestAcked */);
  regularBuilder1.encodePacketHeader();
  // Get a bunch frames
  QuicServerConnectionState conn;
  conn.streamManager->setMaxLocalBidirectionalStreams(10);
  auto stream = conn.streamManager->createNextBidirectionalStream().value();
  StreamId streamId = stream->id;
  auto buf =
      folly::IOBuf::copyBuffer("You can't deny you are looking for the sunset");
  uint64_t cryptoOffset = 0;
  auto cryptoBuf = folly::IOBuf::copyBuffer("NewSessionTicket");

  // Write them with a regular builder
  writeStreamFrameHeader(
      regularBuilder1,
      streamId,
      0,
      buf->computeChainDataLength(),
      buf->computeChainDataLength(),
      true);
  writeStreamFrameData(
      regularBuilder1, buf->clone(), buf->computeChainDataLength());
  writeCryptoFrame(cryptoOffset, cryptoBuf->clone(), regularBuilder1);
  auto packet1 = std::move(regularBuilder1).buildPacket();
  ASSERT_EQ(2, packet1.packet.frames.size());
  stream->retransmissionBuffer.emplace(
      std::piecewise_construct,
      std::forward_as_tuple(0),
      std::forward_as_tuple(
          std::make_unique<StreamBuffer>(buf->clone(), 0, true)));
  // Do not add the buf to crypto stream's retransmission buffer,
  // imagine it was cleared

  // rebuild a packet from the built out packet
  ShortHeader shortHeader2(
      ProtectionType::KeyPhaseZero, getTestConnectionId(), 0);
  RegularQuicPacketBuilder regularBuilder2(
      kDefaultUDPSendPacketLen, std::move(shortHeader2), 0 /* largestAcked */);
  regularBuilder2.encodePacketHeader();
  PacketRebuilder rebuilder(regularBuilder2, conn);
  auto outstanding = makeDummyOutstandingPacket(packet1.packet, 1000);
  EXPECT_TRUE(rebuilder.rebuildFromPacket(outstanding).has_value());
  auto packet2 = std::move(regularBuilder2).buildPacket();
  // rebuilder writes frames to regularBuilder2
  EXPECT_EQ(packet1.packet.frames.size(), packet2.packet.frames.size() + 1);
  for (const auto& frame : packet2.packet.frames) {
    const WriteStreamFrame* streamFrame = frame.asWriteStreamFrame();
    if (!streamFrame) {
      EXPECT_TRUE(false); /* should never happen*/
    }
    EXPECT_EQ(streamId, streamFrame->streamId);
    EXPECT_EQ(0, streamFrame->offset);
    EXPECT_EQ(buf->computeChainDataLength(), streamFrame->len);
    EXPECT_EQ(true, streamFrame->fin);
  }
  EXPECT_TRUE(folly::IOBufEqualTo()(*packet1.header, *packet2.header));
}

TEST_F(QuicPacketRebuilderTest, CannotRebuildEmptyCryptoStream) {
  ShortHeader shortHeader1(
      ProtectionType::KeyPhaseZero, getTestConnectionId(), 0);
  RegularQuicPacketBuilder regularBuilder1(
      kDefaultUDPSendPacketLen, std::move(shortHeader1), 0 /* largestAcked */);
  regularBuilder1.encodePacketHeader();
  // Get a bunch frames
  QuicServerConnectionState conn;
  uint64_t cryptoOffset = 0;
  auto cryptoBuf = folly::IOBuf::copyBuffer("NewSessionTicket");

  // Write them with a regular builder
  writeCryptoFrame(cryptoOffset, cryptoBuf->clone(), regularBuilder1);
  auto packet1 = std::move(regularBuilder1).buildPacket();
  ASSERT_EQ(1, packet1.packet.frames.size());
  // Do not add the buf to crypto stream's retransmission buffer,
  // imagine it was cleared

  // rebuild a packet from the built out packet
  ShortHeader shortHeader2(
      ProtectionType::KeyPhaseZero, getTestConnectionId(), 0);
  RegularQuicPacketBuilder regularBuilder2(
      kDefaultUDPSendPacketLen, std::move(shortHeader2), 0 /* largestAcked */);
  regularBuilder2.encodePacketHeader();
  PacketRebuilder rebuilder(regularBuilder2, conn);
  auto outstanding = makeDummyOutstandingPacket(packet1.packet, 1000);
  EXPECT_FALSE(rebuilder.rebuildFromPacket(outstanding).has_value());
}

TEST_F(QuicPacketRebuilderTest, CannotRebuild) {
  ShortHeader shortHeader1(
      ProtectionType::KeyPhaseZero, getTestConnectionId(), 0);
  RegularQuicPacketBuilder regularBuilder1(
      kDefaultUDPSendPacketLen, std::move(shortHeader1), 0 /* largestAcked */);
  regularBuilder1.encodePacketHeader();
  // Get a bunch frames
  ConnectionCloseFrame connCloseFrame(
      QuicErrorCode(TransportErrorCode::FRAME_ENCODING_ERROR),
      "The sun is in the sky.",
      FrameType::ACK);
  StreamsBlockedFrame maxStreamIdFrame(0x1024, true);
  AckBlocks ackBlocks;
  ackBlocks.insert(10, 100);
  ackBlocks.insert(200, 1000);
  AckFrameMetaData ackMeta(ackBlocks, 0us, kDefaultAckDelayExponent);
  QuicServerConnectionState conn;
  conn.streamManager->setMaxLocalBidirectionalStreams(10);
  auto stream = conn.streamManager->createNextBidirectionalStream().value();
  auto streamId = stream->id;
  auto buf =
      folly::IOBuf::copyBuffer("You can't deny you are looking for the sunset");
  PingFrame pingFrame;
  // Write them with a regular builder
  writeFrame(connCloseFrame, regularBuilder1);
  writeFrame(maxStreamIdFrame, regularBuilder1);
  writeFrame(QuicSimpleFrame(pingFrame), regularBuilder1);
  writeAckFrame(ackMeta, regularBuilder1);
  writeStreamFrameHeader(
      regularBuilder1,
      streamId,
      0,
      buf->computeChainDataLength(),
      buf->computeChainDataLength(),
      true);
  writeStreamFrameData(
      regularBuilder1, buf->clone(), buf->computeChainDataLength());
  auto packet1 = std::move(regularBuilder1).buildPacket();
  ASSERT_EQ(5, packet1.packet.frames.size());
  stream->retransmissionBuffer.emplace(
      std::piecewise_construct,
      std::forward_as_tuple(0),
      std::forward_as_tuple(
          std::make_unique<StreamBuffer>(buf->clone(), 0, true)));

  // new builder has a much smaller writable bytes limit
  ShortHeader shortHeader2(
      ProtectionType::KeyPhaseZero, getTestConnectionId(), 0);
  RegularQuicPacketBuilder regularBuilder2(
      (packet1.header->computeChainDataLength() +
       packet1.body->computeChainDataLength()) /
          2,
      std::move(shortHeader2),
      0 /* largestAcked */);
  regularBuilder2.encodePacketHeader();
  PacketRebuilder rebuilder(regularBuilder2, conn);
  auto outstanding = makeDummyOutstandingPacket(packet1.packet, 1000);
  EXPECT_FALSE(rebuilder.rebuildFromPacket(outstanding).has_value());
}

TEST_F(QuicPacketRebuilderTest, CloneCounter) {
  ShortHeader shortHeader1(
      ProtectionType::KeyPhaseZero, getTestConnectionId(), 0);
  RegularQuicPacketBuilder regularBuilder(
      kDefaultUDPSendPacketLen, std::move(shortHeader1), 0 /* largestAcked */);
  regularBuilder.encodePacketHeader();
  PingFrame pingFrame;
  writeFrame(QuicSimpleFrame(pingFrame), regularBuilder);
  auto packet = std::move(regularBuilder).buildPacket();
  auto outstandingPacket = makeDummyOutstandingPacket(packet.packet, 1000);
  QuicServerConnectionState conn;
  ShortHeader shortHeader2(
      ProtectionType::KeyPhaseZero, getTestConnectionId(), 0);
  RegularQuicPacketBuilder regularBuilder2(
      kDefaultUDPSendPacketLen, std::move(shortHeader2), 0 /* largestAcked */);
  regularBuilder2.encodePacketHeader();
  PacketRebuilder rebuilder(regularBuilder2, conn);
  rebuilder.rebuildFromPacket(outstandingPacket);
  EXPECT_TRUE(outstandingPacket.associatedEvent.has_value());
  EXPECT_EQ(1, conn.outstandingClonedPacketsCount);
}

} // namespace test
} // namespace quic
