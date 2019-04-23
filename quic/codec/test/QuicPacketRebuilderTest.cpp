/*
 * Copyright (c) Facebook, Inc. and its affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 *
 */

// Copyright 2004-present Facebook.  All rights reserved.

#include <folly/portability/GTest.h>

#include <quic/codec/QuicPacketBuilder.h>
#include <quic/codec/QuicPacketRebuilder.h>
#include <quic/common/test/TestUtils.h>
#include <quic/server/state/ServerStateMachine.h>
#include <quic/state/QuicStateFunctions.h>
#include <quic/state/QuicStreamFunctions.h>
#include <quic/state/StateData.h>
#include <quic/state/stream/StreamStateFunctions.h>

using namespace quic;
using namespace testing;

namespace quic {
namespace test {

OutstandingPacket makeDummyOutstandingPacket(
    const RegularQuicWritePacket& writePacket,
    uint64_t totalBytesSentOnConnection) {
  OutstandingPacket packet(
      writePacket,
      Clock::now(),
      1000,
      false,
      false,
      totalBytesSentOnConnection);
  return packet;
}

class QuicPacketRebuilderTest : public Test {};

TEST_F(QuicPacketRebuilderTest, RebuildEmpty) {
  RegularQuicPacketBuilder regularBuilder(
      kDefaultUDPSendPacketLen,
      PacketHeader(
          ShortHeader(ProtectionType::KeyPhaseZero, getTestConnectionId(), 0)),
      0 /* largestAcked */);
  QuicConnectionStateBase conn(QuicNodeType::Client);
  PacketRebuilder rebuilder(regularBuilder, conn);
  auto packet = std::move(regularBuilder).buildPacket();
  EXPECT_TRUE(packet.packet.frames.empty());
  EXPECT_FALSE(packet.header->empty());
  EXPECT_TRUE(!packet.body);
}

TEST_F(QuicPacketRebuilderTest, RebuildPacket) {
  ShortHeader shortHeader(
      ProtectionType::KeyPhaseZero, getTestConnectionId(), 0);
  RegularQuicPacketBuilder regularBuilder1(
      kDefaultUDPSendPacketLen, shortHeader, 0 /* largestAcked */);

  // Get a bunch frames
  ConnectionCloseFrame connCloseFrame(
      TransportErrorCode::FRAME_ENCODING_ERROR,
      "The sun is in the sky.",
      FrameType::ACK);
  MaxStreamsFrame maxStreamIdFrame(0x1024, true);
  PingFrame pingFrame;
  IntervalSet<PacketNum> ackBlocks;
  ackBlocks.insert(10, 100);
  ackBlocks.insert(200, 1000);
  AckFrameMetaData ackMeta(
      ackBlocks, std::chrono::microseconds(0), kDefaultAckDelayExponent);
  QuicServerConnectionState conn;
  conn.streamManager->setMaxLocalBidirectionalStreams(10);
  auto stream = conn.streamManager->createNextBidirectionalStream().value();
  auto streamId = stream->id;
  auto buf =
      folly::IOBuf::copyBuffer("You can't deny you are looking for the sunset");
  StreamFrameMetaData streamMeta(streamId, 0, true, buf->clone(), true);
  MaxDataFrame maxDataFrame(1000);
  MaxStreamDataFrame maxStreamDataFrame(streamId, 2000);
  uint64_t cryptoOffset = 0;
  auto cryptoBuf = folly::IOBuf::copyBuffer("NewSessionTicket");

  // Write them with a regular builder
  writeFrame(connCloseFrame, regularBuilder1);
  writeFrame(maxStreamIdFrame, regularBuilder1);
  writeFrame(pingFrame, regularBuilder1);
  writeAckFrame(ackMeta, regularBuilder1);
  writeStreamFrame(streamMeta, regularBuilder1);
  writeFrame(maxDataFrame, regularBuilder1);
  writeFrame(maxStreamDataFrame, regularBuilder1);
  writeCryptoFrame(cryptoOffset, cryptoBuf->clone(), regularBuilder1);
  auto packet1 = std::move(regularBuilder1).buildPacket();
  ASSERT_EQ(8, packet1.packet.frames.size());
  stream->retransmissionBuffer.emplace(
      stream->retransmissionBuffer.begin(), buf->clone(), 0, true);
  conn.cryptoState->oneRttStream.retransmissionBuffer.emplace(
      conn.cryptoState->oneRttStream.retransmissionBuffer.begin(),
      cryptoBuf->clone(),
      0,
      true);

  // rebuild a packet from the built out packet
  RegularQuicPacketBuilder regularBuilder2(
      kDefaultUDPSendPacketLen, shortHeader, 0 /* largestAcked */);
  PacketRebuilder rebuilder(regularBuilder2, conn);
  auto outstanding = makeDummyOutstandingPacket(packet1.packet, 1000);
  EXPECT_TRUE(rebuilder.rebuildFromPacket(outstanding).hasValue());
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
    folly::variant_match(
        frame,
        [](const ConnectionCloseFrame& closeFrame) {
          EXPECT_EQ(
              TransportErrorCode::FRAME_ENCODING_ERROR, closeFrame.errorCode);
          EXPECT_EQ("The sun is in the sky.", closeFrame.reasonPhrase);
          EXPECT_EQ(FrameType::ACK, closeFrame.closingFrameType);
        },
        [](const MaxStreamsFrame& maxStreamFrame) {
          EXPECT_EQ(0x1024, maxStreamFrame.maxStreams);
        },
        [](const PingFrame& ping) { EXPECT_EQ(PingFrame(), ping); },
        [](const WriteAckFrame& ack) {
          EXPECT_EQ(Interval<PacketNum>(10, 100), ack.ackBlocks.front());
          EXPECT_EQ(Interval<PacketNum>(200, 1000), ack.ackBlocks.back());
        },
        [&buf, &streamId](const WriteStreamFrame& streamFrame) {
          EXPECT_EQ(streamId, streamFrame.streamId);
          EXPECT_EQ(0, streamFrame.offset);
          EXPECT_EQ(buf->computeChainDataLength(), streamFrame.len);
          EXPECT_EQ(true, streamFrame.fin);
        },
        [&cryptoOffset, &cryptoBuf](const WriteCryptoFrame& frame) {
          EXPECT_EQ(frame.offset, cryptoOffset);
          EXPECT_EQ(frame.len, cryptoBuf->computeChainDataLength());
        },
        [&expectedConnFlowControlValue](const MaxDataFrame& maxData) {
          EXPECT_EQ(expectedConnFlowControlValue, maxData.maximumData);
        },
        [&streamId, &expectedStreamFlowControlValue](
            const MaxStreamDataFrame& maxStreamData) {
          EXPECT_EQ(streamId, maxStreamData.streamId);
          EXPECT_EQ(expectedStreamFlowControlValue, maxStreamData.maximumData);
        },
        [](const auto&) {
          EXPECT_TRUE(false); /* should never happen*/
        });
  }
  EXPECT_TRUE(folly::IOBufEqualTo()(*packet1.header, *packet2.header));
  // TODO: I don't have a good way to verify body without decode them
}

TEST_F(QuicPacketRebuilderTest, RebuildAfterResetStream) {
  ShortHeader shortHeader(
      ProtectionType::KeyPhaseZero, getTestConnectionId(), 0);
  RegularQuicPacketBuilder regularBuilder1(
      kDefaultUDPSendPacketLen, shortHeader, 0 /* largestAcked */);
  QuicServerConnectionState conn;
  conn.streamManager->setMaxLocalBidirectionalStreams(10);
  auto stream = conn.streamManager->createNextBidirectionalStream().value();
  auto streamId = stream->id;
  auto buf = folly::IOBuf::copyBuffer("A million miles away.");
  StreamFrameMetaData streamMeta(streamId, 0, true, buf->clone(), false);
  writeStreamFrame(streamMeta, regularBuilder1);
  auto packet1 = std::move(regularBuilder1).buildPacket();
  ASSERT_EQ(1, packet1.packet.frames.size());

  // Then we reset the stream
  invokeStreamStateMachine(
      conn, *stream, StreamEvents::SendReset(ApplicationErrorCode::STOPPING));
  RegularQuicPacketBuilder regularBuilder2(
      kDefaultUDPSendPacketLen, shortHeader, 0 /* largestAcked */);
  PacketRebuilder rebuilder(regularBuilder2, conn);
  auto outstanding = makeDummyOutstandingPacket(packet1.packet, 1000);
  EXPECT_FALSE(rebuilder.rebuildFromPacket(outstanding).hasValue());
}

TEST_F(QuicPacketRebuilderTest, FinOnlyStreamRebuild) {
  ShortHeader shortHeader(
      ProtectionType::KeyPhaseZero, getTestConnectionId(), 0);
  RegularQuicPacketBuilder regularBuilder1(
      kDefaultUDPSendPacketLen, shortHeader, 0 /* largestAcked */);
  QuicServerConnectionState conn;
  conn.streamManager->setMaxLocalBidirectionalStreams(10);
  auto stream = conn.streamManager->createNextBidirectionalStream().value();
  auto streamId = stream->id;
  StreamFrameMetaData streamMeta(streamId, 0, true, nullptr, true);

  // Write them with a regular builder
  writeStreamFrame(streamMeta, regularBuilder1);
  auto packet1 = std::move(regularBuilder1).buildPacket();
  stream->retransmissionBuffer.emplace(
      stream->retransmissionBuffer.begin(), nullptr, 0, true);

  // rebuild a packet from the built out packet
  RegularQuicPacketBuilder regularBuilder2(
      kDefaultUDPSendPacketLen, shortHeader, 0 /* largestAcked */);
  PacketRebuilder rebuilder(regularBuilder2, conn);
  auto outstanding = makeDummyOutstandingPacket(packet1.packet, 2000);
  EXPECT_TRUE(rebuilder.rebuildFromPacket(outstanding).hasValue());
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
  ShortHeader shortHeader(
      ProtectionType::KeyPhaseZero, getTestConnectionId(), 0);
  RegularQuicPacketBuilder regularBuilder1(
      kDefaultUDPSendPacketLen, shortHeader, 0 /* largestAcked */);

  // Get a bunch frames
  QuicServerConnectionState conn;
  conn.streamManager->setMaxLocalBidirectionalStreams(10);
  auto stream = conn.streamManager->createNextBidirectionalStream().value();
  StreamId streamId = stream->id;
  auto buf =
      folly::IOBuf::copyBuffer("You can't deny you are looking for the sunset");
  StreamFrameMetaData streamMeta(streamId, 0, true, buf->clone(), true);
  uint64_t cryptoOffset = 0;
  auto cryptoBuf = folly::IOBuf::copyBuffer("NewSessionTicket");

  // Write them with a regular builder
  writeStreamFrame(streamMeta, regularBuilder1);
  writeCryptoFrame(cryptoOffset, cryptoBuf->clone(), regularBuilder1);
  auto packet1 = std::move(regularBuilder1).buildPacket();
  ASSERT_EQ(2, packet1.packet.frames.size());
  stream->retransmissionBuffer.emplace(
      stream->retransmissionBuffer.begin(), buf->clone(), 0, true);
  // Do not add the buf to crypto stream's retransmission buffer,
  // imagine it was cleared

  // rebuild a packet from the built out packet
  RegularQuicPacketBuilder regularBuilder2(
      kDefaultUDPSendPacketLen, shortHeader, 0 /* largestAcked */);
  PacketRebuilder rebuilder(regularBuilder2, conn);
  auto outstanding = makeDummyOutstandingPacket(packet1.packet, 1000);
  EXPECT_TRUE(rebuilder.rebuildFromPacket(outstanding).hasValue());
  auto packet2 = std::move(regularBuilder2).buildPacket();
  // rebuilder writes frames to regularBuilder2
  EXPECT_EQ(packet1.packet.frames.size(), packet2.packet.frames.size() + 1);
  for (const auto& frame : packet2.packet.frames) {
    folly::variant_match(
        frame,
        [&buf, &streamId](const WriteStreamFrame& streamFrame) {
          EXPECT_EQ(streamId, streamFrame.streamId);
          EXPECT_EQ(0, streamFrame.offset);
          EXPECT_EQ(buf->computeChainDataLength(), streamFrame.len);
          EXPECT_EQ(true, streamFrame.fin);
        },
        [](const auto&) {
          EXPECT_TRUE(false); /* should never happen*/
        });
  }
  EXPECT_TRUE(folly::IOBufEqualTo()(*packet1.header, *packet2.header));
}

TEST_F(QuicPacketRebuilderTest, CannotRebuildEmptyCryptoStream) {
  ShortHeader shortHeader(
      ProtectionType::KeyPhaseZero, getTestConnectionId(), 0);
  RegularQuicPacketBuilder regularBuilder1(
      kDefaultUDPSendPacketLen, shortHeader, 0 /* largestAcked */);

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
  RegularQuicPacketBuilder regularBuilder2(
      kDefaultUDPSendPacketLen, shortHeader, 0 /* largestAcked */);
  PacketRebuilder rebuilder(regularBuilder2, conn);
  auto outstanding = makeDummyOutstandingPacket(packet1.packet, 1000);
  EXPECT_FALSE(rebuilder.rebuildFromPacket(outstanding).hasValue());
}

TEST_F(QuicPacketRebuilderTest, CannotRebuild) {
  ShortHeader shortHeader(
      ProtectionType::KeyPhaseZero, getTestConnectionId(), 0);
  RegularQuicPacketBuilder regularBuilder1(
      kDefaultUDPSendPacketLen, shortHeader, 0 /* largestAcked */);

  // Get a bunch frames
  ConnectionCloseFrame connCloseFrame(
      TransportErrorCode::FRAME_ENCODING_ERROR,
      "The sun is in the sky.",
      FrameType::ACK);
  StreamsBlockedFrame maxStreamIdFrame(0x1024, true);
  PingFrame pingFrame;
  IntervalSet<PacketNum> ackBlocks;
  ackBlocks.insert(10, 100);
  ackBlocks.insert(200, 1000);
  AckFrameMetaData ackMeta(
      ackBlocks, std::chrono::microseconds(0), kDefaultAckDelayExponent);
  QuicServerConnectionState conn;
  conn.streamManager->setMaxLocalBidirectionalStreams(10);
  auto stream = conn.streamManager->createNextBidirectionalStream().value();
  auto streamId = stream->id;
  auto buf =
      folly::IOBuf::copyBuffer("You can't deny you are looking for the sunset");
  StreamFrameMetaData streamMeta(streamId, 0, true, buf->clone(), true);

  // Write them with a regular builder
  writeFrame(connCloseFrame, regularBuilder1);
  writeFrame(maxStreamIdFrame, regularBuilder1);
  writeFrame(pingFrame, regularBuilder1);
  writeAckFrame(ackMeta, regularBuilder1);
  writeStreamFrame(streamMeta, regularBuilder1);
  auto packet1 = std::move(regularBuilder1).buildPacket();
  ASSERT_EQ(5, packet1.packet.frames.size());
  stream->retransmissionBuffer.emplace(
      stream->retransmissionBuffer.begin(), buf->clone(), 0, true);

  // new builder has a much smaller writable bytes limit
  RegularQuicPacketBuilder regularBuilder2(
      (packet1.header->computeChainDataLength() +
       packet1.body->computeChainDataLength()) /
          2,
      shortHeader,
      0 /* largestAcked */);
  PacketRebuilder rebuilder(regularBuilder2, conn);
  auto outstanding = makeDummyOutstandingPacket(packet1.packet, 1000);
  EXPECT_FALSE(rebuilder.rebuildFromPacket(outstanding).hasValue());
}

TEST_F(QuicPacketRebuilderTest, CloneCounter) {
  ShortHeader shortHeader(
      ProtectionType::KeyPhaseZero, getTestConnectionId(), 0);
  RegularQuicPacketBuilder regularBuilder(
      kDefaultUDPSendPacketLen, shortHeader, 0 /* largestAcked */);
  PingFrame pingFrame;
  writeFrame(pingFrame, regularBuilder);
  auto packet = std::move(regularBuilder).buildPacket();
  auto outstandingPacket = makeDummyOutstandingPacket(packet.packet, 1000);
  QuicServerConnectionState conn;
  RegularQuicPacketBuilder regularBuilder2(
      kDefaultUDPSendPacketLen, shortHeader, 0 /* largestAcked */);
  PacketRebuilder rebuilder(regularBuilder2, conn);
  rebuilder.rebuildFromPacket(outstandingPacket);
  EXPECT_TRUE(outstandingPacket.associatedEvent.hasValue());
  EXPECT_EQ(1, conn.outstandingClonedPacketsCount);
}

} // namespace test
} // namespace quic
