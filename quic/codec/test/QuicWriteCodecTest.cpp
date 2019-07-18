/*
 * Copyright (c) Facebook, Inc. and its affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 *
 */

#include <quic/codec/QuicWriteCodec.h>
#include <folly/Random.h>
#include <folly/io/Cursor.h>
#include <folly/io/IOBufQueue.h>
#include <folly/portability/GMock.h>
#include <folly/portability/GTest.h>
#include <quic/QuicException.h>
#include <quic/codec/Decode.h>
#include <quic/codec/Types.h>
#include <quic/codec/test/Mocks.h>
#include <quic/common/test/TestUtils.h>

using namespace quic;
using namespace quic::test;
using namespace testing;
using namespace std::chrono;

ShortHeader buildTestShortHeader() {
  return ShortHeader(ProtectionType::KeyPhaseZero, getTestConnectionId(), 0x01);
}

QuicFrame parseQuicFrame(folly::io::Cursor& cursor) {
  return quic::parseFrame(
      cursor,
      buildTestShortHeader(),
      CodecParameters(kDefaultAckDelayExponent, QuicVersion::MVFST));
}

namespace quic {
namespace test {

void setupCommonExpects(MockQuicPacketBuilder& pktBuilder) {
  EXPECT_CALL(pktBuilder, remainingSpaceInPkt()).WillRepeatedly(Invoke([&]() {
    return pktBuilder.remaining_;
  }));

  EXPECT_CALL(pktBuilder, writeBEUint8(_))
      .WillRepeatedly(WithArgs<0>(Invoke([&](uint8_t value) {
        pktBuilder.appender_.writeBE<uint8_t>(value);
        pktBuilder.remaining_ -= sizeof(uint8_t);
      })));

  EXPECT_CALL(pktBuilder, writeBEUint16(_))
      .WillRepeatedly(WithArgs<0>(Invoke([&](uint16_t value) {
        pktBuilder.appender_.writeBE<uint16_t>(value);
        pktBuilder.remaining_ -= sizeof(uint16_t);
      })));

  EXPECT_CALL(pktBuilder, writeBEUint64(_))
      .WillRepeatedly(WithArgs<0>(Invoke([&](uint64_t value) {
        pktBuilder.appender_.writeBE<uint64_t>(value);
        pktBuilder.remaining_ -= sizeof(uint64_t);
      })));

  EXPECT_CALL(pktBuilder, appendBytes(_, _))
      .WillRepeatedly(
          WithArgs<0, 1>(Invoke([&](PacketNum value, uint8_t byteNumber) {
            pktBuilder.appendBytes(pktBuilder.appender_, value, byteNumber);
          })));
  EXPECT_CALL(pktBuilder, appendBytes(_, _, _))
      .WillRepeatedly((Invoke([&](folly::io::QueueAppender& appender,
                                  PacketNum value,
                                  uint8_t byteNumber) {
        appender.ensure(byteNumber);
        auto bigValue = folly::Endian::big(value);
        appender.push(
            (uint8_t*)&bigValue + sizeof(bigValue) - byteNumber, byteNumber);
        pktBuilder.remaining_ -= byteNumber;
      })));

  EXPECT_CALL(pktBuilder, appendFrame(_))
      .WillRepeatedly(WithArgs<0>(
          Invoke([&](auto frame) { pktBuilder.frames_.push_back(frame); })));

  EXPECT_CALL(pktBuilder, _insert(_))
      .WillRepeatedly(WithArgs<0>(Invoke([&](Buf& buf) {
        pktBuilder.remaining_ -= buf->computeChainDataLength();
        pktBuilder.appender_.insert(std::move(buf));
      })));

  EXPECT_CALL(pktBuilder, push(_, _))
      .WillRepeatedly(
          WithArgs<0, 1>(Invoke([&](const uint8_t* data, size_t len) {
            pktBuilder.appender_.push(data, len);
            pktBuilder.remaining_ -= len;
          })));

  EXPECT_CALL(pktBuilder, write(_))
      .WillRepeatedly(Invoke([&](const QuicInteger& quicInteger) {
        quicInteger.encode(pktBuilder.appender_);
        pktBuilder.remaining_ -= quicInteger.getSize();
      }));
}

class QuicWriteCodecTest : public Test {};

TEST_F(QuicWriteCodecTest, WriteStreamFrameToEmptyPacket) {
  MockQuicPacketBuilder pktBuilder;
  setupCommonExpects(pktBuilder);

  auto inputBuf = buildRandomInputData(10);

  // 1 byte for type
  // 1 byte for stream id
  // 1 byte for length
  // => 3 bytes
  StreamId streamId = 1;
  uint64_t offset = 0;
  bool fin = false;
  bool hasMoreFrames = true;
  StreamFrameMetaData streamFrameMetaData(
      streamId, offset, fin, inputBuf->clone(), hasMoreFrames);
  auto streamFrameWriteResult =
      writeStreamFrame(streamFrameMetaData, pktBuilder);
  auto outputBuf = std::move(streamFrameWriteResult->writtenData);
  EXPECT_EQ(10, outputBuf->computeChainDataLength());
  EXPECT_EQ(10, streamFrameWriteResult->bytesWritten);
  EXPECT_EQ(
      kDefaultUDPSendPacketLen - 3 - 10, pktBuilder.remainingSpaceInPkt());
  auto builtOut = std::move(pktBuilder).buildPacket();
  auto regularPacket = builtOut.first;

  EXPECT_EQ(regularPacket.frames.size(), 1);
  auto resultFrame = boost::get<WriteStreamFrame>(regularPacket.frames.back());
  EXPECT_EQ(resultFrame.streamId, streamId);
  EXPECT_EQ(resultFrame.offset, offset);
  EXPECT_EQ(resultFrame.len, 10);
  EXPECT_TRUE(folly::IOBufEqualTo()(inputBuf, outputBuf));

  auto wireBuf = std::move(builtOut.second);
  folly::io::Cursor cursor(wireBuf.get());
  auto decodedStreamFrame = boost::get<ReadStreamFrame>(parseQuicFrame(cursor));
  EXPECT_EQ(decodedStreamFrame.streamId, streamId);
  EXPECT_EQ(decodedStreamFrame.offset, offset);
  EXPECT_EQ(decodedStreamFrame.data->computeChainDataLength(), 10);
  EXPECT_TRUE(folly::IOBufEqualTo()(inputBuf, decodedStreamFrame.data));
}

TEST_F(QuicWriteCodecTest, WriteStreamFrameToPartialPacket) {
  MockQuicPacketBuilder pktBuilder;
  // 1000 bytes already gone in this packet
  pktBuilder.remaining_ = kDefaultUDPSendPacketLen - 1000;
  setupCommonExpects(pktBuilder);

  StreamId streamId = 200;
  uint64_t offset = 65535;
  bool fin = false;
  bool hasMoreFrames = false;

  auto inputBuf = buildRandomInputData(20);
  // 1 byte for type
  // 2 bytes for stream id
  // 4 bytes offset
  // => 7 bytes of header
  StreamFrameMetaData streamFrameMetaData(
      streamId, offset, fin, inputBuf->clone(), hasMoreFrames);
  auto streamFrameWriteResult =
      writeStreamFrame(streamFrameMetaData, pktBuilder);
  auto outputBuf = std::move(streamFrameWriteResult->writtenData);
  EXPECT_EQ(20, outputBuf->computeChainDataLength());
  EXPECT_EQ(20, streamFrameWriteResult->bytesWritten);
  size_t consumedSize = 1000 + 7 + 20;
  EXPECT_EQ(
      kDefaultUDPSendPacketLen - consumedSize,
      pktBuilder.remainingSpaceInPkt());

  auto builtOut = std::move(pktBuilder).buildPacket();
  auto regularPacket = builtOut.first;
  EXPECT_EQ(regularPacket.frames.size(), 1);
  auto resultFrame = boost::get<WriteStreamFrame>(regularPacket.frames.back());
  EXPECT_EQ(resultFrame.streamId, streamId);
  EXPECT_EQ(resultFrame.offset, offset);
  EXPECT_EQ(resultFrame.len, 20);
  EXPECT_TRUE(folly::IOBufEqualTo()(inputBuf, outputBuf));

  // Verify the on wire bytes via decoder:
  // (Awkwardly, this assumes the decoder is correct)
  auto wireBuf = std::move(builtOut.second);
  folly::io::Cursor cursor(wireBuf.get());
  auto decodedStreamFrame = boost::get<ReadStreamFrame>(parseQuicFrame(cursor));
  EXPECT_EQ(decodedStreamFrame.streamId, streamId);
  EXPECT_EQ(decodedStreamFrame.offset, offset);
  EXPECT_EQ(decodedStreamFrame.data->computeChainDataLength(), 20);
  EXPECT_TRUE(folly::IOBufEqualTo()(inputBuf, decodedStreamFrame.data));
}

TEST_F(QuicWriteCodecTest, WriteTwoStreamFrames) {
  MockQuicPacketBuilder pktBuilder;
  pktBuilder.remaining_ = kDefaultUDPSendPacketLen - 1000;
  setupCommonExpects(pktBuilder);

  // 1 byte for type
  // 2 bytes for stream id
  // 4 bytes for offset
  // 1 byte for length
  // => 8 bytes
  StreamId streamId1 = 300;
  uint64_t offset1 = 65535;
  bool fin1 = false;
  bool hasMoreFrames1 = true;
  auto inputBuf = buildRandomInputData(30);
  StreamFrameMetaData streamFrameMetaData(
      streamId1, offset1, fin1, inputBuf->clone(), hasMoreFrames1);
  auto streamFrameWriteResult =
      writeStreamFrame(streamFrameMetaData, pktBuilder);
  auto outputBuf = std::move(streamFrameWriteResult->writtenData);
  EXPECT_EQ(30, outputBuf->computeChainDataLength());
  EXPECT_EQ(30, streamFrameWriteResult->bytesWritten);
  size_t consumedSize = 1000 + 8 + 30;
  EXPECT_EQ(
      kDefaultUDPSendPacketLen - consumedSize,
      pktBuilder.remainingSpaceInPkt());

  StreamId streamId2 = 300;
  bool hasMoreFrames2 = false;
  uint64_t offset2 = 65565;
  bool fin2 = false;
  auto inputBuf2 = buildRandomInputData(40);
  // 1 byte for type
  // 2 bytes for stream
  // 4 bytes for offset
  // => 7 bytes
  StreamFrameMetaData streamFrameMetaData2(
      streamId2, offset2, fin2, inputBuf2->clone(), hasMoreFrames2);
  auto streamFrameWriteResult2 =
      writeStreamFrame(streamFrameMetaData2, pktBuilder);
  auto outputBuf2 = std::move(streamFrameWriteResult2->writtenData);
  EXPECT_EQ(40, outputBuf2->computeChainDataLength());
  // 4 bytes for stream id, 2 bytes for offset, 1 byte for initial frame type
  EXPECT_EQ(40, streamFrameWriteResult2->bytesWritten);
  consumedSize += 7 + 40;
  EXPECT_EQ(
      kDefaultUDPSendPacketLen - consumedSize,
      pktBuilder.remainingSpaceInPkt());
  auto builtOut = std::move(pktBuilder).buildPacket();
  auto regularPacket = builtOut.first;
  EXPECT_EQ(regularPacket.frames.size(), 2);
  auto resultFrame = boost::get<WriteStreamFrame>(regularPacket.frames.front());
  EXPECT_EQ(resultFrame.streamId, streamId1);
  EXPECT_EQ(resultFrame.offset, offset1);
  EXPECT_EQ(resultFrame.len, 30);
  EXPECT_TRUE(folly::IOBufEqualTo()(inputBuf, outputBuf));

  auto resultFrame2 = boost::get<WriteStreamFrame>(regularPacket.frames.back());
  EXPECT_EQ(resultFrame2.streamId, streamId2);
  EXPECT_EQ(resultFrame2.offset, offset2);
  EXPECT_EQ(resultFrame2.len, 40);
  EXPECT_TRUE(folly::IOBufEqualTo()(inputBuf2, outputBuf2));

  // Verify the on wire bytes via decoder:
  auto wireBuf = std::move(builtOut.second);
  folly::io::Cursor cursor(wireBuf.get());
  auto decodedStreamFrame1 = boost::get<ReadStreamFrame>(quic::parseFrame(
      cursor,
      regularPacket.header,
      CodecParameters(kDefaultAckDelayExponent, QuicVersion::MVFST)));
  EXPECT_EQ(decodedStreamFrame1.streamId, streamId1);
  EXPECT_EQ(decodedStreamFrame1.offset, offset1);
  EXPECT_EQ(decodedStreamFrame1.data->computeChainDataLength(), 30);
  EXPECT_TRUE(folly::IOBufEqualTo()(inputBuf, decodedStreamFrame1.data));
  // Read another one from wire output:
  auto decodedStreamFrame2 = boost::get<ReadStreamFrame>(quic::parseFrame(
      cursor,
      regularPacket.header,
      CodecParameters(kDefaultAckDelayExponent, QuicVersion::MVFST)));
  EXPECT_EQ(decodedStreamFrame2.streamId, streamId2);
  EXPECT_EQ(decodedStreamFrame2.offset, offset2);
  EXPECT_EQ(decodedStreamFrame2.data->computeChainDataLength(), 40);
  EXPECT_TRUE(folly::IOBufEqualTo()(inputBuf2, decodedStreamFrame2.data));
}

TEST_F(QuicWriteCodecTest, WriteStreamFramePartialData) {
  MockQuicPacketBuilder pktBuilder;
  // Networking bytes are just like your youth, they disappear quick:
  pktBuilder.remaining_ = 40;
  setupCommonExpects(pktBuilder);
  auto inputBuf = buildRandomInputData(50);

  StreamId streamId = 300;
  uint64_t offset = 65535;
  bool fin = false;
  bool hasMoreFrames = false;

  // 1 byte for type
  // 2 bytes for stream id
  // 4 bytes for offset
  // => 7 bytes for header
  StreamFrameMetaData streamFrameMetaData(
      streamId, offset, fin, inputBuf->clone(), hasMoreFrames);

  auto streamFrameWriteResult =
      writeStreamFrame(streamFrameMetaData, pktBuilder);
  auto outputBuf = std::move(streamFrameWriteResult->writtenData);
  EXPECT_EQ(outputBuf->computeChainDataLength(), 33);
  EXPECT_EQ(streamFrameWriteResult->bytesWritten, 33);
  EXPECT_EQ(pktBuilder.remainingSpaceInPkt(), 0);
  auto builtOut = std::move(pktBuilder).buildPacket();
  auto regularPacket = builtOut.first;
  EXPECT_EQ(regularPacket.frames.size(), 1);
  auto resultFrame = boost::get<WriteStreamFrame>(regularPacket.frames.back());
  EXPECT_EQ(resultFrame.streamId, streamId);
  EXPECT_EQ(resultFrame.offset, offset);
  EXPECT_EQ(resultFrame.len, 33);

  inputBuf->trimEnd(inputBuf->computeChainDataLength() - 33);
  EXPECT_TRUE(folly::IOBufEqualTo()(inputBuf, outputBuf));

  auto wireBuf = std::move(builtOut.second);
  folly::io::Cursor cursor(wireBuf.get());
  auto decodedStreamFrame = boost::get<ReadStreamFrame>(parseQuicFrame(cursor));
  EXPECT_EQ(decodedStreamFrame.streamId, streamId);
  EXPECT_EQ(decodedStreamFrame.offset, offset);
  EXPECT_EQ(decodedStreamFrame.data->computeChainDataLength(), 33);
  EXPECT_TRUE(folly::IOBufEqualTo()(inputBuf, decodedStreamFrame.data));
}

TEST_F(QuicWriteCodecTest, WriteStreamFrameTooSmallForStreamHeader) {
  MockQuicPacketBuilder pktBuilder;
  pktBuilder.remaining_ = 1;
  setupCommonExpects(pktBuilder);
  auto inputBuf = buildRandomInputData(1);
  StreamId streamId = 1;
  uint64_t offset = 65535;
  bool fin = false;
  bool hasMoreFrames = false;
  StreamFrameMetaData streamFrameMetaData(
      streamId, offset, fin, inputBuf->clone(), hasMoreFrames);
  auto result = writeStreamFrame(streamFrameMetaData, pktBuilder);
  EXPECT_FALSE(result.hasValue());
  EXPECT_EQ(1, pktBuilder.remainingSpaceInPkt());
}

TEST_F(QuicWriteCodecTest, WriteStreamNoSpaceForData) {
  MockQuicPacketBuilder pktBuilder;
  pktBuilder.remaining_ = 4;
  setupCommonExpects(pktBuilder);
  auto inputBuf = buildRandomInputData(10);

  StreamId streamId = 1;
  uint64_t offset = 1;
  bool fin = false;
  bool hasMoreFrames = true;
  // 1 byte for type
  // 1 byte for stream id
  // 1 byte for offset
  // 1 byte for length
  // => 4 bytes
  StreamFrameMetaData streamFrameMetaData(
      streamId, offset, fin, inputBuf->clone(), hasMoreFrames);
  auto result = writeStreamFrame(streamFrameMetaData, pktBuilder);
  EXPECT_FALSE(result.hasValue());
  EXPECT_EQ(pktBuilder.remainingSpaceInPkt(), 4);
}

TEST_F(QuicWriteCodecTest, WriteStreamSpaceForOneByte) {
  // Similar to WriteStreamNoSpaceForData, but this time we
  // do not need the data length field, so we end up actually writing 1 byte
  // real data
  MockQuicPacketBuilder pktBuilder;
  pktBuilder.remaining_ = 4;
  setupCommonExpects(pktBuilder);
  auto inputBuf = buildRandomInputData(100);

  StreamId streamId = 1;
  uint64_t offset = 1;
  bool fin = false;
  bool hasMoreFrames = false;
  // 1 byte for type
  // 1 byte for stream id
  // 1 byte for offet
  // => 3 bytes
  StreamFrameMetaData streamFrameMetaData(
      streamId, offset, fin, inputBuf->clone(), hasMoreFrames);

  auto result = writeStreamFrame(streamFrameMetaData, pktBuilder);
  EXPECT_EQ(result->bytesWritten, 1);
  auto outputBuf = std::move(result->writtenData);
  EXPECT_EQ(outputBuf->computeChainDataLength(), 1);
  EXPECT_EQ(pktBuilder.remainingSpaceInPkt(), 0);
  auto builtOut = std::move(pktBuilder).buildPacket();
  auto regularPacket = builtOut.first;

  EXPECT_EQ(regularPacket.frames.size(), 1);
  auto resultFrame = boost::get<WriteStreamFrame>(regularPacket.frames.back());
  EXPECT_EQ(resultFrame.streamId, streamId);
  EXPECT_EQ(resultFrame.offset, offset);
  EXPECT_EQ(resultFrame.len, 1);
  inputBuf->trimEnd(inputBuf->computeChainDataLength() - 1);
  EXPECT_TRUE(folly::IOBufEqualTo()(inputBuf, outputBuf));

  auto wireBuf = std::move(builtOut.second);
  folly::io::Cursor cursor(wireBuf.get());
  auto decodedStreamFrame = boost::get<ReadStreamFrame>(quic::parseFrame(
      cursor,
      regularPacket.header,
      CodecParameters(kDefaultAckDelayExponent, QuicVersion::MVFST)));
  EXPECT_EQ(decodedStreamFrame.streamId, streamId);
  EXPECT_EQ(decodedStreamFrame.offset, offset);
  EXPECT_EQ(decodedStreamFrame.data->computeChainDataLength(), 1);
  EXPECT_TRUE(folly::IOBufEqualTo()(inputBuf, decodedStreamFrame.data));
}

TEST_F(QuicWriteCodecTest, WriteFinToEmptyPacket) {
  MockQuicPacketBuilder pktBuilder;
  setupCommonExpects(pktBuilder);

  auto inputBuf = buildRandomInputData(10);

  // 1 byte for type
  // => 1 byte
  StreamId streamId = 1;
  uint64_t offset = 0;
  bool fin = true;
  bool hasMoreFrames = false;
  StreamFrameMetaData streamFrameMetaData(
      streamId, offset, fin, inputBuf->clone(), hasMoreFrames);
  auto result = writeStreamFrame(streamFrameMetaData, pktBuilder);
  auto outputBuf = std::move(result->writtenData);
  EXPECT_TRUE(result->finWritten);

  auto builtOut = std::move(pktBuilder).buildPacket();
  auto regularPacket = builtOut.first;

  EXPECT_EQ(regularPacket.frames.size(), 1);
  auto resultFrame = boost::get<WriteStreamFrame>(regularPacket.frames.back());
  EXPECT_EQ(resultFrame.streamId, streamId);
  EXPECT_EQ(resultFrame.offset, offset);
  EXPECT_EQ(inputBuf->computeChainDataLength(), resultFrame.len);
  EXPECT_TRUE(resultFrame.fin);
  EXPECT_TRUE(folly::IOBufEqualTo()(inputBuf, outputBuf));

  auto wireBuf = std::move(builtOut.second);
  folly::io::Cursor cursor(wireBuf.get());
  auto decodedStreamFrame = boost::get<ReadStreamFrame>(quic::parseFrame(
      cursor,
      regularPacket.header,
      CodecParameters(kDefaultAckDelayExponent, QuicVersion::MVFST)));
  EXPECT_EQ(decodedStreamFrame.streamId, streamId);
  EXPECT_EQ(decodedStreamFrame.offset, offset);
  EXPECT_EQ(
      decodedStreamFrame.data->computeChainDataLength(),
      inputBuf->computeChainDataLength());
  EXPECT_TRUE(decodedStreamFrame.fin);
  EXPECT_TRUE(folly::IOBufEqualTo()(inputBuf, decodedStreamFrame.data));
}

TEST_F(QuicWriteCodecTest, TestWriteIncompleteDataAndFin) {
  MockQuicPacketBuilder pktBuilder;
  setupCommonExpects(pktBuilder);
  // make sure we are writing more than the packet can hold and then some
  auto inDataSize = pktBuilder.remainingSpaceInPkt() + 20;
  auto inputBuf = buildRandomInputData(inDataSize);

  // 1 byte for type
  // => 1 byte
  StreamId streamId = 1;
  uint64_t offset = 0;
  bool fin = true;
  bool hasMoreFrames = false;
  StreamFrameMetaData streamFrameMetaData(
      streamId, offset, fin, inputBuf->clone(), hasMoreFrames);
  auto streamFrameWriteResult =
      writeStreamFrame(streamFrameMetaData, pktBuilder);
  EXPECT_FALSE(streamFrameWriteResult->finWritten);
  EXPECT_LT(streamFrameWriteResult->bytesWritten, inDataSize);
}

TEST_F(QuicWriteCodecTest, TestWriteNoDataAndFin) {
  MockQuicPacketBuilder pktBuilder;
  setupCommonExpects(pktBuilder);

  // 1 byte for type
  // => 1 byte
  StreamId streamId = 1;
  uint64_t offset = 0;
  bool fin = true;
  bool hasMoreFrames = false;
  Buf empty;
  StreamFrameMetaData streamFrameMetaData(
      streamId, offset, fin, std::move(empty), hasMoreFrames);
  auto streamFrameWriteResult =
      writeStreamFrame(streamFrameMetaData, pktBuilder);
  EXPECT_TRUE(streamFrameWriteResult->finWritten);
}

TEST_F(QuicWriteCodecTest, TestWriteNoDataAndNoFin) {
  MockQuicPacketBuilder pktBuilder;
  setupCommonExpects(pktBuilder);
  // 1 byte for type
  // => 1 byte
  StreamId streamId = 1;
  uint64_t offset = 0;
  bool fin = false;
  bool hasMoreFrames = false;
  Buf empty;
  StreamFrameMetaData streamFrameMetaData(
      streamId, offset, fin, std::move(empty), hasMoreFrames);
  EXPECT_THROW(
      writeStreamFrame(streamFrameMetaData, pktBuilder), QuicInternalException);
}

TEST_F(QuicWriteCodecTest, PacketOnlyHasSpaceForStreamHeader) {
  // If packet only has space for a stream header, even if FIN is set, we should
  // not write anything if we have data
  MockQuicPacketBuilder pktBuilder;
  pktBuilder.remaining_ = 2;
  setupCommonExpects(pktBuilder);
  auto inputBuf = buildRandomInputData(20);
  // 1 byte for type
  // 1 byte for stream id
  // => 2 byte
  StreamId streamId = 1;
  uint64_t offset = 0;
  bool fin = true;
  bool hasMoreFrames = false;
  auto buf = buildRandomInputData(1);
  StreamFrameMetaData streamFrameMetaData(
      streamId, offset, fin, std::move(buf), hasMoreFrames);
  auto streamFrameWriteResult =
      writeStreamFrame(streamFrameMetaData, pktBuilder);
  EXPECT_FALSE(streamFrameWriteResult.hasValue());
  EXPECT_EQ(pktBuilder.remainingSpaceInPkt(), 2);
}

TEST_F(QuicWriteCodecTest, PacketOnlyHasSpaceForStreamHeaderWithFin) {
  MockQuicPacketBuilder pktBuilder;
  pktBuilder.remaining_ = 2;
  setupCommonExpects(pktBuilder);
  auto inputBuf = buildRandomInputData(20);
  // 1 byte for type
  // 1 byte for stream id
  // => 1 byte
  StreamId streamId = 1;
  uint64_t offset = 0;
  bool fin = true;
  bool hasMoreFrames = false;
  Buf empty;
  StreamFrameMetaData streamFrameMetaData(
      streamId, offset, fin, std::move(empty), hasMoreFrames);
  auto streamFrameWriteResult =
      writeStreamFrame(streamFrameMetaData, pktBuilder);
  ASSERT_TRUE(streamFrameWriteResult.hasValue());
  EXPECT_TRUE(streamFrameWriteResult->finWritten);
  EXPECT_EQ(pktBuilder.remainingSpaceInPkt(), 0);
}

TEST_F(QuicWriteCodecTest, AckFrameGapExceedsRepresentation) {
  MockQuicPacketBuilder pktBuilder;
  setupCommonExpects(pktBuilder);

  PacketNum max = std::numeric_limits<uint64_t>::max();
  // Can't use max directly, because it will exceed interval set's
  // representation.
  IntervalSet<PacketNum> ackBlocks = {{max - 10, max - 10}, {1, 1}};
  EXPECT_THROW(
      writeAckFrame(
          AckFrameMetaData(ackBlocks, 0us, kDefaultAckDelayExponent),
          pktBuilder),
      QuicTransportException);
}

TEST_F(QuicWriteCodecTest, AckFrameVeryLargeAckRange) {
  MockQuicPacketBuilder pktBuilder;
  setupCommonExpects(pktBuilder);

  // 1 type byte,
  // 8 bytes for largest acked, 1 bytes for ack delay => 9 bytes
  // 1 byte for ack block count
  // There is 1 gap => each represented by 8 bytes => 8 bytes
  // total 11 bytes
  PacketNum largest = (uint64_t)1 << 55;
  IntervalSet<PacketNum> ackBlocks = {{1, largest}};
  AckFrameMetaData ackMetadata(ackBlocks, 0us, kDefaultAckDelayExponent);

  auto ackFrameWriteResult = *writeAckFrame(ackMetadata, pktBuilder);

  EXPECT_EQ(19, ackFrameWriteResult.bytesWritten);
  EXPECT_EQ(kDefaultUDPSendPacketLen - 19, pktBuilder.remainingSpaceInPkt());
  auto builtOut = std::move(pktBuilder).buildPacket();
  auto regularPacket = builtOut.first;
  EXPECT_EQ(regularPacket.frames.size(), 1);
  WriteAckFrame ackFrame =
      boost::get<WriteAckFrame>(regularPacket.frames.back());
  EXPECT_EQ(ackFrame.ackBlocks.size(), 1);

  EXPECT_EQ(ackFrame.ackBlocks.front().start, 1);
  EXPECT_EQ(largest, ackFrame.ackBlocks.front().end);
}

TEST_F(QuicWriteCodecTest, AckFrameNotEnoughForAnything) {
  MockQuicPacketBuilder pktBuilder;
  pktBuilder.remaining_ = 4;
  setupCommonExpects(pktBuilder);

  // 1 type byte,
  // 2 bytes for largest acked, 2 bytes for ack delay => 4 bytes
  // 1 byte for ack block count
  // There are 2 gaps => each represented by 2 bytes => 4 bytes
  // 1 byte for first ack block length, then 2 bytes for each pair => 5 bytes
  // total 15 bytes
  IntervalSet<PacketNum> ackBlocks = {{1000, 1000}, {500, 700}, {100, 200}};
  // 4 btyes are just not enough for anything
  AckFrameMetaData ackMetadata(ackBlocks, 555us, kDefaultAckDelayExponent);

  auto result = writeAckFrame(ackMetadata, pktBuilder);
  EXPECT_FALSE(result.hasValue());
  EXPECT_EQ(pktBuilder.remainingSpaceInPkt(), 4);
}

TEST_F(QuicWriteCodecTest, WriteSimpleAckFrame) {
  MockQuicPacketBuilder pktBuilder;
  setupCommonExpects(pktBuilder);
  auto ackDelay = 111us;
  IntervalSet<PacketNum> ackBlocks = {{501, 1000}, {101, 400}};
  AckFrameMetaData meta(ackBlocks, ackDelay, kDefaultAckDelayExponent);

  // 1 type byte,
  // 2 bytes for largest acked, 1 bytes for ack delay => 3 bytes
  // 1 byte for ack block count
  // There is 1 gap => each represented by 2 bytes => 2 bytes
  // 2 byte for first ack block length, then 2 bytes for the next len => 4 bytes
  // total 11 bytes

  auto result = *writeAckFrame(meta, pktBuilder);

  EXPECT_EQ(11, result.bytesWritten);
  EXPECT_EQ(kDefaultUDPSendPacketLen - 11, pktBuilder.remainingSpaceInPkt());
  auto builtOut = std::move(pktBuilder).buildPacket();
  auto regularPacket = builtOut.first;
  WriteAckFrame ackFrame =
      boost::get<WriteAckFrame>(regularPacket.frames.back());
  EXPECT_EQ(ackFrame.ackBlocks.size(), 2);
  auto iter = ackFrame.ackBlocks.cbegin();
  EXPECT_EQ(iter->start, 101);
  EXPECT_EQ(iter->end, 400);
  iter++;
  EXPECT_EQ(iter->start, 501);
  EXPECT_EQ(iter->end, 1000);

  auto wireBuf = std::move(builtOut.second);
  folly::io::Cursor cursor(wireBuf.get());
  auto decodedAckFrame = boost::get<ReadAckFrame>(parseQuicFrame(cursor));
  EXPECT_EQ(decodedAckFrame.largestAcked, 1000);
  EXPECT_EQ(
      decodedAckFrame.ackDelay.count(),
      computeExpectedDelay(ackDelay, kDefaultAckDelayExponent));
  EXPECT_EQ(decodedAckFrame.ackBlocks.size(), 2);
  EXPECT_EQ(decodedAckFrame.ackBlocks[0].startPacket, 501);
  EXPECT_EQ(decodedAckFrame.ackBlocks[0].endPacket, 1000);
  EXPECT_EQ(decodedAckFrame.ackBlocks[1].startPacket, 101);
  EXPECT_EQ(decodedAckFrame.ackBlocks[1].endPacket, 400);
}

TEST_F(QuicWriteCodecTest, WriteAckFrameWillSaveAckDelay) {
  MockQuicPacketBuilder pktBuilder;
  setupCommonExpects(pktBuilder);
  auto ackDelay = 111us;
  IntervalSet<PacketNum> ackBlocks = {{501, 1000}, {101, 400}};
  AckFrameMetaData meta(ackBlocks, ackDelay, kDefaultAckDelayExponent);

  writeAckFrame(meta, pktBuilder);
  auto builtOut = std::move(pktBuilder).buildPacket();
  auto regularPacket = builtOut.first;
  WriteAckFrame ackFrame =
      boost::get<WriteAckFrame>(regularPacket.frames.back());
  EXPECT_EQ(ackDelay, ackFrame.ackDelay);
}

TEST_F(QuicWriteCodecTest, VerifyNumAckBlocksSizeAccounted) {
  // Tests that if we restrict the size to be exactly the size required for a 1
  // byte num blocks size, if the num blocks requires 2 bytes (practically this
  // will never happen), then we won't write the additional blocks.
  MockQuicPacketBuilder pktBuilder;
  pktBuilder.remaining_ = 134;
  setupCommonExpects(pktBuilder);

  // 1 type byte,
  // 2 byte for largest acked, 1 bytes for ack delay => 3 bytes
  // 2 byte for ack block count, (64 additional blocks)
  // 1 byte for largest ack block len
  // There is 64 blocks => each represented by 2 bytes => 128 bytes
  // total 135 bytes needed, instead only giving 134 bytes.
  auto blockLength = 2;
  auto gap = 2;
  PacketNum largest = 1000;
  PacketNum currentEnd = largest - blockLength - gap;
  IntervalSet<PacketNum> ackBlocks;
  for (int i = 0; i < 64; i++) {
    CHECK_GE(currentEnd, blockLength);
    ackBlocks.insert({currentEnd - blockLength, currentEnd});
    currentEnd -= blockLength + gap;
  }
  ackBlocks.insert({largest, largest});
  AckFrameMetaData ackMetadata(ackBlocks, 0us, kDefaultAckDelayExponent);

  auto ackFrameWriteResult = *writeAckFrame(ackMetadata, pktBuilder);

  EXPECT_EQ(ackFrameWriteResult.bytesWritten, 132);
  EXPECT_EQ(pktBuilder.remainingSpaceInPkt(), 2);
  auto builtOut = std::move(pktBuilder).buildPacket();
  auto regularPacket = builtOut.first;
  EXPECT_EQ(regularPacket.frames.size(), 1);
  WriteAckFrame ackFrame =
      boost::get<WriteAckFrame>(regularPacket.frames.back());
  EXPECT_EQ(ackFrame.ackBlocks.size(), 64);

  EXPECT_EQ(ackFrame.ackBlocks.front().start, 746);
  EXPECT_EQ(ackFrame.ackBlocks.front().end, 748);
}

TEST_F(QuicWriteCodecTest, WriteWithDifferentAckDelayExponent) {
  MockQuicPacketBuilder pktBuilder;
  setupCommonExpects(pktBuilder);

  IntervalSet<PacketNum> ackBlocks{{1000, 1000}};
  uint8_t ackDelayExponent = 6;
  AckFrameMetaData ackMetadata(ackBlocks, 1240us, ackDelayExponent);

  writeAckFrame(ackMetadata, pktBuilder);
  auto builtOut = std::move(pktBuilder).buildPacket();
  auto wireBuf = std::move(builtOut.second);
  folly::io::Cursor cursor(wireBuf.get());
  auto decodedAckFrame = boost::get<ReadAckFrame>(quic::parseFrame(
      cursor,
      builtOut.first.header,
      CodecParameters(ackDelayExponent, QuicVersion::MVFST)));
  EXPECT_EQ(
      decodedAckFrame.ackDelay.count(),
      computeExpectedDelay(ackMetadata.ackDelay, ackDelayExponent));
}

TEST_F(QuicWriteCodecTest, WriteExponentInLongHeaderPacket) {
  MockQuicPacketBuilder pktBuilder;
  setupCommonExpects(pktBuilder);

  IntervalSet<PacketNum> ackBlocks{{1000, 1000}};
  uint8_t ackDelayExponent = 6;
  AckFrameMetaData ackMetadata(ackBlocks, 1240us, ackDelayExponent);

  writeAckFrame(ackMetadata, pktBuilder);
  auto builtOut = std::move(pktBuilder).buildLongHeaderPacket();
  auto wireBuf = std::move(builtOut.second);
  folly::io::Cursor cursor(wireBuf.get());
  auto decodedAckFrame = boost::get<ReadAckFrame>(quic::parseFrame(
      cursor,
      builtOut.first.header,
      CodecParameters(ackDelayExponent, QuicVersion::MVFST)));
  EXPECT_EQ(
      decodedAckFrame.ackDelay.count(),
      (uint64_t(ackMetadata.ackDelay.count()) >> ackDelayExponent)
          << kDefaultAckDelayExponent);
}

TEST_F(QuicWriteCodecTest, OnlyAckLargestPacket) {
  MockQuicPacketBuilder pktBuilder;
  setupCommonExpects(pktBuilder);

  // 1 type byte,
  // 2 bytes for largest acked, 2 bytes for ack delay => 4 bytes
  // 1 byte for ack block count
  // 1 byte for first ack block length
  // total 7 bytes
  IntervalSet<PacketNum> ackBlocks{{1000, 1000}};
  AckFrameMetaData ackMetadata(ackBlocks, 555us, kDefaultAckDelayExponent);

  // No AckBlock is added to the metadata. There will still be one block
  // generated as the first block to cover largestAcked => 2 bytes
  auto ackFrameWriteResult = *writeAckFrame(ackMetadata, pktBuilder);
  EXPECT_EQ(7, ackFrameWriteResult.bytesWritten);
  EXPECT_EQ(kDefaultUDPSendPacketLen - 7, pktBuilder.remainingSpaceInPkt());
  auto builtOut = std::move(pktBuilder).buildPacket();
  auto regularPacket = builtOut.first;
  EXPECT_EQ(regularPacket.frames.size(), 1);
  WriteAckFrame ackFrame =
      boost::get<WriteAckFrame>(regularPacket.frames.back());
  EXPECT_EQ(ackFrame.ackBlocks.size(), 1);
  EXPECT_EQ(ackFrame.ackBlocks.front().start, 1000);
  EXPECT_EQ(ackFrame.ackBlocks.front().end, 1000);

  // Verify the on wire bytes via decoder:
  // (Awkwardly, this assumes the decoder is correct)
  auto wireBuf = std::move(builtOut.second);
  folly::io::Cursor cursor(wireBuf.get());
  auto decodedAckFrame = boost::get<ReadAckFrame>(parseQuicFrame(cursor));
  EXPECT_EQ(decodedAckFrame.largestAcked, 1000);
  EXPECT_EQ(
      decodedAckFrame.ackDelay.count(),
      computeExpectedDelay(ackMetadata.ackDelay, kDefaultAckDelayExponent));
  EXPECT_EQ(decodedAckFrame.ackBlocks.size(), 1);
  EXPECT_EQ(decodedAckFrame.ackBlocks[0].startPacket, 1000);
  EXPECT_EQ(decodedAckFrame.ackBlocks[0].endPacket, 1000);
}

TEST_F(QuicWriteCodecTest, WriteSomeAckBlocks) {
  // Too many ack blocks passed in, we can only write some of them
  MockQuicPacketBuilder pktBuilder;
  pktBuilder.remaining_ = 36;
  setupCommonExpects(pktBuilder);

  // 1 type byte,
  // 2 bytes for largest acked, 2 bytes for ack delay => 4 bytes
  // 1 byte for num ack blocks
  // 1 byte for first ack block length
  // each additional ack block 1 byte gap + 1 byte length => 2 bytes
  // total 7 bytes
  IntervalSet<PacketNum> testAckBlocks;
  PacketNum currentEnd = 1000;
  auto blockLength = 5;
  auto gap = 10;
  for (int i = 0; i < 30; i++) {
    testAckBlocks.insert({currentEnd - blockLength + 1, currentEnd});
    currentEnd -= blockLength + gap;
  }
  testAckBlocks.insert({1000, 1000});

  AckFrameMetaData ackMetadata(testAckBlocks, 555ms, kDefaultAckDelayExponent);
  auto ackFrameWriteResult = *writeAckFrame(ackMetadata, pktBuilder);

  EXPECT_EQ(ackFrameWriteResult.bytesWritten, 35);
  EXPECT_EQ(pktBuilder.remainingSpaceInPkt(), 1);
  auto builtOut = std::move(pktBuilder).buildPacket();
  auto regularPacket = builtOut.first;
  EXPECT_EQ(regularPacket.frames.size(), 1);
  WriteAckFrame ackFrame =
      boost::get<WriteAckFrame>(regularPacket.frames.back());
  EXPECT_EQ(ackFrame.ackBlocks.size(), 14);

  // Verify the on wire bytes via decoder:
  // (Awkwardly, this assumes the decoder is correct)
  auto wireBuf = std::move(builtOut.second);
  folly::io::Cursor cursor(wireBuf.get());
  auto decodedAckFrame = boost::get<ReadAckFrame>(parseQuicFrame(cursor));
  EXPECT_EQ(decodedAckFrame.largestAcked, 1000);
  EXPECT_EQ(
      decodedAckFrame.ackDelay.count(),
      computeExpectedDelay(ackMetadata.ackDelay, kDefaultAckDelayExponent));
  EXPECT_EQ(decodedAckFrame.ackBlocks.size(), 14);
}

TEST_F(QuicWriteCodecTest, NoSpaceForAckBlockSection) {
  MockQuicPacketBuilder pktBuilder;
  pktBuilder.remaining_ = 6;
  setupCommonExpects(pktBuilder);

  // 1 type byte,
  // 2 bytes for largest acked, 2 bytes for ack delay => 4 bytes
  // 1 byte for num ack blocks
  // 1 byte for first ack block length
  IntervalSet<PacketNum> ackBlocks = {{1000, 1000}, {701, 900}, {501, 600}};
  AckFrameMetaData ackMetadata(ackBlocks, 555us, kDefaultAckDelayExponent);
  auto ackFrameWriteResult = writeAckFrame(ackMetadata, pktBuilder);
  EXPECT_FALSE(ackFrameWriteResult.hasValue());
}

TEST_F(QuicWriteCodecTest, OnlyHasSpaceForFirstAckBlock) {
  MockQuicPacketBuilder pktBuilder;
  pktBuilder.remaining_ = 10;
  setupCommonExpects(pktBuilder);

  // 1 type byte,
  // 2 bytes for largest acked, 2 bytes for ack delay => 4 bytes
  // 1 byte for num ack blocks
  // 1 byte for first ack block length
  IntervalSet<PacketNum> ackBlocks = {{1000, 1000}, {701, 900}, {501, 600}};
  AckFrameMetaData ackMetadata(ackBlocks, 555us, kDefaultAckDelayExponent);
  auto ackFrameWriteResult = *writeAckFrame(ackMetadata, pktBuilder);

  EXPECT_EQ(ackFrameWriteResult.bytesWritten, 7);
  EXPECT_EQ(pktBuilder.remainingSpaceInPkt(), 3);
  auto builtOut = std::move(pktBuilder).buildPacket();
  WriteAckFrame ackFrame =
      boost::get<WriteAckFrame>(builtOut.first.frames.back());
  EXPECT_EQ(ackFrame.ackBlocks.size(), 1);
  EXPECT_EQ(ackFrame.ackBlocks.front().start, 1000);
  EXPECT_EQ(ackFrame.ackBlocks.front().end, 1000);

  auto wireBuf = std::move(builtOut.second);
  folly::io::Cursor cursor(wireBuf.get());
  auto decodedAckFrame = boost::get<ReadAckFrame>(parseQuicFrame(cursor));
  EXPECT_EQ(decodedAckFrame.largestAcked, 1000);
  EXPECT_EQ(
      decodedAckFrame.ackDelay.count(),
      computeExpectedDelay(ackMetadata.ackDelay, kDefaultAckDelayExponent));
  EXPECT_EQ(decodedAckFrame.ackBlocks.size(), 1);
  EXPECT_EQ(decodedAckFrame.ackBlocks[0].startPacket, 1000);
  EXPECT_EQ(decodedAckFrame.ackBlocks[0].endPacket, 1000);
}

TEST_F(QuicWriteCodecTest, WriteMaxStreamData) {
  MockQuicPacketBuilder pktBuilder;
  setupCommonExpects(pktBuilder);
  StreamId id = 1;
  uint64_t offset = 0x08;
  MaxStreamDataFrame maxStreamDataFrame(id, offset);
  auto bytesWritten = writeFrame(maxStreamDataFrame, pktBuilder);

  auto builtOut = std::move(pktBuilder).buildPacket();
  auto regularPacket = builtOut.first;
  EXPECT_EQ(bytesWritten, 3);
  auto resultMaxStreamDataFrame =
      boost::get<MaxStreamDataFrame>(regularPacket.frames[0]);
  EXPECT_EQ(id, resultMaxStreamDataFrame.streamId);
  EXPECT_EQ(offset, resultMaxStreamDataFrame.maximumData);

  auto wireBuf = std::move(builtOut.second);
  folly::io::Cursor cursor(wireBuf.get());
  auto wireMaxStreamDataFrame =
      boost::get<MaxStreamDataFrame>(parseQuicFrame(cursor));
  EXPECT_EQ(id, wireMaxStreamDataFrame.streamId);
  EXPECT_EQ(offset, wireMaxStreamDataFrame.maximumData);

  // At last, verify there is nothing left in the wire format bytes:
  EXPECT_TRUE(cursor.isAtEnd());
}

TEST_F(QuicWriteCodecTest, NoSpaceForMaxStreamData) {
  MockQuicPacketBuilder pktBuilder;
  pktBuilder.remaining_ = 1;
  setupCommonExpects(pktBuilder);
  MaxStreamDataFrame maxStreamDataFrame(1, 0x08);
  EXPECT_EQ(0, writeFrame(maxStreamDataFrame, pktBuilder));
}

TEST_F(QuicWriteCodecTest, WriteMaxData) {
  MockQuicPacketBuilder pktBuilder;
  setupCommonExpects(pktBuilder);
  MaxDataFrame maxDataFrame(1000);
  auto bytesWritten = writeFrame(maxDataFrame, pktBuilder);

  auto builtOut = std::move(pktBuilder).buildPacket();
  auto regularPacket = builtOut.first;
  EXPECT_EQ(bytesWritten, 3);
  auto resultMaxDataFrame = boost::get<MaxDataFrame>(regularPacket.frames[0]);
  EXPECT_EQ(1000, resultMaxDataFrame.maximumData);

  auto wireBuf = std::move(builtOut.second);
  folly::io::Cursor cursor(wireBuf.get());
  auto wireMaxDataFrame = boost::get<MaxDataFrame>(parseQuicFrame(cursor));
  EXPECT_EQ(1000, wireMaxDataFrame.maximumData);
  EXPECT_TRUE(cursor.isAtEnd());
}

TEST_F(QuicWriteCodecTest, NoSpaceForMaxData) {
  MockQuicPacketBuilder pktBuilder;
  pktBuilder.remaining_ = 0;
  setupCommonExpects(pktBuilder);
  MaxDataFrame maxDataFrame(1000);
  EXPECT_EQ(0, writeFrame(maxDataFrame, pktBuilder));
}

TEST_F(QuicWriteCodecTest, WriteMaxStreamId) {
  for (uint64_t i = 0; i < 100; i++) {
    MockQuicPacketBuilder pktBuilder;
    setupCommonExpects(pktBuilder);
    uint64_t maxStream = i;
    bool isBidirectional = true;
    MaxStreamsFrame maxStreamsFrame(maxStream, isBidirectional);
    auto bytesWritten = writeFrame(maxStreamsFrame, pktBuilder);

    auto builtOut = std::move(pktBuilder).buildPacket();
    auto regularPacket = builtOut.first;
    auto streamCountSize = i < 64 ? 1 : 2;
    // 1 byte for the type and up to 2 bytes for the stream count.
    EXPECT_EQ(1 + streamCountSize, bytesWritten);
    auto resultMaxStreamIdFrame =
        boost::get<MaxStreamsFrame>(regularPacket.frames[0]);
    EXPECT_EQ(i, resultMaxStreamIdFrame.maxStreams);

    auto wireBuf = std::move(builtOut.second);
    folly::io::Cursor cursor(wireBuf.get());
    auto wireStreamsFrame = boost::get<MaxStreamsFrame>(parseQuicFrame(cursor));
    EXPECT_EQ(i, wireStreamsFrame.maxStreams);
    EXPECT_TRUE(cursor.isAtEnd());
  }
}

TEST_F(QuicWriteCodecTest, WriteUniMaxStreamId) {
  for (uint64_t i = 0; i < 100; i++) {
    MockQuicPacketBuilder pktBuilder;
    setupCommonExpects(pktBuilder);
    uint64_t maxStream = i;
    bool isBidirectional = false;
    MaxStreamsFrame maxStreamsFrame(maxStream, isBidirectional);
    auto bytesWritten = writeFrame(maxStreamsFrame, pktBuilder);

    auto builtOut = std::move(pktBuilder).buildPacket();
    auto regularPacket = builtOut.first;
    auto streamCountSize = i < 64 ? 1 : 2;
    // 1 byte for the type and up to 2 bytes for the stream count.
    EXPECT_EQ(1 + streamCountSize, bytesWritten);
    auto resultMaxStreamIdFrame =
        boost::get<MaxStreamsFrame>(regularPacket.frames[0]);
    EXPECT_EQ(i, resultMaxStreamIdFrame.maxStreams);

    auto wireBuf = std::move(builtOut.second);
    folly::io::Cursor cursor(wireBuf.get());
    auto wireStreamsFrame = boost::get<MaxStreamsFrame>(parseQuicFrame(cursor));
    EXPECT_EQ(i, wireStreamsFrame.maxStreams);
    EXPECT_TRUE(cursor.isAtEnd());
  }
}

TEST_F(QuicWriteCodecTest, NoSpaceForMaxStreamId) {
  MockQuicPacketBuilder pktBuilder;
  pktBuilder.remaining_ = 0;
  setupCommonExpects(pktBuilder);
  StreamId maxStream = 0x1234;
  MaxStreamsFrame maxStreamIdFrame(maxStream, true);
  EXPECT_EQ(0, writeFrame(maxStreamIdFrame, pktBuilder));
}

TEST_F(QuicWriteCodecTest, WriteConnClose) {
  MockQuicPacketBuilder pktBuilder;
  setupCommonExpects(pktBuilder);
  std::string reasonPhrase("You are fired");
  ConnectionCloseFrame connectionCloseFrame(
      TransportErrorCode::PROTOCOL_VIOLATION, reasonPhrase);
  auto connCloseBytesWritten = writeFrame(connectionCloseFrame, pktBuilder);

  auto builtOut = std::move(pktBuilder).buildPacket();
  auto regularPacket = builtOut.first;
  // 6 == ErrorCode(2) + FrameType(1) + reasonPhrase-len(2)
  EXPECT_EQ(4 + reasonPhrase.size(), connCloseBytesWritten);
  auto resultConnCloseFrame =
      boost::get<ConnectionCloseFrame>(regularPacket.frames[0]);
  EXPECT_EQ(
      TransportErrorCode::PROTOCOL_VIOLATION, resultConnCloseFrame.errorCode);
  EXPECT_EQ("You are fired", resultConnCloseFrame.reasonPhrase);

  auto wireBuf = std::move(builtOut.second);
  folly::io::Cursor cursor(wireBuf.get());
  auto wireConnCloseFrame =
      boost::get<ConnectionCloseFrame>(parseQuicFrame(cursor));
  EXPECT_EQ(
      TransportErrorCode::PROTOCOL_VIOLATION, wireConnCloseFrame.errorCode);
  EXPECT_EQ("You are fired", wireConnCloseFrame.reasonPhrase);

  // At last, verify there is nothing left in the wire format bytes:
  EXPECT_TRUE(cursor.isAtEnd());
}

TEST_F(QuicWriteCodecTest, DecodeConnCloseLarge) {
  MockQuicPacketBuilder pktBuilder;
  setupCommonExpects(pktBuilder);
  std::string reasonPhrase;
  reasonPhrase.resize(kMaxReasonPhraseLength + 10);
  ConnectionCloseFrame connectionCloseFrame(
      TransportErrorCode::PROTOCOL_VIOLATION, reasonPhrase);
  writeFrame(connectionCloseFrame, pktBuilder);
  auto builtOut = std::move(pktBuilder).buildPacket();
  auto regularPacket = builtOut.first;
  auto resultConnCloseFrame =
      boost::get<ConnectionCloseFrame>(regularPacket.frames[0]);
  EXPECT_EQ(
      TransportErrorCode::PROTOCOL_VIOLATION, resultConnCloseFrame.errorCode);
  EXPECT_EQ(resultConnCloseFrame.reasonPhrase, reasonPhrase);

  auto wireBuf = std::move(builtOut.second);
  folly::io::Cursor cursor(wireBuf.get());
  EXPECT_THROW(
      boost::get<ConnectionCloseFrame>(parseQuicFrame(cursor)),
      std::runtime_error);
}

TEST_F(QuicWriteCodecTest, NoSpaceConnClose) {
  MockQuicPacketBuilder pktBuilder;
  pktBuilder.remaining_ = 2;
  setupCommonExpects(pktBuilder);
  std::string reasonPhrase("You are all fired");
  ConnectionCloseFrame connCloseFrame(
      TransportErrorCode::PROTOCOL_VIOLATION, reasonPhrase);
  EXPECT_EQ(0, writeFrame(connCloseFrame, pktBuilder));
}

TEST_F(QuicWriteCodecTest, DecodeAppCloseLarge) {
  MockQuicPacketBuilder pktBuilder;
  setupCommonExpects(pktBuilder);
  std::string reasonPhrase;
  reasonPhrase.resize(kMaxReasonPhraseLength + 10);
  ApplicationCloseFrame applicationCloseFrame(
      GenericApplicationErrorCode::UNKNOWN, reasonPhrase);
  writeFrame(applicationCloseFrame, pktBuilder);

  auto builtOut = std::move(pktBuilder).buildPacket();
  auto regularPacket = builtOut.first;
  auto resultAppCloseFrame =
      boost::get<ApplicationCloseFrame>(regularPacket.frames[0]);
  EXPECT_EQ(
      GenericApplicationErrorCode::UNKNOWN, resultAppCloseFrame.errorCode);
  EXPECT_EQ(resultAppCloseFrame.reasonPhrase, reasonPhrase);

  auto wireBuf = std::move(builtOut.second);
  folly::io::Cursor cursor(wireBuf.get());
  EXPECT_THROW(
      boost::get<ApplicationCloseFrame>(parseQuicFrame(cursor)),
      std::runtime_error);
}

TEST_F(QuicWriteCodecTest, WritePing) {
  MockQuicPacketBuilder pktBuilder;
  setupCommonExpects(pktBuilder);
  PingFrame pingFrame;
  auto pingBytesWritten = writeFrame(pingFrame, pktBuilder);

  auto builtOut = std::move(pktBuilder).buildPacket();
  auto regularPacket = builtOut.first;
  EXPECT_EQ(1, pingBytesWritten);
  EXPECT_NO_THROW(boost::get<PingFrame>(regularPacket.frames[0]));

  auto wireBuf = std::move(builtOut.second);
  folly::io::Cursor cursor(wireBuf.get());
  boost::get<PingFrame>(parseQuicFrame(cursor));

  // At last, verify there is nothing left in the wire format bytes:
  EXPECT_TRUE(cursor.isAtEnd());
}

TEST_F(QuicWriteCodecTest, NoSpaceForPing) {
  MockQuicPacketBuilder pktBuilder;
  pktBuilder.remaining_ = 0;
  setupCommonExpects(pktBuilder);
  PingFrame pingFrame;
  EXPECT_EQ(0, writeFrame(pingFrame, pktBuilder));
}

TEST_F(QuicWriteCodecTest, WritePadding) {
  MockQuicPacketBuilder pktBuilder;
  setupCommonExpects(pktBuilder);
  PaddingFrame paddingFrame;
  auto paddingBytesWritten = writeFrame(paddingFrame, pktBuilder);

  auto builtOut = std::move(pktBuilder).buildPacket();
  auto regularPacket = builtOut.first;
  EXPECT_EQ(1, paddingBytesWritten);
  EXPECT_NO_THROW(boost::get<PaddingFrame>(regularPacket.frames[0]));

  auto wireBuf = std::move(builtOut.second);
  folly::io::Cursor cursor(wireBuf.get());
  EXPECT_NO_THROW(boost::get<PaddingFrame>(parseQuicFrame(cursor)));

  // At last, verify there is nothing left in the wire format bytes:
  EXPECT_TRUE(cursor.isAtEnd());
}

TEST_F(QuicWriteCodecTest, NoSpaceForPadding) {
  MockQuicPacketBuilder pktBuilder;
  pktBuilder.remaining_ = 0;
  setupCommonExpects(pktBuilder);
  PaddingFrame paddingFrame;
  EXPECT_EQ(0, writeFrame(paddingFrame, pktBuilder));
}

TEST_F(QuicWriteCodecTest, WriteStreamBlocked) {
  MockQuicPacketBuilder pktBuilder;
  setupCommonExpects(pktBuilder);
  StreamId blockedId = 0xF00D;
  uint64_t blockedOffset = 0x1111;
  StreamDataBlockedFrame blockedFrame(blockedId, blockedOffset);
  auto blockedBytesWritten = writeFrame(blockedFrame, pktBuilder);

  auto builtOut = std::move(pktBuilder).buildPacket();
  auto regularPacket = builtOut.first;
  EXPECT_EQ(blockedBytesWritten, 7);
  auto resultBlockedFrame =
      boost::get<StreamDataBlockedFrame>(regularPacket.frames[0]);
  EXPECT_EQ(blockedId, resultBlockedFrame.streamId);

  auto wireBuf = std::move(builtOut.second);
  folly::io::Cursor cursor(wireBuf.get());
  auto wireBlockedFrame =
      boost::get<StreamDataBlockedFrame>(parseQuicFrame(cursor));
  EXPECT_EQ(blockedId, wireBlockedFrame.streamId);
  EXPECT_EQ(blockedOffset, wireBlockedFrame.dataLimit);
  // At last, verify there is nothing left in the wire format bytes:
  EXPECT_TRUE(cursor.isAtEnd());
}

TEST_F(QuicWriteCodecTest, NoSpaceForBlockedStream) {
  MockQuicPacketBuilder pktBuilder;
  pktBuilder.remaining_ = 1;
  setupCommonExpects(pktBuilder);
  StreamId blockedStream = 0x01;
  uint64_t blockedOffset = 0x1111;
  StreamDataBlockedFrame blockedFrame(blockedStream, blockedOffset);
  EXPECT_EQ(0, writeFrame(blockedFrame, pktBuilder));
}

TEST_F(QuicWriteCodecTest, WriteRstStream) {
  MockQuicPacketBuilder pktBuilder;
  setupCommonExpects(pktBuilder);
  StreamId id = 0xBAAD;
  ApplicationErrorCode errorCode = GenericApplicationErrorCode::UNKNOWN;
  uint64_t offset = 0xF00D;
  RstStreamFrame rstStreamFrame(id, errorCode, offset);
  auto rstStreamBytesWritten = writeFrame(rstStreamFrame, pktBuilder);

  auto builtOut = std::move(pktBuilder).buildPacket();
  auto regularPacket = builtOut.first;
  EXPECT_EQ(13, rstStreamBytesWritten);
  auto resultRstStreamFrame =
      boost::get<RstStreamFrame>(regularPacket.frames[0]);
  EXPECT_EQ(errorCode, resultRstStreamFrame.errorCode);
  EXPECT_EQ(id, resultRstStreamFrame.streamId);
  EXPECT_EQ(offset, resultRstStreamFrame.offset);

  auto wireBuf = std::move(builtOut.second);
  folly::io::Cursor cursor(wireBuf.get());
  auto wireRstStreamFrame = boost::get<RstStreamFrame>(parseQuicFrame(cursor));
  EXPECT_EQ(errorCode, wireRstStreamFrame.errorCode);
  EXPECT_EQ(id, wireRstStreamFrame.streamId);
  EXPECT_EQ(offset, wireRstStreamFrame.offset);
  // At last, verify there is nothing left in the wire format bytes:
  EXPECT_TRUE(cursor.isAtEnd());
}

TEST_F(QuicWriteCodecTest, NoSpaceForRst) {
  MockQuicPacketBuilder pktBuilder;
  pktBuilder.remaining_ = 1;
  setupCommonExpects(pktBuilder);
  StreamId id = 0xBAAD;
  ApplicationErrorCode errorCode = GenericApplicationErrorCode::UNKNOWN;
  uint64_t offset = 0xF00D;
  RstStreamFrame rstStreamFrame(id, errorCode, offset);
  EXPECT_EQ(0, writeFrame(rstStreamFrame, pktBuilder));
}

TEST_F(QuicWriteCodecTest, WriteBlockedFrame) {
  MockQuicPacketBuilder pktBuilder;
  setupCommonExpects(pktBuilder);
  uint64_t blockedOffset = 0x11111;
  DataBlockedFrame blockedFrame(blockedOffset);
  auto bytesWritten = writeFrame(blockedFrame, pktBuilder);

  auto builtOut = std::move(pktBuilder).buildPacket();
  auto regularPacket = builtOut.first;
  EXPECT_EQ(bytesWritten, 5);
  EXPECT_NO_THROW(boost::get<DataBlockedFrame>(regularPacket.frames[0]));

  auto wireBuf = std::move(builtOut.second);
  folly::io::Cursor cursor(wireBuf.get());
  auto wireBlockedFrame = boost::get<DataBlockedFrame>(parseQuicFrame(cursor));
  EXPECT_EQ(wireBlockedFrame.dataLimit, blockedOffset);
  EXPECT_TRUE(cursor.isAtEnd());
}

TEST_F(QuicWriteCodecTest, NoSpaceForBlocked) {
  MockQuicPacketBuilder pktBuilder;
  pktBuilder.remaining_ = 0;
  setupCommonExpects(pktBuilder);
  uint64_t blockedOffset = 0x11111;
  DataBlockedFrame blockedFrame(blockedOffset);
  EXPECT_EQ(0, writeFrame(blockedFrame, pktBuilder));
}

TEST_F(QuicWriteCodecTest, WriteStreamIdNeeded) {
  MockQuicPacketBuilder pktBuilder;
  setupCommonExpects(pktBuilder);
  StreamId blockedStreamId = 0x211;
  MaxStreamsFrame streamIdNeeded(blockedStreamId, true);
  auto bytesWritten = writeFrame(streamIdNeeded, pktBuilder);

  auto builtOut = std::move(pktBuilder).buildPacket();
  auto regularPacket = builtOut.first;
  EXPECT_EQ(bytesWritten, 3);
  EXPECT_NO_THROW(boost::get<MaxStreamsFrame>(regularPacket.frames[0]));

  auto wireBuf = std::move(builtOut.second);
  folly::io::Cursor cursor(wireBuf.get());
  auto writeStreamIdBlocked =
      boost::get<MaxStreamsFrame>(parseQuicFrame(cursor));
  EXPECT_EQ(writeStreamIdBlocked.maxStreams, blockedStreamId);
  EXPECT_TRUE(cursor.isAtEnd());
}

TEST_F(QuicWriteCodecTest, NoSpaceForStreamIdNeeded) {
  MockQuicPacketBuilder pktBuilder;
  pktBuilder.remaining_ = 0;
  setupCommonExpects(pktBuilder);
  StreamId blockedStreamId = 0x211;
  MaxStreamsFrame streamIdNeeded(blockedStreamId, true);
  EXPECT_EQ(0, writeFrame(streamIdNeeded, pktBuilder));
}

TEST_F(QuicWriteCodecTest, WriteNewConnId) {
  MockQuicPacketBuilder pktBuilder;
  setupCommonExpects(pktBuilder);
  StatelessResetToken token;
  memset(token.data(), 'a', token.size());
  NewConnectionIdFrame newConnId(1, getTestConnectionId(), token);
  auto bytesWritten = writeFrame(newConnId, pktBuilder);

  auto builtOut = std::move(pktBuilder).buildPacket();
  auto regularPacket = builtOut.first;
  EXPECT_EQ(bytesWritten, 27);
  auto resultNewConnIdFrame = boost::get<NewConnectionIdFrame>(
      boost::get<QuicSimpleFrame>(regularPacket.frames[0]));
  EXPECT_EQ(resultNewConnIdFrame.sequence, 1);
  EXPECT_EQ(resultNewConnIdFrame.connectionId, getTestConnectionId());
  EXPECT_EQ(resultNewConnIdFrame.token, token);

  auto wireBuf = std::move(builtOut.second);
  folly::io::Cursor cursor(wireBuf.get());
  auto wireNewConnIdFrame = boost::get<NewConnectionIdFrame>(
      boost::get<QuicSimpleFrame>(parseQuicFrame(cursor)));
  EXPECT_EQ(1, wireNewConnIdFrame.sequence);
  EXPECT_EQ(getTestConnectionId(), wireNewConnIdFrame.connectionId);
  EXPECT_TRUE(cursor.isAtEnd());
}

TEST_F(QuicWriteCodecTest, WriteStopSending) {
  MockQuicPacketBuilder pktBuilder;
  setupCommonExpects(pktBuilder);
  StreamId streamId = 10;
  auto errorCode = GenericApplicationErrorCode::UNKNOWN;

  StopSendingFrame stopSending(streamId, errorCode);
  auto bytesWritten = writeSimpleFrame(stopSending, pktBuilder);

  auto builtOut = std::move(pktBuilder).buildPacket();
  auto regularPacket = builtOut.first;
  EXPECT_EQ(bytesWritten, 6);

  auto wireBuf = std::move(builtOut.second);
  folly::io::Cursor cursor(wireBuf.get());
  auto wireSimpleFrame = boost::get<QuicSimpleFrame>(parseQuicFrame(cursor));
  auto wireStopSendingFrame = boost::get<StopSendingFrame>(wireSimpleFrame);
  EXPECT_EQ(wireStopSendingFrame.streamId, streamId);
  EXPECT_EQ(wireStopSendingFrame.errorCode, errorCode);
  EXPECT_TRUE(cursor.isAtEnd());
}

TEST_F(QuicWriteCodecTest, NoSpaceForNewConnId) {
  MockQuicPacketBuilder pktBuilder;
  pktBuilder.remaining_ = 0;
  setupCommonExpects(pktBuilder);
  NewConnectionIdFrame newConnId(
      1, getTestConnectionId(), StatelessResetToken());
  EXPECT_EQ(0, writeFrame(newConnId, pktBuilder));
}

TEST_F(QuicWriteCodecTest, WriteExpiredStreamDataFrame) {
  MockQuicPacketBuilder pktBuilder;
  setupCommonExpects(pktBuilder);
  StreamId id = 10;
  uint64_t offset = 0x08;
  ExpiredStreamDataFrame expiredStreamDataFrame(id, offset);
  auto bytesWritten = writeFrame(expiredStreamDataFrame, pktBuilder);

  auto builtOut = std::move(pktBuilder).buildPacket();
  auto regularPacket = builtOut.first;
  EXPECT_EQ(bytesWritten, 4);
  auto result = boost::get<ExpiredStreamDataFrame>(
      boost::get<QuicSimpleFrame>(regularPacket.frames[0]));
  EXPECT_EQ(id, result.streamId);
  EXPECT_EQ(offset, result.minimumStreamOffset);

  auto wireBuf = std::move(builtOut.second);
  folly::io::Cursor cursor(wireBuf.get());
  auto wireExpiredStreamDataFrame = boost::get<ExpiredStreamDataFrame>(
      boost::get<QuicSimpleFrame>(parseQuicFrame(cursor)));
  EXPECT_EQ(id, wireExpiredStreamDataFrame.streamId);
  EXPECT_EQ(offset, wireExpiredStreamDataFrame.minimumStreamOffset);

  // At last, verify there is nothing left in the wire format bytes:
  EXPECT_TRUE(cursor.isAtEnd());
}

TEST_F(QuicWriteCodecTest, WriteMinStreamDataFrame) {
  MockQuicPacketBuilder pktBuilder;
  setupCommonExpects(pktBuilder);
  StreamId id = 10;
  uint64_t maximumData = 0x64;
  uint64_t offset = 0x08;
  MinStreamDataFrame minStreamDataFrame(id, maximumData, offset);
  auto bytesWritten = writeFrame(minStreamDataFrame, pktBuilder);

  auto builtOut = std::move(pktBuilder).buildPacket();
  auto regularPacket = builtOut.first;
  EXPECT_EQ(bytesWritten, 6);
  auto result = boost::get<MinStreamDataFrame>(
      boost::get<QuicSimpleFrame>(regularPacket.frames[0]));
  EXPECT_EQ(id, result.streamId);
  EXPECT_EQ(maximumData, result.maximumData);
  EXPECT_EQ(offset, result.minimumStreamOffset);

  auto wireBuf = std::move(builtOut.second);
  folly::io::Cursor cursor(wireBuf.get());
  auto wireMinStreamDataFrame = boost::get<MinStreamDataFrame>(
      boost::get<QuicSimpleFrame>(parseQuicFrame(cursor)));
  EXPECT_EQ(id, wireMinStreamDataFrame.streamId);
  EXPECT_EQ(maximumData, wireMinStreamDataFrame.maximumData);
  EXPECT_EQ(offset, wireMinStreamDataFrame.minimumStreamOffset);

  // At last, verify there is nothing left in the wire format bytes:
  EXPECT_TRUE(cursor.isAtEnd());
}

TEST_F(QuicWriteCodecTest, WritePathChallenge) {
  MockQuicPacketBuilder pktBuilder;
  setupCommonExpects(pktBuilder);

  uint64_t pathData = 0x64;
  PathChallengeFrame pathChallenge(pathData);
  auto bytesWritten = writeSimpleFrame(pathChallenge, pktBuilder);
  EXPECT_EQ(bytesWritten, 9);

  auto builtOut = std::move(pktBuilder).buildPacket();

  auto regularPacket = builtOut.first;
  auto result = boost::get<PathChallengeFrame>(
      boost::get<QuicSimpleFrame>(regularPacket.frames[0]));
  EXPECT_EQ(result.pathData, pathData);

  auto wireBuf = std::move(builtOut.second);
  folly::io::Cursor cursor(wireBuf.get());
  auto wireSimpleFrame = boost::get<QuicSimpleFrame>(parseQuicFrame(cursor));
  auto wirePathChallengeFrame = boost::get<PathChallengeFrame>(wireSimpleFrame);
  EXPECT_EQ(wirePathChallengeFrame.pathData, pathData);
  EXPECT_TRUE(cursor.isAtEnd());
}

TEST_F(QuicWriteCodecTest, WritePathResponse) {
  MockQuicPacketBuilder pktBuilder;
  setupCommonExpects(pktBuilder);

  uint64_t pathData = 0x64;
  PathResponseFrame pathResponse(pathData);
  auto bytesWritten = writeSimpleFrame(pathResponse, pktBuilder);
  EXPECT_EQ(bytesWritten, 9);

  auto builtOut = std::move(pktBuilder).buildPacket();

  auto regularPacket = builtOut.first;
  auto result = boost::get<PathResponseFrame>(
      boost::get<QuicSimpleFrame>(regularPacket.frames[0]));
  EXPECT_EQ(result.pathData, pathData);

  auto wireBuf = std::move(builtOut.second);
  folly::io::Cursor cursor(wireBuf.get());
  auto wireSimpleFrame = boost::get<QuicSimpleFrame>(parseQuicFrame(cursor));
  auto wirePathResponseFrame = boost::get<PathResponseFrame>(wireSimpleFrame);
  EXPECT_EQ(wirePathResponseFrame.pathData, pathData);
  EXPECT_TRUE(cursor.isAtEnd());
}
} // namespace test
} // namespace quic
