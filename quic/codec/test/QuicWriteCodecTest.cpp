/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <quic/codec/QuicWriteCodec.h>

#include <folly/Random.h>
#include <folly/io/Cursor.h>
#include <folly/portability/GMock.h>
#include <folly/portability/GTest.h>
#include <quic/QuicException.h>
#include <quic/codec/Decode.h>
#include <quic/codec/Types.h>
#include <quic/codec/test/Mocks.h>
#include <quic/common/BufUtil.h>
#include <quic/common/test/TestUtils.h>

using namespace quic;
using namespace quic::test;
using namespace testing;

ShortHeader buildTestShortHeader() {
  return ShortHeader(ProtectionType::KeyPhaseZero, getTestConnectionId(), 0x01);
}

QuicFrame parseQuicFrame(BufQueue& queue) {
  return quic::parseFrame(
      queue,
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
  EXPECT_CALL(pktBuilder, appendBytesWithAppender(_, _, _))
      .WillRepeatedly((Invoke(
          [&](BufAppender& appender, PacketNum value, uint8_t byteNumber) {
            auto bigValue = folly::Endian::big(value);
            appender.push(
                (uint8_t*)&bigValue + sizeof(bigValue) - byteNumber,
                byteNumber);
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

  EXPECT_CALL(pktBuilder, _insert(_, _))
      .WillRepeatedly(WithArgs<0, 1>(Invoke([&](Buf& buf, size_t limit) {
        pktBuilder.remaining_ -= limit;
        std::unique_ptr<folly::IOBuf> cloneBuf;
        folly::io::Cursor cursor(buf.get());
        cursor.clone(cloneBuf, limit);
        pktBuilder.appender_.insert(std::move(cloneBuf));
      })));

  EXPECT_CALL(pktBuilder, insert(_, _))
      .WillRepeatedly(
          WithArgs<0, 1>(Invoke([&](const BufQueue& buf, size_t limit) {
            pktBuilder.remaining_ -= limit;
            std::unique_ptr<folly::IOBuf> cloneBuf;
            folly::io::Cursor cursor(buf.front());
            cursor.clone(cloneBuf, limit);
            pktBuilder.appender_.insert(std::move(cloneBuf));
          })));

  EXPECT_CALL(pktBuilder, push(_, _))
      .WillRepeatedly(
          WithArgs<0, 1>(Invoke([&](const uint8_t* data, size_t len) {
            pktBuilder.appender_.push(data, len);
            pktBuilder.remaining_ -= len;
          })));

  EXPECT_CALL(pktBuilder, write(_))
      .WillRepeatedly(Invoke([&](const QuicInteger& quicInteger) {
        quicInteger.encode(
            [&](auto val) { pktBuilder.appender_.writeBE(val); });
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
  auto dataLen = writeStreamFrameHeader(
      pktBuilder, streamId, offset, 10, 10, fin, folly::none /* skipLenHint */);
  ASSERT_TRUE(dataLen);
  ASSERT_EQ(*dataLen, 10);
  writeStreamFrameData(pktBuilder, inputBuf->clone(), 10);
  auto outputBuf = pktBuilder.data_->clone();
  EXPECT_EQ(13, outputBuf->computeChainDataLength());
  EXPECT_EQ(
      kDefaultUDPSendPacketLen - 3 - 10, pktBuilder.remainingSpaceInPkt());
  auto builtOut = std::move(pktBuilder).buildTestPacket();
  auto regularPacket = std::move(builtOut.first);

  EXPECT_EQ(regularPacket.frames.size(), 1);
  auto& resultFrame = *regularPacket.frames.back().asWriteStreamFrame();
  EXPECT_EQ(resultFrame.streamId, streamId);
  EXPECT_EQ(resultFrame.offset, offset);
  EXPECT_EQ(resultFrame.len, 10);
  outputBuf->trimStart(3);
  EXPECT_TRUE(folly::IOBufEqualTo()(inputBuf, outputBuf));

  auto wireBuf = std::move(builtOut.second);
  BufQueue queue;
  queue.append(wireBuf->clone());
  QuicFrame quicFrameDecoded = parseQuicFrame(queue);
  auto& decodedStreamFrame = *quicFrameDecoded.asReadStreamFrame();
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
  auto inputBuf = buildRandomInputData(20);
  // 1 byte for type
  // 2 bytes for stream id
  // 4 bytes offset
  // 1 byte for length
  // => 8 bytes of header
  auto dataLen = writeStreamFrameHeader(
      pktBuilder, streamId, offset, 20, 20, fin, folly::none /* skipLenHint */);
  ASSERT_TRUE(dataLen);
  EXPECT_EQ(*dataLen, 20);
  writeStreamFrameData(pktBuilder, inputBuf->clone(), 20);
  auto outputBuf = pktBuilder.data_->clone();
  EXPECT_EQ(28, outputBuf->computeChainDataLength());
  size_t consumedSize = 1000 + 8 + 20;
  EXPECT_EQ(
      kDefaultUDPSendPacketLen - consumedSize,
      pktBuilder.remainingSpaceInPkt());

  auto builtOut = std::move(pktBuilder).buildTestPacket();
  auto regularPacket = std::move(builtOut.first);
  EXPECT_EQ(regularPacket.frames.size(), 1);
  auto& resultFrame = *regularPacket.frames.back().asWriteStreamFrame();
  EXPECT_EQ(resultFrame.streamId, streamId);
  EXPECT_EQ(resultFrame.offset, offset);
  EXPECT_EQ(resultFrame.len, 20);
  outputBuf->trimStart(8);
  EXPECT_TRUE(folly::IOBufEqualTo()(inputBuf, outputBuf));

  // Verify the on wire bytes via decoder:
  // (Awkwardly, this assumes the decoder is correct)
  auto wireBuf = std::move(builtOut.second);
  BufQueue queue;
  queue.append(wireBuf->clone());
  QuicFrame quicFrameDecoded = parseQuicFrame(queue);
  auto& decodedStreamFrame = *quicFrameDecoded.asReadStreamFrame();
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
  auto inputBuf = buildRandomInputData(30);
  auto dataLen = writeStreamFrameHeader(
      pktBuilder,
      streamId1,
      offset1,
      30,
      30,
      fin1,
      folly::none /* skipLenHint */);
  ASSERT_TRUE(dataLen);
  ASSERT_EQ(*dataLen, 30);
  writeStreamFrameData(pktBuilder, inputBuf->clone(), 30);
  auto outputBuf = pktBuilder.data_->clone();
  EXPECT_EQ(38, outputBuf->computeChainDataLength());
  size_t consumedSize = 1000 + 8 + 30;
  EXPECT_EQ(
      kDefaultUDPSendPacketLen - consumedSize,
      pktBuilder.remainingSpaceInPkt());

  StreamId streamId2 = 300;
  uint64_t offset2 = 65565;
  bool fin2 = false;
  uint64_t remainingSpace = pktBuilder.remainingSpaceInPkt();
  auto inputBuf2 = buildRandomInputData(remainingSpace);
  // 1 byte for type
  // 2 bytes for stream
  // 4 bytes for offset
  // => 7 bytes
  dataLen = writeStreamFrameHeader(
      pktBuilder,
      streamId2,
      offset2,
      remainingSpace,
      remainingSpace,
      fin2,
      folly::none /* skipLenHint */);
  ASSERT_TRUE(dataLen);
  ASSERT_EQ(*dataLen, remainingSpace - 7);
  writeStreamFrameData(pktBuilder, inputBuf2->clone(), remainingSpace - 7);
  auto outputBuf2 = pktBuilder.data_->clone();
  outputBuf2->coalesce();
  consumedSize += remainingSpace;
  EXPECT_EQ(
      kDefaultUDPSendPacketLen - consumedSize,
      pktBuilder.remainingSpaceInPkt());
  auto builtOut = std::move(pktBuilder).buildTestPacket();
  auto regularPacket = std::move(builtOut.first);
  EXPECT_EQ(regularPacket.frames.size(), 2);
  auto& resultFrame = *regularPacket.frames.front().asWriteStreamFrame();
  EXPECT_EQ(resultFrame.streamId, streamId1);
  EXPECT_EQ(resultFrame.offset, offset1);
  EXPECT_EQ(resultFrame.len, 30);
  outputBuf->trimStart(8);
  EXPECT_TRUE(folly::IOBufEqualTo()(inputBuf, outputBuf));

  auto& resultFrame2 = *regularPacket.frames.back().asWriteStreamFrame();
  EXPECT_EQ(resultFrame2.streamId, streamId2);
  EXPECT_EQ(resultFrame2.offset, offset2);
  EXPECT_EQ(resultFrame2.len, remainingSpace - 7);
  outputBuf2->trimStart(38 + 7);
  inputBuf2->trimEnd(7);
  EXPECT_TRUE(folly::IOBufEqualTo()(inputBuf2, outputBuf2));

  // Verify the on wire bytes via decoder:
  auto wireBuf = std::move(builtOut.second);
  BufQueue queue;
  queue.append(wireBuf->clone());
  QuicFrame streamFrameDecoded1 = quic::parseFrame(
      queue,
      regularPacket.header,
      CodecParameters(kDefaultAckDelayExponent, QuicVersion::MVFST));
  auto& decodedStreamFrame1 = *streamFrameDecoded1.asReadStreamFrame();
  EXPECT_EQ(decodedStreamFrame1.streamId, streamId1);
  EXPECT_EQ(decodedStreamFrame1.offset, offset1);
  EXPECT_EQ(decodedStreamFrame1.data->computeChainDataLength(), 30);
  EXPECT_TRUE(folly::IOBufEqualTo()(inputBuf, decodedStreamFrame1.data));
  // Read another one from wire output:
  QuicFrame streamFrameDecoded2 = quic::parseFrame(
      queue,
      regularPacket.header,
      CodecParameters(kDefaultAckDelayExponent, QuicVersion::MVFST));
  auto& decodedStreamFrame2 = *streamFrameDecoded2.asReadStreamFrame();
  EXPECT_EQ(decodedStreamFrame2.streamId, streamId2);
  EXPECT_EQ(decodedStreamFrame2.offset, offset2);
  EXPECT_EQ(
      decodedStreamFrame2.data->computeChainDataLength(), remainingSpace - 7);
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

  // 1 byte for type
  // 2 bytes for stream id
  // 4 bytes for offset
  // => 7 bytes for header
  auto dataLen = writeStreamFrameHeader(
      pktBuilder, streamId, offset, 50, 50, fin, folly::none /* skipLenHint */);
  ASSERT_TRUE(dataLen);
  ASSERT_EQ(*dataLen, 33);
  writeStreamFrameData(pktBuilder, inputBuf->clone(), 33);
  auto outputBuf = pktBuilder.data_->clone();
  EXPECT_EQ(40, outputBuf->computeChainDataLength());
  EXPECT_EQ(pktBuilder.remainingSpaceInPkt(), 0);
  auto builtOut = std::move(pktBuilder).buildTestPacket();
  auto regularPacket = builtOut.first;
  EXPECT_EQ(regularPacket.frames.size(), 1);
  auto& resultFrame = *regularPacket.frames.back().asWriteStreamFrame();
  EXPECT_EQ(resultFrame.streamId, streamId);
  EXPECT_EQ(resultFrame.offset, offset);
  EXPECT_EQ(resultFrame.len, 33);

  outputBuf->trimStart(7);
  inputBuf->trimEnd(inputBuf->computeChainDataLength() - 33);
  EXPECT_TRUE(folly::IOBufEqualTo()(inputBuf, outputBuf));

  auto wireBuf = std::move(builtOut.second);
  BufQueue queue;
  queue.append(wireBuf->clone());
  QuicFrame quicFrameDecoded = parseQuicFrame(queue);
  auto& decodedStreamFrame = *quicFrameDecoded.asReadStreamFrame();
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
  auto dataLen = writeStreamFrameHeader(
      pktBuilder, streamId, offset, 1, 1, fin, folly::none /* skipLenHint */);
  EXPECT_FALSE(dataLen);
  EXPECT_EQ(1, pktBuilder.remainingSpaceInPkt());
}

TEST_F(QuicWriteCodecTest, WriteStreamNoSpaceForData) {
  MockQuicPacketBuilder pktBuilder;
  pktBuilder.remaining_ = 3;
  setupCommonExpects(pktBuilder);

  StreamId streamId = 1;
  uint64_t offset = 1;
  bool fin = false;
  // 1 byte for type
  // 1 byte for stream id
  // 1 byte for offset
  // => 3 bytes
  auto dataLen = writeStreamFrameHeader(
      pktBuilder, streamId, offset, 10, 10, fin, folly::none /* skipLenHint */);
  EXPECT_FALSE(dataLen.has_value());
  EXPECT_EQ(pktBuilder.remainingSpaceInPkt(), 3);
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
  // 1 byte for type
  // 1 byte for stream id
  // 1 byte for offet
  // => 3 bytes
  auto dataLen = writeStreamFrameHeader(
      pktBuilder,
      streamId,
      offset,
      100,
      100,
      fin,
      folly::none /* skipLenHint */);
  ASSERT_TRUE(dataLen);
  ASSERT_EQ(*dataLen, 1);
  writeStreamFrameData(pktBuilder, inputBuf->clone(), 1);
  auto outputBuf = pktBuilder.data_->clone();
  EXPECT_EQ(pktBuilder.remainingSpaceInPkt(), 0);
  auto builtOut = std::move(pktBuilder).buildTestPacket();
  auto regularPacket = builtOut.first;

  EXPECT_EQ(regularPacket.frames.size(), 1);
  auto& resultFrame = *regularPacket.frames.back().asWriteStreamFrame();
  EXPECT_EQ(resultFrame.streamId, streamId);
  EXPECT_EQ(resultFrame.offset, offset);
  EXPECT_EQ(resultFrame.len, 1);
  inputBuf->trimEnd(inputBuf->computeChainDataLength() - 1);
  outputBuf->trimStart(3);
  EXPECT_TRUE(folly::IOBufEqualTo()(inputBuf, outputBuf));

  auto wireBuf = std::move(builtOut.second);
  BufQueue queue;
  queue.append(wireBuf->clone());
  QuicFrame decodedFrame = quic::parseFrame(
      queue,
      regularPacket.header,
      CodecParameters(kDefaultAckDelayExponent, QuicVersion::MVFST));
  auto decodedStreamFrame = *decodedFrame.asReadStreamFrame();
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
  // 1 byte for stream id
  // 1 byte for length
  // => 3 byte
  StreamId streamId = 1;
  uint64_t offset = 0;
  bool fin = true;
  auto dataLen = writeStreamFrameHeader(
      pktBuilder, streamId, offset, 10, 10, fin, folly::none /* skipLenHint */);
  ASSERT_TRUE(dataLen);
  ASSERT_EQ(*dataLen, 10);
  writeStreamFrameData(pktBuilder, inputBuf->clone(), 10);
  auto outputBuf = pktBuilder.data_->clone();

  auto builtOut = std::move(pktBuilder).buildTestPacket();
  auto regularPacket = builtOut.first;

  EXPECT_EQ(regularPacket.frames.size(), 1);
  auto& resultFrame = *regularPacket.frames.back().asWriteStreamFrame();
  EXPECT_EQ(resultFrame.streamId, streamId);
  EXPECT_EQ(resultFrame.offset, offset);
  EXPECT_EQ(inputBuf->computeChainDataLength(), resultFrame.len);
  EXPECT_TRUE(resultFrame.fin);
  outputBuf->trimStart(3);
  EXPECT_TRUE(folly::IOBufEqualTo()(inputBuf, outputBuf));

  auto wireBuf = std::move(builtOut.second);
  folly::io::Cursor cursor(wireBuf.get());
  BufQueue queue;
  queue.append(wireBuf->clone());
  QuicFrame decodedFrame = quic::parseFrame(
      queue,
      regularPacket.header,
      CodecParameters(kDefaultAckDelayExponent, QuicVersion::MVFST));
  auto& decodedStreamFrame = *decodedFrame.asReadStreamFrame();
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
  // 1 byte for stream id
  // 1 byte for length
  // => 3 byte
  StreamId streamId = 1;
  uint64_t offset = 0;
  bool fin = true;
  auto dataLen = writeStreamFrameHeader(
      pktBuilder,
      streamId,
      offset,
      inDataSize,
      inDataSize,
      fin,
      folly::none /* skipLenHint */);
  ASSERT_TRUE(dataLen);
  EXPECT_LT(*dataLen, inDataSize);
}

TEST_F(QuicWriteCodecTest, TestWriteNoDataAndFin) {
  MockQuicPacketBuilder pktBuilder;
  setupCommonExpects(pktBuilder);

  // 1 byte for type
  // 1 byte for stream id
  // => 2 byte
  StreamId streamId = 1;
  uint64_t offset = 0;
  bool fin = true;
  Buf empty;
  auto dataLen = writeStreamFrameHeader(
      pktBuilder, streamId, offset, 0, 0, fin, folly::none /* skipLenHint */);
  ASSERT_TRUE(dataLen);
  EXPECT_EQ(*dataLen, 0);
}

TEST_F(QuicWriteCodecTest, TestWriteNoDataAndNoFin) {
  MockQuicPacketBuilder pktBuilder;
  setupCommonExpects(pktBuilder);
  StreamId streamId = 1;
  uint64_t offset = 0;
  bool fin = false;
  Buf empty;
  EXPECT_THROW(
      writeStreamFrameHeader(
          pktBuilder,
          streamId,
          offset,
          0,
          0,
          fin,
          folly::none /* skipLenHint */),
      QuicInternalException);
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
  auto dataLen = writeStreamFrameHeader(
      pktBuilder, streamId, offset, 20, 20, fin, folly::none /* skipLenHint */);
  EXPECT_FALSE(dataLen.has_value());
  EXPECT_EQ(pktBuilder.remainingSpaceInPkt(), 2);
}

TEST_F(QuicWriteCodecTest, PacketOnlyHasSpaceForStreamHeaderWithFin) {
  MockQuicPacketBuilder pktBuilder;
  pktBuilder.remaining_ = 3;
  setupCommonExpects(pktBuilder);
  // 1 byte for type
  // 1 byte for stream id
  // 1 byte for length
  // => 3 byte
  StreamId streamId = 1;
  uint64_t offset = 0;
  bool fin = true;
  auto dataLen = writeStreamFrameHeader(
      pktBuilder, streamId, offset, 0, 0, fin, folly::none /* skipLenHint */);
  ASSERT_TRUE(dataLen.has_value());
  EXPECT_EQ(*dataLen, 0);
  EXPECT_EQ(pktBuilder.remainingSpaceInPkt(), 0);
}

TEST_F(QuicWriteCodecTest, PacketNotEnoughSpaceForStreamHeaderWithFin) {
  MockQuicPacketBuilder pktBuilder;
  pktBuilder.remaining_ = 2;
  setupCommonExpects(pktBuilder);
  // 1 byte for type
  // 1 byte for stream id
  // 1 byte for length
  // => 3 byte
  StreamId streamId = 1;
  uint64_t offset = 0;
  bool fin = true;
  auto dataLen = writeStreamFrameHeader(
      pktBuilder, streamId, offset, 0, 0, fin, folly::none /* skipLenHint */);
  ASSERT_FALSE(dataLen.has_value());
  EXPECT_EQ(pktBuilder.remainingSpaceInPkt(), 2);
}

TEST_F(QuicWriteCodecTest, WriteStreamFrameHeadeSkipLen) {
  MockQuicPacketBuilder pktBuilder;
  size_t packetLimit = 1200;
  EXPECT_CALL(pktBuilder, appendFrame(_)).Times(1);
  EXPECT_CALL(pktBuilder, remainingSpaceInPkt()).WillRepeatedly(Invoke([&]() {
    return packetLimit;
  }));
  // initial byte:
  EXPECT_CALL(pktBuilder, writeBEUint8(_)).WillOnce(Invoke([&](uint8_t) {
    packetLimit--;
  }));
  // write twice: stream id and offste
  EXPECT_CALL(pktBuilder, write(_))
      .Times(2)
      .WillRepeatedly(Invoke([&](const QuicInteger& quicInt) {
        packetLimit -= quicInt.getSize();
      }));
  StreamId streamId = 0;
  uint64_t offset = 10;
  bool fin = false;
  auto dataLen = writeStreamFrameHeader(
      pktBuilder, streamId, offset, 1200 * 2, 1200 * 2, fin, folly::none);
  EXPECT_LT(*dataLen, 1200);
}

TEST_F(QuicWriteCodecTest, WriteStreamFrameHeadeNotSkipLen) {
  MockQuicPacketBuilder pktBuilder;
  size_t packetLimit = 1200;
  EXPECT_CALL(pktBuilder, appendFrame(_)).Times(1);
  EXPECT_CALL(pktBuilder, remainingSpaceInPkt()).WillRepeatedly(Invoke([&]() {
    return packetLimit;
  }));
  // initial byte:
  EXPECT_CALL(pktBuilder, writeBEUint8(_)).WillOnce(Invoke([&](uint8_t) {
    packetLimit--;
  }));
  // write three times: stream id and offste and data len
  EXPECT_CALL(pktBuilder, write(_))
      .Times(3)
      .WillRepeatedly(Invoke([&](const QuicInteger& quicInt) {
        packetLimit -= quicInt.getSize();
      }));
  StreamId streamId = 0;
  uint64_t offset = 10;
  bool fin = false;
  auto dataLen = writeStreamFrameHeader(
      pktBuilder, streamId, offset, 200, 200, fin, folly::none);
  EXPECT_EQ(*dataLen, 200);
}

TEST_F(QuicWriteCodecTest, WriteStreamFrameHeadeLengthHintTrue) {
  MockQuicPacketBuilder pktBuilder;
  size_t packetLimit = 1200;
  EXPECT_CALL(pktBuilder, appendFrame(_)).Times(1);
  EXPECT_CALL(pktBuilder, remainingSpaceInPkt()).WillRepeatedly(Invoke([&]() {
    return packetLimit;
  }));
  // initial byte:
  EXPECT_CALL(pktBuilder, writeBEUint8(_)).WillOnce(Invoke([&](uint8_t) {
    packetLimit--;
  }));
  // write twice: stream id and offste
  EXPECT_CALL(pktBuilder, write(_))
      .Times(2)
      .WillRepeatedly(Invoke([&](const QuicInteger& quicInt) {
        packetLimit -= quicInt.getSize();
      }));
  StreamId streamId = 0;
  uint64_t offset = 10;
  bool fin = false;
  auto dataLen =
      writeStreamFrameHeader(pktBuilder, streamId, offset, 200, 200, fin, true);
  EXPECT_EQ(*dataLen, 200);
}

TEST_F(QuicWriteCodecTest, WriteStreamFrameHeadeLengthHintFalse) {
  MockQuicPacketBuilder pktBuilder;
  size_t packetLimit = 1200;
  EXPECT_CALL(pktBuilder, appendFrame(_)).Times(1);
  EXPECT_CALL(pktBuilder, remainingSpaceInPkt()).WillRepeatedly(Invoke([&]() {
    return packetLimit;
  }));
  // initial byte:
  EXPECT_CALL(pktBuilder, writeBEUint8(_)).WillOnce(Invoke([&](uint8_t) {
    packetLimit--;
  }));
  // write three times: stream id and offste and data len
  EXPECT_CALL(pktBuilder, write(_))
      .Times(3)
      .WillRepeatedly(Invoke([&](const QuicInteger& quicInt) {
        packetLimit -= quicInt.getSize();
      }));
  StreamId streamId = 0;
  uint64_t offset = 10;
  bool fin = false;
  auto dataLen = writeStreamFrameHeader(
      pktBuilder, streamId, offset, 1200 * 2, 1200 * 2, fin, false);
  EXPECT_LT(*dataLen, 1200);
}

TEST_F(QuicWriteCodecTest, AckFrameGapExceedsRepresentation) {
  MockQuicPacketBuilder pktBuilder;
  setupCommonExpects(pktBuilder);

  PacketNum max = std::numeric_limits<uint64_t>::max();
  // Can't use max directly, because it will exceed interval set's
  // representation.
  AckBlocks ackBlocks = {{max - 10, max - 10}, {1, 1}};
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
  AckBlocks ackBlocks = {{1, largest}};
  AckFrameMetaData ackMetadata(ackBlocks, 0us, kDefaultAckDelayExponent);

  auto ackFrameWriteResult = *writeAckFrame(ackMetadata, pktBuilder);

  EXPECT_EQ(19, ackFrameWriteResult.bytesWritten);
  EXPECT_EQ(kDefaultUDPSendPacketLen - 19, pktBuilder.remainingSpaceInPkt());
  auto builtOut = std::move(pktBuilder).buildTestPacket();
  auto regularPacket = builtOut.first;
  EXPECT_EQ(regularPacket.frames.size(), 1);
  WriteAckFrame& ackFrame = *regularPacket.frames.back().asWriteAckFrame();
  EXPECT_EQ(ackFrame.ackBlocks.size(), 1);

  EXPECT_EQ(ackFrame.ackBlocks.back().start, 1);
  EXPECT_EQ(largest, ackFrame.ackBlocks.back().end);
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
  AckBlocks ackBlocks = {{1000, 1000}, {500, 700}, {100, 200}};
  // 4 btyes are just not enough for anything
  AckFrameMetaData ackMetadata(ackBlocks, 555us, kDefaultAckDelayExponent);

  auto result = writeAckFrame(ackMetadata, pktBuilder);
  EXPECT_FALSE(result.has_value());
  EXPECT_EQ(pktBuilder.remainingSpaceInPkt(), 4);
}

TEST_F(QuicWriteCodecTest, WriteSimpleAckFrame) {
  MockQuicPacketBuilder pktBuilder;
  setupCommonExpects(pktBuilder);
  auto ackDelay = 111us;
  AckBlocks ackBlocks = {{501, 1000}, {101, 400}};
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
  auto builtOut = std::move(pktBuilder).buildTestPacket();
  auto regularPacket = builtOut.first;
  WriteAckFrame& ackFrame = *regularPacket.frames.back().asWriteAckFrame();
  EXPECT_EQ(ackFrame.ackBlocks.size(), 2);
  auto iter = ackFrame.ackBlocks.crbegin();
  EXPECT_EQ(iter->start, 101);
  EXPECT_EQ(iter->end, 400);
  iter++;
  EXPECT_EQ(iter->start, 501);
  EXPECT_EQ(iter->end, 1000);

  auto wireBuf = std::move(builtOut.second);
  BufQueue queue;
  queue.append(wireBuf->clone());
  QuicFrame decodedFrame = parseQuicFrame(queue);
  auto& decodedAckFrame = *decodedFrame.asReadAckFrame();
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
  AckBlocks ackBlocks = {{501, 1000}, {101, 400}};
  AckFrameMetaData meta(ackBlocks, ackDelay, kDefaultAckDelayExponent);

  writeAckFrame(meta, pktBuilder);
  auto builtOut = std::move(pktBuilder).buildTestPacket();
  auto regularPacket = builtOut.first;
  WriteAckFrame& ackFrame = *regularPacket.frames.back().asWriteAckFrame();
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
  AckBlocks ackBlocks;
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
  auto builtOut = std::move(pktBuilder).buildTestPacket();
  auto regularPacket = builtOut.first;
  EXPECT_EQ(regularPacket.frames.size(), 1);
  WriteAckFrame& ackFrame = *regularPacket.frames.back().asWriteAckFrame();
  EXPECT_EQ(ackFrame.ackBlocks.size(), 64);

  EXPECT_EQ(ackFrame.ackBlocks.back().start, 746);
  EXPECT_EQ(ackFrame.ackBlocks.back().end, 748);
}

TEST_F(QuicWriteCodecTest, WriteWithDifferentAckDelayExponent) {
  MockQuicPacketBuilder pktBuilder;
  setupCommonExpects(pktBuilder);

  AckBlocks ackBlocks{{1000, 1000}};
  uint8_t ackDelayExponent = 6;
  AckFrameMetaData ackMetadata(ackBlocks, 1240us, ackDelayExponent);

  writeAckFrame(ackMetadata, pktBuilder);
  auto builtOut = std::move(pktBuilder).buildTestPacket();
  auto wireBuf = std::move(builtOut.second);
  BufQueue queue;
  queue.append(wireBuf->clone());
  QuicFrame decodedFrame = quic::parseFrame(
      queue,
      builtOut.first.header,
      CodecParameters(ackDelayExponent, QuicVersion::MVFST));
  auto& decodedAckFrame = *decodedFrame.asReadAckFrame();
  EXPECT_EQ(
      decodedAckFrame.ackDelay.count(),
      computeExpectedDelay(ackMetadata.ackDelay, ackDelayExponent));
}

TEST_F(QuicWriteCodecTest, WriteExponentInLongHeaderPacket) {
  MockQuicPacketBuilder pktBuilder;
  setupCommonExpects(pktBuilder);

  AckBlocks ackBlocks{{1000, 1000}};
  uint8_t ackDelayExponent = 6;
  AckFrameMetaData ackMetadata(ackBlocks, 1240us, ackDelayExponent);

  writeAckFrame(ackMetadata, pktBuilder);
  auto builtOut = std::move(pktBuilder).buildLongHeaderPacket();
  auto wireBuf = std::move(builtOut.second);
  folly::io::Cursor cursor(wireBuf.get());
  BufQueue queue;
  queue.append(wireBuf->clone());
  QuicFrame decodedFrame = quic::parseFrame(
      queue,
      builtOut.first.header,
      CodecParameters(ackDelayExponent, QuicVersion::MVFST));
  auto& decodedAckFrame = *decodedFrame.asReadAckFrame();
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
  AckBlocks ackBlocks{{1000, 1000}};
  AckFrameMetaData ackMetadata(ackBlocks, 555us, kDefaultAckDelayExponent);

  // No AckBlock is added to the metadata. There will still be one block
  // generated as the first block to cover largestAcked => 2 bytes
  auto ackFrameWriteResult = *writeAckFrame(ackMetadata, pktBuilder);
  EXPECT_EQ(7, ackFrameWriteResult.bytesWritten);
  EXPECT_EQ(kDefaultUDPSendPacketLen - 7, pktBuilder.remainingSpaceInPkt());
  auto builtOut = std::move(pktBuilder).buildTestPacket();
  auto regularPacket = builtOut.first;
  EXPECT_EQ(regularPacket.frames.size(), 1);
  WriteAckFrame& ackFrame = *regularPacket.frames.back().asWriteAckFrame();
  EXPECT_EQ(ackFrame.ackBlocks.size(), 1);
  EXPECT_EQ(ackFrame.ackBlocks.front().start, 1000);
  EXPECT_EQ(ackFrame.ackBlocks.front().end, 1000);

  // Verify the on wire bytes via decoder:
  // (Awkwardly, this assumes the decoder is correct)
  auto wireBuf = std::move(builtOut.second);
  BufQueue queue;
  queue.append(wireBuf->clone());
  QuicFrame decodedFrame = parseQuicFrame(queue);
  auto& decodedAckFrame = *decodedFrame.asReadAckFrame();
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
  AckBlocks testAckBlocks;
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
  auto builtOut = std::move(pktBuilder).buildTestPacket();
  auto regularPacket = builtOut.first;
  EXPECT_EQ(regularPacket.frames.size(), 1);
  WriteAckFrame& ackFrame = *regularPacket.frames.back().asWriteAckFrame();
  EXPECT_EQ(ackFrame.ackBlocks.size(), 14);

  // Verify the on wire bytes via decoder:
  // (Awkwardly, this assumes the decoder is correct)
  auto wireBuf = std::move(builtOut.second);
  BufQueue queue;
  queue.append(wireBuf->clone());
  QuicFrame decodedFrame = parseQuicFrame(queue);
  auto& decodedAckFrame = *decodedFrame.asReadAckFrame();
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
  AckBlocks ackBlocks = {{1000, 1000}, {701, 900}, {501, 600}};
  AckFrameMetaData ackMetadata(ackBlocks, 555us, kDefaultAckDelayExponent);
  auto ackFrameWriteResult = writeAckFrame(ackMetadata, pktBuilder);
  EXPECT_FALSE(ackFrameWriteResult.has_value());
}

TEST_F(QuicWriteCodecTest, OnlyHasSpaceForFirstAckBlock) {
  MockQuicPacketBuilder pktBuilder;
  pktBuilder.remaining_ = 10;
  setupCommonExpects(pktBuilder);

  // 1 type byte,
  // 2 bytes for largest acked, 2 bytes for ack delay => 4 bytes
  // 1 byte for num ack blocks
  // 1 byte for first ack block length
  AckBlocks ackBlocks = {{1000, 1000}, {701, 900}, {501, 600}};
  AckFrameMetaData ackMetadata(ackBlocks, 555us, kDefaultAckDelayExponent);
  auto ackFrameWriteResult = *writeAckFrame(ackMetadata, pktBuilder);

  EXPECT_EQ(ackFrameWriteResult.bytesWritten, 7);
  EXPECT_EQ(pktBuilder.remainingSpaceInPkt(), 3);
  auto builtOut = std::move(pktBuilder).buildTestPacket();
  WriteAckFrame& ackFrame = *builtOut.first.frames.back().asWriteAckFrame();
  EXPECT_EQ(ackFrame.ackBlocks.size(), 1);
  EXPECT_EQ(ackFrame.ackBlocks.front().start, 1000);
  EXPECT_EQ(ackFrame.ackBlocks.front().end, 1000);

  auto wireBuf = std::move(builtOut.second);
  BufQueue queue;
  queue.append(wireBuf->clone());
  QuicFrame decodedFrame = parseQuicFrame(queue);
  auto& decodedAckFrame = *decodedFrame.asReadAckFrame();
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

  auto builtOut = std::move(pktBuilder).buildTestPacket();
  auto regularPacket = builtOut.first;
  EXPECT_EQ(bytesWritten, 3);
  auto& resultMaxStreamDataFrame =
      *regularPacket.frames[0].asMaxStreamDataFrame();
  EXPECT_EQ(id, resultMaxStreamDataFrame.streamId);
  EXPECT_EQ(offset, resultMaxStreamDataFrame.maximumData);

  auto wireBuf = std::move(builtOut.second);
  BufQueue queue;
  queue.append(wireBuf->clone());
  QuicFrame decodedFrame = parseQuicFrame(queue);
  auto& wireMaxStreamDataFrame = *decodedFrame.asMaxStreamDataFrame();
  EXPECT_EQ(id, wireMaxStreamDataFrame.streamId);
  EXPECT_EQ(offset, wireMaxStreamDataFrame.maximumData);

  // At last, verify there is nothing left in the wire format bytes:
  EXPECT_EQ(queue.chainLength(), 0);
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

  auto builtOut = std::move(pktBuilder).buildTestPacket();
  auto regularPacket = builtOut.first;
  EXPECT_EQ(bytesWritten, 3);
  auto& resultMaxDataFrame = *regularPacket.frames[0].asMaxDataFrame();
  EXPECT_EQ(1000, resultMaxDataFrame.maximumData);

  auto wireBuf = std::move(builtOut.second);
  BufQueue queue;
  queue.append(wireBuf->clone());
  QuicFrame decodedFrame = parseQuicFrame(queue);
  auto& wireMaxDataFrame = *decodedFrame.asMaxDataFrame();
  EXPECT_EQ(1000, wireMaxDataFrame.maximumData);
  EXPECT_EQ(queue.chainLength(), 0);
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
    auto bytesWritten =
        writeFrame(QuicSimpleFrame(maxStreamsFrame), pktBuilder);

    auto builtOut = std::move(pktBuilder).buildTestPacket();
    auto regularPacket = builtOut.first;
    auto streamCountSize = i < 64 ? 1 : 2;
    // 1 byte for the type and up to 2 bytes for the stream count.
    EXPECT_EQ(1 + streamCountSize, bytesWritten);
    MaxStreamsFrame& resultMaxStreamIdFrame =
        *regularPacket.frames[0].asQuicSimpleFrame()->asMaxStreamsFrame();
    EXPECT_EQ(i, resultMaxStreamIdFrame.maxStreams);

    auto wireBuf = std::move(builtOut.second);
    folly::io::Cursor cursor(wireBuf.get());
    BufQueue queue;
    queue.append(wireBuf->clone());
    QuicFrame decodedFrame = parseQuicFrame(queue);
    QuicSimpleFrame& simpleFrame = *decodedFrame.asQuicSimpleFrame();
    MaxStreamsFrame& wireStreamsFrame = *simpleFrame.asMaxStreamsFrame();
    EXPECT_EQ(i, wireStreamsFrame.maxStreams);
    EXPECT_EQ(queue.chainLength(), 0);
  }
}

TEST_F(QuicWriteCodecTest, WriteUniMaxStreamId) {
  for (uint64_t i = 0; i < 100; i++) {
    MockQuicPacketBuilder pktBuilder;
    setupCommonExpects(pktBuilder);
    uint64_t maxStream = i;
    bool isBidirectional = false;
    MaxStreamsFrame maxStreamsFrame(maxStream, isBidirectional);
    auto bytesWritten =
        writeFrame(QuicSimpleFrame(maxStreamsFrame), pktBuilder);

    auto builtOut = std::move(pktBuilder).buildTestPacket();
    auto regularPacket = builtOut.first;
    auto streamCountSize = i < 64 ? 1 : 2;
    // 1 byte for the type and up to 2 bytes for the stream count.
    EXPECT_EQ(1 + streamCountSize, bytesWritten);
    MaxStreamsFrame& resultMaxStreamIdFrame =
        *regularPacket.frames[0].asQuicSimpleFrame()->asMaxStreamsFrame();
    EXPECT_EQ(i, resultMaxStreamIdFrame.maxStreams);

    auto wireBuf = std::move(builtOut.second);
    BufQueue queue;
    queue.append(wireBuf->clone());
    QuicFrame decodedFrame = parseQuicFrame(queue);
    QuicSimpleFrame& simpleFrame = *decodedFrame.asQuicSimpleFrame();
    MaxStreamsFrame& wireStreamsFrame = *simpleFrame.asMaxStreamsFrame();
    EXPECT_EQ(i, wireStreamsFrame.maxStreams);
    EXPECT_EQ(queue.chainLength(), 0);
  }
}

TEST_F(QuicWriteCodecTest, NoSpaceForMaxStreamId) {
  MockQuicPacketBuilder pktBuilder;
  pktBuilder.remaining_ = 0;
  setupCommonExpects(pktBuilder);
  StreamId maxStream = 0x1234;
  MaxStreamsFrame maxStreamIdFrame(maxStream, true);
  EXPECT_EQ(0, writeFrame(QuicSimpleFrame(maxStreamIdFrame), pktBuilder));
}

TEST_F(QuicWriteCodecTest, WriteConnClose) {
  MockQuicPacketBuilder pktBuilder;
  setupCommonExpects(pktBuilder);
  std::string reasonPhrase("You are fired");
  ConnectionCloseFrame connectionCloseFrame(
      QuicErrorCode(TransportErrorCode::PROTOCOL_VIOLATION), reasonPhrase);
  auto connCloseBytesWritten =
      writeFrame(std::move(connectionCloseFrame), pktBuilder);

  auto builtOut = std::move(pktBuilder).buildTestPacket();
  auto regularPacket = builtOut.first;
  // 6 == ErrorCode(2) + FrameType(1) + reasonPhrase-len(2)
  EXPECT_EQ(4 + reasonPhrase.size(), connCloseBytesWritten);
  auto& resultConnCloseFrame =
      *regularPacket.frames[0].asConnectionCloseFrame();
  const TransportErrorCode* transportErrorCode =
      resultConnCloseFrame.errorCode.asTransportErrorCode();
  EXPECT_EQ(TransportErrorCode::PROTOCOL_VIOLATION, *transportErrorCode);
  EXPECT_EQ("You are fired", resultConnCloseFrame.reasonPhrase);

  auto wireBuf = std::move(builtOut.second);
  BufQueue queue;
  queue.append(wireBuf->clone());
  QuicFrame decodedCloseFrame = parseQuicFrame(queue);
  auto& wireConnCloseFrame = *decodedCloseFrame.asConnectionCloseFrame();
  const TransportErrorCode* protocolViolationCode =
      wireConnCloseFrame.errorCode.asTransportErrorCode();
  EXPECT_EQ(TransportErrorCode::PROTOCOL_VIOLATION, *protocolViolationCode);
  EXPECT_EQ("You are fired", wireConnCloseFrame.reasonPhrase);

  // At last, verify there is nothing left in the wire format bytes:
  EXPECT_EQ(queue.chainLength(), 0);
}

TEST_F(QuicWriteCodecTest, DecodeConnCloseLarge) {
  MockQuicPacketBuilder pktBuilder;
  setupCommonExpects(pktBuilder);
  std::string reasonPhrase;
  reasonPhrase.resize(kMaxReasonPhraseLength + 10);
  ConnectionCloseFrame connectionCloseFrame(
      QuicErrorCode(TransportErrorCode::PROTOCOL_VIOLATION), reasonPhrase);
  writeFrame(connectionCloseFrame, pktBuilder);
  auto builtOut = std::move(pktBuilder).buildTestPacket();
  auto regularPacket = builtOut.first;
  auto& resultConnCloseFrame =
      *regularPacket.frames[0].asConnectionCloseFrame();
  const TransportErrorCode* protocolViolationCode =
      resultConnCloseFrame.errorCode.asTransportErrorCode();
  EXPECT_EQ(TransportErrorCode::PROTOCOL_VIOLATION, *protocolViolationCode);
  EXPECT_EQ(resultConnCloseFrame.reasonPhrase, reasonPhrase);

  auto wireBuf = std::move(builtOut.second);
  BufQueue queue;
  queue.append(wireBuf->clone());
  EXPECT_THROW(parseQuicFrame(queue), QuicTransportException);
}

TEST_F(QuicWriteCodecTest, NoSpaceConnClose) {
  MockQuicPacketBuilder pktBuilder;
  pktBuilder.remaining_ = 2;
  setupCommonExpects(pktBuilder);
  std::string reasonPhrase("You are all fired");
  ConnectionCloseFrame connCloseFrame(
      QuicErrorCode(TransportErrorCode::PROTOCOL_VIOLATION), reasonPhrase);
  EXPECT_EQ(0, writeFrame(std::move(connCloseFrame), pktBuilder));
}

TEST_F(QuicWriteCodecTest, DecodeAppCloseLarge) {
  MockQuicPacketBuilder pktBuilder;
  setupCommonExpects(pktBuilder);
  std::string reasonPhrase;
  reasonPhrase.resize(kMaxReasonPhraseLength + 10);
  ConnectionCloseFrame applicationCloseFrame(
      QuicErrorCode(GenericApplicationErrorCode::UNKNOWN),
      reasonPhrase,
      quic::FrameType::CONNECTION_CLOSE_APP_ERR);
  writeFrame(std::move(applicationCloseFrame), pktBuilder);

  auto builtOut = std::move(pktBuilder).buildTestPacket();
  auto regularPacket = builtOut.first;
  auto& resultAppCloseFrame = *regularPacket.frames[0].asConnectionCloseFrame();
  EXPECT_EQ(
      quic::FrameType::CONNECTION_CLOSE_APP_ERR,
      resultAppCloseFrame.closingFrameType);
  EXPECT_EQ(resultAppCloseFrame.reasonPhrase, reasonPhrase);

  auto wireBuf = std::move(builtOut.second);
  BufQueue queue;
  queue.append(wireBuf->clone());
  EXPECT_THROW(parseQuicFrame(queue), QuicTransportException);
}

TEST_F(QuicWriteCodecTest, WritePing) {
  MockQuicPacketBuilder pktBuilder;
  setupCommonExpects(pktBuilder);
  auto pingBytesWritten = writeFrame(PingFrame(), pktBuilder);

  auto builtOut = std::move(pktBuilder).buildTestPacket();
  auto regularPacket = builtOut.first;
  EXPECT_EQ(1, pingBytesWritten);
  auto pingFrame = regularPacket.frames[0].asPingFrame();
  EXPECT_NE(pingFrame, nullptr);

  auto wireBuf = std::move(builtOut.second);
  BufQueue queue;
  queue.append(wireBuf->clone());
  QuicFrame decodedFrame = parseQuicFrame(queue);
  auto decodedPingFrame = decodedFrame.asPingFrame();
  EXPECT_NE(decodedPingFrame, nullptr);

  // At last, verify there is nothing left in the wire format bytes:
  EXPECT_EQ(queue.chainLength(), 0);
}

TEST_F(QuicWriteCodecTest, NoSpaceForPing) {
  MockQuicPacketBuilder pktBuilder;
  pktBuilder.remaining_ = 0;
  setupCommonExpects(pktBuilder);
  EXPECT_EQ(0, writeFrame(PingFrame(), pktBuilder));
}

TEST_F(QuicWriteCodecTest, WritePadding) {
  MockQuicPacketBuilder pktBuilder;
  setupCommonExpects(pktBuilder);
  auto paddingBytesWritten = writeFrame(PaddingFrame(), pktBuilder);

  auto builtOut = std::move(pktBuilder).buildTestPacket();
  auto regularPacket = builtOut.first;
  EXPECT_EQ(1, paddingBytesWritten);
  EXPECT_NE(regularPacket.frames[0].asPaddingFrame(), nullptr);

  auto wireBuf = std::move(builtOut.second);
  BufQueue queue;
  queue.append(wireBuf->clone());
  QuicFrame decodedFrame = parseQuicFrame(queue);
  EXPECT_NE(decodedFrame.asPaddingFrame(), nullptr);

  // At last, verify there is nothing left in the wire format bytes:
  EXPECT_EQ(queue.chainLength(), 0);
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

  auto builtOut = std::move(pktBuilder).buildTestPacket();
  auto regularPacket = builtOut.first;
  EXPECT_EQ(blockedBytesWritten, 7);
  EXPECT_NE(regularPacket.frames[0].asStreamDataBlockedFrame(), nullptr);

  auto wireBuf = std::move(builtOut.second);
  BufQueue queue;
  queue.append(wireBuf->clone());
  QuicFrame decodedFrame = parseQuicFrame(queue);
  auto& wireBlockedFrame = *decodedFrame.asStreamDataBlockedFrame();
  EXPECT_EQ(blockedId, wireBlockedFrame.streamId);
  EXPECT_EQ(blockedOffset, wireBlockedFrame.dataLimit);
  // At last, verify there is nothing left in the wire format bytes:
  EXPECT_EQ(queue.chainLength(), 0);
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

  auto builtOut = std::move(pktBuilder).buildTestPacket();
  auto regularPacket = builtOut.first;
  EXPECT_EQ(13, rstStreamBytesWritten);
  auto& resultRstStreamFrame = *regularPacket.frames[0].asRstStreamFrame();
  EXPECT_EQ(errorCode, resultRstStreamFrame.errorCode);
  EXPECT_EQ(id, resultRstStreamFrame.streamId);
  EXPECT_EQ(offset, resultRstStreamFrame.offset);

  auto wireBuf = std::move(builtOut.second);
  BufQueue queue;
  queue.append(wireBuf->clone());
  QuicFrame decodedFrame = parseQuicFrame(queue);
  auto& wireRstStreamFrame = *decodedFrame.asRstStreamFrame();
  EXPECT_EQ(errorCode, wireRstStreamFrame.errorCode);
  EXPECT_EQ(id, wireRstStreamFrame.streamId);
  EXPECT_EQ(offset, wireRstStreamFrame.offset);
  // At last, verify there is nothing left in the wire format bytes:
  EXPECT_EQ(queue.chainLength(), 0);
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

  auto builtOut = std::move(pktBuilder).buildTestPacket();
  auto regularPacket = builtOut.first;
  EXPECT_EQ(bytesWritten, 5);
  EXPECT_NE(regularPacket.frames[0].asDataBlockedFrame(), nullptr);

  auto wireBuf = std::move(builtOut.second);
  BufQueue queue;
  queue.append(wireBuf->clone());
  QuicFrame decodedFrame = parseQuicFrame(queue);
  auto& wireBlockedFrame = *decodedFrame.asDataBlockedFrame();
  EXPECT_EQ(wireBlockedFrame.dataLimit, blockedOffset);
  EXPECT_EQ(queue.chainLength(), 0);
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
  auto bytesWritten = writeFrame(QuicSimpleFrame(streamIdNeeded), pktBuilder);

  auto builtOut = std::move(pktBuilder).buildTestPacket();
  auto regularPacket = builtOut.first;
  EXPECT_EQ(bytesWritten, 3);
  EXPECT_NE(
      regularPacket.frames[0].asQuicSimpleFrame()->asMaxStreamsFrame(),
      nullptr);

  auto wireBuf = std::move(builtOut.second);
  BufQueue queue;
  queue.append(wireBuf->clone());
  QuicFrame decodedFrame = parseQuicFrame(queue);
  QuicSimpleFrame& simpleFrame = *decodedFrame.asQuicSimpleFrame();
  auto& writeStreamIdBlocked = *simpleFrame.asMaxStreamsFrame();
  EXPECT_EQ(writeStreamIdBlocked.maxStreams, blockedStreamId);
  EXPECT_EQ(queue.chainLength(), 0);
}

TEST_F(QuicWriteCodecTest, NoSpaceForStreamIdNeeded) {
  MockQuicPacketBuilder pktBuilder;
  pktBuilder.remaining_ = 0;
  setupCommonExpects(pktBuilder);
  StreamId blockedStreamId = 0x211;
  MaxStreamsFrame streamIdNeeded(blockedStreamId, true);
  EXPECT_EQ(0, writeFrame(QuicSimpleFrame(streamIdNeeded), pktBuilder));
}

TEST_F(QuicWriteCodecTest, WriteNewConnId) {
  MockQuicPacketBuilder pktBuilder;
  setupCommonExpects(pktBuilder);
  StatelessResetToken token;
  memset(token.data(), 'a', token.size());
  NewConnectionIdFrame newConnId(1, 0, getTestConnectionId(), token);
  auto bytesWritten = writeFrame(QuicSimpleFrame(newConnId), pktBuilder);

  auto builtOut = std::move(pktBuilder).buildTestPacket();
  auto regularPacket = builtOut.first;
  EXPECT_EQ(bytesWritten, 28);
  NewConnectionIdFrame& resultNewConnIdFrame =
      *regularPacket.frames[0].asQuicSimpleFrame()->asNewConnectionIdFrame();
  EXPECT_EQ(resultNewConnIdFrame.sequenceNumber, 1);
  EXPECT_EQ(resultNewConnIdFrame.retirePriorTo, 0);
  EXPECT_EQ(resultNewConnIdFrame.connectionId, getTestConnectionId());
  EXPECT_EQ(resultNewConnIdFrame.token, token);

  auto wireBuf = std::move(builtOut.second);
  BufQueue queue;
  queue.append(wireBuf->clone());
  QuicFrame decodedFrame = parseQuicFrame(queue);
  QuicSimpleFrame& simpleFrame = *decodedFrame.asQuicSimpleFrame();
  NewConnectionIdFrame wireNewConnIdFrame =
      *simpleFrame.asNewConnectionIdFrame();
  EXPECT_EQ(1, wireNewConnIdFrame.sequenceNumber);
  EXPECT_EQ(0, wireNewConnIdFrame.retirePriorTo);
  EXPECT_EQ(getTestConnectionId(), wireNewConnIdFrame.connectionId);
  EXPECT_EQ(queue.chainLength(), 0);
}

TEST_F(QuicWriteCodecTest, WriteRetireConnId) {
  MockQuicPacketBuilder pktBuilder;
  setupCommonExpects(pktBuilder);
  RetireConnectionIdFrame retireConnId(3);
  auto bytesWritten = writeFrame(QuicSimpleFrame(retireConnId), pktBuilder);

  auto builtOut = std::move(pktBuilder).buildTestPacket();
  auto regularPacket = builtOut.first;
  EXPECT_EQ(bytesWritten, 2);
  RetireConnectionIdFrame resultRetireConnIdFrame =
      *regularPacket.frames[0].asQuicSimpleFrame()->asRetireConnectionIdFrame();
  EXPECT_EQ(resultRetireConnIdFrame.sequenceNumber, 3);

  auto wireBuf = std::move(builtOut.second);
  BufQueue queue;
  queue.append(wireBuf->clone());
  QuicFrame decodedFrame = parseQuicFrame(queue);
  QuicSimpleFrame& simpleFrame = *decodedFrame.asQuicSimpleFrame();
  RetireConnectionIdFrame wireRetireConnIdFrame =
      *simpleFrame.asRetireConnectionIdFrame();
  EXPECT_EQ(3, wireRetireConnIdFrame.sequenceNumber);
  EXPECT_EQ(queue.chainLength(), 0);
}

TEST_F(QuicWriteCodecTest, WriteStopSending) {
  MockQuicPacketBuilder pktBuilder;
  setupCommonExpects(pktBuilder);
  StreamId streamId = 10;
  auto errorCode = GenericApplicationErrorCode::UNKNOWN;

  StopSendingFrame stopSending(streamId, errorCode);
  auto bytesWritten = writeSimpleFrame(stopSending, pktBuilder);

  auto builtOut = std::move(pktBuilder).buildTestPacket();
  auto regularPacket = builtOut.first;
  EXPECT_EQ(bytesWritten, 6);

  auto wireBuf = std::move(builtOut.second);
  BufQueue queue;
  queue.append(wireBuf->clone());
  QuicFrame decodedFrame = parseQuicFrame(queue);
  QuicSimpleFrame& simpleFrame = *decodedFrame.asQuicSimpleFrame();
  StopSendingFrame wireStopSendingFrame = *simpleFrame.asStopSendingFrame();
  EXPECT_EQ(wireStopSendingFrame.streamId, streamId);
  EXPECT_EQ(wireStopSendingFrame.errorCode, errorCode);
  EXPECT_EQ(queue.chainLength(), 0);
}

TEST_F(QuicWriteCodecTest, NoSpaceForNewConnId) {
  MockQuicPacketBuilder pktBuilder;
  pktBuilder.remaining_ = 0;
  setupCommonExpects(pktBuilder);
  NewConnectionIdFrame newConnId(
      1, 0, getTestConnectionId(), StatelessResetToken());
  EXPECT_EQ(0, writeFrame(QuicSimpleFrame(newConnId), pktBuilder));
}

TEST_F(QuicWriteCodecTest, WritePathChallenge) {
  MockQuicPacketBuilder pktBuilder;
  setupCommonExpects(pktBuilder);

  uint64_t pathData = 0x64;
  PathChallengeFrame pathChallenge(pathData);
  auto bytesWritten = writeSimpleFrame(pathChallenge, pktBuilder);
  EXPECT_EQ(bytesWritten, 9);

  auto builtOut = std::move(pktBuilder).buildTestPacket();

  auto regularPacket = builtOut.first;
  PathChallengeFrame result =
      *regularPacket.frames[0].asQuicSimpleFrame()->asPathChallengeFrame();
  EXPECT_EQ(result.pathData, pathData);

  auto wireBuf = std::move(builtOut.second);
  BufQueue queue;
  queue.append(wireBuf->clone());
  QuicFrame decodedFrame = parseQuicFrame(queue);
  QuicSimpleFrame& simpleFrame = *decodedFrame.asQuicSimpleFrame();
  PathChallengeFrame wirePathChallengeFrame =
      *simpleFrame.asPathChallengeFrame();
  EXPECT_EQ(wirePathChallengeFrame.pathData, pathData);
  EXPECT_EQ(queue.chainLength(), 0);
}

TEST_F(QuicWriteCodecTest, WritePathResponse) {
  MockQuicPacketBuilder pktBuilder;
  setupCommonExpects(pktBuilder);

  uint64_t pathData = 0x64;
  PathResponseFrame pathResponse(pathData);
  auto bytesWritten = writeSimpleFrame(pathResponse, pktBuilder);
  EXPECT_EQ(bytesWritten, 9);

  auto builtOut = std::move(pktBuilder).buildTestPacket();

  auto regularPacket = builtOut.first;
  PathResponseFrame result =
      *regularPacket.frames[0].asQuicSimpleFrame()->asPathResponseFrame();
  EXPECT_EQ(result.pathData, pathData);

  auto wireBuf = std::move(builtOut.second);
  BufQueue queue;
  queue.append(wireBuf->clone());
  QuicFrame decodedFrame = parseQuicFrame(queue);
  QuicSimpleFrame& simpleFrame = *decodedFrame.asQuicSimpleFrame();
  PathResponseFrame wirePathResponseFrame = *simpleFrame.asPathResponseFrame();
  EXPECT_EQ(wirePathResponseFrame.pathData, pathData);
  EXPECT_EQ(queue.chainLength(), 0);
}
} // namespace test
} // namespace quic
