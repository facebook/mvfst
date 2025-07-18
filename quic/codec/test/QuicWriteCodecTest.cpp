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
#include <quic/QuicConstants.h>
#include <quic/QuicException.h>
#include <quic/codec/Decode.h>
#include <quic/codec/QuicInteger.h>
#include <quic/codec/Types.h>
#include <quic/codec/test/Mocks.h>
#include <quic/common/BufUtil.h>
#include <quic/common/CircularDeque.h>
#include <quic/common/test/TestUtils.h>
#include <quic/state/TransportSettings.h>
#include <algorithm>
#include <chrono>
#include <cstdint>

using namespace quic;
using namespace quic::test;
using namespace testing;

ShortHeader buildTestShortHeader() {
  return ShortHeader(ProtectionType::KeyPhaseZero, getTestConnectionId(), 0x01);
}

QuicFrame parseQuicFrame(
    BufQueue& queue,
    bool isAckReceiveTimestampsSupported = false,
    uint64_t extendedAckSupport = 0) {
  quic::Optional<AckReceiveTimestampsConfig> receiveTimeStampsConfig =
      std::nullopt;
  if (isAckReceiveTimestampsSupported) {
    receiveTimeStampsConfig = AckReceiveTimestampsConfig{
        .maxReceiveTimestampsPerAck = 5, .receiveTimestampsExponent = 3};
  }

  auto result = quic::parseFrame(
      queue,
      buildTestShortHeader(),
      CodecParameters(
          kDefaultAckDelayExponent,
          QuicVersion::MVFST,
          receiveTimeStampsConfig,
          extendedAckSupport));

  if (!result.has_value()) {
    throw QuicTransportException(
        result.error().message, *result.error().code.asTransportErrorCode());
  }

  return std::move(*result);
}

namespace quic::test {

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

  EXPECT_CALL(pktBuilder, appendPaddingFrame()).WillRepeatedly(Invoke([&]() {
    if (!pktBuilder.frames_.empty() &&
        pktBuilder.frames_.back().asPaddingFrame()) {
      pktBuilder.frames_.back().asPaddingFrame()->numFrames++;
    } else {
      pktBuilder.frames_.push_back(PaddingFrame());
    }
  }));

  EXPECT_CALL(pktBuilder, _insert(_))
      .WillRepeatedly(WithArgs<0>(Invoke([&](BufPtr& buf) {
        pktBuilder.remaining_ -= buf->computeChainDataLength();
        pktBuilder.appender_.insert(std::move(buf));
      })));

  EXPECT_CALL(pktBuilder, _insert(_, _))
      .WillRepeatedly(WithArgs<0, 1>(Invoke([&](BufPtr& buf, size_t limit) {
        pktBuilder.remaining_ -= limit;
        std::unique_ptr<folly::IOBuf> cloneBuf;
        Cursor cursor(buf.get());
        cursor.clone(cloneBuf, limit);
        pktBuilder.appender_.insert(std::move(cloneBuf));
      })));

  EXPECT_CALL(pktBuilder, _insertRch(_, _))
      .WillRepeatedly(WithArgs<0, 1>(
          Invoke([&](const ChainedByteRangeHead& rch, size_t limit) {
            auto curr = rch.getHead();
            while (limit > 0 && curr) {
              size_t amount = std::min(curr->length(), limit);
              pktBuilder.remaining_ -= amount;
              pktBuilder.appender_.push(curr->getRange().begin(), amount);
              curr = curr->getNext();
              limit -= amount;
            }
          })));

  EXPECT_CALL(pktBuilder, insert(_, _))
      .WillRepeatedly(
          WithArgs<0, 1>(Invoke([&](const BufQueue& buf, size_t limit) {
            pktBuilder.remaining_ -= limit;
            std::unique_ptr<folly::IOBuf> cloneBuf;
            Cursor cursor(buf.front());
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
        auto size = quicInteger.getSize();
        ASSERT_FALSE(size.hasError());
        quicInteger.encode(
            [&](auto val) { pktBuilder.appender_.writeBE(val); });
        pktBuilder.remaining_ -= *size;
      }));
}

using PacketsReceivedTimestampsDeque =
    CircularDeque<WriteAckFrameState::ReceivedPacket>;
const auto kDefaultTimestampsDelta = 10us;
const AckReceiveTimestampsConfig defaultAckReceiveTimestmpsConfig = {
    .receiveTimestampsExponent = kDefaultReceiveTimestampsExponent};

PacketsReceivedTimestampsDeque populateReceiveTimestamps(
    const AckBlocks& ackBlocks,
    TimePoint connTime,
    uint64_t maxTimeStamps = kMaxReceivedPktsTimestampsStored) {
  PacketsReceivedTimestampsDeque pktsReceivedTimestamps;

  uint64_t countTimestamps = 0;
  for (auto it = ackBlocks.crbegin(); it != ackBlocks.crend(); it++) {
    countTimestamps += (it->end - it->start + 1);
  }
  auto lastPacketDelta = (countTimestamps * kDefaultTimestampsDelta);

  for (auto it = ackBlocks.crbegin(); it != ackBlocks.crend(); it++) {
    for (auto i = it->end; i >= it->start; i--) {
      if (pktsReceivedTimestamps.size() < maxTimeStamps) {
        WriteAckFrameState::ReceivedPacket rpi;
        rpi.pktNum = i;
        auto diff = std::chrono::microseconds(
            lastPacketDelta -= kDefaultTimestampsDelta);
        if ((connTime + diff) > connTime) {
          rpi.timings.receiveTimePoint = connTime + diff;
        } else {
          rpi.timings.receiveTimePoint = connTime;
        }
        pktsReceivedTimestamps.emplace_front(rpi);
      } else {
        break;
      }
    }
  }
  return pktsReceivedTimestamps;
}

size_t computeBytesForOptionalAckFields(
    const WriteAckFrameMetaData& ackFrameMetadata,
    WriteAckFrameResult ackFrameWriteResult,
    FrameType frameType) {
  size_t sizeConsumed = 0;

  auto shouldHaveTimestamps = frameType == FrameType::ACK_RECEIVE_TIMESTAMPS ||
      (ackFrameWriteResult.extendedAckFeaturesEnabled &
       static_cast<ExtendedAckFeatureMaskType>(
           ExtendedAckFeatureMask::RECEIVE_TIMESTAMPS));

  auto shouldHaveECN = frameType == FrameType::ACK_ECN ||
      (ackFrameWriteResult.extendedAckFeaturesEnabled &
       static_cast<ExtendedAckFeatureMaskType>(
           ExtendedAckFeatureMask::ECN_COUNTS));

  if (frameType == FrameType::ACK_EXTENDED) {
    // Account for the extended ack header if it is included into the ack.
    auto sizeResult =
        getQuicIntegerSize(ackFrameWriteResult.extendedAckFeaturesEnabled);
    CHECK(!sizeResult.hasError());
    sizeConsumed += sizeResult.value();
  }

  if (frameType == FrameType::ACK_RECEIVE_TIMESTAMPS ||
      frameType == FrameType::ACK_EXTENDED) {
    // These two types have a longer frameType. Account for that.
    sizeConsumed += 1;
  }

  if (shouldHaveTimestamps) {
    size_t numRanges = ackFrameWriteResult.timestampRangesWritten;
    TimePoint connTime = ackFrameMetadata.connTime;
    auto lastPktNum =
        ackFrameMetadata.ackState.lastRecvdPacketInfo.value().pktNum;
    std::chrono::duration lastTimeStampDelta =
        std::chrono::duration_cast<std::chrono::microseconds>(
            ackFrameMetadata.ackState.lastRecvdPacketInfo.value()
                .timings.receiveTimePoint -
            connTime);

    // When we're including the receive timestamp fields, the minimum additional
    // information that is sent to the peer is:
    // 1. last received packet's timestamp delta,
    // 2. last received packet's number,
    // 3. count of timestamp ranges
    auto lastTimeDeltaSizeResult =
        getQuicIntegerSize(lastTimeStampDelta.count());
    CHECK(!lastTimeDeltaSizeResult.hasError());
    auto lastPktNumSizeResult = getQuicIntegerSize(lastPktNum);
    CHECK(!lastPktNumSizeResult.hasError());
    auto numRangesSizeResult = getQuicIntegerSize(numRanges);
    CHECK(!numRangesSizeResult.hasError());

    sizeConsumed += lastTimeDeltaSizeResult
                        .value() + // latest received packet timestamp delta
        lastPktNumSizeResult.value() + // latest received packet number
        numRangesSizeResult.value(); // count of ack_receive_timestamp ranges

    if (numRanges > 0) {
      auto sizeUsedResult =
          computeSizeUsedByRecvdTimestamps(ackFrameWriteResult.writeAckFrame);
      CHECK(!sizeUsedResult.hasError());
      sizeConsumed += sizeUsedResult.value();
    };
  }

  if (shouldHaveECN) {
    // Account for ECN count fields if they are included into the ack.
    auto ect0SizeResult =
        getQuicIntegerSize(ackFrameMetadata.ackState.ecnECT0CountReceived);
    CHECK(!ect0SizeResult.hasError());
    auto ect1SizeResult =
        getQuicIntegerSize(ackFrameMetadata.ackState.ecnECT1CountReceived);
    CHECK(!ect1SizeResult.hasError());
    auto ceSizeResult =
        getQuicIntegerSize(ackFrameMetadata.ackState.ecnCECountReceived);
    CHECK(!ceSizeResult.hasError());

    sizeConsumed +=
        ect0SizeResult.value() + ect1SizeResult.value() + ceSizeResult.value();
  }
  return sizeConsumed;
}

WriteAckFrameState createTestWriteAckState(
    FrameType frameType,
    const TimePoint& connTime,
    AckBlocks& ackBlocks,
    uint64_t countTimestampsToStore = kMaxReceivedPktsTimestampsStored,
    uint64_t extendedAckSupport = 0) {
  WriteAckFrameState ackState = {.acks = ackBlocks};
  ackState.acks = ackBlocks;
  auto shouldIncludeTimestamps =
      frameType == FrameType::ACK_RECEIVE_TIMESTAMPS ||
      (extendedAckSupport &
       static_cast<ExtendedAckFeatureMaskType>(
           ExtendedAckFeatureMask::RECEIVE_TIMESTAMPS));
  if (shouldIncludeTimestamps) {
    ackState.recvdPacketInfos =
        populateReceiveTimestamps(ackBlocks, connTime, countTimestampsToStore);
    ackState.lastRecvdPacketInfo = WriteAckFrameState::ReceivedPacket{
        .pktNum = ackState.recvdPacketInfos.back().pktNum,
        .timings = ReceivedUdpPacket::Timings{
            .receiveTimePoint =
                ackState.recvdPacketInfos.back().timings.receiveTimePoint,
            .maybeSoftwareTs = std::nullopt}};
  }
  return ackState;
}

void assertsOnDecodedReceiveTimestamps(
    const WriteAckFrameMetaData& ackFrameMetaData,
    const WriteAckFrame& writeAckFrame,
    const ReadAckFrame& readAckFrame,
    uint64_t expectedTimestampRangesCount,
    uint64_t expectedTimestampsCount,
    uint64_t receiveTimestampsExponent) {
  EXPECT_TRUE(readAckFrame.maybeLatestRecvdPacketNum.has_value());
  EXPECT_TRUE(readAckFrame.maybeLatestRecvdPacketTime.has_value());
  EXPECT_EQ(
      readAckFrame.maybeLatestRecvdPacketNum.value(),
      ackFrameMetaData.ackState.lastRecvdPacketInfo.value().pktNum);
  EXPECT_EQ(
      readAckFrame.maybeLatestRecvdPacketTime.value(),
      std::chrono::duration_cast<std::chrono::microseconds>(
          ackFrameMetaData.ackState.lastRecvdPacketInfo.value()
              .timings.receiveTimePoint -
          ackFrameMetaData.connTime));
  EXPECT_EQ(
      readAckFrame.recvdPacketsTimestampRanges.size(),
      expectedTimestampRangesCount);
  auto timeStamps = 0;
  for (auto range : readAckFrame.recvdPacketsTimestampRanges) {
    timeStamps += range.timestamp_delta_count;
  }
  EXPECT_EQ(timeStamps, expectedTimestampsCount);
  EXPECT_EQ(
      readAckFrame.recvdPacketsTimestampRanges.size(),
      writeAckFrame.recvdPacketsTimestampRanges.size());
  // (XXX: sj77, clean this up)
  for (uint64_t i = 0; i < readAckFrame.recvdPacketsTimestampRanges.size();
       ++i) {
    EXPECT_EQ(
        readAckFrame.recvdPacketsTimestampRanges[i].gap,
        writeAckFrame.recvdPacketsTimestampRanges[i].gap);
    EXPECT_EQ(
        readAckFrame.recvdPacketsTimestampRanges[i].timestamp_delta_count,
        writeAckFrame.recvdPacketsTimestampRanges[i].timestamp_delta_count);
    for (uint64_t j = 0;
         j < readAckFrame.recvdPacketsTimestampRanges[i].timestamp_delta_count;
         j++) {
      EXPECT_EQ(
          readAckFrame.recvdPacketsTimestampRanges[i].deltas[j],
          writeAckFrame.recvdPacketsTimestampRanges[i].deltas[j] *
              pow(2,

                  receiveTimestampsExponent));
    }
  }
}

class QuicWriteCodecExtendedAckTest : public TestWithParam<uint64_t> {};

TEST_P(QuicWriteCodecExtendedAckTest, WriteWithFeatures) {
  MockQuicPacketBuilder pktBuilder;
  setupCommonExpects(pktBuilder);
  auto ackDelay = 111us;
  AckBlocks ackBlocks = {{501, 1000}, {101, 400}};
  auto frameType = FrameType::ACK_EXTENDED;
  TimePoint connTime = Clock::now();
  auto extendedAckSupport = GetParam();
  WriteAckFrameState ackState = createTestWriteAckState(
      frameType,
      connTime,
      ackBlocks,
      kMaxReceivedPktsTimestampsStored,
      extendedAckSupport);
  ackState.ecnCECountReceived = 1;
  ackState.ecnECT0CountReceived = 2;
  ackState.ecnECT1CountReceived = 3;

  WriteAckFrameMetaData ackFrameMetaData = {
      .ackState = ackState,
      .ackDelay = ackDelay,
      .ackDelayExponent = static_cast<uint8_t>(kDefaultAckDelayExponent),
      .connTime = connTime,
  };
  // 1 type byte,
  // 2 bytes for largest acked, 1 bytes for ack delay => 3 bytes
  // 1 byte for ack block count
  // There is 1 gap => each represented by 2 bytes => 2 bytes
  // 2 byte for first ack block length, then 2 bytes for the next len => 4 bytes
  // total 11 bytes for base ACK. Extended frame size is added below.
  auto ackFrameWriteResultExpected = writeAckFrame(
      ackFrameMetaData,
      pktBuilder,
      frameType,
      defaultAckReceiveTimestmpsConfig,
      kMaxReceivedPktsTimestampsStored,
      extendedAckSupport);
  ASSERT_FALSE(ackFrameWriteResultExpected.hasError());
  ASSERT_TRUE(ackFrameWriteResultExpected.value().has_value());
  auto& ackFrameWriteResult = ackFrameWriteResultExpected.value().value();
  auto addlBytesConsumed = computeBytesForOptionalAckFields(
      ackFrameMetaData, ackFrameWriteResult, frameType);
  EXPECT_EQ(11 + addlBytesConsumed, ackFrameWriteResult.bytesWritten);
  EXPECT_EQ(
      kDefaultUDPSendPacketLen - 11 - addlBytesConsumed,
      pktBuilder.remainingSpaceInPkt());
  EXPECT_EQ(ackFrameWriteResult.extendedAckFeaturesEnabled, extendedAckSupport);

  // Check the ACK frame base fields
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

  QuicFrame decodedFrame =
      parseQuicFrame(queue, false /*has timestamps*/, extendedAckSupport);
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

  // Check the ECN fields
  if (extendedAckSupport &
      static_cast<ExtendedAckFeatureMaskType>(
          ExtendedAckFeatureMask::ECN_COUNTS)) {
    EXPECT_EQ(ackFrameWriteResult.writeAckFrame.ecnCECount, 1);
    EXPECT_EQ(ackFrameWriteResult.writeAckFrame.ecnECT0Count, 2);
    EXPECT_EQ(ackFrameWriteResult.writeAckFrame.ecnECT1Count, 3);

    EXPECT_EQ(decodedAckFrame.ecnCECount, 1);
    EXPECT_EQ(decodedAckFrame.ecnECT0Count, 2);
    EXPECT_EQ(decodedAckFrame.ecnECT1Count, 3);
  } else {
    EXPECT_EQ(ackFrameWriteResult.writeAckFrame.ecnCECount, 0);
    EXPECT_EQ(ackFrameWriteResult.writeAckFrame.ecnECT0Count, 0);
    EXPECT_EQ(ackFrameWriteResult.writeAckFrame.ecnECT1Count, 0);

    EXPECT_EQ(decodedAckFrame.ecnCECount, 0);
    EXPECT_EQ(decodedAckFrame.ecnECT0Count, 0);
    EXPECT_EQ(decodedAckFrame.ecnECT1Count, 0);
  }

  // Check the Receive Timestamp fields
  if (extendedAckSupport &
      static_cast<ExtendedAckFeatureMaskType>(
          ExtendedAckFeatureMask::RECEIVE_TIMESTAMPS)) {
    // Multiple ack blocks, however received timestamps storage limit limit
    // achieved by the within the latest ack block
    assertsOnDecodedReceiveTimestamps(
        ackFrameMetaData,
        ackFrameWriteResult.writeAckFrame,

        decodedAckFrame,
        1 /* timestamp ranges count */,
        kMaxReceivedPktsTimestampsStored /* timestamps count */,
        defaultAckReceiveTimestmpsConfig.receiveTimestampsExponent);
  } else {
    EXPECT_FALSE(ackFrameWriteResult.writeAckFrame.maybeLatestRecvdPacketNum
                     .has_value());
    EXPECT_FALSE(ackFrameWriteResult.writeAckFrame.maybeLatestRecvdPacketTime
                     .has_value());
    EXPECT_EQ(
        ackFrameWriteResult.writeAckFrame.recvdPacketsTimestampRanges.size(),
        0);

    EXPECT_FALSE(decodedAckFrame.maybeLatestRecvdPacketNum.has_value());
    EXPECT_FALSE(decodedAckFrame.maybeLatestRecvdPacketTime.has_value());
    EXPECT_EQ(decodedAckFrame.recvdPacketsTimestampRanges.size(), 0);
  }
}

INSTANTIATE_TEST_SUITE_P(
    QuicWriteCodecExtendedAckTests,
    QuicWriteCodecExtendedAckTest,
    Values(
        0,
        static_cast<ExtendedAckFeatureMaskType>(
            ExtendedAckFeatureMask::ECN_COUNTS),
        static_cast<ExtendedAckFeatureMaskType>(
            ExtendedAckFeatureMask::RECEIVE_TIMESTAMPS),
        static_cast<ExtendedAckFeatureMaskType>(
            ExtendedAckFeatureMask::ECN_COUNTS) |
            static_cast<ExtendedAckFeatureMaskType>(
                ExtendedAckFeatureMask::RECEIVE_TIMESTAMPS)));

class QuicWriteCodecTest : public TestWithParam<FrameType> {};

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
  auto res = writeStreamFrameHeader(
      pktBuilder,
      streamId,
      offset,
      10,
      10,
      fin,
      std::nullopt /* skipLenHint */);
  ASSERT_TRUE(res.has_value());
  auto dataLen = *res;
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
  auto res = writeStreamFrameHeader(
      pktBuilder,
      streamId,
      offset,
      20,
      20,
      fin,
      std::nullopt /* skipLenHint */);
  ASSERT_TRUE(res.has_value());
  auto dataLen = *res;
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
  auto res = writeStreamFrameHeader(
      pktBuilder,
      streamId1,
      offset1,
      30,
      30,
      fin1,
      std::nullopt /* skipLenHint */);
  ASSERT_TRUE(res.has_value());
  auto dataLen = *res;
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
  res = writeStreamFrameHeader(
      pktBuilder,
      streamId2,
      offset2,
      remainingSpace,
      remainingSpace,
      fin2,
      std::nullopt /* skipLenHint */);
  ASSERT_TRUE(res.has_value());
  dataLen = *res;
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
  auto streamFrameDecoded1 = quic::parseFrame(
      queue,
      regularPacket.header,
      CodecParameters(kDefaultAckDelayExponent, QuicVersion::MVFST));
  ASSERT_TRUE(streamFrameDecoded1.has_value());
  auto& decodedStreamFrame1 = *streamFrameDecoded1->asReadStreamFrame();
  EXPECT_EQ(decodedStreamFrame1.streamId, streamId1);
  EXPECT_EQ(decodedStreamFrame1.offset, offset1);
  EXPECT_EQ(decodedStreamFrame1.data->computeChainDataLength(), 30);
  EXPECT_TRUE(folly::IOBufEqualTo()(inputBuf, decodedStreamFrame1.data));
  // Read another one from wire output:
  auto streamFrameDecoded2 = quic::parseFrame(
      queue,
      regularPacket.header,
      CodecParameters(kDefaultAckDelayExponent, QuicVersion::MVFST));
  ASSERT_TRUE(streamFrameDecoded2.has_value());
  auto& decodedStreamFrame2 = *streamFrameDecoded2->asReadStreamFrame();
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
  auto res = writeStreamFrameHeader(
      pktBuilder,
      streamId,
      offset,
      50,
      50,
      fin,
      std::nullopt /* skipLenHint */);
  ASSERT_TRUE(res.has_value());
  auto dataLen = *res;
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
  auto res = writeStreamFrameHeader(
      pktBuilder, streamId, offset, 1, 1, fin, std::nullopt /* skipLenHint */);
  EXPECT_TRUE(res.has_value());
  auto dataLen = *res;
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
  auto res = writeStreamFrameHeader(
      pktBuilder,
      streamId,
      offset,
      10,
      10,
      fin,
      std::nullopt /* skipLenHint */);
  ASSERT_TRUE(res.has_value());
  auto dataLen = *res;
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
  // 1 byte for offset
  // => 3 bytes
  auto res = writeStreamFrameHeader(
      pktBuilder,
      streamId,
      offset,
      100,
      100,
      fin,
      std::nullopt /* skipLenHint */);
  ASSERT_TRUE(res.has_value());
  auto dataLen = *res;
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
  auto decodedFrame = quic::parseFrame(
      queue,
      regularPacket.header,
      CodecParameters(kDefaultAckDelayExponent, QuicVersion::MVFST));
  ASSERT_TRUE(decodedFrame.has_value());
  auto& decodedStreamFrame = *decodedFrame->asReadStreamFrame();
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
  auto res = writeStreamFrameHeader(
      pktBuilder,
      streamId,
      offset,
      10,
      10,
      fin,
      std::nullopt /* skipLenHint */);
  ASSERT_TRUE(res.has_value());
  auto dataLen = *res;
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
  Cursor cursor(wireBuf.get());
  BufQueue queue;
  queue.append(wireBuf->clone());
  auto decodedFrame = quic::parseFrame(
      queue,
      regularPacket.header,
      CodecParameters(kDefaultAckDelayExponent, QuicVersion::MVFST));
  ASSERT_TRUE(decodedFrame.has_value());
  auto& decodedStreamFrame = *decodedFrame->asReadStreamFrame();
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
  auto res = writeStreamFrameHeader(
      pktBuilder,
      streamId,
      offset,
      inDataSize,
      inDataSize,
      fin,
      std::nullopt /* skipLenHint */);
  ASSERT_TRUE(res.has_value());
  auto dataLen = *res;
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
  BufPtr empty;
  auto res = writeStreamFrameHeader(
      pktBuilder, streamId, offset, 0, 0, fin, std::nullopt /* skipLenHint */);
  ASSERT_TRUE(res.has_value());
  auto dataLen = *res;
  ASSERT_TRUE(dataLen);
  EXPECT_EQ(*dataLen, 0);
}

TEST_F(QuicWriteCodecTest, TestWriteNoDataAndNoFin) {
  MockQuicPacketBuilder pktBuilder;
  setupCommonExpects(pktBuilder);
  StreamId streamId = 1;
  uint64_t offset = 0;
  bool fin = false;
  BufPtr empty;
  auto res = writeStreamFrameHeader(
      pktBuilder, streamId, offset, 0, 0, fin, std::nullopt /* skipLenHint */);
  EXPECT_TRUE(res.hasError());
  EXPECT_EQ(
      res.error(),
      QuicError(
          LocalErrorCode::INTERNAL_ERROR,
          "No data or fin supplied when writing stream."));
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
  auto res = writeStreamFrameHeader(
      pktBuilder,
      streamId,
      offset,
      20,
      20,
      fin,
      std::nullopt /* skipLenHint */);
  ASSERT_TRUE(res.has_value());
  auto dataLen = *res;
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
  auto res = writeStreamFrameHeader(
      pktBuilder, streamId, offset, 0, 0, fin, std::nullopt /* skipLenHint */);
  ASSERT_TRUE(res.has_value());
  auto dataLen = *res;
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
  auto res = writeStreamFrameHeader(
      pktBuilder, streamId, offset, 0, 0, fin, std::nullopt /* skipLenHint */);
  EXPECT_TRUE(res.has_value());
  auto dataLen = *res;
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
        auto size = quicInt.getSize();
        ASSERT_FALSE(size.hasError());
        packetLimit -= size.value();
      }));
  StreamId streamId = 0;
  uint64_t offset = 10;
  bool fin = false;
  auto res = writeStreamFrameHeader(
      pktBuilder, streamId, offset, 1200 * 2, 1200 * 2, fin, std::nullopt);
  EXPECT_TRUE(res.has_value());
  auto dataLen = *res;
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
        ASSERT_FALSE(quicInt.getSize().hasError());
        packetLimit -= quicInt.getSize().value();
      }));
  StreamId streamId = 0;
  uint64_t offset = 10;
  bool fin = false;
  auto res = writeStreamFrameHeader(
      pktBuilder, streamId, offset, 200, 200, fin, std::nullopt);
  EXPECT_TRUE(res.has_value());
  auto dataLen = *res;
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
        ASSERT_FALSE(quicInt.getSize().hasError());
        packetLimit -= quicInt.getSize().value();
      }));
  StreamId streamId = 0;
  uint64_t offset = 10;
  bool fin = false;
  auto res =
      writeStreamFrameHeader(pktBuilder, streamId, offset, 200, 200, fin, true);
  EXPECT_TRUE(res.has_value());
  auto dataLen = *res;
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
        ASSERT_FALSE(quicInt.getSize().hasError());
        packetLimit -= quicInt.getSize().value();
      }));
  StreamId streamId = 0;
  uint64_t offset = 10;
  bool fin = false;
  auto res = writeStreamFrameHeader(
      pktBuilder, streamId, offset, 1200 * 2, 1200 * 2, fin, false);
  EXPECT_TRUE(res.has_value());
  auto dataLen = *res;
  EXPECT_LT(*dataLen, 1200);
}

TEST_P(QuicWriteCodecTest, AckFrameGapExceedsRepresentation) {
  MockQuicPacketBuilder pktBuilder;
  setupCommonExpects(pktBuilder);

  PacketNum max = std::numeric_limits<uint64_t>::max();
  // Can't use max directly, because it will exceed interval set's
  // representation.
  AckBlocks ackBlocks = {{max - 10, max - 10}, {1, 1}};
  auto frameType = GetParam();
  TimePoint connTime = Clock::now();
  WriteAckFrameState ackState =
      createTestWriteAckState(frameType, connTime, ackBlocks);
  WriteAckFrameMetaData ackFrameMetaData = {
      .ackState = ackState,
      .ackDelay = 0us,
      .ackDelayExponent = static_cast<uint8_t>(kDefaultAckDelayExponent),
      .connTime = connTime,
  };

  auto result = writeAckFrame(
      ackFrameMetaData,
      pktBuilder,
      frameType,
      defaultAckReceiveTimestmpsConfig,
      0);
  ASSERT_TRUE(result.hasError());
  ASSERT_NE(result.error().code.asTransportErrorCode(), nullptr);
}

TEST_P(QuicWriteCodecTest, AckFrameVeryLargeAckRange) {
  MockQuicPacketBuilder pktBuilder;
  setupCommonExpects(pktBuilder);

  // 1 type byte,
  // 8 bytes for largest acked, 1 bytes for ack delay => 9 bytes
  // 1 byte for ack block count
  // There is 1 gap => each represented by 8 bytes => 8 bytes
  // total 11 bytes
  PacketNum largest = (uint64_t)1 << 55;
  AckBlocks ackBlocks = {{1, largest}};
  auto frameType = GetParam();

  TimePoint connTime = Clock::now();

  WriteAckFrameState ackState = {.acks = ackBlocks};
  ackState.acks = ackBlocks;
  if (frameType == FrameType::ACK_RECEIVE_TIMESTAMPS) {
    auto lastPacketDelta =
        (kMaxReceivedPktsTimestampsStored * kDefaultTimestampsDelta);
    PacketsReceivedTimestampsDeque pktsReceivedTimestamps;

    for (auto it = ackBlocks.crbegin(); it != ackBlocks.crend(); it++) {
      for (auto i = it->end; i >= it->start; i--) {
        if (pktsReceivedTimestamps.size() < kMaxReceivedPktsTimestampsStored) {
          WriteAckFrameState::ReceivedPacket rpi;
          rpi.pktNum = i;
          auto diff = std::chrono::microseconds(
              lastPacketDelta -= kDefaultTimestampsDelta);
          rpi.timings.receiveTimePoint = connTime + diff;
          pktsReceivedTimestamps.emplace_front(rpi);
        } else {
          break;
        }
      }
    }
    ackState.recvdPacketInfos = pktsReceivedTimestamps;
    WriteAckFrameState::ReceivedPacket receivedPacket;
    receivedPacket.pktNum = ackState.recvdPacketInfos.back().pktNum;
    receivedPacket.timings.receiveTimePoint =
        ackState.recvdPacketInfos.back().timings.receiveTimePoint;
    receivedPacket.timings.maybeSoftwareTs = std::nullopt;
    ackState.lastRecvdPacketInfo = receivedPacket;
  }

  WriteAckFrameMetaData ackFrameMetaData = {
      .ackState = ackState,
      .ackDelay = 0us,
      .ackDelayExponent = static_cast<uint8_t>(kDefaultAckDelayExponent),
      .connTime = connTime,
  };
  auto ackFrameWriteResultExpected = writeAckFrame(
      ackFrameMetaData,
      pktBuilder,
      frameType,
      defaultAckReceiveTimestmpsConfig,
      kMaxReceivedPktsTimestampsStored);
  ASSERT_FALSE(ackFrameWriteResultExpected.hasError());
  ASSERT_TRUE(ackFrameWriteResultExpected.value().has_value());
  auto& ackFrameWriteResult = ackFrameWriteResultExpected.value().value();
  auto addlBytesConsumed = computeBytesForOptionalAckFields(
      ackFrameMetaData, ackFrameWriteResult, frameType);

  EXPECT_EQ(19 + addlBytesConsumed, ackFrameWriteResult.bytesWritten);
  EXPECT_EQ(
      kDefaultUDPSendPacketLen - 19 - addlBytesConsumed,
      pktBuilder.remainingSpaceInPkt());

  auto builtOut = std::move(pktBuilder).buildTestPacket();
  auto regularPacket = builtOut.first;
  EXPECT_EQ(regularPacket.frames.size(), 1);
  WriteAckFrame& ackFrame = *regularPacket.frames.back().asWriteAckFrame();
  EXPECT_EQ(ackFrame.ackBlocks.size(), 1);

  EXPECT_EQ(ackFrame.ackBlocks.back().start, 1);
  EXPECT_EQ(largest, ackFrame.ackBlocks.back().end);

  if (frameType == FrameType::ACK_RECEIVE_TIMESTAMPS) {
    auto wireBuf = std::move(builtOut.second);
    BufQueue queue;
    queue.append(wireBuf->clone());
    QuicFrame decodedFrame =
        parseQuicFrame(queue, frameType == FrameType::ACK_RECEIVE_TIMESTAMPS);
    auto& decodedAckFrame = *decodedFrame.asReadAckFrame();
    // Single contingious ack blocks, default received timestamps stored.
    assertsOnDecodedReceiveTimestamps(
        ackFrameMetaData,
        ackFrameWriteResult.writeAckFrame,
        decodedAckFrame,
        1 /* timestamp ranges count */,
        kMaxReceivedPktsTimestampsStored /* timestamps count */,
        defaultAckReceiveTimestmpsConfig.receiveTimestampsExponent);
  }
}

TEST_P(QuicWriteCodecTest, AckFrameNotEnoughForAnything) {
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
  auto frameType = GetParam();
  TimePoint connTime = Clock::now();
  WriteAckFrameState ackState =
      createTestWriteAckState(frameType, connTime, ackBlocks);
  WriteAckFrameMetaData ackFrameMetaData = {
      .ackState = ackState,
      .ackDelay = 0us,
      .ackDelayExponent = static_cast<uint8_t>(kDefaultAckDelayExponent),
      .connTime = connTime,
  };

  auto result = writeAckFrame(
      ackFrameMetaData,
      pktBuilder,
      frameType,
      defaultAckReceiveTimestmpsConfig,
      kMaxReceivedPktsTimestampsStored);
  EXPECT_FALSE(result.hasError());
  EXPECT_FALSE(result.value().has_value());
  EXPECT_EQ(pktBuilder.remainingSpaceInPkt(), 4);
}

TEST_P(QuicWriteCodecTest, WriteSimpleAckFrame) {
  MockQuicPacketBuilder pktBuilder;
  setupCommonExpects(pktBuilder);
  auto ackDelay = 111us;
  AckBlocks ackBlocks = {{501, 1000}, {101, 400}};
  auto frameType = GetParam();
  TimePoint connTime = Clock::now();
  auto extendedAckSupport = frameType == FrameType::ACK_EXTENDED ? 3 : 0;
  WriteAckFrameState ackState = createTestWriteAckState(
      frameType,
      connTime,
      ackBlocks,
      kMaxReceivedPktsTimestampsStored,
      extendedAckSupport);
  WriteAckFrameMetaData ackFrameMetaData = {
      .ackState = ackState,
      .ackDelay = ackDelay,
      .ackDelayExponent = static_cast<uint8_t>(kDefaultAckDelayExponent),
      .connTime = connTime,
  };
  // 1 type byte,
  // 2 bytes for largest acked, 1 bytes for ack delay => 3 bytes
  // 1 byte for ack block count
  // There is 1 gap => each represented by 2 bytes => 2 bytes
  // 2 byte for first ack block length, then 2 bytes for the next len => 4 bytes
  // total 11 bytes
  auto ackFrameWriteResultExpected = writeAckFrame(
      ackFrameMetaData,
      pktBuilder,
      frameType,
      defaultAckReceiveTimestmpsConfig,
      kMaxReceivedPktsTimestampsStored,
      extendedAckSupport);
  ASSERT_FALSE(ackFrameWriteResultExpected.hasError());
  ASSERT_TRUE(ackFrameWriteResultExpected.value().has_value());
  auto& ackFrameWriteResult = ackFrameWriteResultExpected.value().value();
  auto addlBytesConsumed = computeBytesForOptionalAckFields(
      ackFrameMetaData, ackFrameWriteResult, frameType);
  EXPECT_EQ(11 + addlBytesConsumed, ackFrameWriteResult.bytesWritten);
  EXPECT_EQ(
      kDefaultUDPSendPacketLen - 11 - addlBytesConsumed,
      pktBuilder.remainingSpaceInPkt());

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
  auto hasTimestamps = frameType == FrameType::ACK_RECEIVE_TIMESTAMPS ||
      ackFrameWriteResult.extendedAckFeaturesEnabled &
          static_cast<ExtendedAckFeatureMaskType>(
              ExtendedAckFeatureMask::RECEIVE_TIMESTAMPS);
  QuicFrame decodedFrame =
      parseQuicFrame(queue, hasTimestamps, extendedAckSupport);
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

  if (frameType == FrameType::ACK_RECEIVE_TIMESTAMPS ||
      frameType == FrameType::ACK_EXTENDED) {
    // Multiple ack blocks, however received timestamps storage limit limit
    // achieved by the within the latest ack block
    assertsOnDecodedReceiveTimestamps(
        ackFrameMetaData,
        ackFrameWriteResult.writeAckFrame,

        decodedAckFrame,
        1 /* timestamp ranges count */,
        kMaxReceivedPktsTimestampsStored /* timestamps count */,
        defaultAckReceiveTimestmpsConfig.receiveTimestampsExponent);
  }
}

TEST_P(QuicWriteCodecTest, WriteAckFrameWillSaveAckDelay) {
  MockQuicPacketBuilder pktBuilder;
  setupCommonExpects(pktBuilder);
  auto ackDelay = 111us;
  AckBlocks ackBlocks = {{501, 1000}, {101, 400}};
  auto frameType = GetParam();
  TimePoint connTime = Clock::now();
  WriteAckFrameState ackState =
      createTestWriteAckState(frameType, connTime, ackBlocks);
  WriteAckFrameMetaData ackFrameMetaData = {
      .ackState = ackState,
      .ackDelay = ackDelay,
      .ackDelayExponent = static_cast<uint8_t>(kDefaultAckDelayExponent),
      .connTime = connTime,
  };

  auto ackFrameWriteResult = writeAckFrame(
      ackFrameMetaData,
      pktBuilder,
      frameType,
      defaultAckReceiveTimestmpsConfig,
      kMaxReceivedPktsTimestampsStored);
  ASSERT_FALSE(ackFrameWriteResult.hasError());
  ASSERT_TRUE(ackFrameWriteResult.value().has_value());
  auto builtOut = std::move(pktBuilder).buildTestPacket();
  auto regularPacket = builtOut.first;
  WriteAckFrame& ackFrame = *regularPacket.frames.back().asWriteAckFrame();
  EXPECT_EQ(ackDelay, ackFrame.ackDelay);
}

TEST_P(QuicWriteCodecTest, VerifyNumAckBlocksSizeAccounted) {
  // Tests that if we restrict the size to be exactly the size required
  // for a byte num blocks size, if the num blocks requires 2 bytes
  // practically will never happen), then we won't write the additional
  MockQuicPacketBuilder pktBuilder;
  pktBuilder.remaining_ = 134;
  setupCommonExpects(pktBuilder);
  auto frameType = GetParam();

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
  TimePoint connTime = Clock::now();
  WriteAckFrameState ackState =
      createTestWriteAckState(frameType, connTime, ackBlocks);
  WriteAckFrameMetaData ackFrameMetaData = {
      .ackState = ackState,
      .ackDelay = 0us,
      .ackDelayExponent = static_cast<uint8_t>(kDefaultAckDelayExponent),
      .connTime = connTime,
  };
  // 1 type byte,
  // 2 bytes for largest acked, 1 bytes for ack delay => 3 bytes
  // 1 byte for ack block count
  // There is 1 gap => each represented by 2 bytes => 2 bytes
  // 2 byte for first ack block length, then 2 bytes for the next len => 4 bytes
  // total 11 bytes
  auto ackFrameWriteResultExpected = writeAckFrame(
      ackFrameMetaData,
      pktBuilder,
      frameType,
      defaultAckReceiveTimestmpsConfig,
      kMaxReceivedPktsTimestampsStored);
  ASSERT_FALSE(ackFrameWriteResultExpected.hasError());
  ASSERT_TRUE(ackFrameWriteResultExpected.value().has_value());
  auto& ackFrameWriteResult = ackFrameWriteResultExpected.value().value();
  auto addlBytesConsumed = computeBytesForOptionalAckFields(
      ackFrameMetaData, ackFrameWriteResult, frameType);
  auto builtOut = std::move(pktBuilder).buildTestPacket();
  auto regularPacket = builtOut.first;

  if (frameType == FrameType::ACK) {
    EXPECT_EQ(ackFrameWriteResult.bytesWritten, 132);
    EXPECT_EQ(pktBuilder.remainingSpaceInPkt(), 2);
    EXPECT_EQ(regularPacket.frames.size(), 1);
    WriteAckFrame& ackFrame = *regularPacket.frames.back().asWriteAckFrame();
    EXPECT_EQ(ackFrame.ackBlocks.size(), 64);

    EXPECT_EQ(ackFrame.ackBlocks.back().start, 746);
    EXPECT_EQ(ackFrame.ackBlocks.back().end, 748);
  } else if (frameType == FrameType::ACK_ECN) {
    EXPECT_EQ(ackFrameWriteResult.bytesWritten, 130 + addlBytesConsumed);
    EXPECT_EQ(pktBuilder.remainingSpaceInPkt(), 1);
    EXPECT_EQ(regularPacket.frames.size(), 1);
    WriteAckFrame& ackFrame = *regularPacket.frames.back().asWriteAckFrame();
    EXPECT_EQ(ackFrame.ackBlocks.size(), 63);

    EXPECT_EQ(ackFrame.ackBlocks.back().start, 750);
    EXPECT_EQ(ackFrame.ackBlocks.back().end, 752);
  } else if (frameType == FrameType::ACK_RECEIVE_TIMESTAMPS) {
    EXPECT_EQ(ackFrameWriteResult.bytesWritten, 128 + addlBytesConsumed);
    EXPECT_EQ(pktBuilder.remainingSpaceInPkt(), 0);
    EXPECT_EQ(regularPacket.frames.size(), 1);
    WriteAckFrame& ackFrame = *regularPacket.frames.back().asWriteAckFrame();
    EXPECT_EQ(ackFrame.ackBlocks.size(), 62);

    EXPECT_EQ(ackFrame.ackBlocks.back().start, 754);
    EXPECT_EQ(ackFrame.ackBlocks.back().end, 756);

    auto wireBuf = std::move(builtOut.second);
    BufQueue queue;
    queue.append(wireBuf->clone());
    QuicFrame decodedFrame =
        parseQuicFrame(queue, frameType == FrameType::ACK_RECEIVE_TIMESTAMPS);
    auto& decodedAckFrame = *decodedFrame.asReadAckFrame();
    // Multiple ack blocks, however no space remaining to send received
    // timestamps
    assertsOnDecodedReceiveTimestamps(
        ackFrameMetaData,
        ackFrameWriteResult.writeAckFrame,

        decodedAckFrame,
        0 /* timestamp ranges count */,
        0 /* timestamps count */,
        defaultAckReceiveTimestmpsConfig.receiveTimestampsExponent);
  }
}

TEST_P(QuicWriteCodecTest, WriteWithDifferentAckDelayExponent) {
  MockQuicPacketBuilder pktBuilder;
  setupCommonExpects(pktBuilder);

  AckBlocks ackBlocks{{1000, 1000}};
  uint8_t ackDelayExponent = 6;
  auto frameType = GetParam();

  TimePoint connTime = Clock::now();
  WriteAckFrameState ackState =
      createTestWriteAckState(frameType, connTime, ackBlocks);
  WriteAckFrameMetaData ackFrameMetaData = {
      .ackState = ackState,
      .ackDelay = 1240us,
      .ackDelayExponent = static_cast<uint8_t>(ackDelayExponent),
      .connTime = connTime,
  };

  auto ackFrameWriteResult = writeAckFrame(
      ackFrameMetaData,
      pktBuilder,
      frameType,
      defaultAckReceiveTimestmpsConfig,
      kMaxReceivedPktsTimestampsStored);
  EXPECT_TRUE(ackFrameWriteResult.has_value());
  auto builtOut = std::move(pktBuilder).buildTestPacket();
  auto wireBuf = std::move(builtOut.second);
  BufQueue queue;
  queue.append(wireBuf->clone());
  auto decodedFrameResult = quic::parseFrame(
      queue,
      builtOut.first.header,
      CodecParameters(ackDelayExponent, QuicVersion::MVFST));
  EXPECT_TRUE(decodedFrameResult.has_value());
  auto& decodedAckFrame = *decodedFrameResult.value().asReadAckFrame();
  EXPECT_EQ(
      decodedAckFrame.ackDelay.count(),
      computeExpectedDelay(ackFrameMetaData.ackDelay, ackDelayExponent));
}

TEST_P(QuicWriteCodecTest, WriteExponentInLongHeaderPacket) {
  MockQuicPacketBuilder pktBuilder;
  setupCommonExpects(pktBuilder);

  AckBlocks ackBlocks{{1000, 1000}};
  uint8_t ackDelayExponent = 6;
  auto frameType = GetParam();
  TimePoint connTime = Clock::now();
  WriteAckFrameState ackState =
      createTestWriteAckState(frameType, connTime, ackBlocks);
  WriteAckFrameMetaData ackFrameMetaData = {
      .ackState = ackState,
      .ackDelay = 1240us,
      .ackDelayExponent = static_cast<uint8_t>(ackDelayExponent),
      .connTime = connTime,
  };

  auto ackFrameWriteResult = writeAckFrame(
      ackFrameMetaData,
      pktBuilder,
      frameType,
      defaultAckReceiveTimestmpsConfig,
      kMaxReceivedPktsTimestampsStored);
  EXPECT_TRUE(ackFrameWriteResult.has_value());
  auto builtOut = std::move(pktBuilder).buildLongHeaderPacket();
  auto wireBuf = std::move(builtOut.second);
  Cursor cursor(wireBuf.get());
  BufQueue queue;
  queue.append(wireBuf->clone());
  auto decodedFrameResult = quic::parseFrame(
      queue,
      builtOut.first.header,
      CodecParameters(ackDelayExponent, QuicVersion::MVFST));
  EXPECT_TRUE(decodedFrameResult.has_value());
  auto& decodedAckFrame = *decodedFrameResult.value().asReadAckFrame();
  EXPECT_EQ(
      decodedAckFrame.ackDelay.count(),
      (uint64_t(ackFrameMetaData.ackDelay.count()) >> ackDelayExponent)
          << kDefaultAckDelayExponent);
}

TEST_P(QuicWriteCodecTest, OnlyAckLargestPacket) {
  MockQuicPacketBuilder pktBuilder;
  setupCommonExpects(pktBuilder);

  // 1 type byte,
  // 2 bytes for largest acked, 2 bytes for ack delay => 4 bytes
  // 1 byte for ack block count
  // 1 byte for first ack block length
  // total 7 bytes
  AckBlocks ackBlocks{{1000, 1000}};

  // No AckBlock is added to the metadata. There will still be one block
  // generated as the first block to cover largestAcked => 2 bytes
  auto frameType = GetParam();
  TimePoint connTime = Clock::now();
  WriteAckFrameState ackState =
      createTestWriteAckState(frameType, connTime, ackBlocks);
  WriteAckFrameMetaData ackFrameMetaData = {
      .ackState = ackState,
      .ackDelay = 555us,
      .ackDelayExponent = static_cast<uint8_t>(kDefaultAckDelayExponent),
      .connTime = connTime,
  };

  auto ackFrameWriteResultExpected = writeAckFrame(
      ackFrameMetaData,
      pktBuilder,
      frameType,
      defaultAckReceiveTimestmpsConfig,
      kMaxReceivedPktsTimestampsStored);
  ASSERT_FALSE(ackFrameWriteResultExpected.hasError());
  ASSERT_TRUE(ackFrameWriteResultExpected.value().has_value());
  auto& ackFrameWriteResult = ackFrameWriteResultExpected.value().value();
  auto addlBytesConsumed = computeBytesForOptionalAckFields(
      ackFrameMetaData, ackFrameWriteResult, frameType);

  EXPECT_EQ(ackFrameWriteResult.bytesWritten, 7 + addlBytesConsumed);
  EXPECT_EQ(
      kDefaultUDPSendPacketLen - 7 - addlBytesConsumed,
      pktBuilder.remainingSpaceInPkt());

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
      computeExpectedDelay(
          ackFrameMetaData.ackDelay, kDefaultAckDelayExponent));
  EXPECT_EQ(decodedAckFrame.ackBlocks.size(), 1);
  EXPECT_EQ(decodedAckFrame.ackBlocks[0].startPacket, 1000);
  EXPECT_EQ(decodedAckFrame.ackBlocks[0].endPacket, 1000);

  if (frameType == FrameType::ACK_RECEIVE_TIMESTAMPS) {
    // Single packet received and acked
    assertsOnDecodedReceiveTimestamps(
        ackFrameMetaData,
        ackFrameWriteResult.writeAckFrame,
        decodedAckFrame,
        1 /* timestamp ranges count */,
        1 /* timestamps count */,
        defaultAckReceiveTimestmpsConfig.receiveTimestampsExponent);
  }
}

TEST_P(QuicWriteCodecTest, WriteSomeAckBlocks) {
  // Too many ack blocks passed in, we can only write some of them
  MockQuicPacketBuilder pktBuilder;
  setupCommonExpects(pktBuilder);

  // 1 type byte,
  // 2 bytes for largest acked, 2 bytes for ack delay => 4 bytes
  // 1 byte for num ack blocks
  // 1 byte for first ack block length
  // each additional ack block 1 byte gap + 1 byte length => 2 bytes
  // total 7 bytes
  AckBlocks ackBlocks;
  PacketNum currentEnd = 1000;
  auto blockLength = 5;
  auto gap = 10;
  for (int i = 0; i < 30; i++) {
    ackBlocks.insert({currentEnd - blockLength + 1, currentEnd});
    currentEnd -= blockLength + gap;
  }
  ackBlocks.insert({1000, 1000});

  auto frameType = GetParam();

  if (frameType == FrameType::ACK) {
    pktBuilder.remaining_ = 36;
  } else if (frameType == FrameType::ACK_ECN) {
    pktBuilder.remaining_ = 39;
  } else if (frameType == FrameType::ACK_RECEIVE_TIMESTAMPS) {
    pktBuilder.remaining_ = 42;
  } else if (frameType == FrameType::ACK_EXTENDED) {
    // 4 more bytes than ACK_RECEIVE_TIMESTAMPS
    // - One for the extended ack features header
    // - Three for ECN counts enabled in this test
    pktBuilder.remaining_ = 46;
  }
  TimePoint connTime = Clock::now();
  auto extendedAckSupport = frameType == FrameType::ACK_EXTENDED ? 3 : 0;
  WriteAckFrameState ackState = createTestWriteAckState(
      frameType,
      connTime,
      ackBlocks,
      kMaxReceivedPktsTimestampsStored,
      extendedAckSupport);
  WriteAckFrameMetaData ackFrameMetaData = {
      .ackState = ackState,
      .ackDelay = 555us,
      .ackDelayExponent = static_cast<uint8_t>(kDefaultAckDelayExponent),
      .connTime = connTime,
  };

  auto ackFrameWriteResultExpected = writeAckFrame(
      ackFrameMetaData,
      pktBuilder,
      frameType,
      defaultAckReceiveTimestmpsConfig,
      kMaxReceivedPktsTimestampsStored,
      extendedAckSupport);
  ASSERT_FALSE(ackFrameWriteResultExpected.hasError());
  ASSERT_TRUE(ackFrameWriteResultExpected.value().has_value());
  auto& ackFrameWriteResult = ackFrameWriteResultExpected.value().value();
  auto addlBytesConsumed = computeBytesForOptionalAckFields(
      ackFrameMetaData, ackFrameWriteResult, frameType);

  EXPECT_EQ(ackFrameWriteResult.bytesWritten, 35 + addlBytesConsumed);
  EXPECT_EQ(pktBuilder.remainingSpaceInPkt(), 1);

  auto builtOut = std::move(pktBuilder).buildTestPacket();
  auto regularPacket = builtOut.first;
  EXPECT_EQ(regularPacket.frames.size(), 1);
  WriteAckFrame& ackFrame = *regularPacket.frames.back().asWriteAckFrame();

  EXPECT_EQ(ackFrame.ackBlocks.size(), 15);

  // Verify the on wire bytes via decoder:
  // (Awkwardly, this assumes the decoder is correct)
  auto hasTimestamps = frameType == FrameType::ACK_RECEIVE_TIMESTAMPS ||
      ackFrameWriteResult.extendedAckFeaturesEnabled &
          static_cast<ExtendedAckFeatureMaskType>(
              ExtendedAckFeatureMask::RECEIVE_TIMESTAMPS);
  auto wireBuf = std::move(builtOut.second);
  BufQueue queue;
  queue.append(wireBuf->clone());
  QuicFrame decodedFrame =
      parseQuicFrame(queue, hasTimestamps, extendedAckSupport);
  auto& decodedAckFrame = *decodedFrame.asReadAckFrame();
  EXPECT_EQ(decodedAckFrame.largestAcked, 1000);
  EXPECT_EQ(
      decodedAckFrame.ackDelay.count(),
      computeExpectedDelay(
          ackFrameMetaData.ackDelay, kDefaultAckDelayExponent));

  EXPECT_EQ(decodedAckFrame.ackBlocks.size(), 15);

  if (frameType == FrameType::ACK_RECEIVE_TIMESTAMPS) {
    assertsOnDecodedReceiveTimestamps(
        ackFrameMetaData,
        ackFrameWriteResult.writeAckFrame,
        decodedAckFrame,
        0 /* timestamp ranges count */,
        0 /* timestamps count */,
        defaultAckReceiveTimestmpsConfig.receiveTimestampsExponent);
  }
}

TEST_P(QuicWriteCodecTest, NoSpaceForAckBlockSection) {
  MockQuicPacketBuilder pktBuilder;
  pktBuilder.remaining_ = 6;
  setupCommonExpects(pktBuilder);

  // 1 type byte,
  // 2 bytes for largest acked, 2 bytes for ack delay => 4 bytes
  // 1 byte for num ack blocks
  // 1 byte for first ack block length
  AckBlocks ackBlocks = {{1000, 1000}, {701, 900}, {501, 600}};
  auto frameType = GetParam();
  TimePoint connTime = Clock::now();
  WriteAckFrameState ackState =
      createTestWriteAckState(frameType, connTime, ackBlocks);
  WriteAckFrameMetaData ackFrameMetaData = {
      .ackState = ackState,
      .ackDelay = 555us,
      .ackDelayExponent = static_cast<uint8_t>(kDefaultAckDelayExponent),
      .connTime = connTime,
  };

  auto ackFrameWriteResult = writeAckFrame(
      ackFrameMetaData,
      pktBuilder,
      frameType,
      defaultAckReceiveTimestmpsConfig,
      kMaxReceivedPktsTimestampsStored);
  ASSERT_FALSE(ackFrameWriteResult.hasError());
  EXPECT_FALSE(ackFrameWriteResult.value().has_value());
}

TEST_P(QuicWriteCodecTest, OnlyHasSpaceForFirstAckBlock) {
  MockQuicPacketBuilder pktBuilder;
  auto frameType = GetParam();

  if (frameType == FrameType::ACK) {
    pktBuilder.remaining_ = 10;
  } else if (frameType == FrameType::ACK_ECN) {
    pktBuilder.remaining_ = 13;
  } else if (frameType == FrameType::ACK_RECEIVE_TIMESTAMPS) {
    pktBuilder.remaining_ = 16;
  } else if (frameType == FrameType::ACK_EXTENDED) {
    // Compared to ACK, ACK_EXTENDED uses 2 more bytes:
    // - One for the larger frame type
    // - One for the extended ack features integer (=0 in this test)
    pktBuilder.remaining_ = 12;
  }

  setupCommonExpects(pktBuilder);

  // 1 type byte,
  // 2 bytes for largest acked, 2 bytes for ack delay => 4 bytes
  // 1 byte for num ack blocks
  // 1 byte for first ack block length
  AckBlocks ackBlocks = {{1000, 1000}, {701, 900}, {501, 600}};
  TimePoint connTime = Clock::now();
  WriteAckFrameState ackState =
      createTestWriteAckState(frameType, connTime, ackBlocks);
  WriteAckFrameMetaData ackFrameMetaData = {
      .ackState = ackState,
      .ackDelay = 555us,
      .ackDelayExponent = static_cast<uint8_t>(kDefaultAckDelayExponent),
      .connTime = connTime,
  };

  auto ackFrameWriteResultExpected = writeAckFrame(
      ackFrameMetaData,
      pktBuilder,
      frameType,
      defaultAckReceiveTimestmpsConfig,
      kMaxReceivedPktsTimestampsStored);
  ASSERT_FALSE(ackFrameWriteResultExpected.hasError());
  ASSERT_TRUE(ackFrameWriteResultExpected.value().has_value());
  auto& ackFrameWriteResult = ackFrameWriteResultExpected.value().value();
  auto addlBytesConsumed = computeBytesForOptionalAckFields(
      ackFrameMetaData, ackFrameWriteResult, frameType);

  EXPECT_EQ(ackFrameWriteResult.bytesWritten, 7 + addlBytesConsumed);
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
      computeExpectedDelay(
          ackFrameMetaData.ackDelay, kDefaultAckDelayExponent));
  EXPECT_EQ(decodedAckFrame.ackBlocks.size(), 1);
  EXPECT_EQ(decodedAckFrame.ackBlocks[0].startPacket, 1000);
  EXPECT_EQ(decodedAckFrame.ackBlocks[0].endPacket, 1000);

  if (frameType == FrameType::ACK_RECEIVE_TIMESTAMPS) {
    // No space left for ack blocks, and hence std::nullopt for received
    // timestamps
    assertsOnDecodedReceiveTimestamps(
        ackFrameMetaData,
        ackFrameWriteResult.writeAckFrame,

        decodedAckFrame,
        0 /* timestamp ranges count */,
        0 /* timestamps count */,
        defaultAckReceiveTimestmpsConfig.receiveTimestampsExponent);
  }
}

TEST_P(QuicWriteCodecTest, WriteAckFrameWithMultipleTimestampRanges) {
  MockQuicPacketBuilder pktBuilder;
  setupCommonExpects(pktBuilder);
  auto ackDelay = 111us;
  AckBlocks ackBlocks = {{501, 520}, {471, 490}, {431, 460}};
  // 1 type byte,
  // 2 bytes for largest acked, 1 bytes for ack delay => 3 bytes
  // 1 byte for ack block count
  // There is 1 gap => each represented by 2 bytes => 2 bytes
  // 2 byte for first ack block length, then 2 bytes for the next len => 4
  // bytes
  // total 11 bytes
  auto frameType = GetParam();
  auto extendedAckSupport = frameType == FrameType::ACK_EXTENDED ? 3 : 0;
  TimePoint connTime = Clock::now();
  WriteAckFrameState ackState = createTestWriteAckState(
      frameType,
      connTime,
      ackBlocks,
      50 /*maxRecvTimestampsToSend*/,
      /* extendedAckSupport*/ extendedAckSupport);
  WriteAckFrameMetaData ackFrameMetaData = {
      .ackState = ackState,
      .ackDelay = ackDelay,
      .ackDelayExponent = static_cast<uint8_t>(kDefaultAckDelayExponent),
      .connTime = connTime,
  };

  auto ackFrameWriteResultExpected = writeAckFrame(
      ackFrameMetaData,
      pktBuilder,
      frameType,
      defaultAckReceiveTimestmpsConfig,
      50, /*maxRecvTimestampsToSend*/
      extendedAckSupport);
  ASSERT_FALSE(ackFrameWriteResultExpected.hasError());
  ASSERT_TRUE(ackFrameWriteResultExpected.value().has_value());
  auto& ackFrameWriteResult = ackFrameWriteResultExpected.value().value();
  auto addlBytesConsumed = computeBytesForOptionalAckFields(
      ackFrameMetaData, ackFrameWriteResult, frameType);

  EXPECT_EQ(ackFrameWriteResult.bytesWritten, 10 + addlBytesConsumed);
  EXPECT_EQ(
      kDefaultUDPSendPacketLen - 10 - addlBytesConsumed,
      pktBuilder.remainingSpaceInPkt());

  auto builtOut = std::move(pktBuilder).buildTestPacket();
  auto regularPacket = builtOut.first;
  WriteAckFrame& ackFrame = *regularPacket.frames.back().asWriteAckFrame();
  EXPECT_EQ(ackFrame.ackBlocks.size(), 3);
  auto iter = ackFrame.ackBlocks.crbegin();
  EXPECT_EQ(iter->start, 431);
  EXPECT_EQ(iter->end, 460);
  iter++;
  EXPECT_EQ(iter->start, 471);
  EXPECT_EQ(iter->end, 490);

  auto wireBuf = std::move(builtOut.second);
  BufQueue queue;
  queue.append(wireBuf->clone());
  auto hasTimestamps = frameType == FrameType::ACK_RECEIVE_TIMESTAMPS ||
      ackFrameWriteResult.extendedAckFeaturesEnabled &
          static_cast<ExtendedAckFeatureMaskType>(
              ExtendedAckFeatureMask::RECEIVE_TIMESTAMPS);
  QuicFrame decodedFrame = parseQuicFrame(
      queue, hasTimestamps, ackFrameWriteResult.extendedAckFeaturesEnabled);
  auto& decodedAckFrame = *decodedFrame.asReadAckFrame();
  EXPECT_EQ(decodedAckFrame.largestAcked, 520);
  EXPECT_EQ(
      decodedAckFrame.ackDelay.count(),
      computeExpectedDelay(ackDelay, kDefaultAckDelayExponent));
  EXPECT_EQ(decodedAckFrame.ackBlocks.size(), 3);
  EXPECT_EQ(decodedAckFrame.ackBlocks[0].startPacket, 501);
  EXPECT_EQ(decodedAckFrame.ackBlocks[0].endPacket, 520);
  EXPECT_EQ(decodedAckFrame.ackBlocks[1].startPacket, 471);
  EXPECT_EQ(decodedAckFrame.ackBlocks[1].endPacket, 490);
  if (hasTimestamps) {
    // Multiple ack blocks, and received timestamps up to the configured
    // allowed received timestamps
    assertsOnDecodedReceiveTimestamps(
        ackFrameMetaData,
        ackFrameWriteResult.writeAckFrame,

        decodedAckFrame,
        3 /* timestamp ranges count */,
        50 /* timestamps count */,
        defaultAckReceiveTimestmpsConfig.receiveTimestampsExponent);
  }
}

TEST_P(
    QuicWriteCodecTest,
    WriteAckFrameWithMultipleTimestampRangesPartiallySent) {
  MockQuicPacketBuilder pktBuilder;
  setupCommonExpects(pktBuilder);
  auto ackDelay = 111us;
  AckBlocks ackBlocks = {{501, 520}, {471, 490}, {431, 460}};
  // 1 type byte,
  // 2 bytes for largest acked, 1 bytes for ack delay => 3 bytes
  // 1 byte for ack block count
  // There is 1 gap => each represented by 2 bytes => 2 bytes
  // 2 byte for first ack block length, then 2 bytes for the next len => 4
  // bytes
  // total 11 bytes
  auto frameType = GetParam();
  TimePoint connTime = Clock::now();
  auto extendedAckSupport = frameType == FrameType::ACK_EXTENDED ? 3 : 0;
  WriteAckFrameState ackState = createTestWriteAckState(
      frameType, connTime, ackBlocks, 100, extendedAckSupport);
  WriteAckFrameMetaData ackFrameMetaData = {
      .ackState = ackState,
      .ackDelay = ackDelay,
      .ackDelayExponent = static_cast<uint8_t>(kDefaultAckDelayExponent),
      .connTime = connTime,
  };

  if (frameType == FrameType::ACK_RECEIVE_TIMESTAMPS) {
    pktBuilder.remaining_ = 80;
  } else if (frameType == FrameType::ACK_EXTENDED) {
    // ACK_EXTENDED (with features = 3) uses 4 more bytes than
    // ACK_RECEIVE_TIMESTAMPS:
    // - 1 byte for for extended features integer
    // - 3 bytes for the ECN counts (all 0 in this test)
    pktBuilder.remaining_ = 84;
  }
  auto ackFrameWriteResultExpected = writeAckFrame(
      ackFrameMetaData,
      pktBuilder,
      frameType,
      defaultAckReceiveTimestmpsConfig,
      100,
      extendedAckSupport);
  ASSERT_FALSE(ackFrameWriteResultExpected.hasError());
  ASSERT_TRUE(ackFrameWriteResultExpected.value().has_value());
  auto& ackFrameWriteResult = ackFrameWriteResultExpected.value().value();
  auto addlBytesConsumed = computeBytesForOptionalAckFields(
      ackFrameMetaData, ackFrameWriteResult, frameType);

  if (frameType == FrameType::ACK) {
    EXPECT_EQ(10, ackFrameWriteResult.bytesWritten);
    EXPECT_EQ(kDefaultUDPSendPacketLen - 10, pktBuilder.remainingSpaceInPkt());
  } else if (frameType == FrameType::ACK_ECN) {
    EXPECT_EQ(10 + addlBytesConsumed, ackFrameWriteResult.bytesWritten);
    EXPECT_EQ(
        kDefaultUDPSendPacketLen - (10 + addlBytesConsumed),
        pktBuilder.remainingSpaceInPkt());
  } else if (frameType == FrameType::ACK_RECEIVE_TIMESTAMPS) {
    EXPECT_EQ(10 + addlBytesConsumed, ackFrameWriteResult.bytesWritten);
    EXPECT_EQ(80 - (10 + addlBytesConsumed), pktBuilder.remainingSpaceInPkt());
  } else if (frameType == FrameType::ACK_EXTENDED) {
    EXPECT_EQ(10 + addlBytesConsumed, ackFrameWriteResult.bytesWritten);
    EXPECT_EQ(84 - (10 + addlBytesConsumed), pktBuilder.remainingSpaceInPkt());
  }
  auto builtOut = std::move(pktBuilder).buildTestPacket();
  auto regularPacket = builtOut.first;
  WriteAckFrame& ackFrame = *regularPacket.frames.back().asWriteAckFrame();
  EXPECT_EQ(ackFrame.ackBlocks.size(), 3);
  auto iter = ackFrame.ackBlocks.crbegin();
  EXPECT_EQ(iter->start, 431);
  EXPECT_EQ(iter->end, 460);
  iter++;
  EXPECT_EQ(iter->start, 471);
  EXPECT_EQ(iter->end, 490);

  auto wireBuf = std::move(builtOut.second);
  BufQueue queue;
  queue.append(wireBuf->clone());
  auto hasTimeStamps = frameType == FrameType::ACK_RECEIVE_TIMESTAMPS ||
      ackFrameWriteResult.extendedAckFeaturesEnabled &
          static_cast<ExtendedAckFeatureMaskType>(
              ExtendedAckFeatureMask::RECEIVE_TIMESTAMPS);
  QuicFrame decodedFrame =
      parseQuicFrame(queue, hasTimeStamps, extendedAckSupport);
  auto& decodedAckFrame = *decodedFrame.asReadAckFrame();
  EXPECT_EQ(decodedAckFrame.largestAcked, 520);
  EXPECT_EQ(
      decodedAckFrame.ackDelay.count(),
      computeExpectedDelay(ackDelay, kDefaultAckDelayExponent));
  EXPECT_EQ(decodedAckFrame.ackBlocks.size(), 3);
  EXPECT_EQ(decodedAckFrame.ackBlocks[0].startPacket, 501);
  EXPECT_EQ(decodedAckFrame.ackBlocks[0].endPacket, 520);
  EXPECT_EQ(decodedAckFrame.ackBlocks[1].startPacket, 471);
  EXPECT_EQ(decodedAckFrame.ackBlocks[1].endPacket, 490);

  if (frameType == FrameType::ACK_RECEIVE_TIMESTAMPS ||
      frameType == FrameType::ACK_EXTENDED) {
    // Multiple ack blocks, and received timestamps up to the space available
    assertsOnDecodedReceiveTimestamps(
        ackFrameMetaData,
        ackFrameWriteResult.writeAckFrame,

        decodedAckFrame,
        3 /* timestamp ranges count */,
        57 /* timestamps count */,
        defaultAckReceiveTimestmpsConfig.receiveTimestampsExponent);
  }
}

TEST_F(QuicWriteCodecTest, WriteMaxStreamData) {
  MockQuicPacketBuilder pktBuilder;
  setupCommonExpects(pktBuilder);
  StreamId id = 1;
  uint64_t offset = 0x08;
  MaxStreamDataFrame maxStreamDataFrame(id, offset);
  auto bytesWrittenExpected = writeFrame(maxStreamDataFrame, pktBuilder);
  ASSERT_FALSE(bytesWrittenExpected.hasError());
  auto bytesWritten = bytesWrittenExpected.value();

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
  ASSERT_FALSE(writeFrame(maxStreamDataFrame, pktBuilder).hasError());
  EXPECT_EQ(0, writeFrame(maxStreamDataFrame, pktBuilder).value());
}

TEST_F(QuicWriteCodecTest, WriteMaxData) {
  MockQuicPacketBuilder pktBuilder;
  setupCommonExpects(pktBuilder);
  MaxDataFrame maxDataFrame(1000);
  auto bytesWrittenExpected = writeFrame(maxDataFrame, pktBuilder);
  ASSERT_FALSE(bytesWrittenExpected.hasError());
  auto bytesWritten = bytesWrittenExpected.value();

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
  ASSERT_FALSE(writeFrame(maxDataFrame, pktBuilder).hasError());
  EXPECT_EQ(0, writeFrame(maxDataFrame, pktBuilder).value());
}

TEST_F(QuicWriteCodecTest, WriteMaxStreamId) {
  for (uint64_t i = 0; i < 100; i++) {
    MockQuicPacketBuilder pktBuilder;
    setupCommonExpects(pktBuilder);
    uint64_t maxStream = i;
    bool isBidirectional = true;
    MaxStreamsFrame maxStreamsFrame(maxStream, isBidirectional);
    auto bytesWrittenExpected =
        writeFrame(QuicSimpleFrame(maxStreamsFrame), pktBuilder);
    ASSERT_FALSE(bytesWrittenExpected.hasError());
    auto bytesWritten = bytesWrittenExpected.value();

    auto builtOut = std::move(pktBuilder).buildTestPacket();
    auto regularPacket = builtOut.first;
    auto streamCountSize = i < 64 ? 1 : 2;
    // 1 byte for the type and up to 2 bytes for the stream count.
    EXPECT_EQ(1 + streamCountSize, bytesWritten);
    MaxStreamsFrame& resultMaxStreamIdFrame =
        *regularPacket.frames[0].asQuicSimpleFrame()->asMaxStreamsFrame();
    EXPECT_EQ(i, resultMaxStreamIdFrame.maxStreams);

    auto wireBuf = std::move(builtOut.second);
    Cursor cursor(wireBuf.get());
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
    auto bytesWrittenExpected =
        writeFrame(QuicSimpleFrame(maxStreamsFrame), pktBuilder);
    ASSERT_FALSE(bytesWrittenExpected.hasError());
    auto bytesWritten = bytesWrittenExpected.value();

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
  auto result =
      writeFrame(QuicSimpleFrame(MaxStreamsFrame(maxStream, true)), pktBuilder);
  ASSERT_FALSE(result.hasError());
  EXPECT_EQ(0, result.value());
}

TEST_F(QuicWriteCodecTest, WriteConnClose) {
  MockQuicPacketBuilder pktBuilder;
  setupCommonExpects(pktBuilder);
  std::string reasonPhrase("You are fired");
  auto connCloseBytesWrittenExpected = writeFrame(
      ConnectionCloseFrame(
          QuicErrorCode(TransportErrorCode::PROTOCOL_VIOLATION), reasonPhrase),
      pktBuilder);
  ASSERT_FALSE(connCloseBytesWrittenExpected.hasError());
  auto connCloseBytesWritten = connCloseBytesWrittenExpected.value();

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
  auto result = writeFrame(
      ConnectionCloseFrame(
          QuicErrorCode(TransportErrorCode::PROTOCOL_VIOLATION), reasonPhrase),
      pktBuilder);
  ASSERT_FALSE(result.hasError());
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
  auto result = writeFrame(
      ConnectionCloseFrame(
          QuicErrorCode(TransportErrorCode::PROTOCOL_VIOLATION), reasonPhrase),
      pktBuilder);
  ASSERT_FALSE(result.hasError());
  EXPECT_EQ(0, result.value());
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
  auto result = writeFrame(std::move(applicationCloseFrame), pktBuilder);
  ASSERT_FALSE(result.hasError());

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
  auto pingBytesWrittenExpected = writeFrame(PingFrame(), pktBuilder);
  ASSERT_FALSE(pingBytesWrittenExpected.hasError());
  auto pingBytesWritten = pingBytesWrittenExpected.value();

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
  auto result = writeFrame(PingFrame(), pktBuilder);
  ASSERT_FALSE(result.hasError());
  EXPECT_EQ(0, result.value());
}

TEST_F(QuicWriteCodecTest, WritePadding) {
  MockQuicPacketBuilder pktBuilder;
  setupCommonExpects(pktBuilder);
  auto paddingBytesWrittenExpected = writeFrame(PaddingFrame(), pktBuilder);
  ASSERT_FALSE(paddingBytesWrittenExpected.hasError());
  auto paddingBytesWritten = paddingBytesWrittenExpected.value();

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
  auto result = writeFrame(paddingFrame, pktBuilder);
  ASSERT_FALSE(result.hasError());
  EXPECT_EQ(0, result.value());
}

TEST_F(QuicWriteCodecTest, WriteStreamBlocked) {
  MockQuicPacketBuilder pktBuilder;
  setupCommonExpects(pktBuilder);
  StreamId blockedId = 0xF00D;
  uint64_t blockedOffset = 0x1111;
  StreamDataBlockedFrame blockedFrame(blockedId, blockedOffset);
  auto blockedBytesWrittenExpected = writeFrame(blockedFrame, pktBuilder);
  ASSERT_FALSE(blockedBytesWrittenExpected.hasError());
  auto blockedBytesWritten = blockedBytesWrittenExpected.value();

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
  auto result = writeFrame(blockedFrame, pktBuilder);
  ASSERT_FALSE(result.hasError());
  EXPECT_EQ(0, result.value());
}

TEST_F(QuicWriteCodecTest, WriteRstStream) {
  MockQuicPacketBuilder pktBuilder;
  setupCommonExpects(pktBuilder);
  StreamId id = 0xBAAD;
  ApplicationErrorCode errorCode = GenericApplicationErrorCode::UNKNOWN;
  uint64_t offset = 0xF00D;
  RstStreamFrame rstStreamFrame(id, errorCode, offset);
  auto rstStreamBytesWrittenExpected = writeFrame(rstStreamFrame, pktBuilder);
  ASSERT_FALSE(rstStreamBytesWrittenExpected.hasError());
  auto rstStreamBytesWritten = rstStreamBytesWrittenExpected.value();

  auto builtOut = std::move(pktBuilder).buildTestPacket();
  auto regularPacket = builtOut.first;
  EXPECT_EQ(17, rstStreamBytesWritten);
  auto& resultRstStreamFrame = *regularPacket.frames[0].asRstStreamFrame();
  EXPECT_EQ(errorCode, resultRstStreamFrame.errorCode);
  EXPECT_EQ(id, resultRstStreamFrame.streamId);
  EXPECT_EQ(offset, resultRstStreamFrame.finalSize);

  auto wireBuf = std::move(builtOut.second);
  BufQueue queue;
  queue.append(wireBuf->clone());
  QuicFrame decodedFrame = parseQuicFrame(queue);
  auto& wireRstStreamFrame = *decodedFrame.asRstStreamFrame();
  EXPECT_EQ(errorCode, wireRstStreamFrame.errorCode);
  EXPECT_EQ(id, wireRstStreamFrame.streamId);
  EXPECT_EQ(offset, wireRstStreamFrame.finalSize);
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
  auto result = writeFrame(rstStreamFrame, pktBuilder);
  ASSERT_FALSE(result.hasError());
  EXPECT_EQ(0, result.value());
}

TEST_F(QuicWriteCodecTest, WriteRstStreamAt) {
  MockQuicPacketBuilder pktBuilder;
  setupCommonExpects(pktBuilder);
  StreamId id = 0xBAAD;
  ApplicationErrorCode errorCode = GenericApplicationErrorCode::UNKNOWN;
  uint64_t finalSize = 0xF00D;
  uint64_t reliableSize = 0xF00C;
  RstStreamFrame rstStreamFrame(id, errorCode, finalSize, reliableSize);
  auto rstStreamBytesWrittenExpected = writeFrame(rstStreamFrame, pktBuilder);
  ASSERT_FALSE(rstStreamBytesWrittenExpected.hasError());
  auto rstStreamBytesWritten = rstStreamBytesWrittenExpected.value();

  auto builtOut = std::move(pktBuilder).buildTestPacket();
  auto regularPacket = builtOut.first;
  EXPECT_EQ(21, rstStreamBytesWritten);
  auto& resultRstStreamFrame = *regularPacket.frames[0].asRstStreamFrame();
  EXPECT_EQ(errorCode, resultRstStreamFrame.errorCode);
  EXPECT_EQ(id, resultRstStreamFrame.streamId);
  EXPECT_EQ(finalSize, resultRstStreamFrame.finalSize);
  EXPECT_EQ(reliableSize, resultRstStreamFrame.reliableSize);

  auto wireBuf = std::move(builtOut.second);
  BufQueue queue;
  queue.append(wireBuf->clone());
  QuicFrame decodedFrame = parseQuicFrame(queue);
  auto& wireRstStreamFrame = *decodedFrame.asRstStreamFrame();
  EXPECT_EQ(errorCode, wireRstStreamFrame.errorCode);
  EXPECT_EQ(id, wireRstStreamFrame.streamId);
  EXPECT_EQ(finalSize, wireRstStreamFrame.finalSize);
  EXPECT_EQ(reliableSize, wireRstStreamFrame.reliableSize);
  // At last, verify there is nothing left in the wire format bytes:
  EXPECT_EQ(queue.chainLength(), 0);
}

TEST_F(QuicWriteCodecTest, WriteBlockedFrame) {
  MockQuicPacketBuilder pktBuilder;
  setupCommonExpects(pktBuilder);
  uint64_t blockedOffset = 0x11111;
  DataBlockedFrame blockedFrame(blockedOffset);
  auto bytesWrittenExpected = writeFrame(blockedFrame, pktBuilder);
  ASSERT_FALSE(bytesWrittenExpected.hasError());
  auto bytesWritten = bytesWrittenExpected.value();

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
  auto result = writeFrame(blockedFrame, pktBuilder);
  ASSERT_FALSE(result.hasError());
  EXPECT_EQ(0, result.value());
}

TEST_F(QuicWriteCodecTest, WriteStreamIdNeeded) {
  MockQuicPacketBuilder pktBuilder;
  setupCommonExpects(pktBuilder);
  StreamId blockedStreamId = 0x211;
  MaxStreamsFrame streamIdNeeded(blockedStreamId, true);
  auto bytesWrittenExpected =
      writeFrame(QuicSimpleFrame(streamIdNeeded), pktBuilder);
  ASSERT_FALSE(bytesWrittenExpected.hasError());
  auto bytesWritten = bytesWrittenExpected.value();

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
  auto result = writeFrame(QuicSimpleFrame(streamIdNeeded), pktBuilder);
  ASSERT_FALSE(result.hasError());
  EXPECT_EQ(0, result.value());
}

TEST_F(QuicWriteCodecTest, WriteNewConnId) {
  MockQuicPacketBuilder pktBuilder;
  setupCommonExpects(pktBuilder);
  StatelessResetToken token;
  memset(token.data(), 'a', token.size());
  NewConnectionIdFrame newConnId(1, 0, getTestConnectionId(), token);
  auto bytesWrittenExpected =
      writeFrame(QuicSimpleFrame(newConnId), pktBuilder);
  ASSERT_FALSE(bytesWrittenExpected.hasError());
  auto bytesWritten = bytesWrittenExpected.value();

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
  ASSERT_FALSE(bytesWritten.hasError());

  auto builtOut = std::move(pktBuilder).buildTestPacket();
  auto regularPacket = builtOut.first;
  EXPECT_EQ(bytesWritten.value(), 2);
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
  ASSERT_FALSE(bytesWritten.hasError());

  auto builtOut = std::move(pktBuilder).buildTestPacket();
  auto regularPacket = builtOut.first;
  EXPECT_EQ(bytesWritten.value(), 10);

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
  ASSERT_FALSE(writeFrame(QuicSimpleFrame(newConnId), pktBuilder).hasError());
  EXPECT_EQ(0, writeFrame(QuicSimpleFrame(newConnId), pktBuilder).value());
}

TEST_F(QuicWriteCodecTest, WritePathChallenge) {
  MockQuicPacketBuilder pktBuilder;
  setupCommonExpects(pktBuilder);

  uint64_t pathData = 0x64;
  PathChallengeFrame pathChallenge(pathData);
  auto bytesWritten = writeSimpleFrame(pathChallenge, pktBuilder);
  ASSERT_FALSE(bytesWritten.hasError());
  EXPECT_EQ(bytesWritten.value(), 9);

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
  ASSERT_FALSE(bytesWritten.hasError());
  EXPECT_EQ(bytesWritten.value(), 9);

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

TEST_F(QuicWriteCodecTest, WriteStreamFrameWithGroup) {
  MockQuicPacketBuilder pktBuilder;
  pktBuilder.remaining_ = 1300;
  setupCommonExpects(pktBuilder);
  auto inputBuf = buildRandomInputData(50);

  StreamId streamId = 4;
  StreamGroupId groupId = 64;
  uint64_t offset = 0;
  bool fin = true;

  auto res = writeStreamFrameHeader(
      pktBuilder,
      streamId,
      offset,
      50,
      50,
      fin,
      std::nullopt /* skipLenHint */,
      groupId);
  ASSERT_TRUE(res.has_value());
  auto dataLen = *res;
  ASSERT_TRUE(dataLen);
  ASSERT_EQ(*dataLen, 50);
  writeStreamFrameData(pktBuilder, inputBuf->clone(), 50);

  auto outputBuf = pktBuilder.data_->clone();
  EXPECT_EQ(outputBuf->computeChainDataLength(), 55);

  auto builtOut = std::move(pktBuilder).buildTestPacket();
  auto regularPacket = builtOut.first;
  EXPECT_EQ(regularPacket.frames.size(), 1);
  auto& resultFrame = *regularPacket.frames.back().asWriteStreamFrame();
  EXPECT_EQ(resultFrame.streamId, streamId);
  EXPECT_EQ(resultFrame.streamGroupId, groupId);
  EXPECT_EQ(resultFrame.offset, offset);
  EXPECT_EQ(resultFrame.len, 50);

  // Verify the on wire bytes via decoder.
  auto wireBuf = std::move(builtOut.second);
  BufQueue queue;
  queue.append(wireBuf->clone());
  auto streamFrameDecodedExpected = quic::parseFrame(
      queue,
      regularPacket.header,
      CodecParameters(kDefaultAckDelayExponent, QuicVersion::MVFST));
  ASSERT_TRUE(streamFrameDecodedExpected.has_value());
  auto& decodedStreamFrame = *streamFrameDecodedExpected->asReadStreamFrame();
  EXPECT_EQ(decodedStreamFrame.streamId, streamId);
  EXPECT_EQ(decodedStreamFrame.streamGroupId, groupId);
  EXPECT_EQ(decodedStreamFrame.offset, offset);
  EXPECT_EQ(decodedStreamFrame.data->computeChainDataLength(), 50);
  EXPECT_TRUE(folly::IOBufEqualTo()(inputBuf, decodedStreamFrame.data));
}

TEST_F(QuicWriteCodecTest, WriteAckFrequencyFrame) {
  MockQuicPacketBuilder pktBuilder;
  pktBuilder.remaining_ = 1300;
  setupCommonExpects(pktBuilder);

  AckFrequencyFrame frame;
  frame.sequenceNumber = 5; // Length: 1
  frame.packetTolerance = 100; // Length: 2
  frame.updateMaxAckDelay = 150000; // Length: 4
  frame.reorderThreshold = 50; // Length: 1

  auto dataLen = writeSimpleFrame(frame, pktBuilder);
  ASSERT_FALSE(dataLen.hasError());
  ASSERT_EQ(
      dataLen.value(),
      10); // Based upon the values passed above + 2 (frame-type)

  auto outputBuf = pktBuilder.data_->clone();
  EXPECT_EQ(outputBuf->computeChainDataLength(), 10);

  auto builtOut = std::move(pktBuilder).buildTestPacket();
  auto regularPacket = builtOut.first;
  ASSERT_EQ(regularPacket.frames.size(), 1);
  ASSERT_TRUE(regularPacket.frames[0].asQuicSimpleFrame());
  auto resultFrame =
      regularPacket.frames[0].asQuicSimpleFrame()->asAckFrequencyFrame();
  ASSERT_TRUE(resultFrame);
  EXPECT_EQ(resultFrame->sequenceNumber, frame.sequenceNumber);
  EXPECT_EQ(resultFrame->packetTolerance, frame.packetTolerance);
  EXPECT_EQ(resultFrame->sequenceNumber, frame.sequenceNumber);
  EXPECT_EQ(resultFrame->reorderThreshold, frame.reorderThreshold);

  // Verify the on wire bytes via decoder.
  auto wireBuf = std::move(builtOut.second);
  BufQueue queue;
  queue.append(wireBuf->clone());
  auto parsedFrameExpected = quic::parseFrame(
      queue,
      regularPacket.header,
      CodecParameters(kDefaultAckDelayExponent, QuicVersion::MVFST));
  ASSERT_TRUE(parsedFrameExpected.has_value());
  auto decodedFrame =
      parsedFrameExpected->asQuicSimpleFrame()->asAckFrequencyFrame();
  ASSERT_TRUE(decodedFrame);
  EXPECT_EQ(decodedFrame->sequenceNumber, frame.sequenceNumber);
  EXPECT_EQ(decodedFrame->packetTolerance, frame.packetTolerance);
  EXPECT_EQ(decodedFrame->sequenceNumber, frame.sequenceNumber);
  EXPECT_EQ(decodedFrame->reorderThreshold, frame.reorderThreshold);
}

INSTANTIATE_TEST_SUITE_P(
    QuicWriteCodecTests,
    QuicWriteCodecTest,
    Values(
        FrameType::ACK,
        FrameType::ACK_ECN,
        FrameType::ACK_RECEIVE_TIMESTAMPS,
        FrameType::ACK_EXTENDED));
} // namespace quic::test
