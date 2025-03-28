/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <quic/codec/QuicWriteCodec.h>

#include <algorithm>

#include <quic/QuicConstants.h>
#include <quic/QuicException.h>
#include <quic/codec/QuicInteger.h>
#include <cstdint>
#include <sstream>

namespace {

/**
 * A helper function to check if there are enough space to write in the packet.
 * Return: true if there is enough space, false otherwise
 */
bool packetSpaceCheck(uint64_t limit, size_t require) {
  return (folly::to<uint64_t>(require) <= limit);
}
} // namespace

namespace quic {

folly::Expected<Optional<uint64_t>, QuicError> writeStreamFrameHeader(
    PacketBuilderInterface& builder,
    StreamId id,
    uint64_t offset,
    uint64_t writeBufferLen,
    uint64_t flowControlLen,
    bool fin,
    Optional<bool> skipLenHint,
    OptionalIntegral<StreamGroupId> streamGroupId,
    bool appendFrame) {
  if (builder.remainingSpaceInPkt() == 0) {
    return none;
  }
  if (writeBufferLen == 0 && !fin) {
    return folly::makeUnexpected(QuicError(
        LocalErrorCode::INTERNAL_ERROR,
        "No data or fin supplied when writing stream."));
  }
  StreamTypeField::Builder streamTypeBuilder;
  if (streamGroupId) {
    streamTypeBuilder.switchToStreamGroups();
  }
  QuicInteger idInt(id);
  Optional<QuicInteger> groupIdInt;
  if (streamGroupId) {
    groupIdInt = QuicInteger(*streamGroupId);
  }

  // First account for the things that are non-optional: frame type, stream id
  // and (optional) group id.
  uint64_t headerSize = sizeof(uint8_t) + idInt.getSize();
  if (groupIdInt) {
    headerSize += groupIdInt->getSize();
  }
  if (builder.remainingSpaceInPkt() < headerSize) {
    VLOG(4) << "No space in packet for stream header. stream=" << id
            << " remaining=" << builder.remainingSpaceInPkt();
    return none;
  }
  QuicInteger offsetInt(offset);
  if (offset != 0) {
    streamTypeBuilder.setOffset();
    headerSize += offsetInt.getSize();
  }
  // Next we have to deal with the data length. This is trickier. The length of
  // data we are able to send depends on 3 things: how much we have in the
  // buffer, how much flow control we have, and the remaining size in the
  // packet. If the amount we want to send is >= the remaining packet size after
  // the header so far we can omit the length field and consume the rest of the
  // packet. If it is not then we need to use the minimal varint encoding
  // possible to avoid sending not-full packets.
  // Note: we don't bother with one potential optimization, which is writing
  // a zero length fin-only stream frame and omitting the length field.
  uint64_t dataLen = std::min(writeBufferLen, flowControlLen);
  uint64_t dataLenLen = 0;
  bool shouldSkipLengthField;
  if (skipLenHint) {
    shouldSkipLengthField = *skipLenHint;
  } else {
    // Check if we can fill the entire packet with the rest of this stream frame
    shouldSkipLengthField =
        dataLen > 0 && dataLen >= builder.remainingSpaceInPkt() - headerSize;
  }
  // At most we can write the minimal between data length and what the packet
  // builder allows us to write.
  dataLen = std::min(dataLen, builder.remainingSpaceInPkt() - headerSize);
  if (!shouldSkipLengthField) {
    if (dataLen <= kOneByteLimit - 1) {
      dataLenLen = 1;
    } else if (dataLen <= kTwoByteLimit - 2) {
      dataLenLen = 2;
    } else if (dataLen <= kFourByteLimit - 4) {
      dataLenLen = 4;
    } else if (dataLen <= kEightByteLimit - 8) {
      dataLenLen = 8;
    } else {
      // This should never really happen as dataLen is bounded by the remaining
      // space in the packet which should be << kEightByteLimit.
      LOG(FATAL) << "Stream frame length too large.";
    }
  }
  if (dataLenLen > 0) {
    if (dataLen != 0 &&
        headerSize + dataLenLen >= builder.remainingSpaceInPkt()) {
      VLOG(4) << "No space in packet for stream header. stream=" << id
              << " remaining=" << builder.remainingSpaceInPkt();
      return none;
    }
    // We have to encode the actual data length in the header.
    headerSize += dataLenLen;
    if (builder.remainingSpaceInPkt() < dataLen + headerSize) {
      dataLen = builder.remainingSpaceInPkt() - headerSize;
    }
  }
  bool shouldSetFin = fin && dataLen == writeBufferLen;
  if (dataLen == 0 && !shouldSetFin) {
    // This would be an empty non-fin stream frame.
    return none;
  }
  if (builder.remainingSpaceInPkt() < headerSize) {
    VLOG(4) << "No space in packet for stream header. stream=" << id
            << " remaining=" << builder.remainingSpaceInPkt();
    return none;
  }

  // Done with the accounting, set the bits and write the actual frame header.
  if (dataLenLen > 0) {
    streamTypeBuilder.setLength();
  }
  if (shouldSetFin) {
    streamTypeBuilder.setFin();
  }
  auto streamType = streamTypeBuilder.build();
  builder.writeBE(streamType.fieldValue());
  builder.write(idInt);
  if (groupIdInt) {
    builder.write(*groupIdInt);
  }
  if (offset != 0) {
    builder.write(offsetInt);
  }
  if (dataLenLen > 0) {
    builder.write(QuicInteger(dataLen));
  }
  if (appendFrame) {
    builder.appendFrame(WriteStreamFrame(
        id,
        offset,
        dataLen,
        streamType.hasFin(),
        false /* fromBufMetaIn */,
        streamGroupId));
  } else {
    builder.markNonEmpty();
  }
  return folly::make_optional(dataLen);
}

void writeStreamFrameData(
    PacketBuilderInterface& builder,
    const ChainedByteRangeHead& writeBuffer,
    uint64_t dataLen) {
  if (dataLen > 0) {
    builder.insert(writeBuffer, dataLen);
  }
}

Optional<WriteCryptoFrame> writeCryptoFrame(
    uint64_t offsetIn,
    const ChainedByteRangeHead& data,
    PacketBuilderInterface& builder) {
  uint64_t spaceLeftInPkt = builder.remainingSpaceInPkt();
  QuicInteger intFrameType(static_cast<uint8_t>(FrameType::CRYPTO_FRAME));
  QuicInteger offsetInteger(offsetIn);

  size_t lengthBytes = 2;
  size_t cryptoFrameHeaderSize =
      intFrameType.getSize() + offsetInteger.getSize() + lengthBytes;

  if (spaceLeftInPkt <= cryptoFrameHeaderSize) {
    VLOG(3) << "No space left in packet to write cryptoFrame header of size: "
            << cryptoFrameHeaderSize << ", space left=" << spaceLeftInPkt;
    return none;
  }
  size_t spaceRemaining = spaceLeftInPkt - cryptoFrameHeaderSize;
  size_t dataLength = data.chainLength();
  size_t writableData = std::min(dataLength, spaceRemaining);
  QuicInteger lengthVarInt(writableData);

  CHECK(lengthVarInt.getSize() <= lengthBytes)
      << "Length bytes representation exceeds allocated space";
  builder.write(intFrameType);
  builder.write(offsetInteger);
  builder.write(lengthVarInt);
  builder.insert(data, writableData);
  builder.appendFrame(WriteCryptoFrame(offsetIn, lengthVarInt.getValue()));
  return WriteCryptoFrame(offsetIn, lengthVarInt.getValue());
}

/*
 * This function will fill the parameter ack frame with ack blocks from the
 * parameter ackBlocks until it runs out of space (bytesLimit). The largest
 * ack block should have been inserted by the caller.
 */
static size_t fillFrameWithAckBlocks(
    const AckBlocks& ackBlocks,
    WriteAckFrame& ackFrame,
    uint64_t bytesLimit) {
  PacketNum currentSeqNum = ackBlocks.crbegin()->start;

  // starts off with 0 which is what we assumed the initial ack block to be for
  // the largest acked.
  size_t numAdditionalAckBlocks = 0;
  size_t previousNumAckBlocks = 0;

  // Skip the largest, as it has already been emplaced.
  for (auto blockItr = ackBlocks.crbegin() + 1; blockItr != ackBlocks.crend();
       ++blockItr) {
    const auto& currBlock = *blockItr;
    // These must be true because of the properties of the interval set.
    CHECK_GE(currentSeqNum, currBlock.end + 2);
    PacketNum gap = currentSeqNum - currBlock.end - 2;
    PacketNum currBlockLen = currBlock.end - currBlock.start;

    // TODO this is still extra work, as we end up duplicating these
    // calculations in the caller, we could store the results so they
    // can be reused by the caller when writing the frame.
    size_t gapSize = getQuicIntegerSizeThrows(gap);
    size_t currBlockLenSize = getQuicIntegerSizeThrows(currBlockLen);
    size_t numAdditionalAckBlocksSize =
        getQuicIntegerSizeThrows(numAdditionalAckBlocks + 1);
    size_t previousNumAckBlocksSize =
        getQuicIntegerSizeThrows(previousNumAckBlocks);

    size_t additionalSize = gapSize + currBlockLenSize +
        (numAdditionalAckBlocksSize - previousNumAckBlocksSize);
    if (bytesLimit < additionalSize) {
      break;
    }
    numAdditionalAckBlocks++;
    bytesLimit -= additionalSize;
    previousNumAckBlocks = numAdditionalAckBlocks;
    currentSeqNum = currBlock.start;
    ackFrame.ackBlocks.emplace_back(currBlock.start, currBlock.end);
  }
  return numAdditionalAckBlocks;
}

size_t computeSizeUsedByRecvdTimestamps(WriteAckFrame& ackFrame) {
  size_t usedSize = 0;
  for (auto& recvdPacketsTimestampRanges :
       ackFrame.recvdPacketsTimestampRanges) {
    usedSize += getQuicIntegerSizeThrows(recvdPacketsTimestampRanges.gap);
    usedSize += getQuicIntegerSizeThrows(
        recvdPacketsTimestampRanges.timestamp_delta_count);
    for (auto& timestampDelta : recvdPacketsTimestampRanges.deltas) {
      usedSize += getQuicIntegerSizeThrows(timestampDelta);
    }
  }
  return usedSize;
}

static size_t fillFrameWithPacketReceiveTimestamps(
    const quic::WriteAckFrameMetaData& ackFrameMetaData,
    WriteAckFrame& ackFrame,
    uint64_t largestAckedPacketNum,
    uint64_t spaceLeft,
    uint64_t receiveTimestampsExponent,
    uint64_t maxRecvTimestampsToSend) {
  if (ackFrameMetaData.ackState.recvdPacketInfos.size() == 0) {
    return 0;
  }
  auto recvdPacketInfos = ackFrameMetaData.ackState.recvdPacketInfos;
  // Insert all received packet timestamps into an interval set, to identify
  // contiguous ranges

  uint64_t pktsAdded = 0;
  IntervalSet<PacketNum> receivedPktNumsIntervalSet;
  for (auto& recvdPkt : recvdPacketInfos) {
    // Add up to the peer requested max ack receive timestamps;
    if (pktsAdded == maxRecvTimestampsToSend) {
      break;
    }
    receivedPktNumsIntervalSet.insert(recvdPkt.pktNum);
    pktsAdded++;
  }
  auto prevPktNum = largestAckedPacketNum;
  auto timestampIt = recvdPacketInfos.crbegin();
  size_t cumUsedSpace = 0;
  // We start from the latest timestamp intervals
  bool outOfSpace = false;
  for (auto timestampIntervalsIt = receivedPktNumsIntervalSet.crbegin();
       timestampIntervalsIt != receivedPktNumsIntervalSet.crend();
       timestampIntervalsIt++) {
    RecvdPacketsTimestampsRange nextTimestampRange;
    size_t nextTimestampRangeUsedSpace = 0;
    // Compute pktNum gap for each time-stamp range
    if (ackFrame.recvdPacketsTimestampRanges.empty()) {
      nextTimestampRange.gap = prevPktNum - timestampIntervalsIt->end;
    } else {
      nextTimestampRange.gap = prevPktNum - 2 - timestampIntervalsIt->end;
    }
    // Initialize spaced used by the next candidate time-stamp range
    nextTimestampRangeUsedSpace +=
        getQuicIntegerSizeThrows(nextTimestampRange.gap);

    while (timestampIt != recvdPacketInfos.crend() &&
           timestampIt->pktNum >= timestampIntervalsIt->start &&
           timestampIt->pktNum <= timestampIntervalsIt->end) {
      std::chrono::microseconds deltaDuration;
      if (timestampIt == recvdPacketInfos.crbegin()) {
        deltaDuration =
            (timestampIt->timings.receiveTimePoint > ackFrameMetaData.connTime)
            ? std::chrono::duration_cast<std::chrono::microseconds>(
                  timestampIt->timings.receiveTimePoint -
                  ackFrameMetaData.connTime)
            : 0us;
      } else {
        deltaDuration = std::chrono::duration_cast<std::chrono::microseconds>(
            (timestampIt - 1)->timings.receiveTimePoint -
            timestampIt->timings.receiveTimePoint);
      }
      auto delta = deltaDuration.count() >> receiveTimestampsExponent;
      // Check if adding a new time-stamp delta from the current time-stamp
      // interval Will allow us to run out of space. Since adding a new delta
      // impacts cumulative counts of deltas these are not already incorporated
      // into nextTimestampRangeUsedSpace.
      if (spaceLeft <
          (cumUsedSpace + nextTimestampRangeUsedSpace +
           getQuicIntegerSizeThrows(delta) +
           getQuicIntegerSizeThrows(nextTimestampRange.deltas.size() + 1) +
           getQuicIntegerSizeThrows(
               ackFrame.recvdPacketsTimestampRanges.size() + 1))) {
        outOfSpace = true;
        break;
      }
      nextTimestampRange.deltas.push_back(delta);
      nextTimestampRangeUsedSpace += getQuicIntegerSizeThrows(delta);
      timestampIt++;
    }
    if (nextTimestampRange.deltas.size() > 0) {
      nextTimestampRange.timestamp_delta_count =
          nextTimestampRange.deltas.size();
      cumUsedSpace += nextTimestampRangeUsedSpace +
          getQuicIntegerSizeThrows(nextTimestampRange.deltas.size());
      ackFrame.recvdPacketsTimestampRanges.push_back(nextTimestampRange);
      prevPktNum = timestampIntervalsIt->start;
      DCHECK(cumUsedSpace <= spaceLeft);
    }
    if (outOfSpace) {
      break;
    }
  }
  DCHECK(cumUsedSpace == computeSizeUsedByRecvdTimestamps(ackFrame));
  return ackFrame.recvdPacketsTimestampRanges.size();
}

static Optional<WriteAckFrame> maybeWriteAckBaseFields(
    const quic::WriteAckFrameMetaData& ackFrameMetaData,
    PacketBuilderInterface& builder,
    FrameType frameType,
    uint64_t maxSpaceToUse) {
  auto spaceLeft = maxSpaceToUse;
  const WriteAckFrameState& ackState = ackFrameMetaData.ackState;
  // The last block must be the largest block.
  auto largestAckedPacket = ackState.acks.back().end;
  // ackBlocks are already an interval set so each value is naturally
  // non-overlapping.
  auto firstAckBlockLength = largestAckedPacket - ackState.acks.back().start;
  // We could technically split the range if the size of the representation of
  // the integer is too large, but that gets super tricky and is of dubious
  // value.
  QuicInteger largestAckedPacketInt(largestAckedPacket);
  QuicInteger firstAckBlockLengthInt(firstAckBlockLength);
  // Convert ackDelay to unsigned value explicitly before right shifting to
  // avoid issues with right shifting signed values.
  uint64_t encodedAckDelay = ackFrameMetaData.ackDelay.count();
  encodedAckDelay = encodedAckDelay >> ackFrameMetaData.ackDelayExponent;
  QuicInteger ackDelayInt(encodedAckDelay);
  QuicInteger minAdditionalAckBlockCount(0);

  // Required fields are Type, LargestAcked, AckDelay, AckBlockCount,
  // firstAckBlockLength
  QuicInteger encodedintFrameType(static_cast<uint8_t>(frameType));
  uint64_t headerSize = encodedintFrameType.getSize() +
      largestAckedPacketInt.getSize() + ackDelayInt.getSize() +
      minAdditionalAckBlockCount.getSize() + firstAckBlockLengthInt.getSize();

  if (spaceLeft < headerSize) {
    return none;
  }
  WriteAckFrame ackFrame;
  ackFrame.frameType = frameType;

  // Reserve the number of ack blocks we could fit in the remaining space.
  ackFrame.ackBlocks.reserve(spaceLeft / 4);

  // Account for the header size
  spaceLeft -= headerSize;

  ackFrame.ackBlocks.push_back(ackState.acks.back());
  auto numAdditionalAckBlocks =
      fillFrameWithAckBlocks(ackState.acks, ackFrame, spaceLeft);
  QuicInteger numAdditionalAckBlocksInt(numAdditionalAckBlocks);
  builder.write(encodedintFrameType);
  builder.write(largestAckedPacketInt);
  builder.write(ackDelayInt);
  builder.write(numAdditionalAckBlocksInt);
  builder.write(firstAckBlockLengthInt);

  PacketNum currentSeqNum = ackState.acks.back().start;
  for (auto it = ackFrame.ackBlocks.cbegin() + 1;
       it != ackFrame.ackBlocks.cend();
       ++it) {
    CHECK_GE(currentSeqNum, it->end + 2);
    PacketNum gap = currentSeqNum - it->end - 2;
    PacketNum currBlockLen = it->end - it->start;
    QuicInteger gapInt(gap);
    QuicInteger currentBlockLenInt(currBlockLen);
    builder.write(gapInt);
    builder.write(currentBlockLenInt);
    currentSeqNum = it->start;
  }
  ackFrame.ackDelay = ackFrameMetaData.ackDelay;

  return ackFrame;
}

static uint64_t computeEcnRequiredSpace(
    const quic::WriteAckFrameMetaData& ackFrameMetaData) {
  QuicInteger ecnECT0Count(ackFrameMetaData.ackState.ecnECT0CountReceived);
  QuicInteger ecnECT1Count(ackFrameMetaData.ackState.ecnECT1CountReceived);
  QuicInteger ecnCECount(ackFrameMetaData.ackState.ecnCECountReceived);
  return ecnECT0Count.getSize() + ecnECT1Count.getSize() + ecnCECount.getSize();
}

static uint64_t computeReceiveTimestampsMinimumSpace(
    const quic::WriteAckFrameMetaData& ackFrameMetaData) {
  // Compute minimum size requirements for 3 fields that must be sent
  // in every ACK_RECEIVE_TIMESTAMPS frame
  const WriteAckFrameState& ackState = ackFrameMetaData.ackState;
  uint64_t countTimestampRanges = 0;
  uint64_t maybeLastPktNum = 0;
  std::chrono::microseconds maybeLastPktTsDelta = 0us;
  if (ackState.lastRecvdPacketInfo) {
    maybeLastPktNum = ackState.lastRecvdPacketInfo.value().pktNum;

    maybeLastPktTsDelta =
        (ackState.lastRecvdPacketInfo.value().timings.receiveTimePoint >
                 ackFrameMetaData.connTime
             ? std::chrono::duration_cast<std::chrono::microseconds>(
                   ackState.lastRecvdPacketInfo.value()
                       .timings.receiveTimePoint -
                   ackFrameMetaData.connTime)
             : 0us);
  }

  return getQuicIntegerSize(countTimestampRanges).value_or(0) +
      getQuicIntegerSize(maybeLastPktNum).value_or(0) +
      getQuicIntegerSize(maybeLastPktTsDelta.count()).value_or(0);
}

static void writeECNFieldsToAck(
    const quic::WriteAckFrameMetaData& ackFrameMetaData,
    WriteAckFrame& ackFrame,
    PacketBuilderInterface& builder) {
  ackFrame.ecnECT0Count = ackFrameMetaData.ackState.ecnECT0CountReceived;
  ackFrame.ecnECT1Count = ackFrameMetaData.ackState.ecnECT1CountReceived;
  ackFrame.ecnCECount = ackFrameMetaData.ackState.ecnCECountReceived;
  QuicInteger ecnECT0Count(ackFrameMetaData.ackState.ecnECT0CountReceived);
  QuicInteger ecnECT1Count(ackFrameMetaData.ackState.ecnECT1CountReceived);
  QuicInteger ecnCECount(ackFrameMetaData.ackState.ecnCECountReceived);
  builder.write(ecnECT0Count);
  builder.write(ecnECT1Count);
  builder.write(ecnCECount);
}

namespace {
struct AckReceiveTimesStampsWritten {
  size_t TimestampRangesWritten{0};
  size_t TimestampWritten{0};
};
} // namespace

AckReceiveTimesStampsWritten writeReceiveTimestampFieldsToAck(
    const quic::WriteAckFrameMetaData& ackFrameMetaData,
    WriteAckFrame& ackFrame,
    PacketBuilderInterface& builder,
    const AckReceiveTimestampsConfig& recvTimestampsConfig,
    uint64_t maxRecvTimestampsToSend) {
  const WriteAckFrameState& ackState = ackFrameMetaData.ackState;
  uint64_t spaceLeft = builder.remainingSpaceInPkt();
  uint64_t lastPktNum = 0;
  std::chrono::microseconds lastPktTsDelta = 0us;
  if (ackState.lastRecvdPacketInfo) {
    lastPktNum = ackState.lastRecvdPacketInfo.value().pktNum;
    lastPktTsDelta =
        (ackState.lastRecvdPacketInfo.value().timings.receiveTimePoint >
                 ackFrameMetaData.connTime
             ? std::chrono::duration_cast<std::chrono::microseconds>(
                   ackState.lastRecvdPacketInfo.value()
                       .timings.receiveTimePoint -
                   ackFrameMetaData.connTime)
             : 0us);
  }
  QuicInteger lastRecvdPacketNumInt(lastPktNum);
  builder.write(lastRecvdPacketNumInt);
  ackFrame.maybeLatestRecvdPacketNum = lastRecvdPacketNumInt.getValue();
  QuicInteger lastRecvdPacketTimeInt(lastPktTsDelta.count());
  builder.write(lastRecvdPacketTimeInt);
  ackFrame.maybeLatestRecvdPacketTime =
      std::chrono::microseconds(lastRecvdPacketTimeInt.getValue());

  size_t countTimestampRanges = 0;
  size_t countTimestamps = 0;
  spaceLeft = builder.remainingSpaceInPkt();
  if (spaceLeft > 0) {
    auto largestAckedPacket = ackState.acks.back().end;
    uint64_t receiveTimestampsExponentToUse =
        recvTimestampsConfig.receiveTimestampsExponent;
    countTimestampRanges = fillFrameWithPacketReceiveTimestamps(
        ackFrameMetaData,
        ackFrame,
        largestAckedPacket,
        spaceLeft,
        receiveTimestampsExponentToUse,
        maxRecvTimestampsToSend);
    if (countTimestampRanges > 0) {
      QuicInteger timeStampRangeCountInt(
          ackFrame.recvdPacketsTimestampRanges.size());
      builder.write(timeStampRangeCountInt);
      for (auto& recvdPacketsTimestampRanges :
           ackFrame.recvdPacketsTimestampRanges) {
        QuicInteger gapInt(recvdPacketsTimestampRanges.gap);
        QuicInteger timestampDeltaCountInt(
            recvdPacketsTimestampRanges.timestamp_delta_count);
        builder.write(gapInt);
        builder.write(timestampDeltaCountInt);
        for (auto& timestamp : recvdPacketsTimestampRanges.deltas) {
          QuicInteger deltaInt(timestamp);
          builder.write(deltaInt);
          countTimestamps++;
        }
      }
    } else {
      QuicInteger timeStampRangeCountInt(0);
      builder.write(timeStampRangeCountInt);
    }
  }
  return AckReceiveTimesStampsWritten{countTimestampRanges, countTimestamps};
}

Optional<WriteAckFrameResult> writeAckFrame(
    const quic::WriteAckFrameMetaData& ackFrameMetaData,
    PacketBuilderInterface& builder,
    FrameType frameType,
    const AckReceiveTimestampsConfig& recvTimestampsConfig,
    uint64_t maxRecvTimestampsToSend,
    ExtendedAckFeatureMaskType extendedAckFeatures) {
  if (ackFrameMetaData.ackState.acks.empty()) {
    return none;
  }
  uint64_t beginningSpace = builder.remainingSpaceInPkt();
  uint64_t spaceLeft = beginningSpace;

  bool ecnEnabled = (frameType == FrameType::ACK_ECN) ||
      (extendedAckFeatures &
       static_cast<ExtendedAckFeatureMaskType>(
           ExtendedAckFeatureMask::ECN_COUNTS));

  bool receiveTimestampsEnabled =
      (frameType == FrameType::ACK_RECEIVE_TIMESTAMPS) ||
      (extendedAckFeatures &
       static_cast<ExtendedAckFeatureMaskType>(
           ExtendedAckFeatureMask::RECEIVE_TIMESTAMPS));

  // Reserve space for ACK_EXTENDED header
  if (frameType == FrameType::ACK_EXTENDED) {
    auto extendedAckRequiredSpace = QuicInteger(extendedAckFeatures).getSize();
    if (spaceLeft < extendedAckRequiredSpace) {
      return none;
    }
    spaceLeft -= extendedAckRequiredSpace;
  }

  // Reserve space for ECN counts if enabled
  if (ecnEnabled) {
    auto ecnRequiredSpace = computeEcnRequiredSpace(ackFrameMetaData);
    if (spaceLeft < ecnRequiredSpace) {
      return none;
    }
    spaceLeft -= ecnRequiredSpace;
  }

  // Reserve space for receive timestamps if enabled
  if (receiveTimestampsEnabled) {
    auto receiveTimestampsMinimumSpace =
        computeReceiveTimestampsMinimumSpace(ackFrameMetaData);
    if (spaceLeft < receiveTimestampsMinimumSpace) {
      return none;
    }
    spaceLeft -= receiveTimestampsMinimumSpace;
  }

  // Start writing fields to the builder

  // 1. Write the base ack fields
  auto maybeAckFrame =
      maybeWriteAckBaseFields(ackFrameMetaData, builder, frameType, spaceLeft);
  if (!maybeAckFrame.has_value()) {
    return none;
  }
  auto& ackFrame = maybeAckFrame.value();

  // 2. Write extended ack header if enabled
  if (frameType == FrameType::ACK_EXTENDED) {
    QuicInteger quicExtendedAckFeatures(extendedAckFeatures);
    builder.write(quicExtendedAckFeatures);
  }

  // 3. Write ECN fields if enabled
  if (ecnEnabled) {
    writeECNFieldsToAck(ackFrameMetaData, ackFrame, builder);
  }

  // 4. Write receive timestamp fields if enabled
  AckReceiveTimesStampsWritten receiveTimestampsWritten;
  if (receiveTimestampsEnabled) {
    receiveTimestampsWritten = writeReceiveTimestampFieldsToAck(
        ackFrameMetaData,
        ackFrame,
        builder,
        recvTimestampsConfig,
        maxRecvTimestampsToSend);
  }
  // Everything written
  auto ackFrameWriteResult = WriteAckFrameResult(
      beginningSpace - builder.remainingSpaceInPkt(),
      ackFrame,
      ackFrame.ackBlocks.size(),
      receiveTimestampsWritten.TimestampRangesWritten,
      receiveTimestampsWritten.TimestampWritten,
      extendedAckFeatures);

  builder.appendFrame(std::move(ackFrame));
  return ackFrameWriteResult;
}

size_t writeSimpleFrame(
    QuicSimpleFrame&& frame,
    PacketBuilderInterface& builder) {
  using FrameTypeType = std::underlying_type<FrameType>::type;

  uint64_t spaceLeft = builder.remainingSpaceInPkt();

  switch (frame.type()) {
    case QuicSimpleFrame::Type::StopSendingFrame: {
      const StopSendingFrame& stopSendingFrame = *frame.asStopSendingFrame();
      QuicInteger intFrameType(static_cast<uint8_t>(FrameType::STOP_SENDING));
      QuicInteger streamId(stopSendingFrame.streamId);
      QuicInteger errorCode(static_cast<uint64_t>(stopSendingFrame.errorCode));
      size_t errorSize = errorCode.getSize();
      auto stopSendingFrameSize =
          intFrameType.getSize() + streamId.getSize() + errorSize;
      if (packetSpaceCheck(spaceLeft, stopSendingFrameSize)) {
        builder.write(intFrameType);
        builder.write(streamId);
        builder.write(errorCode);
        builder.appendFrame(QuicSimpleFrame(std::move(stopSendingFrame)));
        return stopSendingFrameSize;
      }
      // no space left in packet
      return size_t(0);
    }
    case QuicSimpleFrame::Type::PathChallengeFrame: {
      const PathChallengeFrame& pathChallengeFrame =
          *frame.asPathChallengeFrame();
      QuicInteger frameType(static_cast<uint8_t>(FrameType::PATH_CHALLENGE));
      auto pathChallengeFrameSize =
          frameType.getSize() + sizeof(pathChallengeFrame.pathData);
      if (packetSpaceCheck(spaceLeft, pathChallengeFrameSize)) {
        builder.write(frameType);
        builder.writeBE(pathChallengeFrame.pathData);
        builder.appendFrame(QuicSimpleFrame(std::move(pathChallengeFrame)));
        return pathChallengeFrameSize;
      }
      // no space left in packet
      return size_t(0);
    }
    case QuicSimpleFrame::Type::PathResponseFrame: {
      const PathResponseFrame& pathResponseFrame = *frame.asPathResponseFrame();
      QuicInteger frameType(static_cast<uint8_t>(FrameType::PATH_RESPONSE));
      auto pathResponseFrameSize =
          frameType.getSize() + sizeof(pathResponseFrame.pathData);
      if (packetSpaceCheck(spaceLeft, pathResponseFrameSize)) {
        builder.write(frameType);
        builder.writeBE(pathResponseFrame.pathData);
        builder.appendFrame(QuicSimpleFrame(std::move(pathResponseFrame)));
        return pathResponseFrameSize;
      }
      // no space left in packet
      return size_t(0);
    }
    case QuicSimpleFrame::Type::NewConnectionIdFrame: {
      const NewConnectionIdFrame& newConnectionIdFrame =
          *frame.asNewConnectionIdFrame();
      QuicInteger frameType(static_cast<uint8_t>(FrameType::NEW_CONNECTION_ID));
      QuicInteger sequenceNumber(newConnectionIdFrame.sequenceNumber);
      QuicInteger retirePriorTo(newConnectionIdFrame.retirePriorTo);
      // Include an 8-bit unsigned integer containing the length of the connId
      auto newConnectionIdFrameSize = frameType.getSize() +
          sequenceNumber.getSize() + retirePriorTo.getSize() + sizeof(uint8_t) +
          newConnectionIdFrame.connectionId.size() +
          newConnectionIdFrame.token.size();
      if (packetSpaceCheck(spaceLeft, newConnectionIdFrameSize)) {
        builder.write(frameType);
        builder.write(sequenceNumber);
        builder.write(retirePriorTo);
        builder.writeBE(newConnectionIdFrame.connectionId.size());
        builder.push(
            newConnectionIdFrame.connectionId.data(),
            newConnectionIdFrame.connectionId.size());
        builder.push(
            newConnectionIdFrame.token.data(),
            newConnectionIdFrame.token.size());
        builder.appendFrame(QuicSimpleFrame(std::move(newConnectionIdFrame)));
        return newConnectionIdFrameSize;
      }
      // no space left in packet
      return size_t(0);
    }
    case QuicSimpleFrame::Type::MaxStreamsFrame: {
      const MaxStreamsFrame& maxStreamsFrame = *frame.asMaxStreamsFrame();
      auto frameType = maxStreamsFrame.isForBidirectionalStream()
          ? FrameType::MAX_STREAMS_BIDI
          : FrameType::MAX_STREAMS_UNI;
      QuicInteger intFrameType(static_cast<FrameTypeType>(frameType));
      QuicInteger streamCount(maxStreamsFrame.maxStreams);
      auto maxStreamsFrameSize = intFrameType.getSize() + streamCount.getSize();
      if (packetSpaceCheck(spaceLeft, maxStreamsFrameSize)) {
        builder.write(intFrameType);
        builder.write(streamCount);
        builder.appendFrame(QuicSimpleFrame(maxStreamsFrame));
        return maxStreamsFrameSize;
      }
      return size_t(0);
    }
    case QuicSimpleFrame::Type::RetireConnectionIdFrame: {
      const RetireConnectionIdFrame& retireConnectionIdFrame =
          *frame.asRetireConnectionIdFrame();
      QuicInteger frameType(
          static_cast<uint8_t>(FrameType::RETIRE_CONNECTION_ID));
      QuicInteger sequence(retireConnectionIdFrame.sequenceNumber);
      auto retireConnectionIdFrameSize =
          frameType.getSize() + sequence.getSize();
      if (packetSpaceCheck(spaceLeft, retireConnectionIdFrameSize)) {
        builder.write(frameType);
        builder.write(sequence);
        builder.appendFrame(QuicSimpleFrame(retireConnectionIdFrame));
        return retireConnectionIdFrameSize;
      }
      // no space left in packet
      return size_t(0);
    }
    case QuicSimpleFrame::Type::HandshakeDoneFrame: {
      const HandshakeDoneFrame& handshakeDoneFrame =
          *frame.asHandshakeDoneFrame();
      CHECK(builder.getPacketHeader().asShort());
      QuicInteger intFrameType(static_cast<uint8_t>(FrameType::HANDSHAKE_DONE));
      if (packetSpaceCheck(spaceLeft, intFrameType.getSize())) {
        builder.write(intFrameType);
        builder.appendFrame(QuicSimpleFrame(handshakeDoneFrame));
        return intFrameType.getSize();
      }
      // no space left in packet
      return size_t(0);
    }
    case QuicSimpleFrame::Type::KnobFrame: {
      const KnobFrame& knobFrame = *frame.asKnobFrame();
      QuicInteger intFrameType(static_cast<uint64_t>(FrameType::KNOB));
      QuicInteger intKnobSpace(knobFrame.knobSpace);
      QuicInteger intKnobId(knobFrame.id);
      QuicInteger intKnobLen(knobFrame.len);
      size_t knobFrameLen = intFrameType.getSize() + intKnobSpace.getSize() +
          intKnobId.getSize() + intKnobLen.getSize() + intKnobLen.getValue();
      if (packetSpaceCheck(spaceLeft, knobFrameLen)) {
        builder.write(intFrameType);
        builder.write(intKnobSpace);
        builder.write(intKnobId);
        builder.write(intKnobLen);
        builder.insert(knobFrame.blob->clone());
        builder.appendFrame(QuicSimpleFrame(knobFrame));
        return knobFrameLen;
      }
      // no space left in packet
      return size_t(0);
    }
    case QuicSimpleFrame::Type::AckFrequencyFrame: {
      const auto ackFrequencyFrame = frame.asAckFrequencyFrame();
      QuicInteger intFrameType(static_cast<uint64_t>(FrameType::ACK_FREQUENCY));
      QuicInteger intSequenceNumber(ackFrequencyFrame->sequenceNumber);
      QuicInteger intPacketTolerance(ackFrequencyFrame->packetTolerance);
      QuicInteger intUpdateMaxAckDelay(ackFrequencyFrame->updateMaxAckDelay);
      QuicInteger intReorderThreshold(ackFrequencyFrame->reorderThreshold);
      size_t ackFrequencyFrameLen = intFrameType.getSize() +
          intSequenceNumber.getSize() + intPacketTolerance.getSize() +
          intUpdateMaxAckDelay.getSize() + intReorderThreshold.getSize();
      if (packetSpaceCheck(spaceLeft, ackFrequencyFrameLen)) {
        builder.write(intFrameType);
        builder.write(intSequenceNumber);
        builder.write(intPacketTolerance);
        builder.write(intUpdateMaxAckDelay);
        builder.write(intReorderThreshold);
        builder.appendFrame(QuicSimpleFrame(*ackFrequencyFrame));
        return ackFrequencyFrameLen;
      }
      // no space left in packet
      return size_t(0);
    }
    case QuicSimpleFrame::Type::NewTokenFrame: {
      const auto newTokenFrame = frame.asNewTokenFrame();
      QuicInteger intFrameType(static_cast<uint8_t>(FrameType::NEW_TOKEN));

      auto& token = newTokenFrame->token;
      QuicInteger tokenLength(token->computeChainDataLength());
      auto newTokenFrameLength = intFrameType.getSize() +
          /*encoding token length*/ tokenLength.getSize() +
          tokenLength.getValue();

      if (packetSpaceCheck(spaceLeft, newTokenFrameLength)) {
        builder.write(intFrameType);
        builder.write(tokenLength);
        builder.insert(token->clone());
        builder.appendFrame(QuicSimpleFrame(*newTokenFrame));
        return newTokenFrameLength;
      }
      // no space left in packet
      return size_t(0);
    }
  }
  folly::assume_unreachable();
}

size_t writeFrame(QuicWriteFrame&& frame, PacketBuilderInterface& builder) {
  using FrameTypeType = std::underlying_type<FrameType>::type;

  uint64_t spaceLeft = builder.remainingSpaceInPkt();

  switch (frame.type()) {
    case QuicWriteFrame::Type::PaddingFrame: {
      QuicInteger intFrameType(static_cast<uint8_t>(FrameType::PADDING));
      if (packetSpaceCheck(spaceLeft, intFrameType.getSize())) {
        builder.write(intFrameType);
        builder.appendPaddingFrame();
        return intFrameType.getSize();
      }
      return size_t(0);
    }
    case QuicWriteFrame::Type::RstStreamFrame: {
      RstStreamFrame& rstStreamFrame = *frame.asRstStreamFrame();
      QuicInteger intFrameType(static_cast<uint8_t>(
          rstStreamFrame.reliableSize ? FrameType::RST_STREAM_AT
                                      : FrameType::RST_STREAM));
      QuicInteger streamId(rstStreamFrame.streamId);
      QuicInteger finalSize(rstStreamFrame.finalSize);
      QuicInteger errorCode(static_cast<uint64_t>(rstStreamFrame.errorCode));
      folly::Optional<QuicInteger> maybeReliableSize = folly::none;
      size_t errorSize = errorCode.getSize();
      auto rstStreamFrameSize = intFrameType.getSize() + errorSize +
          streamId.getSize() + finalSize.getSize();
      if (rstStreamFrame.reliableSize) {
        maybeReliableSize = QuicInteger(*rstStreamFrame.reliableSize);
        rstStreamFrameSize += maybeReliableSize->getSize();
      }
      if (packetSpaceCheck(spaceLeft, rstStreamFrameSize)) {
        builder.write(intFrameType);
        builder.write(streamId);
        builder.write(errorCode);
        builder.write(finalSize);
        if (maybeReliableSize) {
          builder.write(*maybeReliableSize);
        }
        builder.appendFrame(std::move(rstStreamFrame));
        return rstStreamFrameSize;
      }
      // no space left in packet
      return size_t(0);
    }
    case QuicWriteFrame::Type::MaxDataFrame: {
      MaxDataFrame& maxDataFrame = *frame.asMaxDataFrame();
      QuicInteger intFrameType(static_cast<uint8_t>(FrameType::MAX_DATA));
      QuicInteger maximumData(maxDataFrame.maximumData);
      auto frameSize = intFrameType.getSize() + maximumData.getSize();
      if (packetSpaceCheck(spaceLeft, frameSize)) {
        builder.write(intFrameType);
        builder.write(maximumData);
        builder.appendFrame(std::move(maxDataFrame));
        return frameSize;
      }
      // no space left in packet
      return size_t(0);
    }
    case QuicWriteFrame::Type::MaxStreamDataFrame: {
      MaxStreamDataFrame& maxStreamDataFrame = *frame.asMaxStreamDataFrame();
      QuicInteger intFrameType(
          static_cast<uint8_t>(FrameType::MAX_STREAM_DATA));
      QuicInteger streamId(maxStreamDataFrame.streamId);
      QuicInteger maximumData(maxStreamDataFrame.maximumData);
      auto maxStreamDataFrameSize =
          intFrameType.getSize() + streamId.getSize() + maximumData.getSize();
      if (packetSpaceCheck(spaceLeft, maxStreamDataFrameSize)) {
        builder.write(intFrameType);
        builder.write(streamId);
        builder.write(maximumData);
        builder.appendFrame(std::move(maxStreamDataFrame));
        return maxStreamDataFrameSize;
      }
      // no space left in packet
      return size_t(0);
    }
    case QuicWriteFrame::Type::DataBlockedFrame: {
      DataBlockedFrame& blockedFrame = *frame.asDataBlockedFrame();
      QuicInteger intFrameType(static_cast<uint8_t>(FrameType::DATA_BLOCKED));
      QuicInteger dataLimit(blockedFrame.dataLimit);
      auto blockedFrameSize = intFrameType.getSize() + dataLimit.getSize();
      if (packetSpaceCheck(spaceLeft, blockedFrameSize)) {
        builder.write(intFrameType);
        builder.write(dataLimit);
        builder.appendFrame(std::move(blockedFrame));
        return blockedFrameSize;
      }
      // no space left in packet
      return size_t(0);
    }
    case QuicWriteFrame::Type::StreamDataBlockedFrame: {
      StreamDataBlockedFrame& streamBlockedFrame =
          *frame.asStreamDataBlockedFrame();
      QuicInteger intFrameType(
          static_cast<uint8_t>(FrameType::STREAM_DATA_BLOCKED));
      QuicInteger streamId(streamBlockedFrame.streamId);
      QuicInteger dataLimit(streamBlockedFrame.dataLimit);
      auto blockedFrameSize =
          intFrameType.getSize() + streamId.getSize() + dataLimit.getSize();
      if (packetSpaceCheck(spaceLeft, blockedFrameSize)) {
        builder.write(intFrameType);
        builder.write(streamId);
        builder.write(dataLimit);
        builder.appendFrame(std::move(streamBlockedFrame));
        return blockedFrameSize;
      }
      // no space left in packet
      return size_t(0);
    }
    case QuicWriteFrame::Type::StreamsBlockedFrame: {
      StreamsBlockedFrame& streamsBlockedFrame = *frame.asStreamsBlockedFrame();
      auto frameType = streamsBlockedFrame.isForBidirectionalStream()
          ? FrameType::STREAMS_BLOCKED_BIDI
          : FrameType::STREAMS_BLOCKED_UNI;
      QuicInteger intFrameType(static_cast<FrameTypeType>(frameType));
      QuicInteger streamId(streamsBlockedFrame.streamLimit);
      auto streamBlockedFrameSize = intFrameType.getSize() + streamId.getSize();
      if (packetSpaceCheck(spaceLeft, streamBlockedFrameSize)) {
        builder.write(intFrameType);
        builder.write(streamId);
        builder.appendFrame(std::move(streamsBlockedFrame));
        return streamBlockedFrameSize;
      }
      // no space left in packet
      return size_t(0);
    }
    case QuicWriteFrame::Type::ConnectionCloseFrame: {
      ConnectionCloseFrame& connectionCloseFrame =
          *frame.asConnectionCloseFrame();
      // Need to distinguish between CONNECTION_CLOSE & CONNECTINO_CLOSE_APP_ERR
      const TransportErrorCode* isTransportErrorCode =
          connectionCloseFrame.errorCode.asTransportErrorCode();
      const ApplicationErrorCode* isApplicationErrorCode =
          connectionCloseFrame.errorCode.asApplicationErrorCode();

      QuicInteger intFrameType(static_cast<uint8_t>(
          isTransportErrorCode ? FrameType::CONNECTION_CLOSE
                               : FrameType::CONNECTION_CLOSE_APP_ERR));

      QuicInteger reasonLength(connectionCloseFrame.reasonPhrase.size());
      Optional<QuicInteger> closingFrameType;
      if (isTransportErrorCode) {
        closingFrameType = QuicInteger(
            static_cast<FrameTypeType>(connectionCloseFrame.closingFrameType));
      }

      QuicInteger errorCode(
          isTransportErrorCode
              ? static_cast<uint64_t>(TransportErrorCode(*isTransportErrorCode))
              : static_cast<uint64_t>(
                    ApplicationErrorCode(*isApplicationErrorCode)));
      size_t errorSize = errorCode.getSize();
      auto connCloseFrameSize = intFrameType.getSize() + errorSize +
          (closingFrameType ? closingFrameType.value().getSize() : 0) +
          reasonLength.getSize() + connectionCloseFrame.reasonPhrase.size();
      if (packetSpaceCheck(spaceLeft, connCloseFrameSize)) {
        builder.write(intFrameType);
        builder.write(errorCode);
        if (closingFrameType) {
          builder.write(closingFrameType.value());
        }
        builder.write(reasonLength);
        builder.push(
            (const uint8_t*)connectionCloseFrame.reasonPhrase.data(),
            connectionCloseFrame.reasonPhrase.size());
        builder.appendFrame(std::move(connectionCloseFrame));
        return connCloseFrameSize;
      }
      // no space left in packet
      return size_t(0);
    }
    case QuicWriteFrame::Type::PingFrame: {
      const PingFrame& pingFrame = *frame.asPingFrame();
      QuicInteger intFrameType(static_cast<uint8_t>(FrameType::PING));
      if (packetSpaceCheck(spaceLeft, intFrameType.getSize())) {
        builder.write(intFrameType);
        builder.appendFrame(pingFrame);
        return intFrameType.getSize();
      }
      // no space left in packet
      return size_t(0);
    }
    case QuicWriteFrame::Type::QuicSimpleFrame: {
      return writeSimpleFrame(std::move(*frame.asQuicSimpleFrame()), builder);
    }
    case QuicWriteFrame::Type::DatagramFrame: {
      const DatagramFrame& datagramFrame = *frame.asDatagramFrame();
      QuicInteger frameTypeQuicInt(
          static_cast<uint8_t>(FrameType::DATAGRAM_LEN));
      QuicInteger datagramLenInt(datagramFrame.length);
      auto datagramFrameLength = frameTypeQuicInt.getSize() +
          datagramFrame.length + datagramLenInt.getSize();
      if (packetSpaceCheck(spaceLeft, datagramFrameLength)) {
        builder.write(frameTypeQuicInt);
        builder.write(datagramLenInt);
        builder.insert(std::move(datagramFrame.data), datagramFrame.length);
        builder.appendFrame(datagramFrame);
        return datagramFrameLength;
      }
      // no space left in packet
      return size_t(0);
    }
    case QuicWriteFrame::Type::ImmediateAckFrame: {
      const ImmediateAckFrame& immediateAckFrame = *frame.asImmediateAckFrame();
      QuicInteger intFrameType(static_cast<uint8_t>(FrameType::IMMEDIATE_ACK));
      if (packetSpaceCheck(spaceLeft, intFrameType.getSize())) {
        builder.write(intFrameType);
        builder.appendFrame(immediateAckFrame);
        return intFrameType.getSize();
      }
      // no space left in packet
      return size_t(0);
    }
    default: {
      LOG(FATAL) << "Unknown / unsupported frame type received";
    }
  }
}
} // namespace quic
