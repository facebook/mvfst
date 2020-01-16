/*
 * Copyright (c) Facebook, Inc. and its affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 *
 */

#include <quic/codec/QuicWriteCodec.h>

#include <algorithm>

#include <quic/QuicConstants.h>
#include <quic/QuicException.h>
#include <quic/codec/QuicInteger.h>

namespace {

bool packetSpaceCheck(uint64_t limit, size_t require);

/**
 * A helper function to check if there are enough space to write in the packet.
 * Return: true if there is enough space, false otherwise
 */
bool packetSpaceCheck(uint64_t limit, size_t require) {
  return (folly::to<uint64_t>(require) <= limit);
}
} // namespace

namespace quic {

folly::Optional<uint64_t> writeStreamFrameHeader(
    PacketBuilderInterface& builder,
    StreamId id,
    uint64_t offset,
    uint64_t writeBufferLen,
    uint64_t flowControlLen,
    bool fin) {
  if (builder.remainingSpaceInPkt() == 0) {
    return folly::none;
  }
  if (writeBufferLen == 0 && !fin) {
    throw QuicInternalException(
        "No data or fin supplied when writing stream.",
        LocalErrorCode::INTERNAL_ERROR);
  }
  StreamTypeField::Builder streamTypeBuilder;
  QuicInteger idInt(id);
  QuicInteger offsetInt(offset);
  // First account for the things that are non-optional: frame type and stream
  // id.
  uint64_t headerSize = sizeof(FrameType::STREAM) + idInt.getSize();
  if (offset != 0) {
    streamTypeBuilder.setOffset();
    headerSize += offsetInt.getSize();
  }
  if (builder.remainingSpaceInPkt() < headerSize) {
    VLOG(4) << "No space in packet for stream header. stream=" << id
            << " remaining=" << builder.remainingSpaceInPkt();
    return folly::none;
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
  if (dataLen > 0 && dataLen >= builder.remainingSpaceInPkt() - headerSize) {
    // We can fill this entire packet with the rest of this stream frame.
    dataLen = builder.remainingSpaceInPkt() - headerSize;
  } else {
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
      throw QuicInternalException(
          "Stream frame length too large.", LocalErrorCode::INTERNAL_ERROR);
    }
  }
  if (dataLenLen > 0) {
    if (dataLen != 0 &&
        headerSize + dataLenLen >= builder.remainingSpaceInPkt()) {
      VLOG(4) << "No space in packet for stream header. stream=" << id
              << " remaining=" << builder.remainingSpaceInPkt();
      return folly::none;
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
    return folly::none;
  }
  if (builder.remainingSpaceInPkt() < headerSize) {
    VLOG(4) << "No space in packet for stream header. stream=" << id
            << " remaining=" << builder.remainingSpaceInPkt();
    return folly::none;
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
  if (offset != 0) {
    builder.write(offsetInt);
  }
  if (dataLenLen > 0) {
    builder.write(QuicInteger(dataLen));
  }
  builder.appendFrame(
      WriteStreamFrame(id, offset, dataLen, streamType.hasFin()));
  DCHECK(dataLen <= builder.remainingSpaceInPkt());
  return folly::make_optional(dataLen);
}

void writeStreamFrameData(
    PacketBuilderInterface& builder,
    const BufQueue& writeBuffer,
    uint64_t dataLen) {
  if (dataLen > 0) {
    Buf streamData;
    folly::io::Cursor cursor(writeBuffer.front());
    cursor.clone(streamData, dataLen);
    builder.insert(std::move(streamData));
  }
}

void writeStreamFrameData(
    PacketBuilderInterface& builder,
    Buf writeBuffer,
    uint64_t dataLen) {
  if (dataLen > 0) {
    Buf streamData;
    folly::io::Cursor cursor(writeBuffer.get());
    cursor.clone(streamData, dataLen);
    builder.insert(std::move(streamData));
  }
}

folly::Optional<WriteCryptoFrame>
writeCryptoFrame(uint64_t offsetIn, Buf data, PacketBuilderInterface& builder) {
  uint64_t spaceLeftInPkt = builder.remainingSpaceInPkt();
  QuicInteger intFrameType(static_cast<uint8_t>(FrameType::CRYPTO_FRAME));
  QuicInteger offsetInteger(offsetIn);

  size_t lengthBytes = 2;
  size_t cryptoFrameHeaderSize =
      intFrameType.getSize() + offsetInteger.getSize() + lengthBytes;

  if (spaceLeftInPkt <= cryptoFrameHeaderSize) {
    VLOG(3) << "No space left in packet to write cryptoFrame header of size: "
            << cryptoFrameHeaderSize << ", space left=" << spaceLeftInPkt;
    return folly::none;
  }
  size_t spaceRemaining = spaceLeftInPkt - cryptoFrameHeaderSize;
  size_t dataLength = data->computeChainDataLength();
  size_t writeableData = std::min(dataLength, spaceRemaining);
  QuicInteger lengthVarInt(writeableData);

  if (lengthVarInt.getSize() > lengthBytes) {
    throw QuicInternalException(
        std::string("Length bytes representation"),
        LocalErrorCode::CODEC_ERROR);
  }
  data->coalesce();
  data->trimEnd(dataLength - writeableData);

  builder.write(intFrameType);
  builder.write(offsetInteger);
  builder.write(lengthVarInt);
  builder.insert(std::move(data));
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

folly::Optional<AckFrameWriteResult> writeAckFrame(
    const quic::AckFrameMetaData& ackFrameMetaData,
    PacketBuilderInterface& builder) {
  if (ackFrameMetaData.ackBlocks.empty()) {
    return folly::none;
  }
  // The last block must be the largest block.
  auto largestAckedPacket = ackFrameMetaData.ackBlocks.back().end;
  // ackBlocks are already an interval set so each value is naturally
  // non-overlapping.
  auto firstAckBlockLength =
      largestAckedPacket - ackFrameMetaData.ackBlocks.back().start;

  WriteAckFrame ackFrame;
  uint64_t spaceLeft = builder.remainingSpaceInPkt();
  uint64_t beginningSpace = spaceLeft;
  // Reserve enough space a full packet of ACKs with 2 byte varints.
  // TODO is this a good heuristic?
  ackFrame.ackBlocks.reserve(spaceLeft / 4);

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
  QuicInteger encodedintFrameType(static_cast<uint8_t>(FrameType::ACK));
  auto headerSize = encodedintFrameType.getSize() +
      largestAckedPacketInt.getSize() + ackDelayInt.getSize() +
      minAdditionalAckBlockCount.getSize() + firstAckBlockLengthInt.getSize();
  if (spaceLeft < headerSize) {
    return folly::none;
  }
  spaceLeft -= headerSize;

  ackFrame.ackBlocks.push_back(ackFrameMetaData.ackBlocks.back());
  auto numAdditionalAckBlocks =
      fillFrameWithAckBlocks(ackFrameMetaData.ackBlocks, ackFrame, spaceLeft);

  QuicInteger numAdditionalAckBlocksInt(numAdditionalAckBlocks);
  builder.write(encodedintFrameType);
  builder.write(largestAckedPacketInt);
  builder.write(ackDelayInt);
  builder.write(numAdditionalAckBlocksInt);
  builder.write(firstAckBlockLengthInt);

  PacketNum currentSeqNum = ackFrameMetaData.ackBlocks.back().start;
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
  builder.appendFrame(std::move(ackFrame));
  return AckFrameWriteResult(
      beginningSpace - builder.remainingSpaceInPkt(),
      1 + numAdditionalAckBlocks);
}

size_t writeSimpleFrame(
    QuicSimpleFrame&& frame,
    PacketBuilderInterface& builder) {
  using FrameTypeType = std::underlying_type<FrameType>::type;

  uint64_t spaceLeft = builder.remainingSpaceInPkt();

  switch (frame.type()) {
    case QuicSimpleFrame::Type::PingFrame_E: {
      const PingFrame& pingFrame = *frame.asPingFrame();
      QuicInteger intFrameType(static_cast<uint8_t>(FrameType::PING));
      if (packetSpaceCheck(spaceLeft, intFrameType.getSize())) {
        builder.write(intFrameType);
        builder.appendFrame(QuicSimpleFrame(pingFrame));
        return intFrameType.getSize();
      }
      // no space left in packet
      return size_t(0);
    }
    case QuicSimpleFrame::Type::StopSendingFrame_E: {
      const StopSendingFrame& stopSendingFrame = *frame.asStopSendingFrame();
      QuicInteger intFrameType(static_cast<uint8_t>(FrameType::STOP_SENDING));
      QuicInteger streamId(stopSendingFrame.streamId);
      QuicInteger errorCode(static_cast<uint64_t>(stopSendingFrame.errorCode));
      auto version = builder.getVersion();
      size_t errorSize = version == QuicVersion::MVFST_OLD
          ? sizeof(ApplicationErrorCode)
          : errorCode.getSize();
      auto stopSendingFrameSize =
          intFrameType.getSize() + streamId.getSize() + errorSize;
      if (packetSpaceCheck(spaceLeft, stopSendingFrameSize)) {
        builder.write(intFrameType);
        builder.write(streamId);
        if (version == QuicVersion::MVFST_OLD) {
          builder.writeBE(
              static_cast<ApplicationErrorCode>(stopSendingFrame.errorCode));
        } else {
          builder.write(errorCode);
        }
        builder.appendFrame(QuicSimpleFrame(std::move(stopSendingFrame)));
        return stopSendingFrameSize;
      }
      // no space left in packet
      return size_t(0);
    }
    case QuicSimpleFrame::Type::MinStreamDataFrame_E: {
      const MinStreamDataFrame& minStreamDataFrame =
          *frame.asMinStreamDataFrame();
      QuicInteger streamId(minStreamDataFrame.streamId);
      QuicInteger maximumData(minStreamDataFrame.maximumData);
      QuicInteger minimumStreamOffset(minStreamDataFrame.minimumStreamOffset);
      QuicInteger frameType(
          static_cast<FrameTypeType>(FrameType::MIN_STREAM_DATA));
      auto minStreamDataFrameSize = frameType.getSize() + streamId.getSize() +
          maximumData.getSize() + minimumStreamOffset.getSize();
      if (packetSpaceCheck(spaceLeft, minStreamDataFrameSize)) {
        builder.write(frameType);
        builder.write(streamId);
        builder.write(maximumData);
        builder.write(minimumStreamOffset);
        builder.appendFrame(QuicSimpleFrame(std::move(minStreamDataFrame)));
        return minStreamDataFrameSize;
      }
      // no space left in packet
      return size_t(0);
    }
    case QuicSimpleFrame::Type::ExpiredStreamDataFrame_E: {
      const ExpiredStreamDataFrame& expiredStreamDataFrame =
          *frame.asExpiredStreamDataFrame();
      QuicInteger frameType(
          static_cast<FrameTypeType>(FrameType::EXPIRED_STREAM_DATA));
      QuicInteger streamId(expiredStreamDataFrame.streamId);
      QuicInteger minimumStreamOffset(
          expiredStreamDataFrame.minimumStreamOffset);
      auto expiredStreamDataFrameSize = frameType.getSize() +
          streamId.getSize() + minimumStreamOffset.getSize();
      if (packetSpaceCheck(spaceLeft, expiredStreamDataFrameSize)) {
        builder.write(frameType);
        builder.write(streamId);
        builder.write(minimumStreamOffset);
        builder.appendFrame(QuicSimpleFrame(std::move(expiredStreamDataFrame)));
        return expiredStreamDataFrameSize;
      }
      // no space left in packet
      return size_t(0);
    }
    case QuicSimpleFrame::Type::PathChallengeFrame_E: {
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
    case QuicSimpleFrame::Type::PathResponseFrame_E: {
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
    case QuicSimpleFrame::Type::NewConnectionIdFrame_E: {
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
    case QuicSimpleFrame::Type::MaxStreamsFrame_E: {
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
    case QuicSimpleFrame::Type::RetireConnectionIdFrame_E: {
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
  }
  folly::assume_unreachable();
}

size_t writeFrame(QuicWriteFrame&& frame, PacketBuilderInterface& builder) {
  using FrameTypeType = std::underlying_type<FrameType>::type;

  uint64_t spaceLeft = builder.remainingSpaceInPkt();

  switch (frame.type()) {
    case QuicWriteFrame::Type::PaddingFrame_E: {
      PaddingFrame& paddingFrame = *frame.asPaddingFrame();
      QuicInteger intFrameType(static_cast<uint8_t>(FrameType::PADDING));
      if (packetSpaceCheck(spaceLeft, intFrameType.getSize())) {
        builder.write(intFrameType);
        builder.appendFrame(std::move(paddingFrame));
        return intFrameType.getSize();
      }
      return size_t(0);
    }
    case QuicWriteFrame::Type::RstStreamFrame_E: {
      RstStreamFrame& rstStreamFrame = *frame.asRstStreamFrame();
      QuicInteger intFrameType(static_cast<uint8_t>(FrameType::RST_STREAM));
      QuicInteger streamId(rstStreamFrame.streamId);
      QuicInteger offset(rstStreamFrame.offset);
      QuicInteger errorCode(static_cast<uint64_t>(rstStreamFrame.errorCode));
      auto version = builder.getVersion();
      size_t errorSize = version == QuicVersion::MVFST_OLD
          ? sizeof(ApplicationErrorCode)
          : errorCode.getSize();
      auto rstStreamFrameSize = intFrameType.getSize() + errorSize +
          streamId.getSize() + offset.getSize();
      if (packetSpaceCheck(spaceLeft, rstStreamFrameSize)) {
        builder.write(intFrameType);
        builder.write(streamId);
        if (version == QuicVersion::MVFST_OLD) {
          builder.writeBE(
              static_cast<ApplicationErrorCode>(rstStreamFrame.errorCode));
        } else {
          builder.write(errorCode);
        }
        builder.write(offset);
        builder.appendFrame(std::move(rstStreamFrame));
        return rstStreamFrameSize;
      }
      // no space left in packet
      return size_t(0);
    }
    case QuicWriteFrame::Type::MaxDataFrame_E: {
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
    case QuicWriteFrame::Type::MaxStreamDataFrame_E: {
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
    case QuicWriteFrame::Type::DataBlockedFrame_E: {
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
    case QuicWriteFrame::Type::StreamDataBlockedFrame_E: {
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
    case QuicWriteFrame::Type::StreamsBlockedFrame_E: {
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
    case QuicWriteFrame::Type::ConnectionCloseFrame_E: {
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
      folly::Optional<QuicInteger> closingFrameType;
      if (isTransportErrorCode) {
        closingFrameType = QuicInteger(
            static_cast<FrameTypeType>(connectionCloseFrame.closingFrameType));
      }

      QuicInteger errorCode(
          isTransportErrorCode
              ? static_cast<uint64_t>(TransportErrorCode(*isTransportErrorCode))
              : static_cast<uint64_t>(
                    ApplicationErrorCode(*isApplicationErrorCode)));
      auto version = builder.getVersion();
      size_t errorSize = version == QuicVersion::MVFST_OLD
          ? sizeof(TransportErrorCode)
          : errorCode.getSize();
      auto connCloseFrameSize = intFrameType.getSize() + errorSize +
          (closingFrameType ? closingFrameType.value().getSize() : 0) +
          reasonLength.getSize() + connectionCloseFrame.reasonPhrase.size();
      if (packetSpaceCheck(spaceLeft, connCloseFrameSize)) {
        builder.write(intFrameType);
        if (version == QuicVersion::MVFST_OLD) {
          builder.writeBE(
              isTransportErrorCode ? static_cast<uint16_t>(TransportErrorCode(
                                         *isTransportErrorCode))
                                   : static_cast<uint16_t>(ApplicationErrorCode(
                                         *isApplicationErrorCode)));
        } else {
          builder.write(errorCode);
        }
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
    case QuicWriteFrame::Type::QuicSimpleFrame_E: {
      return writeSimpleFrame(std::move(*frame.asQuicSimpleFrame()), builder);
    }
    default: {
      // TODO add support for: RETIRE_CONNECTION_ID and NEW_TOKEN frames
      auto errorStr = folly::to<std::string>(
          "Unknown / unsupported frame type received at ", __func__);
      VLOG(2) << errorStr;
      throw QuicTransportException(
          errorStr, TransportErrorCode::FRAME_ENCODING_ERROR);
    }
  }
}
} // namespace quic
