/*
 * Copyright (c) Facebook, Inc. and its affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 *
 */

#include <quic/codec/QuicWriteCodec.h>

#include <algorithm>
#include <limits>

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

folly::Optional<StreamFrameWriteResult> writeStreamFrame(
    const StreamFrameMetaData& streamFrameMetaData,
    PacketBuilderInterface& builder) {
  if (!builder.remainingSpaceInPkt()) {
    return folly::none;
  }
  if ((!streamFrameMetaData.data ||
       streamFrameMetaData.data->computeChainDataLength() == 0) &&
      !streamFrameMetaData.fin) {
    VLOG(2) << "No data or FIN supplied while writing stream "
            << streamFrameMetaData.id;
    throw QuicInternalException(
        "No data or FIN supplied", LocalErrorCode::INVALID_WRITE_DATA);
  }

  StreamTypeField::Builder initialByte;
  QuicInteger streamId(streamFrameMetaData.id);
  QuicInteger offset(streamFrameMetaData.offset);

  size_t headerSize = sizeof(FrameType::STREAM) + streamId.getSize();
  if (LIKELY(streamFrameMetaData.hasMoreFrames)) {
    initialByte.setLength();
    // We use the size remaining for simplicity here. 2 bytes should be enough
    // for almost anything. We could save 1 byte by deciding whether or not we
    // have < 100 bytes to write, however that seems a bit overkill.
    auto size = getQuicIntegerSize(builder.remainingSpaceInPkt());
    if (size.hasError()) {
      throw QuicTransportException(
          folly::to<std::string>(
              "Stream Frame: Value too large ", builder.remainingSpaceInPkt()),
          size.error());
    }
    headerSize += *size;
  }
  if (streamFrameMetaData.offset != 0) {
    initialByte.setOffset();
    headerSize += offset.getSize();
  }
  uint64_t spaceLeftInPkt = builder.remainingSpaceInPkt();
  if (spaceLeftInPkt < headerSize) {
    // We don't have enough space, this can happen often so exception is too
    // expensive for this. Just return empty result.
    VLOG(4) << "No space in packet for stream header. stream="
            << streamFrameMetaData.id
            << " remaining=" << builder.remainingSpaceInPkt();
    return folly::none;
  }
  spaceLeftInPkt -= headerSize;
  uint64_t dataInStream = 0;
  if (streamFrameMetaData.data) {
    dataInStream = streamFrameMetaData.data->computeChainDataLength();
  }
  auto dataCanWrite = std::min<uint64_t>(spaceLeftInPkt, dataInStream);
  bool canWrite = (dataInStream > 0 && dataCanWrite > 0) ||
      (dataInStream == 0 && streamFrameMetaData.fin);
  if (!canWrite) {
    VLOG(4) << "No space in packet for stream=" << streamFrameMetaData.id
            << " dataInStream=" << dataInStream
            << " fin=" << streamFrameMetaData.fin
            << " remaining=" << spaceLeftInPkt;
    return folly::none;
  }

  QuicInteger actualLength(dataCanWrite);
  bool writtenFin = false;
  if (streamFrameMetaData.fin && dataCanWrite == dataInStream) {
    // We can only write a FIN if we ended up writing all the bytes
    // in the input data.
    initialByte.setFin();
    writtenFin = true;
  }
  builder.writeBE(initialByte.build().fieldValue());
  builder.write(streamId);
  if (streamFrameMetaData.offset != 0) {
    builder.write(offset);
  }
  if (LIKELY(streamFrameMetaData.hasMoreFrames)) {
    builder.write(actualLength);
  }
  Buf bufToWrite;
  if (dataCanWrite > 0) {
    folly::io::Cursor cursor(streamFrameMetaData.data.get());
    cursor.clone(bufToWrite, dataCanWrite);
  } else {
    bufToWrite = folly::IOBuf::create(0);
  }
  VLOG(4) << "writing frame stream=" << streamFrameMetaData.id
          << " offset=" << streamFrameMetaData.offset
          << " data=" << dataCanWrite << " fin=" << writtenFin;
  builder.insert(bufToWrite->clone());
  builder.appendFrame(WriteStreamFrame(
      streamFrameMetaData.id,
      streamFrameMetaData.offset,
      dataCanWrite,
      writtenFin));
  StreamFrameWriteResult result(
      dataCanWrite, writtenFin, std::move(bufToWrite));
  return folly::make_optional(std::move(result));
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

size_t fillFrameWithAckBlocks(
    const IntervalSet<PacketNum>& ackBlocks,
    WriteAckFrame& ackFrame,
    uint64_t bytesLimit);

size_t fillFrameWithAckBlocks(
    const IntervalSet<PacketNum>& ackBlocks,
    WriteAckFrame& ackFrame,
    uint64_t bytesLimit) {
  PacketNum currentSeqNum = ackBlocks.crbegin()->start;

  // starts off with 0 which is what we assumed the initial ack block to be for
  // the largest acked.
  size_t numAdditionalAckBlocks = 0;
  QuicInteger previousNumAckBlockInt(numAdditionalAckBlocks);

  for (auto blockItr = ackBlocks.crbegin() + 1; blockItr != ackBlocks.crend();
       ++blockItr) {
    const auto& currBlock = *blockItr;
    // These must be true because of the properties of the interval set.
    CHECK_GE(currentSeqNum, currBlock.end + 2);
    PacketNum gap = currentSeqNum - currBlock.end - 2;
    PacketNum currBlockLen = currBlock.end - currBlock.start;

    QuicInteger gapInt(gap);
    QuicInteger currentBlockLenInt(currBlockLen);
    QuicInteger numAckBlocksInt(numAdditionalAckBlocks + 1);
    size_t additionalSize = gapInt.getSize() + currentBlockLenInt.getSize() +
        (numAckBlocksInt.getSize() - previousNumAckBlockInt.getSize());
    if (bytesLimit < additionalSize) {
      break;
    }
    numAdditionalAckBlocks++;
    bytesLimit -= additionalSize;
    previousNumAckBlockInt = numAckBlocksInt;
    currentSeqNum = currBlock.start;
    ackFrame.ackBlocks.insert(currBlock.start, currBlock.end);
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

  auto numAdditionalAckBlocks =
      fillFrameWithAckBlocks(ackFrameMetaData.ackBlocks, ackFrame, spaceLeft);

  QuicInteger numAdditionalAckBlocksInt(numAdditionalAckBlocks);
  builder.write(encodedintFrameType);
  builder.write(largestAckedPacketInt);
  builder.write(ackDelayInt);
  builder.write(numAdditionalAckBlocksInt);
  builder.write(firstAckBlockLengthInt);

  PacketNum currentSeqNum = ackFrameMetaData.ackBlocks.back().start;
  for (auto it = ackFrame.ackBlocks.crbegin(); it != ackFrame.ackBlocks.crend();
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
  // also the largest ack block since we already accounted for the space to
  // write to it.
  ackFrame.ackBlocks.insert(
      ackFrameMetaData.ackBlocks.back().start,
      ackFrameMetaData.ackBlocks.back().end);
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

  return folly::variant_match(
      frame,
      [&](StopSendingFrame& stopSendingFrame) {
        QuicInteger intFrameType(static_cast<uint8_t>(FrameType::STOP_SENDING));
        QuicInteger streamId(stopSendingFrame.streamId);
        auto stopSendingFrameSize = intFrameType.getSize() +
            streamId.getSize() + sizeof(ApplicationErrorCode);
        if (packetSpaceCheck(spaceLeft, stopSendingFrameSize)) {
          builder.write(intFrameType);
          builder.write(streamId);
          builder.writeBE(
              static_cast<ApplicationErrorCode>(stopSendingFrame.errorCode));
          builder.appendFrame(std::move(stopSendingFrame));
          return stopSendingFrameSize;
        }
        // no space left in packet
        return size_t(0);
      },
      [&](MinStreamDataFrame& minStreamDataFrame) {
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
          builder.appendFrame(std::move(minStreamDataFrame));
          return minStreamDataFrameSize;
        }
        // no space left in packet
        return size_t(0);
      },
      [&](ExpiredStreamDataFrame& expiredStreamDataFrame) {
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
          builder.appendFrame(std::move(expiredStreamDataFrame));
          return expiredStreamDataFrameSize;
        }
        // no space left in packet
        return size_t(0);
      },
      [&](PathChallengeFrame& pathChallengeFrame) {
        QuicInteger frameType(static_cast<uint8_t>(FrameType::PATH_CHALLENGE));
        auto pathChallengeFrameSize =
            frameType.getSize() + sizeof(pathChallengeFrame.pathData);
        if (packetSpaceCheck(spaceLeft, pathChallengeFrameSize)) {
          builder.write(frameType);
          builder.writeBE(pathChallengeFrame.pathData);
          builder.appendFrame(std::move(pathChallengeFrame));
          return pathChallengeFrameSize;
        }
        // no space left in packet
        return size_t(0);
      },
      [&](PathResponseFrame& pathResponseFrame) {
        QuicInteger frameType(static_cast<uint8_t>(FrameType::PATH_RESPONSE));
        auto pathResponseFrameSize =
            frameType.getSize() + sizeof(pathResponseFrame.pathData);
        if (packetSpaceCheck(spaceLeft, pathResponseFrameSize)) {
          builder.write(frameType);
          builder.writeBE(pathResponseFrame.pathData);
          builder.appendFrame(std::move(pathResponseFrame));
          return pathResponseFrameSize;
        }
        // no space left in packet
        return size_t(0);
      },
      [&](NewConnectionIdFrame& newConnectionIdFrame) {
        QuicInteger frameType(
            static_cast<uint8_t>(FrameType::NEW_CONNECTION_ID));
        QuicInteger sequence(newConnectionIdFrame.sequence);
        // Include an 8-bit unsigned integer containing the length of the connId
        auto newConnectionIdFrameSize = frameType.getSize() + sizeof(uint8_t) +
            sequence.getSize() + newConnectionIdFrame.connectionId.size() +
            newConnectionIdFrame.token.size();
        if (packetSpaceCheck(spaceLeft, newConnectionIdFrameSize)) {
          builder.write(frameType);
          builder.write(sequence);
          builder.writeBE(newConnectionIdFrame.connectionId.size());
          builder.push(
              newConnectionIdFrame.connectionId.data(),
              newConnectionIdFrame.connectionId.size());
          builder.push(
              newConnectionIdFrame.token.data(),
              newConnectionIdFrame.token.size());
          builder.appendFrame(std::move(newConnectionIdFrame));
          return newConnectionIdFrameSize;
        }
        // no space left in packet
        return size_t(0);
      });
}

size_t writeFrame(QuicWriteFrame&& frame, PacketBuilderInterface& builder) {
  using FrameTypeType = std::underlying_type<FrameType>::type;

  uint64_t spaceLeft = builder.remainingSpaceInPkt();

  return folly::variant_match(
      frame,
      [&](PaddingFrame& paddingFrame) {
        QuicInteger intFrameType(static_cast<uint8_t>(FrameType::PADDING));
        if (packetSpaceCheck(spaceLeft, intFrameType.getSize())) {
          builder.write(intFrameType);
          builder.appendFrame(std::move(paddingFrame));
          return intFrameType.getSize();
        }
        return size_t(0);
      },
      [&](PingFrame& pingFrame) {
        QuicInteger intFrameType(static_cast<uint8_t>(FrameType::PING));
        if (packetSpaceCheck(spaceLeft, intFrameType.getSize())) {
          builder.write(intFrameType);
          builder.appendFrame(std::move(pingFrame));
          return intFrameType.getSize();
        }
        // no space left in packet
        return size_t(0);
      },
      [&](RstStreamFrame& rstStreamFrame) {
        QuicInteger intFrameType(static_cast<uint8_t>(FrameType::RST_STREAM));
        QuicInteger streamId(rstStreamFrame.streamId);
        QuicInteger offset(rstStreamFrame.offset);
        auto rstStreamFrameSize = intFrameType.getSize() +
            sizeof(ApplicationErrorCode) + streamId.getSize() +
            offset.getSize();
        if (packetSpaceCheck(spaceLeft, rstStreamFrameSize)) {
          builder.write(intFrameType);
          builder.write(streamId);
          builder.writeBE(
              static_cast<ApplicationErrorCode>(rstStreamFrame.errorCode));
          builder.write(offset);
          builder.appendFrame(std::move(rstStreamFrame));
          return rstStreamFrameSize;
        }
        // no space left in packet
        return size_t(0);
      },
      [&](MaxDataFrame& maxDataFrame) {
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
      },
      [&](MaxStreamDataFrame& maxStreamDataFrame) {
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
      },
      [&](MaxStreamsFrame& maxStreamsFrame) {
        auto frameType = maxStreamsFrame.isForBidirectionalStream()
            ? FrameType::MAX_STREAMS_BIDI
            : FrameType::MAX_STREAMS_UNI;
        QuicInteger intFrameType(static_cast<FrameTypeType>(frameType));
        QuicInteger streamCount(maxStreamsFrame.maxStreams);
        auto maxStreamsFrameSize =
            intFrameType.getSize() + streamCount.getSize();
        if (packetSpaceCheck(spaceLeft, maxStreamsFrameSize)) {
          builder.write(intFrameType);
          builder.write(streamCount);
          builder.appendFrame(std::move(maxStreamsFrame));
          return maxStreamsFrameSize;
        }
        // no space left in packet
        return size_t(0);
      },
      [&](DataBlockedFrame& blockedFrame) {
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
      },
      [&](StreamDataBlockedFrame& streamBlockedFrame) {
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
      },
      [&](StreamsBlockedFrame& streamsBlockedFrame) {
        auto frameType = streamsBlockedFrame.isForBidirectionalStream()
            ? FrameType::STREAMS_BLOCKED_BIDI
            : FrameType::STREAMS_BLOCKED_UNI;
        QuicInteger intFrameType(static_cast<FrameTypeType>(frameType));
        QuicInteger streamId(streamsBlockedFrame.streamLimit);
        auto streamBlockedFrameSize =
            intFrameType.getSize() + streamId.getSize();
        if (packetSpaceCheck(spaceLeft, streamBlockedFrameSize)) {
          builder.write(intFrameType);
          builder.write(streamId);
          builder.appendFrame(std::move(streamsBlockedFrame));
          return streamBlockedFrameSize;
        }
        // no space left in packet
        return size_t(0);
      },
      [&](ConnectionCloseFrame& connectionCloseFrame) {
        QuicInteger intFrameType(
            static_cast<uint8_t>(FrameType::CONNECTION_CLOSE));
        QuicInteger reasonLength(connectionCloseFrame.reasonPhrase.size());
        auto connCloseFrameSize = intFrameType.getSize() +
            sizeof(TransportErrorCode) +
            sizeof(connectionCloseFrame.closingFrameType) +
            reasonLength.getSize() + connectionCloseFrame.reasonPhrase.size();
        if (packetSpaceCheck(spaceLeft, connCloseFrameSize)) {
          builder.write(intFrameType);
          builder.writeBE(
              static_cast<std::underlying_type<TransportErrorCode>::type>(
                  connectionCloseFrame.errorCode));
          QuicInteger closingFrameType(static_cast<FrameTypeType>(
              connectionCloseFrame.closingFrameType));
          builder.write(closingFrameType);
          builder.write(reasonLength);
          builder.push(
              (const uint8_t*)connectionCloseFrame.reasonPhrase.data(),
              connectionCloseFrame.reasonPhrase.size());
          builder.appendFrame(std::move(connectionCloseFrame));
          return connCloseFrameSize;
        }
        // no space left in packet
        return size_t(0);
      },
      [&](ApplicationCloseFrame& applicationCloseFrame) {
        QuicInteger intFrameType(
            static_cast<uint8_t>(FrameType::APPLICATION_CLOSE));
        QuicInteger reasonLength(applicationCloseFrame.reasonPhrase.size());
        auto applicationCloseFrameSize = intFrameType.getSize() +
            sizeof(ApplicationErrorCode) + reasonLength.getSize() +
            applicationCloseFrame.reasonPhrase.size();
        if (packetSpaceCheck(spaceLeft, applicationCloseFrameSize)) {
          builder.write(intFrameType);
          builder.writeBE(static_cast<ApplicationErrorCode>(
              applicationCloseFrame.errorCode));
          builder.write(reasonLength);
          builder.push(
              (const uint8_t*)applicationCloseFrame.reasonPhrase.data(),
              applicationCloseFrame.reasonPhrase.size());
          builder.appendFrame(std::move(applicationCloseFrame));
          return applicationCloseFrameSize;
        }
        // no space left in packet
        return size_t(0);
      },
      [&](QuicSimpleFrame& simpleFrame) {
        return writeSimpleFrame(std::move(simpleFrame), builder);
      },
      [&](auto&) -> size_t {
        // TODO add support for: RETIRE_CONNECTION_ID and NEW_TOKEN frames
        auto errorStr = folly::to<std::string>(
            "Unknown / unsupported frame type received at ", __func__);
        VLOG(2) << errorStr;
        throw QuicTransportException(
            errorStr, TransportErrorCode::FRAME_ENCODING_ERROR);
      });
}
} // namespace quic
