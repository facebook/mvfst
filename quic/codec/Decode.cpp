/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <quic/codec/Decode.h>
#include <quic/codec/QuicInteger.h>
#include <quic/common/MvfstLogging.h>

#include <quic/QuicConstants.h>
#include <quic/QuicException.h>
#include <quic/codec/PacketNumber.h>
#include <chrono>
#include <cstdint>

namespace {

quic::Expected<quic::PacketNum, quic::QuicError> nextAckedPacketGap(
    quic::PacketNum packetNum,
    uint64_t gap) noexcept {
  // Gap cannot overflow because of the definition of quic integer encoding, so
  // we can just add to gap.
  uint64_t adjustedGap = gap + 2;
  if (packetNum < adjustedGap) {
    return quic::make_unexpected(
        quic::QuicError(
            quic::TransportErrorCode::FRAME_ENCODING_ERROR, "Bad gap"));
  }
  return packetNum - adjustedGap;
}

quic::Expected<quic::PacketNum, quic::QuicError> nextAckedPacketLen(
    quic::PacketNum packetNum,
    uint64_t ackBlockLen) noexcept {
  // Going to allow 0 as a valid value.
  if (packetNum < ackBlockLen) {
    return quic::make_unexpected(
        quic::QuicError(
            quic::TransportErrorCode::FRAME_ENCODING_ERROR, "Bad block len"));
  }
  return packetNum - ackBlockLen;
}

} // namespace

namespace quic {

quic::Expected<PaddingFrame, QuicError> decodePaddingFrame(
    ContiguousReadCursor& cursor) {
  // we might have multiple padding frames in sequence in the common case.
  // Let's consume all the padding and return 1 padding frame for everything.
  static_assert(
      static_cast<int>(FrameType::PADDING) == 0, "Padding value is 0");
  ByteRange paddingBytes = cursor.peekBytes();
  if (paddingBytes.size() == 0) {
    return PaddingFrame();
  }
  uint8_t firstByte = paddingBytes.data()[0];
  // While type can be variable length, since PADDING frame is always a 0
  // byte frame, the length of the type should be 1 byte.
  if (static_cast<FrameType>(firstByte) != FrameType::PADDING) {
    return PaddingFrame();
  }
  int ret = memcmp(
      paddingBytes.data(), paddingBytes.data() + 1, paddingBytes.size() - 1);
  if (ret == 0) {
    cursor.skip(paddingBytes.size());
  }
  return PaddingFrame();
}

quic::Expected<PingFrame, QuicError> decodePingFrame(ContiguousReadCursor&) {
  return PingFrame();
}

quic::Expected<QuicFrame, QuicError> decodeKnobFrame(
    ContiguousReadCursor& cursor) {
  auto knobSpace = quic::decodeQuicInteger(cursor);
  if (!knobSpace) {
    return quic::make_unexpected(QuicError(
        quic::TransportErrorCode::FRAME_ENCODING_ERROR, "Bad knob space"));
  }
  auto knobId = quic::decodeQuicInteger(cursor);
  if (!knobId) {
    return quic::make_unexpected(QuicError(
        quic::TransportErrorCode::FRAME_ENCODING_ERROR, "Bad knob id"));
  }
  auto knobLen = quic::decodeQuicInteger(cursor);
  if (!knobLen) {
    return quic::make_unexpected(QuicError(
        quic::TransportErrorCode::FRAME_ENCODING_ERROR, "Bad knob len"));
  }
  BufPtr knobBlob = BufHelpers::create(
      std::min(knobLen->first, (uint64_t)cursor.remaining()));
  size_t amountRead =
      cursor.pullAtMost(knobBlob->writableData(), knobLen->first);
  knobBlob->append(amountRead);
  return QuicFrame(
      KnobFrame(knobSpace->first, knobId->first, std::move(knobBlob)));
}

quic::Expected<QuicSimpleFrame, QuicError> decodeAckFrequencyFrame(
    ContiguousReadCursor& cursor) {
  auto sequenceNumber = quic::decodeQuicInteger(cursor);
  if (!sequenceNumber) {
    return quic::make_unexpected(QuicError(
        quic::TransportErrorCode::FRAME_ENCODING_ERROR, "Bad sequence number"));
  }
  auto packetTolerance = quic::decodeQuicInteger(cursor);
  if (!packetTolerance) {
    return quic::make_unexpected(QuicError(
        quic::TransportErrorCode::FRAME_ENCODING_ERROR,
        "Bad packet tolerance"));
  }
  auto updateMaxAckDelay = quic::decodeQuicInteger(cursor);
  if (!updateMaxAckDelay) {
    return quic::make_unexpected(QuicError(
        quic::TransportErrorCode::FRAME_ENCODING_ERROR,
        "Bad update max ack delay"));
  }
  auto reorderThreshold = quic::decodeQuicInteger(cursor);
  if (!reorderThreshold) {
    return quic::make_unexpected(QuicError(
        quic::TransportErrorCode::FRAME_ENCODING_ERROR,
        "Bad reorder threshold"));
  }

  AckFrequencyFrame frame;
  frame.sequenceNumber = sequenceNumber->first;
  frame.packetTolerance = packetTolerance->first;
  frame.updateMaxAckDelay = updateMaxAckDelay->first;
  frame.reorderThreshold = reorderThreshold->first;
  return QuicSimpleFrame(frame);
}

quic::Expected<ImmediateAckFrame, QuicError> decodeImmediateAckFrame(
    ContiguousReadCursor&) {
  return ImmediateAckFrame();
}

quic::Expected<uint64_t, QuicError> convertEncodedDurationToMicroseconds(
    uint8_t exponentToUse,
    uint64_t delay) noexcept {
  // ackDelayExponentToUse is guaranteed to be less than the size of uint64_t
  uint64_t delayOverflowMask = 0xFFFFFFFFFFFFFFFF;

  constexpr uint8_t delayValWidth = sizeof(delay) * 8;
  if (exponentToUse == 0 || exponentToUse >= delayValWidth) {
    return delay;
  }
  uint8_t leftShift = (delayValWidth - exponentToUse);
  delayOverflowMask = delayOverflowMask << leftShift;
  if ((delay & delayOverflowMask) != 0) {
    return quic::make_unexpected(QuicError(
        quic::TransportErrorCode::FRAME_ENCODING_ERROR,
        "Decoded delay overflows"));
  }
  uint64_t adjustedDelay = delay << exponentToUse;
  if (adjustedDelay >
      static_cast<uint64_t>(
          std::numeric_limits<std::chrono::microseconds::rep>::max())) {
    return quic::make_unexpected(
        QuicError(quic::TransportErrorCode::FRAME_ENCODING_ERROR, "Bad delay"));
  }
  return adjustedDelay;
}

quic::Expected<ReadAckFrame, QuicError> decodeAckFrame(
    ContiguousReadCursor& cursor,
    const PacketHeader& header,
    const CodecParameters& params,
    FrameType frameType) {
  ReadAckFrame frame;
  frame.frameType = frameType;
  auto largestAckedInt = quic::decodeQuicInteger(cursor);
  if (!largestAckedInt) {
    return quic::make_unexpected(QuicError(
        quic::TransportErrorCode::FRAME_ENCODING_ERROR, "Bad largest acked"));
  }
  PacketNum largestAcked = largestAckedInt->first;
  auto ackDelay = quic::decodeQuicInteger(cursor);
  if (!ackDelay) {
    return quic::make_unexpected(QuicError(
        quic::TransportErrorCode::FRAME_ENCODING_ERROR, "Bad ack delay"));
  }
  auto additionalAckBlocks = quic::decodeQuicInteger(cursor);
  if (!additionalAckBlocks) {
    return quic::make_unexpected(QuicError(
        quic::TransportErrorCode::FRAME_ENCODING_ERROR, "Bad ack block count"));
  }
  auto firstAckBlockLen = quic::decodeQuicInteger(cursor);
  if (!firstAckBlockLen) {
    return quic::make_unexpected(QuicError(
        quic::TransportErrorCode::FRAME_ENCODING_ERROR, "Bad first block"));
  }
  // Using default ack delay for long header packets. Before negotiating
  // and ack delay, the sender has to use something, so they use the default
  // ack delay. To keep it consistent the protocol specifies using the same
  // ack delay for all the long header packets.
  uint8_t ackDelayExponentToUse = (header.getHeaderForm() == HeaderForm::Long)
      ? kDefaultAckDelayExponent
      : params.peerAckDelayExponent;
  DCHECK_LT(ackDelayExponentToUse, sizeof(ackDelay->first) * 8);

  auto res = nextAckedPacketLen(largestAcked, firstAckBlockLen->first);
  if (res.hasError()) {
    return quic::make_unexpected(res.error());
  }
  PacketNum currentPacketNum = *res;
  frame.largestAcked = largestAcked;

  auto delayRes = convertEncodedDurationToMicroseconds(
      ackDelayExponentToUse, ackDelay->first);
  if (delayRes.hasError()) {
    return quic::make_unexpected(delayRes.error());
  }
  auto adjustedDelay = *delayRes;

  if (UNLIKELY(adjustedDelay > 1000 * 1000 * 1000 /* 1000s */)) {
    MVLOG_ERROR << "Quic recvd long ack delay=" << adjustedDelay
                << " frame type: " << static_cast<uint64_t>(frameType);
    adjustedDelay = 0;
  }
  frame.ackDelay = std::chrono::microseconds(adjustedDelay);

  frame.ackBlocks.emplace_back(currentPacketNum, largestAcked);
  for (uint64_t numBlocks = 0; numBlocks < additionalAckBlocks->first;
       ++numBlocks) {
    auto currentGap = quic::decodeQuicInteger(cursor);
    if (!currentGap) {
      return quic::make_unexpected(
          QuicError(quic::TransportErrorCode::FRAME_ENCODING_ERROR, "Bad gap"));
    }
    auto blockLen = quic::decodeQuicInteger(cursor);
    if (!blockLen) {
      return quic::make_unexpected(QuicError(
          quic::TransportErrorCode::FRAME_ENCODING_ERROR, "Bad block len"));
    }
    res = nextAckedPacketGap(currentPacketNum, currentGap->first);
    if (res.hasError()) {
      return quic::make_unexpected(res.error());
    }
    PacketNum nextEndPacket = *res;
    res = nextAckedPacketLen(nextEndPacket, blockLen->first);
    if (res.hasError()) {
      return quic::make_unexpected(res.error());
    }
    currentPacketNum = *res;
    // We don't need to add the entry when the block length is zero since we
    // already would have processed it in the previous iteration.
    frame.ackBlocks.emplace_back(currentPacketNum, nextEndPacket);
  }

  return frame;
}

static quic::Expected<void, QuicError> decodeReceiveTimestampsInAck(
    ReadAckFrame& frame,
    ContiguousReadCursor& cursor,
    const CodecParameters& params) {
  auto latestRecvdPacketNum = quic::decodeQuicInteger(cursor);
  if (!latestRecvdPacketNum) {
    return quic::make_unexpected(QuicError(
        quic::TransportErrorCode::FRAME_ENCODING_ERROR,
        "Bad latest received packet number"));
  }
  frame.maybeLatestRecvdPacketNum = latestRecvdPacketNum->first;

  auto latestRecvdPacketTimeDelta = quic::decodeQuicInteger(cursor);
  if (!latestRecvdPacketTimeDelta) {
    return quic::make_unexpected(QuicError(
        quic::TransportErrorCode::FRAME_ENCODING_ERROR,
        "Bad receive packet timestamp delta"));
  }
  frame.maybeLatestRecvdPacketTime =
      std::chrono::microseconds(latestRecvdPacketTimeDelta->first);

  auto timeStampRangeCount = quic::decodeQuicInteger(cursor);
  if (!timeStampRangeCount) {
    return quic::make_unexpected(QuicError(
        quic::TransportErrorCode::FRAME_ENCODING_ERROR,
        "Bad receive timestamps range count"));
  }
  for (uint64_t numRanges = 0; numRanges < timeStampRangeCount->first;
       numRanges++) {
    RecvdPacketsTimestampsRange timeStampRange;
    auto receiveTimeStampsGap = quic::decodeQuicInteger(cursor);
    if (!receiveTimeStampsGap) {
      return quic::make_unexpected(QuicError(
          quic::TransportErrorCode::FRAME_ENCODING_ERROR,
          "Bad receive timestamps gap"));
    }
    timeStampRange.gap = receiveTimeStampsGap->first;
    auto receiveTimeStampsLen = quic::decodeQuicInteger(cursor);
    if (!receiveTimeStampsLen) {
      return quic::make_unexpected(QuicError(
          quic::TransportErrorCode::FRAME_ENCODING_ERROR,
          "Bad receive timestamps block length"));
    }
    timeStampRange.timestamp_delta_count = receiveTimeStampsLen->first;
    uint8_t receiveTimestampsExponentToUse =
        (params.maybeAckReceiveTimestampsConfig)
        ? params.maybeAckReceiveTimestampsConfig.value()
              .receiveTimestampsExponent
        : kDefaultReceiveTimestampsExponent;
    for (uint64_t i = 0; i < receiveTimeStampsLen->first; i++) {
      auto delta = quic::decodeQuicInteger(cursor);
      if (!delta) {
        return quic::make_unexpected(QuicError(
            quic::TransportErrorCode::FRAME_ENCODING_ERROR,
            "Bad receive timestamps delta"));
      }
      DCHECK_LT(receiveTimestampsExponentToUse, sizeof(delta->first) * 8);
      auto res = convertEncodedDurationToMicroseconds(
          receiveTimestampsExponentToUse, delta->first);
      if (res.hasError()) {
        return quic::make_unexpected(res.error());
      }
      auto adjustedDelta = *res;
      timeStampRange.deltas.push_back(adjustedDelta);
    }
    frame.recvdPacketsTimestampRanges.emplace_back(timeStampRange);
  }
  return {};
}

static quic::Expected<void, QuicError> decodeEcnCountsInAck(
    ReadAckFrame& frame,
    ContiguousReadCursor& cursor) {
  auto ect_0 = quic::decodeQuicInteger(cursor);
  auto ect_1 = quic::decodeQuicInteger(cursor);
  auto ce = quic::decodeQuicInteger(cursor);
  if (!ect_0 || !ect_1 || !ce) {
    return quic::make_unexpected(QuicError(
        quic::TransportErrorCode::FRAME_ENCODING_ERROR, "Bad ECN value"));
  }
  frame.ecnECT0Count = ect_0->first;
  frame.ecnECT1Count = ect_1->first;
  frame.ecnCECount = ce->first;
  return {};
}

quic::Expected<ReadAckFrame, QuicError> decodeAckExtendedFrame(
    ContiguousReadCursor& cursor,
    const PacketHeader& header,
    const CodecParameters& params) {
  ReadAckFrame frame;
  auto res = decodeAckFrame(cursor, header, params, FrameType::ACK_EXTENDED);
  if (res.hasError()) {
    return quic::make_unexpected(res.error());
  }
  frame = *res;
  auto extendedAckFeatures = quic::decodeQuicInteger(cursor);
  if (!extendedAckFeatures) {
    return quic::make_unexpected(QuicError(
        quic::TransportErrorCode::FRAME_ENCODING_ERROR,
        "Bad extended ACK features field"));
  }
  auto includedFeatures = extendedAckFeatures->first;
  if ((includedFeatures | params.extendedAckFeatures) !=
      params.extendedAckFeatures) {
    return quic::make_unexpected(QuicError(
        quic::TransportErrorCode::FRAME_ENCODING_ERROR,
        "Extended ACK has unexpected features"));
  }
  if (includedFeatures &
      static_cast<ExtendedAckFeatureMaskType>(
          ExtendedAckFeatureMask::ECN_COUNTS)) {
    auto ecnResult = decodeEcnCountsInAck(frame, cursor);
    if (ecnResult.hasError()) {
      return quic::make_unexpected(ecnResult.error());
    }
  }
  if (includedFeatures &
      static_cast<ExtendedAckFeatureMaskType>(
          ExtendedAckFeatureMask::RECEIVE_TIMESTAMPS)) {
    auto tsResult = decodeReceiveTimestampsInAck(frame, cursor, params);
    if (tsResult.hasError()) {
      return quic::make_unexpected(tsResult.error());
    }
  }
  return frame;
}

quic::Expected<QuicFrame, QuicError> decodeAckFrameWithReceivedTimestamps(
    ContiguousReadCursor& cursor,
    const PacketHeader& header,
    const CodecParameters& params,
    FrameType frameType) {
  ReadAckFrame frame;

  auto ack = decodeAckFrame(cursor, header, params, frameType);
  if (ack.hasError()) {
    return quic::make_unexpected(ack.error());
  }
  frame = *ack;
  frame.frameType = frameType;

  auto ts = decodeReceiveTimestampsInAck(frame, cursor, params);
  if (ts.hasError()) {
    return quic::make_unexpected(ts.error());
  }

  return QuicFrame(frame);
}

quic::Expected<QuicFrame, QuicError> decodeAckFrameWithECN(
    ContiguousReadCursor& cursor,
    const PacketHeader& header,
    const CodecParameters& params) {
  ReadAckFrame readAckFrame;

  auto ack = decodeAckFrame(cursor, header, params);
  if (ack.hasError()) {
    return quic::make_unexpected(ack.error());
  }
  readAckFrame = *ack;
  readAckFrame.frameType = FrameType::ACK_ECN;

  auto ecn = decodeEcnCountsInAck(readAckFrame, cursor);
  if (ecn.hasError()) {
    return quic::make_unexpected(ecn.error());
  }

  return QuicFrame(readAckFrame);
}

quic::Expected<RstStreamFrame, QuicError> decodeRstStreamFrame(
    ContiguousReadCursor& cursor,
    bool reliable) {
  auto streamId = quic::decodeQuicInteger(cursor);
  if (!streamId) {
    return quic::make_unexpected(QuicError(
        quic::TransportErrorCode::FRAME_ENCODING_ERROR, "Bad streamId"));
  }
  ApplicationErrorCode errorCode;
  auto varCode = quic::decodeQuicInteger(cursor);
  if (varCode) {
    errorCode = static_cast<ApplicationErrorCode>(varCode->first);
  } else {
    return quic::make_unexpected(QuicError(
        quic::TransportErrorCode::FRAME_ENCODING_ERROR,
        "Cannot decode error code"));
  }
  auto finalSize = quic::decodeQuicInteger(cursor);
  if (!finalSize) {
    return quic::make_unexpected(QuicError(
        quic::TransportErrorCode::FRAME_ENCODING_ERROR, "Bad offset"));
  }
  Optional<std::pair<uint64_t, size_t>> reliableSize = std::nullopt;
  if (reliable) {
    reliableSize = quic::decodeQuicInteger(cursor);
    if (!reliableSize) {
      return quic::make_unexpected(QuicError(
          quic::TransportErrorCode::FRAME_ENCODING_ERROR,
          "Bad value of reliable size"));
    }

    if (reliableSize->first > finalSize->first) {
      return quic::make_unexpected(QuicError(
          quic::TransportErrorCode::FRAME_ENCODING_ERROR,
          "Reliable size is greater than final size"));
    }
  }
  return RstStreamFrame(
      streamId->first,
      errorCode,
      finalSize->first,
      reliableSize ? Optional<uint64_t>(reliableSize->first) : std::nullopt);
}

quic::Expected<StopSendingFrame, QuicError> decodeStopSendingFrame(
    ContiguousReadCursor& cursor) {
  auto streamId = quic::decodeQuicInteger(cursor);
  if (!streamId) {
    return quic::make_unexpected(QuicError(
        quic::TransportErrorCode::FRAME_ENCODING_ERROR, "Bad streamId"));
  }
  ApplicationErrorCode errorCode;
  auto varCode = quic::decodeQuicInteger(cursor);
  if (varCode) {
    errorCode = static_cast<ApplicationErrorCode>(varCode->first);
  } else {
    return quic::make_unexpected(QuicError(
        quic::TransportErrorCode::FRAME_ENCODING_ERROR,
        "Cannot decode error code"));
  }
  return StopSendingFrame(streamId->first, errorCode);
}

quic::Expected<ReadCryptoFrame, QuicError> decodeCryptoFrame(
    ContiguousReadCursor& cursor) {
  auto optionalOffset = quic::decodeQuicInteger(cursor);
  if (!optionalOffset) {
    return quic::make_unexpected(QuicError(
        quic::TransportErrorCode::FRAME_ENCODING_ERROR, "Invalid offset"));
  }
  uint64_t offset = optionalOffset->first;

  auto dataLength = quic::decodeQuicInteger(cursor);
  if (!dataLength) {
    return quic::make_unexpected(QuicError(
        quic::TransportErrorCode::FRAME_ENCODING_ERROR, "Invalid length"));
  }
  if (cursor.remaining() < dataLength->first) {
    return quic::make_unexpected(QuicError(
        quic::TransportErrorCode::FRAME_ENCODING_ERROR, "Length mismatch"));
  }

  BufPtr data = BufHelpers::create(dataLength->first);
  size_t cloned = cursor.pullAtMost(data->writableData(), dataLength->first);
  if (cloned < dataLength->first) {
    return quic::make_unexpected(QuicError(
        quic::TransportErrorCode::FRAME_ENCODING_ERROR,
        "Failed to clone complete data"));
  }
  data->append(dataLength->first);

  return ReadCryptoFrame(offset, std::move(data));
}

quic::Expected<ReadNewTokenFrame, QuicError> decodeNewTokenFrame(
    ContiguousReadCursor& cursor) {
  auto tokenLength = quic::decodeQuicInteger(cursor);
  if (!tokenLength) {
    return quic::make_unexpected(QuicError(
        quic::TransportErrorCode::FRAME_ENCODING_ERROR, "Invalid length"));
  }
  if (cursor.remaining() < tokenLength->first) {
    return quic::make_unexpected(QuicError(
        quic::TransportErrorCode::FRAME_ENCODING_ERROR, "Length mismatch"));
  }
  BufPtr token = BufHelpers::create(tokenLength->first);
  size_t cloned = cursor.pullAtMost(token->writableData(), tokenLength->first);
  if (cloned < tokenLength->first) {
    return quic::make_unexpected(QuicError(
        quic::TransportErrorCode::FRAME_ENCODING_ERROR,
        "Failed to clone token"));
  }
  token->append(tokenLength->first);

  return ReadNewTokenFrame(std::move(token));
}

quic::Expected<ReadStreamFrame, QuicError> decodeStreamFrame(
    BufQueue& queue,
    StreamTypeField frameTypeField) {
  ContiguousReadCursor cursor(queue.front()->data(), queue.front()->length());

  auto streamId = quic::decodeQuicInteger(cursor);
  if (!streamId) {
    return quic::make_unexpected(QuicError(
        quic::TransportErrorCode::FRAME_ENCODING_ERROR, "Invalid stream id"));
  }

  uint64_t offset = 0;
  if (frameTypeField.hasOffset()) {
    auto optionalOffset = quic::decodeQuicInteger(cursor);
    if (!optionalOffset) {
      return quic::make_unexpected(QuicError(
          quic::TransportErrorCode::FRAME_ENCODING_ERROR, "Invalid offset"));
    }
    offset = optionalOffset->first;
  }
  auto fin = frameTypeField.hasFin();
  Optional<std::pair<uint64_t, size_t>> dataLength;
  if (frameTypeField.hasDataLength()) {
    dataLength = quic::decodeQuicInteger(cursor);
    if (!dataLength) {
      return quic::make_unexpected(QuicError(
          quic::TransportErrorCode::FRAME_ENCODING_ERROR, "Invalid length"));
    }
  }
  BufPtr data;

  // Calculate how much to trim from the start of the queue
  size_t trimAmount = cursor.getCurrentPosition();
  if (trimAmount > 0) {
    size_t trimmed = queue.trimStartAtMost(trimAmount);
    if (trimmed < trimAmount) {
      return quic::make_unexpected(QuicError(
          quic::TransportErrorCode::FRAME_ENCODING_ERROR,
          "Failed to trim queue"));
    }
  }

  if (dataLength.has_value()) {
    if (queue.chainLength() < dataLength->first) {
      return quic::make_unexpected(QuicError(
          quic::TransportErrorCode::FRAME_ENCODING_ERROR, "Length mismatch"));
    }
    data = queue.splitAtMost(dataLength->first);
    if (!data || data->computeChainDataLength() < dataLength->first) {
      return quic::make_unexpected(QuicError(
          quic::TransportErrorCode::FRAME_ENCODING_ERROR,
          "Failed to extract data"));
    }
  } else {
    // Missing Data Length field doesn't mean no data. It means the rest of the
    // frame are all data.
    data = queue.move();
    if (!data) {
      return quic::make_unexpected(QuicError(
          quic::TransportErrorCode::FRAME_ENCODING_ERROR,
          "Failed to extract data"));
    }
  }
  return ReadStreamFrame(streamId->first, offset, std::move(data), fin);
}

quic::Expected<MaxDataFrame, QuicError> decodeMaxDataFrame(
    ContiguousReadCursor& cursor) {
  auto maximumData = quic::decodeQuicInteger(cursor);
  if (!maximumData) {
    return quic::make_unexpected(QuicError(
        quic::TransportErrorCode::FRAME_ENCODING_ERROR, "Bad Max Data"));
  }
  return MaxDataFrame(maximumData->first);
}

quic::Expected<MaxStreamDataFrame, QuicError> decodeMaxStreamDataFrame(
    ContiguousReadCursor& cursor) {
  auto streamId = quic::decodeQuicInteger(cursor);
  if (!streamId) {
    return quic::make_unexpected(QuicError(
        quic::TransportErrorCode::FRAME_ENCODING_ERROR, "Invalid streamId"));
  }
  auto offset = quic::decodeQuicInteger(cursor);
  if (!offset) {
    return quic::make_unexpected(QuicError(
        quic::TransportErrorCode::FRAME_ENCODING_ERROR, "Invalid offset"));
  }
  return MaxStreamDataFrame(streamId->first, offset->first);
}

quic::Expected<MaxStreamsFrame, QuicError> decodeBiDiMaxStreamsFrame(
    ContiguousReadCursor& cursor) {
  auto streamCount = quic::decodeQuicInteger(cursor);
  if (!streamCount || streamCount->first > kMaxMaxStreams) {
    return quic::make_unexpected(QuicError(
        quic::TransportErrorCode::FRAME_ENCODING_ERROR,
        "Invalid Bi-directional streamId"));
  }
  return MaxStreamsFrame(streamCount->first, true /* isBidirectional*/);
}

quic::Expected<MaxStreamsFrame, QuicError> decodeUniMaxStreamsFrame(
    ContiguousReadCursor& cursor) {
  auto streamCount = quic::decodeQuicInteger(cursor);
  if (!streamCount || streamCount->first > kMaxMaxStreams) {
    return quic::make_unexpected(QuicError(
        quic::TransportErrorCode::FRAME_ENCODING_ERROR,
        "Invalid Uni-directional streamId"));
  }
  return MaxStreamsFrame(streamCount->first, false /* isUnidirectional */);
}

quic::Expected<DataBlockedFrame, QuicError> decodeDataBlockedFrame(
    ContiguousReadCursor& cursor) {
  auto dataLimit = quic::decodeQuicInteger(cursor);
  if (!dataLimit) {
    return quic::make_unexpected(QuicError(
        quic::TransportErrorCode::FRAME_ENCODING_ERROR, "Bad offset"));
  }
  return DataBlockedFrame(dataLimit->first);
}

quic::Expected<StreamDataBlockedFrame, QuicError> decodeStreamDataBlockedFrame(
    ContiguousReadCursor& cursor) {
  auto streamId = quic::decodeQuicInteger(cursor);
  if (!streamId) {
    return quic::make_unexpected(QuicError(
        quic::TransportErrorCode::FRAME_ENCODING_ERROR, "Bad streamId"));
  }
  auto dataLimit = quic::decodeQuicInteger(cursor);
  if (!dataLimit) {
    return quic::make_unexpected(QuicError(
        quic::TransportErrorCode::FRAME_ENCODING_ERROR, "Bad offset"));
  }
  return StreamDataBlockedFrame(streamId->first, dataLimit->first);
}

quic::Expected<StreamsBlockedFrame, QuicError> decodeBiDiStreamsBlockedFrame(
    ContiguousReadCursor& cursor) {
  auto streamId = quic::decodeQuicInteger(cursor);
  if (!streamId) {
    return quic::make_unexpected(QuicError(
        quic::TransportErrorCode::FRAME_ENCODING_ERROR,
        "Bad Bi-Directional streamId"));
  }
  return StreamsBlockedFrame(streamId->first, true /* isBidirectional */);
}

quic::Expected<StreamsBlockedFrame, QuicError> decodeUniStreamsBlockedFrame(
    ContiguousReadCursor& cursor) {
  auto streamId = quic::decodeQuicInteger(cursor);
  if (!streamId) {
    return quic::make_unexpected(QuicError(
        quic::TransportErrorCode::FRAME_ENCODING_ERROR,
        "Bad Uni-direcitonal streamId"));
  }
  return StreamsBlockedFrame(streamId->first, false /* isBidirectional */);
}

quic::Expected<NewConnectionIdFrame, QuicError> decodeNewConnectionIdFrame(
    ContiguousReadCursor& cursor) {
  auto sequenceNumber = quic::decodeQuicInteger(cursor);
  if (!sequenceNumber) {
    return quic::make_unexpected(QuicError(
        quic::TransportErrorCode::FRAME_ENCODING_ERROR, "Bad sequence"));
  }
  auto retirePriorTo = quic::decodeQuicInteger(cursor);
  if (!retirePriorTo) {
    return quic::make_unexpected(QuicError(
        quic::TransportErrorCode::FRAME_ENCODING_ERROR, "Bad retire prior to"));
  }
  uint8_t connIdLen = 0;
  if (!cursor.tryReadBE(connIdLen)) {
    return quic::make_unexpected(QuicError(
        quic::TransportErrorCode::FRAME_ENCODING_ERROR,
        "Not enough input bytes to read Dest. ConnectionId"));
  }
  if (cursor.remaining() < connIdLen) {
    return quic::make_unexpected(QuicError(
        quic::TransportErrorCode::FRAME_ENCODING_ERROR, "Bad connid"));
  }
  if (connIdLen > kMaxConnectionIdSize) {
    return quic::make_unexpected(QuicError(
        quic::TransportErrorCode::FRAME_ENCODING_ERROR,
        "ConnectionId invalid length"));
  }

  auto connIdResult = ConnectionId::create(cursor, connIdLen);
  if (connIdResult.hasError()) {
    return quic::make_unexpected(connIdResult.error());
  }
  ConnectionId connId = connIdResult.value();

  StatelessResetToken statelessResetToken;
  size_t bytesRead =
      cursor.pullAtMost(statelessResetToken.data(), statelessResetToken.size());
  if (bytesRead < statelessResetToken.size()) {
    return quic::make_unexpected(QuicError(
        quic::TransportErrorCode::FRAME_ENCODING_ERROR,
        "Failed to read StatelessResetToken"));
  }

  return NewConnectionIdFrame(
      sequenceNumber->first,
      retirePriorTo->first,
      std::move(connId),
      std::move(statelessResetToken));
}

quic::Expected<RetireConnectionIdFrame, QuicError>
decodeRetireConnectionIdFrame(ContiguousReadCursor& cursor) {
  auto sequenceNum = quic::decodeQuicInteger(cursor);
  if (!sequenceNum) {
    return quic::make_unexpected(QuicError(
        quic::TransportErrorCode::FRAME_ENCODING_ERROR, "Bad sequence num"));
  }
  return RetireConnectionIdFrame(sequenceNum->first);
}

quic::Expected<PathChallengeFrame, QuicError> decodePathChallengeFrame(
    ContiguousReadCursor& cursor) {
  uint64_t pathData = 0;
  if (!cursor.tryReadBE<uint64_t>(pathData)) {
    return quic::make_unexpected(QuicError(
        quic::TransportErrorCode::FRAME_ENCODING_ERROR,
        "Not enough input bytes to read path challenge frame."));
  }
  return PathChallengeFrame(pathData);
}

quic::Expected<PathResponseFrame, QuicError> decodePathResponseFrame(
    ContiguousReadCursor& cursor) {
  uint64_t pathData = 0;
  if (!cursor.tryReadBE<uint64_t>(pathData)) {
    return quic::make_unexpected(QuicError(
        quic::TransportErrorCode::FRAME_ENCODING_ERROR,
        "Not enough input bytes to read path response frame."));
  }
  return PathResponseFrame(pathData);
}

quic::Expected<ConnectionCloseFrame, QuicError> decodeConnectionCloseFrame(
    ContiguousReadCursor& cursor) {
  TransportErrorCode errorCode{};
  auto varCode = quic::decodeQuicInteger(cursor);
  if (!varCode) {
    return quic::make_unexpected(QuicError(
        quic::TransportErrorCode::FRAME_ENCODING_ERROR,
        "Failed to parse error code."));
  }
  errorCode = static_cast<TransportErrorCode>(varCode->first);

  auto frameTypeField = quic::decodeQuicInteger(cursor);
  if (!frameTypeField || frameTypeField->second != sizeof(uint8_t)) {
    return quic::make_unexpected(QuicError(
        quic::TransportErrorCode::FRAME_ENCODING_ERROR,
        "Bad connection close triggering frame type value"));
  }
  auto triggeringFrameType = static_cast<FrameType>(frameTypeField->first);

  auto reasonPhraseLength = quic::decodeQuicInteger(cursor);
  if (!reasonPhraseLength ||
      reasonPhraseLength->first > kMaxReasonPhraseLength) {
    return quic::make_unexpected(QuicError(
        quic::TransportErrorCode::FRAME_ENCODING_ERROR,
        "Bad reason phrase length"));
  }

  std::string reasonPhrase;
  auto len = static_cast<size_t>(reasonPhraseLength->first);
  auto bytes = cursor.peekBytes();
  size_t available = std::min(bytes.size(), len);
  reasonPhrase.append(reinterpret_cast<const char*>(bytes.data()), available);
  cursor.skip(available);

  return ConnectionCloseFrame(
      QuicErrorCode(errorCode), std::move(reasonPhrase), triggeringFrameType);
}

quic::Expected<ConnectionCloseFrame, QuicError> decodeApplicationClose(
    ContiguousReadCursor& cursor) {
  ApplicationErrorCode errorCode{};
  auto varCode = quic::decodeQuicInteger(cursor);
  if (!varCode) {
    return quic::make_unexpected(QuicError(
        quic::TransportErrorCode::FRAME_ENCODING_ERROR,
        "Failed to parse error code."));
  }
  errorCode = static_cast<ApplicationErrorCode>(varCode->first);

  auto reasonPhraseLength = quic::decodeQuicInteger(cursor);
  if (!reasonPhraseLength ||
      reasonPhraseLength->first > kMaxReasonPhraseLength) {
    return quic::make_unexpected(QuicError(
        quic::TransportErrorCode::FRAME_ENCODING_ERROR,
        "Bad reason phrase length"));
  }

  std::string reasonPhrase;
  auto len = static_cast<size_t>(reasonPhraseLength->first);
  auto bytes = cursor.peekBytes();
  size_t available = std::min(bytes.size(), len);
  reasonPhrase.append(reinterpret_cast<const char*>(bytes.data()), available);
  cursor.skip(available);

  return ConnectionCloseFrame(
      QuicErrorCode(errorCode), std::move(reasonPhrase));
}

quic::Expected<HandshakeDoneFrame, QuicError> decodeHandshakeDoneFrame(
    ContiguousReadCursor& /*cursor*/) {
  return HandshakeDoneFrame();
}

/**
 * Both retry and new tokens have the same plaintext encoding: timestamp. We
 * differentiate tokens based on the success of decrypting with differing aead
 * associated data.
 */
quic::Expected<uint64_t, TransportErrorCode> parsePlaintextRetryOrNewToken(
    ContiguousReadCursor& cursor) {
  // Read in the timestamp
  uint64_t timestampInMs = 0;
  if (!cursor.tryReadBE<uint64_t>(timestampInMs)) {
    return quic::make_unexpected(TransportErrorCode::INVALID_TOKEN);
  }

  return timestampInMs;
}

quic::Expected<DatagramFrame, QuicError> decodeDatagramFrame(
    BufQueue& queue,
    bool hasLen) {
  ContiguousReadCursor cursor(queue.front()->data(), queue.front()->length());
  size_t length = cursor.remaining();
  if (hasLen) {
    auto decodeLength = quic::decodeQuicInteger(cursor);
    if (!decodeLength) {
      return quic::make_unexpected(QuicError(
          TransportErrorCode::FRAME_ENCODING_ERROR, "Invalid datagram len"));
    }
    length = decodeLength->first;
    if (cursor.remaining() < length) {
      return quic::make_unexpected(QuicError(
          TransportErrorCode::FRAME_ENCODING_ERROR, "Invalid datagram frame"));
    }
    queue.trimStart(decodeLength->second);
  }
  return DatagramFrame(length, queue.splitAtMost(length));
}

quic::Expected<QuicFrame, QuicError> parseFrame(
    BufQueue& queue,
    const PacketHeader& header,
    const CodecParameters& params) {
  ContiguousReadCursor contiguousCursor(
      queue.front()->data(), queue.front()->length());
  auto frameTypeInt = quic::decodeQuicInteger(contiguousCursor);
  if (!frameTypeInt) {
    return quic::make_unexpected(QuicError(
        TransportErrorCode::FRAME_ENCODING_ERROR, "Invalid frame-type field"));
  }
  queue.trimStart(contiguousCursor.getCurrentPosition());
  contiguousCursor.reset(queue.front()->data(), queue.front()->length());
  auto frameType = static_cast<FrameType>(frameTypeInt->first);

  // No more try/catch, just use Expected/make_unexpected pattern
  switch (frameType) {
    case FrameType::PADDING: {
      auto paddingRes = decodePaddingFrame(contiguousCursor);
      if (!paddingRes.has_value()) {
        return quic::make_unexpected(paddingRes.error());
      }
      queue.trimStart(contiguousCursor.getCurrentPosition());
      return QuicFrame(*paddingRes);
    }
    case FrameType::PING: {
      auto pingRes = decodePingFrame(contiguousCursor);
      if (!pingRes.has_value()) {
        return quic::make_unexpected(pingRes.error());
      }
      queue.trimStart(contiguousCursor.getCurrentPosition());
      return QuicFrame(*pingRes);
    }
    case FrameType::ACK: {
      auto ackFrameRes = decodeAckFrame(contiguousCursor, header, params);
      if (ackFrameRes.hasError()) {
        return ackFrameRes;
      }
      queue.trimStart(contiguousCursor.getCurrentPosition());
      return ackFrameRes;
    }
    case FrameType::ACK_ECN: {
      auto ackFrameWithEcnRes =
          decodeAckFrameWithECN(contiguousCursor, header, params);
      if (ackFrameWithEcnRes.hasError()) {
        return ackFrameWithEcnRes;
      }
      queue.trimStart(contiguousCursor.getCurrentPosition());
      return ackFrameWithEcnRes;
    }
    case FrameType::RST_STREAM:
    case FrameType::RST_STREAM_AT: {
      auto rstRes = decodeRstStreamFrame(
          contiguousCursor, frameType == FrameType::RST_STREAM_AT);
      if (!rstRes.has_value()) {
        return quic::make_unexpected(rstRes.error());
      }
      queue.trimStart(contiguousCursor.getCurrentPosition());
      return QuicFrame(*rstRes);
    }
    case FrameType::STOP_SENDING: {
      auto stopRes = decodeStopSendingFrame(contiguousCursor);
      if (!stopRes.has_value()) {
        return quic::make_unexpected(stopRes.error());
      }
      queue.trimStart(contiguousCursor.getCurrentPosition());
      return QuicFrame(*stopRes);
    }
    case FrameType::CRYPTO_FRAME: {
      auto cryptoRes = decodeCryptoFrame(contiguousCursor);
      if (!cryptoRes.has_value()) {
        return quic::make_unexpected(cryptoRes.error());
      }
      queue.trimStart(contiguousCursor.getCurrentPosition());
      return QuicFrame(*cryptoRes);
    }
    case FrameType::NEW_TOKEN: {
      auto tokenRes = decodeNewTokenFrame(contiguousCursor);
      if (!tokenRes.has_value()) {
        return quic::make_unexpected(tokenRes.error());
      }
      queue.trimStart(contiguousCursor.getCurrentPosition());
      return QuicFrame(*tokenRes);
    }
    case FrameType::STREAM:
    case FrameType::STREAM_FIN:
    case FrameType::STREAM_LEN:
    case FrameType::STREAM_LEN_FIN:
    case FrameType::STREAM_OFF:
    case FrameType::STREAM_OFF_FIN:
    case FrameType::STREAM_OFF_LEN:
    case FrameType::STREAM_OFF_LEN_FIN: {
      auto streamRes =
          decodeStreamFrame(queue, StreamTypeField(frameTypeInt->first));
      if (!streamRes.has_value()) {
        return quic::make_unexpected(streamRes.error());
      }
      return QuicFrame(*streamRes);
    }
    case FrameType::MAX_DATA: {
      auto maxDataRes = decodeMaxDataFrame(contiguousCursor);
      if (!maxDataRes.has_value()) {
        return quic::make_unexpected(maxDataRes.error());
      }
      queue.trimStart(contiguousCursor.getCurrentPosition());
      return QuicFrame(*maxDataRes);
    }
    case FrameType::MAX_STREAM_DATA: {
      auto maxStreamRes = decodeMaxStreamDataFrame(contiguousCursor);
      if (!maxStreamRes.has_value()) {
        return quic::make_unexpected(maxStreamRes.error());
      }
      queue.trimStart(contiguousCursor.getCurrentPosition());
      return QuicFrame(*maxStreamRes);
    }
    case FrameType::MAX_STREAMS_BIDI: {
      auto streamsBidiRes = decodeBiDiMaxStreamsFrame(contiguousCursor);
      if (!streamsBidiRes.has_value()) {
        return quic::make_unexpected(streamsBidiRes.error());
      }
      queue.trimStart(contiguousCursor.getCurrentPosition());
      return QuicFrame(*streamsBidiRes);
    }
    case FrameType::MAX_STREAMS_UNI: {
      auto streamsUniRes = decodeUniMaxStreamsFrame(contiguousCursor);
      if (!streamsUniRes.has_value()) {
        return quic::make_unexpected(streamsUniRes.error());
      }
      queue.trimStart(contiguousCursor.getCurrentPosition());
      return QuicFrame(*streamsUniRes);
    }
    case FrameType::DATA_BLOCKED: {
      auto blockedRes = decodeDataBlockedFrame(contiguousCursor);
      if (!blockedRes.has_value()) {
        return quic::make_unexpected(blockedRes.error());
      }
      queue.trimStart(contiguousCursor.getCurrentPosition());
      return QuicFrame(*blockedRes);
    }
    case FrameType::STREAM_DATA_BLOCKED: {
      auto streamBlockedRes = decodeStreamDataBlockedFrame(contiguousCursor);
      if (!streamBlockedRes.has_value()) {
        return quic::make_unexpected(streamBlockedRes.error());
      }
      queue.trimStart(contiguousCursor.getCurrentPosition());
      return QuicFrame(*streamBlockedRes);
    }
    case FrameType::STREAMS_BLOCKED_BIDI: {
      auto streamsBidiBlockedRes =
          decodeBiDiStreamsBlockedFrame(contiguousCursor);
      if (!streamsBidiBlockedRes.has_value()) {
        return quic::make_unexpected(streamsBidiBlockedRes.error());
      }
      queue.trimStart(contiguousCursor.getCurrentPosition());
      return QuicFrame(*streamsBidiBlockedRes);
    }
    case FrameType::STREAMS_BLOCKED_UNI: {
      auto streamsUniBlockedRes =
          decodeUniStreamsBlockedFrame(contiguousCursor);
      if (!streamsUniBlockedRes.has_value()) {
        return quic::make_unexpected(streamsUniBlockedRes.error());
      }
      queue.trimStart(contiguousCursor.getCurrentPosition());
      return QuicFrame(*streamsUniBlockedRes);
    }
    case FrameType::NEW_CONNECTION_ID: {
      auto newConnIdRes = decodeNewConnectionIdFrame(contiguousCursor);
      if (!newConnIdRes.has_value()) {
        return quic::make_unexpected(newConnIdRes.error());
      }
      queue.trimStart(contiguousCursor.getCurrentPosition());
      return QuicFrame(*newConnIdRes);
    }
    case FrameType::RETIRE_CONNECTION_ID: {
      auto retireConnIdRes = decodeRetireConnectionIdFrame(contiguousCursor);
      if (!retireConnIdRes.has_value()) {
        return quic::make_unexpected(retireConnIdRes.error());
      }
      queue.trimStart(contiguousCursor.getCurrentPosition());
      return QuicFrame(*retireConnIdRes);
    }
    case FrameType::PATH_CHALLENGE: {
      auto pathChallengeRes = decodePathChallengeFrame(contiguousCursor);
      if (!pathChallengeRes.has_value()) {
        return quic::make_unexpected(pathChallengeRes.error());
      }
      queue.trimStart(contiguousCursor.getCurrentPosition());
      return QuicFrame(*pathChallengeRes);
    }
    case FrameType::PATH_RESPONSE: {
      auto pathResponseRes = decodePathResponseFrame(contiguousCursor);
      if (!pathResponseRes.has_value()) {
        return quic::make_unexpected(pathResponseRes.error());
      }
      queue.trimStart(contiguousCursor.getCurrentPosition());
      return QuicFrame(*pathResponseRes);
    }
    case FrameType::CONNECTION_CLOSE: {
      auto connCloseRes = decodeConnectionCloseFrame(contiguousCursor);
      if (!connCloseRes.has_value()) {
        return quic::make_unexpected(connCloseRes.error());
      }
      queue.trimStart(contiguousCursor.getCurrentPosition());
      return QuicFrame(*connCloseRes);
    }
    case FrameType::CONNECTION_CLOSE_APP_ERR: {
      auto appCloseRes = decodeApplicationClose(contiguousCursor);
      if (!appCloseRes.has_value()) {
        return quic::make_unexpected(appCloseRes.error());
      }
      queue.trimStart(contiguousCursor.getCurrentPosition());
      return QuicFrame(*appCloseRes);
    }
    case FrameType::HANDSHAKE_DONE: {
      auto handshakeDoneRes = decodeHandshakeDoneFrame(contiguousCursor);
      if (!handshakeDoneRes.has_value()) {
        return quic::make_unexpected(handshakeDoneRes.error());
      }
      queue.trimStart(contiguousCursor.getCurrentPosition());
      return QuicFrame(*handshakeDoneRes);
    }
    case FrameType::DATAGRAM: {
      auto datagramRes = decodeDatagramFrame(queue, false /* hasLen */);
      if (!datagramRes.has_value()) {
        return quic::make_unexpected(datagramRes.error());
      }
      return QuicFrame(*datagramRes);
    }
    case FrameType::DATAGRAM_LEN: {
      auto datagramRes = decodeDatagramFrame(queue, true /* hasLen */);
      if (!datagramRes.has_value()) {
        return quic::make_unexpected(datagramRes.error());
      }
      return QuicFrame(*datagramRes);
    }
    case FrameType::KNOB: {
      auto knobRes = decodeKnobFrame(contiguousCursor);
      if (knobRes.hasError()) {
        return knobRes;
      }
      queue.trimStart(contiguousCursor.getCurrentPosition());
      return QuicFrame(*knobRes);
    }
    case FrameType::ACK_FREQUENCY: {
      auto ackFreqRes = decodeAckFrequencyFrame(contiguousCursor);
      if (!ackFreqRes.has_value()) {
        return quic::make_unexpected(ackFreqRes.error());
      }
      queue.trimStart(contiguousCursor.getCurrentPosition());
      return QuicFrame(*ackFreqRes);
    }
    case FrameType::IMMEDIATE_ACK: {
      auto immediateAckRes = decodeImmediateAckFrame(contiguousCursor);
      if (!immediateAckRes.has_value()) {
        return quic::make_unexpected(immediateAckRes.error());
      }
      queue.trimStart(contiguousCursor.getCurrentPosition());
      return QuicFrame(*immediateAckRes);
    }
    case FrameType::ACK_RECEIVE_TIMESTAMPS: {
      auto ackWithReceiveTiemstampsRes = decodeAckFrameWithReceivedTimestamps(
          contiguousCursor, header, params, FrameType::ACK_RECEIVE_TIMESTAMPS);
      if (ackWithReceiveTiemstampsRes.hasError()) {
        return ackWithReceiveTiemstampsRes;
      }
      queue.trimStart(contiguousCursor.getCurrentPosition());
      return ackWithReceiveTiemstampsRes;
    }
    case FrameType::ACK_EXTENDED: {
      auto ackExtRes = decodeAckExtendedFrame(contiguousCursor, header, params);
      if (!ackExtRes.has_value()) {
        return quic::make_unexpected(ackExtRes.error());
      }
      queue.trimStart(contiguousCursor.getCurrentPosition());
      return QuicFrame(*ackExtRes);
    }
  }

  return quic::make_unexpected(QuicError(
      TransportErrorCode::FRAME_ENCODING_ERROR,
      fmt::format("Unknown frame, type={}", frameTypeInt->first)));
}

// Parse packet

quic::Expected<RegularQuicPacket, QuicError> decodeRegularPacket(
    PacketHeader&& header,
    const CodecParameters& params,
    BufPtr packetData) {
  RegularQuicPacket packet(std::move(header));
  BufQueue queue;
  queue.append(std::move(packetData));
  if (UNLIKELY(queue.chainLength() == 0)) {
    return packet;
  }
  // Parse out one packet before any conditionals.
  auto frameRes = parseFrame(queue, packet.header, params);
  if (!frameRes.has_value()) {
    return quic::make_unexpected(frameRes.error());
  }
  packet.frames.push_back(std::move(*frameRes));

  while (queue.chainLength() > 0) {
    auto fRes = parseFrame(queue, packet.header, params);
    if (!fRes.has_value()) {
      return quic::make_unexpected(fRes.error());
    }
    if (packet.frames.back().asPaddingFrame() && fRes->asPaddingFrame()) {
      packet.frames.back().asPaddingFrame()->numFrames++;
    } else {
      packet.frames.push_back(std::move(*fRes));
    }
  }
  return packet;
}

Optional<VersionNegotiationPacket> decodeVersionNegotiation(
    const ParsedLongHeaderInvariant& longHeaderInvariant,
    ContiguousReadCursor& cursor) {
  auto cursorLength = cursor.remaining();

  if (cursorLength < sizeof(QuicVersionType) ||
      cursorLength % sizeof(QuicVersionType)) {
    MVVLOG(4) << "Version negotiation packet invalid";
    return std::nullopt;
  }

  VersionNegotiationPacket packet(
      longHeaderInvariant.initialByte,
      longHeaderInvariant.invariant.srcConnId,
      longHeaderInvariant.invariant.dstConnId);

  while (!cursor.isAtEnd()) {
    QuicVersionType versionType = 0;
    cursor.tryReadBE(versionType);
    auto quicVersion = static_cast<QuicVersion>(versionType);
    packet.versions.push_back(quicVersion);
  }

  return packet;
}

ParsedLongHeaderResult::ParsedLongHeaderResult(
    bool isVersionNegotiationIn,
    Optional<ParsedLongHeader> parsedLongHeaderIn)
    : isVersionNegotiation(isVersionNegotiationIn),
      parsedLongHeader(std::move(parsedLongHeaderIn)) {
  MVCHECK(isVersionNegotiation || parsedLongHeader);
}

ParsedLongHeaderInvariant::ParsedLongHeaderInvariant(
    uint8_t initialByteIn,
    LongHeaderInvariant headerInvariant,
    size_t length)
    : initialByte(initialByteIn),
      invariant(std::move(headerInvariant)),
      invariantLength(length) {}

quic::Expected<ParsedLongHeaderInvariant, TransportErrorCode>
parseLongHeaderInvariant(uint8_t initialByte, ContiguousReadCursor& cursor) {
  size_t initialLength = cursor.remaining();
  QuicVersionType versionType = 0;
  if (!cursor.tryReadBE(versionType)) {
    MVVLOG(5) << "Not enough input bytes to read Version or connection-id";
    return quic::make_unexpected(TransportErrorCode::FRAME_ENCODING_ERROR);
  }
  auto version = static_cast<QuicVersion>(versionType);
  uint8_t destConnIdLen = 0;
  if (!cursor.tryReadBE(destConnIdLen)) {
    MVVLOG(5) << "Not enough input bytes to read Dest. ConnectionId length";
    return quic::make_unexpected(TransportErrorCode::FRAME_ENCODING_ERROR);
  }
  if (destConnIdLen > kMaxConnectionIdSize) {
    MVVLOG(5) << "destConnIdLen > kMaxConnectionIdSize: " << destConnIdLen;
    return quic::make_unexpected(TransportErrorCode::PROTOCOL_VIOLATION);
  }
  if (!cursor.canAdvance(destConnIdLen)) {
    MVVLOG(5) << "Not enough input bytes to read Dest. ConnectionId";
    return quic::make_unexpected(TransportErrorCode::FRAME_ENCODING_ERROR);
  }
  auto destConnIdResult = ConnectionId::create(cursor, destConnIdLen);
  if (destConnIdResult.hasError()) {
    return quic::make_unexpected(TransportErrorCode::FRAME_ENCODING_ERROR);
  }
  ConnectionId destConnId = destConnIdResult.value();
  uint8_t srcConnIdLen = 0;
  if (!cursor.tryReadBE(srcConnIdLen)) {
    MVVLOG(5) << "Not enough input bytes to read Source ConnectionId length";
    return quic::make_unexpected(TransportErrorCode::FRAME_ENCODING_ERROR);
  }
  if (srcConnIdLen > kMaxConnectionIdSize) {
    MVVLOG(5) << "srcConnIdLen > kMaxConnectionIdSize: " << srcConnIdLen;
    return quic::make_unexpected(TransportErrorCode::PROTOCOL_VIOLATION);
  }
  if (!cursor.canAdvance(srcConnIdLen)) {
    MVVLOG(5) << "Not enough input bytes to read Source ConnectionId";
    return quic::make_unexpected(TransportErrorCode::FRAME_ENCODING_ERROR);
  }
  auto srcConnIdResult = ConnectionId::create(cursor, srcConnIdLen);
  if (srcConnIdResult.hasError()) {
    return quic::make_unexpected(TransportErrorCode::FRAME_ENCODING_ERROR);
  }
  ConnectionId srcConnId = srcConnIdResult.value();
  size_t currentLength = cursor.remaining();
  size_t bytesRead = initialLength - currentLength;
  return ParsedLongHeaderInvariant(
      initialByte,
      LongHeaderInvariant(version, std::move(srcConnId), std::move(destConnId)),
      bytesRead);
}

LongHeader::Types parseLongHeaderType(uint8_t initialByte) {
  return static_cast<LongHeader::Types>(
      (initialByte & LongHeader::kPacketTypeMask) >> LongHeader::kTypeShift);
}

size_t parsePacketNumberLength(uint8_t initialByte) {
  static_assert(
      LongHeader::kPacketNumLenMask == ShortHeader::kPacketNumLenMask,
      "Expected both pn masks are the same");
  return (initialByte & LongHeader::kPacketNumLenMask) + 1;
}

/**
 * Returns the packet number and the length of the packet number
 */
std::pair<PacketNum, size_t> parsePacketNumber(
    uint8_t initialByte,
    ByteRange packetNumberRange,
    PacketNum expectedNextPacketNum) {
  size_t packetNumLen = parsePacketNumberLength(initialByte);
  uint32_t encodedPacketNum = 0;
  memcpy(
      reinterpret_cast<char*>(&encodedPacketNum) + sizeof(uint32_t) -
          packetNumLen,
      packetNumberRange.data(),
      packetNumLen);
  uint32_t bigEncodedPacketNum = folly::Endian::big(encodedPacketNum);
  return std::make_pair(
      decodePacketNumber(
          bigEncodedPacketNum, packetNumLen, expectedNextPacketNum),
      packetNumLen);
}

quic::Expected<ParsedLongHeaderResult, TransportErrorCode> parseLongHeader(
    uint8_t initialByte,
    ContiguousReadCursor& cursor) {
  if (getHeaderForm(initialByte) != HeaderForm::Long) {
    MVVLOG(5) << "Bad header form bit";
    return quic::make_unexpected(TransportErrorCode::FRAME_ENCODING_ERROR);
  }
  LongHeader::Types type = parseLongHeaderType(initialByte);
  switch (type) {
    case LongHeader::Types::Initial:
    case LongHeader::Types::Retry:
    case LongHeader::Types::Handshake:
    case LongHeader::Types::ZeroRtt:
      break;
    default:
      return quic::make_unexpected(TransportErrorCode::FRAME_ENCODING_ERROR);
  }

  auto parsedLongHeaderInvariant =
      parseLongHeaderInvariant(initialByte, cursor);
  if (!parsedLongHeaderInvariant) {
    MVVLOG(5) << "Bad invariants fields in long header";
    return quic::make_unexpected(TransportErrorCode::FRAME_ENCODING_ERROR);
  }

  auto version = parsedLongHeaderInvariant->invariant.version;
  if (version == QuicVersion::VERSION_NEGOTIATION) {
    return ParsedLongHeaderResult(true, std::nullopt);
  }
  auto parsedHeader = parseLongHeaderVariants(
      type, std::move(*parsedLongHeaderInvariant), cursor);
  if (!parsedHeader) {
    return quic::make_unexpected(parsedHeader.error());
  }
  return ParsedLongHeaderResult(false, std::move(*parsedHeader));
}

quic::Expected<ParsedLongHeader, TransportErrorCode> parseLongHeaderVariants(
    LongHeader::Types type,
    ParsedLongHeaderInvariant parsedLongHeaderInvariant,
    ContiguousReadCursor& cursor,
    QuicNodeType nodeType) {
  if (type == LongHeader::Types::Retry) {
    // The integrity tag is kRetryIntegrityTagLen bytes in length, and the
    // token must be at least one byte, so the remaining length must
    // be > kRetryIntegrityTagLen.
    if (cursor.remaining() <= kRetryIntegrityTagLen) {
      MVVLOG(5) << "Not enough bytes for retry token";
      return quic::make_unexpected(TransportErrorCode::FRAME_ENCODING_ERROR);
    }

    size_t retryTokenLen = cursor.remaining() - kRetryIntegrityTagLen;
    BufPtr token = BufHelpers::create(retryTokenLen);
    MVCHECK(cursor.tryPull(token->writableData(), retryTokenLen));
    token->append(retryTokenLen);

    return ParsedLongHeader(
        LongHeader(
            type,
            std::move(parsedLongHeaderInvariant.invariant),
            token ? token->toString() : std::string()),
        PacketLength(0, 0));
  }

  // TODO Checking kMinInitialDestinationConnIdLength isn't necessary
  // if this packet is in response to a retry.
  if (type == LongHeader::Types::Initial && nodeType == QuicNodeType::Server &&
      parsedLongHeaderInvariant.invariant.dstConnId.size() <
          kMinInitialDestinationConnIdLength) {
    MVVLOG(5)
        << "Dest Conn-Id length in client initial packet must be >= 8 bytes.";
    return quic::make_unexpected(TransportErrorCode::FRAME_ENCODING_ERROR);
  }

  BufPtr token;
  if (type == LongHeader::Types::Initial) {
    auto tokenLen = quic::decodeQuicInteger(cursor);
    if (!tokenLen) {
      MVVLOG(5) << "Token len not found in Long header";
      return quic::make_unexpected(TransportErrorCode::FRAME_ENCODING_ERROR);
    }
    if (!cursor.canAdvance(tokenLen->first)) {
      MVVLOG(5) << "Not enough input bytes to read input token";
      return quic::make_unexpected(TransportErrorCode::FRAME_ENCODING_ERROR);
    }

    if (tokenLen->first > 0) {
      BufPtr tokenBuf = BufHelpers::create(tokenLen->first);
      MVCHECK(cursor.tryPull(tokenBuf->writableData(), tokenLen->first));
      tokenBuf->append(tokenLen->first);
      token = std::move(tokenBuf);
    }
  }
  auto pktLen = quic::decodeQuicInteger(cursor);
  if (!pktLen) {
    MVVLOG(5) << "Packet len not found in Long header";
    return quic::make_unexpected(TransportErrorCode::FRAME_ENCODING_ERROR);
  }
  if (!cursor.canAdvance(pktLen->first)) {
    MVVLOG(5) << "Not enough input bytes to read packet number";
    return quic::make_unexpected(TransportErrorCode::FRAME_ENCODING_ERROR);
  }
  size_t packetNumLen =
      parsePacketNumberLength(parsedLongHeaderInvariant.initialByte);
  if (!cursor.canAdvance(packetNumLen)) {
    return quic::make_unexpected(TransportErrorCode::FRAME_ENCODING_ERROR);
  }
  if (packetNumLen > kMaxPacketNumEncodingSize) {
    return quic::make_unexpected(TransportErrorCode::FRAME_ENCODING_ERROR);
  }
  return ParsedLongHeader(
      LongHeader(
          type,
          std::move(parsedLongHeaderInvariant.invariant),
          token ? token->toString() : std::string()),
      PacketLength(pktLen->first, pktLen->second));
}

quic::Expected<ShortHeaderInvariant, TransportErrorCode>
parseShortHeaderInvariants(
    uint8_t initialByte,
    ContiguousReadCursor& cursor,
    size_t dstConnIdSize) {
  if (getHeaderForm(initialByte) != HeaderForm::Short) {
    MVVLOG(5) << "Bad header form bit";
    return quic::make_unexpected(TransportErrorCode::FRAME_ENCODING_ERROR);
  }
  // TODO(t39154014, yangchi): read the length from the connection state in
  // draft-17
  if (dstConnIdSize > kMaxConnectionIdSize) {
    MVVLOG(5) << "dstConnIdSize > kMaxConnectionIdSize: " << dstConnIdSize;
    return quic::make_unexpected(TransportErrorCode::PROTOCOL_VIOLATION);
  }
  if (!cursor.canAdvance(dstConnIdSize)) {
    MVVLOG(5) << "Not enough input bytes for ConnectionId";
    return quic::make_unexpected(TransportErrorCode::FRAME_ENCODING_ERROR);
  }
  auto connIdResult = ConnectionId::create(cursor, dstConnIdSize);
  if (connIdResult.hasError()) {
    return quic::make_unexpected(TransportErrorCode::FRAME_ENCODING_ERROR);
  }
  ConnectionId connId = connIdResult.value();
  return ShortHeaderInvariant(std::move(connId));
}

quic::Expected<ShortHeader, TransportErrorCode> parseShortHeader(
    uint8_t initialByte,
    ContiguousReadCursor& cursor,
    size_t dstConnIdSize) {
  if (getHeaderForm(initialByte) != HeaderForm::Short) {
    MVVLOG(5) << "Bad header form bit";
    return quic::make_unexpected(TransportErrorCode::FRAME_ENCODING_ERROR);
  }
  if (!(initialByte & ShortHeader::kFixedBitMask)) {
    MVVLOG(5) << "Fixed bit in ShortHeader is 0";
    // Specs doesn't say which error code to use
    return quic::make_unexpected(TransportErrorCode::FRAME_ENCODING_ERROR);
  }
  if (initialByte & ShortHeader::kReservedBitsMask) {
    MVVLOG(5) << "Non-zero reserved bits in ShortHeader";
    // Specs asks this to be PROTOCOL_VIOLATION
    return quic::make_unexpected(TransportErrorCode::PROTOCOL_VIOLATION);
  }
  auto invariant =
      parseShortHeaderInvariants(initialByte, cursor, dstConnIdSize);
  if (!invariant) {
    MVVLOG(5) << "Error parsing short header invariant";
    return quic::make_unexpected(TransportErrorCode::FRAME_ENCODING_ERROR);
  }
  auto protectionType = initialByte & ShortHeader::kKeyPhaseMask
      ? ProtectionType::KeyPhaseOne
      : ProtectionType::KeyPhaseZero;
  return ShortHeader(protectionType, std::move(invariant->destinationConnId));
}

} // namespace quic
