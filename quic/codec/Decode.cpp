/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <quic/codec/Decode.h>

#include <quic/QuicConstants.h>
#include <quic/QuicException.h>
#include <quic/codec/PacketNumber.h>
#include <quic/codec/QuicInteger.h>
#include <chrono>
#include <cstdint>

namespace {

folly::Expected<quic::PacketNum, quic::QuicError> nextAckedPacketGap(
    quic::PacketNum packetNum,
    uint64_t gap) noexcept {
  // Gap cannot overflow because of the definition of quic integer encoding, so
  // we can just add to gap.
  uint64_t adjustedGap = gap + 2;
  if (packetNum < adjustedGap) {
    return folly::makeUnexpected(quic::QuicError(
        quic::TransportErrorCode::FRAME_ENCODING_ERROR, "Bad gap"));
  }
  return packetNum - adjustedGap;
}

folly::Expected<quic::PacketNum, quic::QuicError> nextAckedPacketLen(
    quic::PacketNum packetNum,
    uint64_t ackBlockLen) noexcept {
  // Going to allow 0 as a valid value.
  if (packetNum < ackBlockLen) {
    return folly::makeUnexpected(quic::QuicError(
        quic::TransportErrorCode::FRAME_ENCODING_ERROR, "Bad block len"));
  }
  return packetNum - ackBlockLen;
}

} // namespace

namespace quic {

folly::Expected<PaddingFrame, QuicError> decodePaddingFrame(
    folly::io::Cursor& cursor) {
  // we might have multiple padding frames in sequence in the common case.
  // Let's consume all the padding and return 1 padding frame for everything.
  static_assert(
      static_cast<int>(FrameType::PADDING) == 0, "Padding value is 0");
  folly::ByteRange paddingBytes = cursor.peekBytes();
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

folly::Expected<PingFrame, QuicError> decodePingFrame(folly::io::Cursor&) {
  return PingFrame();
}

folly::Expected<QuicFrame, QuicError> decodeKnobFrame(
    folly::io::Cursor& cursor) {
  auto knobSpace = decodeQuicInteger(cursor);
  if (!knobSpace) {
    return folly::makeUnexpected(QuicError(
        quic::TransportErrorCode::FRAME_ENCODING_ERROR, "Bad knob space"));
  }
  auto knobId = decodeQuicInteger(cursor);
  if (!knobId) {
    return folly::makeUnexpected(QuicError(
        quic::TransportErrorCode::FRAME_ENCODING_ERROR, "Bad knob id"));
  }
  auto knobLen = decodeQuicInteger(cursor);
  if (!knobLen) {
    return folly::makeUnexpected(QuicError(
        quic::TransportErrorCode::FRAME_ENCODING_ERROR, "Bad knob len"));
  }
  Buf knobBlob;
  cursor.cloneAtMost(knobBlob, knobLen->first);
  return QuicFrame(
      KnobFrame(knobSpace->first, knobId->first, std::move(knobBlob)));
}

folly::Expected<QuicSimpleFrame, QuicError> decodeAckFrequencyFrame(
    folly::io::Cursor& cursor) {
  auto sequenceNumber = decodeQuicInteger(cursor);
  if (!sequenceNumber) {
    return folly::makeUnexpected(QuicError(
        quic::TransportErrorCode::FRAME_ENCODING_ERROR, "Bad sequence number"));
  }
  auto packetTolerance = decodeQuicInteger(cursor);
  if (!packetTolerance) {
    return folly::makeUnexpected(QuicError(
        quic::TransportErrorCode::FRAME_ENCODING_ERROR,
        "Bad packet tolerance"));
  }
  auto updateMaxAckDelay = decodeQuicInteger(cursor);
  if (!updateMaxAckDelay) {
    return folly::makeUnexpected(QuicError(
        quic::TransportErrorCode::FRAME_ENCODING_ERROR,
        "Bad update max ack delay"));
  }
  auto reorderThreshold = decodeQuicInteger(cursor);
  if (!reorderThreshold) {
    return folly::makeUnexpected(QuicError(
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

folly::Expected<ImmediateAckFrame, QuicError> decodeImmediateAckFrame(
    folly::io::Cursor&) {
  return ImmediateAckFrame();
}

folly::Expected<uint64_t, QuicError> convertEncodedDurationToMicroseconds(
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
    return folly::makeUnexpected(QuicError(
        quic::TransportErrorCode::FRAME_ENCODING_ERROR,
        "Decoded delay overflows"));
  }
  uint64_t adjustedDelay = delay << exponentToUse;
  if (adjustedDelay >
      static_cast<uint64_t>(
          std::numeric_limits<std::chrono::microseconds::rep>::max())) {
    return folly::makeUnexpected(
        QuicError(quic::TransportErrorCode::FRAME_ENCODING_ERROR, "Bad delay"));
  }
  return adjustedDelay;
}

folly::Expected<ReadAckFrame, QuicError> decodeAckFrame(
    folly::io::Cursor& cursor,
    const PacketHeader& header,
    const CodecParameters& params,
    FrameType frameType) {
  ReadAckFrame frame;
  frame.frameType = frameType;
  auto largestAckedInt = decodeQuicInteger(cursor);
  if (!largestAckedInt) {
    return folly::makeUnexpected(QuicError(
        quic::TransportErrorCode::FRAME_ENCODING_ERROR, "Bad largest acked"));
  }
  auto largestAcked = folly::to<PacketNum>(largestAckedInt->first);
  auto ackDelay = decodeQuicInteger(cursor);
  if (!ackDelay) {
    return folly::makeUnexpected(QuicError(
        quic::TransportErrorCode::FRAME_ENCODING_ERROR, "Bad ack delay"));
  }
  auto additionalAckBlocks = decodeQuicInteger(cursor);
  if (!additionalAckBlocks) {
    return folly::makeUnexpected(QuicError(
        quic::TransportErrorCode::FRAME_ENCODING_ERROR, "Bad ack block count"));
  }
  auto firstAckBlockLen = decodeQuicInteger(cursor);
  if (!firstAckBlockLen) {
    return folly::makeUnexpected(QuicError(
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
    return folly::makeUnexpected(res.error());
  }
  PacketNum currentPacketNum = *res;
  frame.largestAcked = largestAcked;

  auto delayRes = convertEncodedDurationToMicroseconds(
      ackDelayExponentToUse, ackDelay->first);
  if (delayRes.hasError()) {
    return folly::makeUnexpected(delayRes.error());
  }
  auto adjustedDelay = *delayRes;

  if (UNLIKELY(adjustedDelay > 1000 * 1000 * 1000 /* 1000s */)) {
    LOG(ERROR) << "Quic recvd long ack delay=" << adjustedDelay
               << " frame type: " << static_cast<uint64_t>(frameType);
    adjustedDelay = 0;
  }
  frame.ackDelay = std::chrono::microseconds(adjustedDelay);

  frame.ackBlocks.emplace_back(currentPacketNum, largestAcked);
  for (uint64_t numBlocks = 0; numBlocks < additionalAckBlocks->first;
       ++numBlocks) {
    auto currentGap = decodeQuicInteger(cursor);
    if (!currentGap) {
      return folly::makeUnexpected(
          QuicError(quic::TransportErrorCode::FRAME_ENCODING_ERROR, "Bad gap"));
    }
    auto blockLen = decodeQuicInteger(cursor);
    if (!blockLen) {
      return folly::makeUnexpected(QuicError(
          quic::TransportErrorCode::FRAME_ENCODING_ERROR, "Bad block len"));
    }
    res = nextAckedPacketGap(currentPacketNum, currentGap->first);
    if (res.hasError()) {
      return folly::makeUnexpected(res.error());
    }
    PacketNum nextEndPacket = *res;
    res = nextAckedPacketLen(nextEndPacket, blockLen->first);
    if (res.hasError()) {
      return folly::makeUnexpected(res.error());
    }
    currentPacketNum = *res;
    // We don't need to add the entry when the block length is zero since we
    // already would have processed it in the previous iteration.
    frame.ackBlocks.emplace_back(currentPacketNum, nextEndPacket);
  }

  return frame;
}

static folly::Expected<folly::Unit, QuicError> decodeReceiveTimestampsInAck(
    ReadAckFrame& frame,
    folly::io::Cursor& cursor,
    const CodecParameters& params) {
  auto latestRecvdPacketNum = decodeQuicInteger(cursor);
  if (!latestRecvdPacketNum) {
    return folly::makeUnexpected(QuicError(
        quic::TransportErrorCode::FRAME_ENCODING_ERROR,
        "Bad latest received packet number"));
  }
  frame.maybeLatestRecvdPacketNum = latestRecvdPacketNum->first;

  auto latestRecvdPacketTimeDelta = decodeQuicInteger(cursor);
  if (!latestRecvdPacketTimeDelta) {
    return folly::makeUnexpected(QuicError(
        quic::TransportErrorCode::FRAME_ENCODING_ERROR,
        "Bad receive packet timestamp delta"));
  }
  frame.maybeLatestRecvdPacketTime =
      std::chrono::microseconds(latestRecvdPacketTimeDelta->first);

  auto timeStampRangeCount = decodeQuicInteger(cursor);
  if (!timeStampRangeCount) {
    return folly::makeUnexpected(QuicError(
        quic::TransportErrorCode::FRAME_ENCODING_ERROR,
        "Bad receive timestamps range count"));
  }
  for (uint64_t numRanges = 0; numRanges < timeStampRangeCount->first;
       numRanges++) {
    RecvdPacketsTimestampsRange timeStampRange;
    auto receiveTimeStampsGap = decodeQuicInteger(cursor);
    if (!receiveTimeStampsGap) {
      return folly::makeUnexpected(QuicError(
          quic::TransportErrorCode::FRAME_ENCODING_ERROR,
          "Bad receive timestamps gap"));
    }
    timeStampRange.gap = receiveTimeStampsGap->first;
    auto receiveTimeStampsLen = decodeQuicInteger(cursor);
    if (!receiveTimeStampsLen) {
      return folly::makeUnexpected(QuicError(
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
      auto delta = decodeQuicInteger(cursor);
      if (!delta) {
        return folly::makeUnexpected(QuicError(
            quic::TransportErrorCode::FRAME_ENCODING_ERROR,
            "Bad receive timestamps delta"));
      }
      DCHECK_LT(receiveTimestampsExponentToUse, sizeof(delta->first) * 8);
      auto res = convertEncodedDurationToMicroseconds(
          receiveTimestampsExponentToUse, delta->first);
      if (res.hasError()) {
        return folly::makeUnexpected(res.error());
      }
      auto adjustedDelta = *res;
      timeStampRange.deltas.push_back(adjustedDelta);
    }
    frame.recvdPacketsTimestampRanges.emplace_back(timeStampRange);
  }
  return folly::unit;
}

static folly::Expected<folly::Unit, QuicError> decodeEcnCountsInAck(
    ReadAckFrame& frame,
    folly::io::Cursor& cursor) {
  auto ect_0 = decodeQuicInteger(cursor);
  auto ect_1 = decodeQuicInteger(cursor);
  auto ce = decodeQuicInteger(cursor);
  if (!ect_0 || !ect_1 || !ce) {
    return folly::makeUnexpected(QuicError(
        quic::TransportErrorCode::FRAME_ENCODING_ERROR, "Bad ECN value"));
  }
  frame.ecnECT0Count = ect_0->first;
  frame.ecnECT1Count = ect_1->first;
  frame.ecnCECount = ce->first;
  return folly::unit;
}

folly::Expected<ReadAckFrame, QuicError> decodeAckExtendedFrame(
    folly::io::Cursor& cursor,
    const PacketHeader& header,
    const CodecParameters& params) {
  ReadAckFrame frame;
  auto res = decodeAckFrame(cursor, header, params, FrameType::ACK_EXTENDED);
  if (res.hasError()) {
    return folly::makeUnexpected(res.error());
  }
  frame = *res;
  auto extendedAckFeatures = decodeQuicInteger(cursor);
  if (!extendedAckFeatures) {
    return folly::makeUnexpected(QuicError(
        quic::TransportErrorCode::FRAME_ENCODING_ERROR,
        "Bad extended ACK features field"));
  }
  auto includedFeatures = extendedAckFeatures->first;
  if ((includedFeatures | params.extendedAckFeatures) !=
      params.extendedAckFeatures) {
    return folly::makeUnexpected(QuicError(
        quic::TransportErrorCode::FRAME_ENCODING_ERROR,
        "Extended ACK has unexpected features"));
  }
  if (includedFeatures &
      static_cast<ExtendedAckFeatureMaskType>(
          ExtendedAckFeatureMask::ECN_COUNTS)) {
    auto ecnResult = decodeEcnCountsInAck(frame, cursor);
    if (ecnResult.hasError()) {
      return folly::makeUnexpected(ecnResult.error());
    }
  }
  if (includedFeatures &
      static_cast<ExtendedAckFeatureMaskType>(
          ExtendedAckFeatureMask::RECEIVE_TIMESTAMPS)) {
    auto tsResult = decodeReceiveTimestampsInAck(frame, cursor, params);
    if (tsResult.hasError()) {
      return folly::makeUnexpected(tsResult.error());
    }
  }
  return frame;
}

folly::Expected<QuicFrame, QuicError> decodeAckFrameWithReceivedTimestamps(
    folly::io::Cursor& cursor,
    const PacketHeader& header,
    const CodecParameters& params,
    FrameType frameType) {
  ReadAckFrame frame;

  auto ack = decodeAckFrame(cursor, header, params, frameType);
  if (ack.hasError()) {
    return folly::makeUnexpected(ack.error());
  }
  frame = *ack;
  frame.frameType = frameType;

  auto ts = decodeReceiveTimestampsInAck(frame, cursor, params);
  if (ts.hasError()) {
    return folly::makeUnexpected(ts.error());
  }

  return QuicFrame(frame);
}

folly::Expected<QuicFrame, QuicError> decodeAckFrameWithECN(
    folly::io::Cursor& cursor,
    const PacketHeader& header,
    const CodecParameters& params) {
  ReadAckFrame readAckFrame;

  auto ack = decodeAckFrame(cursor, header, params);
  if (ack.hasError()) {
    return folly::makeUnexpected(ack.error());
  }
  readAckFrame = *ack;
  readAckFrame.frameType = FrameType::ACK_ECN;

  auto ecn = decodeEcnCountsInAck(readAckFrame, cursor);
  if (ecn.hasError()) {
    return folly::makeUnexpected(ecn.error());
  }

  return QuicFrame(readAckFrame);
}

folly::Expected<RstStreamFrame, QuicError> decodeRstStreamFrame(
    folly::io::Cursor& cursor,
    bool reliable) {
  auto streamId = decodeQuicInteger(cursor);
  if (!streamId) {
    return folly::makeUnexpected(QuicError(
        quic::TransportErrorCode::FRAME_ENCODING_ERROR, "Bad streamId"));
  }
  ApplicationErrorCode errorCode;
  auto varCode = decodeQuicInteger(cursor);
  if (varCode) {
    errorCode = static_cast<ApplicationErrorCode>(varCode->first);
  } else {
    return folly::makeUnexpected(QuicError(
        quic::TransportErrorCode::FRAME_ENCODING_ERROR,
        "Cannot decode error code"));
  }
  auto finalSize = decodeQuicInteger(cursor);
  if (!finalSize) {
    return folly::makeUnexpected(QuicError(
        quic::TransportErrorCode::FRAME_ENCODING_ERROR, "Bad offset"));
  }
  folly::Optional<std::pair<uint64_t, size_t>> reliableSize = folly::none;
  if (reliable) {
    reliableSize = decodeQuicInteger(cursor);
    if (!reliableSize) {
      return folly::makeUnexpected(QuicError(
          quic::TransportErrorCode::FRAME_ENCODING_ERROR,
          "Bad value of reliable size"));
    }

    if (reliableSize->first > finalSize->first) {
      return folly::makeUnexpected(QuicError(
          quic::TransportErrorCode::FRAME_ENCODING_ERROR,
          "Reliable size is greater than final size"));
    }
  }
  return RstStreamFrame(
      folly::to<StreamId>(streamId->first),
      errorCode,
      finalSize->first,
      reliableSize ? folly::Optional<uint64_t>(reliableSize->first)
                   : folly::none);
}

folly::Expected<StopSendingFrame, QuicError> decodeStopSendingFrame(
    folly::io::Cursor& cursor) {
  auto streamId = decodeQuicInteger(cursor);
  if (!streamId) {
    return folly::makeUnexpected(QuicError(
        quic::TransportErrorCode::FRAME_ENCODING_ERROR, "Bad streamId"));
  }
  ApplicationErrorCode errorCode;
  auto varCode = decodeQuicInteger(cursor);
  if (varCode) {
    errorCode = static_cast<ApplicationErrorCode>(varCode->first);
  } else {
    return folly::makeUnexpected(QuicError(
        quic::TransportErrorCode::FRAME_ENCODING_ERROR,
        "Cannot decode error code"));
  }
  return StopSendingFrame(folly::to<StreamId>(streamId->first), errorCode);
}

folly::Expected<ReadCryptoFrame, QuicError> decodeCryptoFrame(
    folly::io::Cursor& cursor) {
  auto optionalOffset = decodeQuicInteger(cursor);
  if (!optionalOffset) {
    return folly::makeUnexpected(QuicError(
        quic::TransportErrorCode::FRAME_ENCODING_ERROR, "Invalid offset"));
  }
  uint64_t offset = optionalOffset->first;

  auto dataLength = decodeQuicInteger(cursor);
  if (!dataLength) {
    return folly::makeUnexpected(QuicError(
        quic::TransportErrorCode::FRAME_ENCODING_ERROR, "Invalid length"));
  }
  Buf data;
  if (cursor.totalLength() < dataLength->first) {
    return folly::makeUnexpected(QuicError(
        quic::TransportErrorCode::FRAME_ENCODING_ERROR, "Length mismatch"));
  }

  size_t cloned = cursor.cloneAtMost(data, dataLength->first);
  if (cloned < dataLength->first) {
    return folly::makeUnexpected(QuicError(
        quic::TransportErrorCode::FRAME_ENCODING_ERROR,
        "Failed to clone complete data"));
  }

  return ReadCryptoFrame(offset, std::move(data));
}

folly::Expected<ReadNewTokenFrame, QuicError> decodeNewTokenFrame(
    folly::io::Cursor& cursor) {
  auto tokenLength = decodeQuicInteger(cursor);
  if (!tokenLength) {
    return folly::makeUnexpected(QuicError(
        quic::TransportErrorCode::FRAME_ENCODING_ERROR, "Invalid length"));
  }
  Buf token;
  if (cursor.totalLength() < tokenLength->first) {
    return folly::makeUnexpected(QuicError(
        quic::TransportErrorCode::FRAME_ENCODING_ERROR, "Length mismatch"));
  }

  size_t cloned = cursor.cloneAtMost(token, tokenLength->first);
  if (cloned < tokenLength->first) {
    return folly::makeUnexpected(QuicError(
        quic::TransportErrorCode::FRAME_ENCODING_ERROR,
        "Failed to clone token"));
  }

  return ReadNewTokenFrame(std::move(token));
}

folly::Expected<ReadStreamFrame, QuicError> decodeStreamFrame(
    BufQueue& queue,
    StreamTypeField frameTypeField,
    bool isGroupFrame) {
  folly::io::Cursor cursor(queue.front());

  auto streamId = decodeQuicInteger(cursor);
  if (!streamId) {
    return folly::makeUnexpected(QuicError(
        quic::TransportErrorCode::FRAME_ENCODING_ERROR, "Invalid stream id"));
  }

  OptionalIntegral<StreamGroupId> groupId;
  if (isGroupFrame) {
    auto gId = decodeQuicInteger(cursor);
    if (!gId) {
      return folly::makeUnexpected(QuicError(
          quic::TransportErrorCode::FRAME_ENCODING_ERROR,
          "Invalid group stream id"));
    }
    groupId = gId->first;
  }

  uint64_t offset = 0;
  if (frameTypeField.hasOffset()) {
    auto optionalOffset = decodeQuicInteger(cursor);
    if (!optionalOffset) {
      return folly::makeUnexpected(QuicError(
          quic::TransportErrorCode::FRAME_ENCODING_ERROR, "Invalid offset"));
    }
    offset = optionalOffset->first;
  }
  auto fin = frameTypeField.hasFin();
  Optional<std::pair<uint64_t, size_t>> dataLength;
  if (frameTypeField.hasDataLength()) {
    dataLength = decodeQuicInteger(cursor);
    if (!dataLength) {
      return folly::makeUnexpected(QuicError(
          quic::TransportErrorCode::FRAME_ENCODING_ERROR, "Invalid length"));
    }
  }
  Buf data;

  // Calculate how much to trim from the start of the queue
  size_t trimAmount = cursor - queue.front();
  if (trimAmount > 0) {
    size_t trimmed = queue.trimStartAtMost(trimAmount);
    if (trimmed < trimAmount) {
      return folly::makeUnexpected(QuicError(
          quic::TransportErrorCode::FRAME_ENCODING_ERROR,
          "Failed to trim queue"));
    }
  }

  if (dataLength.has_value()) {
    if (queue.chainLength() < dataLength->first) {
      return folly::makeUnexpected(QuicError(
          quic::TransportErrorCode::FRAME_ENCODING_ERROR, "Length mismatch"));
    }
    data = queue.splitAtMost(dataLength->first);
    if (!data || data->computeChainDataLength() < dataLength->first) {
      return folly::makeUnexpected(QuicError(
          quic::TransportErrorCode::FRAME_ENCODING_ERROR,
          "Failed to extract data"));
    }
  } else {
    // Missing Data Length field doesn't mean no data. It means the rest of the
    // frame are all data.
    data = queue.move();
    if (!data) {
      return folly::makeUnexpected(QuicError(
          quic::TransportErrorCode::FRAME_ENCODING_ERROR,
          "Failed to extract data"));
    }
  }
  return ReadStreamFrame(
      folly::to<StreamId>(streamId->first),
      offset,
      std::move(data),
      fin,
      groupId);
}

folly::Expected<MaxDataFrame, QuicError> decodeMaxDataFrame(
    folly::io::Cursor& cursor) {
  auto maximumData = decodeQuicInteger(cursor);
  if (!maximumData) {
    return folly::makeUnexpected(QuicError(
        quic::TransportErrorCode::FRAME_ENCODING_ERROR, "Bad Max Data"));
  }
  return MaxDataFrame(maximumData->first);
}

folly::Expected<MaxStreamDataFrame, QuicError> decodeMaxStreamDataFrame(
    folly::io::Cursor& cursor) {
  auto streamId = decodeQuicInteger(cursor);
  if (!streamId) {
    return folly::makeUnexpected(QuicError(
        quic::TransportErrorCode::FRAME_ENCODING_ERROR, "Invalid streamId"));
  }
  auto offset = decodeQuicInteger(cursor);
  if (!offset) {
    return folly::makeUnexpected(QuicError(
        quic::TransportErrorCode::FRAME_ENCODING_ERROR, "Invalid offset"));
  }
  return MaxStreamDataFrame(
      folly::to<StreamId>(streamId->first), offset->first);
}

folly::Expected<MaxStreamsFrame, QuicError> decodeBiDiMaxStreamsFrame(
    folly::io::Cursor& cursor) {
  auto streamCount = decodeQuicInteger(cursor);
  if (!streamCount || streamCount->first > kMaxMaxStreams) {
    return folly::makeUnexpected(QuicError(
        quic::TransportErrorCode::FRAME_ENCODING_ERROR,
        "Invalid Bi-directional streamId"));
  }
  return MaxStreamsFrame(streamCount->first, true /* isBidirectional*/);
}

folly::Expected<MaxStreamsFrame, QuicError> decodeUniMaxStreamsFrame(
    folly::io::Cursor& cursor) {
  auto streamCount = decodeQuicInteger(cursor);
  if (!streamCount || streamCount->first > kMaxMaxStreams) {
    return folly::makeUnexpected(QuicError(
        quic::TransportErrorCode::FRAME_ENCODING_ERROR,
        "Invalid Uni-directional streamId"));
  }
  return MaxStreamsFrame(streamCount->first, false /* isUnidirectional */);
}

folly::Expected<DataBlockedFrame, QuicError> decodeDataBlockedFrame(
    folly::io::Cursor& cursor) {
  auto dataLimit = decodeQuicInteger(cursor);
  if (!dataLimit) {
    return folly::makeUnexpected(QuicError(
        quic::TransportErrorCode::FRAME_ENCODING_ERROR, "Bad offset"));
  }
  return DataBlockedFrame(dataLimit->first);
}

folly::Expected<StreamDataBlockedFrame, QuicError> decodeStreamDataBlockedFrame(
    folly::io::Cursor& cursor) {
  auto streamId = decodeQuicInteger(cursor);
  if (!streamId) {
    return folly::makeUnexpected(QuicError(
        quic::TransportErrorCode::FRAME_ENCODING_ERROR, "Bad streamId"));
  }
  auto dataLimit = decodeQuicInteger(cursor);
  if (!dataLimit) {
    return folly::makeUnexpected(QuicError(
        quic::TransportErrorCode::FRAME_ENCODING_ERROR, "Bad offset"));
  }
  return StreamDataBlockedFrame(
      folly::to<StreamId>(streamId->first), dataLimit->first);
}

folly::Expected<StreamsBlockedFrame, QuicError> decodeBiDiStreamsBlockedFrame(
    folly::io::Cursor& cursor) {
  auto streamId = decodeQuicInteger(cursor);
  if (!streamId) {
    return folly::makeUnexpected(QuicError(
        quic::TransportErrorCode::FRAME_ENCODING_ERROR,
        "Bad Bi-Directional streamId"));
  }
  return StreamsBlockedFrame(
      folly::to<StreamId>(streamId->first), true /* isBidirectional */);
}

folly::Expected<StreamsBlockedFrame, QuicError> decodeUniStreamsBlockedFrame(
    folly::io::Cursor& cursor) {
  auto streamId = decodeQuicInteger(cursor);
  if (!streamId) {
    return folly::makeUnexpected(QuicError(
        quic::TransportErrorCode::FRAME_ENCODING_ERROR,
        "Bad Uni-direcitonal streamId"));
  }
  return StreamsBlockedFrame(
      folly::to<StreamId>(streamId->first), false /* isBidirectional */);
}

folly::Expected<NewConnectionIdFrame, QuicError> decodeNewConnectionIdFrame(
    folly::io::Cursor& cursor) {
  auto sequenceNumber = decodeQuicInteger(cursor);
  if (!sequenceNumber) {
    return folly::makeUnexpected(QuicError(
        quic::TransportErrorCode::FRAME_ENCODING_ERROR, "Bad sequence"));
  }
  auto retirePriorTo = decodeQuicInteger(cursor);
  if (!retirePriorTo) {
    return folly::makeUnexpected(QuicError(
        quic::TransportErrorCode::FRAME_ENCODING_ERROR, "Bad retire prior to"));
  }
  if (!cursor.canAdvance(sizeof(uint8_t))) {
    return folly::makeUnexpected(QuicError(
        quic::TransportErrorCode::FRAME_ENCODING_ERROR,
        "Not enough input bytes to read Dest. ConnectionId"));
  }
  auto connIdLen = cursor.readBE<uint8_t>();
  if (cursor.totalLength() < connIdLen) {
    return folly::makeUnexpected(QuicError(
        quic::TransportErrorCode::FRAME_ENCODING_ERROR, "Bad connid"));
  }
  if (connIdLen > kMaxConnectionIdSize) {
    return folly::makeUnexpected(QuicError(
        quic::TransportErrorCode::FRAME_ENCODING_ERROR,
        "ConnectionId invalid length"));
  }

  ConnectionId connId(cursor, connIdLen);

  StatelessResetToken statelessResetToken;
  size_t bytesRead =
      cursor.pullAtMost(statelessResetToken.data(), statelessResetToken.size());
  if (bytesRead < statelessResetToken.size()) {
    return folly::makeUnexpected(QuicError(
        quic::TransportErrorCode::FRAME_ENCODING_ERROR,
        "Failed to read StatelessResetToken"));
  }

  return NewConnectionIdFrame(
      sequenceNumber->first,
      retirePriorTo->first,
      std::move(connId),
      std::move(statelessResetToken));
}

folly::Expected<RetireConnectionIdFrame, QuicError>
decodeRetireConnectionIdFrame(folly::io::Cursor& cursor) {
  auto sequenceNum = decodeQuicInteger(cursor);
  if (!sequenceNum) {
    return folly::makeUnexpected(QuicError(
        quic::TransportErrorCode::FRAME_ENCODING_ERROR, "Bad sequence num"));
  }
  return RetireConnectionIdFrame(sequenceNum->first);
}

folly::Expected<PathChallengeFrame, QuicError> decodePathChallengeFrame(
    folly::io::Cursor& cursor) {
  if (!cursor.canAdvance(sizeof(uint64_t))) {
    return folly::makeUnexpected(QuicError(
        quic::TransportErrorCode::FRAME_ENCODING_ERROR,
        "Not enough input bytes to read path challenge frame."));
  }
  auto pathData = cursor.readBE<uint64_t>();
  return PathChallengeFrame(pathData);
}

folly::Expected<PathResponseFrame, QuicError> decodePathResponseFrame(
    folly::io::Cursor& cursor) {
  if (!cursor.canAdvance(sizeof(uint64_t))) {
    return folly::makeUnexpected(QuicError(
        quic::TransportErrorCode::FRAME_ENCODING_ERROR,
        "Not enough input bytes to read path response frame."));
  }
  auto pathData = cursor.readBE<uint64_t>();
  return PathResponseFrame(pathData);
}

folly::Expected<ConnectionCloseFrame, QuicError> decodeConnectionCloseFrame(
    folly::io::Cursor& cursor) {
  TransportErrorCode errorCode{};
  auto varCode = decodeQuicInteger(cursor);
  if (!varCode) {
    return folly::makeUnexpected(QuicError(
        quic::TransportErrorCode::FRAME_ENCODING_ERROR,
        "Failed to parse error code."));
  }
  errorCode = static_cast<TransportErrorCode>(varCode->first);

  auto frameTypeField = decodeQuicInteger(cursor);
  if (!frameTypeField || frameTypeField->second != sizeof(uint8_t)) {
    return folly::makeUnexpected(QuicError(
        quic::TransportErrorCode::FRAME_ENCODING_ERROR,
        "Bad connection close triggering frame type value"));
  }
  FrameType triggeringFrameType = static_cast<FrameType>(frameTypeField->first);

  auto reasonPhraseLength = decodeQuicInteger(cursor);
  if (!reasonPhraseLength ||
      reasonPhraseLength->first > kMaxReasonPhraseLength) {
    return folly::makeUnexpected(QuicError(
        quic::TransportErrorCode::FRAME_ENCODING_ERROR,
        "Bad reason phrase length"));
  }

  std::string reasonPhrase;
  size_t len = static_cast<size_t>(reasonPhraseLength->first);
  auto bytes = cursor.peekBytes();
  size_t available = std::min(bytes.size(), len);
  reasonPhrase.append(reinterpret_cast<const char*>(bytes.data()), available);
  cursor.skip(available);

  return ConnectionCloseFrame(
      QuicErrorCode(errorCode), std::move(reasonPhrase), triggeringFrameType);
}

folly::Expected<ConnectionCloseFrame, QuicError> decodeApplicationClose(
    folly::io::Cursor& cursor) {
  ApplicationErrorCode errorCode{};
  auto varCode = decodeQuicInteger(cursor);
  if (!varCode) {
    return folly::makeUnexpected(QuicError(
        quic::TransportErrorCode::FRAME_ENCODING_ERROR,
        "Failed to parse error code."));
  }
  errorCode = static_cast<ApplicationErrorCode>(varCode->first);

  auto reasonPhraseLength = decodeQuicInteger(cursor);
  if (!reasonPhraseLength ||
      reasonPhraseLength->first > kMaxReasonPhraseLength) {
    return folly::makeUnexpected(QuicError(
        quic::TransportErrorCode::FRAME_ENCODING_ERROR,
        "Bad reason phrase length"));
  }

  std::string reasonPhrase;
  size_t len = static_cast<size_t>(reasonPhraseLength->first);
  auto bytes = cursor.peekBytes();
  size_t available = std::min(bytes.size(), len);
  reasonPhrase.append(reinterpret_cast<const char*>(bytes.data()), available);
  cursor.skip(available);

  return ConnectionCloseFrame(
      QuicErrorCode(errorCode), std::move(reasonPhrase));
}

folly::Expected<HandshakeDoneFrame, QuicError> decodeHandshakeDoneFrame(
    folly::io::Cursor& /*cursor*/) {
  return HandshakeDoneFrame();
}

/**
 * Both retry and new tokens have the same plaintext encoding: timestamp. We
 * differentiate tokens based on the success of decrypting with differing aead
 * associated data.
 */
folly::Expected<uint64_t, TransportErrorCode> parsePlaintextRetryOrNewToken(
    folly::io::Cursor& cursor) {
  // Read in the timestamp
  if (!cursor.canAdvance(sizeof(uint64_t))) {
    return folly::makeUnexpected(TransportErrorCode::INVALID_TOKEN);
  }
  auto timestampInMs = cursor.readBE<uint64_t>();

  return timestampInMs;
}

folly::Expected<DatagramFrame, QuicError> decodeDatagramFrame(
    BufQueue& queue,
    bool hasLen) {
  folly::io::Cursor cursor(queue.front());
  size_t length = cursor.length();
  if (hasLen) {
    auto decodeLength = decodeQuicInteger(cursor);
    if (!decodeLength) {
      return folly::makeUnexpected(QuicError(
          TransportErrorCode::FRAME_ENCODING_ERROR, "Invalid datagram len"));
    }
    length = decodeLength->first;
    if (cursor.length() < length) {
      return folly::makeUnexpected(QuicError(
          TransportErrorCode::FRAME_ENCODING_ERROR, "Invalid datagram frame"));
    }
    queue.trimStart(decodeLength->second);
  }
  return DatagramFrame(length, queue.splitAtMost(length));
}

folly::Expected<QuicFrame, QuicError> parseFrame(
    BufQueue& queue,
    const PacketHeader& header,
    const CodecParameters& params) {
  folly::io::Cursor cursor(queue.front());
  auto frameTypeInt = decodeQuicInteger(cursor);
  if (!frameTypeInt) {
    return folly::makeUnexpected(QuicError(
        TransportErrorCode::FRAME_ENCODING_ERROR, "Invalid frame-type field"));
  }
  queue.trimStart(cursor - queue.front());
  cursor.reset(queue.front());
  FrameType frameType = static_cast<FrameType>(frameTypeInt->first);

  // No more try/catch, just use Expected/makeUnexpected pattern
  switch (frameType) {
    case FrameType::PADDING: {
      auto paddingRes = decodePaddingFrame(cursor);
      if (!paddingRes.hasValue()) {
        return folly::makeUnexpected(paddingRes.error());
      }
      queue.trimStart(cursor - queue.front());
      return QuicFrame(*paddingRes);
    }
    case FrameType::PING: {
      auto pingRes = decodePingFrame(cursor);
      if (!pingRes.hasValue()) {
        return folly::makeUnexpected(pingRes.error());
      }
      queue.trimStart(cursor - queue.front());
      return QuicFrame(*pingRes);
    }
    case FrameType::ACK: {
      auto ackFrameRes = decodeAckFrame(cursor, header, params);
      if (ackFrameRes.hasError()) {
        return ackFrameRes;
      }
      queue.trimStart(cursor - queue.front());
      return ackFrameRes;
    }
    case FrameType::ACK_ECN: {
      auto ackFrameWithEcnRes = decodeAckFrameWithECN(cursor, header, params);
      if (ackFrameWithEcnRes.hasError()) {
        return ackFrameWithEcnRes;
      }
      queue.trimStart(cursor - queue.front());
      return ackFrameWithEcnRes;
    }
    case FrameType::RST_STREAM:
    case FrameType::RST_STREAM_AT: {
      auto rstRes =
          decodeRstStreamFrame(cursor, frameType == FrameType::RST_STREAM_AT);
      if (!rstRes.hasValue()) {
        return folly::makeUnexpected(rstRes.error());
      }
      queue.trimStart(cursor - queue.front());
      return QuicFrame(*rstRes);
    }
    case FrameType::STOP_SENDING: {
      auto stopRes = decodeStopSendingFrame(cursor);
      if (!stopRes.hasValue()) {
        return folly::makeUnexpected(stopRes.error());
      }
      queue.trimStart(cursor - queue.front());
      return QuicFrame(*stopRes);
    }
    case FrameType::CRYPTO_FRAME: {
      auto cryptoRes = decodeCryptoFrame(cursor);
      if (!cryptoRes.hasValue()) {
        return folly::makeUnexpected(cryptoRes.error());
      }
      queue.trimStart(cursor - queue.front());
      return QuicFrame(*cryptoRes);
    }
    case FrameType::NEW_TOKEN: {
      auto tokenRes = decodeNewTokenFrame(cursor);
      if (!tokenRes.hasValue()) {
        return folly::makeUnexpected(tokenRes.error());
      }
      queue.trimStart(cursor - queue.front());
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
      auto streamRes = decodeStreamFrame(
          queue,
          StreamTypeField(frameTypeInt->first),
          false /* isGroupFrame */);
      if (!streamRes.hasValue()) {
        return folly::makeUnexpected(streamRes.error());
      }
      return QuicFrame(*streamRes);
    }
    case FrameType::GROUP_STREAM:
    case FrameType::GROUP_STREAM_FIN:
    case FrameType::GROUP_STREAM_LEN:
    case FrameType::GROUP_STREAM_LEN_FIN:
    case FrameType::GROUP_STREAM_OFF:
    case FrameType::GROUP_STREAM_OFF_FIN:
    case FrameType::GROUP_STREAM_OFF_LEN:
    case FrameType::GROUP_STREAM_OFF_LEN_FIN: {
      auto streamRes = decodeStreamFrame(
          queue, StreamTypeField(frameTypeInt->first), true /* isGroupFrame */);
      if (!streamRes.hasValue()) {
        return folly::makeUnexpected(streamRes.error());
      }
      return QuicFrame(*streamRes);
    }
    case FrameType::MAX_DATA: {
      auto maxDataRes = decodeMaxDataFrame(cursor);
      if (!maxDataRes.hasValue()) {
        return folly::makeUnexpected(maxDataRes.error());
      }
      queue.trimStart(cursor - queue.front());
      return QuicFrame(*maxDataRes);
    }
    case FrameType::MAX_STREAM_DATA: {
      auto maxStreamRes = decodeMaxStreamDataFrame(cursor);
      if (!maxStreamRes.hasValue()) {
        return folly::makeUnexpected(maxStreamRes.error());
      }
      queue.trimStart(cursor - queue.front());
      return QuicFrame(*maxStreamRes);
    }
    case FrameType::MAX_STREAMS_BIDI: {
      auto streamsBidiRes = decodeBiDiMaxStreamsFrame(cursor);
      if (!streamsBidiRes.hasValue()) {
        return folly::makeUnexpected(streamsBidiRes.error());
      }
      queue.trimStart(cursor - queue.front());
      return QuicFrame(*streamsBidiRes);
    }
    case FrameType::MAX_STREAMS_UNI: {
      auto streamsUniRes = decodeUniMaxStreamsFrame(cursor);
      if (!streamsUniRes.hasValue()) {
        return folly::makeUnexpected(streamsUniRes.error());
      }
      queue.trimStart(cursor - queue.front());
      return QuicFrame(*streamsUniRes);
    }
    case FrameType::DATA_BLOCKED: {
      auto blockedRes = decodeDataBlockedFrame(cursor);
      if (!blockedRes.hasValue()) {
        return folly::makeUnexpected(blockedRes.error());
      }
      queue.trimStart(cursor - queue.front());
      return QuicFrame(*blockedRes);
    }
    case FrameType::STREAM_DATA_BLOCKED: {
      auto streamBlockedRes = decodeStreamDataBlockedFrame(cursor);
      if (!streamBlockedRes.hasValue()) {
        return folly::makeUnexpected(streamBlockedRes.error());
      }
      queue.trimStart(cursor - queue.front());
      return QuicFrame(*streamBlockedRes);
    }
    case FrameType::STREAMS_BLOCKED_BIDI: {
      auto streamsBidiBlockedRes = decodeBiDiStreamsBlockedFrame(cursor);
      if (!streamsBidiBlockedRes.hasValue()) {
        return folly::makeUnexpected(streamsBidiBlockedRes.error());
      }
      queue.trimStart(cursor - queue.front());
      return QuicFrame(*streamsBidiBlockedRes);
    }
    case FrameType::STREAMS_BLOCKED_UNI: {
      auto streamsUniBlockedRes = decodeUniStreamsBlockedFrame(cursor);
      if (!streamsUniBlockedRes.hasValue()) {
        return folly::makeUnexpected(streamsUniBlockedRes.error());
      }
      queue.trimStart(cursor - queue.front());
      return QuicFrame(*streamsUniBlockedRes);
    }
    case FrameType::NEW_CONNECTION_ID: {
      auto newConnIdRes = decodeNewConnectionIdFrame(cursor);
      if (!newConnIdRes.hasValue()) {
        return folly::makeUnexpected(newConnIdRes.error());
      }
      queue.trimStart(cursor - queue.front());
      return QuicFrame(*newConnIdRes);
    }
    case FrameType::RETIRE_CONNECTION_ID: {
      auto retireConnIdRes = decodeRetireConnectionIdFrame(cursor);
      if (!retireConnIdRes.hasValue()) {
        return folly::makeUnexpected(retireConnIdRes.error());
      }
      queue.trimStart(cursor - queue.front());
      return QuicFrame(*retireConnIdRes);
    }
    case FrameType::PATH_CHALLENGE: {
      auto pathChallengeRes = decodePathChallengeFrame(cursor);
      if (!pathChallengeRes.hasValue()) {
        return folly::makeUnexpected(pathChallengeRes.error());
      }
      queue.trimStart(cursor - queue.front());
      return QuicFrame(*pathChallengeRes);
    }
    case FrameType::PATH_RESPONSE: {
      auto pathResponseRes = decodePathResponseFrame(cursor);
      if (!pathResponseRes.hasValue()) {
        return folly::makeUnexpected(pathResponseRes.error());
      }
      queue.trimStart(cursor - queue.front());
      return QuicFrame(*pathResponseRes);
    }
    case FrameType::CONNECTION_CLOSE: {
      auto connCloseRes = decodeConnectionCloseFrame(cursor);
      if (!connCloseRes.hasValue()) {
        return folly::makeUnexpected(connCloseRes.error());
      }
      queue.trimStart(cursor - queue.front());
      return QuicFrame(*connCloseRes);
    }
    case FrameType::CONNECTION_CLOSE_APP_ERR: {
      auto appCloseRes = decodeApplicationClose(cursor);
      if (!appCloseRes.hasValue()) {
        return folly::makeUnexpected(appCloseRes.error());
      }
      queue.trimStart(cursor - queue.front());
      return QuicFrame(*appCloseRes);
    }
    case FrameType::HANDSHAKE_DONE: {
      auto handshakeDoneRes = decodeHandshakeDoneFrame(cursor);
      if (!handshakeDoneRes.hasValue()) {
        return folly::makeUnexpected(handshakeDoneRes.error());
      }
      queue.trimStart(cursor - queue.front());
      return QuicFrame(*handshakeDoneRes);
    }
    case FrameType::DATAGRAM: {
      auto datagramRes = decodeDatagramFrame(queue, false /* hasLen */);
      if (!datagramRes.hasValue()) {
        return folly::makeUnexpected(datagramRes.error());
      }
      return QuicFrame(*datagramRes);
    }
    case FrameType::DATAGRAM_LEN: {
      auto datagramRes = decodeDatagramFrame(queue, true /* hasLen */);
      if (!datagramRes.hasValue()) {
        return folly::makeUnexpected(datagramRes.error());
      }
      return QuicFrame(*datagramRes);
    }
    case FrameType::KNOB: {
      auto knobRes = decodeKnobFrame(cursor);
      if (knobRes.hasError()) {
        return knobRes;
      }
      queue.trimStart(cursor - queue.front());
      return QuicFrame(*knobRes);
    }
    case FrameType::ACK_FREQUENCY: {
      auto ackFreqRes = decodeAckFrequencyFrame(cursor);
      if (!ackFreqRes.hasValue()) {
        return folly::makeUnexpected(ackFreqRes.error());
      }
      queue.trimStart(cursor - queue.front());
      return QuicFrame(*ackFreqRes);
    }
    case FrameType::IMMEDIATE_ACK: {
      auto immediateAckRes = decodeImmediateAckFrame(cursor);
      if (!immediateAckRes.hasValue()) {
        return folly::makeUnexpected(immediateAckRes.error());
      }
      queue.trimStart(cursor - queue.front());
      return QuicFrame(*immediateAckRes);
    }
    case FrameType::ACK_RECEIVE_TIMESTAMPS: {
      auto ackWithReceiveTiemstampsRes = decodeAckFrameWithReceivedTimestamps(
          cursor, header, params, FrameType::ACK_RECEIVE_TIMESTAMPS);
      if (ackWithReceiveTiemstampsRes.hasError()) {
        return ackWithReceiveTiemstampsRes;
      }
      queue.trimStart(cursor - queue.front());
      return ackWithReceiveTiemstampsRes;
    }
    case FrameType::ACK_EXTENDED: {
      auto ackExtRes = decodeAckExtendedFrame(cursor, header, params);
      if (!ackExtRes.hasValue()) {
        return folly::makeUnexpected(ackExtRes.error());
      }
      queue.trimStart(cursor - queue.front());
      return QuicFrame(*ackExtRes);
    }
  }

  return folly::makeUnexpected(QuicError(
      TransportErrorCode::FRAME_ENCODING_ERROR,
      folly::to<std::string>("Unknown frame, type=", frameTypeInt->first)));
}

// Parse packet

folly::Expected<RegularQuicPacket, QuicError> decodeRegularPacket(
    PacketHeader&& header,
    const CodecParameters& params,
    Buf packetData) {
  RegularQuicPacket packet(std::move(header));
  BufQueue queue;
  queue.append(std::move(packetData));
  if (UNLIKELY(queue.chainLength() == 0)) {
    return packet;
  }
  // Parse out one packet before any conditionals.
  auto frameRes = parseFrame(queue, packet.header, params);
  if (!frameRes.hasValue()) {
    return folly::makeUnexpected(frameRes.error());
  }
  packet.frames.push_back(std::move(*frameRes));

  while (queue.chainLength() > 0) {
    auto fRes = parseFrame(queue, packet.header, params);
    if (!fRes.hasValue()) {
      return folly::makeUnexpected(fRes.error());
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
    folly::io::Cursor& cursor) {
  auto cursorLength = cursor.totalLength();

  if (cursorLength < sizeof(QuicVersionType) ||
      cursorLength % sizeof(QuicVersionType)) {
    VLOG(4) << "Version negotiation packet invalid";
    return none;
  }

  VersionNegotiationPacket packet(
      longHeaderInvariant.initialByte,
      longHeaderInvariant.invariant.srcConnId,
      longHeaderInvariant.invariant.dstConnId);

  while (!cursor.isAtEnd()) {
    packet.versions.push_back(
        static_cast<QuicVersion>(cursor.readBE<QuicVersionType>()));
  }

  return packet;
}

ParsedLongHeaderResult::ParsedLongHeaderResult(
    bool isVersionNegotiationIn,
    Optional<ParsedLongHeader> parsedLongHeaderIn)
    : isVersionNegotiation(isVersionNegotiationIn),
      parsedLongHeader(std::move(parsedLongHeaderIn)) {
  CHECK(isVersionNegotiation || parsedLongHeader);
}

ParsedLongHeaderInvariant::ParsedLongHeaderInvariant(
    uint8_t initialByteIn,
    LongHeaderInvariant headerInvariant,
    size_t length)
    : initialByte(initialByteIn),
      invariant(std::move(headerInvariant)),
      invariantLength(length) {}

folly::Expected<ParsedLongHeaderInvariant, TransportErrorCode>
parseLongHeaderInvariant(uint8_t initialByte, folly::io::Cursor& cursor) {
  size_t initialLength = cursor.totalLength();
  if (!cursor.canAdvance(sizeof(QuicVersionType))) {
    VLOG(5) << "Not enough input bytes to read Version or connection-id";
    return folly::makeUnexpected(TransportErrorCode::FRAME_ENCODING_ERROR);
  }
  auto version = static_cast<QuicVersion>(cursor.readBE<QuicVersionType>());
  if (!cursor.canAdvance(1)) {
    VLOG(5) << "Not enough input bytes to read Dest. ConnectionId length";
    return folly::makeUnexpected(TransportErrorCode::FRAME_ENCODING_ERROR);
  }
  uint8_t destConnIdLen = cursor.readBE<uint8_t>();
  if (destConnIdLen > kMaxConnectionIdSize) {
    VLOG(5) << "destConnIdLen > kMaxConnectionIdSize: " << destConnIdLen;
    return folly::makeUnexpected(TransportErrorCode::PROTOCOL_VIOLATION);
  }
  if (!cursor.canAdvance(destConnIdLen)) {
    VLOG(5) << "Not enough input bytes to read Dest. ConnectionId";
    return folly::makeUnexpected(TransportErrorCode::FRAME_ENCODING_ERROR);
  }
  ConnectionId destConnId(cursor, destConnIdLen);
  if (!cursor.canAdvance(1)) {
    VLOG(5) << "Not enough input bytes to read Source ConnectionId length";
    return folly::makeUnexpected(TransportErrorCode::FRAME_ENCODING_ERROR);
  }
  uint8_t srcConnIdLen = cursor.readBE<uint8_t>();
  if (srcConnIdLen > kMaxConnectionIdSize) {
    VLOG(5) << "srcConnIdLen > kMaxConnectionIdSize: " << srcConnIdLen;
    return folly::makeUnexpected(TransportErrorCode::PROTOCOL_VIOLATION);
  }
  if (!cursor.canAdvance(srcConnIdLen)) {
    VLOG(5) << "Not enough input bytes to read Source ConnectionId";
    return folly::makeUnexpected(TransportErrorCode::FRAME_ENCODING_ERROR);
  }
  ConnectionId srcConnId(cursor, srcConnIdLen);
  size_t currentLength = cursor.totalLength();
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
    folly::ByteRange packetNumberRange,
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

folly::Expected<ParsedLongHeaderResult, TransportErrorCode> parseLongHeader(
    uint8_t initialByte,
    folly::io::Cursor& cursor) {
  if (getHeaderForm(initialByte) != HeaderForm::Long) {
    VLOG(5) << "Bad header form bit";
    return folly::makeUnexpected(TransportErrorCode::FRAME_ENCODING_ERROR);
  }
  LongHeader::Types type = parseLongHeaderType(initialByte);
  switch (type) {
    case LongHeader::Types::Initial:
    case LongHeader::Types::Retry:
    case LongHeader::Types::Handshake:
    case LongHeader::Types::ZeroRtt:
      break;
    default:
      return folly::makeUnexpected(TransportErrorCode::FRAME_ENCODING_ERROR);
  }

  auto parsedLongHeaderInvariant =
      parseLongHeaderInvariant(initialByte, cursor);
  if (!parsedLongHeaderInvariant) {
    VLOG(5) << "Bad invariants fields in long header";
    return folly::makeUnexpected(TransportErrorCode::FRAME_ENCODING_ERROR);
  }

  auto version = parsedLongHeaderInvariant->invariant.version;
  if (version == QuicVersion::VERSION_NEGOTIATION) {
    return ParsedLongHeaderResult(true, none);
  }
  auto parsedHeader = parseLongHeaderVariants(
      type, std::move(*parsedLongHeaderInvariant), cursor);
  if (!parsedHeader) {
    return folly::makeUnexpected(parsedHeader.error());
  }
  return ParsedLongHeaderResult(false, std::move(*parsedHeader));
}

folly::Expected<ParsedLongHeader, TransportErrorCode> parseLongHeaderVariants(
    LongHeader::Types type,
    ParsedLongHeaderInvariant parsedLongHeaderInvariant,
    folly::io::Cursor& cursor,
    QuicNodeType nodeType) {
  if (type == LongHeader::Types::Retry) {
    // The integrity tag is kRetryIntegrityTagLen bytes in length, and the
    // token must be at least one byte, so the remaining length must
    // be > kRetryIntegrityTagLen.
    if (cursor.totalLength() <= kRetryIntegrityTagLen) {
      VLOG(5) << "Not enough bytes for retry token";
      return folly::makeUnexpected(TransportErrorCode::FRAME_ENCODING_ERROR);
    }

    Buf token;
    cursor.clone(token, cursor.totalLength() - kRetryIntegrityTagLen);

    return ParsedLongHeader(
        LongHeader(
            type,
            std::move(parsedLongHeaderInvariant.invariant),
            token ? token->to<std::string>() : std::string()),
        PacketLength(0, 0));
  }

  // TODO Checking kMinInitialDestinationConnIdLength isn't necessary
  // if this packet is in response to a retry.
  if (type == LongHeader::Types::Initial && nodeType == QuicNodeType::Server &&
      parsedLongHeaderInvariant.invariant.dstConnId.size() <
          kMinInitialDestinationConnIdLength) {
    VLOG(5)
        << "Dest Conn-Id length in client initial packet must be >= 8 bytes.";
    return folly::makeUnexpected(TransportErrorCode::FRAME_ENCODING_ERROR);
  }

  Buf token;
  if (type == LongHeader::Types::Initial) {
    auto tokenLen = decodeQuicInteger(cursor);
    if (!tokenLen) {
      VLOG(5) << "Token len not found in Long header";
      return folly::makeUnexpected(TransportErrorCode::FRAME_ENCODING_ERROR);
    }
    if (!cursor.canAdvance(tokenLen->first)) {
      VLOG(5) << "Not enough input bytes to read input token";
      return folly::makeUnexpected(TransportErrorCode::FRAME_ENCODING_ERROR);
    }

    if (tokenLen->first > 0) {
      Buf tokenBuf;
      // If tokenLen > token's actual length then the cursor will throw.
      cursor.clone(tokenBuf, tokenLen->first);
      token = std::move(tokenBuf);
    }
  }
  auto pktLen = decodeQuicInteger(cursor);
  if (!pktLen) {
    VLOG(5) << "Packet len not found in Long header";
    return folly::makeUnexpected(TransportErrorCode::FRAME_ENCODING_ERROR);
  }
  if (!cursor.canAdvance(pktLen->first)) {
    VLOG(5) << "Not enough input bytes to read packet number";
    return folly::makeUnexpected(TransportErrorCode::FRAME_ENCODING_ERROR);
  }
  size_t packetNumLen =
      parsePacketNumberLength(parsedLongHeaderInvariant.initialByte);
  if (!cursor.canAdvance(packetNumLen)) {
    return folly::makeUnexpected(TransportErrorCode::FRAME_ENCODING_ERROR);
  }
  if (packetNumLen > kMaxPacketNumEncodingSize) {
    return folly::makeUnexpected(TransportErrorCode::FRAME_ENCODING_ERROR);
  }
  return ParsedLongHeader(
      LongHeader(
          type,
          std::move(parsedLongHeaderInvariant.invariant),
          token ? token->to<std::string>() : std::string()),
      PacketLength(pktLen->first, pktLen->second));
}

folly::Expected<ShortHeaderInvariant, TransportErrorCode>
parseShortHeaderInvariants(
    uint8_t initialByte,
    folly::io::Cursor& cursor,
    size_t dstConnIdSize) {
  if (getHeaderForm(initialByte) != HeaderForm::Short) {
    VLOG(5) << "Bad header form bit";
    return folly::makeUnexpected(TransportErrorCode::FRAME_ENCODING_ERROR);
  }
  // TODO(t39154014, yangchi): read the length from the connection state in
  // draft-17
  if (dstConnIdSize > kMaxConnectionIdSize) {
    VLOG(5) << "dstConnIdSize > kMaxConnectionIdSize: " << dstConnIdSize;
    return folly::makeUnexpected(TransportErrorCode::PROTOCOL_VIOLATION);
  }
  if (!cursor.canAdvance(dstConnIdSize)) {
    VLOG(5) << "Not enough input bytes for ConnectionId";
    return folly::makeUnexpected(TransportErrorCode::FRAME_ENCODING_ERROR);
  }
  ConnectionId connId(cursor, dstConnIdSize);
  return ShortHeaderInvariant(std::move(connId));
}

folly::Expected<ShortHeader, TransportErrorCode> parseShortHeader(
    uint8_t initialByte,
    folly::io::Cursor& cursor,
    size_t dstConnIdSize) {
  if (getHeaderForm(initialByte) != HeaderForm::Short) {
    VLOG(5) << "Bad header form bit";
    return folly::makeUnexpected(TransportErrorCode::FRAME_ENCODING_ERROR);
  }
  if (!(initialByte & ShortHeader::kFixedBitMask)) {
    VLOG(5) << "Fixed bit in ShortHeader is 0";
    // Specs doesn't say which error code to use
    return folly::makeUnexpected(TransportErrorCode::FRAME_ENCODING_ERROR);
  }
  if (initialByte & ShortHeader::kReservedBitsMask) {
    VLOG(5) << "Non-zero reserved bits in ShortHeader";
    // Specs asks this to be PROTOCOL_VIOLATION
    return folly::makeUnexpected(TransportErrorCode::PROTOCOL_VIOLATION);
  }
  auto invariant =
      parseShortHeaderInvariants(initialByte, cursor, dstConnIdSize);
  if (!invariant) {
    VLOG(5) << "Error parsing short header invariant";
    return folly::makeUnexpected(TransportErrorCode::FRAME_ENCODING_ERROR);
  }
  auto protectionType = initialByte & ShortHeader::kKeyPhaseMask
      ? ProtectionType::KeyPhaseOne
      : ProtectionType::KeyPhaseZero;
  return ShortHeader(protectionType, std::move(invariant->destinationConnId));
}

} // namespace quic
