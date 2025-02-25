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

PaddingFrame decodePaddingFrame(folly::io::Cursor& cursor) {
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

PingFrame decodePingFrame(folly::io::Cursor&) {
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

ImmediateAckFrame decodeImmediateAckFrame(folly::io::Cursor&) {
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

static void decodeEcnCountsInAck(
    ReadAckFrame& frame,
    folly::io::Cursor& cursor) {
  auto ect_0 = decodeQuicInteger(cursor);
  auto ect_1 = decodeQuicInteger(cursor);
  auto ce = decodeQuicInteger(cursor);
  if (!ect_0 || !ect_1 || !ce) {
    throw QuicTransportException(
        "Bad ECN value", quic::TransportErrorCode::FRAME_ENCODING_ERROR);
  }
  frame.ecnECT0Count = ect_0->first;
  frame.ecnECT1Count = ect_1->first;
  frame.ecnCECount = ce->first;
}

ReadAckFrame decodeAckExtendedFrame(
    folly::io::Cursor& cursor,
    const PacketHeader& header,
    const CodecParameters& params) {
  ReadAckFrame frame;
  auto res = decodeAckFrame(cursor, header, params, FrameType::ACK_EXTENDED);
  if (res.hasError()) {
    throw QuicTransportException(
        res.error().message, *res.error().code.asTransportErrorCode());
  }
  frame = *res;
  auto extendedAckFeatures = decodeQuicInteger(cursor);
  if (!extendedAckFeatures) {
    throw QuicTransportException(
        "Bad extended ACK features field",
        quic::TransportErrorCode::FRAME_ENCODING_ERROR);
  }
  auto includedFeatures = extendedAckFeatures->first;
  if ((includedFeatures | params.extendedAckFeatures) !=
      params.extendedAckFeatures) {
    throw QuicTransportException(
        "Extended ACK has unexpected features",
        quic::TransportErrorCode::FRAME_ENCODING_ERROR);
  }
  if (includedFeatures &
      static_cast<ExtendedAckFeatureMaskType>(
          ExtendedAckFeatureMask::ECN_COUNTS)) {
    decodeEcnCountsInAck(frame, cursor);
  }
  if (includedFeatures &
      static_cast<ExtendedAckFeatureMaskType>(
          ExtendedAckFeatureMask::RECEIVE_TIMESTAMPS)) {
    decodeReceiveTimestampsInAck(frame, cursor, params);
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
    throw QuicTransportException(
        ack.error().message, *ack.error().code.asTransportErrorCode());
  }
  frame = *ack;
  frame.frameType = frameType;

  auto ts = decodeReceiveTimestampsInAck(frame, cursor, params);
  if (ts.hasError()) {
    return folly::makeUnexpected(ts.error());
  }

  return QuicFrame(frame);
}

ReadAckFrame decodeAckFrameWithECN(
    folly::io::Cursor& cursor,
    const PacketHeader& header,
    const CodecParameters& params) {
  auto res = decodeAckFrame(cursor, header, params);
  if (res.hasError()) {
    throw QuicTransportException(
        res.error().message, *res.error().code.asTransportErrorCode());
  }
  auto readAckFrame = *res;
  readAckFrame.frameType = FrameType::ACK_ECN;
  decodeEcnCountsInAck(readAckFrame, cursor);
  return readAckFrame;
}

RstStreamFrame decodeRstStreamFrame(folly::io::Cursor& cursor, bool reliable) {
  auto streamId = decodeQuicInteger(cursor);
  if (!streamId) {
    throw QuicTransportException(
        "Bad streamId", quic::TransportErrorCode::FRAME_ENCODING_ERROR);
  }
  ApplicationErrorCode errorCode;
  auto varCode = decodeQuicInteger(cursor);
  if (varCode) {
    errorCode = static_cast<ApplicationErrorCode>(varCode->first);
  } else {
    throw QuicTransportException(
        "Cannot decode error code",
        quic::TransportErrorCode::FRAME_ENCODING_ERROR);
  }
  auto finalSize = decodeQuicInteger(cursor);
  if (!finalSize) {
    throw QuicTransportException(
        "Bad offset", quic::TransportErrorCode::FRAME_ENCODING_ERROR);
  }
  folly::Optional<std::pair<uint64_t, size_t>> reliableSize = folly::none;
  if (reliable) {
    reliableSize = decodeQuicInteger(cursor);
    if (!reliableSize) {
      throw QuicTransportException(
          "Bad value of reliable size",
          quic::TransportErrorCode::FRAME_ENCODING_ERROR);
    }

    if (reliableSize->first > finalSize->first) {
      throw QuicTransportException(
          "Reliable size is greater than final size",
          quic::TransportErrorCode::FRAME_ENCODING_ERROR);
    }
  }
  return RstStreamFrame(
      folly::to<StreamId>(streamId->first),
      errorCode,
      finalSize->first,
      reliableSize ? folly::Optional<uint64_t>(reliableSize->first)
                   : folly::none);
}

StopSendingFrame decodeStopSendingFrame(folly::io::Cursor& cursor) {
  auto streamId = decodeQuicInteger(cursor);
  if (!streamId) {
    throw QuicTransportException(
        "Bad streamId", quic::TransportErrorCode::FRAME_ENCODING_ERROR);
  }
  ApplicationErrorCode errorCode;
  auto varCode = decodeQuicInteger(cursor);
  if (varCode) {
    errorCode = static_cast<ApplicationErrorCode>(varCode->first);
  } else {
    throw QuicTransportException(
        "Cannot decode error code",
        quic::TransportErrorCode::FRAME_ENCODING_ERROR);
  }
  return StopSendingFrame(folly::to<StreamId>(streamId->first), errorCode);
}

ReadCryptoFrame decodeCryptoFrame(folly::io::Cursor& cursor) {
  auto optionalOffset = decodeQuicInteger(cursor);
  if (!optionalOffset) {
    throw QuicTransportException(
        "Invalid offset", quic::TransportErrorCode::FRAME_ENCODING_ERROR);
  }
  uint64_t offset = optionalOffset->first;

  auto dataLength = decodeQuicInteger(cursor);
  if (!dataLength) {
    throw QuicTransportException(
        "Invalid length", quic::TransportErrorCode::FRAME_ENCODING_ERROR);
  }
  Buf data;
  if (cursor.totalLength() < dataLength->first) {
    throw QuicTransportException(
        "Length mismatch", quic::TransportErrorCode::FRAME_ENCODING_ERROR);
  }
  // If dataLength > data's actual length then the cursor will throw.
  cursor.clone(data, dataLength->first);
  return ReadCryptoFrame(offset, std::move(data));
}

ReadNewTokenFrame decodeNewTokenFrame(folly::io::Cursor& cursor) {
  auto tokenLength = decodeQuicInteger(cursor);
  if (!tokenLength) {
    throw QuicTransportException(
        "Invalid length", quic::TransportErrorCode::FRAME_ENCODING_ERROR);
  }
  Buf token;
  if (cursor.totalLength() < tokenLength->first) {
    throw QuicTransportException(
        "Length mismatch", quic::TransportErrorCode::FRAME_ENCODING_ERROR);
  }
  // If tokenLength > token's actual length then the cursor will throw.
  cursor.clone(token, tokenLength->first);
  return ReadNewTokenFrame(std::move(token));
}

ReadStreamFrame decodeStreamFrame(
    BufQueue& queue,
    StreamTypeField frameTypeField,
    bool isGroupFrame) {
  folly::io::Cursor cursor(queue.front());

  auto streamId = decodeQuicInteger(cursor);
  if (!streamId) {
    throw QuicTransportException(
        "Invalid stream id", quic::TransportErrorCode::FRAME_ENCODING_ERROR);
  }

  OptionalIntegral<StreamGroupId> groupId;
  if (isGroupFrame) {
    auto gId = decodeQuicInteger(cursor);
    if (!gId) {
      throw QuicTransportException(
          "Invalid group stream id",
          quic::TransportErrorCode::FRAME_ENCODING_ERROR);
    }
    groupId = gId->first;
  }

  uint64_t offset = 0;
  if (frameTypeField.hasOffset()) {
    auto optionalOffset = decodeQuicInteger(cursor);
    if (!optionalOffset) {
      throw QuicTransportException(
          "Invalid offset", quic::TransportErrorCode::FRAME_ENCODING_ERROR);
    }
    offset = optionalOffset->first;
  }
  auto fin = frameTypeField.hasFin();
  Optional<std::pair<uint64_t, size_t>> dataLength;
  if (frameTypeField.hasDataLength()) {
    dataLength = decodeQuicInteger(cursor);
    if (!dataLength) {
      throw QuicTransportException(
          "Invalid length", quic::TransportErrorCode::FRAME_ENCODING_ERROR);
    }
  }
  Buf data;
  if (dataLength.has_value()) {
    if (cursor.totalLength() < dataLength->first) {
      throw QuicTransportException(
          "Length mismatch", quic::TransportErrorCode::FRAME_ENCODING_ERROR);
    }
    // If dataLength > data's actual length then the cursor will throw.
    queue.trimStart(cursor - queue.front());
    data = queue.splitAtMost(dataLength->first);
  } else {
    // Missing Data Length field doesn't mean no data. It means the rest of the
    // frame are all data.
    queue.trimStart(cursor - queue.front());
    data = queue.move();
  }
  return ReadStreamFrame(
      folly::to<StreamId>(streamId->first),
      offset,
      std::move(data),
      fin,
      groupId);
}

MaxDataFrame decodeMaxDataFrame(folly::io::Cursor& cursor) {
  auto maximumData = decodeQuicInteger(cursor);
  if (!maximumData) {
    throw QuicTransportException(
        "Bad Max Data", quic::TransportErrorCode::FRAME_ENCODING_ERROR);
  }
  return MaxDataFrame(maximumData->first);
}

MaxStreamDataFrame decodeMaxStreamDataFrame(folly::io::Cursor& cursor) {
  auto streamId = decodeQuicInteger(cursor);
  if (!streamId) {
    throw QuicTransportException(
        "Invalid streamId", quic::TransportErrorCode::FRAME_ENCODING_ERROR);
  }
  auto offset = decodeQuicInteger(cursor);
  if (!offset) {
    throw QuicTransportException(
        "Invalid offset", quic::TransportErrorCode::FRAME_ENCODING_ERROR);
  }
  return MaxStreamDataFrame(
      folly::to<StreamId>(streamId->first), offset->first);
}

MaxStreamsFrame decodeBiDiMaxStreamsFrame(folly::io::Cursor& cursor) {
  auto streamCount = decodeQuicInteger(cursor);
  if (!streamCount || streamCount->first > kMaxMaxStreams) {
    throw QuicTransportException(
        "Invalid Bi-directional streamId",
        quic::TransportErrorCode::FRAME_ENCODING_ERROR);
  }
  return MaxStreamsFrame(streamCount->first, true /* isBidirectional*/);
}

MaxStreamsFrame decodeUniMaxStreamsFrame(folly::io::Cursor& cursor) {
  auto streamCount = decodeQuicInteger(cursor);
  if (!streamCount || streamCount->first > kMaxMaxStreams) {
    throw QuicTransportException(
        "Invalid Uni-directional streamId",
        quic::TransportErrorCode::FRAME_ENCODING_ERROR);
  }
  return MaxStreamsFrame(streamCount->first, false /* isUnidirectional */);
}

DataBlockedFrame decodeDataBlockedFrame(folly::io::Cursor& cursor) {
  auto dataLimit = decodeQuicInteger(cursor);
  if (!dataLimit) {
    throw QuicTransportException(
        "Bad offset", quic::TransportErrorCode::FRAME_ENCODING_ERROR);
  }
  return DataBlockedFrame(dataLimit->first);
}

StreamDataBlockedFrame decodeStreamDataBlockedFrame(folly::io::Cursor& cursor) {
  auto streamId = decodeQuicInteger(cursor);
  if (!streamId) {
    throw QuicTransportException(
        "Bad streamId", quic::TransportErrorCode::FRAME_ENCODING_ERROR);
  }
  auto dataLimit = decodeQuicInteger(cursor);
  if (!dataLimit) {
    throw QuicTransportException(
        "Bad offset", quic::TransportErrorCode::FRAME_ENCODING_ERROR);
  }
  return StreamDataBlockedFrame(
      folly::to<StreamId>(streamId->first), dataLimit->first);
}

StreamsBlockedFrame decodeBiDiStreamsBlockedFrame(folly::io::Cursor& cursor) {
  auto streamId = decodeQuicInteger(cursor);
  if (!streamId) {
    throw QuicTransportException(
        "Bad Bi-Directional streamId",
        quic::TransportErrorCode::FRAME_ENCODING_ERROR);
  }
  return StreamsBlockedFrame(
      folly::to<StreamId>(streamId->first), true /* isBidirectional */);
}

StreamsBlockedFrame decodeUniStreamsBlockedFrame(folly::io::Cursor& cursor) {
  auto streamId = decodeQuicInteger(cursor);
  if (!streamId) {
    throw QuicTransportException(
        "Bad Uni-direcitonal streamId",
        quic::TransportErrorCode::FRAME_ENCODING_ERROR);
  }
  return StreamsBlockedFrame(
      folly::to<StreamId>(streamId->first), false /* isBidirectional */);
}

NewConnectionIdFrame decodeNewConnectionIdFrame(folly::io::Cursor& cursor) {
  auto sequenceNumber = decodeQuicInteger(cursor);
  if (!sequenceNumber) {
    throw QuicTransportException(
        "Bad sequence", quic::TransportErrorCode::FRAME_ENCODING_ERROR);
  }
  auto retirePriorTo = decodeQuicInteger(cursor);
  if (!retirePriorTo) {
    throw QuicTransportException(
        "Bad retire prior to", quic::TransportErrorCode::FRAME_ENCODING_ERROR);
  }
  if (!cursor.canAdvance(sizeof(uint8_t))) {
    throw QuicTransportException(
        "Not enough input bytes to read Dest. ConnectionId",
        quic::TransportErrorCode::FRAME_ENCODING_ERROR);
  }
  auto connIdLen = cursor.readBE<uint8_t>();
  if (cursor.totalLength() < connIdLen) {
    throw QuicTransportException(
        "Bad connid", quic::TransportErrorCode::FRAME_ENCODING_ERROR);
  }
  if (connIdLen > kMaxConnectionIdSize) {
    throw QuicTransportException(
        "ConnectionId invalid length",
        quic::TransportErrorCode::FRAME_ENCODING_ERROR);
  }
  ConnectionId connId(cursor, connIdLen);
  StatelessResetToken statelessResetToken;
  cursor.pull(statelessResetToken.data(), statelessResetToken.size());
  return NewConnectionIdFrame(
      sequenceNumber->first,
      retirePriorTo->first,
      std::move(connId),
      std::move(statelessResetToken));
}

RetireConnectionIdFrame decodeRetireConnectionIdFrame(
    folly::io::Cursor& cursor) {
  auto sequenceNum = decodeQuicInteger(cursor);
  if (!sequenceNum) {
    throw QuicTransportException(
        // TODO change the error code
        "Bad sequence num",
        quic::TransportErrorCode::FRAME_ENCODING_ERROR);
  }
  return RetireConnectionIdFrame(sequenceNum->first);
}

PathChallengeFrame decodePathChallengeFrame(folly::io::Cursor& cursor) {
  // just parse and ignore expected data
  // A PATH_CHALLENGE frame contains 8 bytes
  if (!cursor.canAdvance(sizeof(uint64_t))) {
    throw QuicTransportException(
        "Not enough input bytes to read path challenge frame.",
        quic::TransportErrorCode::FRAME_ENCODING_ERROR);
  }
  auto pathData = cursor.readBE<uint64_t>();
  return PathChallengeFrame(pathData);
}

PathResponseFrame decodePathResponseFrame(folly::io::Cursor& cursor) {
  // just parse and ignore expected data
  // Its format is identical to the PATH_CHALLENGE frame
  if (!cursor.canAdvance(sizeof(uint64_t))) {
    throw QuicTransportException(
        "Not enough input bytes to read path response frame.",
        quic::TransportErrorCode::FRAME_ENCODING_ERROR);
  }
  auto pathData = cursor.readBE<uint64_t>();
  return PathResponseFrame(pathData);
}

ConnectionCloseFrame decodeConnectionCloseFrame(folly::io::Cursor& cursor) {
  TransportErrorCode errorCode{};
  auto varCode = decodeQuicInteger(cursor);
  if (varCode) {
    errorCode = static_cast<TransportErrorCode>(varCode->first);
  } else {
    throw QuicTransportException(
        "Failed to parse error code.",
        quic::TransportErrorCode::FRAME_ENCODING_ERROR);
  }
  auto frameTypeField = decodeQuicInteger(cursor);
  if (!frameTypeField || frameTypeField->second != sizeof(uint8_t)) {
    throw QuicTransportException(
        "Bad connection close triggering frame type value",
        quic::TransportErrorCode::FRAME_ENCODING_ERROR);
  }
  FrameType triggeringFrameType = static_cast<FrameType>(frameTypeField->first);
  auto reasonPhraseLength = decodeQuicInteger(cursor);
  if (!reasonPhraseLength ||
      reasonPhraseLength->first > kMaxReasonPhraseLength) {
    throw QuicTransportException(
        "Bad reason phrase length",
        quic::TransportErrorCode::FRAME_ENCODING_ERROR);
  }
  auto reasonPhrase =
      cursor.readFixedString(folly::to<size_t>(reasonPhraseLength->first));
  return ConnectionCloseFrame(
      QuicErrorCode(errorCode), std::move(reasonPhrase), triggeringFrameType);
}

ConnectionCloseFrame decodeApplicationClose(folly::io::Cursor& cursor) {
  ApplicationErrorCode errorCode{};
  auto varCode = decodeQuicInteger(cursor);
  if (varCode) {
    errorCode = static_cast<ApplicationErrorCode>(varCode->first);
  } else {
    throw QuicTransportException(
        "Failed to parse error code.",
        quic::TransportErrorCode::FRAME_ENCODING_ERROR);
  }

  auto reasonPhraseLength = decodeQuicInteger(cursor);
  if (!reasonPhraseLength ||
      reasonPhraseLength->first > kMaxReasonPhraseLength) {
    throw QuicTransportException(
        "Bad reason phrase length",
        quic::TransportErrorCode::FRAME_ENCODING_ERROR);
  }

  auto reasonPhrase =
      cursor.readFixedString(folly::to<size_t>(reasonPhraseLength->first));
  return ConnectionCloseFrame(
      QuicErrorCode(errorCode), std::move(reasonPhrase));
}

HandshakeDoneFrame decodeHandshakeDoneFrame(folly::io::Cursor& /*cursor*/) {
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

DatagramFrame decodeDatagramFrame(BufQueue& queue, bool hasLen) {
  folly::io::Cursor cursor(queue.front());
  size_t length = cursor.length();
  if (hasLen) {
    auto decodeLength = decodeQuicInteger(cursor);
    if (!decodeLength) {
      throw QuicTransportException(
          "Invalid datagram len", TransportErrorCode::FRAME_ENCODING_ERROR);
    }
    length = decodeLength->first;
    if (cursor.length() < length) {
      throw QuicTransportException(
          "Invalid datagram frame", TransportErrorCode::FRAME_ENCODING_ERROR);
    }
    queue.trimStart(decodeLength->second);
  }
  return DatagramFrame(length, queue.splitAtMost(length));
}

QuicFrame parseFrame(
    BufQueue& queue,
    const PacketHeader& header,
    const CodecParameters& params) {
  folly::io::Cursor cursor(queue.front());
  auto frameTypeInt = decodeQuicInteger(cursor);
  if (!frameTypeInt) {
    throw QuicTransportException(
        "Invalid frame-type field", TransportErrorCode::FRAME_ENCODING_ERROR);
  }
  queue.trimStart(cursor - queue.front());
  bool consumedQueue = false;
  bool error = false;
  SCOPE_EXIT {
    if (consumedQueue || error) {
      return;
    }
    queue.trimStart(cursor - queue.front());
  };
  cursor.reset(queue.front());
  FrameType frameType = static_cast<FrameType>(frameTypeInt->first);
  try

  {
    folly::Expected<QuicFrame, QuicError> res = folly::makeUnexpected(
        QuicError(TransportErrorCode::INTERNAL_ERROR, "unintialized frame"));
    switch (frameType) {
      case FrameType::PADDING:
        return QuicFrame(decodePaddingFrame(cursor));
      case FrameType::PING:
        return QuicFrame(decodePingFrame(cursor));
      case FrameType::ACK:
        res = decodeAckFrame(cursor, header, params);
        if (res.hasError()) {
          throw QuicTransportException(
              res.error().message, *res.error().code.asTransportErrorCode());
        }
        return *res;
      case FrameType::ACK_ECN:
        return QuicFrame(decodeAckFrameWithECN(cursor, header, params));
      case FrameType::RST_STREAM:
      case FrameType::RST_STREAM_AT:
        return QuicFrame(decodeRstStreamFrame(
            cursor, frameType == FrameType::RST_STREAM_AT));
      case FrameType::STOP_SENDING:
        return QuicFrame(decodeStopSendingFrame(cursor));
      case FrameType::CRYPTO_FRAME:
        return QuicFrame(decodeCryptoFrame(cursor));
      case FrameType::NEW_TOKEN:
        return QuicFrame(decodeNewTokenFrame(cursor));
      case FrameType::STREAM:
      case FrameType::STREAM_FIN:
      case FrameType::STREAM_LEN:
      case FrameType::STREAM_LEN_FIN:
      case FrameType::STREAM_OFF:
      case FrameType::STREAM_OFF_FIN:
      case FrameType::STREAM_OFF_LEN:
      case FrameType::STREAM_OFF_LEN_FIN:
        consumedQueue = true;
        return QuicFrame(decodeStreamFrame(
            queue,
            StreamTypeField(frameTypeInt->first),
            false /* isGroupFrame */));
      case FrameType::GROUP_STREAM:
      case FrameType::GROUP_STREAM_FIN:
      case FrameType::GROUP_STREAM_LEN:
      case FrameType::GROUP_STREAM_LEN_FIN:
      case FrameType::GROUP_STREAM_OFF:
      case FrameType::GROUP_STREAM_OFF_FIN:
      case FrameType::GROUP_STREAM_OFF_LEN:
      case FrameType::GROUP_STREAM_OFF_LEN_FIN:
        consumedQueue = true;
        return QuicFrame(decodeStreamFrame(
            queue,
            StreamTypeField(frameTypeInt->first),
            true /* isGroupFrame */));
      case FrameType::MAX_DATA:
        return QuicFrame(decodeMaxDataFrame(cursor));
      case FrameType::MAX_STREAM_DATA:
        return QuicFrame(decodeMaxStreamDataFrame(cursor));
      case FrameType::MAX_STREAMS_BIDI:
        return QuicFrame(decodeBiDiMaxStreamsFrame(cursor));
      case FrameType::MAX_STREAMS_UNI:
        return QuicFrame(decodeUniMaxStreamsFrame(cursor));
      case FrameType::DATA_BLOCKED:
        return QuicFrame(decodeDataBlockedFrame(cursor));
      case FrameType::STREAM_DATA_BLOCKED:
        return QuicFrame(decodeStreamDataBlockedFrame(cursor));
      case FrameType::STREAMS_BLOCKED_BIDI:
        return QuicFrame(decodeBiDiStreamsBlockedFrame(cursor));
      case FrameType::STREAMS_BLOCKED_UNI:
        return QuicFrame(decodeUniStreamsBlockedFrame(cursor));
      case FrameType::NEW_CONNECTION_ID:
        return QuicFrame(decodeNewConnectionIdFrame(cursor));
      case FrameType::RETIRE_CONNECTION_ID:
        return QuicFrame(decodeRetireConnectionIdFrame(cursor));
      case FrameType::PATH_CHALLENGE:
        return QuicFrame(decodePathChallengeFrame(cursor));
      case FrameType::PATH_RESPONSE:
        return QuicFrame(decodePathResponseFrame(cursor));
      case FrameType::CONNECTION_CLOSE:
        return QuicFrame(decodeConnectionCloseFrame(cursor));
      case FrameType::CONNECTION_CLOSE_APP_ERR:
        return QuicFrame(decodeApplicationClose(cursor));
      case FrameType::HANDSHAKE_DONE:
        return QuicFrame(decodeHandshakeDoneFrame(cursor));
      case FrameType::DATAGRAM: {
        consumedQueue = true;
        return QuicFrame(decodeDatagramFrame(queue, false /* hasLen */));
      }
      case FrameType::DATAGRAM_LEN: {
        consumedQueue = true;
        return QuicFrame(decodeDatagramFrame(queue, true /* hasLen */));
      }
      case FrameType::KNOB:
        res = decodeKnobFrame(cursor);
        if (res.hasError()) {
          throw QuicTransportException(
              res.error().message, *res.error().code.asTransportErrorCode());
        }
        return QuicFrame(*res);
      case FrameType::ACK_FREQUENCY:
        res = decodeAckFrequencyFrame(cursor);
        if (res.hasError()) {
          throw QuicTransportException(
              res.error().message, *res.error().code.asTransportErrorCode());
        }
        return *res;
      case FrameType::IMMEDIATE_ACK:
        return QuicFrame(decodeImmediateAckFrame(cursor));
      case FrameType::ACK_RECEIVE_TIMESTAMPS: {
        res = decodeAckFrameWithReceivedTimestamps(
            cursor, header, params, FrameType::ACK_RECEIVE_TIMESTAMPS);
        if (res.hasError()) {
          throw QuicTransportException(
              res.error().message, *res.error().code.asTransportErrorCode());
        }
        auto frame = *res;
        return frame;
      }
      case FrameType::ACK_EXTENDED:
        auto frame = QuicFrame(decodeAckExtendedFrame(cursor, header, params));
        return frame;
    }
  } catch (const std::exception& e) {
    error = true;
    throw QuicTransportException(
        fmt::format(
            "Frame format invalid, type={}, error={}",
            frameTypeInt->first,
            e.what()),
        TransportErrorCode::FRAME_ENCODING_ERROR);
  }
  error = true;
  throw QuicTransportException(
      folly::to<std::string>("Unknown frame, type=", frameTypeInt->first),
      TransportErrorCode::FRAME_ENCODING_ERROR);
}

// Parse packet

RegularQuicPacket decodeRegularPacket(
    PacketHeader&& header,
    const CodecParameters& params,
    std::unique_ptr<folly::IOBuf> packetData) {
  RegularQuicPacket packet(std::move(header));
  BufQueue queue;
  queue.append(std::move(packetData));
  if (UNLIKELY(queue.chainLength() == 0)) {
    return packet;
  }
  // Parse out one packet before any conditionals.
  packet.frames.push_back(parseFrame(queue, packet.header, params));
  while (queue.chainLength() > 0) {
    auto f = parseFrame(queue, packet.header, params);
    if (packet.frames.back().asPaddingFrame() && f.asPaddingFrame()) {
      packet.frames.back().asPaddingFrame()->numFrames++;
    } else {
      packet.frames.push_back(std::move(f));
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
