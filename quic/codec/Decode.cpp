/*
 * Copyright (c) Facebook, Inc. and its affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 *
 */

#include <quic/codec/Decode.h>
#include <folly/String.h>
#include <quic/QuicException.h>
#include <quic/codec/PacketNumber.h>
#include <quic/codec/QuicInteger.h>

namespace {
// Minimum required length (in bytes) for the destination connection-id
constexpr size_t kMinInitialDestinationConnIdLength = 8;

template <class T>
inline std::string toHex(
    const typename std::enable_if<std::is_unsigned<T>::value, T>::type& type) {
  auto be = folly::Endian::big(type);
  return folly::to<std::string>(
      "0x", folly::hexlify(folly::ByteRange(&be, sizeof(be))));
}

quic::PacketNum nextAckedPacketGap(quic::PacketNum packetNum, uint64_t gap) {
  // Gap cannot overflow because of the definition of quic integer encoding, so
  // we can just add to gap.
  uint64_t adjustedGap = gap + 2;
  if (UNLIKELY(packetNum < adjustedGap)) {
    throw quic::QuicTransportException(
        "Bad gap",
        quic::TransportErrorCode::FRAME_ENCODING_ERROR,
        quic::FrameType::ACK);
  }
  return packetNum - adjustedGap;
}

quic::PacketNum nextAckedPacketLen(
    quic::PacketNum packetNum,
    uint64_t ackBlockLen) {
  // Going to allow 0 as a valid value.
  if (UNLIKELY(packetNum < ackBlockLen)) {
    throw quic::QuicTransportException(
        "Bad block len",
        quic::TransportErrorCode::FRAME_ENCODING_ERROR,
        quic::FrameType::ACK);
  }
  return packetNum - ackBlockLen;
}

// The octet following the version contains the lengths of the two connection ID
// fields that follow it
constexpr size_t kConnIdLengthOctet = 1;

} // namespace

namespace quic {

PaddingFrame decodePaddingFrame(folly::io::Cursor&) {
  return PaddingFrame();
}

PingFrame decodePingFrame(folly::io::Cursor& /* cursor */) {
  return PingFrame();
}

ReadAckFrame decodeAckFrame(
    folly::io::Cursor& cursor,
    const PacketHeader& header,
    const CodecParameters& params) {
  ReadAckFrame frame;
  auto largestAckedInt = decodeQuicInteger(cursor);
  if (UNLIKELY(!largestAckedInt)) {
    throw QuicTransportException(
        "Bad largest acked",
        quic::TransportErrorCode::FRAME_ENCODING_ERROR,
        quic::FrameType::ACK);
  }
  auto largestAcked = folly::to<PacketNum>(largestAckedInt->first);
  auto ackDelay = decodeQuicInteger(cursor);
  if (UNLIKELY(!ackDelay)) {
    throw QuicTransportException(
        "Bad ack delay",
        quic::TransportErrorCode::FRAME_ENCODING_ERROR,
        quic::FrameType::ACK);
  }
  auto additionalAckBlocks = decodeQuicInteger(cursor);
  if (UNLIKELY(!additionalAckBlocks)) {
    throw QuicTransportException(
        "Bad ack block count",
        quic::TransportErrorCode::FRAME_ENCODING_ERROR,
        quic::FrameType::ACK);
  }
  auto firstAckBlockLen = decodeQuicInteger(cursor);
  if (UNLIKELY(!firstAckBlockLen)) {
    throw QuicTransportException(
        "Bad first block",
        quic::TransportErrorCode::FRAME_ENCODING_ERROR,
        quic::FrameType::ACK);
  }
  // Using default ack delay for long header packets. Before negotiating
  // and ack delay, the sender has to use something, so they use the default
  // ack delay. To keep it consistent the protocol specifies using the same
  // ack delay for all the long header packets.
  uint8_t ackDelayExponentToUse = folly::variant_match(
      header,
      [](const LongHeader&) { return kDefaultAckDelayExponent; },
      [&params](auto&) { return params.peerAckDelayExponent; });
  DCHECK_LT(ackDelayExponentToUse, sizeof(ackDelay->first) * 8);
  // ackDelayExponentToUse is guaranteed to be less than the size of uint64_t
  uint64_t delayOverflowMask = 0xFFFFFFFFFFFFFFFF;
  uint8_t leftShift = (sizeof(ackDelay->first) * 8 - ackDelayExponentToUse);
  DCHECK_LT(leftShift, sizeof(delayOverflowMask) * 8);
  delayOverflowMask = delayOverflowMask << leftShift;
  if (UNLIKELY((ackDelay->first & delayOverflowMask) != 0)) {
    throw QuicTransportException(
        "Decoded ack delay overflows",
        quic::TransportErrorCode::FRAME_ENCODING_ERROR,
        quic::FrameType::ACK);
  }
  uint64_t adjustedAckDelay = ackDelay->first << ackDelayExponentToUse;
  if (UNLIKELY(
          adjustedAckDelay >
          std::numeric_limits<std::chrono::microseconds::rep>::max())) {
    throw QuicTransportException(
        "Bad ack delay",
        quic::TransportErrorCode::FRAME_ENCODING_ERROR,
        quic::FrameType::ACK);
  }
  PacketNum currentPacketNum =
      nextAckedPacketLen(largestAcked, firstAckBlockLen->first);
  frame.largestAcked = largestAcked;
  frame.ackDelay = std::chrono::microseconds(adjustedAckDelay);
  frame.ackBlocks.emplace_back(currentPacketNum, largestAcked);
  for (uint64_t numBlocks = 0; numBlocks < additionalAckBlocks->first;
       ++numBlocks) {
    auto currentGap = decodeQuicInteger(cursor);
    if (UNLIKELY(!currentGap)) {
      throw QuicTransportException(
          "Bad gap",
          quic::TransportErrorCode::FRAME_ENCODING_ERROR,
          quic::FrameType::ACK);
    }
    auto blockLen = decodeQuicInteger(cursor);
    if (UNLIKELY(!blockLen)) {
      throw QuicTransportException(
          "Bad block len",
          quic::TransportErrorCode::FRAME_ENCODING_ERROR,
          quic::FrameType::ACK);
    }
    PacketNum nextEndPacket =
        nextAckedPacketGap(currentPacketNum, currentGap->first);
    currentPacketNum = nextAckedPacketLen(nextEndPacket, blockLen->first);
    // We don't need to add the entry when the block length is zero since we
    // already would have processed it in the previous iteration.
    frame.ackBlocks.emplace_back(currentPacketNum, nextEndPacket);
  }
  return frame;
}

ReadAckFrame decodeAckFrameWithECN(
    folly::io::Cursor& cursor,
    const PacketHeader& header,
    const CodecParameters& params) {
  // TODO this is incomplete
  auto readAckFrame = decodeAckFrame(cursor, header, params);
  // TODO we simply ignore ECN blocks in ACK-ECN frames for now.
  auto ect_0 = decodeQuicInteger(cursor);
  if (UNLIKELY(!ect_0)) {
    throw QuicTransportException(
        "Bad ECT(0) value",
        quic::TransportErrorCode::FRAME_ENCODING_ERROR,
        quic::FrameType::ACK_ECN);
  }
  auto ect_1 = decodeQuicInteger(cursor);
  if (UNLIKELY(!ect_1)) {
    throw QuicTransportException(
        "Bad ECT(1) value",
        quic::TransportErrorCode::FRAME_ENCODING_ERROR,
        quic::FrameType::ACK_ECN);
  }
  auto ect_ce = decodeQuicInteger(cursor);
  if (UNLIKELY(!ect_ce)) {
    throw QuicTransportException(
        "Bad ECT-CE value",
        quic::TransportErrorCode::FRAME_ENCODING_ERROR,
        quic::FrameType::ACK_ECN);
  }
  return readAckFrame;
}

RstStreamFrame decodeRstStreamFrame(
    folly::io::Cursor& cursor,
    const CodecParameters& params) {
  auto streamId = decodeQuicInteger(cursor);
  if (UNLIKELY(!streamId)) {
    throw QuicTransportException(
        "Bad streamId",
        quic::TransportErrorCode::FRAME_ENCODING_ERROR,
        quic::FrameType::RST_STREAM);
  }
  ApplicationErrorCode errorCode;
  if (params.version == QuicVersion::MVFST_OLD) {
    errorCode = static_cast<ApplicationErrorCode>(
        cursor.readBE<ApplicationErrorCode>());
  } else {
    auto varCode = decodeQuicInteger(cursor);
    if (varCode) {
      errorCode = static_cast<ApplicationErrorCode>(varCode->first);
    } else {
      throw QuicTransportException(
          "Cannot decode error code",
          quic::TransportErrorCode::FRAME_ENCODING_ERROR,
          quic::FrameType::RST_STREAM);
    }
  }
  auto offset = decodeQuicInteger(cursor);
  if (UNLIKELY(!offset)) {
    throw QuicTransportException(
        "Bad offset",
        quic::TransportErrorCode::FRAME_ENCODING_ERROR,
        quic::FrameType::RST_STREAM);
  }
  return RstStreamFrame(
      folly::to<StreamId>(streamId->first), errorCode, offset->first);
}

StopSendingFrame decodeStopSendingFrame(
    folly::io::Cursor& cursor,
    const CodecParameters& params) {
  auto streamId = decodeQuicInteger(cursor);
  if (UNLIKELY(!streamId)) {
    throw QuicTransportException(
        "Bad streamId",
        quic::TransportErrorCode::FRAME_ENCODING_ERROR,
        quic::FrameType::STOP_SENDING);
  }
  ApplicationErrorCode errorCode;
  if (params.version == QuicVersion::MVFST_OLD) {
    errorCode = static_cast<ApplicationErrorCode>(
        cursor.readBE<ApplicationErrorCode>());
  } else {
    auto varCode = decodeQuicInteger(cursor);
    if (varCode) {
      errorCode = static_cast<ApplicationErrorCode>(varCode->first);
    } else {
      throw QuicTransportException(
          "Cannot decode error code",
          quic::TransportErrorCode::FRAME_ENCODING_ERROR,
          quic::FrameType::STOP_SENDING);
    }
  }
  return StopSendingFrame(folly::to<StreamId>(streamId->first), errorCode);
}

ReadCryptoFrame decodeCryptoFrame(folly::io::Cursor& cursor) {
  auto optionalOffset = decodeQuicInteger(cursor);
  if (!optionalOffset) {
    throw QuicTransportException(
        "Invalid offset",
        quic::TransportErrorCode::FRAME_ENCODING_ERROR,
        quic::FrameType::CRYPTO_FRAME);
  }
  uint64_t offset = optionalOffset->first;

  auto dataLength = decodeQuicInteger(cursor);
  if (!dataLength) {
    throw QuicTransportException(
        "Invalid length",
        quic::TransportErrorCode::FRAME_ENCODING_ERROR,
        quic::FrameType::CRYPTO_FRAME);
  }
  Buf data;
  if (cursor.totalLength() < dataLength->first) {
    throw QuicTransportException(
        "Length mismatch",
        quic::TransportErrorCode::FRAME_ENCODING_ERROR,
        quic::FrameType::CRYPTO_FRAME);
  }
  // If dataLength > data's actual length then the cursor will throw.
  cursor.clone(data, dataLength->first);
  return ReadCryptoFrame(offset, std::move(data));
}

ReadNewTokenFrame decodeNewTokenFrame(folly::io::Cursor& cursor) {
  auto tokenLength = decodeQuicInteger(cursor);
  if (!tokenLength) {
    throw QuicTransportException(
        "Invalid length",
        quic::TransportErrorCode::FRAME_ENCODING_ERROR,
        quic::FrameType::NEW_TOKEN);
  }
  Buf token;
  if (cursor.totalLength() < tokenLength->first) {
    throw QuicTransportException(
        "Length mismatch",
        quic::TransportErrorCode::FRAME_ENCODING_ERROR,
        quic::FrameType::NEW_TOKEN);
  }
  // If tokenLength > token's actual length then the cursor will throw.
  cursor.clone(token, tokenLength->first);
  return ReadNewTokenFrame(std::move(token));
}

ReadStreamFrame decodeStreamFrame(
    folly::io::Cursor& cursor,
    StreamTypeField frameTypeField) {
  auto streamId = decodeQuicInteger(cursor);
  if (!streamId) {
    throw QuicTransportException(
        "Invalid stream id",
        quic::TransportErrorCode::FRAME_ENCODING_ERROR,
        quic::FrameType::STREAM);
  }
  uint64_t offset = 0;
  if (frameTypeField.hasOffset()) {
    auto optionalOffset = decodeQuicInteger(cursor);
    if (!optionalOffset) {
      throw QuicTransportException(
          "Invalid offset",
          quic::TransportErrorCode::FRAME_ENCODING_ERROR,
          quic::FrameType::STREAM);
    }
    offset = optionalOffset->first;
  }
  auto fin = frameTypeField.hasFin();
  folly::Optional<std::pair<uint64_t, size_t>> dataLength;
  if (frameTypeField.hasDataLength()) {
    dataLength = decodeQuicInteger(cursor);
    if (!dataLength) {
      throw QuicTransportException(
          "Invalid length",
          quic::TransportErrorCode::FRAME_ENCODING_ERROR,
          quic::FrameType::STREAM);
    }
  }
  Buf data;
  if (dataLength.hasValue()) {
    if (cursor.totalLength() < dataLength->first) {
      throw QuicTransportException(
          "Length mismatch",
          quic::TransportErrorCode::FRAME_ENCODING_ERROR,
          quic::FrameType::STREAM);
    }
    // If dataLength > data's actual length then the cursor will throw.
    cursor.clone(data, dataLength->first);
  } else {
    // Missing Data Length field doesn't mean no data. It means the rest of the
    // frame are all data.
    cursor.clone(data, cursor.totalLength());
  }
  return ReadStreamFrame(
      folly::to<StreamId>(streamId->first), offset, std::move(data), fin);
}

MaxDataFrame decodeMaxDataFrame(folly::io::Cursor& cursor) {
  auto maximumData = decodeQuicInteger(cursor);
  if (UNLIKELY(!maximumData)) {
    throw QuicTransportException(
        "Bad Max Data",
        quic::TransportErrorCode::FRAME_ENCODING_ERROR,
        quic::FrameType::MAX_DATA);
  }
  return MaxDataFrame(maximumData->first);
}

MaxStreamDataFrame decodeMaxStreamDataFrame(folly::io::Cursor& cursor) {
  auto streamId = decodeQuicInteger(cursor);
  if (UNLIKELY(!streamId)) {
    throw QuicTransportException(
        "Invalid streamId",
        quic::TransportErrorCode::FRAME_ENCODING_ERROR,
        quic::FrameType::MAX_STREAM_DATA);
  }
  auto offset = decodeQuicInteger(cursor);
  if (UNLIKELY(!offset)) {
    throw QuicTransportException(
        "Invalid offset",
        quic::TransportErrorCode::FRAME_ENCODING_ERROR,
        quic::FrameType::MAX_STREAM_DATA);
  }
  return MaxStreamDataFrame(
      folly::to<StreamId>(streamId->first), offset->first);
}

MaxStreamsFrame decodeBiDiMaxStreamsFrame(folly::io::Cursor& cursor) {
  auto streamCount = decodeQuicInteger(cursor);
  if (UNLIKELY(!streamCount)) {
    throw QuicTransportException(
        "Invalid Bi-directional streamId",
        quic::TransportErrorCode::FRAME_ENCODING_ERROR,
        quic::FrameType::MAX_STREAMS_BIDI);
  }
  return MaxStreamsFrame(streamCount->first, true /* isBidirectional*/);
}

MaxStreamsFrame decodeUniMaxStreamsFrame(folly::io::Cursor& cursor) {
  auto streamCount = decodeQuicInteger(cursor);
  if (UNLIKELY(!streamCount)) {
    throw QuicTransportException(
        "Invalid Uni-directional streamId",
        quic::TransportErrorCode::FRAME_ENCODING_ERROR,
        quic::FrameType::MAX_STREAMS_UNI);
  }
  return MaxStreamsFrame(streamCount->first, false /* isUnidirectional */);
}

DataBlockedFrame decodeDataBlockedFrame(folly::io::Cursor& cursor) {
  auto dataLimit = decodeQuicInteger(cursor);
  if (UNLIKELY(!dataLimit)) {
    throw QuicTransportException(
        "Bad offset",
        quic::TransportErrorCode::FRAME_ENCODING_ERROR,
        quic::FrameType::DATA_BLOCKED);
  }
  return DataBlockedFrame(dataLimit->first);
}

StreamDataBlockedFrame decodeStreamDataBlockedFrame(folly::io::Cursor& cursor) {
  auto streamId = decodeQuicInteger(cursor);
  if (UNLIKELY(!streamId)) {
    throw QuicTransportException(
        "Bad streamId",
        quic::TransportErrorCode::FRAME_ENCODING_ERROR,
        quic::FrameType::STREAM_DATA_BLOCKED);
  }
  auto dataLimit = decodeQuicInteger(cursor);
  if (UNLIKELY(!dataLimit)) {
    throw QuicTransportException(
        "Bad offset",
        quic::TransportErrorCode::FRAME_ENCODING_ERROR,
        quic::FrameType::STREAM_DATA_BLOCKED);
  }
  return StreamDataBlockedFrame(
      folly::to<StreamId>(streamId->first), dataLimit->first);
}

StreamsBlockedFrame decodeBiDiStreamsBlockedFrame(folly::io::Cursor& cursor) {
  auto streamId = decodeQuicInteger(cursor);
  if (UNLIKELY(!streamId)) {
    throw QuicTransportException(
        "Bad Bi-Directional streamId",
        quic::TransportErrorCode::FRAME_ENCODING_ERROR,
        quic::FrameType::STREAMS_BLOCKED_BIDI);
  }
  return StreamsBlockedFrame(
      folly::to<StreamId>(streamId->first), true /* isBidirectional */);
}

StreamsBlockedFrame decodeUniStreamsBlockedFrame(folly::io::Cursor& cursor) {
  auto streamId = decodeQuicInteger(cursor);
  if (UNLIKELY(!streamId)) {
    throw QuicTransportException(
        "Bad Uni-direcitonal streamId",
        quic::TransportErrorCode::FRAME_ENCODING_ERROR,
        quic::FrameType::STREAMS_BLOCKED_UNI);
  }
  return StreamsBlockedFrame(
      folly::to<StreamId>(streamId->first), false /* isBidirectional */);
}

NewConnectionIdFrame decodeNewConnectionIdFrame(folly::io::Cursor& cursor) {
  auto sequence = decodeQuicInteger(cursor);
  if (UNLIKELY(!sequence)) {
    throw QuicTransportException(
        "Bad sequence",
        quic::TransportErrorCode::FRAME_ENCODING_ERROR,
        quic::FrameType::NEW_CONNECTION_ID);
  }
  if (!cursor.canAdvance(sizeof(uint8_t))) {
    throw QuicTransportException(
        "Not enough input bytes to read Dest. ConnectionId",
        quic::TransportErrorCode::FRAME_ENCODING_ERROR,
        quic::FrameType::NEW_CONNECTION_ID);
  }
  auto connIdLen = cursor.readBE<uint8_t>();
  if (UNLIKELY(cursor.totalLength() < connIdLen)) {
    throw QuicTransportException(
        "Bad connid",
        quic::TransportErrorCode::FRAME_ENCODING_ERROR,
        quic::FrameType::NEW_CONNECTION_ID);
  }
  if (connIdLen < kMinConnectionIdSize || connIdLen > kMaxConnectionIdSize) {
    throw QuicTransportException(
        "ConnectionId invalid length",
        quic::TransportErrorCode::FRAME_ENCODING_ERROR,
        quic::FrameType::NEW_CONNECTION_ID);
  }
  ConnectionId connId(cursor, connIdLen);
  StatelessResetToken statelessResetToken;
  cursor.pull(statelessResetToken.data(), statelessResetToken.size());
  return NewConnectionIdFrame(
      folly::to<uint16_t>(sequence->first),
      std::move(connId),
      std::move(statelessResetToken));
}

NoopFrame decodeRetireConnectionIdFrame(folly::io::Cursor& cursor) {
  // TODO we parse this frame, but return NoopFrame. Add proper support for it!
  auto sequenceNum = decodeQuicInteger(cursor);
  if (UNLIKELY(!sequenceNum)) {
    throw QuicTransportException(
        // TODO change the error code
        "Bad sequence num",
        quic::TransportErrorCode::FRAME_ENCODING_ERROR,
        quic::FrameType::RETIRE_CONNECTION_ID);
  }
  return NoopFrame();
}

PathChallengeFrame decodePathChallengeFrame(folly::io::Cursor& cursor) {
  // just parse and ignore expected data
  // A PATH_CHALLENGE frame contains 8 bytes
  if (!cursor.canAdvance(sizeof(uint64_t))) {
    throw QuicTransportException(
        "Not enough input bytes to read path challenge frame.",
        quic::TransportErrorCode::FRAME_ENCODING_ERROR,
        quic::FrameType::PATH_CHALLENGE);
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
        quic::TransportErrorCode::FRAME_ENCODING_ERROR,
        quic::FrameType::PATH_RESPONSE);
  }
  auto pathData = cursor.readBE<uint64_t>();
  return PathResponseFrame(pathData);
}

ConnectionCloseFrame decodeConnectionCloseFrame(
    folly::io::Cursor& cursor,
    const CodecParameters& params) {
  TransportErrorCode errorCode{};
  if (params.version == QuicVersion::MVFST_OLD) {
    auto detailedCode =
        cursor.readBE<std::underlying_type<TransportErrorCode>::type>();
    errorCode = static_cast<TransportErrorCode>(detailedCode);
  } else {
    auto varCode = decodeQuicInteger(cursor);
    if (varCode) {
      errorCode = static_cast<TransportErrorCode>(varCode->first);
    } else {
      throw QuicTransportException(
          "Failed to parse error code.",
          quic::TransportErrorCode::FRAME_ENCODING_ERROR,
          quic::FrameType::CONNECTION_CLOSE);
    }
  }
  auto frameTypeField = decodeQuicInteger(cursor);
  if (UNLIKELY(!frameTypeField || frameTypeField->second != sizeof(uint8_t))) {
    throw QuicTransportException(
        "Bad connection close triggering frame type value",
        quic::TransportErrorCode::FRAME_ENCODING_ERROR,
        quic::FrameType::CONNECTION_CLOSE);
  }
  FrameType triggeringFrameType = static_cast<FrameType>(frameTypeField->first);
  auto reasonPhraseLength = decodeQuicInteger(cursor);
  if (UNLIKELY(
          !reasonPhraseLength ||
          reasonPhraseLength->first > kMaxReasonPhraseLength)) {
    throw QuicTransportException(
        "Bad reason phrase length",
        quic::TransportErrorCode::FRAME_ENCODING_ERROR,
        quic::FrameType::CONNECTION_CLOSE);
  }
  auto reasonPhrase =
      cursor.readFixedString(folly::to<size_t>(reasonPhraseLength->first));
  return ConnectionCloseFrame(
      errorCode, std::move(reasonPhrase), triggeringFrameType);
}

ApplicationCloseFrame decodeApplicationCloseFrame(
    folly::io::Cursor& cursor,
    const CodecParameters& params) {
  ApplicationErrorCode errorCode{};
  if (params.version == QuicVersion::MVFST_OLD) {
    auto detailedCode = cursor.readBE<ApplicationErrorCode>();
    errorCode = static_cast<ApplicationErrorCode>(detailedCode);
  } else {
    auto varCode = decodeQuicInteger(cursor);
    if (varCode) {
      errorCode = static_cast<ApplicationErrorCode>(varCode->first);
    } else {
      throw QuicTransportException(
          "Failed to parse error code.",
          quic::TransportErrorCode::FRAME_ENCODING_ERROR,
          quic::FrameType::APPLICATION_CLOSE);
    }
  }
  auto reasonPhraseLength = decodeQuicInteger(cursor);
  if (UNLIKELY(
          !reasonPhraseLength ||
          reasonPhraseLength->first > kMaxReasonPhraseLength)) {
    throw QuicTransportException(
        "Bad reason phrase length",
        quic::TransportErrorCode::FRAME_ENCODING_ERROR,
        quic::FrameType::APPLICATION_CLOSE);
  }
  auto reasonPhrase =
      cursor.readFixedString(folly::to<size_t>(reasonPhraseLength->first));
  return ApplicationCloseFrame(errorCode, std::move(reasonPhrase));
}

MinStreamDataFrame decodeMinStreamDataFrame(folly::io::Cursor& cursor) {
  auto streamId = decodeQuicInteger(cursor);
  if (UNLIKELY(!streamId)) {
    throw QuicTransportException(
        "Invalid streamId",
        quic::TransportErrorCode::FRAME_ENCODING_ERROR,
        quic::FrameType::MIN_STREAM_DATA);
  }
  auto maximumData = decodeQuicInteger(cursor);
  if (UNLIKELY(!maximumData)) {
    throw QuicTransportException(
        "Invalid maximumData",
        quic::TransportErrorCode::FRAME_ENCODING_ERROR,
        quic::FrameType::MIN_STREAM_DATA);
  }
  auto minimumStreamOffset = decodeQuicInteger(cursor);
  if (UNLIKELY(!minimumStreamOffset)) {
    throw QuicTransportException(
        "Invalid minimumStreamOffset",
        quic::TransportErrorCode::FRAME_ENCODING_ERROR,
        quic::FrameType::MIN_STREAM_DATA);
  }
  return MinStreamDataFrame(
      folly::to<StreamId>(streamId->first),
      maximumData->first,
      minimumStreamOffset->first);
}

ExpiredStreamDataFrame decodeExpiredStreamDataFrame(folly::io::Cursor& cursor) {
  auto streamId = decodeQuicInteger(cursor);
  if (UNLIKELY(!streamId)) {
    throw QuicTransportException(
        "Invalid streamId",
        quic::TransportErrorCode::FRAME_ENCODING_ERROR,
        quic::FrameType::EXPIRED_STREAM_DATA);
  }
  auto minimumStreamOffset = decodeQuicInteger(cursor);
  if (UNLIKELY(!minimumStreamOffset)) {
    throw QuicTransportException(
        "Invalid minimumStreamOffset",
        quic::TransportErrorCode::FRAME_ENCODING_ERROR,
        quic::FrameType::EXPIRED_STREAM_DATA);
  }
  return ExpiredStreamDataFrame(
      folly::to<StreamId>(streamId->first), minimumStreamOffset->first);
}

QuicFrame parseFrame(
    folly::io::Cursor& cursor,
    const PacketHeader& header,
    const CodecParameters& params) {
  if (!cursor.canAdvance(sizeof(FrameType))) {
    throw QuicTransportException(
        "Quic frame parsing: cursor cannot advance",
        TransportErrorCode::FRAME_ENCODING_ERROR);
  }
  auto initialByte = decodeQuicInteger(cursor);
  // TODO add an new api to determine whether the frametype is encoded minimally
  if (UNLIKELY(!initialByte)) {
    throw QuicTransportException(
        "Invalid frame-type field", TransportErrorCode::FRAME_ENCODING_ERROR);
  }
  FrameType frameType = static_cast<FrameType>(initialByte->first);
  try {
    switch (frameType) {
      case FrameType::PADDING:
        return QuicFrame(decodePaddingFrame(cursor));
      case FrameType::PING:
        return QuicFrame(decodePingFrame(cursor));
      case FrameType::ACK:
        return QuicFrame(decodeAckFrame(cursor, header, params));
      case FrameType::ACK_ECN:
        return QuicFrame(decodeAckFrameWithECN(cursor, header, params));
      case FrameType::RST_STREAM:
        return QuicFrame(decodeRstStreamFrame(cursor, params));
      case FrameType::STOP_SENDING:
        return QuicFrame(decodeStopSendingFrame(cursor, params));
      case FrameType::CRYPTO_FRAME:
        return QuicFrame(decodeCryptoFrame(cursor));
      case FrameType::NEW_TOKEN:
        return QuicFrame(decodeNewTokenFrame(cursor));
      case FrameType::STREAM:
        // Stream frames are special and have several values.
        break;
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
        return QuicFrame(decodeConnectionCloseFrame(cursor, params));
      case FrameType::APPLICATION_CLOSE:
        return QuicFrame(decodeApplicationCloseFrame(cursor, params));
      case FrameType::MIN_STREAM_DATA:
        return QuicFrame(decodeMinStreamDataFrame(cursor));
      case FrameType::EXPIRED_STREAM_DATA:
        return QuicFrame(decodeExpiredStreamDataFrame(cursor));
    }
    auto streamFieldType = StreamTypeField::tryStream(initialByte->first);
    if (streamFieldType) {
      return QuicFrame(decodeStreamFrame(cursor, *streamFieldType));
    }
  } catch (const std::exception& e) {
    throw QuicTransportException(
        folly::to<std::string>(
            "Frame format invalid, type=", toHex<uint8_t>(initialByte->first)),
        TransportErrorCode::FRAME_ENCODING_ERROR,
        frameType);
  }
  throw QuicTransportException(
      folly::to<std::string>(
          "Unknown frame, type=", toHex<uint8_t>(initialByte->first)),
      TransportErrorCode::FRAME_ENCODING_ERROR,
      frameType);
}

// Parse packet

static std::vector<QuicFrame> framesDecodeHelper(
    folly::io::Cursor& cursor,
    const PacketHeader& header,
    const CodecParameters& params) {
  std::vector<QuicFrame> frames;
  while (cursor.totalLength()) {
    auto frame = parseFrame(cursor, header, params);
    frames.push_back(std::move(frame));
  }
  return frames;
}

RegularQuicPacket decodeRegularPacket(
    PacketHeader&& header,
    const CodecParameters& params,
    folly::io::Cursor& cursor) {
  RegularQuicPacket packet(std::move(header));
  packet.frames = framesDecodeHelper(cursor, header, params);
  return packet;
}

folly::Optional<VersionNegotiationPacket> decodeVersionNegotiation(
    const ParsedLongHeaderInvariant& longHeaderInvariant,
    folly::io::Cursor& cursor) {
  auto cursorLength = cursor.totalLength();

  if (cursorLength < sizeof(QuicVersionType) ||
      cursorLength % sizeof(QuicVersionType)) {
    VLOG(4) << "Version negotiation packet invalid";
    return folly::none;
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
    folly::Optional<ParsedLongHeader> parsedLongHeaderIn)
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
  if (version == QuicVersion::MVFST_OLD) {
    if (!cursor.canAdvance(kConnIdLengthOctet)) {
      VLOG(5) << "Not enough input bytes to read ConnectionId lengths";
      return folly::makeUnexpected(TransportErrorCode::FRAME_ENCODING_ERROR);
    }
    // Octet with source and destination connId lens encoded as: DCIL(4)|SCIL(4)
    uint8_t encodedConnIdlens = cursor.readBE<uint8_t>();
    auto connIdLens = decodeConnectionIdLengths(encodedConnIdlens);
    uint8_t destConnIdLen = connIdLens.first;
    uint8_t srcConnIdLen = connIdLens.second;

    if (!cursor.canAdvance(destConnIdLen)) {
      VLOG(5) << "Not enough input bytes to read Dest. ConnectionId";
      return folly::makeUnexpected(TransportErrorCode::FRAME_ENCODING_ERROR);
    }
    ConnectionId destConnId(cursor, destConnIdLen);

    if (!cursor.canAdvance(srcConnIdLen)) {
      VLOG(5) << "Not enough input bytes to read Source ConnectionId";
      return folly::makeUnexpected(TransportErrorCode::FRAME_ENCODING_ERROR);
    }
    ConnectionId srcConnId(cursor, srcConnIdLen);
    size_t currentLength = cursor.totalLength();
    size_t bytesRead = initialLength - currentLength;
    return ParsedLongHeaderInvariant(
        initialByte,
        LongHeaderInvariant(
            version, std::move(srcConnId), std::move(destConnId)),
        bytesRead);
  } else {
    if (!cursor.canAdvance(1)) {
      VLOG(5) << "Not enough input bytes to read Dest. ConnectionId length";
      return folly::makeUnexpected(TransportErrorCode::FRAME_ENCODING_ERROR);
    }
    uint8_t destConnIdLen = cursor.readBE<uint8_t>();
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
    if (!cursor.canAdvance(srcConnIdLen)) {
      VLOG(5) << "Not enough input bytes to read Source ConnectionId";
      return folly::makeUnexpected(TransportErrorCode::FRAME_ENCODING_ERROR);
    }
    ConnectionId srcConnId(cursor, srcConnIdLen);
    size_t currentLength = cursor.totalLength();
    size_t bytesRead = initialLength - currentLength;
    return ParsedLongHeaderInvariant(
        initialByte,
        LongHeaderInvariant(
            version, std::move(srcConnId), std::move(destConnId)),
        bytesRead);
  }
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
    return ParsedLongHeaderResult(true, folly::none);
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
    folly::io::Cursor& cursor) {
  if (type == LongHeader::Types::Retry) {
    auto cursorLength = cursor.totalLength();
    auto odcidLenField = parsedLongHeaderInvariant.initialByte & 0X0F;
    uint8_t originalDstConnIdLen = odcidLenField == 0 ? 0 : odcidLenField + 3;
    if (cursorLength < originalDstConnIdLen) {
      VLOG(5) << "Not enough bytes for ODCID";
      return folly::makeUnexpected(TransportErrorCode::FRAME_ENCODING_ERROR);
    }
    ConnectionId originalDstConnId(cursor, originalDstConnIdLen);

    if (cursorLength - originalDstConnId.size() == 0) {
      VLOG(5) << "Not enough bytes for retry token";
      return folly::makeUnexpected(TransportErrorCode::FRAME_ENCODING_ERROR);
    }

    cursorLength -= originalDstConnId.size();

    Buf token;
    cursor.clone(token, cursorLength);

    return ParsedLongHeader(
        LongHeader(
            type,
            std::move(parsedLongHeaderInvariant.invariant),
            std::move(token),
            std::move(originalDstConnId)),
        PacketLength(0, 0));
  }

  if (type == LongHeader::Types::Initial &&
      parsedLongHeaderInvariant.invariant.dstConnId.size() <
          kMinInitialDestinationConnIdLength) {
    VLOG(5) << "Dest Conn-Id length in initial packet must be >= 8 bytes";
    return folly::makeUnexpected(TransportErrorCode::FRAME_ENCODING_ERROR);
  }
  Buf token;
  if (type == LongHeader::Types::Initial) {
    auto tokenLen = decodeQuicInteger(cursor);
    if (UNLIKELY(!tokenLen)) {
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
  if (UNLIKELY(!pktLen)) {
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
          std::move(token)),
      PacketLength(pktLen->first, pktLen->second));
}

folly::Expected<ShortHeaderInvariant, TransportErrorCode>
parseShortHeaderInvariants(uint8_t initialByte, folly::io::Cursor& cursor) {
  if (getHeaderForm(initialByte) != HeaderForm::Short) {
    VLOG(5) << "Bad header form bit";
    return folly::makeUnexpected(TransportErrorCode::FRAME_ENCODING_ERROR);
  }
  // TODO(t39154014, yangchi): read the length from the connection state in
  // draft-17
  if (!cursor.canAdvance(kDefaultConnectionIdSize)) {
    VLOG(5) << "Not enough input bytes for ConnectionId";
    return folly::makeUnexpected(TransportErrorCode::FRAME_ENCODING_ERROR);
  }
  ConnectionId connId(cursor, kDefaultConnectionIdSize);
  return ShortHeaderInvariant(std::move(connId));
}

folly::Expected<ShortHeader, TransportErrorCode> parseShortHeader(
    uint8_t initialByte,
    folly::io::Cursor& cursor) {
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
  auto invariant = parseShortHeaderInvariants(initialByte, cursor);
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
