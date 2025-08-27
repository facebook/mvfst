/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#pragma once

#include <quic/QuicConstants.h>
#include <quic/codec/PacketNumber.h>
#include <quic/codec/Types.h>
#include <quic/common/ContiguousCursor.h>
#include <quic/common/Expected.h>
#include <quic/state/TransportSettings.h>

namespace quic {

/**
 * Connection level parameters needed by the codec to decode the packet
 * successfully.
 */
struct CodecParameters {
  // This must not be set to zero.
  uint8_t peerAckDelayExponent{kDefaultAckDelayExponent};
  QuicVersion version{QuicVersion::MVFST};
  Optional<AckReceiveTimestampsConfig> maybeAckReceiveTimestampsConfig =
      std::nullopt;
  ExtendedAckFeatureMaskType extendedAckFeatures{0};

  CodecParameters() = default;

  CodecParameters(
      uint8_t peerAckDelayExponentIn,
      QuicVersion versionIn,
      Optional<AckReceiveTimestampsConfig> maybeAckReceiveTimestampsConfigIn,
      ExtendedAckFeatureMaskType extendedAckFeaturesIn)
      : peerAckDelayExponent(peerAckDelayExponentIn),
        version(versionIn),
        maybeAckReceiveTimestampsConfig(
            std::move(maybeAckReceiveTimestampsConfigIn)),
        extendedAckFeatures(extendedAckFeaturesIn) {}

  CodecParameters(uint8_t peerAckDelayExponentIn, QuicVersion versionIn)
      : peerAckDelayExponent(peerAckDelayExponentIn), version(versionIn) {}
};

struct ParsedLongHeaderInvariant {
  uint8_t initialByte;
  LongHeaderInvariant invariant;
  size_t invariantLength;

  ParsedLongHeaderInvariant(
      uint8_t initialByteIn,
      LongHeaderInvariant headerInvariant,
      size_t length);
};

/**
 * Decodes a version negotiation packet. Returns a std::nullopt, if it cannot
 * decode the packet.
 */
Optional<VersionNegotiationPacket> decodeVersionNegotiation(
    const ParsedLongHeaderInvariant& longHeaderInvariant,
    Cursor& cursor);

/**
 * Decodes a single regular QUIC packet from the cursor.
 * PacketData represents data from 1 QUIC packet.
 * Throws with a QuicException if the data in the cursor is not a complete QUIC
 * packet or the packet could not be decoded correctly.
 */
[[nodiscard]] quic::Expected<RegularQuicPacket, QuicError> decodeRegularPacket(
    PacketHeader&& header,
    const CodecParameters& params,
    BufPtr packetData);

/**
 * Parses a single frame from the queue. Throws a QuicException if the frame
 * could not be parsed.
 */
[[nodiscard]] quic::Expected<QuicFrame, QuicError> parseFrame(
    BufQueue& queue,
    const PacketHeader& header,
    const CodecParameters& params);

/**
 * The following functions decode frames. They return an Expected with error
 * when decoding fails.
 */
[[nodiscard]] quic::Expected<PaddingFrame, QuicError> decodePaddingFrame(
    ContiguousReadCursor& cursor);

[[nodiscard]] quic::Expected<RstStreamFrame, QuicError> decodeRstStreamFrame(
    ContiguousReadCursor& cursor,
    bool reliable);

[[nodiscard]] quic::Expected<ConnectionCloseFrame, QuicError>
decodeConnectionCloseFrame(Cursor& cursor);

[[nodiscard]] quic::Expected<ConnectionCloseFrame, QuicError>
decodeApplicationClose(Cursor& cursor);

[[nodiscard]] quic::Expected<MaxDataFrame, QuicError> decodeMaxDataFrame(
    ContiguousReadCursor& cursor);

[[nodiscard]] quic::Expected<MaxStreamDataFrame, QuicError>
decodeMaxStreamDataFrame(ContiguousReadCursor& cursor);

[[nodiscard]] quic::Expected<MaxStreamsFrame, QuicError>
decodeBiDiMaxStreamsFrame(ContiguousReadCursor& cursor);

[[nodiscard]] quic::Expected<MaxStreamsFrame, QuicError>
decodeUniMaxStreamsFrame(ContiguousReadCursor& cursor);

[[nodiscard]] quic::Expected<PingFrame, QuicError> decodePingFrame(
    ContiguousReadCursor& cursor);

[[nodiscard]] quic::Expected<QuicFrame, QuicError> decodeKnobFrame(
    Cursor& cursor);

[[nodiscard]] quic::Expected<QuicSimpleFrame, QuicError>
decodeAckFrequencyFrame(Cursor& cursor);

[[nodiscard]] quic::Expected<ImmediateAckFrame, QuicError>
decodeImmediateAckFrame(Cursor& cursor);

[[nodiscard]] quic::Expected<DataBlockedFrame, QuicError>
decodeDataBlockedFrame(ContiguousReadCursor& cursor);

[[nodiscard]] quic::Expected<StreamDataBlockedFrame, QuicError>
decodeStreamDataBlockedFrame(ContiguousReadCursor& cursor);

[[nodiscard]] quic::Expected<StreamsBlockedFrame, QuicError>
decodeBiDiStreamsBlockedFrame(ContiguousReadCursor& cursor);

[[nodiscard]] quic::Expected<StreamsBlockedFrame, QuicError>
decodeUniStreamsBlockedFrame(ContiguousReadCursor& cursor);

[[nodiscard]] quic::Expected<NewConnectionIdFrame, QuicError>
decodeNewConnectionIdFrame(Cursor& cursor);

[[nodiscard]] quic::Expected<RetireConnectionIdFrame, QuicError>
decodeRetireConnectionIdFrame(Cursor& cursor);

[[nodiscard]] quic::Expected<StopSendingFrame, QuicError>
decodeStopSendingFrame(ContiguousReadCursor& cursor);

[[nodiscard]] quic::Expected<PathChallengeFrame, QuicError>
decodePathChallengeFrame(Cursor& cursor);

[[nodiscard]] quic::Expected<PathResponseFrame, QuicError>
decodePathResponseFrame(Cursor& cursor);

[[nodiscard]] quic::Expected<ReadAckFrame, QuicError> decodeAckFrame(
    ContiguousReadCursor& cursor,
    const PacketHeader& header,
    const CodecParameters& params,
    FrameType frameType = FrameType::ACK);

[[nodiscard]] quic::Expected<ReadAckFrame, QuicError> decodeAckExtendedFrame(
    ContiguousReadCursor& cursor,
    const PacketHeader& header,
    const CodecParameters& params);

[[nodiscard]] quic::Expected<QuicFrame, QuicError>
decodeAckFrameWithReceivedTimestamps(
    ContiguousReadCursor& cursor,
    const PacketHeader& header,
    const CodecParameters& params,
    FrameType frameType);

[[nodiscard]] quic::Expected<QuicFrame, QuicError> decodeAckFrameWithECN(
    ContiguousReadCursor& cursor,
    const PacketHeader& header,
    const CodecParameters& params);

[[nodiscard]] quic::Expected<ReadStreamFrame, QuicError> decodeStreamFrame(
    BufQueue& queue,
    StreamTypeField frameTypeField,
    bool isGroupFrame = false);

[[nodiscard]] quic::Expected<ReadCryptoFrame, QuicError> decodeCryptoFrame(
    ContiguousReadCursor& cursor);

[[nodiscard]] quic::Expected<ReadNewTokenFrame, QuicError> decodeNewTokenFrame(
    ContiguousReadCursor& cursor);

[[nodiscard]] quic::Expected<HandshakeDoneFrame, QuicError>
decodeHandshakeDoneFrame(Cursor& cursor);

[[nodiscard]] quic::Expected<uint64_t, TransportErrorCode>
parsePlaintextRetryOrNewToken(Cursor& cursor);

[[nodiscard]] quic::Expected<DatagramFrame, QuicError> decodeDatagramFrame(
    BufQueue& queue,
    bool hasLen);

/**
 * Parse the Invariant fields in Long Header.
 *
 * cursor: points to the byte just past initialByte. After parsing, cursor
 * will be moved to the byte right after Source Connection ID.
 */
[[nodiscard]] quic::Expected<ParsedLongHeaderInvariant, TransportErrorCode>
parseLongHeaderInvariant(uint8_t initalByte, Cursor& cursor);

struct PacketLength {
  // The length of the packet payload (including packet number)
  uint64_t packetLength;
  // Length of the length field.
  size_t lengthLength;

  PacketLength(uint64_t packetLengthIn, size_t lengthLengthIn)
      : packetLength(packetLengthIn), lengthLength(lengthLengthIn) {}
};

struct ParsedLongHeader {
  LongHeader header;
  PacketLength packetLength;

  ParsedLongHeader(LongHeader headerIn, PacketLength packetLengthIn)
      : header(std::move(headerIn)), packetLength(packetLengthIn) {}
};

struct ParsedLongHeaderResult {
  bool isVersionNegotiation;
  Optional<ParsedLongHeader> parsedLongHeader;

  ParsedLongHeaderResult(
      bool isVersionNegotiationIn,
      Optional<ParsedLongHeader> parsedLongHeaderIn);
};

// Functions that operate on the initial byte

LongHeader::Types parseLongHeaderType(uint8_t initialByte);

size_t parsePacketNumberLength(uint8_t initialByte);

/**
 * Returns the packet number and the length of the packet number.
 * packetNumberRange should be kMaxPacketNumEncodingSize size.
 */
std::pair<PacketNum, size_t> parsePacketNumber(
    uint8_t initialByte,
    ByteRange packetNumberRange,
    PacketNum expectedNextPacketNum);

// cursor: has to be point to the byte just past initialByte
[[nodiscard]] quic::Expected<ParsedLongHeaderResult, TransportErrorCode>
parseLongHeader(uint8_t initialByte, Cursor& cursor);

// nodeType: Determine if we allow 0-len dst connection ids.
[[nodiscard]] quic::Expected<ParsedLongHeader, TransportErrorCode>
parseLongHeaderVariants(
    LongHeader::Types type,
    ParsedLongHeaderInvariant longHeaderInvariant,
    Cursor& cursor,
    QuicNodeType nodeType = QuicNodeType::Server);

[[nodiscard]] quic::Expected<ShortHeaderInvariant, TransportErrorCode>
parseShortHeaderInvariants(
    uint8_t initialByte,
    Cursor& cursor,
    size_t dstConnIdSize = kDefaultConnectionIdSize);

[[nodiscard]] quic::Expected<ShortHeader, TransportErrorCode> parseShortHeader(
    uint8_t initialByte,
    Cursor& cursor,
    size_t dstConnIdSize = kDefaultConnectionIdSize);

[[nodiscard]] quic::Expected<uint64_t, QuicError>
convertEncodedDurationToMicroseconds(
    uint8_t exponentToUse,
    uint64_t delay) noexcept;
} // namespace quic
