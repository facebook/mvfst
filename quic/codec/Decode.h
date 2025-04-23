/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#pragma once

#include <folly/io/Cursor.h>
#include <quic/QuicConstants.h>
#include <quic/codec/PacketNumber.h>
#include <quic/codec/Types.h>
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
  Optional<AckReceiveTimestampsConfig> maybeAckReceiveTimestampsConfig = none;
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
 * Decodes a version negotiation packet. Returns a none, if it cannot
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
[[nodiscard]] folly::Expected<RegularQuicPacket, QuicError> decodeRegularPacket(
    PacketHeader&& header,
    const CodecParameters& params,
    BufPtr packetData);

/**
 * Parses a single frame from the queue. Throws a QuicException if the frame
 * could not be parsed.
 */
[[nodiscard]] folly::Expected<QuicFrame, QuicError> parseFrame(
    BufQueue& queue,
    const PacketHeader& header,
    const CodecParameters& params);

/**
 * The following functions decode frames. They return an Expected with error
 * when decoding fails.
 */
[[nodiscard]] folly::Expected<PaddingFrame, QuicError> decodePaddingFrame(
    Cursor& cursor);

[[nodiscard]] folly::Expected<RstStreamFrame, QuicError> decodeRstStreamFrame(
    Cursor& cursor,
    bool reliable);

[[nodiscard]] folly::Expected<ConnectionCloseFrame, QuicError>
decodeConnectionCloseFrame(Cursor& cursor);

[[nodiscard]] folly::Expected<ConnectionCloseFrame, QuicError>
decodeApplicationClose(Cursor& cursor);

[[nodiscard]] folly::Expected<MaxDataFrame, QuicError> decodeMaxDataFrame(
    Cursor& cursor);

[[nodiscard]] folly::Expected<MaxStreamDataFrame, QuicError>
decodeMaxStreamDataFrame(Cursor& cursor);

[[nodiscard]] folly::Expected<MaxStreamsFrame, QuicError>
decodeBiDiMaxStreamsFrame(Cursor& cursor);

[[nodiscard]] folly::Expected<MaxStreamsFrame, QuicError>
decodeUniMaxStreamsFrame(Cursor& cursor);

[[nodiscard]] folly::Expected<PingFrame, QuicError> decodePingFrame(
    Cursor& cursor);

[[nodiscard]] folly::Expected<QuicFrame, QuicError> decodeKnobFrame(
    Cursor& cursor);

[[nodiscard]] folly::Expected<QuicSimpleFrame, QuicError>
decodeAckFrequencyFrame(Cursor& cursor);

[[nodiscard]] folly::Expected<ImmediateAckFrame, QuicError>
decodeImmediateAckFrame(Cursor& cursor);

[[nodiscard]] folly::Expected<DataBlockedFrame, QuicError>
decodeDataBlockedFrame(Cursor& cursor);

[[nodiscard]] folly::Expected<StreamDataBlockedFrame, QuicError>
decodeStreamDataBlockedFrame(Cursor& cursor);

[[nodiscard]] folly::Expected<StreamsBlockedFrame, QuicError>
decodeBiDiStreamsBlockedFrame(Cursor& cursor);

[[nodiscard]] folly::Expected<StreamsBlockedFrame, QuicError>
decodeUniStreamsBlockedFrame(Cursor& cursor);

[[nodiscard]] folly::Expected<NewConnectionIdFrame, QuicError>
decodeNewConnectionIdFrame(Cursor& cursor);

[[nodiscard]] folly::Expected<RetireConnectionIdFrame, QuicError>
decodeRetireConnectionIdFrame(Cursor& cursor);

[[nodiscard]] folly::Expected<StopSendingFrame, QuicError>
decodeStopSendingFrame(Cursor& cursor);

[[nodiscard]] folly::Expected<PathChallengeFrame, QuicError>
decodePathChallengeFrame(Cursor& cursor);

[[nodiscard]] folly::Expected<PathResponseFrame, QuicError>
decodePathResponseFrame(Cursor& cursor);

[[nodiscard]] folly::Expected<ReadAckFrame, QuicError> decodeAckFrame(
    Cursor& cursor,
    const PacketHeader& header,
    const CodecParameters& params,
    FrameType frameType = FrameType::ACK);

[[nodiscard]] folly::Expected<ReadAckFrame, QuicError> decodeAckExtendedFrame(
    Cursor& cursor,
    const PacketHeader& header,
    const CodecParameters& params);

[[nodiscard]] folly::Expected<QuicFrame, QuicError>
decodeAckFrameWithReceivedTimestamps(
    Cursor& cursor,
    const PacketHeader& header,
    const CodecParameters& params,
    FrameType frameType);

[[nodiscard]] folly::Expected<QuicFrame, QuicError> decodeAckFrameWithECN(
    Cursor& cursor,
    const PacketHeader& header,
    const CodecParameters& params);

[[nodiscard]] folly::Expected<ReadStreamFrame, QuicError> decodeStreamFrame(
    BufQueue& queue,
    StreamTypeField frameTypeField,
    bool isGroupFrame = false);

[[nodiscard]] folly::Expected<ReadCryptoFrame, QuicError> decodeCryptoFrame(
    Cursor& cursor);

[[nodiscard]] folly::Expected<ReadNewTokenFrame, QuicError> decodeNewTokenFrame(
    Cursor& cursor);

[[nodiscard]] folly::Expected<HandshakeDoneFrame, QuicError>
decodeHandshakeDoneFrame(Cursor& cursor);

[[nodiscard]] folly::Expected<uint64_t, TransportErrorCode>
parsePlaintextRetryOrNewToken(Cursor& cursor);

[[nodiscard]] folly::Expected<DatagramFrame, QuicError> decodeDatagramFrame(
    BufQueue& queue,
    bool hasLen);

/**
 * Parse the Invariant fields in Long Header.
 *
 * cursor: points to the byte just past initialByte. After parsing, cursor
 * will be moved to the byte right after Source Connection ID.
 */
[[nodiscard]] folly::Expected<ParsedLongHeaderInvariant, TransportErrorCode>
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
[[nodiscard]] folly::Expected<ParsedLongHeaderResult, TransportErrorCode>
parseLongHeader(uint8_t initialByte, Cursor& cursor);

// nodeType: Determine if we allow 0-len dst connection ids.
[[nodiscard]] folly::Expected<ParsedLongHeader, TransportErrorCode>
parseLongHeaderVariants(
    LongHeader::Types type,
    ParsedLongHeaderInvariant longHeaderInvariant,
    Cursor& cursor,
    QuicNodeType nodeType = QuicNodeType::Server);

[[nodiscard]] folly::Expected<ShortHeaderInvariant, TransportErrorCode>
parseShortHeaderInvariants(
    uint8_t initialByte,
    Cursor& cursor,
    size_t dstConnIdSize = kDefaultConnectionIdSize);

[[nodiscard]] folly::Expected<ShortHeader, TransportErrorCode> parseShortHeader(
    uint8_t initialByte,
    Cursor& cursor,
    size_t dstConnIdSize = kDefaultConnectionIdSize);

[[nodiscard]] folly::Expected<uint64_t, QuicError>
convertEncodedDurationToMicroseconds(
    uint8_t exponentToUse,
    uint64_t delay) noexcept;
} // namespace quic
