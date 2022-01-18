/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#pragma once

#include <folly/io/Cursor.h>
#include <quic/codec/PacketNumber.h>
#include <quic/codec/Types.h>

namespace quic {

/**
 * Connection level parameters needed by the codec to decode the packet
 * successfully.
 */
struct CodecParameters {
  // This must not be set to zero.
  uint8_t peerAckDelayExponent{kDefaultAckDelayExponent};
  QuicVersion version{QuicVersion::MVFST};

  CodecParameters() = default;

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
 * Decodes a version negotiation packet. Returns a folly::none, if it cannot
 * decode the packet.
 */
folly::Optional<VersionNegotiationPacket> decodeVersionNegotiation(
    const ParsedLongHeaderInvariant& longHeaderInvariant,
    folly::io::Cursor& cursor);

/**
 * Decodes a single regular QUIC packet from the cursor.
 * PacketData represents data from 1 QUIC packet.
 * Throws with a QuicException if the data in the cursor is not a complete QUIC
 * packet or the packet could not be decoded correctly.
 */
RegularQuicPacket decodeRegularPacket(
    PacketHeader&& header,
    const CodecParameters& params,
    std::unique_ptr<folly::IOBuf> packetData);

/**
 * Parses a single frame from the queue. Throws a QuicException if the frame
 * could not be parsed.
 */
QuicFrame parseFrame(
    BufQueue& queue,
    const PacketHeader& header,
    const CodecParameters& params);

/**
 * The following functions decode frames. They throw an QuicException when error
 * occurs.
 */
PaddingFrame decodePaddingFrame(folly::io::Cursor&);

RstStreamFrame decodeRstStreamFrame(folly::io::Cursor& cursor);

ConnectionCloseFrame decodeConnectionCloseFrame(folly::io::Cursor& cursor);

ConnectionCloseFrame decodeApplicationClose(folly::io::Cursor& cursor);

MaxDataFrame decodeMaxDataFrame(folly::io::Cursor& cursor);

MaxStreamDataFrame decodeMaxStreamDataFrame(folly::io::Cursor& cursor);

MaxStreamsFrame decodeBiDiMaxStreamsFrame(folly::io::Cursor& cursor);

MaxStreamsFrame decodeUniMaxStreamsFrame(folly::io::Cursor& cursor);

PingFrame decodePingFrame(folly::io::Cursor& cursor);

KnobFrame decodeKnobFrame(folly::io::Cursor& cursor);

AckFrequencyFrame decodeAckFrequencyFrame(folly::io::Cursor& cursor);

DataBlockedFrame decodeDataBlockedFrame(folly::io::Cursor& cursor);

StreamDataBlockedFrame decodeStreamDataBlockedFrame(folly::io::Cursor& cursor);

StreamsBlockedFrame decodeBiDiStreamsBlockedFrame(folly::io::Cursor& cursor);

StreamsBlockedFrame decodeUniStreamsBlockedFrame(folly::io::Cursor& cursor);

NewConnectionIdFrame decodeNewConnectionIdFrame(folly::io::Cursor& cursor);

RetireConnectionIdFrame decodeRetireConnectionIdFrame(
    folly::io::Cursor& cursor);

StopSendingFrame decodeStopSendingFrame(folly::io::Cursor& cursor);

PathChallengeFrame decodePathChallengeFrame(folly::io::Cursor& cursor);

PathResponseFrame decodePathResponseFrame(folly::io::Cursor& cursor);

ReadAckFrame decodeAckFrame(
    folly::io::Cursor& cursor,
    const PacketHeader& header,
    const CodecParameters& params);

ReadAckFrame decodeAckFrameWithECN(
    folly::io::Cursor& cursor,
    const PacketHeader& header,
    const CodecParameters& params);

ReadStreamFrame decodeStreamFrame(
    BufQueue& queue,
    StreamTypeField frameTypeField);

ReadCryptoFrame decodeCryptoFrame(folly::io::Cursor& cursor);

ReadNewTokenFrame decodeNewTokenFrame(folly::io::Cursor& cursor);

HandshakeDoneFrame decodeHandshakeDoneFrame(folly::io::Cursor& cursor);

folly::Expected<uint64_t, TransportErrorCode> parsePlaintextRetryOrNewToken(
    folly::io::Cursor& cursor);

DatagramFrame decodeDatagramFrame(BufQueue& queue, bool hasLen);

/**
 * Parse the Invariant fields in Long Header.
 *
 * cursor: points to the byte just past initialByte. After parsing, cursor will
 *         be moved to the byte right after Source Connection ID.
 */
folly::Expected<ParsedLongHeaderInvariant, TransportErrorCode>
parseLongHeaderInvariant(uint8_t initalByte, folly::io::Cursor& cursor);

struct PacketLength {
  // The length of the packet payload (inlcuding packet number)
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
  folly::Optional<ParsedLongHeader> parsedLongHeader;

  ParsedLongHeaderResult(
      bool isVersionNegotiationIn,
      folly::Optional<ParsedLongHeader> parsedLongHeaderIn);
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
    folly::ByteRange packetNumberRange,
    PacketNum expectedNextPacketNum);

// cursor: has to be point to the byte just past initialByte
folly::Expected<ParsedLongHeaderResult, TransportErrorCode> parseLongHeader(
    uint8_t initialByte,
    folly::io::Cursor& cursor);

// nodeType: Determine if we allow 0-len dst connection ids.
folly::Expected<ParsedLongHeader, TransportErrorCode> parseLongHeaderVariants(
    LongHeader::Types type,
    ParsedLongHeaderInvariant longHeaderInvariant,
    folly::io::Cursor& cursor,
    QuicNodeType nodeType = QuicNodeType::Server);

folly::Expected<ShortHeaderInvariant, TransportErrorCode>
parseShortHeaderInvariants(
    uint8_t initialByte,
    folly::io::Cursor& cursor,
    size_t dstConnIdSize = kDefaultConnectionIdSize);

folly::Expected<ShortHeader, TransportErrorCode> parseShortHeader(
    uint8_t initialByte,
    folly::io::Cursor& cursor,
    size_t dstConnIdSize = kDefaultConnectionIdSize);
} // namespace quic
