/*
 * Copyright (c) Facebook, Inc. and its affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 *
 */

#pragma once

#include <boost/variant.hpp>
#include <folly/Conv.h>
#include <folly/Optional.h>
#include <folly/Overload.h>
#include <folly/io/Cursor.h>
#include <folly/io/IOBuf.h>
#include <quic/QuicConstants.h>
#include <quic/QuicException.h>
#include <quic/codec/QuicConnectionId.h>
#include <quic/codec/QuicInteger.h>
#include <quic/common/IntervalSet.h>

/**
 * This details the types of objects that can be serialized or deserialized
 * over the wire.
 */

namespace quic {

using Buf = std::unique_ptr<folly::IOBuf>;

using StreamId = uint64_t;
using PacketNum = uint64_t;

enum class PacketNumberSpace : uint8_t {
  Initial,
  Handshake,
  AppData,
};

using StatelessResetToken = std::array<uint8_t, 16>;

constexpr uint8_t kHeaderFormMask = 0x80;
constexpr auto kMaxPacketNumEncodingSize = 4;

struct PaddingFrame {
  bool operator==(const PaddingFrame& /*rhs*/) const {
    return true;
  }
};

struct PingFrame {
  PingFrame() = default;

  bool operator==(const PingFrame& /*rhs*/) const {
    return true;
  }
};

/**
 * AckBlock represents a series of continuous packet sequences from
 * [startPacket, endPacket]
 */
struct AckBlock {
  PacketNum startPacket;
  PacketNum endPacket;

  AckBlock(PacketNum start, PacketNum end)
      : startPacket(start), endPacket(end) {}
};

/**
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 |                     Largest Acknowledged (i)                ...
 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 |                          ACK Delay (i)                      ...
 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 |                       ACK Block Count (i)                   ...
 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 |                          ACK Blocks (*)                     ...
 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 |                      First ACK Block (i)                    ...
 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 |                             Gap (i)                         ...
 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 |                    Additional ACK Block (i)                 ...
 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */
struct ReadAckFrame {
  PacketNum largestAcked;
  std::chrono::microseconds ackDelay;
  // Should have at least 1 block.
  // These are ordered in descending order by start packet.
  std::vector<AckBlock> ackBlocks;

  bool operator==(const ReadAckFrame& /*rhs*/) const {
    // Can't compare ackBlocks, function is just here to appease compiler.
    return false;
  }
};

struct WriteAckFrame {
  IntervalSet<PacketNum> ackBlocks;
  // Delay in sending ack from time that packet was received.
  std::chrono::microseconds ackDelay;

  bool operator==(const WriteAckFrame& /*rhs*/) const {
    // Can't compare ackBlocks, function is just here to appease compiler.
    return false;
  }
};

struct RstStreamFrame {
  StreamId streamId;
  ApplicationErrorCode errorCode;
  uint64_t offset;

  RstStreamFrame(
      StreamId streamIdIn,
      ApplicationErrorCode errorCodeIn,
      uint64_t offsetIn)
      : streamId(streamIdIn), errorCode(errorCodeIn), offset(offsetIn) {}

  bool operator==(const RstStreamFrame& rhs) const {
    return streamId == rhs.streamId && errorCode == rhs.errorCode &&
        offset == rhs.offset;
  }
};

struct StopSendingFrame {
  StreamId streamId;
  ApplicationErrorCode errorCode;

  StopSendingFrame(StreamId streamIdIn, ApplicationErrorCode errorCodeIn)
      : streamId(streamIdIn), errorCode(errorCodeIn) {}

  bool operator==(const StopSendingFrame& rhs) const {
    return streamId == rhs.streamId && errorCode == rhs.errorCode;
  }
};

struct ReadCryptoFrame {
  uint64_t offset;
  Buf data;

  ReadCryptoFrame(uint64_t offsetIn, Buf dataIn)
      : offset(offsetIn), data(std::move(dataIn)) {}

  explicit ReadCryptoFrame(uint64_t offsetIn)
      : offset(offsetIn), data(folly::IOBuf::create(0)) {}

  // Stuff stored in a variant type needs to be copyable.
  // TODO: can we make this copyable only by the variant, but not
  // by anyone else.
  ReadCryptoFrame(const ReadCryptoFrame& other) {
    offset = other.offset;
    if (other.data) {
      data = other.data->clone();
    }
  }

  ReadCryptoFrame(ReadCryptoFrame&& other) noexcept {
    offset = other.offset;
    data = std::move(other.data);
  }

  ReadCryptoFrame& operator=(const ReadCryptoFrame& other) {
    offset = other.offset;
    if (other.data) {
      data = other.data->clone();
    }
    return *this;
  }

  ReadCryptoFrame& operator=(ReadCryptoFrame&& other) {
    offset = other.offset;
    data = std::move(other.data);
    return *this;
  }

  bool operator==(const ReadCryptoFrame& other) const {
    folly::IOBufEqualTo eq;
    return offset == other.offset && eq(data, other.data);
  }
};

struct WriteCryptoFrame {
  uint64_t offset;
  uint64_t len;

  WriteCryptoFrame(uint64_t offsetIn, uint64_t lenIn)
      : offset(offsetIn), len(lenIn) {}

  bool operator==(const WriteCryptoFrame& rhs) const {
    return offset == rhs.offset && len == rhs.len;
  }
};

struct ReadNewTokenFrame {
  Buf token;

  ReadNewTokenFrame(Buf tokenIn) : token(std::move(tokenIn)) {}

  // Stuff stored in a variant type needs to be copyable.
  // TODO: can we make this copyable only by the variant, but not
  // by anyone else.
  ReadNewTokenFrame(const ReadNewTokenFrame& other) {
    if (other.token) {
      token = other.token->clone();
    }
  }

  ReadNewTokenFrame& operator=(const ReadNewTokenFrame& other) {
    if (other.token) {
      token = other.token->clone();
    }
    return *this;
  }

  bool operator==(const ReadNewTokenFrame& other) const {
    folly::IOBufEqualTo eq;
    return eq(token, other.token);
  }
};

/**
 The structure of the stream frame used for writes.
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 |                         Stream ID (i)                       ...
 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 |                         [Offset (i)]                        ...
 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 |                         [Length (i)]                        ...
 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 |                        Stream Data (*)                      ...
 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/
struct WriteStreamFrame {
  StreamId streamId;
  uint64_t offset;
  uint64_t len;
  bool fin;

  WriteStreamFrame(
      StreamId streamIdIn,
      uint64_t offsetIn,
      uint64_t lenIn,
      bool finIn)
      : streamId(streamIdIn), offset(offsetIn), len(lenIn), fin(finIn) {}

  bool operator==(const WriteStreamFrame& rhs) const {
    return streamId == rhs.streamId && offset == rhs.offset && len == rhs.len &&
        fin == rhs.fin;
  }
};

/**
 * The structure of the stream frame used for reads.
 */
struct ReadStreamFrame {
  StreamId streamId;
  uint64_t offset;
  Buf data;
  bool fin;

  ReadStreamFrame(
      StreamId streamIdIn,
      uint64_t offsetIn,
      Buf dataIn,
      bool finIn)
      : streamId(streamIdIn),
        offset(offsetIn),
        data(std::move(dataIn)),
        fin(finIn) {}

  ReadStreamFrame(StreamId streamIdIn, uint64_t offsetIn, bool finIn)
      : streamId(streamIdIn),
        offset(offsetIn),
        data(folly::IOBuf::create(0)),
        fin(finIn) {}

  // Stuff stored in a variant type needs to be copyable.
  // TODO: can we make this copyable only by the variant, but not
  // by anyone else.
  ReadStreamFrame(const ReadStreamFrame& other) {
    streamId = other.streamId;
    offset = other.offset;
    if (other.data) {
      data = other.data->clone();
    }
    fin = other.fin;
  }

  ReadStreamFrame(ReadStreamFrame&& other) noexcept {
    streamId = other.streamId;
    offset = other.offset;
    data = std::move(other.data);
    fin = other.fin;
  }

  ReadStreamFrame& operator=(const ReadStreamFrame& other) {
    streamId = other.streamId;
    offset = other.offset;
    if (other.data) {
      data = other.data->clone();
    }
    fin = other.fin;
    return *this;
  }

  ReadStreamFrame& operator=(ReadStreamFrame&& other) {
    streamId = other.streamId;
    offset = other.offset;
    data = std::move(other.data);
    fin = other.fin;
    return *this;
  }

  bool operator==(const ReadStreamFrame& other) const {
    folly::IOBufEqualTo eq;
    return streamId == other.streamId && offset == other.offset &&
        fin == other.fin && eq(data, other.data);
  }
};

struct MaxDataFrame {
  uint64_t maximumData;

  explicit MaxDataFrame(uint64_t maximumDataIn) : maximumData(maximumDataIn) {}

  bool operator==(const MaxDataFrame& rhs) const {
    return maximumData == rhs.maximumData;
  }
};

struct MaxStreamDataFrame {
  StreamId streamId;
  uint64_t maximumData;

  MaxStreamDataFrame(StreamId streamIdIn, uint64_t maximumDataIn)
      : streamId(streamIdIn), maximumData(maximumDataIn) {}

  bool operator==(const MaxStreamDataFrame& rhs) const {
    return streamId == rhs.streamId && maximumData == rhs.maximumData;
  }
};

// The MinStreamDataFrame is used by a receiver to inform
// a sender of the maximum amount of data that can be sent on a stream
// (like MAX_STREAM_DATA frame) and to request an update to the minimum
// retransmittable offset for this stream.
struct MinStreamDataFrame {
  StreamId streamId;
  uint64_t maximumData;
  uint64_t minimumStreamOffset;
  MinStreamDataFrame(
      StreamId streamIdIn,
      uint64_t maximumDataIn,
      uint64_t minimumStreamOffsetIn)
      : streamId(streamIdIn),
        maximumData(maximumDataIn),
        minimumStreamOffset(minimumStreamOffsetIn) {}

  bool operator==(const MinStreamDataFrame& rhs) const {
    return streamId == rhs.streamId && maximumData == rhs.maximumData &&
        minimumStreamOffset == rhs.minimumStreamOffset;
  }
};

// The ExpiredStreamDataFrame is used by a sender to
// inform a receiver of the minimum retransmittable offset for a stream.
struct ExpiredStreamDataFrame {
  StreamId streamId;
  uint64_t minimumStreamOffset;
  ExpiredStreamDataFrame(StreamId streamIdIn, uint64_t minimumStreamOffsetIn)
      : streamId(streamIdIn), minimumStreamOffset(minimumStreamOffsetIn) {}

  bool operator==(const ExpiredStreamDataFrame& rhs) const {
    return streamId == rhs.streamId &&
        minimumStreamOffset == rhs.minimumStreamOffset;
  }
};

struct MaxStreamsFrame {
  // A count of the cumulative number of streams
  uint64_t maxStreams;
  bool isForBidirectional{false};

  explicit MaxStreamsFrame(uint64_t maxStreamsIn, bool isBidirectionalIn)
      : maxStreams(maxStreamsIn), isForBidirectional(isBidirectionalIn) {}

  bool isForBidirectionalStream() const {
    return isForBidirectional;
  }

  bool isForUnidirectionalStream() {
    return !isForBidirectional;
  }

  bool operator==(const MaxStreamsFrame& rhs) const {
    return maxStreams == rhs.maxStreams &&
        isForBidirectional == rhs.isForBidirectional;
  }
};

struct DataBlockedFrame {
  // the connection-level limit at which blocking occurred
  uint64_t dataLimit;

  explicit DataBlockedFrame(uint64_t dataLimitIn) : dataLimit(dataLimitIn) {}

  bool operator==(const DataBlockedFrame& rhs) const {
    return dataLimit == rhs.dataLimit;
  }
};

struct StreamDataBlockedFrame {
  StreamId streamId;
  uint64_t dataLimit;

  StreamDataBlockedFrame(StreamId streamIdIn, uint64_t dataLimitIn)
      : streamId(streamIdIn), dataLimit(dataLimitIn) {}

  bool operator==(const StreamDataBlockedFrame& rhs) const {
    return streamId == rhs.streamId && dataLimit == rhs.dataLimit;
  }
};

struct StreamsBlockedFrame {
  uint64_t streamLimit;
  bool isForBidirectional{false};

  explicit StreamsBlockedFrame(uint64_t streamLimitIn, bool isBidirectionalIn)
      : streamLimit(streamLimitIn), isForBidirectional(isBidirectionalIn) {}

  bool isForBidirectionalStream() const {
    return isForBidirectional;
  }

  bool isForUnidirectionalStream() const {
    return !isForBidirectional;
  }

  bool operator==(const StreamsBlockedFrame& rhs) const {
    return streamLimit == rhs.streamLimit;
  }
};

struct NewConnectionIdFrame {
  uint16_t sequence;
  ConnectionId connectionId;
  StatelessResetToken token;

  NewConnectionIdFrame(
      uint16_t sequenceIn,
      ConnectionId connectionIdIn,
      StatelessResetToken tokenIn)
      : sequence(sequenceIn),
        connectionId(connectionIdIn),
        token(std::move(tokenIn)) {}

  bool operator==(const NewConnectionIdFrame& rhs) const {
    return sequence == rhs.sequence && connectionId == rhs.connectionId &&
        token == rhs.token;
  }
};

struct RetireConnectionIdFrame {
  uint64_t sequenceId;

  explicit RetireConnectionIdFrame(uint64_t sequenceIn)
      : sequenceId(sequenceIn) {}
};

struct PathChallengeFrame {
  uint64_t pathData;

  explicit PathChallengeFrame(uint64_t pathDataIn) : pathData(pathDataIn) {}

  bool operator==(const PathChallengeFrame& rhs) const {
    return pathData == rhs.pathData;
  }

  bool operator!=(const PathChallengeFrame& rhs) const {
    return !(*this == rhs);
  }
};

struct PathResponseFrame {
  uint64_t pathData;

  explicit PathResponseFrame(uint64_t pathDataIn) : pathData(pathDataIn) {}

  bool operator==(const PathResponseFrame& rhs) const {
    return pathData == rhs.pathData;
  }
};

struct ConnectionCloseFrame {
  // Members are not const to allow this to be movable.
  TransportErrorCode errorCode;
  std::string reasonPhrase;
  // Per QUIC specification: type of frame that triggered the (close) error.
  // A value of 0 (PADDING frame) implies the frame type is unknown
  FrameType closingFrameType;

  ConnectionCloseFrame(
      TransportErrorCode errorCodeIn,
      std::string reasonPhraseIn,
      FrameType closingFrameTypeIn = FrameType::PADDING)
      : errorCode(errorCodeIn),
        reasonPhrase(std::move(reasonPhraseIn)),
        closingFrameType(closingFrameTypeIn) {}

  FrameType getClosingFrameType() const noexcept {
    return closingFrameType;
  }

  bool operator==(const ConnectionCloseFrame& rhs) const {
    return errorCode == rhs.errorCode && reasonPhrase == rhs.reasonPhrase;
  }
};

struct ApplicationCloseFrame {
  // Members are not const to allow this to be movable.
  ApplicationErrorCode errorCode;
  std::string reasonPhrase;

  ApplicationCloseFrame(
      ApplicationErrorCode errorCodeIn,
      std::string reasonPhraseIn)
      : errorCode(errorCodeIn), reasonPhrase(std::move(reasonPhraseIn)) {}

  bool operator==(const ApplicationCloseFrame& rhs) const {
    return errorCode == rhs.errorCode && reasonPhrase == rhs.reasonPhrase;
  }
};

// Frame to represent ones we skip
struct NoopFrame {};

constexpr uint8_t kStatelessResetTokenLength = 16;
using StatelessResetToken = std::array<uint8_t, kStatelessResetTokenLength>;

struct StatelessReset {
  StatelessResetToken token;

  explicit StatelessReset(StatelessResetToken tokenIn)
      : token(std::move(tokenIn)) {}
};

using QuicSimpleFrame = boost::variant<
    StopSendingFrame,
    MinStreamDataFrame,
    ExpiredStreamDataFrame,
    PathChallengeFrame,
    PathResponseFrame,
    NewConnectionIdFrame>;

// Types of frames that can be read.
using QuicFrame = boost::variant<
    PaddingFrame,
    RstStreamFrame,
    ConnectionCloseFrame,
    ApplicationCloseFrame,
    MaxDataFrame,
    MaxStreamDataFrame,
    MaxStreamsFrame,
    PingFrame,
    DataBlockedFrame,
    StreamDataBlockedFrame,
    StreamsBlockedFrame,
    ReadAckFrame,
    ReadStreamFrame,
    ReadCryptoFrame,
    ReadNewTokenFrame,
    QuicSimpleFrame,
    NoopFrame>;

// Types of frames which are written.
using QuicWriteFrame = boost::variant<
    PaddingFrame,
    RstStreamFrame,
    ConnectionCloseFrame,
    ApplicationCloseFrame,
    MaxDataFrame,
    MaxStreamDataFrame,
    MaxStreamsFrame,
    StreamsBlockedFrame,
    PingFrame,
    DataBlockedFrame,
    StreamDataBlockedFrame,
    WriteAckFrame,
    WriteStreamFrame,
    WriteCryptoFrame,
    QuicSimpleFrame>;

enum class HeaderForm : bool {
  Long = 1,
  Short = 0,
};

enum class ProtectionType {
  Initial,
  Handshake,
  ZeroRtt,
  KeyPhaseZero,
  KeyPhaseOne,
};

struct LongHeaderInvariant {
  QuicVersion version;
  ConnectionId srcConnId;
  ConnectionId dstConnId;

  LongHeaderInvariant(QuicVersion ver, ConnectionId scid, ConnectionId dcid);
};

// TODO: split this into read and write types.
struct LongHeader {
 public:
  static constexpr uint8_t kFixedBitMask = 0x40;
  static constexpr uint8_t kPacketTypeMask = 0x30;
  static constexpr uint8_t kReservedBitsMask = 0x0c;
  static constexpr uint8_t kPacketNumLenMask = 0x03;
  static constexpr uint8_t kTypeBitsMask = 0x0F;

  static constexpr uint8_t kTypeShift = 4;
  enum class Types : uint8_t {
    Initial = 0x0,
    ZeroRtt = 0x1,
    Handshake = 0x2,
    Retry = 0x3,
  };

  LongHeader(
      Types type,
      const ConnectionId& srcConnId,
      const ConnectionId& dstConnId,
      PacketNum packetNum,
      QuicVersion version,
      Buf token = nullptr,
      folly::Optional<ConnectionId> originalDstConnId = folly::none);

  LongHeader(
      Types type,
      LongHeaderInvariant invariant,
      Buf token = nullptr,
      folly::Optional<ConnectionId> originalDstConnId = folly::none);

  void setPacketNumber(PacketNum packetNum);

  // Stuff stored in a variant type needs to be copyable.
  // TODO: can we make this copyable only by the variant, but not
  // by anyone else.
  LongHeader(const LongHeader& other);
  LongHeader& operator=(const LongHeader& other);

  Types getHeaderType() const noexcept;
  const ConnectionId& getSourceConnId() const;
  const ConnectionId& getDestinationConnId() const;
  const folly::Optional<ConnectionId>& getOriginalDstConnId() const;
  PacketNum getPacketSequenceNum() const;
  QuicVersion getVersion() const;
  ProtectionType getProtectionType() const;
  PacketNumberSpace getPacketNumberSpace() const noexcept;
  bool hasToken() const;
  folly::IOBuf* getToken() const;

 private:
  HeaderForm headerForm_;
  Types longHeaderType_;
  LongHeaderInvariant invariant_;
  folly::Optional<PacketNum> packetSequenceNum_; // at most 32 bits on wire
  Buf token_;
  folly::Optional<ConnectionId> originalDstConnId_;
};

struct ShortHeaderInvariant {
  ConnectionId destinationConnId;

  explicit ShortHeaderInvariant(ConnectionId dcid);
};

struct ShortHeader {
 public:
  // There is also a spin bit which is 0x20 that we don't currently implement.
  static constexpr uint8_t kFixedBitMask = 0x40;
  static constexpr uint8_t kReservedBitsMask = 0x18;
  static constexpr uint8_t kKeyPhaseMask = 0x04;
  static constexpr uint8_t kPacketNumLenMask = 0x03;
  static constexpr uint8_t kTypeBitsMask = 0x1F;

  /**
   * The constructor for reading a packet.
   */
  ShortHeader(ProtectionType protectionType, ConnectionId connId);

  /**
   * The constructor for writing a packet.
   */
  ShortHeader(
      ProtectionType protectionType,
      ConnectionId connId,
      PacketNum packetNum);

  ProtectionType getProtectionType() const noexcept;
  PacketNumberSpace getPacketNumberSpace() const noexcept;

  const ConnectionId& getConnectionId() const;
  PacketNum getPacketSequenceNum() const;

  void setPacketNumber(PacketNum packetNum);

 private:
  ShortHeader() = default;
  bool readInitialByte(uint8_t initalByte);
  bool readConnectionId(folly::io::Cursor& cursor);
  bool readPacketNum(
      PacketNum largestReceivedPacketNum,
      folly::io::Cursor& cursor);

 private:
  HeaderForm headerForm_;
  ProtectionType protectionType_;
  ConnectionId connectionId_;
  folly::Optional<PacketNum> packetSequenceNum_; // var-size 8/16/24/32 bits
};

ProtectionType longHeaderTypeToProtectionType(LongHeader::Types type);
PacketNumberSpace longHeaderTypeToPacketNumberSpace(LongHeader::Types type);

using PacketHeader = boost::variant<LongHeader, ShortHeader>;

struct StreamTypeField {
 public:
  /**
   * Returns a StreamTypeField if the field is a stream type.
   */
  static folly::Optional<StreamTypeField> tryStream(uint8_t field);

  bool hasFin() const;
  bool hasDataLength() const;
  bool hasOffset() const;
  uint8_t fieldValue() const;

  struct Builder {
   public:
    Builder& setFin();
    Builder& setOffset();
    Builder& setLength();

    StreamTypeField build();

   private:
    uint8_t field_{kStreamFrameMask};
  };

 private:
  static constexpr uint8_t kStreamFrameMask = 0x08;

  // Stream Frame specific:
  static constexpr uint8_t kFinBit = 0x01;
  static constexpr uint8_t kDataLengthBit = 0x02;
  static constexpr uint8_t kOffsetBit = 0x04;

  explicit StreamTypeField(uint8_t field);

  uint8_t field_;
};

struct VersionNegotiationPacket {
  uint8_t packetType;
  ConnectionId sourceConnectionId;
  ConnectionId destinationConnectionId;
  std::vector<QuicVersion> versions;

  VersionNegotiationPacket(
      uint8_t packetTypeIn,
      ConnectionId sourceConnectionIdIn,
      ConnectionId destinationConnectionIdIn)
      : packetType(packetTypeIn),
        sourceConnectionId(sourceConnectionIdIn),
        destinationConnectionId(destinationConnectionIdIn) {}
};

/**
 * Common struct for regular read and write packets.
 */
struct RegularPacket {
  PacketHeader header;

  explicit RegularPacket(PacketHeader&& headerIn)
      : header(std::move(headerIn)) {}
};

/**
 * A representation of a regular packet that is read from the network.
 * This could be either Cleartext or Encrypted packets in long or short form.
 * Cleartext packets include Client Initial, Client Cleartext, Non-Final Server
 * Cleartext packet or Final Server Cleartext packet. Encrypted packets
 * include 0-RTT, 1-RTT Phase 0 and 1-RTT Phase 1 packets.
 */
struct RegularQuicPacket : public RegularPacket {
  std::vector<QuicFrame> frames;

  explicit RegularQuicPacket(PacketHeader&& headerIn)
      : RegularPacket(std::move(headerIn)) {}
};

/**
 * A representation of a regular packet that is written to the network.
 */
struct RegularQuicWritePacket : public RegularPacket {
  std::vector<QuicWriteFrame> frames;

  explicit RegularQuicWritePacket(PacketHeader&& headerIn)
      : RegularPacket(std::move(headerIn)) {}
};

using QuicPacket = boost::variant<RegularQuicPacket, VersionNegotiationPacket>;

using QuicWritePacket =
    boost::variant<RegularQuicWritePacket, VersionNegotiationPacket>;

/**
 * Returns whether the header is long or short from the initial byte of
 * the QUIC packet.
 *
 * This function is version invariant.
 */
HeaderForm getHeaderForm(uint8_t headerValue);

std::string toString(LongHeader::Types type);

inline std::ostream& operator<<(
    std::ostream& os,
    const LongHeader::Types& type) {
  os << toString(type);
  return os;
}

inline std::ostream& operator<<(std::ostream& os, const PacketHeader& header) {
  folly::variant_match(
      header,
      [&os](const LongHeader& h) {
        os << "header=long"
           << " protectionType=" << (int)h.getProtectionType()
           << " type=" << std::hex << (int)h.getHeaderType();
      },
      [&os](const ShortHeader& h) {
        os << "header=short"
           << " protectionType=" << (int)h.getProtectionType();
      });
  return os;
}

std::string toString(PacketNumberSpace pnSpace);

std::string toString(FrameType frame);

std::string toString(QuicVersion version);

inline std::ostream& operator<<(std::ostream& os, PacketNumberSpace pnSpace) {
  return os << toString(pnSpace);
}

std::string toString(ProtectionType protectionType);

} // namespace quic
