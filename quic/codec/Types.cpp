/*
 * Copyright (c) Facebook, Inc. and its affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 *
 */

#include <quic/codec/Types.h>
#include <quic/QuicException.h>

namespace quic {

LongHeaderInvariant::LongHeaderInvariant(
    QuicVersion ver,
    ConnectionId scid,
    ConnectionId dcid)
    : version(ver), srcConnId(std::move(scid)), dstConnId(std::move(dcid)) {}

HeaderForm getHeaderForm(uint8_t headerValue) {
  if (headerValue & kHeaderFormMask) {
    return HeaderForm::Long;
  }
  return HeaderForm::Short;
}

PacketHeader::PacketHeader(ShortHeader&& shortHeaderIn)
    : headerForm_(HeaderForm::Short) {
  new (&shortHeader) ShortHeader(std::move(shortHeaderIn));
}

PacketHeader::PacketHeader(LongHeader&& longHeaderIn)
    : headerForm_(HeaderForm::Long) {
  new (&longHeader) LongHeader(std::move(longHeaderIn));
}

PacketHeader::PacketHeader(const PacketHeader& other)
    : headerForm_(other.headerForm_) {
  switch (other.headerForm_) {
    case HeaderForm::Long:
      new (&longHeader) LongHeader(other.longHeader);
      break;
    case HeaderForm::Short:
      new (&shortHeader) ShortHeader(other.shortHeader);
      break;
  }
}

PacketHeader::PacketHeader(PacketHeader&& other) noexcept
    : headerForm_(other.headerForm_) {
  switch (other.headerForm_) {
    case HeaderForm::Long:
      new (&longHeader) LongHeader(std::move(other.longHeader));
      break;
    case HeaderForm::Short:
      new (&shortHeader) ShortHeader(std::move(other.shortHeader));
      break;
  }
}

PacketHeader& PacketHeader::operator=(PacketHeader&& other) noexcept {
  destroyHeader();
  switch (other.headerForm_) {
    case HeaderForm::Long:
      new (&longHeader) LongHeader(std::move(other.longHeader));
      break;
    case HeaderForm::Short:
      new (&shortHeader) ShortHeader(std::move(other.shortHeader));
      break;
  }
  headerForm_ = other.headerForm_;
  return *this;
}

PacketHeader& PacketHeader::operator=(const PacketHeader& other) {
  destroyHeader();
  switch (other.headerForm_) {
    case HeaderForm::Long:
      new (&longHeader) LongHeader(other.longHeader);
      break;
    case HeaderForm::Short:
      new (&shortHeader) ShortHeader(other.shortHeader);
      break;
  }
  headerForm_ = other.headerForm_;
  return *this;
}

PacketHeader::~PacketHeader() {
  destroyHeader();
}

void PacketHeader::destroyHeader() {
  switch (headerForm_) {
    case HeaderForm::Long:
      longHeader.~LongHeader();
      break;
    case HeaderForm::Short:
      shortHeader.~ShortHeader();
      break;
  }
}

LongHeader* PacketHeader::asLong() {
  switch (headerForm_) {
    case HeaderForm::Long:
      return &longHeader;
    case HeaderForm::Short:
      return nullptr;
    default:
      folly::assume_unreachable();
  }
}

ShortHeader* PacketHeader::asShort() {
  switch (headerForm_) {
    case HeaderForm::Long:
      return nullptr;
    case HeaderForm::Short:
      return &shortHeader;
    default:
      folly::assume_unreachable();
  }
}

const LongHeader* PacketHeader::asLong() const {
  switch (headerForm_) {
    case HeaderForm::Long:
      return &longHeader;
    case HeaderForm::Short:
      return nullptr;
    default:
      folly::assume_unreachable();
  }
}

const ShortHeader* PacketHeader::asShort() const {
  switch (headerForm_) {
    case HeaderForm::Long:
      return nullptr;
    case HeaderForm::Short:
      return &shortHeader;
    default:
      folly::assume_unreachable();
  }
}

PacketNum PacketHeader::getPacketSequenceNum() const {
  switch (headerForm_) {
    case HeaderForm::Long:
      return longHeader.getPacketSequenceNum();
    case HeaderForm::Short:
      return shortHeader.getPacketSequenceNum();
    default:
      folly::assume_unreachable();
  }
}

HeaderForm PacketHeader::getHeaderForm() const {
  return headerForm_;
}

ProtectionType PacketHeader::getProtectionType() const {
  switch (headerForm_) {
    case HeaderForm::Long:
      return longHeader.getProtectionType();
    case HeaderForm::Short:
      return shortHeader.getProtectionType();
    default:
      folly::assume_unreachable();
  }
}

PacketNumberSpace PacketHeader::getPacketNumberSpace() const {
  switch (headerForm_) {
    case HeaderForm::Long:
      return longHeader.getPacketNumberSpace();
    case HeaderForm::Short:
      return shortHeader.getPacketNumberSpace();
    default:
      folly::assume_unreachable();
  }
}

LongHeader::LongHeader(
    Types type,
    LongHeaderInvariant invariant,
    const std::string& token,
    folly::Optional<ConnectionId> originalDstConnId)
    : longHeaderType_(type),
      invariant_(std::move(invariant)),
      token_(token),
      originalDstConnId_(originalDstConnId) {}

LongHeader::LongHeader(
    Types type,
    const ConnectionId& srcConnId,
    const ConnectionId& dstConnId,
    PacketNum packetNum,
    QuicVersion version,
    const std::string& token,
    folly::Optional<ConnectionId> originalDstConnId)
    : longHeaderType_(type),
      invariant_(LongHeaderInvariant(version, srcConnId, dstConnId)),
      token_(token),
      originalDstConnId_(originalDstConnId) {
  setPacketNumber(packetNum);
}

LongHeader::Types LongHeader::getHeaderType() const noexcept {
  return longHeaderType_;
}

const ConnectionId& LongHeader::getSourceConnId() const {
  return invariant_.srcConnId;
}

const ConnectionId& LongHeader::getDestinationConnId() const {
  return invariant_.dstConnId;
}

const folly::Optional<ConnectionId>& LongHeader::getOriginalDstConnId() const {
  return originalDstConnId_;
}

QuicVersion LongHeader::getVersion() const {
  return invariant_.version;
}

bool LongHeader::hasToken() const {
  return !token_.empty();
}

const std::string& LongHeader::getToken() const {
  return token_;
}

PacketNum LongHeader::getPacketSequenceNum() const {
  return packetSequenceNum_;
}

void LongHeader::setPacketNumber(PacketNum packetNum) {
  packetSequenceNum_ = packetNum;
}

ProtectionType LongHeader::getProtectionType() const {
  return longHeaderTypeToProtectionType(getHeaderType());
}

PacketNumberSpace LongHeader::getPacketNumberSpace() const {
  return longHeaderTypeToPacketNumberSpace(getHeaderType());
}

ProtectionType longHeaderTypeToProtectionType(
    LongHeader::Types longHeaderType) {
  switch (longHeaderType) {
    case LongHeader::Types::Initial:
    case LongHeader::Types::Retry:
      return ProtectionType::Initial;
    case LongHeader::Types::Handshake:
      return ProtectionType::Handshake;
    case LongHeader::Types::ZeroRtt:
      return ProtectionType::ZeroRtt;
  }
  folly::assume_unreachable();
}

ShortHeaderInvariant::ShortHeaderInvariant(ConnectionId dcid)
    : destinationConnId(std::move(dcid)) {}

PacketNumberSpace longHeaderTypeToPacketNumberSpace(
    LongHeader::Types longHeaderType) {
  switch (longHeaderType) {
    case LongHeader::Types::Initial:
    case LongHeader::Types::Retry:
      return PacketNumberSpace::Initial;
    case LongHeader::Types::Handshake:
      return PacketNumberSpace::Handshake;
    case LongHeader::Types::ZeroRtt:
      return PacketNumberSpace::AppData;
  }
  folly::assume_unreachable();
}

ShortHeader::ShortHeader(
    ProtectionType protectionType,
    ConnectionId connId,
    PacketNum packetNum)
    : protectionType_(protectionType), connectionId_(std::move(connId)) {
  if (protectionType_ != ProtectionType::KeyPhaseZero &&
      protectionType_ != ProtectionType::KeyPhaseOne) {
    throw QuicInternalException(
        "bad short header protection type", LocalErrorCode::CODEC_ERROR);
  }
  setPacketNumber(packetNum);
}

ShortHeader::ShortHeader(ProtectionType protectionType, ConnectionId connId)
    : protectionType_(protectionType), connectionId_(std::move(connId)) {
  if (protectionType_ != ProtectionType::KeyPhaseZero &&
      protectionType_ != ProtectionType::KeyPhaseOne) {
    throw QuicInternalException(
        "bad short header protection type", LocalErrorCode::CODEC_ERROR);
  }
}

ProtectionType ShortHeader::getProtectionType() const {
  return protectionType_;
}

PacketNumberSpace ShortHeader::getPacketNumberSpace() const {
  return PacketNumberSpace::AppData;
}

const ConnectionId& ShortHeader::getConnectionId() const {
  return connectionId_;
}

PacketNum ShortHeader::getPacketSequenceNum() const {
  return packetSequenceNum_;
}

void ShortHeader::setPacketNumber(PacketNum packetNum) {
  packetSequenceNum_ = packetNum;
}

bool StreamTypeField::hasDataLength() const {
  return field_ & kDataLengthBit;
}

bool StreamTypeField::hasFin() const {
  return field_ & kFinBit;
}

bool StreamTypeField::hasOffset() const {
  return field_ & kOffsetBit;
}

uint8_t StreamTypeField::fieldValue() const {
  return field_;
}

StreamTypeField::Builder& StreamTypeField::Builder::setFin() {
  field_ |= StreamTypeField::kFinBit;
  return *this;
}

StreamTypeField::Builder& StreamTypeField::Builder::setOffset() {
  field_ |= StreamTypeField::kOffsetBit;
  return *this;
}

StreamTypeField::Builder& StreamTypeField::Builder::setLength() {
  field_ |= StreamTypeField::kDataLengthBit;
  return *this;
}

StreamTypeField StreamTypeField::Builder::build() {
  return StreamTypeField(field_);
}

std::string toString(PacketNumberSpace pnSpace) {
  switch (pnSpace) {
    case PacketNumberSpace::Initial:
      return "InitialSpace";
    case PacketNumberSpace::Handshake:
      return "HandshakeSpace";
    case PacketNumberSpace::AppData:
      return "AppDataSpace";
  }
  CHECK(false) << "Unknown packet number space";
  folly::assume_unreachable();
}

std::string toString(ProtectionType protectionType) {
  switch (protectionType) {
    case ProtectionType::Initial:
      return "Initial";
    case ProtectionType::Handshake:
      return "Handshake";
    case ProtectionType::ZeroRtt:
      return "ZeroRtt";
    case ProtectionType::KeyPhaseZero:
      return "KeyPhaseZero";
    case ProtectionType::KeyPhaseOne:
      return "KeyPhaseOne";
  }
  CHECK(false) << "Unknown protection type";
  folly::assume_unreachable();
}

std::string toString(FrameType frame) {
  switch (frame) {
    case FrameType::PADDING:
      return "PADDING";
    case FrameType::PING:
      return "PING";
    case FrameType::ACK:
      return "ACK";
    case FrameType::ACK_ECN:
      return "ACK_ECN";
    case FrameType::RST_STREAM:
      return "RST_STREAM";
    case FrameType::STOP_SENDING:
      return "STOP_SENDING";
    case FrameType::CRYPTO_FRAME:
      return "CRYPTO_FRAME";
    case FrameType::NEW_TOKEN:
      return "NEW_TOKEN";
    case FrameType::STREAM:
    case FrameType::STREAM_FIN:
    case FrameType::STREAM_LEN:
    case FrameType::STREAM_LEN_FIN:
    case FrameType::STREAM_OFF:
    case FrameType::STREAM_OFF_FIN:
    case FrameType::STREAM_OFF_LEN:
    case FrameType::STREAM_OFF_LEN_FIN:
      return "STREAM";
    case FrameType::MAX_DATA:
      return "MAX_DATA";
    case FrameType::MAX_STREAM_DATA:
      return "MAX_STREAM_DATA";
    case FrameType::MAX_STREAMS_BIDI:
      return "MAX_STREAMS_BIDI";
    case FrameType::MAX_STREAMS_UNI:
      return "MAX_STREAMS_UNI";
    case FrameType::DATA_BLOCKED:
      return "DATA_BLOCKED";
    case FrameType::STREAM_DATA_BLOCKED:
      return "STREAM_DATA_BLOCKED";
    case FrameType::STREAMS_BLOCKED_BIDI:
      return "STREAMS_BLOCKED_BIDI";
    case FrameType::STREAMS_BLOCKED_UNI:
      return "STREAMS_BLOCKED_UNI";
    case FrameType::NEW_CONNECTION_ID:
      return "NEW_CONNECTION_ID";
    case FrameType::RETIRE_CONNECTION_ID:
      return "RETIRE_CONNECTION_ID";
    case FrameType::PATH_CHALLENGE:
      return "PATH_CHALLENGE";
    case FrameType::PATH_RESPONSE:
      return "PATH_RESPONSE";
    case FrameType::CONNECTION_CLOSE:
      return "CONNECTION_CLOSE";
    case FrameType::CONNECTION_CLOSE_APP_ERR:
      return "APPLICATION_CLOSE";
    case FrameType::MIN_STREAM_DATA:
      return "MIN_STREAM_DATA";
    case FrameType::EXPIRED_STREAM_DATA:
      return "EXPIRED_STREAM_DATA";
  }
  LOG(WARNING) << "toString has unhandled frame type";
  return "UNKNOWN";
}

std::string toString(QuicVersion version) {
  switch (version) {
    case QuicVersion::VERSION_NEGOTIATION:
      return "VERSION_NEGOTIATION";
    case QuicVersion::MVFST_OLD:
      return "MVFST_OLD";
    case QuicVersion::MVFST:
      return "MVFST";
    case QuicVersion::QUIC_DRAFT_22:
      return "QUIC_DRAFT_22";
    case QuicVersion::QUIC_DRAFT_23:
      return "QUIC_DRAFT_23";
    case QuicVersion::QUIC_DRAFT:
      return "QUIC_DRAFT";
    case QuicVersion::MVFST_INVALID:
      return "MVFST_INVALID";
  }
  LOG(WARNING) << "toString has unhandled version type";
  return "UNKNOWN";
}

std::string toString(LongHeader::Types type) {
  switch (type) {
    case LongHeader::Types::Initial:
      return "INITIAL";
    case LongHeader::Types::Retry:
      return "RETRY";
    case LongHeader::Types::Handshake:
      return "HANDSHAKE";
    case LongHeader::Types::ZeroRtt:
      return "ZERORTT";
  }
  LOG(WARNING) << "toString has unhandled long header type";
  return "UNKNOWN";
}
} // namespace quic
