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

LongHeader::LongHeader(
    Types type,
    LongHeaderInvariant invariant,
    Buf token,
    folly::Optional<ConnectionId> originalDstConnId)
    : headerForm_(HeaderForm::Long),
      longHeaderType_(type),
      invariant_(std::move(invariant)),
      token_(std::move(token)),
      originalDstConnId_(originalDstConnId) {}

LongHeader::LongHeader(
    Types type,
    const ConnectionId& srcConnId,
    const ConnectionId& dstConnId,
    PacketNum packetNum,
    QuicVersion version,
    Buf token,
    folly::Optional<ConnectionId> originalDstConnId)
    : headerForm_(HeaderForm::Long),
      longHeaderType_(type),
      invariant_(LongHeaderInvariant(version, srcConnId, dstConnId)),
      packetSequenceNum_(packetNum),
      token_(token ? std::move(token) : nullptr),
      originalDstConnId_(originalDstConnId) {}

LongHeader::LongHeader(const LongHeader& other)
    : headerForm_(other.headerForm_),
      longHeaderType_(other.longHeaderType_),
      invariant_(other.invariant_),
      packetSequenceNum_(other.packetSequenceNum_),
      originalDstConnId_(other.originalDstConnId_) {
  if (other.token_) {
    token_ = other.token_->clone();
  }
}

void LongHeader::setPacketNumber(PacketNum packetNum) {
  packetSequenceNum_ = packetNum;
}

LongHeader& LongHeader::operator=(const LongHeader& other) {
  headerForm_ = other.headerForm_;
  longHeaderType_ = other.longHeaderType_;
  invariant_ = other.invariant_;
  packetSequenceNum_ = other.packetSequenceNum_;
  originalDstConnId_ = other.originalDstConnId_;
  if (other.token_) {
    token_ = other.token_->clone();
  }
  return *this;
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

PacketNum LongHeader::getPacketSequenceNum() const {
  return *packetSequenceNum_;
}

QuicVersion LongHeader::getVersion() const {
  return invariant_.version;
}

bool LongHeader::hasToken() const {
  return token_ ? true : false;
}

folly::IOBuf* LongHeader::getToken() const {
  return token_.get();
}

ProtectionType LongHeader::getProtectionType() const {
  return longHeaderTypeToProtectionType(getHeaderType());
}

PacketNumberSpace LongHeader::getPacketNumberSpace() const noexcept {
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
    : headerForm_(HeaderForm::Short),
      protectionType_(protectionType),
      connectionId_(std::move(connId)),
      packetSequenceNum_(packetNum) {
  if (protectionType_ != ProtectionType::KeyPhaseZero &&
      protectionType_ != ProtectionType::KeyPhaseOne) {
    throw QuicInternalException(
        "bad short header protection type", LocalErrorCode::CODEC_ERROR);
  }
}

ShortHeader::ShortHeader(ProtectionType protectionType, ConnectionId connId)
    : headerForm_(HeaderForm::Short),
      protectionType_(protectionType),
      connectionId_(std::move(connId)) {
  if (protectionType_ != ProtectionType::KeyPhaseZero &&
      protectionType_ != ProtectionType::KeyPhaseOne) {
    throw QuicInternalException(
        "bad short header protection type", LocalErrorCode::CODEC_ERROR);
  }
}

ProtectionType ShortHeader::getProtectionType() const noexcept {
  return protectionType_;
}

PacketNumberSpace ShortHeader::getPacketNumberSpace() const noexcept {
  return PacketNumberSpace::AppData;
}

const ConnectionId& ShortHeader::getConnectionId() const {
  return connectionId_;
}

PacketNum ShortHeader::getPacketSequenceNum() const {
  return *packetSequenceNum_;
}

void ShortHeader::setPacketNumber(PacketNum packetNum) {
  packetSequenceNum_ = packetNum;
}

StreamTypeField::StreamTypeField(uint8_t field) : field_(field) {}

folly::Optional<StreamTypeField> StreamTypeField::tryStream(uint8_t field) {
  if ((field & kStreamFrameMask) == kStreamFrameMask) {
    return StreamTypeField(field);
  }
  return folly::none;
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
}
} // namespace quic
