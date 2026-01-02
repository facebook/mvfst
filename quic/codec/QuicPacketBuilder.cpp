/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <folly/io/IOBuf.h>
#include <quic/codec/QuicPacketBuilder.h>
#include <quic/common/MvfstLogging.h>
#include <algorithm>

#include <folly/Random.h>
#include <quic/codec/PacketNumber.h>

namespace quic {
template <typename BufOp = BufAppender>
[[nodiscard]] quic::Expected<PacketNumEncodingResult, QuicError>
encodeLongHeaderHelper(
    const LongHeader& longHeader,
    BufOp& bufop,
    uint32_t& spaceCounter,
    PacketNum largestAckedPacketNum /* unused for retry packets */) {
  bool isInitial = longHeader.getHeaderType() == LongHeader::Types::Initial;
  bool isRetry = longHeader.getHeaderType() == LongHeader::Types::Retry;

  uint8_t initialByte = kHeaderFormMask | LongHeader::kFixedBitMask |
      (static_cast<uint8_t>(longHeader.getHeaderType())
       << LongHeader::kTypeShift);

  PacketNumEncodingResult encodedPacketNum = encodePacketNumber(
      longHeader.getPacketSequenceNum(), largestAckedPacketNum);

  if (!isRetry) {
    // The last 4 bits of the initial byte of a retry packet can be arbitrary.
    // We therefore only set these bits for non-retry packets.
    initialByte &= ~LongHeader::kReservedBitsMask;
    initialByte |= (encodedPacketNum.length - 1);
  }

  bufop.template writeBE<uint8_t>(initialByte);
  uint64_t tokenHeaderLength = 0;
  const std::string& token = longHeader.getToken();
  if (isInitial) {
    // For initial packets, we write both the token length and the token itself.
    uint64_t tokenLength = token.size();
    auto tokenLengthInt = QuicInteger(tokenLength).getSize();
    if (!tokenLengthInt.has_value()) {
      return quic::make_unexpected(tokenLengthInt.error());
    }
    tokenHeaderLength = tokenLengthInt.value() + tokenLength;
  } else if (isRetry) {
    // For retry packets, we write only the token.
    tokenHeaderLength = token.size();
  }
  auto longHeaderSize = sizeof(uint8_t) /* initialByte */ +
      sizeof(QuicVersionType) + sizeof(uint8_t) +
      longHeader.getSourceConnId().size() + sizeof(uint8_t) +
      longHeader.getDestinationConnId().size() + tokenHeaderLength;

  if (!isRetry) {
    // For retry packets, we don't write the packet length or the
    // packet number.
    longHeaderSize += kMaxPacketLenSize + encodedPacketNum.length;
  }
  if (spaceCounter < longHeaderSize) {
    spaceCounter = 0;
  } else {
    spaceCounter -= longHeaderSize;
  }
  bufop.template writeBE<uint32_t>(
      static_cast<uint32_t>(longHeader.getVersion()));
  bufop.template writeBE<uint8_t>(longHeader.getDestinationConnId().size());
  bufop.push(
      longHeader.getDestinationConnId().data(),
      longHeader.getDestinationConnId().size());
  bufop.template writeBE<uint8_t>(longHeader.getSourceConnId().size());
  bufop.push(
      longHeader.getSourceConnId().data(), longHeader.getSourceConnId().size());

  if (isInitial) {
    // Write the token length, followed by the token
    uint64_t tokenLength = token.size();
    QuicInteger tokenLengthInt(tokenLength);
    tokenLengthInt.encode([&](auto val) { bufop.writeBE(val); });
    if (tokenLength > 0) {
      bufop.push((const uint8_t*)token.data(), token.size());
    }
  }

  if (isRetry) {
    // Write the retry token
    CHECK(!token.empty()) << "Retry packet must contain a token";
    bufop.push((const uint8_t*)token.data(), token.size());
  }
  // defer write of the packet num and length till payload has been computed
  // For a retry packet, the returned value is not relevant.
  return encodedPacketNum;
}

template <typename BufOp = BufAppender>
Optional<PacketNumEncodingResult> encodeShortHeaderHelper(
    const ShortHeader& shortHeader,
    BufOp& bufop,
    uint32_t& spaceCounter,
    PacketNum largestAckedPacketNum) {
  auto packetNumberEncoding = encodePacketNumber(
      shortHeader.getPacketSequenceNum(), largestAckedPacketNum);
  if (spaceCounter <
      1U + packetNumberEncoding.length + shortHeader.getConnectionId().size()) {
    spaceCounter = 0;
    return std::nullopt;
  }
  uint8_t initialByte =
      ShortHeader::kFixedBitMask | (packetNumberEncoding.length - 1);
  initialByte &= ~ShortHeader::kReservedBitsMask;
  if (shortHeader.getProtectionType() == ProtectionType::KeyPhaseOne) {
    initialByte |= ShortHeader::kKeyPhaseMask;
  }
  bufop.template writeBE<uint8_t>(initialByte);
  --spaceCounter;

  bufop.push(
      shortHeader.getConnectionId().data(),
      shortHeader.getConnectionId().size());
  spaceCounter -= shortHeader.getConnectionId().size();
  return packetNumberEncoding;
}

RegularQuicPacketBuilder::RegularQuicPacketBuilder(
    uint32_t remainingBytes,
    PacketHeader header,
    PacketNum largestAckedPacketNum,
    uint8_t frameHint)
    : remainingBytes_(remainingBytes),
      largestAckedPacketNum_(largestAckedPacketNum),
      packet_(std::move(header)),
      header_(BufHelpers::CreateOp::CREATE, kLongHeaderHeaderSize),
      body_(BufHelpers::CreateOp::CREATE, kAppenderGrowthSize),
      headerAppender_(&header_, kLongHeaderHeaderSize),
      bodyAppender_(&body_, kAppenderGrowthSize) {
  if (frameHint) {
    packet_.frames.reserve(frameHint);
  }
}

uint32_t RegularQuicPacketBuilder::getHeaderBytes() const {
  bool isLongHeader = packet_.header.getHeaderForm() == HeaderForm::Long;
  CHECK(packetNumberEncoding_)
      << "packetNumberEncoding_ should be valid after ctor";
  return static_cast<uint32_t>(header_.computeChainDataLength()) +
      (isLongHeader ? packetNumberEncoding_->length + kMaxPacketLenSize : 0);
}

uint32_t RegularQuicPacketBuilder::remainingSpaceInPkt() const {
  return remainingBytes_;
}

void RegularQuicPacketBuilder::writeBE(uint8_t data) {
  bodyAppender_.writeBE<uint8_t>(data);
  remainingBytes_ -= sizeof(data);
}

void RegularQuicPacketBuilder::writeBE(uint16_t data) {
  bodyAppender_.writeBE<uint16_t>(data);
  remainingBytes_ -= sizeof(data);
}

void RegularQuicPacketBuilder::writeBE(uint64_t data) {
  bodyAppender_.writeBE<uint64_t>(data);
  remainingBytes_ -= sizeof(data);
}

void RegularQuicPacketBuilder::write(const QuicInteger& quicInteger) {
  remainingBytes_ -=
      quicInteger.encode([&](auto val) { bodyAppender_.writeBE(val); });
}

void RegularQuicPacketBuilder::appendBytes(
    PacketNum value,
    uint8_t byteNumber) {
  appendBytes(bodyAppender_, value, byteNumber);
}

void RegularQuicPacketBuilder::appendBytes(
    BufAppender& appender,
    PacketNum value,
    uint8_t byteNumber) {
  auto bigValue = folly::Endian::big(value);
  appender.push(
      (uint8_t*)&bigValue + sizeof(bigValue) - byteNumber, byteNumber);
  remainingBytes_ -= byteNumber;
}

void RegularQuicPacketBuilder::insert(BufPtr buf) {
  remainingBytes_ -= buf->computeChainDataLength();
  bodyAppender_.insert(std::move(buf));
}

void RegularQuicPacketBuilder::insert(BufPtr buf, size_t limit) {
  insert(BufQueue(std::move(buf)), limit);
}

void RegularQuicPacketBuilder::insert(const BufQueue& buf, size_t limit) {
  const auto* pBuf = CHECK_NOTNULL(buf.front());
  limit = std::min(limit, buf.chainLength());
  BufPtr streamData = BufHelpers::create(limit);
  do {
    ContiguousReadCursor cursor{pBuf->data(), pBuf->length()};
    size_t dataSize = cursor.pullAtMost(streamData->writableTail(), limit);
    streamData->append(dataSize);
    limit -= dataSize;
    pBuf = pBuf->next();
  } while (pBuf != buf.front() && limit > 0);
  insert(std::move(streamData));
}

void RegularQuicPacketBuilder::insert(
    const ChainedByteRangeHead& buf,
    size_t limit) {
  limit = std::min(limit, buf.chainLength());
  BufPtr streamData = BufHelpers::wrapBuffer(
      buf.getHead()->getRange().begin(),
      std::min(limit, buf.getHead()->length()));
  limit -= std::min(limit, buf.getHead()->length());

  auto* current = buf.getHead()->getNext();
  while (limit > 0) {
    size_t amountToChopOff = std::min(limit, current->length());
    auto tempBuf =
        BufHelpers::wrapBuffer(current->getRange().begin(), amountToChopOff);
    streamData->appendToChain(std::move(tempBuf));
    limit -= amountToChopOff;
    current = current->getNext();
  }

  insert(std::move(streamData));
}

void RegularQuicPacketBuilder::appendFrame(QuicWriteFrame frame) {
  packet_.empty = false;
  packet_.frames.push_back(std::move(frame));
}

void RegularQuicPacketBuilder::appendPaddingFrame() {
  packet_.empty = false;
  if (!packet_.frames.empty() &&
      packet_.frames.back().type() == QuicWriteFrame::Type::PaddingFrame) {
    packet_.frames.back().asPaddingFrame()->numFrames++;
  } else {
    packet_.frames.push_back(PaddingFrame());
  }
}

void RegularQuicPacketBuilder::markNonEmpty() {
  packet_.empty = false;
}

RegularQuicPacketBuilder::Packet RegularQuicPacketBuilder::buildPacket() && {
  CHECK(packetNumberEncoding_.has_value());
  // at this point everything should been set in the packet_
  LongHeader* longHeader = packet_.header.asLong();
  size_t minBodySize = kMaxPacketNumEncodingSize -
      packetNumberEncoding_->length + sizeof(Sample);
  size_t extraDataWritten = 0;
  size_t bodyLength = body_.computeChainDataLength();
  while (bodyLength + extraDataWritten + cipherOverhead_ < minBodySize &&
         !packet_.empty && remainingBytes_ > kMaxPacketLenSize) {
    // We can add padding frames, but we don't need to store them.
    QuicInteger paddingType(static_cast<uint8_t>(FrameType::PADDING));
    write(paddingType);
    extraDataWritten++;
  }
  if (longHeader && longHeader->getHeaderType() != LongHeader::Types::Retry) {
    QuicInteger pktLen(
        packetNumberEncoding_->length + body_.computeChainDataLength() +
        cipherOverhead_);
    pktLen.encode([&](auto val) { headerAppender_.writeBE(val); });
    appendBytes(
        headerAppender_,
        packetNumberEncoding_->result,
        packetNumberEncoding_->length);
  }
  return Packet(std::move(packet_), std::move(header_), std::move(body_));
}

quic::Expected<void, QuicError> RegularQuicPacketBuilder::encodeLongHeader(
    const LongHeader& longHeader,
    PacketNum largestAckedPacketNum) {
  auto encodingResult = encodeLongHeaderHelper(
      longHeader, headerAppender_, remainingBytes_, largestAckedPacketNum);
  if (!encodingResult.has_value()) {
    return quic::make_unexpected(encodingResult.error());
  }
  packetNumberEncoding_ = std::move(encodingResult.value());
  return {};
}

void RegularQuicPacketBuilder::encodeShortHeader(
    const ShortHeader& shortHeader,
    PacketNum largestAckedPacketNum) {
  packetNumberEncoding_ = encodeShortHeaderHelper(
      shortHeader, headerAppender_, remainingBytes_, largestAckedPacketNum);
  if (packetNumberEncoding_) {
    RegularQuicPacketBuilder::appendBytes(
        headerAppender_,
        packetNumberEncoding_->result,
        packetNumberEncoding_->length);
  }
}

void RegularQuicPacketBuilder::push(const uint8_t* data, size_t len) {
  bodyAppender_.push(data, len);
  remainingBytes_ -= len;
}

bool RegularQuicPacketBuilder::canBuildPacket() const noexcept {
  return remainingBytes_ != 0 && packetNumberEncoding_.has_value();
}

const PacketHeader& RegularQuicPacketBuilder::getPacketHeader() const {
  return packet_.header;
}

void RegularQuicPacketBuilder::accountForCipherOverhead(
    uint8_t overhead) noexcept {
  cipherOverhead_ = overhead;
  remainingBytes_ -= overhead;
}

PseudoRetryPacketBuilder::PseudoRetryPacketBuilder(
    uint8_t initialByte,
    ConnectionId sourceConnectionId,
    ConnectionId destinationConnectionId,
    ConnectionId originalDestinationConnectionId,
    QuicVersion quicVersion,
    BufPtr&& token)
    : initialByte_(initialByte),
      sourceConnectionId_(sourceConnectionId),
      destinationConnectionId_(destinationConnectionId),
      originalDestinationConnectionId_(originalDestinationConnectionId),
      quicVersion_(quicVersion),
      token_(std::move(token)) {
  writePseudoRetryPacket();
}

void PseudoRetryPacketBuilder::writePseudoRetryPacket() {
  uint64_t packetLength = sizeof(uint8_t) /* ODCID length */ +
      originalDestinationConnectionId_.size() /* ODCID */ +
      sizeof(uint8_t) /* Initial byte */ +
      sizeof(QuicVersionType) /* Version */ +
      sizeof(uint8_t) /* DCID length */ +
      destinationConnectionId_.size() /* DCID */ +
      sizeof(uint8_t) /* SCID length */ +
      sourceConnectionId_.size() /* SCID */ + token_->length() /* Token */;

  if (packetLength > kDefaultUDPSendPacketLen) {
    MVLOG_ERROR << "Retry packet length exceeds default packet length";
  }
  packetBuf_ = BufHelpers::create(packetLength);
  BufWriter bufWriter(packetBuf_->writableData(), packetLength);

  // ODCID length
  bufWriter.writeBE<uint8_t>(originalDestinationConnectionId_.size());

  // ODCID
  bufWriter.push(
      originalDestinationConnectionId_.data(),
      originalDestinationConnectionId_.size());

  // Initial byte
  bufWriter.writeBE<uint8_t>(initialByte_);

  // Version
  bufWriter.writeBE<QuicVersionType>(
      static_cast<QuicVersionType>(quicVersion_));

  // DCID length
  bufWriter.writeBE<uint8_t>(destinationConnectionId_.size());

  // DCID
  bufWriter.push(
      destinationConnectionId_.data(), destinationConnectionId_.size());

  // SCID length
  bufWriter.writeBE<uint8_t>(sourceConnectionId_.size());

  // SCID
  bufWriter.push(sourceConnectionId_.data(), sourceConnectionId_.size());

  // Token
  bufWriter.push((const uint8_t*)token_->data(), token_->length());

  packetBuf_->append(bufWriter.getBytesWritten());
}

BufPtr PseudoRetryPacketBuilder::buildPacket() && {
  return std::move(packetBuf_);
}

StatelessResetPacketBuilder::StatelessResetPacketBuilder(
    uint16_t maxPacketSize,
    const StatelessResetToken& resetToken)
    : data_(BufHelpers::create(kAppenderGrowthSize)) {
  BufAppender appender(data_.get(), kAppenderGrowthSize);
  uint16_t randomOctetLength = maxPacketSize - resetToken.size() - 1;
  uint8_t initialByte =
      ShortHeader::kFixedBitMask | (0x3f & folly::Random::secureRand32());
  appender.writeBE<uint8_t>(initialByte);
  auto randomOctets = BufHelpers::create(randomOctetLength);
  folly::Random::secureRandom(randomOctets->writableData(), randomOctetLength);
  appender.push(randomOctets->data(), randomOctetLength);
  appender.push(resetToken.data(), resetToken.size());
}

BufPtr StatelessResetPacketBuilder::buildPacket() && {
  return std::move(data_);
}

RegularSizeEnforcedPacketBuilder::RegularSizeEnforcedPacketBuilder(
    Packet packet,
    uint64_t enforcedSize,
    uint32_t cipherOverhead)
    : packet_(std::move(packet.packet)),
      header_(std::move(packet.header)),
      body_(std::move(packet.body)),
      bodyAppender_(&body_, kAppenderGrowthSize),
      enforcedSize_(enforcedSize),
      cipherOverhead_(cipherOverhead) {}

bool RegularSizeEnforcedPacketBuilder::canBuildPacket() const noexcept {
  // We only force size of packets with short header, because d6d probes always
  // have short headers and there's no other situations for this type of builder
  const ShortHeader* shortHeader = packet_.header.asShort();
  // We also don't want to send packets longer than kDefaultMaxUDPPayload
  return shortHeader && enforcedSize_ <= kDefaultMaxUDPPayload &&
      (body_.computeChainDataLength() + header_.computeChainDataLength() +
           cipherOverhead_ <
       enforcedSize_);
}

PacketBuilderInterface::Packet
RegularSizeEnforcedPacketBuilder::buildPacket() && {
  // Store counters on the stack to overhead from function calls
  size_t extraDataWritten = 0;
  size_t bodyLength = body_.computeChainDataLength();
  size_t headerLength = header_.computeChainDataLength();
  while (extraDataWritten + bodyLength + headerLength + cipherOverhead_ <
         enforcedSize_) {
    QuicInteger paddingType(static_cast<uint8_t>(FrameType::PADDING));
    paddingType.encode([&](auto val) { bodyAppender_.writeBE(val); });
    extraDataWritten++;
  }
  return Packet(std::move(packet_), std::move(header_), std::move(body_));
}

InplaceSizeEnforcedPacketBuilder::InplaceSizeEnforcedPacketBuilder(
    BufAccessor& bufAccessor,
    Packet packet,
    uint64_t enforcedSize,
    uint32_t cipherOverhead)
    : bufAccessor_(bufAccessor),
      iobuf_(bufAccessor_.obtain()),
      packet_(std::move(packet.packet)),
      header_(std::move(packet.header)),
      body_(std::move(packet.body)),
      enforcedSize_(enforcedSize),
      cipherOverhead_(cipherOverhead) {}

bool InplaceSizeEnforcedPacketBuilder::canBuildPacket() const noexcept {
  const ShortHeader* shortHeader = packet_.header.asShort();
  size_t encryptedPacketSize =
      header_.length() + body_.length() + cipherOverhead_;
  size_t delta = enforcedSize_ - encryptedPacketSize;
  return shortHeader && enforcedSize_ <= kDefaultMaxUDPPayload &&
      encryptedPacketSize < enforcedSize_ && iobuf_->tailroom() >= delta;
}

PacketBuilderInterface::Packet
InplaceSizeEnforcedPacketBuilder::buildPacket() && {
  // Create bodyWriter
  size_t encryptedPacketSize =
      header_.length() + body_.length() + cipherOverhead_;
  size_t paddingSize = enforcedSize_ - encryptedPacketSize;
  BufWriter bodyWriter(iobuf_->writableTail(), paddingSize);

  // Store counters on the stack to overhead from function calls
  size_t extraDataWritten = 0;
  size_t bodyLength = body_.computeChainDataLength();
  size_t headerLength = header_.computeChainDataLength();
  while (extraDataWritten + bodyLength + headerLength + cipherOverhead_ <
         enforcedSize_) {
    QuicInteger paddingType(static_cast<uint8_t>(FrameType::PADDING));
    paddingType.encode([&](auto val) { bodyWriter.writeBE(val); });
    extraDataWritten++;
  }

  PacketBuilderInterface::Packet builtPacket(
      std::move(packet_),
      std::move(header_),
      BufHelpers::wrapBufferAsValue(
          body_.data(), bodyWriter.tail() - body_.data()));

  // Release internal iobuf
  iobuf_->append(bodyWriter.getBytesWritten());
  bufAccessor_.release(std::move(iobuf_));
  return builtPacket;
}

VersionNegotiationPacketBuilder::VersionNegotiationPacketBuilder(
    ConnectionId sourceConnectionId,
    ConnectionId destinationConnectionId,
    const std::vector<QuicVersion>& versions)
    : remainingBytes_(kDefaultUDPSendPacketLen),
      packet_(
          generateRandomPacketType(),
          sourceConnectionId,
          destinationConnectionId),
      data_(BufHelpers::create(kAppenderGrowthSize)) {
  writeVersionNegotiationPacket(versions);
}

uint32_t VersionNegotiationPacketBuilder::remainingSpaceInPkt() {
  return remainingBytes_;
}

std::pair<VersionNegotiationPacket, BufPtr>
VersionNegotiationPacketBuilder::buildPacket() && {
  return std::make_pair<VersionNegotiationPacket, BufPtr>(
      std::move(packet_), std::move(data_));
}

void VersionNegotiationPacketBuilder::writeVersionNegotiationPacket(
    const std::vector<QuicVersion>& versions) {
  // Write header
  BufAppender appender(data_.get(), kAppenderGrowthSize);
  appender.writeBE<decltype(packet_.packetType)>(packet_.packetType);
  remainingBytes_ -= sizeof(decltype(packet_.packetType));
  appender.writeBE(
      static_cast<QuicVersionType>(QuicVersion::VERSION_NEGOTIATION));
  remainingBytes_ -= sizeof(QuicVersionType);
  appender.writeBE<uint8_t>(packet_.destinationConnectionId.size());
  remainingBytes_ -= sizeof(uint8_t);
  appender.push(
      packet_.destinationConnectionId.data(),
      packet_.destinationConnectionId.size());
  remainingBytes_ -= packet_.destinationConnectionId.size();
  appender.writeBE<uint8_t>(packet_.sourceConnectionId.size());
  remainingBytes_ -= sizeof(uint8_t);
  appender.push(
      packet_.sourceConnectionId.data(), packet_.sourceConnectionId.size());
  remainingBytes_ -= packet_.sourceConnectionId.size();
  // Write versions
  for (auto version : versions) {
    if (remainingBytes_ < sizeof(QuicVersionType)) {
      break;
    }
    appender.writeBE<QuicVersionType>(static_cast<QuicVersionType>(version));
    remainingBytes_ -= sizeof(QuicVersionType);
    packet_.versions.push_back(version);
  }
}

uint8_t VersionNegotiationPacketBuilder::generateRandomPacketType() const {
  // TODO: change this back to generating random packet type after we rollout
  // draft-13. For now the 0 packet type will make sure that the version
  // negotiation packet is not interpreted as a long header.
  // folly::Random::secureRandom<decltype(packet_.packetType)>();
  return kHeaderFormMask;
}

bool VersionNegotiationPacketBuilder::canBuildPacket() const noexcept {
  return remainingBytes_ != 0;
}

RetryPacketBuilder::RetryPacketBuilder(
    ConnectionId sourceConnectionId,
    ConnectionId destinationConnectionId,
    QuicVersion quicVersion,
    std::string&& retryToken,
    RetryPacket::IntegrityTagType integrityTag)
    : sourceConnectionId_(sourceConnectionId),
      destinationConnectionId_(destinationConnectionId),
      quicVersion_(quicVersion),
      retryToken_(std::move(retryToken)),
      integrityTag_(integrityTag),
      remainingBytes_(kDefaultUDPSendPacketLen) {
  auto result = writeRetryPacket();
  if (result.hasError()) {
    MVLOG_ERROR << "Failed to write retry packet. " << result.error();
  }
}

quic::Expected<void, QuicError> RetryPacketBuilder::writeRetryPacket() {
  packetBuf_ = BufHelpers::create(kAppenderGrowthSize);

  // Encode the portion of the retry packet that comes before the
  // integrity tag.
  BufAppender appender(packetBuf_.get(), kAppenderGrowthSize);
  LongHeader header(
      LongHeader::Types::Retry,
      sourceConnectionId_,
      destinationConnectionId_,
      0 /* packet number, can be arbitrary for retry packets */,
      quicVersion_,
      retryToken_);
  auto encodeResult =
      encodeLongHeaderHelper(header, appender, remainingBytes_, 0);
  if (!encodeResult.has_value()) {
    return quic::make_unexpected(encodeResult.error());
  }
  packetBuf_->coalesce();

  // Encode the integrity tag.
  if (remainingBytes_ <= kRetryIntegrityTagLen) {
    // Not enough space to write the integrity tag
    remainingBytes_ = 0;
  } else {
    remainingBytes_ -= kRetryIntegrityTagLen;
    BufAppender appender2(packetBuf_.get(), kRetryIntegrityTagLen);
    appender2.push(integrityTag_.data(), integrityTag_.size());
  }
  return {};
}

bool RetryPacketBuilder::canBuildPacket() const noexcept {
  return remainingBytes_ != 0;
}

BufPtr RetryPacketBuilder::buildPacket() && {
  return std::move(packetBuf_);
}

InplaceQuicPacketBuilder::InplaceQuicPacketBuilder(
    BufAccessor& bufAccessor,
    uint32_t remainingBytes,
    PacketHeader header,
    PacketNum largestAckedPacketNum,
    uint8_t frameHint)
    : bufAccessor_(bufAccessor),
      iobuf_(bufAccessor_.obtain()),
      bufWriter_(iobuf_->writableTail(), remainingBytes),
      remainingBytes_(remainingBytes),
      largestAckedPacketNum_(largestAckedPacketNum),
      packet_(std::move(header)),
      headerStart_(iobuf_->tail()) {
  if (frameHint) {
    packet_.frames.reserve(frameHint);
  }
}

uint32_t InplaceQuicPacketBuilder::remainingSpaceInPkt() const {
  return remainingBytes_;
}

void InplaceQuicPacketBuilder::writeBE(uint8_t data) {
  bufWriter_.writeBE<uint8_t>(data);
  remainingBytes_ -= sizeof(data);
}

void InplaceQuicPacketBuilder::writeBE(uint16_t data) {
  bufWriter_.writeBE<uint16_t>(data);
  remainingBytes_ -= sizeof(data);
}

void InplaceQuicPacketBuilder::writeBE(uint64_t data) {
  bufWriter_.writeBE<uint64_t>(data);
  remainingBytes_ -= sizeof(data);
}

void InplaceQuicPacketBuilder::write(const QuicInteger& quicInteger) {
  remainingBytes_ -=
      quicInteger.encode([&](auto val) { bufWriter_.writeBE(val); });
}

void InplaceQuicPacketBuilder::appendBytes(
    PacketNum value,
    uint8_t byteNumber) {
  appendBytes(bufWriter_, value, byteNumber);
}

void InplaceQuicPacketBuilder::appendBytes(
    BufWriter& bufWriter,
    PacketNum value,
    uint8_t byteNumber) {
  auto bigValue = folly::Endian::big(value);
  bufWriter.push(
      (uint8_t*)&bigValue + sizeof(bigValue) - byteNumber, byteNumber);
  remainingBytes_ -= byteNumber;
}

void InplaceQuicPacketBuilder::insert(BufPtr buf) {
  remainingBytes_ -= buf->computeChainDataLength();
  bufWriter_.insert(buf.get());
}

void InplaceQuicPacketBuilder::insert(BufPtr buf, size_t limit) {
  remainingBytes_ -= limit;
  bufWriter_.insert(buf.get(), limit);
}

void InplaceQuicPacketBuilder::insert(const BufQueue& buf, size_t limit) {
  remainingBytes_ -= limit;
  bufWriter_.insert(buf.front(), limit);
}

void InplaceQuicPacketBuilder::insert(
    const ChainedByteRangeHead& buf,
    size_t limit) {
  remainingBytes_ -= limit;
  bufWriter_.insert(&buf, limit);
}

void InplaceQuicPacketBuilder::appendFrame(QuicWriteFrame frame) {
  packet_.empty = false;
  packet_.frames.push_back(std::move(frame));
}

void InplaceQuicPacketBuilder::appendPaddingFrame() {
  packet_.empty = false;
  if (!packet_.frames.empty() &&
      packet_.frames.back().type() == QuicWriteFrame::Type::PaddingFrame) {
    packet_.frames.back().asPaddingFrame()->numFrames++;
  } else {
    packet_.frames.push_back(PaddingFrame());
  }
}

void InplaceQuicPacketBuilder::markNonEmpty() {
  packet_.empty = false;
}

const PacketHeader& InplaceQuicPacketBuilder::getPacketHeader() const {
  return packet_.header;
}

PacketBuilderInterface::Packet InplaceQuicPacketBuilder::buildPacket() && {
  CHECK(packetNumberEncoding_.has_value());
  LongHeader* longHeader = packet_.header.asLong();
  size_t minBodySize = kMaxPacketNumEncodingSize -
      packetNumberEncoding_->length + sizeof(Sample);
  size_t extraDataWritten = 0;
  size_t bodyLength = bufWriter_.tail() - bodyStart_;
  while (bodyLength + extraDataWritten + cipherOverhead_ < minBodySize &&
         !packet_.empty && remainingBytes_ > kMaxPacketLenSize) {
    // We can add padding frames, but we don't need to store them.
    QuicInteger paddingType(static_cast<uint8_t>(FrameType::PADDING));
    write(paddingType);
    extraDataWritten++;
  }
  if (longHeader && longHeader->getHeaderType() != LongHeader::Types::Retry) {
    QuicInteger pktLen(
        packetNumberEncoding_->length + (bufWriter_.tail() - bodyStart_) +
        cipherOverhead_);
    pktLen.encode(
        [&](auto val) {
          auto bigEndian = folly::Endian::big(val);
          CHECK_EQ(sizeof(bigEndian), kMaxPacketLenSize);
          bufWriter_.backFill(
              (uint8_t*)&bigEndian, kMaxPacketLenSize, packetLenOffset_);
        },
        kMaxPacketLenSize);
    auto bigPacketNum = folly::Endian::big(packetNumberEncoding_->result);
    CHECK_GE(sizeof(bigPacketNum), packetNumberEncoding_->length);
    bufWriter_.backFill(
        (uint8_t*)&bigPacketNum + sizeof(bigPacketNum) -
            packetNumberEncoding_->length,
        packetNumberEncoding_->length,
        packetNumOffset_);
  }
  CHECK(
      headerStart_ && headerStart_ >= iobuf_->data() &&
      headerStart_ < bufWriter_.tail());
  CHECK(
      !bodyStart_ ||
      (bodyStart_ > headerStart_ && bodyStart_ <= bufWriter_.tail()));
  // TODO: Get rid of these two wrapBuffer when Fizz::AEAD has a new interface
  // for encryption.
  if (bodyStart_) {
    Buf bodyBuf = BufHelpers::wrapBufferAsValue(
        bodyStart_, bufWriter_.tail() - bodyStart_ + cipherOverhead_);
    bodyBuf.trimEnd(cipherOverhead_);

    PacketBuilderInterface::Packet builtPacket(
        std::move(packet_),
        BufHelpers::wrapBufferAsValue(
            headerStart_, (bodyStart_ - headerStart_)),
        std::move(bodyBuf));
    releaseOutputBufferInternal();
    return builtPacket;
  } else {
    PacketBuilderInterface::Packet builtPacket(
        std::move(packet_), Buf(), Buf());
    releaseOutputBufferInternal();
    return builtPacket;
  }
}

void InplaceQuicPacketBuilder::accountForCipherOverhead(
    uint8_t overhead) noexcept {
  cipherOverhead_ = overhead;
  remainingBytes_ -= overhead;
}

void InplaceQuicPacketBuilder::push(const uint8_t* data, size_t len) {
  bufWriter_.push(data, len);
  remainingBytes_ -= len;
}

bool InplaceQuicPacketBuilder::canBuildPacket() const noexcept {
  return remainingBytes_ != 0 && packetNumberEncoding_.has_value();
}

uint32_t InplaceQuicPacketBuilder::getHeaderBytes() const {
  CHECK(packetNumberEncoding_)
      << "packetNumberEncoding_ should be valid after ctor";
  return static_cast<uint32_t>(bodyStart_ - headerStart_);
}

bool RegularQuicPacketBuilder::hasFramesPending() const {
  return !packet_.frames.empty();
}

bool InplaceQuicPacketBuilder::hasFramesPending() const {
  return !packet_.frames.empty();
}

void RegularQuicPacketBuilder::releaseOutputBuffer() && {
  ; // no-op
}

void InplaceQuicPacketBuilder::releaseOutputBuffer() && {
  releaseOutputBufferInternal();
}

void InplaceQuicPacketBuilder::releaseOutputBufferInternal() {
  if (iobuf_) {
    iobuf_->append(bufWriter_.getBytesWritten());
    bufAccessor_.release(std::move(iobuf_));
  }
}

InplaceQuicPacketBuilder::~InplaceQuicPacketBuilder() {
  releaseOutputBufferInternal();
}

quic::Expected<void, QuicError> RegularQuicPacketBuilder::encodePacketHeader() {
  CHECK(!packetNumberEncoding_.has_value());
  if (packet_.header.getHeaderForm() == HeaderForm::Long) {
    LongHeader& longHeader = *packet_.header.asLong();
    auto result = encodeLongHeader(longHeader, largestAckedPacketNum_);
    if (!result.has_value()) {
      return quic::make_unexpected(result.error());
    }
  } else {
    ShortHeader& shortHeader = *packet_.header.asShort();
    encodeShortHeader(shortHeader, largestAckedPacketNum_);
  }
  return {};
}

quic::Expected<void, QuicError> InplaceQuicPacketBuilder::encodePacketHeader() {
  CHECK(!packetNumberEncoding_.has_value());
  if (packet_.header.getHeaderForm() == HeaderForm::Long) {
    LongHeader& longHeader = *packet_.header.asLong();
    auto encodingResult = encodeLongHeaderHelper(
        longHeader, bufWriter_, remainingBytes_, largestAckedPacketNum_);
    if (!encodingResult.has_value()) {
      return quic::make_unexpected(encodingResult.error());
    }
    packetNumberEncoding_ = std::move(encodingResult.value());
    if (longHeader.getHeaderType() != LongHeader::Types::Retry) {
      // Remember the position to write packet number and packet length.
      packetLenOffset_ = bufWriter_.getBytesWritten();
      // With this builder, we will have to always use kMaxPacketLenSize to
      // write packet length.
      packetNumOffset_ = packetLenOffset_ + kMaxPacketLenSize;
      // Inside BufWriter, we already countde the packet len and packet number
      // bytes as written. Note that remainingBytes_ also already counted them.
      bufWriter_.append(packetNumberEncoding_->length + kMaxPacketLenSize);
    }
  } else {
    ShortHeader& shortHeader = *packet_.header.asShort();
    packetNumberEncoding_ = encodeShortHeaderHelper(
        shortHeader, bufWriter_, remainingBytes_, largestAckedPacketNum_);
    if (packetNumberEncoding_) {
      appendBytes(
          bufWriter_,
          packetNumberEncoding_->result,
          packetNumberEncoding_->length);
    }
  }
  bodyStart_ = bufWriter_.tail();
  return {};
}

Buf buildSconePacket(
    uint8_t rateSignal,
    const ConnectionId& dstCid,
    const ConnectionId& srcCid) {
  // Calculate packet size: first byte + version + DCIL + SCIL + connection IDs
  size_t packetSize = 1 + // first byte
      sizeof(uint32_t) + // version
      1 + // DCIL
      dstCid.size() + // destination connection ID
      1 + // SCIL
      srcCid.size(); // source connection ID

  auto buf = BufHelpers::create(packetSize);
  BufAppender appender(buf.get(), 0);

  // Rate signal encoding per IETF SCONE draft:
  // - High 6 bits go in first byte (bits 0x3f)
  // - Low 1 bit determines version (SCONE_VERSION_1 vs SCONE_VERSION_2)
  //
  // First byte: 0x80 (long header) | 0x40 (fixed bit) | (rateSignal >> 1)
  // The fixed bit (0x40) MUST be set for every QUIC packet (QUIC Invariants).
  uint8_t rateHighBits = (rateSignal >> 1) & 0x3F;
  uint8_t firstByte = 0x80 | 0x40 | rateHighBits;
  appender.writeBE<uint8_t>(firstByte);

  // Select version based on low bit of rate signal
  // SCONE_VERSION_1 (0x6f7dc0fd) has MSB=0, SCONE_VERSION_2 (0xef7dc0fd) has
  // MSB=1
  QuicVersion sconeVersion = (rateSignal & 0x1) ? QuicVersion::SCONE_VERSION_2
                                                : QuicVersion::SCONE_VERSION_1;
  appender.writeBE<uint32_t>(static_cast<uint32_t>(sconeVersion));

  appender.writeBE<uint8_t>(static_cast<uint8_t>(dstCid.size()));

  if (dstCid.size() > 0) {
    appender.push(dstCid.data(), dstCid.size());
  }

  appender.writeBE<uint8_t>(static_cast<uint8_t>(srcCid.size()));

  if (srcCid.size() > 0) {
    appender.push(srcCid.data(), srcCid.size());
  }

  VLOG(4) << "SCONE build: rate=" << (int)rateSignal << " version=0x"
          << std::hex << static_cast<uint32_t>(sconeVersion) << std::dec
          << " dstCidLen=" << dstCid.size() << " srcCidLen=" << srcCid.size()
          << " totalSize=" << packetSize;
  return *std::move(buf);
}

} // namespace quic
