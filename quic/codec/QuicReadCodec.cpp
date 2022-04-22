/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <quic/codec/QuicReadCodec.h>

#include <fizz/crypto/Utils.h>
#include <folly/io/Cursor.h>
#include <quic/codec/Decode.h>
#include <quic/codec/PacketNumber.h>

namespace {
quic::ConnectionId zeroConnId() {
  std::vector<uint8_t> zeroData(quic::kDefaultConnectionIdSize, 0);
  return quic::ConnectionId(zeroData);
}
} // namespace

namespace quic {

QuicReadCodec::QuicReadCodec(QuicNodeType nodeType) : nodeType_(nodeType) {}

folly::Optional<VersionNegotiationPacket>
QuicReadCodec::tryParsingVersionNegotiation(BufQueue& queue) {
  folly::io::Cursor cursor(queue.front());
  if (!cursor.canAdvance(sizeof(uint8_t))) {
    return folly::none;
  }
  uint8_t initialByte = cursor.readBE<uint8_t>();
  auto headerForm = getHeaderForm(initialByte);
  if (headerForm != HeaderForm::Long) {
    return folly::none;
  }
  auto longHeaderInvariant = parseLongHeaderInvariant(initialByte, cursor);
  if (!longHeaderInvariant) {
    // if it is an invalid packet, it's definitely not a VN packet, so ignore
    // it.
    return folly::none;
  }
  if (longHeaderInvariant->invariant.version !=
      QuicVersion::VERSION_NEGOTIATION) {
    return folly::none;
  }
  return decodeVersionNegotiation(*longHeaderInvariant, cursor);
}

folly::Expected<ParsedLongHeader, TransportErrorCode> tryParseLongHeader(
    folly::io::Cursor& cursor,
    QuicNodeType nodeType) {
  if (cursor.isAtEnd() || !cursor.canAdvance(sizeof(uint8_t))) {
    return folly::makeUnexpected(TransportErrorCode::PROTOCOL_VIOLATION);
  }
  auto initialByte = cursor.readBE<uint8_t>();
  auto longHeaderInvariant = parseLongHeaderInvariant(initialByte, cursor);
  if (!longHeaderInvariant) {
    VLOG(4) << "Dropping packet, failed to parse invariant";
    // We've failed to parse the long header, so we have no idea where this
    // packet ends. Clear the queue since no other data in this packet is
    // parse-able.
    return folly::makeUnexpected(longHeaderInvariant.error());
  }
  if (longHeaderInvariant->invariant.version ==
      QuicVersion::VERSION_NEGOTIATION) {
    // We shouldn't handle VN packets while parsing the long header.
    // We assume here that they have been handled before calling this
    // function.
    // Since VN is not allowed to be coalesced with another packet
    // type, we clear out the buffer to avoid anyone else parsing it.
    return folly::makeUnexpected(TransportErrorCode::PROTOCOL_VIOLATION);
  }
  auto type = parseLongHeaderType(initialByte);

  auto parsedLongHeader =
      parseLongHeaderVariants(type, *longHeaderInvariant, cursor, nodeType);
  if (!parsedLongHeader) {
    VLOG(4) << "Dropping due to failed to parse header";
    // We've failed to parse the long header, so we have no idea where this
    // packet ends. Clear the queue since no other data in this packet is
    // parse-able.
    return folly::makeUnexpected(parsedLongHeader.error());
  }

  return std::move(parsedLongHeader.value());
}

CodecResult QuicReadCodec::parseLongHeaderPacket(
    BufQueue& queue,
    const AckStates& ackStates) {
  folly::io::Cursor cursor(queue.front());
  const uint8_t initialByte = *cursor.peekBytes().data();

  auto res = tryParseLongHeader(cursor, nodeType_);
  if (res.hasError()) {
    VLOG(4) << "Failed to parse long header " << connIdToHex();
    queue.move();
    return CodecResult(Nothing());
  }
  auto parsedLongHeader = std::move(res.value());
  auto type = parsedLongHeader.header.getHeaderType();

  // As soon as we have parsed out the long header we can split off any
  // coalesced packets. We do this early since the spec mandates that decryption
  // failure must not stop the processing of subsequent coalesced packets.
  auto longHeader = std::move(parsedLongHeader.header);

  if (type == LongHeader::Types::Retry) {
    Buf integrityTag;
    cursor.clone(integrityTag, kRetryIntegrityTagLen);
    queue.move();
    return RetryPacket(
        std::move(longHeader), std::move(integrityTag), initialByte);
  }

  uint64_t packetNumberOffset = cursor.getCurrentPosition();
  size_t currentPacketLen =
      packetNumberOffset + parsedLongHeader.packetLength.packetLength;
  if (queue.chainLength() < currentPacketLen) {
    // Packet appears truncated, there's no parse-able data left.
    queue.move();
    return CodecResult(Nothing());
  }
  auto currentPacketData = queue.splitAtMost(currentPacketLen);
  cursor.reset(currentPacketData.get());
  cursor.skip(packetNumberOffset);
  // Sample starts after the max packet number size. This ensures that we
  // have enough bytes to skip before we can start reading the sample.
  if (!cursor.canAdvance(kMaxPacketNumEncodingSize)) {
    VLOG(4) << "Dropping packet, not enough for packet number "
            << connIdToHex();
    // Packet appears truncated, there's no parse-able data left.
    queue.move();
    return CodecResult(Nothing());
  }
  cursor.skip(kMaxPacketNumEncodingSize);
  Sample sample;
  if (!cursor.canAdvance(sample.size())) {
    VLOG(4) << "Dropping packet, sample too small " << connIdToHex();
    // Packet appears truncated, there's no parse-able data left.
    queue.move();
    return CodecResult(Nothing());
  }
  cursor.pull(sample.data(), sample.size());
  const PacketNumberCipher* headerCipher{nullptr};
  const Aead* cipher{nullptr};
  auto protectionType = longHeader.getProtectionType();
  switch (protectionType) {
    case ProtectionType::Initial:
      if (!initialHeaderCipher_) {
        VLOG(4) << nodeToString(nodeType_)
                << " dropping initial packet after initial keys dropped"
                << connIdToHex();
        return CodecResult(Nothing());
      }
      headerCipher = initialHeaderCipher_.get();
      cipher = initialReadCipher_.get();
      break;
    case ProtectionType::Handshake:
      headerCipher = handshakeHeaderCipher_.get();
      cipher = handshakeReadCipher_.get();
      break;
    case ProtectionType::ZeroRtt:
      if (handshakeDoneTime_) {
        // TODO actually drop the 0-rtt keys in addition to dropping packets.
        auto timeBetween = Clock::now() - *handshakeDoneTime_;
        if (timeBetween > kTimeToRetainZeroRttKeys) {
          VLOG(4) << nodeToString(nodeType_)
                  << " dropping zero rtt packet for exceeding key timeout"
                  << connIdToHex();
          return CodecResult(Nothing());
        }
      }
      headerCipher = zeroRttHeaderCipher_.get();
      cipher = zeroRttReadCipher_.get();
      break;
    case ProtectionType::KeyPhaseZero:
    case ProtectionType::KeyPhaseOne:
      CHECK(false) << "one rtt protection type in long header";
  }
  if (!headerCipher || !cipher) {
    return CodecResult(
        CipherUnavailable(std::move(currentPacketData), protectionType));
  }

  PacketNum expectedNextPacketNum = 0;
  folly::Optional<PacketNum> largestReceivedPacketNum;
  switch (longHeaderTypeToProtectionType(type)) {
    case ProtectionType::Initial:
      largestReceivedPacketNum =
          ackStates.initialAckState.largestReceivedPacketNum;
      break;
    case ProtectionType::Handshake:
      largestReceivedPacketNum =
          ackStates.handshakeAckState.largestReceivedPacketNum;
      break;
    case ProtectionType::ZeroRtt:
      largestReceivedPacketNum =
          ackStates.appDataAckState.largestReceivedPacketNum;
      break;
    default:
      folly::assume_unreachable();
  }
  if (largestReceivedPacketNum) {
    expectedNextPacketNum = 1 + *largestReceivedPacketNum;
  }
  folly::MutableByteRange initialByteRange(
      currentPacketData->writableData(), 1);
  folly::MutableByteRange packetNumberByteRange(
      currentPacketData->writableData() + packetNumberOffset,
      kMaxPacketNumEncodingSize);
  headerCipher->decryptLongHeader(
      folly::range(sample), initialByteRange, packetNumberByteRange);
  std::pair<PacketNum, size_t> packetNum = parsePacketNumber(
      initialByteRange.data()[0], packetNumberByteRange, expectedNextPacketNum);

  longHeader.setPacketNumber(packetNum.first);
  BufQueue decryptQueue;
  decryptQueue.append(std::move(currentPacketData));
  size_t aadLen = packetNumberOffset + packetNum.second;
  auto headerData = decryptQueue.splitAtMost(aadLen);
  // parsing verifies that packetLength >= packet number length.
  auto encryptedData = decryptQueue.splitAtMost(
      parsedLongHeader.packetLength.packetLength - packetNum.second);
  if (!encryptedData) {
    // There should normally be some integrity tag at least in the data,
    // however allowing the aead to process the data even if the tag is not
    // present helps with writing tests.
    encryptedData = folly::IOBuf::create(0);
  }

  Buf decrypted;
  auto decryptAttempt = cipher->tryDecrypt(
      std::move(encryptedData), headerData.get(), packetNum.first);
  if (!decryptAttempt) {
    VLOG(4) << "Unable to decrypt packet=" << packetNum.first
            << " packetNumLen=" << parsePacketNumberLength(initialByte)
            << " protectionType=" << toString(protectionType) << " "
            << connIdToHex();
    return CodecResult(Nothing());
  }
  decrypted = std::move(*decryptAttempt);

  if (!decrypted) {
    // TODO better way of handling this (tests break without this)
    decrypted = folly::IOBuf::create(0);
  }

  return decodeRegularPacket(
      std::move(longHeader), params_, std::move(decrypted));
}

CodecResult QuicReadCodec::tryParseShortHeaderPacket(
    Buf data,
    const AckStates& ackStates,
    size_t dstConnIdSize,
    folly::io::Cursor& cursor) {
  // TODO: allow other connid lengths from the state.
  size_t packetNumberOffset = 1 + dstConnIdSize;
  PacketNum expectedNextPacketNum =
      ackStates.appDataAckState.largestReceivedPacketNum
      ? (1 + *ackStates.appDataAckState.largestReceivedPacketNum)
      : 0;
  size_t sampleOffset = packetNumberOffset + kMaxPacketNumEncodingSize;
  Sample sample;
  if (data->computeChainDataLength() < sampleOffset + sample.size()) {
    VLOG(10) << "Dropping packet, too small for sample " << connIdToHex();
    // There's not enough space for the short header packet
    return CodecResult(Nothing());
  }

  folly::MutableByteRange initialByteRange(data->writableData(), 1);
  folly::MutableByteRange packetNumberByteRange(
      data->writableData() + packetNumberOffset, kMaxPacketNumEncodingSize);
  folly::ByteRange sampleByteRange(
      data->writableData() + sampleOffset, sample.size());

  oneRttHeaderCipher_->decryptShortHeader(
      sampleByteRange, initialByteRange, packetNumberByteRange);
  std::pair<PacketNum, size_t> packetNum = parsePacketNumber(
      initialByteRange.data()[0], packetNumberByteRange, expectedNextPacketNum);
  auto shortHeader =
      parseShortHeader(initialByteRange.data()[0], cursor, dstConnIdSize);
  if (!shortHeader) {
    VLOG(10) << "Dropping packet, cannot parse " << connIdToHex();
    return CodecResult(Nothing());
  }
  shortHeader->setPacketNumber(packetNum.first);
  if (shortHeader->getProtectionType() == ProtectionType::KeyPhaseOne) {
    VLOG(4) << nodeToString(nodeType_) << " cannot read key phase one packet "
            << connIdToHex();
    return CodecResult(Nothing());
  }

  // We know that the iobuf is not chained. This means that we can safely have a
  // non-owning reference to the header without cloning the buffer. If we don't
  // clone the buffer, the buffer will not show up as shared and we can decrypt
  // in-place.
  size_t aadLen = packetNumberOffset + packetNum.second;
  folly::IOBuf headerData =
      folly::IOBuf::wrapBufferAsValue(data->data(), aadLen);
  data->trimStart(aadLen);

  Buf decrypted;
  auto decryptAttempt = oneRttReadCipher_->tryDecrypt(
      std::move(data), &headerData, packetNum.first);
  if (!decryptAttempt) {
    auto protectionType = shortHeader->getProtectionType();
    VLOG(10) << "Unable to decrypt packet=" << packetNum.first
             << " protectionType=" << (int)protectionType << " "
             << connIdToHex();
    return CodecResult(Nothing());
  }
  decrypted = std::move(*decryptAttempt);
  if (!decrypted) {
    // TODO better way of handling this (tests break without this)
    decrypted = folly::IOBuf::create(0);
  }

  return decodeRegularPacket(
      std::move(*shortHeader), params_, std::move(decrypted));
}

CodecResult QuicReadCodec::parsePacket(
    BufQueue& queue,
    const AckStates& ackStates,
    size_t dstConnIdSize) {
  if (queue.empty()) {
    return CodecResult(Nothing());
  }
  DCHECK(!queue.front()->isChained());
  folly::io::Cursor cursor(queue.front());
  if (!cursor.canAdvance(sizeof(uint8_t))) {
    return CodecResult(Nothing());
  }
  uint8_t initialByte = cursor.readBE<uint8_t>();
  auto headerForm = getHeaderForm(initialByte);
  if (headerForm == HeaderForm::Long) {
    return parseLongHeaderPacket(queue, ackStates);
  }
  // Missing 1-rtt Cipher is the only case we wouldn't consider reset
  // TODO: support key phase one.
  if (!oneRttReadCipher_ || !oneRttHeaderCipher_) {
    VLOG(4) << nodeToString(nodeType_) << " cannot read key phase zero packet";
    VLOG(20) << "cannot read data="
             << folly::hexlify(queue.front()->clone()->moveToFbString()) << " "
             << connIdToHex();
    return CodecResult(
        CipherUnavailable(queue.move(), ProtectionType::KeyPhaseZero));
  }

  auto data = queue.move();
  folly::Optional<StatelessResetToken> token;
  if (nodeType_ == QuicNodeType::Client &&
      initialByte & ShortHeader::kFixedBitMask) {
    auto dataLength = data->length();
    if (statelessResetToken_ && dataLength > sizeof(StatelessResetToken)) {
      const uint8_t* tokenSource =
          data->data() + (dataLength - sizeof(StatelessResetToken));
      // Only allocate & copy the token if it matches the token we have
      if (fizz::CryptoUtils::equal(
              folly::ByteRange(tokenSource, sizeof(StatelessResetToken)),
              folly::ByteRange(
                  statelessResetToken_->data(), sizeof(StatelessResetToken)))) {
        token = StatelessResetToken();
        memcpy(token->data(), tokenSource, token->size());
      }
    }
  }

  auto maybeShortHeaderPacket = tryParseShortHeaderPacket(
      std::move(data), ackStates, dstConnIdSize, cursor);
  if (token && maybeShortHeaderPacket.nothing()) {
    return StatelessReset(*token);
  }
  return maybeShortHeaderPacket;
}

const Aead* QuicReadCodec::getOneRttReadCipher() const {
  return oneRttReadCipher_.get();
}

const Aead* QuicReadCodec::getZeroRttReadCipher() const {
  return zeroRttReadCipher_.get();
}

const Aead* QuicReadCodec::getHandshakeReadCipher() const {
  return handshakeReadCipher_.get();
}

const folly::Optional<StatelessResetToken>&
QuicReadCodec::getStatelessResetToken() const {
  return statelessResetToken_;
}

CodecParameters QuicReadCodec::getCodecParameters() const {
  return params_;
}

void QuicReadCodec::setInitialReadCipher(
    std::unique_ptr<Aead> initialReadCipher) {
  initialReadCipher_ = std::move(initialReadCipher);
}

void QuicReadCodec::setOneRttReadCipher(
    std::unique_ptr<Aead> oneRttReadCipher) {
  oneRttReadCipher_ = std::move(oneRttReadCipher);
}

void QuicReadCodec::setZeroRttReadCipher(
    std::unique_ptr<Aead> zeroRttReadCipher) {
  if (nodeType_ == QuicNodeType::Client) {
    throw QuicTransportException(
        "Invalid cipher", TransportErrorCode::INTERNAL_ERROR);
  }
  zeroRttReadCipher_ = std::move(zeroRttReadCipher);
}

void QuicReadCodec::setHandshakeReadCipher(
    std::unique_ptr<Aead> handshakeReadCipher) {
  handshakeReadCipher_ = std::move(handshakeReadCipher);
}

void QuicReadCodec::setInitialHeaderCipher(
    std::unique_ptr<PacketNumberCipher> initialHeaderCipher) {
  initialHeaderCipher_ = std::move(initialHeaderCipher);
}

void QuicReadCodec::setOneRttHeaderCipher(
    std::unique_ptr<PacketNumberCipher> oneRttHeaderCipher) {
  oneRttHeaderCipher_ = std::move(oneRttHeaderCipher);
}

void QuicReadCodec::setZeroRttHeaderCipher(
    std::unique_ptr<PacketNumberCipher> zeroRttHeaderCipher) {
  zeroRttHeaderCipher_ = std::move(zeroRttHeaderCipher);
}

void QuicReadCodec::setHandshakeHeaderCipher(
    std::unique_ptr<PacketNumberCipher> handshakeHeaderCipher) {
  handshakeHeaderCipher_ = std::move(handshakeHeaderCipher);
}

void QuicReadCodec::setCodecParameters(CodecParameters params) {
  params_ = std::move(params);
}

void QuicReadCodec::setClientConnectionId(ConnectionId connId) {
  clientConnectionId_ = connId;
}

void QuicReadCodec::setServerConnectionId(ConnectionId connId) {
  serverConnectionId_ = connId;
}

void QuicReadCodec::setStatelessResetToken(
    StatelessResetToken statelessResetToken) {
  statelessResetToken_ = std::move(statelessResetToken);
}

const ConnectionId& QuicReadCodec::getClientConnectionId() const {
  return clientConnectionId_.value();
}

const ConnectionId& QuicReadCodec::getServerConnectionId() const {
  return serverConnectionId_.value();
}

const Aead* QuicReadCodec::getInitialCipher() const {
  return initialReadCipher_.get();
}

const PacketNumberCipher* QuicReadCodec::getInitialHeaderCipher() const {
  return initialHeaderCipher_.get();
}

const PacketNumberCipher* QuicReadCodec::getOneRttHeaderCipher() const {
  return oneRttHeaderCipher_.get();
}

const PacketNumberCipher* QuicReadCodec::getHandshakeHeaderCipher() const {
  return handshakeHeaderCipher_.get();
}

const PacketNumberCipher* QuicReadCodec::getZeroRttHeaderCipher() const {
  return zeroRttHeaderCipher_.get();
}

void QuicReadCodec::onHandshakeDone(TimePoint handshakeDoneTime) {
  if (!handshakeDoneTime_) {
    handshakeDoneTime_ = handshakeDoneTime;
  }
}

folly::Optional<TimePoint> QuicReadCodec::getHandshakeDoneTime() {
  return handshakeDoneTime_;
}

std::string QuicReadCodec::connIdToHex() const {
  static ConnectionId zeroConn = zeroConnId();
  const auto& serverId = serverConnectionId_.value_or(zeroConn);
  const auto& clientId = clientConnectionId_.value_or(zeroConn);
  return folly::to<std::string>(
      "server=", serverId.hex(), " ", "client=", clientId.hex());
}

CodecResult::CodecResult(RegularQuicPacket&& regularPacketIn)
    : type_(CodecResult::Type::REGULAR_PACKET) {
  new (&packet) RegularQuicPacket(std::move(regularPacketIn));
}

CodecResult::CodecResult(CipherUnavailable&& cipherUnavailableIn)
    : type_(CodecResult::Type::CIPHER_UNAVAILABLE) {
  new (&cipher) CipherUnavailable(std::move(cipherUnavailableIn));
}

CodecResult::CodecResult(StatelessReset&& statelessResetIn)
    : type_(CodecResult::Type::STATELESS_RESET) {
  new (&reset) StatelessReset(std::move(statelessResetIn));
}

CodecResult::CodecResult(RetryPacket&& retryPacketIn)
    : type_(CodecResult::Type::RETRY) {
  new (&retry) RetryPacket(std::move(retryPacketIn));
}

CodecResult::CodecResult(Nothing&&) : type_(CodecResult::Type::NOTHING) {
  new (&none) Nothing();
}

void CodecResult::destroyCodecResult() {
  switch (type_) {
    case CodecResult::Type::REGULAR_PACKET:
      packet.~RegularQuicPacket();
      break;
    case CodecResult::Type::RETRY:
      retry.~RetryPacket();
      break;
    case CodecResult::Type::CIPHER_UNAVAILABLE:
      cipher.~CipherUnavailable();
      break;
    case CodecResult::Type::STATELESS_RESET:
      reset.~StatelessReset();
      break;
    case CodecResult::Type::NOTHING:
      none.~Nothing();
      break;
  }
}

CodecResult::~CodecResult() {
  destroyCodecResult();
}

CodecResult::CodecResult(CodecResult&& other) noexcept {
  switch (other.type_) {
    case CodecResult::Type::REGULAR_PACKET:
      new (&packet) RegularQuicPacket(std::move(other.packet));
      break;
    case CodecResult::Type::RETRY:
      new (&retry) RetryPacket(std::move(other.retry));
      break;
    case CodecResult::Type::CIPHER_UNAVAILABLE:
      new (&cipher) CipherUnavailable(std::move(other.cipher));
      break;
    case CodecResult::Type::STATELESS_RESET:
      new (&reset) StatelessReset(std::move(other.reset));
      break;
    case CodecResult::Type::NOTHING:
      new (&none) Nothing(std::move(other.none));
      break;
  }
  type_ = other.type_;
}

CodecResult& CodecResult::operator=(CodecResult&& other) noexcept {
  destroyCodecResult();
  switch (other.type_) {
    case CodecResult::Type::REGULAR_PACKET:
      new (&packet) RegularQuicPacket(std::move(other.packet));
      break;
    case CodecResult::Type::RETRY:
      new (&retry) RetryPacket(std::move(other.retry));
      break;
    case CodecResult::Type::CIPHER_UNAVAILABLE:
      new (&cipher) CipherUnavailable(std::move(other.cipher));
      break;
    case CodecResult::Type::STATELESS_RESET:
      new (&reset) StatelessReset(std::move(other.reset));
      break;
    case CodecResult::Type::NOTHING:
      new (&none) Nothing(std::move(other.none));
      break;
  }
  type_ = other.type_;
  return *this;
}

CodecResult::Type CodecResult::type() {
  return type_;
}

RegularQuicPacket* CodecResult::regularPacket() {
  if (type_ == CodecResult::Type::REGULAR_PACKET) {
    return &packet;
  }
  return nullptr;
}

CipherUnavailable* CodecResult::cipherUnavailable() {
  if (type_ == CodecResult::Type::CIPHER_UNAVAILABLE) {
    return &cipher;
  }
  return nullptr;
}

StatelessReset* CodecResult::statelessReset() {
  if (type_ == CodecResult::Type::STATELESS_RESET) {
    return &reset;
  }
  return nullptr;
}

RetryPacket* CodecResult::retryPacket() {
  if (type_ == CodecResult::Type::RETRY) {
    return &retry;
  }
  return nullptr;
}

Nothing* CodecResult::nothing() {
  if (type_ == CodecResult::Type::NOTHING) {
    return &none;
  }
  return nullptr;
}
} // namespace quic
