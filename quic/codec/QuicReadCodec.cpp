/*
 * Copyright (c) Facebook, Inc. and its affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 *
 */

// override-include-guard
#include <quic/codec/QuicReadCodec.h>
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

CodecResult QuicReadCodec::parseLongHeaderPacket(
    folly::IOBufQueue& queue,
    const AckStates& ackStates) {
  folly::io::Cursor cursor(queue.front());
  auto initialByte = cursor.readBE<uint8_t>();
  auto longHeaderInvariant = parseLongHeaderInvariant(initialByte, cursor);
  if (!longHeaderInvariant) {
    VLOG(4) << "Dropping packet, failed to parse invariant " << connIdToHex();
    // We've failed to parse the long header, so we have no idea where this
    // packet ends. Clear the queue since no other data in this packet is
    // parse-able.
    queue.clear();
    return CodecResult(folly::none);
  }
  if (longHeaderInvariant->invariant.version ==
      QuicVersion::VERSION_NEGOTIATION) {
    // Couldn't parse the packet as a regular packet, try parsing it as a
    // version negotiation.

    auto versionNegotiation =
        decodeVersionNegotiation(*longHeaderInvariant, cursor);

    if (versionNegotiation) {
      return std::move(*versionNegotiation);
    } else {
      VLOG(4) << "Dropping version negotiation packet " << connIdToHex();
    }
    // Version negotiation is not allowed to be coalesced with any other packet.
    queue.clear();
    return CodecResult(folly::none);
  }
  auto type = parseLongHeaderType(initialByte);

  auto parsedLongHeader =
      parseLongHeaderVariants(type, std::move(*longHeaderInvariant), cursor);
  if (!parsedLongHeader) {
    VLOG(4) << "Dropping due to failed to parse header " << connIdToHex();
    // We've failed to parse the long header, so we have no idea where this
    // packet ends. Clear the queue since no other data in this packet is
    // parse-able.
    queue.clear();
    return CodecResult(folly::none);
  }
  // As soon as we have parsed out the long header we can split off any
  // coalesced packets. We do this early since the spec mandates that decryption
  // failure must not stop the processing of subsequent coalesced packets.
  auto longHeader = std::move(parsedLongHeader->header);

  if (type == LongHeader::Types::Retry) {
    return RegularQuicPacket(std::move(longHeader));
  }

  uint64_t packetNumberOffset = cursor.getCurrentPosition();
  size_t currentPacketLen =
      packetNumberOffset + parsedLongHeader->packetLength.packetLength;
  if (queue.chainLength() < currentPacketLen) {
    // Packet appears truncated, there's no parse-able data left.
    queue.clear();
    return CodecResult(folly::none);
  }
  auto currentPacketData = queue.split(currentPacketLen);
  cursor.reset(currentPacketData.get());
  cursor.skip(packetNumberOffset);
  // Sample starts after the max packet number size. This ensures that we
  // have enough bytes to skip before we can start reading the sample.
  if (!cursor.canAdvance(kMaxPacketNumEncodingSize)) {
    VLOG(4) << "Dropping packet, not enough for packet number "
            << connIdToHex();
    // Packet appears truncated, there's no parse-able data left.
    queue.clear();
    return CodecResult(folly::none);
  }
  cursor.skip(kMaxPacketNumEncodingSize);
  Sample sample;
  if (!cursor.canAdvance(sample.size())) {
    VLOG(4) << "Dropping packet, sample too small " << connIdToHex();
    // Packet appears truncated, there's no parse-able data left.
    queue.clear();
    return CodecResult(folly::none);
  }
  cursor.pull(sample.data(), sample.size());
  const PacketNumberCipher* headerCipher{nullptr};
  const fizz::Aead* cipher{nullptr};
  auto protectionType = longHeader.getProtectionType();
  switch (protectionType) {
    case ProtectionType::Initial:
      if (handshakeDoneTime_) {
        auto timeBetween = Clock::now() - *handshakeDoneTime_;
        if (timeBetween > kTimeToRetainZeroRttKeys) {
          VLOG(4) << nodeToString(nodeType_)
                  << " dropping initial packet for exceeding key timeout"
                  << connIdToHex();
          return CodecResult(folly::none);
        }
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
        auto timeBetween = Clock::now() - *handshakeDoneTime_;
        if (timeBetween > kTimeToRetainZeroRttKeys) {
          VLOG(4) << nodeToString(nodeType_)
                  << " dropping zero rtt packet for exceeding key timeout"
                  << connIdToHex();
          return CodecResult(folly::none);
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
    // TODO: remove packet number here.
    return CodecResult(
        CipherUnavailable(std::move(currentPacketData), 0, protectionType));
  }

  // TODO: decrypt the long header.
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
  folly::IOBufQueue decryptQueue{folly::IOBufQueue::cacheChainLength()};
  decryptQueue.append(std::move(currentPacketData));
  size_t aadLen = packetNumberOffset + packetNum.second;
  auto headerData = decryptQueue.split(aadLen);
  // parsing verifies that packetLength >= packet number length.
  auto encryptedData = decryptQueue.splitAtMost(
      parsedLongHeader->packetLength.packetLength - packetNum.second);
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
    return CodecResult(folly::none);
  }
  decrypted = std::move(*decryptAttempt);

  if (!decrypted) {
    // TODO better way of handling this (tests break without this)
    decrypted = folly::IOBuf::create(0);
  }

  folly::io::Cursor packetCursor(decrypted.get());
  return decodeRegularPacket(std::move(longHeader), params_, packetCursor);
}

CodecResult QuicReadCodec::parsePacket(
    folly::IOBufQueue& queue,
    const AckStates& ackStates) {
  if (queue.empty()) {
    return CodecResult(folly::none);
  }
  DCHECK(!queue.front()->isChained());
  folly::io::Cursor cursor(queue.front());
  if (!cursor.canAdvance(sizeof(uint8_t))) {
    return folly::none;
  }
  uint8_t initialByte = cursor.readBE<uint8_t>();
  auto headerForm = getHeaderForm(initialByte);
  if (headerForm == HeaderForm::Long) {
    return parseLongHeaderPacket(queue, ackStates);
  }
  // Short header:
  // TODO: support key phase one.
  if (!oneRttReadCipher_ || !oneRttHeaderCipher_) {
    VLOG(4) << nodeToString(nodeType_) << " cannot read key phase zero packet";
    VLOG(20) << "cannot read data="
             << folly::hexlify(queue.front()->clone()->moveToFbString()) << " "
             << connIdToHex();
    return CodecResult(
        CipherUnavailable(queue.move(), 0, ProtectionType::KeyPhaseZero));
  }

  // TODO: allow other connid lengths from the state.
  size_t packetNumberOffset = 1 + kDefaultConnectionIdSize;
  PacketNum expectedNextPacketNum =
      ackStates.appDataAckState.largestReceivedPacketNum
      ? (1 + *ackStates.appDataAckState.largestReceivedPacketNum)
      : 0;
  size_t sampleOffset = packetNumberOffset + kMaxPacketNumEncodingSize;
  Sample sample;
  if (queue.chainLength() < sampleOffset + sample.size()) {
    VLOG(10) << "Dropping packet, too small for sample " << connIdToHex();
    // There's not enough space for the short header packet, clear the queue
    // to indicate there's no more parse-able data.
    queue.clear();
    return CodecResult(folly::none);
  }
  // Take it out of the queue so we can do some writing.
  auto data = queue.move();
  folly::MutableByteRange initialByteRange(data->writableData(), 1);
  folly::MutableByteRange packetNumberByteRange(
      data->writableData() + packetNumberOffset, kMaxPacketNumEncodingSize);
  folly::ByteRange sampleByteRange(
      data->writableData() + sampleOffset, sample.size());

  oneRttHeaderCipher_->decryptShortHeader(
      sampleByteRange, initialByteRange, packetNumberByteRange);
  std::pair<PacketNum, size_t> packetNum = parsePacketNumber(
      initialByteRange.data()[0], packetNumberByteRange, expectedNextPacketNum);
  auto shortHeader = parseShortHeader(initialByteRange.data()[0], cursor);
  if (!shortHeader) {
    VLOG(10) << "Dropping packet, cannot parse " << connIdToHex();
    return folly::none;
  }
  shortHeader->setPacketNumber(packetNum.first);
  if (shortHeader->getProtectionType() == ProtectionType::KeyPhaseOne) {
    VLOG(4) << nodeToString(nodeType_) << " cannot read key phase one packet "
            << connIdToHex();
    return folly::none;
  }

  // Back in the queue so we can split.
  // TODO: this will share the buffer. We should be able to supply an unshared
  // buffer.
  queue.append(std::move(data));
  size_t aadLen = packetNumberOffset + packetNum.second;
  auto headerData = queue.split(aadLen);
  auto encryptedData = queue.move();
  if (!encryptedData) {
    // There should normally be some integrity tag at least in the data,
    // however allowing the aead to process the data even if the tag is not
    // present helps with writing tests.
    encryptedData = folly::IOBuf::create(0);
  }
  Buf decrypted;
  // TODO: small optimization we can do here: only read the token if
  // decryption fails
  folly::Optional<StatelessResetToken> token;
  auto encryptedDataLength = encryptedData->computeChainDataLength();
  if (statelessResetToken_ &&
      encryptedDataLength > sizeof(StatelessResetToken)) {
    token = StatelessResetToken();
    // We want to avoid cloning the IOBuf which would prevent in-place
    // decryption
    folly::io::Cursor statelessTokenCursor(encryptedData.get());
    // TODO: we could possibly use headroom or tailroom of the iobuf to avoid
    // extra allocations
    statelessTokenCursor.skip(
        encryptedDataLength - sizeof(StatelessResetToken));
    statelessTokenCursor.pull(token->data(), token->size());
  }
  auto decryptAttempt = oneRttReadCipher_->tryDecrypt(
      std::move(encryptedData), headerData.get(), packetNum.first);
  if (!decryptAttempt) {
    // Can't return the data now, already consumed it to try decrypting it.
    if (token) {
      return StatelessReset(*token);
    }
    auto protectionType = shortHeader->getProtectionType();
    VLOG(10) << "Unable to decrypt packet=" << packetNum.first
             << " protectionType=" << (int)protectionType << " "
             << connIdToHex();
    return CodecResult(folly::none);
  }
  decrypted = std::move(*decryptAttempt);
  if (!decrypted) {
    // TODO better way of handling this (tests break without this)
    decrypted = folly::IOBuf::create(0);
  }

  folly::io::Cursor packetCursor(decrypted.get());
  return decodeRegularPacket(std::move(*shortHeader), params_, packetCursor);
}

const fizz::Aead* QuicReadCodec::getOneRttReadCipher() const {
  return oneRttReadCipher_.get();
}

const fizz::Aead* QuicReadCodec::getZeroRttReadCipher() const {
  return zeroRttReadCipher_.get();
}

const fizz::Aead* QuicReadCodec::getHandshakeReadCipher() const {
  return handshakeReadCipher_.get();
}

const folly::Optional<StatelessResetToken>&
QuicReadCodec::getStatelessResetToken() const {
  return statelessResetToken_;
}

void QuicReadCodec::setInitialReadCipher(
    std::unique_ptr<fizz::Aead> initialReadCipher) {
  initialReadCipher_ = std::move(initialReadCipher);
}

void QuicReadCodec::setOneRttReadCipher(
    std::unique_ptr<fizz::Aead> oneRttReadCipher) {
  oneRttReadCipher_ = std::move(oneRttReadCipher);
}

void QuicReadCodec::setZeroRttReadCipher(
    std::unique_ptr<fizz::Aead> zeroRttReadCipher) {
  if (nodeType_ == QuicNodeType::Client) {
    throw QuicTransportException(
        "Invalid cipher", TransportErrorCode::INTERNAL_ERROR);
  }
  zeroRttReadCipher_ = std::move(zeroRttReadCipher);
}

void QuicReadCodec::setHandshakeReadCipher(
    std::unique_ptr<fizz::Aead> handshakeReadCipher) {
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

const fizz::Aead* QuicReadCodec::getInitialCipher() const {
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

std::string QuicReadCodec::connIdToHex() {
  static ConnectionId zeroConn = zeroConnId();
  const auto& serverId = serverConnectionId_.value_or(zeroConn);
  const auto& clientId = clientConnectionId_.value_or(zeroConn);
  return folly::to<std::string>(
      "server=", serverId.hex(), " ", "client=", clientId.hex());
}
} // namespace quic
