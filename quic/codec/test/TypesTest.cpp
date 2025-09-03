/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <quic/codec/Types.h>

#include <folly/container/Array.h>
#include <folly/io/IOBuf.h>
#include <folly/portability/GTest.h>
#include <quic/codec/Decode.h>
#include <quic/common/test/TestUtils.h>

using namespace testing;

namespace quic::test {

std::pair<uint8_t, BufPtr> encodeShortHeader(const ShortHeader& header) {
  ShortHeader headerCopy = header;
  RegularQuicPacketBuilder builder(
      kDefaultUDPSendPacketLen, std::move(headerCopy), 0 /* largestAcked */);
  CHECK(!builder.encodePacketHeader().hasError());
  auto packet = std::move(builder).buildPacket();
  BufPtr out;
  Cursor cursor(&packet.header);
  auto initialByte = cursor.readBE<uint8_t>();
  cursor.clone(out, cursor.totalLength());
  return std::make_pair(initialByte, std::move(out));
}

class TypesTest : public Test {};

TEST_F(TypesTest, ReadHeaderForm) {
  EXPECT_EQ(HeaderForm::Short, getHeaderForm(0));
  EXPECT_EQ(HeaderForm::Short, getHeaderForm(0x7F));
  EXPECT_EQ(HeaderForm::Long, getHeaderForm(0x80));
  EXPECT_EQ(HeaderForm::Long, getHeaderForm(0xFF));
}

quic::Expected<ParsedLongHeaderResult, TransportErrorCode> makeLongHeader(
    LongHeader::Types packetType) {
  LongHeader headerRegular(
      packetType,
      getTestConnectionId(),
      getTestConnectionId(),
      321,
      QuicVersion::MVFST);

  LongHeader headerRetry(
      packetType,
      getTestConnectionId(),
      getTestConnectionId(),
      321,
      QuicVersion::MVFST,
      std::string("this is a retry token :)"));

  RegularQuicPacketBuilder builder(
      kDefaultUDPSendPacketLen,
      packetType == LongHeader::Types::Retry ? std::move(headerRetry)
                                             : std::move(headerRegular),
      0 /* largestAcked */);
  CHECK(!builder.encodePacketHeader().hasError());
  auto packet = packetToBuf(std::move(builder).buildPacket());
  packet->coalesce();
  ContiguousReadCursor cursor(packet->data(), packet->length());
  uint8_t initialByte = 0;
  cursor.tryReadBE(initialByte);
  return parseLongHeader(initialByte, cursor);
}

TEST_F(TypesTest, LongHeaderTypes) {
  uint8_t badLongHeader = kHeaderFormMask | 0x00;
  EXPECT_EQ(
      LongHeader::Types::Initial,
      makeLongHeader(LongHeader::Types::Initial)
          ->parsedLongHeader->header.getHeaderType());
  EXPECT_EQ(
      LongHeader::Types::Retry,
      makeLongHeader(LongHeader::Types::Retry)
          ->parsedLongHeader->header.getHeaderType());
  EXPECT_EQ(
      LongHeader::Types::Handshake,
      makeLongHeader(LongHeader::Types::Handshake)
          ->parsedLongHeader->header.getHeaderType());
  EXPECT_EQ(
      LongHeader::Types::ZeroRtt,
      makeLongHeader(LongHeader::Types::ZeroRtt)
          ->parsedLongHeader->header.getHeaderType());
  EXPECT_FALSE(makeLongHeader(static_cast<LongHeader::Types>(badLongHeader))
                   .has_value());
}

TEST_F(TypesTest, LongHeaderEmptyInput) {
  // Empty input
  uint8_t versionNegotiation = LongHeader::kPacketTypeMask;
  auto buf = folly::IOBuf::create(0);
  buf->append(0);
  ContiguousReadCursor cursor(buf->data(), buf->length());
  EXPECT_FALSE(parseLongHeader(versionNegotiation, cursor).has_value());
}

TEST_F(TypesTest, LongHeaderSmallInput) {
  uint8_t clientCleartext = kHeaderFormMask | LongHeader::kFixedBitMask |
      LongHeader::kPacketNumLenMask |
      (static_cast<uint8_t>(LongHeader::Types::Handshake)
       << LongHeader::kTypeShift);
  auto buf = folly::IOBuf::create(15);
  buf->append(15);
  folly::io::RWPrivateCursor wcursor(buf.get());
  wcursor.writeBE<uint32_t>(789);
  auto connId = getTestConnectionId();
  wcursor.push(connId.data(), connId.size());
  wcursor.writeBE<uint8_t>(1);
  wcursor.writeBE<uint8_t>(2);
  wcursor.writeBE<uint8_t>(3);

  ContiguousReadCursor cursor(buf->data(), buf->length());
  EXPECT_FALSE(parseLongHeader(clientCleartext, cursor).has_value());
}

TEST_F(TypesTest, LongHeaderInvalid) {
  uint8_t badInitialValue = 0x03;

  QuicVersion version = QuicVersion::MVFST;
  // Bad initial byte value
  auto buf = folly::IOBuf::create(16);
  buf->append(16);
  folly::io::RWPrivateCursor wcursor(buf.get());
  auto connId = getTestConnectionId();
  wcursor.push(connId.data(), connId.size());
  wcursor.writeBE<uint32_t>(1234);
  wcursor.writeBE<QuicVersionType>(static_cast<QuicVersionType>(version));

  ContiguousReadCursor cursor(buf->data(), buf->length());
  EXPECT_FALSE(parseLongHeader(badInitialValue, cursor).has_value());
}

TEST_F(TypesTest, ShortHeader) {
  PacketNum packetNum = 456;
  auto connId = getTestConnectionId();
  ShortHeader testHeader1(ProtectionType::KeyPhaseZero, connId, packetNum);
  auto result1 = encodeShortHeader(testHeader1);
  ContiguousReadCursor cursor1(
      result1.second->data(), result1.second->length());
  auto shortHeader1 = *parseShortHeader(result1.first, cursor1);
  EXPECT_EQ(ProtectionType::KeyPhaseZero, shortHeader1.getProtectionType());
  EXPECT_EQ(connId, shortHeader1.getConnectionId());

  // Empty buffer
  auto buf4 = folly::IOBuf::create(0);
  buf4->append(0);
  ContiguousReadCursor cursor4(buf4->data(), buf4->length());
  EXPECT_FALSE(parseShortHeader(0x01, cursor4).has_value());
}

TEST_F(TypesTest, TestHasDataLength) {
  auto frameTypeField = StreamTypeField::Builder().setLength().build();
  EXPECT_TRUE(frameTypeField.hasDataLength());
  auto frameTypeField2 = StreamTypeField::Builder().build();
  EXPECT_FALSE(frameTypeField2.hasDataLength());
}

TEST_F(TypesTest, ShortHeaderGetConnectionIdTest) {
  auto connId = getTestConnectionId();
  PacketNum packetNum = 111;

  ShortHeader testHeader(ProtectionType::KeyPhaseZero, connId, packetNum);
  auto result = encodeShortHeader(testHeader);
  ContiguousReadCursor cursor(result.second->data(), result.second->length());
  auto shortHeader = *parseShortHeader(result.first, cursor);
  EXPECT_EQ(connId, shortHeader.getConnectionId());
}

TEST_F(TypesTest, KeyPhase) {
  LongHeader longHeader(
      LongHeader::Types::Handshake,
      getTestConnectionId(),
      getTestConnectionId(),
      0,
      QuicVersion::MVFST);
  EXPECT_EQ(longHeader.getProtectionType(), ProtectionType::Handshake);

  LongHeader longHeader2(
      LongHeader::Types::ZeroRtt,
      getTestConnectionId(),
      getTestConnectionId(),
      0,
      QuicVersion::MVFST);
  EXPECT_EQ(longHeader2.getProtectionType(), ProtectionType::ZeroRtt);
}

TEST_F(TypesTest, ShortHeaderPacketNumberSpace) {
  ShortHeader shortHeaderZero(
      ProtectionType::KeyPhaseZero,
      ConnectionId::createAndMaybeCrash({1, 3, 5, 7, 8}),
      100);
  EXPECT_EQ(PacketNumberSpace::AppData, shortHeaderZero.getPacketNumberSpace());
  EXPECT_EQ(
      PacketNumberSpace::AppData,
      protectionTypeToPacketNumberSpace(shortHeaderZero.getProtectionType()));

  ShortHeader shortHeaderOne(
      ProtectionType::KeyPhaseOne,
      ConnectionId::createAndMaybeCrash({1, 3, 5, 7, 9}),
      101);
  EXPECT_EQ(PacketNumberSpace::AppData, shortHeaderOne.getPacketNumberSpace());
  EXPECT_EQ(
      PacketNumberSpace::AppData,
      protectionTypeToPacketNumberSpace(shortHeaderOne.getProtectionType()));
}

TEST_F(TypesTest, LongHeaderPacketNumberSpace) {
  LongHeader initialLongHeader(
      LongHeader::Types::Initial,
      getTestConnectionId(0),
      getTestConnectionId(1),
      200,
      QuicVersion::MVFST);
  EXPECT_EQ(
      PacketNumberSpace::Initial, initialLongHeader.getPacketNumberSpace());
  EXPECT_EQ(
      PacketNumberSpace::Initial,
      protectionTypeToPacketNumberSpace(initialLongHeader.getProtectionType()));

  LongHeader retryLongHeader(
      LongHeader::Types::Retry,
      getTestConnectionId(2),
      getTestConnectionId(3),
      201,
      QuicVersion::MVFST);
  EXPECT_EQ(PacketNumberSpace::Initial, retryLongHeader.getPacketNumberSpace());
  EXPECT_EQ(
      PacketNumberSpace::Initial,
      protectionTypeToPacketNumberSpace(retryLongHeader.getProtectionType()));

  LongHeader handshakeLongHeader(
      LongHeader::Types::Handshake,
      getTestConnectionId(4),
      getTestConnectionId(5),
      202,
      QuicVersion::MVFST);
  EXPECT_EQ(
      PacketNumberSpace::Handshake, handshakeLongHeader.getPacketNumberSpace());
  EXPECT_EQ(
      PacketNumberSpace::Handshake,
      protectionTypeToPacketNumberSpace(
          handshakeLongHeader.getProtectionType()));

  LongHeader zeroRttLongHeader(
      LongHeader::Types::ZeroRtt,
      getTestConnectionId(6),
      getTestConnectionId(7),
      203,
      QuicVersion::MVFST);
  EXPECT_EQ(
      PacketNumberSpace::AppData, zeroRttLongHeader.getPacketNumberSpace());
  EXPECT_EQ(
      PacketNumberSpace::AppData,
      protectionTypeToPacketNumberSpace(zeroRttLongHeader.getProtectionType()));
}

class PacketHeaderTest : public Test {};

TEST_F(PacketHeaderTest, LongHeader) {
  PacketNum packetNumber = 202;
  LongHeader handshakeLongHeader(
      LongHeader::Types::Handshake,
      getTestConnectionId(4),
      getTestConnectionId(5),
      packetNumber,
      QuicVersion::MVFST);
  PacketHeader readHeader(std::move(handshakeLongHeader));
  EXPECT_NE(readHeader.asLong(), nullptr);
  EXPECT_EQ(readHeader.asShort(), nullptr);
  EXPECT_EQ(readHeader.getPacketSequenceNum(), packetNumber);
  EXPECT_EQ(readHeader.getHeaderForm(), HeaderForm::Long);
  EXPECT_EQ(readHeader.getProtectionType(), ProtectionType::Handshake);
  EXPECT_EQ(readHeader.getPacketNumberSpace(), PacketNumberSpace::Handshake);
  EXPECT_EQ(readHeader.asLong()->getHeaderType(), LongHeader::Types::Handshake);
}

TEST_F(PacketHeaderTest, ShortHeader) {
  PacketNum packetNumber = 202;
  ConnectionId connid = getTestConnectionId(4);
  ShortHeader shortHeader(ProtectionType::KeyPhaseZero, connid, packetNumber);
  PacketHeader readHeader(std::move(shortHeader));
  EXPECT_EQ(readHeader.asLong(), nullptr);
  EXPECT_NE(readHeader.asShort(), nullptr);
  EXPECT_EQ(readHeader.getPacketSequenceNum(), packetNumber);
  EXPECT_EQ(readHeader.getHeaderForm(), HeaderForm::Short);
  EXPECT_EQ(readHeader.getProtectionType(), ProtectionType::KeyPhaseZero);
  EXPECT_EQ(readHeader.getPacketNumberSpace(), PacketNumberSpace::AppData);

  EXPECT_EQ(readHeader.asShort()->getConnectionId(), connid);
}
} // namespace quic::test
