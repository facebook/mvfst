/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <quic/codec/QuicReadCodec.h>

#include <folly/io/Cursor.h>
#include <folly/portability/GTest.h>
#include <quic/QuicException.h>
#include <quic/common/test/TestUtils.h>
#include <quic/fizz/handshake/FizzCryptoFactory.h>

using namespace quic;
using namespace quic::test;
using namespace testing;

bool parseSuccess(CodecResult&& result) {
  return result.regularPacket() != nullptr;
}

bool isReset(CodecResult&& result) {
  return result.statelessReset() != nullptr;
}

class QuicReadCodecTest : public Test {};

std::unique_ptr<QuicReadCodec> makeUnencryptedCodec() {
  auto codec = std::make_unique<QuicReadCodec>(QuicNodeType::Server);
  codec->setCodecParameters(
      CodecParameters(kDefaultAckDelayExponent, QuicVersion::MVFST));
  return codec;
}

std::unique_ptr<QuicReadCodec> makeEncryptedCodec(
    ConnectionId clientConnId,
    std::unique_ptr<Aead> oneRttAead,
    std::unique_ptr<Aead> zeroRttAead = nullptr,
    std::unique_ptr<StatelessResetToken> sourceToken = nullptr,
    QuicNodeType nodeType = QuicNodeType::Server) {
  FizzCryptoFactory cryptoFactory;
  auto codec = std::make_unique<QuicReadCodec>(nodeType);
  codec->setClientConnectionId(clientConnId);
  codec->setInitialReadCipher(
      cryptoFactory.getClientInitialCipher(clientConnId, QuicVersion::MVFST));
  codec->setInitialHeaderCipher(cryptoFactory.makeClientInitialHeaderCipher(
      clientConnId, QuicVersion::MVFST));
  if (zeroRttAead) {
    codec->setZeroRttReadCipher(std::move(zeroRttAead));
  }
  codec->setZeroRttHeaderCipher(test::createNoOpHeaderCipher());
  codec->setOneRttReadCipher(std::move(oneRttAead));
  codec->setOneRttHeaderCipher(test::createNoOpHeaderCipher());
  if (sourceToken) {
    codec->setStatelessResetToken(*sourceToken);
  }
  return codec;
}

TEST_F(QuicReadCodecTest, EmptyBuffer) {
  auto emptyQueue = bufToQueue(folly::IOBuf::create(0));
  AckStates ackStates;
  EXPECT_FALSE(
      parseSuccess(makeUnencryptedCodec()->parsePacket(emptyQueue, ackStates)));
}

TEST_F(QuicReadCodecTest, TooSmallBuffer) {
  auto smallBuffer = folly::IOBuf::create(1);
  smallBuffer->append(1);
  folly::io::RWPrivateCursor wcursor(smallBuffer.get());
  wcursor.writeBE<uint8_t>(0x01);
  AckStates ackStates;
  auto smallQueue = bufToQueue(std::move(smallBuffer));
  EXPECT_FALSE(
      parseSuccess(makeUnencryptedCodec()->parsePacket(smallQueue, ackStates)));
}

TEST_F(QuicReadCodecTest, VersionNegotiationPacketTest) {
  auto srcConnId = getTestConnectionId(0), destConnId = getTestConnectionId(1);
  std::vector<QuicVersion> versions(
      {static_cast<QuicVersion>(1),
       static_cast<QuicVersion>(2),
       static_cast<QuicVersion>(3),
       static_cast<QuicVersion>(4),
       static_cast<QuicVersion>(567),
       static_cast<QuicVersion>(76543),
       static_cast<QuicVersion>(0xffff)});
  VersionNegotiationPacketBuilder builder(srcConnId, destConnId, versions);
  auto packet = std::move(builder).buildPacket();
  auto packetQueue = bufToQueue(std::move(packet.second));
  auto versionNegotiationPacket =
      makeUnencryptedCodec()->tryParsingVersionNegotiation(packetQueue);
  ASSERT_TRUE(versionNegotiationPacket.has_value());
  EXPECT_EQ(versionNegotiationPacket->destinationConnectionId, destConnId);
  EXPECT_EQ(versionNegotiationPacket->sourceConnectionId, srcConnId);
  EXPECT_EQ(versionNegotiationPacket->versions, versions);
}

TEST_F(QuicReadCodecTest, RetryPacketTest) {
  uint8_t initialByte = 0xFF;
  ConnectionId srcConnId = getTestConnectionId(70);
  ConnectionId dstConnId = getTestConnectionId(90);
  auto quicVersion = static_cast<QuicVersion>(0xffff);
  std::string token = "fluffydog";
  std::string integrityTag = "MustBe16CharLong";

  Buf retryPacketEncoded = std::make_unique<folly::IOBuf>();
  BufAppender appender(retryPacketEncoded.get(), 100);

  appender.writeBE<uint8_t>(initialByte);
  appender.writeBE<QuicVersionType>(static_cast<QuicVersionType>(quicVersion));

  appender.writeBE<uint8_t>(dstConnId.size());
  appender.push(dstConnId.data(), dstConnId.size());
  appender.writeBE<uint8_t>(srcConnId.size());
  appender.push(srcConnId.data(), srcConnId.size());

  appender.push((const uint8_t*)token.data(), token.size());
  appender.push((const uint8_t*)integrityTag.data(), integrityTag.size());

  auto packetQueue = bufToQueue(std::move(retryPacketEncoded));

  AckStates ackStates;
  auto result = makeUnencryptedCodec()->parsePacket(packetQueue, ackStates);
  auto retryPacket = result.retryPacket();
  EXPECT_TRUE(retryPacket);

  auto headerOut = retryPacket->header;

  EXPECT_EQ(headerOut.getVersion(), static_cast<QuicVersion>(0xffff));
  EXPECT_EQ(headerOut.getSourceConnId(), srcConnId);
  EXPECT_EQ(headerOut.getDestinationConnId(), dstConnId);
  EXPECT_EQ(headerOut.getToken(), token);
}

TEST_F(QuicReadCodecTest, LongHeaderPacketLenMismatch) {
  LongHeader headerIn(
      LongHeader::Types::Initial,
      getTestConnectionId(70),
      getTestConnectionId(90),
      321,
      QuicVersion::MVFST,
      std::string("fluffydog"));

  RegularQuicPacketBuilder builder(
      kDefaultUDPSendPacketLen, std::move(headerIn), 0 /* largestAcked */);
  builder.encodePacketHeader();
  builder.accountForCipherOverhead(0);
  writeCryptoFrame(0, folly::IOBuf::copyBuffer("CHLO"), builder);
  auto packet = packetToBuf(std::move(builder).buildPacket());
  auto packetQueue = bufToQueue(std::move(packet));

  auto tmp = packetQueue.move();
  tmp->coalesce();
  tmp->trimEnd(1);
  packetQueue.append(std::move(tmp));

  AckStates ackStates;
  auto codec = makeUnencryptedCodec();
  codec->setInitialReadCipher(createNoOpAead());
  codec->setInitialHeaderCipher(test::createNoOpHeaderCipher());
  auto result = codec->parsePacket(packetQueue, ackStates);
  auto nothing = result.nothing();
  EXPECT_NE(nothing, nullptr);
}

TEST_F(QuicReadCodecTest, EmptyVersionNegotiationPacketTest) {
  auto srcConnId = getTestConnectionId(0), destConnId = getTestConnectionId(1);
  std::vector<QuicVersion> versions;
  VersionNegotiationPacketBuilder builder(srcConnId, destConnId, versions);
  auto packet = std::move(builder).buildPacket();
  AckStates ackStates;
  auto packetQueue = bufToQueue(std::move(packet.second));
  EXPECT_FALSE(parseSuccess(
      makeUnencryptedCodec()->parsePacket(packetQueue, ackStates)));
}

TEST_F(QuicReadCodecTest, StreamWithShortHeaderNoCipher) {
  auto connId = getTestConnectionId();
  PacketNum packetNum = 12321;
  StreamId streamId = 2;

  auto data = folly::IOBuf::copyBuffer("hello");
  auto streamPacket = createStreamPacket(
      connId,
      connId,
      packetNum,
      streamId,
      *data,
      0 /* cipherOverhead */,
      0 /* largestAcked */);

  AckStates ackStates;
  auto packetQueue = bufToQueue(packetToBuf(streamPacket));
  EXPECT_FALSE(parseSuccess(
      makeUnencryptedCodec()->parsePacket(packetQueue, ackStates)));
}

TEST_F(QuicReadCodecTest, StreamWithShortHeader) {
  auto connId = getTestConnectionId();
  PacketNum packetNum = 12321;
  StreamId streamId = 2;

  auto data = folly::IOBuf::copyBuffer("hello");
  auto streamPacket = createStreamPacket(
      connId,
      connId,
      packetNum,
      streamId,
      *data,
      0 /* cipherOverhead */,
      0 /* largestAcked */);
  AckStates ackStates;
  auto packetQueue = bufToQueue(packetToBuf(streamPacket));
  auto packet = makeEncryptedCodec(connId, createNoOpAead())
                    ->parsePacket(packetQueue, ackStates);
  EXPECT_TRUE(parseSuccess(std::move(packet)));
}

TEST_F(QuicReadCodecTest, StreamWithShortHeaderOnlyHeader) {
  auto connId = getTestConnectionId();
  PacketNum packetNum = 12321;

  ShortHeader header(ProtectionType::KeyPhaseZero, connId, packetNum);
  RegularQuicPacketBuilder builder(
      kDefaultUDPSendPacketLen, std::move(header), 0 /* largestAcked */);
  builder.encodePacketHeader();
  auto packetBuf = packetToBuf(std::move(builder).buildPacket());

  auto aead = std::make_unique<MockAead>();
  // The size is not large enough.
  EXPECT_CALL(*aead, _tryDecrypt(_, _, _)).Times(0);
  AckStates ackStates;
  auto packetQueue = bufToQueue(std::move(packetBuf));
  auto packet = makeEncryptedCodec(connId, std::move(aead))
                    ->parsePacket(packetQueue, ackStates);
  EXPECT_FALSE(parseSuccess(std::move(packet)));
}

TEST_F(QuicReadCodecTest, PacketDecryptFail) {
  auto connId = getTestConnectionId();
  PacketNum packetNum = 12321;
  StreamId streamId = 2;

  auto aead = std::make_unique<MockAead>();
  EXPECT_CALL(*aead, _tryDecrypt(_, _, _))
      .WillOnce(Invoke([](auto&, const auto, auto) { return folly::none; }));
  auto data = folly::IOBuf::copyBuffer("hello");
  auto streamPacket = createStreamPacket(
      connId,
      connId,
      packetNum,
      streamId,
      *data,
      0 /* cipherOverhead */,
      0 /* largestAcked */);

  AckStates ackStates;
  auto packetQueue = bufToQueue(packetToBuf(streamPacket));
  auto packet = makeEncryptedCodec(connId, std::move(aead))
                    ->parsePacket(packetQueue, ackStates);
  EXPECT_FALSE(parseSuccess(std::move(packet)));
}

TEST_F(QuicReadCodecTest, ShortOneRttPacketWithZeroRttCipher) {
  auto connId = getTestConnectionId();
  PacketNum packetNum = 12321;
  StreamId streamId = 2;

  auto data = folly::IOBuf::copyBuffer("hello");
  auto streamPacket = createStreamPacket(
      connId,
      connId,
      packetNum,
      streamId,
      *data,
      0 /* cipherOverhead */,
      0 /* largestAcked */);

  AckStates ackStates;
  auto packetQueue = bufToQueue(packetToBuf(streamPacket));
  auto packet = makeEncryptedCodec(connId, nullptr, createNoOpAead())
                    ->parsePacket(packetQueue, ackStates);
  EXPECT_FALSE(parseSuccess(std::move(packet)));
}

TEST_F(QuicReadCodecTest, ZeroRttPacketWithOneRttCipher) {
  auto connId = getTestConnectionId();
  PacketNum packetNum = 12321;
  StreamId streamId = 2;

  auto data = folly::IOBuf::copyBuffer("hello");
  auto streamPacket = createStreamPacket(
      connId,
      connId,
      packetNum,
      streamId,
      *data,
      0 /* cipherOverhead */,
      0 /* largestAcked */,
      std::make_pair(LongHeader::Types::ZeroRtt, QuicVersion::MVFST));

  AckStates ackStates;
  auto packetQueue = bufToQueue(packetToBuf(streamPacket));
  auto packet = makeEncryptedCodec(connId, createNoOpAead())
                    ->parsePacket(packetQueue, ackStates);
  EXPECT_FALSE(parseSuccess(std::move(packet)));
}

TEST_F(QuicReadCodecTest, ZeroRttPacketWithZeroRttCipher) {
  auto connId = getTestConnectionId();
  PacketNum packetNum = 12321;
  StreamId streamId = 2;

  auto data = folly::IOBuf::copyBuffer("hello");
  auto streamPacket = createStreamPacket(
      connId,
      connId,
      packetNum,
      streamId,
      *data,
      0 /* cipherOverhead */,
      0 /* largestAcked */,
      std::make_pair(LongHeader::Types::ZeroRtt, QuicVersion::MVFST));

  AckStates ackStates;
  auto packetQueue = bufToQueue(packetToBuf(streamPacket));
  auto packet = makeEncryptedCodec(connId, nullptr, createNoOpAead())
                    ->parsePacket(packetQueue, ackStates);
  EXPECT_TRUE(parseSuccess(std::move(packet)));
}

TEST_F(QuicReadCodecTest, KeyPhaseOnePacket) {
  auto connId = getTestConnectionId();
  PacketNum packetNum = 12321;
  StreamId streamId = 2;

  auto data = folly::IOBuf::copyBuffer("hello");
  auto streamPacket = createStreamPacket(
      connId,
      connId,
      packetNum,
      streamId,
      *data,
      0 /* cipherOverhead */,
      0 /* largestAcked */,
      folly::none,
      true,
      ProtectionType::KeyPhaseOne);
  AckStates ackStates;
  auto packetQueue = bufToQueue(packetToBuf(streamPacket));
  auto packet = makeEncryptedCodec(connId, createNoOpAead(), createNoOpAead())
                    ->parsePacket(packetQueue, ackStates);
  EXPECT_FALSE(parseSuccess(std::move(packet)));
}

TEST_F(QuicReadCodecTest, BadResetFirstTwoBits) {
  auto connId = getTestConnectionId();
  auto aead = std::make_unique<MockAead>();
  auto rawAead = aead.get();

  StatelessResetToken tok(
      {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16});
  auto fakeToken = std::make_unique<StatelessResetToken>(tok);
  auto codec = makeEncryptedCodec(
      connId,
      std::move(aead),
      nullptr /* 0-rtt aead */,
      std::move(fakeToken),
      QuicNodeType::Client);
  EXPECT_CALL(*rawAead, _tryDecrypt(_, _, _))
      .Times(AtMost(1))
      .WillRepeatedly(
          Invoke([](auto&, const auto&, auto) { return folly::none; }));
  PacketNum packetNum = 1;
  StreamId streamId = 2;
  auto data = folly::IOBuf::create(30);
  data->append(30);
  auto streamPacket = createStreamPacket(
      connId,
      connId,
      packetNum,
      streamId,
      *data,
      0 /* cipherOverhead */,
      0 /* largestAcked */,
      folly::none,
      true,
      ProtectionType::KeyPhaseZero);
  overridePacketWithToken(streamPacket, tok);
  uint8_t* packetHeaderBuffer = streamPacket.header.get()->writableData();
  while (*packetHeaderBuffer & 0x40) {
    uint8_t randomByte;
    folly::Random::secureRandom(&randomByte, 1);
    *packetHeaderBuffer =
        (*packetHeaderBuffer & 0b00111111) | (randomByte & 0b11000000);
  }
  AckStates ackStates;
  auto packetQueue = bufToQueue(packetToBuf(streamPacket));
  auto packet = codec->parsePacket(packetQueue, ackStates);
  EXPECT_FALSE(isReset(std::move(packet)));
}

TEST_F(QuicReadCodecTest, RandomizedShortHeaderLeadsToReset) {
  auto connId = getTestConnectionId();
  auto aead = std::make_unique<MockAead>();
  auto rawAead = aead.get();

  StatelessResetToken tok(
      {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16});
  auto fakeToken = std::make_unique<StatelessResetToken>(tok);
  auto codec = makeEncryptedCodec(
      connId,
      std::move(aead),
      nullptr /* 0-rtt aead */,
      std::move(fakeToken),
      QuicNodeType::Client);
  EXPECT_CALL(*rawAead, _tryDecrypt(_, _, _))
      .Times(AtMost(1))
      .WillRepeatedly(
          Invoke([](auto&, const auto&, auto) { return folly::none; }));
  PacketNum packetNum = 1;
  StreamId streamId = 2;
  auto data = folly::IOBuf::create(30);
  data->append(30);
  auto streamPacket = createStreamPacket(
      connId,
      connId,
      packetNum,
      streamId,
      *data,
      0 /* cipherOverhead */,
      0 /* largestAcked */,
      folly::none,
      true,
      ProtectionType::KeyPhaseZero);
  overridePacketWithToken(streamPacket, tok);
  uint8_t* packetHeaderBuffer = streamPacket.header.get()->writableData();
  uint8_t randomByte;
  folly::Random::secureRandom(&randomByte, 1);
  *packetHeaderBuffer = 0x40 | (randomByte & 0b00111111);
  AckStates ackStates;
  auto packetQueue = bufToQueue(packetToBuf(streamPacket));
  auto packet = codec->parsePacket(packetQueue, ackStates);
  EXPECT_TRUE(isReset(std::move(packet)));
}

TEST_F(QuicReadCodecTest, StatelessResetTokenMismatch) {
  auto connId = getTestConnectionId();
  auto aead = std::make_unique<MockAead>();
  auto rawAead = aead.get();

  StatelessResetToken tok(
      {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16});
  auto fakeToken = std::make_unique<StatelessResetToken>(tok);
  auto codec = makeEncryptedCodec(
      connId,
      std::move(aead),
      nullptr /* 0-rtt aead */,
      std::move(fakeToken),
      QuicNodeType::Client);
  EXPECT_CALL(*rawAead, _tryDecrypt(_, _, _))
      .Times(1)
      .WillOnce(Invoke([](auto&, const auto&, auto) { return folly::none; }));
  PacketNum packetNum = 1;
  StreamId streamId = 2;
  auto data = folly::IOBuf::create(30);
  data->append(30);
  auto streamPacket = createStreamPacket(
      connId,
      connId,
      packetNum,
      streamId,
      *data,
      0 /* cipherOverhead */,
      0 /* largestAcked */,
      folly::none,
      true,
      ProtectionType::KeyPhaseZero);
  tok[0] ^= tok[0];
  overridePacketWithToken(streamPacket, tok);
  AckStates ackStates;
  auto packetQueue = bufToQueue(packetToBuf(streamPacket));
  auto packet = codec->parsePacket(packetQueue, ackStates);
  EXPECT_FALSE(isReset(std::move(packet)));
}

TEST_F(QuicReadCodecTest, NoOneRttCipherNoReset) {
  auto connId = getTestConnectionId();
  auto aead = std::make_unique<MockAead>();
  StatelessResetToken tok(
      {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16});
  auto fakeToken = std::make_unique<StatelessResetToken>(tok);
  auto codec = makeEncryptedCodec(
      connId,
      nullptr /* 1-rtt aead */,
      nullptr /* 0-rtt aead */,
      std::move(fakeToken),
      QuicNodeType::Client);
  PacketNum packetNum = 1;
  StreamId streamId = 2;
  auto data = folly::IOBuf::create(30);
  data->append(30);
  auto streamPacket = createStreamPacket(
      connId,
      connId,
      packetNum,
      streamId,
      *data,
      0 /* cipherOverhead */,
      0 /* largestAcked */,
      folly::none,
      true,
      ProtectionType::KeyPhaseZero);
  overridePacketWithToken(streamPacket, tok);
  AckStates ackStates;
  auto packetQueue = bufToQueue(packetToBuf(streamPacket));
  auto packet = codec->parsePacket(packetQueue, ackStates);
  EXPECT_EQ(CodecResult::Type::CIPHER_UNAVAILABLE, packet.type());
  EXPECT_FALSE(isReset(std::move(packet)));
}

TEST_F(QuicReadCodecTest, FailToDecryptLeadsToReset) {
  auto connId = getTestConnectionId();
  auto aead = std::make_unique<MockAead>();
  auto rawAead = aead.get();

  StatelessResetToken tok(
      {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16});
  auto fakeToken = std::make_unique<StatelessResetToken>(tok);
  auto codec = makeEncryptedCodec(
      connId,
      std::move(aead),
      nullptr /* 0-rtt aead */,
      std::move(fakeToken),
      QuicNodeType::Client);
  EXPECT_CALL(*rawAead, _tryDecrypt(_, _, _))
      .Times(1)
      .WillOnce(Invoke([](auto&, const auto&, auto) { return folly::none; }));
  PacketNum packetNum = 1;
  StreamId streamId = 2;
  auto data = folly::IOBuf::create(30);
  data->append(30);
  auto streamPacket = createStreamPacket(
      connId,
      connId,
      packetNum,
      streamId,
      *data,
      0 /* cipherOverhead */,
      0 /* largestAcked */,
      folly::none,
      true,
      ProtectionType::KeyPhaseZero);
  overridePacketWithToken(streamPacket, tok);
  AckStates ackStates;
  auto packetQueue = bufToQueue(packetToBuf(streamPacket));
  auto packet = codec->parsePacket(packetQueue, ackStates);
  EXPECT_TRUE(isReset(std::move(packet)));
}

TEST_F(QuicReadCodecTest, ShortPacketAutoPaddedIsReset) {
  auto connId = getTestConnectionId();
  auto aead = std::make_unique<MockAead>();
  auto rawAead = aead.get();
  StatelessResetToken tok(
      {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16});
  auto fakeToken = std::make_unique<StatelessResetToken>(tok);
  auto codec = makeEncryptedCodec(
      connId,
      std::move(aead),
      nullptr /* 0-rtt aead */,
      std::move(fakeToken),
      QuicNodeType::Client);

  EXPECT_CALL(*rawAead, _tryDecrypt(_, _, _))
      .Times(1)
      .WillOnce(Invoke([](auto&, const auto&, auto) { return folly::none; }));
  PacketNum packetNum = 1;
  StreamId streamId = 2;
  auto data = folly::IOBuf::create(3);
  data->append(3);
  auto streamPacket = createStreamPacket(
      connId,
      connId,
      packetNum,
      streamId,
      *data,
      0 /* cipherOverhead */,
      0 /* largestAcked */,
      folly::none,
      true,
      ProtectionType::KeyPhaseZero);
  overridePacketWithToken(streamPacket, tok);
  AckStates ackStates;
  auto packetQueue = bufToQueue(packetToBuf(streamPacket));
  auto packet = codec->parsePacket(packetQueue, ackStates);
  EXPECT_TRUE(isReset(std::move(packet)));
}

TEST_F(QuicReadCodecTest, FailToDecryptLongHeaderNoReset) {
  auto connId = getTestConnectionId();
  auto aead = std::make_unique<MockAead>();
  auto rawAead = aead.get();

  StatelessResetToken tok(
      {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16});
  auto fakeToken = std::make_unique<StatelessResetToken>(tok);
  auto codec = makeEncryptedCodec(
      connId,
      nullptr /* 1-rtt aead */,
      std::move(aead) /* 0-rtt aead */,
      std::move(fakeToken),
      QuicNodeType::Server);

  EXPECT_CALL(*rawAead, _tryDecrypt(_, _, _))
      .Times(1)
      .WillOnce(Invoke([](auto&, const auto&, auto) { return folly::none; }));
  PacketNum packetNum = 1;
  StreamId streamId = 2;
  auto data = folly::IOBuf::create(30);
  data->append(30);
  auto streamPacket = createStreamPacket(
      connId,
      connId,
      packetNum,
      streamId,
      *data,
      0 /* cipherOverhead */,
      0 /* largestAcked */,
      std::make_pair(LongHeader::Types::ZeroRtt, QuicVersion::MVFST));
  overridePacketWithToken(streamPacket, tok);
  AckStates ackStates;
  auto packetQueue = bufToQueue(packetToBuf(streamPacket));
  auto packet = codec->parsePacket(packetQueue, ackStates);
  EXPECT_FALSE(isReset(std::move(packet)));
}

TEST_F(QuicReadCodecTest, FailToDecryptNoTokenNoReset) {
  auto connId = getTestConnectionId();
  auto aead = std::make_unique<MockAead>();
  auto rawAead = aead.get();

  auto codec = makeEncryptedCodec(
      connId,
      std::move(aead),
      nullptr /* 0-rtt zead */,
      nullptr /* stateless reset token*/,
      QuicNodeType::Client);

  EXPECT_CALL(*rawAead, _tryDecrypt(_, _, _))
      .Times(1)
      .WillOnce(Invoke([](auto&, const auto&, auto) { return folly::none; }));
  PacketNum packetNum = 1;
  StreamId streamId = 2;
  auto data = folly::IOBuf::create(30);
  data->append(30);
  auto streamPacket = createStreamPacket(
      connId,
      connId,
      packetNum,
      streamId,
      *data,
      0 /* cipherOverhead */,
      0 /* largestAcked */,
      folly::none,
      true,
      ProtectionType::KeyPhaseZero);
  AckStates ackStates;
  auto packetQueue = bufToQueue(packetToBuf(streamPacket));
  auto packet = codec->parsePacket(packetQueue, ackStates);
  EXPECT_FALSE(isReset(std::move(packet)));
}

TEST_F(QuicReadCodecTest, TestInitialPacket) {
  auto connId = getTestConnectionId();

  FizzCryptoFactory cryptoFactory;
  PacketNum packetNum = 1;
  uint64_t offset = 0;
  auto aead = cryptoFactory.getClientInitialCipher(connId, QuicVersion::MVFST);
  auto headerCipher =
      cryptoFactory.makeClientInitialHeaderCipher(connId, QuicVersion::MVFST);
  auto packet = createInitialCryptoPacket(
      getTestConnectionId(),
      connId,
      packetNum,
      QuicVersion::MVFST,
      *folly::IOBuf::copyBuffer("CHLO"),
      *aead,
      offset);

  auto codec = makeEncryptedCodec(connId, std::move(aead), nullptr);
  aead = cryptoFactory.getClientInitialCipher(connId, QuicVersion::MVFST);
  AckStates ackStates;
  auto packetQueue =
      bufToQueue(packetToBufCleartext(packet, *aead, *headerCipher, packetNum));
  auto res = codec->parsePacket(packetQueue, ackStates);

  auto regularQuicPacket = res.regularPacket();
  ASSERT_NE(regularQuicPacket, nullptr);

  EXPECT_NE(regularQuicPacket->header.asLong(), nullptr);
  auto longPacketHeader = regularQuicPacket->header.asLong();

  EXPECT_FALSE(longPacketHeader->hasToken());
}

TEST_F(QuicReadCodecTest, TestInitialPacketExtractToken) {
  auto connId = getTestConnectionId();

  FizzCryptoFactory cryptoFactory;
  PacketNum packetNum = 1;
  uint64_t offset = 0;
  auto aead = cryptoFactory.getClientInitialCipher(connId, QuicVersion::MVFST);
  auto headerCipher =
      cryptoFactory.makeClientInitialHeaderCipher(connId, QuicVersion::MVFST);
  std::string token = "aswerdfewdewrgetg";
  auto packet = createInitialCryptoPacket(
      getTestConnectionId(),
      connId,
      packetNum,
      QuicVersion::MVFST,
      *folly::IOBuf::copyBuffer("CHLO"),
      *aead,
      offset,
      0 /* offset */,
      token);

  auto codec = makeEncryptedCodec(connId, std::move(aead), nullptr);
  aead = cryptoFactory.getClientInitialCipher(connId, QuicVersion::MVFST);
  auto packetQueue =
      bufToQueue(packetToBufCleartext(packet, *aead, *headerCipher, packetNum));

  folly::io::Cursor cursor(packetQueue.front());
  auto res = tryParseLongHeader(cursor, QuicNodeType::Client);
  EXPECT_FALSE(res.hasError());
  auto parsedLongHeader = std::move(res.value());
  EXPECT_EQ(parsedLongHeader.header.getDestinationConnId(), connId);
  EXPECT_TRUE(parsedLongHeader.header.hasToken());
  EXPECT_EQ(parsedLongHeader.header.getToken(), token);
}

TEST_F(QuicReadCodecTest, TestHandshakeDone) {
  auto connId = getTestConnectionId();

  FizzCryptoFactory cryptoFactory;
  PacketNum packetNum = 1;
  uint64_t offset = 0;
  auto aead = cryptoFactory.getClientInitialCipher(connId, QuicVersion::MVFST);
  auto headerCipher =
      cryptoFactory.makeClientInitialHeaderCipher(connId, QuicVersion::MVFST);
  auto packet = createInitialCryptoPacket(
      getTestConnectionId(),
      connId,
      packetNum,
      QuicVersion::MVFST,
      *folly::IOBuf::copyBuffer("CHLO"),
      *aead,
      offset);

  auto codec = makeEncryptedCodec(connId, std::move(aead), nullptr);
  aead = cryptoFactory.getClientInitialCipher(connId, QuicVersion::MVFST);
  AckStates ackStates;
  auto packetQueue =
      bufToQueue(packetToBufCleartext(packet, *aead, *headerCipher, packetNum));
  EXPECT_TRUE(parseSuccess(codec->parsePacket(packetQueue, ackStates)));
  codec->onHandshakeDone(Clock::now());
  EXPECT_FALSE(parseSuccess(codec->parsePacket(packetQueue, ackStates)));
}

TEST_F(QuicReadCodecTest, TestZeroRttPacketsImmediatelyAfterHandshakeDone) {
  auto connId = getTestConnectionId();
  PacketNum packetNum = 12321;
  StreamId streamId = 2;

  auto data = folly::IOBuf::copyBuffer("hello");
  auto streamPacket = createStreamPacket(
      connId,
      connId,
      packetNum,
      streamId,
      *data,
      0 /* cipherOverhead */,
      0 /* largestAcked */,
      std::make_pair(LongHeader::Types::ZeroRtt, QuicVersion::MVFST));

  auto codec = makeEncryptedCodec(connId, nullptr, createNoOpAead());
  AckStates ackStates;
  auto packetQueue = bufToQueue(packetToBuf(streamPacket));
  EXPECT_TRUE(parseSuccess(codec->parsePacket(packetQueue, ackStates)));
  codec->onHandshakeDone(Clock::now());
  packetQueue = bufToQueue(packetToBuf(streamPacket));
  EXPECT_TRUE(parseSuccess(codec->parsePacket(packetQueue, ackStates)));
}

TEST_F(QuicReadCodecTest, TestZeroRttPacketsAfterHandshakeDone) {
  auto connId = getTestConnectionId();
  PacketNum packetNum = 12321;
  StreamId streamId = 2;

  auto data = folly::IOBuf::copyBuffer("hello");
  auto streamPacket = createStreamPacket(
      connId,
      connId,
      packetNum,
      streamId,
      *data,
      0 /* cipherOverhead */,
      0 /* largestAcked */,
      std::make_pair(LongHeader::Types::ZeroRtt, QuicVersion::MVFST));

  auto codec = makeEncryptedCodec(connId, nullptr, createNoOpAead());
  AckStates ackStates;
  auto packetQueue = bufToQueue(packetToBuf(streamPacket));
  EXPECT_TRUE(parseSuccess(codec->parsePacket(packetQueue, ackStates)));
  codec->onHandshakeDone(Clock::now() - kTimeToRetainZeroRttKeys * 2);
  EXPECT_FALSE(parseSuccess(codec->parsePacket(packetQueue, ackStates)));
}
