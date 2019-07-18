/*
 * Copyright (c) Facebook, Inc. and its affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 *
 */

#include <quic/codec/QuicReadCodec.h>
#include <folly/io/Cursor.h>
#include <folly/portability/GTest.h>
#include <quic/QuicException.h>
#include <quic/common/test/TestUtils.h>

using namespace quic;
using namespace quic::test;
using namespace testing;

bool parseSuccess(const CodecResult& result) {
  return folly::variant_match(
      result,
      [&](const QuicPacket&) { return true; },
      [&](auto&) { return false; });
}

bool isReset(const CodecResult& result) {
  return folly::variant_match(
      result,
      [](const StatelessReset&) { return true; },
      [](const auto&) { return false; });
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
    std::unique_ptr<StatelessResetToken> sourceToken = nullptr) {
  QuicFizzFactory fizzFactory;
  auto codec = std::make_unique<QuicReadCodec>(QuicNodeType::Server);
  codec->setClientConnectionId(clientConnId);
  codec->setInitialReadCipher(
      getClientInitialCipher(&fizzFactory, clientConnId, QuicVersion::MVFST));
  codec->setInitialHeaderCipher(makeClientInitialHeaderCipher(
      &fizzFactory, clientConnId, QuicVersion::MVFST));
  codec->setZeroRttReadCipher(std::move(zeroRttAead));
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
  std::vector<QuicVersion> versions({static_cast<QuicVersion>(1),
                                     static_cast<QuicVersion>(2),
                                     static_cast<QuicVersion>(3),
                                     static_cast<QuicVersion>(4),
                                     static_cast<QuicVersion>(567),
                                     static_cast<QuicVersion>(76543),
                                     static_cast<QuicVersion>(0xffff)});
  VersionNegotiationPacketBuilder builder(srcConnId, destConnId, versions);
  auto packet = std::move(builder).buildPacket();
  AckStates ackStates;
  auto packetQueue = bufToQueue(std::move(packet.second));
  auto versionNegotiationPacket =
      boost::get<VersionNegotiationPacket>(boost::get<QuicPacket>(
          makeUnencryptedCodec()->parsePacket(packetQueue, ackStates)));
  EXPECT_EQ(versionNegotiationPacket.destinationConnectionId, destConnId);
  EXPECT_EQ(versionNegotiationPacket.sourceConnectionId, srcConnId);
  EXPECT_EQ(versionNegotiationPacket.versions, versions);
}

TEST_F(QuicReadCodecTest, RetryPacketTest) {
  LongHeader headerIn(
      LongHeader::Types::Retry,
      getTestConnectionId(70),
      getTestConnectionId(90),
      321,
      static_cast<QuicVersion>(0xffff),
      folly::IOBuf::copyBuffer("fluffydog"),
      getTestConnectionId(110));

  RegularQuicPacketBuilder builder(
      kDefaultUDPSendPacketLen, std::move(headerIn), 0 /* largestAcked */);
  auto packet = packetToBuf(std::move(builder).buildPacket());
  auto packetQueue = bufToQueue(std::move(packet));

  AckStates ackStates;
  auto retryPacket = boost::get<RegularQuicPacket>(boost::get<QuicPacket>(
      makeUnencryptedCodec()->parsePacket(packetQueue, ackStates)));

  auto headerOut = boost::get<LongHeader>(retryPacket.header);

  EXPECT_EQ(*headerOut.getOriginalDstConnId(), getTestConnectionId(110));
  EXPECT_EQ(headerOut.getVersion(), static_cast<QuicVersion>(0xffff));
  EXPECT_EQ(headerOut.getSourceConnId(), getTestConnectionId(70));
  EXPECT_EQ(headerOut.getDestinationConnId(), getTestConnectionId(90));

  folly::IOBufEqualTo eq;
  auto expectedBuf = folly::IOBuf::copyBuffer("fluffydog");
  EXPECT_TRUE(eq(*headerOut.getToken(), *expectedBuf));
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
  EXPECT_TRUE(parseSuccess(packet));
}

TEST_F(QuicReadCodecTest, StreamWithShortHeaderOnlyHeader) {
  auto connId = getTestConnectionId();
  PacketNum packetNum = 12321;

  ShortHeader header(ProtectionType::KeyPhaseZero, connId, packetNum);
  RegularQuicPacketBuilder builder(
      kDefaultUDPSendPacketLen, std::move(header), 0 /* largestAcked */);
  auto packetBuf = packetToBuf(std::move(builder).buildPacket());

  auto aead = std::make_unique<MockAead>();
  // The size is not large enough.
  EXPECT_CALL(*aead, _tryDecrypt(_, _, _)).Times(0);
  AckStates ackStates;
  auto packetQueue = bufToQueue(std::move(packetBuf));
  auto packet = makeEncryptedCodec(connId, std::move(aead))
                    ->parsePacket(packetQueue, ackStates);
  EXPECT_FALSE(parseSuccess(packet));
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
  EXPECT_FALSE(parseSuccess(packet));
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
  EXPECT_FALSE(parseSuccess(packet));
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
  EXPECT_FALSE(parseSuccess(packet));
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
  EXPECT_TRUE(parseSuccess(packet));
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
  EXPECT_FALSE(parseSuccess(packet));
}

TEST_F(QuicReadCodecTest, FailToDecryptLeadsToReset) {
  auto connId = getTestConnectionId();
  auto aead = std::make_unique<MockAead>();
  auto rawAead = aead.get();

  StatelessResetToken tok(
      {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16});
  auto fakeToken = std::make_unique<StatelessResetToken>(tok);
  auto codec = makeEncryptedCodec(
      connId, std::move(aead), nullptr, std::move(fakeToken));
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
  EXPECT_TRUE(isReset(packet));
}

TEST_F(QuicReadCodecTest, ShortPacketAutoPaddedIsReset) {
  auto connId = getTestConnectionId();
  auto aead = std::make_unique<MockAead>();
  auto rawAead = aead.get();
  StatelessResetToken tok(
      {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16});
  auto fakeToken = std::make_unique<StatelessResetToken>(tok);
  auto codec = makeEncryptedCodec(
      connId, std::move(aead), nullptr, std::move(fakeToken));

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
  AckStates ackStates;
  auto packetQueue = bufToQueue(packetToBuf(streamPacket));
  auto packet = codec->parsePacket(packetQueue, ackStates);
  EXPECT_TRUE(isReset(packet));
}

TEST_F(QuicReadCodecTest, FailToDecryptLongHeaderNoReset) {
  auto connId = getTestConnectionId();
  auto aead = std::make_unique<MockAead>();
  auto rawAead = aead.get();

  StatelessResetToken tok(
      {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16});
  auto fakeToken = std::make_unique<StatelessResetToken>(tok);
  auto codec = makeEncryptedCodec(
      connId, nullptr, std::move(aead), std::move(fakeToken));

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
  AckStates ackStates;
  auto packetQueue = bufToQueue(packetToBuf(streamPacket));
  auto packet = codec->parsePacket(packetQueue, ackStates);
  EXPECT_FALSE(isReset(packet));
}

TEST_F(QuicReadCodecTest, FailToDecryptNoTokenNoReset) {
  auto connId = getTestConnectionId();
  auto aead = std::make_unique<MockAead>();
  auto rawAead = aead.get();

  auto codec = makeEncryptedCodec(connId, std::move(aead), nullptr);

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
  EXPECT_FALSE(isReset(packet));
}

TEST_F(QuicReadCodecTest, TestInitialPacket) {
  auto connId = getTestConnectionId();

  QuicFizzFactory fizzFactory;
  PacketNum packetNum = 1;
  uint64_t offset = 0;
  auto aead = getClientInitialCipher(&fizzFactory, connId, QuicVersion::MVFST);
  auto headerCipher =
      makeClientInitialHeaderCipher(&fizzFactory, connId, QuicVersion::MVFST);
  auto packet = createInitialCryptoPacket(
      getTestConnectionId(),
      connId,
      packetNum,
      QuicVersion::MVFST,
      *folly::IOBuf::copyBuffer("CHLO"),
      *aead,
      offset);

  auto codec = makeEncryptedCodec(connId, std::move(aead), nullptr);
  aead = getClientInitialCipher(&fizzFactory, connId, QuicVersion::MVFST);
  AckStates ackStates;
  auto packetQueue =
      bufToQueue(packetToBufCleartext(packet, *aead, *headerCipher, packetNum));
  auto res = codec->parsePacket(packetQueue, ackStates);

  EXPECT_NO_THROW(boost::get<QuicPacket>(res));
  auto quicPacket = boost::get<QuicPacket>(res);

  EXPECT_NO_THROW(boost::get<RegularQuicPacket>(quicPacket));
  auto regularQuicPacket = boost::get<RegularQuicPacket>(quicPacket);

  EXPECT_NO_THROW(boost::get<LongHeader>(regularQuicPacket.header));
  auto longPacketHeader = boost::get<LongHeader>(regularQuicPacket.header);

  EXPECT_FALSE(longPacketHeader.hasToken());
}

TEST_F(QuicReadCodecTest, TestHandshakeDone) {
  auto connId = getTestConnectionId();

  QuicFizzFactory fizzFactory;
  PacketNum packetNum = 1;
  uint64_t offset = 0;
  auto aead = getClientInitialCipher(&fizzFactory, connId, QuicVersion::MVFST);
  auto headerCipher =
      makeClientInitialHeaderCipher(&fizzFactory, connId, QuicVersion::MVFST);
  auto packet = createInitialCryptoPacket(
      getTestConnectionId(),
      connId,
      packetNum,
      QuicVersion::MVFST,
      *folly::IOBuf::copyBuffer("CHLO"),
      *aead,
      offset);

  auto codec = makeEncryptedCodec(connId, std::move(aead), nullptr);
  aead = getClientInitialCipher(&fizzFactory, connId, QuicVersion::MVFST);
  AckStates ackStates;
  auto packetQueue =
      bufToQueue(packetToBufCleartext(packet, *aead, *headerCipher, packetNum));
  EXPECT_TRUE(parseSuccess(codec->parsePacket(packetQueue, ackStates)));
  codec->onHandshakeDone(Clock::now() - kTimeToRetainInitialKeys * 2);
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
