/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <folly/portability/GTest.h>

#include <folly/Random.h>
#include <folly/io/Cursor.h>
#include <quic/codec/QuicConnectionId.h>
#include <quic/codec/QuicPacketBuilder.h>
#include <quic/codec/QuicReadCodec.h>
#include <quic/codec/Types.h>
#include <quic/codec/test/Mocks.h>
#include <quic/common/test/TestUtils.h>
#include <quic/fizz/handshake/FizzCryptoFactory.h>
#include <quic/fizz/handshake/FizzRetryIntegrityTagGenerator.h>
#include <quic/handshake/HandshakeLayer.h>

using namespace quic;
using namespace quic::test;
using namespace testing;

enum TestFlavor { Regular, Inplace };

Buf packetToBuf(
    RegularQuicPacketBuilder::Packet& packet,
    Aead* aead = nullptr) {
  auto buf = folly::IOBuf::create(0);
  // This does not matter.
  PacketNum num = 10;
  if (packet.header) {
    buf->prependChain(packet.header->clone());
  }
  std::unique_ptr<folly::IOBuf> body = folly::IOBuf::create(0);
  if (packet.body) {
    body = packet.body->clone();
  }
  if (aead && packet.header) {
    auto bodySize = body->computeChainDataLength();
    body = aead->inplaceEncrypt(std::move(body), packet.header.get(), num);
    EXPECT_GT(body->computeChainDataLength(), bodySize);
  }
  if (body) {
    buf->prependChain(std::move(body));
  }
  return buf;
}

size_t longHeaderLength = sizeof(uint32_t) + sizeof(uint32_t) +
    kDefaultConnectionIdSize + sizeof(uint8_t);

constexpr size_t kVersionNegotiationHeaderSize =
    sizeof(uint8_t) + kDefaultConnectionIdSize * 2 + sizeof(QuicVersion);

std::unique_ptr<QuicReadCodec> makeCodec(
    ConnectionId clientConnId,
    QuicNodeType nodeType,
    std::unique_ptr<Aead> zeroRttCipher = nullptr,
    std::unique_ptr<Aead> oneRttCipher = nullptr,
    QuicVersion version = QuicVersion::MVFST) {
  FizzCryptoFactory cryptoFactory;
  auto codec = std::make_unique<QuicReadCodec>(nodeType);
  if (nodeType != QuicNodeType::Client) {
    codec->setZeroRttReadCipher(std::move(zeroRttCipher));
    codec->setZeroRttHeaderCipher(test::createNoOpHeaderCipher());
  }
  codec->setOneRttReadCipher(std::move(oneRttCipher));
  codec->setOneRttHeaderCipher(test::createNoOpHeaderCipher());
  codec->setHandshakeReadCipher(test::createNoOpAead());
  codec->setHandshakeHeaderCipher(test::createNoOpHeaderCipher());
  codec->setClientConnectionId(clientConnId);
  if (nodeType == QuicNodeType::Client) {
    codec->setInitialReadCipher(
        cryptoFactory.getServerInitialCipher(clientConnId, version));
    codec->setInitialHeaderCipher(
        cryptoFactory.makeServerInitialHeaderCipher(clientConnId, version));
  } else {
    codec->setInitialReadCipher(
        cryptoFactory.getClientInitialCipher(clientConnId, version));
    codec->setInitialHeaderCipher(
        cryptoFactory.makeClientInitialHeaderCipher(clientConnId, version));
  }
  return codec;
}

class QuicPacketBuilderTest : public TestWithParam<TestFlavor> {
 protected:
  std::unique_ptr<PacketBuilderInterface> testBuilderProvider(
      TestFlavor flavor,
      uint32_t pktSizeLimit,
      PacketHeader header,
      PacketNum largestAckedPacketNum,
      folly::Optional<size_t> outputBufSize) {
    switch (flavor) {
      case TestFlavor::Regular:
        return std::make_unique<RegularQuicPacketBuilder>(
            pktSizeLimit, std::move(header), largestAckedPacketNum);
      case TestFlavor::Inplace:
        CHECK(outputBufSize);
        simpleBufAccessor_ =
            std::make_unique<SimpleBufAccessor>(*outputBufSize);
        return std::make_unique<InplaceQuicPacketBuilder>(
            *simpleBufAccessor_,
            pktSizeLimit,
            std::move(header),
            largestAckedPacketNum);
    }
    folly::assume_unreachable();
  }

 protected:
  std::unique_ptr<BufAccessor> simpleBufAccessor_;
};

TEST_F(QuicPacketBuilderTest, SimpleVersionNegotiationPacket) {
  auto versions = versionList({1, 2, 3, 4, 5, 6, 7});

  auto srcConnId = getTestConnectionId(0), destConnId = getTestConnectionId(1);
  VersionNegotiationPacketBuilder builder(srcConnId, destConnId, versions);
  EXPECT_TRUE(builder.canBuildPacket());
  auto builtOut = std::move(builder).buildPacket();
  auto resultVersionNegotiationPacket = builtOut.first;

  // Verify the returned packet from packet builder:
  EXPECT_EQ(resultVersionNegotiationPacket.versions, versions);
  EXPECT_EQ(resultVersionNegotiationPacket.sourceConnectionId, srcConnId);
  EXPECT_EQ(resultVersionNegotiationPacket.destinationConnectionId, destConnId);

  // Verify the returned buf from packet builder can be decoded by read codec:
  auto packetQueue = bufToQueue(std::move(builtOut.second));
  auto decodedVersionNegotiationPacket =
      makeCodec(destConnId, QuicNodeType::Client)
          ->tryParsingVersionNegotiation(packetQueue);
  ASSERT_TRUE(decodedVersionNegotiationPacket.has_value());
  EXPECT_EQ(decodedVersionNegotiationPacket->sourceConnectionId, srcConnId);
  EXPECT_EQ(
      decodedVersionNegotiationPacket->destinationConnectionId, destConnId);
  EXPECT_EQ(decodedVersionNegotiationPacket->versions, versions);
}

TEST_F(QuicPacketBuilderTest, TooManyVersions) {
  std::vector<QuicVersion> versions;
  for (size_t i = 0; i < 1000; i++) {
    versions.push_back(static_cast<QuicVersion>(i));
  }
  auto srcConnId = getTestConnectionId(0), destConnId = getTestConnectionId(1);
  size_t expectedVersionsToWrite =
      (kDefaultUDPSendPacketLen - kVersionNegotiationHeaderSize) /
      sizeof(QuicVersion);
  std::vector<QuicVersion> expectedWrittenVersions;
  for (size_t i = 0; i < expectedVersionsToWrite; i++) {
    expectedWrittenVersions.push_back(static_cast<QuicVersion>(i));
  }
  VersionNegotiationPacketBuilder builder(srcConnId, destConnId, versions);
  EXPECT_LE(builder.remainingSpaceInPkt(), sizeof(QuicVersion));
  EXPECT_TRUE(builder.canBuildPacket());
  auto builtOut = std::move(builder).buildPacket();
  auto resultVersionNegotiationPacket = builtOut.first;
  auto resultBuf = std::move(builtOut.second);
  EXPECT_EQ(
      expectedVersionsToWrite, resultVersionNegotiationPacket.versions.size());
  EXPECT_EQ(resultVersionNegotiationPacket.versions, expectedWrittenVersions);
  EXPECT_EQ(resultVersionNegotiationPacket.sourceConnectionId, srcConnId);
  EXPECT_EQ(resultVersionNegotiationPacket.destinationConnectionId, destConnId);

  AckStates ackStates;
  auto packetQueue = bufToQueue(std::move(resultBuf));
  auto decodedPacket = makeCodec(destConnId, QuicNodeType::Client)
                           ->tryParsingVersionNegotiation(packetQueue);
  ASSERT_TRUE(decodedPacket.has_value());
  EXPECT_EQ(decodedPacket->destinationConnectionId, destConnId);
  EXPECT_EQ(decodedPacket->sourceConnectionId, srcConnId);
  EXPECT_EQ(decodedPacket->versions, expectedWrittenVersions);
}

TEST_P(QuicPacketBuilderTest, LongHeaderRegularPacket) {
  ConnectionId clientConnId = getTestConnectionId(),
               serverConnId = ConnectionId({1, 3, 5, 7});
  PacketNum pktNum = 444;
  QuicVersion ver = QuicVersion::MVFST;
  // create a server cleartext write codec.
  FizzCryptoFactory cryptoFactory;
  auto cleartextAead = cryptoFactory.getClientInitialCipher(serverConnId, ver);
  auto headerCipher =
      cryptoFactory.makeClientInitialHeaderCipher(serverConnId, ver);

  std::unique_ptr<PacketBuilderInterface> builderOwner;
  auto builderProvider = [&](PacketHeader header, PacketNum largestAcked) {
    auto builder = testBuilderProvider(
        GetParam(),
        kDefaultUDPSendPacketLen,
        std::move(header),
        largestAcked,
        kDefaultUDPSendPacketLen * 2);
    auto rawBuilder = builder.get();
    builderOwner = std::move(builder);
    return rawBuilder;
  };

  auto resultRegularPacket = createInitialCryptoPacket(
      serverConnId,
      clientConnId,
      pktNum,
      ver,
      *folly::IOBuf::copyBuffer("CHLO"),
      *cleartextAead,
      0 /* largestAcked */,
      0 /* offset */,
      "" /* token */,
      builderProvider);
  auto resultBuf = packetToBufCleartext(
      resultRegularPacket, *cleartextAead, *headerCipher, pktNum);
  auto& resultHeader = resultRegularPacket.packet.header;
  EXPECT_NE(resultHeader.asLong(), nullptr);
  auto& resultLongHeader = *resultHeader.asLong();
  EXPECT_EQ(LongHeader::Types::Initial, resultLongHeader.getHeaderType());
  EXPECT_EQ(serverConnId, resultLongHeader.getSourceConnId());
  EXPECT_EQ(pktNum, resultLongHeader.getPacketSequenceNum());
  EXPECT_EQ(ver, resultLongHeader.getVersion());

  AckStates ackStates;
  auto packetQueue = bufToQueue(std::move(resultBuf));
  auto optionalDecodedPacket = makeCodec(serverConnId, QuicNodeType::Server)
                                   ->parsePacket(packetQueue, ackStates);
  ASSERT_NE(optionalDecodedPacket.regularPacket(), nullptr);
  auto& decodedRegularPacket = *optionalDecodedPacket.regularPacket();
  auto& decodedHeader = *decodedRegularPacket.header.asLong();
  EXPECT_EQ(LongHeader::Types::Initial, decodedHeader.getHeaderType());
  EXPECT_EQ(clientConnId, decodedHeader.getDestinationConnId());
  EXPECT_EQ(pktNum, decodedHeader.getPacketSequenceNum());
  EXPECT_EQ(ver, decodedHeader.getVersion());
}

TEST_P(QuicPacketBuilderTest, ShortHeaderRegularPacket) {
  auto connId = getTestConnectionId();
  PacketNum pktNum = 222;

  PacketNum largestAckedPacketNum = 0;
  auto encodedPacketNum = encodePacketNumber(pktNum, largestAckedPacketNum);
  auto builder = testBuilderProvider(
      GetParam(),
      kDefaultUDPSendPacketLen,
      ShortHeader(ProtectionType::KeyPhaseZero, connId, pktNum),
      largestAckedPacketNum,
      2000);
  builder->encodePacketHeader();

  // write out at least one frame
  writeFrame(PaddingFrame(), *builder);
  EXPECT_TRUE(builder->canBuildPacket());
  auto builtOut = std::move(*builder).buildPacket();
  auto resultRegularPacket = builtOut.packet;

  size_t expectedOutputSize =
      sizeof(Sample) + kMaxPacketNumEncodingSize - encodedPacketNum.length;
  // We wrote less than sample bytes into the packet, so we'll pad it to sample
  EXPECT_EQ(builtOut.body->computeChainDataLength(), expectedOutputSize);
  auto resultBuf = packetToBuf(builtOut);

  auto& resultShortHeader = *resultRegularPacket.header.asShort();
  EXPECT_EQ(
      ProtectionType::KeyPhaseZero, resultShortHeader.getProtectionType());
  EXPECT_EQ(connId, resultShortHeader.getConnectionId());
  EXPECT_EQ(pktNum, resultShortHeader.getPacketSequenceNum());

  // TODO: change this when we start encoding packet numbers.
  AckStates ackStates;
  auto packetQueue = bufToQueue(std::move(resultBuf));
  auto parsedPacket =
      makeCodec(
          connId, QuicNodeType::Client, nullptr, quic::test::createNoOpAead())
          ->parsePacket(packetQueue, ackStates);
  auto& decodedRegularPacket = *parsedPacket.regularPacket();
  auto& decodedHeader = *decodedRegularPacket.header.asShort();
  EXPECT_EQ(ProtectionType::KeyPhaseZero, decodedHeader.getProtectionType());
  EXPECT_EQ(connId, decodedHeader.getConnectionId());
  EXPECT_EQ(pktNum, decodedHeader.getPacketSequenceNum());
}

TEST_P(QuicPacketBuilderTest, EnforcePacketSizeWithCipherOverhead) {
  auto connId = getTestConnectionId();
  PacketNum pktNum = 222;

  PacketNum largestAckedPacketNum = 0;
  size_t cipherOverhead = 2;
  uint64_t enforcedSize = 1400;
  auto aead = std::make_unique<NiceMock<MockAead>>();
  auto aead_ = aead.get();
  EXPECT_CALL(*aead_, _inplaceEncrypt(_, _, _))
      .WillRepeatedly(Invoke([&](auto& buf, auto, auto) {
        auto overhead = folly::IOBuf::create(1000);
        overhead->append(cipherOverhead);
        auto clone = buf->clone();
        clone->prependChain(std::move(overhead));
        return std::move(clone);
      }));

  auto builder = testBuilderProvider(
      GetParam(),
      kDefaultUDPSendPacketLen,
      ShortHeader(ProtectionType::KeyPhaseZero, connId, pktNum),
      largestAckedPacketNum,
      2000);
  builder->accountForCipherOverhead(cipherOverhead);
  builder->encodePacketHeader();

  // write out at least one frame
  writeFrame(PaddingFrame(), *builder);
  EXPECT_TRUE(builder->canBuildPacket());
  auto builtOut = std::move(*builder).buildPacket();

  auto param = GetParam();
  if (param == TestFlavor::Regular) {
    EXPECT_EQ(builtOut.body->isManagedOne(), true);
    RegularSizeEnforcedPacketBuilder sizeEnforcedBuilder(
        std::move(builtOut), enforcedSize, cipherOverhead);
    EXPECT_TRUE(sizeEnforcedBuilder.canBuildPacket());
    auto out = std::move(sizeEnforcedBuilder).buildPacket();
    EXPECT_EQ(
        out.header->computeChainDataLength() +
            out.body->computeChainDataLength(),
        enforcedSize - cipherOverhead);
    auto buf = packetToBuf(out, aead_);
    EXPECT_EQ(buf->computeChainDataLength(), enforcedSize);

  } else {
    EXPECT_EQ(builtOut.body->isManagedOne(), false);
    InplaceSizeEnforcedPacketBuilder sizeEnforcedBuilder(
        *simpleBufAccessor_, std::move(builtOut), enforcedSize, cipherOverhead);
    EXPECT_TRUE(sizeEnforcedBuilder.canBuildPacket());
    auto out = std::move(sizeEnforcedBuilder).buildPacket();
    EXPECT_EQ(
        out.header->computeChainDataLength() +
            out.body->computeChainDataLength(),
        enforcedSize - cipherOverhead);
    auto buf = packetToBuf(out, aead_);
    EXPECT_EQ(buf->computeChainDataLength(), enforcedSize);
  }
}

TEST_P(QuicPacketBuilderTest, ShortHeaderWithNoFrames) {
  auto connId = getTestConnectionId();
  PacketNum pktNum = 222;

  // We expect that the builder will not add new frames to a packet which has no
  // frames already and will be too small to parse.
  auto builder = testBuilderProvider(
      GetParam(),
      kDefaultUDPSendPacketLen,
      ShortHeader(ProtectionType::KeyPhaseZero, connId, pktNum),
      0 /*largestAckedPacketNum*/,
      kDefaultUDPSendPacketLen);
  builder->encodePacketHeader();

  EXPECT_TRUE(builder->canBuildPacket());
  auto builtOut = std::move(*builder).buildPacket();
  auto resultRegularPacket = builtOut.packet;
  auto resultBuf = packetToBuf(builtOut);

  EXPECT_EQ(resultRegularPacket.frames.size(), 0);
  AckStates ackStates;
  auto packetQueue = bufToQueue(std::move(resultBuf));
  auto parsedPacket =
      makeCodec(
          connId, QuicNodeType::Client, nullptr, quic::test::createNoOpAead())
          ->parsePacket(packetQueue, ackStates);
  auto decodedPacket = parsedPacket.regularPacket();
  EXPECT_EQ(decodedPacket, nullptr);
}

TEST_P(QuicPacketBuilderTest, TestPaddingAccountsForCipherOverhead) {
  auto connId = getTestConnectionId();
  PacketNum pktNum = 222;
  PacketNum largestAckedPacketNum = 0;

  auto encodedPacketNum = encodePacketNumber(pktNum, largestAckedPacketNum);

  size_t cipherOverhead = 2;
  auto builder = testBuilderProvider(
      GetParam(),
      kDefaultUDPSendPacketLen,
      ShortHeader(ProtectionType::KeyPhaseZero, connId, pktNum),
      largestAckedPacketNum,
      kDefaultUDPSendPacketLen);
  builder->encodePacketHeader();
  builder->accountForCipherOverhead(cipherOverhead);
  EXPECT_TRUE(builder->canBuildPacket());
  writeFrame(PaddingFrame(), *builder);
  auto builtOut = std::move(*builder).buildPacket();
  auto resultRegularPacket = builtOut.packet;
  // We should have padded the remaining bytes with Padding frames.
  size_t expectedOutputSize =
      sizeof(Sample) + kMaxPacketNumEncodingSize - encodedPacketNum.length;
  EXPECT_EQ(resultRegularPacket.frames.size(), 1);
  EXPECT_EQ(
      builtOut.body->computeChainDataLength(),
      expectedOutputSize - cipherOverhead);
}

TEST_P(QuicPacketBuilderTest, TestPaddingRespectsRemainingBytes) {
  auto connId = getTestConnectionId();
  PacketNum pktNum = 222;
  PacketNum largestAckedPacketNum = 0;

  size_t totalPacketSize = 20;
  auto builder = testBuilderProvider(
      GetParam(),
      totalPacketSize,
      ShortHeader(ProtectionType::KeyPhaseZero, connId, pktNum),
      largestAckedPacketNum,
      2000);
  builder->encodePacketHeader();
  EXPECT_TRUE(builder->canBuildPacket());
  writeFrame(PaddingFrame(), *builder);
  auto builtOut = std::move(*builder).buildPacket();
  auto resultRegularPacket = builtOut.packet;

  size_t headerSize = 13;
  // We should have padded the remaining bytes with Padding frames.
  EXPECT_EQ(resultRegularPacket.frames.size(), 1);
  EXPECT_EQ(
      builtOut.body->computeChainDataLength(), totalPacketSize - headerSize);
}

TEST_F(QuicPacketBuilderTest, PacketBuilderWrapper) {
  MockQuicPacketBuilder builder;
  EXPECT_CALL(builder, remainingSpaceInPkt()).WillRepeatedly(Return(500));
  PacketBuilderWrapper wrapper(builder, 400);

  EXPECT_EQ(400, wrapper.remainingSpaceInPkt());

  EXPECT_CALL(builder, remainingSpaceInPkt()).WillRepeatedly(Return(50));
  EXPECT_EQ(0, wrapper.remainingSpaceInPkt());
}

TEST_P(QuicPacketBuilderTest, LongHeaderBytesCounting) {
  ConnectionId clientCid = getTestConnectionId(0);
  ConnectionId serverCid = getTestConnectionId(1);
  PacketNum pktNum = 8 * 24;
  PacketNum largestAcked = 8 + 24;
  LongHeader header(
      LongHeader::Types::Initial,
      clientCid,
      serverCid,
      pktNum,
      QuicVersion::MVFST);
  auto builder = testBuilderProvider(
      GetParam(),
      kDefaultUDPSendPacketLen,
      std::move(header),
      largestAcked,
      kDefaultUDPSendPacketLen);
  builder->encodePacketHeader();
  auto expectedWrittenHeaderFieldLen = sizeof(uint8_t) +
      sizeof(QuicVersionType) + sizeof(uint8_t) + clientCid.size() +
      sizeof(uint8_t) + serverCid.size();
  auto estimatedHeaderBytes = builder->getHeaderBytes();
  EXPECT_GT(
      estimatedHeaderBytes, expectedWrittenHeaderFieldLen + kMaxPacketLenSize);
  writeFrame(PaddingFrame(), *builder);
  EXPECT_LE(
      std::move(*builder).buildPacket().header->computeChainDataLength(),
      estimatedHeaderBytes);
}

TEST_P(QuicPacketBuilderTest, ShortHeaderBytesCounting) {
  PacketNum pktNum = 8 * 24;
  ConnectionId cid = getTestConnectionId();
  PacketNum largestAcked = 8 + 24;
  auto builder = testBuilderProvider(
      GetParam(),
      kDefaultUDPSendPacketLen,
      ShortHeader(ProtectionType::KeyPhaseZero, cid, pktNum),
      largestAcked,
      2000);
  builder->encodePacketHeader();
  auto headerBytes = builder->getHeaderBytes();
  writeFrame(PaddingFrame(), *builder);
  EXPECT_EQ(
      std::move(*builder).buildPacket().header->computeChainDataLength(),
      headerBytes);
}

TEST_P(QuicPacketBuilderTest, InplaceBuilderReleaseBufferInDtor) {
  SimpleBufAccessor bufAccessor(2000);
  EXPECT_TRUE(bufAccessor.ownsBuffer());
  auto builder = std::make_unique<InplaceQuicPacketBuilder>(
      bufAccessor,
      1000,
      ShortHeader(ProtectionType::KeyPhaseZero, getTestConnectionId(), 0),
      0);
  EXPECT_FALSE(bufAccessor.ownsBuffer());
  builder.reset();
  EXPECT_TRUE(bufAccessor.ownsBuffer());
}

TEST_P(QuicPacketBuilderTest, InplaceBuilderReleaseBufferInBuild) {
  SimpleBufAccessor bufAccessor(2000);
  EXPECT_TRUE(bufAccessor.ownsBuffer());
  auto builder = std::make_unique<InplaceQuicPacketBuilder>(
      bufAccessor,
      1000,
      ShortHeader(ProtectionType::KeyPhaseZero, getTestConnectionId(), 0),
      0);
  builder->encodePacketHeader();
  EXPECT_FALSE(bufAccessor.ownsBuffer());
  writeFrame(PaddingFrame(), *builder);
  std::move(*builder).buildPacket();
  EXPECT_TRUE(bufAccessor.ownsBuffer());
}

TEST_F(QuicPacketBuilderTest, BuildTwoInplaces) {
  SimpleBufAccessor bufAccessor(2000);
  EXPECT_TRUE(bufAccessor.ownsBuffer());
  auto builder1 = std::make_unique<InplaceQuicPacketBuilder>(
      bufAccessor,
      1000,
      ShortHeader(ProtectionType::KeyPhaseZero, getTestConnectionId(), 0),
      0);
  builder1->encodePacketHeader();
  auto headerBytes = builder1->getHeaderBytes();
  for (size_t i = 0; i < 20; i++) {
    writeFrame(PaddingFrame(), *builder1);
  }
  EXPECT_EQ(headerBytes, builder1->getHeaderBytes());
  auto builtOut1 = std::move(*builder1).buildPacket();
  EXPECT_EQ(1, builtOut1.packet.frames.size());
  ASSERT_TRUE(builtOut1.packet.frames[0].asPaddingFrame());
  EXPECT_EQ(builtOut1.packet.frames[0].asPaddingFrame()->numFrames, 20);

  auto builder2 = std::make_unique<InplaceQuicPacketBuilder>(
      bufAccessor,
      1000,
      ShortHeader(ProtectionType::KeyPhaseZero, getTestConnectionId(), 0),
      0);
  builder2->encodePacketHeader();
  EXPECT_EQ(headerBytes, builder2->getHeaderBytes());
  for (size_t i = 0; i < 40; i++) {
    writeFrame(PaddingFrame(), *builder2);
  }
  auto builtOut2 = std::move(*builder2).buildPacket();
  EXPECT_EQ(1, builtOut2.packet.frames.size());
  ASSERT_TRUE(builtOut2.packet.frames[0].asPaddingFrame());
  EXPECT_EQ(builtOut2.packet.frames[0].asPaddingFrame()->numFrames, 40);

  EXPECT_EQ(builtOut2.header->length(), builtOut1.header->length());
  EXPECT_EQ(20, builtOut2.body->length() - builtOut1.body->length());
}

TEST_F(QuicPacketBuilderTest, InplaceBuilderShorterHeaderBytes) {
  auto connId = getTestConnectionId();
  PacketNum packetNum = 0;
  PacketNum largestAckedPacketNum = 0;
  auto inplaceBuilder = testBuilderProvider(
      TestFlavor::Inplace,
      kDefaultUDPSendPacketLen,
      ShortHeader(ProtectionType::KeyPhaseZero, connId, packetNum),
      largestAckedPacketNum,
      kDefaultUDPSendPacketLen);
  inplaceBuilder->encodePacketHeader();
  EXPECT_EQ(2 + connId.size(), inplaceBuilder->getHeaderBytes());
}

TEST_F(QuicPacketBuilderTest, InplaceBuilderLongHeaderBytes) {
  auto srcConnId = getTestConnectionId(0);
  auto destConnId = getTestConnectionId(1);
  PacketNum packetNum = 0;
  PacketNum largestAckedPacketNum = 0;
  auto inplaceBuilder = testBuilderProvider(
      TestFlavor::Inplace,
      kDefaultUDPSendPacketLen,
      LongHeader(
          LongHeader::Types::Initial,
          srcConnId,
          destConnId,
          packetNum,
          QuicVersion::MVFST),
      largestAckedPacketNum,
      kDefaultUDPSendPacketLen);
  inplaceBuilder->encodePacketHeader();
  EXPECT_EQ(
      9 /* initial + version + cid + cid + token length */ + srcConnId.size() +
          destConnId.size() + kMaxPacketLenSize,
      inplaceBuilder->getHeaderBytes());
}

TEST_F(QuicPacketBuilderTest, PseudoRetryPacket) {
  // The values used in this test case are based on Appendix-A.4 of the
  // QUIC-TLS draft v29.

  uint8_t initialByte = 0xff;
  ConnectionId sourceConnectionId(
      {0xf0, 0x67, 0xa5, 0x50, 0x2a, 0x42, 0x62, 0xb5});
  ConnectionId destinationConnectionId((std::vector<uint8_t>()));
  ConnectionId originalDestinationConnectionId(
      {0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08});
  auto quicVersion = static_cast<QuicVersion>(0xff00001d);
  Buf token = folly::IOBuf::copyBuffer(R"(token)");

  PseudoRetryPacketBuilder builder(
      initialByte,
      sourceConnectionId,
      destinationConnectionId,
      originalDestinationConnectionId,
      quicVersion,
      std::move(token));

  Buf pseudoRetryPacketBuf = std::move(builder).buildPacket();
  FizzRetryIntegrityTagGenerator fizzRetryIntegrityTagGenerator;
  auto integrityTag = fizzRetryIntegrityTagGenerator.getRetryIntegrityTag(
      quicVersion, pseudoRetryPacketBuf.get());
  Buf expectedIntegrityTag = folly::IOBuf::copyBuffer(
      "\xd1\x69\x26\xd8\x1f\x6f\x9c\xa2\x95\x3a\x8a\xa4\x57\x5e\x1e\x49");

  folly::io::Cursor cursorActual(integrityTag.get());
  folly::io::Cursor cursorExpected(expectedIntegrityTag.get());

  EXPECT_TRUE(folly::IOBufEqualTo()(*expectedIntegrityTag, *integrityTag));
}

TEST_F(QuicPacketBuilderTest, PseudoRetryPacketLarge) {
  uint8_t initialByte = 0xff;
  ConnectionId sourceConnectionId(
      {0xf0, 0x67, 0xa5, 0x50, 0x2a, 0x42, 0x62, 0xb5});
  ConnectionId destinationConnectionId((std::vector<uint8_t>()));
  ConnectionId originalDestinationConnectionId(
      {0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08});
  auto quicVersion = static_cast<QuicVersion>(0xff00001d);
  Buf token = folly::IOBuf::create(500);
  token->append(500);

  PseudoRetryPacketBuilder builder(
      initialByte,
      sourceConnectionId,
      destinationConnectionId,
      originalDestinationConnectionId,
      quicVersion,
      std::move(token));
  Buf pseudoRetryPacketBuf = std::move(builder).buildPacket();
}

TEST_F(QuicPacketBuilderTest, RetryPacketValid) {
  auto srcConnId = getTestConnectionId(0), dstConnId = getTestConnectionId(1);
  auto quicVersion = static_cast<QuicVersion>(0xff00001d);
  std::string retryToken = "token";
  Buf integrityTag = folly::IOBuf::copyBuffer(
      "\xaa\xbb\xcc\xdd\xee\xff\x11\x22\x33\x44\x55\x66\x77\x88\x99\x11");

  RetryPacketBuilder builder(
      srcConnId,
      dstConnId,
      quicVersion,
      std::string(retryToken),
      integrityTag->clone());

  EXPECT_TRUE(builder.canBuildPacket());
  Buf retryPacket = std::move(builder).buildPacket();

  uint32_t expectedPacketLen = 1 /* initial byte */ + 4 /* version */ +
      1 /* dcid length */ + dstConnId.size() + 1 /* scid length */ +
      srcConnId.size() + retryToken.size() + kRetryIntegrityTagLen;

  // Check that the buffer containing the packet is of the correct length
  EXPECT_EQ(retryPacket->computeChainDataLength(), expectedPacketLen);

  // initial byte
  folly::io::Cursor cursor(retryPacket.get());
  auto initialByte = cursor.readBE<uint8_t>();
  EXPECT_EQ(initialByte & 0xf0, 0xf0);

  // version
  EXPECT_EQ(cursor.readBE<uint32_t>(), 0xff00001d);

  // dcid length
  auto dcidLen = cursor.readBE<uint8_t>();
  EXPECT_EQ(dcidLen, dstConnId.size());

  // dcid
  ConnectionId dcidObtained(cursor, dcidLen);
  EXPECT_EQ(dcidObtained, dstConnId);

  // scid length
  auto scidLen = cursor.readBE<uint8_t>();
  EXPECT_EQ(scidLen, srcConnId.size());

  // scid
  ConnectionId scidObtained(cursor, scidLen);
  EXPECT_EQ(scidObtained, srcConnId);

  // retry token
  Buf retryTokenObtained;
  cursor.clone(
      retryTokenObtained, cursor.totalLength() - kRetryIntegrityTagLen);
  std::string retryTokenObtainedString =
      retryTokenObtained->moveToFbString().toStdString();
  EXPECT_EQ(retryTokenObtainedString, retryToken);

  // integrity tag
  Buf integrityTagObtained;
  cursor.clone(integrityTagObtained, kRetryIntegrityTagLen);
  EXPECT_TRUE(folly::IOBufEqualTo()(integrityTagObtained, integrityTag));
}

TEST_F(QuicPacketBuilderTest, RetryPacketGiganticToken) {
  auto srcConnId = getTestConnectionId(0), dstConnId = getTestConnectionId(1);
  auto quicVersion = static_cast<QuicVersion>(0xff00001d);
  std::string retryToken;
  for (uint32_t i = 0; i < 500; i++) {
    retryToken += "aaaaaaaaaa";
  }
  Buf integrityTag = folly::IOBuf::copyBuffer(
      "\xaa\xbb\xcc\xdd\xee\xff\x11\x22\x33\x44\x55\x66\x77\x88\x99\x11");

  RetryPacketBuilder builder(
      srcConnId,
      dstConnId,
      quicVersion,
      std::string(retryToken),
      integrityTag->clone());

  EXPECT_FALSE(builder.canBuildPacket());
}

TEST_P(QuicPacketBuilderTest, PadUpLongHeaderPacket) {
  ConnectionId emptyCID(std::vector<uint8_t>(0));
  PacketNum packetNum = 0;
  PacketNum largestAcked = 0;
  auto builder = testBuilderProvider(
      GetParam(),
      kDefaultUDPSendPacketLen,
      LongHeader(
          LongHeader::Types::Handshake,
          emptyCID,
          emptyCID,
          packetNum,
          QuicVersion::MVFST),
      largestAcked,
      kDefaultUDPSendPacketLen);
  builder->encodePacketHeader();
  writeFrame(PingFrame(), *builder);
  EXPECT_TRUE(builder->canBuildPacket());
  auto builtOut = std::move(*builder).buildPacket();
  auto resultPacket = builtOut.packet;
  auto resultBuf = packetToBuf(builtOut);
  auto packetQueue = bufToQueue(std::move(resultBuf));
  AckStates ackStates;
  auto parsedPacket =
      makeCodec(
          emptyCID, QuicNodeType::Client, nullptr, quic::test::createNoOpAead())
          ->parsePacket(packetQueue, ackStates);
  auto& decodedRegularPacket = *parsedPacket.regularPacket();
  EXPECT_NE(nullptr, decodedRegularPacket.header.asLong());
  EXPECT_GT(decodedRegularPacket.frames.size(), 1);
}

TEST_P(QuicPacketBuilderTest, TestCipherOverhead) {
  ConnectionId emptyCID(std::vector<uint8_t>(0));
  PacketNum packetNum = 0;
  PacketNum largestAcked = 0;
  size_t cipherOverhead = 200;
  auto builder = testBuilderProvider(
      GetParam(),
      kDefaultUDPSendPacketLen,
      LongHeader(
          LongHeader::Types::Handshake,
          emptyCID,
          emptyCID,
          packetNum,
          QuicVersion::MVFST),
      largestAcked,
      kDefaultUDPSendPacketLen);
  builder->encodePacketHeader();
  builder->accountForCipherOverhead(cipherOverhead);
  while (builder->canBuildPacket()) {
    writeFrame(PingFrame(), *builder);
  }
  auto builtOut = std::move(*builder).buildPacket();
  auto resultRegularPacket = builtOut.packet;
  EXPECT_LT(
      resultRegularPacket.frames.size(),
      kDefaultUDPSendPacketLen - cipherOverhead);
}

INSTANTIATE_TEST_SUITE_P(
    QuicPacketBuilderTests,
    QuicPacketBuilderTest,
    Values(TestFlavor::Regular, TestFlavor::Inplace));
