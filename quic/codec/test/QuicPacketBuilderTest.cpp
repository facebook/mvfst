/*
 * Copyright (c) Facebook, Inc. and its affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 *
 */

#include <folly/portability/GTest.h>

#include <folly/Random.h>
#include <quic/codec/QuicPacketBuilder.h>
#include <quic/codec/QuicReadCodec.h>
#include <quic/codec/Types.h>
#include <quic/codec/test/Mocks.h>
#include <quic/common/test/TestUtils.h>
#include <quic/fizz/handshake/FizzCryptoFactory.h>
#include <quic/handshake/HandshakeLayer.h>

using namespace quic;
using namespace quic::test;
using namespace testing;

enum TestFlavor { Regular, Inplace };

struct BuilderWithBuffer {
  std::unique_ptr<PacketBuilderInterface> builder;
  Buf buf;

  BuilderWithBuffer() = default;
  explicit BuilderWithBuffer(
      std::unique_ptr<PacketBuilderInterface> builderIn,
      Buf bufIn)
      : builder(std::move(builderIn)), buf(std::move(bufIn)) {}
};

BuilderWithBuffer testBuilderProvider(
    TestFlavor flavor,
    uint32_t pktSizeLimit,
    PacketHeader header,
    PacketNum largestAckedPacketNum,
    folly::Optional<size_t> outputBufSize) {
  switch (flavor) {
    case TestFlavor::Regular:
      return BuilderWithBuffer(
          std::make_unique<RegularQuicPacketBuilder>(
              pktSizeLimit, std::move(header), largestAckedPacketNum),
          nullptr);

    case TestFlavor::Inplace:
      auto outputBuf = folly::IOBuf::create(*outputBufSize);
      return BuilderWithBuffer(
          std::make_unique<InplaceQuicPacketBuilder>(
              *outputBuf,
              pktSizeLimit,
              std::move(header),
              largestAckedPacketNum),
          std::move(outputBuf));
  }
  folly::assume_unreachable();
}

Buf packetToBuf(
    RegularQuicPacketBuilder::Packet& packet,
    Aead* aead = nullptr) {
  auto buf = folly::IOBuf::create(0);
  // This doesnt matter.
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
    body = aead->encrypt(std::move(body), packet.header.get(), num);
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
    sizeof(FrameType) + kDefaultConnectionIdSize * 2 + sizeof(QuicVersion);

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

class QuicPacketBuilderTest : public TestWithParam<TestFlavor> {};

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

TEST_P(QuicPacketBuilderTest, SimpleRetryPacket) {
  LongHeader headerIn(
      LongHeader::Types::Retry,
      getTestConnectionId(0),
      getTestConnectionId(1),
      321,
      QuicVersion::MVFST,
      std::string("454358"),
      getTestConnectionId(2));

  auto builderAndBuf = testBuilderProvider(
      GetParam(),
      kDefaultUDPSendPacketLen,
      std::move(headerIn),
      0 /* largestAcked */,
      2000);
  auto packet = packetToBuf(std::move(*(builderAndBuf.builder)).buildPacket());
  auto packetQueue = bufToQueue(std::move(packet));

  // Verify the returned buf from packet builder can be decoded by read codec:
  AckStates ackStates;
  auto optionalDecodedPacket =
      makeCodec(getTestConnectionId(1), QuicNodeType::Client)
          ->parsePacket(packetQueue, ackStates);
  ASSERT_NE(optionalDecodedPacket.regularPacket(), nullptr);
  auto& retryPacket = *optionalDecodedPacket.regularPacket();

  auto& headerOut = *retryPacket.header.asLong();

  EXPECT_EQ(*headerOut.getOriginalDstConnId(), getTestConnectionId(2));
  EXPECT_EQ(headerOut.getVersion(), QuicVersion::MVFST);
  EXPECT_EQ(headerOut.getSourceConnId(), getTestConnectionId(0));
  EXPECT_EQ(headerOut.getDestinationConnId(), getTestConnectionId(1));

  auto expected = std::string("454358");
  EXPECT_EQ(headerOut.getToken(), expected);
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

  // To make sure they live long enough
  // TODO: remove this ownership and builder provider theater once we are ready
  // to land the GSO optimization.
  BuilderWithBuffer pinnedBuilderAndBuf;
  auto builderProvider = [&](PacketHeader header, PacketNum largestAcked) {
    auto builderAndBuf = testBuilderProvider(
        GetParam(),
        kDefaultUDPSendPacketLen,
        std::move(header),
        largestAcked,
        kDefaultUDPSendPacketLen * 2);
    PacketBuilderInterface* builder = builderAndBuf.builder.get();
    pinnedBuilderAndBuf.builder = std::move(builderAndBuf.builder);
    pinnedBuilderAndBuf.buf = std::move(builderAndBuf.buf);
    return builder;
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
  auto builderAndBuf = testBuilderProvider(
      GetParam(),
      kDefaultUDPSendPacketLen,
      ShortHeader(ProtectionType::KeyPhaseZero, connId, pktNum),
      largestAckedPacketNum,
      2000);
  PacketBuilderInterface* builder = builderAndBuf.builder.get();

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

TEST_P(QuicPacketBuilderTest, ShortHeaderWithNoFrames) {
  auto connId = getTestConnectionId();
  PacketNum pktNum = 222;

  // We expect that the builder will not add new frames to a packet which has no
  // frames already and will be too small to parse.
  auto builderAndBuf = testBuilderProvider(
      GetParam(),
      kDefaultUDPSendPacketLen,
      ShortHeader(ProtectionType::KeyPhaseZero, connId, pktNum),
      0 /*largestAckedPacketNum*/,
      kDefaultUDPSendPacketLen);
  PacketBuilderInterface* builder = builderAndBuf.builder.get();

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
  auto builderAndBuf = testBuilderProvider(
      GetParam(),
      kDefaultUDPSendPacketLen,
      ShortHeader(ProtectionType::KeyPhaseZero, connId, pktNum),
      largestAckedPacketNum,
      kDefaultUDPSendPacketLen);
  PacketBuilderInterface* builder = builderAndBuf.builder.get();
  builder->setCipherOverhead(cipherOverhead);
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
  auto builderAndBuf = testBuilderProvider(
      GetParam(),
      totalPacketSize,
      ShortHeader(ProtectionType::KeyPhaseZero, connId, pktNum),
      largestAckedPacketNum,
      2000);
  PacketBuilderInterface* builder = builderAndBuf.builder.get();
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
  auto builderAndBuf = testBuilderProvider(
      GetParam(),
      kDefaultUDPSendPacketLen,
      std::move(header),
      largestAcked,
      kDefaultUDPSendPacketLen);
  PacketBuilderInterface* builder = builderAndBuf.builder.get();
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
  auto builderAndBuf = testBuilderProvider(
      GetParam(),
      kDefaultUDPSendPacketLen,
      ShortHeader(ProtectionType::KeyPhaseZero, cid, pktNum),
      largestAcked,
      2000);
  PacketBuilderInterface* builder = builderAndBuf.builder.get();
  auto headerBytes = builder->getHeaderBytes();
  writeFrame(PaddingFrame(), *builder);
  EXPECT_EQ(
      std::move(*builder).buildPacket().header->computeChainDataLength(),
      headerBytes);
}

INSTANTIATE_TEST_CASE_P(
    QuicPacketBuilderTests,
    QuicPacketBuilderTest,
    Values(TestFlavor::Regular, TestFlavor::Inplace));
