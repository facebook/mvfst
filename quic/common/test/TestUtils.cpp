/*
 * Copyright (c) Facebook, Inc. and its affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 *
 */

#include <quic/common/test/TestUtils.h>

#include <fizz/crypto/test/TestUtil.h>
#include <fizz/protocol/clock/test/Mocks.h>
#include <fizz/protocol/test/Mocks.h>
#include <quic/api/QuicTransportFunctions.h>
#include <quic/codec/DefaultConnectionIdAlgo.h>
#include <quic/fizz/handshake/QuicFizzFactory.h>
#include <quic/fizz/server/handshake/AppToken.h>
#include <quic/handshake/test/Mocks.h>
#include <quic/server/handshake/StatelessResetGenerator.h>
#include <quic/state/stream/StreamSendHandlers.h>

namespace quic {
namespace test {

std::function<MockClock::time_point()> MockClock::mockNow;

const RegularQuicWritePacket& writeQuicPacket(
    QuicServerConnectionState& conn,
    ConnectionId srcConnId,
    ConnectionId dstConnId,
    folly::test::MockAsyncUDPSocket& sock,
    QuicStreamState& stream,
    const folly::IOBuf& data,
    bool eof) {
  auto version = conn.version.value_or(*conn.originalVersion);
  auto aead = createNoOpAead();
  auto headerCipher = createNoOpHeaderCipher();
  writeDataToQuicStream(stream, data.clone(), eof);
  writeQuicDataToSocket(
      sock,
      conn,
      srcConnId,
      dstConnId,
      *aead,
      *headerCipher,
      version,
      conn.transportSettings.writeConnectionDataPacketsLimit);
  CHECK(
      conn.outstandings.packets.rend() !=
      getLastOutstandingPacket(conn, PacketNumberSpace::AppData));
  return getLastOutstandingPacket(conn, PacketNumberSpace::AppData)->packet;
}

PacketNum rstStreamAndSendPacket(
    QuicServerConnectionState& conn,
    folly::AsyncUDPSocket& sock,
    QuicStreamState& stream,
    ApplicationErrorCode errorCode) {
  auto aead = createNoOpAead();
  auto headerCipher = createNoOpHeaderCipher();
  auto version = conn.version.value_or(*conn.originalVersion);
  sendRstSMHandler(stream, errorCode);
  writeQuicDataToSocket(
      sock,
      conn,
      *conn.clientConnectionId,
      *conn.serverConnectionId,
      *aead,
      *headerCipher,
      version,
      conn.transportSettings.writeConnectionDataPacketsLimit);

  for (const auto& packet : conn.outstandings.packets) {
    for (const auto& frame : packet.packet.frames) {
      auto rstFrame = frame.asRstStreamFrame();
      if (!rstFrame) {
        continue;
      }
      if (rstFrame->streamId == stream.id) {
        return packet.packet.header.getPacketSequenceNum();
      }
    }
  }
  CHECK(false) << "no packet with reset stream";
  // some compilers are weird.
  return 0;
}

RegularQuicPacketBuilder::Packet createAckPacket(
    QuicConnectionStateBase& dstConn,
    PacketNum pn,
    AckBlocks& acks,
    PacketNumberSpace pnSpace,
    const Aead* aead) {
  // This function sends ACK to dstConn
  auto srcConnId =
      (dstConn.nodeType == QuicNodeType::Client ? *dstConn.serverConnectionId
                                                : *dstConn.clientConnectionId);
  auto dstConnId =
      (dstConn.nodeType == QuicNodeType::Client ? *dstConn.clientConnectionId
                                                : *dstConn.serverConnectionId);
  folly::Optional<PacketHeader> header;
  if (pnSpace == PacketNumberSpace::Initial) {
    header = LongHeader(
        LongHeader::Types::Initial,
        srcConnId,
        dstConnId,
        pn,
        QuicVersion::MVFST);
  } else if (pnSpace == PacketNumberSpace::Handshake) {
    header = LongHeader(
        LongHeader::Types::Handshake,
        srcConnId,
        dstConnId,
        pn,
        QuicVersion::MVFST);
  } else {
    header = ShortHeader(ProtectionType::KeyPhaseZero, dstConnId, pn);
  }
  RegularQuicPacketBuilder builder(
      dstConn.udpSendPacketLen,
      std::move(*header),
      getAckState(dstConn, pnSpace).largestAckedByPeer.value_or(0));
  builder.encodePacketHeader();
  if (aead) {
    builder.accountForCipherOverhead(aead->getCipherOverhead());
  }
  DCHECK(builder.canBuildPacket());
  AckFrameMetaData ackData(
      acks, 0us, dstConn.transportSettings.ackDelayExponent);
  writeAckFrame(ackData, builder);
  return std::move(builder).buildPacket();
}

std::shared_ptr<fizz::SelfCert> readCert() {
  auto certificate = fizz::test::getCert(fizz::test::kP256Certificate);
  auto privKey = fizz::test::getPrivateKey(fizz::test::kP256Key);
  std::vector<folly::ssl::X509UniquePtr> certs;
  certs.emplace_back(std::move(certificate));
  return std::make_shared<fizz::SelfCertImpl<fizz::KeyType::P256>>(
      std::move(privKey), std::move(certs));
}

std::shared_ptr<fizz::server::FizzServerContext> createServerCtx() {
  auto cert = readCert();
  auto certManager = std::make_unique<fizz::server::CertManager>();
  certManager->addCert(std::move(cert), true);
  auto serverCtx = std::make_shared<fizz::server::FizzServerContext>();
  serverCtx->setFactory(std::make_shared<QuicFizzFactory>());
  serverCtx->setCertManager(std::move(certManager));
  serverCtx->setOmitEarlyRecordLayer(true);
  serverCtx->setClock(std::make_shared<NiceMock<fizz::test::MockClock>>());
  return serverCtx;
}

class AcceptingTicketCipher : public fizz::server::TicketCipher {
 public:
  ~AcceptingTicketCipher() override = default;

  folly::Future<folly::Optional<
      std::pair<std::unique_ptr<folly::IOBuf>, std::chrono::seconds>>>
  encrypt(fizz::server::ResumptionState) const override {
    // Fake handshake, no need todo anything here.
    return std::make_pair(folly::IOBuf::create(0), 2s);
  }

  void setPsk(const QuicCachedPsk& cachedPsk) {
    cachedPsk_ = cachedPsk;
  }

  fizz::server::ResumptionState createResumptionState() const {
    fizz::server::ResumptionState resState;
    resState.version = cachedPsk_.cachedPsk.version;
    resState.cipher = cachedPsk_.cachedPsk.cipher;
    resState.resumptionSecret =
        folly::IOBuf::copyBuffer(cachedPsk_.cachedPsk.secret);
    resState.serverCert = cachedPsk_.cachedPsk.serverCert;
    resState.alpn = cachedPsk_.cachedPsk.alpn;
    resState.ticketAgeAdd = 0;
    resState.ticketIssueTime = std::chrono::system_clock::time_point();
    resState.handshakeTime = std::chrono::system_clock::time_point();
    AppToken appToken;
    appToken.transportParams = createTicketTransportParameters(
        kDefaultIdleTimeout.count(),
        kDefaultUDPReadBufferSize,
        kDefaultConnectionWindowSize,
        kDefaultStreamWindowSize,
        kDefaultStreamWindowSize,
        kDefaultStreamWindowSize,
        kDefaultMaxStreamsBidirectional,
        kDefaultMaxStreamsUnidirectional);
    appToken.version = QuicVersion::MVFST;
    resState.appToken = encodeAppToken(appToken);
    return resState;
  }

  folly::Future<
      std::pair<fizz::PskType, folly::Optional<fizz::server::ResumptionState>>>
  decrypt(std::unique_ptr<folly::IOBuf>) const override {
    return std::make_pair(fizz::PskType::Resumption, createResumptionState());
  }

 private:
  QuicCachedPsk cachedPsk_;
};

void setupZeroRttOnServerCtx(
    fizz::server::FizzServerContext& serverCtx,
    const QuicCachedPsk& cachedPsk) {
  serverCtx.setEarlyDataSettings(
      true,
      fizz::server::ClockSkewTolerance{-100000ms, 100000ms},
      std::make_shared<fizz::server::AllowAllReplayReplayCache>());
  auto ticketCipher = std::make_shared<AcceptingTicketCipher>();
  ticketCipher->setPsk(cachedPsk);
  serverCtx.setTicketCipher(ticketCipher);
}

QuicCachedPsk setupZeroRttOnClientCtx(
    fizz::client::FizzClientContext& clientCtx,
    std::string hostname) {
  clientCtx.setSendEarlyData(true);

  QuicCachedPsk quicCachedPsk;
  auto& psk = quicCachedPsk.cachedPsk;
  psk.psk = std::string("psk");
  psk.secret = std::string("secret");
  psk.type = fizz::PskType::Resumption;
  psk.version = clientCtx.getSupportedVersions()[0];
  psk.cipher = clientCtx.getSupportedCiphers()[0];
  psk.group = clientCtx.getSupportedGroups()[0];
  auto mockCert = std::make_shared<NiceMock<fizz::test::MockCert>>();
  ON_CALL(*mockCert, getIdentity()).WillByDefault(Return(hostname));
  psk.serverCert = mockCert;
  psk.alpn = clientCtx.getSupportedAlpns()[0];
  psk.ticketAgeAdd = 1;
  psk.ticketIssueTime = std::chrono::system_clock::time_point();
  psk.ticketExpirationTime =
      std::chrono::system_clock::time_point(std::chrono::minutes(100));
  psk.ticketHandshakeTime = std::chrono::system_clock::time_point();
  psk.maxEarlyDataSize = 2;

  quicCachedPsk.transportParams.idleTimeout = kDefaultIdleTimeout.count();
  quicCachedPsk.transportParams.maxRecvPacketSize = kDefaultUDPReadBufferSize;
  quicCachedPsk.transportParams.initialMaxData = kDefaultConnectionWindowSize;
  quicCachedPsk.transportParams.initialMaxStreamDataBidiLocal =
      kDefaultStreamWindowSize;
  quicCachedPsk.transportParams.initialMaxStreamDataBidiRemote =
      kDefaultStreamWindowSize;
  quicCachedPsk.transportParams.initialMaxStreamDataUni =
      kDefaultStreamWindowSize;
  quicCachedPsk.transportParams.initialMaxStreamsBidi =
      kDefaultMaxStreamsBidirectional;
  quicCachedPsk.transportParams.initialMaxStreamsUni =
      kDefaultMaxStreamsUnidirectional;
  return quicCachedPsk;
}

void setupCtxWithTestCert(fizz::server::FizzServerContext& ctx) {
  auto cert = readCert();
  auto certManager = std::make_unique<fizz::server::CertManager>();
  certManager->addCert(std::move(cert), true);
  ctx.setCertManager(std::move(certManager));
}

template <class T>
std::unique_ptr<T> createNoOpAeadImpl() {
  // Fake that the handshake has already occured
  auto aead = std::make_unique<NiceMock<T>>();
  ON_CALL(*aead, _inplaceEncrypt(_, _, _))
      .WillByDefault(Invoke([&](auto& buf, auto, auto) {
        if (buf) {
          return std::move(buf);
        } else {
          return folly::IOBuf::create(0);
        }
      }));
  // Fake that the handshake has already occured and fix the keys.
  ON_CALL(*aead, _decrypt(_, _, _))
      .WillByDefault(
          Invoke([&](auto& buf, auto, auto) { return buf->clone(); }));
  ON_CALL(*aead, _tryDecrypt(_, _, _))
      .WillByDefault(
          Invoke([&](auto& buf, auto, auto) { return buf->clone(); }));
  ON_CALL(*aead, getCipherOverhead()).WillByDefault(Return(0));
  return aead;
}

std::unique_ptr<MockAead> createNoOpAead() {
  return createNoOpAeadImpl<MockAead>();
}

std::unique_ptr<PacketNumberCipher> createNoOpHeaderCipher() {
  auto headerCipher = std::make_unique<NiceMock<MockPacketNumberCipher>>();
  ON_CALL(*headerCipher, mask(_)).WillByDefault(Return(HeaderProtectionMask{}));
  ON_CALL(*headerCipher, keyLength()).WillByDefault(Return(16));
  return headerCipher;
}

RegularQuicPacketBuilder::Packet createStreamPacket(
    ConnectionId srcConnId,
    ConnectionId dstConnId,
    PacketNum packetNum,
    StreamId streamId,
    folly::IOBuf& data,
    uint8_t cipherOverhead,
    PacketNum largestAcked,
    folly::Optional<std::pair<LongHeader::Types, QuicVersion>>
        longHeaderOverride,
    bool eof,
    folly::Optional<ProtectionType> shortHeaderOverride,
    uint64_t offset,
    uint64_t packetSizeLimit) {
  std::unique_ptr<RegularQuicPacketBuilder> builder;
  if (longHeaderOverride) {
    LongHeader header(
        longHeaderOverride->first,
        srcConnId,
        dstConnId,
        packetNum,
        longHeaderOverride->second);
    builder.reset(new RegularQuicPacketBuilder(
        packetSizeLimit, std::move(header), largestAcked));
  } else {
    ProtectionType protectionType = ProtectionType::KeyPhaseZero;
    if (shortHeaderOverride) {
      protectionType = *shortHeaderOverride;
    }
    ShortHeader header(protectionType, dstConnId, packetNum);
    builder.reset(new RegularQuicPacketBuilder(
        packetSizeLimit, std::move(header), largestAcked));
  }
  builder->encodePacketHeader();
  builder->accountForCipherOverhead(cipherOverhead);
  writeStreamFrameHeader(
      *builder,
      streamId,
      offset,
      data.computeChainDataLength(),
      data.computeChainDataLength(),
      eof,
      folly::none /* skipLenHint */);
  writeStreamFrameData(*builder, data.clone(), data.computeChainDataLength());
  return std::move(*builder).buildPacket();
}

RegularQuicPacketBuilder::Packet createInitialCryptoPacket(
    ConnectionId srcConnId,
    ConnectionId dstConnId,
    PacketNum packetNum,
    QuicVersion version,
    folly::IOBuf& data,
    const Aead& aead,
    PacketNum largestAcked,
    uint64_t offset,
    const BuilderProvider& builderProvider) {
  LongHeader header(
      LongHeader::Types::Initial, srcConnId, dstConnId, packetNum, version);
  LongHeader copyHeader(header);
  PacketBuilderInterface* builder = nullptr;
  if (builderProvider) {
    builder = builderProvider(std::move(header), largestAcked);
  }
  RegularQuicPacketBuilder fallbackBuilder(
      kDefaultUDPSendPacketLen, std::move(copyHeader), largestAcked);
  if (!builder) {
    builder = &fallbackBuilder;
  }
  builder->encodePacketHeader();
  builder->accountForCipherOverhead(aead.getCipherOverhead());
  writeCryptoFrame(offset, data.clone(), *builder);
  return std::move(*builder).buildPacket();
}

RegularQuicPacketBuilder::Packet createCryptoPacket(
    ConnectionId srcConnId,
    ConnectionId dstConnId,
    PacketNum packetNum,
    QuicVersion version,
    ProtectionType protectionType,
    folly::IOBuf& data,
    const Aead& aead,
    PacketNum largestAcked,
    uint64_t offset,
    uint64_t packetSizeLimit) {
  folly::Optional<PacketHeader> header;
  switch (protectionType) {
    case ProtectionType::Initial:
      header = LongHeader(
          LongHeader::Types::Initial, srcConnId, dstConnId, packetNum, version);
      break;
    case ProtectionType::Handshake:
      header = LongHeader(
          LongHeader::Types::Handshake,
          srcConnId,
          dstConnId,
          packetNum,
          version);
      break;
    case ProtectionType::ZeroRtt:
      header = LongHeader(
          LongHeader::Types::ZeroRtt, srcConnId, dstConnId, packetNum, version);
      break;
    case ProtectionType::KeyPhaseOne:
    case ProtectionType::KeyPhaseZero:
      header = ShortHeader(protectionType, dstConnId, packetNum);
      break;
  }
  RegularQuicPacketBuilder builder(
      packetSizeLimit, std::move(*header), largestAcked);
  builder.encodePacketHeader();
  builder.accountForCipherOverhead(aead.getCipherOverhead());
  writeCryptoFrame(offset, data.clone(), builder);
  return std::move(builder).buildPacket();
}

Buf packetToBuf(const RegularQuicPacketBuilder::Packet& packet) {
  auto packetBuf = packet.header->clone();
  if (packet.body) {
    packetBuf->prependChain(packet.body->clone());
  }
  return packetBuf;
}

Buf packetToBufCleartext(
    const RegularQuicPacketBuilder::Packet& packet,
    const Aead& cleartextCipher,
    const PacketNumberCipher& headerCipher,
    PacketNum packetNum) {
  VLOG(10) << __func__ << " packet header: "
           << folly::hexlify(packet.header->clone()->moveToFbString());
  auto packetBuf = packet.header->clone();
  Buf body;
  if (packet.body) {
    packet.body->coalesce();
    body = packet.body->clone();
  } else {
    body = folly::IOBuf::create(0);
  }
  auto headerForm = packet.packet.header.getHeaderForm();
  packet.header->coalesce();
  auto tagLen = cleartextCipher.getCipherOverhead();
  if (body->tailroom() < tagLen) {
    body->prependChain(folly::IOBuf::create(tagLen));
  }
  body->coalesce();
  auto encryptedBody = cleartextCipher.inplaceEncrypt(
      std::move(body), packet.header.get(), packetNum);
  encryptedBody->coalesce();
  encryptPacketHeader(
      headerForm,
      packet.header->writableData(),
      packet.header->length(),
      encryptedBody->data(),
      encryptedBody->length(),
      headerCipher);
  packetBuf->prependChain(std::move(encryptedBody));
  return packetBuf;
}

uint64_t computeExpectedDelay(
    std::chrono::microseconds ackDelay,
    uint8_t ackDelayExponent) {
  uint64_t divide = uint64_t(ackDelay.count()) >> ackDelayExponent;
  return divide << ackDelayExponent;
}

ConnectionId getTestConnectionId(uint16_t hostId) {
  ServerConnectionIdParams params(hostId, 0, 0);
  DefaultConnectionIdAlgo connIdAlgo;
  auto connId = *connIdAlgo.encodeConnectionId(params);
  connId.data()[3] = 3;
  connId.data()[4] = 4;
  connId.data()[5] = 5;
  connId.data()[6] = 6;
  connId.data()[7] = 7;
  return connId;
}

class TestCertificateVerifier : public fizz::CertificateVerifier {
 public:
  ~TestCertificateVerifier() override = default;

  void verify(const std::vector<std::shared_ptr<const fizz::PeerCert>>&)
      const override {
    return;
  }

  std::vector<fizz::Extension> getCertificateRequestExtensions()
      const override {
    return std::vector<fizz::Extension>();
  }
};

std::unique_ptr<fizz::CertificateVerifier> createTestCertificateVerifier() {
  return std::make_unique<TestCertificateVerifier>();
}

ProtectionType encryptionLevelToProtectionType(
    fizz::EncryptionLevel encryptionLevel) {
  switch (encryptionLevel) {
    case fizz::EncryptionLevel::Plaintext:
      return ProtectionType::Initial;
    case fizz::EncryptionLevel::Handshake:
      // TODO: change this in draft-14
      return ProtectionType::Initial;
    case fizz::EncryptionLevel::EarlyData:
      return ProtectionType::ZeroRtt;
    case fizz::EncryptionLevel::AppTraffic:
      return ProtectionType::KeyPhaseZero;
  }
  folly::assume_unreachable();
}

void updateAckState(
    QuicConnectionStateBase& conn,
    PacketNumberSpace pnSpace,
    PacketNum packetNum,
    bool pkHasRetransmittableData,
    bool pkHasCryptoData,
    TimePoint receivedTime) {
  bool outOfOrder = updateLargestReceivedPacketNum(
      getAckState(conn, pnSpace), packetNum, receivedTime);
  updateAckSendStateOnRecvPacket(
      conn,
      getAckState(conn, pnSpace),
      outOfOrder,
      pkHasRetransmittableData,
      pkHasCryptoData);
}

std::unique_ptr<folly::IOBuf> buildRandomInputData(size_t length) {
  auto buf = folly::IOBuf::create(length);
  buf->append(length);
  folly::Random::secureRandom(buf->writableData(), buf->length());
  return buf;
}

void addAckStatesWithCurrentTimestamps(
    AckState& ackState,
    PacketNum start,
    PacketNum end) {
  ackState.acks.insert(start, end);
  ackState.largestRecvdPacketTime = Clock::now();
}

OutstandingPacket makeTestingWritePacket(
    PacketNum desiredPacketSeqNum,
    size_t desiredSize,
    uint64_t totalBytesSent,
    TimePoint sentTime /* = Clock::now() */,
    uint64_t inflightBytes /* = 0 */) {
  LongHeader longHeader(
      LongHeader::Types::ZeroRtt,
      getTestConnectionId(1),
      getTestConnectionId(),
      desiredPacketSeqNum,
      QuicVersion::MVFST);
  RegularQuicWritePacket packet(std::move(longHeader));
  return OutstandingPacket(
      packet, sentTime, desiredSize, false, totalBytesSent, inflightBytes);
}

CongestionController::AckEvent makeAck(
    PacketNum seq,
    uint64_t ackedSize,
    TimePoint ackedTime,
    TimePoint sentTime) {
  CHECK(sentTime < ackedTime);
  RegularQuicWritePacket packet(
      ShortHeader(ProtectionType::KeyPhaseZero, getTestConnectionId(), seq));
  CongestionController::AckEvent ack;
  ack.ackedBytes = ackedSize;
  ack.ackTime = ackedTime;
  ack.largestAckedPacket = seq;
  ack.ackedPackets.emplace_back(
      CongestionController::AckEvent::AckPacket::Builder()
          .setSentTime(sentTime)
          .setEncodedSize(ackedSize)
          .build());
  ack.largestAckedPacketSentTime = sentTime;
  return ack;
}

BufQueue bufToQueue(Buf buf) {
  BufQueue queue;
  buf->coalesce();
  queue.append(std::move(buf));
  return queue;
}

StatelessResetToken generateStatelessResetToken() {
  StatelessResetSecret secret;
  folly::Random::secureRandom(secret.data(), secret.size());
  folly::SocketAddress address("1.2.3.4", 8080);
  StatelessResetGenerator generator(secret, address.getFullyQualified());

  return generator.generateToken(ConnectionId({0x14, 0x35, 0x22, 0x11}));
}

std::array<uint8_t, kStatelessResetTokenSecretLength> getRandSecret() {
  std::array<uint8_t, kStatelessResetTokenSecretLength> secret;
  folly::Random::secureRandom(secret.data(), secret.size());
  return secret;
}

RegularQuicWritePacket createNewPacket(
    PacketNum packetNum,
    PacketNumberSpace pnSpace) {
  switch (pnSpace) {
    case PacketNumberSpace::Initial:
      return RegularQuicWritePacket(LongHeader(
          LongHeader::Types::Initial,
          getTestConnectionId(1),
          getTestConnectionId(2),
          packetNum,
          QuicVersion::QUIC_DRAFT));
    case PacketNumberSpace::Handshake:
      return RegularQuicWritePacket(LongHeader(
          LongHeader::Types::Handshake,
          getTestConnectionId(0),
          getTestConnectionId(4),
          packetNum,
          QuicVersion::QUIC_DRAFT));
    case PacketNumberSpace::AppData:
      return RegularQuicWritePacket(ShortHeader(
          ProtectionType::KeyPhaseOne, getTestConnectionId(), packetNum));
  }

  folly::assume_unreachable();
}

std::vector<QuicVersion> versionList(
    std::initializer_list<QuicVersionType> types) {
  std::vector<QuicVersion> versions;
  for (auto type : types) {
    versions.push_back(static_cast<QuicVersion>(type));
  }
  return versions;
}

RegularQuicWritePacket createRegularQuicWritePacket(
    StreamId streamId,
    uint64_t offset,
    uint64_t len,
    bool fin) {
  auto regularWritePacket = createNewPacket(10, PacketNumberSpace::Initial);
  WriteStreamFrame frame(streamId, offset, len, fin);
  regularWritePacket.frames.emplace_back(frame);
  return regularWritePacket;
}

VersionNegotiationPacket createVersionNegotiationPacket() {
  auto versions = {QuicVersion::VERSION_NEGOTIATION, QuicVersion::MVFST};
  auto packet = VersionNegotiationPacketBuilder(
                    getTestConnectionId(0), getTestConnectionId(1), versions)
                    .buildPacket()
                    .first;
  return packet;
}

RegularQuicWritePacket createPacketWithAckFrames() {
  RegularQuicWritePacket packet =
      createNewPacket(100, PacketNumberSpace::Initial);
  WriteAckFrame ackFrame;
  ackFrame.ackDelay = 111us;
  ackFrame.ackBlocks.emplace_back(900, 1000);
  ackFrame.ackBlocks.emplace_back(500, 700);

  packet.frames.emplace_back(std::move(ackFrame));
  return packet;
}

RegularQuicWritePacket createPacketWithPaddingFrames() {
  RegularQuicWritePacket packet =
      createNewPacket(100, PacketNumberSpace::Initial);
  for (int i = 0; i < 20; ++i) {
    PaddingFrame paddingFrame;
    packet.frames.emplace_back(paddingFrame);
  }
  return packet;
}

std::vector<int> getQLogEventIndices(
    QLogEventType type,
    const std::shared_ptr<FileQLogger>& q) {
  std::vector<int> indices;
  for (uint64_t i = 0; i < q->logs.size(); ++i) {
    if (q->logs[i]->eventType == type) {
      indices.push_back(i);
    }
  }
  return indices;
}

bool matchError(
    std::pair<QuicErrorCode, folly::Optional<folly::StringPiece>> errorCode,
    LocalErrorCode error) {
  return errorCode.first.type() == QuicErrorCode::Type::LocalErrorCode_E &&
      *errorCode.first.asLocalErrorCode() == error;
}

bool matchError(
    std::pair<QuicErrorCode, folly::Optional<folly::StringPiece>> errorCode,
    TransportErrorCode error) {
  return errorCode.first.type() == QuicErrorCode::Type::TransportErrorCode_E &&
      *errorCode.first.asTransportErrorCode() == error;
}

bool matchError(
    std::pair<QuicErrorCode, folly::Optional<folly::StringPiece>> errorCode,
    ApplicationErrorCode error) {
  return errorCode.first.type() ==
      QuicErrorCode::Type::ApplicationErrorCode_E &&
      *errorCode.first.asApplicationErrorCode() == error;
}

bool matchError(
    std::pair<QuicErrorCode, std::string> errorCode,
    ApplicationErrorCode error) {
  return errorCode.first.type() ==
      QuicErrorCode::Type::ApplicationErrorCode_E &&
      *errorCode.first.asApplicationErrorCode() == error;
}

bool matchError(
    std::pair<QuicErrorCode, std::string> errorCode,
    TransportErrorCode error) {
  return errorCode.first.type() == QuicErrorCode::Type::TransportErrorCode_E &&
      *errorCode.first.asTransportErrorCode() == error;
}

CongestionController::AckEvent::AckPacket makeAckPacketFromOutstandingPacket(
    OutstandingPacket outstandingPacket) {
  return CongestionController::AckEvent::AckPacket::Builder()
      .setSentTime(outstandingPacket.metadata.time)
      .setEncodedSize(outstandingPacket.metadata.encodedSize)
      .setLastAckedPacketInfo(std::move(outstandingPacket.lastAckedPacketInfo))
      .setTotalBytesSentThen(outstandingPacket.metadata.totalBytesSent)
      .setAppLimited(outstandingPacket.isAppLimited)
      .build();
}

folly::Optional<WriteCryptoFrame>
writeCryptoFrame(uint64_t offsetIn, Buf data, PacketBuilderInterface& builder) {
  BufQueue bufQueue(std::move(data));
  return writeCryptoFrame(offsetIn, bufQueue, builder);
}

void overridePacketWithToken(
    PacketBuilderInterface::Packet& packet,
    const StatelessResetToken& token) {
  overridePacketWithToken(*packet.body, token);
}

void overridePacketWithToken(
    folly::IOBuf& bodyBuf,
    const StatelessResetToken& token) {
  bodyBuf.coalesce();
  CHECK(bodyBuf.length() > sizeof(StatelessResetToken));
  memcpy(
      bodyBuf.writableData() + bodyBuf.length() - sizeof(StatelessResetToken),
      token.data(),
      token.size());
}

} // namespace test
} // namespace quic
