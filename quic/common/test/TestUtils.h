/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#pragma once

#include <quic/api/QuicBatchWriter.h>
#include <quic/codec/QuicPacketBuilder.h>
#include <quic/codec/Types.h>
#include <quic/common/BufUtil.h>
#include <quic/common/test/TestPacketBuilders.h>
#include <quic/fizz/client/handshake/QuicPskCache.h>
#include <quic/fizz/handshake/FizzCryptoFactory.h>
#include <quic/fizz/server/handshake/FizzServerHandshake.h>
#include <quic/handshake/test/Mocks.h>
#include <quic/logging/FileQLogger.h>
#include <quic/server/state/ServerStateMachine.h>
#include <quic/state/AckStates.h>
#include <quic/state/QuicStreamManager.h>
#include <quic/state/StateData.h>

#include <fizz/client/FizzClientContext.h>
#include <fizz/server/FizzServerContext.h>
#include <quic/common/testutil/MockAsyncUDPSocket.h>

#include <folly/ssl/Init.h>
#include <quic/codec/QuicConnectionId.h>

namespace quic {
namespace test {

class MockClock {
 public:
  using time_point = quic::Clock::time_point;
  using duration = quic::Clock::duration;
  static std::function<time_point()> mockNow;

  static time_point now() {
    return mockNow();
  }
};

constexpr QuicVersion MVFST1 = static_cast<QuicVersion>(0xfaceb00d);
constexpr QuicVersion MVFST2 = static_cast<QuicVersion>(0xfaceb00e);

constexpr folly::StringPiece kTestHost = "host";

const RegularQuicWritePacket& writeQuicPacket(
    QuicServerConnectionState& conn,
    ConnectionId srcConnId,
    ConnectionId dstConnId,
    quic::test::MockAsyncUDPSocket& sock,
    QuicStreamState& stream,
    const folly::IOBuf& data,
    bool eof = false);

RegularQuicPacketBuilder::Packet createAckPacket(
    QuicConnectionStateBase& dstConn,
    PacketNum pn,
    AckBlocks& acks,
    PacketNumberSpace pnSpace,
    const Aead* aead = nullptr,
    std::chrono::microseconds ackDelay = 0us);

PacketNum rstStreamAndSendPacket(
    QuicServerConnectionState& conn,
    QuicAsyncUDPSocketWrapper& sock,
    QuicStreamState& stream,
    ApplicationErrorCode errorCode);

// TODO: this is a really horrible API. User can easily pass srcConnId and
// destConnId wrong and won't realize it. All the other createXXXPacket are also
// horrible.
RegularQuicPacketBuilder::Packet createStreamPacket(
    ConnectionId srcConnId,
    ConnectionId dstConnId,
    PacketNum packetNum,
    StreamId streamId,
    folly::IOBuf& data,
    uint8_t cipherOverhead,
    PacketNum largestAcked,
    folly::Optional<std::pair<LongHeader::Types, QuicVersion>>
        longHeaderOverride = folly::none,
    bool eof = true,
    folly::Optional<ProtectionType> shortHeaderOverride = folly::none,
    uint64_t offset = 0,
    uint64_t packetSizeLimit = kDefaultUDPSendPacketLen);

using BuilderProvider =
    std::function<PacketBuilderInterface*(PacketHeader, PacketNum)>;

RegularQuicPacketBuilder::Packet createInitialCryptoPacket(
    ConnectionId srcConnId,
    ConnectionId dstConnId,
    PacketNum packetNum,
    QuicVersion version,
    folly::IOBuf& data,
    const Aead& aead,
    PacketNum largestAcked,
    uint64_t offset = 0,
    std::string token = "",
    const BuilderProvider& builderProvider = nullptr);

RegularQuicPacketBuilder::Packet createCryptoPacket(
    ConnectionId srcConnId,
    ConnectionId dstConnId,
    PacketNum packetNum,
    QuicVersion version,
    ProtectionType protectionType,
    folly::IOBuf& data,
    const Aead& aead,
    PacketNum largestAcked,
    uint64_t offset = 0,
    uint64_t packetSizeLimit = kDefaultUDPSendPacketLen);

Buf packetToBuf(const RegularQuicPacketBuilder::Packet& packet);

Buf packetToBufCleartext(
    const RegularQuicPacketBuilder::Packet& packet,
    const Aead& cleartextCipher,
    const PacketNumberCipher& headerCipher,
    PacketNum packetNum);

template <typename T, typename S>
bool isState(const S& s) {
  return folly::variant_match(
      s.state,
      [](const T&) { return true; },
      [](const auto&) { return false; });
}

std::shared_ptr<fizz::server::FizzServerContext> createServerCtx();

void setupCtxWithTestCert(fizz::server::FizzServerContext& ctx);

TrafficKey getQuicTestKey();

void setupZeroRttOnServerCtx(
    fizz::server::FizzServerContext& serverCtx,
    const QuicCachedPsk& cachedPsk);

QuicCachedPsk setupZeroRttOnClientCtx(
    fizz::client::FizzClientContext& clientCtx,
    std::string hostname);

template <class T>
std::unique_ptr<T> createNoOpAeadImpl(uint64_t cipherOverhead = 0) {
  // Fake that the handshake has already occurred
  auto aead = std::make_unique<testing::NiceMock<T>>();
  ON_CALL(*aead, _inplaceEncrypt(testing::_, testing::_, testing::_))
      .WillByDefault(testing::Invoke([&](auto& buf, auto, auto) {
        if (buf) {
          return std::move(buf);
        } else {
          return folly::IOBuf::create(0);
        }
      }));
  // Fake that the handshake has already occurred and fix the keys.
  ON_CALL(*aead, _decrypt(testing::_, testing::_, testing::_))
      .WillByDefault(
          testing::Invoke([&](auto& buf, auto, auto) { return buf->clone(); }));
  ON_CALL(*aead, _tryDecrypt(testing::_, testing::_, testing::_))
      .WillByDefault(
          testing::Invoke([&](auto& buf, auto, auto) { return buf->clone(); }));
  ON_CALL(*aead, getCipherOverhead())
      .WillByDefault(testing::Return(cipherOverhead));
  ON_CALL(*aead, getKey()).WillByDefault(testing::Invoke([]() {
    return getQuicTestKey();
  }));
  return aead;
}

std::unique_ptr<MockAead> createNoOpAead(uint64_t cipherOverhead = 0);

std::unique_ptr<MockPacketNumberCipher> createNoOpHeaderCipher();

uint64_t computeExpectedDelay(
    std::chrono::microseconds ackDelay,
    uint8_t ackDelayExponent);

// match error functions
bool matchError(QuicError errorCode, LocalErrorCode error);
bool matchError(QuicError errorCode, TransportErrorCode error);
bool matchError(QuicError errorCode, ApplicationErrorCode error);

ConnectionId getTestConnectionId(
    uint32_t hostId = 0,
    ConnectionIdVersion version = ConnectionIdVersion::V1);

ProtectionType encryptionLevelToProtectionType(
    fizz::EncryptionLevel encryptionLevel);

MATCHER_P(IsError, error, "") {
  return matchError(arg, error);
}

MATCHER_P(IsAppError, error, "") {
  return matchError(arg, error);
}

void updateAckState(
    QuicConnectionStateBase& conn,
    PacketNumberSpace pnSpace,
    PacketNum packetNum,
    bool pkHasRetransmittableData,
    bool pkHasCryptoData,
    TimePoint receivedTime);

template <typename Match>
OutstandingPacketWrapper* findOutstandingPacket(
    QuicConnectionStateBase& conn,
    Match match) {
  auto helper = [&](std::deque<OutstandingPacketWrapper>& packets)
      -> OutstandingPacketWrapper* {
    for (auto& packet : packets) {
      if (match(packet)) {
        return &packet;
      }
    }
    return nullptr;
  };
  return helper(conn.outstandings.packets);
}

// Helper function to generate a buffer containing random data of given length
std::unique_ptr<folly::IOBuf> buildRandomInputData(size_t length);

void addAckStatesWithCurrentTimestamps(
    AckState& ackState,
    PacketNum start,
    PacketNum end);

OutstandingPacketWrapper makeTestingWritePacket(
    PacketNum desiredPacketSeqNum,
    size_t desiredSize,
    uint64_t totalBytesSent,
    TimePoint sentTime = Clock::now(),
    uint64_t inflightBytes = 0,
    uint64_t writeCount = 0);

// TODO: The way we setup packet sent, ack, loss in test cases can use some
// major refactor.
CongestionController::AckEvent makeAck(
    PacketNum seq,
    uint64_t ackedSize,
    TimePoint ackedTime,
    TimePoint sendTime);

BufQueue bufToQueue(Buf buf);

StatelessResetToken generateStatelessResetToken();

std::array<uint8_t, kStatelessResetTokenSecretLength> getRandSecret();

RegularQuicWritePacket createNewPacket(
    PacketNum packetNum,
    PacketNumberSpace pnSpace);

std::vector<QuicVersion> versionList(
    std::initializer_list<QuicVersionType> types);

RegularQuicWritePacket createRegularQuicWritePacket(
    StreamId streamId,
    uint64_t offset,
    uint64_t len,
    bool fin);

VersionNegotiationPacket createVersionNegotiationPacket();

RegularQuicWritePacket createPacketWithAckFrames();

RegularQuicWritePacket createPacketWithPaddingFrames();

// Helper function which takes in a specific event type and fetches all the
// instances of that type in QLogger
std::vector<int> getQLogEventIndices(
    QLogEventType type,
    const std::shared_ptr<FileQLogger>& q);

template <QuicWriteFrame::Type Type>
auto findFrameInPacketFunc() {
  return [&](auto& p) {
    return std::find_if(
               p.packet.frames.begin(), p.packet.frames.end(), [&](auto& f) {
                 return f.type() == Type;
               }) != p.packet.frames.end();
  };
}

template <QuicSimpleFrame::Type Type>
auto findFrameInPacketFunc() {
  return [&](auto& p) {
    return std::find_if(
               p.packet.frames.begin(), p.packet.frames.end(), [&](auto& f) {
                 QuicSimpleFrame* simpleFrame = f.asQuicSimpleFrame();
                 return simpleFrame && simpleFrame->type() == Type;
               }) != p.packet.frames.end();
  };
}

CongestionController::AckEvent::AckPacket makeAckPacketFromOutstandingPacket(
    OutstandingPacketWrapper outstandingPacket);

// A Buf based overload of writeCryptoFrame for test only
folly::Optional<WriteCryptoFrame>
writeCryptoFrame(uint64_t offsetIn, Buf data, PacketBuilderInterface& builder);

void overridePacketWithToken(
    PacketBuilderInterface::Packet& packet,
    const StatelessResetToken& token);

void overridePacketWithToken(
    folly::IOBuf& bodyBuf,
    const StatelessResetToken& token);

/*
 * Returns if the current writable streams contains the given id.
 */
bool writableContains(QuicStreamManager& streamManager, StreamId streamId);

class FizzCryptoTestFactory : public FizzCryptoFactory {
 public:
  FizzCryptoTestFactory() = default;
  explicit FizzCryptoTestFactory(std::shared_ptr<fizz::Factory> fizzFactory) {
    fizzFactory_ = std::move(fizzFactory);
  }

  ~FizzCryptoTestFactory() override = default;

  using FizzCryptoFactory::makePacketNumberCipher;
  std::unique_ptr<PacketNumberCipher> makePacketNumberCipher(
      fizz::CipherSuite) const override;

  MOCK_METHOD(
      std::unique_ptr<PacketNumberCipher>,
      _makePacketNumberCipher,
      (folly::ByteRange),
      (const));

  std::unique_ptr<PacketNumberCipher> makePacketNumberCipher(
      folly::ByteRange secret) const override;

  void setMockPacketNumberCipher(
      std::unique_ptr<PacketNumberCipher> packetNumberCipher);

  void setDefault();

  mutable std::unique_ptr<PacketNumberCipher> packetNumberCipher_;
};

class TestPacketBatchWriter : public IOBufBatchWriter {
 public:
  explicit TestPacketBatchWriter(int maxBufs) : maxBufs_(maxBufs) {}
  ~TestPacketBatchWriter() override {
    CHECK_EQ(bufNum_, 0);
    CHECK_EQ(bufSize_, 0);
  }

  void reset() override;

  bool append(
      std::unique_ptr<folly::IOBuf>&& /*unused*/,
      size_t size,
      const folly::SocketAddress& /*unused*/,
      QuicAsyncUDPSocketWrapper* /*unused*/) override;

  ssize_t write(
      QuicAsyncUDPSocketWrapper& /*unused*/,
      const folly::SocketAddress& /*unused*/) override;

  size_t getBufSize() const {
    return bufSize_;
  }

 private:
  int maxBufs_{0};
  int bufNum_{0};
  size_t bufSize_{0};
};

std::unique_ptr<folly::IOBuf> getProtectionKey();

class FakeServerHandshake : public FizzServerHandshake {
 public:
  explicit FakeServerHandshake(
      QuicServerConnectionState& conn,
      std::shared_ptr<FizzServerQuicHandshakeContext> fizzContext,
      bool chloSync = false,
      bool cfinSync = false,
      folly::Optional<uint64_t> clientActiveConnectionIdLimit = folly::none)
      : FizzServerHandshake(
            &conn,
            std::move(fizzContext),
            std::make_unique<FizzCryptoFactory>()),
        conn_(conn),
        chloSync_(chloSync),
        cfinSync_(cfinSync),
        clientActiveConnectionIdLimit_(
            std::move(clientActiveConnectionIdLimit)) {}

  void accept(std::shared_ptr<ServerTransportParametersExtension>) override {}

  MOCK_METHOD(void, writeNewSessionTicket, (const AppToken&));

  void onClientHello(bool chloWithCert = false) {
    // Do NOT invoke onCryptoEventAvailable callback
    // Fall through and let the ServerStateMachine to process the event
    writeDataToQuicStream(
        *getCryptoStream(*conn_.cryptoState, EncryptionLevel::Initial),
        folly::IOBuf::copyBuffer("SHLO"));
    if (chloWithCert) {
      /* write 4000 bytes of data to the handshake crypto stream */
      writeDataToQuicStream(
          *getCryptoStream(*conn_.cryptoState, EncryptionLevel::Handshake),
          folly::IOBuf::copyBuffer(std::string(4000, '.')));
    }

    if (allowZeroRttKeys_) {
      validateAndUpdateSourceToken(conn_, sourceAddrs_);
      phase_ = Phase::KeysDerived;
      setEarlyKeys();
    }
    setHandshakeKeys();
  }

  void onClientFin() {
    // Do NOT invoke onCryptoEventAvailable callback
    // Fall through and let the ServerStateMachine to process the event
    setOneRttKeys();
    phase_ = Phase::Established;
    handshakeDone_ = true;
  }

  void doHandshake(std::unique_ptr<folly::IOBuf> data, EncryptionLevel)
      override {
    folly::IOBufEqualTo eq;
    auto chlo = folly::IOBuf::copyBuffer("CHLO");
    auto chloWithCert = folly::IOBuf::copyBuffer("CHLO_CERT");
    auto clientFinished = folly::IOBuf::copyBuffer("FINISHED");
    bool sendHandshakeBytes = false;

    if (eq(data, chlo) || (sendHandshakeBytes = eq(data, chloWithCert))) {
      if (chloSync_) {
        onClientHello(sendHandshakeBytes);
      } else {
        // Asynchronously schedule the callback
        executor_->add([sendHandshakeBytes, this] {
          onClientHello(sendHandshakeBytes);
          if (callback_) {
            callback_->onCryptoEventAvailable();
          }
        });
      }
    } else if (eq(data, clientFinished)) {
      if (cfinSync_) {
        onClientFin();
      } else {
        // Asynchronously schedule the callback
        executor_->add([&] {
          onClientFin();
          if (callback_) {
            callback_->onCryptoEventAvailable();
          }
        });
      }
    }
  }

  folly::Optional<ClientTransportParameters> getClientTransportParams()
      override {
    std::vector<TransportParameter> transportParams;
    transportParams.push_back(encodeIntegerParameter(
        TransportParameterId::initial_max_stream_data_bidi_local,
        kDefaultStreamFlowControlWindow));
    transportParams.push_back(encodeIntegerParameter(
        TransportParameterId::initial_max_stream_data_bidi_remote,
        kDefaultStreamFlowControlWindow));
    transportParams.push_back(encodeIntegerParameter(
        TransportParameterId::initial_max_stream_data_uni,
        kDefaultStreamFlowControlWindow));
    transportParams.push_back(encodeIntegerParameter(
        TransportParameterId::initial_max_streams_bidi,
        kDefaultMaxStreamsBidirectional));
    transportParams.push_back(encodeIntegerParameter(
        TransportParameterId::initial_max_streams_uni,
        kDefaultMaxStreamsUnidirectional));
    transportParams.push_back(encodeIntegerParameter(
        TransportParameterId::initial_max_data,
        kDefaultConnectionFlowControlWindow));
    transportParams.push_back(encodeIntegerParameter(
        TransportParameterId::idle_timeout, kDefaultIdleTimeout.count()));
    transportParams.push_back(encodeIntegerParameter(
        TransportParameterId::max_packet_size, maxRecvPacketSize));
    if (clientActiveConnectionIdLimit_) {
      transportParams.push_back(encodeIntegerParameter(
          TransportParameterId::active_connection_id_limit,
          *clientActiveConnectionIdLimit_));
    }
    transportParams.push_back(encodeConnIdParameter(
        TransportParameterId::initial_source_connection_id,
        getTestConnectionId()));

    return ClientTransportParameters{std::move(transportParams)};
  }

  void setEarlyKeys() {
    oneRttWriteCipher_ = createNoOpAead();
    oneRttWriteHeaderCipher_ = createNoOpHeaderCipher();
    zeroRttReadCipher_ = createNoOpAead();
    zeroRttReadHeaderCipher_ = createNoOpHeaderCipher();
  }

  void setOneRttKeys() {
    // Mimic ServerHandshake behavior.
    // oneRttWriteCipher would already be set during ReportEarlyHandshakeSuccess
    if (!allowZeroRttKeys_) {
      auto mockOneRttWriteCipher = createNoOpAead();
      ON_CALL(*mockOneRttWriteCipher, getKey())
          .WillByDefault(testing::Invoke([]() { return getQuicTestKey(); }));
      oneRttWriteCipher_ = std::move(mockOneRttWriteCipher);
      auto mockOneRttWriteHeaderCipher = createNoOpHeaderCipher();
      mockOneRttWriteHeaderCipher->setDefaultKey();
      oneRttWriteHeaderCipher_ = std::move(mockOneRttWriteHeaderCipher);
    }
    oneRttReadCipher_ = createNoOpAead();
    oneRttReadHeaderCipher_ = createNoOpHeaderCipher();
  }

  void setHandshakeKeys() {
    conn_.handshakeWriteCipher = createNoOpAead();
    conn_.handshakeWriteHeaderCipher = createNoOpHeaderCipher();
    handshakeReadCipher_ = createNoOpAead();
    handshakeReadHeaderCipher_ = createNoOpHeaderCipher();
  }

  void setHandshakeDone(bool done) {
    handshakeDone_ = done;
  }

  void allowZeroRttKeys() {
    allowZeroRttKeys_ = true;
  }

  void setSourceTokens(std::vector<folly::IPAddress> srcAddrs) {
    sourceAddrs_ = std::move(srcAddrs);
  }

  void setCipherSuite(fizz::CipherSuite cipher) {
    state_.cipher() = cipher;
  }

  QuicServerConnectionState& conn_;
  bool chloSync_{false};
  bool cfinSync_{false};
  uint64_t maxRecvPacketSize{kDefaultMaxUDPPayload};
  bool allowZeroRttKeys_{false};
  std::vector<folly::IPAddress> sourceAddrs_;
  folly::Optional<uint64_t> clientActiveConnectionIdLimit_;
};

} // namespace test
} // namespace quic
