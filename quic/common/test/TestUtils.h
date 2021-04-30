/*
 * Copyright (c) Facebook, Inc. and its affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 *
 */

#pragma once

#include <quic/api/QuicBatchWriter.h>
#include <quic/codec/QuicPacketBuilder.h>
#include <quic/codec/Types.h>
#include <quic/common/BufUtil.h>
#include <quic/fizz/client/handshake/QuicPskCache.h>
#include <quic/fizz/handshake/FizzCryptoFactory.h>
#include <quic/handshake/test/Mocks.h>
#include <quic/logging/FileQLogger.h>
#include <quic/server/state/ServerStateMachine.h>
#include <quic/state/AckStates.h>
#include <quic/state/QuicStreamManager.h>
#include <quic/state/StateData.h>

#include <fizz/client/FizzClientContext.h>
#include <fizz/server/FizzServerContext.h>
#include <folly/io/async/test/MockAsyncUDPSocket.h>

#include <folly/ssl/Init.h>
#include "quic/codec/QuicConnectionId.h"

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
    folly::test::MockAsyncUDPSocket& sock,
    QuicStreamState& stream,
    const folly::IOBuf& data,
    bool eof = false);

RegularQuicPacketBuilder::Packet createAckPacket(
    QuicConnectionStateBase& dstConn,
    PacketNum pn,
    AckBlocks& acks,
    PacketNumberSpace pnSpace,
    const Aead* aead = nullptr);

PacketNum rstStreamAndSendPacket(
    QuicServerConnectionState& conn,
    folly::AsyncUDPSocket& sock,
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

void setupZeroRttOnServerCtx(
    fizz::server::FizzServerContext& serverCtx,
    const QuicCachedPsk& cachedPsk);

QuicCachedPsk setupZeroRttOnClientCtx(
    fizz::client::FizzClientContext& clientCtx,
    std::string hostname);

template <class T>
std::unique_ptr<T> createNoOpAeadImpl() {
  // Fake that the handshake has already occured
  auto aead = std::make_unique<testing::NiceMock<T>>();
  ON_CALL(*aead, _inplaceEncrypt(testing::_, testing::_, testing::_))
      .WillByDefault(testing::Invoke([&](auto& buf, auto, auto) {
        if (buf) {
          return std::move(buf);
        } else {
          return folly::IOBuf::create(0);
        }
      }));
  // Fake that the handshake has already occured and fix the keys.
  ON_CALL(*aead, _decrypt(testing::_, testing::_, testing::_))
      .WillByDefault(
          testing::Invoke([&](auto& buf, auto, auto) { return buf->clone(); }));
  ON_CALL(*aead, _tryDecrypt(testing::_, testing::_, testing::_))
      .WillByDefault(
          testing::Invoke([&](auto& buf, auto, auto) { return buf->clone(); }));
  ON_CALL(*aead, getCipherOverhead()).WillByDefault(testing::Return(0));
  return aead;
}

std::unique_ptr<MockAead> createNoOpAead();

std::unique_ptr<PacketNumberCipher> createNoOpHeaderCipher();

uint64_t computeExpectedDelay(
    std::chrono::microseconds ackDelay,
    uint8_t ackDelayExponent);

std::unique_ptr<fizz::CertificateVerifier> createTestCertificateVerifier();

// match error functions
bool matchError(
    std::pair<QuicErrorCode, folly::Optional<folly::StringPiece>> errorCode,
    LocalErrorCode error);

bool matchError(
    std::pair<QuicErrorCode, folly::Optional<folly::StringPiece>> errorCode,
    TransportErrorCode error);

bool matchError(
    std::pair<QuicErrorCode, folly::Optional<folly::StringPiece>> errorCode,
    ApplicationErrorCode error);

bool matchError(
    std::pair<QuicErrorCode, std::string> errorCode,
    ApplicationErrorCode error);

bool matchError(
    std::pair<QuicErrorCode, std::string> errorCode,
    TransportErrorCode error);

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
OutstandingPacket* findOutstandingPacket(
    QuicConnectionStateBase& conn,
    Match match) {
  auto helper =
      [&](std::deque<OutstandingPacket>& packets) -> OutstandingPacket* {
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

OutstandingPacket makeTestingWritePacket(
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

template <QuicSimpleFrame::Type Type>
auto findFrameInPacketFunc() {
  return [&](auto& p) {
    return std::find_if(
               p.packet.frames.begin(), p.packet.frames.end(), [&](auto& f) {
                 QuicSimpleFrame* simpleFrame = f.asQuicSimpleFrame();
                 if (!simpleFrame) {
                   return false;
                 }
                 return simpleFrame->type() == Type;
               }) != p.packet.frames.end();
  };
}

CongestionController::AckEvent::AckPacket makeAckPacketFromOutstandingPacket(
    OutstandingPacket outstandingPacket);

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

  MOCK_CONST_METHOD1(
      _makePacketNumberCipher,
      std::unique_ptr<PacketNumberCipher>(folly::ByteRange));

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
      folly::AsyncUDPSocket* /*unused*/) override;

  ssize_t write(
      folly::AsyncUDPSocket& /*unused*/,
      const folly::SocketAddress& /*unused*/) override;

  size_t getBufSize() const {
    return bufSize_;
  }

 private:
  int maxBufs_{0};
  int bufNum_{0};
  size_t bufSize_{0};
};

} // namespace test
} // namespace quic
