/*
 * Copyright (c) Facebook, Inc. and its affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 *
 */

#pragma once

#include <quic/client/handshake/QuicPskCache.h>
#include <quic/codec/QuicPacketBuilder.h>
#include <quic/codec/Types.h>
#include <quic/common/test/QuicCodecUtils.h>
#include <quic/handshake/test/Mocks.h>
#include <quic/server/state/ServerStateMachine.h>
#include <quic/state/AckStates.h>
#include <quic/state/StateData.h>

#include <fizz/client/FizzClientContext.h>
#include <fizz/crypto/aead/test/Mocks.h>
#include <fizz/server/FizzServerContext.h>
#include <folly/io/async/test/MockAsyncUDPSocket.h>

#include <folly/ssl/Init.h>

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

constexpr QuicVersion MVFST1 = static_cast<QuicVersion>(0xfaceb001);
constexpr QuicVersion MVFST2 = static_cast<QuicVersion>(0xfaceb002);

constexpr folly::StringPiece kTestHost = "host";

const RegularQuicWritePacket& writeQuicPacket(
    QuicServerConnectionState& conn,
    ConnectionId srcConnId,
    ConnectionId dstConnId,
    folly::test::MockAsyncUDPSocket& sock,
    QuicStreamState& stream,
    const folly::IOBuf& data,
    bool eof = false);

PacketNum getPacketSequenceNum(const RegularQuicWritePacket& packet);

RegularQuicPacketBuilder::Packet createAckPacket(
    QuicConnectionStateBase& dstConn,
    PacketNum pn,
    IntervalSet<PacketNum>& acks,
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

RegularQuicPacketBuilder::Packet createInitialCryptoPacket(
    ConnectionId srcConnId,
    ConnectionId dstConnId,
    PacketNum packetNum,
    QuicVersion version,
    folly::IOBuf& data,
    const Aead& aead,
    PacketNum largestAcked,
    uint64_t offset = 0);

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
    std::string hostname,
    QuicVersion version);

std::unique_ptr<MockAead> createNoOpAead();
std::unique_ptr<fizz::test::MockAead> createNoOpFizzAead();

std::unique_ptr<PacketNumberCipher> createNoOpHeaderCipher();

uint64_t computeExpectedDelay(
    std::chrono::microseconds ackDelay,
    uint8_t ackDelayExponent);

std::unique_ptr<fizz::CertificateVerifier> createTestCertificateVerifier();

template <class T>
bool matchError(std::pair<QuicErrorCode, std::string> errorCode, T error) {
  return folly::variant_match(
      errorCode.first,
      [&](T err) { return err == error; },
      [](auto) { return false; });
}

template <class T>
bool matchError(
    std::pair<QuicErrorCode, folly::Optional<folly::StringPiece>> errorCode,
    T error) {
  return folly::variant_match(
      errorCode.first,
      [&](T err) { return err == error; },
      [](auto) { return false; });
}

ConnectionId getTestConnectionId(uint16_t hostId = 0);

ProtectionType encryptionLevelToProtectionType(
    fizz::EncryptionLevel encryptionLevel);

MATCHER_P(IsError, error, "") {
  return matchError(arg, error);
}

inline bool matchAppError(
    std::pair<QuicErrorCode, std::string> errorCode,
    ApplicationErrorCode error) {
  return folly::variant_match(
      errorCode.first,
      [&](ApplicationErrorCode err) { return err == error; },
      [](auto) { return false; });
}

inline bool matchAppError(
    std::pair<QuicErrorCode, folly::Optional<folly::StringPiece>> errorCode,
    ApplicationErrorCode error) {
  return folly::variant_match(
      errorCode.first,
      [&](ApplicationErrorCode err) { return err == error; },
      [](auto) { return false; });
}

MATCHER_P(IsAppError, error, "") {
  return matchAppError(arg, error);
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
  return helper(conn.outstandingPackets);
}

std::deque<OutstandingPacket>::reverse_iterator getLastOutstandingPacket(
    QuicConnectionStateBase& conn,
    PacketNumberSpace packetNumberSpace);

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
    bool pureAck = false,
    TimePoint sentTime = Clock::now());

// TODO: The way we setup packet sent, ack, loss in test cases can use some
// major refactor.
CongestionController::AckEvent makeAck(
    PacketNum seq,
    uint64_t ackedSize,
    TimePoint ackedTime,
    TimePoint sendTime);

folly::IOBufQueue bufToQueue(Buf buf);

StatelessResetToken generateStatelessResetToken();

std::array<uint8_t, kStatelessResetTokenSecretLength> getRandSecret();

} // namespace test
} // namespace quic
