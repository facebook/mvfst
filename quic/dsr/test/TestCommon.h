/*
 * Copyright (c) Facebook, Inc. and its affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 *
 */

#include <folly/portability/GTest.h>
#include <quic/common/test/TestUtils.h>
#include <quic/dsr/Scheduler.h>
#include <quic/dsr/test/Mocks.h>
#include <quic/fizz/server/handshake/FizzServerQuicHandshakeContext.h>
#include <quic/server/state/ServerStateMachine.h>
#include <algorithm>

namespace quic::test {

std::unique_ptr<folly::IOBuf> getProtectionKey() {
  FizzCryptoFactory factory;
  auto secret = folly::range(test::getRandSecret());
  auto pnCipher =
      factory.makePacketNumberCipher(fizz::CipherSuite::TLS_AES_128_GCM_SHA256);
  auto deriver = factory.getFizzFactory()->makeKeyDeriver(
      fizz::CipherSuite::TLS_AES_128_GCM_SHA256);
  return deriver->expandLabel(
      secret, kQuicPNLabel, folly::IOBuf::create(0), pnCipher->keyLength());
}

TrafficKey getQuicTestKey() {
  TrafficKey testKey;
  testKey.key = folly::IOBuf::copyBuffer(
      folly::unhexlify("000102030405060708090A0B0C0D0E0F"));
  testKey.iv =
      folly::IOBuf::copyBuffer(folly::unhexlify("000102030405060708090A0B"));
  return testKey;
}

class DSRCommonTestFixture : public testing::Test {
 public:
  DSRCommonTestFixture()
      : conn_(FizzServerQuicHandshakeContext::Builder().build()),
        scheduler_(conn_),
        aead_(createNoOpAead()) {
    conn_.clientConnectionId = getTestConnectionId(0);
    conn_.serverConnectionId = getTestConnectionId(1);
    auto mockHeaderCipher = std::make_unique<MockPacketNumberCipher>();
    packetProtectionKey_ = getProtectionKey();
    EXPECT_CALL(*mockHeaderCipher, getKey())
        .WillRepeatedly(testing::ReturnRef(packetProtectionKey_));
    conn_.oneRttWriteHeaderCipher = std::move(mockHeaderCipher);
    auto mockCipher = std::make_unique<MockAead>();
    EXPECT_CALL(*mockCipher, getKey()).WillRepeatedly(testing::Invoke([] {
      return getQuicTestKey();
    }));
    conn_.oneRttWriteCipher = std::move(mockCipher);

    ON_CALL(sender_, addSendInstruction(testing::_))
        .WillByDefault(testing::Invoke([&](const SendInstruction& instruction) {
          pendingInstructions_.push_back(instruction);
          instructionCounter_++;
          return true;
        }));
    ON_CALL(sender_, flush()).WillByDefault(testing::Return(true));

    serverHandshake_ = std::make_unique<FakeServerHandshake>(
        conn_,
        FizzServerQuicHandshakeContext::Builder()
            .setFizzServerContext(createServerCtx())
            .build());
    serverHandshake_->setCipherSuite(fizz::CipherSuite::TLS_AES_128_GCM_SHA256);
    conn_.serverHandshakeLayer = serverHandshake_.get();
    conn_.handshakeLayer = std::move(serverHandshake_);
  }

 protected:
  void prepareFlowControlAndStreamLimit() {
    conn_.flowControlState.peerAdvertisedInitialMaxStreamOffsetBidiLocal =
        kDefaultStreamWindowSize;
    conn_.flowControlState.peerAdvertisedInitialMaxStreamOffsetBidiRemote =
        kDefaultStreamWindowSize;
    conn_.flowControlState.peerAdvertisedInitialMaxStreamOffsetUni =
        kDefaultStreamWindowSize;
    conn_.flowControlState.peerAdvertisedMaxOffset =
        kDefaultConnectionWindowSize;
    conn_.streamManager->setMaxLocalBidirectionalStreams(
        kDefaultMaxStreamsBidirectional);
    conn_.streamManager->setMaxLocalUnidirectionalStreams(
        kDefaultMaxStreamsUnidirectional);
  }

  StreamId prepareOneStream(size_t bufMetaLength = 1000) {
    conn_.streamManager->setMaxLocalBidirectionalStreams(
        kDefaultMaxStreamsBidirectional);
    conn_.streamManager->setMaxLocalUnidirectionalStreams(
        kDefaultMaxStreamsUnidirectional);
    auto id = conn_.streamManager->createNextBidirectionalStream().value()->id;
    auto stream = conn_.streamManager->findStream(id);
    writeDataToQuicStream(
        *stream,
        folly::IOBuf::copyBuffer("MetroCard Customer Claims"),
        false /* eof */);
    BufferMeta bufMeta(bufMetaLength);
    writeBufMetaToQuicStream(*stream, bufMeta, true /* eof */);
    return id;
  }

  bool verifyAllOutstandingsAreDSR() const {
    return std::all_of(
        conn_.outstandings.packets.begin(),
        conn_.outstandings.packets.end(),
        [](const OutstandingPacket& packet) { return packet.isDSRPacket; });
  }

 protected:
  QuicServerConnectionState conn_;
  DSRStreamFrameScheduler scheduler_;
  std::unique_ptr<Aead> aead_;
  MockDSRPacketizationRequestSender sender_;
  size_t instructionCounter_{0};
  std::vector<SendInstruction> pendingInstructions_;
  Buf packetProtectionKey_;
  std::unique_ptr<FakeServerHandshake> serverHandshake_;
};
} // namespace quic::test
