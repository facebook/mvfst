/*
 * Copyright (c) Facebook, Inc. and its affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 *
 */

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <quic/codec/QuicConnectionId.h>
#include <quic/common/test/TestUtils.h>
#include <quic/handshake/HandshakeLayer.h>
#include <quic/handshake/QuicFizzFactory.h>
#include <quic/handshake/test/Mocks.h>
#include <vector>

using namespace folly;
using namespace testing;

namespace quic {
namespace test {

class QuicTestFizzFactory : public QuicFizzFactory {
 public:
  ~QuicTestFizzFactory() override = default;

  std::unique_ptr<fizz::Aead> makeAead(fizz::CipherSuite) const override {
    return std::move(aead_);
  }

  std::unique_ptr<PacketNumberCipher> makePacketNumberCipher(
      fizz::CipherSuite) const override {
    return std::move(packetNumberCipher_);
  }

  void setMockAead(std::unique_ptr<fizz::Aead> aead) {
    aead_ = std::move(aead);
  }

  void setMockPacketNumberCipher(
      std::unique_ptr<MockPacketNumberCipher> packetNumberCipher) {
    packetNumberCipher_ = std::move(packetNumberCipher);
  }

  mutable std::unique_ptr<fizz::Aead> aead_;
  mutable std::unique_ptr<MockPacketNumberCipher> packetNumberCipher_;
};

class HandshakeLayerTest : public Test {
 public:
  std::unique_ptr<fizz::test::MockAead> createMockAead() {
    auto mockAead = std::make_unique<StrictMock<fizz::test::MockAead>>();
    EXPECT_CALL(*mockAead, _setKey(_)).WillOnce(Invoke([&](auto& trafficKey) {
      trafficKey_ = std::move(trafficKey);
    }));
    EXPECT_CALL(*mockAead, keyLength())
        .WillRepeatedly(Return(fizz::AESGCM128::kKeyLength));
    EXPECT_CALL(*mockAead, ivLength())
        .WillRepeatedly(Return(fizz::AESGCM128::kIVLength));
    return mockAead;
  }

  std::unique_ptr<MockPacketNumberCipher> createMockPacketNumberCipher() {
    auto mockPacketNumberCipher = std::make_unique<MockPacketNumberCipher>();
    EXPECT_CALL(*mockPacketNumberCipher, setKey(_))
        .WillOnce(Invoke([&](folly::ByteRange key) {
          packetCipherKey_ = folly::IOBuf::copyBuffer(key);
        }));
    EXPECT_CALL(*mockPacketNumberCipher, keyLength())
        .WillRepeatedly(Return(fizz::AESGCM128::kKeyLength));
    return mockPacketNumberCipher;
  }

  folly::Optional<fizz::TrafficKey> trafficKey_;
  folly::Optional<std::unique_ptr<folly::IOBuf>> packetCipherKey_;
};

TEST_F(HandshakeLayerTest, TestDraft17ClearTextCipher) {
  // test vector taken from
  // https://github.com/quicwg/base-drafts/wiki/Test-Vector-for-the-Clear-Text-AEAD-key-derivation
  auto connid = folly::unhexlify("c654efd8a31b4792");
  std::vector<uint8_t> destinationConnidVector;
  for (size_t i = 0; i < connid.size(); ++i) {
    destinationConnidVector.push_back(connid.data()[i]);
  }
  ConnectionId destinationConnid(destinationConnidVector);
  QuicTestFizzFactory factory;
  factory.setMockAead(createMockAead());
  auto aead = getClientInitialCipher(
      &factory, destinationConnid, QuicVersion::MVFST_OLD);

  std::string expectedKey = "86d1830480b40f86cf9d68dcadf35dfe";
  std::string expectedIv = "12f3938aca34aa02543163d4";
  auto trafficKeyHex = folly::hexlify(trafficKey_->key->coalesce());
  auto trafficIvHex = folly::hexlify(trafficKey_->iv->coalesce());
  EXPECT_EQ(trafficKeyHex, expectedKey);
  EXPECT_EQ(trafficIvHex, expectedIv);
}

TEST_F(HandshakeLayerTest, TestPacketEncryptionKey) {
  QuicTestFizzFactory factory;
  factory.setMockPacketNumberCipher(createMockPacketNumberCipher());
  auto clientKey = std::vector<uint8_t>(
      {0x0c, 0x74, 0xbb, 0x95, 0xa1, 0x04, 0x8e, 0x52, 0xef, 0x3b, 0x72,
       0xe1, 0x28, 0x89, 0x35, 0x1c, 0xd7, 0x3a, 0x55, 0x0f, 0xb6, 0x2c,
       0x4b, 0xb0, 0x87, 0xe9, 0x15, 0xcc, 0xe9, 0x6c, 0xe3, 0xa0});
  auto expectedHex = "cd253a36ff93937c469384a823af6c56";
  auto packetCipher = makePacketNumberCipher(
      &factory,
      folly::range(clientKey),
      fizz::CipherSuite::TLS_AES_128_GCM_SHA256);
  auto secretHex = folly::hexlify(packetCipherKey_.value()->coalesce());
  EXPECT_EQ(secretHex, expectedHex);

  // reset the cipher
  factory.setMockPacketNumberCipher(createMockPacketNumberCipher());
  auto serverKey = std::vector<uint8_t>(
      {0x4c, 0x9e, 0xdf, 0x24, 0xb0, 0xe5, 0xe5, 0x06, 0xdd, 0x3b, 0xfa,
       0x4e, 0x0a, 0x03, 0x11, 0xe8, 0xc4, 0x1f, 0x35, 0x42, 0x73, 0xd8,
       0xcb, 0x49, 0xdd, 0xd8, 0x46, 0x41, 0x38, 0xd4, 0x7e, 0xc6});

  auto expectedKey2 = "2579d8696f85eda68d3502b65596586b";

  auto packetCipher2 = makePacketNumberCipher(
      &factory,
      folly::range(serverKey),
      fizz::CipherSuite::TLS_AES_128_GCM_SHA256);
  auto secretHex2 = folly::hexlify(packetCipherKey_.value()->coalesce());
  EXPECT_EQ(secretHex2, expectedKey2);
}
} // namespace test
} // namespace quic
