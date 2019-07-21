/*
 * Copyright (c) Facebook, Inc. and its affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 *
 */

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <quic/common/test/TestUtils.h>
#include <quic/handshake/FizzCryptoFactory.h>
#include <quic/handshake/QuicFizzFactory.h>
#include <quic/handshake/test/Mocks.h>

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

  void setMockAead(std::unique_ptr<fizz::Aead> aead) {
    aead_ = std::move(aead);
  }

  mutable std::unique_ptr<fizz::Aead> aead_;
};

class FizzCryptoFactoryTest : public Test {
public:
  std::unique_ptr<fizz::test::MockAead> createMockAead() {
    auto mockAead = std::make_unique<StrictMock<fizz::test::MockAead>>();
    EXPECT_CALL(*mockAead, _setKey(_)).WillOnce(Invoke([&](auto &trafficKey) {
      trafficKey_ = std::move(trafficKey);
    }));
    EXPECT_CALL(*mockAead, keyLength())
        .WillRepeatedly(Return(fizz::AESGCM128::kKeyLength));
    EXPECT_CALL(*mockAead, ivLength())
        .WillRepeatedly(Return(fizz::AESGCM128::kIVLength));
    return mockAead;
  }

  folly::Optional<fizz::TrafficKey> trafficKey_;
};

TEST_F(FizzCryptoFactoryTest, TestDraft17ClearTextCipher) {
  // test vector taken from
  // https://github.com/quicwg/base-drafts/wiki/Test-Vector-for-the-Clear-Text-AEAD-key-derivation
  auto connid = folly::unhexlify("c654efd8a31b4792");
  std::vector<uint8_t> destinationConnidVector;
  for (size_t i = 0; i < connid.size(); ++i) {
    destinationConnidVector.push_back(connid.data()[i]);
  }
  ConnectionId destinationConnid(destinationConnidVector);
  QuicTestFizzFactory fizzFactory;
  fizzFactory.setMockAead(createMockAead());
  FizzCryptoFactory cryptoFactory(&fizzFactory);
  auto aead = cryptoFactory.getClientInitialCipher(destinationConnid,
                                                   QuicVersion::MVFST_OLD);

  std::string expectedKey = "86d1830480b40f86cf9d68dcadf35dfe";
  std::string expectedIv = "12f3938aca34aa02543163d4";
  auto trafficKeyHex = folly::hexlify(trafficKey_->key->coalesce());
  auto trafficIvHex = folly::hexlify(trafficKey_->iv->coalesce());
  EXPECT_EQ(trafficKeyHex, expectedKey);
  EXPECT_EQ(trafficIvHex, expectedIv);
}

} // namespace test
} // namespace quic