/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <quic/fizz/handshake/HaberdasheryAead.h>

#include <fizz/protocol/Types.h>
#include <fmt/format.h>
#include <folly/portability/GTest.h>
#include <quic/fizz/handshake/FizzBridge.h>
#include <quic/fizz/handshake/QuicFizzFactory.h>

namespace quic::test {

namespace {

constexpr folly::StringPiece kPlaintext = "hello quic packet protection";
constexpr folly::StringPiece kHeader = "packet header";
constexpr uint64_t kSeqNum = 42;
constexpr size_t kTagLength = 16;

std::unique_ptr<fizz::Aead> makeFizzAead(
    fizz::CipherSuite suite,
    size_t keyLength) {
  std::unique_ptr<fizz::Aead> aead;
  fizz::Error err;
  FIZZ_THROW_ON_ERROR(QuicFizzFactory().makeAead(aead, err, suite), err);
  fizz::TrafficKey key;
  key.key = folly::IOBuf::copyBuffer(std::string(keyLength, '\x42'));
  key.iv = folly::IOBuf::copyBuffer(std::string(12, '\x01'));
  FIZZ_THROW_ON_ERROR(aead->setKey(err, std::move(key)), err);
  return aead;
}

std::unique_ptr<fizz::Aead> makeAes128Gcm() {
  return makeFizzAead(fizz::CipherSuite::TLS_AES_128_GCM_SHA256, 16);
}

BufPtr makePlaintext(size_t length) {
  auto buf = folly::IOBuf::create(length + kTagLength);
  for (size_t i = 0; i < length; ++i) {
    buf->writableTail()[i] = static_cast<uint8_t>(i);
  }
  buf->append(length);
  return buf;
}

BufPtr encrypt(
    const Aead& aead,
    BufPtr plaintext,
    folly::StringPiece header,
    uint64_t seqNum) {
  auto result = aead.inplaceEncrypt(
      std::move(plaintext), folly::IOBuf::copyBuffer(header).get(), seqNum);
  EXPECT_TRUE(result.has_value()) << result.error().message;
  return std::move(result.value());
}

BufPtr encrypt(const Aead& aead) {
  return encrypt(
      aead,
      folly::IOBuf::copyBuffer(kPlaintext, /*headroom=*/0, kTagLength),
      kHeader,
      kSeqNum);
}

std::string toString(const BufPtr& buf) {
  return buf->clone()->moveToFbString().toStdString();
}

class HaberdasheryAeadTest : public testing::Test {
 protected:
  void SetUp() override {
    if (HaberdasheryAead::supportedImplementations().empty()) {
      GTEST_SKIP() << "no haberdashery implementation supports this CPU";
    }
  }
};

} // namespace

TEST_F(HaberdasheryAeadTest, WrapsAes128Gcm) {
  const auto aead = HaberdasheryAead::wrap(makeAes128Gcm());

  ASSERT_NE(aead, nullptr);
  EXPECT_EQ(dynamic_cast<FizzAead*>(aead.get()), nullptr);
}

TEST_F(HaberdasheryAeadTest, EncryptMatchesFizz) {
  const auto aead = HaberdasheryAead::wrap(makeAes128Gcm());
  const auto fizzAead = FizzAead::wrap(makeAes128Gcm());

  EXPECT_EQ(toString(encrypt(*aead)), toString(encrypt(*fizzAead)));
}

TEST_F(HaberdasheryAeadTest, DecryptsFizzCiphertext) {
  const auto aead = HaberdasheryAead::wrap(makeAes128Gcm());
  auto ciphertext = encrypt(*FizzAead::wrap(makeAes128Gcm()));

  const auto plaintext = aead->tryDecrypt(
      std::move(ciphertext), folly::IOBuf::copyBuffer(kHeader).get(), kSeqNum);

  ASSERT_TRUE(plaintext.has_value());
  EXPECT_EQ(toString(*plaintext), kPlaintext);
}

TEST_F(HaberdasheryAeadTest, EveryImplementationMatchesFizz) {
  const auto fizzAead = FizzAead::wrap(makeAes128Gcm());
  const std::string longHeader(64, 'h');
  const std::vector<folly::StringPiece> headers = {
      "", "h", kHeader, longHeader};
  const std::vector<size_t> lengths = {
      0, 1, 15, 16, 17, 255, 256, 1200, 1452, 16384};
  const std::vector<uint64_t> seqNums = {0, kSeqNum, 1ULL << 62};

  for (const auto name : HaberdasheryAead::supportedImplementations()) {
    const auto aead = HaberdasheryAead::wrapWith(name, *makeAes128Gcm());
    ASSERT_NE(aead, nullptr) << name;
    for (const auto header : headers) {
      for (const auto length : lengths) {
        for (const auto seqNum : seqNums) {
          SCOPED_TRACE(
              fmt::format(
                  "{} header={} length={} seqNum={}",
                  name,
                  header.size(),
                  length,
                  seqNum));
          auto ciphertext =
              encrypt(*aead, makePlaintext(length), header, seqNum);
          EXPECT_EQ(
              toString(ciphertext),
              toString(
                  encrypt(*fizzAead, makePlaintext(length), header, seqNum)));

          const auto plaintext = aead->tryDecrypt(
              std::move(ciphertext),
              folly::IOBuf::copyBuffer(header).get(),
              seqNum);
          ASSERT_TRUE(plaintext.has_value());
          EXPECT_EQ(toString(*plaintext), toString(makePlaintext(length)));
        }
      }
    }
  }
}

TEST_F(HaberdasheryAeadTest, EveryImplementationRejectsTamperedCiphertext) {
  for (const auto name : HaberdasheryAead::supportedImplementations()) {
    const auto aead = HaberdasheryAead::wrapWith(name, *makeAes128Gcm());
    ASSERT_NE(aead, nullptr) << name;
    auto ciphertext = encrypt(*aead);
    ciphertext->writableData()[0] ^= 0x01;

    EXPECT_FALSE(aead->tryDecrypt(
                         std::move(ciphertext),
                         folly::IOBuf::copyBuffer(kHeader).get(),
                         kSeqNum)
                     .has_value())
        << name;
  }
}

TEST_F(HaberdasheryAeadTest, WrapWithRejectsUnknownName) {
  EXPECT_EQ(HaberdasheryAead::wrapWith("unknown", *makeAes128Gcm()), nullptr);
}

TEST(HaberdasheryAeadFallbackTest, Aes256GcmUsesFizz) {
  const auto aead = HaberdasheryAead::wrap(
      makeFizzAead(fizz::CipherSuite::TLS_AES_256_GCM_SHA384, 32));

  EXPECT_NE(dynamic_cast<FizzAead*>(aead.get()), nullptr);
}

TEST(HaberdasheryAeadFallbackTest, WrapReturnsNullForNull) {
  EXPECT_EQ(HaberdasheryAead::wrap(nullptr), nullptr);
}

} // namespace quic::test
