/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <folly/portability/GTest.h>

#include <fizz/record/Types.h>
#include <quic/fizz/handshake/FizzCryptoFactory.h>
#include <quic/fizz/handshake/FizzPacketNumberCipher.h>

#include <quic/common/StringUtils.h>

using namespace testing;

namespace quic::test {

struct HeaderParams {
  fizz::CipherSuite cipher;
  folly::StringPiece key;
  folly::StringPiece sample;
  folly::StringPiece packetNumberBytes;
  folly::StringPiece initialByte;
  folly::StringPiece decryptedPacketNumberBytes;
  folly::StringPiece decryptedInitialByte;
};

// TODO: add tests for short headers.
class LongPacketNumberCipherTest : public TestWithParam<HeaderParams> {
 public:
  void SetUp() override {}
};

template <typename Array>
Array hexToBytes(const folly::StringPiece hex) {
  auto bytesStringOpt = quic::unhexlify(std::string(hex));
  CHECK(bytesStringOpt.has_value()) << "Failed to unhexlify: " << hex;
  auto bytesString = bytesStringOpt.value();
  Array bytes;
  memcpy(bytes.data(), bytesString.data(), bytes.size());
  return bytes;
}

using SampleBytes = std::array<uint8_t, 16>;
using InitialByte = std::array<uint8_t, 1>;
using PacketNumberBytes = std::array<uint8_t, 4>;

struct CipherBytes {
  SampleBytes sample;
  InitialByte initial;
  PacketNumberBytes packetNumber;

  explicit CipherBytes(
      const folly::StringPiece sampleHex,
      const folly::StringPiece initialHex,
      const folly::StringPiece packetNumberHex)
      : sample(hexToBytes<SampleBytes>(sampleHex)),
        initial(hexToBytes<InitialByte>(initialHex)),
        packetNumber(hexToBytes<PacketNumberBytes>(packetNumberHex)) {}
};

TEST_P(LongPacketNumberCipherTest, TestEncryptDecrypt) {
  FizzCryptoFactory cryptoFactory;
  auto cipherResult = cryptoFactory.makePacketNumberCipher(GetParam().cipher);
  ASSERT_FALSE(cipherResult.hasError());
  auto cipher = std::move(cipherResult.value());
  auto keyOpt = quic::unhexlify(std::string(GetParam().key));
  CHECK(keyOpt.has_value()) << "Failed to unhexlify key: " << GetParam().key;
  auto key = keyOpt.value();
  EXPECT_EQ(cipher->keyLength(), key.size());
  auto setKeyResult = cipher->setKey(folly::range(key));
  ASSERT_FALSE(setKeyResult.hasError());
  EXPECT_TRUE(!memcmp(cipher->getKey()->data(), key.c_str(), key.size()));
  CipherBytes cipherBytes(
      GetParam().sample,
      GetParam().decryptedInitialByte,
      GetParam().decryptedPacketNumberBytes);
  auto encryptResult = cipher->encryptLongHeader(
      cipherBytes.sample,
      folly::range(cipherBytes.initial),
      folly::range(cipherBytes.packetNumber));
  ASSERT_FALSE(encryptResult.hasError());
  EXPECT_EQ(
      quic::hexlify(std::string(
          reinterpret_cast<const char*>(cipherBytes.initial.data()),
          cipherBytes.initial.size())),
      GetParam().initialByte);
  EXPECT_EQ(
      quic::hexlify(std::string(
          reinterpret_cast<const char*>(cipherBytes.packetNumber.data()),
          cipherBytes.packetNumber.size())),
      GetParam().packetNumberBytes);
  auto decryptResult = cipher->decryptLongHeader(
      cipherBytes.sample,
      folly::range(cipherBytes.initial),
      folly::range(cipherBytes.packetNumber));
  ASSERT_FALSE(decryptResult.hasError());
  EXPECT_EQ(
      quic::hexlify(std::string(
          reinterpret_cast<const char*>(cipherBytes.initial.data()),
          cipherBytes.initial.size())),
      GetParam().decryptedInitialByte);
  EXPECT_EQ(
      quic::hexlify(std::string(
          reinterpret_cast<const char*>(cipherBytes.packetNumber.data()),
          cipherBytes.packetNumber.size())),
      GetParam().decryptedPacketNumberBytes);
}

INSTANTIATE_TEST_SUITE_P(
    LongPacketNumberCipherTests,
    LongPacketNumberCipherTest,
    ::testing::Values(
        HeaderParams{
            fizz::CipherSuite::TLS_AES_128_GCM_SHA256,
            folly::StringPiece{"0edd982a6ac527f2eddcbb7348dea5d7"},
            folly::StringPiece{"0000f3a694c75775b4e546172ce9e047"},
            folly::StringPiece{"0dbc195a"},
            folly::StringPiece{"c1"},
            folly::StringPiece{"00000002"},
            folly::StringPiece{"c3"}},
        HeaderParams{
            fizz::CipherSuite::TLS_AES_128_GCM_SHA256,
            folly::StringPiece{"94b9452d2b3c7c7f6da7fdd8593537fd"},
            folly::StringPiece{"c4c2a2303d297e3c519bf6b22386e3d0"},
            folly::StringPiece{"f7ed5f01"},
            folly::StringPiece{"c4"},
            folly::StringPiece{"00015f01"},
            folly::StringPiece{"c1"}},
        HeaderParams{
            fizz::CipherSuite::TLS_AES_256_GCM_SHA384,
            folly::StringPiece{
                "0edd982a6ac527f2eddcbb7348dea5d70edd982a6ac527f2eddcbb7348dea5d7"},
            folly::StringPiece{"0000f3a694c75775b4e546172ce9e047"},
            folly::StringPiece{"664d195a"},
            folly::StringPiece{"c7"},
            folly::StringPiece{"7d51195a"},
            folly::StringPiece{"c9"}},
        HeaderParams{
            fizz::CipherSuite::TLS_AES_256_GCM_SHA384,
            folly::StringPiece{
                "94b9452d2b3c7c7f6da7fdd8593537fd0edd982a6ac527f2eddcbb7348dea5d7"},
            folly::StringPiece{"c4c2a2303d297e3c519bf6b22386e3d0"},
            folly::StringPiece{"2e2fad01"},
            folly::StringPiece{"c8"},
            folly::StringPiece{"772aa701"},
            folly::StringPiece{"ce"}}));

} // namespace quic::test
