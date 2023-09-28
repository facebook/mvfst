/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <folly/Random.h>
#include <folly/String.h>
#include <folly/portability/GTest.h>
#include <quic/mbed/MbedPacketNumCipher.h>

using namespace testing;

// copied over from quic/fizz/handshake/test/FizzPacketNumberCipherTest.cpp
namespace quic::test {

struct HeaderParams {
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
  void SetUp() override {
    // set up a random 128-bit key initally to verify
    // mbedtls_cipher_reset works as expected
    std::array<uint8_t, 16> randKey;
    folly::Random::secureRandom(randKey.data(), randKey.size());
    cipher_.setKey(folly::Range(randKey.data(), randKey.size()));
  }

  MbedPacketNumCipher cipher_{quic::CipherType::AESGCM128};
};

template <typename Array>
Array hexToBytes(const folly::StringPiece hex) {
  auto bytesString = folly::unhexlify(hex);
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
  auto key = folly::unhexlify(GetParam().key);
  EXPECT_EQ(cipher_.keyLength(), key.size());
  cipher_.setKey(folly::range(key));
  EXPECT_TRUE(!memcmp(cipher_.getKey()->data(), key.c_str(), key.size()));
  CipherBytes cipherBytes(
      GetParam().sample,
      GetParam().decryptedInitialByte,
      GetParam().decryptedPacketNumberBytes);
  cipher_.encryptLongHeader(
      cipherBytes.sample,
      folly::range(cipherBytes.initial),
      folly::range(cipherBytes.packetNumber));
  EXPECT_EQ(folly::hexlify(cipherBytes.initial), GetParam().initialByte);
  EXPECT_EQ(
      folly::hexlify(cipherBytes.packetNumber), GetParam().packetNumberBytes);
  cipher_.decryptLongHeader(
      cipherBytes.sample,
      folly::range(cipherBytes.initial),
      folly::range(cipherBytes.packetNumber));
  EXPECT_EQ(
      folly::hexlify(cipherBytes.initial), GetParam().decryptedInitialByte);
  EXPECT_EQ(
      folly::hexlify(cipherBytes.packetNumber),
      GetParam().decryptedPacketNumberBytes);
}

INSTANTIATE_TEST_SUITE_P(
    LongPacketNumberCipherTests,
    LongPacketNumberCipherTest,
    ::testing::Values(
        HeaderParams{
            folly::StringPiece{"0edd982a6ac527f2eddcbb7348dea5d7"},
            folly::StringPiece{"0000f3a694c75775b4e546172ce9e047"},
            folly::StringPiece{"0dbc195a"},
            folly::StringPiece{"c1"},
            folly::StringPiece{"00000002"},
            folly::StringPiece{"c3"}},
        HeaderParams{
            folly::StringPiece{"94b9452d2b3c7c7f6da7fdd8593537fd"},
            folly::StringPiece{"c4c2a2303d297e3c519bf6b22386e3d0"},
            folly::StringPiece{"f7ed5f01"},
            folly::StringPiece{"c4"},
            folly::StringPiece{"00015f01"},
            folly::StringPiece{"c1"}}));

} // namespace quic::test
