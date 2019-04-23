/*
 * Copyright (c) Facebook, Inc. and its affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 *
 */

#include <folly/portability/GTest.h>

#include <quic/codec/PacketNumberCipher.h>

#include <folly/String.h>

using namespace testing;

namespace quic {
namespace test {

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
  void SetUp() override {}

 protected:
  Aes128PacketNumberCipher cipher_;
};

TEST_P(LongPacketNumberCipherTest, TestDecrypt) {
  auto key = folly::unhexlify(GetParam().key);
  cipher_.setKey(folly::range(key));
  std::array<uint8_t, 1> initialByte;
  std::array<uint8_t, 16> sample;
  std::array<uint8_t, 4> packetNumberBytes;

  auto initialByteString = folly::unhexlify(GetParam().initialByte);
  auto sampleString = folly::unhexlify(GetParam().sample);
  auto packetNumberBytesString = folly::unhexlify(GetParam().packetNumberBytes);

  memcpy(initialByte.data(), initialByteString.data(), initialByte.size());
  memcpy(sample.data(), sampleString.data(), sample.size());
  memcpy(
      packetNumberBytes.data(),
      packetNumberBytesString.data(),
      packetNumberBytes.size());

  cipher_.decryptLongHeader(
      sample, folly::range(initialByte), folly::range(packetNumberBytes));

  EXPECT_EQ(
      folly::hexlify(packetNumberBytes), GetParam().decryptedPacketNumberBytes);
  EXPECT_EQ(folly::hexlify(initialByte), GetParam().decryptedInitialByte);

  memcpy(initialByte.data(), initialByteString.data(), initialByte.size());
  memcpy(sample.data(), sampleString.data(), sample.size());
  memcpy(
      packetNumberBytes.data(),
      packetNumberBytesString.data(),
      packetNumberBytes.size());
  cipher_.decryptLongHeader(
      sample, folly::range(initialByte), folly::range(packetNumberBytes));

  EXPECT_EQ(
      folly::hexlify(packetNumberBytes), GetParam().decryptedPacketNumberBytes);
  EXPECT_EQ(folly::hexlify(initialByte), GetParam().decryptedInitialByte);
}

TEST_P(LongPacketNumberCipherTest, TestEncrypt) {
  auto key = folly::unhexlify(GetParam().key);
  cipher_.setKey(folly::range(key));
  std::array<uint8_t, 1> initialByte;
  std::array<uint8_t, 16> sample;
  std::array<uint8_t, 4> packetNumberBytes;

  auto initialByteString = folly::unhexlify(GetParam().decryptedInitialByte);
  auto sampleString = folly::unhexlify(GetParam().sample);
  auto packetNumberBytesString =
      folly::unhexlify(GetParam().decryptedPacketNumberBytes);

  memcpy(initialByte.data(), initialByteString.data(), initialByte.size());
  memcpy(sample.data(), sampleString.data(), sample.size());
  memcpy(
      packetNumberBytes.data(),
      packetNumberBytesString.data(),
      packetNumberBytes.size());

  cipher_.encryptLongHeader(
      sample, folly::range(initialByte), folly::range(packetNumberBytes));

  EXPECT_EQ(folly::hexlify(packetNumberBytes), GetParam().packetNumberBytes);
  EXPECT_EQ(folly::hexlify(initialByte), GetParam().initialByte);

  memcpy(initialByte.data(), initialByteString.data(), initialByte.size());
  memcpy(sample.data(), sampleString.data(), sample.size());
  memcpy(
      packetNumberBytes.data(),
      packetNumberBytesString.data(),
      packetNumberBytes.size());
  cipher_.encryptLongHeader(
      sample, folly::range(initialByte), folly::range(packetNumberBytes));

  EXPECT_EQ(folly::hexlify(packetNumberBytes), GetParam().packetNumberBytes);
  EXPECT_EQ(folly::hexlify(initialByte), GetParam().initialByte);
}

INSTANTIATE_TEST_CASE_P(
    LongPacketNumberCipherTests,
    LongPacketNumberCipherTest,
    ::testing::Values(
        HeaderParams{folly::StringPiece{"0edd982a6ac527f2eddcbb7348dea5d7"},
                     folly::StringPiece{"0000f3a694c75775b4e546172ce9e047"},
                     folly::StringPiece{"0dbc195a"},
                     folly::StringPiece{"c1"},
                     folly::StringPiece{"00000002"},
                     folly::StringPiece{"c3"}},
        HeaderParams{folly::StringPiece{"94b9452d2b3c7c7f6da7fdd8593537fd"},
                     folly::StringPiece{"c4c2a2303d297e3c519bf6b22386e3d0"},
                     folly::StringPiece{"f7ed5f01"},
                     folly::StringPiece{"c4"},
                     folly::StringPiece{"00015f01"},
                     folly::StringPiece{"c1"}}));
} // namespace test
} // namespace quic
