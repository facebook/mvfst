/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <quic/codec/PacketNumber.h>

#include <folly/portability/GTest.h>
#include <quic/codec/Types.h>

using namespace testing;

namespace quic {
namespace test {

struct Packet8DecodeData {
  PacketNum largestReceivedPacketNum;
  uint8_t encoded;
  PacketNum expected;
};

struct Packet16DecodeData {
  PacketNum largestReceivedPacketNum;
  uint16_t encoded;
  PacketNum expected;
};

struct Packet32DecodeData {
  PacketNum largestReceivedPacketNum;
  uint32_t encoded;
  PacketNum expected;
};

class Packet8DecodeTest : public TestWithParam<Packet8DecodeData> {};
class Packet16DecodeTest : public TestWithParam<Packet16DecodeData> {};
class Packet32DecodeTest : public TestWithParam<Packet32DecodeData> {};

TEST_P(Packet8DecodeTest, Decode) {
  EXPECT_EQ(
      GetParam().expected,
      decodePacketNumber(
          GetParam().encoded,
          sizeof(GetParam().encoded),
          GetParam().largestReceivedPacketNum + 1));
}

TEST_P(Packet16DecodeTest, Decode) {
  EXPECT_EQ(
      GetParam().expected,
      decodePacketNumber(
          GetParam().encoded,
          sizeof(GetParam().encoded),
          GetParam().largestReceivedPacketNum + 1));
}

TEST_P(Packet32DecodeTest, Decode) {
  auto decoded = decodePacketNumber(
      GetParam().encoded,
      sizeof(GetParam().encoded),
      GetParam().largestReceivedPacketNum + 1);
  EXPECT_EQ(GetParam().expected, decoded) << std::hex << decoded;
}

INSTANTIATE_TEST_SUITE_P(
    Packet8DecodeTests,
    Packet8DecodeTest,
    Values(
        Packet8DecodeData{0xaa82f30e, 0x94, 0xaa82f294},
        Packet8DecodeData{0xaa82f3fe, 0xff, 0xaa82f3ff},
        Packet8DecodeData{0xaa82ffff, 0x01, 0xaa830001},
        Packet8DecodeData{0xaa82fffe, 0x01, 0xaa830001}));

INSTANTIATE_TEST_SUITE_P(
    Packet16DecodeTests,
    Packet16DecodeTest,
    Values(
        Packet16DecodeData{0xaa82f30e, 0x1f94, 0xaa831f94},
        Packet16DecodeData{0x10000, 0x9000, 0x9000},
        Packet16DecodeData{0x10000, 0x8000, 0x18000},
        Packet16DecodeData{0xffff, 0x8000, 0x18000},
        Packet16DecodeData{0xf20000, 0xffff, 0xf1ffff},
        Packet16DecodeData{0x0fff00f, 0x0000, 0x1000000},
        Packet16DecodeData{0x001f, 0x010f, 0x010f},
        Packet16DecodeData{0x001f, 0x000f, 0x000f},
        Packet16DecodeData{0x0001, 0x0fff, 0x0fff},
        Packet16DecodeData{0x0001, 0x0002, 0x0002},
        Packet16DecodeData{0x10000, 0x0001, 0x10001},
        Packet16DecodeData{0xaa82f30e, 0x9b3, 0xaa8309b3},
        Packet16DecodeData{0xa82f30ea, 0x9b32, 0xa82f9b32}));

INSTANTIATE_TEST_SUITE_P(
    Packet32DecodeTests,
    Packet32DecodeTest,
    Values(
        Packet32DecodeData{0xaa82f30e, 0x0094f30e, 0x10094f30e},
        Packet32DecodeData{0xbcaa82f30e, 0x00000000, 0xbd00000000},
        Packet32DecodeData{0xbcaa82f30e, 0xaa82f30f, 0xbcaa82f30f}));

class EncodingTest : public Test {};

TEST_F(EncodingTest, Draft17Example) {
  EXPECT_EQ(2, encodePacketNumber(0xac5c02, 0xabe8bc).length);
  EXPECT_EQ(3, encodePacketNumber(0xace8fe, 0xabe8bc).length);
}

} // namespace test
} // namespace quic
