/*
 * Copyright (c) Facebook, Inc. and its affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 *
 */

#include <quic/codec/QuicConnectionId.h>

#include <iterator>

#include <folly/portability/GTest.h>

using namespace testing;
using namespace folly;

namespace quic {
namespace test {

struct ConnectionIdLengthParams {
  uint8_t dcidLen;
  uint8_t scidLen;
  uint8_t lengthByte;
};

class ConnectionIdLengthTest : public TestWithParam<ConnectionIdLengthParams> {
};

TEST_P(ConnectionIdLengthTest, TestDecode) {
  auto decoded = decodeConnectionIdLengths(GetParam().lengthByte);
  EXPECT_EQ(decoded.first, GetParam().dcidLen);
  EXPECT_EQ(decoded.second, GetParam().scidLen);
}

TEST_P(ConnectionIdLengthTest, TestEncode) {
  auto length =
      encodeConnectionIdLengths(GetParam().dcidLen, GetParam().scidLen);
  EXPECT_EQ(length, GetParam().lengthByte);
}

TEST_P(ConnectionIdLengthTest, DecodeEncode) {
  auto length =
      encodeConnectionIdLengths(GetParam().dcidLen, GetParam().scidLen);
  auto decoded = decodeConnectionIdLengths(length);
  EXPECT_EQ(decoded.first, GetParam().dcidLen);
  EXPECT_EQ(decoded.second, GetParam().scidLen);
}

TEST_P(ConnectionIdLengthTest, EncodeDecode) {
  auto decoded = decodeConnectionIdLengths(GetParam().lengthByte);
  auto length = encodeConnectionIdLengths(decoded.first, decoded.second);
  EXPECT_EQ(length, GetParam().lengthByte);
}

INSTANTIATE_TEST_CASE_P(
    ConnectionIdLengthTests,
    ConnectionIdLengthTest,
    testing::Values(
        (ConnectionIdLengthParams){0, 0, 0},
        (ConnectionIdLengthParams){0, 4, 0x01},
        (ConnectionIdLengthParams){4, 18, 0x1F},
        (ConnectionIdLengthParams){18, 18, 0xFF}));

} // namespace test
} // namespace quic
