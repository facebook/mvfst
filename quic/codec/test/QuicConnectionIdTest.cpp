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

namespace quic {
namespace test {

TEST(ConnectionIdTest, TestConnidLen) {
  std::string out = folly::unhexlify("ffaabbee00");
  folly::IOBuf buf = folly::IOBuf::wrapBufferAsValue(out.data(), out.size());
  folly::io::Cursor cursor(&buf);
  ConnectionId connid(cursor, out.size());
  EXPECT_EQ(static_cast<size_t>(connid.size()), out.size());
  for (size_t i = 0; i < connid.size(); ++i) {
    EXPECT_EQ(*(connid.data() + i), static_cast<uint8_t>(out[i]));
  }
  std::string hexconnid = folly::hexlify(out);
  EXPECT_EQ(connid.hex(), hexconnid);
}

TEST(ConnectionIdTest, TestZeroLenConnid) {
  std::string out = "";
  folly::IOBuf buf = folly::IOBuf::wrapBufferAsValue(out.data(), out.size());
  folly::io::Cursor cursor(&buf);
  ConnectionId connid(cursor, out.size());
  EXPECT_EQ(static_cast<size_t>(connid.size()), out.size());
}

TEST(ConnectionIdTest, CompareConnId) {
  ConnectionId connid1(std::vector<uint8_t>{});
  ConnectionId connid2(std::vector<uint8_t>{});
  EXPECT_EQ(connid1, connid2);

  ConnectionId connid3(std::vector<uint8_t>{0x00, 0x01, 0x02, 0x03});
  ConnectionId connid4(std::vector<uint8_t>{0x00, 0x01, 0x02, 0x03});
  EXPECT_NE(connid3, connid1);
  EXPECT_NE(connid1, connid3);

  EXPECT_EQ(connid3, connid4);
  EXPECT_EQ(connid4, connid3);
}

TEST(ConnectionIdTest, ConnIdSize) {
  std::vector<uint8_t> testconnid;
  for (size_t i = 0; i < kMaxConnectionIdSize + 2; ++i) {
    testconnid.push_back(0);
  }
  EXPECT_THROW(ConnectionId{testconnid}, std::runtime_error);
  testconnid.clear();
  for (size_t i = 0; i < kMinSelfConnectionIdSize - 1; ++i) {
    testconnid.push_back(0);
  }
  EXPECT_NO_THROW(ConnectionId{testconnid});
}

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
