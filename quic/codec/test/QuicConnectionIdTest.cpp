/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <quic/codec/QuicConnectionId.h>

#include <iterator>

#include <folly/portability/GTest.h>

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
  for (size_t i = 0; i < kMinSelfConnectionIdV1Size - 1; ++i) {
    testconnid.push_back(0);
  }
  EXPECT_NO_THROW(ConnectionId{testconnid});
}

} // namespace test
} // namespace quic
