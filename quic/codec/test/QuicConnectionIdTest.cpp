/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <folly/portability/GTest.h>
#include <quic/codec/QuicConnectionId.h>
#include <quic/common/StringUtils.h>

#include <folly/portability/GTest.h>

namespace quic::test {

TEST(ConnectionIdTest, TestConnidLen) {
  auto outOpt = quic::unhexlify("ffaabbee00");
  CHECK(outOpt.has_value()) << "Failed to unhexlify connection ID";
  std::string out = outOpt.value();
  folly::IOBuf buf = folly::IOBuf::wrapBufferAsValue(out.data(), out.size());
  Cursor cursor(&buf);
  auto connidExpected = ConnectionId::create(cursor, out.size());
  EXPECT_TRUE(connidExpected.has_value());
  ConnectionId connid = std::move(connidExpected.value());
  EXPECT_EQ(static_cast<size_t>(connid.size()), out.size());
  for (size_t i = 0; i < connid.size(); ++i) {
    EXPECT_EQ(*(connid.data() + i), static_cast<uint8_t>(out[i]));
  }
  std::string hexconnid = quic::hexlify(out);
  EXPECT_EQ(connid.hex(), hexconnid);
}

TEST(ConnectionIdTest, TestZeroLenConnid) {
  std::string out;
  folly::IOBuf buf = folly::IOBuf::wrapBufferAsValue(out.data(), out.size());
  Cursor cursor(&buf);
  auto connidExpected = ConnectionId::create(cursor, out.size());
  EXPECT_TRUE(connidExpected.has_value());
  ConnectionId connid = std::move(connidExpected.value());
  EXPECT_EQ(static_cast<size_t>(connid.size()), out.size());
}

TEST(ConnectionIdTest, CompareConnId) {
  ConnectionId connid1 = ConnectionId::createZeroLength();
  ConnectionId connid2 = ConnectionId::createZeroLength();
  EXPECT_EQ(connid1, connid2);

  ConnectionId connid3 = ConnectionId::createAndMaybeCrash(
      std::vector<uint8_t>{0x00, 0x01, 0x02, 0x03});
  ConnectionId connid4 = ConnectionId::createAndMaybeCrash(
      std::vector<uint8_t>{0x00, 0x01, 0x02, 0x03});
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
  EXPECT_FALSE(ConnectionId::create(testconnid).has_value());
  testconnid.clear();
  for (size_t i = 0; i < kMinSelfConnectionIdV1Size - 1; ++i) {
    testconnid.push_back(0);
  }
  EXPECT_TRUE(ConnectionId::create(testconnid).has_value());
}

} // namespace quic::test
