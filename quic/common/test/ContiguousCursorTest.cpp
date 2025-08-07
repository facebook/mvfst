/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <gtest/gtest.h>

#include <quic/common/ContiguousCursor.h>

namespace quic {

TEST(ContiguousCursor, EmptyBufTest) {
  quic::ContiguousReadCursor cursor{nullptr, 0};

  // empty buf => at end && can't adv && 0 bytes remaining
  EXPECT_TRUE(cursor.isAtEnd());
  EXPECT_TRUE(cursor.canAdvance(0));
  EXPECT_TRUE(cursor.skip(0));
  EXPECT_EQ(cursor.remaining(), 0);
  EXPECT_EQ(cursor.data(), cursor.end());

  // fails any try.* fns
  uint64_t test{0};
  uint8_t test_buf[1] = {0};
  std::string test_str;
  EXPECT_FALSE(cursor.tryReadBE(test));
  EXPECT_FALSE(cursor.tryPull(test_buf, 1));
  EXPECT_FALSE(cursor.tryReadFixedSizeString(test_str, 2));
  EXPECT_FALSE(cursor.skip(3));
}

TEST(ContiguousCursor, SimpleTest) {
  char str[] = {"\x00\x01\x02\x03\x04\x05\x06\x07hello world"};
  size_t bufSize = sizeof(str) - 1;
  quic::ContiguousReadCursor cursor{
      reinterpret_cast<const uint8_t*>(str), bufSize};

  // non-empty buf => not at end && can adv && > 0 remaining
  EXPECT_FALSE(cursor.isAtEnd());
  EXPECT_TRUE(cursor.canAdvance(bufSize));
  EXPECT_EQ(cursor.remaining(), bufSize);

  // pull first four bytes
  uint8_t test_buf[4] = {0};
  EXPECT_TRUE(cursor.tryPull(test_buf, 4));
  for (uint8_t idx = 0; idx < sizeof(test_buf); idx++) {
    EXPECT_EQ(test_buf[idx], idx);
  }

  // readBE next four bytes
  uint32_t test_be{0};
  EXPECT_TRUE(cursor.tryReadBE(test_be));
  EXPECT_EQ(test_be, 0x04050607);

  // remaining data should yield the string "hello world"
  std::string read;
  EXPECT_TRUE(cursor.tryReadFixedSizeString(read, cursor.remaining()));
  EXPECT_EQ(read, "hello world");
}

TEST(ContiguousCursor, RollbackTest) {
  std::string str{"\xa0\xa1\xa2\xa3hello world"};
  quic::ContiguousReadCursor cursor{
      reinterpret_cast<const uint8_t*>(str.data()), str.length()};
  EXPECT_EQ(cursor.remaining(), str.length());

  uint32_t test_be{0};

  // read four bytes in callback and return true
  cursor.withRollback([&]() {
    EXPECT_TRUE(cursor.tryReadBE(test_be));
    EXPECT_EQ(test_be, 0xa0a1a2a3);
    return true;
  });

  // lambda ret true => cursor is now back at first byte
  EXPECT_EQ(cursor.remaining(), str.length());
  test_be = *reinterpret_cast<const uint32_t*>(cursor.data());
  test_be = folly::Endian::big(test_be);
  EXPECT_EQ(test_be, 0xa0a1a2a3);

  // read four bytes in callback and return false
  cursor.withRollback([&]() {
    EXPECT_TRUE(cursor.tryReadBE(test_be));
    EXPECT_EQ(test_be, 0xa0a1a2a3);
    return false;
  });
  EXPECT_EQ(cursor.remaining(), str.length() - 4);

  // remaining data should yield string "hello world"
  std::string read;
  EXPECT_TRUE(cursor.tryReadFixedSizeString(read, cursor.remaining()));
  EXPECT_EQ(read, "hello world");
}

} // namespace quic
