/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <gtest/gtest.h>
#include <cstring>

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

// Tests for getCurrentPosition()
TEST(ContiguousCursor, GetCurrentPositionTest) {
  uint8_t data[] = {0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80};
  quic::ContiguousReadCursor cursor{data, sizeof(data)};

  // Initial position should be 0
  EXPECT_EQ(cursor.getCurrentPosition(), 0);

  // Position should advance as we read data
  cursor.skip(1);
  EXPECT_EQ(cursor.getCurrentPosition(), 1);

  cursor.skip(3);
  EXPECT_EQ(cursor.getCurrentPosition(), 4);

  cursor.skip(4);
  EXPECT_EQ(cursor.getCurrentPosition(), 8);

  // Test with empty buffer
  quic::ContiguousReadCursor emptyCursor{nullptr, 0};
  EXPECT_EQ(emptyCursor.getCurrentPosition(), 0);
}

// Tests for pullAtMost()
TEST(ContiguousCursor, PullAtMostTest) {
  uint8_t data[] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07};
  quic::ContiguousReadCursor cursor{data, sizeof(data)};

  // Test pulling exact available amount
  uint8_t buf1[4];
  size_t pulled = cursor.pullAtMost(buf1, 4);
  EXPECT_EQ(pulled, 4);
  EXPECT_EQ(cursor.getCurrentPosition(), 4);
  for (size_t i = 0; i < 4; i++) {
    EXPECT_EQ(buf1[i], i);
  }

  // Test pulling more than available (should get remaining bytes)
  uint8_t buf2[10];
  pulled = cursor.pullAtMost(buf2, 10);
  EXPECT_EQ(pulled, 4); // only 4 bytes remaining
  EXPECT_TRUE(cursor.isAtEnd());
  for (size_t i = 0; i < 4; i++) {
    EXPECT_EQ(buf2[i], i + 4);
  }

  // Test pulling from empty cursor
  uint8_t buf3[4];
  pulled = cursor.pullAtMost(buf3, 4);
  EXPECT_EQ(pulled, 0);

  // Test pulling zero bytes
  cursor.reset(data, sizeof(data));
  uint8_t buf4[4];
  pulled = cursor.pullAtMost(buf4, 0);
  EXPECT_EQ(pulled, 0);
  EXPECT_EQ(cursor.getCurrentPosition(), 0); // cursor shouldn't move
}

TEST(ContiguousCursor, PullAtMostConsecutiveTest) {
  uint8_t data[] = {0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80, 0x90, 0xa0};
  quic::ContiguousReadCursor cursor{data, sizeof(data)};

  // First pull: get 3 bytes
  uint8_t buf1[3];
  size_t pulled1 = cursor.pullAtMost(buf1, 3);
  EXPECT_EQ(pulled1, 3);
  EXPECT_EQ(buf1[0], 0x10);
  EXPECT_EQ(buf1[1], 0x20);
  EXPECT_EQ(buf1[2], 0x30);
  EXPECT_EQ(cursor.getCurrentPosition(), 3);

  // Second pull: get 2 bytes
  uint8_t buf2[2];
  size_t pulled2 = cursor.pullAtMost(buf2, 2);
  EXPECT_EQ(pulled2, 2);
  EXPECT_EQ(buf2[0], 0x40);
  EXPECT_EQ(buf2[1], 0x50);
  EXPECT_EQ(cursor.getCurrentPosition(), 5);

  // Third pull: try to get 10 bytes but only 5 remaining
  uint8_t buf3[10];
  size_t pulled3 = cursor.pullAtMost(buf3, 10);
  EXPECT_EQ(pulled3, 5); // only 5 bytes left
  EXPECT_EQ(buf3[0], 0x60);
  EXPECT_EQ(buf3[1], 0x70);
  EXPECT_EQ(buf3[2], 0x80);
  EXPECT_EQ(buf3[3], 0x90);
  EXPECT_EQ(buf3[4], 0xa0);
  EXPECT_TRUE(cursor.isAtEnd());
}

} // namespace quic
