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

// Tests for totalLength()
TEST(ContiguousCursor, TotalLengthTest) {
  // Test with empty buffer
  quic::ContiguousReadCursor emptyCursor{nullptr, 0};
  EXPECT_EQ(emptyCursor.totalLength(), 0);

  // Test with non-empty buffer
  uint8_t data[] = {0x01, 0x02, 0x03, 0x04, 0x05};
  quic::ContiguousReadCursor cursor{data, sizeof(data)};
  EXPECT_EQ(cursor.totalLength(), 5);

  // totalLength should decrease as we advance
  cursor.skip(2);
  EXPECT_EQ(cursor.totalLength(), 3);

  cursor.skip(3);
  EXPECT_EQ(cursor.totalLength(), 0);
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

// Tests for pull()
TEST(ContiguousCursor, PullTest) {
  uint8_t data[] = {0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x11, 0x22};
  quic::ContiguousReadCursor cursor{data, sizeof(data)};

  // Test pulling single byte
  uint8_t singleByte;
  cursor.pull(&singleByte, 1);
  EXPECT_EQ(singleByte, 0xAA);
  EXPECT_EQ(cursor.getCurrentPosition(), 1);
  EXPECT_EQ(cursor.totalLength(), 7);

  // Test pulling multiple bytes
  uint8_t buffer[4];
  cursor.pull(buffer, 4);
  EXPECT_EQ(buffer[0], 0xBB);
  EXPECT_EQ(buffer[1], 0xCC);
  EXPECT_EQ(buffer[2], 0xDD);
  EXPECT_EQ(buffer[3], 0xEE);
  EXPECT_EQ(cursor.getCurrentPosition(), 5);
  EXPECT_EQ(cursor.totalLength(), 3);

  // Test pulling remaining bytes
  uint8_t remaining[3];
  cursor.pull(remaining, 3);
  EXPECT_EQ(remaining[0], 0xFF);
  EXPECT_EQ(remaining[1], 0x11);
  EXPECT_EQ(remaining[2], 0x22);
  EXPECT_EQ(cursor.getCurrentPosition(), 8);
  EXPECT_EQ(cursor.totalLength(), 0);
}

// Tests for read<T>()
TEST(ContiguousCursor, ReadTest) {
  // Create test data with known values
  uint8_t data[] = {
      0x12, // uint8_t
      0x34,
      0x56, // uint16_t (little-endian: 0x5634)
      0x78,
      0x9A,
      0xBC,
      0xDE, // uint32_t (little-endian: 0xDEBC9A78)
      0x11,
      0x22,
      0x33,
      0x44,
      0x55,
      0x66,
      0x77,
      0x88 // uint64_t
  };
  quic::ContiguousReadCursor cursor{data, sizeof(data)};

  // Test reading uint8_t
  uint8_t val8 = cursor.read<uint8_t>();
  EXPECT_EQ(val8, 0x12);
  EXPECT_EQ(cursor.getCurrentPosition(), 1);

  // Test reading uint16_t
  uint16_t val16 = cursor.read<uint16_t>();
  EXPECT_EQ(val16, 0x5634); // Little-endian
  EXPECT_EQ(cursor.getCurrentPosition(), 3);

  // Test reading uint32_t
  uint32_t val32 = cursor.read<uint32_t>();
  EXPECT_EQ(val32, 0xDEBC9A78); // Little-endian
  EXPECT_EQ(cursor.getCurrentPosition(), 7);

  // Test reading uint64_t
  uint64_t val64 = cursor.read<uint64_t>();
  EXPECT_EQ(val64, 0x8877665544332211ULL); // Little-endian
  EXPECT_EQ(cursor.getCurrentPosition(), 15);
  EXPECT_EQ(cursor.totalLength(), 0);
}

// Test edge cases and boundary conditions
TEST(ContiguousCursor, EdgeCasesTest) {
  uint8_t data[] = {0x01, 0x02, 0x03, 0x04};
  quic::ContiguousReadCursor cursor{data, sizeof(data)};

  // Test totalLength and getCurrentPosition consistency
  EXPECT_EQ(cursor.totalLength() + cursor.getCurrentPosition(), 4);

  cursor.skip(2);
  EXPECT_EQ(cursor.totalLength() + cursor.getCurrentPosition(), 4);

  cursor.skip(2);
  EXPECT_EQ(cursor.totalLength() + cursor.getCurrentPosition(), 4);

  // Test with zero-byte pull
  uint8_t buffer[1];
  cursor.reset(data, sizeof(data));
  cursor.pull(buffer, 0); // Should not advance cursor
  EXPECT_EQ(cursor.getCurrentPosition(), 0);
  EXPECT_EQ(cursor.totalLength(), 4);
}

} // namespace quic
