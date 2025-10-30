/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <gtest/gtest.h>
#include <quic/common/QuicRange.h>

namespace quic {
namespace test {

TEST(QuicRangeConversionTest, MutableToConstConversion) {
  // Test basic conversion from MutableByteRange to ByteRange
  uint8_t data[] = {1, 2, 3, 4, 5};
  MutableByteRange mutableRange(data, sizeof(data));

  // Implicit conversion should work
  ByteRange constRange = mutableRange;

  EXPECT_EQ(constRange.size(), 5);
  EXPECT_EQ(constRange[0], 1);
  EXPECT_EQ(constRange[4], 5);
}

TEST(QuicRangeConversionTest, PassToFunction) {
  // Test that we can pass MutableByteRange to a function expecting ByteRange
  auto processBytes = [](ByteRange range) -> size_t { return range.size(); };

  uint8_t data[] = {1, 2, 3};
  MutableByteRange mutableRange(data, sizeof(data));

  // Should be able to pass mutableRange directly
  EXPECT_EQ(processBytes(mutableRange), 3);
}

TEST(QuicRangeConversionTest, CopyConstruction) {
  // Test explicit copy construction
  uint8_t data[] = {10, 20, 30};
  MutableByteRange mutableRange(data, sizeof(data));

  ByteRange constRange(mutableRange);

  EXPECT_EQ(constRange.size(), 3);
  EXPECT_EQ(constRange[0], 10);
  EXPECT_EQ(constRange[1], 20);
  EXPECT_EQ(constRange[2], 30);
}

} // namespace test
} // namespace quic
