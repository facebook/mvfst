/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <gtest/gtest.h>
#include <quic/common/QuicRange.h>
#include <array>

namespace quic::test {

TEST(QuicRangeConversionTest, MutableToConstConversion) {
  // Test basic conversion from MutableByteRange to ByteRange
  auto data = std::to_array<uint8_t>({1, 2, 3, 4, 5});
  MutableByteRange mutableRange(data.data(), data.size());

  // Implicit conversion should work
  ByteRange constRange = mutableRange;

  EXPECT_EQ(constRange.size(), 5);
  EXPECT_EQ(constRange[0], 1);
  EXPECT_EQ(constRange[4], 5);
}

TEST(QuicRangeConversionTest, PassToFunction) {
  // Test that we can pass MutableByteRange to a function expecting ByteRange
  auto processBytes = [](ByteRange range) -> size_t { return range.size(); };

  auto data = std::to_array<uint8_t>({1, 2, 3});
  MutableByteRange mutableRange(data.data(), data.size());

  // Should be able to pass mutableRange directly
  EXPECT_EQ(processBytes(mutableRange), 3);
}

TEST(QuicRangeConversionTest, CopyConstruction) {
  // Test explicit copy construction
  auto data = std::to_array<uint8_t>({10, 20, 30});
  MutableByteRange mutableRange(data.data(), data.size());

  ByteRange constRange(mutableRange);

  EXPECT_EQ(constRange.size(), 3);
  EXPECT_EQ(constRange[0], 10);
  EXPECT_EQ(constRange[1], 20);
  EXPECT_EQ(constRange[2], 30);
}

} // namespace quic::test
