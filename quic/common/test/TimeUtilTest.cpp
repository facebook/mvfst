/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <quic/common/TimeUtil.h>

#include <gtest/gtest.h>

namespace quic {
namespace test {

using namespace quic;

TEST(TimeUtil, TestMinTwo) {
  std::chrono::milliseconds ms1 = 10ms;
  std::chrono::milliseconds ms2 = 20ms;
  EXPECT_EQ(timeMin(ms1, ms2).count(), 10);
}

TEST(TimeUtil, TestMinFive) {
  std::chrono::milliseconds ms1 = 20ms;
  std::chrono::milliseconds ms2 = 30ms;
  std::chrono::milliseconds ms3 = 40ms;
  std::chrono::milliseconds ms4 = 10ms;
  EXPECT_EQ(timeMin(ms1, ms2, ms3, ms4).count(), 10);
}

TEST(TimeUtil, TestMaxTwo) {
  std::chrono::milliseconds ms1 = 10ms;
  std::chrono::milliseconds ms2 = 20ms;
  EXPECT_EQ(timeMax(ms1, ms2).count(), 20);
}

TEST(TimeUtil, TestMaxFive) {
  std::chrono::milliseconds ms1 = 20ms;
  std::chrono::milliseconds ms2 = 30ms;
  std::chrono::milliseconds ms3 = 40ms;
  std::chrono::milliseconds ms4 = 10ms;
  EXPECT_EQ(timeMax(ms1, ms2, ms3, ms4).count(), 40);
}
} // namespace test
} // namespace quic
