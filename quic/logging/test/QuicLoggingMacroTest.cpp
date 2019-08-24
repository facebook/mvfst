/*
 * Copyright (c) Facebook, Inc. and its affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 *
 */

#include <folly/portability/GTest.h>
#include <quic/logging/QuicLogger.h>

using namespace testing;

namespace quic {
namespace test {

template <typename T>
static T sum(T first) {
  return first;
}

template <typename T, typename... Args>
static T sum(T first, Args... args) {
  return first + sum(args...);
}

class QuicLoggingMacroTest : public Test {};

TEST_F(QuicLoggingMacroTest, ParameterTaker) {
  EXPECT_EQ(1, sum(TAKE_ATMOST_8(1)));
  EXPECT_EQ(2, sum(TAKE_ATMOST_8(1, 1)));
  EXPECT_EQ(3, sum(TAKE_ATMOST_8(1, 1, 1)));
  EXPECT_EQ(4, sum(TAKE_ATMOST_8(1, 1, 1, 1)));
  EXPECT_EQ(5, sum(TAKE_ATMOST_8(1, 1, 1, 1, 1)));
  EXPECT_EQ(6, sum(TAKE_ATMOST_8(1, 1, 1, 1, 1, 1)));
  EXPECT_EQ(7, sum(TAKE_ATMOST_8(1, 1, 1, 1, 1, 1, 1)));
  EXPECT_EQ(8, sum(TAKE_ATMOST_8(1, 1, 1, 1, 1, 1, 1, 1)));
  // 9 params:
  EXPECT_EQ(8, sum(TAKE_ATMOST_8(1, 1, 1, 1, 1, 1, 1, 1, 1)));
  // 10 params:
  EXPECT_EQ(8, sum(TAKE_ATMOST_8(1, 1, 1, 1, 1, 1, 1, 1, 1, 1)));
  // 11 params:
  EXPECT_EQ(8, sum(TAKE_ATMOST_8(1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1)));

  // 12 params, won't compile, leave it here as example:
  // EXPECT_EQ(8, sum(TAKE_ATMOST_8(1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1)));
}

} // namespace test
} // namespace quic
