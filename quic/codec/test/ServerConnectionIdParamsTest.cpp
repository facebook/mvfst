/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <folly/portability/GTest.h>
#include <quic/codec/QuicConnectionId.h>

namespace quic {
namespace test {
TEST(ServerConnectionIdParamsTest, EqOpTest) {
  ServerConnectionIdParams first(1, 5, 7);
  ServerConnectionIdParams second(1, 7, 5);
  ServerConnectionIdParams third(1, 5, 7);
  EXPECT_EQ(first, third);
  EXPECT_NE(first, second);
}
} // namespace test
} // namespace quic
