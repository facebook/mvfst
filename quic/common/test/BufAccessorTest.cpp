/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <quic/common/BufAccessor.h>

#include <folly/portability/GTest.h>

namespace quic {
TEST(SimpleBufAccessor, BasicAccess) {
  SimpleBufAccessor accessor(1000);
  EXPECT_TRUE(accessor.ownsBuffer());
  auto buf = accessor.obtain();
  EXPECT_LE(1000, buf->capacity());
  EXPECT_FALSE(accessor.ownsBuffer());
  auto empty = accessor.obtain();
  EXPECT_EQ(nullptr, empty);
  accessor.release(buf->clone());
  EXPECT_TRUE(accessor.ownsBuffer());
  EXPECT_DEATH(accessor.release(std::move(buf)), "");
}

TEST(SimpleBufAccessor, CapacityMatch) {
  SimpleBufAccessor accessor(1000);
  auto buf = accessor.obtain();
  buf = folly::IOBuf::create(2000);
  EXPECT_DEATH(accessor.release(std::move(buf)), "");
}

TEST(SimpleBufAccessor, RefuseChainedBuf) {
  SimpleBufAccessor accessor(1000);
  auto buf = accessor.obtain();
  buf->prependChain(folly::IOBuf::create(0));
  EXPECT_DEATH(accessor.release(std::move(buf)), "");
}
} // namespace quic
