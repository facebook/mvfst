/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <folly/portability/GTest.h>
#include <quic/common/QuicBuffer.h>

namespace quic {

TEST(QuicBufferTest, TestBasic) {
  auto quicBuffer = QuicBuffer::create(100);
  EXPECT_EQ(quicBuffer->next(), quicBuffer.get());
  EXPECT_EQ(quicBuffer->prev(), quicBuffer.get());

  EXPECT_EQ(quicBuffer->capacity(), 100);
  EXPECT_EQ(quicBuffer->length(), 0);
  EXPECT_EQ(quicBuffer->tailroom(), 100);
  EXPECT_EQ(quicBuffer->headroom(), 0);
  quicBuffer->append(10);
  EXPECT_EQ(quicBuffer->capacity(), 100);
  EXPECT_EQ(quicBuffer->length(), 10);
  EXPECT_EQ(quicBuffer->tailroom(), 90);
  EXPECT_EQ(quicBuffer->headroom(), 0);
}

} // namespace quic
