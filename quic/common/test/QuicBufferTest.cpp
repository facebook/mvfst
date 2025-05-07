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

TEST(QuicBufferTest, TestAppendToChain) {
  auto quicBuffer1 = QuicBuffer::create(100);
  QuicBuffer* quicBufferRawPtr1 = quicBuffer1.get();
  auto quicBuffer2 = QuicBuffer::create(100);
  QuicBuffer* quicBufferRawPtr2 = quicBuffer2.get();
  auto quicBuffer3 = QuicBuffer::create(100);
  QuicBuffer* quicBufferRawPtr3 = quicBuffer3.get();

  quicBuffer2->appendToChain(std::move(quicBuffer3));
  quicBuffer1->appendToChain(std::move(quicBuffer2));

  // Check next pointers
  EXPECT_EQ(quicBufferRawPtr1->next(), quicBufferRawPtr2);
  EXPECT_EQ(quicBufferRawPtr2->next(), quicBufferRawPtr3);
  EXPECT_EQ(quicBufferRawPtr3->next(), quicBufferRawPtr1);

  // Check prev pointers
  EXPECT_EQ(quicBufferRawPtr1->prev(), quicBufferRawPtr3);
  EXPECT_EQ(quicBufferRawPtr2->prev(), quicBufferRawPtr1);
  EXPECT_EQ(quicBufferRawPtr3->prev(), quicBufferRawPtr2);
}

} // namespace quic
