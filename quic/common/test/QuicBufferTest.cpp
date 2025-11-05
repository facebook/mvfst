/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <glog/logging.h>
#include <gtest/gtest.h>
#include <quic/common/QuicBuffer.h>
#include <quic/common/QuicRange.h>

namespace quic {

std::string toString(const ByteRange& byteRange) {
  return std::string(
      reinterpret_cast<const char*>(byteRange.begin()), byteRange.size());
}

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

TEST(QuicBufferTest, TestAppendChain) {
  const uint8_t* data1 = (const uint8_t*)"hello";
  const uint8_t* data2 = (const uint8_t*)"my";
  const uint8_t* data3 = (const uint8_t*)"friend";

  auto quicBuffer1 = QuicBuffer::wrapBuffer((void*)data1, 5);
  auto quicBuffer2 = QuicBuffer::wrapBuffer((void*)data2, 2);
  auto quicBuffer3 = QuicBuffer::wrapBuffer((void*)data3, 6);

  quicBuffer1->appendChain(std::move(quicBuffer2));
  // hello -> my

  quicBuffer1->appendChain(std::move(quicBuffer3));
  // hello -> friend -> my

  EXPECT_EQ(memcmp(quicBuffer1->data(), "hello", 5), 0);
  EXPECT_EQ(memcmp(quicBuffer1->next()->data(), "friend", 6), 0);
  EXPECT_EQ(memcmp(quicBuffer1->next()->next()->data(), "my", 2), 0);
}

TEST(QuicBufferTest, TestSeparateChain) {
  auto quicBuffer1 = QuicBuffer::create(100);
  QuicBuffer* quicBufferRawPtr1 = quicBuffer1.get();
  auto quicBuffer2 = QuicBuffer::create(100);
  QuicBuffer* quicBufferRawPtr2 = quicBuffer2.get();
  auto quicBuffer3 = QuicBuffer::create(100);
  QuicBuffer* quicBufferRawPtr3 = quicBuffer3.get();
  auto quicBuffer4 = QuicBuffer::create(100);
  QuicBuffer* quicBufferRawPtr4 = quicBuffer4.get();
  auto quicBuffer5 = QuicBuffer::create(100);
  QuicBuffer* quicBufferRawPtr5 = quicBuffer5.get();
  auto quicBuffer6 = QuicBuffer::create(100);
  QuicBuffer* quicBufferRawPtr6 = quicBuffer6.get();

  // Make the chain like
  // 1->2->3->4->5->6
  quicBuffer5->appendToChain(std::move(quicBuffer6));
  quicBuffer4->appendToChain(std::move(quicBuffer5));
  quicBuffer3->appendToChain(std::move(quicBuffer4));
  quicBuffer2->appendToChain(std::move(quicBuffer3));
  quicBuffer1->appendToChain(std::move(quicBuffer2));

  // The below separateChain call should make things look like:
  // 2->3->4 and 1->5->6
  auto returnedChain =
      quicBuffer1->separateChain(quicBufferRawPtr2, quicBufferRawPtr4);

  EXPECT_EQ(quicBufferRawPtr2->next(), quicBufferRawPtr3);
  EXPECT_EQ(quicBufferRawPtr3->next(), quicBufferRawPtr4);
  EXPECT_EQ(quicBufferRawPtr4->next(), quicBufferRawPtr2);

  EXPECT_EQ(returnedChain.get(), quicBufferRawPtr2);
  EXPECT_EQ(quicBufferRawPtr1->next(), quicBufferRawPtr5);
  EXPECT_EQ(quicBufferRawPtr5->next(), quicBufferRawPtr6);
  EXPECT_EQ(quicBufferRawPtr6->next(), quicBufferRawPtr1);
}

TEST(QuicBufferTest, TestCloneOne) {
  auto quicBuffer1 = QuicBuffer::create(100);
  quicBuffer1->append(10);

  auto quicBuffer2 = quicBuffer1->cloneOne();
  EXPECT_EQ(quicBuffer1->length(), quicBuffer2->length());
  EXPECT_EQ(quicBuffer1->capacity(), quicBuffer2->capacity());
  EXPECT_EQ(quicBuffer1->data(), quicBuffer2->data());
}

TEST(QuicBufferTest, TestClone) {
  auto quicBuffer1 = QuicBuffer::create(100);
  quicBuffer1->append(10);
  auto quicBuffer2 = QuicBuffer::create(100);
  quicBuffer2->append(20);
  auto quicBuffer3 = QuicBuffer::create(100);
  quicBuffer3->append(30);

  auto clonedBuffer = quicBuffer1->clone();
  QuicBuffer* ptr1 = quicBuffer1.get();
  QuicBuffer* ptr2 = clonedBuffer.get();

  for (int i = 0; i < 3; i++) {
    EXPECT_EQ(ptr1->length(), ptr2->length());
    EXPECT_EQ(ptr1->capacity(), ptr2->capacity());
    EXPECT_EQ(ptr1->data(), ptr2->data());
    ptr1 = ptr1->next();
    ptr2 = ptr2->next();
  }
}

TEST(QuicBufferTest, TestCloneCoalescedSingle) {
  // Test cloneCoalesced on a single buffer (should behave like cloneOne)
  const std::string testData = "hello world";
  auto buffer =
      QuicBuffer::copyBuffer(testData, 10, 20); // 10 headroom, 20 tailroom

  auto coalesced = buffer->cloneCoalesced();

  // Should not be chained
  EXPECT_FALSE(coalesced->isChained());
  EXPECT_EQ(coalesced->next(), coalesced.get());
  EXPECT_EQ(coalesced->prev(), coalesced.get());

  // Data should be identical
  EXPECT_EQ(coalesced->length(), buffer->length());
  EXPECT_EQ(
      toString(ByteRange(coalesced->data(), coalesced->length())), testData);

  // Should preserve headroom and tailroom
  EXPECT_EQ(coalesced->headroom(), buffer->headroom());
  EXPECT_EQ(coalesced->tailroom(), buffer->tailroom());

  // Should be memory isolated (different buffer)
  EXPECT_NE(coalesced->data(), buffer->data());
}

TEST(QuicBufferTest, TestCloneCoalescedChain) {
  // Create a chain of 3 buffers with different data
  auto buffer1 =
      QuicBuffer::copyBuffer(std::string("hello"), 5, 10); // 5 headroom
  auto buffer2 = QuicBuffer::copyBuffer(std::string(" world"), 0, 0);
  auto buffer3 =
      QuicBuffer::copyBuffer(std::string("!!!"), 0, 15); // 15 tailroom

  buffer1->appendToChain(std::move(buffer2));
  buffer1->appendToChain(std::move(buffer3));

  // Total data should be "hello world!!!"
  EXPECT_EQ(buffer1->computeChainDataLength(), 14);

  auto coalesced = buffer1->cloneCoalesced();

  // Should not be chained
  EXPECT_FALSE(coalesced->isChained());
  EXPECT_EQ(coalesced->next(), coalesced.get());

  // Should contain all data coalesced
  EXPECT_EQ(coalesced->length(), 14);
  EXPECT_EQ(
      toString(ByteRange(coalesced->data(), coalesced->length())),
      "hello world!!!");

  // Should preserve headroom from first buffer and tailroom from last buffer
  EXPECT_EQ(coalesced->headroom(), 5); // from buffer1
  EXPECT_EQ(coalesced->tailroom(), 15); // from buffer3

  // Original chain should be unchanged
  EXPECT_TRUE(buffer1->isChained());
  EXPECT_EQ(buffer1->computeChainDataLength(), 14);
}

TEST(QuicBufferTest, TestCloneCoalescedWithEmptyBuffers) {
  // Create a chain with some empty buffers
  auto buffer1 =
      QuicBuffer::copyBuffer(std::string("hello"), 8, 0); // 8 headroom
  auto buffer2 = QuicBuffer::create(50); // empty buffer
  auto buffer3 = QuicBuffer::copyBuffer(std::string(" world"), 0, 0);
  auto buffer4 = QuicBuffer::create(50); // empty buffer
  auto buffer5 = QuicBuffer::copyBuffer(std::string("!"), 0, 12); // 12 tailroom

  buffer1->appendToChain(std::move(buffer2));
  buffer1->appendToChain(std::move(buffer3));
  buffer1->appendToChain(std::move(buffer4));
  buffer1->appendToChain(std::move(buffer5));

  auto coalesced = buffer1->cloneCoalesced();

  // Should not be chained
  EXPECT_FALSE(coalesced->isChained());

  // Should contain only non-empty data
  EXPECT_EQ(coalesced->length(), 12); // "hello world!"
  EXPECT_EQ(
      toString(ByteRange(coalesced->data(), coalesced->length())),
      "hello world!");

  // Should preserve headroom from first and tailroom from last
  EXPECT_EQ(coalesced->headroom(), 8); // from buffer1
  EXPECT_EQ(coalesced->tailroom(), 12); // from buffer5
}

TEST(QuicBufferTest, TestCloneCoalescedIsolation) {
  // Test that modifications to original don't affect cloned buffer
  auto buffer1 = QuicBuffer::copyBuffer(std::string("hello"), 0, 0);
  auto buffer2 = QuicBuffer::copyBuffer(std::string(" world"), 0, 0);

  buffer1->appendToChain(std::move(buffer2));

  auto coalesced = buffer1->cloneCoalesced();

  // Modify original data
  memcpy(buffer1->writableData(), "HELLO", 5);

  // Coalesced should be unaffected
  EXPECT_EQ(
      toString(ByteRange(coalesced->data(), coalesced->length())),
      "hello world");
  EXPECT_EQ(toString(ByteRange(buffer1->data(), buffer1->length())), "HELLO");
}

TEST(QuicBufferTest, TestCloneCoalescedAllEmpty) {
  // Test chain of all empty buffers
  auto buffer1 = QuicBuffer::create(50); // empty, some headroom by default
  auto buffer2 = QuicBuffer::create(50); // empty
  auto buffer3 = QuicBuffer::create(50); // empty

  buffer1->appendToChain(std::move(buffer2));
  buffer1->appendToChain(std::move(buffer3));

  auto coalesced = buffer1->cloneCoalesced();

  // Should not be chained
  EXPECT_FALSE(coalesced->isChained());

  // Should be empty
  EXPECT_EQ(coalesced->length(), 0);

  // Should still preserve headroom/tailroom structure
  EXPECT_GE(
      coalesced->capacity(), coalesced->headroom() + coalesced->tailroom());
}

TEST(QuicBufferTest, TestAdvance) {
  const uint8_t* data = (const uint8_t*)"hello";
  auto quicBuffer1 = QuicBuffer::create(100);
  memcpy(quicBuffer1->writableData(), data, 5);
  quicBuffer1->append(5);
  const uint8_t* prevData = quicBuffer1->data();
  quicBuffer1->advance(10);
  EXPECT_EQ(quicBuffer1->data(), prevData + 10);
  EXPECT_EQ(memcmp(quicBuffer1->data(), "hello", 5), 0);
}

TEST(QuicBufferTest, TestAdvanceNotEnoughRoom) {
  const uint8_t* data = (const uint8_t*)"hello";
  auto quicBuffer1 = QuicBuffer::create(6);
  memcpy(quicBuffer1->writableData(), data, 5);
  quicBuffer1->append(5);
  quicBuffer1->advance(1); // Should succeed
  EXPECT_DEATH(quicBuffer1->advance(1), "");
}

TEST(QuicBufferTest, TestRetreat) {
  const uint8_t* data = (const uint8_t*)"hello";
  auto quicBuffer1 = QuicBuffer::copyBuffer(data, 5, 3);
  const uint8_t* originalBufData = quicBuffer1->data();
  EXPECT_EQ(quicBuffer1->length(), 5);

  quicBuffer1->retreat(1);
  EXPECT_EQ(originalBufData, quicBuffer1->data() + 1);
  EXPECT_EQ(memcmp(data, quicBuffer1->data(), 5), 0);
  EXPECT_EQ(quicBuffer1->length(), 5);

  quicBuffer1->retreat(2);
  EXPECT_EQ(originalBufData, quicBuffer1->data() + 3);
  EXPECT_EQ(memcmp(data, quicBuffer1->data(), 5), 0);
  EXPECT_EQ(quicBuffer1->length(), 5);
}

TEST(QuicBufferTest, TestRetreatNotEnoughRoom) {
  const uint8_t* data = (const uint8_t*)"hello";
  auto quicBuffer1 = QuicBuffer::copyBuffer(data, 5, 3);
  EXPECT_DEATH(quicBuffer1->retreat(5), "");
}

TEST(QuicBufferTest, TestIsSharedOne) {
  const uint8_t* data = (const uint8_t*)"hello";
  auto quicBuffer1 = QuicBuffer::wrapBuffer((void*)data, 5);
  EXPECT_TRUE(quicBuffer1->isSharedOne());

  auto quicBuffer2 = QuicBuffer::copyBuffer(data, 5);
  EXPECT_FALSE(quicBuffer2->isSharedOne());
  auto quicBuffer3 = quicBuffer2->clone();
  EXPECT_TRUE(quicBuffer2->isSharedOne());
  EXPECT_TRUE(quicBuffer3->isSharedOne());
  quicBuffer3 = nullptr;
  EXPECT_FALSE(quicBuffer2->isSharedOne());
}

TEST(QuicBufferTest, TestIsShared) {
  const uint8_t* data = (const uint8_t*)"hello";
  auto quicBuffer1 = QuicBuffer::copyBuffer(data, 5);
  auto quicBuffer2 = QuicBuffer::copyBuffer(data, 5);
  quicBuffer1->appendToChain(std::move(quicBuffer2));

  EXPECT_FALSE(quicBuffer1->isShared());
  auto quicBuffer3 = quicBuffer1->next()->clone();
  EXPECT_TRUE(quicBuffer1->isShared());
  quicBuffer3 = nullptr;
  EXPECT_FALSE(quicBuffer1->isShared());
}

TEST(QuicBufferTest, TestCopyBufferSpan) {
  const uint8_t* data = (const uint8_t*)"hello";
  ByteRange range(data, 5);
  auto quicBuffer =
      QuicBuffer::copyBuffer(range, 1 /*headroom*/, 3 /*tailroom*/);
  EXPECT_EQ(quicBuffer->length(), 5);
  EXPECT_EQ(quicBuffer->capacity(), 9);
  EXPECT_EQ(memcmp(quicBuffer->data(), data, 5), 0);
}

TEST(QuicBufferTest, TestCopyBufferString) {
  std::string input("hello");
  auto quicBuffer =
      QuicBuffer::copyBuffer(input, 1 /*headroom*/, 3 /*tailroom*/);
  EXPECT_EQ(quicBuffer->length(), 5);
  EXPECT_EQ(quicBuffer->capacity(), 9);
  EXPECT_EQ(memcmp(quicBuffer->data(), "hello", 5), 0);
}

TEST(QuicBufferTest, TestCopyBufferPointerAndSize) {
  const uint8_t* data = (const uint8_t*)"hello";
  auto quicBuffer =
      QuicBuffer::copyBuffer(data, 5 /*size*/, 1 /*headroom*/, 3 /*tailroom*/);
  EXPECT_EQ(quicBuffer->length(), 5);
  EXPECT_EQ(quicBuffer->capacity(), 9);
  EXPECT_EQ(memcmp(quicBuffer->data(), "hello", 5), 0);
}

TEST(QuicBufferTest, TestWrapBufferPointer) {
  const auto* data = (const uint8_t*)"hello";
  auto quicBuffer = QuicBuffer::wrapBuffer((void*)data, 5);
  EXPECT_EQ(quicBuffer->capacity(), 5);
  EXPECT_EQ(quicBuffer->headroom(), 0);
  EXPECT_EQ(quicBuffer->tailroom(), 0);
  EXPECT_EQ(quicBuffer->data(), data);
}

TEST(QuicBufferTest, TestWrapBufferSpan) {
  const auto* data = (const uint8_t*)"hello";
  ByteRange range(data, 5);
  auto quicBuffer = QuicBuffer::wrapBuffer(range);
  EXPECT_EQ(quicBuffer->capacity(), 5);
  EXPECT_EQ(quicBuffer->headroom(), 0);
  EXPECT_EQ(quicBuffer->tailroom(), 0);
  EXPECT_EQ(quicBuffer->data(), data);
}

TEST(QuicBufferTest, TestComputeChainDataLength) {
  auto quicBuffer1 = QuicBuffer::create(10);
  quicBuffer1->append(5);

  auto quicBuffer2 = QuicBuffer::create(10);
  quicBuffer2->append(3);

  auto quicBuffer3 = QuicBuffer::create(10);
  quicBuffer3->append(6);

  quicBuffer1->appendToChain(std::move(quicBuffer2));
  quicBuffer1->appendToChain(std::move(quicBuffer3));

  EXPECT_EQ(quicBuffer1->computeChainDataLength(), 5 + 3 + 6);
}

TEST(QuicBufferTest, TestCoalesce) {
  const uint8_t* data1 = (const uint8_t*)"hello";
  const uint8_t* data2 = (const uint8_t*)"my";
  const uint8_t* data3 = (const uint8_t*)"friend";

  auto quicBuffer1 =
      QuicBuffer::copyBuffer(data1, 5 /* size */, 2 /* headroom */);
  auto quicBuffer2 = QuicBuffer::copyBuffer(data2, 2 /* size */);
  auto quicBuffer3 = QuicBuffer::copyBuffer(
      data3, 6 /* size */, 0 /* headroom */, 4 /* tailroom */);

  quicBuffer1->appendToChain(std::move(quicBuffer2));
  quicBuffer1->appendToChain(std::move(quicBuffer3));

  auto span = quicBuffer1->coalesce();
  EXPECT_EQ(quicBuffer1->headroom(), 2);
  EXPECT_EQ(quicBuffer1->tailroom(), 4);
  EXPECT_EQ(quicBuffer1->length(), 13);
  EXPECT_FALSE(quicBuffer1->isChained());
  EXPECT_EQ(memcmp(span.data(), "hellomyfriend", 13), 0);
}

TEST(QuicBufferTest, TestCountChainElements) {
  const uint8_t* data1 = (const uint8_t*)"hello";
  const uint8_t* data2 = (const uint8_t*)"my";
  const uint8_t* data3 = (const uint8_t*)"friend";

  auto quicBuffer1 = QuicBuffer::copyBuffer(data1, 5 /* size */);
  EXPECT_EQ(quicBuffer1->countChainElements(), 1);

  auto quicBuffer2 = QuicBuffer::copyBuffer(data2, 2 /* size */);
  quicBuffer1->appendToChain(std::move(quicBuffer2));
  EXPECT_EQ(quicBuffer1->countChainElements(), 2);

  auto quicBuffer3 = QuicBuffer::copyBuffer(data3, 6 /* size */);
  quicBuffer1->appendToChain(std::move(quicBuffer3));
  EXPECT_EQ(quicBuffer1->countChainElements(), 3);
}

TEST(QuicBufferTest, TestTrimStart) {
  const uint8_t* data = (const uint8_t*)"hello";

  auto quicBuffer = QuicBuffer::copyBuffer(data, 5 /* size */);
  quicBuffer->trimStart(2);
  EXPECT_EQ(quicBuffer->length(), 3);
  EXPECT_EQ(memcmp(quicBuffer->data(), "llo", 3), 0);
  quicBuffer->trimStart(3);
  EXPECT_EQ(quicBuffer->length(), 0);
}

TEST(QuicBufferTest, TestTrimEnd) {
  const uint8_t* data = (const uint8_t*)"hello";

  auto quicBuffer = QuicBuffer::copyBuffer(data, 5 /* size */);
  quicBuffer->trimEnd(2);
  EXPECT_EQ(quicBuffer->length(), 3);
  EXPECT_EQ(memcmp(quicBuffer->data(), "hel", 3), 0);
  quicBuffer->trimEnd(3);
  EXPECT_EQ(quicBuffer->length(), 0);
}

TEST(QuicBufferTest, TestPopOneChainElement) {
  const uint8_t* data = (const uint8_t*)"hello";

  auto quicBuffer = QuicBuffer::copyBuffer(data, 5 /* size */);
  auto result = quicBuffer->pop();
  EXPECT_EQ(result, nullptr);
  EXPECT_EQ(quicBuffer->length(), 5);
  EXPECT_EQ(quicBuffer->countChainElements(), 1);
}

TEST(QuicBufferTest, TestPopManyChainElements) {
  const uint8_t* data1 = (const uint8_t*)"hello";
  const uint8_t* data2 = (const uint8_t*)"my";
  const uint8_t* data3 = (const uint8_t*)"friend";

  auto quicBuffer1 = QuicBuffer::copyBuffer(data1, 5 /* size */);
  EXPECT_EQ(quicBuffer1->countChainElements(), 1);

  auto quicBuffer2 = QuicBuffer::copyBuffer(data2, 2 /* size */);
  quicBuffer1->appendToChain(std::move(quicBuffer2));
  EXPECT_EQ(quicBuffer1->countChainElements(), 2);

  auto quicBuffer3 = QuicBuffer::copyBuffer(data3, 6 /* size */);
  quicBuffer1->appendToChain(std::move(quicBuffer3));
  EXPECT_EQ(quicBuffer1->countChainElements(), 3);

  auto result = quicBuffer1->pop();
  // Now,
  // quicBuffer1 = "hello"
  // result = "my", "friend"
  EXPECT_EQ(result->computeChainDataLength(), 8);
  EXPECT_EQ(result->countChainElements(), 2);
  EXPECT_EQ(quicBuffer1->computeChainDataLength(), 5);
  EXPECT_EQ(quicBuffer1->countChainElements(), 1);

  auto result2 = result->pop();
  // Now,
  // result = "my"
  // result 2 = "friend"
  EXPECT_EQ(result2->countChainElements(), 1);
  EXPECT_EQ(result2->computeChainDataLength(), 6);
  EXPECT_EQ(result->computeChainDataLength(), 2);
  EXPECT_EQ(result->countChainElements(), 1);
}

TEST(QuicBufferTest, TestEmpty) {
  auto quicBuffer1 = QuicBuffer::create(10);
  EXPECT_TRUE(quicBuffer1->empty());
  quicBuffer1->append(5);
  EXPECT_FALSE(quicBuffer1->empty());
  quicBuffer1->trimStart(5);
  EXPECT_TRUE(quicBuffer1->empty());
  auto quicBuffer2 = QuicBuffer::create(10);
  quicBuffer1->appendToChain(std::move(quicBuffer2));
  EXPECT_TRUE(quicBuffer1->empty());
  quicBuffer1->next()->append(5);
  EXPECT_FALSE(quicBuffer1->empty());
}

TEST(QuicBufferTest, FillIov) {
  auto quicBuffer1 = QuicBuffer::create(10);
  quicBuffer1->append(10);

  auto quicBuffer2 = QuicBuffer::create(5);
  quicBuffer2->append(5);

  auto quicBuffer3 = QuicBuffer::create(7);
  quicBuffer3->append(7);

  quicBuffer1->appendToChain(std::move(quicBuffer2));
  quicBuffer1->appendToChain(std::move(quicBuffer3));

  iovec iov1[5];
  quicBuffer1->fillIov(iov1, 3);
  QuicBuffer* iter = quicBuffer1.get();
  for (int i = 0; i < 3; i++) {
    EXPECT_EQ(iov1[i].iov_base, iter->data());
    EXPECT_EQ(iov1[i].iov_len, iter->length());
    iter = iter->next();
  }

  iovec iov2[2];
  quicBuffer1->fillIov(iov2, 2);
  iter = quicBuffer1.get();
  for (int i = 0; i < 2; i++) {
    EXPECT_EQ(iov1[i].iov_base, iter->data());
    EXPECT_EQ(iov1[i].iov_len, iter->length());
    iter = iter->next();
  }
}

TEST(QuicBufferTest, TestClear) {
  const auto* data = (const uint8_t*)"hello";
  auto quicBuffer = QuicBuffer::wrapBufferAsValue((void*)data, 5);
  EXPECT_EQ(quicBuffer.capacity(), 5);
  EXPECT_EQ(quicBuffer.length(), 5);
  quicBuffer.clear();
  EXPECT_EQ(quicBuffer.capacity(), 5);
  EXPECT_EQ(quicBuffer.length(), 0);
}

TEST(QuicBufferTest, TestWrapBufferAsValue) {
  const auto* data = (const uint8_t*)"hello";
  auto quicBuffer = QuicBuffer::wrapBufferAsValue((void*)data, 5);
  EXPECT_EQ(quicBuffer.capacity(), 5);
  EXPECT_EQ(quicBuffer.length(), 5);
  EXPECT_EQ(quicBuffer.headroom(), 0);
  EXPECT_EQ(quicBuffer.tailroom(), 0);
  EXPECT_EQ(quicBuffer.data(), data);
}

TEST(QuicBufferTest, TestIterator) {
  const auto* data1 = (const uint8_t*)"hello";
  const auto* data2 = (const uint8_t*)"my";
  const auto* data3 = (const uint8_t*)"friend";

  auto quicBuffer1 = QuicBuffer::copyBuffer(data1, 5 /* size */);
  EXPECT_EQ(quicBuffer1->countChainElements(), 1);

  auto quicBuffer2 = QuicBuffer::copyBuffer(data2, 2 /* size */);
  quicBuffer1->appendToChain(std::move(quicBuffer2));

  auto quicBuffer3 = QuicBuffer::copyBuffer(data3, 6 /* size */);
  quicBuffer1->appendToChain(std::move(quicBuffer3));

  auto it = quicBuffer1->begin();
  EXPECT_EQ(it->size(), 5);
  EXPECT_EQ(memcmp(it->data(), "hello", 5), 0);
  ++it;
  EXPECT_EQ(it->size(), 2);
  EXPECT_EQ(memcmp(it->data(), "my", 2), 0);
  ++it;
  EXPECT_EQ(it->size(), 6);
  EXPECT_EQ(memcmp(it->data(), "friend", 6), 0);
}

TEST(QuicBufferTest, TestRange) {
  const uint8_t* data = (const uint8_t*)"hello";
  ByteRange range(data, 5);
  EXPECT_FALSE(range.empty());
  EXPECT_EQ(range.begin(), data);
  EXPECT_EQ(range.end(), data + 5);
  EXPECT_EQ(range.size(), 5);
  EXPECT_EQ(toString(range), std::string("hello"));
  range.advance(2);
  EXPECT_EQ(toString(range), std::string("llo"));
  EXPECT_EQ(range[0], 'l');
  range.advance(3);
  EXPECT_TRUE(range.empty());
}

TEST(QuicBufferTest, TestEqualsSingleBuffer) {
  QuicBufferEqualTo equalTo;

  // Test identical single buffers
  auto buffer1 = QuicBuffer::copyBuffer("hello", 5);
  auto buffer2 = QuicBuffer::copyBuffer("hello", 5);
  EXPECT_TRUE(equalTo(buffer1.get(), buffer2.get()));

  // Test different single buffers
  auto buffer3 = QuicBuffer::copyBuffer("world", 5);
  EXPECT_FALSE(equalTo(buffer1.get(), buffer3.get()));

  // Test different lengths
  auto buffer4 = QuicBuffer::copyBuffer("hell", 4);
  EXPECT_FALSE(equalTo(buffer1.get(), buffer4.get()));
}

TEST(QuicBufferTest, TestEqualsEmptyBuffers) {
  QuicBufferEqualTo equalTo;

  // Test two empty buffers
  auto buffer1 = QuicBuffer::create(100);
  auto buffer2 = QuicBuffer::create(200);
  EXPECT_TRUE(equalTo(buffer1.get(), buffer2.get()));

  // Test empty vs non-empty
  auto buffer3 = QuicBuffer::copyBuffer("hello", 5);
  EXPECT_FALSE(equalTo(buffer1.get(), buffer3.get()));
  EXPECT_FALSE(equalTo(buffer3.get(), buffer1.get()));
}

TEST(QuicBufferTest, TestEqualsChainedBuffers) {
  QuicBufferEqualTo equalTo;

  // Create first chained buffer: "hello" + "world"
  auto buffer1_1 = QuicBuffer::copyBuffer("hello", 5);
  auto buffer1_2 = QuicBuffer::copyBuffer("world", 5);
  buffer1_1->appendToChain(std::move(buffer1_2));

  // Create second chained buffer: "hello" + "world"
  auto buffer2_1 = QuicBuffer::copyBuffer("hello", 5);
  auto buffer2_2 = QuicBuffer::copyBuffer("world", 5);
  buffer2_1->appendToChain(std::move(buffer2_2));

  EXPECT_TRUE(equalTo(buffer1_1.get(), buffer2_1.get()));

  // Create third chained buffer: "hello" + "earth"
  auto buffer3_1 = QuicBuffer::copyBuffer("hello", 5);
  auto buffer3_2 = QuicBuffer::copyBuffer("earth", 5);
  buffer3_1->appendToChain(std::move(buffer3_2));

  EXPECT_FALSE(equalTo(buffer1_1.get(), buffer3_1.get()));
}

TEST(QuicBufferTest, TestEqualsDifferentSegmentation) {
  QuicBufferEqualTo equalTo;

  // Create single buffer: "helloworld"
  auto singleBuffer = QuicBuffer::copyBuffer("helloworld", 10);

  // Create chained buffer: "hello" + "world"
  auto chainedBuffer1 = QuicBuffer::copyBuffer("hello", 5);
  auto chainedBuffer2 = QuicBuffer::copyBuffer("world", 5);
  chainedBuffer1->appendToChain(std::move(chainedBuffer2));

  // Should be equal despite different segmentation
  EXPECT_TRUE(equalTo(singleBuffer.get(), chainedBuffer1.get()));
  EXPECT_TRUE(equalTo(chainedBuffer1.get(), singleBuffer.get()));

  // Create differently segmented chain: "he" + "llo" + "wo" + "rld"
  auto chainedBuffer3_1 = QuicBuffer::copyBuffer("he", 2);
  auto chainedBuffer3_2 = QuicBuffer::copyBuffer("llo", 3);
  auto chainedBuffer3_3 = QuicBuffer::copyBuffer("wo", 2);
  auto chainedBuffer3_4 = QuicBuffer::copyBuffer("rld", 3);
  chainedBuffer3_1->appendToChain(std::move(chainedBuffer3_2));
  chainedBuffer3_1->appendToChain(std::move(chainedBuffer3_3));
  chainedBuffer3_1->appendToChain(std::move(chainedBuffer3_4));

  // Should all be equal
  EXPECT_TRUE(equalTo(singleBuffer.get(), chainedBuffer3_1.get()));
  EXPECT_TRUE(equalTo(chainedBuffer1.get(), chainedBuffer3_1.get()));
}

TEST(QuicBufferTest, TestEqualsWithEmptyBuffersInChain) {
  QuicBufferEqualTo equalTo;

  // Create chain with empty buffers: "hello" + "" + "world" + ""
  auto buffer1_1 = QuicBuffer::copyBuffer("hello", 5);
  auto buffer1_2 = QuicBuffer::create(100); // empty
  auto buffer1_3 = QuicBuffer::copyBuffer("world", 5);
  auto buffer1_4 = QuicBuffer::create(100); // empty
  buffer1_1->appendToChain(std::move(buffer1_2));
  buffer1_1->appendToChain(std::move(buffer1_3));
  buffer1_1->appendToChain(std::move(buffer1_4));

  // Create simple chain: "hello" + "world"
  auto buffer2_1 = QuicBuffer::copyBuffer("hello", 5);
  auto buffer2_2 = QuicBuffer::copyBuffer("world", 5);
  buffer2_1->appendToChain(std::move(buffer2_2));

  // Should be equal despite empty buffers
  EXPECT_TRUE(equalTo(buffer1_1.get(), buffer2_1.get()));
  EXPECT_TRUE(equalTo(buffer2_1.get(), buffer1_1.get()));
}

TEST(QuicBufferTest, TestEqualsSelf) {
  QuicBufferEqualTo equalTo;

  // Test buffer equals itself
  auto buffer = QuicBuffer::copyBuffer("hello", 5);
  EXPECT_TRUE(equalTo(buffer.get(), buffer.get()));

  // Test chained buffer equals itself
  auto chainedBuffer = QuicBuffer::copyBuffer("hello", 5);
  auto chainedBuffer2 = QuicBuffer::copyBuffer("world", 5);
  chainedBuffer->appendToChain(std::move(chainedBuffer2));
  EXPECT_TRUE(equalTo(chainedBuffer.get(), chainedBuffer.get()));
}

TEST(QuicBufferTest, TestEqualsNullPointers) {
  QuicBufferEqualTo equalTo;

  // Test null pointer cases
  EXPECT_TRUE(equalTo(nullptr, nullptr));

  auto buffer = QuicBuffer::copyBuffer("hello", 5);
  EXPECT_FALSE(equalTo(buffer.get(), nullptr));
  EXPECT_FALSE(equalTo(nullptr, buffer.get()));
}

} // namespace quic

namespace quic {

TEST(QuicBufferTest, TestTakeOwnershipBasic) {
  // Allocate a raw buffer
  std::size_t cap = 16;
  void* raw = malloc(cap);
  ASSERT_NE(raw, nullptr);
  // Fill with pattern
  memset(raw, 0xAB, cap);

  auto buf = QuicBuffer::takeOwnership(raw, cap);
  EXPECT_EQ(buf->capacity(), cap);
  EXPECT_EQ(buf->length(), cap);
  EXPECT_EQ(buf->headroom(), 0);
  EXPECT_EQ(buf->tailroom(), 0);
  EXPECT_EQ(buf->data(), raw);
  // Verify content
  for (size_t i = 0; i < cap; ++i) {
    EXPECT_EQ(buf->data()[i], (uint8_t)0xAB);
  }
}

namespace {
struct FreeFnState {
  int frees{0};
  void* lastPtr{nullptr};
};

static void testFreeFn(void* p, void* user) {
  auto* st = static_cast<FreeFnState*>(user);
  st->frees++;
  st->lastPtr = p;
  free(p);
}
} // namespace

TEST(QuicBufferTest, TestTakeOwnershipCustomFreeFn) {
  std::size_t cap = 8;
  void* raw = malloc(cap);
  ASSERT_NE(raw, nullptr);
  FreeFnState state;
  auto buf = QuicBuffer::takeOwnership(raw, cap, &testFreeFn, &state);
  // Destroy buffer and ensure free function called exactly once
  buf.reset();
  EXPECT_EQ(state.frees, 1);
  EXPECT_EQ(state.lastPtr, raw);
}

TEST(QuicBufferTest, TestTakeOwnershipCloneSharing) {
  std::size_t cap = 4;
  void* raw = malloc(cap);
  ASSERT_NE(raw, nullptr);
  memset(raw, 0xCD, cap);

  FreeFnState state;
  {
    auto buf = QuicBuffer::takeOwnership(raw, cap, &testFreeFn, &state);
    EXPECT_FALSE(buf->isSharedOne());
    auto clone = buf->cloneOne();
    EXPECT_TRUE(buf->isSharedOne());
    EXPECT_TRUE(clone->isSharedOne());
    // Both go out of scope here
  }
  EXPECT_EQ(state.frees, 1);
  EXPECT_EQ(state.lastPtr, raw);
}

} // namespace quic

namespace quic {

TEST(QuicBufferTest, TestFromStringBasic) {
  auto buf = QuicBuffer::fromString(std::string("hello"));
  EXPECT_EQ(buf->length(), 5);
  EXPECT_EQ(buf->capacity(), 5);
  EXPECT_EQ(buf->headroom(), 0);
  EXPECT_EQ(buf->tailroom(), 0);
  EXPECT_EQ(memcmp(buf->data(), "hello", 5), 0);
  EXPECT_FALSE(buf->isSharedOne());
  auto clone = buf->cloneOne();
  EXPECT_TRUE(buf->isSharedOne());
  EXPECT_TRUE(clone->isSharedOne());
}

TEST(QuicBufferTest, TestFromStringUniquePtr) {
  auto s = std::make_unique<std::string>("abc");
  auto buf = QuicBuffer::fromString(std::move(s));
  EXPECT_EQ(buf->length(), 3);
  EXPECT_EQ(buf->capacity(), 3);
  EXPECT_EQ(buf->headroom(), 0);
  EXPECT_EQ(buf->tailroom(), 0);
  EXPECT_EQ(memcmp(buf->data(), "abc", 3), 0);
  EXPECT_FALSE(buf->isSharedOne());
  auto clone = buf->cloneOne();
  EXPECT_TRUE(buf->isSharedOne());
  EXPECT_TRUE(clone->isSharedOne());
}

TEST(QuicBufferTest, TestFromStringEmpty) {
  auto buf = QuicBuffer::fromString(std::string());
  EXPECT_EQ(buf->length(), 0);
  EXPECT_EQ(buf->capacity(), 0);
  EXPECT_EQ(buf->headroom(), 0);
  EXPECT_EQ(buf->tailroom(), 0);
  EXPECT_TRUE(buf->empty());
}

TEST(QuicBufferTest, RangeToString) {
  // Test basic ByteRange to string conversion
  const uint8_t data[] = "Hello, World!";
  ByteRange range(data, 13);
  EXPECT_EQ(range.toString(), "Hello, World!");

  // Test empty range
  ByteRange emptyRange(nullptr, nullptr);
  EXPECT_EQ(emptyRange.toString(), "");

  // Test range with subset of data
  ByteRange subRange(data, 5);
  EXPECT_EQ(subRange.toString(), "Hello");

  // Test range constructed with begin/end pointers
  ByteRange pointerRange(data, data + 7);
  EXPECT_EQ(pointerRange.toString(), "Hello, ");

  // Test StringPiece (Range<const char*>) to string
  const char* strData = "StringPiece test";
  StringPiece strPiece(strData, 11);
  EXPECT_EQ(strPiece.toString(), "StringPiece");

  // Test with binary data (including null bytes)
  const uint8_t binaryData[] = {
      0x48, 0x65, 0x6C, 0x6C, 0x6F, 0x00, 0x57, 0x6F, 0x72, 0x6C, 0x64};
  ByteRange binaryRange(binaryData, 11);
  std::string expectedBinary =
      std::string(reinterpret_cast<const char*>(binaryData), 11);
  EXPECT_EQ(binaryRange.toString(), expectedBinary);
  EXPECT_EQ(binaryRange.toString().size(), 11); // Should include the null byte
}

TEST(QuicBufferTest, TestToStringSingleBuffer) {
  // Create a single buffer with headroom and tailroom
  const std::string kData = "hello";
  auto buf = QuicBuffer::copyBuffer(kData, 3 /* headroom */, 4 /* tailroom */);

  // Capture state before toString()
  auto* dataPtrBefore = buf->data();
  auto headroomBefore = buf->headroom();
  auto tailroomBefore = buf->tailroom();
  auto lengthBefore = buf->length();

  // Convert to string
  auto out = buf->toString();
  EXPECT_EQ(out, kData);

  // Verify buffer is unchanged
  EXPECT_EQ(buf->data(), dataPtrBefore);
  EXPECT_EQ(buf->headroom(), headroomBefore);
  EXPECT_EQ(buf->tailroom(), tailroomBefore);
  EXPECT_EQ(buf->length(), lengthBefore);
  EXPECT_FALSE(buf->isChained());
}

TEST(QuicBufferTest, TestToStringChain) {
  // Create a chain: "hello" + " world" + "!!!" => "hello world!!!"
  auto b1 = QuicBuffer::copyBuffer(std::string("hello"), 5 /* headroom */, 0);
  auto b2 = QuicBuffer::copyBuffer(std::string(" world"), 0, 0);
  auto b3 = QuicBuffer::copyBuffer(std::string("!!!"), 0, 15 /* tailroom */);

  auto headroomFirstBefore = b1->headroom();
  auto tailroomLastBefore = b3->tailroom();

  b1->appendToChain(std::move(b2));
  b1->appendToChain(std::move(b3));

  // Sanity checks
  EXPECT_TRUE(b1->isChained());
  EXPECT_EQ(b1->computeChainDataLength(), 14);

  // Capture ring pointers after chain is formed
  auto* b1NextBefore = b1->next();
  auto* b1PrevBefore = b1->prev();

  // Convert to string
  auto out = b1->toString();
  EXPECT_EQ(out, std::string("hello world!!!"));

  // Verify chain structure and buffer metadata unchanged
  EXPECT_TRUE(b1->isChained());
  EXPECT_EQ(b1->headroom(), headroomFirstBefore);
  EXPECT_EQ(b1->prev()->tailroom(), tailroomLastBefore);
  EXPECT_EQ(b1->computeChainDataLength(), 14);

  // Verify next/prev still form a ring and head unchanged
  EXPECT_EQ(b1->next(), b1NextBefore);
  EXPECT_EQ(b1->prev(), b1PrevBefore);
}

TEST(QuicBufferTest, TestToStringWithEmptyBuffers) {
  // Chain with empty buffers interleaved
  auto b1 = QuicBuffer::copyBuffer(std::string("hello"), 3 /* headroom */, 0);
  auto bEmpty1 = QuicBuffer::create(50); // empty
  auto b2 = QuicBuffer::copyBuffer(std::string(" world"), 0, 0);
  auto bEmpty2 = QuicBuffer::create(50); // empty
  auto b3 = QuicBuffer::copyBuffer(std::string("!"), 0, 12 /* tailroom */);

  b1->appendToChain(std::move(bEmpty1));
  b1->appendToChain(std::move(b2));
  b1->appendToChain(std::move(bEmpty2));
  b1->appendToChain(std::move(b3));

  auto totalBefore = b1->computeChainDataLength();
  EXPECT_EQ(totalBefore, 12); // "hello world!" => 12 chars

  auto out = b1->toString();
  EXPECT_EQ(out, std::string("hello world!"));

  // Verify unchanged
  EXPECT_EQ(b1->computeChainDataLength(), totalBefore);
  EXPECT_TRUE(b1->isChained());
}

TEST(QuicBufferTest, TestToStringAllEmpty) {
  auto b1 = QuicBuffer::create(10);
  auto b2 = QuicBuffer::create(10);
  auto b3 = QuicBuffer::create(10);

  b1->appendToChain(std::move(b2));
  b1->appendToChain(std::move(b3));

  EXPECT_TRUE(b1->empty());
  EXPECT_EQ(b1->computeChainDataLength(), 0);

  auto out = b1->toString();
  EXPECT_TRUE(out.empty());

  // Chain still intact and empty
  EXPECT_TRUE(b1->empty());
  EXPECT_TRUE(b1->isChained());
  EXPECT_EQ(b1->computeChainDataLength(), 0);
}

TEST(QuicBufferTest, TestWrapIovEmpty) {
  // Test with empty iovec array (count = 0)
  struct iovec vec[1];
  auto buf = QuicBuffer::wrapIov(vec, 0);

  ASSERT_NE(buf, nullptr);
  EXPECT_EQ(buf->length(), 0);
  EXPECT_FALSE(buf->isChained());
}

TEST(QuicBufferTest, TestWrapIovSingle) {
  // Test with a single iovec containing data
  const char* data = "hello world";
  struct iovec vec[1];
  vec[0].iov_base = (void*)data;
  vec[0].iov_len = 11;

  auto buf = QuicBuffer::wrapIov(vec, 1);

  ASSERT_NE(buf, nullptr);
  EXPECT_EQ(buf->length(), 11);
  EXPECT_FALSE(buf->isChained());
  EXPECT_EQ(memcmp(buf->data(), data, 11), 0);
}

TEST(QuicBufferTest, TestWrapIovMultiple) {
  // Test with multiple iovecs containing data
  const char* data1 = "hello";
  const char* data2 = " ";
  const char* data3 = "world";

  struct iovec vec[3];
  vec[0].iov_base = (void*)data1;
  vec[0].iov_len = 5;
  vec[1].iov_base = (void*)data2;
  vec[1].iov_len = 1;
  vec[2].iov_base = (void*)data3;
  vec[2].iov_len = 5;

  auto buf = QuicBuffer::wrapIov(vec, 3);

  ASSERT_NE(buf, nullptr);
  EXPECT_TRUE(buf->isChained());
  EXPECT_EQ(buf->countChainElements(), 3);
  EXPECT_EQ(buf->computeChainDataLength(), 11);

  // Verify each buffer in the chain
  EXPECT_EQ(buf->length(), 5);
  EXPECT_EQ(memcmp(buf->data(), "hello", 5), 0);

  EXPECT_EQ(buf->next()->length(), 1);
  EXPECT_EQ(memcmp(buf->next()->data(), " ", 1), 0);

  EXPECT_EQ(buf->next()->next()->length(), 5);
  EXPECT_EQ(memcmp(buf->next()->next()->data(), "world", 5), 0);
}

TEST(QuicBufferTest, TestWrapIovWithZeroLengthIovecs) {
  // Test with iovecs that have zero length (should be skipped)
  const char* data1 = "hello";
  const char* data2 = "world";

  struct iovec vec[4];
  vec[0].iov_base = (void*)data1;
  vec[0].iov_len = 5;
  vec[1].iov_base = nullptr;
  vec[1].iov_len = 0; // zero length, should be skipped
  vec[2].iov_base = (void*)data2;
  vec[2].iov_len = 5;
  vec[3].iov_base = nullptr;
  vec[3].iov_len = 0; // zero length, should be skipped

  auto buf = QuicBuffer::wrapIov(vec, 4);

  ASSERT_NE(buf, nullptr);
  EXPECT_TRUE(buf->isChained());
  // Should only have 2 elements since zero-length iovecs are skipped
  EXPECT_EQ(buf->countChainElements(), 2);
  EXPECT_EQ(buf->computeChainDataLength(), 10);

  EXPECT_EQ(buf->length(), 5);
  EXPECT_EQ(memcmp(buf->data(), "hello", 5), 0);

  EXPECT_EQ(buf->next()->length(), 5);
  EXPECT_EQ(memcmp(buf->next()->data(), "world", 5), 0);
}

TEST(QuicBufferTest, TestWrapIovAllZeroLength) {
  // Test with all iovecs having zero length
  struct iovec vec[3];
  vec[0].iov_base = nullptr;
  vec[0].iov_len = 0;
  vec[1].iov_base = nullptr;
  vec[1].iov_len = 0;
  vec[2].iov_base = nullptr;
  vec[2].iov_len = 0;

  auto buf = QuicBuffer::wrapIov(vec, 3);

  // Should return a zero-length buffer, not nullptr
  ASSERT_NE(buf, nullptr);
  EXPECT_EQ(buf->length(), 0);
  EXPECT_FALSE(buf->isChained());
}

TEST(QuicBufferTest, TestWrapIovChainIntegrity) {
  // Test that the chain is properly formed with correct next/prev pointers
  const char* data1 = "A";
  const char* data2 = "B";
  const char* data3 = "C";

  struct iovec vec[3];
  vec[0].iov_base = (void*)data1;
  vec[0].iov_len = 1;
  vec[1].iov_base = (void*)data2;
  vec[1].iov_len = 1;
  vec[2].iov_base = (void*)data3;
  vec[2].iov_len = 1;

  auto buf = QuicBuffer::wrapIov(vec, 3);

  ASSERT_NE(buf, nullptr);

  QuicBuffer* first = buf.get();
  QuicBuffer* second = first->next();
  QuicBuffer* third = second->next();

  // Verify forward chain
  EXPECT_EQ(third->next(), first);

  // Verify backward chain
  EXPECT_EQ(first->prev(), third);
  EXPECT_EQ(second->prev(), first);
  EXPECT_EQ(third->prev(), second);
}

TEST(QuicBufferTest, TestPrepend) {
  // Create a buffer with headroom
  const uint8_t* data = (const uint8_t*)"hello";
  auto quicBuffer = QuicBuffer::copyBuffer(data, 5, 10, 0);

  EXPECT_EQ(quicBuffer->length(), 5);
  EXPECT_EQ(quicBuffer->headroom(), 10);
  EXPECT_EQ(memcmp(quicBuffer->data(), "hello", 5), 0);

  const uint8_t* originalData = quicBuffer->data();

  // Prepend 3 bytes
  quicBuffer->prepend(3);

  // After prepend:
  // - data pointer should move backward by 3
  // - length should increase by 3
  // - original data should still be accessible at offset 3
  EXPECT_EQ(quicBuffer->data(), originalData - 3);
  EXPECT_EQ(quicBuffer->length(), 8);
  EXPECT_EQ(quicBuffer->headroom(), 7);
  EXPECT_EQ(memcmp(quicBuffer->data() + 3, "hello", 5), 0);
}

TEST(QuicBufferTest, TestPrependWithDataPopulation) {
  // Create a buffer with headroom
  const uint8_t* data = (const uint8_t*)"world";
  auto quicBuffer = QuicBuffer::copyBuffer(data, 5, 6, 0);

  EXPECT_EQ(quicBuffer->length(), 5);
  EXPECT_EQ(quicBuffer->headroom(), 6);

  // Prepend 6 bytes and populate with "hello "
  quicBuffer->prepend(6);

  // Write data into the prepended space
  memcpy(quicBuffer->writableData(), "hello ", 6);

  // Now the buffer should contain "hello world"
  EXPECT_EQ(quicBuffer->length(), 11);
  EXPECT_EQ(memcmp(quicBuffer->data(), "hello world", 11), 0);
}

TEST(QuicBufferTest, TestPrependZeroBytes) {
  // Create a buffer with headroom
  const uint8_t* data = (const uint8_t*)"test";
  auto quicBuffer = QuicBuffer::copyBuffer(data, 4, 5, 0);

  const uint8_t* originalData = quicBuffer->data();
  std::size_t originalLength = quicBuffer->length();
  std::size_t originalHeadroom = quicBuffer->headroom();

  // Prepend 0 bytes should not change anything
  quicBuffer->prepend(0);

  EXPECT_EQ(quicBuffer->data(), originalData);
  EXPECT_EQ(quicBuffer->length(), originalLength);
  EXPECT_EQ(quicBuffer->headroom(), originalHeadroom);
  EXPECT_EQ(memcmp(quicBuffer->data(), "test", 4), 0);
}

TEST(QuicBufferTest, TestPrependInsufficientHeadroom) {
  // Create a buffer with limited headroom
  const uint8_t* data = (const uint8_t*)"hello";
  auto quicBuffer = QuicBuffer::copyBuffer(data, 5, 3, 0);

  EXPECT_EQ(quicBuffer->headroom(), 3);

  // Attempting to prepend more than available headroom should fail
  EXPECT_DEATH(quicBuffer->prepend(5), "");
}

TEST(QuicBufferTest, TestPrependMultipleTimes) {
  // Create a buffer with ample headroom
  const uint8_t* data = (const uint8_t*)"end";
  auto quicBuffer = QuicBuffer::copyBuffer(data, 3, 10, 0);

  const uint8_t* originalData = quicBuffer->data();

  // First prepend
  quicBuffer->prepend(5);
  memcpy(quicBuffer->writableData(), "start", 5);
  EXPECT_EQ(quicBuffer->length(), 8);
  EXPECT_EQ(quicBuffer->data(), originalData - 5);

  // Second prepend
  quicBuffer->prepend(2);
  memcpy(quicBuffer->writableData(), ">>", 2);
  EXPECT_EQ(quicBuffer->length(), 10);
  EXPECT_EQ(quicBuffer->data(), originalData - 7);

  // Verify final content: ">>startend"
  EXPECT_EQ(memcmp(quicBuffer->data(), ">>startend", 10), 0);
}

TEST(QuicBufferTest, TestPrependExhaustHeadroom) {
  // Create a buffer with specific headroom
  const uint8_t* data = (const uint8_t*)"data";
  auto quicBuffer = QuicBuffer::copyBuffer(data, 4, 8, 0);

  EXPECT_EQ(quicBuffer->headroom(), 8);

  // Prepend exactly all available headroom
  quicBuffer->prepend(8);

  EXPECT_EQ(quicBuffer->length(), 12);
  EXPECT_EQ(quicBuffer->headroom(), 0);

  // Verify original data is still intact at the end
  EXPECT_EQ(memcmp(quicBuffer->data() + 8, "data", 4), 0);
}

} // namespace quic
