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

} // namespace quic
