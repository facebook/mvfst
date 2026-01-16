/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <quic/folly_utils/BufConv.h>

#include <folly/io/IOBuf.h>
#include <gtest/gtest.h>
#include <quic/common/QuicBuffer.h>

namespace quic::follyutils {

template <typename T>
std::unique_ptr<T> createBuffer(const std::string& data) {
  if constexpr (std::is_same_v<T, QuicBuffer>) {
    return QuicBuffer::copyBuffer(data);
  } else {
    return folly::IOBuf::copyBuffer(data);
  }
}

template <typename T>
auto convert(std::unique_ptr<T>&& buf) {
  if constexpr (std::is_same_v<T, QuicBuffer>) {
    return toIOBuf(std::move(buf));
  } else {
    return toQuicBuf(std::move(buf));
  }
}

template <typename T>
class BufConvTest : public ::testing::Test {};

using TestTypes = ::testing::Types<QuicBuffer, folly::IOBuf>;
TYPED_TEST_SUITE(BufConvTest, TestTypes);

TYPED_TEST(BufConvTest, SingleBuffer) {
  const std::string data = "hello world";
  auto srcBuf = createBuffer<TypeParam>(data);

  auto dstBuf = convert(std::move(srcBuf));

  ASSERT_EQ(srcBuf, nullptr);
  ASSERT_NE(dstBuf, nullptr);
  EXPECT_FALSE(dstBuf->isChained());
  EXPECT_EQ(dstBuf->length(), data.size());
  EXPECT_EQ(
      std::string(
          reinterpret_cast<const char*>(dstBuf->data()), dstBuf->length()),
      data);
}

TYPED_TEST(BufConvTest, ChainedBuffer) {
  auto buf1 = createBuffer<TypeParam>("hello");
  auto buf2 = createBuffer<TypeParam>(" ");
  auto buf3 = createBuffer<TypeParam>("world");

  buf1->appendToChain(std::move(buf2));
  buf1->appendToChain(std::move(buf3));

  EXPECT_TRUE(buf1->isChained());
  EXPECT_EQ(buf1->countChainElements(), 3);
  EXPECT_EQ(buf1->computeChainDataLength(), 11);

  auto dstBuf = convert(std::move(buf1));

  ASSERT_EQ(buf1, nullptr);
  ASSERT_NE(dstBuf, nullptr);
  EXPECT_TRUE(dstBuf->isChained());
  EXPECT_EQ(dstBuf->countChainElements(), 3);
  EXPECT_EQ(dstBuf->computeChainDataLength(), 11);

  std::string result;
  for (const auto& range : *dstBuf) {
    result.append(reinterpret_cast<const char*>(range.data()), range.size());
  }
  EXPECT_EQ(result, "hello world");
}

TYPED_TEST(BufConvTest, NullBuffer) {
  std::unique_ptr<TypeParam> srcBuf = nullptr;

  auto dstBuf = convert(std::move(srcBuf));

  EXPECT_EQ(dstBuf, nullptr);
}

TYPED_TEST(BufConvTest, ZeroCopySingleBuffer) {
  const std::string data = "zero copy test";
  auto srcBuf = createBuffer<TypeParam>(data);

  const void* originalDataPtr = srcBuf->data();

  auto dstBuf = convert(std::move(srcBuf));

  ASSERT_EQ(srcBuf, nullptr);
  ASSERT_NE(dstBuf, nullptr);
  EXPECT_EQ(dstBuf->data(), originalDataPtr)
      << "Buffer data was copied instead of being transferred";
}

TYPED_TEST(BufConvTest, ZeroCopyChainedBuffer) {
  auto buf1 = createBuffer<TypeParam>("hello");
  auto buf2 = createBuffer<TypeParam>(" ");
  auto buf3 = createBuffer<TypeParam>("world");

  const void* ptr1 = buf1->data();
  const void* ptr2 = buf2->data();
  const void* ptr3 = buf3->data();

  buf1->appendToChain(std::move(buf2));
  buf1->appendToChain(std::move(buf3));

  auto dstBuf = convert(std::move(buf1));

  ASSERT_EQ(buf1, nullptr);
  ASSERT_NE(dstBuf, nullptr);
  EXPECT_TRUE(dstBuf->isChained());

  std::vector<const void*> dstPtrs;
  for (const auto& range : *dstBuf) {
    dstPtrs.push_back(range.data());
  }

  ASSERT_EQ(dstPtrs.size(), 3);
  EXPECT_EQ(dstPtrs[0], ptr1)
      << "First buffer in chain was copied instead of being transferred";
  EXPECT_EQ(dstPtrs[1], ptr2)
      << "Second buffer in chain was copied instead of being transferred";
  EXPECT_EQ(dstPtrs[2], ptr3)
      << "Third buffer in chain was copied instead of being transferred";
}

TYPED_TEST(BufConvTest, ChainedBufferWithCoalesce) {
  auto buf1 = createBuffer<TypeParam>("hello");
  auto buf2 = createBuffer<TypeParam>(" ");
  auto buf3 = createBuffer<TypeParam>("world");

  buf1->appendToChain(std::move(buf2));
  buf1->appendToChain(std::move(buf3));

  EXPECT_TRUE(buf1->isChained());
  EXPECT_EQ(buf1->countChainElements(), 3);

  auto dstBuf = convert(std::move(buf1));

  ASSERT_EQ(buf1, nullptr);
  ASSERT_NE(dstBuf, nullptr);
  EXPECT_TRUE(dstBuf->isChained());

  dstBuf->coalesce();

  EXPECT_FALSE(dstBuf->isChained());
  EXPECT_EQ(dstBuf->countChainElements(), 1);
  EXPECT_EQ(dstBuf->length(), 11);
  EXPECT_EQ(
      std::string(
          reinterpret_cast<const char*>(dstBuf->data()), dstBuf->length()),
      "hello world");
}

} // namespace quic::follyutils
