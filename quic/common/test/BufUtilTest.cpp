/*
 * Copyright (c) Facebook, Inc. and its affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 *
 */

#include <gtest/gtest.h>

#include <quic/common/BufUtil.h>

using namespace std;
using namespace folly;
using namespace quic;

#define SCL(x) (x), sizeof(x) - 1

namespace {

void checkConsistency(const BufQueue& queue) {
  size_t len = queue.front() ? queue.front()->computeChainDataLength() : 0;
  EXPECT_EQ(len, queue.chainLength());
}

} // namespace

TEST(BufQueue, Append) {
  BufQueue queue;
  queue.append(IOBuf::copyBuffer(SCL("Hello")));
  BufQueue queue2;
  queue2.append(IOBuf::copyBuffer(SCL(", ")));
  queue2.append(IOBuf::copyBuffer(SCL("World")));
  checkConsistency(queue);
  checkConsistency(queue2);
  queue.append(queue2.move());
  checkConsistency(queue);
  checkConsistency(queue2);
  const IOBuf* chain = queue.front();
  EXPECT_NE((IOBuf*)nullptr, chain);
  EXPECT_EQ(12, chain->computeChainDataLength());
  EXPECT_EQ(nullptr, queue2.front());
}

TEST(BufQueue, Append2) {
  BufQueue queue;
  queue.append(IOBuf::copyBuffer(SCL("Hello")));
  BufQueue queue2;
  queue2.append(IOBuf::copyBuffer(SCL(", ")));
  queue2.append(IOBuf::copyBuffer(SCL("World")));
  checkConsistency(queue);
  checkConsistency(queue2);
}

TEST(BufQueue, AppendStringPiece) {
  std::string s("Hello, World");
  BufQueue queue;
  BufQueue queue2;
  queue.append(IOBuf::copyBuffer(s.data(), s.length()));
  queue2.append(IOBuf::copyBuffer(s));
  checkConsistency(queue);
  checkConsistency(queue2);
  const IOBuf* chain = queue.front();
  const IOBuf* chain2 = queue2.front();
  EXPECT_EQ(s.length(), chain->computeChainDataLength());
  EXPECT_EQ(s.length(), chain2->computeChainDataLength());
  EXPECT_EQ(0, memcmp(chain->data(), chain2->data(), s.length()));
}

TEST(BufQueue, Split) {
  BufQueue queue;
  queue.append(IOBuf::copyBuffer(SCL("Hello")));
  queue.append(IOBuf::copyBuffer(SCL(",")));
  queue.append(IOBuf::copyBuffer(SCL(" ")));
  queue.append(IOBuf::copyBuffer(SCL("")));
  queue.append(IOBuf::copyBuffer(SCL("World")));
  checkConsistency(queue);
  EXPECT_EQ(12, queue.front()->computeChainDataLength());

  unique_ptr<IOBuf> prefix(queue.split(1));
  checkConsistency(queue);
  EXPECT_EQ(1, prefix->computeChainDataLength());
  EXPECT_EQ(11, queue.front()->computeChainDataLength());
  prefix = queue.split(2);
  checkConsistency(queue);
  EXPECT_EQ(2, prefix->computeChainDataLength());
  EXPECT_EQ(9, queue.front()->computeChainDataLength());
  prefix = queue.split(3);
  checkConsistency(queue);
  EXPECT_EQ(3, prefix->computeChainDataLength());
  EXPECT_EQ(6, queue.front()->computeChainDataLength());
  prefix = queue.split(1);
  checkConsistency(queue);
  EXPECT_EQ(1, prefix->computeChainDataLength());
  EXPECT_EQ(5, queue.front()->computeChainDataLength());
  prefix = queue.split(5);
  checkConsistency(queue);
  EXPECT_EQ(5, prefix->computeChainDataLength());
  EXPECT_EQ((IOBuf*)nullptr, queue.front());

  queue.append(IOBuf::copyBuffer(SCL("Hello,")));
  queue.append(IOBuf::copyBuffer(SCL(" World")));
  checkConsistency(queue);
  EXPECT_THROW({ prefix = queue.split(13); }, std::underflow_error);
  checkConsistency(queue);
}

TEST(BufQueue, SplitZero) {
  BufQueue queue;
  queue.append(IOBuf::copyBuffer(SCL("Hello world")));
  auto buf = queue.split(0);
  EXPECT_EQ(buf->computeChainDataLength(), 0);
}
