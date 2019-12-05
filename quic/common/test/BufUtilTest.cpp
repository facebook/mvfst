/*
 * Copyright (c) Facebook, Inc. and its affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 *
 */

#include <gtest/gtest.h>

#include <folly/String.h>
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
  prefix = queue.split(3);
  EXPECT_EQ(3, prefix->computeChainDataLength());
  EXPECT_EQ(3, queue.chainLength());
  checkConsistency(queue);

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

TEST(BufQueue, SplitEmpty) {
  BufQueue queue;
  auto buf = queue.split(0);
  EXPECT_EQ(buf->computeChainDataLength(), 0);
}

TEST(BufQueue, SplitEmptyInvalid) {
  BufQueue queue;
  EXPECT_THROW(queue.split(1), std::underflow_error);
}

TEST(BufQueue, TrimStartAtMost) {
  BufQueue queue;
  queue.append(IOBuf::copyBuffer(SCL("Hello")));
  auto prefixLen = queue.trimStartAtMost(3);
  EXPECT_EQ(3, prefixLen);
  EXPECT_EQ(2, queue.chainLength());
  checkConsistency(queue);

  prefixLen = queue.trimStartAtMost(2);
  EXPECT_EQ(2, prefixLen);
  EXPECT_EQ(0, queue.chainLength());
  checkConsistency(queue);

  queue.append(IOBuf::copyBuffer(SCL("Hello")));
  queue.append(IOBuf::copyBuffer(SCL("World")));
  prefixLen = queue.trimStartAtMost(7);
  EXPECT_EQ(7, prefixLen);
  EXPECT_EQ(3, queue.chainLength());
  checkConsistency(queue);

  prefixLen = queue.trimStartAtMost(10);
  EXPECT_EQ(3, prefixLen);
  EXPECT_EQ(0, queue.chainLength());
  checkConsistency(queue);

  queue.append(IOBuf::copyBuffer(SCL("Hello")));
  queue.append(IOBuf::copyBuffer(SCL("World")));

  prefixLen = queue.trimStartAtMost(12);
  EXPECT_EQ(10, prefixLen);
  EXPECT_EQ(0, queue.chainLength());
  checkConsistency(queue);

  queue.append(IOBuf::copyBuffer(SCL("Hello")));
  queue.append(IOBuf::copyBuffer(SCL("World")));
  queue.append(IOBuf::copyBuffer(SCL("Hello")));

  prefixLen = queue.trimStartAtMost(12);
  EXPECT_EQ(12, prefixLen);
  EXPECT_EQ(3, queue.chainLength());
  checkConsistency(queue);
}

TEST(BufAppender, TestPushAlreadyFits) {
  std::unique_ptr<folly::IOBuf> data = folly::IOBuf::create(10);
  BufAppender appender(data.get(), 10);
  std::string str = "12456";
  appender.push((uint8_t*)str.data(), str.size());
  EXPECT_EQ(data->computeChainDataLength(), str.size());
  EXPECT_EQ(data->countChainElements(), 1);
  EXPECT_EQ(data->moveToFbString().toStdString(), str);
}

TEST(BufAppender, TestPushLargerThanAppendLen) {
  std::unique_ptr<folly::IOBuf> data = folly::IOBuf::create(10);
  BufAppender appender(data.get(), 10);
  std::string str = "12456134134134134134134";
  appender.push((uint8_t*)str.data(), str.size());
  EXPECT_EQ(data->computeChainDataLength(), str.size());
  EXPECT_EQ(data->moveToFbString().toStdString(), str);
}

TEST(BufAppender, TestPushExpands) {
  std::unique_ptr<folly::IOBuf> data = folly::IOBuf::create(0);
  BufAppender appender(data.get(), 20);
  std::string str = "12456";
  appender.push((uint8_t*)str.data(), str.size());
  appender.push((uint8_t*)str.data(), str.size());
  EXPECT_EQ(data->computeChainDataLength(), str.size() * 2);

  appender.push((uint8_t*)str.data(), str.size());
  appender.push((uint8_t*)str.data(), str.size());
  appender.push((uint8_t*)str.data(), str.size());
  EXPECT_EQ(data->computeChainDataLength(), str.size() * 5);

  std::string expected = str + str + str + str + str;
  EXPECT_EQ(data->moveToFbString().toStdString(), expected);
}

TEST(BufAppender, TestInsertIOBuf) {
  std::unique_ptr<folly::IOBuf> data = folly::IOBuf::create(0);
  BufAppender appender(data.get(), 20);
  std::string str = "12456";
  appender.push((uint8_t*)str.data(), str.size());
  appender.push((uint8_t*)str.data(), str.size());

  auto hello = IOBuf::copyBuffer("helloworld");
  hello->trimEnd(4);
  appender.insert(hello->clone());

  appender.push((uint8_t*)str.data(), str.size());
  appender.insert(hello->clone());

  EXPECT_EQ(
      data->computeChainDataLength(), str.size() * 3 + hello->length() * 2);

  auto helloStr = hello->clone()->moveToFbString().toStdString();
  std::string expected = str + str + helloStr + str + helloStr;
  EXPECT_EQ(data->moveToFbString().toStdString(), expected);
  hello->append(4);
  EXPECT_EQ(hello->moveToFbString().toStdString(), "helloworld");
}

TEST(BufAppender, TestInsertIOBufMoved) {
  std::unique_ptr<folly::IOBuf> data = folly::IOBuf::create(0);
  BufAppender appender(data.get(), 20);
  std::string str = "12456";
  appender.push((uint8_t*)str.data(), str.size());
  appender.push((uint8_t*)str.data(), str.size());

  auto hello = IOBuf::copyBuffer("helloworld");
  hello->trimEnd(5);

  size_t helloLen = hello->length();

  folly::IOBuf* helloPtr = hello.get();
  appender.insert(std::move(hello));

  appender.push((uint8_t*)str.data(), str.size());

  EXPECT_EQ(data->computeChainDataLength(), str.size() * 3 + helloLen);

  // test that the bufAppender uses the tailroom that is available in the hello
  // buffer.
  auto helloStr = helloPtr->cloneOne()->moveToFbString().toStdString();
  std::string expected = str + str + "hello" + str;
  EXPECT_EQ(data->moveToFbString().toStdString(), expected);
  EXPECT_EQ(helloStr, "hello12456");
}

TEST(BufAppender, TestBigEndianOneByte) {
  uint8_t oneByte = 0x12;

  std::unique_ptr<folly::IOBuf> data = folly::IOBuf::create(0);
  BufAppender appender(data.get(), 20);
  appender.writeBE(oneByte);
  std::string out = folly::hexlify(data->coalesce());
  EXPECT_EQ(out, "12");
}

TEST(BufAppender, TestBigEndianTwoBytes) {
  uint16_t twoBytes = 0x3412;

  std::unique_ptr<folly::IOBuf> data = folly::IOBuf::create(0);
  BufAppender appender(data.get(), 20);
  appender.writeBE(twoBytes);
  std::string out = folly::hexlify(data->coalesce());
  EXPECT_EQ(out, "3412");
}

TEST(BufAppender, TestBigEndianFourBytes) {
  uint32_t fourBytes = 0x78563412;

  std::unique_ptr<folly::IOBuf> data = folly::IOBuf::create(0);
  BufAppender appender(data.get(), 20);
  appender.writeBE(fourBytes);
  std::string out = folly::hexlify(data->coalesce());
  EXPECT_EQ(out, "78563412");
}

TEST(BufAppender, TestBigEndianEightBytes) {
  uint64_t eightBytes = 0xBC9A78563412;

  std::unique_ptr<folly::IOBuf> data = folly::IOBuf::create(0);
  BufAppender appender(data.get(), 20);
  appender.writeBE(eightBytes);
  std::string out = folly::hexlify(data->coalesce());
  EXPECT_EQ(out, "0000bc9a78563412");
}
