/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <gtest/gtest.h>

#include <folly/String.h>
#include <folly/io/Cursor.h>
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

  unique_ptr<IOBuf> prefix(queue.splitAtMost(1));
  checkConsistency(queue);
  EXPECT_EQ(1, prefix->computeChainDataLength());
  EXPECT_EQ(11, queue.front()->computeChainDataLength());
  EXPECT_EQ(prefix->to<std::string>(), "H");

  prefix = queue.splitAtMost(2);
  checkConsistency(queue);
  EXPECT_EQ(2, prefix->computeChainDataLength());
  EXPECT_EQ(9, queue.front()->computeChainDataLength());
  EXPECT_EQ(prefix->to<std::string>(), "el");

  prefix = queue.splitAtMost(3);
  checkConsistency(queue);
  EXPECT_EQ(3, prefix->computeChainDataLength());
  EXPECT_EQ(6, queue.front()->computeChainDataLength());
  EXPECT_EQ(prefix->to<std::string>(), "lo,");

  prefix = queue.splitAtMost(1);
  checkConsistency(queue);
  EXPECT_EQ(1, prefix->computeChainDataLength());
  EXPECT_EQ(5, queue.front()->computeChainDataLength());
  EXPECT_EQ(prefix->to<std::string>(), " ");

  prefix = queue.splitAtMost(5);
  checkConsistency(queue);
  EXPECT_EQ(5, prefix->computeChainDataLength());
  EXPECT_EQ((IOBuf*)nullptr, queue.front());
  EXPECT_EQ(prefix->to<std::string>(), "World");

  queue.append(IOBuf::copyBuffer(SCL("Hello,")));
  checkConsistency(queue);
  prefix = queue.splitAtMost(3);
  checkConsistency(queue);
  EXPECT_EQ(3, prefix->computeChainDataLength());
  EXPECT_EQ(3, queue.chainLength());
  EXPECT_EQ(prefix->to<std::string>(), "Hel");

  queue.append(IOBuf::copyBuffer(SCL(" World")));
  checkConsistency(queue);
  prefix = queue.splitAtMost(13);
  EXPECT_EQ(9, prefix->computeChainDataLength());
  EXPECT_EQ(0, queue.chainLength());
  EXPECT_EQ(prefix->to<std::string>(), "lo, World");
  checkConsistency(queue);
}

TEST(BufQueue, SplitZero) {
  BufQueue queue;
  queue.append(IOBuf::copyBuffer(SCL("Hello world")));
  auto buf = queue.splitAtMost(0);
  EXPECT_EQ(buf->computeChainDataLength(), 0);
}

TEST(BufQueue, SplitEmpty) {
  BufQueue queue;
  auto buf = queue.splitAtMost(0);
  EXPECT_EQ(buf->computeChainDataLength(), 0);
}

TEST(BufQueue, SplitEmptt) {
  BufQueue queue;
  auto res = queue.splitAtMost(1);
  EXPECT_EQ(res->computeChainDataLength(), 0);
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

TEST(BufQueue, TrimStartOneByte) {
  BufQueue queue;
  queue.append(IOBuf::copyBuffer(SCL("H")));
  checkConsistency(queue);
  queue.trimStart(1);
  checkConsistency(queue);
  // trimStart(queue.chainLength()) should not free the buffer
  EXPECT_NE(queue.front(), nullptr);
}

TEST(BufQueue, TrimStartClearChain) {
  BufQueue queue;
  constexpr string_view alphabet = "abcdefghijklmnopqrstuvwxyz";
  queue.append(IOBuf::copyBuffer(alphabet));
  queue.append(IOBuf::copyBuffer(alphabet));
  // validate chain length
  const size_t expectedChainLength = alphabet.size() * 2;
  EXPECT_EQ(queue.chainLength(), expectedChainLength);
  checkConsistency(queue);
  // attempt to trim more than chainLength
  queue.trimStartAtMost(expectedChainLength + 1);
  checkConsistency(queue);
  EXPECT_EQ(queue.front(), nullptr);
}

TEST(BufQueue, CloneBufNull) {
  BufQueue queue;
  auto buf = queue.clone();
  EXPECT_EQ(nullptr, buf);
}

TEST(BufQueue, CloneBuf) {
  std::string s("Hello, World");
  BufQueue queue;
  queue.append(IOBuf::copyBuffer(s.data(), s.length()));
  auto buf = queue.clone();
  const IOBuf* chain = queue.front();
  EXPECT_EQ(s.length(), chain->computeChainDataLength());
  EXPECT_EQ(s.length(), buf->computeChainDataLength());
  EXPECT_EQ(0, memcmp(chain->data(), buf->data(), s.length()));
  queue.append(IOBuf::copyBuffer(s.data(), s.length()));
  EXPECT_EQ(2 * s.length(), chain->computeChainDataLength());
  EXPECT_EQ(s.length(), buf->computeChainDataLength());
  buf = queue.clone();
  EXPECT_EQ(2 * s.length(), buf->computeChainDataLength());
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

TEST(BufWriterTest, BasicWrite) {
  auto testBuffer = folly::IOBuf::create(100);
  BufWriter writer(*testBuffer, 100);
  uint8_t eight = 8;
  uint16_t sixteen = 16;
  uint32_t thirtytwo = 32;
  uint64_t sixtyfour = 64;
  writer.writeBE(eight);
  writer.writeBE(sixteen);
  writer.writeBE(thirtytwo);
  writer.writeBE(sixtyfour);

  folly::io::Cursor reader(testBuffer.get());
  EXPECT_EQ(8, reader.template readBE<uint8_t>());
  EXPECT_EQ(16, reader.template readBE<uint16_t>());
  EXPECT_EQ(32, reader.template readBE<uint32_t>());
  EXPECT_EQ(64, reader.template readBE<uint64_t>());
}

#ifndef NDEBUG
TEST(BufWriterTest, WriteLimit) {
  auto testBuffer = folly::IOBuf::create(100);
  BufWriter writer(*testBuffer, 0);
  uint8_t eight = 8;
  EXPECT_DEATH(writer.writeBE(eight), "");
}

TEST(BufWriterTest, PushLimit) {
  auto testBuffer = folly::IOBuf::create(100);
  BufWriter writer(*testBuffer, 100);
  auto biggerBuffer = folly::IOBuf::create(200);
  EXPECT_DEATH(writer.push(biggerBuffer->data(), 200), "");
}
#endif

TEST(BufWriterTest, Push) {
  auto testBuffer = folly::IOBuf::create(100);
  BufWriter writer(*testBuffer, 100);
  auto inputBuffer =
      folly::IOBuf::copyBuffer("All you're gonna see it someday");
  writer.push(inputBuffer->data(), inputBuffer->computeChainDataLength());
  folly::io::Cursor reader(testBuffer.get());
  EXPECT_EQ(
      "All you're gonna see it someday",
      reader.readFixedString(inputBuffer->computeChainDataLength()));
}

TEST(BufWriterTest, InsertSingle) {
  auto testBuffer = folly::IOBuf::create(100);
  BufWriter writer(*testBuffer, 100);
  auto inputBuffer =
      folly::IOBuf::copyBuffer("Steady on dreaming, I sleepwalk");
  auto len = inputBuffer->computeChainDataLength();
  writer.insert(inputBuffer.get());
  folly::io::Cursor reader(testBuffer.get());
  EXPECT_EQ(inputBuffer->to<string>(), reader.readFixedString(len));
}

TEST(BufWriterTest, InsertChain) {
  auto testBuffer = folly::IOBuf::create(1000);
  BufWriter writer(*testBuffer, 1000);
  auto inputBuffer =
      folly::IOBuf::copyBuffer("Cause I lost you and now what am i to do?");
  inputBuffer->prependChain(
      folly::IOBuf::copyBuffer(" Can't believe that we are through."));
  inputBuffer->prependChain(
      folly::IOBuf::copyBuffer(" While the memory of you linger like a song."));
  auto len = inputBuffer->computeChainDataLength();
  writer.insert(inputBuffer.get());
  folly::io::Cursor reader(testBuffer.get());
  EXPECT_EQ(
      "Cause I lost you and now what am i to do?"
      " Can't believe that we are through."
      " While the memory of you linger like a song.",
      reader.readFixedString(len));
}

TEST(BufWriterTest, BackFill) {
  auto testBuffer = folly::IOBuf::create(100);
  BufWriter bufWriter(*testBuffer, 100);
  std::string testInput1("1 2 3 4 5");
  std::string testInput2(" 11 12 13 14 15");
  std::string testInput3(" 6 7 8 9 10");
  bufWriter.push((uint8_t*)testInput1.data(), testInput1.size());
  bufWriter.append(testInput3.size());
  bufWriter.push((uint8_t*)testInput2.data(), testInput2.size());
  bufWriter.backFill(
      (uint8_t*)testInput3.data(), testInput3.size(), testInput1.size());
  folly::io::Cursor reader(testBuffer.get());
  EXPECT_EQ(
      "1 2 3 4 5 6 7 8 9 10 11 12 13 14 15",
      reader.readFixedString(
          testInput1.size() + testInput2.size() + testInput3.size()));
}

TEST(BufWriterTest, BufQueueCopy) {
  BufQueue queue;
  queue.append(folly::IOBuf::copyBuffer("I feel like I'm drowning"));
  auto outputBuffer = folly::IOBuf::create(200);
  BufWriter bufWriter(*outputBuffer, 200);
  bufWriter.insert(queue.front(), queue.chainLength());
  folly::io::Cursor reader(outputBuffer.get());
  EXPECT_EQ(
      "I feel like I'm drowning", reader.readFixedString(queue.chainLength()));
}

TEST(BufWriterTest, BufQueueCopyPartial) {
  BufQueue queue;
  queue.append(folly::IOBuf::copyBuffer("I feel like I'm drowning"));
  auto outputBuffer = folly::IOBuf::create(200);
  BufWriter bufWriter(*outputBuffer, 200);
  bufWriter.insert(queue.front(), 6);
  folly::io::Cursor reader(outputBuffer.get());
  EXPECT_EQ(
      "I feel", reader.readFixedString(outputBuffer->computeChainDataLength()));
}

TEST(BufWriterTest, BufQueueChainCopy) {
  BufQueue queue;
  queue.append(folly::IOBuf::copyBuffer("I'm a hotpot. "));
  queue.append(folly::IOBuf::copyBuffer("You mere are hotpot soup base."));
  auto outputBuffer = folly::IOBuf::create(1000);
  BufWriter bufWriter(*outputBuffer, 1000);
  bufWriter.insert(queue.front(), queue.chainLength());
  folly::io::Cursor reader(outputBuffer.get());
  EXPECT_EQ(
      "I'm a hotpot. You mere are hotpot soup base.",
      reader.readFixedString(queue.chainLength()));
}

TEST(BufWriterTest, BufQueueChainCopyPartial) {
  BufQueue queue;
  std::string testStr1("I remember when I first noticed. ");
  std::string testStr2("That you liked me back.");
  queue.append(folly::IOBuf::copyBuffer(testStr1));
  queue.append(folly::IOBuf::copyBuffer(testStr2));
  auto outputBuffer = folly::IOBuf::create(1000);
  BufWriter bufWriter(*outputBuffer, 1000);
  bufWriter.insert(queue.front(), testStr1.size() + 10);
  folly::io::Cursor reader(outputBuffer.get());
  EXPECT_EQ(
      folly::to<std::string>(testStr1, "That you l"),
      reader.readFixedString(testStr1.size() + 10));
}

TEST(BufWriterTest, IOBufChainCopyTooLargeLimit) {
  auto outputBuffer = folly::IOBuf::create(1000);
  BufWriter bufWriter(*outputBuffer, 1000);
  auto inputBuffer =
      folly::IOBuf::copyBuffer("Tired of seeing adventures on a cafe wall. ");
  inputBuffer->prependChain(
      folly::IOBuf::copyBuffer("Think I'll take a turn from the known road. "));
  inputBuffer->prependChain(
      folly::IOBuf::copyBuffer("Think I'll write a tale of my own."));
  // Use a limit that's larger than input size
  bufWriter.insert(
      inputBuffer.get(), inputBuffer->computeChainDataLength() * 3);
  folly::io::Cursor reader(outputBuffer.get());
  EXPECT_EQ(
      "Tired of seeing adventures on a cafe wall. "
      "Think I'll take a turn from the known road. "
      "Think I'll write a tale of my own.",
      reader.readFixedString(outputBuffer->computeChainDataLength()));
}

TEST(BufWriterTest, BufQueueChainCopyTooLargeLimit) {
  BufQueue queue;
  std::string testStr1("I see trees of green. ");
  std::string testStr2("Red rose too. ");
  std::string testStr3("I see them bloom.");
  queue.append(folly::IOBuf::copyBuffer(testStr1));
  queue.append(folly::IOBuf::copyBuffer(testStr2));
  queue.append(folly::IOBuf::copyBuffer(testStr3));
  auto outputBuffer = folly::IOBuf::create(1000);
  BufWriter bufWriter(*outputBuffer, 1000);
  bufWriter.insert(
      queue.front(), (testStr1.size() + testStr2.size() + testStr3.size()) * 5);
  folly::io::Cursor reader(outputBuffer.get());
  EXPECT_EQ(
      "I see trees of green. "
      "Red rose too. "
      "I see them bloom.",
      reader.readFixedString(
          testStr1.size() + testStr2.size() + testStr3.size()));
}

TEST(BufWriterTest, TwoWriters) {
  auto outputBuffer = folly::IOBuf::create(1000);
  auto inputBuffer = folly::IOBuf::copyBuffer("Destroyer");
  BufWriter bufWriter(*outputBuffer, 1000);
  bufWriter.insert(inputBuffer.get());
  EXPECT_EQ(9, outputBuffer->length());

  BufWriter bufWriter2(*outputBuffer, outputBuffer->length());
  auto inputBuffer2 = folly::IOBuf::copyBuffer(" Saint");
  bufWriter2.insert(inputBuffer2.get());
  folly::io::Cursor reader(outputBuffer.get());
  EXPECT_EQ(15, outputBuffer->length());
  EXPECT_EQ("Destroyer Saint", reader.readFixedString(outputBuffer->length()));
}
