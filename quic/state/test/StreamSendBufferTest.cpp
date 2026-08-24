/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <quic/state/StreamSendBuffer.h>

#include <string>

#include <folly/portability/GTest.h>

namespace quic::test {
namespace {

BufPtr makeBuffer(const std::string& data) {
  return folly::IOBuf::copyBuffer(data);
}

BufPtr makeChainedBuffer(const std::string& first, const std::string& second) {
  auto buffer = makeBuffer(first);
  if (!buffer) {
    return nullptr;
  }
  auto secondBuffer = makeBuffer(second);
  if (!secondBuffer) {
    return nullptr;
  }
  buffer->appendChain(std::move(secondBuffer));
  return buffer;
}

bool writeToString(
    const StreamSendBuffer& buffer,
    uint64_t offset,
    uint64_t len,
    std::string& output) {
  auto writer = [&output](ByteRange range) {
    output.append(reinterpret_cast<const char*>(range.data()), range.size());
    return true;
  };
  return buffer.writeAt(offset, len, writer);
}

void expectRange(
    const Optional<StreamSendBuffer::SendRange>& actual,
    const StreamSendBuffer::SendRange& expected) {
  ASSERT_TRUE(actual.has_value());
  EXPECT_EQ(expected, *actual);
}

TEST(StreamSendBufferTest, WritesBoundedRangesAcrossOwnedEntries) {
  StreamSendBuffer buffer;
  EXPECT_TRUE(buffer.append(makeChainedBuffer("abc", "def"), false));
  EXPECT_TRUE(buffer.append(makeBuffer("ghi"), true));

  std::string output;
  EXPECT_TRUE(writeToString(buffer, 2, 5, output));
  EXPECT_EQ("cdefg", output);
  EXPECT_FALSE(writeToString(buffer, 7, 3, output));

  expectRange(buffer.nextNewData(4), {.offset = 0, .len = 4, .fin = false});
  EXPECT_TRUE(buffer.markNewDataSent({0, 4, false}));
  expectRange(buffer.nextNewData(10), {.offset = 4, .len = 5, .fin = true});
  EXPECT_TRUE(buffer.markNewDataSent({4, 5, true}));
  EXPECT_EQ(9, buffer.outstandingBytes());
  EXPECT_FALSE(buffer.nextNewData(10).has_value());
}

TEST(StreamSendBufferTest, FindsRangesAcrossManyEntriesOutOfOrder) {
  StreamSendBuffer buffer;
  std::string expected;
  for (size_t i = 0; i < 128; ++i) {
    const std::string entry(3, static_cast<char>('a' + i % 26));
    expected.append(entry);
    ASSERT_TRUE(buffer.append(makeBuffer(entry), false));
  }

  for (const auto offset : {255, 0, 126, 378, 63, 300}) {
    std::string output;
    ASSERT_TRUE(writeToString(buffer, offset, 6, output));
    EXPECT_EQ(expected.substr(offset, 6), output);
  }
}

TEST(StreamSendBufferTest, AckIsIdempotentForPartialOverlappingRanges) {
  StreamSendBuffer buffer;
  ASSERT_TRUE(buffer.append(makeBuffer(std::string(20, 'a')), false));
  ASSERT_TRUE(buffer.markNewDataSent({0, 20, false}));

  auto ack = buffer.markAcked({.offset = 5, .len = 5, .fin = false});
  ASSERT_TRUE(ack.has_value());
  EXPECT_EQ(5, ack->newlyAckedBytes);
  EXPECT_EQ(15, buffer.outstandingBytes());

  ack = buffer.markAcked({.offset = 0, .len = 8, .fin = false});
  ASSERT_TRUE(ack.has_value());
  EXPECT_EQ(5, ack->newlyAckedBytes);
  EXPECT_EQ(10, buffer.outstandingBytes());

  ack = buffer.markAcked({.offset = 8, .len = 4, .fin = false});
  ASSERT_TRUE(ack.has_value());
  EXPECT_EQ(2, ack->newlyAckedBytes);
  ack = buffer.markAcked({.offset = 15, .len = 5, .fin = false});
  ASSERT_TRUE(ack.has_value());
  EXPECT_EQ(5, ack->newlyAckedBytes);
  ack = buffer.markAcked({.offset = 10, .len = 5, .fin = false});
  ASSERT_TRUE(ack.has_value());
  EXPECT_EQ(3, ack->newlyAckedBytes);
  EXPECT_EQ(0, buffer.outstandingBytes());

  ack = buffer.markAcked({.offset = 0, .len = 20, .fin = false});
  ASSERT_TRUE(ack.has_value());
  EXPECT_EQ(0, ack->newlyAckedBytes);
}

TEST(StreamSendBufferTest, AckBeforeLossOnlySchedulesUnackedBytes) {
  StreamSendBuffer buffer;
  ASSERT_TRUE(buffer.append(makeBuffer(std::string(8, 'a')), false));
  ASSERT_TRUE(buffer.markNewDataSent({0, 8, false}));
  ASSERT_TRUE(buffer.markAcked({2, 4, false}).has_value());

  buffer.markLoss({.offset = 0, .len = 8, .fin = false});
  expectRange(buffer.nextLoss(8), {.offset = 0, .len = 2, .fin = false});
  buffer.markRetransmissionSent({.offset = 0, .len = 2, .fin = false});
  expectRange(buffer.nextLoss(8), {.offset = 6, .len = 2, .fin = false});
  buffer.markRetransmissionSent({.offset = 6, .len = 2, .fin = false});
  EXPECT_FALSE(buffer.hasPendingLoss());
}

TEST(StreamSendBufferTest, AckAfterLossWithdrawsPendingBytes) {
  StreamSendBuffer buffer;
  ASSERT_TRUE(buffer.append(makeBuffer(std::string(10, 'a')), false));
  ASSERT_TRUE(buffer.markNewDataSent({0, 10, false}));

  buffer.markLoss({.offset = 0, .len = 10, .fin = false});
  buffer.markLoss({.offset = 0, .len = 10, .fin = false});
  ASSERT_TRUE(buffer.markAcked({3, 4, false}).has_value());
  expectRange(buffer.nextLoss(10), {.offset = 0, .len = 3, .fin = false});
  buffer.markRetransmissionSent({.offset = 0, .len = 3, .fin = false});
  expectRange(buffer.nextLoss(10), {.offset = 7, .len = 3, .fin = false});
  ASSERT_TRUE(buffer.markAcked({7, 3, false}).has_value());
  EXPECT_FALSE(buffer.hasPendingLoss());
}

TEST(StreamSendBufferTest, FindsNextFragmentedLossAtOrAfterOffset) {
  StreamSendBuffer buffer;
  ASSERT_TRUE(buffer.append(makeBuffer(std::string(64, 'a')), false));
  ASSERT_TRUE(buffer.markNewDataSent({.offset = 0, .len = 64, .fin = false}));
  for (uint64_t offset = 0; offset < 64; offset += 2) {
    buffer.markLoss({.offset = offset, .len = 1, .fin = false});
  }

  for (uint64_t offset = 1; offset < 63; offset += 2) {
    expectRange(
        buffer.nextLossAfter(offset, false, 1),
        {.offset = offset + 1, .len = 1, .fin = false});
  }
  EXPECT_FALSE(buffer.nextLossAfter(64, false, 1).has_value());
}

TEST(StreamSendBufferTest, FinOnlyTracksSendLossAndAckIndependently) {
  StreamSendBuffer buffer;
  ASSERT_TRUE(buffer.append(nullptr, true));
  expectRange(buffer.nextNewData(0), {.offset = 0, .len = 0, .fin = true});
  ASSERT_TRUE(buffer.markNewDataSent({0, 0, true}));
  EXPECT_TRUE(buffer.finSent());
  EXPECT_EQ(0, buffer.outstandingBytes());

  buffer.markLoss({.offset = 0, .len = 0, .fin = true});
  EXPECT_TRUE(buffer.finLost());
  expectRange(buffer.nextLoss(0), {.offset = 0, .len = 0, .fin = true});
  buffer.markRetransmissionSent({.offset = 0, .len = 0, .fin = true});
  EXPECT_FALSE(buffer.finLost());

  auto ack = buffer.markAcked({.offset = 0, .len = 0, .fin = true});
  ASSERT_TRUE(ack.has_value());
  EXPECT_TRUE(ack->newlyAckedFin);
  ack = buffer.markAcked({.offset = 0, .len = 0, .fin = true});
  ASSERT_TRUE(ack.has_value());
  EXPECT_FALSE(ack->newlyAckedFin);
  EXPECT_FALSE(
      buffer.markAcked({.offset = 0, .len = 0, .fin = false}).has_value());
}

TEST(StreamSendBufferTest, DataAndFinShareRangeStateTransitions) {
  StreamSendBuffer buffer;
  ASSERT_TRUE(buffer.append(makeBuffer("abc"), true));
  expectRange(buffer.nextNewData(10), {.offset = 0, .len = 3, .fin = true});
  ASSERT_TRUE(buffer.markNewDataSent({0, 3, true}));

  buffer.markLoss({.offset = 0, .len = 3, .fin = true});
  expectRange(buffer.nextLoss(10), {.offset = 0, .len = 3, .fin = true});
  buffer.markRetransmissionSent({.offset = 0, .len = 3, .fin = true});
  EXPECT_FALSE(buffer.hasPendingLoss());

  auto ack = buffer.markAcked({.offset = 0, .len = 3, .fin = true});
  ASSERT_TRUE(ack.has_value());
  EXPECT_EQ(3, ack->newlyAckedBytes);
  EXPECT_TRUE(ack->newlyAckedFin);
  EXPECT_TRUE(buffer.finAcked());
  EXPECT_EQ(0, buffer.outstandingBytes());
  EXPECT_TRUE(buffer.allBytesAckedTill(3));
  ASSERT_TRUE(buffer.largestDeliverableOffset().has_value());
  EXPECT_EQ(3u, *buffer.largestDeliverableOffset());
}

TEST(StreamSendBufferTest, AckMetadataMatchesDeliveryOffsetSemantics) {
  StreamSendBuffer buffer;
  ASSERT_TRUE(buffer.append(makeBuffer("abc"), true));
  ASSERT_TRUE(buffer.markNewDataSent({0, 3, true}));

  EXPECT_EQ(0, buffer.ackInsertVersion());
  ASSERT_TRUE(buffer.markAcked({1, 2, true}).has_value());
  EXPECT_EQ(1, buffer.ackInsertVersion());
  EXPECT_FALSE(buffer.largestDeliverableOffset().has_value());

  ASSERT_TRUE(buffer.markAcked({0, 1, false}).has_value());
  EXPECT_EQ(2, buffer.ackInsertVersion());
  ASSERT_TRUE(buffer.largestDeliverableOffset().has_value());
  EXPECT_EQ(3u, *buffer.largestDeliverableOffset());
  EXPECT_TRUE(buffer.allBytesAckedTill(3));

  ASSERT_TRUE(buffer.markAcked({1, 2, true}).has_value());
  EXPECT_EQ(2, buffer.ackInsertVersion());
  EXPECT_FALSE(buffer.markAcked({0, 0, false}).has_value());
}

TEST(StreamSendBufferTest, AppendAfterFinIsRejected) {
  StreamSendBuffer buffer;
  ASSERT_TRUE(buffer.append(makeBuffer("abc"), true));
  EXPECT_FALSE(buffer.append(makeBuffer("def"), false));
  EXPECT_EQ(3, buffer.tailOffset());

  std::string output;
  ASSERT_TRUE(writeToString(buffer, 0, 3, output));
  EXPECT_EQ("abc", output);
}

TEST(StreamSendBufferTest, EmptyWriteWithoutFinIsAcceptedAsNoOp) {
  StreamSendBuffer buffer;

  EXPECT_TRUE(buffer.append(nullptr, false));
  EXPECT_EQ(0, buffer.tailOffset());
  EXPECT_FALSE(buffer.nextNewData(10).has_value());
}

TEST(StreamSendBufferTest, TruncateDiscardsTailStateAndOutstandingBytes) {
  StreamSendBuffer buffer;
  ASSERT_TRUE(buffer.append(makeBuffer("abc"), false));
  ASSERT_TRUE(buffer.append(makeBuffer("def"), true));
  ASSERT_TRUE(buffer.markNewDataSent({0, 6, true}));
  ASSERT_TRUE(buffer.markAcked({1, 2, false}).has_value());
  buffer.markLoss({.offset = 0, .len = 6, .fin = true});

  ASSERT_TRUE(buffer.truncateFrom(4));
  EXPECT_EQ(6, buffer.tailOffset());
  EXPECT_EQ(6, buffer.nextUnsentOffset());
  EXPECT_EQ(2, buffer.outstandingBytes());
  EXPECT_FALSE(buffer.finBuffered());
  EXPECT_FALSE(buffer.finLost());
  expectRange(buffer.nextLoss(10), {.offset = 0, .len = 1, .fin = false});

  std::string output;
  EXPECT_TRUE(writeToString(buffer, 0, 4, output));
  EXPECT_EQ("abcd", output);
  EXPECT_FALSE(writeToString(buffer, 4, 1, output));
  EXPECT_FALSE(buffer.append(makeBuffer("g"), false));
}

TEST(StreamSendBufferTest, TruncateAtTailPreservesFinState) {
  StreamSendBuffer buffer;
  ASSERT_TRUE(buffer.append(makeBuffer("abc"), true));
  ASSERT_TRUE(buffer.markNewDataSent({0, 3, true}));
  auto ack = buffer.markAcked({.offset = 0, .len = 3, .fin = true});
  ASSERT_TRUE(ack.has_value());

  ASSERT_TRUE(buffer.truncateFrom(buffer.tailOffset()));
  EXPECT_TRUE(buffer.finBuffered());
  EXPECT_TRUE(buffer.finSent());
  EXPECT_TRUE(buffer.finAcked());
}

TEST(StreamSendBufferTest, TruncateBeforeTailDiscardsAcknowledgedFin) {
  StreamSendBuffer buffer;
  ASSERT_TRUE(buffer.append(makeBuffer("abc"), true));
  ASSERT_TRUE(buffer.markNewDataSent({0, 3, true}));
  ASSERT_TRUE(buffer.markAcked({.offset = 0, .len = 3, .fin = true}));

  ASSERT_TRUE(buffer.truncateFrom(2));
  EXPECT_FALSE(buffer.finBuffered());
  EXPECT_FALSE(buffer.finSent());
  EXPECT_FALSE(buffer.finAcked());
}

TEST(StreamSendBufferTest, TruncateBeyondSentRetainsReliablePrefix) {
  StreamSendBuffer buffer;
  ASSERT_TRUE(buffer.append(makeBuffer("abcdefghij"), false));
  ASSERT_TRUE(buffer.markNewDataSent({0, 3, false}));

  ASSERT_TRUE(buffer.truncateFrom(5));
  EXPECT_EQ(5, buffer.tailOffset());
  EXPECT_EQ(3, buffer.nextUnsentOffset());
  EXPECT_EQ(2, buffer.unsentBytes());
  expectRange(buffer.nextNewData(10), {.offset = 3, .len = 2, .fin = false});

  std::string output;
  EXPECT_TRUE(writeToString(buffer, 3, 2, output));
  EXPECT_EQ("de", output);
}

TEST(StreamSendBufferTest, AckAfterTruncateExcludesAbandonedBytes) {
  StreamSendBuffer buffer;
  ASSERT_TRUE(buffer.append(makeBuffer("abcdef"), false));
  ASSERT_TRUE(buffer.markNewDataSent({0, 6, false}));
  ASSERT_TRUE(buffer.truncateFrom(4));

  const auto ack = buffer.markAcked({.offset = 3, .len = 3, .fin = false});
  ASSERT_TRUE(ack.has_value());
  EXPECT_EQ(1, ack->newlyAckedBytes);
  EXPECT_EQ(3, buffer.outstandingBytes());
}

TEST(StreamSendBufferTest, CancelAllReleasesAllPendingState) {
  StreamSendBuffer buffer;
  ASSERT_TRUE(buffer.append(makeBuffer("abcdef"), true));
  ASSERT_TRUE(buffer.markNewDataSent({0, 6, true}));
  buffer.markLoss({.offset = 0, .len = 6, .fin = true});

  buffer.cancelAll();
  EXPECT_TRUE(buffer.cancelled());
  EXPECT_EQ(0, buffer.outstandingBytes());
  EXPECT_EQ(buffer.tailOffset(), buffer.nextUnsentOffset());
  EXPECT_FALSE(buffer.nextNewData(10).has_value());
  EXPECT_FALSE(buffer.nextLoss(10).has_value());
  EXPECT_FALSE(buffer.hasPendingLoss());
  EXPECT_FALSE(buffer.writeAt(0, 1, [](ByteRange) { return true; }));
  EXPECT_FALSE(buffer.append(makeBuffer("g"), false));
  EXPECT_FALSE(
      buffer.markAcked({.offset = 0, .len = 0, .fin = false}).has_value());
}

TEST(StreamSendBufferTest, CancelPreservesLargestSentOffset) {
  StreamSendBuffer buffer;
  ASSERT_TRUE(buffer.append(makeBuffer("abcdefghij"), false));
  ASSERT_TRUE(buffer.markNewDataSent({0, 4, false}));

  buffer.cancelAll();
  EXPECT_EQ(4, buffer.tailOffset());
  EXPECT_EQ(4, buffer.nextUnsentOffset());
  EXPECT_EQ(0, buffer.unsentBytes());
}

TEST(StreamSendBufferTest, AckOfEitherDuplicateRetiresLossState) {
  StreamSendBuffer buffer;
  ASSERT_TRUE(buffer.append(makeBuffer("abc"), true));
  ASSERT_TRUE(buffer.markNewDataSent({0, 3, true}));

  buffer.markLoss({.offset = 0, .len = 3, .fin = true});
  buffer.markRetransmissionSent({.offset = 0, .len = 3, .fin = true});
  ASSERT_TRUE(buffer.markAcked({0, 3, true}).has_value());
  buffer.markLoss({.offset = 0, .len = 3, .fin = true});
  EXPECT_FALSE(buffer.hasPendingLoss());

  StreamSendBuffer reordered;
  ASSERT_TRUE(reordered.append(makeBuffer("abc"), true));
  ASSERT_TRUE(reordered.markNewDataSent({0, 3, true}));
  reordered.markLoss({.offset = 0, .len = 3, .fin = true});
  reordered.markRetransmissionSent({.offset = 0, .len = 3, .fin = true});
  reordered.markLoss({.offset = 0, .len = 3, .fin = true});
  EXPECT_TRUE(reordered.hasPendingLoss());
  ASSERT_TRUE(reordered.markAcked({0, 3, true}).has_value());
  EXPECT_FALSE(reordered.hasPendingLoss());
}

TEST(StreamSendBufferTest, AckOfEitherFinOnlyDuplicateRetiresLossState) {
  StreamSendBuffer buffer;
  ASSERT_TRUE(buffer.append(nullptr, true));
  ASSERT_TRUE(buffer.markNewDataSent({0, 0, true}));
  buffer.markLoss({.offset = 0, .len = 0, .fin = true});
  buffer.markRetransmissionSent({.offset = 0, .len = 0, .fin = true});
  buffer.markLoss({.offset = 0, .len = 0, .fin = true});
  EXPECT_TRUE(buffer.hasPendingLoss());

  ASSERT_TRUE(buffer.markAcked({0, 0, true}).has_value());
  EXPECT_FALSE(buffer.hasPendingLoss());
}

} // namespace
} // namespace quic::test
