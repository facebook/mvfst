/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <quic/state/StreamData.h>

using namespace quic;
using namespace testing;

namespace quic::test {

Buf createBuffer(uint32_t len) {
  auto buf = folly::IOBuf::create(len);
  buf->append(len);
  return buf;
}

std::unique_ptr<WriteStreamBuffer>
createWriteStreamBuffer(uint32_t offset, Buf& buf, bool eof) {
  ChainedByteRangeHead cbrh(buf);
  return std::make_unique<WriteStreamBuffer>(std::move(cbrh), offset, eof);
}

void addDataToBufQueue(BufQueue& bufQueue, uint32_t len) {
  auto buf = folly::IOBuf::create(len);
  buf->append(len);
  bufQueue.append(std::move(buf));
}

TEST(StreamDataTest, LossBufferRemovalAll) {
  QuicStreamLike state;
  // [1, 2] [5, 12] [17, 19]
  auto buf1 = createBuffer(2);
  auto buf2 = createBuffer(8);
  auto buf3 = createBuffer(3);
  state.insertIntoLossBuffer(createWriteStreamBuffer(1, buf1, false));
  state.insertIntoLossBuffer(createWriteStreamBuffer(5, buf2, false));
  state.insertIntoLossBuffer(createWriteStreamBuffer(17, buf3, false));

  state.removeFromLossBufAfterOffset(0);
  EXPECT_EQ(state.lossBuffer.size(), 0);
}

TEST(StreamDataTest, LossBufferRemovalExactMatch) {
  QuicStreamLike state;
  // [1, 2] [5, 12] [17, 19]
  auto buf1 = createBuffer(2);
  auto buf2 = createBuffer(8);
  auto buf3 = createBuffer(3);
  state.insertIntoLossBuffer(createWriteStreamBuffer(1, buf1, false));
  state.insertIntoLossBuffer(createWriteStreamBuffer(5, buf2, false));
  state.insertIntoLossBuffer(createWriteStreamBuffer(17, buf3, false));

  state.removeFromLossBufAfterOffset(4);
  EXPECT_EQ(state.lossBuffer.size(), 1);
  EXPECT_EQ(state.lossBuffer[0].offset, 1);
  EXPECT_EQ(state.lossBuffer[0].data.chainLength(), 2);
}

TEST(StreamDataTest, LossBufferRemovalPartialMatch) {
  QuicStreamLike state;
  // [1, 2] [5, 12] [17, 19]
  auto buf1 = createBuffer(2);
  auto buf2 = createBuffer(8);
  auto buf3 = createBuffer(3);
  state.insertIntoLossBuffer(createWriteStreamBuffer(1, buf1, false));
  state.insertIntoLossBuffer(createWriteStreamBuffer(5, buf2, false));
  state.insertIntoLossBuffer(createWriteStreamBuffer(17, buf3, false));

  state.removeFromLossBufAfterOffset(5);
  EXPECT_EQ(state.lossBuffer.size(), 2);

  EXPECT_EQ(state.lossBuffer[0].offset, 1);
  EXPECT_EQ(state.lossBuffer[0].data.chainLength(), 2);

  EXPECT_EQ(state.lossBuffer[1].offset, 5);
  EXPECT_EQ(state.lossBuffer[1].data.chainLength(), 1);
}

TEST(StreamDataTest, LossBufferRemovalNoMatch) {
  QuicStreamLike state;
  // [1, 2] [5, 12] [17, 19]
  auto buf1 = createBuffer(2);
  auto buf2 = createBuffer(8);
  auto buf3 = createBuffer(3);
  state.insertIntoLossBuffer(createWriteStreamBuffer(1, buf1, false));
  state.insertIntoLossBuffer(createWriteStreamBuffer(5, buf2, false));
  state.insertIntoLossBuffer(createWriteStreamBuffer(17, buf3, false));

  state.removeFromLossBufAfterOffset(20);
  EXPECT_EQ(state.lossBuffer.size(), 3);

  EXPECT_EQ(state.lossBuffer[0].offset, 1);
  EXPECT_EQ(state.lossBuffer[0].data.chainLength(), 2);

  EXPECT_EQ(state.lossBuffer[1].offset, 5);
  EXPECT_EQ(state.lossBuffer[1].data.chainLength(), 8);

  EXPECT_EQ(state.lossBuffer[2].offset, 17);
  EXPECT_EQ(state.lossBuffer[2].data.chainLength(), 3);
}

TEST(StreamDataTest, RetxBufferRemovalAll) {
  QuicStreamLike state;
  // [1, 2] [5, 12] [17, 19]
  auto buf1 = createBuffer(2);
  auto buf2 = createBuffer(8);
  auto buf3 = createBuffer(3);
  state.retransmissionBuffer.emplace(
      1, createWriteStreamBuffer(1, buf1, false));
  state.retransmissionBuffer.emplace(
      5, createWriteStreamBuffer(5, buf2, false));
  state.retransmissionBuffer.emplace(
      17, createWriteStreamBuffer(17, buf3, false));

  state.removeFromRetransmissionBufAfterOffset(0);
  EXPECT_EQ(state.retransmissionBuffer.size(), 0);
}

TEST(StreamDataTest, RetxBufferRemovalExactMatch) {
  QuicStreamLike state;
  // [1, 2] [5, 12] [17, 19]
  auto buf1 = createBuffer(2);
  auto buf2 = createBuffer(8);
  auto buf3 = createBuffer(3);
  state.retransmissionBuffer.emplace(
      1, createWriteStreamBuffer(1, buf1, false));
  state.retransmissionBuffer.emplace(
      5, createWriteStreamBuffer(5, buf2, false));
  state.retransmissionBuffer.emplace(
      17, createWriteStreamBuffer(17, buf3, false));

  state.removeFromRetransmissionBufAfterOffset(16);
  EXPECT_EQ(state.retransmissionBuffer.size(), 2);

  EXPECT_EQ(state.retransmissionBuffer[1]->offset, 1);
  EXPECT_EQ(state.retransmissionBuffer[1]->data.chainLength(), 2);

  EXPECT_EQ(state.retransmissionBuffer[5]->offset, 5);
  EXPECT_EQ(state.retransmissionBuffer[5]->data.chainLength(), 8);
}

TEST(StreamDataTest, RetxBufferRemovalPartialMatch) {
  QuicStreamLike state;
  // [1, 2] [5, 12] [17, 19]
  auto buf1 = createBuffer(2);
  auto buf2 = createBuffer(8);
  auto buf3 = createBuffer(3);
  state.retransmissionBuffer.emplace(
      1, createWriteStreamBuffer(1, buf1, false));
  state.retransmissionBuffer.emplace(
      5, createWriteStreamBuffer(5, buf2, false));
  state.retransmissionBuffer.emplace(
      17, createWriteStreamBuffer(17, buf3, false));

  state.removeFromRetransmissionBufAfterOffset(5);
  EXPECT_EQ(state.retransmissionBuffer.size(), 2);

  EXPECT_EQ(state.retransmissionBuffer[1]->offset, 1);
  EXPECT_EQ(state.retransmissionBuffer[1]->data.chainLength(), 2);

  EXPECT_EQ(state.retransmissionBuffer[5]->offset, 5);
  EXPECT_EQ(state.retransmissionBuffer[5]->data.chainLength(), 1);
}

TEST(StreamDataTest, RetxBufferRemovalNoMatch) {
  QuicStreamLike state;
  // [1, 2] [5, 12] [17, 19]
  auto buf1 = createBuffer(2);
  auto buf2 = createBuffer(8);
  auto buf3 = createBuffer(3);
  state.retransmissionBuffer.emplace(
      1, createWriteStreamBuffer(1, buf1, false));
  state.retransmissionBuffer.emplace(
      5, createWriteStreamBuffer(5, buf2, false));
  state.retransmissionBuffer.emplace(
      17, createWriteStreamBuffer(17, buf3, false));

  state.removeFromRetransmissionBufAfterOffset(19);
  EXPECT_EQ(state.retransmissionBuffer.size(), 3);

  EXPECT_EQ(state.retransmissionBuffer[1]->offset, 1);
  EXPECT_EQ(state.retransmissionBuffer[1]->data.chainLength(), 2);

  EXPECT_EQ(state.retransmissionBuffer[5]->offset, 5);
  EXPECT_EQ(state.retransmissionBuffer[5]->data.chainLength(), 8);

  EXPECT_EQ(state.retransmissionBuffer[17]->offset, 17);
  EXPECT_EQ(state.retransmissionBuffer[17]->data.chainLength(), 3);
}

TEST(StreamDataTest, WriteBufferRemovalAll) {
  QuicStreamLike state;
  state.writeBufferStartOffset = 5;

  // [5, 16]
  addDataToBufQueue(state.writeBuffer, 3);
  addDataToBufQueue(state.writeBuffer, 2);
  addDataToBufQueue(state.writeBuffer, 7);

  state.removeFromWriteBufAfterOffset(0);
  EXPECT_EQ(state.writeBuffer.chainLength(), 0);
}

TEST(StreamDataTest, WriteBufferRemoval) {
  QuicStreamLike state;
  state.writeBufferStartOffset = 5;

  // [5, 16]
  addDataToBufQueue(state.writeBuffer, 3);
  addDataToBufQueue(state.writeBuffer, 2);
  addDataToBufQueue(state.writeBuffer, 7);

  state.removeFromWriteBufAfterOffset(5);
  EXPECT_EQ(state.writeBuffer.chainLength(), 1);
}

TEST(StreamDataTest, WriteBufferRemovalNoChange) {
  QuicStreamLike state;
  state.writeBufferStartOffset = 5;

  // [5, 16]
  addDataToBufQueue(state.writeBuffer, 3);
  addDataToBufQueue(state.writeBuffer, 2);
  addDataToBufQueue(state.writeBuffer, 7);

  state.removeFromWriteBufAfterOffset(16);
  EXPECT_EQ(state.writeBuffer.chainLength(), 12);
}

TEST(StreamDataTest, PendingWritesRemovalAll) {
  QuicStreamLike state;
  state.currentWriteOffset = 5;

  // [5, 12]
  Buf buf1 = folly::IOBuf::create(3);
  buf1->append(3);
  Buf buf2 = folly::IOBuf::create(5);
  buf2->append(5);
  buf1->appendChain(std::move(buf2));

  state.pendingWrites = ChainedByteRangeHead(buf1);
  state.removeFromPendingWritesAfterOffset(0);
  EXPECT_EQ(state.pendingWrites.chainLength(), 0);
}

TEST(StreamDataTest, PendingWritesRemoval) {
  QuicStreamLike state;
  state.currentWriteOffset = 5;

  // [5, 12]
  Buf buf1 = folly::IOBuf::create(3);
  buf1->append(3);
  Buf buf2 = folly::IOBuf::create(5);
  buf2->append(5);
  buf1->appendChain(std::move(buf2));

  state.pendingWrites = ChainedByteRangeHead(buf1);
  state.removeFromPendingWritesAfterOffset(11);
  EXPECT_EQ(state.pendingWrites.chainLength(), 7);
}

TEST(StreamDataTest, PendingWritesRemovalNoChange) {
  QuicStreamLike state;
  state.currentWriteOffset = 5;

  // [5, 12]
  Buf buf1 = folly::IOBuf::create(3);
  buf1->append(3);
  Buf buf2 = folly::IOBuf::create(5);
  buf2->append(5);
  buf1->appendChain(std::move(buf2));

  state.pendingWrites = ChainedByteRangeHead(buf1);
  state.removeFromPendingWritesAfterOffset(12);
  EXPECT_EQ(state.pendingWrites.chainLength(), 8);
}

} // namespace quic::test
