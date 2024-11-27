/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <quic/state/StateData.h>
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

  state.removeFromLossBufStartingAtOffset(1);
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

  state.removeFromLossBufStartingAtOffset(5);
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

  state.removeFromLossBufStartingAtOffset(6);
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

  state.removeFromLossBufStartingAtOffset(21);
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

  state.removeFromRetransmissionBufStartingAtOffset(1);
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

  state.removeFromRetransmissionBufStartingAtOffset(17);
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

  state.removeFromRetransmissionBufStartingAtOffset(6);
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

  state.removeFromRetransmissionBufStartingAtOffset(20);
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

  state.removeFromWriteBufStartingAtOffset(1);
  EXPECT_EQ(state.writeBuffer.chainLength(), 0);
}

TEST(StreamDataTest, WriteBufferRemoval) {
  QuicStreamLike state;
  state.writeBufferStartOffset = 5;

  // [5, 16]
  addDataToBufQueue(state.writeBuffer, 3);
  addDataToBufQueue(state.writeBuffer, 2);
  addDataToBufQueue(state.writeBuffer, 7);

  state.removeFromWriteBufStartingAtOffset(6);
  EXPECT_EQ(state.writeBuffer.chainLength(), 1);
}

TEST(StreamDataTest, WriteBufferRemovalNoChange) {
  QuicStreamLike state;
  state.writeBufferStartOffset = 5;

  // [5, 16]
  addDataToBufQueue(state.writeBuffer, 3);
  addDataToBufQueue(state.writeBuffer, 2);
  addDataToBufQueue(state.writeBuffer, 7);

  state.removeFromWriteBufStartingAtOffset(17);
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
  state.removeFromPendingWritesStartingAtOffset(1);
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
  state.removeFromPendingWritesStartingAtOffset(12);
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
  state.removeFromPendingWritesStartingAtOffset(13);
  EXPECT_EQ(state.pendingWrites.chainLength(), 8);
}

TEST(StreamDataTest, LossBufferMetaRemovalAll) {
  QuicConnectionStateBase qcsb(QuicNodeType::Client);
  QuicStreamState state(0, qcsb);

  // [1, 2] [5, 12] [17, 19]
  WriteBufferMeta wbm1 = WriteBufferMeta::Builder()
                             .setOffset(1)
                             .setLength(2)
                             .setEOF(false)
                             .build();
  WriteBufferMeta wbm2 = WriteBufferMeta::Builder()
                             .setOffset(5)
                             .setLength(8)
                             .setEOF(false)
                             .build();
  WriteBufferMeta wbm3 = WriteBufferMeta::Builder()
                             .setOffset(17)
                             .setLength(3)
                             .setEOF(false)
                             .build();
  state.insertIntoLossBufMeta(wbm1);
  state.insertIntoLossBufMeta(wbm2);
  state.insertIntoLossBufMeta(wbm3);

  state.removeFromLossBufMetasStartingAtOffset(1);

  EXPECT_EQ(state.lossBufMetas.size(), 0);
}

TEST(StreamDataTest, LossBufferMetaRemovalExactMatch) {
  QuicConnectionStateBase qcsb(QuicNodeType::Client);
  QuicStreamState state(0, qcsb);

  // [1, 2] [5, 12] [17, 19]
  WriteBufferMeta wbm1 = WriteBufferMeta::Builder()
                             .setOffset(1)
                             .setLength(2)
                             .setEOF(false)
                             .build();
  WriteBufferMeta wbm2 = WriteBufferMeta::Builder()
                             .setOffset(5)
                             .setLength(8)
                             .setEOF(false)
                             .build();
  WriteBufferMeta wbm3 = WriteBufferMeta::Builder()
                             .setOffset(17)
                             .setLength(3)
                             .setEOF(false)
                             .build();
  state.insertIntoLossBufMeta(wbm1);
  state.insertIntoLossBufMeta(wbm2);
  state.insertIntoLossBufMeta(wbm3);

  state.removeFromLossBufMetasStartingAtOffset(5);
  EXPECT_EQ(state.lossBufMetas.size(), 1);
  EXPECT_EQ(state.lossBufMetas[0].offset, 1);
  EXPECT_EQ(state.lossBufMetas[0].length, 2);
}

TEST(StreamDataTest, LossBufferMetaRemovalPartialMatch) {
  QuicConnectionStateBase qcsb(QuicNodeType::Client);
  QuicStreamState state(0, qcsb);

  // [1, 2] [5, 12] [17, 19]
  WriteBufferMeta wbm1 = WriteBufferMeta::Builder()
                             .setOffset(1)
                             .setLength(2)
                             .setEOF(false)
                             .build();
  WriteBufferMeta wbm2 = WriteBufferMeta::Builder()
                             .setOffset(5)
                             .setLength(8)
                             .setEOF(false)
                             .build();
  WriteBufferMeta wbm3 = WriteBufferMeta::Builder()
                             .setOffset(17)
                             .setLength(3)
                             .setEOF(false)
                             .build();
  state.insertIntoLossBufMeta(wbm1);
  state.insertIntoLossBufMeta(wbm2);
  state.insertIntoLossBufMeta(wbm3);

  state.removeFromLossBufMetasStartingAtOffset(6);
  EXPECT_EQ(state.lossBufMetas.size(), 2);

  EXPECT_EQ(state.lossBufMetas[0].offset, 1);
  EXPECT_EQ(state.lossBufMetas[0].length, 2);

  EXPECT_EQ(state.lossBufMetas[1].offset, 5);
  EXPECT_EQ(state.lossBufMetas[1].length, 1);
}

TEST(StreamDataTest, LossBufferMetaRemovalNoMatch) {
  QuicConnectionStateBase qcsb(QuicNodeType::Client);
  QuicStreamState state(0, qcsb);

  // [1, 2] [5, 12] [17, 19]
  WriteBufferMeta wbm1 = WriteBufferMeta::Builder()
                             .setOffset(1)
                             .setLength(2)
                             .setEOF(false)
                             .build();
  WriteBufferMeta wbm2 = WriteBufferMeta::Builder()
                             .setOffset(5)
                             .setLength(8)
                             .setEOF(false)
                             .build();
  WriteBufferMeta wbm3 = WriteBufferMeta::Builder()
                             .setOffset(17)
                             .setLength(3)
                             .setEOF(false)
                             .build();
  state.insertIntoLossBufMeta(wbm1);
  state.insertIntoLossBufMeta(wbm2);
  state.insertIntoLossBufMeta(wbm3);

  state.removeFromLossBufStartingAtOffset(21);
  EXPECT_EQ(state.lossBufMetas.size(), 3);

  EXPECT_EQ(state.lossBufMetas[0].offset, 1);
  EXPECT_EQ(state.lossBufMetas[0].length, 2);

  EXPECT_EQ(state.lossBufMetas[1].offset, 5);
  EXPECT_EQ(state.lossBufMetas[1].length, 8);

  EXPECT_EQ(state.lossBufMetas[2].offset, 17);
  EXPECT_EQ(state.lossBufMetas[2].length, 3);
}

TEST(StreamDataTest, RetxBufferMetaRemovalAll) {
  QuicConnectionStateBase qcsb(QuicNodeType::Client);
  QuicStreamState state(0, qcsb);

  // [1, 2] [5, 12] [17, 19]
  WriteBufferMeta wbm1 = WriteBufferMeta::Builder()
                             .setOffset(1)
                             .setLength(2)
                             .setEOF(false)
                             .build();
  WriteBufferMeta wbm2 = WriteBufferMeta::Builder()
                             .setOffset(5)
                             .setLength(8)
                             .setEOF(false)
                             .build();
  WriteBufferMeta wbm3 = WriteBufferMeta::Builder()
                             .setOffset(17)
                             .setLength(3)
                             .setEOF(false)
                             .build();
  state.retransmissionBufMetas.emplace(1, wbm1);
  state.retransmissionBufMetas.emplace(5, wbm2);
  state.retransmissionBufMetas.emplace(17, wbm3);

  state.removeFromRetransmissionBufMetasStartingAtOffset(1);
  EXPECT_EQ(state.retransmissionBufMetas.size(), 0);
}

TEST(StreamDataTest, RetxBufferMetaRemovalExactMatch) {
  QuicConnectionStateBase qcsb(QuicNodeType::Client);
  QuicStreamState state(0, qcsb);

  // [1, 2] [5, 12] [17, 19]
  WriteBufferMeta wbm1 = WriteBufferMeta::Builder()
                             .setOffset(1)
                             .setLength(2)
                             .setEOF(false)
                             .build();
  WriteBufferMeta wbm2 = WriteBufferMeta::Builder()
                             .setOffset(5)
                             .setLength(8)
                             .setEOF(false)
                             .build();
  WriteBufferMeta wbm3 = WriteBufferMeta::Builder()
                             .setOffset(17)
                             .setLength(3)
                             .setEOF(false)
                             .build();
  state.retransmissionBufMetas.emplace(1, wbm1);
  state.retransmissionBufMetas.emplace(5, wbm2);
  state.retransmissionBufMetas.emplace(17, wbm3);

  state.removeFromRetransmissionBufMetasStartingAtOffset(17);
  EXPECT_EQ(state.retransmissionBufMetas.size(), 2);

  EXPECT_EQ(state.retransmissionBufMetas[1].offset, 1);
  EXPECT_EQ(state.retransmissionBufMetas[1].length, 2);

  EXPECT_EQ(state.retransmissionBufMetas[5].offset, 5);
  EXPECT_EQ(state.retransmissionBufMetas[5].length, 8);
}

TEST(StreamDataTest, RetxBufferMetaRemovalPartialMatch) {
  QuicConnectionStateBase qcsb(QuicNodeType::Client);
  QuicStreamState state(0, qcsb);

  // [1, 2] [5, 12] [17, 19]
  WriteBufferMeta wbm1 = WriteBufferMeta::Builder()
                             .setOffset(1)
                             .setLength(2)
                             .setEOF(false)
                             .build();
  WriteBufferMeta wbm2 = WriteBufferMeta::Builder()
                             .setOffset(5)
                             .setLength(8)
                             .setEOF(false)
                             .build();
  WriteBufferMeta wbm3 = WriteBufferMeta::Builder()
                             .setOffset(17)
                             .setLength(3)
                             .setEOF(false)
                             .build();
  state.retransmissionBufMetas.emplace(1, wbm1);
  state.retransmissionBufMetas.emplace(5, wbm2);
  state.retransmissionBufMetas.emplace(17, wbm3);

  state.removeFromRetransmissionBufMetasStartingAtOffset(6);
  EXPECT_EQ(state.retransmissionBufMetas.size(), 2);

  EXPECT_EQ(state.retransmissionBufMetas[1].offset, 1);
  EXPECT_EQ(state.retransmissionBufMetas[1].length, 2);

  EXPECT_EQ(state.retransmissionBufMetas[5].offset, 5);
  EXPECT_EQ(state.retransmissionBufMetas[5].length, 1);
}

TEST(StreamDataTest, RetxBufferMetaRemovalNoMatch) {
  QuicConnectionStateBase qcsb(QuicNodeType::Client);
  QuicStreamState state(0, qcsb);

  // [1, 2] [5, 12] [17, 19]
  WriteBufferMeta wbm1 = WriteBufferMeta::Builder()
                             .setOffset(1)
                             .setLength(2)
                             .setEOF(false)
                             .build();
  WriteBufferMeta wbm2 = WriteBufferMeta::Builder()
                             .setOffset(5)
                             .setLength(8)
                             .setEOF(false)
                             .build();
  WriteBufferMeta wbm3 = WriteBufferMeta::Builder()
                             .setOffset(17)
                             .setLength(3)
                             .setEOF(false)
                             .build();
  state.retransmissionBufMetas.emplace(1, wbm1);
  state.retransmissionBufMetas.emplace(5, wbm2);
  state.retransmissionBufMetas.emplace(17, wbm3);

  state.removeFromRetransmissionBufMetasStartingAtOffset(20);
  EXPECT_EQ(state.retransmissionBufMetas.size(), 3);

  EXPECT_EQ(state.retransmissionBufMetas[1].offset, 1);
  EXPECT_EQ(state.retransmissionBufMetas[1].length, 2);

  EXPECT_EQ(state.retransmissionBufMetas[5].offset, 5);
  EXPECT_EQ(state.retransmissionBufMetas[5].length, 8);

  EXPECT_EQ(state.retransmissionBufMetas[17].offset, 17);
  EXPECT_EQ(state.retransmissionBufMetas[17].length, 3);
}

TEST(StreamDataTest, WriteBufferMetaRemovalAll) {
  QuicConnectionStateBase qcsb(QuicNodeType::Client);
  QuicStreamState state(0, qcsb);

  // [5, 16]
  state.writeBufMeta.offset = 5;
  state.writeBufMeta.length = 12;

  state.removeFromWriteBufMetaStartingAtOffset(1);
  EXPECT_EQ(state.writeBufMeta.length, 0);
}

TEST(StreamDataTest, WriteBufferMetaRemoval) {
  QuicConnectionStateBase qcsb(QuicNodeType::Client);
  QuicStreamState state(0, qcsb);

  state.writeBufferStartOffset = 5;

  // [5, 16]
  state.writeBufMeta.offset = 5;
  state.writeBufMeta.length = 12;

  state.removeFromWriteBufMetaStartingAtOffset(6);
  EXPECT_EQ(state.writeBufMeta.length, 1);
}

TEST(StreamDataTest, WriteBufferMetaRemovalNoChange) {
  QuicConnectionStateBase qcsb(QuicNodeType::Client);
  QuicStreamState state(0, qcsb);

  state.writeBufferStartOffset = 5;

  // [5, 16]
  state.writeBufMeta.offset = 5;
  state.writeBufMeta.length = 12;

  state.removeFromWriteBufMetaStartingAtOffset(17);
  EXPECT_EQ(state.writeBufMeta.length, 12);
}

} // namespace quic::test
