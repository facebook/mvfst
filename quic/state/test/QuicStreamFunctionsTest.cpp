/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <quic/state/QuicStreamUtilities.h>

#include <quic/state/QuicStreamFunctions.h>

#include <quic/client/state/ClientStateMachine.h>
#include <quic/common/test/TestUtils.h>
#include <quic/fizz/client/handshake/FizzClientQuicHandshakeContext.h>
#include <quic/fizz/server/handshake/FizzServerQuicHandshakeContext.h>
#include <quic/server/state/ServerStateMachine.h>

using namespace folly;
using namespace testing;

namespace quic::test {

constexpr uint8_t kStreamIncrement = 0x04;

using PeekIterator = CircularDeque<StreamBuffer>::const_iterator;

class QuicStreamFunctionsTest : public Test {
 public:
  QuicStreamFunctionsTest()
      : conn(FizzClientQuicHandshakeContext::Builder().build()) {}

  void SetUp() override {
    conn.flowControlState.peerAdvertisedInitialMaxStreamOffsetBidiLocal =
        kDefaultStreamFlowControlWindow;
    conn.flowControlState.peerAdvertisedInitialMaxStreamOffsetBidiRemote =
        kDefaultStreamFlowControlWindow;
    conn.flowControlState.peerAdvertisedInitialMaxStreamOffsetUni =
        kDefaultStreamFlowControlWindow;
    conn.flowControlState.peerAdvertisedMaxOffset =
        kDefaultConnectionFlowControlWindow;
    CHECK(
        !conn.streamManager
             ->setMaxLocalBidirectionalStreams(kDefaultMaxStreamsBidirectional)
             .hasError());
    CHECK(!conn.streamManager
               ->setMaxLocalUnidirectionalStreams(
                   kDefaultMaxStreamsUnidirectional)
               .hasError());
  }

  QuicClientConnectionState conn;
};

class QuicServerStreamFunctionsTest : public Test {
 public:
  QuicServerStreamFunctionsTest()
      : conn(FizzServerQuicHandshakeContext::Builder().build()) {}

  void SetUp() override {
    conn.flowControlState.peerAdvertisedInitialMaxStreamOffsetBidiLocal =
        kDefaultStreamFlowControlWindow;
    conn.flowControlState.peerAdvertisedInitialMaxStreamOffsetBidiRemote =
        kDefaultStreamFlowControlWindow;
    conn.flowControlState.peerAdvertisedInitialMaxStreamOffsetUni =
        kDefaultStreamFlowControlWindow;
    conn.flowControlState.peerAdvertisedMaxOffset =
        kDefaultConnectionFlowControlWindow;
    CHECK(
        !conn.streamManager
             ->setMaxLocalBidirectionalStreams(kDefaultMaxStreamsBidirectional)
             .hasError());
    CHECK(!conn.streamManager
               ->setMaxLocalUnidirectionalStreams(
                   kDefaultMaxStreamsUnidirectional)
               .hasError());
  }

  QuicServerConnectionState conn;
};

using QuicStreamFunctionsTestBase = QuicStreamFunctionsTest;

TEST_F(QuicStreamFunctionsTestBase, TestCreateBidirectionalStream) {
  const auto stream =
      conn.streamManager->createNextBidirectionalStream().value();
  EXPECT_EQ(conn.streamManager->streamCount(), 1);
  EXPECT_EQ(stream->id, 0x00);
}

TEST_F(QuicStreamFunctionsTestBase, TestCreateUnidirectionalStream) {
  const auto stream =
      conn.streamManager->createNextUnidirectionalStream().value();
  EXPECT_EQ(conn.streamManager->streamCount(), 1);
  EXPECT_EQ(stream->id, 0x02);
}

TEST_F(QuicStreamFunctionsTestBase, TestCreateBoth) {
  for (int i = 0; i < 50; i++) {
    auto stream = conn.streamManager->createNextUnidirectionalStream().value();
    ASSERT_EQ(conn.streamManager->streamCount(), i + 1);
    ASSERT_EQ(stream->id, 0x02 + i * kStreamIncrement);
  }
  for (int i = 0; i < 50; i++) {
    auto stream = conn.streamManager->createNextBidirectionalStream().value();
    ASSERT_EQ(conn.streamManager->streamCount(), i + 51);
    ASSERT_EQ(stream->id, 0x00 + i * kStreamIncrement);
  }
}

TEST_F(QuicStreamFunctionsTestBase, TestWriteStream) {
  auto stream = conn.streamManager->createNextBidirectionalStream().value();
  auto buf1 = IOBuf::copyBuffer("I just met you");
  auto buf2 = IOBuf::copyBuffer("and this is crazy");

  ASSERT_FALSE(writeDataToQuicStream(*stream, buf1->clone(), false).hasError());
  ASSERT_FALSE(writeDataToQuicStream(*stream, buf2->clone(), false).hasError());

  IOBufEqualTo eq;
  buf1->appendToChain(std::move(buf2));

  EXPECT_TRUE(eq(stream->writeBuffer.move(), buf1));
}

TEST_F(QuicStreamFunctionsTestBase, TestReadDataWrittenInOrder) {
  auto stream = conn.streamManager->createNextBidirectionalStream().value();
  auto streamLastMaxOffset = stream->maxOffsetObserved;
  auto connLastMaxOffset = conn.flowControlState.sumMaxObservedOffset;
  auto buf1 = IOBuf::copyBuffer("I just met you ");
  buf1->appendToChain(IOBuf::copyBuffer("and this is crazy. "));

  auto buf2 = IOBuf::copyBuffer("Here's my number ");
  buf2->appendToChain(IOBuf::copyBuffer("so call me maybe"));

  ASSERT_FALSE(appendDataToReadBuffer(*stream, StreamBuffer(buf1->clone(), 0))
                   .hasError());
  ASSERT_FALSE(
      appendDataToReadBuffer(
          *stream,
          StreamBuffer(buf2->clone(), buf1->computeChainDataLength(), true))
          .hasError());
  EXPECT_EQ(
      stream->maxOffsetObserved - streamLastMaxOffset,
      conn.flowControlState.sumMaxObservedOffset - connLastMaxOffset);

  auto readData1 = readDataFromQuicStream(*stream, 10);
  EXPECT_EQ("I just met", readData1->first->toString());
  EXPECT_FALSE(readData1->second);

  auto readData2 = readDataFromQuicStream(*stream, 30);
  EXPECT_EQ(" you and this is crazy. Here's", readData2->first->toString());
  EXPECT_FALSE(readData2->second);

  auto readData3 = readDataFromQuicStream(*stream, 21);
  EXPECT_EQ(" my number so call me", readData3->first->toString());
  EXPECT_FALSE(readData3->second);

  auto readData4 = readDataFromQuicStream(*stream, 20);
  EXPECT_EQ(" maybe", readData4->first->toString());
  EXPECT_TRUE(readData4->second);
}

TEST_F(QuicStreamFunctionsTestBase, TestPeekAndConsumeContiguousData) {
  auto stream = conn.streamManager->createNextBidirectionalStream().value();
  auto streamLastMaxOffset = stream->maxOffsetObserved;
  auto connLastMaxOffset = conn.flowControlState.sumMaxObservedOffset;
  auto buf1 = IOBuf::copyBuffer("I just met you ");
  buf1->appendToChain(IOBuf::copyBuffer("and this is crazy. "));

  auto buf2 = IOBuf::copyBuffer("Here's my number ");
  buf2->appendToChain(IOBuf::copyBuffer("so call me maybe"));

  ASSERT_FALSE(appendDataToReadBuffer(*stream, StreamBuffer(buf1->clone(), 0))
                   .hasError());
  ASSERT_FALSE(
      appendDataToReadBuffer(
          *stream,
          StreamBuffer(buf2->clone(), buf1->computeChainDataLength(), true))
          .hasError());
  EXPECT_EQ(
      stream->maxOffsetObserved - streamLastMaxOffset,
      conn.flowControlState.sumMaxObservedOffset - connLastMaxOffset);

  bool peekCbCalled = false;

  auto peekCallback = [&](StreamId /* unused */,
                          const folly::Range<PeekIterator>& range) {
    peekCbCalled = true;
    EXPECT_EQ(range.size(), 1);
    for (const auto& streamBuf : range) {
      auto bufClone = streamBuf.data.front()->clone();
      EXPECT_EQ(
          "I just met you and this is crazy. Here's my number so call me maybe",
          bufClone->toString());
    }
  };

  peekDataFromQuicStream(*stream, peekCallback);
  EXPECT_TRUE(peekCbCalled);

  EXPECT_NO_THROW(((void)consumeDataFromQuicStream(*stream, 81)));

  peekCbCalled = false;
  auto peekCallback2 = [&](StreamId /* unused */,
                           const folly::Range<PeekIterator>& range) {
    peekCbCalled = true;
    EXPECT_EQ(range.size(), 0);
  };

  peekDataFromQuicStream(*stream, peekCallback2);
  EXPECT_TRUE(peekCbCalled);
}

TEST_F(QuicStreamFunctionsTestBase, TestPeekAndConsumeNonContiguousData) {
  auto stream = conn.streamManager->createNextBidirectionalStream().value();
  auto streamLastMaxOffset = stream->maxOffsetObserved;
  auto connLastMaxOffset = conn.flowControlState.sumMaxObservedOffset;
  auto buf1 = IOBuf::copyBuffer("I just met you ");
  buf1->appendToChain(IOBuf::copyBuffer("and this is crazy. "));

  auto buf2 = IOBuf::copyBuffer("'s my number ");
  buf2->appendToChain(IOBuf::copyBuffer("so call me maybe"));

  ASSERT_FALSE(appendDataToReadBuffer(*stream, StreamBuffer(buf1->clone(), 0))
                   .hasError());
  ASSERT_FALSE(
      appendDataToReadBuffer(
          *stream,
          StreamBuffer(buf2->clone(), buf1->computeChainDataLength() + 4, true))
          .hasError());
  EXPECT_EQ(
      stream->maxOffsetObserved - streamLastMaxOffset,
      conn.flowControlState.sumMaxObservedOffset - connLastMaxOffset);

  bool cbCalled = false;
  peekDataFromQuicStream(
      *stream,
      [&](StreamId /* unused */, const folly::Range<PeekIterator>& range) {
        cbCalled = true;
        EXPECT_EQ(range.size(), 2);

        auto bufClone = range[0].data.front()->clone();
        EXPECT_EQ("I just met you and this is crazy. ", bufClone->toString());

        bufClone = range[1].data.front()->clone();
        EXPECT_EQ("'s my number so call me maybe", bufClone->toString());
      });
  EXPECT_TRUE(cbCalled);

  // Consume left side.
  EXPECT_NO_THROW(((void)consumeDataFromQuicStream(*stream, 81)));

  cbCalled = false;
  auto peekCallback2 = [&](StreamId /* unused */,
                           const folly::Range<PeekIterator>& range) {
    cbCalled = true;
    EXPECT_EQ(range.size(), 1);

    auto bufClone = range[0].data.front()->clone();
    EXPECT_EQ("'s my number so call me maybe", bufClone->toString());
  };
  peekDataFromQuicStream(*stream, peekCallback2);
  EXPECT_TRUE(cbCalled);

  // Try consuming again.
  // Nothing has changed since we're missing data in the middle.
  EXPECT_NO_THROW(((void)consumeDataFromQuicStream(*stream, 81)));
  cbCalled = false;
  peekDataFromQuicStream(*stream, peekCallback2);
  EXPECT_TRUE(cbCalled);

  // Add missing middle bytes.
  auto buf3 = IOBuf::copyBuffer("Here");
  ASSERT_FALSE(appendDataToReadBuffer(*stream, StreamBuffer(buf3->clone(), 0))
                   .hasError());
  ASSERT_FALSE(
      appendDataToReadBuffer(
          *stream, StreamBuffer(buf3->clone(), buf1->computeChainDataLength()))
          .hasError());

  cbCalled = false;
  peekDataFromQuicStream(
      *stream,
      [&](StreamId /* unused */, const folly::Range<PeekIterator>& range) {
        cbCalled = true;
        EXPECT_EQ(range.size(), 1);

        auto bufClone = range[0].data.front()->clone();
        EXPECT_EQ("Here's my number so call me maybe", bufClone->toString());
      });
  EXPECT_TRUE(cbCalled);

  // Consume the rest of the buffer.
  EXPECT_NO_THROW(((void)consumeDataFromQuicStream(*stream, 81)));

  cbCalled = false;
  peekDataFromQuicStream(
      *stream,
      [&](StreamId /* unused */, const folly::Range<PeekIterator>& range) {
        cbCalled = true;
        EXPECT_EQ(range.size(), 0);
      });
  EXPECT_TRUE(cbCalled);
}

TEST_F(QuicStreamFunctionsTestBase, TestPeekAndConsumeEmptyData) {
  auto stream = conn.streamManager->createNextBidirectionalStream().value();

  bool cbCalled = false;
  auto peekCallback = [&](StreamId /* unused */,
                          const folly::Range<PeekIterator>& range) {
    cbCalled = true;
    EXPECT_EQ(range.size(), 0);
  };

  peekDataFromQuicStream(*stream, peekCallback);
  EXPECT_TRUE(cbCalled);

  EXPECT_NO_THROW(((void)consumeDataFromQuicStream(*stream, 81)));

  cbCalled = false;
  peekDataFromQuicStream(*stream, peekCallback);
  EXPECT_TRUE(cbCalled);
}

TEST_F(QuicStreamFunctionsTestBase, TestPeekAndConsumeEmptyDataEof) {
  auto stream = conn.streamManager->createNextBidirectionalStream().value();

  bool cbCalled = false;
  auto peekCallback = [&](StreamId /* unused */,
                          const folly::Range<PeekIterator>& range) {
    cbCalled = true;
    EXPECT_EQ(range.size(), 0);
  };

  ASSERT_FALSE(appendDataToReadBuffer(*stream, StreamBuffer(nullptr, 0, true))
                   .hasError());

  peekDataFromQuicStream(*stream, peekCallback);
  EXPECT_TRUE(cbCalled);

  EXPECT_NO_THROW(((void)consumeDataFromQuicStream(*stream, 42)));

  cbCalled = false;
  peekDataFromQuicStream(*stream, peekCallback);
  EXPECT_TRUE(cbCalled);
}

TEST_F(QuicStreamFunctionsTestBase, TestReadDataFromMultipleBufs) {
  auto stream = conn.streamManager->createNextBidirectionalStream().value();
  auto buf1 = IOBuf::copyBuffer("I just met you ");
  buf1->appendToChain(IOBuf::copyBuffer("and this is crazy. "));

  auto buf2 = IOBuf::copyBuffer("Here's my number ");
  buf2->appendToChain(IOBuf::copyBuffer("so call me maybe"));

  auto streamLastMaxOffset = stream->maxOffsetObserved;
  auto connLastMaxOffset = conn.flowControlState.sumMaxObservedOffset;
  ASSERT_FALSE(appendDataToReadBuffer(*stream, StreamBuffer(buf1->clone(), 0))
                   .hasError());
  ASSERT_FALSE(
      appendDataToReadBuffer(
          *stream,
          StreamBuffer(buf2->clone(), buf1->computeChainDataLength(), true))
          .hasError());

  EXPECT_EQ(
      stream->maxOffsetObserved - streamLastMaxOffset,
      conn.flowControlState.sumMaxObservedOffset - connLastMaxOffset);
  EXPECT_EQ(
      stream->maxOffsetObserved - streamLastMaxOffset,
      conn.flowControlState.sumMaxObservedOffset - connLastMaxOffset);
  auto readData1 = readDataFromQuicStream(*stream, 100);
  EXPECT_EQ(
      "I just met you and this is crazy. Here's my number so call me maybe",
      readData1->first->toString());
  EXPECT_TRUE(readData1->first);

  auto readData2 = readDataFromQuicStream(*stream, 30);
  EXPECT_EQ(nullptr, readData2->first);
}

TEST_F(QuicStreamFunctionsTestBase, TestReadDataFromMultipleBufsShared) {
  auto stream = conn.streamManager->createNextBidirectionalStream().value();
  auto buf1 = IOBuf::copyBuffer("I just met you ");
  buf1->appendToChain(IOBuf::copyBuffer("and this is crazy. "));
  buf1->coalesceWithHeadroomTailroom(0, 8000);

  auto buf2 = IOBuf::copyBuffer("Here's my number ");
  buf2->appendToChain(IOBuf::copyBuffer("so call me maybe"));

  // Manually share the buffers like multiple stream frames in a packet.
  auto buf3 = buf1->clone();
  buf3->trimStart(buf3->length());
  memcpy(buf3->writableTail(), " it's hard to look right at you", 31);
  buf3->append(31);

  auto streamLastMaxOffset = stream->maxOffsetObserved;
  auto connLastMaxOffset = conn.flowControlState.sumMaxObservedOffset;
  ASSERT_FALSE(appendDataToReadBuffer(*stream, StreamBuffer(buf1->clone(), 0))
                   .hasError());
  ASSERT_FALSE(
      appendDataToReadBuffer(
          *stream,
          StreamBuffer(std::move(buf2), buf1->computeChainDataLength(), false))
          .hasError());
  ASSERT_FALSE(
      appendDataToReadBuffer(
          *stream,
          StreamBuffer(
              std::move(buf3), buf1->computeChainDataLength() + 33, true))
          .hasError());

  EXPECT_EQ(
      stream->maxOffsetObserved - streamLastMaxOffset,
      conn.flowControlState.sumMaxObservedOffset - connLastMaxOffset);
  EXPECT_EQ(
      stream->maxOffsetObserved - streamLastMaxOffset,
      conn.flowControlState.sumMaxObservedOffset - connLastMaxOffset);
  auto readData1 = readDataFromQuicStream(*stream, 100);
  EXPECT_EQ(
      "I just met you and this is crazy. Here's my number so call me maybe it's hard to look right at you",
      readData1->first->toString());
  EXPECT_TRUE(readData1->first);

  auto readData2 = readDataFromQuicStream(*stream, 30);
  EXPECT_EQ(nullptr, readData2->first);
}

TEST_F(QuicStreamFunctionsTestBase, TestReadDataOutOfOrder) {
  auto stream = conn.streamManager->createNextBidirectionalStream().value();
  auto buf1 = IOBuf::copyBuffer(" you ");
  buf1->appendToChain(IOBuf::copyBuffer("and this is crazy. "));

  auto buf2 = IOBuf::copyBuffer("Here's my number ");
  buf2->appendToChain(IOBuf::copyBuffer("so call me maybe"));
  auto streamLastMaxOffset = stream->maxOffsetObserved;
  auto connLastMaxOffset = conn.flowControlState.sumMaxObservedOffset;

  ASSERT_FALSE(appendDataToReadBuffer(*stream, StreamBuffer(buf1->clone(), 10))
                   .hasError());
  ASSERT_FALSE(
      appendDataToReadBuffer(
          *stream,
          StreamBuffer(
              buf2->clone(), buf1->computeChainDataLength() + 10, true))
          .hasError());
  EXPECT_EQ(
      stream->maxOffsetObserved - streamLastMaxOffset,
      conn.flowControlState.sumMaxObservedOffset - connLastMaxOffset);

  auto readData1 = readDataFromQuicStream(*stream, 100);
  EXPECT_EQ(nullptr, readData1->first);

  ASSERT_FALSE(appendDataToReadBuffer(
                   *stream, StreamBuffer(IOBuf::copyBuffer("I just met"), 0))
                   .hasError());
  auto readData2 = readDataFromQuicStream(*stream, 19);
  EXPECT_EQ("I just met you and ", readData2->first->toString());
  EXPECT_FALSE(readData2->second);

  auto readData3 = readDataFromQuicStream(*stream, 31);
  EXPECT_EQ("this is crazy. Here's my number", readData3->first->toString());
  EXPECT_FALSE(readData3->second);

  auto readData4 = readDataFromQuicStream(*stream);
  EXPECT_EQ(" so call me maybe", readData4->first->toString());
  EXPECT_TRUE(readData4->second);
}

TEST_F(QuicStreamFunctionsTestBase, TestReadOverlappingData) {
  auto stream = conn.streamManager->createNextBidirectionalStream().value();
  auto buf1 = IOBuf::copyBuffer("I just met you ");
  buf1->appendToChain(IOBuf::copyBuffer("and this"));

  auto buf2 = IOBuf::copyBuffer("met you and this is crazy. ");
  buf2->appendToChain(IOBuf::copyBuffer("Here's my number"));

  auto buf3 = IOBuf::copyBuffer("Here's my number, ");
  buf3->appendToChain(IOBuf::copyBuffer("so call me maybe."));

  auto streamLastMaxOffset = stream->maxOffsetObserved;
  auto connLastMaxOffset = conn.flowControlState.sumMaxObservedOffset;
  ASSERT_FALSE(appendDataToReadBuffer(*stream, StreamBuffer(buf1->clone(), 0))
                   .hasError());
  ASSERT_FALSE(appendDataToReadBuffer(*stream, StreamBuffer(buf2->clone(), 7))
                   .hasError());
  ASSERT_FALSE(
      appendDataToReadBuffer(*stream, StreamBuffer(buf3->clone(), 34, true))
          .hasError());

  EXPECT_EQ(
      stream->maxOffsetObserved - streamLastMaxOffset,
      conn.flowControlState.sumMaxObservedOffset - connLastMaxOffset);
  auto readData1 = readDataFromQuicStream(*stream, 100);
  auto str = readData1->first->toString();
  EXPECT_EQ(
      "I just met you and this is crazy. Here's my number, so call me maybe.",
      str);
  EXPECT_TRUE(readData1->second);
}

TEST_F(QuicStreamFunctionsTestBase, TestCompleteOverlap) {
  auto stream = conn.streamManager->createNextBidirectionalStream().value();
  auto buf1 = IOBuf::copyBuffer("met you ");
  auto buf2 = IOBuf::copyBuffer("this is");
  auto buf3 = IOBuf::copyBuffer("I just met you and this is crazy");

  auto streamLastMaxOffset = stream->maxOffsetObserved;
  auto connLastMaxOffset = conn.flowControlState.sumMaxObservedOffset;
  ASSERT_FALSE(appendDataToReadBuffer(*stream, StreamBuffer(buf1->clone(), 7))
                   .hasError());
  ASSERT_FALSE(appendDataToReadBuffer(*stream, StreamBuffer(buf2->clone(), 19))
                   .hasError());
  ASSERT_FALSE(
      appendDataToReadBuffer(*stream, StreamBuffer(buf3->clone(), 0, true))
          .hasError());
  EXPECT_EQ(
      stream->maxOffsetObserved - streamLastMaxOffset,
      conn.flowControlState.sumMaxObservedOffset - connLastMaxOffset);

  EXPECT_EQ(stream->readBuffer.size(), 1);
  auto readData1 = readDataFromQuicStream(*stream, 100);
  EXPECT_EQ("I just met you and this is crazy", readData1->first->toString());
  EXPECT_TRUE(readData1->second);
  EXPECT_TRUE(stream->readBuffer.empty());
}

TEST_F(QuicStreamFunctionsTestBase, TestTotalOverlap) {
  auto stream = conn.streamManager->createNextBidirectionalStream().value();
  auto buf1 = IOBuf::copyBuffer("met you ");
  auto streamLastMaxOffset = stream->maxOffsetObserved;
  auto connLastMaxOffset = conn.flowControlState.sumMaxObservedOffset;

  ASSERT_FALSE(appendDataToReadBuffer(*stream, StreamBuffer(buf1->clone(), 0))
                   .hasError());
  ASSERT_FALSE(appendDataToReadBuffer(*stream, StreamBuffer(buf1->clone(), 0))
                   .hasError());
  ASSERT_FALSE(
      appendDataToReadBuffer(*stream, StreamBuffer(buf1->clone(), 0, true))
          .hasError());

  EXPECT_EQ(
      stream->maxOffsetObserved - streamLastMaxOffset,
      conn.flowControlState.sumMaxObservedOffset - connLastMaxOffset);
  EXPECT_EQ(stream->readBuffer.size(), 1);
  auto readData1 = readDataFromQuicStream(*stream, 100);
  EXPECT_EQ("met you ", readData1->first->toString());
  EXPECT_TRUE(readData1->second);
  EXPECT_TRUE(stream->readBuffer.empty());
}

TEST_F(QuicStreamFunctionsTestBase, TestSubsetOverlap) {
  auto stream = conn.streamManager->createNextBidirectionalStream().value();
  auto buf1 = IOBuf::copyBuffer("met you ");
  auto buf2 = IOBuf::copyBuffer("you");
  auto buf3 = IOBuf::copyBuffer("you ");

  auto streamLastMaxOffset = stream->maxOffsetObserved;
  auto connLastMaxOffset = conn.flowControlState.sumMaxObservedOffset;
  ASSERT_FALSE(appendDataToReadBuffer(*stream, StreamBuffer(buf1->clone(), 0))
                   .hasError());
  ASSERT_FALSE(appendDataToReadBuffer(*stream, StreamBuffer(buf2->clone(), 4))
                   .hasError());
  ASSERT_FALSE(
      appendDataToReadBuffer(*stream, StreamBuffer(buf3->clone(), 4, true))
          .hasError());

  EXPECT_EQ(
      stream->maxOffsetObserved - streamLastMaxOffset,
      conn.flowControlState.sumMaxObservedOffset - connLastMaxOffset);
  EXPECT_EQ(stream->readBuffer.size(), 1);
  auto readData1 = readDataFromQuicStream(*stream, 100);
  EXPECT_EQ("met you ", readData1->first->toString());
  EXPECT_TRUE(readData1->second);
  EXPECT_TRUE(stream->readBuffer.empty());
}

TEST_F(QuicStreamFunctionsTestBase, TestLeftOverlap) {
  auto stream = conn.streamManager->createNextBidirectionalStream().value();
  auto buf1 = IOBuf::copyBuffer("met you ");
  auto buf2 = IOBuf::copyBuffer("I just met");

  auto streamLastMaxOffset = stream->maxOffsetObserved;
  auto connLastMaxOffset = conn.flowControlState.sumMaxObservedOffset;
  ASSERT_FALSE(
      appendDataToReadBuffer(*stream, StreamBuffer(buf1->clone(), 7, true))
          .hasError());
  ASSERT_FALSE(appendDataToReadBuffer(*stream, StreamBuffer(buf2->clone(), 0))
                   .hasError());
  EXPECT_EQ(
      stream->maxOffsetObserved - streamLastMaxOffset,
      conn.flowControlState.sumMaxObservedOffset - connLastMaxOffset);

  EXPECT_EQ(stream->readBuffer.size(), 1);
  auto readData1 = readDataFromQuicStream(*stream, 100);
  EXPECT_EQ("I just met you ", readData1->first->toString());
  EXPECT_TRUE(readData1->second);
  EXPECT_TRUE(stream->readBuffer.empty());
}

TEST_F(QuicStreamFunctionsTestBase, TestLeftNoOverlap) {
  auto stream = conn.streamManager->createNextBidirectionalStream().value();
  auto buf1 = IOBuf::copyBuffer("met you ");
  auto buf2 = IOBuf::copyBuffer("I just");

  auto streamLastMaxOffset = stream->maxOffsetObserved;
  auto connLastMaxOffset = conn.flowControlState.sumMaxObservedOffset;
  ASSERT_FALSE(
      appendDataToReadBuffer(*stream, StreamBuffer(buf1->clone(), 7, true))
          .hasError());
  ASSERT_FALSE(appendDataToReadBuffer(*stream, StreamBuffer(buf2->clone(), 0))
                   .hasError());
  EXPECT_EQ(
      stream->maxOffsetObserved - streamLastMaxOffset,
      conn.flowControlState.sumMaxObservedOffset - connLastMaxOffset);

  EXPECT_EQ(
      stream->maxOffsetObserved - streamLastMaxOffset,
      conn.flowControlState.sumMaxObservedOffset - connLastMaxOffset);
  EXPECT_EQ(stream->readBuffer.size(), 2);
  auto readData1 = readDataFromQuicStream(*stream, 100);
  EXPECT_EQ("I just", readData1->first->toString());
  EXPECT_FALSE(readData1->second);
  EXPECT_EQ(stream->readBuffer.size(), 1);
}

TEST_F(QuicStreamFunctionsTestBase, TestRightOverlap) {
  auto stream = conn.streamManager->createNextBidirectionalStream().value();
  auto buf1 = IOBuf::copyBuffer("I just");
  auto buf2 = IOBuf::copyBuffer(" met you ");
  auto buf3 = IOBuf::copyBuffer("you and this is crazy");

  auto streamLastMaxOffset = stream->maxOffsetObserved;
  auto connLastMaxOffset = conn.flowControlState.sumMaxObservedOffset;
  ASSERT_FALSE(appendDataToReadBuffer(*stream, StreamBuffer(buf1->clone(), 0))
                   .hasError());
  ASSERT_FALSE(appendDataToReadBuffer(*stream, StreamBuffer(buf2->clone(), 6))
                   .hasError());
  ASSERT_FALSE(
      appendDataToReadBuffer(*stream, StreamBuffer(buf3->clone(), 11, true))
          .hasError());

  EXPECT_EQ(
      stream->maxOffsetObserved - streamLastMaxOffset,
      conn.flowControlState.sumMaxObservedOffset - connLastMaxOffset);
  EXPECT_EQ(stream->readBuffer.size(), 1);
  auto readData1 = readDataFromQuicStream(*stream, 100);
  EXPECT_EQ("I just met you and this is crazy", readData1->first->toString());
  EXPECT_TRUE(readData1->second);
  EXPECT_TRUE(stream->readBuffer.empty());
} // namespace test

TEST_F(QuicStreamFunctionsTestBase, TestRightNoOverlap) {
  auto stream = conn.streamManager->createNextBidirectionalStream().value();
  auto buf1 = IOBuf::copyBuffer("I just");
  auto buf2 = IOBuf::copyBuffer("met you ");

  auto streamLastMaxOffset = stream->maxOffsetObserved;
  auto connLastMaxOffset = conn.flowControlState.sumMaxObservedOffset;
  ASSERT_FALSE(appendDataToReadBuffer(*stream, StreamBuffer(buf1->clone(), 0))
                   .hasError());
  ASSERT_FALSE(appendDataToReadBuffer(*stream, StreamBuffer(buf2->clone(), 7))
                   .hasError());

  EXPECT_EQ(
      stream->maxOffsetObserved - streamLastMaxOffset,
      conn.flowControlState.sumMaxObservedOffset - connLastMaxOffset);
  EXPECT_EQ(stream->readBuffer.size(), 2);
  auto readData1 = readDataFromQuicStream(*stream, 100);
  EXPECT_EQ("I just", readData1->first->toString());
  EXPECT_FALSE(readData1->second);
  EXPECT_EQ(stream->readBuffer.size(), 1);
}

TEST_F(QuicStreamFunctionsTestBase, TestRightLeftOverlap) {
  auto stream = conn.streamManager->createNextBidirectionalStream().value();
  auto buf1 = IOBuf::copyBuffer("I just met");
  auto buf2 = IOBuf::copyBuffer("met you");
  auto buf3 = IOBuf::copyBuffer("you and this is crazy");

  auto streamLastMaxOffset = stream->maxOffsetObserved;
  auto connLastMaxOffset = conn.flowControlState.sumMaxObservedOffset;
  ASSERT_FALSE(appendDataToReadBuffer(*stream, StreamBuffer(buf1->clone(), 0))
                   .hasError());
  ASSERT_FALSE(
      appendDataToReadBuffer(*stream, StreamBuffer(buf3->clone(), 11, true))
          .hasError());
  ASSERT_FALSE(appendDataToReadBuffer(*stream, StreamBuffer(buf2->clone(), 7))
                   .hasError());
  EXPECT_EQ(
      stream->maxOffsetObserved - streamLastMaxOffset,
      conn.flowControlState.sumMaxObservedOffset - connLastMaxOffset);
  EXPECT_EQ(stream->readBuffer.size(), 1);
  auto readData1 = readDataFromQuicStream(*stream, 100);
  EXPECT_EQ("I just met you and this is crazy", readData1->first->toString());
  EXPECT_TRUE(readData1->second);
  EXPECT_TRUE(stream->readBuffer.empty());
}

TEST_F(QuicStreamFunctionsTestBase, TestInsertVariations) {
  auto stream = conn.streamManager->createNextBidirectionalStream().value();
  auto buf1 = IOBuf::copyBuffer("met you ");
  auto buf2 = IOBuf::copyBuffer("this is crazy.");
  auto buf3 = IOBuf::copyBuffer(" Here's my number");
  auto buf4 = IOBuf::copyBuffer("number so call");
  auto buf5 = IOBuf::copyBuffer(
      "just met you and this is crazy. Here's my number so call");
  auto buf6 = IOBuf::copyBuffer(" me maybe");
  auto buf7 = IOBuf::copyBuffer("this is crazy. Here's my number so call");
  auto buf8 = IOBuf::copyBuffer("I just met you");
  buf8->appendToChain(IOBuf::copyBuffer(" and this"));
  auto buf9 = IOBuf::copyBuffer("Here's my number so call me maybe");
  auto buf10 = IOBuf::copyBuffer("I ");

  auto streamLastMaxOffset = stream->maxOffsetObserved;
  auto connLastMaxOffset = conn.flowControlState.sumMaxObservedOffset;
  ASSERT_FALSE(appendDataToReadBuffer(*stream, StreamBuffer(buf1->clone(), 7))
                   .hasError());
  ASSERT_FALSE(appendDataToReadBuffer(*stream, StreamBuffer(buf2->clone(), 19))
                   .hasError());
  ASSERT_FALSE(appendDataToReadBuffer(*stream, StreamBuffer(buf3->clone(), 33))
                   .hasError());
  ASSERT_FALSE(appendDataToReadBuffer(*stream, StreamBuffer(buf4->clone(), 44))
                   .hasError());
  ASSERT_FALSE(appendDataToReadBuffer(*stream, StreamBuffer(buf5->clone(), 2))
                   .hasError());
  ASSERT_FALSE(appendDataToReadBuffer(*stream, StreamBuffer(buf6->clone(), 58))
                   .hasError());
  ASSERT_FALSE(appendDataToReadBuffer(*stream, StreamBuffer(buf7->clone(), 19))
                   .hasError());
  ASSERT_FALSE(appendDataToReadBuffer(*stream, StreamBuffer(buf8->clone(), 0))
                   .hasError());
  ASSERT_FALSE(
      appendDataToReadBuffer(*stream, StreamBuffer(buf9->clone(), 34, true))
          .hasError());
  ASSERT_FALSE(appendDataToReadBuffer(*stream, StreamBuffer(buf10->clone(), 0))
                   .hasError());
  EXPECT_EQ(
      stream->maxOffsetObserved - streamLastMaxOffset,
      conn.flowControlState.sumMaxObservedOffset - connLastMaxOffset);

  auto readData1 = readDataFromQuicStream(*stream, 100);
  auto str = readData1->first->toString();
  EXPECT_EQ(
      "I just met you and this is crazy. Here's my number so call me maybe",
      str);
  EXPECT_TRUE(readData1->second);
  EXPECT_TRUE(stream->readBuffer.empty());
}

TEST_F(QuicStreamFunctionsTestBase, TestAppendAlreadyReadData) {
  auto stream = conn.streamManager->createNextBidirectionalStream().value();
  auto buf1 = IOBuf::copyBuffer("I just met you and this is crazy");
  auto buf2 = IOBuf::copyBuffer("I just met you and this is");
  auto buf3 = IOBuf::copyBuffer("I just met you and this is crazy");
  auto buf4 =
      IOBuf::copyBuffer("I just met you and this is crazy. Here's my number");
  auto buf5 = IOBuf::copyBuffer(
      "I just met you and this is crazy. Here's my number so call me");
  auto buf6 = IOBuf::copyBuffer(
      "I just met you and this is crazy. Here's my number so call me maybe");

  auto streamLastMaxOffset = stream->maxOffsetObserved;
  auto connLastMaxOffset = conn.flowControlState.sumMaxObservedOffset;
  ASSERT_FALSE(appendDataToReadBuffer(*stream, StreamBuffer(buf1->clone(), 0))
                   .hasError());
  auto readData1 = readDataFromQuicStream(*stream, 100);
  EXPECT_EQ("I just met you and this is crazy", readData1->first->toString());
  EXPECT_FALSE(readData1->second);

  ASSERT_FALSE(appendDataToReadBuffer(*stream, StreamBuffer(buf2->clone(), 0))
                   .hasError());
  auto readData2 = readDataFromQuicStream(*stream, 100);
  EXPECT_EQ(readData2->first, nullptr);
  EXPECT_FALSE(readData2->second);
  EXPECT_TRUE(stream->readBuffer.empty());

  ASSERT_FALSE(appendDataToReadBuffer(*stream, StreamBuffer(buf3->clone(), 0))
                   .hasError());
  auto readData3 = readDataFromQuicStream(*stream, 100);
  EXPECT_EQ(readData3->first, nullptr);
  EXPECT_FALSE(readData3->second);
  EXPECT_TRUE(stream->readBuffer.empty());

  ASSERT_FALSE(appendDataToReadBuffer(*stream, StreamBuffer(buf4->clone(), 0))
                   .hasError());
  auto readData4 = readDataFromQuicStream(*stream, 100);
  EXPECT_EQ(". Here's my number", readData4->first->toString());
  EXPECT_FALSE(readData4->second);
  EXPECT_TRUE(stream->readBuffer.empty());

  ASSERT_FALSE(appendDataToReadBuffer(*stream, StreamBuffer(buf5->clone(), 0))
                   .hasError());
  ASSERT_FALSE(appendDataToReadBuffer(*stream, StreamBuffer(buf6->clone(), 0))
                   .hasError());
  auto readData5 = readDataFromQuicStream(*stream, 100);
  EXPECT_EQ(" so call me maybe", readData5->first->toString());
  EXPECT_FALSE(readData5->second);
  EXPECT_TRUE(stream->readBuffer.empty());

  ASSERT_FALSE(
      appendDataToReadBuffer(*stream, StreamBuffer(buf6->clone(), 0, true))
          .hasError());
  auto readData6 = readDataFromQuicStream(*stream, 100);
  EXPECT_EQ(readData6->first, nullptr);
  EXPECT_TRUE(readData6->second);
  EXPECT_EQ(
      stream->maxOffsetObserved - streamLastMaxOffset,
      conn.flowControlState.sumMaxObservedOffset - connLastMaxOffset);
}

TEST_F(QuicStreamFunctionsTestBase, TestEmptyEOF) {
  auto stream = conn.streamManager->createNextBidirectionalStream().value();
  auto buf1 = IOBuf::copyBuffer("I just");
  auto buf2 = IOBuf::copyBuffer("");

  ASSERT_FALSE(appendDataToReadBuffer(*stream, StreamBuffer(buf1->clone(), 0))
                   .hasError());
  ASSERT_FALSE(
      appendDataToReadBuffer(*stream, StreamBuffer(buf2->clone(), 7, true))
          .hasError());

  EXPECT_EQ(stream->readBuffer.size(), 1);
  auto readData1 = readDataFromQuicStream(*stream, 100);
  EXPECT_EQ("I just", readData1->first->toString());
  EXPECT_FALSE(readData1->second);
  EXPECT_TRUE(stream->readBuffer.empty());

  auto buf3 = IOBuf::copyBuffer("m");
  ASSERT_FALSE(appendDataToReadBuffer(*stream, StreamBuffer(buf3->clone(), 6))
                   .hasError());
  auto readData2 = readDataFromQuicStream(*stream, 100);
  EXPECT_EQ("m", readData2->first->toString());
  EXPECT_TRUE(readData2->second);
  EXPECT_TRUE(stream->readBuffer.empty());
}

TEST_F(QuicStreamFunctionsTestBase, TestEmptyEOFOverlap) {
  auto stream = conn.streamManager->createNextBidirectionalStream().value();
  auto buf1 = IOBuf::copyBuffer("I just");
  auto buf2 = IOBuf::copyBuffer("");

  ASSERT_FALSE(
      appendDataToReadBuffer(*stream, StreamBuffer(buf1->clone(), 0, true))
          .hasError());
  ASSERT_FALSE(
      appendDataToReadBuffer(*stream, StreamBuffer(buf2->clone(), 6, true))
          .hasError());

  EXPECT_EQ(stream->readBuffer.size(), 1);
  auto readData1 = readDataFromQuicStream(*stream, 100);
  EXPECT_EQ("I just", readData1->first->toString());
  EXPECT_TRUE(readData1->second);
  EXPECT_TRUE(stream->readBuffer.empty());
}

TEST_F(QuicStreamFunctionsTestBase, TestOverlapEOF) {
  auto stream = conn.streamManager->createNextBidirectionalStream().value();
  auto buf1 = IOBuf::copyBuffer("just");
  auto buf2 = IOBuf::copyBuffer("I ");

  ASSERT_FALSE(appendDataToReadBuffer(*stream, StreamBuffer(buf1->clone(), 2))
                   .hasError());
  ASSERT_FALSE(
      appendDataToReadBuffer(*stream, StreamBuffer(buf1->clone(), 2, true))
          .hasError());
  ASSERT_FALSE(appendDataToReadBuffer(*stream, StreamBuffer(buf2->clone(), 0))
                   .hasError());

  EXPECT_EQ(stream->readBuffer.size(), 1);
  auto readData1 = readDataFromQuicStream(*stream, 100);
  EXPECT_EQ("I just", readData1->first->toString());
  EXPECT_TRUE(readData1->second);
  EXPECT_TRUE(stream->readBuffer.empty());
}

TEST_F(QuicStreamFunctionsTestBase, TestEmptyBuffer) {
  auto stream = conn.streamManager->createNextBidirectionalStream().value();
  auto buf1 = IOBuf::copyBuffer("");
  ASSERT_FALSE(appendDataToReadBuffer(*stream, StreamBuffer(buf1->clone(), 0))
                   .hasError());
}

TEST_F(QuicStreamFunctionsTestBase, TestInvalidEOFWithAlreadyReadData) {
  auto stream = conn.streamManager->createNextBidirectionalStream().value();
  auto buf1 = IOBuf::copyBuffer("I just");
  auto buf2 = IOBuf::copyBuffer(" met you");

  ASSERT_FALSE(appendDataToReadBuffer(*stream, StreamBuffer(buf1->clone(), 0))
                   .hasError());
  ASSERT_FALSE(appendDataToReadBuffer(*stream, StreamBuffer(buf2->clone(), 6))
                   .hasError());
  auto readData1 = readDataFromQuicStream(*stream, 6);
  EXPECT_EQ(stream->readBuffer.size(), 1);

  auto result =
      appendDataToReadBuffer(*stream, StreamBuffer(buf1->clone(), 0, true));
  ASSERT_TRUE(result.hasError());
  EXPECT_NE(result.error().code.asTransportErrorCode(), nullptr);
}

TEST_F(QuicStreamFunctionsTestBase, TestInvalidEOFWithSubsetData) {
  auto stream = conn.streamManager->createNextBidirectionalStream().value();
  auto buf1 = IOBuf::copyBuffer("I just");
  auto buf2 = IOBuf::copyBuffer("I");

  ASSERT_FALSE(appendDataToReadBuffer(*stream, StreamBuffer(buf1->clone(), 0))
                   .hasError());
  auto result =
      appendDataToReadBuffer(*stream, StreamBuffer(buf2->clone(), 0, true));
  ASSERT_TRUE(result.hasError());
  EXPECT_NE(result.error().code.asTransportErrorCode(), nullptr);
}

TEST_F(QuicStreamFunctionsTestBase, TestInvalidEOFWithNoOverlap) {
  auto stream = conn.streamManager->createNextBidirectionalStream().value();
  auto buf1 = IOBuf::copyBuffer("just");
  auto buf2 = IOBuf::copyBuffer("I");

  ASSERT_FALSE(appendDataToReadBuffer(*stream, StreamBuffer(buf1->clone(), 2))
                   .hasError());
  auto result =
      appendDataToReadBuffer(*stream, StreamBuffer(buf2->clone(), 0, true));
  ASSERT_TRUE(result.hasError());
  EXPECT_NE(result.error().code.asTransportErrorCode(), nullptr);
}

TEST_F(QuicStreamFunctionsTestBase, TestInvalidExistingEOFWithCompleteOverlap) {
  auto stream = conn.streamManager->createNextBidirectionalStream().value();
  auto buf1 = IOBuf::copyBuffer("just");
  auto buf2 = IOBuf::copyBuffer("I just met");

  ASSERT_FALSE(
      appendDataToReadBuffer(*stream, StreamBuffer(buf1->clone(), 2, true))
          .hasError());
  auto result = appendDataToReadBuffer(*stream, StreamBuffer(buf2->clone(), 0));
  ASSERT_TRUE(result.hasError());
  EXPECT_NE(result.error().code.asTransportErrorCode(), nullptr);
}

TEST_F(QuicStreamFunctionsTestBase, TestInvalidExistingEOFNotLastBuffer) {
  auto stream = conn.streamManager->createNextBidirectionalStream().value();

  auto buf1 = IOBuf::copyBuffer("just met");
  auto buf2 = IOBuf::copyBuffer("you");
  auto buf3 = IOBuf::copyBuffer("I just");

  ASSERT_FALSE(appendDataToReadBuffer(*stream, StreamBuffer(buf1->clone(), 2))
                   .hasError());
  ASSERT_FALSE(appendDataToReadBuffer(*stream, StreamBuffer(buf2->clone(), 11))
                   .hasError());
  auto result =
      appendDataToReadBuffer(*stream, StreamBuffer(buf3->clone(), 0, true));
  ASSERT_TRUE(result.hasError());
  EXPECT_NE(result.error().code.asTransportErrorCode(), nullptr);
}

TEST_F(QuicStreamFunctionsTestBase, TestInvalidExistingEOFRightOverlap) {
  auto stream = conn.streamManager->createNextBidirectionalStream().value();

  auto buf1 = IOBuf::copyBuffer("just met");
  auto buf2 = IOBuf::copyBuffer("met you");

  ASSERT_FALSE(
      appendDataToReadBuffer(*stream, StreamBuffer(buf1->clone(), 2, true))
          .hasError());
  auto result =
      appendDataToReadBuffer(*stream, StreamBuffer(buf2->clone(), 7, true));
  ASSERT_TRUE(result.hasError());
  EXPECT_NE(result.error().code.asTransportErrorCode(), nullptr);
}

TEST_F(QuicStreamFunctionsTestBase, TestInvalidExistingEOFRightOverlapNotLast) {
  auto stream = conn.streamManager->createNextBidirectionalStream().value();

  auto buf1 = IOBuf::copyBuffer("just met");
  auto buf2 = IOBuf::copyBuffer("this is");
  auto buf3 = IOBuf::copyBuffer("met you");

  ASSERT_FALSE(appendDataToReadBuffer(*stream, StreamBuffer(buf1->clone(), 2))
                   .hasError());
  ASSERT_FALSE(appendDataToReadBuffer(*stream, StreamBuffer(buf1->clone(), 16))
                   .hasError());
  auto result =
      appendDataToReadBuffer(*stream, StreamBuffer(buf3->clone(), 7, true));
  ASSERT_TRUE(result.hasError());
  EXPECT_NE(result.error().code.asTransportErrorCode(), nullptr);
}

TEST_F(QuicStreamFunctionsTestBase, SetInvalidMaxStreams) {
  ASSERT_FALSE(conn.streamManager->setMaxLocalBidirectionalStreams(100, true)
                   .hasError());
  ASSERT_FALSE(conn.streamManager->setMaxLocalUnidirectionalStreams(100, true)
                   .hasError());
  ASSERT_FALSE(
      conn.streamManager->setMaxLocalBidirectionalStreams(0).hasError());
  ASSERT_FALSE(
      conn.streamManager->setMaxLocalUnidirectionalStreams(0).hasError());
  EXPECT_EQ(conn.streamManager->openableLocalBidirectionalStreams(), 100);
  EXPECT_EQ(conn.streamManager->openableLocalUnidirectionalStreams(), 100);

  auto bidirectionalResult =
      conn.streamManager->setMaxLocalBidirectionalStreams(kMaxMaxStreams + 1);
  EXPECT_TRUE(bidirectionalResult.hasError());
  EXPECT_EQ(
      bidirectionalResult.error().code, TransportErrorCode::STREAM_LIMIT_ERROR);

  auto unidirectionalResult =
      conn.streamManager->setMaxLocalUnidirectionalStreams(kMaxMaxStreams + 1);
  EXPECT_TRUE(unidirectionalResult.hasError());
  EXPECT_EQ(
      unidirectionalResult.error().code,
      TransportErrorCode::STREAM_LIMIT_ERROR);
}

TEST_F(QuicStreamFunctionsTestBase, GetOrCreateClientCryptoStream) {
  EXPECT_NE(conn.cryptoState, nullptr);
}

TEST_F(QuicServerStreamFunctionsTest, GetOrCreateClientOutOfOrderStream) {
  StreamId outOfOrderStream = 100;
  StreamId existingStream = 88;
  StreamId closedStream = 84;
  ASSERT_FALSE(conn.streamManager->getStream(outOfOrderStream).hasError());

  EXPECT_EQ(conn.streamManager->streamCount(), 1);
  EXPECT_TRUE(conn.streamManager->streamExists(outOfOrderStream));
  // peer stream starts from 0x00
  EXPECT_EQ(
      conn.streamManager->openBidirectionalPeerStreams().size(),
      ((outOfOrderStream) / kStreamIncrement) + 1);

  ASSERT_FALSE(conn.streamManager->getStream(existingStream).hasError());
  EXPECT_EQ(conn.streamManager->streamCount(), 2);
  EXPECT_TRUE(conn.streamManager->streamExists(outOfOrderStream));
  EXPECT_EQ(
      conn.streamManager->openBidirectionalPeerStreams().size(),
      ((outOfOrderStream) / kStreamIncrement) + 1);

  conn.streamManager->openBidirectionalPeerStreams().remove(closedStream);
  auto streamResult = conn.streamManager->getStream(closedStream);
  ASSERT_FALSE(streamResult.hasError());
  EXPECT_EQ(streamResult.value(), nullptr);
}

TEST_F(QuicServerStreamFunctionsTest, GetOrCreateExistingClientStream) {
  StreamId outOfOrderStream1 = 100;
  StreamId outOfOrderStream2 = 48;

  auto stream = conn.streamManager->getStream(outOfOrderStream1);
  auto stream2 = conn.streamManager->getStream(outOfOrderStream1);
  EXPECT_EQ(stream, stream2);
  ASSERT_FALSE(conn.streamManager->getStream(outOfOrderStream2).hasError());
}

TEST_F(QuicStreamFunctionsTestBase, GetOrCreateExistingServerStream) {
  StreamId outOfOrderStream1 = 101;
  StreamId outOfOrderStream2 = 49;
  auto stream = conn.streamManager->getStream(outOfOrderStream1);
  auto stream2 = conn.streamManager->getStream(outOfOrderStream1);
  EXPECT_EQ(stream, stream2);
  ASSERT_FALSE(conn.streamManager->getStream(outOfOrderStream2).hasError());
}

TEST_F(QuicServerStreamFunctionsTest, GetOrCreateClosedClientStream) {
  StreamId outOfOrderStream1 = 100;
  StreamId closedStream = 48;
  ASSERT_FALSE(conn.streamManager->getStream(outOfOrderStream1).hasError());
  conn.streamManager->openBidirectionalPeerStreams().remove(closedStream);
  auto streamResult = conn.streamManager->getStream(closedStream);
  ASSERT_FALSE(streamResult.hasError());
  EXPECT_EQ(streamResult.value(), nullptr);
}

TEST_F(
    QuicServerStreamFunctionsTest,
    GetOrCreateClientStreamAfterClosingLastStream) {
  StreamId outOfOrderStream1 = 96;
  StreamId outOfOrderStream2 = 100;
  ASSERT_FALSE(conn.streamManager->getStream(outOfOrderStream1).hasError());
  conn.streamManager->openBidirectionalPeerStreams().remove(outOfOrderStream1);
  ASSERT_FALSE(conn.streamManager->getStream(outOfOrderStream2).hasError());
  EXPECT_EQ(
      conn.streamManager->openBidirectionalPeerStreams().size(),
      (outOfOrderStream2) / kStreamIncrement);
}

TEST_F(
    QuicStreamFunctionsTestBase,
    GetOrCreateServerStreamAfterClosingLastStream) {
  StreamId outOfOrderStream1 = 97;
  StreamId outOfOrderStream2 = 101;
  ASSERT_FALSE(conn.streamManager->getStream(outOfOrderStream1).hasError());
  conn.streamManager->openBidirectionalPeerStreams().remove(outOfOrderStream1);
  ASSERT_FALSE(conn.streamManager->getStream(outOfOrderStream2).hasError());
  EXPECT_EQ(
      conn.streamManager->openBidirectionalPeerStreams().size(),
      (outOfOrderStream2 + 1) / kStreamIncrement);
}

TEST_F(QuicStreamFunctionsTestBase, GetOrCreateClosedServerStream) {
  StreamId outOfOrderStream1 = 97;
  StreamId closedStream = 49;
  ASSERT_FALSE(conn.streamManager->getStream(outOfOrderStream1).hasError());
  conn.streamManager->openBidirectionalPeerStreams().remove(closedStream);
  auto streamResult = conn.streamManager->getStream(closedStream);
  ASSERT_FALSE(streamResult.hasError());
  EXPECT_EQ(streamResult.value(), nullptr);
}

TEST_F(QuicServerStreamFunctionsTest, GetOrCreateServerStreamOnServer) {
  StreamId serverStream = 101;
  auto streamResult = conn.streamManager->getStream(serverStream);
  ASSERT_TRUE(streamResult.hasError());
  EXPECT_EQ(streamResult.error().code, TransportErrorCode::STREAM_STATE_ERROR);
}

TEST_F(QuicStreamFunctionsTestBase, GetOrCreateClientStreamOnClient) {
  StreamId clientStream = 100;
  auto streamResult = conn.streamManager->getStream(clientStream);
  ASSERT_TRUE(streamResult.hasError());
  EXPECT_EQ(streamResult.error().code, TransportErrorCode::STREAM_STATE_ERROR);
}

TEST_F(QuicStreamFunctionsTestBase, GetOrCreateNonClientOrServer) {
  StreamId streamZero = 0;
  auto streamResult = conn.streamManager->getStream(streamZero);
  ASSERT_TRUE(streamResult.hasError());
  EXPECT_EQ(streamResult.error().code, TransportErrorCode::STREAM_STATE_ERROR);
}

TEST_F(QuicServerStreamFunctionsTest, CreateQuicStreamServerOutOfOrder) {
  StreamId outOfOrderStream1 = 101;
  StreamId outOfOrderStream2 = 49;
  ASSERT_FALSE(conn.streamManager->createStream(outOfOrderStream1).hasError());
  EXPECT_EQ(conn.streamManager->streamCount(), 1);
  EXPECT_EQ(
      conn.streamManager->openUnidirectionalLocalStreams().size() +
          conn.streamManager->openBidirectionalLocalStreams().size(),
      26);
  ASSERT_FALSE(conn.streamManager->createStream(outOfOrderStream2).hasError());
  EXPECT_EQ(conn.streamManager->streamCount(), 2);
  EXPECT_EQ(
      conn.streamManager->openUnidirectionalLocalStreams().size() +
          conn.streamManager->openBidirectionalLocalStreams().size(),
      26);
}

TEST_F(QuicStreamFunctionsTestBase, CreateQuicStreamClientOutOfOrder) {
  StreamId outOfOrderStream1 = 96;
  StreamId outOfOrderStream2 = 48;
  ASSERT_FALSE(conn.streamManager->createStream(outOfOrderStream1).hasError());
  EXPECT_EQ(conn.streamManager->streamCount(), 1);
  EXPECT_EQ(
      conn.streamManager->openUnidirectionalLocalStreams().size() +
          conn.streamManager->openBidirectionalLocalStreams().size(),
      25);
  ASSERT_FALSE(conn.streamManager->createStream(outOfOrderStream2).hasError());
  EXPECT_EQ(conn.streamManager->streamCount(), 2);
  EXPECT_EQ(
      conn.streamManager->openUnidirectionalLocalStreams().size() +
          conn.streamManager->openBidirectionalLocalStreams().size(),
      25);
}

TEST_F(QuicServerStreamFunctionsTest, CreateClosedServerStream) {
  StreamId outOfOrderStream1 = 101;
  StreamId outOfOrderStream2 = 49;
  auto result1 = conn.streamManager->createStream(outOfOrderStream1);
  ASSERT_FALSE(result1.hasError());
  ASSERT_TRUE(result1.value());
  conn.streamManager->openBidirectionalLocalStreams().remove(outOfOrderStream2);
  auto result2 = conn.streamManager->createStream(outOfOrderStream2);
  ASSERT_TRUE(result2.hasError());
}

TEST_F(QuicStreamFunctionsTestBase, CreateClosedClientStream) {
  StreamId outOfOrderStream1 = 96;
  StreamId outOfOrderStream2 = 48;
  conn.streamManager->createStream(outOfOrderStream1).value();
  conn.streamManager->openBidirectionalLocalStreams().remove(outOfOrderStream2);
  EXPECT_FALSE(conn.streamManager->createStream(outOfOrderStream2));
}

TEST_F(QuicStreamFunctionsTestBase, CreateInvalidServerStreamOnClient) {
  StreamId serverStream = 0x09;
  auto result = conn.streamManager->createStream(serverStream);
  EXPECT_TRUE(result.hasError());
  EXPECT_EQ(result.error().code, TransportErrorCode::STREAM_STATE_ERROR);
}

TEST_F(QuicServerStreamFunctionsTest, CreateInvalidClientStreamOnServer) {
  StreamId clientStream = 0x04;
  auto result = conn.streamManager->createStream(clientStream);
  EXPECT_TRUE(result.hasError());
  EXPECT_EQ(result.error().code, TransportErrorCode::STREAM_STATE_ERROR);
}

TEST_F(QuicStreamFunctionsTestBase, CreateAlreadyExistingStream) {
  StreamId stream = 0x08;
  conn.streamManager->createStream(stream).value();
  auto result = conn.streamManager->createStream(stream);
  EXPECT_TRUE(result.hasError());
  EXPECT_EQ(result.error().code, TransportErrorCode::STREAM_STATE_ERROR);
}

TEST_F(QuicStreamFunctionsTestBase, IsClientStream) {
  EXPECT_TRUE(isClientStream(0));
  EXPECT_TRUE(isClientStream(0x04));
  EXPECT_TRUE(isClientStream(104));
  EXPECT_TRUE(isClientStream(0x08));
  EXPECT_FALSE(isClientStream(0x01));
  EXPECT_FALSE(isClientStream(0x07));
  EXPECT_FALSE(isClientStream(0x11));
}

TEST_F(QuicStreamFunctionsTestBase, IsServerStream) {
  EXPECT_TRUE(isServerStream(0x05));
  EXPECT_TRUE(isServerStream(105));
  EXPECT_TRUE(isServerStream(0x25));
  EXPECT_FALSE(isServerStream(0x02));
  EXPECT_FALSE(isServerStream(0x04));
  EXPECT_FALSE(isServerStream(0));
}

TEST_F(QuicStreamFunctionsTestBase, IsUnidirectionalStream) {
  EXPECT_TRUE(isUnidirectionalStream(0x02));
  EXPECT_TRUE(isUnidirectionalStream(0x03));
  EXPECT_TRUE(isUnidirectionalStream(0xff));
  EXPECT_FALSE(isUnidirectionalStream(0x01));
  EXPECT_FALSE(isUnidirectionalStream(0xf0));
  EXPECT_FALSE(isUnidirectionalStream(0xf1));
}

TEST_F(QuicStreamFunctionsTestBase, IsBidirectionalStream) {
  EXPECT_TRUE(isBidirectionalStream(0x01));
  EXPECT_TRUE(isBidirectionalStream(0xf0));
  EXPECT_TRUE(isBidirectionalStream(0xf1));
  EXPECT_FALSE(isBidirectionalStream(0x02));
  EXPECT_FALSE(isBidirectionalStream(0x03));
  EXPECT_FALSE(isBidirectionalStream(0xff));
}

TEST_F(QuicStreamFunctionsTestBase, IsServerUnidirectionalStream) {
  EXPECT_TRUE(isServerUnidirectionalStream(0x03));
  EXPECT_TRUE(isServerUnidirectionalStream(0x07));
  EXPECT_TRUE(isServerUnidirectionalStream(0x0f));
  EXPECT_TRUE(isServerUnidirectionalStream(0xf3));
  EXPECT_TRUE(isServerUnidirectionalStream(0xff));
  EXPECT_FALSE(isServerUnidirectionalStream(0x01));
  EXPECT_FALSE(isServerUnidirectionalStream(0x02));
  EXPECT_FALSE(isServerUnidirectionalStream(0x0e));
  EXPECT_FALSE(isServerUnidirectionalStream(0xf1));
  EXPECT_FALSE(isServerUnidirectionalStream(0xfd));
}

TEST_F(QuicStreamFunctionsTestBase, IsClientBidirectionalStream) {
  EXPECT_TRUE(isClientBidirectionalStream(0x00));
  EXPECT_TRUE(isClientBidirectionalStream(0x04));
  EXPECT_TRUE(isClientBidirectionalStream(0x08));
  EXPECT_TRUE(isClientBidirectionalStream(0xf0));
  EXPECT_TRUE(isClientBidirectionalStream(0xfc));
  EXPECT_FALSE(isClientBidirectionalStream(0x01));
  EXPECT_FALSE(isClientBidirectionalStream(0x02));
  EXPECT_FALSE(isClientBidirectionalStream(0x03));
  EXPECT_FALSE(isClientBidirectionalStream(0xf1));
  EXPECT_FALSE(isClientBidirectionalStream(0xff));
}

TEST_F(QuicStreamFunctionsTestBase, GetStreamDirectionality) {
  EXPECT_EQ(StreamDirectionality::Bidirectional, getStreamDirectionality(0x01));
  EXPECT_EQ(StreamDirectionality::Bidirectional, getStreamDirectionality(0xf0));
  EXPECT_EQ(StreamDirectionality::Bidirectional, getStreamDirectionality(0xf1));
  EXPECT_EQ(
      StreamDirectionality::Unidirectional, getStreamDirectionality(0x02));
  EXPECT_EQ(
      StreamDirectionality::Unidirectional, getStreamDirectionality(0x03));
  EXPECT_EQ(
      StreamDirectionality::Unidirectional, getStreamDirectionality(0xff));
}

TEST_F(QuicStreamFunctionsTestBase, IsSendingStream) {
  QuicClientConnectionState clientState(
      FizzClientQuicHandshakeContext::Builder().build());
  QuicServerConnectionState serverState(
      FizzServerQuicHandshakeContext::Builder().build());
  QuicNodeType nodeType;
  StreamId id;

  QuicStreamState biClientStream(0, clientState);
  nodeType = biClientStream.conn.nodeType;
  id = biClientStream.id;
  EXPECT_FALSE(isSendingStream(nodeType, id));

  QuicStreamState biServerStream(0, serverState);
  nodeType = biServerStream.conn.nodeType;
  id = biServerStream.id;
  EXPECT_FALSE(isSendingStream(nodeType, id));

  QuicStreamState uniClientSendingStream(0x2, clientState);
  nodeType = uniClientSendingStream.conn.nodeType;
  id = uniClientSendingStream.id;
  EXPECT_TRUE(isSendingStream(nodeType, id));

  QuicStreamState uniServerSendingStream(0x3, serverState);
  nodeType = uniServerSendingStream.conn.nodeType;
  id = uniServerSendingStream.id;
  EXPECT_TRUE(isSendingStream(nodeType, id));
}

TEST_F(QuicStreamFunctionsTestBase, IsReceivingStream) {
  QuicClientConnectionState clientState(
      FizzClientQuicHandshakeContext::Builder().build());
  QuicServerConnectionState serverState(
      FizzServerQuicHandshakeContext::Builder().build());
  QuicNodeType nodeType;
  StreamId id;

  QuicStreamState biClientStream(0, clientState);
  nodeType = biClientStream.conn.nodeType;
  id = biClientStream.id;
  EXPECT_FALSE(isReceivingStream(nodeType, id));

  QuicStreamState biServerStream(0, serverState);
  nodeType = biServerStream.conn.nodeType;
  id = biServerStream.id;
  EXPECT_FALSE(isReceivingStream(nodeType, id));

  QuicStreamState uniClientReceivingStream(0x3, clientState);
  nodeType = uniClientReceivingStream.conn.nodeType;
  id = uniClientReceivingStream.id;
  EXPECT_TRUE(isReceivingStream(nodeType, id));

  QuicStreamState uniServerReceivingStream(0x2, serverState);
  nodeType = uniServerReceivingStream.conn.nodeType;
  id = uniServerReceivingStream.id;
  EXPECT_TRUE(isReceivingStream(nodeType, id));
}

TEST_F(QuicStreamFunctionsTestBase, GetStreamInitiatorBidirectional) {
  const auto clientStream1Id =
      conn.streamManager->createNextBidirectionalStream().value()->id;
  EXPECT_EQ(conn.streamManager->streamCount(), 1);
  const auto clientStream2Id =
      conn.streamManager->createNextBidirectionalStream().value()->id;
  EXPECT_EQ(conn.streamManager->streamCount(), 2);
  EXPECT_EQ(clientStream1Id, 0x00);
  EXPECT_EQ(clientStream2Id, 0x04);

  const auto serverStream1Id =
      CHECK_NOTNULL(
          conn.streamManager->getStream(clientStream1Id + 1).value_or(nullptr))
          ->id;
  const auto serverStream2Id =
      conn.streamManager->getStream(clientStream2Id + 1).value_or(nullptr)->id;

  EXPECT_EQ(
      StreamDirectionality::Bidirectional,
      getStreamDirectionality(clientStream1Id));
  EXPECT_EQ(
      StreamDirectionality::Bidirectional,
      getStreamDirectionality(clientStream2Id));
  EXPECT_EQ(
      StreamDirectionality::Bidirectional,
      getStreamDirectionality(serverStream1Id));
  EXPECT_EQ(
      StreamDirectionality::Bidirectional,
      getStreamDirectionality(serverStream2Id));

  EXPECT_EQ(
      StreamInitiator::Local,
      getStreamInitiator(conn.nodeType, clientStream1Id));
  EXPECT_EQ(
      StreamInitiator::Local,
      getStreamInitiator(conn.nodeType, clientStream2Id));
  EXPECT_EQ(
      StreamInitiator::Remote,
      getStreamInitiator(conn.nodeType, serverStream1Id));
  EXPECT_EQ(
      StreamInitiator::Remote,
      getStreamInitiator(conn.nodeType, serverStream2Id));
}

TEST_F(QuicServerStreamFunctionsTest, GetStreamInitiatorBidirectional) {
  const auto serverStream1Id =
      conn.streamManager->createNextBidirectionalStream().value()->id;
  EXPECT_EQ(conn.streamManager->streamCount(), 1);
  const auto serverStream2Id =
      conn.streamManager->createNextBidirectionalStream().value()->id;
  EXPECT_EQ(conn.streamManager->streamCount(), 2);
  EXPECT_EQ(serverStream1Id, 0x01);
  EXPECT_EQ(serverStream2Id, 0x05);

  const auto clientStream1Id =
      conn.streamManager->getStream(serverStream1Id - 1).value_or(nullptr)->id;
  const auto clientStream2Id =
      conn.streamManager->getStream(serverStream2Id - 1).value_or(nullptr)->id;

  EXPECT_EQ(
      StreamDirectionality::Bidirectional,
      getStreamDirectionality(serverStream1Id));
  EXPECT_EQ(
      StreamDirectionality::Bidirectional,
      getStreamDirectionality(serverStream2Id));
  EXPECT_EQ(
      StreamDirectionality::Bidirectional,
      getStreamDirectionality(clientStream1Id));
  EXPECT_EQ(
      StreamDirectionality::Bidirectional,
      getStreamDirectionality(clientStream2Id));

  EXPECT_EQ(
      StreamInitiator::Local,
      getStreamInitiator(conn.nodeType, serverStream1Id));
  EXPECT_EQ(
      StreamInitiator::Local,
      getStreamInitiator(conn.nodeType, serverStream2Id));
  EXPECT_EQ(
      StreamInitiator::Remote,
      getStreamInitiator(conn.nodeType, clientStream1Id));
  EXPECT_EQ(
      StreamInitiator::Remote,
      getStreamInitiator(conn.nodeType, clientStream2Id));
}

TEST_F(QuicStreamFunctionsTestBase, GetStreamInitiatorUnidirectional) {
  const auto clientStream1Id =
      conn.streamManager->createNextUnidirectionalStream().value()->id;
  EXPECT_EQ(conn.streamManager->streamCount(), 1);
  const auto clientStream2Id =
      conn.streamManager->createNextUnidirectionalStream().value()->id;
  EXPECT_EQ(conn.streamManager->streamCount(), 2);
  EXPECT_EQ(clientStream1Id, 0x02);
  EXPECT_EQ(clientStream2Id, 0x06);

  const auto serverStream1Id =
      conn.streamManager->getStream(clientStream1Id + 1).value_or(nullptr)->id;
  const auto serverStream2Id =
      conn.streamManager->getStream(clientStream2Id + 1).value_or(nullptr)->id;

  EXPECT_EQ(
      StreamDirectionality::Unidirectional,
      getStreamDirectionality(clientStream1Id));
  EXPECT_EQ(
      StreamDirectionality::Unidirectional,
      getStreamDirectionality(clientStream2Id));
  EXPECT_EQ(
      StreamDirectionality::Unidirectional,
      getStreamDirectionality(serverStream1Id));
  EXPECT_EQ(
      StreamDirectionality::Unidirectional,
      getStreamDirectionality(serverStream2Id));

  EXPECT_EQ(
      StreamInitiator::Local,
      getStreamInitiator(conn.nodeType, clientStream1Id));
  EXPECT_EQ(
      StreamInitiator::Local,
      getStreamInitiator(conn.nodeType, clientStream2Id));
  EXPECT_EQ(
      StreamInitiator::Remote,
      getStreamInitiator(conn.nodeType, serverStream1Id));
  EXPECT_EQ(
      StreamInitiator::Remote,
      getStreamInitiator(conn.nodeType, serverStream2Id));
}

TEST_F(QuicServerStreamFunctionsTest, GetStreamInitiatorUnidirectional) {
  const auto serverStream1Id =
      conn.streamManager->createNextUnidirectionalStream().value()->id;
  EXPECT_EQ(conn.streamManager->streamCount(), 1);
  const auto serverStream2Id =
      conn.streamManager->createNextUnidirectionalStream().value()->id;
  EXPECT_EQ(conn.streamManager->streamCount(), 2);
  EXPECT_EQ(serverStream1Id, 0x03);
  EXPECT_EQ(serverStream2Id, 0x07);

  const auto clientStream1Id =
      conn.streamManager->getStream(serverStream1Id - 1).value_or(nullptr)->id;
  const auto clientStream2Id =
      conn.streamManager->getStream(serverStream2Id - 1).value_or(nullptr)->id;

  EXPECT_EQ(
      StreamDirectionality::Unidirectional,
      getStreamDirectionality(serverStream1Id));
  EXPECT_EQ(
      StreamDirectionality::Unidirectional,
      getStreamDirectionality(serverStream2Id));
  EXPECT_EQ(
      StreamDirectionality::Unidirectional,
      getStreamDirectionality(clientStream1Id));
  EXPECT_EQ(
      StreamDirectionality::Unidirectional,
      getStreamDirectionality(clientStream2Id));

  EXPECT_EQ(
      StreamInitiator::Local,
      getStreamInitiator(conn.nodeType, serverStream1Id));
  EXPECT_EQ(
      StreamInitiator::Local,
      getStreamInitiator(conn.nodeType, serverStream2Id));
  EXPECT_EQ(
      StreamInitiator::Remote,
      getStreamInitiator(conn.nodeType, clientStream1Id));
  EXPECT_EQ(
      StreamInitiator::Remote,
      getStreamInitiator(conn.nodeType, clientStream2Id));
}

TEST_F(QuicStreamFunctionsTestBase, HasReadableDataNoData) {
  auto stream = conn.streamManager->createNextBidirectionalStream().value();
  auto buf1 = IOBuf::copyBuffer("just");
  auto buf2 = IOBuf::copyBuffer("I ");

  ASSERT_FALSE(appendDataToReadBuffer(*stream, StreamBuffer(buf1->clone(), 2))
                   .hasError());
  EXPECT_FALSE(stream->hasReadableData());
}

TEST_F(QuicStreamFunctionsTestBase, HasReadableDataNoDataInBuf) {
  auto stream = conn.streamManager->createNextBidirectionalStream().value();
  EXPECT_FALSE(stream->hasReadableData());
}

TEST_F(QuicStreamFunctionsTestBase, HasReadableDataEofInBuf) {
  auto stream = conn.streamManager->createNextBidirectionalStream().value();

  ASSERT_FALSE(appendDataToReadBuffer(*stream, StreamBuffer(nullptr, 1, true))
                   .hasError());
  EXPECT_FALSE(stream->hasReadableData());
  ASSERT_FALSE(
      appendDataToReadBuffer(*stream, StreamBuffer(IOBuf::copyBuffer("1"), 0))
          .hasError());
  EXPECT_TRUE(stream->hasReadableData());
  auto read1 = readDataFromQuicStream(*stream, 1);
  EXPECT_TRUE(read1->second);
  EXPECT_FALSE(stream->hasReadableData());
  auto read2 = readDataFromQuicStream(*stream, 1);
  EXPECT_TRUE(read2->second);
}

TEST_F(QuicStreamFunctionsTestBase, HasReadableDataEofInEmptyBuf) {
  auto stream = conn.streamManager->createNextBidirectionalStream().value();

  ASSERT_FALSE(appendDataToReadBuffer(*stream, StreamBuffer(nullptr, 0, true))
                   .hasError());
  EXPECT_TRUE(stream->hasReadableData());
  auto read1 = readDataFromQuicStream(*stream, 1);
  EXPECT_TRUE(read1->second);
  EXPECT_FALSE(stream->hasReadableData());
  auto read2 = readDataFromQuicStream(*stream, 1);
  EXPECT_TRUE(read2->second);
}

TEST_F(QuicStreamFunctionsTestBase, HasReadableDataOnlyEof) {
  auto stream = conn.streamManager->createNextBidirectionalStream().value();
  ASSERT_FALSE(appendDataToReadBuffer(*stream, StreamBuffer(nullptr, 0, true))
                   .hasError());
  EXPECT_TRUE(stream->hasReadableData());
}

TEST_F(QuicStreamFunctionsTestBase, HasReadableData) {
  auto stream = conn.streamManager->createNextBidirectionalStream().value();
  auto buf1 = IOBuf::copyBuffer("I ");
  auto buf2 = IOBuf::copyBuffer("met");
  ASSERT_FALSE(appendDataToReadBuffer(*stream, StreamBuffer(buf1->clone(), 0))
                   .hasError());
  ASSERT_FALSE(appendDataToReadBuffer(*stream, StreamBuffer(buf2->clone(), 7))
                   .hasError());
  EXPECT_TRUE(stream->hasReadableData());

  (void)readDataFromQuicStream(*stream);
  EXPECT_FALSE(stream->hasReadableData());

  auto buf3 = IOBuf::copyBuffer("just ");
  ASSERT_FALSE(appendDataToReadBuffer(*stream, StreamBuffer(buf3->clone(), 2))
                   .hasError());
  EXPECT_TRUE(stream->hasReadableData());
  (void)readDataFromQuicStream(*stream, 5);
  EXPECT_TRUE(stream->hasReadableData());
  (void)readDataFromQuicStream(*stream);
  EXPECT_FALSE(stream->hasReadableData());
}

TEST_F(QuicStreamFunctionsTestBase, HasPeekableDataGappedData) {
  auto stream = conn.streamManager->createNextBidirectionalStream().value();
  auto buf1 = IOBuf::copyBuffer("just");
  auto buf2 = IOBuf::copyBuffer("I ");

  ASSERT_FALSE(appendDataToReadBuffer(*stream, StreamBuffer(buf1->clone(), 2))
                   .hasError());
  EXPECT_TRUE(stream->hasPeekableData());
}

TEST_F(QuicStreamFunctionsTestBase, HasPeekableDataNoDataInBuf) {
  auto stream = conn.streamManager->createNextBidirectionalStream().value();
  EXPECT_FALSE(stream->hasPeekableData());
}

TEST_F(QuicStreamFunctionsTestBase, HasPeekableDataEofInBuf) {
  auto stream = conn.streamManager->createNextBidirectionalStream().value();

  ASSERT_FALSE(appendDataToReadBuffer(*stream, StreamBuffer(nullptr, 1, true))
                   .hasError());
  EXPECT_FALSE(stream->hasPeekableData());
  ASSERT_FALSE(
      appendDataToReadBuffer(*stream, StreamBuffer(IOBuf::copyBuffer("1"), 0))
          .hasError());
  EXPECT_TRUE(stream->hasPeekableData());
  auto read1 = readDataFromQuicStream(*stream, 1);
  EXPECT_TRUE(read1->second);
  EXPECT_FALSE(stream->hasPeekableData());
  auto read2 = readDataFromQuicStream(*stream, 1);
  EXPECT_TRUE(read2->second);
}

TEST_F(QuicStreamFunctionsTestBase, HasPeekableDataEofInEmptyBuf) {
  auto stream = conn.streamManager->createNextBidirectionalStream().value();

  ASSERT_FALSE(appendDataToReadBuffer(*stream, StreamBuffer(nullptr, 0, true))
                   .hasError());
  EXPECT_FALSE(stream->hasPeekableData());
  auto read1 = readDataFromQuicStream(*stream, 1);
  EXPECT_TRUE(read1->second);
  EXPECT_FALSE(stream->hasPeekableData());
  auto read2 = readDataFromQuicStream(*stream, 1);
  EXPECT_TRUE(read2->second);
}

TEST_F(QuicStreamFunctionsTestBase, HasPeekableDataOnlyEof) {
  auto stream = conn.streamManager->createNextBidirectionalStream().value();
  ASSERT_FALSE(appendDataToReadBuffer(*stream, StreamBuffer(nullptr, 0, true))
                   .hasError());
  EXPECT_FALSE(stream->hasPeekableData());
}

TEST_F(QuicStreamFunctionsTestBase, HasPeekableData) {
  auto stream = conn.streamManager->createNextBidirectionalStream().value();
  auto buf1 = IOBuf::copyBuffer("I ");
  auto buf2 = IOBuf::copyBuffer("met");
  ASSERT_FALSE(appendDataToReadBuffer(*stream, StreamBuffer(buf1->clone(), 0))
                   .hasError());
  ASSERT_FALSE(appendDataToReadBuffer(*stream, StreamBuffer(buf2->clone(), 7))
                   .hasError());
  EXPECT_TRUE(stream->hasPeekableData());

  (void)readDataFromQuicStream(*stream);
  EXPECT_TRUE(stream->hasPeekableData());

  auto buf3 = IOBuf::copyBuffer("just ");
  ASSERT_FALSE(appendDataToReadBuffer(*stream, StreamBuffer(buf3->clone(), 2))
                   .hasError());
  EXPECT_TRUE(stream->hasPeekableData());
  (void)readDataFromQuicStream(*stream, 5);
  EXPECT_TRUE(stream->hasPeekableData());
  (void)readDataFromQuicStream(*stream);
  EXPECT_FALSE(stream->hasPeekableData());
}

TEST_F(QuicStreamFunctionsTestBase, UpdatesLastHolbTime) {
  auto stream = conn.streamManager->createNextBidirectionalStream().value();
  auto buf1 = IOBuf::copyBuffer("just");
  auto buf2 = IOBuf::copyBuffer("I ");

  ASSERT_FALSE(appendDataToReadBuffer(*stream, StreamBuffer(buf1->clone(), 2))
                   .hasError());
  // Should not be HOL blocked before data has arrived
  EXPECT_FALSE(stream->lastHolbTime);
  (void)readDataFromQuicStream(*stream);
  // Should be HOL blocked
  EXPECT_TRUE(stream->lastHolbTime);
}

TEST_F(
    QuicStreamFunctionsTestBase,
    HolbTimingUpdateReadingListIdempotentWrtHolb) {
  // test that calling uRL in succession (without new data or readsd)
  // does not affect the HOLB state
  auto stream = conn.streamManager->createNextBidirectionalStream().value();
  auto buf1 = IOBuf::copyBuffer("just");
  auto buf2 = IOBuf::copyBuffer("I ");
  auto buf3 = IOBuf::copyBuffer("you");
  auto buf4 = IOBuf::copyBuffer(" met ");

  ASSERT_FALSE(appendDataToReadBuffer(*stream, StreamBuffer(buf1->clone(), 2))
                   .hasError());
  // Should not be HOL blocked until the readable list has been updated
  EXPECT_FALSE(stream->lastHolbTime);

  // uRL 0.0 - expected state transition:
  //   !HOLB => HOLB in progress
  conn.streamManager->updateReadableStreams(*stream);
  // HOLB state must be detected after the first readable list update
  auto lastHolbTimeMark = stream->lastHolbTime;
  EXPECT_TRUE(lastHolbTimeMark);
  // No total holb time should be recorded
  EXPECT_EQ(0us, stream->totalHolbTime);
  EXPECT_EQ(1, stream->holbCount);

  // uRL 0.1 - expected state transition: std::nullopt
  conn.streamManager->updateReadableStreams(*stream);

  EXPECT_EQ(lastHolbTimeMark, stream->lastHolbTime);
  EXPECT_EQ(0us, stream->totalHolbTime);
  EXPECT_EQ(1, stream->holbCount);

  ASSERT_FALSE(appendDataToReadBuffer(*stream, StreamBuffer(buf2->clone(), 0))
                   .hasError());

  // uRL 1.0 - expected state transition:
  //   HOLB in progress -> !HOLB && holbCount == 1
  conn.streamManager->updateReadableStreams(*stream);
  auto totalHolbTimeMark = stream->totalHolbTime;

  // HOLB state must be cleared by buf2, and total time should be available
  EXPECT_FALSE(stream->lastHolbTime);
  EXPECT_EQ(1, stream->holbCount);

  // uRL 1.1 - expected state transition: std::nullopt
  conn.streamManager->updateReadableStreams(*stream);
  EXPECT_FALSE(stream->lastHolbTime);
  EXPECT_EQ(totalHolbTimeMark, stream->totalHolbTime);

  ASSERT_FALSE(appendDataToReadBuffer(*stream, StreamBuffer(buf3->clone(), 11))
                   .hasError());

  // uRL 2.0 - expected state transition:
  // !HOLB && holbCount == 1
  //   => !HOLB && totalTime == totalTimeMark
  // NOTE: the stream is not HOLB since the reading cursor is not
  // at the hole
  conn.streamManager->updateReadableStreams(*stream);
  EXPECT_FALSE(stream->lastHolbTime);
  EXPECT_EQ(totalHolbTimeMark, stream->totalHolbTime);
  EXPECT_EQ(1, stream->holbCount);

  // uRL 2.1 - expected state transition: std::nullopt
  conn.streamManager->updateReadableStreams(*stream);
  EXPECT_FALSE(stream->lastHolbTime);
  EXPECT_EQ(totalHolbTimeMark, stream->totalHolbTime);

  // uRL 3.0 - expected state transition:
  // !HOLB && totalTime == totalTimeMark
  //   => HOLB && holbCount == 2
  //       && totalHolbTime == totalTimeMark
  (void)readDataFromQuicStream(*stream);
  EXPECT_TRUE(stream->lastHolbTime);
  EXPECT_EQ(2, stream->holbCount);
  EXPECT_EQ(totalHolbTimeMark, stream->totalHolbTime);
  auto lastHolbTimeMark2 = stream->lastHolbTime;

  // uRL 3.1 - expected state transition: std::nullopt
  conn.streamManager->updateReadableStreams(*stream);
  EXPECT_EQ(lastHolbTimeMark2, stream->lastHolbTime);
  EXPECT_EQ(totalHolbTimeMark, stream->totalHolbTime);
  EXPECT_EQ(2, stream->holbCount);

  // uRL 4.0 - add the rest of the data to the stream.
  // HOLB && holbCount == 2
  //     && totalTime == totalTimeMark
  // => !HOLB && holbCount == 2
  ASSERT_FALSE(appendDataToReadBuffer(*stream, StreamBuffer(buf4->clone(), 6))
                   .hasError());
  conn.streamManager->updateReadableStreams(*stream);
  EXPECT_FALSE(stream->lastHolbTime);
  EXPECT_EQ(2, stream->holbCount);

  // uRL 4.1 - read the entire stream - expected state transition:
  // !HOLB && holbCount == 2
  // => !HOLB && holbCount == 2
  (void)readDataFromQuicStream(*stream);
  EXPECT_FALSE(stream->lastHolbTime);
  EXPECT_EQ(2, stream->holbCount);

  // uRL 4.1 - expected state change: std::nullopt
  conn.streamManager->updateReadableStreams(*stream);
  EXPECT_FALSE(stream->lastHolbTime);
  EXPECT_EQ(2, stream->holbCount);
}

TEST_F(QuicStreamFunctionsTestBase, HolbTimingFirstBufferHOLBlocked) {
  auto stream = conn.streamManager->createNextBidirectionalStream().value();
  auto buf1 = IOBuf::copyBuffer("just");
  auto buf2 = IOBuf::copyBuffer("I ");

  ASSERT_FALSE(appendDataToReadBuffer(*stream, StreamBuffer(buf1->clone(), 2))
                   .hasError());
  // Should not be HOL blocked until the readable list has been updated
  EXPECT_FALSE(stream->lastHolbTime);

  conn.streamManager->updateReadableStreams(*stream);
  // HOLB state must be detected after the first readable list update
  EXPECT_TRUE(stream->lastHolbTime);
  EXPECT_EQ(1, stream->holbCount);
  EXPECT_EQ(0us, stream->totalHolbTime);
  auto lastHolbTimeMark = stream->lastHolbTime;

  (void)readDataFromQuicStream(*stream);
  // Read data should fail since there is no data available at
  // the reading cursor
  EXPECT_EQ(lastHolbTimeMark, stream->lastHolbTime);
  EXPECT_TRUE(stream->lastHolbTime);
  EXPECT_EQ(1, stream->holbCount);

  ASSERT_FALSE(appendDataToReadBuffer(*stream, StreamBuffer(buf2->clone(), 0))
                   .hasError());
  conn.streamManager->updateReadableStreams(*stream);
  // HOLB state must be cleared by buf2, and total time should be available

  EXPECT_FALSE(stream->lastHolbTime);
  EXPECT_EQ(1, stream->holbCount);
}

TEST_F(QuicStreamFunctionsTestBase, HolbTimingReadingEntireStream) {
  auto stream = conn.streamManager->createNextBidirectionalStream().value();
  auto buf1 = IOBuf::copyBuffer("just");
  auto buf2 = IOBuf::copyBuffer("I ");

  ASSERT_FALSE(appendDataToReadBuffer(*stream, StreamBuffer(buf1->clone(), 2))
                   .hasError());
  conn.streamManager->updateReadableStreams(*stream);
  EXPECT_TRUE(stream->lastHolbTime);
  EXPECT_EQ(1, stream->holbCount);

  ASSERT_FALSE(appendDataToReadBuffer(*stream, StreamBuffer(buf2->clone(), 0))
                   .hasError());
  conn.streamManager->updateReadableStreams(*stream);
  // HOLB state must be cleared by buf2, and total time should be available
  EXPECT_FALSE(stream->lastHolbTime);
  EXPECT_EQ(1, stream->holbCount);

  // Consume the entire stream. This should not change the holb status
  (void)readDataFromQuicStream(*stream);
  EXPECT_FALSE(stream->lastHolbTime);
  EXPECT_EQ(1, stream->holbCount);
}

TEST_F(QuicStreamFunctionsTestBase, HolbTimingLockstepScenario) {
  auto stream = conn.streamManager->createNextBidirectionalStream().value();
  auto buf1 = IOBuf::copyBuffer("just");
  auto buf2 = IOBuf::copyBuffer("I ");
  auto buf3 = IOBuf::copyBuffer("met you ");
  auto buf4 = IOBuf::copyBuffer("and this is crazy");

  ASSERT_FALSE(appendDataToReadBuffer(*stream, StreamBuffer(buf1->clone(), 2))
                   .hasError());
  // Should not be HOL blocked before data has arrived
  EXPECT_FALSE(stream->lastHolbTime);

  (void)readDataFromQuicStream(*stream);
  // Should be HOL blocked now
  EXPECT_TRUE(stream->lastHolbTime);
  EXPECT_EQ(1, stream->holbCount);

  // At this point, the stream has not been unblocked even once,
  // hence the total holb time is expected to be zero
  EXPECT_EQ(0us, stream->totalHolbTime);

  // Data has arrived
  ASSERT_FALSE(appendDataToReadBuffer(*stream, StreamBuffer(buf2->clone(), 0))
                   .hasError());
  ASSERT_FALSE(appendDataToReadBuffer(*stream, StreamBuffer(buf4->clone(), 15))
                   .hasError());

  // Update readable list has not been called yet, hence
  // the total holb time has not been set yet
  EXPECT_TRUE(stream->lastHolbTime);
  EXPECT_EQ(1, stream->holbCount);

  // Update readable list
  conn.streamManager->updateReadableStreams(*stream);

  // The new data should have unblocked the HOLB
  EXPECT_FALSE(stream->lastHolbTime);
  EXPECT_EQ(1, stream->holbCount);
  auto snapshotHolbTime = stream->totalHolbTime;

  // Consume all available data from the stream
  (void)readDataFromQuicStream(*stream);

  // Should be HOL blocked at missing buf3.
  EXPECT_TRUE(stream->lastHolbTime);
  EXPECT_EQ(2, stream->holbCount);
  // The total HOLB time shouldn't have changed since the last update
  EXPECT_EQ(snapshotHolbTime, stream->totalHolbTime);

  ASSERT_FALSE(appendDataToReadBuffer(*stream, StreamBuffer(buf3->clone(), 6))
                   .hasError());
  conn.streamManager->updateReadableStreams(*stream);

  // Should be not HOLB
  EXPECT_FALSE(stream->lastHolbTime);
  EXPECT_EQ(2, stream->holbCount);
}

TEST_F(QuicStreamFunctionsTestBase, HolbTimingReadDataCallsUpdateRL) {
  auto stream = conn.streamManager->createNextBidirectionalStream().value();
  auto buf1 = IOBuf::copyBuffer("just");
  auto buf2 = IOBuf::copyBuffer("I ");

  ASSERT_FALSE(appendDataToReadBuffer(*stream, StreamBuffer(buf1->clone(), 2))
                   .hasError());
  (void)readDataFromQuicStream(*stream);
  // Should be HOL blocked
  EXPECT_TRUE(stream->lastHolbTime);
  EXPECT_EQ(1, stream->holbCount);

  ASSERT_FALSE(appendDataToReadBuffer(*stream, StreamBuffer(buf2->clone(), 0))
                   .hasError());
  (void)readDataFromQuicStream(*stream);
  EXPECT_FALSE(stream->lastHolbTime);
  EXPECT_EQ(1, stream->holbCount);
}

TEST_F(QuicStreamFunctionsTestBase, RemovedClosedState) {
  auto stream = conn.streamManager->createNextBidirectionalStream().value();
  auto streamId = stream->id;
  conn.streamManager->readableStreams().emplace(streamId);
  conn.streamManager->peekableStreams().emplace(streamId);
  ASSERT_FALSE(writeDataToQuicStream(
                   *stream, folly::IOBuf::copyBuffer("write data"), true)
                   .hasError());
  conn.streamManager->updateWritableStreams(*stream);
  conn.streamManager->queueBlocked(streamId, 0);
  conn.streamManager->addDeliverable(streamId);
  conn.streamManager->addLoss(streamId);
  conn.streamManager->queueWindowUpdate(streamId);
  conn.streamManager->addStopSending(
      streamId, GenericApplicationErrorCode::UNKNOWN);
  conn.streamManager->queueFlowControlUpdated(streamId);
  stream->sendState = StreamSendState::Closed;
  stream->recvState = StreamRecvState::Closed;
  ASSERT_FALSE(conn.streamManager->removeClosedStream(streamId).hasError());
  EXPECT_FALSE(conn.streamManager->streamExists(streamId));
  EXPECT_TRUE(conn.streamManager->readableStreams().empty());
  EXPECT_TRUE(conn.streamManager->peekableStreams().empty());
  EXPECT_FALSE(writableContains(*conn.streamManager, streamId));
  EXPECT_FALSE(conn.streamManager->hasBlocked());
  EXPECT_FALSE(conn.streamManager->deliverableContains(streamId));
  EXPECT_FALSE(conn.streamManager->hasLoss());
  EXPECT_FALSE(conn.streamManager->pendingWindowUpdate(streamId));
  EXPECT_TRUE(conn.streamManager->stopSendingStreams().empty());
  EXPECT_FALSE(conn.streamManager->flowControlUpdatedContains(streamId));
}

TEST_F(QuicServerStreamFunctionsTest, ServerGetClientQuicStream) {
  StreamId clientStream = 0x10;
  std::vector<StreamId> newStreams = {0x0, 0x4, 0x8, 0xc, 0x10};
  auto streamResult = conn.streamManager->getStream(clientStream);
  ASSERT_FALSE(streamResult.hasError());
  EXPECT_EQ(streamResult.value()->id, clientStream);
  EXPECT_EQ(conn.streamManager->streamCount(), 1);
  EXPECT_EQ(conn.streamManager->openBidirectionalPeerStreams().size(), 5);
  EXPECT_EQ(conn.streamManager->newPeerStreams(), newStreams);

  StreamId clientStream2 = 0x4;
  auto streamResult2 = conn.streamManager->getStream(clientStream2);
  ASSERT_FALSE(streamResult2.hasError());
  EXPECT_EQ(streamResult2.value()->id, clientStream2);
  EXPECT_EQ(conn.streamManager->streamCount(), 2);
  EXPECT_EQ(conn.streamManager->openBidirectionalPeerStreams().size(), 5);
  EXPECT_EQ(conn.streamManager->newPeerStreams().size(), 5);
  EXPECT_EQ(conn.streamManager->newPeerStreams(), newStreams);

  StreamId clientStream3 = 0x6;
  newStreams = {0x0, 0x2, 0x4, 0x6, 0x8, 0xc, 0x10};
  auto streamResult3 = conn.streamManager->getStream(clientStream3);
  ASSERT_FALSE(streamResult3.hasError());
  EXPECT_EQ(streamResult3.value()->id, clientStream3);
  EXPECT_EQ(conn.streamManager->streamCount(), 3);
  EXPECT_EQ(conn.streamManager->openUnidirectionalPeerStreams().size(), 2);
  std::sort(
      conn.streamManager->newPeerStreams().begin(),
      conn.streamManager->newPeerStreams().end());
  EXPECT_EQ(conn.streamManager->newPeerStreams(), newStreams);
}

TEST_F(QuicServerStreamFunctionsTest, ServerGetServerQuicStream) {
  StreamId serverStream = 0x09;
  conn.streamManager->createStream(serverStream).value();
  auto streamResult = conn.streamManager->getStream(serverStream);
  ASSERT_FALSE(streamResult.hasError());
  EXPECT_EQ(streamResult.value()->id, serverStream);
  EXPECT_EQ(conn.streamManager->streamCount(), 1);
  EXPECT_EQ(
      conn.streamManager->openUnidirectionalLocalStreams().size() +
          conn.streamManager->openBidirectionalLocalStreams().size(),
      3);

  StreamId serverStream2 = 0x05;
  auto streamResult2 = conn.streamManager->getStream(serverStream2);
  ASSERT_FALSE(streamResult2.hasError());
  EXPECT_EQ(streamResult2.value()->id, serverStream2);
  EXPECT_EQ(conn.streamManager->streamCount(), 2);
  EXPECT_EQ(
      conn.streamManager->openUnidirectionalLocalStreams().size() +
          conn.streamManager->openBidirectionalLocalStreams().size(),
      3);

  StreamId serverStream3 = 0x0D;
  auto streamResult3 = conn.streamManager->getStream(serverStream3);
  EXPECT_TRUE(streamResult3.hasError());
  EXPECT_EQ(streamResult3.error().code, TransportErrorCode::STREAM_STATE_ERROR);
}

TEST_F(QuicServerStreamFunctionsTest, ServerGetBothDirections) {
  StreamId serverBiStream = 0x09;
  conn.streamManager->createStream(serverBiStream).value();
  auto streamResult = conn.streamManager->getStream(serverBiStream);
  ASSERT_FALSE(streamResult.hasError());
  EXPECT_EQ(streamResult.value()->id, serverBiStream);
  EXPECT_EQ(conn.streamManager->streamCount(), 1);
  EXPECT_EQ(
      conn.streamManager->openUnidirectionalLocalStreams().size() +
          conn.streamManager->openBidirectionalLocalStreams().size(),
      3);

  StreamId serverUniStream = 0x0B;
  conn.streamManager->createStream(serverUniStream).value();
  auto streamResult2 = conn.streamManager->getStream(serverUniStream);
  ASSERT_FALSE(streamResult2.hasError());
  EXPECT_EQ(streamResult2.value()->id, serverUniStream);
  EXPECT_EQ(conn.streamManager->streamCount(), 2);
  EXPECT_EQ(
      conn.streamManager->openUnidirectionalLocalStreams().size() +
          conn.streamManager->openBidirectionalLocalStreams().size(),
      6);
}

TEST_F(QuicServerStreamFunctionsTest, ServerGetCloseBothDirections) {
  StreamId serverBiStream = 0x09;
  ASSERT_FALSE(conn.streamManager->createStream(serverBiStream).hasError());
  auto streamResult = conn.streamManager->getStream(serverBiStream);
  ASSERT_FALSE(streamResult.hasError());
  EXPECT_EQ(streamResult.value()->id, serverBiStream);
  StreamId serverUniStream = 0x0B;
  auto stream = conn.streamManager->createStream(serverUniStream).value();
  stream->sendState = StreamSendState::Closed;

  ASSERT_FALSE(
      conn.streamManager->removeClosedStream(serverUniStream).hasError());
  auto streamResult2 =
      conn.streamManager->getStream(serverUniStream - kStreamIncrement);
  ASSERT_FALSE(streamResult2.hasError());
  EXPECT_EQ(conn.streamManager->streamCount(), 2);

  EXPECT_FALSE(conn.streamManager->streamExists(serverUniStream));
  EXPECT_TRUE(conn.streamManager->streamExists(serverBiStream));
  EXPECT_TRUE(
      conn.streamManager->streamExists(serverUniStream - kStreamIncrement));
  EXPECT_TRUE(
      conn.streamManager->streamExists(serverBiStream - kStreamIncrement));
  EXPECT_FALSE(
      conn.streamManager->streamExists(serverUniStream + kStreamIncrement));
  EXPECT_FALSE(
      conn.streamManager->streamExists(serverBiStream + kStreamIncrement));
}

TEST_F(QuicServerStreamFunctionsTest, ServerGetServerUnidirectionalQuicStream) {
  StreamId serverStream = 0x0F;
  ASSERT_FALSE(conn.streamManager->createStream(serverStream).hasError());
  auto streamResult = conn.streamManager->getStream(serverStream);
  ASSERT_FALSE(streamResult.hasError());
  EXPECT_EQ(streamResult.value()->id, serverStream);
  EXPECT_EQ(conn.streamManager->streamCount(), 1);
  EXPECT_EQ(
      conn.streamManager->openUnidirectionalLocalStreams().size() +
          conn.streamManager->openBidirectionalLocalStreams().size(),
      4);

  StreamId serverStream2 = 0x0B;
  auto streamResult2 = conn.streamManager->getStream(serverStream2);
  ASSERT_FALSE(streamResult2.hasError());
  EXPECT_EQ(streamResult2.value()->id, serverStream2);
  EXPECT_EQ(conn.streamManager->streamCount(), 2);
  EXPECT_EQ(
      conn.streamManager->openUnidirectionalLocalStreams().size() +
          conn.streamManager->openBidirectionalLocalStreams().size(),
      4);

  StreamId serverStream3 = 0x1F;
  auto streamResult3 = conn.streamManager->getStream(serverStream3);
  ASSERT_TRUE(streamResult3.hasError());
  EXPECT_NE(streamResult3.error().code.asTransportErrorCode(), nullptr);
}

TEST_F(QuicStreamFunctionsTestBase, ClientGetServerQuicStream) {
  StreamId serverStream = 0x09;
  auto streamResult = conn.streamManager->getStream(serverStream);
  ASSERT_FALSE(streamResult.hasError());
  EXPECT_EQ(streamResult.value()->id, serverStream);
  EXPECT_EQ(conn.streamManager->streamCount(), 1);
  EXPECT_EQ(conn.streamManager->openBidirectionalPeerStreams().size(), 3);

  StreamId serverStream2 = 0x05;
  auto streamResult2 = conn.streamManager->getStream(serverStream2);
  ASSERT_FALSE(streamResult2.hasError());
  EXPECT_EQ(streamResult2.value()->id, serverStream2);
  EXPECT_EQ(conn.streamManager->streamCount(), 2);
  EXPECT_EQ(conn.streamManager->openBidirectionalPeerStreams().size(), 3);
}

TEST_F(QuicStreamFunctionsTestBase, ClientGetClientQuicStream) {
  StreamId clientStream = 0x0C;
  ASSERT_FALSE(conn.streamManager->createStream(clientStream).hasError());
  auto streamResult = conn.streamManager->getStream(clientStream);
  ASSERT_FALSE(streamResult.hasError());
  EXPECT_EQ(streamResult.value()->id, clientStream);
  EXPECT_EQ(conn.streamManager->streamCount(), 1);
  EXPECT_EQ(
      conn.streamManager->openUnidirectionalLocalStreams().size() +
          conn.streamManager->openBidirectionalLocalStreams().size(),
      4);

  StreamId clientStream2 = 0x08;
  auto streamResult2 = conn.streamManager->getStream(clientStream2);
  ASSERT_FALSE(streamResult2.hasError());
  EXPECT_EQ(streamResult2.value()->id, clientStream2);
  EXPECT_EQ(conn.streamManager->streamCount(), 2);
  EXPECT_EQ(
      conn.streamManager->openUnidirectionalLocalStreams().size() +
          conn.streamManager->openBidirectionalLocalStreams().size(),
      4);

  StreamId clientStream3 = 0x10;
  auto streamResult3 = conn.streamManager->getStream(clientStream3);
  ASSERT_TRUE(streamResult3.hasError());
  EXPECT_NE(streamResult3.error().code.asTransportErrorCode(), nullptr);
}

TEST_F(QuicStreamFunctionsTestBase, StreamExists) {
  StreamId localStream = 12;
  StreamId peerStream = 13;

  StreamId localAutoOpened = 8;
  StreamId peerAutoOpened = 5;
  StreamId peerAutoOpened2 = 9;
  StreamId notOpenedLocal = 16;
  StreamId notOpenedPeer = 17;

  ASSERT_FALSE(conn.streamManager->createStream(localStream).hasError());
  EXPECT_TRUE(conn.streamManager->streamExists(localStream));
  EXPECT_TRUE(conn.streamManager->streamExists(localAutoOpened));
  EXPECT_FALSE(conn.streamManager->streamExists(notOpenedLocal));
  EXPECT_FALSE(conn.streamManager->streamExists(notOpenedPeer));
  EXPECT_FALSE(conn.streamManager->streamExists(peerStream));
  EXPECT_FALSE(conn.streamManager->streamExists(peerAutoOpened));

  auto streamResult = conn.streamManager->getStream(peerStream);
  ASSERT_FALSE(streamResult.hasError());
  streamResult.value()->sendState = StreamSendState::Closed;
  streamResult.value()->recvState = StreamRecvState::Closed;
  EXPECT_TRUE(conn.streamManager->streamExists(localStream));
  EXPECT_TRUE(conn.streamManager->streamExists(localAutoOpened));
  EXPECT_FALSE(conn.streamManager->streamExists(notOpenedLocal));
  EXPECT_FALSE(conn.streamManager->streamExists(notOpenedPeer));
  EXPECT_TRUE(conn.streamManager->streamExists(peerStream));
  EXPECT_TRUE(conn.streamManager->streamExists(peerAutoOpened));

  conn.streamManager->openBidirectionalPeerStreams().remove(peerAutoOpened);

  ASSERT_FALSE(conn.streamManager->removeClosedStream(peerStream).hasError());

  EXPECT_FALSE(conn.streamManager->streamExists(peerAutoOpened));
  EXPECT_FALSE(conn.streamManager->streamExists(peerStream));
  EXPECT_TRUE(conn.streamManager->streamExists(peerAutoOpened2));
}

TEST_F(QuicStreamFunctionsTestBase, StreamLimitUpdates) {
  StreamId peerStream = 13;
  StreamId peerAutoOpened = 5;
  StreamId peerAutoOpened2 = 9;
  StreamId notOpenedPeer = 17;

  conn.streamManager->setStreamLimitWindowingFraction(
      conn.transportSettings.advertisedInitialMaxStreamsBidi);
  auto streamResult = conn.streamManager->getStream(peerStream);
  ASSERT_FALSE(streamResult.hasError());
  streamResult.value()->sendState = StreamSendState::Closed;
  streamResult.value()->recvState = StreamRecvState::Closed;
  EXPECT_FALSE(conn.streamManager->streamExists(notOpenedPeer));
  EXPECT_TRUE(conn.streamManager->streamExists(peerStream));
  EXPECT_TRUE(conn.streamManager->streamExists(peerAutoOpened));

  ASSERT_FALSE(conn.streamManager->removeClosedStream(peerStream).hasError());

  EXPECT_FALSE(conn.streamManager->streamExists(peerStream));
  EXPECT_TRUE(conn.streamManager->streamExists(peerAutoOpened));
  EXPECT_TRUE(conn.streamManager->streamExists(peerAutoOpened2));
  auto update = conn.streamManager->remoteBidirectionalStreamLimitUpdate();
  ASSERT_TRUE(update);
  EXPECT_EQ(
      update.value(),
      conn.transportSettings.advertisedInitialMaxStreamsBidi + 1);
}

TEST_F(QuicStreamFunctionsTestBase, AllBytesTillFinAcked) {
  StreamId id = 3;
  QuicStreamState stream(id, conn);
  stream.finalWriteOffset = 1;
  stream.currentWriteOffset = 2;
  EXPECT_TRUE(allBytesTillFinAcked(stream));
}

TEST_F(QuicStreamFunctionsTestBase, AllBytesTillFinAckedFinOnly) {
  StreamId id = 3;
  QuicStreamState stream(id, conn);
  stream.finalWriteOffset = 0;
  stream.currentWriteOffset = 1;
  EXPECT_TRUE(allBytesTillFinAcked(stream));
}

TEST_F(QuicStreamFunctionsTestBase, AllBytesTillFinAckedNewStream) {
  StreamId id = 3;
  QuicStreamState stream(id, conn);
  EXPECT_FALSE(allBytesTillFinAcked(stream));
}

TEST_F(QuicStreamFunctionsTestBase, AllBytesTillFinAckedStillLost) {
  StreamId id = 3;
  QuicStreamState stream(id, conn);
  stream.finalWriteOffset = 20;
  stream.currentWriteOffset = 21;
  auto dataBuf = IOBuf::create(10);
  stream.lossBuffer.emplace_back(ChainedByteRangeHead(dataBuf), 10, false);
  EXPECT_FALSE(allBytesTillFinAcked(stream));
}

TEST_F(QuicStreamFunctionsTestBase, AllBytesTillFinAckedStillRetransmitting) {
  StreamId id = 3;
  QuicStreamState stream(id, conn);
  stream.finalWriteOffset = 12;

  auto retxBufData = IOBuf::create(10);
  stream.retransmissionBuffer.emplace(
      0,
      std::make_unique<WriteStreamBuffer>(
          ChainedByteRangeHead(retxBufData), 10, false));
  EXPECT_FALSE(allBytesTillFinAcked(stream));
}

TEST_F(QuicStreamFunctionsTestBase, AllBytesTillFinAckedStillWriting) {
  StreamId id = 3;
  QuicStreamState stream(id, conn);
  stream.finalWriteOffset = 10;
  auto buf = IOBuf::create(10);
  buf->append(10);
  stream.writeBuffer.append(std::move(buf));
  EXPECT_FALSE(allBytesTillFinAcked(stream));
}

TEST_F(QuicServerStreamFunctionsTest, TestAppendPendingStreamResetAllData) {
  StreamId id = 3;
  QuicStreamState stream(id, conn);
  auto data = IOBuf::copyBuffer("this is data");
  auto len = data->computeChainDataLength();
  ASSERT_FALSE(writeDataToQuicStream(stream, std::move(data), true).hasError());

  // Simulate all bytes and EOF written on network.
  stream.currentWriteOffset = len + 1;
  stream.retransmissionBuffer.clear();

  appendPendingStreamReset(conn, stream, GenericApplicationErrorCode::UNKNOWN);
  auto rst = conn.pendingEvents.resets.at(id);
  EXPECT_EQ(rst.errorCode, GenericApplicationErrorCode::UNKNOWN);
  EXPECT_EQ(rst.finalSize, len);
}

TEST_F(
    QuicServerStreamFunctionsTest,
    TestAppendPendingStreamResetAllDataWithoutFin) {
  StreamId id = 3;
  QuicStreamState stream(id, conn);
  auto data = IOBuf::copyBuffer("this is data");
  auto len = data->computeChainDataLength();
  ASSERT_FALSE(writeDataToQuicStream(stream, std::move(data), true).hasError());

  // Simulate all bytes except EOF written on network.
  stream.currentWriteOffset = len;
  stream.retransmissionBuffer.clear();

  appendPendingStreamReset(conn, stream, GenericApplicationErrorCode::UNKNOWN);
  auto rst = conn.pendingEvents.resets.at(id);
  EXPECT_EQ(rst.errorCode, GenericApplicationErrorCode::UNKNOWN);
  EXPECT_EQ(rst.finalSize, len);
}

// This tests the scenario in which the reliable size is greater than the
// current write offset.
TEST_F(QuicServerStreamFunctionsTest, TestAppendPendingStreamReliableReset1) {
  StreamId id = 3;
  QuicStreamState stream(id, conn);
  auto data = IOBuf::copyBuffer("this is data");
  auto len = data->computeChainDataLength();
  ASSERT_FALSE(
      writeDataToQuicStream(stream, std::move(data), false).hasError());

  stream.currentWriteOffset = len - 5;

  appendPendingStreamReset(
      conn, stream, GenericApplicationErrorCode::UNKNOWN, len - 3);
  auto rst = conn.pendingEvents.resets.at(id);
  EXPECT_EQ(rst.errorCode, GenericApplicationErrorCode::UNKNOWN);
  EXPECT_EQ(rst.finalSize, len - 3);
}

// This tests the scenario in which the reliable size is less than the
// current write offset.
TEST_F(QuicServerStreamFunctionsTest, TestAppendPendingStreamReliableReset2) {
  StreamId id = 3;
  QuicStreamState stream(id, conn);
  auto data = IOBuf::copyBuffer("this is data");
  auto len = data->computeChainDataLength();
  ASSERT_FALSE(
      writeDataToQuicStream(stream, std::move(data), false).hasError());

  stream.currentWriteOffset = len - 5;

  appendPendingStreamReset(
      conn, stream, GenericApplicationErrorCode::UNKNOWN, len - 7);
  auto rst = conn.pendingEvents.resets.at(id);
  EXPECT_EQ(rst.errorCode, GenericApplicationErrorCode::UNKNOWN);
  EXPECT_EQ(rst.finalSize, len - 5);
}

TEST_F(QuicStreamFunctionsTestBase, LargestWriteOffsetSeenFIN) {
  QuicStreamState stream(3, conn);
  stream.finalWriteOffset = 100;
  EXPECT_EQ(100, getLargestWriteOffsetSeen(stream));
}

TEST_F(QuicStreamFunctionsTestBase, LargestWriteOffsetSeenNoFIN) {
  QuicStreamState stream(3, conn);
  stream.currentWriteOffset = 100;
  auto randomInputData = buildRandomInputData(20);
  stream.pendingWrites.append(randomInputData);
  stream.writeBuffer.append(std::move(randomInputData));
  EXPECT_EQ(120, getLargestWriteOffsetSeen(stream));
}

TEST_F(QuicStreamFunctionsTestBase, StreamLargestWriteOffsetTxedNothingTxed) {
  QuicStreamState stream(3, conn);
  stream.currentWriteOffset = 0;
  EXPECT_EQ(std::nullopt, getLargestWriteOffsetTxed(stream));
}

TEST_F(QuicStreamFunctionsTestBase, StreamLargestWriteOffsetTxedOneByteTxed) {
  QuicStreamState stream(3, conn);
  stream.currentWriteOffset = 1;
  ASSERT_TRUE(getLargestWriteOffsetTxed(stream).has_value());
  EXPECT_EQ(0, getLargestWriteOffsetTxed(stream).value());
}

TEST_F(
    QuicStreamFunctionsTestBase,
    StreamLargestWriteOffsetTxedHundredBytesTxed) {
  QuicStreamState stream(3, conn);
  stream.currentWriteOffset = 100;
  ASSERT_TRUE(getLargestWriteOffsetTxed(stream).has_value());
  EXPECT_EQ(99, getLargestWriteOffsetTxed(stream).value());
}

TEST_F(
    QuicStreamFunctionsTest,
    StreamLargestWriteOffsetTxedIgnoreFinalWriteOffset) {
  // finalWriteOffset is set when writeChain is called with EoR, but we should
  // always use currentWriteOffset to determine how many bytes have been TXed
  QuicStreamState stream(3, conn);
  stream.currentWriteOffset = 10;
  stream.finalWriteOffset = 100;
  ASSERT_TRUE(getLargestWriteOffsetTxed(stream).has_value());
  EXPECT_EQ(9, getLargestWriteOffsetTxed(stream).value());
}

TEST_F(QuicStreamFunctionsTestBase, StreamNextOffsetToDeliverNothingAcked) {
  QuicStreamState stream(3, conn);
  stream.currentWriteOffset = 100;
  EXPECT_EQ(std::nullopt, getLargestDeliverableOffset(stream));
}

TEST_F(QuicStreamFunctionsTestBase, StreamNextOffsetToDeliverAllAcked) {
  QuicStreamState stream(3, conn);
  stream.currentWriteOffset = 100;
  stream.ackedIntervals.insert(0, 99);
  EXPECT_EQ(99, getLargestDeliverableOffset(stream).value());
}

TEST_F(QuicStreamFunctionsTestBase, LossBufferEmpty) {
  StreamId id = 4;
  QuicStreamState stream(id, conn);
  conn.streamManager->addLoss(id);
  conn.streamManager->updateWritableStreams(stream);
  EXPECT_FALSE(conn.streamManager->hasLoss());
}

TEST_F(QuicStreamFunctionsTestBase, LossBufferEmptyNoChange) {
  StreamId id = 4;
  QuicStreamState stream(id, conn);
  conn.streamManager->updateWritableStreams(stream);
  EXPECT_FALSE(conn.streamManager->hasLoss());
}

TEST_F(QuicStreamFunctionsTestBase, LossBufferHasData) {
  StreamId id = 4;
  QuicStreamState stream(id, conn);
  auto dataBuf = IOBuf::create(10);
  stream.lossBuffer.emplace_back(ChainedByteRangeHead(dataBuf), 10, false);
  conn.streamManager->updateWritableStreams(stream);
  EXPECT_TRUE(conn.streamManager->hasLoss());
}

TEST_F(QuicStreamFunctionsTestBase, LossBufferStillHasData) {
  StreamId id = 4;
  QuicStreamState stream(id, conn);
  conn.streamManager->addLoss(id);
  auto dataBuf = IOBuf::create(10);
  stream.lossBuffer.emplace_back(ChainedByteRangeHead(dataBuf), 10, false);
  conn.streamManager->updateWritableStreams(stream);
  EXPECT_TRUE(conn.streamManager->hasLoss());
}

TEST_F(QuicStreamFunctionsTestBase, WritableList) {
  StreamId id = 3;
  QuicStreamState stream(id, conn);
  stream.currentWriteOffset = 100;
  stream.flowControlState.peerAdvertisedMaxOffset = 200;

  conn.streamManager->updateWritableStreams(stream);
  EXPECT_FALSE(writableContains(*stream.conn.streamManager, id));

  auto buf = IOBuf::create(100);
  buf->append(100);
  ASSERT_FALSE(writeDataToQuicStream(stream, std::move(buf), false).hasError());
  conn.streamManager->updateWritableStreams(stream);
  EXPECT_TRUE(writableContains(*stream.conn.streamManager, id));

  // Flow control
  stream.flowControlState.peerAdvertisedMaxOffset = stream.currentWriteOffset;
  conn.streamManager->updateWritableStreams(stream);
  EXPECT_FALSE(writableContains(*stream.conn.streamManager, id));

  // Fin
  ASSERT_FALSE(writeDataToQuicStream(stream, nullptr, true).hasError());
  stream.writeBuffer.move();
  ChainedByteRangeHead(std::move(stream.pendingWrites));
  stream.currentWriteOffset += 100;
  stream.flowControlState.peerAdvertisedMaxOffset = stream.currentWriteOffset;
  conn.streamManager->updateWritableStreams(stream);
  EXPECT_TRUE(writableContains(*stream.conn.streamManager, id));

  // After Fin
  stream.currentWriteOffset++;
  conn.streamManager->updateWritableStreams(stream);
  EXPECT_FALSE(writableContains(*stream.conn.streamManager, id));
}

TEST_F(QuicStreamFunctionsTestBase, AckCryptoStream) {
  auto chlo = IOBuf::copyBuffer("CHLO");
  conn.cryptoState->handshakeStream.retransmissionBuffer.emplace(
      0, std::make_unique<WriteStreamBuffer>(ChainedByteRangeHead(chlo), 0));
  processCryptoStreamAck(conn.cryptoState->handshakeStream, 0, chlo->length());
  EXPECT_EQ(conn.cryptoState->handshakeStream.retransmissionBuffer.size(), 0);
}

TEST_F(QuicStreamFunctionsTestBase, AckCryptoStreamOffsetLengthMismatch) {
  auto chlo = IOBuf::copyBuffer("CHLO");
  auto& cryptoStream = conn.cryptoState->handshakeStream;
  cryptoStream.retransmissionBuffer.emplace(
      0, std::make_unique<WriteStreamBuffer>(ChainedByteRangeHead(chlo), 0));
  processCryptoStreamAck(cryptoStream, 1, chlo->length());
  EXPECT_EQ(cryptoStream.retransmissionBuffer.size(), 1);

  processCryptoStreamAck(cryptoStream, 0, chlo->length() - 2);
  EXPECT_EQ(cryptoStream.retransmissionBuffer.size(), 1);

  processCryptoStreamAck(cryptoStream, 20, chlo->length());
  EXPECT_EQ(cryptoStream.retransmissionBuffer.size(), 1);
}

TEST_F(QuicStreamFunctionsTestBase, CryptoStreamBufferLimitExceeded) {
  auto& cryptoStream = conn.cryptoState->handshakeStream;

  // Test the limit directly - add data that should exceed 256kB
  size_t chunk = 256 * 1024; // 256kB
  auto buf = IOBuf::create(chunk);
  buf->append(chunk);

  // First 256kB should succeed
  auto res1 =
      appendDataToReadBuffer(cryptoStream, StreamBuffer(std::move(buf), 0));
  ASSERT_FALSE(res1.hasError());

  // Second chunk should fail (total would be 512kB > 256kB limit)
  auto badBuf = IOBuf::create(chunk);
  badBuf->append(chunk);
  auto res2 = appendDataToReadBuffer(
      cryptoStream, StreamBuffer(std::move(badBuf), chunk));
  ASSERT_TRUE(res2.hasError());
  EXPECT_EQ(
      res2.error().code,
      QuicErrorCode(TransportErrorCode::CRYPTO_BUFFER_EXCEEDED));
}

} // namespace quic::test
