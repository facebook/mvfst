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
#include <quic/state/QuicStreamUtilities.h>

#include <quic/client/state/ClientStateMachine.h>
#include <quic/common/test/TestUtils.h>
#include <quic/fizz/client/handshake/FizzClientQuicHandshakeContext.h>
#include <quic/fizz/server/handshake/FizzServerQuicHandshakeContext.h>
#include <quic/server/state/ServerStateMachine.h>

using namespace folly;
using namespace testing;

namespace quic {
namespace test {

constexpr uint8_t kStreamIncrement = 0x04;

using PeekIterator = std::deque<StreamBuffer>::const_iterator;

class QuicStreamFunctionsTest : public Test {
 public:
  QuicStreamFunctionsTest()
      : conn(FizzClientQuicHandshakeContext::Builder().build()) {}

  void SetUp() override {
    conn.flowControlState.peerAdvertisedInitialMaxStreamOffsetBidiLocal =
        kDefaultStreamWindowSize;
    conn.flowControlState.peerAdvertisedInitialMaxStreamOffsetBidiRemote =
        kDefaultStreamWindowSize;
    conn.flowControlState.peerAdvertisedInitialMaxStreamOffsetUni =
        kDefaultStreamWindowSize;
    conn.flowControlState.peerAdvertisedMaxOffset =
        kDefaultConnectionWindowSize;
    conn.streamManager->setMaxLocalBidirectionalStreams(
        kDefaultMaxStreamsBidirectional);
    conn.streamManager->setMaxLocalUnidirectionalStreams(
        kDefaultMaxStreamsUnidirectional);
  }

  QuicClientConnectionState conn;
};

class QuicServerStreamFunctionsTest : public Test {
 public:
  QuicServerStreamFunctionsTest()
      : conn(FizzServerQuicHandshakeContext::Builder().build()) {}

  void SetUp() override {
    conn.flowControlState.peerAdvertisedInitialMaxStreamOffsetBidiLocal =
        kDefaultStreamWindowSize;
    conn.flowControlState.peerAdvertisedInitialMaxStreamOffsetBidiRemote =
        kDefaultStreamWindowSize;
    conn.flowControlState.peerAdvertisedInitialMaxStreamOffsetUni =
        kDefaultStreamWindowSize;
    conn.flowControlState.peerAdvertisedMaxOffset =
        kDefaultConnectionWindowSize;
    conn.streamManager->setMaxLocalBidirectionalStreams(
        kDefaultMaxStreamsBidirectional);
    conn.streamManager->setMaxLocalUnidirectionalStreams(
        kDefaultMaxStreamsUnidirectional);
  }

  QuicServerConnectionState conn;
};

TEST_F(QuicStreamFunctionsTest, TestCreateBidirectionalStream) {
  const auto stream =
      conn.streamManager->createNextBidirectionalStream().value();
  EXPECT_EQ(conn.streamManager->streamCount(), 1);
  EXPECT_EQ(stream->id, 0x00);
}

TEST_F(QuicStreamFunctionsTest, TestCreateUnidirectionalStream) {
  const auto stream =
      conn.streamManager->createNextUnidirectionalStream().value();
  EXPECT_EQ(conn.streamManager->streamCount(), 1);
  EXPECT_EQ(stream->id, 0x02);
}

TEST_F(QuicStreamFunctionsTest, TestCreateBoth) {
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

TEST_F(QuicStreamFunctionsTest, TestWriteStream) {
  auto stream = conn.streamManager->createNextBidirectionalStream().value();
  auto buf1 = IOBuf::copyBuffer("I just met you");
  auto buf2 = IOBuf::copyBuffer("and this is crazy");

  writeDataToQuicStream(*stream, buf1->clone(), false);
  writeDataToQuicStream(*stream, buf2->clone(), false);

  IOBufEqualTo eq;
  buf1->prependChain(std::move(buf2));

  EXPECT_TRUE(eq(stream->writeBuffer.move(), buf1));
}

TEST_F(QuicStreamFunctionsTest, TestReadDataWrittenInOrder) {
  auto stream = conn.streamManager->createNextBidirectionalStream().value();
  auto streamLastMaxOffset = stream->maxOffsetObserved;
  auto connLastMaxOffset = conn.flowControlState.sumMaxObservedOffset;
  auto buf1 = IOBuf::copyBuffer("I just met you ");
  buf1->prependChain(IOBuf::copyBuffer("and this is crazy. "));

  auto buf2 = IOBuf::copyBuffer("Here's my number ");
  buf2->prependChain(IOBuf::copyBuffer("so call me maybe"));

  appendDataToReadBuffer(*stream, StreamBuffer(buf1->clone(), 0));
  appendDataToReadBuffer(
      *stream,
      StreamBuffer(buf2->clone(), buf1->computeChainDataLength(), true));
  EXPECT_EQ(
      stream->maxOffsetObserved - streamLastMaxOffset,
      conn.flowControlState.sumMaxObservedOffset - connLastMaxOffset);

  auto readData1 = readDataFromQuicStream(*stream, 10);
  EXPECT_EQ("I just met", readData1.first->moveToFbString().toStdString());
  EXPECT_FALSE(readData1.second);

  auto readData2 = readDataFromQuicStream(*stream, 30);
  EXPECT_EQ(
      " you and this is crazy. Here's",
      readData2.first->moveToFbString().toStdString());
  EXPECT_FALSE(readData2.second);

  auto readData3 = readDataFromQuicStream(*stream, 21);
  EXPECT_EQ(
      " my number so call me", readData3.first->moveToFbString().toStdString());
  EXPECT_FALSE(readData3.second);

  auto readData4 = readDataFromQuicStream(*stream, 20);
  EXPECT_EQ(" maybe", readData4.first->moveToFbString().toStdString());
  EXPECT_TRUE(readData4.second);
}

TEST_F(QuicStreamFunctionsTest, TestPeekAndConsumeContiguousData) {
  auto stream = conn.streamManager->createNextBidirectionalStream().value();
  auto streamLastMaxOffset = stream->maxOffsetObserved;
  auto connLastMaxOffset = conn.flowControlState.sumMaxObservedOffset;
  auto buf1 = IOBuf::copyBuffer("I just met you ");
  buf1->prependChain(IOBuf::copyBuffer("and this is crazy. "));

  auto buf2 = IOBuf::copyBuffer("Here's my number ");
  buf2->prependChain(IOBuf::copyBuffer("so call me maybe"));

  appendDataToReadBuffer(*stream, StreamBuffer(buf1->clone(), 0));
  appendDataToReadBuffer(
      *stream,
      StreamBuffer(buf2->clone(), buf1->computeChainDataLength(), true));
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
          bufClone->moveToFbString().toStdString());
    }
  };

  peekDataFromQuicStream(*stream, peekCallback);
  EXPECT_TRUE(peekCbCalled);

  EXPECT_NO_THROW(consumeDataFromQuicStream(*stream, 81));

  peekCbCalled = false;
  auto peekCallback2 = [&](StreamId /* unused */,
                           const folly::Range<PeekIterator>& range) {
    peekCbCalled = true;
    EXPECT_EQ(range.size(), 0);
  };

  peekDataFromQuicStream(*stream, peekCallback2);
  EXPECT_TRUE(peekCbCalled);
}

TEST_F(QuicStreamFunctionsTest, TestPeekAndConsumeNonContiguousData) {
  auto stream = conn.streamManager->createNextBidirectionalStream().value();
  auto streamLastMaxOffset = stream->maxOffsetObserved;
  auto connLastMaxOffset = conn.flowControlState.sumMaxObservedOffset;
  auto buf1 = IOBuf::copyBuffer("I just met you ");
  buf1->prependChain(IOBuf::copyBuffer("and this is crazy. "));

  auto buf2 = IOBuf::copyBuffer("'s my number ");
  buf2->prependChain(IOBuf::copyBuffer("so call me maybe"));

  appendDataToReadBuffer(*stream, StreamBuffer(buf1->clone(), 0));
  appendDataToReadBuffer(
      *stream,
      StreamBuffer(buf2->clone(), buf1->computeChainDataLength() + 4, true));
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
        EXPECT_EQ(
            "I just met you and this is crazy. ",
            bufClone->moveToFbString().toStdString());

        bufClone = range[1].data.front()->clone();
        EXPECT_EQ(
            "'s my number so call me maybe",
            bufClone->moveToFbString().toStdString());
      });
  EXPECT_TRUE(cbCalled);

  // Consume left side.
  EXPECT_NO_THROW(consumeDataFromQuicStream(*stream, 81));

  cbCalled = false;
  auto peekCallback2 = [&](StreamId /* unused */,
                           const folly::Range<PeekIterator>& range) {
    cbCalled = true;
    EXPECT_EQ(range.size(), 1);

    auto bufClone = range[0].data.front()->clone();
    EXPECT_EQ(
        "'s my number so call me maybe",
        bufClone->moveToFbString().toStdString());
  };
  peekDataFromQuicStream(*stream, peekCallback2);
  EXPECT_TRUE(cbCalled);

  // Try consuming again.
  // Nothing has changed since we're missing data in the middle.
  EXPECT_NO_THROW(consumeDataFromQuicStream(*stream, 81));
  cbCalled = false;
  peekDataFromQuicStream(*stream, peekCallback2);
  EXPECT_TRUE(cbCalled);

  // Add missing middle bytes.
  auto buf3 = IOBuf::copyBuffer("Here");
  appendDataToReadBuffer(*stream, StreamBuffer(buf3->clone(), 0));
  appendDataToReadBuffer(
      *stream, StreamBuffer(buf3->clone(), buf1->computeChainDataLength()));

  cbCalled = false;
  peekDataFromQuicStream(
      *stream,
      [&](StreamId /* unused */, const folly::Range<PeekIterator>& range) {
        cbCalled = true;
        EXPECT_EQ(range.size(), 1);

        auto bufClone = range[0].data.front()->clone();
        EXPECT_EQ(
            "Here's my number so call me maybe",
            bufClone->moveToFbString().toStdString());
      });
  EXPECT_TRUE(cbCalled);

  // Consume the rest of the buffer.
  EXPECT_NO_THROW(consumeDataFromQuicStream(*stream, 81));

  cbCalled = false;
  peekDataFromQuicStream(
      *stream,
      [&](StreamId /* unused */, const folly::Range<PeekIterator>& range) {
        cbCalled = true;
        EXPECT_EQ(range.size(), 0);
      });
  EXPECT_TRUE(cbCalled);
}

TEST_F(QuicStreamFunctionsTest, TestPeekAndConsumeEmptyData) {
  auto stream = conn.streamManager->createNextBidirectionalStream().value();

  bool cbCalled = false;
  auto peekCallback = [&](StreamId /* unused */,
                          const folly::Range<PeekIterator>& range) {
    cbCalled = true;
    EXPECT_EQ(range.size(), 0);
  };

  peekDataFromQuicStream(*stream, peekCallback);
  EXPECT_TRUE(cbCalled);

  EXPECT_NO_THROW(consumeDataFromQuicStream(*stream, 81));

  cbCalled = false;
  peekDataFromQuicStream(*stream, peekCallback);
  EXPECT_TRUE(cbCalled);
}

TEST_F(QuicStreamFunctionsTest, TestPeekAndConsumeEmptyDataEof) {
  auto stream = conn.streamManager->createNextBidirectionalStream().value();

  bool cbCalled = false;
  auto peekCallback = [&](StreamId /* unused */,
                          const folly::Range<PeekIterator>& range) {
    cbCalled = true;
    EXPECT_EQ(range.size(), 0);
  };

  appendDataToReadBuffer(*stream, StreamBuffer(nullptr, 0, true));

  peekDataFromQuicStream(*stream, peekCallback);
  EXPECT_TRUE(cbCalled);

  EXPECT_NO_THROW(consumeDataFromQuicStream(*stream, 42));

  cbCalled = false;
  peekDataFromQuicStream(*stream, peekCallback);
  EXPECT_TRUE(cbCalled);
}

TEST_F(QuicStreamFunctionsTest, TestReadDataFromMultipleBufs) {
  auto stream = conn.streamManager->createNextBidirectionalStream().value();
  auto buf1 = IOBuf::copyBuffer("I just met you ");
  buf1->prependChain(IOBuf::copyBuffer("and this is crazy. "));

  auto buf2 = IOBuf::copyBuffer("Here's my number ");
  buf2->prependChain(IOBuf::copyBuffer("so call me maybe"));

  auto streamLastMaxOffset = stream->maxOffsetObserved;
  auto connLastMaxOffset = conn.flowControlState.sumMaxObservedOffset;
  appendDataToReadBuffer(*stream, StreamBuffer(buf1->clone(), 0));
  appendDataToReadBuffer(
      *stream,
      StreamBuffer(buf2->clone(), buf1->computeChainDataLength(), true));

  EXPECT_EQ(
      stream->maxOffsetObserved - streamLastMaxOffset,
      conn.flowControlState.sumMaxObservedOffset - connLastMaxOffset);
  EXPECT_EQ(
      stream->maxOffsetObserved - streamLastMaxOffset,
      conn.flowControlState.sumMaxObservedOffset - connLastMaxOffset);
  auto readData1 = readDataFromQuicStream(*stream, 100);
  EXPECT_EQ(
      "I just met you and this is crazy. Here's my number so call me maybe",
      readData1.first->moveToFbString().toStdString());
  EXPECT_TRUE(readData1.first);

  auto readData2 = readDataFromQuicStream(*stream, 30);
  EXPECT_EQ(nullptr, readData2.first);
}

TEST_F(QuicStreamFunctionsTest, TestReadDataOutOfOrder) {
  auto stream = conn.streamManager->createNextBidirectionalStream().value();
  auto buf1 = IOBuf::copyBuffer(" you ");
  buf1->prependChain(IOBuf::copyBuffer("and this is crazy. "));

  auto buf2 = IOBuf::copyBuffer("Here's my number ");
  buf2->prependChain(IOBuf::copyBuffer("so call me maybe"));
  auto streamLastMaxOffset = stream->maxOffsetObserved;
  auto connLastMaxOffset = conn.flowControlState.sumMaxObservedOffset;

  appendDataToReadBuffer(*stream, StreamBuffer(buf1->clone(), 10));
  appendDataToReadBuffer(
      *stream,
      StreamBuffer(buf2->clone(), buf1->computeChainDataLength() + 10, true));
  EXPECT_EQ(
      stream->maxOffsetObserved - streamLastMaxOffset,
      conn.flowControlState.sumMaxObservedOffset - connLastMaxOffset);

  auto readData1 = readDataFromQuicStream(*stream, 100);
  EXPECT_EQ(nullptr, readData1.first);

  appendDataToReadBuffer(
      *stream, StreamBuffer(IOBuf::copyBuffer("I just met"), 0));
  auto readData2 = readDataFromQuicStream(*stream, 19);
  EXPECT_EQ(
      "I just met you and ", readData2.first->moveToFbString().toStdString());
  EXPECT_FALSE(readData2.second);

  auto readData3 = readDataFromQuicStream(*stream, 31);
  EXPECT_EQ(
      "this is crazy. Here's my number",
      readData3.first->moveToFbString().toStdString());
  EXPECT_FALSE(readData3.second);

  auto readData4 = readDataFromQuicStream(*stream);
  EXPECT_EQ(
      " so call me maybe", readData4.first->moveToFbString().toStdString());
  EXPECT_TRUE(readData4.second);
}

TEST_F(QuicStreamFunctionsTest, TestReadOverlappingData) {
  auto stream = conn.streamManager->createNextBidirectionalStream().value();
  auto buf1 = IOBuf::copyBuffer("I just met you ");
  buf1->prependChain(IOBuf::copyBuffer("and this"));

  auto buf2 = IOBuf::copyBuffer("met you and this is crazy. ");
  buf2->prependChain(IOBuf::copyBuffer("Here's my number"));

  auto buf3 = IOBuf::copyBuffer("Here's my number, ");
  buf3->prependChain(IOBuf::copyBuffer("so call me maybe."));

  auto streamLastMaxOffset = stream->maxOffsetObserved;
  auto connLastMaxOffset = conn.flowControlState.sumMaxObservedOffset;
  appendDataToReadBuffer(*stream, StreamBuffer(buf1->clone(), 0));
  appendDataToReadBuffer(*stream, StreamBuffer(buf2->clone(), 7));
  appendDataToReadBuffer(*stream, StreamBuffer(buf3->clone(), 34, true));

  EXPECT_EQ(
      stream->maxOffsetObserved - streamLastMaxOffset,
      conn.flowControlState.sumMaxObservedOffset - connLastMaxOffset);
  auto readData1 = readDataFromQuicStream(*stream, 100);
  auto str = readData1.first->moveToFbString().toStdString();
  EXPECT_EQ(
      "I just met you and this is crazy. Here's my number, so call me maybe.",
      str);
  EXPECT_TRUE(readData1.second);
}

TEST_F(QuicStreamFunctionsTest, TestCompleteOverlap) {
  auto stream = conn.streamManager->createNextBidirectionalStream().value();
  auto buf1 = IOBuf::copyBuffer("met you ");
  auto buf2 = IOBuf::copyBuffer("this is");
  auto buf3 = IOBuf::copyBuffer("I just met you and this is crazy");

  auto streamLastMaxOffset = stream->maxOffsetObserved;
  auto connLastMaxOffset = conn.flowControlState.sumMaxObservedOffset;
  appendDataToReadBuffer(*stream, StreamBuffer(buf1->clone(), 7));
  appendDataToReadBuffer(*stream, StreamBuffer(buf2->clone(), 19));
  appendDataToReadBuffer(*stream, StreamBuffer(buf3->clone(), 0, true));
  EXPECT_EQ(
      stream->maxOffsetObserved - streamLastMaxOffset,
      conn.flowControlState.sumMaxObservedOffset - connLastMaxOffset);

  EXPECT_EQ(stream->readBuffer.size(), 1);
  auto readData1 = readDataFromQuicStream(*stream, 100);
  EXPECT_EQ(
      "I just met you and this is crazy",
      readData1.first->moveToFbString().toStdString());
  EXPECT_TRUE(readData1.second);
  EXPECT_TRUE(stream->readBuffer.empty());
}

TEST_F(QuicStreamFunctionsTest, TestTotalOverlap) {
  auto stream = conn.streamManager->createNextBidirectionalStream().value();
  auto buf1 = IOBuf::copyBuffer("met you ");
  auto streamLastMaxOffset = stream->maxOffsetObserved;
  auto connLastMaxOffset = conn.flowControlState.sumMaxObservedOffset;

  appendDataToReadBuffer(*stream, StreamBuffer(buf1->clone(), 0));
  appendDataToReadBuffer(*stream, StreamBuffer(buf1->clone(), 0));
  appendDataToReadBuffer(*stream, StreamBuffer(buf1->clone(), 0, true));

  EXPECT_EQ(
      stream->maxOffsetObserved - streamLastMaxOffset,
      conn.flowControlState.sumMaxObservedOffset - connLastMaxOffset);
  EXPECT_EQ(stream->readBuffer.size(), 1);
  auto readData1 = readDataFromQuicStream(*stream, 100);
  EXPECT_EQ("met you ", readData1.first->moveToFbString().toStdString());
  EXPECT_TRUE(readData1.second);
  EXPECT_TRUE(stream->readBuffer.empty());
}

TEST_F(QuicStreamFunctionsTest, TestSubsetOverlap) {
  auto stream = conn.streamManager->createNextBidirectionalStream().value();
  auto buf1 = IOBuf::copyBuffer("met you ");
  auto buf2 = IOBuf::copyBuffer("you");
  auto buf3 = IOBuf::copyBuffer("you ");

  auto streamLastMaxOffset = stream->maxOffsetObserved;
  auto connLastMaxOffset = conn.flowControlState.sumMaxObservedOffset;
  appendDataToReadBuffer(*stream, StreamBuffer(buf1->clone(), 0));
  appendDataToReadBuffer(*stream, StreamBuffer(buf2->clone(), 4));
  appendDataToReadBuffer(*stream, StreamBuffer(buf3->clone(), 4, true));

  EXPECT_EQ(
      stream->maxOffsetObserved - streamLastMaxOffset,
      conn.flowControlState.sumMaxObservedOffset - connLastMaxOffset);
  EXPECT_EQ(stream->readBuffer.size(), 1);
  auto readData1 = readDataFromQuicStream(*stream, 100);
  EXPECT_EQ("met you ", readData1.first->moveToFbString().toStdString());
  EXPECT_TRUE(readData1.second);
  EXPECT_TRUE(stream->readBuffer.empty());
}

TEST_F(QuicStreamFunctionsTest, TestLeftOverlap) {
  auto stream = conn.streamManager->createNextBidirectionalStream().value();
  auto buf1 = IOBuf::copyBuffer("met you ");
  auto buf2 = IOBuf::copyBuffer("I just met");

  auto streamLastMaxOffset = stream->maxOffsetObserved;
  auto connLastMaxOffset = conn.flowControlState.sumMaxObservedOffset;
  appendDataToReadBuffer(*stream, StreamBuffer(buf1->clone(), 7, true));
  appendDataToReadBuffer(*stream, StreamBuffer(buf2->clone(), 0));
  EXPECT_EQ(
      stream->maxOffsetObserved - streamLastMaxOffset,
      conn.flowControlState.sumMaxObservedOffset - connLastMaxOffset);

  EXPECT_EQ(stream->readBuffer.size(), 1);
  auto readData1 = readDataFromQuicStream(*stream, 100);
  EXPECT_EQ("I just met you ", readData1.first->moveToFbString().toStdString());
  EXPECT_TRUE(readData1.second);
  EXPECT_TRUE(stream->readBuffer.empty());
}

TEST_F(QuicStreamFunctionsTest, TestLeftNoOverlap) {
  auto stream = conn.streamManager->createNextBidirectionalStream().value();
  auto buf1 = IOBuf::copyBuffer("met you ");
  auto buf2 = IOBuf::copyBuffer("I just");

  auto streamLastMaxOffset = stream->maxOffsetObserved;
  auto connLastMaxOffset = conn.flowControlState.sumMaxObservedOffset;
  appendDataToReadBuffer(*stream, StreamBuffer(buf1->clone(), 7, true));
  appendDataToReadBuffer(*stream, StreamBuffer(buf2->clone(), 0));
  EXPECT_EQ(
      stream->maxOffsetObserved - streamLastMaxOffset,
      conn.flowControlState.sumMaxObservedOffset - connLastMaxOffset);

  EXPECT_EQ(
      stream->maxOffsetObserved - streamLastMaxOffset,
      conn.flowControlState.sumMaxObservedOffset - connLastMaxOffset);
  EXPECT_EQ(stream->readBuffer.size(), 2);
  auto readData1 = readDataFromQuicStream(*stream, 100);
  EXPECT_EQ("I just", readData1.first->moveToFbString().toStdString());
  EXPECT_FALSE(readData1.second);
  EXPECT_EQ(stream->readBuffer.size(), 1);
}

TEST_F(QuicStreamFunctionsTest, TestRightOverlap) {
  auto stream = conn.streamManager->createNextBidirectionalStream().value();
  auto buf1 = IOBuf::copyBuffer("I just");
  auto buf2 = IOBuf::copyBuffer(" met you ");
  auto buf3 = IOBuf::copyBuffer("you and this is crazy");

  auto streamLastMaxOffset = stream->maxOffsetObserved;
  auto connLastMaxOffset = conn.flowControlState.sumMaxObservedOffset;
  appendDataToReadBuffer(*stream, StreamBuffer(buf1->clone(), 0));
  appendDataToReadBuffer(*stream, StreamBuffer(buf2->clone(), 6));
  appendDataToReadBuffer(*stream, StreamBuffer(buf3->clone(), 11, true));

  EXPECT_EQ(
      stream->maxOffsetObserved - streamLastMaxOffset,
      conn.flowControlState.sumMaxObservedOffset - connLastMaxOffset);
  EXPECT_EQ(stream->readBuffer.size(), 1);
  auto readData1 = readDataFromQuicStream(*stream, 100);
  EXPECT_EQ(
      "I just met you and this is crazy",
      readData1.first->moveToFbString().toStdString());
  EXPECT_TRUE(readData1.second);
  EXPECT_TRUE(stream->readBuffer.empty());
} // namespace test

TEST_F(QuicStreamFunctionsTest, TestRightNoOverlap) {
  auto stream = conn.streamManager->createNextBidirectionalStream().value();
  auto buf1 = IOBuf::copyBuffer("I just");
  auto buf2 = IOBuf::copyBuffer("met you ");

  auto streamLastMaxOffset = stream->maxOffsetObserved;
  auto connLastMaxOffset = conn.flowControlState.sumMaxObservedOffset;
  appendDataToReadBuffer(*stream, StreamBuffer(buf1->clone(), 0));
  appendDataToReadBuffer(*stream, StreamBuffer(buf2->clone(), 7));

  EXPECT_EQ(
      stream->maxOffsetObserved - streamLastMaxOffset,
      conn.flowControlState.sumMaxObservedOffset - connLastMaxOffset);
  EXPECT_EQ(stream->readBuffer.size(), 2);
  auto readData1 = readDataFromQuicStream(*stream, 100);
  EXPECT_EQ("I just", readData1.first->moveToFbString().toStdString());
  EXPECT_FALSE(readData1.second);
  EXPECT_EQ(stream->readBuffer.size(), 1);
}

TEST_F(QuicStreamFunctionsTest, TestRightLeftOverlap) {
  auto stream = conn.streamManager->createNextBidirectionalStream().value();
  auto buf1 = IOBuf::copyBuffer("I just met");
  auto buf2 = IOBuf::copyBuffer("met you");
  auto buf3 = IOBuf::copyBuffer("you and this is crazy");

  auto streamLastMaxOffset = stream->maxOffsetObserved;
  auto connLastMaxOffset = conn.flowControlState.sumMaxObservedOffset;
  appendDataToReadBuffer(*stream, StreamBuffer(buf1->clone(), 0));
  appendDataToReadBuffer(*stream, StreamBuffer(buf3->clone(), 11, true));
  appendDataToReadBuffer(*stream, StreamBuffer(buf2->clone(), 7));
  EXPECT_EQ(
      stream->maxOffsetObserved - streamLastMaxOffset,
      conn.flowControlState.sumMaxObservedOffset - connLastMaxOffset);
  EXPECT_EQ(stream->readBuffer.size(), 1);
  auto readData1 = readDataFromQuicStream(*stream, 100);
  EXPECT_EQ(
      "I just met you and this is crazy",
      readData1.first->moveToFbString().toStdString());
  EXPECT_TRUE(readData1.second);
  EXPECT_TRUE(stream->readBuffer.empty());
}

TEST_F(QuicStreamFunctionsTest, TestInsertVariations) {
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
  buf8->prependChain(IOBuf::copyBuffer(" and this"));
  auto buf9 = IOBuf::copyBuffer("Here's my number so call me maybe");
  auto buf10 = IOBuf::copyBuffer("I ");

  auto streamLastMaxOffset = stream->maxOffsetObserved;
  auto connLastMaxOffset = conn.flowControlState.sumMaxObservedOffset;
  appendDataToReadBuffer(*stream, StreamBuffer(buf1->clone(), 7));
  appendDataToReadBuffer(*stream, StreamBuffer(buf2->clone(), 19));
  appendDataToReadBuffer(*stream, StreamBuffer(buf3->clone(), 33));
  appendDataToReadBuffer(*stream, StreamBuffer(buf4->clone(), 44));
  appendDataToReadBuffer(*stream, StreamBuffer(buf5->clone(), 2));
  appendDataToReadBuffer(*stream, StreamBuffer(buf6->clone(), 58));
  appendDataToReadBuffer(*stream, StreamBuffer(buf7->clone(), 19));
  appendDataToReadBuffer(*stream, StreamBuffer(buf8->clone(), 0));
  appendDataToReadBuffer(*stream, StreamBuffer(buf9->clone(), 34, true));
  appendDataToReadBuffer(*stream, StreamBuffer(buf10->clone(), 0));
  EXPECT_EQ(
      stream->maxOffsetObserved - streamLastMaxOffset,
      conn.flowControlState.sumMaxObservedOffset - connLastMaxOffset);

  auto readData1 = readDataFromQuicStream(*stream, 100);
  auto str = readData1.first->moveToFbString().toStdString();
  EXPECT_EQ(
      "I just met you and this is crazy. Here's my number so call me maybe",
      str);
  EXPECT_TRUE(readData1.second);
  EXPECT_TRUE(stream->readBuffer.empty());
}

TEST_F(QuicStreamFunctionsTest, TestAppendAlreadyReadData) {
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
  appendDataToReadBuffer(*stream, StreamBuffer(buf1->clone(), 0));
  auto readData1 = readDataFromQuicStream(*stream, 100);
  EXPECT_EQ(
      "I just met you and this is crazy",
      readData1.first->moveToFbString().toStdString());
  EXPECT_FALSE(readData1.second);

  appendDataToReadBuffer(*stream, StreamBuffer(buf2->clone(), 0));
  auto readData2 = readDataFromQuicStream(*stream, 100);
  EXPECT_EQ(readData2.first, nullptr);
  EXPECT_FALSE(readData2.second);
  EXPECT_TRUE(stream->readBuffer.empty());

  appendDataToReadBuffer(*stream, StreamBuffer(buf3->clone(), 0));
  auto readData3 = readDataFromQuicStream(*stream, 100);
  EXPECT_EQ(readData3.first, nullptr);
  EXPECT_FALSE(readData3.second);
  EXPECT_TRUE(stream->readBuffer.empty());

  appendDataToReadBuffer(*stream, StreamBuffer(buf4->clone(), 0));
  auto readData4 = readDataFromQuicStream(*stream, 100);
  EXPECT_EQ(
      ". Here's my number", readData4.first->moveToFbString().toStdString());
  EXPECT_FALSE(readData4.second);
  EXPECT_TRUE(stream->readBuffer.empty());

  appendDataToReadBuffer(*stream, StreamBuffer(buf5->clone(), 0));
  appendDataToReadBuffer(*stream, StreamBuffer(buf6->clone(), 0));
  auto readData5 = readDataFromQuicStream(*stream, 100);
  EXPECT_EQ(
      " so call me maybe", readData5.first->moveToFbString().toStdString());
  EXPECT_FALSE(readData5.second);
  EXPECT_TRUE(stream->readBuffer.empty());

  appendDataToReadBuffer(*stream, StreamBuffer(buf6->clone(), 0, true));
  auto readData6 = readDataFromQuicStream(*stream, 100);
  EXPECT_EQ(readData6.first, nullptr);
  EXPECT_TRUE(readData6.second);
  EXPECT_EQ(
      stream->maxOffsetObserved - streamLastMaxOffset,
      conn.flowControlState.sumMaxObservedOffset - connLastMaxOffset);
}

TEST_F(QuicStreamFunctionsTest, TestEmptyEOF) {
  auto stream = conn.streamManager->createNextBidirectionalStream().value();
  auto buf1 = IOBuf::copyBuffer("I just");
  auto buf2 = IOBuf::copyBuffer("");

  appendDataToReadBuffer(*stream, StreamBuffer(buf1->clone(), 0));
  appendDataToReadBuffer(*stream, StreamBuffer(buf2->clone(), 7, true));

  EXPECT_EQ(stream->readBuffer.size(), 1);
  auto readData1 = readDataFromQuicStream(*stream, 100);
  EXPECT_EQ("I just", readData1.first->moveToFbString().toStdString());
  EXPECT_FALSE(readData1.second);
  EXPECT_TRUE(stream->readBuffer.empty());

  auto buf3 = IOBuf::copyBuffer("m");
  appendDataToReadBuffer(*stream, StreamBuffer(buf3->clone(), 6));
  auto readData2 = readDataFromQuicStream(*stream, 100);
  EXPECT_EQ("m", readData2.first->moveToFbString().toStdString());
  EXPECT_TRUE(readData2.second);
  EXPECT_TRUE(stream->readBuffer.empty());
}

TEST_F(QuicStreamFunctionsTest, TestEmptyEOFOverlap) {
  auto stream = conn.streamManager->createNextBidirectionalStream().value();
  auto buf1 = IOBuf::copyBuffer("I just");
  auto buf2 = IOBuf::copyBuffer("");

  appendDataToReadBuffer(*stream, StreamBuffer(buf1->clone(), 0, true));
  appendDataToReadBuffer(*stream, StreamBuffer(buf2->clone(), 6, true));

  EXPECT_EQ(stream->readBuffer.size(), 1);
  auto readData1 = readDataFromQuicStream(*stream, 100);
  EXPECT_EQ("I just", readData1.first->moveToFbString().toStdString());
  EXPECT_TRUE(readData1.second);
  EXPECT_TRUE(stream->readBuffer.empty());
}

TEST_F(QuicStreamFunctionsTest, TestOverlapEOF) {
  auto stream = conn.streamManager->createNextBidirectionalStream().value();
  auto buf1 = IOBuf::copyBuffer("just");
  auto buf2 = IOBuf::copyBuffer("I ");

  appendDataToReadBuffer(*stream, StreamBuffer(buf1->clone(), 2));
  appendDataToReadBuffer(*stream, StreamBuffer(buf1->clone(), 2, true));
  appendDataToReadBuffer(*stream, StreamBuffer(buf2->clone(), 0));

  EXPECT_EQ(stream->readBuffer.size(), 1);
  auto readData1 = readDataFromQuicStream(*stream, 100);
  EXPECT_EQ("I just", readData1.first->moveToFbString().toStdString());
  EXPECT_TRUE(readData1.second);
  EXPECT_TRUE(stream->readBuffer.empty());
}

TEST_F(QuicStreamFunctionsTest, TestEmptyBuffer) {
  auto stream = conn.streamManager->createNextBidirectionalStream().value();
  auto buf1 = IOBuf::copyBuffer("");
  appendDataToReadBuffer(*stream, StreamBuffer(buf1->clone(), 0));
}

TEST_F(QuicStreamFunctionsTest, TestInvalidEOFWithAlreadyReadData) {
  auto stream = conn.streamManager->createNextBidirectionalStream().value();
  auto buf1 = IOBuf::copyBuffer("I just");
  auto buf2 = IOBuf::copyBuffer(" met you");

  appendDataToReadBuffer(*stream, StreamBuffer(buf1->clone(), 0));
  appendDataToReadBuffer(*stream, StreamBuffer(buf2->clone(), 6));
  auto readData1 = readDataFromQuicStream(*stream, 6);
  EXPECT_EQ(stream->readBuffer.size(), 1);

  EXPECT_THROW(
      appendDataToReadBuffer(*stream, StreamBuffer(buf1->clone(), 0, true)),
      QuicTransportException);
}

TEST_F(QuicStreamFunctionsTest, TestInvalidEOFWithSubsetData) {
  auto stream = conn.streamManager->createNextBidirectionalStream().value();
  auto buf1 = IOBuf::copyBuffer("I just");
  auto buf2 = IOBuf::copyBuffer("I");

  appendDataToReadBuffer(*stream, StreamBuffer(buf1->clone(), 0));
  EXPECT_THROW(
      appendDataToReadBuffer(*stream, StreamBuffer(buf2->clone(), 0, true)),
      QuicTransportException);
}

TEST_F(QuicStreamFunctionsTest, TestInvalidEOFWithNoOverlap) {
  auto stream = conn.streamManager->createNextBidirectionalStream().value();
  auto buf1 = IOBuf::copyBuffer("just");
  auto buf2 = IOBuf::copyBuffer("I");

  appendDataToReadBuffer(*stream, StreamBuffer(buf1->clone(), 2));
  EXPECT_THROW(
      appendDataToReadBuffer(*stream, StreamBuffer(buf2->clone(), 0, true)),
      QuicTransportException);
}

TEST_F(QuicStreamFunctionsTest, TestInvalidExistingEOFWithCompleteOverlap) {
  auto stream = conn.streamManager->createNextBidirectionalStream().value();
  auto buf1 = IOBuf::copyBuffer("just");
  auto buf2 = IOBuf::copyBuffer("I just met");

  appendDataToReadBuffer(*stream, StreamBuffer(buf1->clone(), 2, true));
  EXPECT_THROW(
      appendDataToReadBuffer(*stream, StreamBuffer(buf2->clone(), 0)),
      QuicTransportException);
}

TEST_F(QuicStreamFunctionsTest, TestInvalidExistingEOFNotLastBuffer) {
  auto stream = conn.streamManager->createNextBidirectionalStream().value();

  auto buf1 = IOBuf::copyBuffer("just met");
  auto buf2 = IOBuf::copyBuffer("you");
  auto buf3 = IOBuf::copyBuffer("I just");

  appendDataToReadBuffer(*stream, StreamBuffer(buf1->clone(), 2));
  appendDataToReadBuffer(*stream, StreamBuffer(buf2->clone(), 11));
  EXPECT_THROW(
      appendDataToReadBuffer(*stream, StreamBuffer(buf3->clone(), 0, true)),
      QuicTransportException);
}

TEST_F(QuicStreamFunctionsTest, TestInvalidExistingEOFRightOverlap) {
  auto stream = conn.streamManager->createNextBidirectionalStream().value();

  auto buf1 = IOBuf::copyBuffer("just met");
  auto buf2 = IOBuf::copyBuffer("met you");

  appendDataToReadBuffer(*stream, StreamBuffer(buf1->clone(), 2, true));
  EXPECT_THROW(
      appendDataToReadBuffer(*stream, StreamBuffer(buf2->clone(), 7, true)),
      QuicTransportException);
}

TEST_F(QuicStreamFunctionsTest, TestInvalidExistingEOFRightOverlapNotLast) {
  auto stream = conn.streamManager->createNextBidirectionalStream().value();

  auto buf1 = IOBuf::copyBuffer("just met");
  auto buf2 = IOBuf::copyBuffer("this is");
  auto buf3 = IOBuf::copyBuffer("met you");

  appendDataToReadBuffer(*stream, StreamBuffer(buf1->clone(), 2));
  appendDataToReadBuffer(*stream, StreamBuffer(buf1->clone(), 16));
  EXPECT_THROW(
      appendDataToReadBuffer(*stream, StreamBuffer(buf3->clone(), 7, true)),
      QuicTransportException);
}

TEST_F(QuicStreamFunctionsTest, SetInvalidMaxStreams) {
  conn.streamManager->setMaxLocalBidirectionalStreams(100, true);
  conn.streamManager->setMaxLocalUnidirectionalStreams(100, true);
  conn.streamManager->setMaxLocalBidirectionalStreams(0);
  conn.streamManager->setMaxLocalUnidirectionalStreams(0);
  EXPECT_EQ(conn.streamManager->openableLocalBidirectionalStreams(), 100);
  EXPECT_EQ(conn.streamManager->openableLocalUnidirectionalStreams(), 100);
  EXPECT_THROW(
      conn.streamManager->setMaxLocalBidirectionalStreams(kMaxMaxStreams + 1),
      QuicTransportException);
  EXPECT_THROW(
      conn.streamManager->setMaxLocalUnidirectionalStreams(kMaxMaxStreams + 1),
      QuicTransportException);
}

TEST_F(QuicStreamFunctionsTest, GetOrCreateClientCryptoStream) {
  EXPECT_NE(conn.cryptoState, nullptr);
}

TEST_F(QuicServerStreamFunctionsTest, GetOrCreateClientOutOfOrderStream) {
  StreamId outOfOrderStream = 100;
  StreamId existingStream = 88;
  StreamId closedStream = 84;
  conn.streamManager->getStream(outOfOrderStream);

  EXPECT_EQ(conn.streamManager->streamCount(), 1);
  EXPECT_TRUE(conn.streamManager->streamExists(outOfOrderStream));
  // peer stream starts from 0x00
  EXPECT_EQ(
      conn.streamManager->openBidirectionalPeerStreams().size(),
      ((outOfOrderStream) / kStreamIncrement) + 1);

  conn.streamManager->getStream(existingStream);
  EXPECT_EQ(conn.streamManager->streamCount(), 2);
  EXPECT_TRUE(conn.streamManager->streamExists(outOfOrderStream));
  EXPECT_EQ(
      conn.streamManager->openBidirectionalPeerStreams().size(),
      ((outOfOrderStream) / kStreamIncrement) + 1);

  conn.streamManager->openBidirectionalPeerStreams().erase(std::find(
      conn.streamManager->openBidirectionalPeerStreams().begin(),
      conn.streamManager->openBidirectionalPeerStreams().end(),
      closedStream));
  EXPECT_EQ(conn.streamManager->getStream(closedStream), nullptr);
}

TEST_F(QuicServerStreamFunctionsTest, GetOrCreateExistingClientStream) {
  StreamId outOfOrderStream1 = 100;
  StreamId outOfOrderStream2 = 48;

  auto stream = conn.streamManager->getStream(outOfOrderStream1);
  auto stream2 = conn.streamManager->getStream(outOfOrderStream1);
  EXPECT_EQ(stream, stream2);
  conn.streamManager->getStream(outOfOrderStream2);
}

TEST_F(QuicStreamFunctionsTest, GetOrCreateExistingServerStream) {
  StreamId outOfOrderStream1 = 101;
  StreamId outOfOrderStream2 = 49;
  auto stream = conn.streamManager->getStream(outOfOrderStream1);
  auto stream2 = conn.streamManager->getStream(outOfOrderStream1);
  EXPECT_EQ(stream, stream2);
  conn.streamManager->getStream(outOfOrderStream2);
}

TEST_F(QuicServerStreamFunctionsTest, GetOrCreateClosedClientStream) {
  StreamId outOfOrderStream1 = 100;
  StreamId closedStream = 48;
  conn.streamManager->getStream(outOfOrderStream1);
  conn.streamManager->openBidirectionalPeerStreams().erase(std::find(
      conn.streamManager->openBidirectionalPeerStreams().begin(),
      conn.streamManager->openBidirectionalPeerStreams().end(),
      closedStream));
  EXPECT_EQ(conn.streamManager->getStream(closedStream), nullptr);
}

TEST_F(
    QuicServerStreamFunctionsTest,
    GetOrCreateClientStreamAfterClosingLastStream) {
  StreamId outOfOrderStream1 = 96;
  StreamId outOfOrderStream2 = 100;
  conn.streamManager->getStream(outOfOrderStream1);
  conn.streamManager->openBidirectionalPeerStreams().erase(std::find(
      conn.streamManager->openBidirectionalPeerStreams().begin(),
      conn.streamManager->openBidirectionalPeerStreams().end(),
      outOfOrderStream1));
  conn.streamManager->getStream(outOfOrderStream2);
  EXPECT_EQ(
      conn.streamManager->openBidirectionalPeerStreams().size(),
      (outOfOrderStream2) / kStreamIncrement);
}

TEST_F(QuicStreamFunctionsTest, GetOrCreateServerStreamAfterClosingLastStream) {
  StreamId outOfOrderStream1 = 97;
  StreamId outOfOrderStream2 = 101;
  conn.streamManager->getStream(outOfOrderStream1);
  conn.streamManager->openBidirectionalPeerStreams().erase(std::find(
      conn.streamManager->openBidirectionalPeerStreams().begin(),
      conn.streamManager->openBidirectionalPeerStreams().end(),
      outOfOrderStream1));
  conn.streamManager->getStream(outOfOrderStream2);
  EXPECT_EQ(
      conn.streamManager->openBidirectionalPeerStreams().size(),
      (outOfOrderStream2 + 1) / kStreamIncrement);
}

TEST_F(QuicStreamFunctionsTest, GetOrCreateClosedServerStream) {
  StreamId outOfOrderStream1 = 97;
  StreamId closedStream = 49;
  conn.streamManager->getStream(outOfOrderStream1);
  conn.streamManager->openBidirectionalPeerStreams().erase(std::find(
      conn.streamManager->openBidirectionalPeerStreams().begin(),
      conn.streamManager->openBidirectionalPeerStreams().end(),
      closedStream));
  EXPECT_EQ(conn.streamManager->getStream(closedStream), nullptr);
}

TEST_F(QuicServerStreamFunctionsTest, GetOrCreateServerStreamOnServer) {
  StreamId serverStream = 101;
  EXPECT_THROW(
      conn.streamManager->getStream(serverStream), QuicTransportException);
}

TEST_F(QuicStreamFunctionsTest, GetOrCreateClientStreamOnClient) {
  StreamId clientStream = 100;
  EXPECT_THROW(
      conn.streamManager->getStream(clientStream), QuicTransportException);
}

TEST_F(QuicStreamFunctionsTest, GetOrCreateNonClientOrServer) {
  StreamId streamZero = 0;
  EXPECT_THROW(
      conn.streamManager->getStream(streamZero), QuicTransportException);
}

TEST_F(QuicServerStreamFunctionsTest, CreateQuicStreamServerOutOfOrder) {
  StreamId outOfOrderStream1 = 101;
  StreamId outOfOrderStream2 = 49;
  conn.streamManager->createStream(outOfOrderStream1).value();
  EXPECT_EQ(conn.streamManager->streamCount(), 1);
  EXPECT_EQ(
      conn.streamManager->openUnidirectionalLocalStreams().size() +
          conn.streamManager->openBidirectionalLocalStreams().size(),
      26);
  conn.streamManager->createStream(outOfOrderStream2).value();
  EXPECT_EQ(conn.streamManager->streamCount(), 2);
  EXPECT_EQ(
      conn.streamManager->openUnidirectionalLocalStreams().size() +
          conn.streamManager->openBidirectionalLocalStreams().size(),
      26);
}

TEST_F(QuicStreamFunctionsTest, CreateQuicStreamClientOutOfOrder) {
  StreamId outOfOrderStream1 = 96;
  StreamId outOfOrderStream2 = 48;
  conn.streamManager->createStream(outOfOrderStream1);
  EXPECT_EQ(conn.streamManager->streamCount(), 1);
  EXPECT_EQ(
      conn.streamManager->openUnidirectionalLocalStreams().size() +
          conn.streamManager->openBidirectionalLocalStreams().size(),
      25);
  conn.streamManager->createStream(outOfOrderStream2).value();
  EXPECT_EQ(conn.streamManager->streamCount(), 2);
  EXPECT_EQ(
      conn.streamManager->openUnidirectionalLocalStreams().size() +
          conn.streamManager->openBidirectionalLocalStreams().size(),
      25);
}

TEST_F(QuicServerStreamFunctionsTest, CreateClosedServerStream) {
  StreamId outOfOrderStream1 = 101;
  StreamId outOfOrderStream2 = 49;
  conn.streamManager->createStream(outOfOrderStream1);
  conn.streamManager->openBidirectionalLocalStreams().erase(std::find(
      conn.streamManager->openBidirectionalLocalStreams().begin(),
      conn.streamManager->openBidirectionalLocalStreams().end(),
      outOfOrderStream2));
  EXPECT_FALSE(conn.streamManager->createStream(outOfOrderStream2));
}

TEST_F(QuicStreamFunctionsTest, CreateClosedClientStream) {
  StreamId outOfOrderStream1 = 96;
  StreamId outOfOrderStream2 = 48;
  conn.streamManager->createStream(outOfOrderStream1).value();
  conn.streamManager->openBidirectionalLocalStreams().erase(std::find(
      conn.streamManager->openBidirectionalLocalStreams().begin(),
      conn.streamManager->openBidirectionalLocalStreams().end(),
      outOfOrderStream2));
  EXPECT_FALSE(conn.streamManager->createStream(outOfOrderStream2));
}

TEST_F(QuicStreamFunctionsTest, CreateInvalidServerStreamOnClient) {
  StreamId serverStream = 0x09;
  EXPECT_THROW(
      conn.streamManager->createStream(serverStream), QuicTransportException);
}

TEST_F(QuicServerStreamFunctionsTest, CreateInvalidClientStreamOnServer) {
  StreamId clientStream = 0x04;
  EXPECT_THROW(
      conn.streamManager->createStream(clientStream), QuicTransportException);
}

TEST_F(QuicStreamFunctionsTest, CreateAlreadyExistingStream) {
  StreamId stream = 0x08;
  conn.streamManager->createStream(stream).value();
  EXPECT_THROW(
      conn.streamManager->createStream(stream), QuicTransportException);
}

TEST_F(QuicStreamFunctionsTest, IsClientStream) {
  EXPECT_TRUE(isClientStream(0));
  EXPECT_TRUE(isClientStream(0x04));
  EXPECT_TRUE(isClientStream(104));
  EXPECT_TRUE(isClientStream(0x08));
  EXPECT_FALSE(isClientStream(0x01));
  EXPECT_FALSE(isClientStream(0x07));
  EXPECT_FALSE(isClientStream(0x11));
}

TEST_F(QuicStreamFunctionsTest, IsServerStream) {
  EXPECT_TRUE(isServerStream(0x05));
  EXPECT_TRUE(isServerStream(105));
  EXPECT_TRUE(isServerStream(0x25));
  EXPECT_FALSE(isServerStream(0x02));
  EXPECT_FALSE(isServerStream(0x04));
  EXPECT_FALSE(isServerStream(0));
}

TEST_F(QuicStreamFunctionsTest, IsUnidirectionalStream) {
  EXPECT_TRUE(isUnidirectionalStream(0x02));
  EXPECT_TRUE(isUnidirectionalStream(0x03));
  EXPECT_TRUE(isUnidirectionalStream(0xff));
  EXPECT_FALSE(isUnidirectionalStream(0x01));
  EXPECT_FALSE(isUnidirectionalStream(0xf0));
  EXPECT_FALSE(isUnidirectionalStream(0xf1));
}

TEST_F(QuicStreamFunctionsTest, IsBidirectionalStream) {
  EXPECT_TRUE(isBidirectionalStream(0x01));
  EXPECT_TRUE(isBidirectionalStream(0xf0));
  EXPECT_TRUE(isBidirectionalStream(0xf1));
  EXPECT_FALSE(isBidirectionalStream(0x02));
  EXPECT_FALSE(isBidirectionalStream(0x03));
  EXPECT_FALSE(isBidirectionalStream(0xff));
}

TEST_F(QuicStreamFunctionsTest, IsServerUnidirectionalStream) {
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

TEST_F(QuicStreamFunctionsTest, IsClientBidirectionalStream) {
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

TEST_F(QuicStreamFunctionsTest, GetStreamDirectionality) {
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

TEST_F(QuicStreamFunctionsTest, IsSendingStream) {
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

TEST_F(QuicStreamFunctionsTest, IsReceivingStream) {
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

TEST_F(QuicStreamFunctionsTest, GetStreamInitiatorBidirectional) {
  const auto clientStream1Id =
      conn.streamManager->createNextBidirectionalStream().value()->id;
  EXPECT_EQ(conn.streamManager->streamCount(), 1);
  const auto clientStream2Id =
      conn.streamManager->createNextBidirectionalStream().value()->id;
  EXPECT_EQ(conn.streamManager->streamCount(), 2);
  EXPECT_EQ(clientStream1Id, 0x00);
  EXPECT_EQ(clientStream2Id, 0x04);

  const auto serverStream1Id =
      CHECK_NOTNULL(conn.streamManager->getStream(clientStream1Id + 1))->id;
  const auto serverStream2Id =
      CHECK_NOTNULL(conn.streamManager->getStream(clientStream2Id + 1))->id;

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
      CHECK_NOTNULL(conn.streamManager->getStream(serverStream1Id - 1))->id;
  const auto clientStream2Id =
      CHECK_NOTNULL(conn.streamManager->getStream(serverStream2Id - 1))->id;

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

TEST_F(QuicStreamFunctionsTest, GetStreamInitiatorUnidirectional) {
  const auto clientStream1Id =
      conn.streamManager->createNextUnidirectionalStream().value()->id;
  EXPECT_EQ(conn.streamManager->streamCount(), 1);
  const auto clientStream2Id =
      conn.streamManager->createNextUnidirectionalStream().value()->id;
  EXPECT_EQ(conn.streamManager->streamCount(), 2);
  EXPECT_EQ(clientStream1Id, 0x02);
  EXPECT_EQ(clientStream2Id, 0x06);

  const auto serverStream1Id =
      CHECK_NOTNULL(conn.streamManager->getStream(clientStream1Id + 1))->id;
  const auto serverStream2Id =
      CHECK_NOTNULL(conn.streamManager->getStream(clientStream2Id + 1))->id;

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
      CHECK_NOTNULL(conn.streamManager->getStream(serverStream1Id - 1))->id;
  const auto clientStream2Id =
      CHECK_NOTNULL(conn.streamManager->getStream(serverStream2Id - 1))->id;

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

TEST_F(QuicStreamFunctionsTest, HasReadableDataNoData) {
  auto stream = conn.streamManager->createNextBidirectionalStream().value();
  auto buf1 = IOBuf::copyBuffer("just");
  auto buf2 = IOBuf::copyBuffer("I ");

  appendDataToReadBuffer(*stream, StreamBuffer(buf1->clone(), 2));
  EXPECT_FALSE(stream->hasReadableData());
}

TEST_F(QuicStreamFunctionsTest, HasReadableDataNoDataInBuf) {
  auto stream = conn.streamManager->createNextBidirectionalStream().value();
  EXPECT_FALSE(stream->hasReadableData());
}

TEST_F(QuicStreamFunctionsTest, HasReadableDataEofInBuf) {
  auto stream = conn.streamManager->createNextBidirectionalStream().value();

  appendDataToReadBuffer(*stream, StreamBuffer(nullptr, 1, true));
  EXPECT_FALSE(stream->hasReadableData());
  appendDataToReadBuffer(*stream, StreamBuffer(IOBuf::copyBuffer("1"), 0));
  EXPECT_TRUE(stream->hasReadableData());
  auto read1 = readDataFromQuicStream(*stream, 1);
  EXPECT_TRUE(read1.second);
  EXPECT_FALSE(stream->hasReadableData());
  auto read2 = readDataFromQuicStream(*stream, 1);
  EXPECT_TRUE(read2.second);
}

TEST_F(QuicStreamFunctionsTest, HasReadableDataEofInEmptyBuf) {
  auto stream = conn.streamManager->createNextBidirectionalStream().value();

  appendDataToReadBuffer(*stream, StreamBuffer(nullptr, 0, true));
  EXPECT_TRUE(stream->hasReadableData());
  auto read1 = readDataFromQuicStream(*stream, 1);
  EXPECT_TRUE(read1.second);
  EXPECT_FALSE(stream->hasReadableData());
  auto read2 = readDataFromQuicStream(*stream, 1);
  EXPECT_TRUE(read2.second);
}

TEST_F(QuicStreamFunctionsTest, HasReadableDataOnlyEof) {
  auto stream = conn.streamManager->createNextBidirectionalStream().value();
  appendDataToReadBuffer(*stream, StreamBuffer(nullptr, 0, true));
  EXPECT_TRUE(stream->hasReadableData());
}

TEST_F(QuicStreamFunctionsTest, HasReadableData) {
  auto stream = conn.streamManager->createNextBidirectionalStream().value();
  auto buf1 = IOBuf::copyBuffer("I ");
  auto buf2 = IOBuf::copyBuffer("met");
  appendDataToReadBuffer(*stream, StreamBuffer(buf1->clone(), 0));
  appendDataToReadBuffer(*stream, StreamBuffer(buf2->clone(), 7));
  EXPECT_TRUE(stream->hasReadableData());

  readDataFromQuicStream(*stream);
  EXPECT_FALSE(stream->hasReadableData());

  auto buf3 = IOBuf::copyBuffer("just ");
  appendDataToReadBuffer(*stream, StreamBuffer(buf3->clone(), 2));
  EXPECT_TRUE(stream->hasReadableData());
  readDataFromQuicStream(*stream, 5);
  EXPECT_TRUE(stream->hasReadableData());
  readDataFromQuicStream(*stream);
  EXPECT_FALSE(stream->hasReadableData());
}

TEST_F(QuicStreamFunctionsTest, HasPeekableDataGappedData) {
  auto stream = conn.streamManager->createNextBidirectionalStream().value();
  auto buf1 = IOBuf::copyBuffer("just");
  auto buf2 = IOBuf::copyBuffer("I ");

  appendDataToReadBuffer(*stream, StreamBuffer(buf1->clone(), 2));
  EXPECT_TRUE(stream->hasPeekableData());
}

TEST_F(QuicStreamFunctionsTest, HasPeekableDataNoDataInBuf) {
  auto stream = conn.streamManager->createNextBidirectionalStream().value();
  EXPECT_FALSE(stream->hasPeekableData());
}

TEST_F(QuicStreamFunctionsTest, HasPeekableDataEofInBuf) {
  auto stream = conn.streamManager->createNextBidirectionalStream().value();

  appendDataToReadBuffer(*stream, StreamBuffer(nullptr, 1, true));
  EXPECT_FALSE(stream->hasPeekableData());
  appendDataToReadBuffer(*stream, StreamBuffer(IOBuf::copyBuffer("1"), 0));
  EXPECT_TRUE(stream->hasPeekableData());
  auto read1 = readDataFromQuicStream(*stream, 1);
  EXPECT_TRUE(read1.second);
  EXPECT_FALSE(stream->hasPeekableData());
  auto read2 = readDataFromQuicStream(*stream, 1);
  EXPECT_TRUE(read2.second);
}

TEST_F(QuicStreamFunctionsTest, HasPeekableDataEofInEmptyBuf) {
  auto stream = conn.streamManager->createNextBidirectionalStream().value();

  appendDataToReadBuffer(*stream, StreamBuffer(nullptr, 0, true));
  EXPECT_FALSE(stream->hasPeekableData());
  auto read1 = readDataFromQuicStream(*stream, 1);
  EXPECT_TRUE(read1.second);
  EXPECT_FALSE(stream->hasPeekableData());
  auto read2 = readDataFromQuicStream(*stream, 1);
  EXPECT_TRUE(read2.second);
}

TEST_F(QuicStreamFunctionsTest, HasPeekableDataOnlyEof) {
  auto stream = conn.streamManager->createNextBidirectionalStream().value();
  appendDataToReadBuffer(*stream, StreamBuffer(nullptr, 0, true));
  EXPECT_FALSE(stream->hasPeekableData());
}

TEST_F(QuicStreamFunctionsTest, HasPeekableData) {
  auto stream = conn.streamManager->createNextBidirectionalStream().value();
  auto buf1 = IOBuf::copyBuffer("I ");
  auto buf2 = IOBuf::copyBuffer("met");
  appendDataToReadBuffer(*stream, StreamBuffer(buf1->clone(), 0));
  appendDataToReadBuffer(*stream, StreamBuffer(buf2->clone(), 7));
  EXPECT_TRUE(stream->hasPeekableData());

  readDataFromQuicStream(*stream);
  EXPECT_TRUE(stream->hasPeekableData());

  auto buf3 = IOBuf::copyBuffer("just ");
  appendDataToReadBuffer(*stream, StreamBuffer(buf3->clone(), 2));
  EXPECT_TRUE(stream->hasPeekableData());
  readDataFromQuicStream(*stream, 5);
  EXPECT_TRUE(stream->hasPeekableData());
  readDataFromQuicStream(*stream);
  EXPECT_FALSE(stream->hasPeekableData());
}

TEST_F(QuicStreamFunctionsTest, UpdatesLastHolbTime) {
  auto stream = conn.streamManager->createNextBidirectionalStream().value();
  auto buf1 = IOBuf::copyBuffer("just");
  auto buf2 = IOBuf::copyBuffer("I ");

  appendDataToReadBuffer(*stream, StreamBuffer(buf1->clone(), 2));
  // Should not be HOL blocked before data has arrived
  EXPECT_FALSE(stream->lastHolbTime);
  readDataFromQuicStream(*stream);
  // Should be HOL blocked
  EXPECT_TRUE(stream->lastHolbTime);
}

TEST_F(QuicStreamFunctionsTest, HolbTimingUpdateReadingListIdempotentWrtHolb) {
  // test that calling uRL in succession (without new data or readsd)
  // does not affect the HOLB state
  auto stream = conn.streamManager->createNextBidirectionalStream().value();
  auto buf1 = IOBuf::copyBuffer("just");
  auto buf2 = IOBuf::copyBuffer("I ");
  auto buf3 = IOBuf::copyBuffer("you");
  auto buf4 = IOBuf::copyBuffer(" met ");

  appendDataToReadBuffer(*stream, StreamBuffer(buf1->clone(), 2));
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

  // uRL 0.1 - expected state transition: none
  conn.streamManager->updateReadableStreams(*stream);

  EXPECT_EQ(lastHolbTimeMark, stream->lastHolbTime);
  EXPECT_EQ(0us, stream->totalHolbTime);
  EXPECT_EQ(1, stream->holbCount);

  appendDataToReadBuffer(*stream, StreamBuffer(buf2->clone(), 0));

  // uRL 1.0 - expected state transition:
  //   HOLB in progress -> !HOLB && holbCount == 1
  conn.streamManager->updateReadableStreams(*stream);
  auto totalHolbTimeMark = stream->totalHolbTime;

  // HOLB state must be cleared by buf2, and total time should be available
  EXPECT_FALSE(stream->lastHolbTime);
  EXPECT_EQ(1, stream->holbCount);

  // uRL 1.1 - expected state transition: none
  conn.streamManager->updateReadableStreams(*stream);
  EXPECT_FALSE(stream->lastHolbTime);
  EXPECT_EQ(totalHolbTimeMark, stream->totalHolbTime);

  appendDataToReadBuffer(*stream, StreamBuffer(buf3->clone(), 11));

  // uRL 2.0 - expected state transition:
  // !HOLB && holbCount == 1
  //   => !HOLB && totalTime == totalTimeMark
  // NOTE: the stream is not HOLB since the reading cursor is not
  // at the hole
  conn.streamManager->updateReadableStreams(*stream);
  EXPECT_FALSE(stream->lastHolbTime);
  EXPECT_EQ(totalHolbTimeMark, stream->totalHolbTime);
  EXPECT_EQ(1, stream->holbCount);

  // uRL 2.1 - expected state transition: none
  conn.streamManager->updateReadableStreams(*stream);
  EXPECT_FALSE(stream->lastHolbTime);
  EXPECT_EQ(totalHolbTimeMark, stream->totalHolbTime);

  // uRL 3.0 - expected state transition:
  // !HOLB && totalTime == totalTimeMark
  //   => HOLB && holbCount == 2
  //       && totalHolbTime == totalTimeMark
  readDataFromQuicStream(*stream);
  EXPECT_TRUE(stream->lastHolbTime);
  EXPECT_EQ(2, stream->holbCount);
  EXPECT_EQ(totalHolbTimeMark, stream->totalHolbTime);
  auto lastHolbTimeMark2 = stream->lastHolbTime;

  // uRL 3.1 - expected state transition: none
  conn.streamManager->updateReadableStreams(*stream);
  EXPECT_EQ(lastHolbTimeMark2, stream->lastHolbTime);
  EXPECT_EQ(totalHolbTimeMark, stream->totalHolbTime);
  EXPECT_EQ(2, stream->holbCount);

  // uRL 4.0 - add the rest of the data to the stream.
  // HOLB && holbCount == 2
  //     && totalTime == totalTimeMark
  // => !HOLB && holbCount == 2
  appendDataToReadBuffer(*stream, StreamBuffer(buf4->clone(), 6));
  conn.streamManager->updateReadableStreams(*stream);
  EXPECT_FALSE(stream->lastHolbTime);
  EXPECT_EQ(2, stream->holbCount);

  // uRL 4.1 - read the entire stream - expected state transition:
  // !HOLB && holbCount == 2
  // => !HOLB && holbCount == 2
  readDataFromQuicStream(*stream);
  EXPECT_FALSE(stream->lastHolbTime);
  EXPECT_EQ(2, stream->holbCount);

  // uRL 4.1 - expected state change: none
  conn.streamManager->updateReadableStreams(*stream);
  EXPECT_FALSE(stream->lastHolbTime);
  EXPECT_EQ(2, stream->holbCount);
}

TEST_F(QuicStreamFunctionsTest, HolbTimingFirstBufferHOLBlocked) {
  auto stream = conn.streamManager->createNextBidirectionalStream().value();
  auto buf1 = IOBuf::copyBuffer("just");
  auto buf2 = IOBuf::copyBuffer("I ");

  appendDataToReadBuffer(*stream, StreamBuffer(buf1->clone(), 2));
  // Should not be HOL blocked until the readable list has been updated
  EXPECT_FALSE(stream->lastHolbTime);

  conn.streamManager->updateReadableStreams(*stream);
  // HOLB state must be detected after the first readable list update
  EXPECT_TRUE(stream->lastHolbTime);
  EXPECT_EQ(1, stream->holbCount);
  EXPECT_EQ(0us, stream->totalHolbTime);
  auto lastHolbTimeMark = stream->lastHolbTime;

  readDataFromQuicStream(*stream);
  // Read data should fail since there is no data available at
  // the reading cursor
  EXPECT_EQ(lastHolbTimeMark, stream->lastHolbTime);
  EXPECT_TRUE(stream->lastHolbTime);
  EXPECT_EQ(1, stream->holbCount);

  appendDataToReadBuffer(*stream, StreamBuffer(buf2->clone(), 0));
  conn.streamManager->updateReadableStreams(*stream);
  // HOLB state must be cleared by buf2, and total time should be available

  EXPECT_FALSE(stream->lastHolbTime);
  EXPECT_EQ(1, stream->holbCount);
}

TEST_F(QuicStreamFunctionsTest, HolbTimingReadingEntireStream) {
  auto stream = conn.streamManager->createNextBidirectionalStream().value();
  auto buf1 = IOBuf::copyBuffer("just");
  auto buf2 = IOBuf::copyBuffer("I ");

  appendDataToReadBuffer(*stream, StreamBuffer(buf1->clone(), 2));
  conn.streamManager->updateReadableStreams(*stream);
  EXPECT_TRUE(stream->lastHolbTime);
  EXPECT_EQ(1, stream->holbCount);

  appendDataToReadBuffer(*stream, StreamBuffer(buf2->clone(), 0));
  conn.streamManager->updateReadableStreams(*stream);
  // HOLB state must be cleared by buf2, and total time should be available
  EXPECT_FALSE(stream->lastHolbTime);
  EXPECT_EQ(1, stream->holbCount);

  // Consume the entire stream. This should not change the holb status
  readDataFromQuicStream(*stream);
  EXPECT_FALSE(stream->lastHolbTime);
  EXPECT_EQ(1, stream->holbCount);
}

TEST_F(QuicStreamFunctionsTest, HolbTimingLockstepScenario) {
  auto stream = conn.streamManager->createNextBidirectionalStream().value();
  auto buf1 = IOBuf::copyBuffer("just");
  auto buf2 = IOBuf::copyBuffer("I ");
  auto buf3 = IOBuf::copyBuffer("met you ");
  auto buf4 = IOBuf::copyBuffer("and this is crazy");

  appendDataToReadBuffer(*stream, StreamBuffer(buf1->clone(), 2));
  // Should not be HOL blocked before data has arrived
  EXPECT_FALSE(stream->lastHolbTime);

  readDataFromQuicStream(*stream);
  // Should be HOL blocked now
  EXPECT_TRUE(stream->lastHolbTime);
  EXPECT_EQ(1, stream->holbCount);

  // At this point, the stream has not been unblocked even once,
  // hence the total holb time is expected to be zero
  EXPECT_EQ(0us, stream->totalHolbTime);

  // Data has arrived
  appendDataToReadBuffer(*stream, StreamBuffer(buf2->clone(), 0));
  appendDataToReadBuffer(*stream, StreamBuffer(buf4->clone(), 15));

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
  readDataFromQuicStream(*stream);

  // Should be HOL blocked at missing buf3.
  EXPECT_TRUE(stream->lastHolbTime);
  EXPECT_EQ(2, stream->holbCount);
  // The total HOLB time shouldn't have changed since the last update
  EXPECT_EQ(snapshotHolbTime, stream->totalHolbTime);

  appendDataToReadBuffer(*stream, StreamBuffer(buf3->clone(), 6));
  conn.streamManager->updateReadableStreams(*stream);

  // Should be not HOLB
  EXPECT_FALSE(stream->lastHolbTime);
  EXPECT_EQ(2, stream->holbCount);
}

TEST_F(QuicStreamFunctionsTest, HolbTimingReadDataCallsUpdateRL) {
  auto stream = conn.streamManager->createNextBidirectionalStream().value();
  auto buf1 = IOBuf::copyBuffer("just");
  auto buf2 = IOBuf::copyBuffer("I ");

  appendDataToReadBuffer(*stream, StreamBuffer(buf1->clone(), 2));
  readDataFromQuicStream(*stream);
  // Should be HOL blocked
  EXPECT_TRUE(stream->lastHolbTime);
  EXPECT_EQ(1, stream->holbCount);

  appendDataToReadBuffer(*stream, StreamBuffer(buf2->clone(), 0));
  readDataFromQuicStream(*stream);
  EXPECT_FALSE(stream->lastHolbTime);
  EXPECT_EQ(1, stream->holbCount);
}

TEST_F(QuicStreamFunctionsTest, RemovedClosedState) {
  auto stream = conn.streamManager->createNextBidirectionalStream().value();
  auto streamId = stream->id;
  conn.streamManager->readableStreams().emplace(streamId);
  conn.streamManager->peekableStreams().emplace(streamId);
  writeDataToQuicStream(*stream, folly::IOBuf::copyBuffer("write data"), true);
  conn.streamManager->addWritable(*stream);
  conn.streamManager->queueBlocked(streamId, 0);
  conn.streamManager->addDeliverable(streamId);
  conn.streamManager->addLoss(streamId);
  conn.streamManager->queueWindowUpdate(streamId);
  conn.streamManager->addStopSending(
      streamId, GenericApplicationErrorCode::UNKNOWN);
  conn.streamManager->queueFlowControlUpdated(streamId);
  stream->sendState = StreamSendState::Closed;
  stream->recvState = StreamRecvState::Closed;
  conn.streamManager->removeClosedStream(streamId);
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
  EXPECT_EQ(conn.streamManager->getStream(clientStream)->id, clientStream);
  EXPECT_EQ(conn.streamManager->streamCount(), 1);
  EXPECT_EQ(conn.streamManager->openBidirectionalPeerStreams().size(), 5);
  EXPECT_EQ(conn.streamManager->newPeerStreams(), newStreams);

  StreamId clientStream2 = 0x4;
  EXPECT_EQ(conn.streamManager->getStream(clientStream2)->id, clientStream2);
  EXPECT_EQ(conn.streamManager->streamCount(), 2);
  EXPECT_EQ(conn.streamManager->openBidirectionalPeerStreams().size(), 5);
  EXPECT_EQ(conn.streamManager->newPeerStreams().size(), 5);
  EXPECT_EQ(conn.streamManager->newPeerStreams(), newStreams);

  StreamId clientStream3 = 0x6;
  newStreams = {0x0, 0x2, 0x4, 0x6, 0x8, 0xc, 0x10};
  EXPECT_EQ(conn.streamManager->getStream(clientStream3)->id, clientStream3);
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
  EXPECT_EQ(conn.streamManager->getStream(serverStream)->id, serverStream);
  EXPECT_EQ(conn.streamManager->streamCount(), 1);
  EXPECT_EQ(
      conn.streamManager->openUnidirectionalLocalStreams().size() +
          conn.streamManager->openBidirectionalLocalStreams().size(),
      3);

  StreamId serverStream2 = 0x05;
  EXPECT_EQ(conn.streamManager->getStream(serverStream2)->id, serverStream2);
  EXPECT_EQ(conn.streamManager->streamCount(), 2);
  EXPECT_EQ(
      conn.streamManager->openUnidirectionalLocalStreams().size() +
          conn.streamManager->openBidirectionalLocalStreams().size(),
      3);

  StreamId serverStream3 = 0x0D;
  EXPECT_THROW(
      conn.streamManager->getStream(serverStream3), QuicTransportException);
}

TEST_F(QuicServerStreamFunctionsTest, ServerGetBothDirections) {
  StreamId serverBiStream = 0x09;
  conn.streamManager->createStream(serverBiStream).value();
  EXPECT_EQ(conn.streamManager->getStream(serverBiStream)->id, serverBiStream);
  EXPECT_EQ(conn.streamManager->streamCount(), 1);
  EXPECT_EQ(
      conn.streamManager->openUnidirectionalLocalStreams().size() +
          conn.streamManager->openBidirectionalLocalStreams().size(),
      3);

  StreamId serverUniStream = 0x0B;
  conn.streamManager->createStream(serverUniStream).value();
  EXPECT_EQ(
      conn.streamManager->getStream(serverUniStream)->id, serverUniStream);
  EXPECT_EQ(conn.streamManager->streamCount(), 2);
  EXPECT_EQ(
      conn.streamManager->openUnidirectionalLocalStreams().size() +
          conn.streamManager->openBidirectionalLocalStreams().size(),
      6);
}

TEST_F(QuicServerStreamFunctionsTest, ServerGetCloseBothDirections) {
  StreamId serverBiStream = 0x09;
  conn.streamManager->createStream(serverBiStream).value();
  EXPECT_EQ(conn.streamManager->getStream(serverBiStream)->id, serverBiStream);
  StreamId serverUniStream = 0x0B;
  auto stream = conn.streamManager->createStream(serverUniStream).value();
  stream->sendState = StreamSendState::Closed;

  conn.streamManager->removeClosedStream(serverUniStream);
  EXPECT_TRUE(
      conn.streamManager->getStream(serverUniStream - kStreamIncrement));
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
  conn.streamManager->createStream(serverStream).value();
  EXPECT_EQ(conn.streamManager->getStream(serverStream)->id, serverStream);
  EXPECT_EQ(conn.streamManager->streamCount(), 1);
  EXPECT_EQ(
      conn.streamManager->openUnidirectionalLocalStreams().size() +
          conn.streamManager->openBidirectionalLocalStreams().size(),
      4);

  StreamId serverStream2 = 0x0B;
  EXPECT_EQ(conn.streamManager->getStream(serverStream2)->id, serverStream2);
  EXPECT_EQ(conn.streamManager->streamCount(), 2);
  EXPECT_EQ(
      conn.streamManager->openUnidirectionalLocalStreams().size() +
          conn.streamManager->openBidirectionalLocalStreams().size(),
      4);

  StreamId serverStream3 = 0x1F;
  EXPECT_THROW(
      conn.streamManager->getStream(serverStream3), QuicTransportException);
}

TEST_F(QuicStreamFunctionsTest, ClientGetServerQuicStream) {
  StreamId serverStream = 0x09;
  EXPECT_EQ(conn.streamManager->getStream(serverStream)->id, serverStream);
  EXPECT_EQ(conn.streamManager->streamCount(), 1);
  EXPECT_EQ(conn.streamManager->openBidirectionalPeerStreams().size(), 3);

  StreamId serverStream2 = 0x05;
  EXPECT_EQ(conn.streamManager->getStream(serverStream2)->id, serverStream2);
  EXPECT_EQ(conn.streamManager->streamCount(), 2);
  EXPECT_EQ(conn.streamManager->openBidirectionalPeerStreams().size(), 3);
}

TEST_F(QuicStreamFunctionsTest, ClientGetClientQuicStream) {
  StreamId clientStream = 0x0C;
  conn.streamManager->createStream(clientStream).value();

  EXPECT_EQ(conn.streamManager->getStream(clientStream)->id, clientStream);
  EXPECT_EQ(conn.streamManager->streamCount(), 1);
  EXPECT_EQ(
      conn.streamManager->openUnidirectionalLocalStreams().size() +
          conn.streamManager->openBidirectionalLocalStreams().size(),
      4);

  StreamId clientStream2 = 0x08;
  EXPECT_EQ(conn.streamManager->getStream(clientStream2)->id, clientStream2);
  EXPECT_EQ(conn.streamManager->streamCount(), 2);
  EXPECT_EQ(
      conn.streamManager->openUnidirectionalLocalStreams().size() +
          conn.streamManager->openBidirectionalLocalStreams().size(),
      4);

  StreamId clientStream3 = 0x10;
  EXPECT_THROW(
      conn.streamManager->getStream(clientStream3), QuicTransportException);
}

TEST_F(QuicStreamFunctionsTest, StreamExists) {
  StreamId localStream = 12;
  StreamId peerStream = 13;

  StreamId localAutoOpened = 8;
  StreamId peerAutoOpened = 5;
  StreamId peerAutoOpened2 = 9;
  StreamId notOpenedLocal = 16;
  StreamId notOpenedPeer = 17;

  conn.streamManager->createStream(localStream).value();
  EXPECT_TRUE(conn.streamManager->streamExists(localStream));
  EXPECT_TRUE(conn.streamManager->streamExists(localAutoOpened));
  EXPECT_FALSE(conn.streamManager->streamExists(notOpenedLocal));
  EXPECT_FALSE(conn.streamManager->streamExists(notOpenedPeer));
  EXPECT_FALSE(conn.streamManager->streamExists(peerStream));
  EXPECT_FALSE(conn.streamManager->streamExists(peerAutoOpened));

  conn.streamManager->getStream(peerStream)->sendState =
      StreamSendState::Closed;
  conn.streamManager->getStream(peerStream)->recvState =
      StreamRecvState::Closed;
  EXPECT_TRUE(conn.streamManager->streamExists(localStream));
  EXPECT_TRUE(conn.streamManager->streamExists(localAutoOpened));
  EXPECT_FALSE(conn.streamManager->streamExists(notOpenedLocal));
  EXPECT_FALSE(conn.streamManager->streamExists(notOpenedPeer));
  EXPECT_TRUE(conn.streamManager->streamExists(peerStream));
  EXPECT_TRUE(conn.streamManager->streamExists(peerAutoOpened));

  auto it = std::find(
      conn.streamManager->openBidirectionalPeerStreams().begin(),
      conn.streamManager->openBidirectionalPeerStreams().end(),
      peerAutoOpened);
  conn.streamManager->openBidirectionalPeerStreams().erase(it);

  conn.streamManager->removeClosedStream(peerStream);

  EXPECT_FALSE(conn.streamManager->streamExists(peerAutoOpened));
  EXPECT_FALSE(conn.streamManager->streamExists(peerStream));
  EXPECT_TRUE(conn.streamManager->streamExists(peerAutoOpened2));
}

TEST_F(QuicStreamFunctionsTest, StreamLimitUpdates) {
  StreamId peerStream = 13;
  StreamId peerAutoOpened = 5;
  StreamId peerAutoOpened2 = 9;
  StreamId notOpenedPeer = 17;

  conn.streamManager->setStreamLimitWindowingFraction(
      conn.transportSettings.advertisedInitialMaxStreamsBidi);
  conn.streamManager->getStream(peerStream)->sendState =
      StreamSendState::Closed;
  conn.streamManager->getStream(peerStream)->recvState =
      StreamRecvState::Closed;
  EXPECT_FALSE(conn.streamManager->streamExists(notOpenedPeer));
  EXPECT_TRUE(conn.streamManager->streamExists(peerStream));
  EXPECT_TRUE(conn.streamManager->streamExists(peerAutoOpened));

  conn.streamManager->removeClosedStream(peerStream);

  EXPECT_FALSE(conn.streamManager->streamExists(peerStream));
  EXPECT_TRUE(conn.streamManager->streamExists(peerAutoOpened));
  EXPECT_TRUE(conn.streamManager->streamExists(peerAutoOpened2));
  auto update = conn.streamManager->remoteBidirectionalStreamLimitUpdate();
  ASSERT_TRUE(update);
  EXPECT_EQ(
      update.value(),
      conn.transportSettings.advertisedInitialMaxStreamsBidi + 1);
}

TEST_F(QuicStreamFunctionsTest, AllBytesTillFinAcked) {
  StreamId id = 3;
  QuicStreamState stream(id, conn);
  stream.finalWriteOffset = 1;
  stream.currentWriteOffset = 2;
  EXPECT_TRUE(allBytesTillFinAcked(stream));
}

TEST_F(QuicStreamFunctionsTest, AllBytesTillFinAckedDSR) {
  StreamId id = 3;
  QuicStreamState stream(id, conn);
  stream.finalWriteOffset = 1;
  stream.writeBufMeta.offset = 2;
  EXPECT_TRUE(allBytesTillFinAcked(stream));
}

TEST_F(QuicStreamFunctionsTest, AllBytesTillFinAckedFinOnly) {
  StreamId id = 3;
  QuicStreamState stream(id, conn);
  stream.finalWriteOffset = 0;
  stream.currentWriteOffset = 1;
  EXPECT_TRUE(allBytesTillFinAcked(stream));
}

TEST_F(QuicStreamFunctionsTest, AllBytesTillFinAckedFinOnlyDSR) {
  StreamId id = 3;
  QuicStreamState stream(id, conn);
  stream.finalWriteOffset = 0;
  stream.writeBufMeta.offset = 1;
  EXPECT_TRUE(allBytesTillFinAcked(stream));
}

TEST_F(QuicStreamFunctionsTest, AllBytesTillFinAckedNewStream) {
  StreamId id = 3;
  QuicStreamState stream(id, conn);
  EXPECT_FALSE(allBytesTillFinAcked(stream));
}

TEST_F(QuicStreamFunctionsTest, AllBytesTillFinAckedStillLost) {
  StreamId id = 3;
  QuicStreamState stream(id, conn);
  stream.finalWriteOffset = 20;
  stream.currentWriteOffset = 21;
  stream.lossBuffer.emplace_back(IOBuf::create(10), 10, false);
  EXPECT_FALSE(allBytesTillFinAcked(stream));
}

TEST_F(QuicStreamFunctionsTest, AllBytesTillFinAckedStillLostDSR) {
  StreamId id = 3;
  QuicStreamState stream(id, conn);
  stream.finalWriteOffset = 20;
  stream.writeBufMeta.offset = 21;
  WriteBufferMeta::Builder b;
  b.setLength(10);
  b.setOffset(10);
  b.setEOF(false);
  stream.lossBufMetas.emplace_back(b.build());
  EXPECT_FALSE(allBytesTillFinAcked(stream));
}

TEST_F(QuicStreamFunctionsTest, AllBytesTillFinAckedStillRetransmitting) {
  StreamId id = 3;
  QuicStreamState stream(id, conn);
  stream.finalWriteOffset = 12;
  stream.retransmissionBuffer.emplace(
      0, std::make_unique<StreamBuffer>(IOBuf::create(10), 10, false));
  EXPECT_FALSE(allBytesTillFinAcked(stream));
}

TEST_F(QuicStreamFunctionsTest, AllBytesTillFinAckedStillRetransmittingDSR) {
  StreamId id = 3;
  QuicStreamState stream(id, conn);
  stream.finalWriteOffset = 12;
  WriteBufferMeta::Builder b;
  b.setLength(10);
  b.setOffset(10);
  b.setEOF(false);
  stream.retransmissionBufMetas.emplace(0, b.build());
  EXPECT_FALSE(allBytesTillFinAcked(stream));
}

TEST_F(QuicStreamFunctionsTest, AllBytesTillFinAckedStillWriting) {
  StreamId id = 3;
  QuicStreamState stream(id, conn);
  stream.finalWriteOffset = 10;
  auto buf = IOBuf::create(10);
  buf->append(10);
  stream.writeBuffer.append(std::move(buf));
  EXPECT_FALSE(allBytesTillFinAcked(stream));
}

TEST_F(QuicStreamFunctionsTest, AllBytesTillFinAckedStillWritingDSR) {
  StreamId id = 3;
  QuicStreamState stream(id, conn);
  stream.finalWriteOffset = 10;
  stream.writeBufMeta.length = 10;
  EXPECT_FALSE(allBytesTillFinAcked(stream));
}

TEST_F(QuicServerStreamFunctionsTest, TestAppendPendingStreamResetAllData) {
  StreamId id = 3;
  QuicStreamState stream(id, conn);
  auto data = IOBuf::copyBuffer("this is data");
  auto len = data->computeChainDataLength();
  writeDataToQuicStream(stream, std::move(data), true);

  // Simulate all bytes and EOF written on network.
  stream.currentWriteOffset = len + 1;
  stream.retransmissionBuffer.clear();

  appendPendingStreamReset(conn, stream, GenericApplicationErrorCode::UNKNOWN);
  auto rst = conn.pendingEvents.resets.at(id);
  EXPECT_EQ(rst.errorCode, GenericApplicationErrorCode::UNKNOWN);
  EXPECT_EQ(rst.offset, len);
}

TEST_F(
    QuicServerStreamFunctionsTest,
    TestAppendPendingStreamResetAllDataWithoutFin) {
  StreamId id = 3;
  QuicStreamState stream(id, conn);
  auto data = IOBuf::copyBuffer("this is data");
  auto len = data->computeChainDataLength();
  writeDataToQuicStream(stream, std::move(data), true);

  // Simulate all bytes except EOF written on network.
  stream.currentWriteOffset = len;
  stream.retransmissionBuffer.clear();

  appendPendingStreamReset(conn, stream, GenericApplicationErrorCode::UNKNOWN);
  auto rst = conn.pendingEvents.resets.at(id);
  EXPECT_EQ(rst.errorCode, GenericApplicationErrorCode::UNKNOWN);
  EXPECT_EQ(rst.offset, len);
}

TEST_F(QuicStreamFunctionsTest, LargestWriteOffsetSeenFIN) {
  QuicStreamState stream(3, conn);
  stream.finalWriteOffset = 100;
  EXPECT_EQ(100, getLargestWriteOffsetSeen(stream));
}

TEST_F(QuicStreamFunctionsTest, LargestWriteOffsetSeenNoFIN) {
  QuicStreamState stream(3, conn);
  stream.currentWriteOffset = 100;
  stream.writeBuffer.append(buildRandomInputData(20));
  EXPECT_EQ(120, getLargestWriteOffsetSeen(stream));
}

TEST_F(QuicStreamFunctionsTest, StreamLargestWriteOffsetTxedNothingTxed) {
  QuicStreamState stream(3, conn);
  stream.currentWriteOffset = 0;
  EXPECT_EQ(folly::none, getLargestWriteOffsetTxed(stream));
}

TEST_F(QuicStreamFunctionsTest, StreamLargestWriteOffsetTxedOneByteTxed) {
  QuicStreamState stream(3, conn);
  stream.currentWriteOffset = 1;
  ASSERT_TRUE(getLargestWriteOffsetTxed(stream).has_value());
  EXPECT_EQ(0, getLargestWriteOffsetTxed(stream).value());
}

TEST_F(QuicStreamFunctionsTest, StreamLargestWriteOffsetTxedHundredBytesTxed) {
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

TEST_F(QuicStreamFunctionsTest, StreamNextOffsetToDeliverNothingAcked) {
  QuicStreamState stream(3, conn);
  stream.currentWriteOffset = 100;
  EXPECT_EQ(folly::none, getLargestDeliverableOffset(stream));
}

TEST_F(QuicStreamFunctionsTest, StreamNextOffsetToDeliverAllAcked) {
  QuicStreamState stream(3, conn);
  stream.currentWriteOffset = 100;
  stream.ackedIntervals.insert(0, 99);
  EXPECT_EQ(99, getLargestDeliverableOffset(stream).value());
}

TEST_F(QuicStreamFunctionsTest, LossBufferEmpty) {
  StreamId id = 4;
  QuicStreamState stream(id, conn);
  conn.streamManager->addLoss(id);
  conn.streamManager->updateLossStreams(stream);
  EXPECT_FALSE(conn.streamManager->hasLoss());
}

TEST_F(QuicStreamFunctionsTest, LossBufferEmptyNoChange) {
  StreamId id = 4;
  QuicStreamState stream(id, conn);
  conn.streamManager->updateLossStreams(stream);
  EXPECT_FALSE(conn.streamManager->hasLoss());
}

TEST_F(QuicStreamFunctionsTest, LossBufferHasData) {
  StreamId id = 4;
  QuicStreamState stream(id, conn);
  stream.lossBuffer.emplace_back(IOBuf::create(10), 10, false);
  conn.streamManager->updateLossStreams(stream);
  EXPECT_TRUE(conn.streamManager->hasLoss());
}

TEST_F(QuicStreamFunctionsTest, LossBufferStillHasData) {
  StreamId id = 4;
  QuicStreamState stream(id, conn);
  conn.streamManager->addLoss(id);
  stream.lossBuffer.emplace_back(IOBuf::create(10), 10, false);
  conn.streamManager->updateLossStreams(stream);
  EXPECT_TRUE(conn.streamManager->hasLoss());
}

TEST_F(QuicStreamFunctionsTest, WritableList) {
  StreamId id = 3;
  QuicStreamState stream(id, conn);
  stream.currentWriteOffset = 100;
  stream.flowControlState.peerAdvertisedMaxOffset = 200;

  conn.streamManager->updateWritableStreams(stream);
  EXPECT_FALSE(writableContains(*stream.conn.streamManager, id));

  auto buf = IOBuf::create(100);
  buf->append(100);
  writeDataToQuicStream(stream, std::move(buf), false);
  conn.streamManager->updateWritableStreams(stream);
  EXPECT_TRUE(writableContains(*stream.conn.streamManager, id));

  // Flow control
  stream.flowControlState.peerAdvertisedMaxOffset = stream.currentWriteOffset;
  conn.streamManager->updateWritableStreams(stream);
  EXPECT_FALSE(writableContains(*stream.conn.streamManager, id));

  // Fin
  writeDataToQuicStream(stream, nullptr, true);
  stream.writeBuffer.move();
  stream.currentWriteOffset += 100;
  stream.flowControlState.peerAdvertisedMaxOffset = stream.currentWriteOffset;
  conn.streamManager->updateWritableStreams(stream);
  EXPECT_TRUE(writableContains(*stream.conn.streamManager, id));

  // After Fin
  stream.currentWriteOffset++;
  conn.streamManager->updateWritableStreams(stream);
  EXPECT_FALSE(writableContains(*stream.conn.streamManager, id));
}

TEST_F(QuicStreamFunctionsTest, AckCryptoStream) {
  auto chlo = IOBuf::copyBuffer("CHLO");
  conn.cryptoState->handshakeStream.retransmissionBuffer.emplace(
      0, std::make_unique<StreamBuffer>(chlo->clone(), 0));
  processCryptoStreamAck(conn.cryptoState->handshakeStream, 0, chlo->length());
  EXPECT_EQ(conn.cryptoState->handshakeStream.retransmissionBuffer.size(), 0);
}

TEST_F(QuicStreamFunctionsTest, AckCryptoStreamOffsetLengthMismatch) {
  auto chlo = IOBuf::copyBuffer("CHLO");
  auto& cryptoStream = conn.cryptoState->handshakeStream;
  cryptoStream.retransmissionBuffer.emplace(
      0, std::make_unique<StreamBuffer>(chlo->clone(), 0));
  processCryptoStreamAck(cryptoStream, 1, chlo->length());
  EXPECT_EQ(cryptoStream.retransmissionBuffer.size(), 1);

  processCryptoStreamAck(cryptoStream, 0, chlo->length() - 2);
  EXPECT_EQ(cryptoStream.retransmissionBuffer.size(), 1);

  processCryptoStreamAck(cryptoStream, 20, chlo->length());
  EXPECT_EQ(cryptoStream.retransmissionBuffer.size(), 1);
}

} // namespace test
} // namespace quic
