/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <quic/api/IoBufQuicBatch.h>

#include <gtest/gtest.h>
#include <quic/client/state/ClientStateMachine.h>
#include <quic/common/events/FollyQuicEventBase.h>
#include <quic/common/test/TestUtils.h>
#include <quic/common/testutil/MockAsyncUDPSocket.h>
#include <quic/common/udpsocket/FollyQuicAsyncUDPSocket.h>
#include <quic/fizz/client/handshake/FizzClientQuicHandshakeContext.h>

constexpr const auto kNumLoops = 64;
constexpr const auto kMaxBufs = 10;

namespace quic::testing {
void RunTest(int numBatch) {
  folly::EventBase evb;
  std::shared_ptr<FollyQuicEventBase> qEvb =
      std::make_shared<FollyQuicEventBase>(&evb);
  FollyQuicAsyncUDPSocket sock(qEvb);

  auto batchWriter = BatchWriterPtr(new test::TestPacketBatchWriter(numBatch));
  quic::SocketAddress peerAddress{"127.0.0.1", 1234};
  QuicClientConnectionState conn(
      FizzClientQuicHandshakeContext::Builder().build());
  QuicClientConnectionState::HappyEyeballsState happyEyeballsState;

  IOBufQuicBatch ioBufBatch(
      std::move(batchWriter),
      sock,
      peerAddress,
      conn.statsCallback,
      nullptr /* happyEyeballsState */);

  std::string strTest("Test");

  for (size_t i = 0; i < kNumLoops; i++) {
    auto buf = folly::IOBuf::copyBuffer(strTest.c_str(), strTest.length());
    CHECK(ioBufBatch.write(std::move(buf), strTest.length()));
  }
  // check flush is successful
  CHECK(ioBufBatch.flush());
  // check we sent all the packets
  CHECK_EQ(ioBufBatch.getPktSent(), kNumLoops);
}

TEST(QuicBatch, TestBatchingNone) {
  RunTest(1);
}

TEST(QuicBatch, TestBatchingNoFlush) {
  RunTest(-1);
}

TEST(QuicBatch, TestBatching) {
  RunTest(kMaxBufs);
}

TEST(QuicBatch, SendmmsgPropagatesSocketErrors) {
  for (const auto path :
       {DataPathType::ChainedMemory, DataPathType::ContinuousMemory}) {
    for (const int socketError : {EAGAIN, EWOULDBLOCK, ENOBUFS, EIO}) {
      SCOPED_TRACE(static_cast<int>(path));
      SCOPED_TRACE(socketError);
      folly::EventBase evb;
      auto qEvb = std::make_shared<FollyQuicEventBase>(&evb);
      quic::test::MockAsyncUDPSocket sock(qEvb);
      QuicClientConnectionState conn(
          FizzClientQuicHandshakeContext::Builder().build());
      BufAccessor accessor(4096);
      conn.bufAccessor = &accessor;
      BatchWriterPtr writer;
      if (path == DataPathType::ContinuousMemory) {
        writer.reset(new SendmmsgInplacePacketBatchWriter(conn, 2));
      } else {
        writer.reset(new SendmmsgPacketBatchWriter(2));
      }
      SocketAddress peerAddress("127.0.0.1", 1234);
      IOBufQuicBatch batch(
          std::move(writer), sock, peerAddress, nullptr, nullptr);
      EXPECT_CALL(sock, writem(::testing::_, ::testing::_, ::testing::_, 2))
          .WillOnce(::testing::InvokeWithoutArgs([&]() {
            errno = socketError;
            return -1;
          }));
      for (size_t i = 0; i < 2; ++i) {
        auto buf = folly::IOBuf::copyBuffer("packet");
        const auto size = buf->length();
        if (path == DataPathType::ContinuousMemory) {
          memcpy(accessor.writableTail(), buf->data(), size);
          accessor.append(size);
          buf.reset();
        }
        auto result = batch.write(std::move(buf), size);
        if (i == 0) {
          ASSERT_TRUE(result.has_value());
          EXPECT_TRUE(result.value());
        } else if (socketError == EIO) {
          EXPECT_TRUE(result.hasError());
        } else {
          ASSERT_TRUE(result.has_value());
          EXPECT_FALSE(result.value());
        }
      }
      EXPECT_EQ(batch.getLastRetryableErrno(), socketError);
      EXPECT_EQ(accessor.length(), 0);
    }
  }
}
} // namespace quic::testing
