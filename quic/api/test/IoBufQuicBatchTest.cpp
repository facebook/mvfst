/*
 * Copyright (c) Facebook, Inc. and its affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 *
 */

#include <quic/api/IoBufQuicBatch.h>
#include <gtest/gtest.h>
#include <quic/state/StateData.h>

constexpr const auto kNumLoops = 64;
constexpr const auto kMaxBufs = 10;

namespace quic {
namespace testing {
class TestPacketBatchWriter : public IOBufBatchWriter {
 public:
  explicit TestPacketBatchWriter(int maxBufs) : maxBufs_(maxBufs) {}
  ~TestPacketBatchWriter() override {
    CHECK_EQ(bufNum_, 0);
    CHECK_EQ(bufSize_, 0);
  }

  void reset() override {
    bufNum_ = 0;
    bufSize_ = 0;
  }

  bool append(std::unique_ptr<folly::IOBuf>&& /*unused*/, size_t size)
      override {
    bufNum_++;
    bufSize_ += size;
    return ((maxBufs_ < 0) || (bufNum_ >= maxBufs_));
  }
  ssize_t write(
      folly::AsyncUDPSocket& /*unused*/,
      const folly::SocketAddress& /*unused*/) override {
    return bufSize_;
  }

 private:
  int maxBufs_{0};
  int bufNum_{0};
  size_t bufSize_{0};
};

void RunTest(int numBatch) {
  folly::EventBase evb;
  folly::AsyncUDPSocket sock(&evb);

  auto batchWriter = std::make_unique<TestPacketBatchWriter>(numBatch);
  folly::SocketAddress peerAddress{"127.0.0.1", 1234};
  QuicConnectionStateBase::HappyEyeballsState happyEyeballsState;

  IOBufQuicBatch ioBufBatch(
      std::move(batchWriter), sock, peerAddress, happyEyeballsState);

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
} // namespace testing
} // namespace quic
