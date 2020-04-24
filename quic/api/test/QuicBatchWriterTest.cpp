/*
 * Copyright (c) Facebook, Inc. and its affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 *
 */

#include <quic/api/QuicBatchWriter.h>

#include <gtest/gtest.h>

namespace quic {
namespace testing {

constexpr const auto kStrLen = 10;
constexpr const auto kStrLenGT = 20;
constexpr const auto kStrLenLT = 5;
constexpr const auto kBatchNum = 3;
constexpr const auto kNumLoops = 10;

struct QuicBatchWriterTest : public ::testing::Test,
                             public ::testing::WithParamInterface<bool> {};

TEST_P(QuicBatchWriterTest, TestBatchingNone) {
  bool useThreadLocal = GetParam();
  folly::EventBase evb;
  folly::AsyncUDPSocket sock(&evb);
  sock.setReuseAddr(false);
  sock.bind(folly::SocketAddress("127.0.0.1", 0));

  auto batchWriter = quic::BatchWriterFactory::makeBatchWriter(
      sock,
      quic::QuicBatchingMode::BATCHING_MODE_NONE,
      kBatchNum,
      useThreadLocal,
      quic::kDefaultThreadLocalDelay);
  CHECK(batchWriter);
  std::string strTest('A', kStrLen);

  // run multiple loops
  for (size_t i = 0; i < kNumLoops; i++) {
    CHECK(batchWriter->empty());
    CHECK_EQ(batchWriter->size(), 0);
    auto buf = folly::IOBuf::copyBuffer(strTest.c_str(), kStrLen);

    CHECK(batchWriter->append(
        std::move(buf), kStrLen, folly::SocketAddress(), nullptr));
    CHECK_EQ(batchWriter->size(), kStrLen);
    batchWriter->reset();
  }
}

TEST_P(QuicBatchWriterTest, TestBatchingGSOBase) {
  bool useThreadLocal = GetParam();
  folly::EventBase evb;
  folly::AsyncUDPSocket sock(&evb);
  sock.setReuseAddr(false);
  sock.bind(folly::SocketAddress("127.0.0.1", 0));

  auto batchWriter = quic::BatchWriterFactory::makeBatchWriter(
      sock,
      quic::QuicBatchingMode::BATCHING_MODE_GSO,
      1,
      useThreadLocal,
      quic::kDefaultThreadLocalDelay);
  CHECK(batchWriter);
  std::string strTest(kStrLen, 'A');
  // if GSO is not available, just test we've got a regular
  // batch writer
  if (sock.getGSO() < 0) {
    CHECK(batchWriter->empty());
    CHECK_EQ(batchWriter->size(), 0);
    auto buf = folly::IOBuf::copyBuffer(strTest);
    CHECK(batchWriter->append(
        std::move(buf), strTest.size(), folly::SocketAddress(), nullptr));
    EXPECT_FALSE(batchWriter->needsFlush(kStrLenLT));
  }
}

TEST_P(QuicBatchWriterTest, TestBatchingGSOLastSmallPacket) {
  bool useThreadLocal = GetParam();
  folly::EventBase evb;
  folly::AsyncUDPSocket sock(&evb);
  sock.setReuseAddr(false);
  sock.bind(folly::SocketAddress("127.0.0.1", 0));

  auto batchWriter = quic::BatchWriterFactory::makeBatchWriter(
      sock,
      quic::QuicBatchingMode::BATCHING_MODE_GSO,
      1,
      useThreadLocal,
      quic::kDefaultThreadLocalDelay);
  CHECK(batchWriter);
  std::string strTest;
  // only if GSO is available
  if (sock.getGSO() >= 0) {
    // run multiple loops
    for (size_t i = 0; i < kNumLoops; i++) {
      // batch kStrLen, kStrLenLT
      CHECK(batchWriter->empty());
      CHECK_EQ(batchWriter->size(), 0);
      strTest = std::string(kStrLen, 'A');
      auto buf = folly::IOBuf::copyBuffer(strTest);
      EXPECT_FALSE(batchWriter->needsFlush(kStrLen));
      EXPECT_FALSE(batchWriter->append(
          std::move(buf), kStrLen, folly::SocketAddress(), nullptr));
      CHECK_EQ(batchWriter->size(), kStrLen);
      strTest = std::string(kStrLenLT, 'A');
      buf = folly::IOBuf::copyBuffer(strTest);
      EXPECT_FALSE(batchWriter->needsFlush(kStrLenLT));
      CHECK(batchWriter->append(
          std::move(buf), kStrLenLT, folly::SocketAddress(), nullptr));
      CHECK_EQ(batchWriter->size(), kStrLen + kStrLenLT);
      batchWriter->reset();
    }
  }
}

TEST_P(QuicBatchWriterTest, TestBatchingGSOLastBigPacket) {
  bool useThreadLocal = GetParam();
  folly::EventBase evb;
  folly::AsyncUDPSocket sock(&evb);
  sock.setReuseAddr(false);
  sock.bind(folly::SocketAddress("127.0.0.1", 0));

  auto batchWriter = quic::BatchWriterFactory::makeBatchWriter(
      sock,
      quic::QuicBatchingMode::BATCHING_MODE_GSO,
      1,
      useThreadLocal,
      quic::kDefaultThreadLocalDelay);
  CHECK(batchWriter);
  std::string strTest;
  // only if GSO is available
  if (sock.getGSO() >= 0) {
    // run multiple loops
    for (size_t i = 0; i < kNumLoops; i++) {
      // try to batch kStrLen, kStrLenGT
      CHECK(batchWriter->empty());
      CHECK_EQ(batchWriter->size(), 0);
      strTest = std::string(kStrLen, 'A');
      auto buf = folly::IOBuf::copyBuffer(strTest);
      EXPECT_FALSE(batchWriter->needsFlush(kStrLen));
      EXPECT_FALSE(batchWriter->append(
          std::move(buf), kStrLen, folly::SocketAddress(), nullptr));
      CHECK_EQ(batchWriter->size(), kStrLen);
      CHECK(batchWriter->needsFlush(kStrLenGT));
      batchWriter->reset();
    }
  }
}

TEST_P(QuicBatchWriterTest, TestBatchingGSOBatchNum) {
  bool useThreadLocal = GetParam();
  folly::EventBase evb;
  folly::AsyncUDPSocket sock(&evb);
  sock.setReuseAddr(false);
  sock.bind(folly::SocketAddress("127.0.0.1", 0));

  auto batchWriter = quic::BatchWriterFactory::makeBatchWriter(
      sock,
      quic::QuicBatchingMode::BATCHING_MODE_GSO,
      kBatchNum,
      useThreadLocal,
      quic::kDefaultThreadLocalDelay);
  CHECK(batchWriter);
  std::string strTest(kStrLen, 'A');
  // if GSO is not available, just test we've got a regular
  // batch writer
  if (sock.getGSO() >= 0) {
    // run multiple loops
    for (size_t i = 0; i < kNumLoops; i++) {
      // try to batch up to kBatchNum
      CHECK(batchWriter->empty());
      CHECK_EQ(batchWriter->size(), 0);
      size_t size = 0;
      for (auto j = 0; j < kBatchNum - 1; j++) {
        auto buf = folly::IOBuf::copyBuffer(strTest);
        EXPECT_FALSE(batchWriter->append(
            std::move(buf), kStrLen, folly::SocketAddress(), nullptr));
        size += kStrLen;
        CHECK_EQ(batchWriter->size(), size);
      }

      // add the kBatchNum buf
      auto buf = folly::IOBuf::copyBuffer(strTest.c_str(), kStrLen);
      CHECK(batchWriter->append(
          std::move(buf), kStrLen, folly::SocketAddress(), nullptr));
      size += kStrLen;
      CHECK_EQ(batchWriter->size(), size);
      batchWriter->reset();
    }
  }
}

TEST_P(QuicBatchWriterTest, TestBatchingSendmmsg) {
  bool useThreadLocal = GetParam();
  folly::EventBase evb;
  folly::AsyncUDPSocket sock(&evb);
  sock.setReuseAddr(false);
  sock.bind(folly::SocketAddress("127.0.0.1", 0));

  auto batchWriter = quic::BatchWriterFactory::makeBatchWriter(
      sock,
      quic::QuicBatchingMode::BATCHING_MODE_SENDMMSG,
      kBatchNum,
      useThreadLocal,
      quic::kDefaultThreadLocalDelay);
  CHECK(batchWriter);
  std::string strTest(kStrLen, 'A');

  // run multiple loops
  for (size_t i = 0; i < kNumLoops; i++) {
    // try to batch up to kBatchNum
    CHECK(batchWriter->empty());
    CHECK_EQ(batchWriter->size(), 0);
    size_t size = 0;
    for (auto j = 0; j < kBatchNum - 1; j++) {
      auto buf = folly::IOBuf::copyBuffer(strTest);
      EXPECT_FALSE(batchWriter->append(
          std::move(buf), kStrLen, folly::SocketAddress(), nullptr));
      size += kStrLen;
      CHECK_EQ(batchWriter->size(), size);
    }

    // add the kBatchNum buf
    auto buf = folly::IOBuf::copyBuffer(strTest.c_str(), kStrLen);
    CHECK(batchWriter->append(
        std::move(buf), kStrLen, folly::SocketAddress(), nullptr));
    size += kStrLen;
    CHECK_EQ(batchWriter->size(), size);
    batchWriter->reset();
  }
}

TEST_P(QuicBatchWriterTest, TestBatchingSendmmsgGSOBatchNum) {
  bool useThreadLocal = GetParam();
  folly::EventBase evb;
  folly::AsyncUDPSocket sock(&evb);
  sock.setReuseAddr(false);
  sock.bind(folly::SocketAddress("127.0.0.1", 0));

  auto batchWriter = quic::BatchWriterFactory::makeBatchWriter(
      sock,
      quic::QuicBatchingMode::BATCHING_MODE_SENDMMSG_GSO,
      kBatchNum,
      useThreadLocal,
      quic::kDefaultThreadLocalDelay);
  CHECK(batchWriter);
  std::string strTest(kStrLen, 'A');
  // if GSO is not available, just test we've got a regular
  // batch writer
  if (sock.getGSO() >= 0) {
    // run multiple loops
    for (size_t i = 0; i < kNumLoops; i++) {
      // try to batch up to kBatchNum
      CHECK(batchWriter->empty());
      CHECK_EQ(batchWriter->size(), 0);
      size_t size = 0;
      for (auto j = 0; j < kBatchNum - 1; j++) {
        auto buf = folly::IOBuf::copyBuffer(strTest);
        EXPECT_FALSE(batchWriter->append(
            std::move(buf), kStrLen, folly::SocketAddress(), nullptr));
        size += kStrLen;
        CHECK_EQ(batchWriter->size(), size);
      }

      // add the kBatchNum buf
      auto buf = folly::IOBuf::copyBuffer(strTest.c_str(), kStrLen);
      CHECK(batchWriter->append(
          std::move(buf), kStrLen, folly::SocketAddress(), nullptr));
      size += kStrLen;
      CHECK_EQ(batchWriter->size(), size);
      batchWriter->reset();
    }
  }
}

TEST_P(QuicBatchWriterTest, TestBatchingSendmmsgGSOBatcBigSmallPacket) {
  bool useThreadLocal = GetParam();
  folly::EventBase evb;
  folly::AsyncUDPSocket sock(&evb);
  sock.setReuseAddr(false);
  sock.bind(folly::SocketAddress("127.0.0.1", 0));

  auto batchWriter = quic::BatchWriterFactory::makeBatchWriter(
      sock,
      quic::QuicBatchingMode::BATCHING_MODE_SENDMMSG_GSO,
      3 * kBatchNum,
      useThreadLocal,
      quic::kDefaultThreadLocalDelay);
  CHECK(batchWriter);
  std::string strTest(kStrLen, 'A');
  // if GSO is not available, just test we've got a regular
  // batch writer
  if (sock.getGSO() >= 0) {
    // run multiple loops
    for (size_t i = 0; i < kNumLoops; i++) {
      // try to batch up to kBatchNum
      CHECK(batchWriter->empty());
      CHECK_EQ(batchWriter->size(), 0);
      size_t size = 0;
      for (auto j = 0; j < 3 * kBatchNum - 1; j++) {
        strTest = (j % 3 == 0) ? std::string(kStrLen, 'A')
                               : ((j % 3 == 1) ? std::string(kStrLenLT, 'A')
                                               : std::string(kStrLenGT, 'A'));
        auto buf = folly::IOBuf::copyBuffer(strTest);
        // we can add various sizes without the need to flush until we add
        // the maxBufs buffer
        EXPECT_FALSE(batchWriter->append(
            std::move(buf), strTest.length(), folly::SocketAddress(), nullptr));
        size += strTest.length();
        CHECK_EQ(batchWriter->size(), size);
      }

      // add the kBatchNum buf
      auto buf = folly::IOBuf::copyBuffer(strTest.c_str(), kStrLen);
      CHECK(batchWriter->append(
          std::move(buf), strTest.length(), folly::SocketAddress(), nullptr));
      size += strTest.length();
      CHECK_EQ(batchWriter->size(), size);
      batchWriter->reset();
    }
  }
}

INSTANTIATE_TEST_CASE_P(
    QuicBatchWriterTest,
    QuicBatchWriterTest,
    ::testing::Values(false, true));

} // namespace testing
} // namespace quic
