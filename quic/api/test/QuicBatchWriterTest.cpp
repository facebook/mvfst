/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <quic/api/QuicBatchWriter.h>

#include <folly/io/async/test/MockAsyncUDPSocket.h>
#include <gtest/gtest.h>
#include <quic/fizz/server/handshake/FizzServerQuicHandshakeContext.h>
#include <quic/server/state/ServerStateMachine.h>

using namespace testing;

namespace quic {
namespace testing {

constexpr const auto kStrLen = 10;
constexpr const auto kStrLenGT = 20;
constexpr const auto kStrLenLT = 5;
constexpr const auto kBatchNum = 3;
constexpr const auto kNumLoops = 10;

struct QuicBatchWriterTest : public ::testing::Test,
                             public ::testing::WithParamInterface<bool> {
  QuicBatchWriterTest()
      : conn_(FizzServerQuicHandshakeContext::Builder().build()) {}

 protected:
  QuicServerConnectionState conn_;
};

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
      quic::kDefaultThreadLocalDelay,
      DataPathType::ChainedMemory,
      conn_);
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
      quic::kDefaultThreadLocalDelay,
      DataPathType::ChainedMemory,
      conn_);
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
      quic::kDefaultThreadLocalDelay,
      DataPathType::ChainedMemory,
      conn_);
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
      quic::kDefaultThreadLocalDelay,
      DataPathType::ChainedMemory,
      conn_);
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
      quic::kDefaultThreadLocalDelay,
      DataPathType::ChainedMemory,
      conn_);
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
      quic::kDefaultThreadLocalDelay,
      DataPathType::ChainedMemory,
      conn_);
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
      quic::kDefaultThreadLocalDelay,
      DataPathType::ChainedMemory,
      conn_);
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
      quic::kDefaultThreadLocalDelay,
      DataPathType::ChainedMemory,
      conn_);
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

TEST_P(QuicBatchWriterTest, InplaceWriterNeedsFlush) {
  bool useThreadLocal = GetParam();
  folly::EventBase evb;
  folly::test::MockAsyncUDPSocket sock(&evb);
  EXPECT_CALL(sock, getGSO()).WillRepeatedly(Return(1));
  uint32_t batchSize = 20;
  auto bufAccessor =
      std::make_unique<SimpleBufAccessor>(conn_.udpSendPacketLen * batchSize);
  conn_.bufAccessor = bufAccessor.get();
  auto batchWriter = quic::BatchWriterFactory::makeBatchWriter(
      sock,
      quic::QuicBatchingMode::BATCHING_MODE_GSO,
      batchSize,
      useThreadLocal,
      quic::kDefaultThreadLocalDelay,
      DataPathType::ContinuousMemory,
      conn_);
  CHECK(batchWriter);
  EXPECT_FALSE(batchWriter->needsFlush(1000));

  for (size_t i = 0; i < 10; i++) {
    EXPECT_FALSE(batchWriter->needsFlush(1000));
    batchWriter->append(nullptr, 1000, folly::SocketAddress(), nullptr);
  }
  EXPECT_TRUE(batchWriter->needsFlush(conn_.udpSendPacketLen));
}

TEST_P(QuicBatchWriterTest, InplaceWriterAppendLimit) {
  bool useThreadLocal = GetParam();
  folly::EventBase evb;
  folly::test::MockAsyncUDPSocket sock(&evb);
  EXPECT_CALL(sock, getGSO()).WillRepeatedly(Return(1));
  uint32_t batchSize = 20;
  auto bufAccessor =
      std::make_unique<SimpleBufAccessor>(conn_.udpSendPacketLen * batchSize);
  conn_.bufAccessor = bufAccessor.get();
  auto batchWriter = quic::BatchWriterFactory::makeBatchWriter(
      sock,
      quic::QuicBatchingMode::BATCHING_MODE_GSO,
      batchSize,
      useThreadLocal,
      quic::kDefaultThreadLocalDelay,
      DataPathType::ContinuousMemory,
      conn_);
  CHECK(batchWriter);
  EXPECT_FALSE(batchWriter->needsFlush(1000));

  for (size_t i = 0; i < batchSize - 1; i++) {
    auto buf = bufAccessor->obtain();
    buf->append(1000);
    bufAccessor->release(std::move(buf));
    EXPECT_FALSE(
        batchWriter->append(nullptr, 1000, folly::SocketAddress(), nullptr));
  }

  auto buf = bufAccessor->obtain();
  buf->append(1000);
  bufAccessor->release(std::move(buf));
  EXPECT_TRUE(
      batchWriter->append(nullptr, 1000, folly::SocketAddress(), nullptr));
}

TEST_P(QuicBatchWriterTest, InplaceWriterAppendSmaller) {
  bool useThreadLocal = GetParam();
  folly::EventBase evb;
  folly::test::MockAsyncUDPSocket sock(&evb);
  EXPECT_CALL(sock, getGSO()).WillRepeatedly(Return(1));
  uint32_t batchSize = 20;
  auto bufAccessor =
      std::make_unique<SimpleBufAccessor>(conn_.udpSendPacketLen * batchSize);
  conn_.bufAccessor = bufAccessor.get();
  auto batchWriter = quic::BatchWriterFactory::makeBatchWriter(
      sock,
      quic::QuicBatchingMode::BATCHING_MODE_GSO,
      batchSize,
      useThreadLocal,
      quic::kDefaultThreadLocalDelay,
      DataPathType::ContinuousMemory,
      conn_);
  CHECK(batchWriter);
  EXPECT_FALSE(batchWriter->needsFlush(1000));

  for (size_t i = 0; i < batchSize / 2; i++) {
    auto buf = bufAccessor->obtain();
    buf->append(1000);
    bufAccessor->release(std::move(buf));
    EXPECT_FALSE(
        batchWriter->append(nullptr, 1000, folly::SocketAddress(), nullptr));
  }

  auto buf = bufAccessor->obtain();
  buf->append(700);
  bufAccessor->release(std::move(buf));
  EXPECT_TRUE(
      batchWriter->append(nullptr, 700, folly::SocketAddress(), nullptr));
}

TEST_P(QuicBatchWriterTest, InplaceWriterWriteAll) {
  bool useThreadLocal = GetParam();
  folly::EventBase evb;
  folly::test::MockAsyncUDPSocket sock(&evb);
  uint32_t batchSize = 20;
  auto bufAccessor =
      std::make_unique<SimpleBufAccessor>(conn_.udpSendPacketLen * batchSize);
  conn_.bufAccessor = bufAccessor.get();
  EXPECT_CALL(sock, getGSO()).WillRepeatedly(Return(1));
  auto batchWriter = quic::BatchWriterFactory::makeBatchWriter(
      sock,
      quic::QuicBatchingMode::BATCHING_MODE_GSO,
      batchSize,
      useThreadLocal,
      quic::kDefaultThreadLocalDelay,
      DataPathType::ContinuousMemory,
      conn_);
  CHECK(batchWriter);
  ASSERT_FALSE(batchWriter->needsFlush(1000));

  for (size_t i = 0; i < 5; i++) {
    auto buf = bufAccessor->obtain();
    buf->append(1000);
    bufAccessor->release(std::move(buf));
    ASSERT_FALSE(
        batchWriter->append(nullptr, 1000, folly::SocketAddress(), nullptr));
  }
  auto buf = bufAccessor->obtain();
  buf->append(700);
  bufAccessor->release(std::move(buf));
  ASSERT_TRUE(
      batchWriter->append(nullptr, 700, folly::SocketAddress(), nullptr));

  EXPECT_CALL(sock, writeGSO(_, _, _))
      .Times(1)
      .WillOnce(Invoke([&](const auto& /* addr */,
                           const std::unique_ptr<folly::IOBuf>& buf,
                           int gso) {
        EXPECT_EQ(1000 * 5 + 700, buf->length());
        EXPECT_EQ(1000, gso);
        return 1000 * 5 + 700;
      }));
  EXPECT_EQ(1000 * 5 + 700, batchWriter->write(sock, folly::SocketAddress()));

  EXPECT_TRUE(bufAccessor->ownsBuffer());
  buf = bufAccessor->obtain();
  EXPECT_EQ(0, buf->length());
}

TEST_P(QuicBatchWriterTest, InplaceWriterWriteOne) {
  bool useThreadLocal = GetParam();
  folly::EventBase evb;
  folly::test::MockAsyncUDPSocket sock(&evb);
  uint32_t batchSize = 20;
  auto bufAccessor =
      std::make_unique<SimpleBufAccessor>(conn_.udpSendPacketLen * batchSize);
  conn_.bufAccessor = bufAccessor.get();
  EXPECT_CALL(sock, getGSO()).WillRepeatedly(Return(1));
  auto batchWriter = quic::BatchWriterFactory::makeBatchWriter(
      sock,
      quic::QuicBatchingMode::BATCHING_MODE_GSO,
      batchSize,
      useThreadLocal,
      quic::kDefaultThreadLocalDelay,
      DataPathType::ContinuousMemory,
      conn_);
  CHECK(batchWriter);
  ASSERT_FALSE(batchWriter->needsFlush(1000));

  auto buf = bufAccessor->obtain();
  buf->append(1000);
  bufAccessor->release(std::move(buf));
  ASSERT_FALSE(
      batchWriter->append(nullptr, 1000, folly::SocketAddress(), nullptr));

  EXPECT_CALL(sock, write(_, _))
      .Times(1)
      .WillOnce(Invoke([&](const auto& /* addr */,
                           const std::unique_ptr<folly::IOBuf>& buf) {
        EXPECT_EQ(1000, buf->length());
        return 1000;
      }));
  EXPECT_EQ(1000, batchWriter->write(sock, folly::SocketAddress()));

  EXPECT_TRUE(bufAccessor->ownsBuffer());
  buf = bufAccessor->obtain();
  EXPECT_EQ(0, buf->length());
}

TEST_P(QuicBatchWriterTest, InplaceWriterLastOneTooBig) {
  bool useThreadLocal = GetParam();
  folly::EventBase evb;
  folly::test::MockAsyncUDPSocket sock(&evb);
  uint32_t batchSize = 20;
  auto bufAccessor =
      std::make_unique<SimpleBufAccessor>(conn_.udpSendPacketLen * batchSize);
  conn_.bufAccessor = bufAccessor.get();
  EXPECT_CALL(sock, getGSO()).WillRepeatedly(Return(1));
  auto batchWriter = quic::BatchWriterFactory::makeBatchWriter(
      sock,
      quic::QuicBatchingMode::BATCHING_MODE_GSO,
      batchSize,
      useThreadLocal,
      quic::kDefaultThreadLocalDelay,
      DataPathType::ContinuousMemory,
      conn_);
  for (size_t i = 0; i < 5; i++) {
    auto buf = bufAccessor->obtain();
    buf->append(700);
    bufAccessor->release(std::move(buf));
    ASSERT_FALSE(
        batchWriter->append(nullptr, 700, folly::SocketAddress(), nullptr));
  }
  auto buf = bufAccessor->obtain();
  buf->append(1000);
  bufAccessor->release(std::move(buf));
  EXPECT_TRUE(batchWriter->needsFlush(1000));

  EXPECT_CALL(sock, writeGSO(_, _, _))
      .Times(1)
      .WillOnce(Invoke([&](const auto& /* addr */,
                           const std::unique_ptr<folly::IOBuf>& buf,
                           int gso) {
        EXPECT_EQ(5 * 700, buf->length());
        EXPECT_EQ(700, gso);
        return 700 * 5;
      }));
  EXPECT_EQ(5 * 700, batchWriter->write(sock, folly::SocketAddress()));

  EXPECT_TRUE(bufAccessor->ownsBuffer());
  buf = bufAccessor->obtain();
  EXPECT_EQ(1000, buf->length());
  EXPECT_EQ(0, buf->headroom());
}

TEST_P(QuicBatchWriterTest, InplaceWriterBufResidueCheck) {
  bool useThreadLocal = GetParam();
  folly::EventBase evb;
  folly::test::MockAsyncUDPSocket sock(&evb);
  EXPECT_CALL(sock, getGSO()).WillRepeatedly(Return(1));

  uint32_t batchSize = 20;
  auto bufAccessor =
      std::make_unique<SimpleBufAccessor>(conn_.udpSendPacketLen * batchSize);
  conn_.bufAccessor = bufAccessor.get();
  conn_.udpSendPacketLen = 1000;
  auto batchWriter = quic::BatchWriterFactory::makeBatchWriter(
      sock,
      quic::QuicBatchingMode::BATCHING_MODE_GSO,
      batchSize,
      useThreadLocal,
      quic::kDefaultThreadLocalDelay,
      DataPathType::ContinuousMemory,
      conn_);
  auto buf = bufAccessor->obtain();
  folly::IOBuf* rawBuf = buf.get();
  bufAccessor->release(std::move(buf));
  rawBuf->append(700);
  ASSERT_FALSE(
      batchWriter->append(nullptr, 700, folly::SocketAddress(), nullptr));

  // There is a check against packet 10 bytes or more larger than the size limit
  size_t packetSizeBig = 1009;
  rawBuf->append(packetSizeBig);
  EXPECT_TRUE(batchWriter->needsFlush(packetSizeBig));

  EXPECT_CALL(sock, write(_, _))
      .Times(1)
      .WillOnce(Invoke([&](const auto& /* addr */,
                           const std::unique_ptr<folly::IOBuf>& buf) {
        EXPECT_EQ(700, buf->length());
        return 700;
      }));
  // No crash:
  EXPECT_EQ(700, batchWriter->write(sock, folly::SocketAddress()));
  EXPECT_EQ(1009, rawBuf->length());
  EXPECT_EQ(0, rawBuf->headroom());
}

INSTANTIATE_TEST_SUITE_P(
    QuicBatchWriterTest,
    QuicBatchWriterTest,
    ::testing::Values(false, true));

} // namespace testing
} // namespace quic
