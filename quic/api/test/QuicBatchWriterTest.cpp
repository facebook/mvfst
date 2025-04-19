/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <quic/api/QuicBatchWriter.h>
#include <quic/api/QuicBatchWriterFactory.h>
#include <quic/common/events/FollyQuicEventBase.h>
#include <quic/common/test/TestUtils.h>
#include <quic/common/udpsocket/FollyQuicAsyncUDPSocket.h>

#include <gtest/gtest.h>
#include <quic/common/testutil/MockAsyncUDPSocket.h>
#include <quic/fizz/server/handshake/FizzServerQuicHandshakeContext.h>
#include <quic/server/state/ServerStateMachine.h>

using namespace testing;

namespace quic::testing {

constexpr const auto kStrLen = 10;
constexpr const auto kStrLenGT = 20;
constexpr const auto kStrLenLT = 5;
constexpr const auto kBatchNum = 3;
constexpr const auto kNumLoops = 10;

struct QuicBatchWriterTest : public ::testing::Test {
  QuicBatchWriterTest()
      : conn_(FizzServerQuicHandshakeContext::Builder().build()) {}

 protected:
  QuicServerConnectionState conn_;
  bool gsoSupported_{false};
};

TEST_F(QuicBatchWriterTest, TestBatchingNone) {
  auto batchWriter = quic::BatchWriterFactory::makeBatchWriter(
      quic::QuicBatchingMode::BATCHING_MODE_NONE,
      kBatchNum,
      false, /* enable backpressure */
      DataPathType::ChainedMemory,
      conn_,
      gsoSupported_);
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

TEST_F(QuicBatchWriterTest, TestBatchingGSOBase) {
  folly::EventBase evb;
  std::shared_ptr<FollyQuicEventBase> qEvb =
      std::make_shared<FollyQuicEventBase>(&evb);
  FollyQuicAsyncUDPSocket sock(qEvb);
  sock.setReuseAddr(false);
  ASSERT_FALSE(sock.bind(folly::SocketAddress("127.0.0.1", 0)).hasError());
  auto gsoResult = sock.getGSO();
  ASSERT_FALSE(gsoResult.hasError());
  gsoSupported_ = gsoResult.value();

  auto batchWriter = quic::BatchWriterFactory::makeBatchWriter(
      quic::QuicBatchingMode::BATCHING_MODE_GSO,
      1,
      false, /* enable backpressure */
      DataPathType::ChainedMemory,
      conn_,
      gsoSupported_);
  CHECK(batchWriter);
  std::string strTest(kStrLen, 'A');
  // if GSO is not available, just test we've got a regular
  // batch writer
  if (!gsoSupported_) {
    CHECK(batchWriter->empty());
    CHECK_EQ(batchWriter->size(), 0);
    auto buf = folly::IOBuf::copyBuffer(strTest);
    CHECK(batchWriter->append(
        std::move(buf), strTest.size(), folly::SocketAddress(), nullptr));
    EXPECT_FALSE(batchWriter->needsFlush(kStrLenLT));
  }
}

TEST_F(QuicBatchWriterTest, TestBatchingGSOLastSmallPacket) {
  folly::EventBase evb;
  std::shared_ptr<FollyQuicEventBase> qEvb =
      std::make_shared<FollyQuicEventBase>(&evb);
  FollyQuicAsyncUDPSocket sock(qEvb);
  sock.setReuseAddr(false);
  ASSERT_FALSE(sock.bind(folly::SocketAddress("127.0.0.1", 0)).hasError());
  auto gsoResult = sock.getGSO();
  ASSERT_FALSE(gsoResult.hasError());
  gsoSupported_ = gsoResult.value();

  auto batchWriter = quic::BatchWriterFactory::makeBatchWriter(
      quic::QuicBatchingMode::BATCHING_MODE_GSO,
      1,
      false, /* enable backpressure */
      DataPathType::ChainedMemory,
      conn_,
      gsoSupported_);
  CHECK(batchWriter);
  std::string strTest;
  // only if GSO is available
  if (gsoSupported_) {
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

TEST_F(QuicBatchWriterTest, TestBatchingGSOLastBigPacket) {
  folly::EventBase evb;
  std::shared_ptr<FollyQuicEventBase> qEvb =
      std::make_shared<FollyQuicEventBase>(&evb);
  FollyQuicAsyncUDPSocket sock(qEvb);
  sock.setReuseAddr(false);
  ASSERT_FALSE(sock.bind(folly::SocketAddress("127.0.0.1", 0)).hasError());
  auto gsoResult = sock.getGSO();
  ASSERT_FALSE(gsoResult.hasError());
  gsoSupported_ = gsoResult.value();

  auto batchWriter = quic::BatchWriterFactory::makeBatchWriter(
      quic::QuicBatchingMode::BATCHING_MODE_GSO,
      1,
      false, /* enable backpressure */
      DataPathType::ChainedMemory,
      conn_,
      gsoSupported_);
  CHECK(batchWriter);
  std::string strTest;
  // only if GSO is available
  if (gsoSupported_) {
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

TEST_F(QuicBatchWriterTest, TestBatchingGSOBatchNum) {
  folly::EventBase evb;
  std::shared_ptr<FollyQuicEventBase> qEvb =
      std::make_shared<FollyQuicEventBase>(&evb);
  FollyQuicAsyncUDPSocket sock(qEvb);
  sock.setReuseAddr(false);
  ASSERT_FALSE(sock.bind(folly::SocketAddress("127.0.0.1", 0)).hasError());
  auto gsoResult = sock.getGSO();
  ASSERT_FALSE(gsoResult.hasError());
  gsoSupported_ = gsoResult.value();

  auto batchWriter = quic::BatchWriterFactory::makeBatchWriter(
      quic::QuicBatchingMode::BATCHING_MODE_GSO,
      kBatchNum,
      false, /* enable backpressure */
      DataPathType::ChainedMemory,
      conn_,
      gsoSupported_);
  CHECK(batchWriter);
  std::string strTest(kStrLen, 'A');
  // if GSO is not available, just test we've got a regular
  // batch writer
  if (gsoSupported_) {
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

TEST_F(QuicBatchWriterTest, TestBatchingSendmmsg) {
  auto batchWriter = quic::BatchWriterFactory::makeBatchWriter(
      quic::QuicBatchingMode::BATCHING_MODE_SENDMMSG,
      kBatchNum,
      false, /* enable backpressure */
      DataPathType::ChainedMemory,
      conn_,
      gsoSupported_);
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

TEST_F(QuicBatchWriterTest, TestBatchingSendmmsgInplaceIovecMatches) {
  // In this test case, we don't surpass the kNumIovecBufferChains limit
  // (i.e. the number of contiguous buffers we are sending)
  folly::EventBase evb;
  std::shared_ptr<FollyQuicEventBase> qEvb =
      std::make_shared<FollyQuicEventBase>(&evb);
  quic::test::MockAsyncUDPSocket sock(qEvb);

  auto batchWriter = quic::BatchWriterFactory::makeBatchWriter(
      quic::QuicBatchingMode::BATCHING_MODE_SENDMMSG,
      kBatchNum,
      false, /* enable backpressure */
      DataPathType::ChainedMemory,
      conn_,
      gsoSupported_);
  CHECK(batchWriter);

  std::vector<std::string> messages{"It", "is", "sunny!"};

  CHECK(batchWriter->empty());
  CHECK_EQ(batchWriter->size(), 0);
  size_t size = 0;
  for (auto& message : messages) {
    auto buf = folly::IOBuf::copyBuffer(
        folly::ByteRange((unsigned char*)message.data(), message.size()));
    batchWriter->append(
        std::move(buf), message.size(), folly::SocketAddress(), nullptr);
    size += message.size();
    CHECK_EQ(batchWriter->size(), size);
  }

  EXPECT_CALL(sock, writem(_, _, _, _))
      .Times(1)
      .WillOnce(Invoke([&](folly::Range<folly::SocketAddress const*> addrs,
                           iovec* iovecs,
                           size_t* messageSizes,
                           size_t count) {
        EXPECT_EQ(addrs.size(), 1);
        EXPECT_EQ(count, messages.size());

        size_t currentIovIndex = 0;
        for (size_t i = 0; i < count; i++) {
          auto wrappedIovBuffer =
              folly::IOBuf::wrapIov(iovecs + currentIovIndex, messageSizes[i]);
          currentIovIndex += messageSizes[i];

          folly::IOBufEqualTo eq;
          EXPECT_TRUE(
              eq(wrappedIovBuffer,
                 folly::IOBuf::copyBuffer(folly::ByteRange(
                     (unsigned char*)messages[i].data(), messages[i].size()))));
        }

        return 0;
      }));

  batchWriter->write(sock, folly::SocketAddress());
}

TEST_F(QuicBatchWriterTest, TestBatchingSendmmsgNewlyAllocatedIovecMatches) {
  // In this test case, we surpass the kNumIovecBufferChains limit
  // (i.e. the number of contiguous buffers we are sending)
  folly::EventBase evb;
  std::shared_ptr<FollyQuicEventBase> qEvb =
      std::make_shared<FollyQuicEventBase>(&evb);
  quic::test::MockAsyncUDPSocket sock(qEvb);

  auto batchWriter = quic::BatchWriterFactory::makeBatchWriter(
      quic::QuicBatchingMode::BATCHING_MODE_SENDMMSG,
      kBatchNum,
      false, /* enable backpressure */
      DataPathType::ChainedMemory,
      conn_,
      gsoSupported_);
  CHECK(batchWriter);

  std::vector<std::vector<std::string>> messages{
      {"It", "is", "sunny!"},
      {"but", "it", "is", "so", "cold"},
      {"my",
       "jacket",
       "isn't",
       "warm",
       "enough",
       "and",
       "my",
       "hands",
       "are",
       "freezing"}};

  CHECK(batchWriter->empty());
  CHECK_EQ(batchWriter->size(), 0);

  std::vector<Buf> buffers;

  size_t size = 0;
  for (auto& message : messages) {
    auto buf = std::make_unique<folly::IOBuf>();
    for (size_t j = 0; j < message.size(); j++) {
      auto partBuf = folly::IOBuf::copyBuffer(folly::ByteRange(
          (unsigned char*)message[j].data(), message[j].size()));
      buf->appendToChain(std::move(partBuf));
    }
    buffers.emplace_back(std::move(buf));
  }

  for (size_t i = 0; i < messages.size(); i++) {
    batchWriter->append(
        buffers[i]->clone(),
        buffers[i]->computeChainDataLength(),
        folly::SocketAddress(),
        nullptr);
    size += buffers[i]->computeChainDataLength();
    CHECK_EQ(batchWriter->size(), size);
  }

  EXPECT_CALL(sock, writem(_, _, _, _))
      .Times(1)
      .WillOnce(Invoke([&](folly::Range<folly::SocketAddress const*> addrs,
                           iovec* iovecs,
                           size_t* messageSizes,
                           size_t count) {
        EXPECT_EQ(addrs.size(), 1);
        EXPECT_EQ(count, messages.size());

        size_t currentIovIndex = 0;
        for (size_t i = 0; i < count; i++) {
          auto wrappedIovBuffer =
              folly::IOBuf::wrapIov(iovecs + currentIovIndex, messageSizes[i]);
          currentIovIndex += messageSizes[i];

          folly::IOBufEqualTo eq;
          EXPECT_TRUE(eq(wrappedIovBuffer, buffers[i]));
        }

        return 0;
      }));

  batchWriter->write(sock, folly::SocketAddress());
}

TEST_F(QuicBatchWriterTest, TestBatchingSendmmsgInplace) {
  auto bufAccessor =
      std::make_unique<BufAccessor>(conn_.udpSendPacketLen * kBatchNum);
  conn_.bufAccessor = bufAccessor.get();

  folly::EventBase evb;
  std::shared_ptr<FollyQuicEventBase> qEvb =
      std::make_shared<FollyQuicEventBase>(&evb);
  quic::test::MockAsyncUDPSocket sock(qEvb);

  gsoSupported_ = false;

  auto batchWriter = quic::BatchWriterFactory::makeBatchWriter(
      quic::QuicBatchingMode::BATCHING_MODE_SENDMMSG,
      kBatchNum,
      false, /* enable backpressure */
      DataPathType::ContinuousMemory,
      conn_,
      gsoSupported_);
  CHECK(batchWriter);

  // run multiple loops
  for (size_t i = 0; i < kNumLoops; i++) {
    std::vector<iovec> expectedIovecs;

    // try to batch up to kBatchNum
    CHECK(batchWriter->empty());
    CHECK_EQ(batchWriter->size(), 0);
    size_t size = 0;
    for (auto j = 0; j < kBatchNum - 1; j++) {
      iovec vec{};
      vec.iov_base = (void*)bufAccessor->buf()->tail();
      vec.iov_len = kStrLen;
      bufAccessor->buf()->append(kStrLen);
      expectedIovecs.push_back(vec);

      EXPECT_FALSE(batchWriter->append(
          nullptr, kStrLen, folly::SocketAddress(), nullptr));
      size += kStrLen;
      CHECK_EQ(batchWriter->size(), size);
    }

    // add the kBatchNum buf
    iovec vec{};
    vec.iov_base = (void*)bufAccessor->buf()->tail();
    vec.iov_len = kStrLen;
    bufAccessor->buf()->append(kStrLen);
    expectedIovecs.push_back(vec);

    CHECK(
        batchWriter->append(nullptr, kStrLen, folly::SocketAddress(), nullptr));
    size += kStrLen;
    CHECK_EQ(batchWriter->size(), size);

    EXPECT_CALL(sock, writem(_, _, _, _))
        .Times(1)
        .WillOnce(Invoke([&](folly::Range<folly::SocketAddress const*> addrs,
                             iovec* iovecs,
                             size_t* messageSizes,
                             size_t count) {
          EXPECT_EQ(addrs.size(), 1);
          EXPECT_EQ(count, kBatchNum);

          for (size_t k = 0; k < count; k++) {
            EXPECT_EQ(messageSizes[k], 1);
            EXPECT_EQ(expectedIovecs[k].iov_base, iovecs[k].iov_base);
            EXPECT_EQ(expectedIovecs[k].iov_len, iovecs[k].iov_len);
          }

          return 0;
        }));
    batchWriter->write(sock, folly::SocketAddress());
    expectedIovecs.clear();
    EXPECT_TRUE(bufAccessor->buf()->empty());

    batchWriter->reset();
  }
}

TEST_F(QuicBatchWriterTest, TestBatchingSendmmsgGSOBatchNum) {
  folly::EventBase evb;
  std::shared_ptr<FollyQuicEventBase> qEvb =
      std::make_shared<FollyQuicEventBase>(&evb);
  FollyQuicAsyncUDPSocket sock(qEvb);
  sock.setReuseAddr(false);
  ASSERT_FALSE(sock.bind(folly::SocketAddress("127.0.0.1", 0)).hasError());
  auto gsoResult = sock.getGSO();
  ASSERT_FALSE(gsoResult.hasError());
  gsoSupported_ = gsoResult.value();

  auto batchWriter = quic::BatchWriterFactory::makeBatchWriter(
      quic::QuicBatchingMode::BATCHING_MODE_SENDMMSG_GSO,
      kBatchNum,
      false, /* enable backpressure */
      DataPathType::ChainedMemory,
      conn_,
      gsoSupported_);
  CHECK(batchWriter);
  std::string strTest(kStrLen, 'A');
  // if GSO is not available, just test we've got a regular
  // batch writer
  if (gsoSupported_) {
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

TEST_F(QuicBatchWriterTest, TestBatchingSendmmsgGSOBatcBigSmallPacket) {
  folly::EventBase evb;
  std::shared_ptr<FollyQuicEventBase> qEvb =
      std::make_shared<FollyQuicEventBase>(&evb);
  FollyQuicAsyncUDPSocket sock(qEvb);
  sock.setReuseAddr(false);
  ASSERT_FALSE(sock.bind(folly::SocketAddress("127.0.0.1", 0)).hasError());
  auto gsoResult = sock.getGSO();
  ASSERT_FALSE(gsoResult.hasError());
  gsoSupported_ = gsoResult.value();

  auto batchWriter = quic::BatchWriterFactory::makeBatchWriter(
      quic::QuicBatchingMode::BATCHING_MODE_SENDMMSG_GSO,
      3 * kBatchNum,
      false, /* enable backpressure */
      DataPathType::ChainedMemory,
      conn_,
      gsoSupported_);
  CHECK(batchWriter);
  std::string strTest(kStrLen, 'A');
  // if GSO is not available, just test we've got a regular
  // batch writer
  if (gsoSupported_) {
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

// Test the case where we send 5 packets, all of the same size, to the
// same address.
TEST_F(QuicBatchWriterTest, TestBatchingSendmmsgGSOInplaceSameSizeAll) {
  gsoSupported_ = true;
  size_t batchSize = 5;
  size_t packetSize = 100;

  folly::EventBase evb;
  std::shared_ptr<FollyQuicEventBase> qEvb =
      std::make_shared<FollyQuicEventBase>(&evb);
  quic::test::MockAsyncUDPSocket sock(qEvb);

  auto bufAccessor =
      std::make_unique<BufAccessor>(conn_.udpSendPacketLen * batchSize);
  conn_.bufAccessor = bufAccessor.get();

  auto batchWriter = quic::BatchWriterFactory::makeBatchWriter(
      quic::QuicBatchingMode::BATCHING_MODE_SENDMMSG_GSO,
      batchSize,
      false, /* enable backpressure */
      DataPathType::ContinuousMemory,
      conn_,
      gsoSupported_);
  CHECK(batchWriter);
  CHECK(batchWriter->empty());
  CHECK_EQ(batchWriter->size(), 0);
  size_t size = 0;
  for (size_t j = 0; j < batchSize - 1; j++) {
    bufAccessor->append(packetSize);
    EXPECT_FALSE(batchWriter->append(
        nullptr, packetSize, folly::SocketAddress(), nullptr));
    size += packetSize;
    EXPECT_EQ(batchWriter->size(), size);
  }
  bufAccessor->append(packetSize);
  EXPECT_TRUE(batchWriter->append(
      nullptr, packetSize, folly::SocketAddress(), nullptr));
  size += packetSize;
  EXPECT_EQ(batchWriter->size(), size);

  EXPECT_CALL(sock, writeGSO(_, _, _, _))
      .Times(1)
      .WillOnce(Invoke([&](const folly::SocketAddress&,
                           const struct iovec* iovecs,
                           size_t iovec_len,
                           QuicAsyncUDPSocket::WriteOptions writeOptions) {
        EXPECT_EQ(iovec_len, 5);
        EXPECT_EQ(writeOptions.gso, packetSize);

        for (uint32_t i = 0; i < 5; i++) {
          EXPECT_EQ(
              iovecs[i].iov_base,
              (uint8_t*)bufAccessor->buf()->buffer() + packetSize * i);
          EXPECT_EQ(iovecs[i].iov_len, packetSize);
        }

        return 1;
      }));
  batchWriter->write(sock, folly::SocketAddress());
  EXPECT_TRUE(bufAccessor->buf()->empty());
}

// Test the case where we do the following for the same address, in order:
// (1) Send 3 packets of the same size
// (2) Send 1 packet that's smaller than the previous 3
// (3) Send 1 packet of the same size as the 3 initial ones
TEST_F(QuicBatchWriterTest, TestBatchingSendmmsgGSOInplaceSmallerSizeInMiddle) {
  gsoSupported_ = true;
  size_t batchSize = 5;

  std::vector<size_t> packetSizes = {100, 100, 100, 70, 100};

  folly::EventBase evb;
  std::shared_ptr<FollyQuicEventBase> qEvb =
      std::make_shared<FollyQuicEventBase>(&evb);
  quic::test::MockAsyncUDPSocket sock(qEvb);

  auto bufAccessor =
      std::make_unique<BufAccessor>(conn_.udpSendPacketLen * batchSize);
  conn_.bufAccessor = bufAccessor.get();

  auto batchWriter = quic::BatchWriterFactory::makeBatchWriter(
      quic::QuicBatchingMode::BATCHING_MODE_SENDMMSG_GSO,
      batchSize,
      false, /* enable backpressure */
      DataPathType::ContinuousMemory,
      conn_,
      gsoSupported_);
  CHECK(batchWriter);
  CHECK(batchWriter->empty());
  CHECK_EQ(batchWriter->size(), 0);
  size_t size = 0;
  for (size_t j = 0; j < batchSize - 1; j++) {
    bufAccessor->append(packetSizes[j]);
    EXPECT_FALSE(batchWriter->append(
        nullptr, packetSizes[j], folly::SocketAddress(), nullptr));
    size += packetSizes[j];
    EXPECT_EQ(batchWriter->size(), size);
  }
  bufAccessor->append(packetSizes[batchSize - 1]);
  EXPECT_TRUE(batchWriter->append(
      nullptr, packetSizes[batchSize - 1], folly::SocketAddress(), nullptr));
  size += packetSizes[batchSize - 1];
  EXPECT_EQ(batchWriter->size(), size);

  EXPECT_CALL(sock, writemGSO(_, _, _, _, _))
      .Times(1)
      .WillOnce(
          Invoke([&](folly::Range<folly::SocketAddress const*> /* addrs */,
                     iovec* iov,
                     size_t* numIovecsInBuffer,
                     size_t count,
                     const QuicAsyncUDPSocket::WriteOptions* options) {
            EXPECT_EQ(count, 2);
            EXPECT_EQ(numIovecsInBuffer[0], 4);
            EXPECT_EQ(numIovecsInBuffer[1], 1);
            EXPECT_EQ(options[0].gso, 100);
            // There's just one packet in the second series, so we don't use GSO
            // there.
            EXPECT_EQ(options[1].gso, 0);

            auto* currBufferAddr = (uint8_t*)bufAccessor->buf()->buffer();
            for (uint32_t i = 0; i < batchSize; i++) {
              EXPECT_EQ(iov[i].iov_base, currBufferAddr);
              EXPECT_EQ(iov[i].iov_len, packetSizes[i]);

              currBufferAddr += packetSizes[i];
            }

            return 2;
          }));
  batchWriter->write(sock, folly::SocketAddress());
  EXPECT_TRUE(bufAccessor->buf()->empty());
}

// Test the case where we do the following for the same address, in order:
// (1) Send 3 packets of the same size
// (2) Send 1 packet that's larger than the previous 3
// (3) Send 1 packet of the same size as the 3 initial ones
TEST_F(QuicBatchWriterTest, TestBatchingSendmmsgGSOInplaceLargerSizeInMiddle) {
  gsoSupported_ = true;
  size_t batchSize = 5;

  std::vector<size_t> packetSizes = {100, 100, 100, 120, 100};

  folly::EventBase evb;
  std::shared_ptr<FollyQuicEventBase> qEvb =
      std::make_shared<FollyQuicEventBase>(&evb);
  quic::test::MockAsyncUDPSocket sock(qEvb);

  auto bufAccessor =
      std::make_unique<BufAccessor>(conn_.udpSendPacketLen * batchSize);
  conn_.bufAccessor = bufAccessor.get();

  auto batchWriter = quic::BatchWriterFactory::makeBatchWriter(
      quic::QuicBatchingMode::BATCHING_MODE_SENDMMSG_GSO,
      batchSize,
      false, /* enable backpressure */
      DataPathType::ContinuousMemory,
      conn_,
      gsoSupported_);
  CHECK(batchWriter);
  CHECK(batchWriter->empty());
  CHECK_EQ(batchWriter->size(), 0);
  size_t size = 0;
  for (size_t j = 0; j < batchSize - 1; j++) {
    bufAccessor->append(packetSizes[j]);
    EXPECT_FALSE(batchWriter->append(
        nullptr, packetSizes[j], folly::SocketAddress(), nullptr));
    size += packetSizes[j];
    EXPECT_EQ(batchWriter->size(), size);
  }
  bufAccessor->append(packetSizes[batchSize - 1]);
  EXPECT_TRUE(batchWriter->append(
      nullptr, packetSizes[batchSize - 1], folly::SocketAddress(), nullptr));
  size += packetSizes[batchSize - 1];
  EXPECT_EQ(batchWriter->size(), size);

  EXPECT_CALL(sock, writemGSO(_, _, _, _, _))
      .Times(1)
      .WillOnce(
          Invoke([&](folly::Range<folly::SocketAddress const*> /* addrs */,
                     iovec* iov,
                     size_t* numIovecsInBuffer,
                     size_t count,
                     const QuicAsyncUDPSocket::WriteOptions* options) {
            EXPECT_EQ(count, 2);
            EXPECT_EQ(numIovecsInBuffer[0], 3);
            EXPECT_EQ(numIovecsInBuffer[1], 2);
            EXPECT_EQ(options[0].gso, 100);
            EXPECT_EQ(options[1].gso, 120);

            auto* currBufferAddr = (uint8_t*)bufAccessor->buf()->buffer();
            for (uint32_t i = 0; i < batchSize; i++) {
              EXPECT_EQ(iov[i].iov_base, currBufferAddr);
              EXPECT_EQ(iov[i].iov_len, packetSizes[i]);

              currBufferAddr += packetSizes[i];
            }

            return 2;
          }));
  batchWriter->write(sock, folly::SocketAddress());
  EXPECT_TRUE(bufAccessor->buf()->empty());
}

// Send 5 packets of the same length.
// Packets 1, 2, and 5 are to address A.
// Packets 3 and 4 are to address B.
TEST_F(QuicBatchWriterTest, TestBatchingSendmmsgGSOInplaceDifferentAddrs) {
  folly::SocketAddress addrA("127.0.0.1", 80);
  folly::SocketAddress addrB("127.0.0.1", 443);

  std::vector<folly::SocketAddress> addrs = {addrA, addrA, addrB, addrB, addrA};

  gsoSupported_ = true;
  size_t batchSize = 5;
  size_t packetSize = 100;

  folly::EventBase evb;
  std::shared_ptr<FollyQuicEventBase> qEvb =
      std::make_shared<FollyQuicEventBase>(&evb);
  quic::test::MockAsyncUDPSocket sock(qEvb);

  auto bufAccessor =
      std::make_unique<BufAccessor>(conn_.udpSendPacketLen * batchSize);
  conn_.bufAccessor = bufAccessor.get();

  auto batchWriter = quic::BatchWriterFactory::makeBatchWriter(
      quic::QuicBatchingMode::BATCHING_MODE_SENDMMSG_GSO,
      batchSize,
      false, /* enable backpressure */
      DataPathType::ContinuousMemory,
      conn_,
      gsoSupported_);
  CHECK(batchWriter);
  CHECK(batchWriter->empty());
  CHECK_EQ(batchWriter->size(), 0);
  size_t size = 0;
  for (size_t j = 0; j < batchSize - 1; j++) {
    bufAccessor->append(packetSize);
    EXPECT_FALSE(batchWriter->append(nullptr, packetSize, addrs[j], nullptr));
    size += packetSize;
    EXPECT_EQ(batchWriter->size(), size);
  }
  bufAccessor->append(packetSize);
  EXPECT_TRUE(
      batchWriter->append(nullptr, packetSize, addrs[batchSize - 1], nullptr));
  size += packetSize;
  EXPECT_EQ(batchWriter->size(), size);

  EXPECT_CALL(sock, writemGSO(_, _, _, _, _))
      .Times(1)
      .WillOnce(Invoke([&](folly::Range<folly::SocketAddress const*> addrs,
                           iovec* iov,
                           size_t* numIovecsInBuffer,
                           size_t count,
                           const QuicAsyncUDPSocket::WriteOptions* options) {
        EXPECT_EQ(count, 2);
        EXPECT_EQ(numIovecsInBuffer[0], 3);
        EXPECT_EQ(numIovecsInBuffer[1], 2);

        EXPECT_EQ(options[0].gso, packetSize);
        EXPECT_EQ(options[1].gso, packetSize);

        // All packets are of size packetSize
        for (uint32_t i = 0; i < batchSize; i++) {
          EXPECT_EQ(iov[i].iov_len, packetSize);
        }

        // If the shared buffer looks like this:
        // [slot1, slot2, slot3, slot4, slot5]
        // Then iov should look like
        // [slot1, slot2, slot5, slot3, slot4]
        auto* bufferStart = (uint8_t*)bufAccessor->buf()->buffer();
        std::vector<uint8_t*> expectedBufferStartPositions = {
            bufferStart,
            bufferStart + packetSize,
            bufferStart + 4 * packetSize,
            bufferStart + 2 * packetSize,
            bufferStart + 3 * packetSize};
        for (uint32_t i = 0; i < batchSize; i++) {
          EXPECT_EQ(iov[i].iov_base, expectedBufferStartPositions[i]);
        }

        EXPECT_EQ(addrs[0], addrA);
        EXPECT_EQ(addrs[1], addrB);

        return 2;
      }));

  batchWriter->write(sock, folly::SocketAddress());
  EXPECT_TRUE(bufAccessor->buf()->empty());
}

// Test the case where we send 5 packets, all of the same size, to the
// same address, with an external writer writing data to the shared buffer right
// before we write the batch.
TEST_F(QuicBatchWriterTest, TestBatchingSendmmsgGSOInplaceExternalDataWritten) {
  gsoSupported_ = true;
  size_t batchSize = 5;
  size_t packetSize = 100;

  folly::EventBase evb;
  std::shared_ptr<FollyQuicEventBase> qEvb =
      std::make_shared<FollyQuicEventBase>(&evb);
  quic::test::MockAsyncUDPSocket sock(qEvb);

  auto bufAccessor =
      std::make_unique<BufAccessor>(conn_.udpSendPacketLen * batchSize);
  conn_.bufAccessor = bufAccessor.get();

  auto batchWriter = quic::BatchWriterFactory::makeBatchWriter(
      quic::QuicBatchingMode::BATCHING_MODE_SENDMMSG_GSO,
      batchSize,
      false, /* enable backpressure */
      DataPathType::ContinuousMemory,
      conn_,
      gsoSupported_);
  CHECK(batchWriter);
  CHECK(batchWriter->empty());
  CHECK_EQ(batchWriter->size(), 0);
  size_t size = 0;
  for (size_t j = 0; j < batchSize - 1; j++) {
    bufAccessor->append(packetSize);
    EXPECT_FALSE(batchWriter->append(
        nullptr, packetSize, folly::SocketAddress(), nullptr));
    size += packetSize;
    EXPECT_EQ(batchWriter->size(), size);
  }
  bufAccessor->append(packetSize);
  EXPECT_TRUE(batchWriter->append(
      nullptr, packetSize, folly::SocketAddress(), nullptr));
  size += packetSize;
  EXPECT_EQ(batchWriter->size(), size);

  EXPECT_CALL(sock, writeGSO(_, _, _, _))
      .Times(1)
      .WillOnce(Invoke([&](const folly::SocketAddress&,
                           const struct iovec* iovecs,
                           size_t iovec_len,
                           QuicAsyncUDPSocket::WriteOptions writeOptions) {
        EXPECT_EQ(iovec_len, 5);
        EXPECT_EQ(writeOptions.gso, packetSize);

        for (uint32_t i = 0; i < 5; i++) {
          EXPECT_EQ(
              iovecs[i].iov_base,
              (uint8_t*)bufAccessor->buf()->buffer() + packetSize * i);
          EXPECT_EQ(iovecs[i].iov_len, packetSize);
        }

        return 1;
      }));
  std::string externalData = "external data";
  memcpy(
      bufAccessor->buf()->writableTail(),
      externalData.data(),
      externalData.size());
  bufAccessor->buf()->append(externalData.size());
  batchWriter->write(sock, folly::SocketAddress());
  EXPECT_EQ(bufAccessor->buf()->length(), externalData.size());
  EXPECT_EQ(
      memcmp(
          externalData.data(), bufAccessor->buf()->data(), externalData.size()),
      0);
}

TEST_F(QuicBatchWriterTest, InplaceWriterNeedsFlush) {
  gsoSupported_ = true;
  uint32_t batchSize = 20;
  auto bufAccessor =
      std::make_unique<BufAccessor>(conn_.udpSendPacketLen * batchSize);
  conn_.bufAccessor = bufAccessor.get();
  auto batchWriter = quic::BatchWriterFactory::makeBatchWriter(
      quic::QuicBatchingMode::BATCHING_MODE_GSO,
      batchSize,
      false, /* enable backpressure */
      DataPathType::ContinuousMemory,
      conn_,
      gsoSupported_);
  CHECK(batchWriter);
  EXPECT_FALSE(batchWriter->needsFlush(1000));

  for (size_t i = 0; i < 10; i++) {
    EXPECT_FALSE(batchWriter->needsFlush(1000));
    batchWriter->append(nullptr, 1000, folly::SocketAddress(), nullptr);
  }
  EXPECT_TRUE(batchWriter->needsFlush(conn_.udpSendPacketLen));
}

TEST_F(QuicBatchWriterTest, InplaceWriterAppendLimit) {
  gsoSupported_ = true;
  uint32_t batchSize = 20;
  auto bufAccessor =
      std::make_unique<BufAccessor>(conn_.udpSendPacketLen * batchSize);
  conn_.bufAccessor = bufAccessor.get();
  auto batchWriter = quic::BatchWriterFactory::makeBatchWriter(
      quic::QuicBatchingMode::BATCHING_MODE_GSO,
      batchSize,
      false, /* enable backpressure */
      DataPathType::ContinuousMemory,
      conn_,
      gsoSupported_);
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

TEST_F(QuicBatchWriterTest, InplaceWriterAppendSmaller) {
  gsoSupported_ = true;
  uint32_t batchSize = 20;
  auto bufAccessor =
      std::make_unique<BufAccessor>(conn_.udpSendPacketLen * batchSize);
  conn_.bufAccessor = bufAccessor.get();
  auto batchWriter = quic::BatchWriterFactory::makeBatchWriter(
      quic::QuicBatchingMode::BATCHING_MODE_GSO,
      batchSize,
      false, /* enable backpressure */
      DataPathType::ContinuousMemory,
      conn_,
      gsoSupported_);
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

TEST_F(QuicBatchWriterTest, InplaceWriterWriteAll) {
  folly::EventBase evb;
  std::shared_ptr<FollyQuicEventBase> qEvb =
      std::make_shared<FollyQuicEventBase>(&evb);
  quic::test::MockAsyncUDPSocket sock(qEvb);
  uint32_t batchSize = 20;
  auto bufAccessor =
      std::make_unique<BufAccessor>(conn_.udpSendPacketLen * batchSize);
  conn_.bufAccessor = bufAccessor.get();
  gsoSupported_ = true;
  auto batchWriter = quic::BatchWriterFactory::makeBatchWriter(
      quic::QuicBatchingMode::BATCHING_MODE_GSO,
      batchSize,
      false, /* enable backpressure */
      DataPathType::ContinuousMemory,
      conn_,
      gsoSupported_);
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

  EXPECT_CALL(sock, writeGSO(_, _, _, _))
      .Times(1)
      .WillOnce(Invoke([&](const auto& /* addr */,
                           const struct iovec* vec,
                           size_t,
                           QuicAsyncUDPSocket::WriteOptions options) {
        EXPECT_EQ(1000 * 5 + 700, vec[0].iov_len);
        EXPECT_EQ(1000, options.gso);
        return 1000 * 5 + 700;
      }));
  EXPECT_EQ(1000 * 5 + 700, batchWriter->write(sock, folly::SocketAddress()));

  EXPECT_TRUE(bufAccessor->ownsBuffer());
  buf = bufAccessor->obtain();
  EXPECT_EQ(0, buf->length());
}

TEST_F(QuicBatchWriterTest, InplaceWriterWriteOne) {
  folly::EventBase evb;
  std::shared_ptr<FollyQuicEventBase> qEvb =
      std::make_shared<FollyQuicEventBase>(&evb);
  quic::test::MockAsyncUDPSocket sock(qEvb);
  uint32_t batchSize = 20;
  auto bufAccessor =
      std::make_unique<BufAccessor>(conn_.udpSendPacketLen * batchSize);
  conn_.bufAccessor = bufAccessor.get();
  gsoSupported_ = true;
  auto batchWriter = quic::BatchWriterFactory::makeBatchWriter(
      quic::QuicBatchingMode::BATCHING_MODE_GSO,
      batchSize,
      false, /* enable backpressure */
      DataPathType::ContinuousMemory,
      conn_,
      gsoSupported_);
  CHECK(batchWriter);
  ASSERT_FALSE(batchWriter->needsFlush(1000));

  auto buf = bufAccessor->obtain();
  buf->append(1000);
  bufAccessor->release(std::move(buf));
  ASSERT_FALSE(
      batchWriter->append(nullptr, 1000, folly::SocketAddress(), nullptr));

  EXPECT_CALL(sock, writeGSO(_, _, _, _))
      .Times(1)
      .WillOnce(Invoke(
          [&](const auto& /* addr */, const struct iovec* vec, size_t, auto) {
            EXPECT_EQ(1000, vec[0].iov_len);
            return 1000;
          }));
  EXPECT_EQ(1000, batchWriter->write(sock, folly::SocketAddress()));

  EXPECT_TRUE(bufAccessor->ownsBuffer());
  buf = bufAccessor->obtain();
  EXPECT_EQ(0, buf->length());
}

TEST_F(QuicBatchWriterTest, InplaceWriterLastOneTooBig) {
  folly::EventBase evb;
  std::shared_ptr<FollyQuicEventBase> qEvb =
      std::make_shared<FollyQuicEventBase>(&evb);
  quic::test::MockAsyncUDPSocket sock(qEvb);
  uint32_t batchSize = 20;
  auto bufAccessor =
      std::make_unique<BufAccessor>(conn_.udpSendPacketLen * batchSize);
  conn_.bufAccessor = bufAccessor.get();
  gsoSupported_ = true;
  auto batchWriter = quic::BatchWriterFactory::makeBatchWriter(
      quic::QuicBatchingMode::BATCHING_MODE_GSO,
      batchSize,
      false, /* enable backpressure */
      DataPathType::ContinuousMemory,
      conn_,
      gsoSupported_);
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

  EXPECT_CALL(sock, writeGSO(_, _, _, _))
      .Times(1)
      .WillOnce(Invoke([&](const auto& /* addr */,
                           const struct iovec* vec,
                           size_t,
                           QuicAsyncUDPSocket::WriteOptions options) {
        EXPECT_EQ(5 * 700, vec[0].iov_len);
        EXPECT_EQ(700, options.gso);
        return 700 * 5;
      }));
  EXPECT_EQ(5 * 700, batchWriter->write(sock, folly::SocketAddress()));

  EXPECT_TRUE(bufAccessor->ownsBuffer());
  buf = bufAccessor->obtain();
  EXPECT_EQ(1000, buf->length());
  EXPECT_EQ(0, buf->headroom());
}

TEST_F(QuicBatchWriterTest, InplaceWriterBufResidueCheck) {
  folly::EventBase evb;
  std::shared_ptr<FollyQuicEventBase> qEvb =
      std::make_shared<FollyQuicEventBase>(&evb);
  quic::test::MockAsyncUDPSocket sock(qEvb);
  gsoSupported_ = true;

  uint32_t batchSize = 20;
  auto bufAccessor =
      std::make_unique<BufAccessor>(conn_.udpSendPacketLen * batchSize);
  conn_.bufAccessor = bufAccessor.get();
  conn_.udpSendPacketLen = 1000;
  auto batchWriter = quic::BatchWriterFactory::makeBatchWriter(
      quic::QuicBatchingMode::BATCHING_MODE_GSO,
      batchSize,
      false, /* enable backpressure */
      DataPathType::ContinuousMemory,
      conn_,
      gsoSupported_);
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

  EXPECT_CALL(sock, writeGSO(_, _, _, _))
      .Times(1)
      .WillOnce(Invoke(
          [&](const auto& /* addr */, const struct iovec* vec, size_t, auto) {
            EXPECT_EQ(700, vec[0].iov_len);
            return 700;
          }));
  // No crash:
  EXPECT_EQ(700, batchWriter->write(sock, folly::SocketAddress()));
  EXPECT_EQ(1009, rawBuf->length());
  EXPECT_EQ(0, rawBuf->headroom());
}

class SinglePacketInplaceBatchWriterTest : public ::testing::Test {
 public:
  SinglePacketInplaceBatchWriterTest()
      : conn_(FizzServerQuicHandshakeContext::Builder().build()) {}

  void SetUp() override {
    bufAccessor_ = std::make_unique<quic::BufAccessor>(conn_.udpSendPacketLen);
    conn_.bufAccessor = bufAccessor_.get();
  }

  quic::BatchWriterPtr makeBatchWriter(
      quic::QuicBatchingMode batchingMode =
          quic::QuicBatchingMode::BATCHING_MODE_NONE) {
    return quic::BatchWriterFactory::makeBatchWriter(
        batchingMode,
        conn_.transportSettings.maxBatchSize,
        conn_.transportSettings.enableWriterBackpressure,
        conn_.transportSettings.dataPathType,
        conn_,
        false /* gsoSupported_ */);
  }

  void enableSinglePacketInplaceBatchWriter() {
    conn_.transportSettings.maxBatchSize = 1;
    conn_.transportSettings.dataPathType = DataPathType::ContinuousMemory;
  }

 protected:
  std::unique_ptr<quic::BufAccessor> bufAccessor_;
  QuicServerConnectionState conn_;
};

TEST_F(SinglePacketInplaceBatchWriterTest, TestFactorySuccess) {
  enableSinglePacketInplaceBatchWriter();

  auto batchWriter = makeBatchWriter();
  CHECK(batchWriter);
  CHECK(dynamic_cast<quic::SinglePacketInplaceBatchWriter*>(batchWriter.get()));
}

TEST_F(SinglePacketInplaceBatchWriterTest, TestFactoryNoTransportSetting) {
  conn_.transportSettings.maxBatchSize = 1;
  conn_.transportSettings.dataPathType = DataPathType::ChainedMemory;
  auto batchWriter = makeBatchWriter();
  CHECK(batchWriter);
  EXPECT_EQ(
      dynamic_cast<quic::SinglePacketInplaceBatchWriter*>(batchWriter.get()),
      nullptr);
}

TEST_F(SinglePacketInplaceBatchWriterTest, TestFactoryNoTransportSetting2) {
  conn_.transportSettings.maxBatchSize = 16;
  conn_.transportSettings.dataPathType = DataPathType::ContinuousMemory;
  auto batchWriter = makeBatchWriter();
  CHECK(batchWriter);
  EXPECT_EQ(
      dynamic_cast<quic::SinglePacketInplaceBatchWriter*>(batchWriter.get()),
      nullptr);
}

TEST_F(SinglePacketInplaceBatchWriterTest, TestFactoryWrongBatchingMode) {
  enableSinglePacketInplaceBatchWriter();

  auto batchWriter = makeBatchWriter(quic::QuicBatchingMode::BATCHING_MODE_GSO);
  CHECK(batchWriter);
  EXPECT_EQ(
      dynamic_cast<quic::SinglePacketInplaceBatchWriter*>(batchWriter.get()),
      nullptr);
}

TEST_F(SinglePacketInplaceBatchWriterTest, TestReset) {
  enableSinglePacketInplaceBatchWriter();

  auto batchWriter = makeBatchWriter();
  CHECK(batchWriter);
  CHECK(dynamic_cast<quic::SinglePacketInplaceBatchWriter*>(batchWriter.get()));

  auto buf = bufAccessor_->obtain();
  folly::IOBuf* rawBuf = buf.get();
  bufAccessor_->release(std::move(buf));
  rawBuf->append(700);

  EXPECT_EQ(rawBuf->computeChainDataLength(), 700);
  batchWriter->reset();
  EXPECT_EQ(rawBuf->computeChainDataLength(), 0);
}

TEST_F(SinglePacketInplaceBatchWriterTest, TestAppend) {
  enableSinglePacketInplaceBatchWriter();

  auto batchWriter = makeBatchWriter();
  CHECK(batchWriter);
  CHECK(dynamic_cast<quic::SinglePacketInplaceBatchWriter*>(batchWriter.get()));

  EXPECT_EQ(
      true, batchWriter->append(nullptr, 0, folly::SocketAddress(), nullptr));
}

TEST_F(SinglePacketInplaceBatchWriterTest, TestEmpty) {
  enableSinglePacketInplaceBatchWriter();

  auto batchWriter = makeBatchWriter();
  CHECK(batchWriter);
  CHECK(dynamic_cast<quic::SinglePacketInplaceBatchWriter*>(batchWriter.get()));
  EXPECT_TRUE(batchWriter->empty());

  auto buf = bufAccessor_->obtain();
  folly::IOBuf* rawBuf = buf.get();
  bufAccessor_->release(std::move(buf));
  rawBuf->append(700);

  EXPECT_EQ(rawBuf->computeChainDataLength(), 700);
  EXPECT_FALSE(batchWriter->empty());

  batchWriter->reset();
  EXPECT_TRUE(batchWriter->empty());
}

TEST_F(SinglePacketInplaceBatchWriterTest, TestWrite) {
  enableSinglePacketInplaceBatchWriter();

  auto batchWriter = makeBatchWriter();
  CHECK(batchWriter);
  CHECK(dynamic_cast<quic::SinglePacketInplaceBatchWriter*>(batchWriter.get()));
  EXPECT_TRUE(batchWriter->empty());

  auto buf = bufAccessor_->obtain();
  folly::IOBuf* rawBuf = buf.get();
  bufAccessor_->release(std::move(buf));
  const auto appendSize = conn_.udpSendPacketLen - 200;
  rawBuf->append(appendSize);

  EXPECT_EQ(rawBuf->computeChainDataLength(), appendSize);
  EXPECT_FALSE(batchWriter->empty());

  folly::EventBase evb;
  std::shared_ptr<FollyQuicEventBase> qEvb =
      std::make_shared<FollyQuicEventBase>(&evb);
  quic::test::MockAsyncUDPSocket sock(qEvb);
  EXPECT_CALL(sock, write(_, _, _))
      .Times(1)
      .WillOnce(
          Invoke([&](const auto& /* addr */, const struct iovec* vec, size_t) {
            EXPECT_EQ(appendSize, vec[0].iov_len);
            return appendSize;
          }));
  EXPECT_EQ(appendSize, batchWriter->write(sock, folly::SocketAddress()));
  EXPECT_TRUE(batchWriter->empty());
}

struct SinglePacketBackpressureBatchWriterTest : public ::testing::Test {
  SinglePacketBackpressureBatchWriterTest()
      : conn_(FizzServerQuicHandshakeContext::Builder().build()),
        qEvb_(std::make_shared<FollyQuicEventBase>(&evb_)),
        sock_(qEvb_) {
    conn_.transportSettings.dataPathType = DataPathType::ChainedMemory;
    conn_.transportSettings.batchingMode = QuicBatchingMode::BATCHING_MODE_NONE;
    conn_.transportSettings.maxBatchSize = 1;
    conn_.transportSettings.enableWriterBackpressure = true;
    conn_.transportSettings.useSockWritableEvents = true;
  }

  BatchWriterPtr makeBatchWriter() {
    return quic::BatchWriterFactory::makeBatchWriter(
        conn_.transportSettings.batchingMode,
        conn_.transportSettings.maxBatchSize,
        conn_.transportSettings.enableWriterBackpressure,
        conn_.transportSettings.dataPathType,
        conn_,
        false /* gsoSupported */);
  }

 protected:
  QuicServerConnectionState conn_;
  folly::EventBase evb_;
  std::shared_ptr<FollyQuicEventBase> qEvb_;
  quic::test::MockAsyncUDPSocket sock_;
};

TEST_F(SinglePacketBackpressureBatchWriterTest, TestAppendRequestsFlush) {
  auto batchWriter = makeBatchWriter();
  CHECK(batchWriter);
  CHECK(dynamic_cast<quic::SinglePacketBackpressureBatchWriter*>(
      batchWriter.get()));
  EXPECT_TRUE(batchWriter->empty());

  auto buf = folly::IOBuf::copyBuffer("append attempt");
  EXPECT_TRUE(batchWriter->append(
      std::move(buf),
      buf->computeChainDataLength(),
      folly::SocketAddress(),
      &sock_));
}

TEST_F(SinglePacketBackpressureBatchWriterTest, TestFailedWriteCachedOnEAGAIN) {
  auto batchWriter = makeBatchWriter();
  CHECK(batchWriter);
  CHECK(dynamic_cast<quic::SinglePacketBackpressureBatchWriter*>(
      batchWriter.get()));
  EXPECT_TRUE(batchWriter->empty());

  std::string testString = "append attempt";
  auto buf = folly::IOBuf::copyBuffer(testString);

  EXPECT_TRUE(batchWriter->append(
      std::move(buf),
      buf->computeChainDataLength(),
      folly::SocketAddress(),
      &sock_));

  EXPECT_CALL(sock_, write(_, _, _))
      .Times(1)
      .WillOnce(Invoke([&](const auto& /* addr */,
                           const struct iovec* /* vec */,
                           size_t /* iovec_len */) {
        errno = EAGAIN;
        return 0;
      }));
  // The write fails
  EXPECT_EQ(batchWriter->write(sock_, folly::SocketAddress()), 0);

  // Resetting does not clear the cached buffer from the writer but the buffer
  // is not yet cached in the transport.
  batchWriter->reset();
  EXPECT_FALSE(conn_.pendingWriteBatch_.buf);

  // Destroying the writer caches the buffer in the transport.
  batchWriter = nullptr;
  EXPECT_TRUE(conn_.pendingWriteBatch_.buf);

  // A new batch writer picks up the cached buffer from the transport
  batchWriter = makeBatchWriter();
  EXPECT_FALSE(conn_.pendingWriteBatch_.buf);

  // The write succeeds
  EXPECT_CALL(sock_, write(_, _, _))
      .Times(1)
      .WillOnce(Invoke([&](const auto& /* addr */,
                           const struct iovec* vec,
                           size_t iovec_len) {
        return ::quic::test::getTotalIovecLen(vec, iovec_len);
      }));
  EXPECT_EQ(
      batchWriter->write(sock_, folly::SocketAddress()), testString.size());

  // Nothing is cached in the transport after the writer is reset and destroyed.
  batchWriter->reset();
  batchWriter = nullptr;
  EXPECT_FALSE(conn_.pendingWriteBatch_.buf);
}

} // namespace quic::testing
