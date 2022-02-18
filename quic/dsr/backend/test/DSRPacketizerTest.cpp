/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <folly/portability/GTest.h>
#include <quic/common/test/TestUtils.h>
#include <quic/dsr/backend/DSRPacketizer.h>
#include <quic/dsr/backend/test/TestUtils.h>
#include <quic/dsr/frontend/WriteFunctions.h>
#include <quic/dsr/test/TestCommon.h>

using namespace testing;

namespace {
fizz::TrafficKey getFizzTestKey() {
  fizz::TrafficKey testKey;
  auto quicKey = quic::test::getQuicTestKey();
  testKey.key = std::move(quicKey.key);
  testKey.iv = std::move(quicKey.iv);
  return testKey;
}
} // namespace

namespace quic {
namespace test {

class DSRPacketizerTest : public DSRCommonTestFixture {};

TEST_F(DSRPacketizerTest, BuildCipher) {
  CipherBuilder cipherBuilder;
  auto cipherPair = cipherBuilder.buildCiphers(
      getFizzTestKey(),
      fizz::CipherSuite::TLS_AES_128_GCM_SHA256,
      packetProtectionKey_->clone());
  EXPECT_NE(cipherPair.aead, nullptr);
  EXPECT_NE(cipherPair.headerCipher, nullptr);
}

class DSRPacketizerSingleWriteTest : public Test {
 protected:
  void SetUp() override {
    aead = test::createNoOpAead();
    headerCipher = test::createNoOpHeaderCipher();
  }

  folly::EventBase evb;
  folly::SocketAddress peerAddress{"127.0.0.1", 1234};
  std::unique_ptr<Aead> aead;
  std::unique_ptr<PacketNumberCipher> headerCipher;
};

TEST_F(DSRPacketizerSingleWriteTest, SingleWrite) {
  auto testBatchWriter = new test::TestPacketBatchWriter(16);
  auto batchWriter = BatchWriterPtr(testBatchWriter);
  auto socket =
      std::make_unique<NiceMock<folly::test::MockAsyncUDPSocket>>(&evb);
  IOBufQuicBatch ioBufBatch(
      std::move(batchWriter),
      false /* threadLocal */,
      *socket,
      peerAddress,
      nullptr /* statsCallback */,
      nullptr /* happyEyeballsState */);
  PacketNum packetNum = 20;
  PacketNum largestAckedByPeer = 0;
  StreamId streamId = 0;
  size_t offset = 0;
  size_t length = 100;
  bool eof = false;
  auto dcid = test::getTestConnectionId();
  auto ret = writeSingleQuicPacket(
      ioBufBatch,
      dcid,
      packetNum,
      largestAckedByPeer,
      *aead,
      *headerCipher,
      streamId,
      offset,
      length,
      eof,
      test::buildRandomInputData(5000));
  EXPECT_TRUE(ret);
  // This sucks. But i can't think of a better way to verify we do not
  // write a stream frame length into the packet.
  EXPECT_EQ(
      testBatchWriter->getBufSize(),
      1 /* short header initial byte */ + 1 /* packet num */ +
          dcid.size() /* dcid */ + 1 /* stream frame initial byte */ +
          1 /* stream id */ + length /* actual data */ +
          aead->getCipherOverhead());
  ioBufBatch.flush();
  EXPECT_EQ(1, ioBufBatch.getPktSent());
}

TEST_F(DSRPacketizerSingleWriteTest, NotEnoughData) {
  auto batchWriter = BatchWriterPtr(new test::TestPacketBatchWriter(16));
  auto socket =
      std::make_unique<NiceMock<folly::test::MockAsyncUDPSocket>>(&evb);
  IOBufQuicBatch ioBufBatch(
      std::move(batchWriter),
      false /* threadLocal */,
      *socket,
      peerAddress,
      nullptr /* statsCallback */,
      nullptr /* happyEyeballsState */);
  PacketNum packetNum = 20;
  PacketNum largestAckedByPeer = 0;
  StreamId streamId = 0;
  size_t offset = 0;
  size_t length = 100;
  bool eof = false;
  auto ret = writeSingleQuicPacket(
      ioBufBatch,
      test::getTestConnectionId(),
      packetNum,
      largestAckedByPeer,
      *aead,
      *headerCipher,
      streamId,
      offset,
      length,
      eof,
      folly::IOBuf::copyBuffer("Clif"));
  EXPECT_FALSE(ret);
  ioBufBatch.flush();
  EXPECT_EQ(0, ioBufBatch.getPktSent());
}

class DSRMultiWriteTest : public DSRCommonTestFixture {
 protected:
  FizzCryptoFactory factory_;
  folly::EventBase evb;
};

TEST_F(DSRMultiWriteTest, TwoRequestsWithLoss) {
  prepareFlowControlAndStreamLimit();
  auto streamId = prepareOneStream(1000);
  auto stream = conn_.streamManager->findStream(streamId);
  auto bufMetaStartingOffset = stream->writeBufMeta.offset;
  // Move part of the BufMetas to lossBufMetas
  auto split = stream->writeBufMeta.split(500);
  stream->lossBufMetas.push_back(split);
  size_t packetLimit = 10;
  EXPECT_EQ(
      2,
      writePacketizationRequest(
          conn_, getTestConnectionId(), packetLimit, *aead_));
  EXPECT_EQ(2, countInstructions(streamId));
  EXPECT_EQ(2, conn_.outstandings.packets.size());
  auto& packet1 = conn_.outstandings.packets.front().packet;
  auto& packet2 = conn_.outstandings.packets.back().packet;
  EXPECT_EQ(1, packet1.frames.size());
  WriteStreamFrame expectedFirstFrame(
      streamId, bufMetaStartingOffset, 500, false, true);
  WriteStreamFrame expectedSecondFrame(
      streamId, 500 + bufMetaStartingOffset, 500, true, true);
  EXPECT_EQ(expectedFirstFrame, *packet1.frames[0].asWriteStreamFrame());
  EXPECT_EQ(expectedSecondFrame, *packet2.frames[0].asWriteStreamFrame());

  std::vector<Buf> sentData;
  auto sock = std::make_unique<NiceMock<folly::test::MockAsyncUDPSocket>>(&evb);
  EXPECT_CALL(*sock, writeGSO(conn_.peerAddress, _, _))
      .WillRepeatedly(Invoke([&](const folly::SocketAddress&,
                                 const std::unique_ptr<folly::IOBuf>& buf,
                                 int) {
        sentData.push_back(buf->clone());
        return buf->computeChainDataLength();
      }));
  EXPECT_CALL(*sock, write(conn_.peerAddress, _))
      .WillRepeatedly(Invoke([&](const folly::SocketAddress&,
                                 const std::unique_ptr<folly::IOBuf>& buf) {
        sentData.push_back(buf->clone());
        return buf->computeChainDataLength();
      }));
  auto& instruction = pendingInstructions_.front();
  CipherBuilder builder;
  auto cipherPair = builder.buildCiphers(
      fizz::TrafficKey{
          std::move(instruction.trafficKey.key),
          std::move(instruction.trafficKey.iv)},
      instruction.cipherSuite,
      instruction.packetProtectionKey->clone());
  RequestGroup requests{
      instruction.dcid,
      instruction.scid,
      instruction.clientAddress,
      &cipherPair,
      {}};

  for (const auto& i : pendingInstructions_) {
    requests.requests.push_back(sendInstructionToPacketizationRequest(i));
  }
  auto result =
      writePacketsGroup(*sock, requests, [](const PacketizationRequest& req) {
        return buildRandomInputData(req.len);
      });
  EXPECT_EQ(2, result.packetsSent);
  EXPECT_EQ(2, sentData.size());
  EXPECT_GT(sentData[0]->computeChainDataLength(), 500);
  EXPECT_GT(sentData[1]->computeChainDataLength(), 500);
}

} // namespace test
} // namespace quic
