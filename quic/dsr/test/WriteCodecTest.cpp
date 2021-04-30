/*
 * Copyright (c) Facebook, Inc. and its affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 *
 */

#include <quic/dsr/WriteCodec.h>

#include <folly/portability/GTest.h>
#include <quic/QuicConstants.h>
#include <quic/dsr/test/MockDSRPacketBuilder.h>
#include <quic/dsr/test/Mocks.h>

using namespace testing;

namespace quic {
namespace test {

class WriteCodecTest : public Test {
 public:
  void SetUp() override {
    EXPECT_CALL(builder_, remainingSpaceNonConst())
        .WillRepeatedly(Invoke([&]() { return packetSize_; }));
  }

 protected:
  size_t packetSize_{kDefaultUDPSendPacketLen};
  MockDSRPacketBuilder builder_;
};

TEST_F(WriteCodecTest, NoPacketSize) {
  packetSize_ = 0;
  EXPECT_EQ(folly::none, writeDSRStreamFrame(builder_, 0, 0, 100, 100, true));
}

TEST_F(WriteCodecTest, TooSmallPacketSize) {
  packetSize_ = 1;
  EXPECT_EQ(folly::none, writeDSRStreamFrame(builder_, 0, 0, 100, 100, true));
}

TEST_F(WriteCodecTest, RegularWrite) {
  StreamId stream = 1;
  uint64_t offset = 65535;
  bool fin = false;
  uint64_t dataLen = 1000;
  uint64_t flowControlLen = 1000;
  auto result = writeDSRStreamFrame(
      builder_, stream, offset, dataLen, flowControlLen, fin);
  EXPECT_TRUE(result.has_value());
  EXPECT_GT(result->encodedSize, 0);
  EXPECT_EQ(stream, result->sendInstruction.streamId);
  EXPECT_EQ(offset, result->sendInstruction.offset);
  EXPECT_EQ(dataLen, result->sendInstruction.len);
  EXPECT_EQ(fin, result->sendInstruction.fin);
}

TEST_F(WriteCodecTest, PacketSizeLimit) {
  StreamId stream = 1;
  uint64_t offset = 65535;
  bool fin = false;
  uint64_t dataLen = 1000 * 1000;
  uint64_t flowControlLen = 1000 * 1000;
  auto result = writeDSRStreamFrame(
      builder_, stream, offset, dataLen, flowControlLen, fin);
  EXPECT_TRUE(result.has_value());
  EXPECT_GT(result->encodedSize, 0);
  EXPECT_EQ(stream, result->sendInstruction.streamId);
  EXPECT_EQ(offset, result->sendInstruction.offset);
  EXPECT_GT(dataLen, result->sendInstruction.len);
  EXPECT_EQ(fin, result->sendInstruction.fin);
}

TEST_F(WriteCodecTest, FlowControlLimit) {
  StreamId stream = 1;
  uint64_t offset = 65535;
  bool fin = false;
  uint64_t dataLen = 1000 * 1000;
  uint64_t flowControlLen = 500;
  auto result = writeDSRStreamFrame(
      builder_, stream, offset, dataLen, flowControlLen, fin);
  EXPECT_TRUE(result.has_value());
  EXPECT_GT(result->encodedSize, 0);
  EXPECT_EQ(stream, result->sendInstruction.streamId);
  EXPECT_EQ(offset, result->sendInstruction.offset);
  EXPECT_EQ(flowControlLen, result->sendInstruction.len);
  EXPECT_EQ(fin, result->sendInstruction.fin);
}

TEST_F(WriteCodecTest, NoSpaceForData) {
  StreamId stream = 1;
  uint64_t offset = 1;
  bool fin = false;
  uint64_t dataLen = 1000;
  uint64_t flowControlLen = 1000;
  packetSize_ = 3;
  auto result = writeDSRStreamFrame(
      builder_, stream, offset, dataLen, flowControlLen, fin);
  EXPECT_FALSE(result.has_value());
}

TEST_F(WriteCodecTest, CanHaveOneByteData) {
  StreamId stream = 1;
  uint64_t offset = 1;
  bool fin = false;
  uint64_t dataLen = 10;
  uint64_t flowControlLen = 10;
  packetSize_ = 4;
  auto result = writeDSRStreamFrame(
      builder_, stream, offset, dataLen, flowControlLen, fin);
  EXPECT_TRUE(result.has_value());
  EXPECT_GT(result->encodedSize, 0);
  EXPECT_EQ(stream, result->sendInstruction.streamId);
  EXPECT_EQ(offset, result->sendInstruction.offset);
  EXPECT_EQ(1, result->sendInstruction.len);
  EXPECT_EQ(fin, result->sendInstruction.fin);
}

TEST_F(WriteCodecTest, PacketSpaceEqStreamHeaderSize) {
  StreamId stream = 1;
  uint64_t offset = 0;
  bool fin = true;
  uint64_t dataLen = 10;
  uint64_t flowControlLen = 10;
  packetSize_ = 2;
  auto result = writeDSRStreamFrame(
      builder_, stream, offset, dataLen, flowControlLen, fin);
  EXPECT_FALSE(result.has_value());
}

TEST_F(WriteCodecTest, PacketSpaceEqStreamHeaderSizeWithFIN) {
  StreamId stream = 1;
  uint64_t offset = 0;
  bool fin = true;
  uint64_t dataLen = 0;
  uint64_t flowControlLen = 10;
  packetSize_ = 2;
  auto result = writeDSRStreamFrame(
      builder_, stream, offset, dataLen, flowControlLen, fin);
  EXPECT_TRUE(result.has_value());
  EXPECT_GT(result->encodedSize, 0);
  EXPECT_EQ(stream, result->sendInstruction.streamId);
  EXPECT_EQ(offset, result->sendInstruction.offset);
  EXPECT_EQ(0, result->sendInstruction.len);
  EXPECT_TRUE(result->sendInstruction.fin);
}

TEST_F(WriteCodecTest, WriteFIN) {
  StreamId stream = 1;
  uint64_t offset = 1;
  bool fin = true;
  uint64_t dataLen = 10;
  uint64_t flowControlLen = 10;
  auto result = writeDSRStreamFrame(
      builder_, stream, offset, dataLen, flowControlLen, fin);
  EXPECT_TRUE(result.has_value());
  EXPECT_GT(result->encodedSize, 0);
  EXPECT_EQ(stream, result->sendInstruction.streamId);
  EXPECT_EQ(offset, result->sendInstruction.offset);
  EXPECT_EQ(10, result->sendInstruction.len);
  EXPECT_TRUE(result->sendInstruction.fin);
}

TEST_F(WriteCodecTest, FINWithoutData) {
  StreamId stream = 1;
  uint64_t offset = 1;
  bool fin = true;
  uint64_t dataLen = 0;
  uint64_t flowControlLen = 10;
  auto result = writeDSRStreamFrame(
      builder_, stream, offset, dataLen, flowControlLen, fin);
  EXPECT_TRUE(result.has_value());
  EXPECT_GT(result->encodedSize, 0);
  EXPECT_EQ(stream, result->sendInstruction.streamId);
  EXPECT_EQ(offset, result->sendInstruction.offset);
  EXPECT_EQ(0, result->sendInstruction.len);
  EXPECT_TRUE(result->sendInstruction.fin);
}

TEST_F(WriteCodecTest, NoFINNoData) {
  StreamId stream = 1;
  uint64_t offset = 1;
  bool fin = false;
  uint64_t dataLen = 0;
  uint64_t flowControlLen = 10;
  EXPECT_THROW(
      writeDSRStreamFrame(
          builder_, stream, offset, dataLen, flowControlLen, fin),
      QuicInternalException);
}
} // namespace test
} // namespace quic
