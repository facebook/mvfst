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

using namespace testing;

namespace quic {
namespace test {

TEST(WriteCodecTest, NoPacketSize) {
  EXPECT_EQ(std::nullopt, writeDSRStreamFrame(0, 0, 0, 100, 100, true));
}

TEST(WriteCodecTest, TooSmallPacketSize) {
  EXPECT_EQ(std::nullopt, writeDSRStreamFrame(1, 0, 0, 100, 100, true));
}

TEST(WriteCodecTest, RegularWrite) {
  StreamId stream = 1;
  uint64_t offset = 65535;
  bool fin = false;
  uint64_t dataLen = 1000;
  uint64_t flowControlLen = 1000;
  auto result = writeDSRStreamFrame(
      kDefaultUDPSendPacketLen, stream, offset, dataLen, flowControlLen, fin);
  EXPECT_TRUE(result.has_value());
  EXPECT_GT(result->encodedSize, 0);
  EXPECT_EQ(stream, result->sendInstruction.streamId);
  EXPECT_EQ(offset, result->sendInstruction.offset);
  EXPECT_EQ(dataLen, result->sendInstruction.len);
  EXPECT_EQ(fin, result->sendInstruction.fin);
}

TEST(WriteCodecTest, PacketSizeLimit) {
  StreamId stream = 1;
  uint64_t offset = 65535;
  bool fin = false;
  uint64_t dataLen = 1000 * 1000;
  uint64_t flowControlLen = 1000 * 1000;
  auto packetSizeLimit = kDefaultUDPSendPacketLen;
  auto result = writeDSRStreamFrame(
      packetSizeLimit, stream, offset, dataLen, flowControlLen, fin);
  EXPECT_TRUE(result.has_value());
  EXPECT_GT(result->encodedSize, 0);
  EXPECT_EQ(stream, result->sendInstruction.streamId);
  EXPECT_EQ(offset, result->sendInstruction.offset);
  EXPECT_GT(dataLen, result->sendInstruction.len);
  EXPECT_GT(packetSizeLimit, result->sendInstruction.len);
  EXPECT_EQ(fin, result->sendInstruction.fin);
}

TEST(WriteCodecTest, FlowControlLimit) {
  StreamId stream = 1;
  uint64_t offset = 65535;
  bool fin = false;
  uint64_t dataLen = 1000 * 1000;
  uint64_t flowControlLen = 500;
  auto packetSizeLimit = kDefaultUDPSendPacketLen;
  auto result = writeDSRStreamFrame(
      packetSizeLimit, stream, offset, dataLen, flowControlLen, fin);
  EXPECT_TRUE(result.has_value());
  EXPECT_GT(result->encodedSize, 0);
  EXPECT_EQ(stream, result->sendInstruction.streamId);
  EXPECT_EQ(offset, result->sendInstruction.offset);
  EXPECT_EQ(flowControlLen, result->sendInstruction.len);
  EXPECT_EQ(fin, result->sendInstruction.fin);
}

TEST(WriteCodecTest, NoSpaceForData) {
  StreamId stream = 1;
  uint64_t offset = 1;
  bool fin = false;
  uint64_t dataLen = 1000;
  uint64_t flowControlLen = 1000;
  auto packetSizeLimit = 3;
  auto result = writeDSRStreamFrame(
      packetSizeLimit, stream, offset, dataLen, flowControlLen, fin);
  EXPECT_FALSE(result.has_value());
}

TEST(WriteCodecTest, CanHaveOneByteData) {
  StreamId stream = 1;
  uint64_t offset = 1;
  bool fin = false;
  uint64_t dataLen = 10;
  uint64_t flowControlLen = 10;
  auto packetSizeLimit = 4;
  auto result = writeDSRStreamFrame(
      packetSizeLimit, stream, offset, dataLen, flowControlLen, fin);
  EXPECT_TRUE(result.has_value());
  EXPECT_GT(result->encodedSize, 0);
  EXPECT_EQ(stream, result->sendInstruction.streamId);
  EXPECT_EQ(offset, result->sendInstruction.offset);
  EXPECT_EQ(1, result->sendInstruction.len);
  EXPECT_EQ(fin, result->sendInstruction.fin);
}

TEST(WriteCodecTest, PacketSpaceEqStreamHeaderSize) {
  StreamId stream = 1;
  uint64_t offset = 0;
  bool fin = true;
  uint64_t dataLen = 10;
  uint64_t flowControlLen = 10;
  auto packetSizeLimit = 2;
  auto result = writeDSRStreamFrame(
      packetSizeLimit, stream, offset, dataLen, flowControlLen, fin);
  EXPECT_FALSE(result.has_value());
}

TEST(WriteCodecTest, PacketSpaceEqStreamHeaderSizeWithFIN) {
  StreamId stream = 1;
  uint64_t offset = 0;
  bool fin = true;
  uint64_t dataLen = 0;
  uint64_t flowControlLen = 10;
  auto packetSizeLimit = 2;
  auto result = writeDSRStreamFrame(
      packetSizeLimit, stream, offset, dataLen, flowControlLen, fin);
  EXPECT_TRUE(result.has_value());
  EXPECT_GT(result->encodedSize, 0);
  EXPECT_EQ(stream, result->sendInstruction.streamId);
  EXPECT_EQ(offset, result->sendInstruction.offset);
  EXPECT_EQ(0, result->sendInstruction.len);
  EXPECT_TRUE(result->sendInstruction.fin);
}

TEST(WriteCodecTest, WriteFIN) {
  StreamId stream = 1;
  uint64_t offset = 1;
  bool fin = true;
  uint64_t dataLen = 10;
  uint64_t flowControlLen = 10;
  auto packetSizeLimit = kDefaultUDPSendPacketLen;
  auto result = writeDSRStreamFrame(
      packetSizeLimit, stream, offset, dataLen, flowControlLen, fin);
  EXPECT_TRUE(result.has_value());
  EXPECT_GT(result->encodedSize, 0);
  EXPECT_EQ(stream, result->sendInstruction.streamId);
  EXPECT_EQ(offset, result->sendInstruction.offset);
  EXPECT_EQ(10, result->sendInstruction.len);
  EXPECT_TRUE(result->sendInstruction.fin);
}

TEST(WriteCodecTest, FINWithoutData) {
  StreamId stream = 1;
  uint64_t offset = 1;
  bool fin = true;
  uint64_t dataLen = 0;
  uint64_t flowControlLen = 10;
  auto packetSizeLimit = kDefaultUDPSendPacketLen;
  auto result = writeDSRStreamFrame(
      packetSizeLimit, stream, offset, dataLen, flowControlLen, fin);
  EXPECT_TRUE(result.has_value());
  EXPECT_GT(result->encodedSize, 0);
  EXPECT_EQ(stream, result->sendInstruction.streamId);
  EXPECT_EQ(offset, result->sendInstruction.offset);
  EXPECT_EQ(0, result->sendInstruction.len);
  EXPECT_TRUE(result->sendInstruction.fin);
}

TEST(WriteCodecTest, NoFINNoData) {
  StreamId stream = 1;
  uint64_t offset = 1;
  bool fin = false;
  uint64_t dataLen = 0;
  uint64_t flowControlLen = 10;
  auto packetSizeLimit = kDefaultUDPSendPacketLen;
  EXPECT_THROW(
      writeDSRStreamFrame(
          packetSizeLimit, stream, offset, dataLen, flowControlLen, fin),
      QuicInternalException);
}
} // namespace test
} // namespace quic
