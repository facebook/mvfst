/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <quic/dsr/frontend/WriteCodec.h>

#include <folly/portability/GTest.h>
#include <quic/QuicConstants.h>
#include <quic/common/test/TestUtils.h>
#include <quic/dsr/frontend/test/Mocks.h>
#include <quic/dsr/test/TestCommon.h>
#include <quic/fizz/server/handshake/FizzServerQuicHandshakeContext.h>
#include <quic/handshake/test/Mocks.h>
#include <quic/server/state/ServerStateMachine.h>

using namespace testing;

namespace quic {
namespace test {

class WriteCodecTest : public DSRCommonTestFixture {
 public:
  void SetUp() override {
    EXPECT_CALL(builder_, remainingSpaceNonConst())
        .WillRepeatedly(Invoke([&]() { return packetSize_; }));
    prepareFlowControlAndStreamLimit();
  }

 protected:
  SendInstruction::Builder createBuilder() {
    auto stream = *conn_.streamManager->createNextBidirectionalStream();
    SendInstruction::Builder builder(conn_, stream->id);
    return builder;
  }

 protected:
  size_t packetSize_{kDefaultUDPSendPacketLen};
  MockDSRPacketBuilder builder_;
};

TEST_F(WriteCodecTest, NoPacketSize) {
  packetSize_ = 0;
  auto instructionBuilder = createBuilder();
  EXPECT_EQ(
      0,
      writeDSRStreamFrame(
          builder_, instructionBuilder, 0, 0, 100, 100, true, 3));
}

TEST_F(WriteCodecTest, TooSmallPacketSize) {
  packetSize_ = 1;
  auto instructionBuilder = createBuilder();
  EXPECT_EQ(
      0,
      writeDSRStreamFrame(
          builder_, instructionBuilder, 0, 0, 100, 100, true, 1));
}

TEST_F(WriteCodecTest, RegularWrite) {
  StreamId stream = 1;
  uint64_t offset = 65535;
  bool fin = false;
  uint64_t dataLen = 1000;
  uint64_t flowControlLen = 1000;
  uint64_t bufMetaStartingOffset = 333;
  auto instructionBuilder = createBuilder();
  auto result = writeDSRStreamFrame(
      builder_,
      instructionBuilder,
      stream,
      offset,
      dataLen,
      flowControlLen,
      fin,
      bufMetaStartingOffset);
  auto sendInstruction = instructionBuilder.build();
  EXPECT_GT(result, 0);
  EXPECT_EQ(stream, sendInstruction.streamId);
  EXPECT_EQ(offset, sendInstruction.streamOffset);
  EXPECT_EQ(dataLen, sendInstruction.len);
  EXPECT_EQ(fin, sendInstruction.fin);
  EXPECT_EQ(bufMetaStartingOffset, sendInstruction.bufMetaStartingOffset);
}

TEST_F(WriteCodecTest, PacketSizeLimit) {
  StreamId stream = 1;
  uint64_t offset = 65535;
  bool fin = false;
  uint64_t dataLen = 1000 * 1000;
  uint64_t flowControlLen = 1000 * 1000;
  uint64_t bufMetaStartingOffset = 333;
  auto instructionBuilder = createBuilder();
  auto result = writeDSRStreamFrame(
      builder_,
      instructionBuilder,
      stream,
      offset,
      dataLen,
      flowControlLen,
      fin,
      bufMetaStartingOffset);
  auto sendInstruction = instructionBuilder.build();
  EXPECT_GT(result, 0);
  EXPECT_EQ(stream, sendInstruction.streamId);
  EXPECT_EQ(offset, sendInstruction.streamOffset);
  EXPECT_GT(dataLen, sendInstruction.len);
  EXPECT_EQ(fin, sendInstruction.fin);
  EXPECT_EQ(bufMetaStartingOffset, sendInstruction.bufMetaStartingOffset);
}

TEST_F(WriteCodecTest, FlowControlLimit) {
  StreamId stream = 1;
  uint64_t offset = 65535;
  bool fin = false;
  uint64_t dataLen = 1000 * 1000;
  uint64_t flowControlLen = 500;
  uint64_t bufMetaStartingOffset = 333;
  auto instructionBuilder = createBuilder();
  auto result = writeDSRStreamFrame(
      builder_,
      instructionBuilder,
      stream,
      offset,
      dataLen,
      flowControlLen,
      fin,
      bufMetaStartingOffset);
  auto sendInstruction = instructionBuilder.build();
  EXPECT_GT(result, 0);
  EXPECT_EQ(stream, sendInstruction.streamId);
  EXPECT_EQ(offset, sendInstruction.streamOffset);
  EXPECT_EQ(flowControlLen, sendInstruction.len);
  EXPECT_EQ(fin, sendInstruction.fin);
  EXPECT_EQ(bufMetaStartingOffset, sendInstruction.bufMetaStartingOffset);
}

TEST_F(WriteCodecTest, NoSpaceForData) {
  StreamId stream = 1;
  uint64_t offset = 1;
  bool fin = false;
  uint64_t dataLen = 1000;
  uint64_t flowControlLen = 1000;
  uint64_t bufMetaStartingOffset = 333;
  auto instructionBuilder = createBuilder();
  packetSize_ = 3;
  auto result = writeDSRStreamFrame(
      builder_,
      instructionBuilder,
      stream,
      offset,
      dataLen,
      flowControlLen,
      fin,
      bufMetaStartingOffset);
  EXPECT_EQ(0, result);
}

TEST_F(WriteCodecTest, CanHaveOneByteData) {
  StreamId stream = 1;
  uint64_t offset = 1;
  bool fin = false;
  uint64_t dataLen = 10;
  uint64_t flowControlLen = 10;
  uint64_t bufMetaStartingOffset = 333;
  auto instructionBuilder = createBuilder();
  packetSize_ = 4;
  auto result = writeDSRStreamFrame(
      builder_,
      instructionBuilder,
      stream,
      offset,
      dataLen,
      flowControlLen,
      fin,
      bufMetaStartingOffset);
  auto sendInstruction = instructionBuilder.build();
  EXPECT_GT(result, 0);
  EXPECT_EQ(stream, sendInstruction.streamId);
  EXPECT_EQ(offset, sendInstruction.streamOffset);
  EXPECT_EQ(1, sendInstruction.len);
  EXPECT_EQ(fin, sendInstruction.fin);
  EXPECT_EQ(bufMetaStartingOffset, sendInstruction.bufMetaStartingOffset);
}

TEST_F(WriteCodecTest, PacketSpaceEqStreamHeaderSize) {
  StreamId stream = 1;
  uint64_t offset = 0;
  bool fin = true;
  uint64_t dataLen = 10;
  uint64_t flowControlLen = 10;
  uint64_t bufMetaStartingOffset = 333;
  auto instructionBuilder = createBuilder();
  packetSize_ = 2;
  EXPECT_EQ(
      0,
      writeDSRStreamFrame(
          builder_,
          instructionBuilder,
          stream,
          offset,
          dataLen,
          flowControlLen,
          fin,
          bufMetaStartingOffset));
}

TEST_F(WriteCodecTest, PacketSpaceEqStreamHeaderSizeWithFIN) {
  StreamId stream = 1;
  uint64_t offset = 0;
  bool fin = true;
  uint64_t dataLen = 0;
  uint64_t flowControlLen = 10;
  uint64_t bufMetaStartingOffset = 333;
  auto instructionBuilder = createBuilder();
  packetSize_ = 2;
  auto result = writeDSRStreamFrame(
      builder_,
      instructionBuilder,
      stream,
      offset,
      dataLen,
      flowControlLen,
      fin,
      bufMetaStartingOffset);
  auto sendInstruction = instructionBuilder.build();
  EXPECT_GT(result, 0);
  EXPECT_EQ(stream, sendInstruction.streamId);
  EXPECT_EQ(offset, sendInstruction.streamOffset);
  EXPECT_EQ(0, sendInstruction.len);
  EXPECT_TRUE(sendInstruction.fin);
  EXPECT_EQ(bufMetaStartingOffset, sendInstruction.bufMetaStartingOffset);
}

TEST_F(WriteCodecTest, WriteFIN) {
  StreamId stream = 1;
  uint64_t offset = 1;
  bool fin = true;
  uint64_t dataLen = 10;
  uint64_t flowControlLen = 10;
  uint64_t bufMetaStartingOffset = 333;
  auto instructionBuilder = createBuilder();
  auto result = writeDSRStreamFrame(
      builder_,
      instructionBuilder,
      stream,
      offset,
      dataLen,
      flowControlLen,
      fin,
      bufMetaStartingOffset);
  auto sendInstruction = instructionBuilder.build();
  EXPECT_GT(result, 0);
  EXPECT_EQ(stream, sendInstruction.streamId);
  EXPECT_EQ(offset, sendInstruction.streamOffset);
  EXPECT_EQ(10, sendInstruction.len);
  EXPECT_TRUE(sendInstruction.fin);
  EXPECT_EQ(bufMetaStartingOffset, sendInstruction.bufMetaStartingOffset);
}

TEST_F(WriteCodecTest, FINWithoutData) {
  StreamId stream = 1;
  uint64_t offset = 1;
  bool fin = true;
  uint64_t dataLen = 0;
  uint64_t flowControlLen = 10;
  uint64_t bufMetaStartingOffset = 333;
  auto instructionBuilder = createBuilder();
  auto result = writeDSRStreamFrame(
      builder_,
      instructionBuilder,
      stream,
      offset,
      dataLen,
      flowControlLen,
      fin,
      bufMetaStartingOffset);
  auto sendInstruction = instructionBuilder.build();
  EXPECT_GT(result, 0);
  EXPECT_EQ(stream, sendInstruction.streamId);
  EXPECT_EQ(offset, sendInstruction.streamOffset);
  EXPECT_EQ(0, sendInstruction.len);
  EXPECT_TRUE(sendInstruction.fin);
  EXPECT_EQ(bufMetaStartingOffset, sendInstruction.bufMetaStartingOffset);
}

TEST_F(WriteCodecTest, NoFINNoData) {
  StreamId stream = 1;
  uint64_t offset = 1;
  bool fin = false;
  uint64_t dataLen = 0;
  uint64_t flowControlLen = 10;
  uint64_t bufMetaStartingOffset = 333;
  auto instructionBuilder = createBuilder();
  EXPECT_THROW(
      writeDSRStreamFrame(
          builder_,
          instructionBuilder,
          stream,
          offset,
          dataLen,
          flowControlLen,
          fin,
          bufMetaStartingOffset),
      QuicInternalException);
}
} // namespace test
} // namespace quic
