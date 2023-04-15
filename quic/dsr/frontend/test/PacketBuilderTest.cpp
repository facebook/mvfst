/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <folly/portability/GTest.h>
#include <quic/common/test/TestUtils.h>
#include <quic/dsr/Types.h>
#include <quic/dsr/frontend/PacketBuilder.h>
#include <quic/dsr/test/TestCommon.h>
#include <quic/fizz/server/handshake/FizzServerQuicHandshakeContext.h>
#include <quic/handshake/test/Mocks.h>
#include <quic/server/state/ServerStateMachine.h>

namespace quic {
namespace test {

bool operator==(
    const SendInstruction& instruction,
    const WriteStreamFrame& frame) {
  return instruction.streamId == frame.streamId &&
      instruction.streamOffset == frame.offset &&
      instruction.len == frame.len && instruction.fin == frame.fin;
}

bool operator==(
    const WriteStreamFrame& frame,
    const SendInstruction& instruction) {
  return instruction == frame;
}

class PacketBuilderTest : public DSRCommonTestFixture {
 public:
  PacketBuilderTest()
      : cid(getTestConnectionId(0)),
        header(ProtectionType::KeyPhaseZero, cid) {}

 protected:
  ConnectionId cid;
  ShortHeader header;
};

TEST_F(PacketBuilderTest, SimpleBuild) {
  StreamId id = 0;
  uint64_t offset = 1;
  uint64_t length = 1000;
  bool fin = true;
  uint64_t bufMetaStartingOffset = 333;
  SendInstruction::Builder siBuilder(conn_, id);
  siBuilder.setStreamOffset(offset);
  siBuilder.setLength(length);
  siBuilder.setFin(fin);
  siBuilder.setBufMetaStartingOffset(bufMetaStartingOffset);
  auto sendInstruction = siBuilder.build();
  DSRPacketBuilder packetBuilder(kDefaultUDPSendPacketLen, header, 0);
  uint32_t streamEncodedSize = 1003;
  SendInstruction instructionCopy(sendInstruction);
  packetBuilder.addSendInstruction(
      std::move(sendInstruction), streamEncodedSize, 5);
  auto packet = std::move(packetBuilder).buildPacket();
  const auto& writePacket = packet.packet;
  const auto& si = packet.sendInstructions.front();
  EXPECT_EQ(1, writePacket.frames.size());
  const auto& writeStreamFrame =
      *writePacket.frames.front().asWriteStreamFrame();
  EXPECT_TRUE(writeStreamFrame == instructionCopy);
  EXPECT_TRUE(writeStreamFrame == si);
  EXPECT_TRUE(writeStreamFrame.fromBufMeta);
  EXPECT_EQ(writeStreamFrame.streamPacketIdx, 5);
  EXPECT_GT(packet.encodedSize, streamEncodedSize);
}

TEST_F(PacketBuilderTest, SizeTooSmall) {
  DSRPacketBuilder packetBuilder(5, header, 0);
  EXPECT_EQ(0, packetBuilder.remainingSpace());
}

TEST_F(PacketBuilderTest, WriteTwoInstructions) {
  DSRPacketBuilder packetBuilder(kDefaultUDPSendPacketLen, header, 0);

  StreamId id = 0;
  packetBuilder.addSendInstruction(
      SendInstruction::Builder(conn_, id)
          .setStreamOffset(0)
          .setLength(100)
          .setFin(false)
          .setBufMetaStartingOffset(333)
          .build(),
      110,
      5);
  packetBuilder.addSendInstruction(
      SendInstruction::Builder(conn_, id)
          .setStreamOffset(100)
          .setLength(100)
          .setFin(true)
          .setBufMetaStartingOffset(333)
          .build(),
      110,
      6);
  auto packet = std::move(packetBuilder).buildPacket();
  const auto& writePacket = packet.packet;
  EXPECT_EQ(2, packet.sendInstructions.size());
  EXPECT_EQ(2, writePacket.frames.size());
  WriteStreamFrame expectedFirstFrame(id, 0, 100, false, true, folly::none, 5);
  WriteStreamFrame expectedSecondFrame(
      id, 100, 100, true, true, folly::none, 6);
  EXPECT_EQ(expectedFirstFrame, *writePacket.frames[0].asWriteStreamFrame());
  EXPECT_EQ(expectedSecondFrame, *writePacket.frames[1].asWriteStreamFrame());
  EXPECT_TRUE(expectedFirstFrame == packet.sendInstructions[0]);
  EXPECT_TRUE(expectedSecondFrame == packet.sendInstructions[1]);
}

} // namespace test
} // namespace quic
