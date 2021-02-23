/*
 * Copyright (c) Facebook, Inc. and its affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 *
 */

#include <folly/portability/GTest.h>
#include <quic/common/test/TestUtils.h>
#include <quic/dsr/PacketBuilder.h>
#include <quic/dsr/Types.h>

using namespace testing;

namespace quic {
namespace test {

bool operator==(
    const SendInstruction& instruction,
    const WriteStreamFrame& frame) {
  return instruction.streamId == frame.streamId &&
      instruction.offset == frame.offset && instruction.len == frame.len &&
      instruction.fin == frame.fin;
}

bool operator==(
    const WriteStreamFrame& frame,
    const SendInstruction& instruction) {
  return instruction == frame;
}

// TODO: Remove this later
SendInstruction clone(const SendInstruction& origin) {
  SendInstruction::Builder builder(origin.streamId);
  builder.setOffset(origin.offset).setLength(origin.len).setFin(origin.fin);
  auto instruction = builder.build();
  instruction.connKey = origin.connKey;
  instruction.clientAddress = origin.clientAddress;
  instruction.packetNum = origin.packetNum;
  instruction.largestAckedPacketNum = origin.largestAckedPacketNum;
  if (instruction.packetProtectionKey) {
    instruction.packetProtectionKey = origin.packetProtectionKey->clone();
  }
  instruction.cipherSuite = origin.cipherSuite;
  return instruction;
}

class PacketBuilderTest : public Test {
 public:
  PacketBuilderTest()
      : cid(getTestConnectionId()), header(ProtectionType::KeyPhaseZero, cid) {}

 protected:
  ConnectionId cid;
  ShortHeader header;
};

TEST_F(PacketBuilderTest, SimpleBuild) {
  StreamId id = 0;
  uint64_t offset = 1;
  uint64_t length = 1000;
  bool fin = true;
  SendInstruction::Builder siBuilder(id);
  siBuilder.setOffset(offset);
  siBuilder.setLength(length);
  siBuilder.setFin(fin);
  auto sendInstruction = siBuilder.build();
  DSRPacketBuilder packetBuilder(kDefaultUDPSendPacketLen, header, 0);
  uint32_t streamEncodedSize = 1003;
  auto instructionCopy = clone(sendInstruction);
  packetBuilder.addSendInstruction(
      std::move(sendInstruction), streamEncodedSize);
  auto packet = std::move(packetBuilder).buildPacket();
  const auto& writePacket = packet.packet;
  const auto& si = packet.sendInstruction;
  EXPECT_EQ(1, writePacket.frames.size());
  const auto& writeStreamFrame =
      *writePacket.frames.front().asWriteStreamFrame();
  EXPECT_TRUE(writeStreamFrame == instructionCopy);
  EXPECT_TRUE(writeStreamFrame == si);
  EXPECT_GT(packet.encodedSize, streamEncodedSize);
}

TEST_F(PacketBuilderTest, SizeTooSmall) {
  DSRPacketBuilder packetBuilder(5, header, 0);
  EXPECT_EQ(0, packetBuilder.remainingSpace());
}

} // namespace test
} // namespace quic
