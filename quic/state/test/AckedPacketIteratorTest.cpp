/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <quic/common/test/TestUtils.h>
#include <quic/state/AckedPacketIterator.h>

using namespace testing;

namespace quic::test {

class AckedPacketIteratorTest : public virtual testing::Test {
 public:
  struct PacketNumAndSpace {
    PacketNumAndSpace(PacketNum packetNumIn, PacketNumberSpace pnSpaceIn)
        : packetNum(packetNumIn), pnSpace(pnSpaceIn) {}

    bool operator==(const PacketNumAndSpace& other) const {
      return packetNum == other.packetNum && pnSpace == other.pnSpace;
    }

    PacketNum packetNum;
    PacketNumberSpace pnSpace;
  };

  AckedPacketIteratorTest() : conn_(QuicNodeType::Client) {}

  void initializeAckedPacketIterator(
      const quic::ReadAckFrame::Vec& ackBlocks,
      PacketNumberSpace pnSpace) {
    ackedPacketIterator_ =
        std::make_unique<AckedPacketIterator>(ackBlocks, conn_, pnSpace);
  }

  void addPackets(const std::vector<PacketNumAndSpace>& packets) {
    for (const auto& packet : packets) {
      auto regularPacket = createNewPacket(packet.packetNum, packet.pnSpace);
      conn_.outstandings
          .packetCount[regularPacket.header.getPacketNumberSpace()]++;
      OutstandingPacketWrapper sentPacket(
          std::move(regularPacket),
          TimePoint(),
          1,
          0,
          packet.packetNum,
          packet.packetNum + 1,
          quic::LossState(),
          0,
          OutstandingPacketMetadata::DetailsPerStream());
      conn_.outstandings.packets.emplace_back(std::move(sentPacket));
    }
  }

  std::vector<PacketNumAndSpace> getOutstandings() {
    std::vector<PacketNumAndSpace> packetNumAndSpace;
    for (const auto& packet : conn_.outstandings.packets) {
      packetNumAndSpace.emplace_back(
          packet.packet.header.getPacketSequenceNum(),
          packet.packet.header.getPacketNumberSpace());
    }
    return packetNumAndSpace;
  }

  void markPacketsScheduledForDestruction(
      const quic::ReadAckFrame::Vec& ackBlocks,
      PacketNumberSpace pnSpace) {
    AckedPacketIterator ackedPacketIterator(ackBlocks, conn_, pnSpace);
    while (ackedPacketIterator.valid()) {
      ackedPacketIterator->metadata.scheduledForDestruction = true;
      conn_.outstandings.scheduledForDestructionCount++;
      ackedPacketIterator.next();
    }
  }

 protected:
  QuicConnectionStateBase conn_;
  std::unique_ptr<AckedPacketIterator> ackedPacketIterator_;
};

// Outstanding packets: [0, 5]
// Acked blocks: [2, 4]
TEST_F(AckedPacketIteratorTest, BasicIteration) {
  std::vector<PacketNumAndSpace> packets;
  for (size_t i = 0; i < 6; i++) {
    packets.emplace_back(i, PacketNumberSpace::AppData);
  }
  addPackets(packets);

  quic::ReadAckFrame::Vec ackBlocks = {{2, 4}};
  initializeAckedPacketIterator(ackBlocks, PacketNumberSpace::AppData);

  std::vector<PacketNumAndSpace> iteratedPackets;
  while (ackedPacketIterator_->valid()) {
    auto& packetHeader = (*ackedPacketIterator_)->packet.header;
    iteratedPackets.emplace_back(
        packetHeader.getPacketSequenceNum(),
        packetHeader.getPacketNumberSpace());
    ackedPacketIterator_->next();
  }

  std::vector<PacketNumAndSpace> expectedIteratedPackets = {
      {4, PacketNumberSpace::AppData},
      {3, PacketNumberSpace::AppData},
      {2, PacketNumberSpace::AppData}};
  EXPECT_THAT(iteratedPackets, ContainerEq(expectedIteratedPackets));
}

// Outstanding packets: [0, 7]
// Acked blocks: [5, 7], [1, 3]
TEST_F(AckedPacketIteratorTest, IterationTwoBlocks) {
  std::vector<PacketNumAndSpace> packets;
  for (size_t i = 0; i < 8; i++) {
    packets.emplace_back(i, PacketNumberSpace::AppData);
  }
  addPackets(packets);

  quic::ReadAckFrame::Vec ackBlocks = {{5, 7}, {1, 3}};
  initializeAckedPacketIterator(ackBlocks, PacketNumberSpace::AppData);

  std::vector<PacketNumAndSpace> iteratedPackets;
  while (ackedPacketIterator_->valid()) {
    auto& packetHeader = (*ackedPacketIterator_)->packet.header;
    iteratedPackets.emplace_back(
        packetHeader.getPacketSequenceNum(),
        packetHeader.getPacketNumberSpace());
    ackedPacketIterator_->next();
  }

  std::vector<PacketNumAndSpace> expectedIteratedPackets = {
      {7, PacketNumberSpace::AppData},
      {6, PacketNumberSpace::AppData},
      {5, PacketNumberSpace::AppData},
      {3, PacketNumberSpace::AppData},
      {2, PacketNumberSpace::AppData},
      {1, PacketNumberSpace::AppData}};
  EXPECT_THAT(iteratedPackets, ContainerEq(expectedIteratedPackets));
}

// Outstanding packets: [0, 7]
// Acked blocks: [4, 5], [1, 3]
TEST_F(AckedPacketIteratorTest, IterationTwoBlocksAdjacent) {
  std::vector<PacketNumAndSpace> packets;
  for (size_t i = 0; i < 8; i++) {
    packets.emplace_back(i, PacketNumberSpace::AppData);
  }
  addPackets(packets);

  quic::ReadAckFrame::Vec ackBlocks = {{4, 5}, {1, 3}};
  initializeAckedPacketIterator(ackBlocks, PacketNumberSpace::AppData);

  std::vector<PacketNumAndSpace> iteratedPackets;
  while (ackedPacketIterator_->valid()) {
    auto& packetHeader = (*ackedPacketIterator_)->packet.header;
    iteratedPackets.emplace_back(
        packetHeader.getPacketSequenceNum(),
        packetHeader.getPacketNumberSpace());
    ackedPacketIterator_->next();
  }

  std::vector<PacketNumAndSpace> expectedIteratedPackets = {
      {5, PacketNumberSpace::AppData},
      {4, PacketNumberSpace::AppData},
      {3, PacketNumberSpace::AppData},
      {2, PacketNumberSpace::AppData},
      {1, PacketNumberSpace::AppData}};
  EXPECT_THAT(iteratedPackets, ContainerEq(expectedIteratedPackets));
}

// Outstanding packets: [4, 7]
// Acked blocks: [8, 10], [1, 3]
TEST_F(AckedPacketIteratorTest, IterationNoOverlap) {
  std::vector<PacketNumAndSpace> packets;
  for (size_t i = 4; i < 8; i++) {
    packets.emplace_back(i, PacketNumberSpace::AppData);
  }
  addPackets(packets);

  quic::ReadAckFrame::Vec ackBlocks = {{8, 10}, {1, 3}};
  initializeAckedPacketIterator(ackBlocks, PacketNumberSpace::AppData);

  std::vector<PacketNumAndSpace> iteratedPackets;
  while (ackedPacketIterator_->valid()) {
    auto& packetHeader = (*ackedPacketIterator_)->packet.header;
    iteratedPackets.emplace_back(
        packetHeader.getPacketSequenceNum(),
        packetHeader.getPacketNumberSpace());
    ackedPacketIterator_->next();
  }

  std::vector<PacketNumAndSpace> expectedIteratedPackets = {};
  EXPECT_THAT(iteratedPackets, ContainerEq(expectedIteratedPackets));
}

// Outstanding packets: [4, 9]
// Acked blocks: [8, 11], [2, 5]
TEST_F(AckedPacketIteratorTest, IterationPartialOverlap) {
  std::vector<PacketNumAndSpace> packets;
  for (size_t i = 4; i < 10; i++) {
    packets.emplace_back(i, PacketNumberSpace::AppData);
  }
  addPackets(packets);

  quic::ReadAckFrame::Vec ackBlocks = {{8, 11}, {2, 5}};
  initializeAckedPacketIterator(ackBlocks, PacketNumberSpace::AppData);

  std::vector<PacketNumAndSpace> iteratedPackets;
  while (ackedPacketIterator_->valid()) {
    auto& packetHeader = (*ackedPacketIterator_)->packet.header;
    iteratedPackets.emplace_back(
        packetHeader.getPacketSequenceNum(),
        packetHeader.getPacketNumberSpace());
    ackedPacketIterator_->next();
  }

  std::vector<PacketNumAndSpace> expectedIteratedPackets = {
      {9, PacketNumberSpace::AppData},
      {8, PacketNumberSpace::AppData},
      {5, PacketNumberSpace::AppData},
      {4, PacketNumberSpace::AppData}};
  EXPECT_THAT(iteratedPackets, ContainerEq(expectedIteratedPackets));
}

// Outstanding packets: [0, 3], [7, 9]
// Acked blocks: [6, 8], [3, 4]
TEST_F(AckedPacketIteratorTest, IterationTwoOpIntervals) {
  std::vector<PacketNumAndSpace> packets;
  for (size_t i = 0; i < 4; i++) {
    packets.emplace_back(i, PacketNumberSpace::AppData);
  }

  for (size_t i = 7; i < 10; i++) {
    packets.emplace_back(i, PacketNumberSpace::AppData);
  }
  addPackets(packets);

  quic::ReadAckFrame::Vec ackBlocks = {{6, 8}, {3, 4}};
  initializeAckedPacketIterator(ackBlocks, PacketNumberSpace::AppData);

  std::vector<PacketNumAndSpace> iteratedPackets;
  while (ackedPacketIterator_->valid()) {
    auto& packetHeader = (*ackedPacketIterator_)->packet.header;
    iteratedPackets.emplace_back(
        packetHeader.getPacketSequenceNum(),
        packetHeader.getPacketNumberSpace());
    ackedPacketIterator_->next();
  }

  std::vector<PacketNumAndSpace> expectedIteratedPackets = {
      {8, PacketNumberSpace::AppData},
      {7, PacketNumberSpace::AppData},
      {3, PacketNumberSpace::AppData}};
  EXPECT_THAT(iteratedPackets, ContainerEq(expectedIteratedPackets));
}

// Outstanding packets: [0, 5]
// Acked blocks: [2, 4]
TEST_F(AckedPacketIteratorTest, BasicErasure) {
  std::vector<PacketNumAndSpace> packets;
  for (size_t i = 0; i < 6; i++) {
    packets.emplace_back(i, PacketNumberSpace::AppData);
  }
  addPackets(packets);

  quic::ReadAckFrame::Vec ackBlocks = {{2, 4}};

  markPacketsScheduledForDestruction(ackBlocks, PacketNumberSpace::AppData);
  initializeAckedPacketIterator(ackBlocks, PacketNumberSpace::AppData);
  ackedPacketIterator_->eraseAckedOutstandings();

  std::vector<PacketNumAndSpace> expectedOutstandings = {
      {0, PacketNumberSpace::AppData},
      {1, PacketNumberSpace::AppData},
      {5, PacketNumberSpace::AppData}};
  EXPECT_THAT(expectedOutstandings, ContainerEq(getOutstandings()));
}

// Outstanding packets: [0, 7]
// Acked blocks: [5, 7], [1, 3]
TEST_F(AckedPacketIteratorTest, ErasureTwoBlocks) {
  std::vector<PacketNumAndSpace> packets;
  for (size_t i = 0; i < 8; i++) {
    packets.emplace_back(i, PacketNumberSpace::AppData);
  }
  addPackets(packets);

  quic::ReadAckFrame::Vec ackBlocks = {{5, 7}, {1, 3}};

  markPacketsScheduledForDestruction(ackBlocks, PacketNumberSpace::AppData);
  initializeAckedPacketIterator(ackBlocks, PacketNumberSpace::AppData);
  ackedPacketIterator_->eraseAckedOutstandings();

  std::vector<PacketNumAndSpace> expectedOutstandings = {
      {0, PacketNumberSpace::AppData}, {4, PacketNumberSpace::AppData}};
  EXPECT_THAT(expectedOutstandings, ContainerEq(getOutstandings()));
}

// Outstanding packets: [0, 8] (packet 6 is in a different space)
// Acked blocks: [5, 8]
TEST_F(AckedPacketIteratorTest, ErasureMultiplePnSpaces) {
  std::vector<PacketNumAndSpace> packets;
  for (size_t i = 0; i < 8; i++) {
    PacketNumberSpace pnSpace =
        (i == 6) ? PacketNumberSpace::Initial : PacketNumberSpace::AppData;
    packets.emplace_back(i, pnSpace);
  }
  addPackets(packets);

  quic::ReadAckFrame::Vec ackBlocks = {{5, 8}};

  markPacketsScheduledForDestruction(ackBlocks, PacketNumberSpace::AppData);
  initializeAckedPacketIterator(ackBlocks, PacketNumberSpace::AppData);
  ackedPacketIterator_->eraseAckedOutstandings();

  std::vector<PacketNumAndSpace> expectedOutstandings = {
      {0, PacketNumberSpace::AppData},
      {1, PacketNumberSpace::AppData},
      {2, PacketNumberSpace::AppData},
      {3, PacketNumberSpace::AppData},
      {4, PacketNumberSpace::AppData},
      {6, PacketNumberSpace::Initial}};
  EXPECT_THAT(expectedOutstandings, ContainerEq(getOutstandings()));
}

// Outstanding packets: [4, 7]
// Acked blocks: [8, 10], [1, 3]
TEST_F(AckedPacketIteratorTest, ErasureNoOverlap) {
  std::vector<PacketNumAndSpace> packets;
  for (size_t i = 4; i < 8; i++) {
    packets.emplace_back(i, PacketNumberSpace::AppData);
  }
  addPackets(packets);

  quic::ReadAckFrame::Vec ackBlocks = {{8, 10}, {1, 3}};

  markPacketsScheduledForDestruction(ackBlocks, PacketNumberSpace::AppData);
  initializeAckedPacketIterator(ackBlocks, PacketNumberSpace::AppData);
  ackedPacketIterator_->eraseAckedOutstandings();

  std::vector<PacketNumAndSpace> expectedOutstandings = {
      {4, PacketNumberSpace::AppData},
      {5, PacketNumberSpace::AppData},
      {6, PacketNumberSpace::AppData},
      {7, PacketNumberSpace::AppData}};
  EXPECT_THAT(expectedOutstandings, ContainerEq(getOutstandings()));
}

// Outstanding packets: [4, 9]
// Acked blocks: [8, 11], [2, 5]
TEST_F(AckedPacketIteratorTest, ErasurePartialOverlap) {
  std::vector<PacketNumAndSpace> packets;
  for (size_t i = 4; i < 10; i++) {
    packets.emplace_back(i, PacketNumberSpace::AppData);
  }
  addPackets(packets);

  quic::ReadAckFrame::Vec ackBlocks = {{8, 11}, {2, 5}};
  markPacketsScheduledForDestruction(ackBlocks, PacketNumberSpace::AppData);
  initializeAckedPacketIterator(ackBlocks, PacketNumberSpace::AppData);
  ackedPacketIterator_->eraseAckedOutstandings();

  std::vector<PacketNumAndSpace> expectedOutstandings = {
      {6, PacketNumberSpace::AppData}, {7, PacketNumberSpace::AppData}};
  EXPECT_THAT(expectedOutstandings, ContainerEq(getOutstandings()));
}

// Outstanding packets: [0, 3], [7, 9]
// Acked blocks: [6, 8], [3, 4]
TEST_F(AckedPacketIteratorTest, ErasureTwoOpIntervals) {
  std::vector<PacketNumAndSpace> packets;
  for (size_t i = 0; i < 4; i++) {
    packets.emplace_back(i, PacketNumberSpace::AppData);
  }

  for (size_t i = 7; i < 10; i++) {
    packets.emplace_back(i, PacketNumberSpace::AppData);
  }
  addPackets(packets);

  quic::ReadAckFrame::Vec ackBlocks = {{6, 8}, {3, 4}};
  markPacketsScheduledForDestruction(ackBlocks, PacketNumberSpace::AppData);
  initializeAckedPacketIterator(ackBlocks, PacketNumberSpace::AppData);
  ackedPacketIterator_->eraseAckedOutstandings();

  std::vector<PacketNumAndSpace> expectedOutstandings = {
      {0, PacketNumberSpace::AppData},
      {1, PacketNumberSpace::AppData},
      {2, PacketNumberSpace::AppData},
      {9, PacketNumberSpace::AppData}};
  EXPECT_THAT(expectedOutstandings, ContainerEq(getOutstandings()));
}

} // namespace quic::test
