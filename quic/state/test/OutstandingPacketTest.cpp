/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <quic/QuicConstants.h>
#include <quic/api/test/MockQuicSocket.h>
#include <quic/api/test/Mocks.h>
#include <quic/common/test/TestUtils.h>
#include <quic/logging/test/Mocks.h>
#include <quic/state/OutstandingPacket.h>
#include <quic/state/stream/StreamSendHandlers.h>
#include <quic/state/test/Mocks.h>

#include <memory>
#include <numeric>
using namespace testing;

namespace quic::test {

TEST(OutstandingPacketTest, BasicPacketDestructionCallback) {
  // Mock packet processor to test packet callbacks.
  auto mockPacketProcessor = std::make_unique<MockPacketProcessor>();
  auto rawPacketProcessor = mockPacketProcessor.get();
  std::function<void(const quic::OutstandingPacketWrapper&)> packetDestroyFn =
      [&](const quic::OutstandingPacketWrapper& pkt) {
        rawPacketProcessor->onPacketDestroyed(pkt);
      };
  std::deque<OutstandingPacketWrapper> packets;

  StreamId currentStreamId = 10;
  auto sentTime = Clock::now();
  int maxPackets = 10;

  for (PacketNum packetNum = 1; packetNum <= (unsigned long)maxPackets;
       packetNum++) {
    RegularQuicWritePacket regularPacket =
        createNewPacket(packetNum, PacketNumberSpace::AppData);
    WriteStreamFrame frame(currentStreamId++, 0, 0, true);
    regularPacket.frames.emplace_back(std::move(frame));
    OutstandingPacketWrapper testPacket(
        std::move(regularPacket),
        sentTime,
        1,
        0,
        false,
        packetNum,
        0,
        0,
        0,
        LossState(),
        0,
        OutstandingPacketMetadata::DetailsPerStream(),
        0us,
        packetDestroyFn);
    packets.emplace_back(std::move(testPacket));
  }
  EXPECT_EQ(maxPackets, packets.size());
  EXPECT_CALL(
      *rawPacketProcessor,
      onPacketDestroyed(testing::Property(
          &OutstandingPacket::getPacketSequenceNum,
          AllOf(Lt(maxPackets + 1), Gt(0)))))
      .Times(maxPackets);

  // Erase all packets and check the number of destructors
  packets.clear();
  EXPECT_EQ(0, packets.size());
}

TEST(OutstandingPacketTest, BasicPacketDestructionDequeDestroy) {
  // Mock packet processor to test packet callbacks.
  auto mockPacketProcessor = std::make_unique<MockPacketProcessor>();
  auto rawPacketProcessor = mockPacketProcessor.get();
  std::function<void(const quic::OutstandingPacketWrapper&)> packetDestroyFn =
      [&](const quic::OutstandingPacketWrapper& pkt) {
        rawPacketProcessor->onPacketDestroyed(pkt);
      };

  {
    std::deque<OutstandingPacketWrapper> packets;

    StreamId currentStreamId = 10;
    auto sentTime = Clock::now();
    int maxPackets = 10;

    for (PacketNum packetNum = 1; packetNum <= (unsigned long)maxPackets;
         packetNum++) {
      RegularQuicWritePacket regularPacket =
          createNewPacket(packetNum, PacketNumberSpace::AppData);
      WriteStreamFrame frame(currentStreamId++, 0, 0, true);
      regularPacket.frames.emplace_back(std::move(frame));
      OutstandingPacketWrapper testPacket(
          std::move(regularPacket),
          sentTime,
          1,
          0,
          false,
          packetNum,
          0,
          0,
          0,
          LossState(),
          0,
          OutstandingPacketMetadata::DetailsPerStream(),
          0us,
          packetDestroyFn);
      packets.emplace_back(std::move(testPacket));
    }
    EXPECT_EQ(maxPackets, packets.size());
    // Deque will be destroyed out of scope - expect the right destroy
    // callbacks.
    EXPECT_CALL(
        *rawPacketProcessor,
        onPacketDestroyed(testing::Property(
            &OutstandingPacket::getPacketSequenceNum,
            AllOf(Lt(maxPackets + 1), Gt(0)))))
        .Times(maxPackets);
  }
}

TEST(OutstandingPacketTest, BasicPacketDestructionNoCallback) {
  {
    std::deque<OutstandingPacketWrapper> packets;
    StreamId currentStreamId = 10;
    auto sentTime = Clock::now();

    int maxPackets = 10;
    for (PacketNum packetNum = 1; packetNum <= (unsigned long)maxPackets;
         packetNum++) {
      RegularQuicWritePacket regularPacket =
          createNewPacket(packetNum, PacketNumberSpace::AppData);
      WriteStreamFrame frame(currentStreamId++, 0, 0, true);
      regularPacket.frames.emplace_back(std::move(frame));
      OutstandingPacketWrapper testPacket(
          std::move(regularPacket),
          sentTime,
          1,
          0,
          false,
          packetNum,
          0,
          0,
          0,
          LossState(),
          0,
          OutstandingPacketMetadata::DetailsPerStream(),
          0us);
      packets.emplace_back(std::move(testPacket));
    }
    EXPECT_EQ(maxPackets, packets.size());
    packets.clear();
    EXPECT_EQ(0, packets.size());
  }
}

TEST(OutstandingPacketTest, PacketMoveConstuctorCallback) {
  // Mock packet processor to test packet callbacks.
  auto mockPacketProcessor = std::make_unique<MockPacketProcessor>();
  auto rawPacketProcessor = mockPacketProcessor.get();
  std::function<void(const quic::OutstandingPacketWrapper&)> packetDestroyFn =
      [&](const quic::OutstandingPacketWrapper& pkt) {
        rawPacketProcessor->onPacketDestroyed(pkt);
      };
  {
    StreamId currentStreamId = 10;
    auto sentTime = Clock::now();
    quic::PacketNum packetNum = 1;
    RegularQuicWritePacket regularPacket =
        createNewPacket(packetNum, PacketNumberSpace::AppData);
    WriteStreamFrame frame(currentStreamId++, 0, 0, true);
    regularPacket.frames.emplace_back(std::move(frame));
    auto testPacket = std::make_unique<OutstandingPacketWrapper>(
        std::move(regularPacket),
        sentTime,
        1,
        0,
        false,
        packetNum,
        0,
        0,
        0,
        LossState(),
        0,
        OutstandingPacketMetadata::DetailsPerStream(),
        0us,
        packetDestroyFn);

    // Move the packet - packet destructor shouldn't be called.
    EXPECT_CALL(*rawPacketProcessor, onPacketDestroyed(_)).Times(0);
    auto testPacket2(std::move(*testPacket));

    // Destroy the moved from packet - no destructor calls.
    EXPECT_CALL(*rawPacketProcessor, onPacketDestroyed(_)).Times(0);
    testPacket.reset();

    // The moved packet is destroyed out of scope, confirm the callback.
    EXPECT_CALL(*rawPacketProcessor, onPacketDestroyed(_)).Times(1);
  }
}

TEST(OutstandingPacketTest, PacketMoveAssignCallback) {
  auto mockPacketProcessor = std::make_unique<MockPacketProcessor>();
  auto rawPacketProcessor = mockPacketProcessor.get();
  std::function<void(const quic::OutstandingPacketWrapper&)> packetDestroyFn =
      [&](const quic::OutstandingPacketWrapper& pkt) {
        rawPacketProcessor->onPacketDestroyed(pkt);
      };
  {
    StreamId currentStreamId = 1;
    auto sentTime = Clock::now();
    quic::PacketNum packetNum = 10;
    RegularQuicWritePacket regularPacket =
        createNewPacket(packetNum, PacketNumberSpace::AppData);
    WriteStreamFrame frame(currentStreamId++, 0, 0, true);
    regularPacket.frames.emplace_back(std::move(frame));

    auto testPacket = std::make_unique<OutstandingPacketWrapper>(
        std::move(regularPacket),
        sentTime,
        1,
        0,
        false,
        packetNum,
        0,
        0,
        0,
        LossState(),
        0,
        OutstandingPacketMetadata::DetailsPerStream(),
        0us,
        packetDestroyFn);

    // Move the packet - packet destructor shouldn't be called.
    EXPECT_CALL(*rawPacketProcessor, onPacketDestroyed(_)).Times(0);
    auto testPacket2 = std::move(*testPacket);

    // Destroy the moved from packet - no destructor calls.
    EXPECT_CALL(*rawPacketProcessor, onPacketDestroyed(_)).Times(0);
    testPacket.reset();

    // The moved packet is destroyed out of scope, confirm the callback.
    EXPECT_CALL(*rawPacketProcessor, onPacketDestroyed(_)).Times(1);
  }
}

TEST(OutstandingPacketTest, PacketMoveAssignExistingPacketCallback) {
  auto mockPacketProcessor = std::make_unique<MockPacketProcessor>();
  auto rawPacketProcessor = mockPacketProcessor.get();
  std::function<void(const quic::OutstandingPacketWrapper&)> packetDestroyFn =
      [&](const quic::OutstandingPacketWrapper& pkt) {
        rawPacketProcessor->onPacketDestroyed(pkt);
      };
  {
    StreamId currentStreamId = 10;
    auto sentTime = Clock::now();
    quic::PacketNum packetNum = 1;
    RegularQuicWritePacket regularPacket =
        createNewPacket(packetNum, PacketNumberSpace::AppData);
    WriteStreamFrame frame(currentStreamId++, 0, 0, true);
    regularPacket.frames.emplace_back(std::move(frame));

    OutstandingPacketWrapper testPacket1(
        std::move(regularPacket),
        sentTime,
        1,
        0,
        false,
        packetNum,
        0,
        0,
        0,
        LossState(),
        0,
        OutstandingPacketMetadata::DetailsPerStream(),
        0us,
        packetDestroyFn);

    sentTime = Clock::now();
    packetNum = 2;
    regularPacket = createNewPacket(packetNum, PacketNumberSpace::AppData);
    frame = WriteStreamFrame(currentStreamId++, 0, 0, true);

    regularPacket.frames.emplace_back(frame);
    OutstandingPacketWrapper testPacket2(
        std::move(regularPacket),
        sentTime,
        1,
        0,
        false,
        packetNum + 1,
        0,
        0,
        0,
        LossState(),
        0,
        OutstandingPacketMetadata::DetailsPerStream(),
        0us,
        packetDestroyFn);

    // Move the packet 1 into packet 2. Packet 2 destructor should be called
    // from move assign operator.
    EXPECT_CALL(*rawPacketProcessor, onPacketDestroyed(_))
        .Times(1)
        .WillOnce(Invoke([&](auto& outstandingPacket) {
          EXPECT_EQ(2, outstandingPacket.packet.header.getPacketSequenceNum());
        }));
    testPacket2 = std::move(testPacket1);

    // Packet 1 to be destroyed out of scope, confirm the callback.
    EXPECT_CALL(*rawPacketProcessor, onPacketDestroyed(_))
        .Times(1)
        .WillOnce(Invoke([&](auto& outstandingPacket) {
          EXPECT_EQ(1, outstandingPacket.packet.header.getPacketSequenceNum());
        }));
  }
}

TEST(OutstandingPacketTest, DequeMoveAssignPacketDestructionCallback) {
  int numDestroyCallbacks = 0;
  int maxPackets = 10;
  auto mockPacketProcessor = std::make_unique<MockPacketProcessor>();
  auto rawPacketProcessor = mockPacketProcessor.get();
  std::function<void(const quic::OutstandingPacketWrapper&)> packetDestroyFn =
      [&](const quic::OutstandingPacketWrapper& pkt) {
        rawPacketProcessor->onPacketDestroyed(pkt);
        numDestroyCallbacks++;
      };
  {
    std::deque<OutstandingPacketWrapper> packets;
    StreamId currentStreamId = 10;
    auto sentTime = Clock::now();

    for (PacketNum packetNum = 1; packetNum <= (unsigned long)maxPackets;
         packetNum++) {
      RegularQuicWritePacket regularPacket =
          createNewPacket(packetNum, PacketNumberSpace::AppData);
      WriteStreamFrame frame(currentStreamId++, 0, 0, true);
      regularPacket.frames.emplace_back(std::move(frame));
      OutstandingPacketWrapper testPacket(
          std::move(regularPacket),
          sentTime,
          1,
          0,
          false,
          packetNum,
          0,
          0,
          0,
          LossState(),
          0,
          OutstandingPacketMetadata::DetailsPerStream(),
          0us,
          packetDestroyFn);
      packets.emplace_back(std::move(testPacket));
    }
    EXPECT_EQ(maxPackets, packets.size());
    // Erase packets in the middle and confirm the appropriate destructors are
    // called via move assign.
    EXPECT_CALL(*rawPacketProcessor, onPacketDestroyed(_))
        .Times(2)
        .WillOnce(Invoke([&](auto& outstandingPacket) {
          EXPECT_EQ(4, outstandingPacket.packet.header.getPacketSequenceNum());
        }))
        .WillOnce(Invoke([&](auto& outstandingPacket) {
          EXPECT_EQ(3, outstandingPacket.packet.header.getPacketSequenceNum());
        }));
    packets.erase(packets.begin() + 2, packets.begin() + 4);
    EXPECT_EQ(numDestroyCallbacks, 2);
    EXPECT_CALL(*rawPacketProcessor, onPacketDestroyed(_)).Times(8);
  }
  EXPECT_EQ(numDestroyCallbacks, maxPackets);
}

} // namespace quic::test
