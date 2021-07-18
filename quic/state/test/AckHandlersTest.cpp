/*
 * Copyright (c) Facebook, Inc. and its affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 *
 */

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <quic/common/test/TestUtils.h>

#include <quic/QuicConstants.h>
#include <quic/api/test/Mocks.h>
#include <quic/fizz/server/handshake/FizzServerQuicHandshakeContext.h>
#include <quic/logging/test/Mocks.h>
#include <quic/server/state/ServerStateMachine.h>
#include <quic/state/AckHandlers.h>
#include <quic/state/StateData.h>
#include <quic/state/test/Mocks.h>

#include <numeric>

using namespace testing;

namespace quic {
namespace test {

class AckHandlersTest : public TestWithParam<PacketNumberSpace> {};

auto testLossHandler(std::vector<PacketNum>& lostPackets) -> decltype(auto) {
  return [&lostPackets](QuicConnectionStateBase&, auto& packet, bool) {
    auto packetNum = packet.header.getPacketSequenceNum();
    lostPackets.push_back(packetNum);
  };
}

auto emplacePackets(
    QuicServerConnectionState& conn,
    PacketNum lastPacketNum,
    TimePoint startTime,
    PacketNumberSpace pnSpace) {
  PacketNum packetNum = 0;
  StreamId streamid = 0;
  TimePoint sentTime;
  std::vector<TimePoint> packetRcvTime;
  while (packetNum < lastPacketNum) {
    auto regularPacket = createNewPacket(packetNum, pnSpace);
    WriteStreamFrame frame(streamid++, 0, 0, true);
    regularPacket.frames.emplace_back(frame);
    sentTime = startTime + std::chrono::milliseconds(packetNum);
    packetRcvTime.emplace_back(sentTime);
    conn.outstandings
        .packetCount[regularPacket.header.getPacketNumberSpace()]++;
    OutstandingPacket sentPacket(
        std::move(regularPacket),
        sentTime,
        1,
        0,
        false /* handshake */,
        packetNum,
        0,
        packetNum + 1,
        packetNum + 1,
        quic::LossState(),
        0);
    conn.outstandings.packets.emplace_back(sentPacket);
    packetNum++;
  }
}

TEST_P(AckHandlersTest, TestAckMultipleSequentialBlocks) {
  QuicServerConnectionState conn(
      FizzServerQuicHandshakeContext::Builder().build());
  conn.lossState.reorderingThreshold = 85;
  auto mockCongestionController = std::make_unique<MockCongestionController>();
  auto rawCongestionController = mockCongestionController.get();
  conn.congestionController = std::move(mockCongestionController);
  // Get the time based loss detection out of the way
  conn.lossState.srtt = 10s;

  StreamId currentStreamId = 10;
  auto sentTime = Clock::now();
  for (PacketNum packetNum = 10; packetNum <= 101; packetNum++) {
    RegularQuicWritePacket regularPacket =
        createNewPacket(packetNum, GetParam());
    WriteStreamFrame frame(currentStreamId++, 0, 0, true);
    regularPacket.frames.emplace_back(std::move(frame));
    conn.outstandings
        .packetCount[regularPacket.header.getPacketNumberSpace()]++;
    conn.outstandings.packets.emplace_back(OutstandingPacket(
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
        0));
  }
  ReadAckFrame ackFrame;
  ackFrame.largestAcked = 101;
  // ACK packet ranges 21 - 101
  for (PacketNum packetNum = 101; packetNum > 30; packetNum -= 20) {
    ackFrame.ackBlocks.emplace_back(packetNum - 20, packetNum);
  }

  std::vector<WriteStreamFrame> streams;
  std::vector<PacketNum> lostPackets;
  uint64_t expectedAckedBytes = 81;
  uint64_t expectedAckedPackets = expectedAckedBytes; // each packet size is 1
  size_t lostPacketsCounter = 0;
  EXPECT_CALL(*rawCongestionController, onPacketAckOrLoss(_, _))
      .WillRepeatedly(Invoke([&](auto ack, auto loss) {
        if (ack) {
          EXPECT_EQ(101, *ack->largestAckedPacket);
          EXPECT_EQ(expectedAckedBytes, ack->ackedBytes);
          EXPECT_EQ(expectedAckedPackets, ack->ackedPackets.size());
        }
        if (loss) {
          lostPacketsCounter++;
        }
      }));
  processAckFrame(
      conn,
      GetParam(),
      ackFrame,
      [&](const auto&, const auto& packetFrame, const ReadAckFrame&) {
        auto& stream = *packetFrame.asWriteStreamFrame();
        streams.emplace_back(stream);
      },
      testLossHandler(lostPackets),
      Clock::now());
  EXPECT_EQ(lostPacketsCounter, lostPackets.empty() ? 0 : 1);

  StreamId start = currentStreamId - 1;
  for (auto& stream : streams) {
    EXPECT_EQ(stream.streamId, start);
    start--;
  }
  // only unacked packets should be remaining
  auto numDeclaredLost = std::count_if(
      conn.outstandings.packets.begin(),
      conn.outstandings.packets.end(),
      [](auto& op) { return op.declaredLost; });
  EXPECT_GT(numDeclaredLost, 0);
  EXPECT_EQ(numDeclaredLost, lostPackets.size());
  EXPECT_EQ(numDeclaredLost, conn.outstandings.declaredLostCount);
  EXPECT_EQ(conn.outstandings.packets.size(), numDeclaredLost + 5);
}

TEST_P(AckHandlersTest, TestAckMultipleSequentialBlocksLoss) {
  QuicServerConnectionState conn(
      FizzServerQuicHandshakeContext::Builder().build());
  conn.lossState.reorderingThreshold = 85;
  auto mockCongestionController = std::make_unique<MockCongestionController>();
  auto rawCongestionController = mockCongestionController.get();
  conn.congestionController = std::move(mockCongestionController);
  // Get the time based loss detection out of the way
  conn.lossState.srtt = 10s;

  StreamId currentStreamId = 10;
  auto sentTime = Clock::now();
  for (PacketNum packetNum = 10; packetNum <= 101; packetNum++) {
    RegularQuicWritePacket regularPacket =
        createNewPacket(packetNum, GetParam());
    WriteStreamFrame frame(currentStreamId++, 0, 0, true);
    regularPacket.frames.emplace_back(std::move(frame));
    conn.outstandings
        .packetCount[regularPacket.header.getPacketNumberSpace()]++;
    conn.outstandings.packets.emplace_back(OutstandingPacket(
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
        0));
  }
  ReadAckFrame ackFrame;
  ackFrame.largestAcked = 101;
  // ACK packet ranges 21 - 101
  for (PacketNum packetNum = 101; packetNum > 30; packetNum -= 20) {
    ackFrame.ackBlocks.emplace_back(packetNum - 20, packetNum);
  }

  std::vector<WriteStreamFrame> streams;
  std::vector<PacketNum> lostPackets;
  uint64_t expectedAckedBytes = 81;
  uint64_t expectedAckedPackets = expectedAckedBytes; // each packet size is 1
  size_t lostPacketsCounter = 0;
  EXPECT_CALL(*rawCongestionController, onPacketAckOrLoss(_, _))
      .Times(3)
      .WillOnce(Invoke([&](auto ack, auto loss) {
        if (ack) {
          EXPECT_EQ(101, *ack->largestAckedPacket);
          EXPECT_EQ(expectedAckedBytes, ack->ackedBytes);
          EXPECT_EQ(expectedAckedPackets, ack->ackedPackets.size());
        }
        if (loss) {
          lostPacketsCounter++;
        }
      }))
      .WillRepeatedly(Invoke([](auto, auto) {}));
  processAckFrame(
      conn,
      GetParam(),
      ackFrame,
      [&](const auto&, const auto& packetFrame, const ReadAckFrame&) {
        auto& stream = *packetFrame.asWriteStreamFrame();
        streams.emplace_back(stream);
      },
      testLossHandler(lostPackets),
      Clock::now());
  EXPECT_EQ(lostPacketsCounter, lostPackets.empty() ? 0 : 1);

  StreamId start = currentStreamId - 1;
  for (auto& stream : streams) {
    EXPECT_EQ(stream.streamId, start);
    start--;
  }
  // only unacked packets should be remaining
  auto numDeclaredLost = std::count_if(
      conn.outstandings.packets.begin(),
      conn.outstandings.packets.end(),
      [](auto& op) { return op.declaredLost; });
  EXPECT_GT(numDeclaredLost, 0);
  EXPECT_EQ(numDeclaredLost, lostPackets.size());
  EXPECT_EQ(numDeclaredLost, conn.outstandings.declaredLostCount);
  EXPECT_EQ(conn.outstandings.packets.size(), numDeclaredLost + 5);
  PacketNum lostPackt = 10;
  for (auto& pkt : lostPackets) {
    EXPECT_EQ(pkt, lostPackt++);
  }
  PacketNum packetNum = 16;
  for (auto& packet : conn.outstandings.packets) {
    if (packet.declaredLost) {
      continue;
    }
    auto currentPacketNum = packet.packet.header.getPacketSequenceNum();
    EXPECT_EQ(currentPacketNum, packetNum);
    packetNum++;
  }

  // 15 is lost, 16 is not, if we get an ack covering both both should be
  // cleared.
  auto itr = std::find_if(
      conn.outstandings.packets.begin(),
      conn.outstandings.packets.end(),
      [](auto& op) {
        return op.packet.header.getPacketSequenceNum() == 15 ||
            op.packet.header.getPacketSequenceNum() == 16;
      });
  EXPECT_TRUE(itr != conn.outstandings.packets.end());
  EXPECT_TRUE(itr->declaredLost);
  EXPECT_EQ(itr->packet.header.getPacketSequenceNum(), 15);
  itr++;
  EXPECT_TRUE(itr != conn.outstandings.packets.end());
  EXPECT_FALSE(itr->declaredLost);
  EXPECT_EQ(itr->packet.header.getPacketSequenceNum(), 16);
  EXPECT_EQ(conn.lossState.totalPacketsSpuriouslyMarkedLost, 0);
  ackFrame.ackBlocks.emplace_back(15, 16);
  processAckFrame(
      conn,
      GetParam(),
      ackFrame,
      [](auto, auto, auto) {},
      [](auto&, auto&, auto) {},
      Clock::now());
  itr = std::find_if(
      conn.outstandings.packets.begin(),
      conn.outstandings.packets.end(),
      [](auto& op) {
        return op.packet.header.getPacketSequenceNum() == 15 ||
            op.packet.header.getPacketSequenceNum() == 16;
      });
  EXPECT_TRUE(itr == conn.outstandings.packets.end());

  // Duplicate ACK much later, should clear out declared lost.
  processAckFrame(
      conn,
      GetParam(),
      ackFrame,
      [](auto, auto, auto) {},
      [](auto&, auto&, auto) {},
      Clock::now() + 2 * calculatePTO(conn));

  numDeclaredLost = std::count_if(
      conn.outstandings.packets.begin(),
      conn.outstandings.packets.end(),
      [](auto& op) { return op.declaredLost; });
  EXPECT_EQ(numDeclaredLost, 0);
  EXPECT_EQ(numDeclaredLost, conn.outstandings.declaredLostCount);
  EXPECT_EQ(conn.lossState.totalPacketsSpuriouslyMarkedLost, 1);
}

TEST_P(AckHandlersTest, TestAckBlocksWithGaps) {
  QuicServerConnectionState conn(
      FizzServerQuicHandshakeContext::Builder().build());
  conn.lossState.reorderingThreshold = 30;
  auto mockCongestionController = std::make_unique<MockCongestionController>();
  auto rawCongestionController = mockCongestionController.get();
  conn.congestionController = std::move(mockCongestionController);
  // Get the time based loss detection out of the way
  conn.lossState.srtt = 10s;

  StreamId currentStreamId = 10;
  for (PacketNum packetNum = 10; packetNum < 51; packetNum++) {
    auto regularPacket = createNewPacket(packetNum, GetParam());
    WriteStreamFrame frame(currentStreamId++, 0, 0, true);
    regularPacket.frames.emplace_back(std::move(frame));
    conn.outstandings
        .packetCount[regularPacket.header.getPacketNumberSpace()]++;
    conn.outstandings.packets.emplace_back(OutstandingPacket(
        std::move(regularPacket),
        Clock::now(),
        1,
        0,
        false,
        packetNum,
        0,
        0,
        0,
        LossState(),
        0));
  }

  ReadAckFrame ackFrame;
  ackFrame.largestAcked = 45;
  ackFrame.ackBlocks.emplace_back(45, 45);
  ackFrame.ackBlocks.emplace_back(33, 44);
  ackFrame.ackBlocks.emplace_back(12, 21);

  std::vector<WriteStreamFrame> streams;
  std::vector<PacketNum> lostPackets;
  uint64_t expectedAckedBytes = 21 - 12 + 1 + 44 - 33 + 1 + 45 - 45 + 1;
  uint64_t expectedAckedPackets = expectedAckedBytes; // each packet size is 1
  size_t lostPacketsCounter = 0;
  EXPECT_CALL(*rawCongestionController, onPacketAckOrLoss(_, _))
      .WillRepeatedly(Invoke([&](auto ack, auto loss) {
        if (ack) {
          EXPECT_EQ(45, *ack->largestAckedPacket);
          EXPECT_EQ(expectedAckedBytes, ack->ackedBytes);
          EXPECT_EQ(expectedAckedPackets, ack->ackedPackets.size());
        }
        if (loss) {
          lostPacketsCounter++;
        }
      }));
  processAckFrame(
      conn,
      GetParam(),
      ackFrame,
      [&](const auto&, const auto& packetFrame, const ReadAckFrame&) {
        auto& stream = *packetFrame.asWriteStreamFrame();
        streams.emplace_back(stream);
      },
      testLossHandler(lostPackets),
      Clock::now());
  EXPECT_EQ(lostPacketsCounter, lostPackets.empty() ? 0 : 1);

  StreamId start = 45;
  std::vector<StreamId> ids(45 - 33 + 1);
  std::generate(ids.begin(), ids.end(), [&]() { return start--; });
  EXPECT_TRUE(std::equal(
      streams.begin(),
      streams.begin() + (45 - 33 + 1),
      ids.begin(),
      ids.end(),
      [](const auto& frame, auto id) { return frame.streamId == id; }));

  start = 21;
  std::vector<StreamId> ids2(10);
  std::generate(ids2.begin(), ids2.end(), [&]() { return start--; });
  EXPECT_TRUE(std::equal(
      streams.begin() + (45 - 33 + 1),
      streams.end(),
      ids2.begin(),
      ids2.end(),
      [](const auto& frame, auto id) { return frame.streamId == id; }));

  std::vector<PacketNum> remainingPackets(11 + 5);
  std::iota(remainingPackets.begin(), remainingPackets.begin() + 11, 22);
  std::iota(remainingPackets.begin() + 11, remainingPackets.end(), 46);

  std::vector<PacketNum> actualPacketNumbers;
  for (auto& op : conn.outstandings.packets) {
    if (!op.declaredLost) {
      actualPacketNumbers.push_back(op.packet.header.getPacketSequenceNum());
    }
  }
  EXPECT_TRUE(std::equal(
      actualPacketNumbers.begin(),
      actualPacketNumbers.end(),
      remainingPackets.begin(),
      remainingPackets.end()));

  std::vector<PacketNum> actualLostPackets = {10, 11};

  EXPECT_TRUE(std::equal(
      actualLostPackets.begin(),
      actualLostPackets.end(),
      lostPackets.begin(),
      lostPackets.end()));
}

TEST_P(AckHandlersTest, TestNonSequentialPacketNumbers) {
  QuicServerConnectionState conn(
      FizzServerQuicHandshakeContext::Builder().build());
  conn.lossState.reorderingThreshold = 10;
  auto mockCongestionController = std::make_unique<MockCongestionController>();
  auto rawCongestionController = mockCongestionController.get();
  conn.congestionController = std::move(mockCongestionController);
  // Get the time based loss detection out of the way
  conn.lossState.srtt = 10s;

  StreamId current = 10;
  for (PacketNum packetNum = 10; packetNum < 20; packetNum++) {
    auto regularPacket = createNewPacket(packetNum, GetParam());
    WriteStreamFrame frame(current++, 0, 0, true);
    regularPacket.frames.emplace_back(std::move(frame));
    conn.outstandings
        .packetCount[regularPacket.header.getPacketNumberSpace()]++;
    conn.outstandings.packets.emplace_back(OutstandingPacket(
        std::move(regularPacket),
        Clock::now(),
        1,
        0,
        false,
        packetNum,
        0,
        0,
        0,
        LossState(),
        0));
  }

  for (PacketNum packetNum = 20; packetNum < 40; packetNum += 3) {
    auto regularPacket = createNewPacket(packetNum, GetParam());
    WriteStreamFrame frame(current, 0, 0, true);
    current += 3;
    regularPacket.frames.emplace_back(std::move(frame));
    conn.outstandings
        .packetCount[regularPacket.header.getPacketNumberSpace()]++;
    conn.outstandings.packets.emplace_back(OutstandingPacket(
        std::move(regularPacket),
        Clock::now(),
        1,
        0,
        false,
        packetNum,
        0,
        0,
        0,
        LossState(),
        0));
  }

  ReadAckFrame ackFrame;
  ackFrame.largestAcked = 26;
  ackFrame.ackBlocks.emplace_back(26, 26);
  // This intentionally acks an unsent packet. When we start enforcing
  // unsent packets then disable this.
  ackFrame.ackBlocks.emplace_back(5, 20);

  std::vector<WriteStreamFrame> streams;
  std::vector<PacketNum> lostPackets;
  // Only 26 and [10, 20] are acked:
  uint64_t expectedAckedBytes = 20 - 10 + 1 + 1;
  uint64_t expectedAckedPackets = expectedAckedBytes; // each packet size is 1
  EXPECT_CALL(*rawCongestionController, onPacketAckOrLoss(_, _))
      .Times(1)
      .WillOnce(Invoke([&](auto ackEvent, auto) {
        EXPECT_EQ(26, *ackEvent->largestAckedPacket);
        EXPECT_EQ(expectedAckedBytes, ackEvent->ackedBytes);
        EXPECT_EQ(expectedAckedPackets, ackEvent->ackedPackets.size());
      }));
  processAckFrame(
      conn,
      GetParam(),
      ackFrame,
      [&](const auto&, const auto& packetFrame, const ReadAckFrame&) {
        auto& stream = *packetFrame.asWriteStreamFrame();
        streams.emplace_back(stream);
      },
      testLossHandler(lostPackets),
      Clock::now());

  EXPECT_EQ(26, streams.begin()->streamId);

  StreamId start = 20;
  std::vector<StreamId> ids(20 - 10 + 1);
  std::generate(ids.begin(), ids.end(), [&]() { return start--; });
  EXPECT_TRUE(std::equal(
      streams.begin() + 1,
      streams.end(),
      ids.begin(),
      ids.end(),
      [](const auto& frame, auto id) { return frame.streamId == id; }));

  std::vector<PacketNum> remainingPackets(5);
  remainingPackets[0] = 23;
  int remainingIdx = 1;
  for (PacketNum num = 29; num < 40; num += 3) {
    remainingPackets[remainingIdx++] = num;
  }

  std::vector<PacketNum> actualPacketNumbers;
  std::transform(
      conn.outstandings.packets.begin(),
      conn.outstandings.packets.end(),
      std::back_insert_iterator<decltype(actualPacketNumbers)>(
          actualPacketNumbers),
      [](const auto& packet) {
        return packet.packet.header.getPacketSequenceNum();
      });

  EXPECT_TRUE(std::equal(
      actualPacketNumbers.begin(),
      actualPacketNumbers.end(),
      remainingPackets.begin(),
      remainingPackets.end()));
}

TEST_P(AckHandlersTest, AckVisitorForAckTest) {
  QuicServerConnectionState conn(
      FizzServerQuicHandshakeContext::Builder().build());
  conn.connectionTime = Clock::now();
  auto firstPacket = createNewPacket(100 /* packetNum */, GetParam());
  WriteAckFrame firstAckFrame;
  firstAckFrame.ackBlocks.emplace_back(900, 1000);
  firstAckFrame.ackBlocks.emplace_back(500, 700);
  conn.ackStates.appDataAckState.acks.insert(900, 1000);
  conn.ackStates.appDataAckState.acks.insert(500, 700);
  firstPacket.frames.emplace_back(std::move(firstAckFrame));
  conn.outstandings.packetCount[firstPacket.header.getPacketNumberSpace()]++;
  conn.outstandings.packets.emplace_back(OutstandingPacket(
      std::move(firstPacket),
      Clock::now(),
      0,
      0,
      false,
      0,
      0,
      0,
      0,
      LossState(),
      0));

  auto secondPacket = createNewPacket(101 /* packetNum */, GetParam());
  WriteAckFrame secondAckFrame;
  secondAckFrame.ackBlocks.emplace_back(1100, 2000);
  secondAckFrame.ackBlocks.emplace_back(1002, 1090);
  conn.ackStates.appDataAckState.acks.insert(1100, 2000);
  conn.ackStates.appDataAckState.acks.insert(1002, 1090);
  secondPacket.frames.emplace_back(std::move(secondAckFrame));
  conn.outstandings.packetCount[secondPacket.header.getPacketNumberSpace()]++;
  conn.outstandings.packets.emplace_back(OutstandingPacket(
      std::move(secondPacket),
      Clock::now(),
      0,
      0,
      false,
      0,
      0,
      0,
      0,
      LossState(),
      0));

  ReadAckFrame firstReceivedAck;
  firstReceivedAck.largestAcked = 100;
  firstReceivedAck.ackBlocks.emplace_back(100, 100);
  processAckFrame(
      conn,
      GetParam(),
      firstReceivedAck,
      [&](const auto& outstandingPacket,
          const auto& packetFrame,
          const ReadAckFrame&) {
        auto ackedPacketNum =
            outstandingPacket.packet.header.getPacketSequenceNum();
        EXPECT_EQ(ackedPacketNum, firstReceivedAck.largestAcked);
        const WriteAckFrame* frame = packetFrame.asWriteAckFrame();
        if (frame) {
          commonAckVisitorForAckFrame(conn.ackStates.appDataAckState, *frame);
        }
      },
      [](auto& /* conn */, auto& /* packet */, bool /* processed */
      ) {},
      Clock::now());
  EXPECT_EQ(2, conn.ackStates.appDataAckState.acks.size());
  EXPECT_EQ(
      Interval<PacketNum>(1002, 1090),
      conn.ackStates.appDataAckState.acks.front());
  EXPECT_EQ(
      Interval<PacketNum>(1100, 2000),
      conn.ackStates.appDataAckState.acks.back());

  ReadAckFrame secondReceivedAck;
  secondReceivedAck.largestAcked = 101;
  secondReceivedAck.ackBlocks.emplace_back(101, 101);
  processAckFrame(
      conn,
      GetParam(),
      secondReceivedAck,
      [&](const auto&, const auto& packetFrame, const ReadAckFrame&) {
        const WriteAckFrame* frame = packetFrame.asWriteAckFrame();
        if (frame) {
          commonAckVisitorForAckFrame(conn.ackStates.appDataAckState, *frame);
        }
      },
      [](auto& /* conn */, auto& /* packet */, bool /* processed */
      ) {},
      Clock::now());
  EXPECT_TRUE(conn.ackStates.appDataAckState.acks.empty());
}

TEST_P(AckHandlersTest, NoNewAckedPacket) {
  QuicServerConnectionState conn(
      FizzServerQuicHandshakeContext::Builder().build());
  auto mockController = std::make_unique<MockCongestionController>();
  auto rawController = mockController.get();
  conn.congestionController = std::move(mockController);

  conn.lossState.ptoCount = 1;
  PacketNum packetAfterRtoNum = 10;
  auto packetAfterRto = createNewPacket(packetAfterRtoNum, GetParam());
  conn.outstandings.packetCount[packetAfterRto.header.getPacketNumberSpace()]++;
  conn.outstandings.packets.emplace_back(OutstandingPacket(
      std::move(packetAfterRto),
      Clock::now(),
      0,
      0,
      false,
      0,
      0,
      0,
      0,
      LossState(),
      0));

  ReadAckFrame ackFrame;
  ackFrame.largestAcked = 5;
  EXPECT_CALL(*rawController, onPacketAckOrLoss(_, _)).Times(0);
  processAckFrame(
      conn,
      GetParam(),
      ackFrame,
      [](const auto&, const auto&, const auto&) {},
      [](auto&, auto&, bool) {},
      Clock::now());
  EXPECT_TRUE(conn.pendingEvents.setLossDetectionAlarm);
  EXPECT_EQ(conn.lossState.ptoCount, 1);
  EXPECT_TRUE(!conn.ackStates.appDataAckState.largestAckedByPeer.has_value());
}

TEST_P(AckHandlersTest, LossByAckedRecovered) {
  QuicServerConnectionState conn(
      FizzServerQuicHandshakeContext::Builder().build());
  auto mockController = std::make_unique<MockCongestionController>();
  conn.congestionController = std::move(mockController);

  ReadAckFrame ackFrame;
  ackFrame.largestAcked = 10;
  ackFrame.ackBlocks.emplace_back(5, 10);
  processAckFrame(
      conn,
      GetParam(),
      ackFrame,
      [](const auto&, const auto&, const auto&) {},
      [](auto&, auto&, bool) {},
      Clock::now());
}

TEST_P(AckHandlersTest, AckPacketNumDoesNotExist) {
  QuicServerConnectionState conn(
      FizzServerQuicHandshakeContext::Builder().build());
  auto mockController = std::make_unique<MockCongestionController>();
  conn.congestionController = std::move(mockController);
  // Get the time based loss detection out of the way
  conn.lossState.srtt = 10s;

  PacketNum packetNum1 = 9;
  auto regularPacket1 = createNewPacket(packetNum1, GetParam());
  conn.outstandings.packetCount[regularPacket1.header.getPacketNumberSpace()]++;
  conn.outstandings.packets.emplace_back(
      std::move(regularPacket1),
      Clock::now(),
      0,
      0,
      false,
      0,
      0,
      0,
      0,
      LossState(),
      0);

  PacketNum packetNum2 = 10;
  auto regularPacket2 = createNewPacket(packetNum2, GetParam());
  conn.outstandings.packetCount[regularPacket2.header.getPacketNumberSpace()]++;
  conn.outstandings.packets.emplace_back(
      std::move(regularPacket2),
      Clock::now(),
      0,
      0,
      false,
      0,
      0,
      0,
      0,
      LossState(),
      0);

  // Ack a packet one higher than the packet so that we don't trigger reordering
  // threshold.
  ReadAckFrame ackFrame;
  ackFrame.largestAcked = 1000;
  ackFrame.ackBlocks.emplace_back(1000, 1000);
  ackFrame.ackBlocks.emplace_back(10, 10);
  processAckFrame(
      conn,
      GetParam(),
      ackFrame,
      [](const auto&, const auto&, const auto&) {},
      [](auto&, auto&, bool) {},
      Clock::now());
  EXPECT_EQ(1, conn.outstandings.packets.size());
}

TEST_P(AckHandlersTest, TestHandshakeCounterUpdate) {
  QuicServerConnectionState conn(
      FizzServerQuicHandshakeContext::Builder().build());
  StreamId stream = 1;
  for (PacketNum packetNum = 0; packetNum < 10; packetNum++) {
    auto regularPacket = createNewPacket(
        packetNum, (packetNum % 2 ? GetParam() : PacketNumberSpace::AppData));
    WriteStreamFrame frame(
        stream, 100 * packetNum + 0, 100 * packetNum + 100, false);
    regularPacket.frames.emplace_back(std::move(frame));
    conn.outstandings
        .packetCount[regularPacket.header.getPacketNumberSpace()]++;
    conn.outstandings.packets.emplace_back(
        std::move(regularPacket),
        Clock::now(),
        0,
        0,
        packetNum % 2 && GetParam() != PacketNumberSpace::AppData,
        packetNum / 2,
        0,
        0,
        0,
        LossState(),
        0);
  }

  ReadAckFrame ackFrame;
  ackFrame.largestAcked = 9;
  ackFrame.ackBlocks.emplace_back(3, 7);

  std::vector<PacketNum> lostPackets;
  processAckFrame(
      conn,
      GetParam(),
      ackFrame,
      [&](const auto&, const auto&, const ReadAckFrame&) {},
      testLossHandler(lostPackets),
      Clock::now());
  // When [3, 7] are acked, [0, 2] may also be marked loss if they are in the
  // same packet number space, due to reordering threshold
  auto numDeclaredLost = std::count_if(
      conn.outstandings.packets.begin(),
      conn.outstandings.packets.end(),
      [](auto& op) { return op.declaredLost; });
  EXPECT_EQ(numDeclaredLost, conn.outstandings.declaredLostCount);
  if (GetParam() == PacketNumberSpace::Initial) {
    EXPECT_EQ(numDeclaredLost, 1);
    EXPECT_EQ(1, conn.outstandings.packetCount[PacketNumberSpace::Initial]);
    // AppData packets won't be acked by an ack in Initial space:
    // So 0, 2, 4, 6, 8 and 9 are left in OP list
    EXPECT_EQ(numDeclaredLost + 6, conn.outstandings.packets.size());
  } else if (GetParam() == PacketNumberSpace::Handshake) {
    EXPECT_EQ(numDeclaredLost, 1);
    EXPECT_EQ(1, conn.outstandings.packetCount[PacketNumberSpace::Handshake]);
    // AppData packets won't be acked by an ack in Handshake space:
    // So 0, 2, 4, 6, 8 and 9 are left in OP list
    EXPECT_EQ(numDeclaredLost + 6, conn.outstandings.packets.size());
  } else {
    EXPECT_EQ(numDeclaredLost + 2, conn.outstandings.packets.size());
  }
}

TEST_P(AckHandlersTest, PurgeAcks) {
  QuicServerConnectionState conn(
      FizzServerQuicHandshakeContext::Builder().build());
  WriteAckFrame ackFrame;
  ackFrame.ackBlocks.emplace_back(900, 1000);
  ackFrame.ackBlocks.emplace_back(500, 700);
  conn.ackStates.initialAckState.acks.insert(900, 1200);
  conn.ackStates.initialAckState.acks.insert(500, 800);
  auto expectedTime = Clock::now();
  conn.ackStates.initialAckState.largestRecvdPacketTime = expectedTime;
  commonAckVisitorForAckFrame(conn.ackStates.initialAckState, ackFrame);
  // We should have purged old packets in ack state
  EXPECT_EQ(conn.ackStates.initialAckState.acks.size(), 1);
  EXPECT_EQ(conn.ackStates.initialAckState.acks.front().start, 1001);
  EXPECT_EQ(conn.ackStates.initialAckState.acks.front().end, 1200);
  EXPECT_EQ(
      expectedTime, *conn.ackStates.initialAckState.largestRecvdPacketTime);
}

TEST_P(AckHandlersTest, NoSkipAckVisitor) {
  QuicServerConnectionState conn(
      FizzServerQuicHandshakeContext::Builder().build());
  auto mockCongestionController = std::make_unique<MockCongestionController>();
  auto rawCongestionController = mockCongestionController.get();
  conn.congestionController = std::move(mockCongestionController);
  EXPECT_CALL(*rawCongestionController, onPacketAckOrLoss(_, _))
      .Times(1)
      .WillOnce(Invoke([&](auto ackEvent, auto) {
        EXPECT_EQ(1, ackEvent->ackedPackets.size());
        EXPECT_EQ(1, ackEvent->ackedPackets.front().encodedSize);
        EXPECT_EQ(1, ackEvent->ackedPackets.front().totalBytesSentThen);
      }));

  PacketNum packetNum = 0;
  auto regularPacket = createNewPacket(packetNum, GetParam());
  // We need to at least have one frame to trigger ackVisitor
  WriteStreamFrame frame(0, 0, 0, true);
  regularPacket.frames.emplace_back(std::move(frame));
  conn.outstandings.packetCount[regularPacket.header.getPacketNumberSpace()]++;
  conn.outstandings.packets.emplace_back(OutstandingPacket(
      std::move(regularPacket),
      Clock::now(),
      1,
      0,
      false,
      1,
      0,
      0,
      0,
      LossState(),
      0));
  ReadAckFrame ackFrame;
  ackFrame.largestAcked = 0;
  ackFrame.ackBlocks.emplace_back(0, 0);
  uint16_t ackVisitorCounter = 0;
  // A counting ack visitor
  auto countingAckVisitor = [&](const auto& /* outstandingPacket */,
                                const auto& /* packetFrame */,
                                const auto& /* readAckFrame */) {
    ackVisitorCounter++;
  };
  processAckFrame(
      conn,
      GetParam(),
      ackFrame,
      countingAckVisitor,
      [&](auto& /*conn*/, auto& /* packet */, bool /* processed */
      ) { /* no-op lossVisitor */ },
      Clock::now());
  EXPECT_EQ(1, ackVisitorCounter);
}

TEST_P(AckHandlersTest, SkipAckVisitor) {
  QuicServerConnectionState conn(
      FizzServerQuicHandshakeContext::Builder().build());
  auto mockCongestionController = std::make_unique<MockCongestionController>();
  auto rawCongestionController = mockCongestionController.get();
  conn.congestionController = std::move(mockCongestionController);
  EXPECT_CALL(*rawCongestionController, onPacketAckOrLoss(_, _))
      .Times(1)
      .WillOnce(Invoke([&](auto ackEvent, auto) {
        EXPECT_EQ(1, ackEvent->ackedPackets.size());
        EXPECT_EQ(1, ackEvent->ackedPackets.front().encodedSize);
        EXPECT_EQ(1, ackEvent->ackedPackets.front().totalBytesSentThen);
      }));

  PacketNum packetNum = 0;
  auto regularPacket = createNewPacket(packetNum, GetParam());
  // We need to at least have one frame to trigger ackVisitor
  WriteStreamFrame frame(0, 0, 0, true);
  regularPacket.frames.emplace_back(std::move(frame));
  OutstandingPacket outstandingPacket(
      std::move(regularPacket),
      Clock::now(),
      1,
      0,
      false,
      1,
      0,
      0,
      0,
      LossState(),
      0);
  // Give this outstandingPacket an associatedEvent that's not in
  // outstandings.packetEvents
  outstandingPacket.associatedEvent.emplace(GetParam(), 0);
  conn.outstandings.packets.push_back(std::move(outstandingPacket));
  conn.outstandings.clonedPacketCount[GetParam()]++;

  ReadAckFrame ackFrame;
  ackFrame.largestAcked = 0;
  ackFrame.ackBlocks.emplace_back(0, 0);
  uint16_t ackVisitorCounter = 0;
  // A counting ack visitor
  auto countingAckVisitor = [&](const auto& /* outstandingPacket */,
                                const auto& /* packetFrame */,
                                const auto& /* readAckFrame */) {
    ackVisitorCounter++;
  };
  processAckFrame(
      conn,
      GetParam(),
      ackFrame,
      countingAckVisitor,
      [&](auto& /*conn*/, auto& /* packet */, bool /* processed */
      ) { /* no-op lossVisitor */ },
      Clock::now());
  EXPECT_EQ(0, ackVisitorCounter);
}

TEST_P(AckHandlersTest, NoDoubleProcess) {
  QuicServerConnectionState conn(
      FizzServerQuicHandshakeContext::Builder().build());
  conn.congestionController.reset();

  WriteStreamFrame frame(0, 0, 0, true);
  PacketNum packetNum1 = 0, packetNum2 = 1;
  auto regularPacket1 = createNewPacket(packetNum1, GetParam()),
       regularPacket2 = createNewPacket(packetNum2, GetParam());
  regularPacket1.frames.push_back(frame);
  regularPacket2.frames.push_back(frame);

  OutstandingPacket outstandingPacket1(
      std::move(regularPacket1),
      Clock::now(),
      1,
      0,
      false,
      1,
      0,
      0,
      0,
      LossState(),
      0);
  outstandingPacket1.associatedEvent.emplace(GetParam(), packetNum1);

  OutstandingPacket outstandingPacket2(
      std::move(regularPacket2),
      Clock::now(),
      1,
      0,
      false,
      1,
      0,
      0,
      0,
      LossState(),
      0);
  // The seconds packet has the same PacketEvent
  outstandingPacket2.associatedEvent.emplace(GetParam(), packetNum1);

  conn.outstandings.packetCount[GetParam()]++;
  conn.outstandings.packets.push_back(std::move(outstandingPacket1));
  conn.outstandings.packets.push_back(std::move(outstandingPacket2));
  conn.outstandings.clonedPacketCount[GetParam()] += 2;
  conn.outstandings.packetEvents.emplace(GetParam(), packetNum1);

  // A counting ack visitor
  uint16_t ackVisitorCounter = 0;
  auto countingAckVisitor = [&](const auto& /* outstandingPacket */,
                                const auto& /* packetFrame */,
                                const auto& /* readAckFrame */) {
    ackVisitorCounter++;
  };

  // First ack. This will ack first packet, and trigger a ack visiting.
  ReadAckFrame ackFrame1;
  ackFrame1.largestAcked = 0;
  ackFrame1.ackBlocks.emplace_back(0, 0);
  processAckFrame(
      conn,
      GetParam(),
      ackFrame1,
      countingAckVisitor,
      [&](auto& /*conn*/, auto& /* packet */, bool /* processed */
      ) { /* no-op lossVisitor */ },
      Clock::now());
  EXPECT_EQ(1, ackVisitorCounter);

  // Second ack that acks the second packet.  This won't trigger a visit.
  ReadAckFrame ackFrame2;
  ackFrame2.largestAcked = 1;
  ackFrame2.ackBlocks.emplace_back(1, 1);
  processAckFrame(
      conn,
      GetParam(),
      ackFrame2,
      countingAckVisitor,
      [&](auto& /* conn */, auto& /* packet */, bool /* processed */
      ) { /* no-op */ },
      Clock::now());
  EXPECT_EQ(1, ackVisitorCounter);
}

TEST_P(AckHandlersTest, ClonedPacketsCounter) {
  QuicServerConnectionState conn(
      FizzServerQuicHandshakeContext::Builder().build());
  conn.congestionController = nullptr;
  WriteStreamFrame frame(0, 0, 0, true);
  auto packetNum1 = conn.ackStates.appDataAckState.nextPacketNum;
  auto regularPacket1 = createNewPacket(packetNum1, GetParam());
  regularPacket1.frames.push_back(frame);
  OutstandingPacket outstandingPacket1(
      std::move(regularPacket1),
      Clock::now(),
      1,
      0,
      false,
      1,
      0,
      0,
      0,
      LossState(),
      0);
  outstandingPacket1.associatedEvent.emplace(GetParam(), packetNum1);

  conn.ackStates.appDataAckState.nextPacketNum++;
  auto packetNum2 = conn.ackStates.appDataAckState.nextPacketNum;
  auto regularPacket2 = createNewPacket(packetNum2, GetParam());
  regularPacket2.frames.push_back(frame);
  OutstandingPacket outstandingPacket2(
      std::move(regularPacket2),
      Clock::now(),
      1,
      0,
      false,
      1,
      0,
      0,
      0,
      LossState(),
      0);

  conn.outstandings
      .packetCount[outstandingPacket1.packet.header.getPacketNumberSpace()]++;
  conn.outstandings
      .packetCount[outstandingPacket2.packet.header.getPacketNumberSpace()]++;
  conn.outstandings.packets.push_back(std::move(outstandingPacket1));
  conn.outstandings.packets.push_back(std::move(outstandingPacket2));
  conn.outstandings.clonedPacketCount[GetParam()] = 1;
  conn.outstandings.packetEvents.emplace(GetParam(), packetNum1);

  ReadAckFrame ackFrame;
  ackFrame.largestAcked = packetNum2;
  ackFrame.ackBlocks.emplace_back(packetNum1, packetNum2);

  uint16_t ackVisitorCounter = 0;
  auto countingAckVisitor = [&](const auto& /* outstandingPacket */,
                                const auto& /* packetFrame */,
                                const auto& /* readAckFrame */) {
    ackVisitorCounter++;
  };
  processAckFrame(
      conn,
      GetParam(),
      ackFrame,
      countingAckVisitor,
      [&](auto& /* conn */, auto& /* packet */, bool /* processed */
      ) { /* no-op */ },
      Clock::now());
  EXPECT_EQ(2, ackVisitorCounter);
  EXPECT_EQ(0, conn.outstandings.numClonedPackets());
}

TEST_P(AckHandlersTest, UpdateMaxAckDelay) {
  QuicServerConnectionState conn(
      FizzServerQuicHandshakeContext::Builder().build());
  conn.congestionController = nullptr;
  conn.lossState.mrtt = 200us;
  PacketNum packetNum = 0;
  auto regularPacket = createNewPacket(packetNum, GetParam());
  auto sentTime = Clock::now();
  conn.outstandings.packetCount[regularPacket.header.getPacketNumberSpace()]++;
  conn.outstandings.packets.emplace_back(OutstandingPacket(
      std::move(regularPacket),
      sentTime,
      1,
      0,
      false,
      1,
      0,
      0,
      0,
      LossState(),
      0));

  ReadAckFrame ackFrame;
  // ackDelay has no effect on mrtt
  ackFrame.ackDelay = 50us;
  ackFrame.largestAcked = 0;
  ackFrame.ackBlocks.emplace_back(0, 0);

  auto receiveTime = sentTime + 10us;
  processAckFrame(
      conn,
      GetParam(),
      ackFrame,
      [&](const auto&, const auto&, const auto&) { /* ackVisitor */ },
      [&](auto&, auto&, bool) { /* lossVisitor */ },
      receiveTime);
  EXPECT_EQ(10us, conn.lossState.mrtt);
}

// Ack only acks packets aren't outstanding, but TimeReordering still finds loss
TEST_P(AckHandlersTest, AckNotOutstandingButLoss) {
  QuicServerConnectionState conn(
      FizzServerQuicHandshakeContext::Builder().build());
  auto mockQLogger = std::make_shared<MockQLogger>(VantagePoint::Server);
  conn.qLogger = mockQLogger;

  conn.lossState.srtt = 200ms;
  conn.lossState.lrtt = 150ms;
  // Packet 2 has been sent and acked:
  if (GetParam() == PacketNumberSpace::Initial) {
    conn.ackStates.initialAckState.largestAckedByPeer = 2;
  } else if (GetParam() == PacketNumberSpace::Handshake) {
    conn.ackStates.handshakeAckState.largestAckedByPeer = 2;
  } else {
    conn.ackStates.appDataAckState.largestAckedByPeer = 2;
  }
  auto mockCongestionController = std::make_unique<MockCongestionController>();
  auto rawCongestionController = mockCongestionController.get();
  conn.congestionController = std::move(mockCongestionController);
  EXPECT_CALL(*rawCongestionController, onPacketAckOrLoss(_, _))
      .Times(1)
      .WillOnce(Invoke(
          [&](folly::Optional<CongestionController::AckEvent> ackEvent,
              folly::Optional<CongestionController::LossEvent> lossEvent) {
            EXPECT_FALSE(ackEvent->largestAckedPacket.has_value());
            EXPECT_TRUE(lossEvent->largestLostPacketNum.has_value());
          }));

  // But packet 1 has been outstanding for longer than delayUntilLost:
  PacketNum packetNum = 1;
  auto regularPacket = createNewPacket(packetNum, GetParam());
  // We need to at least have one frame to trigger ackVisitor
  WriteStreamFrame frame(0, 0, 0, true);
  regularPacket.frames.emplace_back(std::move(frame));
  auto delayUntilLost = 200ms *
      conn.transportSettings.timeReorderingThreshDividend /
      conn.transportSettings.timeReorderingThreshDivisor;
  OutstandingPacket outstandingPacket(
      std::move(regularPacket),
      Clock::now() - delayUntilLost - 20ms,
      1,
      0,
      false,
      1,
      0,
      0,
      0,
      LossState(),
      0);
  conn.outstandings.packets.push_back(std::move(outstandingPacket));
  conn.outstandings.packetCount[GetParam()]++;

  EXPECT_CALL(*mockQLogger, addPacketsLost(1, 1, 1));

  // Peer acks 2 again:
  ReadAckFrame ackFrame;
  ackFrame.largestAcked = 2;
  ackFrame.ackBlocks.emplace_back(2, 2);
  uint16_t ackVisitorCounter = 0;
  conn.lossState.largestSent = 2;
  // A counting ack visitor
  auto countingAckVisitor = [&](const auto& /* outstandingPacket */,
                                const auto& /* packetFrame */,
                                const auto& /* readAckFrame */) {
    ackVisitorCounter++;
  };
  processAckFrame(
      conn,
      GetParam(),
      ackFrame,
      countingAckVisitor,
      [&](auto& /*conn*/, auto& /* packet */, bool /* processed */
      ) { /* no-op lossVisitor */ },
      Clock::now());
  EXPECT_EQ(0, ackVisitorCounter);
}

TEST_P(AckHandlersTest, UpdatePendingAckStates) {
  QuicServerConnectionState conn(
      FizzServerQuicHandshakeContext::Builder().build());
  conn.congestionController = nullptr;
  conn.lossState.totalBytesSent = 2468;
  conn.lossState.totalBodyBytesSent = 2000;
  conn.lossState.totalBytesAcked = 1357;
  conn.lossState.totalBodyBytesAcked = 1000;
  PacketNum packetNum = 0;
  auto regularPacket = createNewPacket(packetNum, GetParam());
  auto sentTime = Clock::now() - 1500ms;
  conn.outstandings.packetCount[regularPacket.header.getPacketNumberSpace()]++;
  conn.outstandings.packets.emplace_back(OutstandingPacket(
      std::move(regularPacket),
      sentTime,
      111,
      100,
      false,
      conn.lossState.totalBytesSent + 111,
      conn.lossState.totalBodyBytesSent + 100,
      0,
      0,
      LossState(),
      0));
  conn.lossState.totalBytesSent += 111;
  conn.lossState.totalBodyBytesSent += 100;

  ReadAckFrame ackFrame;
  ackFrame.largestAcked = 0;
  ackFrame.ackBlocks.emplace_back(0, 0);

  auto receiveTime = Clock::now() - 200ms;
  processAckFrame(
      conn,
      GetParam(),
      ackFrame,
      [&](auto, auto, auto) { /* ackVisitor */ },
      [&](auto&, auto&, auto) { /* lossVisitor */ },
      receiveTime);
  EXPECT_EQ(2468 + 111, conn.lossState.totalBytesSentAtLastAck);
  EXPECT_EQ(1357 + 111, conn.lossState.totalBytesAckedAtLastAck);
  EXPECT_EQ(sentTime, *conn.lossState.lastAckedPacketSentTime);
  EXPECT_EQ(receiveTime, *conn.lossState.lastAckedTime);
  EXPECT_EQ(111 + 1357, conn.lossState.totalBytesAcked);
  EXPECT_EQ(100 + 1000, conn.lossState.totalBodyBytesAcked);
}

TEST_P(AckHandlersTest, AckEventCreation) {
  QuicServerConnectionState conn(
      FizzServerQuicHandshakeContext::Builder().build());
  auto mockCongestionController = std::make_unique<MockCongestionController>();
  auto rawCongestionController = mockCongestionController.get();
  conn.congestionController = std::move(mockCongestionController);

  PacketNum packetNum = 0;
  StreamId streamid = 0;
  TimePoint largestSentTime;
  while (packetNum < 10) {
    auto regularPacket = createNewPacket(packetNum, GetParam());
    WriteStreamFrame frame(streamid++, 0, 0, true);
    regularPacket.frames.emplace_back(std::move(frame));
    largestSentTime =
        Clock::now() - 100ms + std::chrono::milliseconds(packetNum);
    conn.outstandings
        .packetCount[regularPacket.header.getPacketNumberSpace()]++;
    OutstandingPacket sentPacket(
        std::move(regularPacket),
        largestSentTime,
        1,
        0,
        false /* handshake */,
        packetNum,
        0,
        0,
        0,
        LossState(),
        0);
    sentPacket.isAppLimited = (packetNum % 2);
    conn.outstandings.packets.emplace_back(sentPacket);
    packetNum++;
  }

  ReadAckFrame ackFrame;
  ackFrame.largestAcked = 9;
  ackFrame.ackBlocks.emplace_back(0, 9);
  auto ackTime = Clock::now() + 10ms;
  EXPECT_CALL(*rawCongestionController, onPacketAckOrLoss(_, _))
      .Times(1)
      .WillOnce(Invoke([&](auto ack, auto /* loss */) {
        EXPECT_EQ(ackTime, ack->ackTime);
        EXPECT_EQ(9, ack->largestAckedPacket.value());
        EXPECT_EQ(largestSentTime, ack->largestAckedPacketSentTime);
        EXPECT_EQ(10, ack->ackedBytes);
        EXPECT_TRUE(ack->largestAckedPacketAppLimited);
        EXPECT_EQ(
            std::chrono::duration_cast<std::chrono::microseconds>(
                ackTime - largestSentTime),
            ack->mrttSample.value());
      }));

  processAckFrame(
      conn,
      GetParam(),
      ackFrame,
      [](const auto&, const auto&, const auto&) {},
      [](auto&, auto&, bool) {},
      ackTime);
}

TEST_P(AckHandlersTest, ImplictAckEventCreation) {
  QuicServerConnectionState conn(
      FizzServerQuicHandshakeContext::Builder().build());
  auto mockCongestionController = std::make_unique<MockCongestionController>();
  auto rawCongestionController = mockCongestionController.get();
  conn.congestionController = std::move(mockCongestionController);

  PacketNum packetNum = 0;
  StreamId streamid = 0;
  TimePoint largestSentTime;
  while (packetNum < 10) {
    auto regularPacket = createNewPacket(packetNum, GetParam());
    WriteStreamFrame frame(streamid++, 0, 0, true);
    regularPacket.frames.emplace_back(std::move(frame));
    largestSentTime =
        Clock::now() - 100ms + std::chrono::milliseconds(packetNum);
    conn.outstandings
        .packetCount[regularPacket.header.getPacketNumberSpace()]++;
    OutstandingPacket sentPacket(
        std::move(regularPacket),
        largestSentTime,
        1,
        0,
        false /* handshake */,
        packetNum,
        0,
        packetNum + 1,
        0,
        LossState(),
        0);
    sentPacket.isAppLimited = (packetNum % 2);
    conn.outstandings.packets.emplace_back(sentPacket);
    packetNum++;
  }

  auto srttBefore = conn.lossState.srtt;
  ReadAckFrame ackFrame;
  ackFrame.largestAcked = 9;
  ackFrame.ackBlocks.emplace_back(0, 9);
  ackFrame.implicit = true;
  auto ackTime = Clock::now() + 10ms;
  EXPECT_CALL(*rawCongestionController, onPacketAckOrLoss(_, _))
      .Times(1)
      .WillOnce(Invoke([&](auto ack, auto /* loss */) {
        EXPECT_EQ(ackTime, ack->ackTime);
        EXPECT_EQ(9, ack->largestAckedPacket.value());
        EXPECT_EQ(largestSentTime, ack->largestAckedPacketSentTime);
        EXPECT_EQ(10, ack->ackedBytes);
        EXPECT_TRUE(ack->largestAckedPacketAppLimited);
        EXPECT_TRUE(ack->implicit);
        EXPECT_FALSE(ack->mrttSample.has_value());
        EXPECT_EQ(srttBefore, conn.lossState.srtt);
      }));

  processAckFrame(
      conn,
      GetParam(),
      ackFrame,
      [](const auto&, const auto&, const auto&) {},
      [](auto&, auto&, bool) {},
      ackTime);
}

TEST_P(AckHandlersTest, TestRTTPacketObserverCallback) {
  QuicServerConnectionState conn(
      FizzServerQuicHandshakeContext::Builder().build());
  auto mockCongestionController = std::make_unique<MockCongestionController>();
  conn.congestionController = std::move(mockCongestionController);

  // Register 1 observer
  Observer::Config config = {};
  config.rttSamples = true;
  auto ib = MockObserver(config);

  auto observers = std::make_shared<ObserverVec>();
  observers->emplace_back(&ib);
  conn.observers = observers;

  PacketNum packetNum = 0;
  StreamId streamid = 0;
  TimePoint sentTime;
  std::vector<TimePoint> packetRcvTime;
  while (packetNum < 30) {
    auto regularPacket = createNewPacket(packetNum, GetParam());
    WriteStreamFrame frame(streamid++, 0, 0, true);
    regularPacket.frames.emplace_back(std::move(frame));
    sentTime = Clock::now() - 100ms + std::chrono::milliseconds(packetNum);
    packetRcvTime.emplace_back(sentTime);
    conn.outstandings
        .packetCount[regularPacket.header.getPacketNumberSpace()]++;
    OutstandingPacket sentPacket(
        std::move(regularPacket),
        sentTime,
        1,
        0,
        false /* handshake */,
        packetNum,
        0,
        packetNum + 1,
        0,
        LossState(),
        0);
    sentPacket.isAppLimited = false;
    conn.outstandings.packets.emplace_back(sentPacket);
    packetNum++;
  }

  struct ackPacketData {
    PacketNum startSeq, endSeq;
    std::chrono::milliseconds ackDelay;
    TimePoint ackTime;
    ReadAckFrame ackFrame;

    explicit ackPacketData(
        PacketNum startSeqIn,
        PacketNum endSeqIn,
        std::chrono::milliseconds ackDelayIn)
        : startSeq(startSeqIn),
          endSeq(endSeqIn),
          ackDelay(ackDelayIn),
          ackTime(Clock::now() + 5ms) {
      ackFrame.largestAcked = endSeq;
      ackFrame.ackDelay = ackDelay;
      ackFrame.ackBlocks.emplace_back(startSeq, endSeq);
    }
  };

  // See each emplace as the ACK Block [X, Y] with size (Y-X+1)
  std::vector<ackPacketData> ackVec;
  // Sequential test
  ackVec.emplace_back(0, 5, 4ms); // +1 callback
  ackVec.emplace_back(6, 10, 5ms); // +1
  ackVec.emplace_back(11, 15, 6ms); // +1
  // Out-of-order test
  //
  // Its important to check the if
  // largestAcked - currentPacketNum > reorderingThreshold (currently 3)
  // else it can trigger Observer::packetLossDetected
  // and increase the number of callbacks
  ackVec.emplace_back(18, 18, 0ms); // +1
  ackVec.emplace_back(16, 17, 2ms); // +1
  ackVec.emplace_back(19, 29, 12ms); // +1 = 6 callbacks

  // 0 pending callbacks
  EXPECT_EQ(0, size(conn.pendingCallbacks));

  for (const auto ackData : ackVec) {
    processAckFrame(
        conn,
        GetParam(),
        ackData.ackFrame,
        [](const auto&, const auto&, const auto&) {},
        [](auto&, auto&, bool) {},
        ackData.ackTime);
  }

  // see above
  EXPECT_EQ(6, size(conn.pendingCallbacks));

  for (const auto ackData : ackVec) {
    auto rttSample = std::chrono::duration_cast<std::chrono::microseconds>(
        ackData.ackTime - packetRcvTime[ackData.endSeq]);
    EXPECT_CALL(
        ib,
        rttSampleGenerated(
            nullptr,
            AllOf(
                Field(&Observer::PacketRTT::rcvTime, ackData.ackTime),
                Field(&Observer::PacketRTT::rttSample, rttSample),
                Field(&Observer::PacketRTT::ackDelay, ackData.ackDelay),
                Field(
                    &Observer::PacketRTT::metadata,
                    Field(
                        &quic::OutstandingPacketMetadata::inflightBytes,
                        ackData.endSeq + 1)))));
  }

  for (auto& callback : conn.pendingCallbacks) {
    callback(nullptr);
  }
}

TEST_P(AckHandlersTest, TestSpuriousObserverReorder) {
  QuicServerConnectionState conn(
      FizzServerQuicHandshakeContext::Builder().build());
  auto mockCongestionController = std::make_unique<MockCongestionController>();
  conn.congestionController = std::move(mockCongestionController);

  // Register 1 observer
  Observer::Config config = {};
  config.spuriousLossEvents = true;
  config.lossEvents = true;
  auto ib = MockObserver(config);

  auto observers = std::make_shared<ObserverVec>();
  observers->emplace_back(&ib);
  conn.observers = observers;
  auto noopLossVisitor = [](auto&, auto&, bool) {};

  TimePoint startTime = Clock::now();
  emplacePackets(conn, 10, startTime, GetParam());

  // from [0, 9], [3, 4] already acked
  auto beginPacket = getFirstOutstandingPacket(conn, GetParam());
  conn.outstandings.packets.erase(beginPacket + 3, beginPacket + 5);
  conn.outstandings.packetCount[GetParam()] -= 4;

  // setting a very low reordering threshold to force loss by reorder
  conn.lossState.reorderingThreshold = 1;
  // setting time out parameters higher than the time at which detectLossPackets
  // is called to make sure there are no losses by timeout
  conn.lossState.srtt = 400ms;
  conn.lossState.lrtt = 350ms;
  conn.transportSettings.timeReorderingThreshDividend = 1.0;
  conn.transportSettings.timeReorderingThreshDivisor = 1.0;
  TimePoint checkTime = startTime + 20ms;

  detectLossPackets(conn, 4, noopLossVisitor, checkTime, GetParam());

  // expecting 1 callback to be stacked
  EXPECT_EQ(1, size(conn.pendingCallbacks));

  EXPECT_CALL(
      ib,
      packetLossDetected(
          nullptr,
          Field(
              &Observer::LossEvent::lostPackets,
              UnorderedElementsAre(
                  MockObserver::getLossPacketMatcher(0, true, false),
                  MockObserver::getLossPacketMatcher(1, true, false),
                  MockObserver::getLossPacketMatcher(2, true, false)))))
      .Times(1);

  // Here we receive the spurious loss packets in a late ack
  {
    ReadAckFrame ackFrame;
    ackFrame.largestAcked = 2;
    ackFrame.ackBlocks.emplace_back(0, 2);

    processAckFrame(
        conn,
        GetParam(),
        ackFrame,
        [](const auto&, const auto&, const auto&) {},
        [](auto&, auto&, bool) {},
        startTime + 30ms);
  }

  // Spurious loss observer call added
  EXPECT_EQ(2, size(conn.pendingCallbacks));

  EXPECT_CALL(
      ib,
      spuriousLossDetected(
          nullptr,
          Field(
              &Observer::SpuriousLossEvent::spuriousPackets,
              UnorderedElementsAre(
                  MockObserver::getLossPacketMatcher(0, true, false),
                  MockObserver::getLossPacketMatcher(1, true, false),
                  MockObserver::getLossPacketMatcher(2, true, false)))))
      .Times(1);

  for (auto& callback : conn.pendingCallbacks) {
    callback(nullptr);
  }
}

TEST_P(AckHandlersTest, TestSpuriousObserverTimeout) {
  QuicServerConnectionState conn(
      FizzServerQuicHandshakeContext::Builder().build());
  auto mockCongestionController = std::make_unique<MockCongestionController>();
  conn.congestionController = std::move(mockCongestionController);

  // Register 1 observer
  Observer::Config config = {};
  config.spuriousLossEvents = true;
  config.lossEvents = true;
  auto ib = MockObserver(config);

  auto observers = std::make_shared<ObserverVec>();
  observers->emplace_back(&ib);
  conn.observers = observers;
  auto noopLossVisitor = [](auto&, auto&, bool) {};

  TimePoint startTime = Clock::now();
  emplacePackets(conn, 10, startTime, GetParam());

  // from [0, 9], [0, 4] already acked
  auto beginPacket = getFirstOutstandingPacket(conn, GetParam());
  conn.outstandings.packets.erase(beginPacket, beginPacket + 5);
  conn.outstandings.packetCount[GetParam()] -= 5;

  // setting a very high reordering threshold to force loss by timeout only
  conn.lossState.reorderingThreshold = 100;
  // setting time out parameters lower than the time at which detectLossPackets
  // is called to make sure all packets timeout
  conn.lossState.srtt = 400ms;
  conn.lossState.lrtt = 350ms;
  conn.transportSettings.timeReorderingThreshDividend = 1.0;
  conn.transportSettings.timeReorderingThreshDivisor = 1.0;
  TimePoint checkTime = startTime + 500ms;

  detectLossPackets(conn, 10, noopLossVisitor, checkTime, GetParam());

  // expecting 1 callback to be stacked
  EXPECT_EQ(1, size(conn.pendingCallbacks));

  EXPECT_CALL(
      ib,
      packetLossDetected(
          nullptr,
          Field(
              &Observer::LossEvent::lostPackets,
              UnorderedElementsAre(
                  MockObserver::getLossPacketMatcher(5, false, true),
                  MockObserver::getLossPacketMatcher(6, false, true),
                  MockObserver::getLossPacketMatcher(7, false, true),
                  MockObserver::getLossPacketMatcher(8, false, true),
                  MockObserver::getLossPacketMatcher(9, false, true)))))
      .Times(1);

  // Here we receive the spurious loss packets in a late ack
  {
    ReadAckFrame ackFrame;
    ackFrame.largestAcked = 9;
    ackFrame.ackBlocks.emplace_back(5, 9);

    processAckFrame(
        conn,
        GetParam(),
        ackFrame,
        [](const auto&, const auto&, const auto&) {},
        [](auto&, auto&, bool) {},
        startTime + 510ms);
  }

  // Spurious loss observer call added
  EXPECT_EQ(2, size(conn.pendingCallbacks));

  EXPECT_CALL(
      ib,
      spuriousLossDetected(
          nullptr,
          Field(
              &Observer::SpuriousLossEvent::spuriousPackets,
              UnorderedElementsAre(
                  MockObserver::getLossPacketMatcher(5, false, true),
                  MockObserver::getLossPacketMatcher(6, false, true),
                  MockObserver::getLossPacketMatcher(7, false, true),
                  MockObserver::getLossPacketMatcher(8, false, true),
                  MockObserver::getLossPacketMatcher(9, false, true)))))
      .Times(1);

  for (auto& callback : conn.pendingCallbacks) {
    callback(nullptr);
  }
}

TEST_P(AckHandlersTest, TestPacketsDeletedObserver) {
  QuicServerConnectionState conn(
      FizzServerQuicHandshakeContext::Builder().build());
  auto mockCongestionController = std::make_unique<MockCongestionController>();
  conn.congestionController = std::move(mockCongestionController);

  // Register 1 observer
  Observer::Config config = {};
  config.packetsRemovedEvents = true;
  auto ib = MockObserver(config);

  auto observers = std::make_shared<ObserverVec>();
  observers->emplace_back(&ib);
  conn.observers = observers;

  TimePoint startTime = Clock::now();
  emplacePackets(conn, 6, startTime, GetParam());
  EXPECT_EQ(6, size(conn.outstandings.packets));

  {
    ReadAckFrame ackFrame;
    ackFrame.largestAcked = 2;
    ackFrame.ackBlocks.emplace_back(0, 2);

    processAckFrame(
        conn,
        GetParam(),
        ackFrame,
        [](const auto&, const auto&, const auto&) {},
        [](auto&, auto&, bool) {},
        startTime);
  }

  EXPECT_EQ(1, size(conn.pendingCallbacks));

  EXPECT_CALL(
      ib,
      packetsRemoved(
          nullptr,
          Pointee(ElementsAre(
              MockObserver::getPacketNum(0),
              MockObserver::getPacketNum(1),
              MockObserver::getPacketNum(2)))));

  {
    ReadAckFrame ackFrame;
    ackFrame.largestAcked = 5;
    ackFrame.ackBlocks.emplace_back(3, 5);

    processAckFrame(
        conn,
        GetParam(),
        ackFrame,
        [](const auto&, const auto&, const auto&) {},
        [](auto&, auto&, bool) {},
        startTime);
  }

  EXPECT_EQ(2, size(conn.pendingCallbacks));

  EXPECT_CALL(
      ib,
      packetsRemoved(
          nullptr,
          Pointee(ElementsAre(
              MockObserver::getPacketNum(3),
              MockObserver::getPacketNum(4),
              MockObserver::getPacketNum(5)))));

  for (auto& callback : conn.pendingCallbacks) {
    callback(nullptr);
  }
  conn.pendingCallbacks.clear();

  EXPECT_EQ(0, size(conn.outstandings.packets));
}

TEST_P(AckHandlersTest, TestRemoveOutstandingPacketsNoObserver) {
  QuicServerConnectionState conn(
      FizzServerQuicHandshakeContext::Builder().build());
  auto mockCongestionController = std::make_unique<MockCongestionController>();
  conn.congestionController = std::move(mockCongestionController);
  TimePoint startTime = Clock::now();
  emplacePackets(conn, 6, startTime, GetParam());
  EXPECT_EQ(6, size(conn.outstandings.packets));
  // 0 1 2 3 4 5
  // 0 1 x x 2 3
  auto startIt = conn.outstandings.packets.begin() + 2;
  auto endIt = conn.outstandings.packets.begin() + 4;
  // removeOutstandingPackets should return the iterator to endIt / iterator
  // following the last removed element
  auto itReturn = removeOutstandingPackets(conn, startIt, endIt);
  auto expectedIt = conn.outstandings.packets.begin() + 2;
  EXPECT_EQ(
      expectedIt->packet.header.getPacketSequenceNum(),
      itReturn->packet.header.getPacketSequenceNum());
  EXPECT_EQ(
      endIt->packet.header.getPacketSequenceNum(),
      itReturn->packet.header.getPacketSequenceNum());
  EXPECT_EQ(4, size(conn.outstandings.packets));
  EXPECT_EQ(0, size(conn.pendingCallbacks));
}

TEST_P(AckHandlersTest, TestRemoveOutstandingPacketsWithObserver) {
  QuicServerConnectionState conn(
      FizzServerQuicHandshakeContext::Builder().build());
  auto mockCongestionController = std::make_unique<MockCongestionController>();
  conn.congestionController = std::move(mockCongestionController);

  Observer::Config config = {};
  config.packetsRemovedEvents = true;
  auto ib = MockObserver(config);

  auto observers = std::make_shared<ObserverVec>();
  observers->emplace_back(&ib);
  conn.observers = observers;

  TimePoint startTime = Clock::now();
  emplacePackets(conn, 6, startTime, GetParam());
  EXPECT_EQ(6, size(conn.outstandings.packets));
  // 0 1 2 3 4 5
  // 0 1 x x 2 3
  auto startIt = conn.outstandings.packets.begin() + 2;
  auto endIt = conn.outstandings.packets.begin() + 4;
  // removeOutstandingPackets should return the iterator to endIt / iterator
  // following the last removed element
  auto itReturn = removeOutstandingPackets(conn, startIt, endIt);
  auto expectedIt = conn.outstandings.packets.begin() + 2;
  EXPECT_EQ(
      expectedIt->packet.header.getPacketSequenceNum(),
      itReturn->packet.header.getPacketSequenceNum());
  EXPECT_EQ(
      endIt->packet.header.getPacketSequenceNum(),
      itReturn->packet.header.getPacketSequenceNum());
  EXPECT_EQ(4, size(conn.outstandings.packets));
  EXPECT_EQ(1, size(conn.pendingCallbacks));
  conn.pendingCallbacks.clear();
}

INSTANTIATE_TEST_CASE_P(
    AckHandlersTests,
    AckHandlersTest,
    Values(
        PacketNumberSpace::Initial,
        PacketNumberSpace::Handshake,
        PacketNumberSpace::AppData));
} // namespace test
} // namespace quic
