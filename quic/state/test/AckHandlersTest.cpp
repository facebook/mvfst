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

#include <quic/server/state/ServerStateMachine.h>
#include <quic/state/AckHandlers.h>
#include <quic/state/StateData.h>
#include <quic/state/test/Mocks.h>

#include <numeric>

using namespace folly;
using namespace testing;
using namespace std::chrono_literals;

namespace quic {
namespace test {

class AckHandlersTest : public TestWithParam<PacketNumberSpace> {};

auto testLossHandler(std::vector<PacketNum>& lostPackets) -> decltype(auto) {
  return [&lostPackets](
             QuicConnectionStateBase&, auto& packet, bool, PacketNum) {
    auto packetNum = folly::variant_match(
        packet.header, [](const auto& h) { return h.getPacketSequenceNum(); });
    lostPackets.push_back(packetNum);
  };
}

TEST_P(AckHandlersTest, TestAckMultipleSequentialBlocks) {
  QuicServerConnectionState conn;
  conn.lossState.reorderingThreshold = 85;
  auto mockCongestionController = std::make_unique<MockCongestionController>();
  auto rawCongestionController = mockCongestionController.get();
  conn.congestionController = std::move(mockCongestionController);
  // Get the time based loss detection out of the way
  conn.lossState.srtt = 10s;

  StreamId current = 10;
  auto sentTime = Clock::now();
  for (PacketNum packetNum = 10; packetNum <= 101; packetNum++) {
    RegularQuicWritePacket regularPacket =
        createNewPacket(packetNum, GetParam());
    WriteStreamFrame frame(current++, 0, 0, true);
    regularPacket.frames.emplace_back(std::move(frame));
    conn.outstandingPackets.emplace_back(OutstandingPacket(
        std::move(regularPacket), sentTime, 1, false, false, packetNum));
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
        auto& stream = boost::get<WriteStreamFrame>(packetFrame);
        streams.emplace_back(stream);
      },
      testLossHandler(lostPackets),
      Clock::now());
  EXPECT_EQ(lostPacketsCounter, lostPackets.empty() ? 0 : 1);

  StreamId start = 21;
  for (auto& stream : streams) {
    EXPECT_EQ(stream.streamId, start);
    start++;
  }
  // only unacked packets should be remaining
  EXPECT_EQ(conn.outstandingPackets.size(), 5);
  PacketNum lostPackt = 10;
  for (auto& pkt : lostPackets) {
    EXPECT_EQ(pkt, lostPackt++);
  }
  PacketNum packetNum = 16;
  for (auto& packet : conn.outstandingPackets) {
    auto currentPacketNum = folly::variant_match(
        packet.packet.header,
        [](const auto& h) { return h.getPacketSequenceNum(); });
    EXPECT_EQ(currentPacketNum, packetNum);
    packetNum++;
  }
}

TEST_P(AckHandlersTest, TestAckBlocksWithGaps) {
  QuicServerConnectionState conn;
  conn.lossState.reorderingThreshold = 30;
  auto mockCongestionController = std::make_unique<MockCongestionController>();
  auto rawCongestionController = mockCongestionController.get();
  conn.congestionController = std::move(mockCongestionController);
  // Get the time based loss detection out of the way
  conn.lossState.srtt = 10s;

  StreamId current = 10;
  for (PacketNum packetNum = 10; packetNum < 51; packetNum++) {
    auto regularPacket = createNewPacket(packetNum, GetParam());
    WriteStreamFrame frame(current++, 0, 0, true);
    regularPacket.frames.emplace_back(std::move(frame));
    conn.outstandingPackets.emplace_back(OutstandingPacket(
        std::move(regularPacket), Clock::now(), 1, false, false, packetNum));
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
        auto& stream = boost::get<WriteStreamFrame>(packetFrame);
        streams.emplace_back(stream);
      },
      testLossHandler(lostPackets),
      Clock::now());
  EXPECT_EQ(lostPacketsCounter, lostPackets.empty() ? 0 : 1);

  StreamId start = 12;
  std::vector<StreamId> ids(10);
  std::iota(ids.begin(), ids.end(), start);
  EXPECT_TRUE(std::equal(
      streams.begin(),
      streams.begin() + 10,
      ids.begin(),
      ids.end(),
      [](const auto& frame, auto id) { return frame.streamId == id; }));

  std::vector<StreamId> ids2(12);
  std::iota(ids2.begin(), ids2.end(), 33);
  EXPECT_TRUE(std::equal(
      streams.begin() + 10,
      streams.begin() + 10 + 12,
      ids2.begin(),
      ids2.end(),
      [](const auto& frame, auto id) { return frame.streamId == id; }));

  StreamId stream45 = 45;
  EXPECT_EQ((streams.begin() + 10 + 12)->streamId, stream45);

  std::vector<PacketNum> remainingPackets(11 + 5);
  std::iota(remainingPackets.begin(), remainingPackets.begin() + 11, 22);
  std::iota(remainingPackets.begin() + 11, remainingPackets.end(), 46);

  std::vector<PacketNum> actualPacketNumbers;
  std::transform(
      conn.outstandingPackets.begin(),
      conn.outstandingPackets.end(),
      std::back_insert_iterator<decltype(actualPacketNumbers)>(
          actualPacketNumbers),
      [](const auto& packet) {
        return folly::variant_match(packet.packet.header, [](const auto& h) {
          return h.getPacketSequenceNum();
        });
      });

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
  QuicServerConnectionState conn;
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
    conn.outstandingPackets.emplace_back(OutstandingPacket(
        std::move(regularPacket), Clock::now(), 1, false, false, packetNum));
  }

  for (PacketNum packetNum = 20; packetNum < 40; packetNum += 3) {
    auto regularPacket = createNewPacket(packetNum, GetParam());
    WriteStreamFrame frame(current, 0, 0, true);
    current += 3;
    regularPacket.frames.emplace_back(std::move(frame));
    conn.outstandingPackets.emplace_back(OutstandingPacket(
        std::move(regularPacket), Clock::now(), 1, false, false, packetNum));
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
        auto& stream = boost::get<WriteStreamFrame>(packetFrame);
        streams.emplace_back(stream);
      },
      testLossHandler(lostPackets),
      Clock::now());

  StreamId start = 10;
  std::vector<StreamId> ids(11);
  std::iota(ids.begin(), ids.end(), start);
  EXPECT_TRUE(std::equal(
      streams.begin(),
      streams.begin() + 11,
      ids.begin(),
      ids.end(),
      [](const auto& frame, auto id) { return frame.streamId == id; }));

  EXPECT_EQ(streams.begin() + 11 + 1, streams.end());
  EXPECT_EQ((streams.begin() + 11)->streamId, 26);

  std::vector<PacketNum> remainingPackets(5);
  remainingPackets[0] = 23;
  int remainingIdx = 1;
  for (PacketNum num = 29; num < 40; num += 3) {
    remainingPackets[remainingIdx++] = num;
  }

  std::vector<PacketNum> actualPacketNumbers;
  std::transform(
      conn.outstandingPackets.begin(),
      conn.outstandingPackets.end(),
      std::back_insert_iterator<decltype(actualPacketNumbers)>(
          actualPacketNumbers),
      [](const auto& packet) {
        return folly::variant_match(packet.packet.header, [](const auto& h) {
          return h.getPacketSequenceNum();
        });
      });

  EXPECT_TRUE(std::equal(
      actualPacketNumbers.begin(),
      actualPacketNumbers.end(),
      remainingPackets.begin(),
      remainingPackets.end()));
}

TEST_P(AckHandlersTest, AckVisitorForAckTest) {
  QuicServerConnectionState conn;
  conn.connectionTime = Clock::now();
  auto firstPacket = createNewPacket(100 /* packetNum */, GetParam());
  WriteAckFrame firstAckFrame;
  firstAckFrame.ackBlocks.insert(900, 1000);
  firstAckFrame.ackBlocks.insert(500, 700);
  conn.ackStates.appDataAckState.acks.insert(900, 1000);
  conn.ackStates.appDataAckState.acks.insert(500, 700);
  firstPacket.frames.emplace_back(std::move(firstAckFrame));
  conn.outstandingPackets.emplace_back(OutstandingPacket(
      std::move(firstPacket), Clock::now(), 0, false, false, 0));

  auto secondPacket = createNewPacket(101 /* packetNum */, GetParam());
  WriteAckFrame secondAckFrame;
  secondAckFrame.ackBlocks.insert(1100, 2000);
  secondAckFrame.ackBlocks.insert(1002, 1090);
  conn.ackStates.appDataAckState.acks.insert(1100, 2000);
  conn.ackStates.appDataAckState.acks.insert(1002, 1090);
  secondPacket.frames.emplace_back(std::move(secondAckFrame));
  conn.outstandingPackets.emplace_back(OutstandingPacket(
      std::move(secondPacket), Clock::now(), 0, false, false, 0));

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
        auto ackedPacketNum = folly::variant_match(
            outstandingPacket.packet.header,
            [](const auto& h) { return h.getPacketSequenceNum(); });
        EXPECT_EQ(ackedPacketNum, firstReceivedAck.largestAcked);
        folly::variant_match(
            packetFrame,
            [&](const WriteAckFrame& frame) {
              commonAckVisitorForAckFrame(
                  conn.ackStates.appDataAckState, frame);
            },
            [&](const auto& /* frame */) {
              // Ignore other frames.
            });
      },
      [](auto& /* conn */,
         auto& /* packet */,
         bool /* processed */,
         PacketNum /* currentPacketNum */) {},
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
        folly::variant_match(
            packetFrame,
            [&](const WriteAckFrame& frame) {
              commonAckVisitorForAckFrame(
                  conn.ackStates.appDataAckState, frame);
            },
            [&](const auto& /* frame */) {
              // Ignore other frames.
            });
      },
      [](auto& /* conn */,
         auto& /* packet */,
         bool /* processed */,
         PacketNum /* currentPacketNum */) {},
      Clock::now());
  EXPECT_TRUE(conn.ackStates.appDataAckState.acks.empty());
}

TEST_P(AckHandlersTest, NoNewAckedPacket) {
  QuicServerConnectionState conn;
  auto mockController = std::make_unique<MockCongestionController>();
  auto rawController = mockController.get();
  conn.congestionController = std::move(mockController);

  conn.lossState.ptoCount = 1;
  PacketNum packetAfterRtoNum = 10;
  auto packetAfterRto = createNewPacket(packetAfterRtoNum, GetParam());
  conn.outstandingPackets.emplace_back(OutstandingPacket(
      std::move(packetAfterRto), Clock::now(), 0, false, false, 0));

  ReadAckFrame ackFrame;
  ackFrame.largestAcked = 5;
  EXPECT_CALL(*rawController, onPacketAckOrLoss(_, _)).Times(0);
  processAckFrame(
      conn,
      GetParam(),
      ackFrame,
      [](const auto&, const auto&, const auto&) {},
      [](auto&, auto&, bool, PacketNum) {},
      Clock::now());
  EXPECT_TRUE(conn.pendingEvents.setLossDetectionAlarm);
  EXPECT_EQ(conn.lossState.ptoCount, 1);
  EXPECT_EQ(conn.ackStates.appDataAckState.largestAckedByPeer, 0);
}

TEST_P(AckHandlersTest, LossByAckedRecovered) {
  QuicServerConnectionState conn;
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
      [](auto&, auto&, bool, PacketNum) {},
      Clock::now());
}

TEST_P(AckHandlersTest, AckPacketNumDoesNotExist) {
  QuicServerConnectionState conn;
  auto mockController = std::make_unique<MockCongestionController>();
  conn.congestionController = std::move(mockController);
  // Get the time based loss detection out of the way
  conn.lossState.srtt = 10s;

  PacketNum packetNum1 = 9;
  auto regularPacket1 = createNewPacket(packetNum1, GetParam());
  conn.outstandingPackets.emplace_back(
      std::move(regularPacket1), Clock::now(), 0, false, false, 0);

  PacketNum packetNum2 = 10;
  auto regularPacket2 = createNewPacket(packetNum2, GetParam());
  conn.outstandingPackets.emplace_back(
      std::move(regularPacket2), Clock::now(), 0, false, false, 0);

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
      [](auto&, auto&, bool, PacketNum) {},
      Clock::now());
  EXPECT_EQ(1, conn.outstandingPackets.size());
}

TEST_P(AckHandlersTest, TestHandshakeCounterUpdate) {
  QuicServerConnectionState conn;
  StreamId stream = 1;
  for (PacketNum packetNum = 0; packetNum < 10; packetNum++) {
    auto regularPacket = createNewPacket(packetNum, GetParam());
    WriteStreamFrame frame(
        stream, 100 * packetNum + 0, 100 * packetNum + 100, false);
    regularPacket.frames.emplace_back(std::move(frame));
    conn.outstandingPackets.emplace_back(
        std::move(regularPacket),
        Clock::now(),
        0,
        packetNum % 2,
        false,
        packetNum / 2);
    conn.outstandingHandshakePacketsCount += packetNum % 2;
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
  // When [3, 7] are acked, [0, 2] will also be marked loss, due to reordering
  // threshold
  EXPECT_EQ(1, conn.outstandingHandshakePacketsCount);
  EXPECT_EQ(2, conn.outstandingPackets.size());
}

TEST_P(AckHandlersTest, PurgeAcks) {
  QuicServerConnectionState conn;
  WriteAckFrame ackFrame;
  ackFrame.ackBlocks.insert(900, 1000);
  ackFrame.ackBlocks.insert(500, 700);
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

TEST_P(AckHandlersTest, PureAckBytesCountedTowardsTotalBytesAcked) {
  QuicServerConnectionState conn;
  ASSERT_EQ(0, conn.lossState.totalBytesAcked);
  auto regularPacket = createNewPacket(10, GetParam());
  WriteAckFrame ack;
  ack.ackBlocks.insert(2, 5);
  conn.outstandingPackets.emplace_back(OutstandingPacket(
      std::move(regularPacket), Clock::now(), 2, false, true, 2));
  conn.outstandingPureAckPacketsCount++;

  ReadAckFrame ackFrame;
  ackFrame.largestAcked = 12;
  ackFrame.ackBlocks.emplace_back(5, 12);

  std::vector<PacketNum> lostPackets;
  processAckFrame(
      conn,
      GetParam(),
      ackFrame,
      [&](const auto&, const auto&, const auto&) {},
      testLossHandler(lostPackets),
      Clock::now());
  // Packet should be removed from outstandingPackets without triggering
  // onPacketAckOrLoss
  EXPECT_TRUE(conn.outstandingPackets.empty());
  EXPECT_GT(conn.lossState.totalBytesAcked, 0);
}

TEST_P(AckHandlersTest, PureAckBytesSkipsCongestionControl) {
  QuicServerConnectionState conn;
  auto mockController = std::make_unique<MockCongestionController>();
  auto rawController = mockController.get();
  conn.congestionController = std::move(mockController);

  auto regularPacket = createNewPacket(10, GetParam());
  WriteAckFrame ack;
  ack.ackBlocks.insert(2, 5);
  conn.outstandingPackets.emplace_back(OutstandingPacket(
      std::move(regularPacket), Clock::now(), 2, false, true, 2));
  conn.outstandingPureAckPacketsCount++;

  ReadAckFrame ackFrame;
  ackFrame.largestAcked = 12;
  ackFrame.ackBlocks.emplace_back(5, 12);

  std::vector<PacketNum> lostPackets;
  // onPacketAckOrLoss will be called, but the ackedBytes is 0. We only need the
  // largestAckedPacket
  EXPECT_CALL(*rawController, onPacketAckOrLoss(_, _))
      .Times(1)
      .WillOnce(Invoke([&](auto ackEvent, auto) {
        EXPECT_EQ(0, ackEvent->ackedBytes);
        EXPECT_EQ(10, ackEvent->largestAckedPacket.value());
        EXPECT_FALSE(ackEvent->ackedPackets.empty());
        EXPECT_EQ(1, ackEvent->ackedPackets.size());
        EXPECT_EQ(2, ackEvent->ackedPackets.front().encodedSize);
        EXPECT_FALSE(ackEvent->ackedPackets.front().isHandshake);
        EXPECT_TRUE(ackEvent->ackedPackets.front().pureAck);
        EXPECT_EQ(2, ackEvent->ackedPackets.front().totalBytesSent);
      }));
  processAckFrame(
      conn,
      GetParam(),
      ackFrame,
      [&](const auto&, const auto&, const auto&) {},
      testLossHandler(lostPackets),
      Clock::now());
  // Packet should be removed from outstandingPackets without triggering
  // onPacketAckOrLoss
  EXPECT_TRUE(conn.outstandingPackets.empty());
}

TEST_P(AckHandlersTest, NoSkipAckVisitor) {
  QuicServerConnectionState conn;
  auto mockCongestionController = std::make_unique<MockCongestionController>();
  auto rawCongestionController = mockCongestionController.get();
  conn.congestionController = std::move(mockCongestionController);
  EXPECT_CALL(*rawCongestionController, onPacketAckOrLoss(_, _))
      .Times(1)
      .WillOnce(Invoke([&](auto ackEvent, auto) {
        EXPECT_EQ(1, ackEvent->ackedPackets.size());
        EXPECT_EQ(1, ackEvent->ackedPackets.front().encodedSize);
        EXPECT_FALSE(ackEvent->ackedPackets.front().pureAck);
        EXPECT_FALSE(ackEvent->ackedPackets.front().isHandshake);
        EXPECT_EQ(1, ackEvent->ackedPackets.front().totalBytesSent);
      }));

  PacketNum packetNum = 0;
  auto regularPacket = createNewPacket(packetNum, GetParam());
  // We need to at least have one frame to trigger ackVisitor
  WriteStreamFrame frame(0, 0, 0, true);
  regularPacket.frames.emplace_back(std::move(frame));
  conn.outstandingPackets.emplace_back(OutstandingPacket(
      std::move(regularPacket), Clock::now(), 1, false, false, 1));
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
      [&](auto& /*conn*/,
          auto& /* packet */,
          bool /* processed */,
          PacketNum) { /* no-op lossVisitor */ },
      Clock::now());
  EXPECT_EQ(1, ackVisitorCounter);
}

TEST_P(AckHandlersTest, SkipAckVisitor) {
  QuicServerConnectionState conn;
  auto mockCongestionController = std::make_unique<MockCongestionController>();
  auto rawCongestionController = mockCongestionController.get();
  conn.congestionController = std::move(mockCongestionController);
  EXPECT_CALL(*rawCongestionController, onPacketAckOrLoss(_, _))
      .Times(1)
      .WillOnce(Invoke([&](auto ackEvent, auto) {
        EXPECT_EQ(1, ackEvent->ackedPackets.size());
        EXPECT_EQ(1, ackEvent->ackedPackets.front().encodedSize);
        EXPECT_FALSE(ackEvent->ackedPackets.front().pureAck);
        EXPECT_FALSE(ackEvent->ackedPackets.front().isHandshake);
        EXPECT_EQ(1, ackEvent->ackedPackets.front().totalBytesSent);
      }));

  PacketNum packetNum = 0;
  auto regularPacket = createNewPacket(packetNum, GetParam());
  // We need to at least have one frame to trigger ackVisitor
  WriteStreamFrame frame(0, 0, 0, true);
  regularPacket.frames.emplace_back(std::move(frame));
  OutstandingPacket outstandingPacket(
      std::move(regularPacket), Clock::now(), 1, false, false, 1);
  // Give this outstandingPacket an associatedEvent that's not in
  // outstandingPacketEvents
  outstandingPacket.associatedEvent = 0;
  conn.outstandingPackets.push_back(std::move(outstandingPacket));
  conn.outstandingClonedPacketsCount++;

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
      [&](auto& /*conn*/,
          auto& /* packet */,
          bool /* processed */,
          PacketNum) { /* no-op lossVisitor */ },
      Clock::now());
  EXPECT_EQ(0, ackVisitorCounter);
}

TEST_P(AckHandlersTest, NoDoubleProcess) {
  QuicServerConnectionState conn;
  conn.congestionController.reset();

  WriteStreamFrame frame(0, 0, 0, true);
  PacketNum packetNum1 = 0, packetNum2 = 1;
  auto regularPacket1 = createNewPacket(packetNum1, GetParam()),
       regularPacket2 = createNewPacket(packetNum2, GetParam());
  regularPacket1.frames.push_back(frame);
  regularPacket2.frames.push_back(frame);

  OutstandingPacket outstandingPacket1(
      std::move(regularPacket1), Clock::now(), 1, false, false, 1);
  outstandingPacket1.associatedEvent = packetNum1;

  OutstandingPacket outstandingPacket2(
      std::move(regularPacket2), Clock::now(), 1, false, false, 1);
  // The seconds packet has the same PacketEvent
  outstandingPacket2.associatedEvent = packetNum1;

  conn.outstandingPackets.push_back(std::move(outstandingPacket1));
  conn.outstandingPackets.push_back(std::move(outstandingPacket2));
  conn.outstandingClonedPacketsCount += 2;
  conn.outstandingPacketEvents.insert(packetNum1);

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
      [&](auto& /*conn*/,
          auto& /* packet */,
          bool /* processed */,
          PacketNum) { /* no-op lossVisitor */ },
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
      [&](auto& /* conn */,
          auto& /* packet */,
          bool /* processed */,
          PacketNum) { /* no-op */ },
      Clock::now());
  EXPECT_EQ(1, ackVisitorCounter);
}

TEST_P(AckHandlersTest, ClonedPacketsCounter) {
  QuicServerConnectionState conn;
  conn.congestionController = nullptr;
  WriteStreamFrame frame(0, 0, 0, true);
  auto packetNum1 = conn.ackStates.appDataAckState.nextPacketNum;
  auto regularPacket1 = createNewPacket(packetNum1, GetParam());
  regularPacket1.frames.push_back(frame);
  OutstandingPacket outstandingPacket1(
      std::move(regularPacket1), Clock::now(), 1, false, false, 1);
  outstandingPacket1.associatedEvent = packetNum1;

  conn.ackStates.appDataAckState.nextPacketNum++;
  auto packetNum2 = conn.ackStates.appDataAckState.nextPacketNum;
  auto regularPacket2 = createNewPacket(packetNum2, GetParam());
  regularPacket2.frames.push_back(frame);
  OutstandingPacket outstandingPacket2(
      std::move(regularPacket2), Clock::now(), 1, false, false, 1);

  conn.outstandingPackets.push_back(std::move(outstandingPacket1));
  conn.outstandingPackets.push_back(std::move(outstandingPacket2));
  conn.outstandingClonedPacketsCount = 1;
  conn.outstandingPacketEvents.insert(packetNum1);

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
      [&](auto& /* conn */,
          auto& /* packet */,
          bool /* processed */,
          PacketNum) { /* no-op */ },
      Clock::now());
  EXPECT_EQ(2, ackVisitorCounter);
  EXPECT_EQ(0, conn.outstandingClonedPacketsCount);
}

TEST_P(AckHandlersTest, UpdateMaxAckDelay) {
  QuicServerConnectionState conn;
  conn.congestionController = nullptr;
  conn.lossState.mrtt = 200us;
  PacketNum packetNum = 0;
  auto regularPacket = createNewPacket(packetNum, GetParam());
  auto sentTime = Clock::now();
  conn.outstandingPackets.emplace_back(OutstandingPacket(
      std::move(regularPacket), sentTime, 1, false, false, 1));

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
      [&](auto&, auto&, bool, PacketNum) { /* lossVisitor */ },
      receiveTime);
  EXPECT_EQ(10us, conn.lossState.mrtt);
}

// Ack only acks packets aren't outstanding, but TimeReordering still finds loss
TEST_P(AckHandlersTest, AckNotOutstandingButLoss) {
  QuicServerConnectionState conn;
  conn.lossState.srtt = 200ms;
  conn.lossState.lrtt = 150ms;
  // Packet 2 has been sent and acked:
  conn.ackStates.appDataAckState.largestAckedByPeer = 2;
  auto mockCongestionController = std::make_unique<MockCongestionController>();
  auto rawCongestionController = mockCongestionController.get();
  conn.congestionController = std::move(mockCongestionController);
  EXPECT_CALL(*rawCongestionController, onPacketAckOrLoss(_, _))
      .Times(1)
      .WillOnce(Invoke(
          [&](folly::Optional<CongestionController::AckEvent> ackEvent,
              folly::Optional<CongestionController::LossEvent> lossEvent) {
            EXPECT_FALSE(ackEvent->largestAckedPacket.hasValue());
            EXPECT_TRUE(lossEvent->largestLostPacketNum.hasValue());
          }));

  // But packet 1 has been outstanding for longer than delayUntilLost:
  PacketNum packetNum = 1;
  auto regularPacket = createNewPacket(packetNum, PacketNumberSpace::AppData);
  // We need to at least have one frame to trigger ackVisitor
  WriteStreamFrame frame(0, 0, 0, true);
  regularPacket.frames.emplace_back(std::move(frame));
  auto delayUntilLost = 200ms * 9 / 8;
  OutstandingPacket outstandingPacket(
      std::move(regularPacket),
      Clock::now() - delayUntilLost - 20ms,
      1,
      false,
      false,
      1);
  conn.outstandingPackets.push_back(std::move(outstandingPacket));
  conn.outstandingClonedPacketsCount++;

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
      PacketNumberSpace::AppData,
      ackFrame,
      countingAckVisitor,
      [&](auto& /*conn*/,
          auto& /* packet */,
          bool /* processed */,
          PacketNum) { /* no-op lossVisitor */ },
      Clock::now());
  EXPECT_EQ(0, ackVisitorCounter);
}

TEST_P(AckHandlersTest, UpdatePendingAckStates) {
  QuicServerConnectionState conn;
  conn.congestionController = nullptr;
  conn.lossState.totalBytesSent = 2468;
  conn.lossState.totalBytesAcked = 1357;
  PacketNum packetNum = 0;
  auto regularPacket = createNewPacket(packetNum, GetParam());
  auto sentTime = Clock::now() - 1500ms;
  conn.outstandingPackets.emplace_back(OutstandingPacket(
      std::move(regularPacket),
      sentTime,
      111,
      false,
      false,
      conn.lossState.totalBytesSent + 111));
  conn.lossState.totalBytesSent += 111;

  ReadAckFrame ackFrame;
  ackFrame.largestAcked = 0;
  ackFrame.ackBlocks.emplace_back(0, 0);

  auto receiveTime = Clock::now() - 200ms;
  processAckFrame(
      conn,
      GetParam(),
      ackFrame,
      [&](auto, auto, auto) { /* ackVisitor */ },
      [&](auto&, auto&, auto, auto) { /* lossVisitor */ },
      receiveTime);
  EXPECT_EQ(2468 + 111, conn.lossState.totalBytesSentAtLastAck);
  EXPECT_EQ(1357 + 111, conn.lossState.totalBytesAckedAtLastAck);
  EXPECT_EQ(sentTime, *conn.lossState.lastAckedPacketSentTime);
  EXPECT_EQ(receiveTime, *conn.lossState.lastAckedTime);
  EXPECT_EQ(111 + 1357, conn.lossState.totalBytesAcked);
}

TEST_F(AckHandlersTest, PureAckDoesNotUpdateRtt) {
  QuicServerConnectionState conn;
  conn.congestionController = nullptr;
  PacketNum packetNum = 0;
  auto regularPacket = createNewPacket(packetNum, PacketNumberSpace::AppData);
  conn.outstandingPackets.emplace_back(OutstandingPacket(
      std::move(regularPacket),
      Clock::now() - 200ms,
      111,
      false /* handshake */,
      true /* pureAck */,
      111));
  conn.outstandingPureAckPacketsCount++;
  ASSERT_FALSE(conn.outstandingPackets.empty());
  ReadAckFrame ackFrame;
  ackFrame.largestAcked = packetNum;
  ackFrame.ackDelay = 100us;
  ackFrame.ackBlocks.emplace_back(packetNum, packetNum);
  processAckFrame(
      conn,
      PacketNumberSpace::AppData,
      ackFrame,
      [&](const auto&, const auto&, const auto&) {},
      [&](auto&, auto&, bool, auto) {},
      Clock::now() - 150ms);
  EXPECT_EQ(std::chrono::microseconds::max(), conn.lossState.mrtt);
  EXPECT_EQ(0us, conn.lossState.srtt);
  EXPECT_EQ(0us, conn.lossState.lrtt);
  EXPECT_EQ(0us, conn.lossState.rttvar);
  EXPECT_TRUE(conn.outstandingPackets.empty());

  packetNum++;
  regularPacket = createNewPacket(packetNum, PacketNumberSpace::AppData);
  conn.outstandingPackets.emplace_back(OutstandingPacket(
      std::move(regularPacket),
      Clock::now() - 100ms,
      111,
      false /* handshake */,
      false /* pureAck */,
      111));
  ASSERT_FALSE(conn.outstandingPackets.empty());
  ackFrame.largestAcked = packetNum;
  ackFrame.ackDelay = 100us;
  ackFrame.ackBlocks.clear();
  ackFrame.ackBlocks.emplace_back(packetNum, packetNum);
  processAckFrame(
      conn,
      PacketNumberSpace::AppData,
      ackFrame,
      [&](const auto&, const auto&, const auto&) {},
      [&](auto&, auto&, bool, auto) {},
      Clock::now());
  EXPECT_NE(std::chrono::microseconds::max(), conn.lossState.mrtt);
  EXPECT_NE(0us, conn.lossState.srtt);
  EXPECT_NE(0us, conn.lossState.lrtt);
  EXPECT_NE(0us, conn.lossState.rttvar);
  EXPECT_TRUE(conn.outstandingPackets.empty());
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
