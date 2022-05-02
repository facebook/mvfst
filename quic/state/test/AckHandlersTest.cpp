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
#include <quic/fizz/server/handshake/FizzServerQuicHandshakeContext.h>
#include <quic/logging/test/Mocks.h>
#include <quic/server/state/ServerStateMachine.h>
#include <quic/state/AckHandlers.h>
#include <quic/state/OutstandingPacket.h>
#include <quic/state/StateData.h>
#include <quic/state/stream/StreamSendHandlers.h>
#include <quic/state/test/AckEventTestUtil.h>
#include <quic/state/test/Mocks.h>

#include <numeric>

using namespace testing;

namespace quic {
namespace test {

class AckHandlersTest : public TestWithParam<PacketNumberSpace> {};

template <typename T>
uint64_t ul(T val) {
  return static_cast<uint64_t>(val);
}

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
        0,
        OutstandingPacketMetadata::DetailsPerStream());
    conn.outstandings.packets.emplace_back(sentPacket);
    packetNum++;
  }
}

auto getAckPacketMatcher(
    PacketNum packetNum,
    uint64_t writeCount,
    TimePoint sentTime) {
  return testing::AllOf(
      testing::Field(&AckEvent::AckPacket::packetNum, packetNum),
      testing::Field(
          &AckEvent::AckPacket::outstandingPacketMetadata,
          testing::AllOf(
              testing::Field(&OutstandingPacketMetadata::time, sentTime),
              testing::Field(
                  &OutstandingPacketMetadata::totalBytesSent,
                  1 * (packetNum + 1)),
              testing::Field(
                  &OutstandingPacketMetadata::writeCount, writeCount))));
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

  const StreamId startStreamId = 10;
  StreamId currentStreamId = startStreamId;
  auto sentTime = Clock::now();
  for (PacketNum packetNum = 10; packetNum <= 101; packetNum++) {
    RegularQuicWritePacket regularPacket =
        createNewPacket(packetNum, GetParam());
    WriteStreamFrame frame(currentStreamId++, 0, 0, true);
    regularPacket.frames.emplace_back(std::move(frame));
    conn.outstandings
        .packetCount[regularPacket.header.getPacketNumberSpace()]++;
    conn.outstandings.packets.emplace_back(
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
        OutstandingPacketMetadata::DetailsPerStream());
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
          EXPECT_EQ(ul(101), ack->largestAckedPacket);
          EXPECT_EQ(ul(101), ack->largestNewlyAckedPacket);
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

  StreamId nextExpectedStream = 21; // packets (streams) 21 - 101 are ACKed
  for (auto& stream : streams) {
    EXPECT_EQ(stream.streamId, nextExpectedStream);
    nextExpectedStream++;
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

TEST_P(AckHandlersTest, TestSpuriousLossFullRemoval) {
  QuicServerConnectionState conn(
      FizzServerQuicHandshakeContext::Builder().build());
  auto mockCongestionController = std::make_unique<MockCongestionController>();
  conn.congestionController = std::move(mockCongestionController);
  conn.streamManager->setMaxLocalBidirectionalStreams(100);
  conn.transportSettings.removeFromLossBufferOnSpurious = true;

  auto noopLossVisitor = [](auto&, auto&, bool) {};

  StreamId streamId = 1;
  auto streamState = conn.streamManager->createStream(streamId).value();
  BufQueue data{};
  auto iob = folly::IOBuf::createChain(200, 200);
  iob->append(200);
  data.append(std::move(iob));
  ASSERT_EQ(data.chainLength(), 200);
  auto streamBuffer = std::make_unique<StreamBuffer>(data.move(), 0, false);
  streamState->insertIntoLossBuffer(std::move(streamBuffer));

  TimePoint startTime = Clock::now();
  auto regularPacket = createNewPacket(0, GetParam());
  WriteStreamFrame frame(streamId, 0, 200, false);
  regularPacket.frames.emplace_back(frame);
  conn.outstandings.packetCount[regularPacket.header.getPacketNumberSpace()]++;
  OutstandingPacket sentPacket(
      std::move(regularPacket),
      startTime,
      1,
      0,
      false /* handshake */,
      0,
      0,
      1,
      1,
      quic::LossState(),
      0,
      OutstandingPacketMetadata::DetailsPerStream());
  conn.outstandings.packets.emplace_back(sentPacket);

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

  // Here we receive the spurious loss packets in a late ack
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

  EXPECT_TRUE(streamState->lossBuffer.empty());
}

TEST_P(AckHandlersTest, TestSpuriousLossSplitMiddleRemoval) {
  QuicServerConnectionState conn(
      FizzServerQuicHandshakeContext::Builder().build());
  auto mockCongestionController = std::make_unique<MockCongestionController>();
  conn.congestionController = std::move(mockCongestionController);
  conn.streamManager->setMaxLocalBidirectionalStreams(100);
  conn.transportSettings.removeFromLossBufferOnSpurious = true;

  auto noopLossVisitor = [](auto&, auto&, bool) {};

  StreamId streamId = 1;
  auto streamState = conn.streamManager->createStream(streamId).value();
  BufQueue data{};
  auto iob = folly::IOBuf::createChain(200, 200);
  iob->append(200);
  data.append(std::move(iob));
  ASSERT_EQ(data.chainLength(), 200);
  auto streamBuffer = std::make_unique<StreamBuffer>(data.move(), 0, false);
  streamState->insertIntoLossBuffer(std::move(streamBuffer));

  TimePoint startTime = Clock::now();
  auto regularPacket = createNewPacket(0, GetParam());
  WriteStreamFrame frame(streamId, 50, 50, false);
  regularPacket.frames.emplace_back(frame);
  conn.outstandings.packetCount[regularPacket.header.getPacketNumberSpace()]++;
  OutstandingPacket sentPacket(
      std::move(regularPacket),
      startTime,
      1,
      0,
      false /* handshake */,
      0,
      0,
      1,
      1,
      quic::LossState(),
      0,
      OutstandingPacketMetadata::DetailsPerStream());
  conn.outstandings.packets.emplace_back(sentPacket);

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

  // Here we receive the spurious loss packets in a late ack
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

  ASSERT_EQ(streamState->lossBuffer.size(), 2);
  EXPECT_EQ(streamState->lossBuffer[0].offset, 0);
  EXPECT_EQ(streamState->lossBuffer[0].data.chainLength(), 50);
  EXPECT_EQ(streamState->lossBuffer[0].eof, false);
  EXPECT_EQ(streamState->lossBuffer[1].offset, 100);
  EXPECT_EQ(streamState->lossBuffer[1].data.chainLength(), 100);
  EXPECT_EQ(streamState->lossBuffer[1].eof, false);
}

TEST_P(AckHandlersTest, TestSpuriousLossTrimFrontRemoval) {
  QuicServerConnectionState conn(
      FizzServerQuicHandshakeContext::Builder().build());
  auto mockCongestionController = std::make_unique<MockCongestionController>();
  conn.congestionController = std::move(mockCongestionController);
  conn.streamManager->setMaxLocalBidirectionalStreams(100);
  conn.transportSettings.removeFromLossBufferOnSpurious = true;

  auto noopLossVisitor = [](auto&, auto&, bool) {};

  StreamId streamId = 1;
  auto streamState = conn.streamManager->createStream(streamId).value();
  BufQueue data{};
  auto iob = folly::IOBuf::createChain(200, 200);
  iob->append(200);
  data.append(std::move(iob));
  ASSERT_EQ(data.chainLength(), 200);
  auto streamBuffer = std::make_unique<StreamBuffer>(data.move(), 0, false);
  streamState->insertIntoLossBuffer(std::move(streamBuffer));

  TimePoint startTime = Clock::now();
  auto regularPacket = createNewPacket(0, GetParam());
  WriteStreamFrame frame(streamId, 0, 50, false);
  regularPacket.frames.emplace_back(frame);
  conn.outstandings.packetCount[regularPacket.header.getPacketNumberSpace()]++;
  OutstandingPacket sentPacket(
      std::move(regularPacket),
      startTime,
      1,
      0,
      false /* handshake */,
      0,
      0,
      1,
      1,
      quic::LossState(),
      0,
      OutstandingPacketMetadata::DetailsPerStream());
  conn.outstandings.packets.emplace_back(sentPacket);

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

  // Here we receive the spurious loss packets in a late ack
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

  ASSERT_EQ(streamState->lossBuffer.size(), 1);
  EXPECT_EQ(streamState->lossBuffer[0].offset, 50);
  EXPECT_EQ(streamState->lossBuffer[0].data.chainLength(), 150);
  EXPECT_EQ(streamState->lossBuffer[0].eof, false);
}

TEST_P(AckHandlersTest, TestSpuriousLossSplitFrontRemoval) {
  QuicServerConnectionState conn(
      FizzServerQuicHandshakeContext::Builder().build());
  auto mockCongestionController = std::make_unique<MockCongestionController>();
  conn.congestionController = std::move(mockCongestionController);
  conn.streamManager->setMaxLocalBidirectionalStreams(100);
  conn.transportSettings.removeFromLossBufferOnSpurious = true;

  auto noopLossVisitor = [](auto&, auto&, bool) {};

  StreamId streamId = 1;
  auto streamState = conn.streamManager->createStream(streamId).value();
  BufQueue data{};
  auto iob = folly::IOBuf::createChain(200, 200);
  iob->append(200);
  data.append(std::move(iob));
  ASSERT_EQ(data.chainLength(), 200);
  auto streamBuffer = std::make_unique<StreamBuffer>(data.move(), 0, false);
  streamState->insertIntoLossBuffer(std::move(streamBuffer));

  TimePoint startTime = Clock::now();
  auto regularPacket = createNewPacket(0, GetParam());
  WriteStreamFrame frame(streamId, 50, 150, false);
  regularPacket.frames.emplace_back(frame);
  conn.outstandings.packetCount[regularPacket.header.getPacketNumberSpace()]++;
  OutstandingPacket sentPacket(
      std::move(regularPacket),
      startTime,
      1,
      0,
      false /* handshake */,
      0,
      0,
      1,
      1,
      quic::LossState(),
      0,
      OutstandingPacketMetadata::DetailsPerStream());
  conn.outstandings.packets.emplace_back(sentPacket);

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

  // Here we receive the spurious loss packets in a late ack
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

  ASSERT_EQ(streamState->lossBuffer.size(), 1);
  EXPECT_EQ(streamState->lossBuffer[0].offset, 0);
  EXPECT_EQ(streamState->lossBuffer[0].data.chainLength(), 50);
  EXPECT_EQ(streamState->lossBuffer[0].eof, false);
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
    conn.outstandings.packets.emplace_back(
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
        OutstandingPacketMetadata::DetailsPerStream());
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
          EXPECT_EQ(ul(101), ack->largestAckedPacket);
          EXPECT_EQ(ul(101), ack->largestNewlyAckedPacket);
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

  StreamId nextExpectedStream = 21; // packets (streams) 21 - 101 are ACKed
  for (auto& stream : streams) {
    EXPECT_EQ(stream.streamId, nextExpectedStream);
    nextExpectedStream++;
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
    conn.outstandings.packets.emplace_back(
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
        0,
        OutstandingPacketMetadata::DetailsPerStream());
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
          EXPECT_EQ(ul(45), ack->largestAckedPacket);
          EXPECT_EQ(ul(45), ack->largestNewlyAckedPacket);
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
      streams.rbegin(),
      streams.rbegin() + (45 - 33 + 1),
      ids.begin(),
      ids.end(),
      [](const auto& frame, auto id) { return frame.streamId == id; }));

  start = 21;
  std::vector<StreamId> ids2(10);
  std::generate(ids2.begin(), ids2.end(), [&]() { return start--; });
  EXPECT_TRUE(std::equal(
      streams.rbegin() + (45 - 33 + 1),
      streams.rend(),
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
    conn.outstandings.packets.emplace_back(
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
        0,
        OutstandingPacketMetadata::DetailsPerStream());
  }

  for (PacketNum packetNum = 20; packetNum < 40; packetNum += 3) {
    auto regularPacket = createNewPacket(packetNum, GetParam());
    WriteStreamFrame frame(current, 0, 0, true);
    current += 3;
    regularPacket.frames.emplace_back(std::move(frame));
    conn.outstandings
        .packetCount[regularPacket.header.getPacketNumberSpace()]++;
    conn.outstandings.packets.emplace_back(
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
        0,
        OutstandingPacketMetadata::DetailsPerStream());
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
        EXPECT_EQ(ul(26), ackEvent->largestAckedPacket);
        EXPECT_EQ(ul(26), ackEvent->largestNewlyAckedPacket);
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

  EXPECT_EQ(26, streams.rbegin()->streamId);

  StreamId start = 20;
  std::vector<StreamId> ids(20 - 10 + 1);
  std::generate(ids.begin(), ids.end(), [&]() { return start--; });
  EXPECT_TRUE(std::equal(
      streams.rbegin() + 1,
      streams.rend(),
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
  conn.outstandings.packets.emplace_back(
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
      0,
      OutstandingPacketMetadata::DetailsPerStream());

  auto secondPacket = createNewPacket(101 /* packetNum */, GetParam());
  WriteAckFrame secondAckFrame;
  secondAckFrame.ackBlocks.emplace_back(1100, 2000);
  secondAckFrame.ackBlocks.emplace_back(1002, 1090);
  conn.ackStates.appDataAckState.acks.insert(1100, 2000);
  conn.ackStates.appDataAckState.acks.insert(1002, 1090);
  secondPacket.frames.emplace_back(std::move(secondAckFrame));
  conn.outstandings.packetCount[secondPacket.header.getPacketNumberSpace()]++;
  conn.outstandings.packets.emplace_back(
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
      0,
      OutstandingPacketMetadata::DetailsPerStream());

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
  conn.outstandings.packets.emplace_back(
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
      0,
      OutstandingPacketMetadata::DetailsPerStream());

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
      0,
      OutstandingPacketMetadata::DetailsPerStream());

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
      0,
      OutstandingPacketMetadata::DetailsPerStream());

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
        0,
        OutstandingPacketMetadata::DetailsPerStream());
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
        EXPECT_EQ(
            1,
            ackEvent->ackedPackets.front()
                .outstandingPacketMetadata.encodedSize);
        EXPECT_EQ(
            1,
            ackEvent->ackedPackets.front()
                .outstandingPacketMetadata.totalBytesSent);
      }));

  PacketNum packetNum = 0;
  auto regularPacket = createNewPacket(packetNum, GetParam());
  // We need to at least have one frame to trigger ackVisitor
  WriteStreamFrame frame(0, 0, 0, true);
  regularPacket.frames.emplace_back(std::move(frame));
  conn.outstandings.packetCount[regularPacket.header.getPacketNumberSpace()]++;
  conn.outstandings.packets.emplace_back(
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
      0,
      OutstandingPacketMetadata::DetailsPerStream());
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
        EXPECT_EQ(
            1,
            ackEvent->ackedPackets.front()
                .outstandingPacketMetadata.encodedSize);
        EXPECT_EQ(
            1,
            ackEvent->ackedPackets.front()
                .outstandingPacketMetadata.totalBytesSent);
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
      0,
      OutstandingPacketMetadata::DetailsPerStream());
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
      0,
      OutstandingPacketMetadata::DetailsPerStream());
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
      0,
      OutstandingPacketMetadata::DetailsPerStream());
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
      0,
      OutstandingPacketMetadata::DetailsPerStream());
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
      0,
      OutstandingPacketMetadata::DetailsPerStream());

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
  conn.outstandings.packets.emplace_back(
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
      0,
      OutstandingPacketMetadata::DetailsPerStream());

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
          [&](const CongestionController::AckEvent* FOLLY_NULLABLE ackEvent,
              const CongestionController::LossEvent* FOLLY_NULLABLE lossEvent) {
            EXPECT_FALSE(
                CHECK_NOTNULL(ackEvent)->largestNewlyAckedPacket.has_value());
            EXPECT_TRUE(
                CHECK_NOTNULL(lossEvent)->largestLostPacketNum.has_value());
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
      0,
      OutstandingPacketMetadata::DetailsPerStream());
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
  conn.outstandings.packets.emplace_back(
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
      0,
      OutstandingPacketMetadata::DetailsPerStream());
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

  const TimePoint startTime = Clock::now();
  PacketNum packetNum = 0;
  StreamId streamid = 0;

  auto getWriteCount = [](PacketNum packetNum) {
    return (packetNum <= 4) ? 1 : 2;
  };
  auto getSentTime = [&startTime](PacketNum packetNum) {
    return startTime +
        std::chrono::milliseconds(10ms * ((packetNum <= 4) ? 1 : 2));
  };

  // write 10 packets, with half in write #1, the other half in write #2
  // packets in each write have the same timestamp and writeCount
  while (packetNum < 10) {
    auto regularPacket = createNewPacket(packetNum, GetParam());
    WriteStreamFrame frame(streamid++, 0, 0, true);
    regularPacket.frames.emplace_back(frame);

    conn.outstandings
        .packetCount[regularPacket.header.getPacketNumberSpace()]++;
    OutstandingPacket sentPacket(
        std::move(regularPacket),
        getSentTime(packetNum),
        1 /* encodedSizeIn */,
        0 /* encodedBodySizeIn */,
        false /* isHandshakeIn */,
        1 * (packetNum + 1) /* totalBytesSentIn */,
        0 /* totalBodyBytesSentIn */,
        0 /* inflightBytesIn */,
        0 /* packetsInflightIn */,
        LossState(),
        getWriteCount(packetNum) /* writeCountIn */,
        OutstandingPacketMetadata::DetailsPerStream());
    sentPacket.isAppLimited = (packetNum % 2);
    conn.outstandings.packets.emplace_back(sentPacket);
    packetNum++;
  }

  ReadAckFrame ackFrame;
  ackFrame.largestAcked = 9;
  ackFrame.ackBlocks.emplace_back(0, 9);
  ackFrame.ackDelay = 5ms;
  const auto ackTime = getSentTime(9) + 10ms;
  const auto writableBytes = 10;
  const auto congestionWindow = 20;
  auto checkAck = [&](auto ack) {
    EXPECT_EQ(ackTime, ack.ackTime);
    EXPECT_EQ(ackTime - ackFrame.ackDelay, ack.adjustedAckTime);
    EXPECT_EQ(ackFrame.ackDelay, ack.ackDelay);

    EXPECT_EQ(ul(9), ack.largestAckedPacket);
    EXPECT_EQ(ul(9), ack.largestNewlyAckedPacket);
    EXPECT_EQ(getSentTime(9), ack.largestNewlyAckedPacketSentTime);
    EXPECT_THAT(
        ack.getRttSampleAckedPacket(),
        Pointee(getAckPacketMatcher(9, getWriteCount(9), getSentTime(9))));
    EXPECT_THAT(
        ack.getRttSampleAckedPacket(),
        Pointee(getAckPacketMatcher(9, getWriteCount(9), getSentTime(9))));
    EXPECT_THAT(
        ack.getLargestNewlyAckedPacket(),
        Pointee(getAckPacketMatcher(9, getWriteCount(9), getSentTime(9))));

    EXPECT_EQ(10, ack.ackedBytes);
    EXPECT_TRUE(ack.largestNewlyAckedPacketAppLimited);
    EXPECT_EQ(GetParam(), ack.packetNumberSpace);
    EXPECT_EQ(
        std::chrono::ceil<std::chrono::microseconds>(ackTime - getSentTime(9)),
        ack.rttSample);
    EXPECT_EQ(
        std::chrono::ceil<std::chrono::microseconds>(
            ackTime - getSentTime(9) - ackFrame.ackDelay),
        ack.rttSampleNoAckDelay);
    EXPECT_THAT(ack.ackedPackets, SizeIs(10));
    EXPECT_THAT(
        ack.ackedPackets,
        ElementsAre(
            getAckPacketMatcher(0, getWriteCount(0), getSentTime(0)),
            getAckPacketMatcher(1, getWriteCount(1), getSentTime(1)),
            getAckPacketMatcher(2, getWriteCount(2), getSentTime(2)),
            getAckPacketMatcher(3, getWriteCount(3), getSentTime(3)),
            getAckPacketMatcher(4, getWriteCount(4), getSentTime(4)),
            getAckPacketMatcher(5, getWriteCount(5), getSentTime(5)),
            getAckPacketMatcher(6, getWriteCount(6), getSentTime(6)),
            getAckPacketMatcher(7, getWriteCount(7), getSentTime(7)),
            getAckPacketMatcher(8, getWriteCount(8), getSentTime(8)),
            getAckPacketMatcher(9, getWriteCount(9), getSentTime(9))));
  };

  EXPECT_CALL(*rawCongestionController, onPacketAckOrLoss(_, _))
      .Times(1)
      .WillOnce(Invoke([&](auto ack, auto loss) {
        ASSERT_THAT(ack, Not(IsNull()));
        EXPECT_THAT(loss, IsNull());
        checkAck(*ack);
      }));
  EXPECT_CALL(*rawCongestionController, getWritableBytes())
      .WillOnce(Return(writableBytes));
  EXPECT_CALL(*rawCongestionController, getCongestionWindow())
      .WillOnce(Return(congestionWindow));

  // check the AckEvent returned by processAckFrame so everything is filled out
  auto ackEvent = processAckFrame(
      conn,
      GetParam(),
      ackFrame,
      [](const auto&, const auto&, const auto&) {},
      [](auto&, auto&, bool) {},
      ackTime);
  checkAck(ackEvent);
  ASSERT_TRUE(ackEvent.ccState.has_value());
  EXPECT_EQ(
      writableBytes,
      CHECK_NOTNULL(ackEvent.ccState.get_pointer())->writableBytes);
  EXPECT_EQ(
      congestionWindow,
      CHECK_NOTNULL(ackEvent.ccState.get_pointer())->congestionWindowBytes);
}

TEST_P(AckHandlersTest, AckEventCreationSingleWrite) {
  QuicServerConnectionState conn(
      FizzServerQuicHandshakeContext::Builder().build());
  auto mockCongestionController = std::make_unique<MockCongestionController>();
  auto rawCongestionController = mockCongestionController.get();
  conn.congestionController = std::move(mockCongestionController);

  const TimePoint startTime = Clock::now();
  PacketNum packetNum = 0;
  StreamId streamid = 0;

  // all packets written in a single write
  auto getWriteCount = [](PacketNum /* packetNum */) { return 1; };
  auto getSentTime = [&startTime](PacketNum /* packetNum */) {
    return startTime + std::chrono::milliseconds(10ms);
  };

  while (packetNum < 10) {
    auto regularPacket = createNewPacket(packetNum, GetParam());
    WriteStreamFrame frame(streamid++, 0, 0, true);
    regularPacket.frames.emplace_back(frame);

    conn.outstandings
        .packetCount[regularPacket.header.getPacketNumberSpace()]++;
    OutstandingPacket sentPacket(
        std::move(regularPacket),
        getSentTime(packetNum),
        1 /* encodedSizeIn */,
        0 /* encodedBodySizeIn */,
        false /* isHandshakeIn */,
        1 * (packetNum + 1) /* totalBytesSentIn */,
        0 /* totalBodyBytesSentIn */,
        0 /* inflightBytesIn */,
        0 /* packetsInflightIn */,
        LossState(),
        getWriteCount(packetNum) /* writeCountIn */,
        OutstandingPacketMetadata::DetailsPerStream());
    sentPacket.isAppLimited = (packetNum % 2);
    conn.outstandings.packets.emplace_back(sentPacket);
    packetNum++;
  }

  ReadAckFrame ackFrame;
  ackFrame.largestAcked = 9;
  ackFrame.ackBlocks.emplace_back(0, 9);
  ackFrame.ackDelay = 5ms;
  const auto ackTime = getSentTime(9) + 10ms;
  const auto writableBytes = 10;
  const auto congestionWindow = 20;
  auto checkAck = [&](auto ack) {
    EXPECT_EQ(ackTime, ack.ackTime);
    EXPECT_EQ(ackTime - ackFrame.ackDelay, ack.adjustedAckTime);
    EXPECT_EQ(ackFrame.ackDelay, ack.ackDelay);

    EXPECT_EQ(ul(9), ack.largestAckedPacket);
    EXPECT_EQ(ul(9), ack.largestNewlyAckedPacket);
    EXPECT_EQ(getSentTime(9), ack.largestNewlyAckedPacketSentTime);
    EXPECT_THAT(
        ack.getRttSampleAckedPacket(),
        Pointee(getAckPacketMatcher(9, getWriteCount(9), getSentTime(9))));
    EXPECT_THAT(
        ack.getLargestAckedPacket(),
        Pointee(getAckPacketMatcher(9, getWriteCount(9), getSentTime(9))));
    EXPECT_THAT(
        ack.getLargestNewlyAckedPacket(),
        Pointee(getAckPacketMatcher(9, getWriteCount(9), getSentTime(9))));

    EXPECT_EQ(10, ack.ackedBytes);
    EXPECT_TRUE(ack.largestNewlyAckedPacketAppLimited);
    EXPECT_EQ(GetParam(), ack.packetNumberSpace);
    EXPECT_EQ(
        std::chrono::ceil<std::chrono::microseconds>(ackTime - getSentTime(9)),
        ack.rttSample);
    EXPECT_EQ(
        std::chrono::ceil<std::chrono::microseconds>(
            ackTime - getSentTime(9) - ackFrame.ackDelay),
        ack.rttSampleNoAckDelay);
    EXPECT_THAT(ack.ackedPackets, SizeIs(10));
    EXPECT_THAT(
        ack.ackedPackets,
        ElementsAre(
            getAckPacketMatcher(0, getWriteCount(0), getSentTime(0)),
            getAckPacketMatcher(1, getWriteCount(1), getSentTime(1)),
            getAckPacketMatcher(2, getWriteCount(2), getSentTime(2)),
            getAckPacketMatcher(3, getWriteCount(3), getSentTime(3)),
            getAckPacketMatcher(4, getWriteCount(4), getSentTime(4)),
            getAckPacketMatcher(5, getWriteCount(5), getSentTime(5)),
            getAckPacketMatcher(6, getWriteCount(6), getSentTime(6)),
            getAckPacketMatcher(7, getWriteCount(7), getSentTime(7)),
            getAckPacketMatcher(8, getWriteCount(8), getSentTime(8)),
            getAckPacketMatcher(9, getWriteCount(9), getSentTime(9))));
  };

  EXPECT_CALL(*rawCongestionController, onPacketAckOrLoss(_, _))
      .Times(1)
      .WillOnce(Invoke([&](auto ack, auto loss) {
        EXPECT_THAT(ack, Not(IsNull()));
        EXPECT_THAT(loss, IsNull());
      }));
  EXPECT_CALL(*rawCongestionController, getWritableBytes())
      .WillOnce(Return(writableBytes));
  EXPECT_CALL(*rawCongestionController, getCongestionWindow())
      .WillOnce(Return(congestionWindow));

  // check the AckEvent returned by processAckFrame so everything is filled out
  auto ackEvent = processAckFrame(
      conn,
      GetParam(),
      ackFrame,
      [](const auto&, const auto&, const auto&) {},
      [](auto&, auto&, bool) {},
      ackTime);
  checkAck(ackEvent);
  ASSERT_TRUE(ackEvent.ccState.has_value());
  EXPECT_EQ(
      writableBytes,
      CHECK_NOTNULL(ackEvent.ccState.get_pointer())->writableBytes);
  EXPECT_EQ(
      congestionWindow,
      CHECK_NOTNULL(ackEvent.ccState.get_pointer())->congestionWindowBytes);
}

TEST_P(AckHandlersTest, AckEventCreationNoCongestionController) {
  QuicServerConnectionState conn(
      FizzServerQuicHandshakeContext::Builder().build());
  conn.congestionController = nullptr; // no congestion control

  const TimePoint startTime = Clock::now();
  PacketNum packetNum = 0;
  StreamId streamid = 0;

  auto getWriteCount = [](PacketNum packetNum) {
    return (packetNum <= 4) ? 1 : 2;
  };
  auto getSentTime = [&startTime](PacketNum packetNum) {
    return startTime +
        std::chrono::milliseconds(10ms * ((packetNum <= 4) ? 1 : 2));
  };

  // write 10 packets, with half in write #1, the other half in write #2
  // packets in each write have the same timestamp and writeCount
  while (packetNum < 10) {
    auto regularPacket = createNewPacket(packetNum, GetParam());
    WriteStreamFrame frame(streamid++, 0, 0, true);
    regularPacket.frames.emplace_back(frame);

    conn.outstandings
        .packetCount[regularPacket.header.getPacketNumberSpace()]++;
    OutstandingPacket sentPacket(
        std::move(regularPacket),
        getSentTime(packetNum),
        1 /* encodedSizeIn */,
        0 /* encodedBodySizeIn */,
        false /* isHandshakeIn */,
        1 * (packetNum + 1) /* totalBytesSentIn */,
        0 /* totalBodyBytesSentIn */,
        0 /* inflightBytesIn */,
        0 /* packetsInflightIn */,
        LossState(),
        getWriteCount(packetNum) /* writeCountIn */,
        OutstandingPacketMetadata::DetailsPerStream());
    sentPacket.isAppLimited = (packetNum % 2);
    conn.outstandings.packets.emplace_back(sentPacket);
    packetNum++;
  }

  ReadAckFrame ackFrame;
  ackFrame.largestAcked = 9;
  ackFrame.ackBlocks.emplace_back(0, 9);
  ackFrame.ackDelay = 5ms;
  const auto ackTime = getSentTime(9) + 10ms;
  auto checkAck = [&](auto ack) {
    EXPECT_EQ(ackTime, ack.ackTime);
    EXPECT_EQ(ackTime - ackFrame.ackDelay, ack.adjustedAckTime);
    EXPECT_EQ(ackFrame.ackDelay, ack.ackDelay);

    EXPECT_EQ(ul(9), ack.largestAckedPacket);
    EXPECT_EQ(ul(9), ack.largestNewlyAckedPacket);
    EXPECT_EQ(getSentTime(9), ack.largestNewlyAckedPacketSentTime);
    EXPECT_THAT(
        ack.getRttSampleAckedPacket(),
        Pointee(getAckPacketMatcher(9, getWriteCount(9), getSentTime(9))));
    EXPECT_THAT(
        ack.getRttSampleAckedPacket(),
        Pointee(getAckPacketMatcher(9, getWriteCount(9), getSentTime(9))));
    EXPECT_THAT(
        ack.getLargestNewlyAckedPacket(),
        Pointee(getAckPacketMatcher(9, getWriteCount(9), getSentTime(9))));

    EXPECT_EQ(10, ack.ackedBytes);
    EXPECT_TRUE(ack.largestNewlyAckedPacketAppLimited);
    EXPECT_EQ(GetParam(), ack.packetNumberSpace);
    EXPECT_EQ(
        std::chrono::ceil<std::chrono::microseconds>(ackTime - getSentTime(9)),
        ack.rttSample);
    EXPECT_EQ(
        std::chrono::ceil<std::chrono::microseconds>(
            ackTime - getSentTime(9) - ackFrame.ackDelay),
        ack.rttSampleNoAckDelay);
    EXPECT_THAT(ack.ackedPackets, SizeIs(10));
    EXPECT_THAT(
        ack.ackedPackets,
        ElementsAre(
            getAckPacketMatcher(0, getWriteCount(0), getSentTime(0)),
            getAckPacketMatcher(1, getWriteCount(1), getSentTime(1)),
            getAckPacketMatcher(2, getWriteCount(2), getSentTime(2)),
            getAckPacketMatcher(3, getWriteCount(3), getSentTime(3)),
            getAckPacketMatcher(4, getWriteCount(4), getSentTime(4)),
            getAckPacketMatcher(5, getWriteCount(5), getSentTime(5)),
            getAckPacketMatcher(6, getWriteCount(6), getSentTime(6)),
            getAckPacketMatcher(7, getWriteCount(7), getSentTime(7)),
            getAckPacketMatcher(8, getWriteCount(8), getSentTime(8)),
            getAckPacketMatcher(9, getWriteCount(9), getSentTime(9))));
  };

  // check the AckEvent returned by processAckFrame so everything is filled out
  auto ackEvent = processAckFrame(
      conn,
      GetParam(),
      ackFrame,
      [](const auto&, const auto&, const auto&) {},
      [](auto&, auto&, bool) {},
      ackTime);
  checkAck(ackEvent);
  ASSERT_FALSE(ackEvent.ccState.has_value()); // no congestion control
}

TEST_P(AckHandlersTest, AckEventCreationInvalidAckDelay) {
  QuicServerConnectionState conn(
      FizzServerQuicHandshakeContext::Builder().build());
  auto mockCongestionController = std::make_unique<MockCongestionController>();
  auto rawCongestionController = mockCongestionController.get();
  conn.congestionController = std::move(mockCongestionController);

  const TimePoint startTime = Clock::now();
  PacketNum packetNum = 0;
  StreamId streamid = 0;

  auto getWriteCount = [](PacketNum packetNum) {
    return (packetNum <= 4) ? 1 : 2;
  };
  auto getSentTime = [&startTime](PacketNum packetNum) {
    return startTime +
        std::chrono::milliseconds(10ms * ((packetNum <= 4) ? 1 : 2));
  };

  // write 10 packets, with half in write #1, the other half in write #2
  // packets in each write have the same timestamp and writeCount
  while (packetNum < 10) {
    auto regularPacket = createNewPacket(packetNum, GetParam());
    WriteStreamFrame frame(streamid++, 0, 0, true);
    regularPacket.frames.emplace_back(frame);

    conn.outstandings
        .packetCount[regularPacket.header.getPacketNumberSpace()]++;
    OutstandingPacket sentPacket(
        std::move(regularPacket),
        getSentTime(packetNum),
        1 /* encodedSizeIn */,
        0 /* encodedBodySizeIn */,
        false /* isHandshakeIn */,
        1 * (packetNum + 1) /* totalBytesSentIn */,
        0 /* totalBodyBytesSentIn */,
        0 /* inflightBytesIn */,
        0 /* packetsInflightIn */,
        LossState(),
        getWriteCount(packetNum) /* writeCountIn */,
        OutstandingPacketMetadata::DetailsPerStream());
    sentPacket.isAppLimited = (packetNum % 2);
    conn.outstandings.packets.emplace_back(sentPacket);
    packetNum++;
  }

  // propagation delay used for this test
  const auto propDelay = 10ms;

  ReadAckFrame ackFrame;
  ackFrame.largestAcked = 9;
  ackFrame.ackBlocks.emplace_back(0, 9);
  ackFrame.ackDelay = propDelay + 1ms; // impossible given ack and send time
  const auto ackTime = getSentTime(9) + propDelay; // do not include ack delay
  const auto writableBytes = 10;
  const auto congestionWindow = 20;
  EXPECT_CALL(*rawCongestionController, onPacketAckOrLoss(_, _))
      .Times(1)
      .WillOnce(Invoke([&](auto ack, auto /* loss */) {
        EXPECT_EQ(ackTime, ack->ackTime);
        EXPECT_EQ(ackTime - ackFrame.ackDelay, ack->adjustedAckTime);
        EXPECT_EQ(ackFrame.ackDelay, ack->ackDelay);

        EXPECT_EQ(ul(9), ack->largestAckedPacket);
        EXPECT_EQ(ul(9), ack->largestNewlyAckedPacket);
        EXPECT_EQ(getSentTime(9), ack->largestNewlyAckedPacketSentTime);
        EXPECT_THAT(
            ack->getRttSampleAckedPacket(),
            Pointee(getAckPacketMatcher(9, getWriteCount(9), getSentTime(9))));
        EXPECT_THAT(
            ack->getLargestAckedPacket(),
            Pointee(getAckPacketMatcher(9, getWriteCount(9), getSentTime(9))));
        EXPECT_THAT(
            ack->getLargestNewlyAckedPacket(),
            Pointee(getAckPacketMatcher(9, getWriteCount(9), getSentTime(9))));

        EXPECT_EQ(
            std::chrono::ceil<std::chrono::microseconds>(
                ackTime - getSentTime(9)),
            ack->rttSample);
        EXPECT_EQ(
            folly::none, // ack delay > RTT, so not set
            ack->rttSampleNoAckDelay);
      }));
  EXPECT_CALL(*rawCongestionController, getWritableBytes())
      .WillOnce(Return(writableBytes));
  EXPECT_CALL(*rawCongestionController, getCongestionWindow())
      .WillOnce(Return(congestionWindow));

  processAckFrame(
      conn,
      GetParam(),
      ackFrame,
      [](const auto&, const auto&, const auto&) {},
      [](auto&, auto&, bool) {},
      ackTime);
}

TEST_P(AckHandlersTest, AckEventCreationRttMinusAckDelayIsZero) {
  QuicServerConnectionState conn(
      FizzServerQuicHandshakeContext::Builder().build());
  auto mockCongestionController = std::make_unique<MockCongestionController>();
  auto rawCongestionController = mockCongestionController.get();
  conn.congestionController = std::move(mockCongestionController);

  const TimePoint startTime = Clock::now();
  PacketNum packetNum = 0;
  StreamId streamid = 0;

  auto getWriteCount = [](PacketNum packetNum) {
    return (packetNum <= 4) ? 1 : 2;
  };
  auto getSentTime = [&startTime](PacketNum packetNum) {
    return startTime +
        std::chrono::milliseconds(10ms * ((packetNum <= 4) ? 1 : 2));
  };

  // write 10 packets, with half in write #1, the other half in write #2
  // packets in each write have the same timestamp and writeCount
  while (packetNum < 10) {
    auto regularPacket = createNewPacket(packetNum, GetParam());
    WriteStreamFrame frame(streamid++, 0, 0, true);
    regularPacket.frames.emplace_back(frame);

    conn.outstandings
        .packetCount[regularPacket.header.getPacketNumberSpace()]++;
    OutstandingPacket sentPacket(
        std::move(regularPacket),
        getSentTime(packetNum),
        1 /* encodedSizeIn */,
        0 /* encodedBodySizeIn */,
        false /* isHandshakeIn */,
        1 * (packetNum + 1) /* totalBytesSentIn */,
        0 /* totalBodyBytesSentIn */,
        0 /* inflightBytesIn */,
        0 /* packetsInflightIn */,
        LossState(),
        getWriteCount(packetNum) /* writeCountIn */,
        OutstandingPacketMetadata::DetailsPerStream());
    sentPacket.isAppLimited = (packetNum % 2);
    conn.outstandings.packets.emplace_back(sentPacket);
    packetNum++;
  }

  // propagation delay used for this test
  const auto propDelay = 10ms;

  ReadAckFrame ackFrame;
  ackFrame.largestAcked = 9;
  ackFrame.ackBlocks.emplace_back(0, 9);
  ackFrame.ackDelay = propDelay; // equals prop delay
  const auto ackTime = getSentTime(9) + propDelay; // subtracting propDelay = 0
  const auto writableBytes = 10;
  const auto congestionWindow = 20;
  EXPECT_CALL(*rawCongestionController, onPacketAckOrLoss(_, _))
      .Times(1)
      .WillOnce(Invoke([&](auto ack, auto /* loss */) {
        EXPECT_EQ(ackTime, ack->ackTime);
        EXPECT_EQ(ackTime - ackFrame.ackDelay, ack->adjustedAckTime);
        EXPECT_EQ(ackFrame.ackDelay, ack->ackDelay);

        EXPECT_EQ(ul(9), ack->largestAckedPacket);
        EXPECT_EQ(ul(9), ack->largestNewlyAckedPacket);
        EXPECT_EQ(getSentTime(9), ack->largestNewlyAckedPacketSentTime);
        EXPECT_THAT(
            ack->getRttSampleAckedPacket(),
            Pointee(getAckPacketMatcher(9, getWriteCount(9), getSentTime(9))));
        EXPECT_THAT(
            ack->getLargestAckedPacket(),
            Pointee(getAckPacketMatcher(9, getWriteCount(9), getSentTime(9))));
        EXPECT_THAT(
            ack->getLargestNewlyAckedPacket(),
            Pointee(getAckPacketMatcher(9, getWriteCount(9), getSentTime(9))));

        EXPECT_EQ(
            std::chrono::ceil<std::chrono::microseconds>(
                ackTime - getSentTime(9)),
            ack->rttSample);
        EXPECT_EQ(0ms, ack->rttSampleNoAckDelay);
      }));
  EXPECT_CALL(*rawCongestionController, getWritableBytes())
      .WillOnce(Return(writableBytes));
  EXPECT_CALL(*rawCongestionController, getCongestionWindow())
      .WillOnce(Return(congestionWindow));

  processAckFrame(
      conn,
      GetParam(),
      ackFrame,
      [](const auto&, const auto&, const auto&) {},
      [](auto&, auto&, bool) {},
      ackTime);
}

TEST_P(AckHandlersTest, AckEventCreationReorderingLargestPacketAcked) {
  QuicServerConnectionState conn(
      FizzServerQuicHandshakeContext::Builder().build());
  auto mockCongestionController =
      std::make_unique<StrictMock<MockCongestionController>>();
  auto rawCongestionController = mockCongestionController.get();
  conn.congestionController = std::move(mockCongestionController);

  // prevent packets from being marked as lost
  // must initialize srtt and lrtt in parallel
  conn.lossState.srtt = 1ms;
  conn.lossState.lrtt = 1ms;
  conn.lossState.reorderingThreshold = 10;
  conn.transportSettings.timeReorderingThreshDividend = 1000;
  conn.transportSettings.timeReorderingThreshDivisor = 1;

  const TimePoint startTime = Clock::now();
  PacketNum packetNum = 0;
  StreamId streamid = 0;

  auto getWriteCount = [](PacketNum packetNum) {
    return (packetNum <= 4) ? 1 : 2;
  };
  auto getSentTime = [&startTime](PacketNum packetNum) {
    return startTime +
        std::chrono::milliseconds(10ms * ((packetNum <= 4) ? 1 : 2));
  };

  // write 10 packets, with half in write #1, the other half in write #2
  // packets in each write have the same timestamp and writeCount
  while (packetNum < 10) {
    auto regularPacket = createNewPacket(packetNum, GetParam());
    WriteStreamFrame frame(streamid++, 0, 0, true);
    regularPacket.frames.emplace_back(frame);

    conn.outstandings
        .packetCount[regularPacket.header.getPacketNumberSpace()]++;
    OutstandingPacket sentPacket(
        std::move(regularPacket),
        getSentTime(packetNum),
        1 /* encodedSizeIn */,
        0 /* encodedBodySizeIn */,
        false /* isHandshakeIn */,
        1 * (packetNum + 1) /* totalBytesSentIn */,
        0 /* totalBodyBytesSentIn */,
        0 /* inflightBytesIn */,
        0 /* packetsInflightIn */,
        LossState(),
        getWriteCount(packetNum) /* writeCountIn */,
        OutstandingPacketMetadata::DetailsPerStream());
    sentPacket.isAppLimited = (packetNum % 2);
    conn.outstandings.packets.emplace_back(sentPacket);
    packetNum++;
  }

  // propagation delay used for this test
  const auto propDelay = 10ms;

  // AckFrame acking packets (0 -> 3, 7 -> 9)
  {
    ReadAckFrame ackFrame;
    ackFrame.largestAcked = 9;
    ackFrame.ackBlocks.emplace_back(7, 9);
    ackFrame.ackBlocks.emplace_back(0, 3);
    ackFrame.ackDelay = 10ms;
    const auto ackTime = getSentTime(9) + propDelay + ackFrame.ackDelay;
    const auto writableBytes = 10;
    const auto congestionWindow = 20;
    EXPECT_CALL(*rawCongestionController, onPacketAckOrLoss(_, _))
        .Times(1)
        .WillOnce(Invoke([&](auto ack, auto /* loss */) {
          EXPECT_EQ(ackTime, ack->ackTime);
          EXPECT_EQ(ackTime - ackFrame.ackDelay, ack->adjustedAckTime);
          EXPECT_EQ(ackFrame.ackDelay, ack->ackDelay);

          EXPECT_EQ(ul(9), ack->largestAckedPacket);
          EXPECT_EQ(ul(9), ack->largestNewlyAckedPacket);
          EXPECT_EQ(getSentTime(9), ack->largestNewlyAckedPacketSentTime);
          EXPECT_THAT(
              ack->getRttSampleAckedPacket(),
              Pointee(
                  getAckPacketMatcher(9, getWriteCount(9), getSentTime(9))));
          EXPECT_THAT(
              ack->getLargestAckedPacket(),
              Pointee(
                  getAckPacketMatcher(9, getWriteCount(9), getSentTime(9))));
          EXPECT_THAT(
              ack->getLargestNewlyAckedPacket(),
              Pointee(
                  getAckPacketMatcher(9, getWriteCount(9), getSentTime(9))));

          EXPECT_EQ(propDelay + ackFrame.ackDelay, ack->rttSample);
          EXPECT_EQ(
              std::chrono::ceil<std::chrono::microseconds>(
                  ackTime - getSentTime(9)),
              ack->rttSample);
          EXPECT_EQ(propDelay, ack->rttSampleNoAckDelay);
          EXPECT_THAT(ack->ackedPackets, SizeIs(7));
          EXPECT_THAT(
              ack->ackedPackets,
              ElementsAre(
                  getAckPacketMatcher(0, getWriteCount(0), getSentTime(0)),
                  getAckPacketMatcher(1, getWriteCount(1), getSentTime(1)),
                  getAckPacketMatcher(2, getWriteCount(2), getSentTime(2)),
                  getAckPacketMatcher(3, getWriteCount(3), getSentTime(3)),
                  getAckPacketMatcher(7, getWriteCount(7), getSentTime(7)),
                  getAckPacketMatcher(8, getWriteCount(8), getSentTime(8)),
                  getAckPacketMatcher(9, getWriteCount(9), getSentTime(9))));
        }));
    EXPECT_CALL(*rawCongestionController, getWritableBytes())
        .WillOnce(Return(writableBytes));
    EXPECT_CALL(*rawCongestionController, getCongestionWindow())
        .WillOnce(Return(congestionWindow));

    processAckFrame(
        conn,
        GetParam(),
        ackFrame,
        [](const auto&, const auto&, const auto&) {},
        [](auto&, auto&, bool) {},
        ackTime);
  }

  // AckFrame acking packets (0 -> 4, 7 -> 9)
  // (e.g., packet 4 arrived later)
  //
  // no RTT sample as packet 9 acked (removed from OutstandingPackets) earlier
  {
    ReadAckFrame ackFrame;
    ackFrame.largestAcked = 9;
    ackFrame.ackBlocks.emplace_back(7, 9);
    ackFrame.ackBlocks.emplace_back(0, 4);
    ackFrame.ackDelay = 0ms;
    const auto ackTime = getSentTime(9) + propDelay + ackFrame.ackDelay + 1ms;
    const auto writableBytes = 10;
    const auto congestionWindow = 20;
    EXPECT_CALL(*rawCongestionController, onPacketAckOrLoss(_, _))
        .Times(1)
        .WillOnce(Invoke([&](auto ack, auto /* loss */) {
          EXPECT_EQ(ackTime, ack->ackTime);
          EXPECT_EQ(ackTime - ackFrame.ackDelay, ack->adjustedAckTime);
          EXPECT_EQ(ackFrame.ackDelay, ack->ackDelay);

          EXPECT_EQ(ul(9), ack->largestAckedPacket);
          EXPECT_EQ(ul(4), ack->largestNewlyAckedPacket); // 4 = newly acked
          EXPECT_EQ(getSentTime(4), ack->largestNewlyAckedPacketSentTime);
          EXPECT_THAT(ack->getRttSampleAckedPacket(), IsNull()); // unavailable
          EXPECT_THAT(ack->getLargestAckedPacket(), IsNull()); // unavailable
          EXPECT_THAT(
              ack->getLargestNewlyAckedPacket(),
              Pointee(
                  getAckPacketMatcher(4, getWriteCount(4), getSentTime(4))));

          EXPECT_EQ(folly::none, ack->rttSample); // no RTT sample
          EXPECT_EQ(folly::none, ack->rttSampleNoAckDelay); // no RTT sample
          EXPECT_THAT(ack->ackedPackets, SizeIs(1));
          EXPECT_THAT(
              ack->ackedPackets,
              ElementsAre(
                  getAckPacketMatcher(4, getWriteCount(4), getSentTime(4))));
        }));
    EXPECT_CALL(*rawCongestionController, getWritableBytes())
        .WillOnce(Return(writableBytes));
    EXPECT_CALL(*rawCongestionController, getCongestionWindow())
        .WillOnce(Return(congestionWindow));

    processAckFrame(
        conn,
        GetParam(),
        ackFrame,
        [](const auto&, const auto&, const auto&) {},
        [](auto&, auto&, bool) {},
        ackTime);
  }

  // AckFrame acking packets (0 -> 9)
  // (e.g., packet 5, 6 arrived later)
  //
  // no RTT sample as packet 9 acked (removed from OutstandingPackets) earlier
  {
    ReadAckFrame ackFrame;
    ackFrame.largestAcked = 9;
    ackFrame.ackBlocks.emplace_back(0, 9);
    ackFrame.ackDelay = 5ms;
    const auto ackTime = getSentTime(9) + propDelay + ackFrame.ackDelay + 2ms;
    const auto writableBytes = 10;
    const auto congestionWindow = 20;
    EXPECT_CALL(*rawCongestionController, onPacketAckOrLoss(_, _))
        .Times(1)
        .WillOnce(Invoke([&](auto ack, auto /* loss */) {
          EXPECT_EQ(ackTime, ack->ackTime);
          EXPECT_EQ(ackTime - ackFrame.ackDelay, ack->adjustedAckTime);
          EXPECT_EQ(ackFrame.ackDelay, ack->ackDelay);

          EXPECT_EQ(ul(9), ack->largestAckedPacket);
          EXPECT_EQ(ul(6), ack->largestNewlyAckedPacket); // 6 = newly acked
          EXPECT_EQ(getSentTime(6), ack->largestNewlyAckedPacketSentTime);
          EXPECT_THAT(ack->getRttSampleAckedPacket(), IsNull()); // unavailable
          EXPECT_THAT(ack->getLargestAckedPacket(), IsNull()); // unavailable
          EXPECT_THAT(
              ack->getLargestNewlyAckedPacket(),
              Pointee(
                  getAckPacketMatcher(6, getWriteCount(6), getSentTime(6))));

          EXPECT_EQ(folly::none, ack->rttSample); // no RTT sample
          EXPECT_EQ(folly::none, ack->rttSampleNoAckDelay); // no RTT sample
          EXPECT_THAT(ack->ackedPackets, SizeIs(2));
          EXPECT_THAT(
              ack->ackedPackets,
              ElementsAre(
                  getAckPacketMatcher(5, getWriteCount(5), getSentTime(5)),
                  getAckPacketMatcher(6, getWriteCount(6), getSentTime(6))));
        }));
    EXPECT_CALL(*rawCongestionController, getWritableBytes())
        .WillOnce(Return(writableBytes));
    EXPECT_CALL(*rawCongestionController, getCongestionWindow())
        .WillOnce(Return(congestionWindow));

    processAckFrame(
        conn,
        GetParam(),
        ackFrame,
        [](const auto&, const auto&, const auto&) {},
        [](auto&, auto&, bool) {},
        ackTime);
  }
}

TEST_P(AckHandlersTest, AckEventCreationNoMatchingPacketDueToLoss) {
  QuicServerConnectionState conn(
      FizzServerQuicHandshakeContext::Builder().build());
  auto mockCongestionController =
      std::make_unique<StrictMock<MockCongestionController>>();
  auto rawCongestionController = mockCongestionController.get();
  conn.congestionController = std::move(mockCongestionController);

  // setting a very low reordering threshold to force loss by reorder
  conn.lossState.reorderingThreshold = 1;

  const TimePoint startTime = Clock::now();
  PacketNum packetNum = 0;
  StreamId streamid = 0;

  auto getWriteCount = [](PacketNum /* packetNum */) { return 1; };
  auto getSentTime = [&startTime](PacketNum packetNum) {
    return startTime + std::chrono::milliseconds(10ms * packetNum);
  };

  // write 4 packets
  while (packetNum < 4) {
    auto regularPacket = createNewPacket(packetNum, GetParam());
    WriteStreamFrame frame(streamid++, 0, 0, true);
    regularPacket.frames.emplace_back(frame);

    conn.outstandings
        .packetCount[regularPacket.header.getPacketNumberSpace()]++;
    OutstandingPacket sentPacket(
        std::move(regularPacket),
        getSentTime(packetNum),
        1 /* encodedSizeIn */,
        0 /* encodedBodySizeIn */,
        false /* isHandshakeIn */,
        1 * (packetNum + 1) /* totalBytesSentIn */,
        0 /* totalBodyBytesSentIn */,
        0 /* inflightBytesIn */,
        0 /* packetsInflightIn */,
        LossState(),
        getWriteCount(packetNum) /* writeCountIn */,
        OutstandingPacketMetadata::DetailsPerStream());
    sentPacket.isAppLimited = false;
    conn.outstandings.packets.emplace_back(sentPacket);
    packetNum++;
  }
  EXPECT_EQ(4, conn.outstandings.numOutstanding());

  // propagation delay used for this test
  const auto propDelay = 10ms;

  // AckFrame acking packets (0, 2, 3)
  {
    ReadAckFrame ackFrame;
    ackFrame.largestAcked = 3;
    ackFrame.ackBlocks.emplace_back(2, 3);
    ackFrame.ackBlocks.emplace_back(0, 0);
    ackFrame.ackDelay = 10ms;
    const auto ackTime = getSentTime(3) + propDelay + ackFrame.ackDelay;
    const auto writableBytes = 10;
    const auto congestionWindow = 20;
    EXPECT_CALL(*rawCongestionController, onPacketAckOrLoss(_, _))
        .Times(1)
        .WillOnce(Invoke([&](auto ack, auto loss) {
          EXPECT_EQ(ackTime, ack->ackTime);
          EXPECT_EQ(ackTime - ackFrame.ackDelay, ack->adjustedAckTime);
          EXPECT_EQ(ackFrame.ackDelay, ack->ackDelay);

          EXPECT_EQ(ul(3), ack->largestAckedPacket);
          EXPECT_EQ(ul(3), ack->largestNewlyAckedPacket);
          EXPECT_EQ(getSentTime(3), ack->largestNewlyAckedPacketSentTime);
          EXPECT_THAT(
              ack->getRttSampleAckedPacket(),
              Pointee(
                  getAckPacketMatcher(3, getWriteCount(3), getSentTime(3))));
          EXPECT_THAT(
              ack->getLargestAckedPacket(),
              Pointee(
                  getAckPacketMatcher(3, getWriteCount(3), getSentTime(3))));
          EXPECT_THAT(
              ack->getLargestNewlyAckedPacket(),
              Pointee(
                  getAckPacketMatcher(3, getWriteCount(3), getSentTime(3))));

          EXPECT_EQ(propDelay + ackFrame.ackDelay, ack->rttSample);
          EXPECT_EQ(
              std::chrono::ceil<std::chrono::microseconds>(
                  ackTime - getSentTime(3)),
              ack->rttSample);
          EXPECT_EQ(propDelay, ack->rttSampleNoAckDelay);
          EXPECT_THAT(ack->ackedPackets, SizeIs(3));
          EXPECT_THAT(
              ack->ackedPackets,
              ElementsAre(
                  getAckPacketMatcher(0, 1 /* writeCount */, getSentTime(0)),
                  getAckPacketMatcher(2, 1 /* writeCount */, getSentTime(2)),
                  getAckPacketMatcher(3, 1 /* writeCount */, getSentTime(3))));

          // should have a loss as well
          EXPECT_THAT(loss, Not(IsNull()));
        }));
    EXPECT_CALL(*rawCongestionController, getWritableBytes())
        .WillOnce(Return(writableBytes));
    EXPECT_CALL(*rawCongestionController, getCongestionWindow())
        .WillOnce(Return(congestionWindow));

    processAckFrame(
        conn,
        GetParam(),
        ackFrame,
        [](const auto&, const auto&, const auto&) {},
        [](auto&, auto&, bool) {},
        ackTime);
  }

  // should have zero outstanding at this point
  EXPECT_EQ(0, conn.outstandings.numOutstanding());

  // AckFrame acking packets (0 -> 3)
  // (e.g., packet 1 arrived later)
  //
  // because packet 1 was already declared lost, no event
  {
    ReadAckFrame ackFrame;
    ackFrame.largestAcked = 3;
    ackFrame.ackBlocks.emplace_back(2, 3);
    ackFrame.ackBlocks.emplace_back(0, 0);
    ackFrame.ackDelay = 10ms;
    const auto ackTime = getSentTime(3) + propDelay + ackFrame.ackDelay + 5ms;
    EXPECT_CALL(*rawCongestionController, onPacketAckOrLoss(_, _)).Times(0);
    processAckFrame(
        conn,
        GetParam(),
        ackFrame,
        [](const auto&, const auto&, const auto&) {},
        [](auto&, auto&, bool) {},
        ackTime);
  }
}

TEST_P(AckHandlersTest, ImplictAckEventCreation) {
  QuicServerConnectionState conn(
      FizzServerQuicHandshakeContext::Builder().build());
  auto mockCongestionController = std::make_unique<MockCongestionController>();
  auto rawCongestionController = mockCongestionController.get();
  conn.congestionController = std::move(mockCongestionController);

  const TimePoint startTime = Clock::now();
  PacketNum packetNum = 0;
  StreamId streamid = 0;

  auto getWriteCount = [](PacketNum /* packetNum */) { return 0; };
  auto getSentTime = [&startTime](PacketNum packetNum) {
    return startTime + std::chrono::milliseconds(10ms * packetNum);
  };

  while (packetNum < 10) {
    auto regularPacket = createNewPacket(packetNum, GetParam());
    WriteStreamFrame frame(streamid++, 0, 0, true);
    regularPacket.frames.emplace_back(std::move(frame));
    conn.outstandings
        .packetCount[regularPacket.header.getPacketNumberSpace()]++;
    OutstandingPacket sentPacket(
        std::move(regularPacket),
        getSentTime(packetNum),
        1 /* encodedSizeIn */,
        0 /* encodedBodySizeIn */,
        false /* isHandshakeIn */,
        1 * (packetNum + 1) /* totalBytesSentIn */,
        0 /* totalBodyBytesSentIn */,
        0 /* inflightBytesIn */,
        packetNum + 1 /* packetsInflightIn */,
        LossState(),
        getWriteCount(packetNum) /* writeCountIn */,
        OutstandingPacketMetadata::DetailsPerStream());
    sentPacket.isAppLimited = (packetNum % 2);
    conn.outstandings.packets.emplace_back(sentPacket);
    LOG(INFO) << "sentPacket.metadata.isD6DProbe = "
              << sentPacket.metadata.isD6DProbe;
    packetNum++;
  }

  // propagation delay used for this test
  const auto propDelay = 10ms;

  const auto srttBefore = conn.lossState.srtt;
  ReadAckFrame ackFrame;
  ackFrame.largestAcked = 9;
  ackFrame.ackBlocks.emplace_back(0, 9);
  ackFrame.implicit = true;
  const auto ackTime = getSentTime(9) + propDelay;
  const auto writableBytes = 10;
  const auto congestionWindow = 20;
  EXPECT_CALL(*rawCongestionController, onPacketAckOrLoss(_, _))
      .Times(1)
      .WillOnce(Invoke([&](auto ack, auto /* loss */) {
        EXPECT_EQ(ackTime, ack->ackTime);

        EXPECT_EQ(ul(9), ack->largestAckedPacket);
        EXPECT_EQ(ul(9), ack->largestNewlyAckedPacket);
        EXPECT_EQ(getSentTime(9), ack->largestNewlyAckedPacketSentTime);
        EXPECT_TRUE(ack->largestNewlyAckedPacketAppLimited);
        EXPECT_THAT(ack->getRttSampleAckedPacket(), IsNull());
        EXPECT_THAT(
            ack->getLargestAckedPacket(),
            Pointee(getAckPacketMatcher(9, getWriteCount(9), getSentTime(9))));
        EXPECT_THAT(
            ack->getLargestNewlyAckedPacket(),
            Pointee(getAckPacketMatcher(9, getWriteCount(9), getSentTime(9))));

        EXPECT_EQ(10, ack->ackedBytes);
        EXPECT_TRUE(ack->implicit);
        EXPECT_FALSE(ack->rttSample.has_value());
        EXPECT_EQ(srttBefore, conn.lossState.srtt);
      }));
  EXPECT_CALL(*rawCongestionController, getWritableBytes())
      .WillOnce(Return(writableBytes));
  EXPECT_CALL(*rawCongestionController, getCongestionWindow())
      .WillOnce(Return(congestionWindow));

  processAckFrame(
      conn,
      GetParam(),
      ackFrame,
      [](const auto&, const auto&, const auto&) {},
      [](auto&, auto&, bool) {},
      ackTime);
}

TEST_P(AckHandlersTest, ObserverRttSample) {
  auto socket = std::make_shared<MockQuicSocket>();
  const auto observerContainer =
      std::make_shared<SocketObserverContainer>(socket.get());

  QuicServerConnectionState conn(
      FizzServerQuicHandshakeContext::Builder().build());
  auto mockCongestionController = std::make_unique<MockCongestionController>();
  conn.congestionController = std::move(mockCongestionController);
  conn.observerContainer = observerContainer;

  LegacyObserver::EventSet eventSet;
  eventSet.enable(SocketObserverInterface::Events::rttSamples);
  auto obs1 = std::make_unique<NiceMock<MockLegacyObserver>>(eventSet);
  observerContainer->addObserver(obs1.get());

  // send packet numbers 0 -> 29
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
        0,
        OutstandingPacketMetadata::DetailsPerStream());
    sentPacket.isAppLimited = false;
    conn.outstandings.packets.emplace_back(sentPacket);
    packetNum++;
  }

  struct AckFrameWithTestData {
    PacketNum startSeq, endSeq;
    std::chrono::milliseconds ackDelay;
    TimePoint ackTime;
    ReadAckFrame ackFrame;

    explicit AckFrameWithTestData(
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
  std::vector<AckFrameWithTestData> ackVec;
  // Sequential test
  ackVec.emplace_back(0, 5, 4ms);
  ackVec.emplace_back(6, 10, 5ms);
  ackVec.emplace_back(11, 15, 6ms);
  // Out-of-order test
  ackVec.emplace_back(18, 18, 0ms);
  ackVec.emplace_back(16, 17, 2ms);
  ackVec.emplace_back(19, 29, 12ms);

  // Setup expectations, then process the actual ACKs
  for (const auto& ackData : ackVec) {
    auto rttSample = std::chrono::ceil<std::chrono::microseconds>(
        ackData.ackTime - packetRcvTime[ackData.endSeq]);
    EXPECT_CALL(
        *obs1,
        rttSampleGenerated(
            socket.get(),
            AllOf(
                Field(
                    &SocketObserverInterface::PacketRTT::rcvTime,
                    ackData.ackTime),
                Field(
                    &SocketObserverInterface::PacketRTT::rttSample, rttSample),
                Field(
                    &SocketObserverInterface::PacketRTT::ackDelay,
                    ackData.ackDelay),
                Field(
                    &SocketObserverInterface::PacketRTT::metadata,
                    Field(
                        &quic::OutstandingPacketMetadata::inflightBytes,
                        ackData.endSeq + 1)))));
  }
  for (const auto& ackData : ackVec) {
    processAckFrame(
        conn,
        GetParam(),
        ackData.ackFrame,
        [](const auto&, const auto&, const auto&) {},
        [](auto&, auto&, bool) {},
        ackData.ackTime);
  }

  observerContainer->removeObserver(obs1.get());
}

TEST_P(AckHandlersTest, ObserverSpuriousLostEventReorderThreshold) {
  auto socket = std::make_shared<MockQuicSocket>();
  const auto observerContainer =
      std::make_shared<SocketObserverContainer>(socket.get());

  QuicServerConnectionState conn(
      FizzServerQuicHandshakeContext::Builder().build());
  auto mockCongestionController = std::make_unique<MockCongestionController>();
  conn.congestionController = std::move(mockCongestionController);
  conn.observerContainer = observerContainer;

  LegacyObserver::EventSet eventSet;
  eventSet.enable(
      SocketObserverInterface::Events::lossEvents,
      SocketObserverInterface::Events::spuriousLossEvents);
  auto obs1 = std::make_unique<NiceMock<MockLegacyObserver>>(eventSet);
  observerContainer->addObserver(obs1.get());

  // send 10 packets
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

  // expect packets to be marked lost on call to detectLostPackets
  EXPECT_CALL(
      *obs1,
      packetLossDetected(
          socket.get(),
          Field(
              &SocketObserverInterface::LossEvent::lostPackets,
              UnorderedElementsAre(
                  MockLegacyObserver::getLossPacketMatcher(0, true, false),
                  MockLegacyObserver::getLossPacketMatcher(1, true, false),
                  MockLegacyObserver::getLossPacketMatcher(2, true, false)))))
      .Times(1);
  detectLossPackets(
      conn, 4, [](auto&, auto&, bool) {}, checkTime, GetParam());

  // now we get acks for packets marked lost, triggering spuriousLossDetected
  EXPECT_CALL(
      *obs1,
      spuriousLossDetected(
          socket.get(),
          Field(
              &SocketObserverInterface::SpuriousLossEvent::spuriousPackets,
              UnorderedElementsAre(
                  MockLegacyObserver::getLossPacketMatcher(0, true, false),
                  MockLegacyObserver::getLossPacketMatcher(1, true, false),
                  MockLegacyObserver::getLossPacketMatcher(2, true, false)))))
      .Times(1);
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

  observerContainer->removeObserver(obs1.get());
}

TEST_P(AckHandlersTest, ObserverSpuriousLostEventTimeout) {
  auto socket = std::make_shared<MockQuicSocket>();
  const auto observerContainer =
      std::make_shared<SocketObserverContainer>(socket.get());

  QuicServerConnectionState conn(
      FizzServerQuicHandshakeContext::Builder().build());
  auto mockCongestionController = std::make_unique<MockCongestionController>();
  conn.congestionController = std::move(mockCongestionController);
  conn.observerContainer = observerContainer;

  LegacyObserver::EventSet eventSet;
  eventSet.enable(
      SocketObserverInterface::Events::lossEvents,
      SocketObserverInterface::Events::spuriousLossEvents);
  auto obs1 = std::make_unique<NiceMock<MockLegacyObserver>>(eventSet);
  observerContainer->addObserver(obs1.get());

  // send 10 packets
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

  // expect packets to be marked lost on call to detectLostPackets
  EXPECT_CALL(
      *obs1,
      packetLossDetected(
          socket.get(),
          Field(
              &SocketObserverInterface::LossEvent::lostPackets,
              UnorderedElementsAre(
                  MockLegacyObserver::getLossPacketMatcher(5, false, true),
                  MockLegacyObserver::getLossPacketMatcher(6, false, true),
                  MockLegacyObserver::getLossPacketMatcher(7, false, true),
                  MockLegacyObserver::getLossPacketMatcher(8, false, true),
                  MockLegacyObserver::getLossPacketMatcher(9, false, true)))))
      .Times(1);
  detectLossPackets(
      conn, 10, [](auto&, auto&, bool) {}, checkTime, GetParam());

  // now we get acks for packets marked lost, triggering spuriousLossDetected
  EXPECT_CALL(
      *obs1,
      spuriousLossDetected(
          socket.get(),
          Field(
              &SocketObserverInterface::SpuriousLossEvent::spuriousPackets,
              UnorderedElementsAre(
                  MockLegacyObserver::getLossPacketMatcher(5, false, true),
                  MockLegacyObserver::getLossPacketMatcher(6, false, true),
                  MockLegacyObserver::getLossPacketMatcher(7, false, true),
                  MockLegacyObserver::getLossPacketMatcher(8, false, true),
                  MockLegacyObserver::getLossPacketMatcher(9, false, true)))))
      .Times(1);
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

  observerContainer->removeObserver(obs1.get());
}

TEST_P(AckHandlersTest, SubMicrosecondRTT) {
  // Verify that an ackReceive timestamp that is less than 1 us
  // after the packet send timestamp results in an rtt sample rounded up to 1 us
  // rather than rounded down to 0. <1 us differences could occur because we
  // mix socket-provided timestamps for incoming packets (which can move
  // backwards) with steady_clock timestamps for outgoing packets. Clock
  // adjustments are more likely to result in < 1us differences when the clients
  // are close.
  QuicServerConnectionState conn(
      FizzServerQuicHandshakeContext::Builder().build());

  auto packetSendTime = Clock::now();
  auto packet = createNewPacket(5, GetParam());
  conn.outstandings.packetCount[packet.header.getPacketNumberSpace()]++;
  conn.outstandings.packets.emplace_back(
      std::move(packet),
      packetSendTime,
      0,
      0,
      false,
      0,
      0,
      0,
      0,
      LossState(),
      0,
      OutstandingPacketMetadata::DetailsPerStream());

  ReadAckFrame ackFrame;
  auto ackReceiveTime = packetSendTime + 400ns;
  ackFrame.largestAcked = 5;
  ackFrame.ackBlocks.emplace_back(5, 5);
  processAckFrame(
      conn,
      GetParam(),
      ackFrame,
      [](const auto&, const auto&, const auto&) {},
      [](auto&, auto&, bool) {},
      ackReceiveTime);
  EXPECT_EQ(conn.lossState.lrtt, 1us);
}

class AckEventForAppDataTest : public Test {
 public:
  void SetUp() override {
    aead_ = test::createNoOpAead();
    headerCipher_ = test::createNoOpHeaderCipher();
    conn_ = createConn();
  }

  static std::unique_ptr<QuicServerConnectionState> createConn() {
    auto conn = std::make_unique<QuicServerConnectionState>(
        FizzServerQuicHandshakeContext::Builder().build());
    conn->serverConnectionId = getTestConnectionId();
    conn->clientConnectionId = getTestConnectionId();
    conn->version = QuicVersion::MVFST;
    conn->flowControlState.peerAdvertisedInitialMaxStreamOffsetBidiLocal =
        kDefaultStreamWindowSize;
    conn->flowControlState.peerAdvertisedInitialMaxStreamOffsetBidiRemote =
        kDefaultStreamWindowSize;
    conn->flowControlState.peerAdvertisedInitialMaxStreamOffsetUni =
        kDefaultStreamWindowSize;
    conn->flowControlState.peerAdvertisedMaxOffset =
        kDefaultConnectionWindowSize;
    conn->initialWriteCipher = createNoOpAead();
    conn->initialHeaderCipher = createNoOpHeaderCipher();
    conn->streamManager->setMaxLocalBidirectionalStreams(
        kDefaultMaxStreamsBidirectional);
    conn->streamManager->setMaxLocalUnidirectionalStreams(
        kDefaultMaxStreamsUnidirectional);
    return conn;
  }

  auto writeDataToQuicStreamAndGetFrame(
      QuicStreamState& stream,
      Buf&& data,
      const bool eof) {
    const auto offset = getLargestWriteOffsetSeen(stream);
    const auto len = data->computeChainDataLength();
    writeDataToQuicStream(stream, data->clone(), eof);
    return WriteStreamFrame(stream.id, offset, len, eof);
  }

  auto writeDataToQuicStreamAndGetFrame(
      const StreamId streamId,
      Buf&& data,
      const bool eof) {
    auto stream = conn_->streamManager->findStream(streamId);
    CHECK_NOTNULL(stream);
    return writeDataToQuicStreamAndGetFrame(*stream, std::move(data), eof);
  }

  auto writeDataToQuicStreamAndGetFrame(
      const StreamId streamId,
      const std::string& str,
      const bool eof) {
    return writeDataToQuicStreamAndGetFrame(
        streamId, folly::IOBuf::copyBuffer(str), eof);
  }

  auto buildEmptyPacket(
      const PacketNumberSpace pnSpace,
      const bool shortHeader = false) {
    folly::Optional<PacketHeader> header;
    if (shortHeader) {
      header = ShortHeader(
          ProtectionType::KeyPhaseZero,
          *conn_->clientConnectionId,
          conn_->ackStates.appDataAckState.nextPacketNum);
    } else {
      if (pnSpace == PacketNumberSpace::Initial) {
        header = LongHeader(
            LongHeader::Types::Initial,
            *conn_->clientConnectionId,
            *conn_->serverConnectionId,
            conn_->ackStates.initialAckState.nextPacketNum,
            *conn_->version);
      } else if (pnSpace == PacketNumberSpace::Handshake) {
        header = LongHeader(
            LongHeader::Types::Handshake,
            *conn_->clientConnectionId,
            *conn_->serverConnectionId,
            conn_->ackStates.handshakeAckState.nextPacketNum,
            *conn_->version);
      } else if (pnSpace == PacketNumberSpace::AppData) {
        header = LongHeader(
            LongHeader::Types::ZeroRtt,
            *conn_->clientConnectionId,
            *conn_->serverConnectionId,
            conn_->ackStates.appDataAckState.nextPacketNum,
            *conn_->version);
      }
    }
    RegularQuicPacketBuilder builder(
        conn_->udpSendPacketLen,
        std::move(*header),
        getAckState(*conn_, pnSpace).largestAckedByPeer.value_or(0));
    builder.encodePacketHeader();
    DCHECK(builder.canBuildPacket());
    return std::move(builder).buildPacket();
  }

  uint64_t getEncodedSize(const RegularQuicPacketBuilder::Packet& packet) {
    // calculate size as the plaintext size
    uint32_t encodedSize = 0;
    if (packet.header) {
      encodedSize += packet.header->computeChainDataLength();
    }
    if (packet.body) {
      encodedSize += packet.body->computeChainDataLength();
    }
    return encodedSize;
  }

  uint64_t getEncodedBodySize(const RegularQuicPacketBuilder::Packet& packet) {
    // calculate size as the plaintext size
    uint32_t encodedBodySize = 0;
    if (packet.body) {
      encodedBodySize += packet.body->computeChainDataLength();
    }
    return encodedBodySize;
  }

  void sendAppDataPacket(
      const RegularQuicPacketBuilder::Packet& packet,
      const TimePoint timepoint = Clock::now()) {
    updateConnection(
        *conn_,
        folly::none,
        packet.packet,
        timepoint,
        getEncodedSize(packet),
        getEncodedBodySize(packet),
        false /* isDSRPacket */);
  }

  auto deliverAckForAppDataPackets(
      const quic::AckBlocks& ackBlocks,
      const TimePoint timepoint = Clock::now(),
      const std::chrono::microseconds ackDelay = 0us) {
    ReadAckFrame ackFrame = {};
    ackFrame.largestAcked = ackBlocks.back().end;
    ackFrame.ackDelay = ackDelay;

    // ack blocks are ordered based on the end packet number in the interval
    auto it = ackBlocks.crbegin();
    while (it != ackBlocks.crend()) {
      ackFrame.ackBlocks.emplace_back(it->start, it->end);
      it++;
    }

    return processAckFrame(
        *conn_,
        PacketNumberSpace::AppData,
        ackFrame,
        [&](const OutstandingPacket& /* packet */,
            const QuicWriteFrame& packetFrame,
            const ReadAckFrame&) {
          switch (packetFrame.type()) {
            case QuicWriteFrame::Type::WriteStreamFrame: {
              const WriteStreamFrame& frame = *packetFrame.asWriteStreamFrame();
              VLOG(4) << "Received ack for stream=" << frame.streamId
                      << " offset=" << frame.offset << " fin=" << frame.fin
                      << " len=" << frame.len << " " << *conn_;
              auto ackedStream =
                  conn_->streamManager->getStream(frame.streamId);
              if (ackedStream) {
                sendAckSMHandler(*ackedStream, frame);
              }
            } break;
            default:
              FAIL();
          }
        },
        [&](auto&, auto&, auto) { /* lossVisitor */ },
        timepoint);
  }

  auto deliverAckForAppDataPackets(
      const quic::PacketNum intervalStart,
      const quic::PacketNum intervalEnd,
      const TimePoint timepoint = Clock::now(),
      const std::chrono::microseconds ackDelay = 0us) {
    quic::AckBlocks acks = {{intervalStart, intervalEnd}};
    return deliverAckForAppDataPackets(acks, timepoint, ackDelay);
  }

  auto getConn() {
    return conn_.get();
  }

 private:
  std::unique_ptr<Aead> aead_;
  std::unique_ptr<PacketNumberCipher> headerCipher_;
  std::unique_ptr<QuicServerConnectionState> conn_;
};

/**
 * Check AckEvent::ackTime, adjustedAckTime, and rttSample.
 *
 * Two packets sent, ACKed in single ACK.
 */
TEST_F(AckEventForAppDataTest, AckEventAckTimeAndMrttSample) {
  // two writes to two different streams
  auto s1Id =
      getConn()->streamManager->createNextBidirectionalStream().value()->id;
  auto s2Id =
      getConn()->streamManager->createNextBidirectionalStream().value()->id;
  auto s1f1 = writeDataToQuicStreamAndGetFrame(s1Id, "hey-", false);
  auto s2f1 = writeDataToQuicStreamAndGetFrame(s2Id, "whats-", false);

  std::vector<PacketNum> appDataPacketNumSent;

  TimePoint startTime = Clock::now();

  // packet 1, frame 1 from stream 1
  auto packet1 = buildEmptyPacket(PacketNumberSpace::AppData);
  packet1.packet.frames.push_back(s1f1);
  const auto packet1SendTime = startTime + 500ms;
  sendAppDataPacket(packet1, packet1SendTime);
  appDataPacketNumSent.push_back(packet1.packet.header.getPacketSequenceNum());

  // packet 2, frame 1 from stream 1 and frame 1 from stream 2
  // mimics a retransmission
  auto packet2 = buildEmptyPacket(PacketNumberSpace::AppData);
  packet2.packet.frames.push_back(s1f1);
  packet2.packet.frames.push_back(s2f1);
  const auto packet2SendTime = packet1SendTime + 7ms;
  sendAppDataPacket(packet2, packet2SendTime);
  appDataPacketNumSent.push_back(packet2.packet.header.getPacketSequenceNum());

  ASSERT_THAT(appDataPacketNumSent, SizeIs(2));

  // deliver ACK for packet1 and packet2
  const auto ackArrivalTime = packet2SendTime + 50ms;
  const auto ackDelay = 11ms;
  const auto ackEvent = deliverAckForAppDataPackets(
      appDataPacketNumSent[0],
      appDataPacketNumSent[1],
      ackArrivalTime,
      ackDelay);

  // check ackTime and adjustedAckTime
  EXPECT_EQ(ackArrivalTime, ackEvent.ackTime);
  EXPECT_EQ(ackArrivalTime - ackDelay, ackEvent.adjustedAckTime);

  // check mrtt sample (includes ack delay)
  EXPECT_EQ(ackArrivalTime - packet2SendTime, ackEvent.rttSample);
}

/**
 * Check AckEvent::ackedBytes, verify it includes bytes even if spurious.
 *
 * Two packets sent, ACKed in single ACK.
 */
TEST_F(AckEventForAppDataTest, AckEventAckedBytes) {
  // two writes to two different streams
  auto s1Id =
      getConn()->streamManager->createNextBidirectionalStream().value()->id;
  auto s2Id =
      getConn()->streamManager->createNextBidirectionalStream().value()->id;
  auto s1f1 = writeDataToQuicStreamAndGetFrame(s1Id, "hey-", false);
  auto s2f1 = writeDataToQuicStreamAndGetFrame(s2Id, "whats-", false);

  std::vector<PacketNum> appDataPacketNumSent;

  // packet 1, frame 1 from stream 1
  auto packet1 = buildEmptyPacket(PacketNumberSpace::AppData);
  packet1.packet.frames.push_back(s1f1);
  sendAppDataPacket(packet1);
  appDataPacketNumSent.push_back(packet1.packet.header.getPacketSequenceNum());

  // packet 2, frame 1 from stream 1 and frame 1 from stream 2
  // mimics a retransmission
  auto packet2 = buildEmptyPacket(PacketNumberSpace::AppData);
  packet2.packet.frames.push_back(s1f1);
  packet2.packet.frames.push_back(s2f1);
  sendAppDataPacket(packet2);
  appDataPacketNumSent.push_back(packet2.packet.header.getPacketSequenceNum());

  ASSERT_THAT(appDataPacketNumSent, SizeIs(2));

  // deliver ACK for packet1 and packet2
  const auto ackEvent = deliverAckForAppDataPackets(
      appDataPacketNumSent[0], appDataPacketNumSent[1]);

  // check ackedBytes
  EXPECT_EQ(
      getEncodedSize(packet1) + getEncodedSize(packet2), ackEvent.ackedBytes);
}

/**
 * Check AckEvent::ackedBytes, verify it includes bytes even if spurious.
 *
 * Two packets sent, ACKed in two separate ACKs.
 */
TEST_F(AckEventForAppDataTest, AckEventAckedBytesSeparateAcks) {
  // two writes to two different streams
  auto s1Id =
      getConn()->streamManager->createNextBidirectionalStream().value()->id;
  auto s2Id =
      getConn()->streamManager->createNextBidirectionalStream().value()->id;
  auto s1f1 = writeDataToQuicStreamAndGetFrame(s1Id, "hey-", false);
  auto s2f1 = writeDataToQuicStreamAndGetFrame(s2Id, "whats-", false);

  std::vector<PacketNum> appDataPacketNumSent;

  // packet 1, frame 1 from stream 1
  auto packet1 = buildEmptyPacket(PacketNumberSpace::AppData);
  packet1.packet.frames.push_back(s1f1);
  sendAppDataPacket(packet1);
  appDataPacketNumSent.push_back(packet1.packet.header.getPacketSequenceNum());

  // packet 2, frame 1 from stream 1 and frame 1 from stream 2
  // mimics a retransmission
  auto packet2 = buildEmptyPacket(PacketNumberSpace::AppData);
  packet2.packet.frames.push_back(s1f1);
  packet2.packet.frames.push_back(s2f1);
  sendAppDataPacket(packet2);
  appDataPacketNumSent.push_back(packet2.packet.header.getPacketSequenceNum());

  ASSERT_THAT(appDataPacketNumSent, SizeIs(2));

  // deliver ACK for packet1
  {
    const auto ackEvent = deliverAckForAppDataPackets(
        appDataPacketNumSent[0], appDataPacketNumSent[0]);

    // check ackedBytes
    EXPECT_EQ(getEncodedSize(packet1), ackEvent.ackedBytes);
  }

  // deliver ACK for packet2
  {
    const auto ackEvent = deliverAckForAppDataPackets(
        appDataPacketNumSent[1], appDataPacketNumSent[1]);

    // check ackedBytes
    EXPECT_EQ(getEncodedSize(packet2), ackEvent.ackedBytes);
  }
}

/**
 * Verify that AckEventStreamDetailsMatcherBuilder matcher works correctly.
 */
TEST_F(AckEventForAppDataTest, AckEventStreamDetailsMatcher) {
  auto s1Id =
      getConn()->streamManager->createNextBidirectionalStream().value()->id;
  auto s2Id =
      getConn()->streamManager->createNextBidirectionalStream().value()->id;
  auto s1f1 = writeDataToQuicStreamAndGetFrame(s1Id, "hey-", false);
  auto s1f2 = writeDataToQuicStreamAndGetFrame(s1Id, "whats-", false);
  auto s1f3 = writeDataToQuicStreamAndGetFrame(s1Id, "up?", false);

  // anon lambda to enable us to construct detailsPerStream and keep it const
  // this ensures the rest of our test does not modify it inadvertently
  const auto detailsPerStream = [&]() {
    AckEvent::AckPacket::DetailsPerStream detailsPerStreamL;
    detailsPerStreamL.recordFrameAlreadyDelivered(s1f1, true);
    detailsPerStreamL.recordFrameDelivered(s1f2, false);
    detailsPerStreamL.recordFrameDelivered(s1f3, true);
    detailsPerStreamL.recordDeliveryOffsetUpdate(s1Id, s1f3.offset + s1f3.len);
    return detailsPerStreamL;
  }();

  // default matcher builder
  const auto&& getDefaultBuilder = [&]() {
    return AckEventStreamDetailsMatcherBuilder()
        .setStreamID(s1Id)
        .setStreamBytesAcked(s1f2.len + s1f3.len)
        .setStreamBytesAckedByRetrans(s1f3.len)
        .setMaybeNewDeliveryOffset(s1f3.offset + s1f3.len)
        .addDupAckedStreamInterval(s1f1.offset, s1f1.offset + s1f1.len - 1);
  };

  // correct
  {
    EXPECT_THAT(
        detailsPerStream, UnorderedElementsAre(getDefaultBuilder().build()));
  }

  // wrong stream id
  {
    EXPECT_THAT(
        detailsPerStream,
        Not(UnorderedElementsAre(
            getDefaultBuilder().setStreamID(s2Id).build())));

    // prove that matcher works if fixed
    EXPECT_THAT(
        detailsPerStream,
        UnorderedElementsAre(getDefaultBuilder().setStreamID(s1Id).build()));
  }

  // wrong stream bytes acked
  {
    EXPECT_THAT(
        detailsPerStream,
        Not(UnorderedElementsAre(
            getDefaultBuilder()
                .setStreamBytesAcked(s1f2.len + s1f3.len + 1)
                .build())));

    // prove that matcher works if fixed
    EXPECT_THAT(
        detailsPerStream,
        UnorderedElementsAre(getDefaultBuilder()
                                 .setStreamBytesAcked(s1f2.len + s1f3.len)
                                 .build()));
  }

  // wrong stream bytes acked (empty)
  {
    EXPECT_THAT(
        detailsPerStream,
        Not(UnorderedElementsAre(
            getDefaultBuilder().setStreamBytesAcked(0).build())));
  }

  // wrong stream bytes acked by retransmission
  {
    EXPECT_THAT(
        detailsPerStream,
        Not(UnorderedElementsAre(getDefaultBuilder()
                                     .setStreamBytesAckedByRetrans(s1f3.len + 1)
                                     .build())));

    // prove that matcher works if fixed
    EXPECT_THAT(
        detailsPerStream,
        UnorderedElementsAre(getDefaultBuilder()
                                 .setStreamBytesAckedByRetrans(s1f3.len)
                                 .build()));
  }

  // wrong stream bytes acked by retransmission (empty)
  {
    EXPECT_THAT(
        detailsPerStream,
        Not(UnorderedElementsAre(
            getDefaultBuilder().setStreamBytesAckedByRetrans(0).build())));
  }

  // wrong new delivery offset
  {
    EXPECT_THAT(
        detailsPerStream,
        Not(UnorderedElementsAre(
            getDefaultBuilder()
                .setMaybeNewDeliveryOffset(s1f3.offset + s1f3.len + 1)
                .build())));

    // prove that matcher works if fixed
    EXPECT_THAT(
        detailsPerStream,
        UnorderedElementsAre(
            getDefaultBuilder()
                .setMaybeNewDeliveryOffset(s1f3.offset + s1f3.len)
                .build()));
  }

  // wrong new delivery offset (empty)
  {
    EXPECT_THAT(
        detailsPerStream,
        Not(UnorderedElementsAre(getDefaultBuilder()
                                     .setMaybeNewDeliveryOffset(folly::none)
                                     .build())));
  }

  // wrong dup acked stream intervals (add f3)
  {
    EXPECT_THAT(
        detailsPerStream,
        Not(UnorderedElementsAre(
            getDefaultBuilder()
                .addDupAckedStreamInterval(
                    s1f3.offset, s1f3.offset + s1f3.len - 1) // wrong
                .build())));
  }

  // wrong dup acked stream intervals (clear and add f1 wrong)
  {
    EXPECT_THAT(
        detailsPerStream,
        Not(UnorderedElementsAre(
            getDefaultBuilder()
                .clearDupAckedStreamIntervals()
                .addDupAckedStreamInterval(
                    s1f1.offset, s1f1.offset + s1f1.len) // wrong
                .build())));
  }

  // wrong dup acked stream intervals (empty)
  {
    EXPECT_THAT(
        detailsPerStream,
        Not(UnorderedElementsAre(
            getDefaultBuilder().clearDupAckedStreamIntervals().build())));
  }
}

/**
 * Verify handling of stream details: five packets, one ACK for all five.
 */
TEST_F(AckEventForAppDataTest, AckEventMultiStreamPacketSingleAck) {
  // two streams, both writing "hey whats up!" split across four frames
  auto s1Id =
      getConn()->streamManager->createNextBidirectionalStream().value()->id;
  auto s2Id =
      getConn()->streamManager->createNextBidirectionalStream().value()->id;
  auto s1f1 = writeDataToQuicStreamAndGetFrame(s1Id, "hey-", false);
  auto s2f1 = writeDataToQuicStreamAndGetFrame(s2Id, "hey ", false);
  auto s1f2 = writeDataToQuicStreamAndGetFrame(s1Id, "whats-", false);
  auto s2f2 = writeDataToQuicStreamAndGetFrame(s2Id, "whats ", false);
  auto s1f3 = writeDataToQuicStreamAndGetFrame(s1Id, "up-", false);
  auto s2f3 = writeDataToQuicStreamAndGetFrame(s2Id, "up ", false);
  auto s1f4 = writeDataToQuicStreamAndGetFrame(s1Id, "!", true);
  auto s2f4 = writeDataToQuicStreamAndGetFrame(s2Id, "!", true);

  // third stream in which "yt??" is written in a single frame
  auto s3Id =
      getConn()->streamManager->createNextBidirectionalStream().value()->id;
  auto s3f1 = writeDataToQuicStreamAndGetFrame(s3Id, "yt??", true);

  std::vector<PacketNum> appDataPacketNumSent;

  // packet 1, frame 1 from streams 1 & 2
  {
    auto packet = buildEmptyPacket(PacketNumberSpace::AppData);
    packet.packet.frames.push_back(s1f1);
    packet.packet.frames.push_back(s2f1);
    sendAppDataPacket(packet);
    appDataPacketNumSent.push_back(packet.packet.header.getPacketSequenceNum());
  }

  // packet 2, frame 2 from streams 1 & 2
  {
    auto packet = buildEmptyPacket(PacketNumberSpace::AppData);
    packet.packet.frames.push_back(s1f2);
    packet.packet.frames.push_back(s2f2);
    sendAppDataPacket(packet);
    appDataPacketNumSent.push_back(packet.packet.header.getPacketSequenceNum());
  }

  // packet 3, frame 3 from streams 1 & 2
  {
    auto packet = buildEmptyPacket(PacketNumberSpace::AppData);
    packet.packet.frames.push_back(s1f3);
    packet.packet.frames.push_back(s2f3);
    sendAppDataPacket(packet);
    appDataPacketNumSent.push_back(packet.packet.header.getPacketSequenceNum());
  }

  // packet 4, frame 1 from stream 3
  {
    auto packet = buildEmptyPacket(PacketNumberSpace::AppData);
    packet.packet.frames.push_back(s3f1);
    sendAppDataPacket(packet);
    appDataPacketNumSent.push_back(packet.packet.header.getPacketSequenceNum());
  }

  // packet 5, frame 4 from streams 1 & 2
  {
    auto packet = buildEmptyPacket(PacketNumberSpace::AppData);
    packet.packet.frames.push_back(s1f4);
    packet.packet.frames.push_back(s2f4);
    sendAppDataPacket(packet);
    appDataPacketNumSent.push_back(packet.packet.header.getPacketSequenceNum());
  }

  // deliver an ACK with all five packets at once
  ASSERT_THAT(appDataPacketNumSent, SizeIs(5));
  const auto ackEvent = deliverAckForAppDataPackets(
      appDataPacketNumSent.front(), appDataPacketNumSent.back());

  // check ackedPackets
  EXPECT_THAT(
      ackEvent.ackedPackets,
      ElementsAre(
          // pkt1
          Field(
              &AckEvent::AckPacket::detailsPerStream,
              UnorderedElementsAre(
                  // s1f1
                  AckEventStreamDetailsMatcherBuilder()
                      .setStreamID(s1Id)
                      .setStreamBytesAcked(s1f1.len)
                      .setStreamBytesAckedByRetrans(0)
                      .setMaybeNewDeliveryOffset(s1f1.offset + s1f1.len)
                      .build(),
                  // s2f1
                  AckEventStreamDetailsMatcherBuilder()
                      .setStreamID(s2Id)
                      .setStreamBytesAcked(s2f1.len)
                      .setStreamBytesAckedByRetrans(0)
                      .setMaybeNewDeliveryOffset(s2f1.offset + s2f1.len)
                      .build())),
          // pkt2
          Field(
              &AckEvent::AckPacket::detailsPerStream,
              UnorderedElementsAre(
                  // s1f2
                  AckEventStreamDetailsMatcherBuilder()
                      .setStreamID(s1Id)
                      .setStreamBytesAcked(s1f2.len)
                      .setStreamBytesAckedByRetrans(0)
                      .setMaybeNewDeliveryOffset(s1f2.offset + s1f2.len)
                      .build(),
                  // s2f2
                  AckEventStreamDetailsMatcherBuilder()
                      .setStreamID(s2Id)
                      .setStreamBytesAcked(s2f2.len)
                      .setStreamBytesAckedByRetrans(0)
                      .setMaybeNewDeliveryOffset(s2f2.offset + s2f2.len)
                      .build())),
          // pkt3
          Field(
              &AckEvent::AckPacket::detailsPerStream,
              UnorderedElementsAre(
                  // s1f3
                  AckEventStreamDetailsMatcherBuilder()
                      .setStreamID(s1Id)
                      .setStreamBytesAcked(s1f3.len)
                      .setStreamBytesAckedByRetrans(0)
                      .setMaybeNewDeliveryOffset(s1f3.offset + s1f3.len)
                      .build(),
                  // s2f3
                  AckEventStreamDetailsMatcherBuilder()
                      .setStreamID(s2Id)
                      .setStreamBytesAcked(s2f3.len)
                      .setStreamBytesAckedByRetrans(0)
                      .setMaybeNewDeliveryOffset(s2f3.offset + s2f3.len)
                      .build())),
          // pkt4
          Field(
              &AckEvent::AckPacket::detailsPerStream,
              UnorderedElementsAre(
                  // s3f1
                  AckEventStreamDetailsMatcherBuilder()
                      .setStreamID(s3Id)
                      .setStreamBytesAcked(s3f1.len)
                      .setStreamBytesAckedByRetrans(0)
                      .setMaybeNewDeliveryOffset(s3f1.offset + s3f1.len)
                      .build())),
          // pkt5
          Field(
              &AckEvent::AckPacket::detailsPerStream,
              UnorderedElementsAre(
                  // s1f4 w/ EOR
                  AckEventStreamDetailsMatcherBuilder()
                      .setStreamID(s1Id)
                      .setStreamBytesAcked(s1f4.len)
                      .setStreamBytesAckedByRetrans(0)
                      .setMaybeNewDeliveryOffset(s1f4.offset + s1f4.len)
                      .build(),
                  // s2f4 w/ EOR
                  AckEventStreamDetailsMatcherBuilder()
                      .setStreamID(s2Id)
                      .setStreamBytesAcked(s2f4.len)
                      .setStreamBytesAckedByRetrans(0)
                      .setMaybeNewDeliveryOffset(s2f4.offset + s2f4.len)
                      .build()))));
}

/**
 * Verify handling of stream details: five packets, five ACKs.
 */
TEST_F(AckEventForAppDataTest, AckEventMultiStreamPacketIndividualAcks) {
  // two streams, both writing "hey whats up!" split across four frames
  auto s1Id =
      getConn()->streamManager->createNextBidirectionalStream().value()->id;
  auto s2Id =
      getConn()->streamManager->createNextBidirectionalStream().value()->id;
  auto s1f1 = writeDataToQuicStreamAndGetFrame(s1Id, "hey-", false);
  auto s2f1 = writeDataToQuicStreamAndGetFrame(s2Id, "hey ", false);
  auto s1f2 = writeDataToQuicStreamAndGetFrame(s1Id, "whats-", false);
  auto s2f2 = writeDataToQuicStreamAndGetFrame(s2Id, "whats ", false);
  auto s1f3 = writeDataToQuicStreamAndGetFrame(s1Id, "up-", false);
  auto s2f3 = writeDataToQuicStreamAndGetFrame(s2Id, "up ", false);
  auto s1f4 = writeDataToQuicStreamAndGetFrame(s1Id, "!", true);
  auto s2f4 = writeDataToQuicStreamAndGetFrame(s2Id, "!", true);

  // third stream in which "yt??" is written in a single frame
  auto s3Id =
      getConn()->streamManager->createNextBidirectionalStream().value()->id;
  auto s3f1 = writeDataToQuicStreamAndGetFrame(s3Id, "yt??", true);

  std::vector<PacketNum> appDataPacketNumSent;

  // packet 1, frame 1 from streams 1 & 2
  {
    auto packet = buildEmptyPacket(PacketNumberSpace::AppData);
    packet.packet.frames.push_back(s1f1);
    packet.packet.frames.push_back(s2f1);
    sendAppDataPacket(packet);
    appDataPacketNumSent.push_back(packet.packet.header.getPacketSequenceNum());
  }

  // packet 2, frame 2 from streams 1 & 2
  {
    auto packet = buildEmptyPacket(PacketNumberSpace::AppData);
    packet.packet.frames.push_back(s1f2);
    packet.packet.frames.push_back(s2f2);
    sendAppDataPacket(packet);
    appDataPacketNumSent.push_back(packet.packet.header.getPacketSequenceNum());
  }

  // packet 3, frame 3 from streams 1 & 2
  {
    auto packet = buildEmptyPacket(PacketNumberSpace::AppData);
    packet.packet.frames.push_back(s1f3);
    packet.packet.frames.push_back(s2f3);
    sendAppDataPacket(packet);
    appDataPacketNumSent.push_back(packet.packet.header.getPacketSequenceNum());
  }

  // packet 4, frame 1 from stream 3
  {
    auto packet = buildEmptyPacket(PacketNumberSpace::AppData);
    packet.packet.frames.push_back(s3f1);
    sendAppDataPacket(packet);
    appDataPacketNumSent.push_back(packet.packet.header.getPacketSequenceNum());
  }

  // packet 5, frame 4 from streams 1 & 2
  {
    auto packet = buildEmptyPacket(PacketNumberSpace::AppData);
    packet.packet.frames.push_back(s1f4);
    packet.packet.frames.push_back(s2f4);
    sendAppDataPacket(packet);
    appDataPacketNumSent.push_back(packet.packet.header.getPacketSequenceNum());
  }

  ASSERT_THAT(appDataPacketNumSent, SizeIs(5));

  // deliver ACK for packet 1
  {
    const auto ackEvent = deliverAckForAppDataPackets(
        appDataPacketNumSent[0], appDataPacketNumSent[0]);

    // check ackedPackets
    EXPECT_THAT(
        ackEvent.ackedPackets,
        ElementsAre(
            // pkt1
            Field(
                &AckEvent::AckPacket::detailsPerStream,
                UnorderedElementsAre(
                    // s1f1
                    AckEventStreamDetailsMatcherBuilder()
                        .setStreamID(s1Id)
                        .setStreamBytesAcked(s1f1.len)
                        .setStreamBytesAckedByRetrans(0)
                        .setMaybeNewDeliveryOffset(s1f1.offset + s1f1.len)
                        .build(),
                    // s2f1
                    AckEventStreamDetailsMatcherBuilder()
                        .setStreamID(s2Id)
                        .setStreamBytesAcked(s2f1.len)
                        .setStreamBytesAckedByRetrans(0)
                        .setMaybeNewDeliveryOffset(s2f1.offset + s2f1.len)
                        .build()))));
  }

  // deliver ACK for packet 2
  {
    const auto ackEvent = deliverAckForAppDataPackets(
        appDataPacketNumSent[1], appDataPacketNumSent[1]);

    // check ackedPackets
    EXPECT_THAT(
        ackEvent.ackedPackets,
        ElementsAre(
            // pkt2
            Field(
                &AckEvent::AckPacket::detailsPerStream,
                UnorderedElementsAre(
                    // s1f2
                    AckEventStreamDetailsMatcherBuilder()
                        .setStreamID(s1Id)
                        .setStreamBytesAcked(s1f2.len)
                        .setStreamBytesAckedByRetrans(0)
                        .setMaybeNewDeliveryOffset(s1f2.offset + s1f2.len)
                        .build(),
                    // s2f2
                    AckEventStreamDetailsMatcherBuilder()
                        .setStreamID(s2Id)
                        .setStreamBytesAcked(s2f2.len)
                        .setStreamBytesAckedByRetrans(0)
                        .setMaybeNewDeliveryOffset(s2f2.offset + s2f2.len)
                        .build()))));
  }

  // deliver ACK for packet 3
  {
    const auto ackEvent = deliverAckForAppDataPackets(
        appDataPacketNumSent[2], appDataPacketNumSent[2]);

    // check ackedPackets
    EXPECT_THAT(
        ackEvent.ackedPackets,
        ElementsAre(
            // pkt3
            Field(
                &AckEvent::AckPacket::detailsPerStream,
                UnorderedElementsAre(
                    // s1f3
                    AckEventStreamDetailsMatcherBuilder()
                        .setStreamID(s1Id)
                        .setStreamBytesAcked(s1f3.len)
                        .setStreamBytesAckedByRetrans(0)
                        .setMaybeNewDeliveryOffset(s1f3.offset + s1f3.len)
                        .build(),
                    // s2f3
                    AckEventStreamDetailsMatcherBuilder()
                        .setStreamID(s2Id)
                        .setStreamBytesAcked(s2f3.len)
                        .setStreamBytesAckedByRetrans(0)
                        .setMaybeNewDeliveryOffset(s2f3.offset + s2f3.len)
                        .build()))));
  }

  // deliver ACK for packet 4
  {
    const auto ackEvent = deliverAckForAppDataPackets(
        appDataPacketNumSent[3], appDataPacketNumSent[3]);

    // check ackedPackets
    EXPECT_THAT(
        ackEvent.ackedPackets,
        ElementsAre(
            // pkt4
            Field(
                &AckEvent::AckPacket::detailsPerStream,
                UnorderedElementsAre(
                    // s3f1
                    AckEventStreamDetailsMatcherBuilder()
                        .setStreamID(s3Id)
                        .setStreamBytesAcked(s3f1.len)
                        .setStreamBytesAckedByRetrans(0)
                        .setMaybeNewDeliveryOffset(s3f1.offset + s3f1.len)
                        .build()))));
  }

  // deliver ACK for packet 5
  {
    const auto ackEvent = deliverAckForAppDataPackets(
        appDataPacketNumSent[4], appDataPacketNumSent[4]);

    // check ackedPackets
    EXPECT_THAT(
        ackEvent.ackedPackets,
        ElementsAre(
            // pkt5
            Field(
                &AckEvent::AckPacket::detailsPerStream,
                UnorderedElementsAre(
                    // s1f4 w/ EOR
                    AckEventStreamDetailsMatcherBuilder()
                        .setStreamID(s1Id)
                        .setStreamBytesAcked(s1f4.len)
                        .setStreamBytesAckedByRetrans(0)
                        .setMaybeNewDeliveryOffset(s1f4.offset + s1f4.len)
                        .build(),
                    // s2f4 w/ EOR
                    AckEventStreamDetailsMatcherBuilder()
                        .setStreamID(s2Id)
                        .setStreamBytesAcked(s2f4.len)
                        .setStreamBytesAckedByRetrans(0)
                        .setMaybeNewDeliveryOffset(s2f4.offset + s2f4.len)
                        .build()))));
  }
}

/**
 * Deliver packets out of order, with packet one arriving late.
 *
 * No delivery offset updates for stream 1 or stream 2 until packet 1 arrives.
 * Stream 3 won't be affected
 */
TEST_F(
    AckEventForAppDataTest,
    AckEventMultiStreamPacketTwoAcksPacketOneOutOfOrder) {
  // prevent packets from being marked as lost
  // must initialize srtt and lrtt in parallel
  getConn()->lossState.srtt = 1ms;
  getConn()->lossState.lrtt = 1ms;
  getConn()->lossState.reorderingThreshold = 10;
  getConn()->transportSettings.timeReorderingThreshDividend = 1000;
  getConn()->transportSettings.timeReorderingThreshDivisor = 1;

  // two streams, both writing "hey whats up!" split across four frames
  auto s1Id =
      getConn()->streamManager->createNextBidirectionalStream().value()->id;
  auto s2Id =
      getConn()->streamManager->createNextBidirectionalStream().value()->id;
  auto s1f1 = writeDataToQuicStreamAndGetFrame(s1Id, "hey-", false);
  auto s2f1 = writeDataToQuicStreamAndGetFrame(s2Id, "hey ", false);
  auto s1f2 = writeDataToQuicStreamAndGetFrame(s1Id, "whats-", false);
  auto s2f2 = writeDataToQuicStreamAndGetFrame(s2Id, "whats ", false);
  auto s1f3 = writeDataToQuicStreamAndGetFrame(s1Id, "up-", false);
  auto s2f3 = writeDataToQuicStreamAndGetFrame(s2Id, "up ", false);
  auto s1f4 = writeDataToQuicStreamAndGetFrame(s1Id, "!", true);
  auto s2f4 = writeDataToQuicStreamAndGetFrame(s2Id, "!", true);

  // third stream in which "yt??" is written in a single frame
  auto s3Id =
      getConn()->streamManager->createNextBidirectionalStream().value()->id;
  auto s3f1 = writeDataToQuicStreamAndGetFrame(s3Id, "yt??", true);

  std::vector<PacketNum> appDataPacketNumSent;

  // packet 1, frame 1 from streams 1 & 2
  {
    auto packet = buildEmptyPacket(PacketNumberSpace::AppData);
    packet.packet.frames.push_back(s1f1);
    packet.packet.frames.push_back(s2f1);
    sendAppDataPacket(packet);
    appDataPacketNumSent.push_back(packet.packet.header.getPacketSequenceNum());
  }

  // packet 2, frame 2 from streams 1 & 2
  {
    auto packet = buildEmptyPacket(PacketNumberSpace::AppData);
    packet.packet.frames.push_back(s1f2);
    packet.packet.frames.push_back(s2f2);
    sendAppDataPacket(packet);
    appDataPacketNumSent.push_back(packet.packet.header.getPacketSequenceNum());
  }

  // packet 3, frame 3 from streams 1 & 2
  {
    auto packet = buildEmptyPacket(PacketNumberSpace::AppData);
    packet.packet.frames.push_back(s1f3);
    packet.packet.frames.push_back(s2f3);
    sendAppDataPacket(packet);
    appDataPacketNumSent.push_back(packet.packet.header.getPacketSequenceNum());
  }

  // packet 4, frame 1 from stream 3
  {
    auto packet = buildEmptyPacket(PacketNumberSpace::AppData);
    packet.packet.frames.push_back(s3f1);
    sendAppDataPacket(packet);
    appDataPacketNumSent.push_back(packet.packet.header.getPacketSequenceNum());
  }

  // packet 5, frame 4 from streams 1 & 2
  {
    auto packet = buildEmptyPacket(PacketNumberSpace::AppData);
    packet.packet.frames.push_back(s1f4);
    packet.packet.frames.push_back(s2f4);
    sendAppDataPacket(packet);
    appDataPacketNumSent.push_back(packet.packet.header.getPacketSequenceNum());
  }

  ASSERT_THAT(appDataPacketNumSent, SizeIs(5));

  // deliver ACK for packets 2 - 5
  {
    AckBlocks blocks;
    blocks.insert(appDataPacketNumSent[1], appDataPacketNumSent[4]);
    const auto ackEvent = deliverAckForAppDataPackets(blocks);

    // check ackedPackets
    EXPECT_THAT(
        ackEvent.ackedPackets,
        ElementsAre(
            // pkt2
            Field(
                &AckEvent::AckPacket::detailsPerStream,
                UnorderedElementsAre(
                    // s1f2
                    AckEventStreamDetailsMatcherBuilder()
                        .setStreamID(s1Id)
                        .setStreamBytesAcked(s1f2.len)
                        .setStreamBytesAckedByRetrans(0)
                        // no update due to out of order, f1 not received yet
                        .setMaybeNewDeliveryOffset(folly::none)
                        .build(),
                    // s2f2
                    AckEventStreamDetailsMatcherBuilder()
                        .setStreamID(s2Id)
                        .setStreamBytesAcked(s2f2.len)
                        .setStreamBytesAckedByRetrans(0)
                        // no update due to out of order, f1 not received yet
                        .setMaybeNewDeliveryOffset(folly::none)
                        .build())),
            // pkt3
            Field(
                &AckEvent::AckPacket::detailsPerStream,
                UnorderedElementsAre(
                    // s1f3
                    AckEventStreamDetailsMatcherBuilder()
                        .setStreamID(s1Id)
                        .setStreamBytesAcked(s1f3.len)
                        .setStreamBytesAckedByRetrans(0)
                        // no update due to out of order, f1 not received yet
                        .setMaybeNewDeliveryOffset(folly::none)
                        .build(),
                    // s2f3
                    AckEventStreamDetailsMatcherBuilder()
                        .setStreamID(s2Id)
                        .setStreamBytesAcked(s2f3.len)
                        .setStreamBytesAckedByRetrans(0)
                        // no update due to out of order, f1 not received yet
                        .setMaybeNewDeliveryOffset(folly::none)
                        .build())),
            // pkt4
            Field(
                &AckEvent::AckPacket::detailsPerStream,
                UnorderedElementsAre(
                    // s3f1
                    AckEventStreamDetailsMatcherBuilder()
                        .setStreamID(s3Id)
                        .setStreamBytesAcked(s3f1.len)
                        .setStreamBytesAckedByRetrans(0)
                        .setMaybeNewDeliveryOffset(s3f1.offset + s3f1.len)
                        .build())),
            // pkt5
            Field(
                &AckEvent::AckPacket::detailsPerStream,
                UnorderedElementsAre(
                    // s1f4 w/ EOR
                    AckEventStreamDetailsMatcherBuilder()
                        .setStreamID(s1Id)
                        .setStreamBytesAcked(s1f4.len)
                        .setStreamBytesAckedByRetrans(0)
                        // no update due to out of order, f1 not received yet
                        .setMaybeNewDeliveryOffset(folly::none)
                        .build(),
                    // s2f4 w/ EOR
                    AckEventStreamDetailsMatcherBuilder()
                        .setStreamID(s2Id)
                        .setStreamBytesAcked(s2f4.len)
                        .setStreamBytesAckedByRetrans(0)
                        // no update due to out of order, f1 not received yet
                        .setMaybeNewDeliveryOffset(folly::none)
                        .build()))));
  }

  // deliver ACK for packet 1
  {
    const auto ackEvent = deliverAckForAppDataPackets(
        appDataPacketNumSent[0], appDataPacketNumSent[0]);

    // check ackedPackets
    EXPECT_THAT(
        ackEvent.ackedPackets,
        ElementsAre(
            // pkt1
            Field(
                &AckEvent::AckPacket::detailsPerStream,
                UnorderedElementsAre(
                    // s1f1
                    AckEventStreamDetailsMatcherBuilder()
                        .setStreamID(s1Id)
                        .setStreamBytesAcked(s1f1.len)
                        .setStreamBytesAckedByRetrans(0)
                        // f1 - f4 now done, delivery offset = end of f4
                        .setMaybeNewDeliveryOffset(s1f4.offset + s1f4.len)
                        .build(),
                    // s2f1
                    AckEventStreamDetailsMatcherBuilder()
                        .setStreamID(s2Id)
                        .setStreamBytesAcked(s2f1.len)
                        .setStreamBytesAckedByRetrans(0)
                        // f1 - f4 now done, delivery offset = end of f4
                        .setMaybeNewDeliveryOffset(s2f4.offset + s2f4.len)
                        .build()))));
  }
}

/**
 * Deliver packets out of order, with packet two arriving late.
 *
 * No delivery offset updates for stream 1 or stream 2 for frames in packets 4
 * and 5 until ACK for packet 2 arrives. Stream 3 won't be affected.
 */
TEST_F(
    AckEventForAppDataTest,
    AckEventMultiStreamPacketTwoAcksPacketTwoOutOfOrder) {
  // prevent packets from being marked as lost
  // must initialize srtt and lrtt in parallel
  getConn()->lossState.srtt = 1ms;
  getConn()->lossState.lrtt = 1ms;
  getConn()->lossState.reorderingThreshold = 10;
  getConn()->transportSettings.timeReorderingThreshDividend = 1000;
  getConn()->transportSettings.timeReorderingThreshDivisor = 1;

  // two streams, both writing "hey whats up!" split across four frames
  auto s1Id =
      getConn()->streamManager->createNextBidirectionalStream().value()->id;
  auto s2Id =
      getConn()->streamManager->createNextBidirectionalStream().value()->id;
  auto s1f1 = writeDataToQuicStreamAndGetFrame(s1Id, "hey-", false);
  auto s2f1 = writeDataToQuicStreamAndGetFrame(s2Id, "hey ", false);
  auto s1f2 = writeDataToQuicStreamAndGetFrame(s1Id, "whats-", false);
  auto s2f2 = writeDataToQuicStreamAndGetFrame(s2Id, "whats ", false);
  auto s1f3 = writeDataToQuicStreamAndGetFrame(s1Id, "up-", false);
  auto s2f3 = writeDataToQuicStreamAndGetFrame(s2Id, "up ", false);
  auto s1f4 = writeDataToQuicStreamAndGetFrame(s1Id, "!", true);
  auto s2f4 = writeDataToQuicStreamAndGetFrame(s2Id, "!", true);

  // third stream in which "yt??" is written in a single frame
  auto s3Id =
      getConn()->streamManager->createNextBidirectionalStream().value()->id;
  auto s3f1 = writeDataToQuicStreamAndGetFrame(s3Id, "yt??", true);

  std::vector<PacketNum> appDataPacketNumSent;

  // packet 1, frame 1 from streams 1 & 2
  {
    auto packet = buildEmptyPacket(PacketNumberSpace::AppData);
    packet.packet.frames.push_back(s1f1);
    packet.packet.frames.push_back(s2f1);
    sendAppDataPacket(packet);
    appDataPacketNumSent.push_back(packet.packet.header.getPacketSequenceNum());
  }

  // packet 2, frame 2 from streams 1 & 2
  {
    auto packet = buildEmptyPacket(PacketNumberSpace::AppData);
    packet.packet.frames.push_back(s1f2);
    packet.packet.frames.push_back(s2f2);
    sendAppDataPacket(packet);
    appDataPacketNumSent.push_back(packet.packet.header.getPacketSequenceNum());
  }

  // packet 3, frame 3 from streams 1 & 2
  {
    auto packet = buildEmptyPacket(PacketNumberSpace::AppData);
    packet.packet.frames.push_back(s1f3);
    packet.packet.frames.push_back(s2f3);
    sendAppDataPacket(packet);
    appDataPacketNumSent.push_back(packet.packet.header.getPacketSequenceNum());
  }

  // packet 4, frame 1 from stream 3
  {
    auto packet = buildEmptyPacket(PacketNumberSpace::AppData);
    packet.packet.frames.push_back(s3f1);
    sendAppDataPacket(packet);
    appDataPacketNumSent.push_back(packet.packet.header.getPacketSequenceNum());
  }

  // packet 5, frame 4 from streams 1 & 2
  {
    auto packet = buildEmptyPacket(PacketNumberSpace::AppData);
    packet.packet.frames.push_back(s1f4);
    packet.packet.frames.push_back(s2f4);
    sendAppDataPacket(packet);
    appDataPacketNumSent.push_back(packet.packet.header.getPacketSequenceNum());
  }

  ASSERT_THAT(appDataPacketNumSent, SizeIs(5));

  // deliver ACK for packets 1, 3 - 5
  {
    AckBlocks blocks;
    blocks.insert(appDataPacketNumSent[0], appDataPacketNumSent[0]);
    blocks.insert(appDataPacketNumSent[2], appDataPacketNumSent[4]);
    const auto ackEvent = deliverAckForAppDataPackets(blocks);

    // check ackedPackets
    EXPECT_THAT(
        ackEvent.ackedPackets,
        ElementsAre(
            // pkt1
            Field(
                &AckEvent::AckPacket::detailsPerStream,
                UnorderedElementsAre(
                    // s1f1
                    AckEventStreamDetailsMatcherBuilder()
                        .setStreamID(s1Id)
                        .setStreamBytesAcked(s1f1.len)
                        .setStreamBytesAckedByRetrans(0)
                        .setMaybeNewDeliveryOffset(s1f1.offset + s1f1.len)
                        .build(),
                    // s2f1
                    AckEventStreamDetailsMatcherBuilder()
                        .setStreamID(s2Id)
                        .setStreamBytesAcked(s2f1.len)
                        .setStreamBytesAckedByRetrans(0)
                        .setMaybeNewDeliveryOffset(s1f1.offset + s1f1.len)
                        .build())),
            // pkt3
            Field(
                &AckEvent::AckPacket::detailsPerStream,
                UnorderedElementsAre(
                    // s1f3
                    AckEventStreamDetailsMatcherBuilder()
                        .setStreamID(s1Id)
                        .setStreamBytesAcked(s1f3.len)
                        .setStreamBytesAckedByRetrans(0)
                        // no update due to out of order, f2 not received yet
                        .setMaybeNewDeliveryOffset(folly::none)
                        .build(),
                    // s2f3
                    AckEventStreamDetailsMatcherBuilder()
                        .setStreamID(s2Id)
                        .setStreamBytesAcked(s2f3.len)
                        .setStreamBytesAckedByRetrans(0)
                        // no update due to out of order, f2 not received yet
                        .setMaybeNewDeliveryOffset(folly::none)
                        .build())),
            // pkt4
            Field(
                &AckEvent::AckPacket::detailsPerStream,
                UnorderedElementsAre(
                    // s3f1
                    AckEventStreamDetailsMatcherBuilder()
                        .setStreamID(s3Id)
                        .setStreamBytesAcked(s3f1.len)
                        .setStreamBytesAckedByRetrans(0)
                        // not affected by out of order
                        .setMaybeNewDeliveryOffset(s3f1.offset + s3f1.len)
                        .build())),
            // pkt5
            Field(
                &AckEvent::AckPacket::detailsPerStream,
                UnorderedElementsAre(
                    // s1f4 w/ EOR
                    AckEventStreamDetailsMatcherBuilder()
                        .setStreamID(s1Id)
                        .setStreamBytesAcked(s1f4.len)
                        .setStreamBytesAckedByRetrans(0)
                        // no update due to out of order, f2 not received yet
                        .setMaybeNewDeliveryOffset(folly::none)
                        .build(),
                    // s2f4 w/ EOR
                    AckEventStreamDetailsMatcherBuilder()
                        .setStreamID(s2Id)
                        .setStreamBytesAcked(s2f4.len)
                        .setStreamBytesAckedByRetrans(0)
                        // no update due to out of order, f2 not received yet
                        .setMaybeNewDeliveryOffset(folly::none)
                        .build()))));
  }

  // deliver ACK for packet 2
  {
    const auto ackEvent = deliverAckForAppDataPackets(
        appDataPacketNumSent[1], appDataPacketNumSent[1]);

    // check ackedPackets
    EXPECT_THAT(
        ackEvent.ackedPackets,
        ElementsAre(
            // pkt2
            Field(
                &AckEvent::AckPacket::detailsPerStream,
                UnorderedElementsAre(
                    // s1f1
                    AckEventStreamDetailsMatcherBuilder()
                        .setStreamID(s1Id)
                        .setStreamBytesAcked(s1f2.len)
                        .setStreamBytesAckedByRetrans(0)
                        // f1 - f4 now done, delivery offset = end of f4
                        .setMaybeNewDeliveryOffset(s1f4.offset + s1f4.len)
                        .build(),
                    // s2f1
                    AckEventStreamDetailsMatcherBuilder()
                        .setStreamID(s2Id)
                        .setStreamBytesAcked(s2f2.len)
                        .setStreamBytesAckedByRetrans(0)
                        // f1 - f4 now done, delivery offset = end of f4
                        .setMaybeNewDeliveryOffset(s2f4.offset + s2f4.len)
                        .build()))));
  }
}

/**
 * Deliver packets out of order, with packet four arriving late.
 *
 * Since packet four contains only bytes for stream 3, and is the first packet
 * with bytes for stream 3, there should be no impact on delivery offsets.
 */
TEST_F(
    AckEventForAppDataTest,
    AckEventMultiStreamPacketTwoAcksPacketFourOutOfOrder) {
  // prevent packets from being marked as lost
  // must initialize srtt and lrtt in parallel
  getConn()->lossState.srtt = 1ms;
  getConn()->lossState.lrtt = 1ms;
  getConn()->lossState.reorderingThreshold = 10;
  getConn()->transportSettings.timeReorderingThreshDividend = 1000;
  getConn()->transportSettings.timeReorderingThreshDivisor = 1;

  // two streams, both writing "hey whats up!" split across four frames
  auto s1Id =
      getConn()->streamManager->createNextBidirectionalStream().value()->id;
  auto s2Id =
      getConn()->streamManager->createNextBidirectionalStream().value()->id;
  auto s1f1 = writeDataToQuicStreamAndGetFrame(s1Id, "hey-", false);
  auto s2f1 = writeDataToQuicStreamAndGetFrame(s2Id, "hey ", false);
  auto s1f2 = writeDataToQuicStreamAndGetFrame(s1Id, "whats-", false);
  auto s2f2 = writeDataToQuicStreamAndGetFrame(s2Id, "whats ", false);
  auto s1f3 = writeDataToQuicStreamAndGetFrame(s1Id, "up-", false);
  auto s2f3 = writeDataToQuicStreamAndGetFrame(s2Id, "up ", false);
  auto s1f4 = writeDataToQuicStreamAndGetFrame(s1Id, "!", true);
  auto s2f4 = writeDataToQuicStreamAndGetFrame(s2Id, "!", true);

  // third stream in which "yt??" is written in a single frame
  auto s3Id =
      getConn()->streamManager->createNextBidirectionalStream().value()->id;
  auto s3f1 = writeDataToQuicStreamAndGetFrame(s3Id, "yt??", true);

  std::vector<PacketNum> appDataPacketNumSent;

  // packet 1, frame 1 from streams 1 & 2
  {
    auto packet = buildEmptyPacket(PacketNumberSpace::AppData);
    packet.packet.frames.push_back(s1f1);
    packet.packet.frames.push_back(s2f1);
    sendAppDataPacket(packet);
    appDataPacketNumSent.push_back(packet.packet.header.getPacketSequenceNum());
  }

  // packet 2, frame 2 from streams 1 & 2
  {
    auto packet = buildEmptyPacket(PacketNumberSpace::AppData);
    packet.packet.frames.push_back(s1f2);
    packet.packet.frames.push_back(s2f2);
    sendAppDataPacket(packet);
    appDataPacketNumSent.push_back(packet.packet.header.getPacketSequenceNum());
  }

  // packet 3, frame 3 from streams 1 & 2
  {
    auto packet = buildEmptyPacket(PacketNumberSpace::AppData);
    packet.packet.frames.push_back(s1f3);
    packet.packet.frames.push_back(s2f3);
    sendAppDataPacket(packet);
    appDataPacketNumSent.push_back(packet.packet.header.getPacketSequenceNum());
  }

  // packet 4, frame 1 from stream 3
  {
    auto packet = buildEmptyPacket(PacketNumberSpace::AppData);
    packet.packet.frames.push_back(s3f1);
    sendAppDataPacket(packet);
    appDataPacketNumSent.push_back(packet.packet.header.getPacketSequenceNum());
  }

  // packet 5, frame 4 from streams 1 & 2
  {
    auto packet = buildEmptyPacket(PacketNumberSpace::AppData);
    packet.packet.frames.push_back(s1f4);
    packet.packet.frames.push_back(s2f4);
    sendAppDataPacket(packet);
    appDataPacketNumSent.push_back(packet.packet.header.getPacketSequenceNum());
  }

  ASSERT_THAT(appDataPacketNumSent, SizeIs(5));

  // deliver ACK for packets 1 - 3, and 5
  {
    AckBlocks blocks;
    blocks.insert(appDataPacketNumSent[0], appDataPacketNumSent[2]);
    blocks.insert(appDataPacketNumSent[4], appDataPacketNumSent[4]);
    const auto ackEvent = deliverAckForAppDataPackets(blocks);

    // check ackedPackets
    EXPECT_THAT(
        ackEvent.ackedPackets,
        ElementsAre(
            // pkt1
            Field(
                &AckEvent::AckPacket::detailsPerStream,
                UnorderedElementsAre(
                    // s1f1
                    AckEventStreamDetailsMatcherBuilder()
                        .setStreamID(s1Id)
                        .setStreamBytesAcked(s1f1.len)
                        .setStreamBytesAckedByRetrans(0)
                        .setMaybeNewDeliveryOffset(s1f1.offset + s1f1.len)
                        .build(),
                    // s2f1
                    AckEventStreamDetailsMatcherBuilder()
                        .setStreamID(s2Id)
                        .setStreamBytesAcked(s2f1.len)
                        .setStreamBytesAckedByRetrans(0)
                        .setMaybeNewDeliveryOffset(s2f1.offset + s2f1.len)
                        .build())),
            // pkt2
            Field(
                &AckEvent::AckPacket::detailsPerStream,
                UnorderedElementsAre(
                    // s1f2
                    AckEventStreamDetailsMatcherBuilder()
                        .setStreamID(s1Id)
                        .setStreamBytesAcked(s1f2.len)
                        .setStreamBytesAckedByRetrans(0)
                        .setMaybeNewDeliveryOffset(s1f2.offset + s1f2.len)
                        .build(),
                    // s2f2
                    AckEventStreamDetailsMatcherBuilder()
                        .setStreamID(s2Id)
                        .setStreamBytesAcked(s2f2.len)
                        .setStreamBytesAckedByRetrans(0)
                        .setMaybeNewDeliveryOffset(s2f2.offset + s2f2.len)
                        .build())),
            // pkt3
            Field(
                &AckEvent::AckPacket::detailsPerStream,
                UnorderedElementsAre(
                    // s1f3
                    AckEventStreamDetailsMatcherBuilder()
                        .setStreamID(s1Id)
                        .setStreamBytesAcked(s1f3.len)
                        .setStreamBytesAckedByRetrans(0)
                        .setMaybeNewDeliveryOffset(s1f3.offset + s1f3.len)
                        .build(),
                    // s2f3
                    AckEventStreamDetailsMatcherBuilder()
                        .setStreamID(s2Id)
                        .setStreamBytesAcked(s2f3.len)
                        .setStreamBytesAckedByRetrans(0)
                        .setMaybeNewDeliveryOffset(s2f3.offset + s2f3.len)
                        .build())),
            // pkt5
            Field(
                &AckEvent::AckPacket::detailsPerStream,
                UnorderedElementsAre(
                    // s1f4 w/ EOR
                    AckEventStreamDetailsMatcherBuilder()
                        .setStreamID(s1Id)
                        .setStreamBytesAcked(s1f4.len)
                        .setStreamBytesAckedByRetrans(0)
                        .setMaybeNewDeliveryOffset(s1f4.offset + s1f4.len)
                        .build(),
                    // s2f4 w/ EOR
                    AckEventStreamDetailsMatcherBuilder()
                        .setStreamID(s2Id)
                        .setStreamBytesAcked(s2f4.len)
                        .setStreamBytesAckedByRetrans(0)
                        .setMaybeNewDeliveryOffset(s2f4.offset + s2f4.len)
                        .build()))));
  }

  // deliver ACK for packet 4
  {
    const auto ackEvent = deliverAckForAppDataPackets(
        appDataPacketNumSent[3], appDataPacketNumSent[3]);

    // check ackedPackets
    EXPECT_THAT(
        ackEvent.ackedPackets,
        ElementsAre(
            // pkt4
            Field(
                &AckEvent::AckPacket::detailsPerStream,
                UnorderedElementsAre(
                    // s3f1
                    AckEventStreamDetailsMatcherBuilder()
                        .setStreamID(s3Id)
                        .setStreamBytesAcked(s3f1.len)
                        .setStreamBytesAckedByRetrans(0)
                        .setMaybeNewDeliveryOffset(s3f1.offset + s3f1.len)
                        .build()))));
  }
}

/**
 * Deliver packets out of order, with packet two arriving late.
 *
 * Each packet is ACKed individually.
 *
 * No delivery offset updates for stream 1 or stream 2 for frames in packets 4
 * and 5 until ACK for packet 2 arrives. Stream 3 won't be affected.
 */
TEST_F(
    AckEventForAppDataTest,
    AckEventMultiStreamPacketTwoAcksPacketTwoOutOfOrderIndividualAcks) {
  // two streams, both writing "hey whats up!" split across four frames
  auto s1Id =
      getConn()->streamManager->createNextBidirectionalStream().value()->id;
  auto s2Id =
      getConn()->streamManager->createNextBidirectionalStream().value()->id;
  auto s1f1 = writeDataToQuicStreamAndGetFrame(s1Id, "hey-", false);
  auto s2f1 = writeDataToQuicStreamAndGetFrame(s2Id, "hey ", false);
  auto s1f2 = writeDataToQuicStreamAndGetFrame(s1Id, "whats-", false);
  auto s2f2 = writeDataToQuicStreamAndGetFrame(s2Id, "whats ", false);
  auto s1f3 = writeDataToQuicStreamAndGetFrame(s1Id, "up-", false);
  auto s2f3 = writeDataToQuicStreamAndGetFrame(s2Id, "up ", false);
  auto s1f4 = writeDataToQuicStreamAndGetFrame(s1Id, "!", true);
  auto s2f4 = writeDataToQuicStreamAndGetFrame(s2Id, "!", true);

  // third stream in which "yt??" is written in a single frame
  auto s3Id =
      getConn()->streamManager->createNextBidirectionalStream().value()->id;
  auto s3f1 = writeDataToQuicStreamAndGetFrame(s3Id, "yt??", true);

  std::vector<PacketNum> appDataPacketNumSent;

  // packet 1, frame 1 from streams 1 & 2
  {
    auto packet = buildEmptyPacket(PacketNumberSpace::AppData);
    packet.packet.frames.push_back(s1f1);
    packet.packet.frames.push_back(s2f1);
    sendAppDataPacket(packet);
    appDataPacketNumSent.push_back(packet.packet.header.getPacketSequenceNum());
  }

  // packet 2, frame 2 from streams 1 & 2
  {
    auto packet = buildEmptyPacket(PacketNumberSpace::AppData);
    packet.packet.frames.push_back(s1f2);
    packet.packet.frames.push_back(s2f2);
    sendAppDataPacket(packet);
    appDataPacketNumSent.push_back(packet.packet.header.getPacketSequenceNum());
  }

  // packet 3, frame 3 from streams 1 & 2
  {
    auto packet = buildEmptyPacket(PacketNumberSpace::AppData);
    packet.packet.frames.push_back(s1f3);
    packet.packet.frames.push_back(s2f3);
    sendAppDataPacket(packet);
    appDataPacketNumSent.push_back(packet.packet.header.getPacketSequenceNum());
  }

  // packet 4, frame 1 from stream 3
  {
    auto packet = buildEmptyPacket(PacketNumberSpace::AppData);
    packet.packet.frames.push_back(s3f1);
    sendAppDataPacket(packet);
    appDataPacketNumSent.push_back(packet.packet.header.getPacketSequenceNum());
  }

  // packet 5, frame 4 from streams 1 & 2
  {
    auto packet = buildEmptyPacket(PacketNumberSpace::AppData);
    packet.packet.frames.push_back(s1f4);
    packet.packet.frames.push_back(s2f4);
    sendAppDataPacket(packet);
    appDataPacketNumSent.push_back(packet.packet.header.getPacketSequenceNum());
  }

  ASSERT_THAT(appDataPacketNumSent, SizeIs(5));

  // deliver ACK for packet 1
  {
    const auto ackEvent = deliverAckForAppDataPackets(
        appDataPacketNumSent[0], appDataPacketNumSent[0]);

    // check ackedPackets
    EXPECT_THAT(
        ackEvent.ackedPackets,
        ElementsAre(
            // pkt1
            Field(
                &AckEvent::AckPacket::detailsPerStream,
                UnorderedElementsAre(
                    // s1f1
                    AckEventStreamDetailsMatcherBuilder()
                        .setStreamID(s1Id)
                        .setStreamBytesAcked(s1f1.len)
                        .setStreamBytesAckedByRetrans(0)
                        .setMaybeNewDeliveryOffset(s1f1.offset + s1f1.len)
                        .build(),
                    // s2f1
                    AckEventStreamDetailsMatcherBuilder()
                        .setStreamID(s2Id)
                        .setStreamBytesAcked(s2f1.len)
                        .setStreamBytesAckedByRetrans(0)
                        .setMaybeNewDeliveryOffset(s2f1.offset + s2f1.len)
                        .build()))));
  }

  // deliver ACK for packet 3
  {
    const auto ackEvent = deliverAckForAppDataPackets(
        appDataPacketNumSent[2], appDataPacketNumSent[2]);

    // check ackedPackets
    EXPECT_THAT(
        ackEvent.ackedPackets,
        ElementsAre(
            // pkt3
            Field(
                &AckEvent::AckPacket::detailsPerStream,
                UnorderedElementsAre(
                    // s1f3
                    AckEventStreamDetailsMatcherBuilder()
                        .setStreamID(s1Id)
                        .setStreamBytesAcked(s1f3.len)
                        .setStreamBytesAckedByRetrans(0)
                        // no update due to out of order, f2 not received yet
                        .setMaybeNewDeliveryOffset(folly::none)
                        .build(),
                    // s2f3
                    AckEventStreamDetailsMatcherBuilder()
                        .setStreamID(s2Id)
                        .setStreamBytesAcked(s2f3.len)
                        .setStreamBytesAckedByRetrans(0)
                        // no update due to out of order, f2 not received yet
                        .setMaybeNewDeliveryOffset(folly::none)
                        .build()))));
  }

  // deliver ACK for packet 4
  {
    const auto ackEvent = deliverAckForAppDataPackets(
        appDataPacketNumSent[3], appDataPacketNumSent[3]);

    // check ackedPackets
    EXPECT_THAT(
        ackEvent.ackedPackets,
        ElementsAre(
            // pkt4
            Field(
                &AckEvent::AckPacket::detailsPerStream,
                UnorderedElementsAre(
                    // s3f1
                    AckEventStreamDetailsMatcherBuilder()
                        .setStreamID(s3Id)
                        .setStreamBytesAcked(s3f1.len)
                        .setStreamBytesAckedByRetrans(0)
                        .setMaybeNewDeliveryOffset(s3f1.offset + s3f1.len)
                        .build()))));
  }

  // deliver ACK for packet 5
  {
    const auto ackEvent = deliverAckForAppDataPackets(
        appDataPacketNumSent[4], appDataPacketNumSent[4]);

    // check ackedPackets
    EXPECT_THAT(
        ackEvent.ackedPackets,
        ElementsAre(
            // pkt5
            Field(
                &AckEvent::AckPacket::detailsPerStream,
                UnorderedElementsAre(
                    // s1f4 w/ EOR
                    AckEventStreamDetailsMatcherBuilder()
                        .setStreamID(s1Id)
                        .setStreamBytesAcked(s1f4.len)
                        .setStreamBytesAckedByRetrans(0)
                        // no update due to out of order, f2 not received yet
                        .setMaybeNewDeliveryOffset(folly::none)
                        .build(),
                    // s2f4 w/ EOR
                    AckEventStreamDetailsMatcherBuilder()
                        .setStreamID(s2Id)
                        .setStreamBytesAcked(s2f4.len)
                        .setStreamBytesAckedByRetrans(0)
                        // no update due to out of order, f2 not received yet
                        .setMaybeNewDeliveryOffset(folly::none)
                        .build()))));
  }

  // deliver ACK for packet 2
  {
    const auto ackEvent = deliverAckForAppDataPackets(
        appDataPacketNumSent[1], appDataPacketNumSent[1]);

    // check ackedPackets
    EXPECT_THAT(
        ackEvent.ackedPackets,
        ElementsAre(
            // pkt2
            Field(
                &AckEvent::AckPacket::detailsPerStream,
                UnorderedElementsAre(
                    // s1f2
                    AckEventStreamDetailsMatcherBuilder()
                        .setStreamID(s1Id)
                        .setStreamBytesAcked(s1f2.len)
                        .setStreamBytesAckedByRetrans(0)
                        // f1 - f4 now done, delivery offset = end of f4
                        .setMaybeNewDeliveryOffset(s1f4.offset + s1f4.len)
                        .build(),
                    // s2f2
                    AckEventStreamDetailsMatcherBuilder()
                        .setStreamID(s2Id)
                        .setStreamBytesAcked(s2f2.len)
                        .setStreamBytesAckedByRetrans(0)
                        // f1 - f4 now done, delivery offset = end of f4
                        .setMaybeNewDeliveryOffset(s2f4.offset + s2f4.len)
                        .build()))));
  }
}

/**
 * Frames in packet two retransmitted in packet six.
 * Packet six ACKed, packet two never ACKed.
 */
TEST_F(AckEventForAppDataTest, AckEventMultiStreamPacketPacketTwoRetrans) {
  // prevent packets from being marked as lost
  // must initialize srtt and lrtt in parallel
  getConn()->lossState.srtt = 1ms;
  getConn()->lossState.lrtt = 1ms;
  getConn()->lossState.reorderingThreshold = 10;
  getConn()->transportSettings.timeReorderingThreshDividend = 1000;
  getConn()->transportSettings.timeReorderingThreshDivisor = 1;

  // two streams, both writing "hey whats up!" split across four frames
  auto s1Id =
      getConn()->streamManager->createNextBidirectionalStream().value()->id;
  auto s2Id =
      getConn()->streamManager->createNextBidirectionalStream().value()->id;
  auto s1f1 = writeDataToQuicStreamAndGetFrame(s1Id, "hey-", false);
  auto s2f1 = writeDataToQuicStreamAndGetFrame(s2Id, "hey ", false);
  auto s1f2 = writeDataToQuicStreamAndGetFrame(s1Id, "whats-", false);
  auto s2f2 = writeDataToQuicStreamAndGetFrame(s2Id, "whats ", false);
  auto s1f3 = writeDataToQuicStreamAndGetFrame(s1Id, "up-", false);
  auto s2f3 = writeDataToQuicStreamAndGetFrame(s2Id, "up ", false);
  auto s1f4 = writeDataToQuicStreamAndGetFrame(s1Id, "!", true);
  auto s2f4 = writeDataToQuicStreamAndGetFrame(s2Id, "!", true);

  // third stream in which "yt??" is written in a single frame
  auto s3Id =
      getConn()->streamManager->createNextBidirectionalStream().value()->id;
  auto s3f1 = writeDataToQuicStreamAndGetFrame(s3Id, "yt??", true);

  std::vector<PacketNum> appDataPacketNumSent;

  // packet 1, frame 1 from streams 1 & 2
  {
    auto packet = buildEmptyPacket(PacketNumberSpace::AppData);
    packet.packet.frames.push_back(s1f1);
    packet.packet.frames.push_back(s2f1);
    sendAppDataPacket(packet);
    appDataPacketNumSent.push_back(packet.packet.header.getPacketSequenceNum());
  }

  // packet 2, frame 2 from streams 1 & 2
  {
    auto packet = buildEmptyPacket(PacketNumberSpace::AppData);
    packet.packet.frames.push_back(s1f2);
    packet.packet.frames.push_back(s2f2);
    sendAppDataPacket(packet);
    appDataPacketNumSent.push_back(packet.packet.header.getPacketSequenceNum());
  }

  // packet 3, frame 3 from streams 1 & 2
  {
    auto packet = buildEmptyPacket(PacketNumberSpace::AppData);
    packet.packet.frames.push_back(s1f3);
    packet.packet.frames.push_back(s2f3);
    sendAppDataPacket(packet);
    appDataPacketNumSent.push_back(packet.packet.header.getPacketSequenceNum());
  }

  // packet 4, frame 1 from stream 3
  {
    auto packet = buildEmptyPacket(PacketNumberSpace::AppData);
    packet.packet.frames.push_back(s3f1);
    sendAppDataPacket(packet);
    appDataPacketNumSent.push_back(packet.packet.header.getPacketSequenceNum());
  }

  // packet 5, frame 4 from streams 1 & 2
  {
    auto packet = buildEmptyPacket(PacketNumberSpace::AppData);
    packet.packet.frames.push_back(s1f4);
    packet.packet.frames.push_back(s2f4);
    sendAppDataPacket(packet);
    appDataPacketNumSent.push_back(packet.packet.header.getPacketSequenceNum());
  }

  ASSERT_THAT(appDataPacketNumSent, SizeIs(5));

  // deliver ACK for packets 1, 3 - 5
  {
    AckBlocks blocks;
    blocks.insert(appDataPacketNumSent[0], appDataPacketNumSent[0]);
    blocks.insert(appDataPacketNumSent[2], appDataPacketNumSent[4]);
    const auto ackEvent = deliverAckForAppDataPackets(blocks);

    // check ackedPackets
    EXPECT_THAT(
        ackEvent.ackedPackets,
        ElementsAre(
            // pkt1
            Field(
                &AckEvent::AckPacket::detailsPerStream,
                UnorderedElementsAre(
                    // s1f1
                    AckEventStreamDetailsMatcherBuilder()
                        .setStreamID(s1Id)
                        .setStreamBytesAcked(s1f1.len)
                        .setStreamBytesAckedByRetrans(0)
                        .setMaybeNewDeliveryOffset(s1f1.offset + s1f1.len)
                        .build(),
                    // s2f1
                    AckEventStreamDetailsMatcherBuilder()
                        .setStreamID(s2Id)
                        .setStreamBytesAcked(s2f1.len)
                        .setStreamBytesAckedByRetrans(0)
                        .setMaybeNewDeliveryOffset(s1f1.offset + s1f1.len)
                        .build())),
            // pkt3
            Field(
                &AckEvent::AckPacket::detailsPerStream,
                UnorderedElementsAre(
                    // s1f3
                    AckEventStreamDetailsMatcherBuilder()
                        .setStreamID(s1Id)
                        .setStreamBytesAcked(s1f3.len)
                        .setStreamBytesAckedByRetrans(0)
                        // no update due to out of order, f2 not received yet
                        .setMaybeNewDeliveryOffset(folly::none)
                        .build(),
                    // s2f3
                    AckEventStreamDetailsMatcherBuilder()
                        .setStreamID(s2Id)
                        .setStreamBytesAcked(s2f3.len)
                        .setStreamBytesAckedByRetrans(0)
                        // no update due to out of order, f2 not received yet
                        .setMaybeNewDeliveryOffset(folly::none)
                        .build())),
            // pkt4
            Field(
                &AckEvent::AckPacket::detailsPerStream,
                UnorderedElementsAre(
                    // s3f1
                    AckEventStreamDetailsMatcherBuilder()
                        .setStreamID(s3Id)
                        .setStreamBytesAcked(s3f1.len)
                        .setStreamBytesAckedByRetrans(0)
                        // not affected by out of order
                        .setMaybeNewDeliveryOffset(s3f1.offset + s3f1.len)
                        .build())),
            // pkt5
            Field(
                &AckEvent::AckPacket::detailsPerStream,
                UnorderedElementsAre(
                    // s1f4 w/ EOR
                    AckEventStreamDetailsMatcherBuilder()
                        .setStreamID(s1Id)
                        .setStreamBytesAcked(s1f4.len)
                        .setStreamBytesAckedByRetrans(0)
                        // no update due to out of order, f2 not received yet
                        .setMaybeNewDeliveryOffset(folly::none)
                        .build(),
                    // s2f4 w/ EOR
                    AckEventStreamDetailsMatcherBuilder()
                        .setStreamID(s2Id)
                        .setStreamBytesAcked(s2f4.len)
                        .setStreamBytesAckedByRetrans(0)
                        // no update due to out of order, f2 not received yet
                        .setMaybeNewDeliveryOffset(folly::none)
                        .build()))));
  }

  // packet 6, frame 2 from streams 1 & 2 (retrans of frame packet 1)
  {
    auto packet = buildEmptyPacket(PacketNumberSpace::AppData);
    packet.packet.frames.push_back(s1f2);
    packet.packet.frames.push_back(s2f2);
    sendAppDataPacket(packet);
    appDataPacketNumSent.push_back(packet.packet.header.getPacketSequenceNum());
  }

  ASSERT_THAT(appDataPacketNumSent, SizeIs(6));

  // deliver ACK for packet 6
  {
    const auto ackEvent = deliverAckForAppDataPackets(
        appDataPacketNumSent[5], appDataPacketNumSent[5]);

    // check ackedPackets
    EXPECT_THAT(
        ackEvent.ackedPackets,
        ElementsAre(
            // pkt2
            Field(
                &AckEvent::AckPacket::detailsPerStream,
                UnorderedElementsAre(
                    // s1f1
                    AckEventStreamDetailsMatcherBuilder()
                        .setStreamID(s1Id)
                        .setStreamBytesAcked(s1f2.len)
                        .setStreamBytesAckedByRetrans(s1f2.len) // retrans
                        // f1 - f4 now done, delivery offset = end of f4
                        .setMaybeNewDeliveryOffset(s1f4.offset + s1f4.len)
                        .build(),
                    // s2f1
                    AckEventStreamDetailsMatcherBuilder()
                        .setStreamID(s2Id)
                        .setStreamBytesAcked(s2f2.len)
                        .setStreamBytesAckedByRetrans(s1f2.len) // retrans
                        // f1 - f4 now done, delivery offset = end of f4
                        .setMaybeNewDeliveryOffset(s2f4.offset + s2f4.len)
                        .build()))));
  }
}

/**
 * Frames in packet two retransmitted in packet six.
 * Packet two and packet six ACKed at the same time.
 *
 * No stream bytes should be recorded as ACKed (including by retransmission) for
 * packet six, since packet two already arrived. We will however record frames
 * as having been duplicate ACKed for packet six.
 */
TEST_F(
    AckEventForAppDataTest,
    AckEventMultiStreamPacketPacketTwoRetransSpuriousOrigAckedSameTime) {
  // prevent packets from being marked as lost
  // must initialize srtt and lrtt in parallel
  getConn()->lossState.srtt = 1ms;
  getConn()->lossState.lrtt = 1ms;
  getConn()->lossState.reorderingThreshold = 10;
  getConn()->transportSettings.timeReorderingThreshDividend = 1000;
  getConn()->transportSettings.timeReorderingThreshDivisor = 1;

  // two streams, both writing "hey whats up!" split across four frames
  auto s1Id =
      getConn()->streamManager->createNextBidirectionalStream().value()->id;
  auto s2Id =
      getConn()->streamManager->createNextBidirectionalStream().value()->id;
  auto s1f1 = writeDataToQuicStreamAndGetFrame(s1Id, "hey-", false);
  auto s2f1 = writeDataToQuicStreamAndGetFrame(s2Id, "hey ", false);
  auto s1f2 = writeDataToQuicStreamAndGetFrame(s1Id, "whats-", false);
  auto s2f2 = writeDataToQuicStreamAndGetFrame(s2Id, "whats ", false);
  auto s1f3 = writeDataToQuicStreamAndGetFrame(s1Id, "up-", false);
  auto s2f3 = writeDataToQuicStreamAndGetFrame(s2Id, "up ", false);
  auto s1f4 = writeDataToQuicStreamAndGetFrame(s1Id, "!", true);
  auto s2f4 = writeDataToQuicStreamAndGetFrame(s2Id, "!", true);

  // third stream in which "yt??" is written in a single frame
  auto s3Id =
      getConn()->streamManager->createNextBidirectionalStream().value()->id;
  auto s3f1 = writeDataToQuicStreamAndGetFrame(s3Id, "yt??", true);

  std::vector<PacketNum> appDataPacketNumSent;

  // packet 1, frame 1 from streams 1 & 2
  {
    auto packet = buildEmptyPacket(PacketNumberSpace::AppData);
    packet.packet.frames.push_back(s1f1);
    packet.packet.frames.push_back(s2f1);
    sendAppDataPacket(packet);
    appDataPacketNumSent.push_back(packet.packet.header.getPacketSequenceNum());
  }

  // packet 2, frame 2 from streams 1 & 2
  {
    auto packet = buildEmptyPacket(PacketNumberSpace::AppData);
    packet.packet.frames.push_back(s1f2);
    packet.packet.frames.push_back(s2f2);
    sendAppDataPacket(packet);
    appDataPacketNumSent.push_back(packet.packet.header.getPacketSequenceNum());
  }

  // packet 3, frame 3 from streams 1 & 2
  {
    auto packet = buildEmptyPacket(PacketNumberSpace::AppData);
    packet.packet.frames.push_back(s1f3);
    packet.packet.frames.push_back(s2f3);
    sendAppDataPacket(packet);
    appDataPacketNumSent.push_back(packet.packet.header.getPacketSequenceNum());
  }

  // packet 4, frame 1 from stream 3
  {
    auto packet = buildEmptyPacket(PacketNumberSpace::AppData);
    packet.packet.frames.push_back(s3f1);
    sendAppDataPacket(packet);
    appDataPacketNumSent.push_back(packet.packet.header.getPacketSequenceNum());
  }

  // packet 5, frame 4 from streams 1 & 2
  {
    auto packet = buildEmptyPacket(PacketNumberSpace::AppData);
    packet.packet.frames.push_back(s1f4);
    packet.packet.frames.push_back(s2f4);
    sendAppDataPacket(packet);
    appDataPacketNumSent.push_back(packet.packet.header.getPacketSequenceNum());
  }

  ASSERT_THAT(appDataPacketNumSent, SizeIs(5));

  // deliver ACK for packets 1, 3 - 5
  {
    AckBlocks blocks;
    blocks.insert(appDataPacketNumSent[0], appDataPacketNumSent[0]);
    blocks.insert(appDataPacketNumSent[2], appDataPacketNumSent[4]);
    const auto ackEvent = deliverAckForAppDataPackets(blocks);

    // check ackedPackets
    EXPECT_THAT(
        ackEvent.ackedPackets,
        ElementsAre(
            // pkt1
            Field(
                &AckEvent::AckPacket::detailsPerStream,
                UnorderedElementsAre(
                    // s1f1
                    AckEventStreamDetailsMatcherBuilder()
                        .setStreamID(s1Id)
                        .setStreamBytesAcked(s1f1.len)
                        .setStreamBytesAckedByRetrans(0)
                        .setMaybeNewDeliveryOffset(s1f1.offset + s1f1.len)
                        .build(),
                    // s2f1
                    AckEventStreamDetailsMatcherBuilder()
                        .setStreamID(s2Id)
                        .setStreamBytesAcked(s2f1.len)
                        .setStreamBytesAckedByRetrans(0)
                        .setMaybeNewDeliveryOffset(s1f1.offset + s1f1.len)
                        .build())),
            // pkt3
            Field(
                &AckEvent::AckPacket::detailsPerStream,
                UnorderedElementsAre(
                    // s1f3
                    AckEventStreamDetailsMatcherBuilder()
                        .setStreamID(s1Id)
                        .setStreamBytesAcked(s1f3.len)
                        .setStreamBytesAckedByRetrans(0)
                        // no update due to out of order, f2 not received yet
                        .setMaybeNewDeliveryOffset(folly::none)
                        .build(),
                    // s2f3
                    AckEventStreamDetailsMatcherBuilder()
                        .setStreamID(s2Id)
                        .setStreamBytesAcked(s2f3.len)
                        .setStreamBytesAckedByRetrans(0)
                        // no update due to out of order, f2 not received yet
                        .setMaybeNewDeliveryOffset(folly::none)
                        .build())),
            // pkt4
            Field(
                &AckEvent::AckPacket::detailsPerStream,
                UnorderedElementsAre(
                    // s3f1
                    AckEventStreamDetailsMatcherBuilder()
                        .setStreamID(s3Id)
                        .setStreamBytesAcked(s3f1.len)
                        .setStreamBytesAckedByRetrans(0)
                        // not affected by out of order
                        .setMaybeNewDeliveryOffset(s3f1.offset + s3f1.len)
                        .build())),
            // pkt5
            Field(
                &AckEvent::AckPacket::detailsPerStream,
                UnorderedElementsAre(
                    // s1f4 w/ EOR
                    AckEventStreamDetailsMatcherBuilder()
                        .setStreamID(s1Id)
                        .setStreamBytesAcked(s1f4.len)
                        .setStreamBytesAckedByRetrans(0)
                        // no update due to out of order, f2 not received yet
                        .setMaybeNewDeliveryOffset(folly::none)
                        .build(),
                    // s2f4 w/ EOR
                    AckEventStreamDetailsMatcherBuilder()
                        .setStreamID(s2Id)
                        .setStreamBytesAcked(s2f4.len)
                        .setStreamBytesAckedByRetrans(0)
                        // no update due to out of order, f2 not received yet
                        .setMaybeNewDeliveryOffset(folly::none)
                        .build()))));
  }

  // packet 6, frame 2 from streams 1 & 2 (retrans of frame packet 1)
  {
    auto packet = buildEmptyPacket(PacketNumberSpace::AppData);
    packet.packet.frames.push_back(s1f2);
    packet.packet.frames.push_back(s2f2);
    sendAppDataPacket(packet);
    appDataPacketNumSent.push_back(packet.packet.header.getPacketSequenceNum());
  }

  ASSERT_THAT(appDataPacketNumSent, SizeIs(6));

  // deliver ACK for packets 2 and 6
  {
    AckBlocks blocks;
    blocks.insert(appDataPacketNumSent[1], appDataPacketNumSent[1]);
    blocks.insert(appDataPacketNumSent[5], appDataPacketNumSent[5]);
    const auto ackEvent = deliverAckForAppDataPackets(blocks);

    // check ackedPackets
    EXPECT_THAT(
        ackEvent.ackedPackets,
        ElementsAre(
            // pkt2
            Field(
                &AckEvent::AckPacket::detailsPerStream,
                UnorderedElementsAre(
                    // s1f1
                    AckEventStreamDetailsMatcherBuilder()
                        .setStreamID(s1Id)
                        .setStreamBytesAcked(s1f2.len)
                        .setStreamBytesAckedByRetrans(0) // original arrived
                        // f1 - f4 now done, delivery offset = end of f4
                        .setMaybeNewDeliveryOffset(s1f4.offset + s1f4.len)
                        .build(),
                    // s2f1
                    AckEventStreamDetailsMatcherBuilder()
                        .setStreamID(s2Id)
                        .setStreamBytesAcked(s2f2.len)
                        .setStreamBytesAckedByRetrans(0) // original arrived
                        // f1 - f4 now done, delivery offset = end of f4
                        .setMaybeNewDeliveryOffset(s2f4.offset + s2f4.len)
                        .build())),
            // pkt6
            Field(
                &AckEvent::AckPacket::detailsPerStream,
                UnorderedElementsAre(
                    // s1f1
                    AckEventStreamDetailsMatcherBuilder()
                        .setStreamID(s1Id)
                        .setStreamBytesAcked(0) // original arrived
                        .setStreamBytesAckedByRetrans(0) // original arrived
                        // no change, since already ACKed by original
                        .setMaybeNewDeliveryOffset(folly::none)
                        // retrans ACKed after original, thus making f2 dupacked
                        .addDupAckedStreamInterval(
                            s1f2.offset, s1f2.offset + s1f2.len - 1)
                        .build(),
                    // s2f1
                    AckEventStreamDetailsMatcherBuilder()
                        .setStreamID(s2Id)
                        .setStreamBytesAcked(0) // original arrived
                        .setStreamBytesAckedByRetrans(0) // original arrived
                        // no change, since already ACKed by original
                        .setMaybeNewDeliveryOffset(folly::none)
                        // retrans ACKed after original, thus making f2 dupacked
                        .addDupAckedStreamInterval(
                            s2f2.offset, s2f2.offset + s2f2.len - 1)
                        .build()))));
  }
}

/**
 * Frames in packet two retransmitted in packet six.
 * Packet six ACKed, then two ACKed.
 *
 * Stream bytes should be recorded for packet six as ACKed by retransmission.
 *
 * No stream bytes should be recorded as ACKed (including by retransmission) for
 * packet two, since packet six already arrived. We will however record frames
 * as having been duplicate ACKed for packet two.
 */
TEST_F(
    AckEventForAppDataTest,
    AckEventMultiStreamPacketPacketTwoRetransSpuriousOrigThenRetransAcked) {
  // prevent packets from being marked as lost
  // must initialize srtt and lrtt in parallel
  getConn()->lossState.srtt = 1ms;
  getConn()->lossState.lrtt = 1ms;
  getConn()->lossState.reorderingThreshold = 10;
  getConn()->transportSettings.timeReorderingThreshDividend = 1000;
  getConn()->transportSettings.timeReorderingThreshDivisor = 1;

  // two streams, both writing "hey whats up!" split across four frames
  auto s1Id =
      getConn()->streamManager->createNextBidirectionalStream().value()->id;
  auto s2Id =
      getConn()->streamManager->createNextBidirectionalStream().value()->id;
  auto s1f1 = writeDataToQuicStreamAndGetFrame(s1Id, "hey-", false);
  auto s2f1 = writeDataToQuicStreamAndGetFrame(s2Id, "hey ", false);
  auto s1f2 = writeDataToQuicStreamAndGetFrame(s1Id, "whats-", false);
  auto s2f2 = writeDataToQuicStreamAndGetFrame(s2Id, "whats ", false);
  auto s1f3 = writeDataToQuicStreamAndGetFrame(s1Id, "up-", false);
  auto s2f3 = writeDataToQuicStreamAndGetFrame(s2Id, "up ", false);
  auto s1f4 = writeDataToQuicStreamAndGetFrame(s1Id, "!", true);
  auto s2f4 = writeDataToQuicStreamAndGetFrame(s2Id, "!", true);

  // third stream in which "yt??" is written in a single frame
  auto s3Id =
      getConn()->streamManager->createNextBidirectionalStream().value()->id;
  auto s3f1 = writeDataToQuicStreamAndGetFrame(s3Id, "yt??", true);

  std::vector<PacketNum> appDataPacketNumSent;

  // packet 1, frame 1 from streams 1 & 2
  {
    auto packet = buildEmptyPacket(PacketNumberSpace::AppData);
    packet.packet.frames.push_back(s1f1);
    packet.packet.frames.push_back(s2f1);
    sendAppDataPacket(packet);
    appDataPacketNumSent.push_back(packet.packet.header.getPacketSequenceNum());
  }

  // packet 2, frame 2 from streams 1 & 2
  {
    auto packet = buildEmptyPacket(PacketNumberSpace::AppData);
    packet.packet.frames.push_back(s1f2);
    packet.packet.frames.push_back(s2f2);
    sendAppDataPacket(packet);
    appDataPacketNumSent.push_back(packet.packet.header.getPacketSequenceNum());
  }

  // packet 3, frame 3 from streams 1 & 2
  {
    auto packet = buildEmptyPacket(PacketNumberSpace::AppData);
    packet.packet.frames.push_back(s1f3);
    packet.packet.frames.push_back(s2f3);
    sendAppDataPacket(packet);
    appDataPacketNumSent.push_back(packet.packet.header.getPacketSequenceNum());
  }

  // packet 4, frame 1 from stream 3
  {
    auto packet = buildEmptyPacket(PacketNumberSpace::AppData);
    packet.packet.frames.push_back(s3f1);
    sendAppDataPacket(packet);
    appDataPacketNumSent.push_back(packet.packet.header.getPacketSequenceNum());
  }

  // packet 5, frame 4 from streams 1 & 2
  {
    auto packet = buildEmptyPacket(PacketNumberSpace::AppData);
    packet.packet.frames.push_back(s1f4);
    packet.packet.frames.push_back(s2f4);
    sendAppDataPacket(packet);
    appDataPacketNumSent.push_back(packet.packet.header.getPacketSequenceNum());
  }

  ASSERT_THAT(appDataPacketNumSent, SizeIs(5));

  // deliver ACK for packets 1, 3 - 5
  {
    AckBlocks blocks;
    blocks.insert(appDataPacketNumSent[0], appDataPacketNumSent[0]);
    blocks.insert(appDataPacketNumSent[2], appDataPacketNumSent[4]);
    const auto ackEvent = deliverAckForAppDataPackets(blocks);

    // check ackedPackets
    EXPECT_THAT(
        ackEvent.ackedPackets,
        ElementsAre(
            // pkt1
            Field(
                &AckEvent::AckPacket::detailsPerStream,
                UnorderedElementsAre(
                    // s1f1
                    AckEventStreamDetailsMatcherBuilder()
                        .setStreamID(s1Id)
                        .setStreamBytesAcked(s1f1.len)
                        .setStreamBytesAckedByRetrans(0)
                        .setMaybeNewDeliveryOffset(s1f1.offset + s1f1.len)
                        .build(),
                    // s2f1
                    AckEventStreamDetailsMatcherBuilder()
                        .setStreamID(s2Id)
                        .setStreamBytesAcked(s2f1.len)
                        .setStreamBytesAckedByRetrans(0)
                        .setMaybeNewDeliveryOffset(s1f1.offset + s1f1.len)
                        .build())),
            // pkt3
            Field(
                &AckEvent::AckPacket::detailsPerStream,
                UnorderedElementsAre(
                    // s1f3
                    AckEventStreamDetailsMatcherBuilder()
                        .setStreamID(s1Id)
                        .setStreamBytesAcked(s1f3.len)
                        .setStreamBytesAckedByRetrans(0)
                        // no update due to out of order, f2 not received yet
                        .setMaybeNewDeliveryOffset(folly::none)
                        .build(),
                    // s2f3
                    AckEventStreamDetailsMatcherBuilder()
                        .setStreamID(s2Id)
                        .setStreamBytesAcked(s2f3.len)
                        .setStreamBytesAckedByRetrans(0)
                        // no update due to out of order, f2 not received yet
                        .setMaybeNewDeliveryOffset(folly::none)
                        .build())),
            // pkt4
            Field(
                &AckEvent::AckPacket::detailsPerStream,
                UnorderedElementsAre(
                    // s3f1
                    AckEventStreamDetailsMatcherBuilder()
                        .setStreamID(s3Id)
                        .setStreamBytesAcked(s3f1.len)
                        .setStreamBytesAckedByRetrans(0)
                        // not affected by out of order
                        .setMaybeNewDeliveryOffset(s3f1.offset + s3f1.len)
                        .build())),
            // pkt5
            Field(
                &AckEvent::AckPacket::detailsPerStream,
                UnorderedElementsAre(
                    // s1f4 w/ EOR
                    AckEventStreamDetailsMatcherBuilder()
                        .setStreamID(s1Id)
                        .setStreamBytesAcked(s1f4.len)
                        .setStreamBytesAckedByRetrans(0)
                        // no update due to out of order, f2 not received yet
                        .setMaybeNewDeliveryOffset(folly::none)
                        .build(),
                    // s2f4 w/ EOR
                    AckEventStreamDetailsMatcherBuilder()
                        .setStreamID(s2Id)
                        .setStreamBytesAcked(s2f4.len)
                        .setStreamBytesAckedByRetrans(0)
                        // no update due to out of order, f2 not received yet
                        .setMaybeNewDeliveryOffset(folly::none)
                        .build()))));
  }

  // packet 6, frame 2 from streams 1 & 2 (retrans of frame packet 1)
  {
    auto packet = buildEmptyPacket(PacketNumberSpace::AppData);
    packet.packet.frames.push_back(s1f2);
    packet.packet.frames.push_back(s2f2);
    sendAppDataPacket(packet);
    appDataPacketNumSent.push_back(packet.packet.header.getPacketSequenceNum());
  }

  ASSERT_THAT(appDataPacketNumSent, SizeIs(6));

  // deliver ACK for packet 6
  {
    const auto ackEvent = deliverAckForAppDataPackets(
        appDataPacketNumSent[5], appDataPacketNumSent[5]);

    // check ackedPackets
    EXPECT_THAT(
        ackEvent.ackedPackets,
        ElementsAre(
            // pkt6
            Field(
                &AckEvent::AckPacket::detailsPerStream,
                UnorderedElementsAre(
                    // s1f1
                    AckEventStreamDetailsMatcherBuilder()
                        .setStreamID(s1Id)
                        .setStreamBytesAcked(s1f2.len)
                        .setStreamBytesAckedByRetrans(s1f2.len)
                        // f1 - f4 now done, delivery offset = end of f4
                        .setMaybeNewDeliveryOffset(s1f4.offset + s1f4.len)
                        .build(),
                    // s2f1
                    AckEventStreamDetailsMatcherBuilder()
                        .setStreamID(s2Id)
                        .setStreamBytesAcked(s2f2.len)
                        .setStreamBytesAckedByRetrans(s2f2.len)
                        // f1 - f4 now done, delivery offset = end of f4
                        .setMaybeNewDeliveryOffset(s2f4.offset + s2f4.len)
                        .build()))));
  }

  // deliver ACK for packet 2
  {
    const auto ackEvent = deliverAckForAppDataPackets(
        appDataPacketNumSent[1], appDataPacketNumSent[1]);

    // check ackedPackets
    EXPECT_THAT(
        ackEvent.ackedPackets,
        ElementsAre(
            // pkt2
            Field(
                &AckEvent::AckPacket::detailsPerStream,
                UnorderedElementsAre(
                    // s1f1
                    AckEventStreamDetailsMatcherBuilder()
                        .setStreamID(s1Id)
                        .setStreamBytesAcked(0) // retrans ACKed earlier
                        .setStreamBytesAckedByRetrans(0) // retrans ACK earlier
                        // no change, since already ACKed by retrans
                        .setMaybeNewDeliveryOffset(folly::none)
                        // orig ACKed after retrans, thus making f2 dupacked
                        .addDupAckedStreamInterval(
                            s1f2.offset, s1f2.offset + s1f2.len - 1)
                        .build(),
                    // s2f1
                    AckEventStreamDetailsMatcherBuilder()
                        .setStreamID(s2Id)
                        .setStreamBytesAcked(0) // retrans ACKed earlier
                        .setStreamBytesAckedByRetrans(0) // retrans ACK earlier
                        // no change, since already ACKed by retrans
                        .setMaybeNewDeliveryOffset(folly::none)
                        // orig ACKed after retrans, thus making f2 dupacked
                        .addDupAckedStreamInterval(
                            s2f2.offset, s2f2.offset + s2f2.len - 1)
                        .build()))));
  }
}

/**
 * Frames in packet two retransmitted in packet six.
 * Packet two ACKed, then six ACKed.
 *
 * No stream bytes should be recorded as ACKed (including by retransmission) for
 * packet six, since packet two already arrived. We will however record frames
 * as having been duplicate ACKed for packet six.
 */
TEST_F(
    AckEventForAppDataTest,
    AckEventMultiStreamPacketPacketTwoRetransSpuriousRetransThenOrigAcked) {
  // prevent packets from being marked as lost
  // must initialize srtt and lrtt in parallel
  getConn()->lossState.srtt = 1ms;
  getConn()->lossState.lrtt = 1ms;
  getConn()->lossState.reorderingThreshold = 10;
  getConn()->transportSettings.timeReorderingThreshDividend = 1000;
  getConn()->transportSettings.timeReorderingThreshDivisor = 1;

  // two streams, both writing "hey whats up!" split across four frames
  auto s1Id =
      getConn()->streamManager->createNextBidirectionalStream().value()->id;
  auto s2Id =
      getConn()->streamManager->createNextBidirectionalStream().value()->id;
  auto s1f1 = writeDataToQuicStreamAndGetFrame(s1Id, "hey-", false);
  auto s2f1 = writeDataToQuicStreamAndGetFrame(s2Id, "hey ", false);
  auto s1f2 = writeDataToQuicStreamAndGetFrame(s1Id, "whats-", false);
  auto s2f2 = writeDataToQuicStreamAndGetFrame(s2Id, "whats ", false);
  auto s1f3 = writeDataToQuicStreamAndGetFrame(s1Id, "up-", false);
  auto s2f3 = writeDataToQuicStreamAndGetFrame(s2Id, "up ", false);
  auto s1f4 = writeDataToQuicStreamAndGetFrame(s1Id, "!", true);
  auto s2f4 = writeDataToQuicStreamAndGetFrame(s2Id, "!", true);

  // third stream in which "yt??" is written in a single frame
  auto s3Id =
      getConn()->streamManager->createNextBidirectionalStream().value()->id;
  auto s3f1 = writeDataToQuicStreamAndGetFrame(s3Id, "yt??", true);

  std::vector<PacketNum> appDataPacketNumSent;

  // packet 1, frame 1 from streams 1 & 2
  {
    auto packet = buildEmptyPacket(PacketNumberSpace::AppData);
    packet.packet.frames.push_back(s1f1);
    packet.packet.frames.push_back(s2f1);
    sendAppDataPacket(packet);
    appDataPacketNumSent.push_back(packet.packet.header.getPacketSequenceNum());
  }

  // packet 2, frame 2 from streams 1 & 2
  {
    auto packet = buildEmptyPacket(PacketNumberSpace::AppData);
    packet.packet.frames.push_back(s1f2);
    packet.packet.frames.push_back(s2f2);
    sendAppDataPacket(packet);
    appDataPacketNumSent.push_back(packet.packet.header.getPacketSequenceNum());
  }

  // packet 3, frame 3 from streams 1 & 2
  {
    auto packet = buildEmptyPacket(PacketNumberSpace::AppData);
    packet.packet.frames.push_back(s1f3);
    packet.packet.frames.push_back(s2f3);
    sendAppDataPacket(packet);
    appDataPacketNumSent.push_back(packet.packet.header.getPacketSequenceNum());
  }

  // packet 4, frame 1 from stream 3
  {
    auto packet = buildEmptyPacket(PacketNumberSpace::AppData);
    packet.packet.frames.push_back(s3f1);
    sendAppDataPacket(packet);
    appDataPacketNumSent.push_back(packet.packet.header.getPacketSequenceNum());
  }

  // packet 5, frame 4 from streams 1 & 2
  {
    auto packet = buildEmptyPacket(PacketNumberSpace::AppData);
    packet.packet.frames.push_back(s1f4);
    packet.packet.frames.push_back(s2f4);
    sendAppDataPacket(packet);
    appDataPacketNumSent.push_back(packet.packet.header.getPacketSequenceNum());
  }

  ASSERT_THAT(appDataPacketNumSent, SizeIs(5));

  // deliver ACK for packets 1, 3 - 5
  {
    AckBlocks blocks;
    blocks.insert(appDataPacketNumSent[0], appDataPacketNumSent[0]);
    blocks.insert(appDataPacketNumSent[2], appDataPacketNumSent[4]);
    const auto ackEvent = deliverAckForAppDataPackets(blocks);

    // check ackedPackets
    EXPECT_THAT(
        ackEvent.ackedPackets,
        ElementsAre(
            // pkt1
            Field(
                &AckEvent::AckPacket::detailsPerStream,
                UnorderedElementsAre(
                    // s1f1
                    AckEventStreamDetailsMatcherBuilder()
                        .setStreamID(s1Id)
                        .setStreamBytesAcked(s1f1.len)
                        .setStreamBytesAckedByRetrans(0)
                        .setMaybeNewDeliveryOffset(s1f1.offset + s1f1.len)
                        .build(),
                    // s2f1
                    AckEventStreamDetailsMatcherBuilder()
                        .setStreamID(s2Id)
                        .setStreamBytesAcked(s2f1.len)
                        .setStreamBytesAckedByRetrans(0)
                        .setMaybeNewDeliveryOffset(s1f1.offset + s1f1.len)
                        .build())),
            // pkt3
            Field(
                &AckEvent::AckPacket::detailsPerStream,
                UnorderedElementsAre(
                    // s1f3
                    AckEventStreamDetailsMatcherBuilder()
                        .setStreamID(s1Id)
                        .setStreamBytesAcked(s1f3.len)
                        .setStreamBytesAckedByRetrans(0)
                        // no update due to out of order, f2 not received yet
                        .setMaybeNewDeliveryOffset(folly::none)
                        .build(),
                    // s2f3
                    AckEventStreamDetailsMatcherBuilder()
                        .setStreamID(s2Id)
                        .setStreamBytesAcked(s2f3.len)
                        .setStreamBytesAckedByRetrans(0)
                        // no update due to out of order, f2 not received yet
                        .setMaybeNewDeliveryOffset(folly::none)
                        .build())),
            // pkt4
            Field(
                &AckEvent::AckPacket::detailsPerStream,
                UnorderedElementsAre(
                    // s3f1
                    AckEventStreamDetailsMatcherBuilder()
                        .setStreamID(s3Id)
                        .setStreamBytesAcked(s3f1.len)
                        .setStreamBytesAckedByRetrans(0)
                        // not affected by out of order
                        .setMaybeNewDeliveryOffset(s3f1.offset + s3f1.len)
                        .build())),
            // pkt5
            Field(
                &AckEvent::AckPacket::detailsPerStream,
                UnorderedElementsAre(
                    // s1f4 w/ EOR
                    AckEventStreamDetailsMatcherBuilder()
                        .setStreamID(s1Id)
                        .setStreamBytesAcked(s1f4.len)
                        .setStreamBytesAckedByRetrans(0)
                        // no update due to out of order, f2 not received yet
                        .setMaybeNewDeliveryOffset(folly::none)
                        .build(),
                    // s2f4 w/ EOR
                    AckEventStreamDetailsMatcherBuilder()
                        .setStreamID(s2Id)
                        .setStreamBytesAcked(s2f4.len)
                        .setStreamBytesAckedByRetrans(0)
                        // no update due to out of order, f2 not received yet
                        .setMaybeNewDeliveryOffset(folly::none)
                        .build()))));
  }

  // packet 6, frame 2 from streams 1 & 2 (retrans of frame packet 1)
  {
    auto packet = buildEmptyPacket(PacketNumberSpace::AppData);
    packet.packet.frames.push_back(s1f2);
    packet.packet.frames.push_back(s2f2);
    sendAppDataPacket(packet);
    appDataPacketNumSent.push_back(packet.packet.header.getPacketSequenceNum());
  }

  ASSERT_THAT(appDataPacketNumSent, SizeIs(6));

  // deliver ACK for packet 2
  {
    const auto ackEvent = deliverAckForAppDataPackets(
        appDataPacketNumSent[1], appDataPacketNumSent[1]);

    // check ackedPackets
    EXPECT_THAT(
        ackEvent.ackedPackets,
        ElementsAre(
            // pkt2
            Field(
                &AckEvent::AckPacket::detailsPerStream,
                UnorderedElementsAre(
                    // s1f1
                    AckEventStreamDetailsMatcherBuilder()
                        .setStreamID(s1Id)
                        .setStreamBytesAcked(s1f2.len)
                        .setStreamBytesAckedByRetrans(0) // original arrived
                        // f1 - f4 now done, delivery offset = end of f4
                        .setMaybeNewDeliveryOffset(s1f4.offset + s1f4.len)
                        .build(),
                    // s2f1
                    AckEventStreamDetailsMatcherBuilder()
                        .setStreamID(s2Id)
                        .setStreamBytesAcked(s2f2.len)
                        .setStreamBytesAckedByRetrans(0) // original arrived
                        // f1 - f4 now done, delivery offset = end of f4
                        .setMaybeNewDeliveryOffset(s2f4.offset + s2f4.len)
                        .build()))));
  }

  // deliver ACK for packet 6
  {
    const auto ackEvent = deliverAckForAppDataPackets(
        appDataPacketNumSent[5], appDataPacketNumSent[5]);

    // check ackedPackets
    EXPECT_THAT(
        ackEvent.ackedPackets,
        ElementsAre(
            // pkt6
            Field(
                &AckEvent::AckPacket::detailsPerStream,
                UnorderedElementsAre(
                    // s1f1
                    AckEventStreamDetailsMatcherBuilder()
                        .setStreamID(s1Id)
                        .setStreamBytesAcked(0) // original arrived
                        .setStreamBytesAckedByRetrans(0) // original arrived
                        // no change, since already ACKed by original
                        .setMaybeNewDeliveryOffset(folly::none)
                        // retrans ACKed after original, thus making f2 dupacked
                        .addDupAckedStreamInterval(
                            s1f2.offset, s1f2.offset + s1f2.len - 1)
                        .build(),
                    // s2f1
                    AckEventStreamDetailsMatcherBuilder()
                        .setStreamID(s2Id)
                        .setStreamBytesAcked(0) // original arrived
                        .setStreamBytesAckedByRetrans(0) // original arrived
                        // no change, since already ACKed by original
                        .setMaybeNewDeliveryOffset(folly::none)
                        // retrans ACKed after original, thus making f2 dupacked
                        .addDupAckedStreamInterval(
                            s2f2.offset, s2f2.offset + s2f2.len - 1)
                        .build()))));
  }
}

/**
 * Frame retransmitted in a packet with a new frame (new data) for same stream.
 * Second packet ACKed, original never ACKed.
 */
TEST_F(AckEventForAppDataTest, AckEventRetransHasNewFrame) {
  // prevent packets from being marked as lost
  // must initialize srtt and lrtt in parallel
  getConn()->lossState.srtt = 1ms;
  getConn()->lossState.lrtt = 1ms;
  getConn()->lossState.reorderingThreshold = 10;
  getConn()->transportSettings.timeReorderingThreshDividend = 1000;
  getConn()->transportSettings.timeReorderingThreshDivisor = 1;

  // two writes
  auto s1Id =
      getConn()->streamManager->createNextBidirectionalStream().value()->id;
  auto s1f1 = writeDataToQuicStreamAndGetFrame(s1Id, "hey-", false);
  auto s1f2 = writeDataToQuicStreamAndGetFrame(s1Id, "whats-", false);

  std::vector<PacketNum> appDataPacketNumSent;

  // packet 1, frame 1 from stream 1
  {
    auto packet = buildEmptyPacket(PacketNumberSpace::AppData);
    packet.packet.frames.push_back(s1f1);
    sendAppDataPacket(packet);
    appDataPacketNumSent.push_back(packet.packet.header.getPacketSequenceNum());
  }

  // packet 2, frames 1 and 2 from stream 1
  {
    auto packet = buildEmptyPacket(PacketNumberSpace::AppData);
    packet.packet.frames.push_back(s1f1);
    packet.packet.frames.push_back(s1f2);
    sendAppDataPacket(packet);
    appDataPacketNumSent.push_back(packet.packet.header.getPacketSequenceNum());
  }

  ASSERT_THAT(appDataPacketNumSent, SizeIs(2));

  // deliver ACK for packet2
  {
    const auto ackEvent = deliverAckForAppDataPackets(
        appDataPacketNumSent[1], appDataPacketNumSent[1]);

    // check ackedPackets
    EXPECT_THAT(
        ackEvent.ackedPackets,
        ElementsAre(
            // pkt2
            Field(
                &AckEvent::AckPacket::detailsPerStream,
                UnorderedElementsAre(
                    // s1f1 + s1f2
                    AckEventStreamDetailsMatcherBuilder()
                        .setStreamID(s1Id)
                        .setStreamBytesAcked(s1f1.len + s1f2.len)
                        .setStreamBytesAckedByRetrans(s1f1.len)
                        .setMaybeNewDeliveryOffset(s1f2.offset + s1f2.len)
                        .build()))));
  }
}

/**
 * Frame retransmitted in a packet with a new frame (new data) for same stream.
 * Original and second packet ACKed at same time (spurious).
 */
TEST_F(
    AckEventForAppDataTest,
    AckEventRetransHasNewFrameSpuriousOrigAckedSameTime) {
  // prevent packets from being marked as lost
  // must initialize srtt and lrtt in parallel
  getConn()->lossState.srtt = 1ms;
  getConn()->lossState.lrtt = 1ms;
  getConn()->lossState.reorderingThreshold = 10;
  getConn()->transportSettings.timeReorderingThreshDividend = 1000;
  getConn()->transportSettings.timeReorderingThreshDivisor = 1;

  // two writes
  auto s1Id =
      getConn()->streamManager->createNextBidirectionalStream().value()->id;
  auto s1f1 = writeDataToQuicStreamAndGetFrame(s1Id, "hey-", false);
  auto s1f2 = writeDataToQuicStreamAndGetFrame(s1Id, "whats-", false);

  std::vector<PacketNum> appDataPacketNumSent;

  // packet 1, frame 1 from stream 1
  {
    auto packet = buildEmptyPacket(PacketNumberSpace::AppData);
    packet.packet.frames.push_back(s1f1);
    sendAppDataPacket(packet);
    appDataPacketNumSent.push_back(packet.packet.header.getPacketSequenceNum());
  }

  // packet 2, frames 1 and 2 from stream 1
  {
    auto packet = buildEmptyPacket(PacketNumberSpace::AppData);
    packet.packet.frames.push_back(s1f1);
    packet.packet.frames.push_back(s1f2);
    sendAppDataPacket(packet);
    appDataPacketNumSent.push_back(packet.packet.header.getPacketSequenceNum());
  }

  ASSERT_THAT(appDataPacketNumSent, SizeIs(2));

  // deliver ACK for packets 1 and 2
  {
    const auto ackEvent = deliverAckForAppDataPackets(
        appDataPacketNumSent[0], appDataPacketNumSent[1]);

    // check ackedPackets
    EXPECT_THAT(
        ackEvent.ackedPackets,
        ElementsAre(
            // pkt1
            Field(
                &AckEvent::AckPacket::detailsPerStream,
                UnorderedElementsAre(
                    AckEventStreamDetailsMatcherBuilder()
                        .setStreamID(s1Id)
                        .setStreamBytesAcked(s1f1.len)
                        .setStreamBytesAckedByRetrans(0)
                        .setMaybeNewDeliveryOffset(s1f1.offset + s1f1.len)
                        .build())),
            // pkt2
            Field(
                &AckEvent::AckPacket::detailsPerStream,
                UnorderedElementsAre(
                    AckEventStreamDetailsMatcherBuilder()
                        .setStreamID(s1Id)
                        .setStreamBytesAcked(s1f2.len) // only f2
                        .setStreamBytesAckedByRetrans(0) // f1 ACKed earlier
                        // moved forward to f2
                        .setMaybeNewDeliveryOffset(s1f2.offset + s1f2.len)
                        // retrans ACKed after original, thus making f1 dupacked
                        .addDupAckedStreamInterval(
                            s1f1.offset, s1f1.offset + s1f1.len - 1)
                        .build()))));
  }
}

/**
 * Frame retransmitted in a packet with a new frame (new data) for same stream.
 * Original packet ACKed then second packet ACKed (spurious retrans).
 */
TEST_F(
    AckEventForAppDataTest,
    AckEventRetransHasNewFrameSpuriousOrigThenRetransAcked) {
  // prevent packets from being marked as lost
  // must initialize srtt and lrtt in parallel
  getConn()->lossState.srtt = 1ms;
  getConn()->lossState.lrtt = 1ms;
  getConn()->lossState.reorderingThreshold = 10;
  getConn()->transportSettings.timeReorderingThreshDividend = 1000;
  getConn()->transportSettings.timeReorderingThreshDivisor = 1;

  // two writes
  auto s1Id =
      getConn()->streamManager->createNextBidirectionalStream().value()->id;
  auto s1f1 = writeDataToQuicStreamAndGetFrame(s1Id, "hey-", false);
  auto s1f2 = writeDataToQuicStreamAndGetFrame(s1Id, "whats-", false);

  std::vector<PacketNum> appDataPacketNumSent;

  // packet 1, frame 1 from stream 1
  {
    auto packet = buildEmptyPacket(PacketNumberSpace::AppData);
    packet.packet.frames.push_back(s1f1);
    sendAppDataPacket(packet);
    appDataPacketNumSent.push_back(packet.packet.header.getPacketSequenceNum());
  }

  // packet 2, frames 1 and 2 from stream 1
  {
    auto packet = buildEmptyPacket(PacketNumberSpace::AppData);
    packet.packet.frames.push_back(s1f1);
    packet.packet.frames.push_back(s1f2);
    sendAppDataPacket(packet);
    appDataPacketNumSent.push_back(packet.packet.header.getPacketSequenceNum());
  }

  ASSERT_THAT(appDataPacketNumSent, SizeIs(2));

  // deliver ACK for packet1
  {
    const auto ackEvent = deliverAckForAppDataPackets(
        appDataPacketNumSent[0], appDataPacketNumSent[0]);

    // check ackedPackets
    EXPECT_THAT(
        ackEvent.ackedPackets,
        ElementsAre(
            // pkt1
            Field(
                &AckEvent::AckPacket::detailsPerStream,
                UnorderedElementsAre(
                    AckEventStreamDetailsMatcherBuilder()
                        .setStreamID(s1Id)
                        .setStreamBytesAcked(s1f1.len)
                        .setStreamBytesAckedByRetrans(0)
                        .setMaybeNewDeliveryOffset(s1f1.offset + s1f1.len)
                        .build()))));
  }

  // deliver ACK for packet2
  {
    const auto ackEvent = deliverAckForAppDataPackets(
        appDataPacketNumSent[1], appDataPacketNumSent[1]);

    // check ackedPackets
    EXPECT_THAT(
        ackEvent.ackedPackets,
        ElementsAre(
            // pkt2
            Field(
                &AckEvent::AckPacket::detailsPerStream,
                UnorderedElementsAre(
                    AckEventStreamDetailsMatcherBuilder()
                        .setStreamID(s1Id)
                        .setStreamBytesAcked(s1f2.len)
                        .setStreamBytesAckedByRetrans(0)
                        .setMaybeNewDeliveryOffset(s1f2.offset + s1f2.len)
                        // p1 acked earlier, thus making f1 dupacked
                        .addDupAckedStreamInterval(
                            s1f1.offset, s1f1.offset + s1f1.len - 1)
                        .build()))));
  }
}

/**
 * Frame retransmitted in a packet with a new frame (new data) for same stream.
 * Second packet ACKed, then original packet ACKed (spurious + out of order).
 */
TEST_F(
    AckEventForAppDataTest,
    AckEventRetransHasNewFrameSpuriousRetransThenOrigAcked) {
  // prevent packets from being marked as lost
  // must initialize srtt and lrtt in parallel
  getConn()->lossState.srtt = 1ms;
  getConn()->lossState.lrtt = 1ms;
  getConn()->lossState.reorderingThreshold = 10;
  getConn()->transportSettings.timeReorderingThreshDividend = 1000;
  getConn()->transportSettings.timeReorderingThreshDivisor = 1;

  // two writes
  auto s1Id =
      getConn()->streamManager->createNextBidirectionalStream().value()->id;
  auto s1f1 = writeDataToQuicStreamAndGetFrame(s1Id, "hey-", false);
  auto s1f2 = writeDataToQuicStreamAndGetFrame(s1Id, "whats-", false);

  std::vector<PacketNum> appDataPacketNumSent;

  // packet 1, frame 1 from stream 1
  {
    auto packet = buildEmptyPacket(PacketNumberSpace::AppData);
    packet.packet.frames.push_back(s1f1);
    sendAppDataPacket(packet);
    appDataPacketNumSent.push_back(packet.packet.header.getPacketSequenceNum());
  }

  // packet 2, frames 1 and 2 from stream 1
  {
    auto packet = buildEmptyPacket(PacketNumberSpace::AppData);
    packet.packet.frames.push_back(s1f1);
    packet.packet.frames.push_back(s1f2);
    sendAppDataPacket(packet);
    appDataPacketNumSent.push_back(packet.packet.header.getPacketSequenceNum());
  }

  ASSERT_THAT(appDataPacketNumSent, SizeIs(2));

  // deliver ACK for packet2
  {
    const auto ackEvent = deliverAckForAppDataPackets(
        appDataPacketNumSent[1], appDataPacketNumSent[1]);

    // check ackedPackets
    EXPECT_THAT(
        ackEvent.ackedPackets,
        ElementsAre(
            // pkt2
            Field(
                &AckEvent::AckPacket::detailsPerStream,
                UnorderedElementsAre(
                    AckEventStreamDetailsMatcherBuilder()
                        .setStreamID(s1Id)
                        .setStreamBytesAcked(s1f1.len + s1f2.len)
                        .setStreamBytesAckedByRetrans(s1f1.len)
                        .setMaybeNewDeliveryOffset(s1f2.offset + s1f2.len)
                        .build()))));
  }

  // deliver ACK for packet1
  {
    const auto ackEvent = deliverAckForAppDataPackets(
        appDataPacketNumSent[0], appDataPacketNumSent[0]);

    // check ackedPackets
    EXPECT_THAT(
        ackEvent.ackedPackets,
        ElementsAre(
            // pkt1
            Field(
                &AckEvent::AckPacket::detailsPerStream,
                UnorderedElementsAre(
                    AckEventStreamDetailsMatcherBuilder()
                        .setStreamID(s1Id)
                        .setStreamBytesAcked(0) // p2 ACKed earlier
                        .setStreamBytesAckedByRetrans(0) // p2 ACKed earlier
                        // no change, since already advanced by p2
                        .setMaybeNewDeliveryOffset(folly::none)
                        // orig ACKed after retrans, thus making f1 dupacked
                        .addDupAckedStreamInterval(
                            s1f1.offset, s1f1.offset + s1f1.len - 1)
                        .build()))));
  }
}

/**
 * Frame retransmitted in a packet with a new frame (new data) for new stream.
 * Second packet ACKed, original never ACKed.
 */
TEST_F(AckEventForAppDataTest, AckEventRetransHasNewStreamFrame) {
  // prevent packets from being marked as lost
  // must initialize srtt and lrtt in parallel
  getConn()->lossState.srtt = 1ms;
  getConn()->lossState.lrtt = 1ms;
  getConn()->lossState.reorderingThreshold = 10;
  getConn()->transportSettings.timeReorderingThreshDividend = 1000;
  getConn()->transportSettings.timeReorderingThreshDivisor = 1;

  // two writes to two different streams
  auto s1Id =
      getConn()->streamManager->createNextBidirectionalStream().value()->id;
  auto s2Id =
      getConn()->streamManager->createNextBidirectionalStream().value()->id;
  auto s1f1 = writeDataToQuicStreamAndGetFrame(s1Id, "hey-", false);
  auto s2f1 = writeDataToQuicStreamAndGetFrame(s2Id, "whats-", false);

  std::vector<PacketNum> appDataPacketNumSent;

  // packet 1, frame 1 from stream 1
  {
    auto packet = buildEmptyPacket(PacketNumberSpace::AppData);
    packet.packet.frames.push_back(s1f1);
    sendAppDataPacket(packet);
    appDataPacketNumSent.push_back(packet.packet.header.getPacketSequenceNum());
  }

  // packet 2, frame 1 from stream 1 and frame 1 from stream 2
  {
    auto packet = buildEmptyPacket(PacketNumberSpace::AppData);
    packet.packet.frames.push_back(s1f1);
    packet.packet.frames.push_back(s2f1);
    sendAppDataPacket(packet);
    appDataPacketNumSent.push_back(packet.packet.header.getPacketSequenceNum());
  }

  ASSERT_THAT(appDataPacketNumSent, SizeIs(2));

  // deliver ACK for packet2
  {
    const auto ackEvent = deliverAckForAppDataPackets(
        appDataPacketNumSent[1], appDataPacketNumSent[1]);

    // check ackedPackets
    EXPECT_THAT(
        ackEvent.ackedPackets,
        ElementsAre(
            // pkt2
            Field(
                &AckEvent::AckPacket::detailsPerStream,
                UnorderedElementsAre(
                    AckEventStreamDetailsMatcherBuilder()
                        .setStreamID(s1Id)
                        .setStreamBytesAcked(s1f1.len)
                        .setStreamBytesAckedByRetrans(s1f1.len)
                        .setMaybeNewDeliveryOffset(s1f1.offset + s1f1.len)
                        .build(),
                    AckEventStreamDetailsMatcherBuilder()
                        .setStreamID(s2Id)
                        .setStreamBytesAcked(s2f1.len)
                        .setStreamBytesAckedByRetrans(0)
                        .setMaybeNewDeliveryOffset(s2f1.offset + s2f1.len)
                        .build()))));
  }
}

/**
 * Frame retransmitted in a packet with a new frame (new data) for new stream.
 * Original and second packet ACKed at same time (spurious).
 */
TEST_F(
    AckEventForAppDataTest,
    AckEventRetransHasNewStreamFrameSpuriousOrigAckedSameTime) {
  // prevent packets from being marked as lost
  // must initialize srtt and lrtt in parallel
  getConn()->lossState.srtt = 1ms;
  getConn()->lossState.lrtt = 1ms;
  getConn()->lossState.reorderingThreshold = 10;
  getConn()->transportSettings.timeReorderingThreshDividend = 1000;
  getConn()->transportSettings.timeReorderingThreshDivisor = 1;

  // two writes to two different streams
  auto s1Id =
      getConn()->streamManager->createNextBidirectionalStream().value()->id;
  auto s2Id =
      getConn()->streamManager->createNextBidirectionalStream().value()->id;
  auto s1f1 = writeDataToQuicStreamAndGetFrame(s1Id, "hey-", false);
  auto s2f1 = writeDataToQuicStreamAndGetFrame(s2Id, "whats-", false);

  std::vector<PacketNum> appDataPacketNumSent;

  // packet 1, frame 1 from stream 1
  {
    auto packet = buildEmptyPacket(PacketNumberSpace::AppData);
    packet.packet.frames.push_back(s1f1);
    sendAppDataPacket(packet);
    appDataPacketNumSent.push_back(packet.packet.header.getPacketSequenceNum());
  }

  // packet 2, frame 1 from stream 1 and frame 1 from stream 2
  {
    auto packet = buildEmptyPacket(PacketNumberSpace::AppData);
    packet.packet.frames.push_back(s1f1);
    packet.packet.frames.push_back(s2f1);
    sendAppDataPacket(packet);
    appDataPacketNumSent.push_back(packet.packet.header.getPacketSequenceNum());
  }

  ASSERT_THAT(appDataPacketNumSent, SizeIs(2));

  // deliver ACK for packets 1 and 2
  {
    const auto ackEvent = deliverAckForAppDataPackets(
        appDataPacketNumSent[0], appDataPacketNumSent[1]);

    // check ackedPackets
    EXPECT_THAT(
        ackEvent.ackedPackets,
        ElementsAre(
            // pkt1
            Field(
                &AckEvent::AckPacket::detailsPerStream,
                UnorderedElementsAre(
                    AckEventStreamDetailsMatcherBuilder()
                        .setStreamID(s1Id)
                        .setStreamBytesAcked(s1f1.len)
                        .setStreamBytesAckedByRetrans(0)
                        .setMaybeNewDeliveryOffset(s1f1.offset + s1f1.len)
                        .build())),
            // pkt2
            Field(
                &AckEvent::AckPacket::detailsPerStream,
                UnorderedElementsAre(
                    AckEventStreamDetailsMatcherBuilder()
                        .setStreamID(s1Id)
                        .setStreamBytesAcked(0)
                        .setStreamBytesAckedByRetrans(0)
                        .setMaybeNewDeliveryOffset(folly::none)
                        // retrans ACKed after original, thus making f1 dupacked
                        .addDupAckedStreamInterval(
                            s1f1.offset, s1f1.offset + s1f1.len - 1)
                        .build(),
                    AckEventStreamDetailsMatcherBuilder()
                        .setStreamID(s2Id)
                        .setStreamBytesAcked(s2f1.len)
                        .setStreamBytesAckedByRetrans(0)
                        .setMaybeNewDeliveryOffset(s2f1.offset + s2f1.len)
                        .build()))));
  }
}

/**
 * Frame retransmitted in a packet with a new frame (new data) for new stream.
 * Original packet ACKed then second packet ACKed (spurious retrans).
 */
TEST_F(
    AckEventForAppDataTest,
    AckEventRetransHasNewStreamFrameSpuriousOrigThenRetransAcked) {
  // prevent packets from being marked as lost
  // must initialize srtt and lrtt in parallel
  getConn()->lossState.srtt = 1ms;
  getConn()->lossState.lrtt = 1ms;
  getConn()->lossState.reorderingThreshold = 10;
  getConn()->transportSettings.timeReorderingThreshDividend = 1000;
  getConn()->transportSettings.timeReorderingThreshDivisor = 1;

  // two writes to two different streams
  auto s1Id =
      getConn()->streamManager->createNextBidirectionalStream().value()->id;
  auto s2Id =
      getConn()->streamManager->createNextBidirectionalStream().value()->id;
  auto s1f1 = writeDataToQuicStreamAndGetFrame(s1Id, "hey-", false);
  auto s2f1 = writeDataToQuicStreamAndGetFrame(s2Id, "whats-", false);

  std::vector<PacketNum> appDataPacketNumSent;

  // packet 1, frame 1 from stream 1
  {
    auto packet = buildEmptyPacket(PacketNumberSpace::AppData);
    packet.packet.frames.push_back(s1f1);
    sendAppDataPacket(packet);
    appDataPacketNumSent.push_back(packet.packet.header.getPacketSequenceNum());
  }

  // packet 2, frame 1 from stream 1 and frame 1 from stream 2
  {
    auto packet = buildEmptyPacket(PacketNumberSpace::AppData);
    packet.packet.frames.push_back(s1f1);
    packet.packet.frames.push_back(s2f1);
    sendAppDataPacket(packet);
    appDataPacketNumSent.push_back(packet.packet.header.getPacketSequenceNum());
  }

  ASSERT_THAT(appDataPacketNumSent, SizeIs(2));

  // deliver ACK for packet 1
  {
    const auto ackEvent = deliverAckForAppDataPackets(
        appDataPacketNumSent[0], appDataPacketNumSent[0]);

    // check ackedPackets
    EXPECT_THAT(
        ackEvent.ackedPackets,
        ElementsAre(
            // pkt1
            Field(
                &AckEvent::AckPacket::detailsPerStream,
                UnorderedElementsAre(
                    AckEventStreamDetailsMatcherBuilder()
                        .setStreamID(s1Id)
                        .setStreamBytesAcked(s1f1.len)
                        .setStreamBytesAckedByRetrans(0)
                        .setMaybeNewDeliveryOffset(s1f1.offset + s1f1.len)
                        .build()))));
  }

  // deliver ACK for packet 2
  {
    const auto ackEvent = deliverAckForAppDataPackets(
        appDataPacketNumSent[1], appDataPacketNumSent[1]);

    // check ackedPackets
    EXPECT_THAT(
        ackEvent.ackedPackets,
        ElementsAre(
            // pkt2
            Field(
                &AckEvent::AckPacket::detailsPerStream,
                UnorderedElementsAre(
                    AckEventStreamDetailsMatcherBuilder()
                        .setStreamID(s1Id)
                        .setStreamBytesAcked(0)
                        .setStreamBytesAckedByRetrans(0)
                        .setMaybeNewDeliveryOffset(folly::none)
                        // retrans ACKed after original, thus making f1 dupacked
                        .addDupAckedStreamInterval(
                            s1f1.offset, s1f1.offset + s1f1.len - 1)
                        .build(),
                    AckEventStreamDetailsMatcherBuilder()
                        .setStreamID(s2Id)
                        .setStreamBytesAcked(s2f1.len)
                        .setStreamBytesAckedByRetrans(0)
                        .setMaybeNewDeliveryOffset(s2f1.offset + s2f1.len)
                        .build()))));
  }
}

/**
 * Frame retransmitted in a packet with a new frame (new data) for new stream.
 * Second packet ACKed, then original packet ACKed (spurious + out of order).
 */
TEST_F(
    AckEventForAppDataTest,
    AckEventRetransHasNewStreamFrameSpuriousRetransThenOrigAcked) {
  // prevent packets from being marked as lost
  // must initialize srtt and lrtt in parallel
  getConn()->lossState.srtt = 1ms;
  getConn()->lossState.lrtt = 1ms;
  getConn()->lossState.reorderingThreshold = 10;
  getConn()->transportSettings.timeReorderingThreshDividend = 1000;
  getConn()->transportSettings.timeReorderingThreshDivisor = 1;

  // two writes to two different streams
  auto s1Id =
      getConn()->streamManager->createNextBidirectionalStream().value()->id;
  auto s2Id =
      getConn()->streamManager->createNextBidirectionalStream().value()->id;
  auto s1f1 = writeDataToQuicStreamAndGetFrame(s1Id, "hey-", false);
  auto s2f1 = writeDataToQuicStreamAndGetFrame(s2Id, "whats-", false);

  std::vector<PacketNum> appDataPacketNumSent;

  // packet 1, frame 1 from stream 1
  {
    auto packet = buildEmptyPacket(PacketNumberSpace::AppData);
    packet.packet.frames.push_back(s1f1);
    sendAppDataPacket(packet);
    appDataPacketNumSent.push_back(packet.packet.header.getPacketSequenceNum());
  }

  // packet 2, frame 1 from stream 1 and frame 1 from stream 2
  {
    auto packet = buildEmptyPacket(PacketNumberSpace::AppData);
    packet.packet.frames.push_back(s1f1);
    packet.packet.frames.push_back(s2f1);
    sendAppDataPacket(packet);
    appDataPacketNumSent.push_back(packet.packet.header.getPacketSequenceNum());
  }

  ASSERT_THAT(appDataPacketNumSent, SizeIs(2));

  // deliver ACK for packet 2
  {
    const auto ackEvent = deliverAckForAppDataPackets(
        appDataPacketNumSent[1], appDataPacketNumSent[1]);

    // check ackedPackets
    EXPECT_THAT(
        ackEvent.ackedPackets,
        ElementsAre(
            // pkt2
            Field(
                &AckEvent::AckPacket::detailsPerStream,
                UnorderedElementsAre(
                    AckEventStreamDetailsMatcherBuilder()
                        .setStreamID(s1Id)
                        .setStreamBytesAcked(s1f1.len)
                        .setStreamBytesAckedByRetrans(s1f1.len)
                        .setMaybeNewDeliveryOffset(s1f1.offset + s1f1.len)
                        .build(),
                    AckEventStreamDetailsMatcherBuilder()
                        .setStreamID(s2Id)
                        .setStreamBytesAcked(s2f1.len)
                        .setStreamBytesAckedByRetrans(0)
                        .setMaybeNewDeliveryOffset(s2f1.offset + s2f1.len)
                        .build()))));
  }

  // deliver ACK for packet1
  {
    const auto ackEvent = deliverAckForAppDataPackets(
        appDataPacketNumSent[0], appDataPacketNumSent[0]);

    // check ackedPackets
    EXPECT_THAT(
        ackEvent.ackedPackets,
        ElementsAre(
            // pkt1
            Field(
                &AckEvent::AckPacket::detailsPerStream,
                UnorderedElementsAre(
                    AckEventStreamDetailsMatcherBuilder()
                        .setStreamID(s1Id)
                        .setStreamBytesAcked(0) // p2 ACKed earlier
                        .setStreamBytesAckedByRetrans(0) // p2 ACKed earlier
                        // no change, since already advanced by p2
                        .setMaybeNewDeliveryOffset(folly::none)
                        // orig ACKed after retrans, thus making f1 dupacked
                        .addDupAckedStreamInterval(
                            s1f1.offset, s1f1.offset + s1f1.len - 1)
                        .build()))));
  }
}

/**
 * Scenario where there are multiple dupacked intervals on a packet ACK.
 */
TEST_F(AckEventForAppDataTest, AckEventRetransMultipleDupack) {
  // prevent packets from being marked as lost
  // must initialize srtt and lrtt in parallel
  getConn()->lossState.srtt = 1ms;
  getConn()->lossState.lrtt = 1ms;
  getConn()->lossState.reorderingThreshold = 10;
  getConn()->transportSettings.timeReorderingThreshDividend = 1000;
  getConn()->transportSettings.timeReorderingThreshDivisor = 1;

  // three writes to a single stream
  auto s1Id =
      getConn()->streamManager->createNextBidirectionalStream().value()->id;
  auto s1f1 = writeDataToQuicStreamAndGetFrame(s1Id, "hey-", false);
  auto s1f2 = writeDataToQuicStreamAndGetFrame(s1Id, "whats-", false);
  auto s1f3 = writeDataToQuicStreamAndGetFrame(s1Id, "up?", true);

  std::vector<PacketNum> appDataPacketNumSent;

  // packet 1, frame 1 from stream 1
  {
    auto packet = buildEmptyPacket(PacketNumberSpace::AppData);
    packet.packet.frames.push_back(s1f1);
    sendAppDataPacket(packet);
    appDataPacketNumSent.push_back(packet.packet.header.getPacketSequenceNum());
  }

  // packet 2, frame 2 from stream 1
  {
    auto packet = buildEmptyPacket(PacketNumberSpace::AppData);
    packet.packet.frames.push_back(s1f2);
    sendAppDataPacket(packet);
    appDataPacketNumSent.push_back(packet.packet.header.getPacketSequenceNum());
  }

  // packet 3, frame 3 from stream 1
  {
    auto packet = buildEmptyPacket(PacketNumberSpace::AppData);
    packet.packet.frames.push_back(s1f3);
    sendAppDataPacket(packet);
    appDataPacketNumSent.push_back(packet.packet.header.getPacketSequenceNum());
  }

  ASSERT_THAT(appDataPacketNumSent, SizeIs(3));

  // deliver ACK for packet 2
  {
    const auto ackEvent = deliverAckForAppDataPackets(
        appDataPacketNumSent[1], appDataPacketNumSent[1]);

    // check ackedPackets
    EXPECT_THAT(
        ackEvent.ackedPackets,
        ElementsAre(
            // pkt2
            Field(
                &AckEvent::AckPacket::detailsPerStream,
                UnorderedElementsAre(
                    AckEventStreamDetailsMatcherBuilder()
                        .setStreamID(s1Id)
                        .setStreamBytesAcked(s1f2.len)
                        .setStreamBytesAckedByRetrans(0)
                        // missing f1, so delivery offset cannot increase
                        .setMaybeNewDeliveryOffset(folly::none)
                        .build()))));
  }

  // packet 4, retransmission of frame 1 and frame 3
  {
    auto packet = buildEmptyPacket(PacketNumberSpace::AppData);
    packet.packet.frames.push_back(s1f1);
    packet.packet.frames.push_back(s1f3);
    sendAppDataPacket(packet);
    appDataPacketNumSent.push_back(packet.packet.header.getPacketSequenceNum());
  }

  ASSERT_THAT(appDataPacketNumSent, SizeIs(4));

  // deliver ACK for packet 1 and packet 3
  {
    AckBlocks blocks;
    blocks.insert(appDataPacketNumSent[0], appDataPacketNumSent[0]);
    blocks.insert(appDataPacketNumSent[2], appDataPacketNumSent[2]);
    const auto ackEvent = deliverAckForAppDataPackets(blocks);

    // check ackedPackets
    EXPECT_THAT(
        ackEvent.ackedPackets,
        ElementsAre(
            // pkt1
            Field(
                &AckEvent::AckPacket::detailsPerStream,
                UnorderedElementsAre(
                    AckEventStreamDetailsMatcherBuilder()
                        .setStreamID(s1Id)
                        .setStreamBytesAcked(s1f1.len)
                        .setStreamBytesAckedByRetrans(0)
                        // since f2 ACKed already, advance to there
                        .setMaybeNewDeliveryOffset(s1f2.offset + s1f2.len)
                        .build())),
            // pkt3
            Field(
                &AckEvent::AckPacket::detailsPerStream,
                UnorderedElementsAre(
                    AckEventStreamDetailsMatcherBuilder()
                        .setStreamID(s1Id)
                        .setStreamBytesAcked(s1f3.len)
                        .setStreamBytesAckedByRetrans(0)
                        .setMaybeNewDeliveryOffset(s1f3.offset + s1f3.len)
                        .build()))));
  }

  // deliver ACK for packet 4
  {
    const auto ackEvent = deliverAckForAppDataPackets(
        appDataPacketNumSent[3], appDataPacketNumSent[3]);

    // check ackedPackets
    EXPECT_THAT(
        ackEvent.ackedPackets,
        ElementsAre(
            // pkt4
            Field(
                &AckEvent::AckPacket::detailsPerStream,
                UnorderedElementsAre(
                    AckEventStreamDetailsMatcherBuilder()
                        .setStreamID(s1Id)
                        .setStreamBytesAcked(0)
                        .setStreamBytesAckedByRetrans(0)
                        .setMaybeNewDeliveryOffset(folly::none)
                        // retrans ACKed after original, thus making dupacks
                        // for both f1 and f3 (in ACKed packets p1 and p3)
                        .addDupAckedStreamInterval(
                            s1f1.offset, s1f1.offset + s1f1.len - 1)
                        .addDupAckedStreamInterval(
                            s1f3.offset, s1f3.offset + s1f3.len - 1)
                        .build()))));
  }
}

INSTANTIATE_TEST_SUITE_P(
    AckHandlersTests,
    AckHandlersTest,
    Values(
        PacketNumberSpace::Initial,
        PacketNumberSpace::Handshake,
        PacketNumberSpace::AppData));
} // namespace test
} // namespace quic
