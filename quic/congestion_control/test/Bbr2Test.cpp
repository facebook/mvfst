/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <quic/congestion_control/Bbr2.h>

#include <folly/portability/GMock.h>
#include <folly/portability/GTest.h>
#include <quic/common/test/TestUtils.h>
#include <quic/congestion_control/test/Mocks.h>
#include <quic/state/test/Mocks.h>

using namespace testing;

namespace quic::test {

class Bbr2Test : public Test {
 public:
  void SetUp() override {
    testStart_ = Clock::now();
    auto mockPacer = std::make_unique<MockPacer>();
    rawPacer_ = mockPacer.get();
    conn_ = std::make_unique<QuicConnectionStateBase>(QuicNodeType::Client);
    conn_->pacer = std::move(mockPacer);
    conn_->udpSendPacketLen = 1000;
    conn_->connectionTime = testStart_;
  }

  std::unique_ptr<QuicConnectionStateBase> conn_;
  MockPacer* rawPacer_;
  TimePoint testStart_;
};

TEST_F(Bbr2Test, InitBbr2) {
  Bbr2CongestionController bbr2(*conn_);
  EXPECT_EQ(CongestionControlType::BBR2, bbr2.type());
  EXPECT_EQ("Startup", bbr2StateToString(bbr2.getState()));
  EXPECT_EQ(
      1000 * conn_->transportSettings.initCwndInMss,
      bbr2.getCongestionWindow());
  EXPECT_EQ(bbr2.getWritableBytes(), bbr2.getCongestionWindow());
}

TEST_F(Bbr2Test, BytesInFlightAccounting) {
  Bbr2CongestionController bbr2(*conn_);

  auto packetSize = 3000;
  auto totalSent = 0;
  PacketNum pn = 0;

  // Send 3 packets
  for (int i = 0; i < 3; i++) {
    auto packet =
        makeTestingWritePacket(pn++, packetSize, totalSent += packetSize);
    bbr2.onPacketSent(packet);
    EXPECT_EQ(conn_->lossState.inflightBytes, totalSent);
  }

  // Ack one packet
  auto ackTime = Clock::now();
  auto ackEvent = CongestionController::AckEvent::Builder()
                      .setAckTime(ackTime)
                      .setAdjustedAckTime(ackTime)
                      .setAckDelay(0us)
                      .setPacketNumberSpace(PacketNumberSpace::Handshake)
                      .setLargestAckedPacket(0)
                      .build();
  ackEvent.ackedBytes = 3000;
  bbr2.onPacketAckOrLoss(&ackEvent, nullptr);
  EXPECT_EQ(conn_->lossState.inflightBytes, 6000);

  // Mark 1 packet as lost
  CongestionController::LossEvent lossEvent;
  lossEvent.lostPackets = 1;
  lossEvent.lostBytes = 3000;
  bbr2.onPacketAckOrLoss(nullptr, &lossEvent);
  EXPECT_EQ(conn_->lossState.inflightBytes, 3000);

  // Remove 1 packet from inflight
  bbr2.onRemoveBytesFromInflight(3000);
  EXPECT_EQ(conn_->lossState.inflightBytes, 0);
}

TEST_F(Bbr2Test, StartupCwndGrowthBasic) {
  Bbr2CongestionController bbr2(*conn_);

  auto packetSize = 1000;
  auto totalSent = 0;
  PacketNum pn = 0;

  auto cwnd = bbr2.getCongestionWindow();

  // Send 10 packets. All get sent at once 10 ms into the connection
  for (int i = 0; i < 10; i++) {
    auto packet = makeTestingWritePacket(
        pn, packetSize, totalSent += packetSize, testStart_ + 10ms);
    bbr2.onPacketSent(packet);
    packet.nonDsrPacketSequenceNumber = pn++;
    conn_->outstandings.packets.emplace_back(std::move(packet));
    ASSERT_EQ(conn_->lossState.inflightBytes, totalSent);
  }

  // Sending packets should update writable bytes but not cwnd
  ASSERT_EQ(bbr2.getCongestionWindow(), cwnd);
  ASSERT_EQ(bbr2.getWritableBytes(), cwnd - totalSent);

  // Ack 5 packets in 100ms RTT and ensure cwnd growth.
  auto ackTime = testStart_ + 100ms;
  auto ackEvent = CongestionController::AckEvent::Builder()
                      .setAckTime(ackTime)
                      .setAdjustedAckTime(ackTime)
                      .setAckDelay(0us)
                      .setPacketNumberSpace(PacketNumberSpace::Handshake)
                      .setLargestAckedPacket(4)
                      .build();
  ackEvent.ackedBytes = 5000;
  ackEvent.totalBytesAcked = 5000;
  ackEvent.largestNewlyAckedPacket = 4;
  for (int i = 0; i < 5; i++) {
    auto& pkt = conn_->outstandings.packets.at(i);
    auto ackPkt =
        CongestionController::AckEvent::AckPacket::Builder()
            .setPacketNum(pkt.getPacketSequenceNum())
            .setNonDsrPacketSequenceNumber(
                pkt.nonDsrPacketSequenceNumber.value())
            .setOutstandingPacketMetadata(std::move(pkt.metadata))
            .setLastAckedPacketInfo(std::move(pkt.lastAckedPacketInfo))
            .setAppLimited(pkt.isAppLimited)
            .setDetailsPerStream(
                CongestionController::AckEvent::AckPacket::DetailsPerStream())
            .build();
    ackEvent.ackedPackets.push_back(ackPkt);
  }
  // The pace should be updated.
  EXPECT_CALL(*rawPacer_, refreshPacingRate(_, _, _));
  bbr2.onPacketAckOrLoss(&ackEvent, nullptr);
  // Cwnd should increase.
  EXPECT_GT(bbr2.getCongestionWindow(), cwnd);
}

TEST_F(Bbr2Test, GracefullyHandleMissingFields) {
  // Call the different bbr2 APIs with missing data. There should be no crashes.
  Bbr2CongestionController bbr2(*conn_);

  auto packet = makeTestingWritePacket(0, 0, 0, testStart_);
  packet.lastAckedPacketInfo.clear();
  packet.associatedEvent.clear();
  EXPECT_NO_THROW(bbr2.onPacketSent(packet));

  EXPECT_NO_THROW(bbr2.onPacketAckOrLoss(nullptr, nullptr));
  auto ackEvent = CongestionController::AckEvent::Builder()
                      .setAckTime(testStart_)
                      .setAdjustedAckTime(testStart_)
                      .setAckDelay(0us)
                      .setPacketNumberSpace(PacketNumberSpace::Handshake)
                      .setLargestAckedPacket(4)
                      .build();
  EXPECT_NO_THROW(bbr2.onPacketAckOrLoss(&ackEvent, nullptr));

  CongestionController::LossEvent lossEvent;
  bbr2.onPacketAckOrLoss(nullptr, &lossEvent);
  EXPECT_NO_THROW(bbr2.onPacketAckOrLoss(nullptr, &lossEvent));
}
} // namespace quic::test
