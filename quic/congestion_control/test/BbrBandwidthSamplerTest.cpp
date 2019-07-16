/*
 * Copyright (c) Facebook, Inc. and its affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 *
 */

// Copyright 2004-present Facebook.  All rights reserved.

#include <quic/congestion_control/BbrBandwidthSampler.h>
#include <folly/portability/GMock.h>
#include <folly/portability/GTest.h>
#include <quic/common/test/TestUtils.h>

using namespace quic;
using namespace testing;

namespace quic {
namespace test {

class BbrBandwidthSamplerTest : public Test {
 protected:
  QuicConnectionStateBase conn_{QuicNodeType::Client};
};

TEST_F(BbrBandwidthSamplerTest, InitBandwidth) {
  BbrBandwidthSampler sampler(conn_);
  EXPECT_EQ(0, sampler.getBandwidth().bytes);
}

TEST_F(BbrBandwidthSamplerTest, NoPreviousAckedPacket) {
  BbrBandwidthSampler sampler(conn_);
  conn_.lossState.totalBytesAcked = 1000;
  CongestionController::AckEvent ackEvent;
  ackEvent.ackedBytes = 5000;
  ackEvent.ackedPackets.emplace_back(
      makeTestingWritePacket(0, 1000, 1000, false));
  sampler.onPacketAcked(ackEvent, 0);
  EXPECT_EQ(0, sampler.getBandwidth().bytes);
}

TEST_F(BbrBandwidthSamplerTest, RateCalculation) {
  BbrBandwidthSampler sampler(conn_);
  CongestionController::AckEvent ackEvent;
  ackEvent.ackedBytes = 5000;
  conn_.lossState.totalBytesAcked = 5000;
  auto ackTime = Clock::now();
  ackEvent.ackTime = ackTime;
  auto lastAckedPacketSentTime = ackTime - 200us;
  auto lastAckedPacketAckTime = ackTime - 100us;
  for (PacketNum pn = 0; pn < 5; pn++) {
    auto packet = makeTestingWritePacket(pn, 1000, 1000 + 1000 * pn, false);
    packet.lastAckedPacketInfo.emplace(
        lastAckedPacketSentTime, lastAckedPacketAckTime, 0, 0);
    packet.time = ackTime - 50us;
    ackEvent.ackedPackets.push_back(packet);
  }

  sampler.onPacketAcked(ackEvent, 0);
  EXPECT_EQ(
      Bandwidth(5000, std::chrono::microseconds(100)), sampler.getBandwidth());
}

TEST_F(BbrBandwidthSamplerTest, SampleExpiration) {
  BbrBandwidthSampler sampler(conn_);
  CongestionController::AckEvent ackEvent;
  conn_.lossState.totalBytesAcked = 1000;
  ackEvent.ackedBytes = 1000;
  auto ackTime = Clock::now();
  ackEvent.ackTime = ackTime;
  auto lastAckedPacketSentTime = ackTime - 200us;
  auto lastAckedPacketAckTime = ackTime - 100us;
  PacketNum pn = 1;
  auto packet = makeTestingWritePacket(pn, 1000, 2000, false);
  packet.lastAckedPacketInfo.emplace(
      lastAckedPacketSentTime, lastAckedPacketAckTime, 1000, 1000);
  packet.time = ackTime - 50us;
  ackEvent.ackedPackets.push_back(packet);
  sampler.onPacketAcked(ackEvent, 0);
  auto firstBandwidthSample = sampler.getBandwidth();

  pn++;
  conn_.lossState.totalBytesAcked = 2000;
  auto packet2 = makeTestingWritePacket(pn, 500, 2500, false);
  packet2.lastAckedPacketInfo.emplace(packet.time, ackTime, 2000, 1000);
  auto ackTime2 = ackTime + 150us;
  CongestionController::AckEvent ackEvent2;
  ackEvent2.ackTime = ackTime2;
  packet2.time = ackTime + 110us;
  ackEvent2.ackedPackets.push_back(packet2);
  sampler.onPacketAcked(ackEvent2, kBandwidthWindowLength / 4 + 1);
  auto secondBandwidthSample = sampler.getBandwidth();
  EXPECT_EQ(firstBandwidthSample, sampler.getBandwidth());

  pn++;
  conn_.lossState.totalBytesAcked = 2500;
  auto packet3 = makeTestingWritePacket(pn, 200, 2700, false);
  packet3.lastAckedPacketInfo.emplace(packet2.time, ackTime2, 2500, 2000);
  auto ackTime3 = ackTime + 250us;
  CongestionController::AckEvent ackEvent3;
  ackEvent3.ackTime = ackTime3;
  packet3.time = ackTime + 210us;
  ackEvent3.ackedPackets.push_back(packet3);
  sampler.onPacketAcked(ackEvent3, kBandwidthWindowLength / 2 + 1);
  EXPECT_EQ(firstBandwidthSample, sampler.getBandwidth());

  pn++;
  conn_.lossState.totalBytesAcked = 2700;
  auto packet4 = makeTestingWritePacket(pn, 100, 2800, false);
  packet4.lastAckedPacketInfo.emplace(packet3.time, ackTime3, 2700, 2500);
  auto ackTime4 = ackTime + 350us;
  CongestionController::AckEvent ackEvent4;
  ackEvent4.ackTime = ackTime4;
  packet4.time = ackTime + 310us;
  ackEvent4.ackedPackets.push_back(packet4);
  sampler.onPacketAcked(ackEvent4, kBandwidthWindowLength + 1);
  // The bandwidth we got from packet1 has expired. Packet2 should have
  // generated the current max:
  EXPECT_EQ(secondBandwidthSample, sampler.getBandwidth());
}

TEST_F(BbrBandwidthSamplerTest, AppLimited) {
  QuicConnectionStateBase conn(QuicNodeType::Client);
  auto qLogger = std::make_shared<FileQLogger>();
  conn.qLogger = qLogger;

  BbrBandwidthSampler sampler(conn);
  EXPECT_FALSE(sampler.isAppLimited());
  sampler.onAppLimited();
  EXPECT_TRUE(sampler.isAppLimited());
  CongestionController::AckEvent ackEvent;
  ackEvent.largestAckedPacket = ++conn.lossState.largestSent;
  auto packet =
      makeTestingWritePacket(*ackEvent.largestAckedPacket, 1000, 1000, false);
  ackEvent.ackedPackets.push_back(std::move(packet));
  sampler.onPacketAcked(ackEvent, 0);
  EXPECT_FALSE(sampler.isAppLimited());

  std::vector<int> indices =
      getQLogEventIndices(QLogEventType::CongestionMetricUpdate, qLogger);
  EXPECT_EQ(indices.size(), 2);
  auto tmp = std::move(qLogger->logs[indices[0]]);
  auto event = dynamic_cast<QLogCongestionMetricUpdateEvent*>(tmp.get());
  EXPECT_EQ(event->bytesInFlight, 0);
  EXPECT_EQ(event->currentCwnd, 0);
  EXPECT_EQ(event->congestionEvent, kCongestionAppLimited.str());

  auto tmp2 = std::move(qLogger->logs[indices[1]]);
  auto event2 = dynamic_cast<QLogCongestionMetricUpdateEvent*>(tmp2.get());
  EXPECT_EQ(event2->bytesInFlight, 0);
  EXPECT_EQ(event2->currentCwnd, 0);
  EXPECT_EQ(event2->congestionEvent, kCongestionAppUnlimited.str());
}

TEST_F(BbrBandwidthSamplerTest, AppLimitedOutstandingPacket) {
  QuicConnectionStateBase conn(QuicNodeType::Client);
  BbrBandwidthSampler sampler(conn);
  CongestionController::AckEvent ackEvent;
  ackEvent.ackedBytes = 1000;
  auto ackTime = Clock::now();
  ackEvent.ackTime = ackTime;
  auto lastAckedPacketSentTime = ackTime - 200us;
  auto lastAckedPacketAckTime = ackTime - 100us;
  PacketNum pn = 0;
  auto packet = makeTestingWritePacket(pn, 1000, 1000 + 1000 * pn, false);
  packet.isAppLimited = true;
  packet.lastAckedPacketInfo.emplace(
      lastAckedPacketSentTime, lastAckedPacketAckTime, 0, 0);
  packet.time = ackTime - 50us;
  ackEvent.ackedPackets.push_back(packet);
  // AppLimited packet, but sample is larger than current best
  sampler.onPacketAcked(ackEvent, 0);
  EXPECT_LT(0, sampler.getBandwidth().bytes);
  auto bandwidth = sampler.getBandwidth();

  pn++;
  auto packet1 = makeTestingWritePacket(pn, 1000, 1000 + 1000 * pn, false);
  packet1.isAppLimited = true;
  packet1.lastAckedPacketInfo.emplace(packet.time, ackTime, 1000, 0);
  packet1.time = ackTime + 500us;
  CongestionController::AckEvent ackEvent1;
  ackEvent1.ackedBytes = 1000;
  ackEvent1.ackTime = ackTime + 2000us;
  ackEvent1.ackedPackets.push_back(packet1);
  // AppLImited packet, bandwidth sampler is less than current best
  sampler.onPacketAcked(ackEvent1, 0);
  EXPECT_EQ(bandwidth, sampler.getBandwidth());
}
} // namespace test
} // namespace quic
