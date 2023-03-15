/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <quic/congestion_control/BbrBandwidthSampler.h>

#include <folly/portability/GMock.h>
#include <folly/portability/GTest.h>
#include <quic/common/test/TestUtils.h>

using namespace testing;

namespace quic {
namespace test {

class BbrBandwidthSamplerTest : public Test {
 protected:
  QuicConnectionStateBase conn_{QuicNodeType::Client};
};

TEST_F(BbrBandwidthSamplerTest, InitBandwidth) {
  BbrBandwidthSampler sampler(conn_);
  EXPECT_EQ(0, sampler.getBandwidth().units);
}

TEST_F(BbrBandwidthSamplerTest, NoPreviousAckedPacket) {
  BbrBandwidthSampler sampler(conn_);
  conn_.lossState.totalBytesAcked = 1000;
  auto ackTime = Clock::now();
  auto ackEvent = AckEvent::Builder()
                      .setAckTime(ackTime)
                      .setAdjustedAckTime(ackTime)
                      .setAckDelay(0us)
                      .setPacketNumberSpace(PacketNumberSpace::AppData)
                      .setLargestAckedPacket(0)
                      .build();
  ackEvent.ackedBytes = 5000;
  ackEvent.ackedPackets.push_back(makeAckPacketFromOutstandingPacket(
      makeTestingWritePacket(0, 1000, 1000)));
  sampler.onPacketAcked(ackEvent, 0);
  EXPECT_EQ(0, sampler.getBandwidth().units);
}

TEST_F(BbrBandwidthSamplerTest, NoPreviousAckedPacketFallback) {
  BbrBandwidthSampler sampler(conn_);
  conn_.lossState.totalBytesAcked = 1000;
  auto sentTime = Clock::now();
  auto ackTime = sentTime + 50ms;
  auto ackEvent = AckEvent::Builder()
                      .setAckTime(ackTime)
                      .setAdjustedAckTime(ackTime)
                      .setAckDelay(0us)
                      .setPacketNumberSpace(PacketNumberSpace::AppData)
                      .setLargestAckedPacket(0)
                      .build();
  ackEvent.ackedBytes = 5000;
  ackEvent.ackedPackets.push_back(makeAckPacketFromOutstandingPacket(
      makeTestingWritePacket(0, 1000, 1000, sentTime)));
  sampler.onPacketAcked(ackEvent, 0);
  EXPECT_EQ(5000, sampler.getBandwidth().units);
  EXPECT_EQ(50ms, sampler.getBandwidth().interval);
}

TEST_F(BbrBandwidthSamplerTest, RateCalculation) {
  BbrBandwidthSampler sampler(conn_);
  auto ackTime = Clock::now();
  auto ackEvent = AckEvent::Builder()
                      .setAckTime(ackTime)
                      .setAdjustedAckTime(ackTime)
                      .setAckDelay(0us)
                      .setPacketNumberSpace(PacketNumberSpace::AppData)
                      .setLargestAckedPacket(4)
                      .build();
  ackEvent.ackedBytes = 5000;
  conn_.lossState.totalBytesAcked = 5000;
  auto lastAckedPacketSentTime = ackTime - 200us;
  auto lastAckedPacketAckTime = ackTime - 100us;
  for (PacketNum pn = 0; pn < 5; pn++) {
    auto packet = makeTestingWritePacket(pn, 1000, 1000 + 1000 * pn);
    packet.lastAckedPacketInfo.emplace(
        lastAckedPacketSentTime,
        lastAckedPacketAckTime,
        lastAckedPacketAckTime,
        0,
        0);
    packet.metadata.time = ackTime - 50us;
    ackEvent.ackedPackets.push_back(
        makeAckPacketFromOutstandingPacket(std::move(packet)));
  }

  sampler.onPacketAcked(ackEvent, 0);
  EXPECT_EQ(
      Bandwidth(5000, std::chrono::microseconds(100)), sampler.getBandwidth());
}

TEST_F(BbrBandwidthSamplerTest, RateCalculationWithAdjustedAckTime) {
  BbrBandwidthSampler sampler(conn_);
  auto ackTime = Clock::now();
  auto ackEvent = AckEvent::Builder()
                      .setAckTime(ackTime)
                      .setAdjustedAckTime(ackTime - 100us)
                      .setAckDelay(0us)
                      .setPacketNumberSpace(PacketNumberSpace::AppData)
                      .setLargestAckedPacket(4)
                      .build();
  ackEvent.ackedBytes = 5000;
  conn_.lossState.totalBytesAcked = 5000;
  auto lastAckedPacketSentTime = ackTime - 500us;
  auto lastAckedPacketAckTime = ackTime - 100us;
  auto adjustedAckedPacketAckTime = lastAckedPacketAckTime - 200us;
  for (PacketNum pn = 0; pn < 5; pn++) {
    auto packet = makeTestingWritePacket(pn, 1000, 1000 + 1000 * pn);
    packet.lastAckedPacketInfo.emplace(
        lastAckedPacketSentTime,
        lastAckedPacketAckTime,
        adjustedAckedPacketAckTime,
        0,
        0);
    packet.metadata.time = ackTime - 50us;
    ackEvent.ackedPackets.push_back(
        makeAckPacketFromOutstandingPacket(std::move(packet)));
  }

  sampler.onPacketAcked(ackEvent, 0);
  EXPECT_EQ(
      Bandwidth(5000, std::chrono::microseconds(200)), sampler.getBandwidth());
}

TEST_F(BbrBandwidthSamplerTest, SampleExpiration) {
  BbrBandwidthSampler sampler(conn_);
  PacketNum pn = 1;
  auto ackTime = Clock::now();
  auto ackEvent = AckEvent::Builder()
                      .setAckTime(ackTime)
                      .setAdjustedAckTime(ackTime)
                      .setAckDelay(0us)
                      .setPacketNumberSpace(PacketNumberSpace::AppData)
                      .setLargestAckedPacket(pn)
                      .build();
  conn_.lossState.totalBytesAcked = 1000;
  ackEvent.ackedBytes = 1000;
  auto lastAckedPacketSentTime = ackTime - 200us;
  auto lastAckedPacketAckTime = ackTime - 100us;
  auto packet = makeTestingWritePacket(pn, 1000, 2000);
  packet.lastAckedPacketInfo.emplace(
      lastAckedPacketSentTime,
      lastAckedPacketAckTime,
      lastAckedPacketAckTime,
      1000,
      1000);
  auto packetSentTime = packet.metadata.time = ackTime - 50us;
  ackEvent.ackedPackets.push_back(
      makeAckPacketFromOutstandingPacket(std::move(packet)));
  sampler.onPacketAcked(ackEvent, 0);
  auto firstBandwidthSample = sampler.getBandwidth();

  pn++;
  conn_.lossState.totalBytesAcked = 2000;
  auto packet2 = makeTestingWritePacket(pn, 500, 2500);
  packet2.lastAckedPacketInfo.emplace(
      packetSentTime, ackTime, ackTime, 2000, 1000);
  auto ackTime2 = ackTime + 150us;
  auto ackEvent2 = AckEvent::Builder()
                       .setAckTime(ackTime2)
                       .setAdjustedAckTime(ackTime2)
                       .setAckDelay(0us)
                       .setPacketNumberSpace(PacketNumberSpace::AppData)
                       .setLargestAckedPacket(pn)
                       .build();
  packetSentTime = packet2.metadata.time = ackTime + 110us;
  ackEvent2.ackedPackets.push_back(
      makeAckPacketFromOutstandingPacket(std::move(packet2)));
  sampler.onPacketAcked(ackEvent2, bandwidthWindowLength(kNumOfCycles) / 4 + 1);
  auto secondBandwidthSample = sampler.getBandwidth();
  EXPECT_EQ(firstBandwidthSample, sampler.getBandwidth());

  pn++;
  conn_.lossState.totalBytesAcked = 2500;
  auto packet3 = makeTestingWritePacket(pn, 200, 2700);
  packet3.lastAckedPacketInfo.emplace(
      packetSentTime, ackTime2, ackTime2, 2500, 2000);
  auto ackTime3 = ackTime + 250us;
  auto ackEvent3 = AckEvent::Builder()
                       .setAckTime(ackTime3)
                       .setAdjustedAckTime(ackTime3)
                       .setAckDelay(0us)
                       .setPacketNumberSpace(PacketNumberSpace::AppData)
                       .setLargestAckedPacket(pn)
                       .build();
  packetSentTime = packet3.metadata.time = ackTime + 210us;

  ackEvent3.ackedPackets.push_back(
      makeAckPacketFromOutstandingPacket(std::move(packet3)));
  sampler.onPacketAcked(ackEvent3, bandwidthWindowLength(kNumOfCycles) / 2 + 1);
  EXPECT_EQ(firstBandwidthSample, sampler.getBandwidth());

  pn++;
  conn_.lossState.totalBytesAcked = 2700;
  auto packet4 = makeTestingWritePacket(pn, 100, 2800);
  packet4.lastAckedPacketInfo.emplace(
      packetSentTime, ackTime3, ackTime3, 2700, 2500);
  auto ackTime4 = ackTime + 350us;
  auto ackEvent4 = AckEvent::Builder()
                       .setAckTime(ackTime4)
                       .setAdjustedAckTime(ackTime4)
                       .setAckDelay(0us)
                       .setPacketNumberSpace(PacketNumberSpace::AppData)
                       .setLargestAckedPacket(pn)
                       .build();
  packet4.metadata.time = ackTime + 310us;
  ackEvent4.ackedPackets.push_back(
      makeAckPacketFromOutstandingPacket(std::move(packet4)));
  sampler.onPacketAcked(ackEvent4, bandwidthWindowLength(kNumOfCycles) + 1);
  // The bandwidth we got from packet1 has expired. Packet2 should have
  // generated the current max:
  EXPECT_EQ(secondBandwidthSample, sampler.getBandwidth());
}

TEST_F(BbrBandwidthSamplerTest, AppLimited) {
  QuicConnectionStateBase conn(QuicNodeType::Client);
  auto qLogger = std::make_shared<FileQLogger>(VantagePoint::Client);
  conn.qLogger = qLogger;

  conn.lossState.largestSent = conn.lossState.largestSent.value_or(0);
  const auto pn = ++conn.lossState.largestSent.value();

  BbrBandwidthSampler sampler(conn);
  EXPECT_FALSE(sampler.isAppLimited());
  sampler.onAppLimited();
  EXPECT_TRUE(sampler.isAppLimited());
  auto ackTime = Clock::now();
  auto ackEvent = AckEvent::Builder()
                      .setAckTime(ackTime)
                      .setAdjustedAckTime(ackTime)
                      .setAckDelay(0us)
                      .setPacketNumberSpace(PacketNumberSpace::AppData)
                      .setLargestAckedPacket(pn)
                      .build();
  auto packet = makeTestingWritePacket(pn, 1000, 1000);
  ackEvent.largestNewlyAckedPacket = pn;
  ackEvent.largestNewlyAckedPacketSentTime = packet.metadata.time;
  ackEvent.ackedPackets.push_back(
      makeAckPacketFromOutstandingPacket(std::move(packet)));
  sampler.onPacketAcked(ackEvent, 0);
  EXPECT_FALSE(sampler.isAppLimited());

  std::vector<int> indices =
      getQLogEventIndices(QLogEventType::AppLimitedUpdate, qLogger);
  EXPECT_EQ(indices.size(), 2);
  auto tmp = std::move(qLogger->logs[indices[0]]);
  auto event = dynamic_cast<QLogAppLimitedUpdateEvent*>(tmp.get());
  EXPECT_EQ(event->limited, true);

  auto tmp2 = std::move(qLogger->logs[indices[1]]);
  auto event2 = dynamic_cast<QLogAppLimitedUpdateEvent*>(tmp2.get());
  EXPECT_EQ(event2->limited, false);
}

TEST_F(BbrBandwidthSamplerTest, AppLimitedOutstandingPacket) {
  QuicConnectionStateBase conn(QuicNodeType::Client);
  BbrBandwidthSampler sampler(conn);
  PacketNum pn = 0;
  auto ackTime1 = Clock::now();
  auto ackEvent1 = AckEvent::Builder()
                       .setAckTime(ackTime1)
                       .setAdjustedAckTime(ackTime1)
                       .setAckDelay(0us)
                       .setPacketNumberSpace(PacketNumberSpace::AppData)
                       .setLargestAckedPacket(pn)
                       .build();
  ackEvent1.ackedBytes = 1000;
  auto lastAckedPacketSentTime = ackTime1 - 200us;
  auto lastAckedPacketAckTime = ackTime1 - 100us;
  auto packet = makeTestingWritePacket(pn, 1000, 1000 + 1000 * pn);
  packet.isAppLimited = true;
  packet.lastAckedPacketInfo.emplace(
      lastAckedPacketSentTime,
      lastAckedPacketAckTime,
      lastAckedPacketAckTime,
      0,
      0);
  auto packetSentTime = packet.metadata.time = ackTime1 - 50us;
  ackEvent1.ackedPackets.push_back(
      makeAckPacketFromOutstandingPacket(std::move(packet)));
  // AppLimited packet, but sample is larger than current best
  sampler.onPacketAcked(ackEvent1, 0);
  EXPECT_LT(0, sampler.getBandwidth().units);
  auto bandwidth = sampler.getBandwidth();

  pn++;
  auto packet1 = makeTestingWritePacket(pn, 1000, 1000 + 1000 * pn);
  packet1.isAppLimited = true;
  packet1.lastAckedPacketInfo.emplace(
      packetSentTime, ackTime1, ackTime1, 1000, 0);
  packet1.metadata.time = ackTime1 + 500us;
  auto ackTime2 = ackTime1 + 2000us;
  auto ackEvent2 = AckEvent::Builder()
                       .setAckTime(ackTime2)
                       .setAdjustedAckTime(ackTime2)
                       .setAckDelay(0us)
                       .setPacketNumberSpace(PacketNumberSpace::AppData)
                       .setLargestAckedPacket(pn)
                       .build();
  ackEvent2.ackedBytes = 1000;
  ackEvent2.ackedPackets.push_back(
      makeAckPacketFromOutstandingPacket(std::move(packet1)));

  // AppLimited packet, bandwidth sampler is less than current best
  sampler.onPacketAcked(ackEvent2, 0);
  EXPECT_EQ(bandwidth, sampler.getBandwidth());
}
} // namespace test
} // namespace quic
