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
#include <quic/state/StateData.h>

using namespace quic;
using namespace testing;

constexpr QuicVersion kVersion = static_cast<QuicVersion>(0);

namespace quic {
namespace test {

class StateDataTest : public Test {};

TEST_F(StateDataTest, EmptyLossEvent) {
  CongestionController::LossEvent loss;
  EXPECT_EQ(0, loss.lostBytes);
  EXPECT_FALSE(loss.largestLostPacketNum);
}

TEST_F(StateDataTest, SingleLostPacketEvent) {
  RegularQuicWritePacket packet(LongHeader(
      LongHeader::Types::Initial,
      getTestConnectionId(1),
      getTestConnectionId(),
      100,
      kVersion));
  OutstandingPacket outstandingPacket(packet, Clock::now(), 1234, false, 1234, 0);
  CongestionController::LossEvent loss;
  loss.addLostPacket(outstandingPacket);
  EXPECT_EQ(1234, loss.lostBytes);
  EXPECT_EQ(100, *loss.largestLostPacketNum);
}

TEST_F(StateDataTest, MultipleLostPacketsEvent) {
  RegularQuicWritePacket packet1(LongHeader(
      LongHeader::Types::Initial,
      getTestConnectionId(1),
      getTestConnectionId(),
      100,
      kVersion));
  OutstandingPacket outstandingPacket1(
      packet1, Clock::now(), 1234, false, 1234, 0);

  RegularQuicWritePacket packet2(LongHeader(
      LongHeader::Types::Initial,
      getTestConnectionId(1),
      getTestConnectionId(),
      110,
      kVersion));
  OutstandingPacket outstandingPacket2(
      packet2, Clock::now(), 1357, false, 1357, 0);

  CongestionController::LossEvent loss;
  loss.addLostPacket(outstandingPacket1);
  loss.addLostPacket(outstandingPacket2);
  EXPECT_EQ(1234 + 1357, loss.lostBytes);
  EXPECT_EQ(110, *loss.largestLostPacketNum);
}

constexpr size_t kRtt{100000};

class PendingPathRateLimiterTest : public Test {
 public:
  void SetUp() override {
    now = std::chrono::steady_clock::now();
  }

 protected:
  QuicConnectionStateBase conn_{QuicNodeType::Server};
  PendingPathRateLimiter limiter_{conn_.udpSendPacketLen};
  size_t maxWindowBytes{kMinCwndInMss * conn_.udpSendPacketLen};
  TimePoint now;
};

TEST_F(PendingPathRateLimiterTest, TestSetInitialCredit) {
  EXPECT_EQ(
      limiter_.currentCredit(now, std::chrono::microseconds{kRtt}),
      maxWindowBytes);
  conn_.udpSendPacketLen = 2000;
  PendingPathRateLimiter limiter2{conn_.udpSendPacketLen};
  EXPECT_EQ(
      limiter2.currentCredit(now, std::chrono::microseconds{kRtt}),
      kMinCwndInMss * 2000);
}

TEST_F(PendingPathRateLimiterTest, TestNoImmediateCreditRefresh) {
  EXPECT_EQ(
      limiter_.currentCredit(now, std::chrono::microseconds{kRtt}),
      maxWindowBytes);
  limiter_.onPacketSent(420);
  EXPECT_EQ(
      limiter_.currentCredit(now, std::chrono::microseconds{kRtt}),
      maxWindowBytes - 420);
}

TEST_F(PendingPathRateLimiterTest, TestBoundaryRttPassedCreditRefresh) {
  EXPECT_EQ(
      limiter_.currentCredit(now, std::chrono::microseconds{kRtt}),
      maxWindowBytes);
  limiter_.onPacketSent(420);
  auto halfRtt = std::chrono::microseconds(kRtt / 2);
  now += halfRtt;
  EXPECT_EQ(
      limiter_.currentCredit(now, std::chrono::microseconds{kRtt}),
      maxWindowBytes - 420);
  limiter_.onPacketSent(420);
  now += halfRtt;
  EXPECT_EQ(
      limiter_.currentCredit(now, std::chrono::microseconds{kRtt}),
      maxWindowBytes - 840);

  now += std::chrono::microseconds(10);
  EXPECT_EQ(
      limiter_.currentCredit(now, std::chrono::microseconds{kRtt}),
      maxWindowBytes);
}

TEST_F(PendingPathRateLimiterTest, TestCreditRefreshOnInfrequentSends) {
  auto delta =
      std::chrono::microseconds{kRtt} + std::chrono::microseconds{1000};
  EXPECT_EQ(
      limiter_.currentCredit(now, std::chrono::microseconds{kRtt}),
      maxWindowBytes);
  limiter_.onPacketSent(420);
  now += delta;
  EXPECT_EQ(
      limiter_.currentCredit(now, std::chrono::microseconds{kRtt}),
      maxWindowBytes);
  limiter_.onPacketSent(420);
  now += delta;
  EXPECT_EQ(
      limiter_.currentCredit(now, std::chrono::microseconds{kRtt}),
      maxWindowBytes);
}

} // namespace test
} // namespace quic
