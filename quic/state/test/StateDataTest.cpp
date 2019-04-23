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
  OutstandingPacket outstandingPacket(
      packet, Clock::now(), 1234, false, false, 1234);
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
      packet1, Clock::now(), 1234, false, false, 1234);

  RegularQuicWritePacket packet2(LongHeader(
      LongHeader::Types::Initial,
      getTestConnectionId(1),
      getTestConnectionId(),
      110,
      kVersion));
  OutstandingPacket outstandingPacket2(
      packet2, Clock::now(), 1357, false, false, 1357);

  CongestionController::LossEvent loss;
  loss.addLostPacket(outstandingPacket1);
  loss.addLostPacket(outstandingPacket2);
  EXPECT_EQ(1234 + 1357, loss.lostBytes);
  EXPECT_EQ(110, *loss.largestLostPacketNum);
}
} // namespace test
} // namespace quic
