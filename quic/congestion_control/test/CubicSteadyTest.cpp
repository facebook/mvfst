/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <folly/portability/GTest.h>
#include <quic/common/test/TestUtils.h>
#include <quic/congestion_control/QuicCubic.h>

using namespace quic;
using namespace quic::test;
using namespace testing;

class CubicSteadyTest : public Test {};

TEST_F(CubicSteadyTest, CubicReduction) {
  QuicConnectionStateBase conn(QuicNodeType::Client);
  // initCwnd > initSsthresh: an ack will immediately make the state machine
  // transit to Steady state:
  conn.udpSendPacketLen = 200; // initCwnd = 2000, minCwnd = 400
  Cubic cubic(conn, 0, 1000);

  // Send one and get acked, this moves the state machine to steady. Cwnd will
  // be 3000, inflight will be 0
  auto packet0 = makeTestingWritePacket(0, 1000, 1000);
  conn.lossState.largestSent = 0;
  cubic.onPacketSent(packet0);
  cubic.onPacketAckOrLoss(
      makeAck(0, 1000, Clock::now(), packet0.metadata.time), folly::none);
  EXPECT_EQ(3000, cubic.getWritableBytes());
  EXPECT_EQ(CubicStates::Steady, cubic.state());

  // Send one and get lost, this moves the state machine to FastRecovery. Cwnd
  // will be reduced, inflight will be 0
  auto packet1 = makeTestingWritePacket(1, 1000, 2000);
  conn.lossState.largestSent = 1;
  cubic.onPacketSent(packet1);
  CongestionController::LossEvent loss;
  loss.addLostPacket(packet1);
  cubic.onPacketAckOrLoss(folly::none, std::move(loss));
  EXPECT_EQ(2100, cubic.getWritableBytes());
  EXPECT_EQ(CubicStates::FastRecovery, cubic.state());
}
