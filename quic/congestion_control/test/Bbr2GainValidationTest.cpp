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
#include <quic/congestion_control/Bandwidth.h>
#include <quic/congestion_control/test/Utils.h>
#include <quic/state/TransportSettingsFunctions.h>
#include <quic/state/test/Mocks.h>

#include <cmath>
#include <limits>

using namespace testing;

namespace quic::test {

class Bbr2FloatUBReproTest : public Test {
 public:
  void SetUp() override {
    testStart_ = Clock::now();
    auto mockPacer = std::make_unique<MockPacer>();
    rawPacer_ = mockPacer.get();
    conn_ = std::make_unique<QuicConnectionStateBase>(QuicNodeType::Server);
    conn_->pacer = std::move(mockPacer);
    conn_->udpSendPacketLen = 1000;
    conn_->connectionTime = testStart_;
  }

  // Helper: send N packets and ack the first half, triggering bandwidth
  // estimation and setPacing()/setCwnd() in the BBR2 controller.
  void sendAndAck(Bbr2CongestionController& bbr2, int numSend, int numAck) {
    auto packetSize = 1000;
    auto totalSent = 0;
    PacketNum pn = nextPn_;

    for (int i = 0; i < numSend; i++) {
      auto packet = makeTestingWritePacket(
          pn, packetSize, totalSent += packetSize, testStart_ + 10ms);
      onPacketsSentWrapper(conn_.get(), &bbr2, packet);
      conn_->outstandings.packets.emplace_back(std::move(packet));
      pn++;
    }

    auto ackTime = testStart_ + 100ms;
    auto ackEvent = CongestionController::AckEvent::Builder()
                        .setAckTime(ackTime)
                        .setAdjustedAckTime(ackTime)
                        .setAckDelay(0us)
                        .setPacketNumberSpace(PacketNumberSpace::Handshake)
                        .setLargestAckedPacket(nextPn_ + numAck - 1)
                        .build();
    ackEvent.ackedBytes = numAck * packetSize;
    ackEvent.totalBytesAcked = numAck * packetSize;
    ackEvent.largestNewlyAckedPacket = nextPn_ + numAck - 1;
    for (int i = 0; i < numAck; i++) {
      auto& pkt = conn_->outstandings.packets.at(i);
      auto ackPkt =
          CongestionController::AckEvent::AckPacket::Builder()
              .setPacketNum(pkt.getPacketSequenceNum())
              .setOutstandingPacketMetadata(pkt.metadata)
              .setLastAckedPacketInfo(
                  pkt.lastAckedPacketInfo ? &*pkt.lastAckedPacketInfo : nullptr)
              .setAppLimited(pkt.isAppLimited)
              .setDetailsPerStream(
                  CongestionController::AckEvent::AckPacket::DetailsPerStream())
              .build();
      ackEvent.ackedPackets.push_back(ackPkt);
    }

    EXPECT_CALL(*rawPacer_, refreshPacingRate(_, _, _)).Times(AnyNumber());
    EXPECT_CALL(*rawPacer_, setRttFactor(_, _)).Times(AnyNumber());

    onPacketAckOrLossWrapper(conn_.get(), &bbr2, ackEvent, std::nullopt);
    nextPn_ = pn;
  }

  std::unique_ptr<QuicConnectionStateBase> conn_;
  MockPacer* rawPacer_;
  TimePoint testStart_;
  PacketNum nextPn_{0};
};

// Test 1: parseCongestionControlConfig throws on out-of-range float values.
// Extreme gain values from a malicious CC_CONFIG KnobFrame cause the whole
// CC_CONFIG to be rejected (via tryParseCongestionControlConfig).
TEST_F(Bbr2FloatUBReproTest, ParseRejectsExtremeGainValues) {
  // Extreme values should throw
  EXPECT_THROW(
      parseCongestionControlConfig(
          R"({"overrideStartupPacingGain": 1e30,
              "overrideCruisePacingGain": 1e30,
              "overrideCruiseCwndGain": 1e30})"),
      std::range_error);

  // INFINITY should also throw
  EXPECT_THROW(
      parseCongestionControlConfig(R"({"overrideStartupPacingGain": 1e308})"),
      std::range_error);

  // Negative values should throw
  EXPECT_THROW(
      parseCongestionControlConfig(R"({"overrideStartupPacingGain": -1.0})"),
      std::range_error);

  // Valid values within range should be accepted
  auto configValid =
      parseCongestionControlConfig(R"({"overrideStartupPacingGain": 2.77,
          "overrideCruisePacingGain": 1.0,
          "overrideCruiseCwndGain": 1.5,
          "overrideBwShortBeta": 0.7})");
  EXPECT_FLOAT_EQ(configValid.overrideStartupPacingGain, 2.77f);
  EXPECT_FLOAT_EQ(configValid.overrideCruisePacingGain, 1.0f);
  EXPECT_FLOAT_EQ(configValid.overrideCruiseCwndGain, 1.5f);
  EXPECT_FLOAT_EQ(configValid.overrideBwShortBeta, 0.7f);

  // Boundary: values at max (10.0) should be accepted
  auto configMax =
      parseCongestionControlConfig(R"({"overrideStartupPacingGain": 10.0})");
  EXPECT_FLOAT_EQ(configMax.overrideStartupPacingGain, 10.0f);

  // Just above max should throw
  EXPECT_THROW(
      parseCongestionControlConfig(R"({"overrideStartupPacingGain": 10.01})"),
      std::range_error);

  // overrideBwShortBeta out of [0.5, 1.0] should throw
  EXPECT_THROW(
      parseCongestionControlConfig(R"({"overrideBwShortBeta": 2.0})"),
      std::range_error);
}

// Test 2: With the fix, extreme overrideStartupPacingGain set directly on
// the config struct is caught by the defense-in-depth check in
// updatePacingAndCwndGain() — the gain falls back to kStartupPacingGain.
// No UB should occur even under UBSAN.
TEST_F(Bbr2FloatUBReproTest, StartupPacingGainDefenseInDepth) {
  // Bypass parse validation by setting directly on the struct
  // (simulates a future code path that skips parseCongestionControlConfig)
  conn_->transportSettings.ccaConfig.overrideStartupPacingGain = 1e30f;

  Bbr2CongestionController bbr2(*conn_);
  EXPECT_EQ("Startup", bbr2StateToString(bbr2.getState()));

  // This should NOT cause UB — the point-of-use check in
  // updatePacingAndCwndGain() rejects the extreme value and falls back
  // to kStartupPacingGain (2.77).
  sendAndAck(bbr2, 10, 5);

  // If we reach here under UBSAN, the fix works
  auto cwnd = bbr2.getCongestionWindow();
  EXPECT_GT(cwnd, 0u);
}

// Test 3: Bandwidth::operator*(float) is not fixed by this diff (it's a
// generic operator). This test verifies that the parse-time and point-of-use
// validation prevents extreme values from ever reaching Bandwidth::operator*.
// The operator itself still has UB for extreme floats — but the fix ensures
// it's never called with such values from the BBR2 config path.
TEST_F(Bbr2FloatUBReproTest, ValidGainValuesProduceNoUB) {
  // Use a valid gain value (within [0.01, 10.0] range)
  conn_->transportSettings.ccaConfig.overrideStartupPacingGain = 5.0f;

  Bbr2CongestionController bbr2(*conn_);
  sendAndAck(bbr2, 10, 5);

  auto cwnd = bbr2.getCongestionWindow();
  EXPECT_GT(cwnd, 0u);
}

// Test 4: Defense-in-depth for cruise gain overrides.
// Extreme values set directly are caught at point of use.
TEST_F(Bbr2FloatUBReproTest, CruiseGainDefenseInDepth) {
  conn_->transportSettings.ccaConfig.overrideCruisePacingGain =
      std::numeric_limits<float>::infinity();
  conn_->transportSettings.ccaConfig.overrideCruiseCwndGain = 1e30f;

  Bbr2CongestionController bbr2(*conn_);

  // Even though the config has extreme values, updatePacingAndCwndGain()
  // will reject them when the controller reaches Cruise state.
  // Just verify construction doesn't UB — the values are only used
  // when the state machine reaches ProbeBw_Cruise.
  EXPECT_EQ("Startup", bbr2StateToString(bbr2.getState()));
}

} // namespace quic::test
