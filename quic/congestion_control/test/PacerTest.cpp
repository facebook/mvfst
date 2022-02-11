/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <quic/congestion_control/Pacer.h>

#include <folly/portability/GTest.h>
#include <quic/congestion_control/TokenlessPacer.h>
#include <quic/state/test/MockQuicStats.h>
#include <quic/state/test/Mocks.h>

using namespace testing;

namespace quic {
namespace test {

class TokenlessPacerTest : public Test {
 public:
  void SetUp() override {
    conn.transportSettings.pacingTimerTickInterval = 1us;
  }

 protected:
  QuicConnectionStateBase conn{QuicNodeType::Client};
  TokenlessPacer pacer{conn, conn.transportSettings.minCwndInMss};
};

TEST_F(TokenlessPacerTest, RateCalculator) {
  pacer.setPacingRateCalculator([](const QuicConnectionStateBase&,
                                   uint64_t,
                                   uint64_t,
                                   std::chrono::microseconds) {
    return PacingRate::Builder().setInterval(1234us).setBurstSize(4321).build();
  });
  pacer.refreshPacingRate(200000, 200us);
  EXPECT_EQ(0us, pacer.getTimeUntilNextWrite());
  EXPECT_EQ(4321, pacer.updateAndGetWriteBatchSize(Clock::now()));
  EXPECT_NEAR(1234, pacer.getTimeUntilNextWrite().count(), 100);
}

TEST_F(TokenlessPacerTest, NoCompensateTimerDrift) {
  pacer.setPacingRateCalculator([](const QuicConnectionStateBase&,
                                   uint64_t,
                                   uint64_t,
                                   std::chrono::microseconds) {
    return PacingRate::Builder().setInterval(1000us).setBurstSize(10).build();
  });
  auto currentTime = Clock::now();
  pacer.refreshPacingRate(20, 100us); // These two values do not matter here
  EXPECT_EQ(10, pacer.updateAndGetWriteBatchSize(currentTime + 1000us));
  EXPECT_EQ(10, pacer.updateAndGetWriteBatchSize(currentTime + 2000us));
}

TEST_F(TokenlessPacerTest, CompensateTimerDriftForExperimental) {
  auto mockCongestionController = std::make_unique<MockCongestionController>();
  auto rawCongestionController = mockCongestionController.get();
  conn.congestionController = std::move(mockCongestionController);
  EXPECT_CALL(*rawCongestionController, isAppLimited())
      .WillRepeatedly(Return(false));

  auto mockStats = std::make_shared<MockQuicStats>();
  conn.statsCallback = mockStats.get();
  // This should be called for two of the three updateAndGetWriteBatchSize calls
  // below.
  EXPECT_CALL(*mockStats, onPacerTimerLagged()).Times(2);

  pacer.setPacingRateCalculator([](const QuicConnectionStateBase&,
                                   uint64_t,
                                   uint64_t,
                                   std::chrono::microseconds) {
    return PacingRate::Builder().setInterval(1000us).setBurstSize(10).build();
  });

  pacer.setExperimental(true);
  auto currentTime = Clock::now();
  pacer.refreshPacingRate(20, 100us); // These two values do not matter here
  EXPECT_EQ(10, pacer.updateAndGetWriteBatchSize(currentTime + 1000us));

  // 2 intervals later should return twice the burst size
  EXPECT_EQ(20, pacer.updateAndGetWriteBatchSize(currentTime + 3000us));

  // 6 intervals later should only return 50 (maxBurstInterval * 10)
  EXPECT_EQ(50, pacer.updateAndGetWriteBatchSize(currentTime + 9000us));
}

TEST_F(TokenlessPacerTest, NextWriteTime) {
  EXPECT_EQ(0us, pacer.getTimeUntilNextWrite());

  pacer.setPacingRateCalculator([](const QuicConnectionStateBase&,
                                   uint64_t,
                                   uint64_t,
                                   std::chrono::microseconds rtt) {
    return PacingRate::Builder().setInterval(rtt).setBurstSize(10).build();
  });
  pacer.refreshPacingRate(20, 1000us);
  // Right after refresh, it's always 0us. You can always send right after an
  // ack.
  EXPECT_EQ(0us, pacer.getTimeUntilNextWrite());
  EXPECT_EQ(10, pacer.updateAndGetWriteBatchSize(Clock::now()));

  // Then we use real delay:
  EXPECT_NEAR(1000, pacer.getTimeUntilNextWrite().count(), 100);
}

TEST_F(TokenlessPacerTest, RttFactor) {
  auto realRtt = 100ms;
  bool calculatorCalled = false;
  pacer.setRttFactor(1, 2);
  pacer.setPacingRateCalculator([&](const QuicConnectionStateBase&,
                                    uint64_t,
                                    uint64_t,
                                    std::chrono::microseconds rtt) {
    EXPECT_EQ(rtt, realRtt / 2);
    calculatorCalled = true;
    return PacingRate::Builder().setInterval(rtt).setBurstSize(10).build();
  });
  pacer.refreshPacingRate(20, realRtt);
  EXPECT_TRUE(calculatorCalled);
}

TEST_F(TokenlessPacerTest, ImpossibleToPace) {
  conn.transportSettings.pacingTimerTickInterval = 1ms;
  pacer.setPacingRateCalculator([](const QuicConnectionStateBase& conn,
                                   uint64_t cwndBytes,
                                   uint64_t,
                                   std::chrono::microseconds rtt) {
    return PacingRate::Builder()
        .setInterval(rtt)
        .setBurstSize(cwndBytes / conn.udpSendPacketLen)
        .build();
  });
  pacer.refreshPacingRate(200 * conn.udpSendPacketLen, 100us);
  EXPECT_EQ(0us, pacer.getTimeUntilNextWrite());
  EXPECT_EQ(
      conn.transportSettings.writeConnectionDataPacketsLimit,
      pacer.updateAndGetWriteBatchSize(Clock::now()));
}

TEST_F(TokenlessPacerTest, ChangeMaxPacingRate) {
  int calculatorCallCount = 0;
  pacer.setPacingRateCalculator([&calculatorCallCount](
                                    const QuicConnectionStateBase& conn,
                                    uint64_t cwndBytes,
                                    uint64_t,
                                    std::chrono::microseconds rtt) {
    calculatorCallCount++;
    return PacingRate::Builder()
        .setInterval(rtt)
        .setBurstSize(cwndBytes / conn.udpSendPacketLen)
        .build();
  });
  auto rtt = 500 * 1000us;
  auto timestamp = Clock::now();
  // Request pacing at 50 Mbps
  pacer.refreshPacingRate(3125000, rtt);
  EXPECT_EQ(1, calculatorCallCount);
  EXPECT_EQ(
      3125000 / kDefaultUDPSendPacketLen,
      pacer.updateAndGetWriteBatchSize(timestamp));
  EXPECT_EQ(rtt.count(), pacer.getTimeUntilNextWrite(timestamp).count());

  // Set max pacing rate to 40 Mbps
  pacer.setMaxPacingRate(5 * 1000 * 1000u); // Bytes per second
  // This should bring down the pacer rate to 40 Mbps
  EXPECT_EQ(0us, pacer.getTimeUntilNextWrite(timestamp));
  auto burst = pacer.updateAndGetWriteBatchSize(timestamp);
  auto interval = pacer.getTimeUntilNextWrite(timestamp);
  uint64_t pacerRate =
      burst * kDefaultUDPSendPacketLen * std::chrono::seconds{1} / interval;
  EXPECT_EQ(5 * 1000 * 1000u, pacerRate);
  pacer.reset();
  // Requesting a rate of 50 Mbps should not change interval or burst
  pacer.refreshPacingRate(3125000, rtt);
  EXPECT_EQ(1, calculatorCallCount); // Calculator not called again.
  EXPECT_EQ(burst, pacer.updateAndGetWriteBatchSize(timestamp));
  EXPECT_EQ(interval.count(), pacer.getTimeUntilNextWrite(timestamp).count());
  pacer.reset();

  // The setPacingRate API shouldn't make changes either
  pacer.setPacingRate(6250 * 1000u); // 50 Mbps
  EXPECT_EQ(burst, pacer.updateAndGetWriteBatchSize(timestamp));
  EXPECT_EQ(interval.count(), pacer.getTimeUntilNextWrite(timestamp).count());
  pacer.reset();

  // Increasing max pacing rate to 75 Mbps shouldn't make changes
  pacer.setMaxPacingRate(9375 * 1000u);
  EXPECT_EQ(burst, pacer.updateAndGetWriteBatchSize(timestamp));
  EXPECT_EQ(interval.count(), pacer.getTimeUntilNextWrite(timestamp).count());
  pacer.reset();

  // Increase pacing to 50 Mbps and ensure it takes effect
  pacer.refreshPacingRate(3125000, rtt);
  EXPECT_EQ(2, calculatorCallCount); // Calculator called
  EXPECT_EQ(
      3125000 / kDefaultUDPSendPacketLen,
      pacer.updateAndGetWriteBatchSize(timestamp));
  EXPECT_EQ(rtt.count(), pacer.getTimeUntilNextWrite(timestamp).count());
  pacer.reset();

  // Increase pacing to 80 Mbps using alternative API and ensure rate is limited
  // to 75 Mbps
  pacer.setPacingRate(10 * 1000 * 1000u);
  burst = pacer.updateAndGetWriteBatchSize(timestamp);
  interval = pacer.getTimeUntilNextWrite(timestamp);
  pacerRate =
      burst * kDefaultUDPSendPacketLen * std::chrono::seconds{1} / interval;
  EXPECT_NEAR(9375 * 1000u, pacerRate, 1000); // To accommodate rounding
}

TEST_F(TokenlessPacerTest, SetMaxPacingRateOnUnlimitedPacer) {
  auto timestamp = Clock::now();
  // Pacing is currently not pacing
  EXPECT_EQ(0us, pacer.getTimeUntilNextWrite(timestamp));
  EXPECT_NE(0, pacer.updateAndGetWriteBatchSize(timestamp));
  EXPECT_EQ(0us, pacer.getTimeUntilNextWrite(timestamp));

  // Set max pacing rate 40 Mbps and ensure it took effect
  pacer.setMaxPacingRate(5 * 1000 * 1000u); // Bytes per second
  EXPECT_EQ(0us, pacer.getTimeUntilNextWrite(timestamp));
  auto burst = pacer.updateAndGetWriteBatchSize(timestamp);
  auto interval = pacer.getTimeUntilNextWrite(timestamp);
  uint64_t pacerRate =
      burst * kDefaultUDPSendPacketLen * std::chrono::seconds{1} / interval;
  EXPECT_NEAR(5 * 1000 * 1000u, pacerRate, 1000); // To accommodate rounding
}

TEST_F(TokenlessPacerTest, SetZeroPacingRate) {
  auto timestamp = Clock::now();
  // A Zero pacing rate should not result in a divide-by-zero
  conn.transportSettings.pacingTimerTickInterval = 1000us;
  pacer.setPacingRate(0);
  EXPECT_EQ(0, pacer.updateAndGetWriteBatchSize(timestamp));
  EXPECT_EQ(1000, pacer.getTimeUntilNextWrite(timestamp).count());
}

TEST_F(TokenlessPacerTest, RefreshPacingRateWhenRTTIsZero) {
  auto timestamp = Clock::now();
  // rtt=0 should not result in a divide-by-zero
  conn.transportSettings.pacingTimerTickInterval = 1000us;
  pacer.refreshPacingRate(100, 0us);
  // Verify burst is writeConnectionDataPacketsLimit and interval is
  // 0us right after writing
  EXPECT_EQ(
      conn.transportSettings.writeConnectionDataPacketsLimit,
      pacer.updateAndGetWriteBatchSize(timestamp));
  EXPECT_EQ(0us, pacer.getTimeUntilNextWrite(timestamp));
}

TEST_F(TokenlessPacerTest, RefreshPacingRateWhenRTTIsDefault) {
  auto timestamp = Clock::now();
  auto tick = 1000us;
  pacer.setPacingRateCalculator([](const QuicConnectionStateBase&,
                                   uint64_t cwnd,
                                   uint64_t,
                                   std::chrono::microseconds rtt) {
    return PacingRate::Builder().setInterval(rtt).setBurstSize(cwnd).build();
  });
  conn.transportSettings.pacingTimerTickInterval = tick;

  // rtt=kDefaultMinRTT should result in this update being skipped
  // There should be no pacing. Interval and Burst should use the defaults
  pacer.refreshPacingRate(100, kDefaultMinRtt);
  EXPECT_EQ(
      conn.transportSettings.writeConnectionDataPacketsLimit,
      pacer.updateAndGetWriteBatchSize(timestamp));
  EXPECT_EQ(0us, pacer.getTimeUntilNextWrite(timestamp));

  // This won't be skipped
  pacer.refreshPacingRate(
      20, tick); // writes these values to the burst and interval directly
  EXPECT_EQ(20, pacer.updateAndGetWriteBatchSize(timestamp));
  EXPECT_EQ(tick, pacer.getTimeUntilNextWrite(timestamp));

  // rtt=kDefaultMinRTT should result in this update being skipped
  // Interval should not change.
  pacer.refreshPacingRate(100, kDefaultMinRtt);
  EXPECT_EQ(tick, pacer.getTimeUntilNextWrite(timestamp));
}

} // namespace test
} // namespace quic
