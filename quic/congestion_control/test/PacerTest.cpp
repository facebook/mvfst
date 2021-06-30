/*
 * Copyright (c) Facebook, Inc. and its affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 *
 */

#include <quic/congestion_control/Pacer.h>

#include <folly/portability/GTest.h>
#include <quic/congestion_control/TokenlessPacer.h>

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
  // Request pacing at 50 Mbps
  pacer.refreshPacingRate(3125000, rtt);
  EXPECT_EQ(1, calculatorCallCount);
  EXPECT_EQ(
      3125000 / kDefaultUDPSendPacketLen,
      pacer.updateAndGetWriteBatchSize(Clock::now()));
  EXPECT_NEAR(rtt.count(), pacer.getTimeUntilNextWrite().count(), 100);

  // Set max pacing rate to 40 Mbps
  pacer.setMaxPacingRate(5 * 1000 * 1000u); // Bytes per second
  // This should bring down the pacer rate to 40 Mbps
  EXPECT_EQ(0us, pacer.getTimeUntilNextWrite());
  auto burst = pacer.updateAndGetWriteBatchSize(Clock::now());
  auto interval = pacer.getTimeUntilNextWrite();
  uint64_t pacerRate =
      burst * kDefaultUDPSendPacketLen * std::chrono::seconds{1} / interval;
  EXPECT_NEAR(5 * 1000 * 1000u, pacerRate, 5000); // 0.1% cushion for timing
  pacer.reset();
  // Requesting a rate of 50 Mbps should not change interval or burst
  pacer.refreshPacingRate(3125000, rtt);
  EXPECT_EQ(1, calculatorCallCount); // Calculator not called again.
  EXPECT_EQ(burst, pacer.updateAndGetWriteBatchSize(Clock::now()));
  EXPECT_NEAR(interval.count(), pacer.getTimeUntilNextWrite().count(), 1000);
  pacer.reset();

  // The setPacingRate API shouldn't make changes either
  pacer.setPacingRate(6250 * 1000u); // 50 Mbps
  EXPECT_EQ(burst, pacer.updateAndGetWriteBatchSize(Clock::now()));
  EXPECT_NEAR(interval.count(), pacer.getTimeUntilNextWrite().count(), 1000);
  pacer.reset();

  // Increasing max pacing rate to 75 Mbps shouldn't make changes
  pacer.setMaxPacingRate(9375 * 1000u);
  EXPECT_EQ(burst, pacer.updateAndGetWriteBatchSize(Clock::now()));
  EXPECT_NEAR(interval.count(), pacer.getTimeUntilNextWrite().count(), 1000);
  pacer.reset();

  // Increase pacing to 50 Mbps and ensure it takes effect
  pacer.refreshPacingRate(3125000, rtt);
  EXPECT_EQ(2, calculatorCallCount); // Calculator called
  EXPECT_EQ(
      3125000 / kDefaultUDPSendPacketLen,
      pacer.updateAndGetWriteBatchSize(Clock::now()));
  EXPECT_NEAR(rtt.count(), pacer.getTimeUntilNextWrite().count(), 1000);
  pacer.reset();

  // Increase pacing to 80 Mbps using alternative API and ensure rate is limited
  // to 75 Mbps
  pacer.setPacingRate(10 * 1000 * 1000u);
  burst = pacer.updateAndGetWriteBatchSize(Clock::now());
  interval = pacer.getTimeUntilNextWrite();
  pacerRate =
      burst * kDefaultUDPSendPacketLen * std::chrono::seconds{1} / interval;
  EXPECT_NEAR(9375 * 1000u, pacerRate, 9375); // 0.1% cushion for timing
}

TEST_F(TokenlessPacerTest, SetMaxPacingRateOnUnlimitedPacer) {
  // Pacing is currently not pacing
  EXPECT_EQ(0us, pacer.getTimeUntilNextWrite());
  EXPECT_NE(0, pacer.updateAndGetWriteBatchSize(Clock::now()));
  EXPECT_EQ(0us, pacer.getTimeUntilNextWrite());

  // Set max pacing rate 40 Mbps and ensure it took effect
  pacer.setMaxPacingRate(5 * 1000 * 1000u); // Bytes per second
  EXPECT_EQ(0us, pacer.getTimeUntilNextWrite());
  auto burst = pacer.updateAndGetWriteBatchSize(Clock::now());
  auto interval = pacer.getTimeUntilNextWrite();
  uint64_t pacerRate =
      burst * kDefaultUDPSendPacketLen * std::chrono::seconds{1} / interval;
  EXPECT_NEAR(5 * 1000 * 1000u, pacerRate, 5000); // 0.1% cushion for timing
}

TEST_F(TokenlessPacerTest, SetZeroPacingRate) {
  // A Zero pacing rate should not result in a divide-by-zero
  conn.transportSettings.pacingTimerTickInterval = 1000us;
  pacer.setPacingRate(0);
  EXPECT_EQ(0, pacer.updateAndGetWriteBatchSize(Clock::now()));
  EXPECT_NEAR(1000, pacer.getTimeUntilNextWrite().count(), 100);
}

} // namespace test
} // namespace quic
