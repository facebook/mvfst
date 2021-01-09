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
} // namespace test
} // namespace quic
