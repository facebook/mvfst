/*
 * Copyright (c) Facebook, Inc. and its affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 *
 */

#include <quic/congestion_control/Pacer.h>
#include <folly/portability/GTest.h>

using namespace testing;

namespace quic {
namespace test {

namespace {
void consumeTokensHelper(Pacer& pacer, size_t tokensToConsume) {
  for (size_t i = 0; i < tokensToConsume; i++) {
    pacer.onPacketSent(1000);
  }
}
} // namespace

class PacerTest : public Test {
 public:
  void SetUp() override {
    conn.transportSettings.pacingTimerTickInterval = 1us;
  }

 protected:
  QuicConnectionStateBase conn{QuicNodeType::Client};
  DefaultPacer pacer{conn, conn.transportSettings.minCwndInMss};
};

TEST_F(PacerTest, WriteBeforeScheduled) {
  EXPECT_EQ(
      conn.transportSettings.writeConnectionDataPacketsLimit,
      pacer.updateAndGetWriteBatchSize(Clock::now()));
  EXPECT_EQ(0us, pacer.getTimeUntilNextWrite());
}

TEST_F(PacerTest, RateCalculator) {
  pacer.setPacingRateCalculator([](const QuicConnectionStateBase&,
                                   uint64_t,
                                   uint64_t,
                                   std::chrono::microseconds) {
    return PacingRate::Builder().setInterval(500ms).setBurstSize(4321).build();
  });
  auto currentTime = Clock::now();
  pacer.refreshPacingRate(200000, 200us);
  EXPECT_EQ(0us, pacer.getTimeUntilNextWrite());
  EXPECT_EQ(4321, pacer.updateAndGetWriteBatchSize(currentTime));
  consumeTokensHelper(pacer, 4321);
  EXPECT_NEAR(
      std::chrono::duration_cast<std::chrono::microseconds>(
          500ms + currentTime - Clock::now())
          .count(),
      pacer.getTimeUntilNextWrite().count(),
      2000);
}

TEST_F(PacerTest, CompensateTimerDrift) {
  pacer.setPacingRateCalculator([](const QuicConnectionStateBase&,
                                   uint64_t,
                                   uint64_t,
                                   std::chrono::microseconds) {
    return PacingRate::Builder().setInterval(1000us).setBurstSize(10).build();
  });
  auto currentTime = Clock::now();
  pacer.refreshPacingRate(20, 100us); // These two values do not matter here
  // After refresh, both last and next write time is very close to currentTime
  EXPECT_NEAR(10, pacer.updateAndGetWriteBatchSize(currentTime + 1000us), 2);
  // lastWriteTime ~= currentTime, nextWriteTime ~= currentTime + 1000us

  EXPECT_NEAR(20, pacer.updateAndGetWriteBatchSize(currentTime + 2000us), 2);
  // lastWriteTime ~= currentTime + 1000us, nextWriteTime ~= currentTime +
  // 2000us

  // Consume a few:
  consumeTokensHelper(pacer, 3);

  EXPECT_NEAR(20, pacer.updateAndGetWriteBatchSize(currentTime + 2000us), 2);
}

TEST_F(PacerTest, NextWriteTime) {
  EXPECT_EQ(0us, pacer.getTimeUntilNextWrite());

  pacer.setPacingRateCalculator([](const QuicConnectionStateBase&,
                                   uint64_t,
                                   uint64_t,
                                   std::chrono::microseconds rtt) {
    return PacingRate::Builder().setInterval(rtt).setBurstSize(10).build();
  });
  auto currentTime = Clock::now();
  pacer.refreshPacingRate(20, 100ms);
  // Right after refresh, it's always 0us. You can always send right after an
  // ack.
  EXPECT_EQ(0us, pacer.getTimeUntilNextWrite());

  pacer.updateAndGetWriteBatchSize(currentTime);
  // Consume all the tokens:
  consumeTokensHelper(pacer, 10);

  // Then we use real delay:
  EXPECT_NEAR(100 * 1000, pacer.getTimeUntilNextWrite().count(), 1000);
}

TEST_F(PacerTest, ImpossibleToPace) {
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

TEST_F(PacerTest, CachedBatchSize) {
  EXPECT_EQ(
      conn.transportSettings.writeConnectionDataPacketsLimit,
      pacer.getCachedWriteBatchSize());
  pacer.setPacingRateCalculator([](const QuicConnectionStateBase& conn,
                                   uint64_t cwndBytes,
                                   uint64_t,
                                   std::chrono::microseconds rtt) {
    return PacingRate::Builder()
        .setInterval(rtt)
        .setBurstSize(cwndBytes / conn.udpSendPacketLen * 2)
        .build();
  });
  auto currentTime = Clock::now();
  pacer.refreshPacingRate(20 * conn.udpSendPacketLen, 100ms);
  EXPECT_EQ(40, pacer.getCachedWriteBatchSize());

  pacer.updateAndGetWriteBatchSize(currentTime);
  // lastWriteTime ~= currentTime, nextWriteTime_ ~= currentTime + 100ms
  EXPECT_EQ(40, pacer.getCachedWriteBatchSize());

  EXPECT_EQ(80, pacer.updateAndGetWriteBatchSize(currentTime + 200ms));
  EXPECT_EQ(40, pacer.getCachedWriteBatchSize());
}

TEST_F(PacerTest, AppLimited) {
  conn.transportSettings.writeConnectionDataPacketsLimit = 12;
  pacer.setAppLimited(true);
  EXPECT_EQ(0us, pacer.getTimeUntilNextWrite());
  EXPECT_EQ(12, pacer.updateAndGetWriteBatchSize(Clock::now()));
}

TEST_F(PacerTest, PacingLimited) {
  pacer.setPacingRateCalculator([](const QuicConnectionStateBase& conn,
                                   uint64_t cwndBytes,
                                   uint64_t,
                                   std::chrono::microseconds rtt) {
    return PacingRate::Builder()
        .setInterval(rtt)
        .setBurstSize(cwndBytes / conn.udpSendPacketLen)
        .build();
  });
  pacer.refreshPacingRate(2000 * conn.udpSendPacketLen, 1us);
  pacer.onPacketSent(1);
  EXPECT_TRUE(pacer.isPacingLimited());
}
} // namespace test
} // namespace quic
