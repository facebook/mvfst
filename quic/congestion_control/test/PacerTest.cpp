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

namespace {
void consumeTokensHelper(Pacer& pacer, size_t tokensToConsume) {
  for (size_t i = 0; i < tokensToConsume; i++) {
    pacer.onPacketSent();
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

class TokenlessPacerTest : public Test {
 public:
  void SetUp() override {
    conn.transportSettings.pacingTimerTickInterval = 1us;
  }

 protected:
  QuicConnectionStateBase conn{QuicNodeType::Client};
  TokenlessPacer pacer{conn, conn.transportSettings.minCwndInMss};
};

TEST_F(PacerTest, WriteBeforeScheduled) {
  EXPECT_EQ(
      conn.transportSettings.writeConnectionDataPacketsLimit,
      pacer.updateAndGetWriteBatchSize(Clock::now()));
  EXPECT_EQ(0us, pacer.getTimeUntilNextWrite());
}

TEST_F(TokenlessPacerTest, WriteBeforeScheduled) {
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
    return PacingRate::Builder().setInterval(1234us).setBurstSize(4321).build();
  });
  pacer.refreshPacingRate(200000, 200us);
  EXPECT_EQ(0us, pacer.getTimeUntilNextWrite());
  EXPECT_EQ(4321, pacer.updateAndGetWriteBatchSize(Clock::now()));
  consumeTokensHelper(pacer, 4321);
  EXPECT_EQ(1234us, pacer.getTimeUntilNextWrite());
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
  EXPECT_EQ(10, pacer.updateAndGetWriteBatchSize(currentTime + 1000us));
  EXPECT_EQ(20, pacer.updateAndGetWriteBatchSize(currentTime + 2000us));
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

TEST_F(PacerTest, NextWriteTime) {
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

  // Consume all the tokens:
  consumeTokensHelper(
      pacer, 10 + conn.transportSettings.writeConnectionDataPacketsLimit);

  // Then we use real delay:
  EXPECT_EQ(1000us, pacer.getTimeUntilNextWrite());
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
  pacer.refreshPacingRate(20 * conn.udpSendPacketLen, 100ms);
  EXPECT_EQ(40, pacer.getCachedWriteBatchSize());

  auto currentTime = Clock::now();
  pacer.updateAndGetWriteBatchSize(currentTime);
  EXPECT_EQ(40, pacer.getCachedWriteBatchSize());

  pacer.updateAndGetWriteBatchSize(currentTime + 200ms);
  EXPECT_EQ(120, pacer.getCachedWriteBatchSize());
}

TEST_F(PacerTest, Tokens) {
  // Pacer has tokens right after init:
  auto currentTime = Clock::now();
  EXPECT_EQ(0us, pacer.getTimeUntilNextWrite());
  EXPECT_EQ(
      conn.transportSettings.writeConnectionDataPacketsLimit,
      pacer.updateAndGetWriteBatchSize(currentTime));

  // Consume all initial tokens:
  consumeTokensHelper(
      pacer, conn.transportSettings.writeConnectionDataPacketsLimit);

  // Pacing rate: 10 mss per 10 ms
  pacer.setPacingRateCalculator([](const QuicConnectionStateBase&,
                                   uint64_t,
                                   uint64_t,
                                   std::chrono::microseconds) {
    return PacingRate::Builder().setInterval(10ms).setBurstSize(10).build();
  });

  // These input doesn't matter, the rate calculator above returns fixed values.
  pacer.refreshPacingRate(100, 100ms, currentTime);

  EXPECT_EQ(0us, pacer.getTimeUntilNextWrite());
  EXPECT_EQ(10 + 10, pacer.updateAndGetWriteBatchSize(currentTime + 10ms));

  // Consume all tokens:
  consumeTokensHelper(pacer, 20);

  EXPECT_EQ(10ms, pacer.getTimeUntilNextWrite());
  EXPECT_EQ(0, pacer.updateAndGetWriteBatchSize(currentTime + 10ms));

  // 10ms later you should have 10 mss credit:
  EXPECT_EQ(10, pacer.updateAndGetWriteBatchSize(currentTime + 20ms));

  // Schedule again from this point:
  // Then elapse another 10ms, and previous tokens hasn't been used:
  EXPECT_EQ(20, pacer.updateAndGetWriteBatchSize(currentTime + 30ms));

  // Refresh the pacing rate between writes. Our rate never changes, so we
  // should end up with batchSize (10) + the amount since the last write (10)
  // = 20.
  pacer.refreshPacingRate(100, 100ms, currentTime + 40ms);
  // After this call, we should collect an additional 10 tokens, as 10ms have
  // elapsed since the refresh call.
  EXPECT_EQ(30, pacer.updateAndGetWriteBatchSize(currentTime + 50ms));

  // Simulate going to app-limited by consuming a single token.
  consumeTokensHelper(pacer, 1);
  // Reset the pacing tokens, we should effectively be totally reset.
  pacer.resetPacingTokens();
  EXPECT_EQ(0ms, pacer.getTimeUntilNextWrite());
  EXPECT_EQ(10, pacer.updateAndGetWriteBatchSize(currentTime + 500ms));
}

} // namespace test
} // namespace quic
