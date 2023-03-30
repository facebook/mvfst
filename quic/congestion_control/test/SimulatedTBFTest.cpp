/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <folly/portability/GTest.h>
#include <quic/QuicException.h>
#include <quic/congestion_control/SimulatedTBF.h>

using namespace testing;

namespace quic::test {

class SimulatedTBFTest : public Test {};

TEST_F(SimulatedTBFTest, Init) {
  SimulatedTBF::Config config;
  config.rateBytesPerSecond = 100;
  config.burstSizeBytes = 200;
  SimulatedTBF stbf(config);
  EXPECT_EQ(stbf.getRateBytesPerSecond(), config.rateBytesPerSecond);
  EXPECT_EQ(stbf.getBurstSizeBytes(), config.burstSizeBytes);
  EXPECT_FALSE(stbf.getMaxDebtQueueSizeBytes().has_value());
  EXPECT_EQ(stbf.getNumEmptyIntervalsTracked(), 0);
}

TEST_F(SimulatedTBFTest, InitWithMaxQueueSize) {
  SimulatedTBF::Config config;
  config.rateBytesPerSecond = 100;
  config.burstSizeBytes = 200;
  config.maybeMaxDebtQueueSizeBytes = 400;
  SimulatedTBF stbf(config);
  EXPECT_EQ(stbf.getRateBytesPerSecond(), config.rateBytesPerSecond);
  EXPECT_EQ(stbf.getBurstSizeBytes(), config.burstSizeBytes);
  EXPECT_EQ(stbf.getMaxDebtQueueSizeBytes(), config.maybeMaxDebtQueueSizeBytes);
  EXPECT_EQ(stbf.getNumEmptyIntervalsTracked(), 0);
}

TEST_F(SimulatedTBFTest, InitWithEmptyIntervalsTrackingDisabled) {
  SimulatedTBF::Config config;
  config.rateBytesPerSecond = 100;
  config.burstSizeBytes = 200;
  config.maybeMaxDebtQueueSizeBytes = 400;
  config.trackEmptyIntervals = false;
  SimulatedTBF stbf(config);
  EXPECT_EQ(stbf.getRateBytesPerSecond(), config.rateBytesPerSecond);
  EXPECT_EQ(stbf.getBurstSizeBytes(), config.burstSizeBytes);
  EXPECT_EQ(stbf.getMaxDebtQueueSizeBytes(), config.maybeMaxDebtQueueSizeBytes);
  EXPECT_THROW((void)stbf.getNumEmptyIntervalsTracked(), QuicInternalException);
}

/*
 * Case with empty intervals tracking disabled.
 * Expectations:
 *    - With or without any consume operations, calling the functions that
 *      operate on empty intervals should always throw a QuicInternalException.
 *    - Without empty intervals tracking, the SimulatedTBF should operate as
 *      expected when consuming bytes.
 */
TEST_F(SimulatedTBFTest, EmptyIntervalsTrackingDisabled_WithConsume) {
  SimulatedTBF::Config config;
  config.rateBytesPerSecond = 100;
  config.burstSizeBytes = 200;
  config.maybeMaxDebtQueueSizeBytes = 0;
  config.trackEmptyIntervals = false;
  SimulatedTBF stbf(config);
  const TimePoint t = Clock::now();
  EXPECT_EQ(stbf.getNumAvailableTokensInBytes(t), stbf.getBurstSizeBytes());

  EXPECT_THROW((void)stbf.bucketEmptyAt(t), QuicInternalException);
  EXPECT_THROW(
      (void)stbf.bucketEmptyThroughoutWindow(t, t), QuicInternalException);
  EXPECT_THROW(
      (void)stbf.forgetEmptyIntervalsPriorTo(t), QuicInternalException);

  // Consume 100 bytes
  EXPECT_EQ(stbf.consumeWithBorrowNonBlockingAndUpdateState(100, t), 100);
  EXPECT_EQ(stbf.getNumAvailableTokensInBytes(t), config.burstSizeBytes - 100);
  // Consume the rest of the bytes in bucket
  EXPECT_EQ(
      stbf.consumeWithBorrowNonBlockingAndUpdateState(
          config.burstSizeBytes - 100, t),
      config.burstSizeBytes - 100);
  EXPECT_EQ(stbf.getNumAvailableTokensInBytes(t), 0);
  EXPECT_EQ(stbf.consumeWithBorrowNonBlockingAndUpdateState(1, t), 0);

  EXPECT_THROW((void)stbf.bucketEmptyAt(t), QuicInternalException);
  EXPECT_THROW(
      (void)stbf.bucketEmptyThroughoutWindow(t, t), QuicInternalException);
  EXPECT_THROW(
      (void)stbf.forgetEmptyIntervalsPriorTo(t), QuicInternalException);
}

/*
 * Case with no consume operations, should have no empty intervals.
 */
TEST_F(SimulatedTBFTest, NoConsumeCheckNoEmptyIntervals) {
  SimulatedTBF::Config config;
  config.rateBytesPerSecond = 100;
  config.burstSizeBytes = 200;
  SimulatedTBF stbf(config);
  const TimePoint t = Clock::now();
  EXPECT_EQ(stbf.getNumEmptyIntervalsTracked(), 0);
  EXPECT_FALSE(stbf.bucketEmptyAt(t));
  EXPECT_FALSE(stbf.bucketEmptyThroughoutWindow(t, t));
  EXPECT_FALSE(stbf.bucketEmptyThroughoutWindow(t, t + 20s));
  EXPECT_EQ(stbf.getNumAvailableTokensInBytes(t), stbf.getBurstSizeBytes());
}

/*
 * Case with consuming more than the specified burst size should throw an
 * exception
 */
TEST_F(SimulatedTBFTest, ConsumeMoreThanBurstSize) {
  SimulatedTBF::Config config;
  config.rateBytesPerSecond = 100;
  config.burstSizeBytes = 200;
  SimulatedTBF stbf(config);
  const TimePoint t = Clock::now();
  EXPECT_EQ(stbf.getNumEmptyIntervalsTracked(), 0);
  EXPECT_EQ(stbf.getNumAvailableTokensInBytes(t), stbf.getBurstSizeBytes());
  EXPECT_THROW(
      stbf.consumeWithBorrowNonBlockingAndUpdateState(
          config.burstSizeBytes + 1, t),
      QuicInternalException);
  EXPECT_EQ(stbf.getNumEmptyIntervalsTracked(), 0);
  EXPECT_FALSE(stbf.bucketEmptyAt(t));
  EXPECT_FALSE(stbf.bucketEmptyThroughoutWindow(t, t));
  EXPECT_NO_THROW(stbf.consumeWithBorrowNonBlockingAndUpdateState(
      config.burstSizeBytes, t));
}

/*
 * Check the size and content of the deque after some consumes that eventually
 * put the bucket in debt
 */
TEST_F(SimulatedTBFTest, MultiConsumeWithEmptyInterval) {
  SimulatedTBF::Config config;
  config.rateBytesPerSecond = 100;
  config.burstSizeBytes = 200;
  SimulatedTBF stbf(config);
  const TimePoint t = Clock::now();

  // Consume but not drain completely: burstBytes - (burstBytes - 10) = 10
  EXPECT_EQ(
      stbf.consumeWithBorrowNonBlockingAndUpdateState(
          config.burstSizeBytes - 10, t - 1s),
      config.burstSizeBytes - 10);
  EXPECT_NEAR(stbf.getNumAvailableTokensInBytes(t - 1s), 10, 0.01);
  EXPECT_EQ(stbf.getNumEmptyIntervalsTracked(), 0);
  EXPECT_FALSE(stbf.bucketEmptyAt(t - 1s));

  // Drain the bucket completely at t: 10 - burstBytes + 1 *
  // rateBytesPerSecond = -90
  EXPECT_NEAR(
      stbf.getNumAvailableTokensInBytes(t),
      10 + config.rateBytesPerSecond,
      0.01);
  EXPECT_EQ(
      stbf.consumeWithBorrowNonBlockingAndUpdateState(config.burstSizeBytes, t),
      config.burstSizeBytes);
  EXPECT_EQ(stbf.getNumAvailableTokensInBytes(t), 0);
  // No interval added because bucket had 10 tokens before consuming
  EXPECT_EQ(stbf.getNumEmptyIntervalsTracked(), 0);
  EXPECT_FALSE(stbf.bucketEmptyThroughoutWindow(t - 1s, t));
  EXPECT_FALSE(stbf.bucketEmptyThroughoutWindow(t, t));
  EXPECT_FALSE(stbf.bucketEmptyAt(t));

  // Bucket is in debt now, so any consume after t will put the bucket in debt
  EXPECT_EQ(stbf.consumeWithBorrowNonBlockingAndUpdateState(1, t + 1ms), 1);
  EXPECT_EQ(stbf.getNumAvailableTokensInBytes(t + 1ms), 0);
  EXPECT_EQ(stbf.getNumEmptyIntervalsTracked(), 1);

  EXPECT_FALSE(stbf.bucketEmptyAt(t));
  EXPECT_FALSE(stbf.bucketEmptyThroughoutWindow(t, t));
  EXPECT_TRUE(stbf.bucketEmptyAt(t + 1ms));
  EXPECT_TRUE(stbf.bucketEmptyThroughoutWindow(t + 1ms, t + 1ms));
  EXPECT_FALSE(stbf.bucketEmptyThroughoutWindow(t, t + 1ms));

  // At t + 1ms, its debt is -90 + 0.1 - 1 = -90.9 tokens, precisely. It takes
  // 909ms to pay this debt. Note that the time range below is adjusted to avoid
  // inconsistencies across different runs due to floating point calculations
  EXPECT_TRUE(stbf.bucketEmptyThroughoutWindow(t + 1ms, t + 909ms));
  EXPECT_EQ(stbf.getNumAvailableTokensInBytes(t + 909ms), 0);
  EXPECT_FALSE(stbf.bucketEmptyAt(t + 911ms));
  EXPECT_GT(stbf.getNumAvailableTokensInBytes(t + 911ms), 0);
}

/*
 * Check the size and content of the deque after multiple consumes at increasing
 * time intervals, where none of them put the bucket in debt.
 */
TEST_F(SimulatedTBFTest, MultiConsumeNoEmptyInterval) {
  SimulatedTBF::Config config;
  config.rateBytesPerSecond = 100;
  config.burstSizeBytes = 200;
  SimulatedTBF stbf(config);
  const TimePoint t = Clock::now();

  // Consume 100 bytes every seconds
  for (int i = 0; i < 10; i++) {
    EXPECT_EQ(
        stbf.consumeWithBorrowNonBlockingAndUpdateState(
            100, t + std::chrono::seconds{i}),
        100);
    EXPECT_NEAR(
        stbf.getNumAvailableTokensInBytes(t + std::chrono::seconds{i}),
        100,
        0.01);
  }

  EXPECT_EQ(stbf.getNumEmptyIntervalsTracked(), 0);
  EXPECT_FALSE(stbf.bucketEmptyAt(t));
  EXPECT_FALSE(stbf.bucketEmptyAt(t + 1s));
  EXPECT_FALSE(stbf.bucketEmptyAt(t + 9s));
}

/*
 * Test not creating an interval when draining a bucket. Note that to create an
 * interval in the deque, the bucket must be empty or in debt at the start and
 * end of the interval. So draining the bucket with some tokens at time t should
 * not create (t, t)
 */

TEST_F(SimulatedTBFTest, NoEmptyIntervalAfterDrainIfTsHadTokens) {
  SimulatedTBF::Config config;
  config.rateBytesPerSecond = 100;
  config.burstSizeBytes = 200;
  SimulatedTBF stbf(config);
  const TimePoint t = Clock::now();

  // Put the bucket in debt:
  // At t = 10s, tokens = (200) - (200 * 10) = -1800
  for (int i = 0; i < 10; i++) {
    EXPECT_EQ(
        stbf.consumeWithBorrowNonBlockingAndUpdateState(
            config.burstSizeBytes, t),
        config.burstSizeBytes);
  }
  // No interval created because at time t, bucket had 200 tokens (burst size)
  EXPECT_EQ(stbf.getNumEmptyIntervalsTracked(), 0);
  EXPECT_FALSE(stbf.bucketEmptyAt(t));
  EXPECT_FALSE(stbf.bucketEmptyThroughoutWindow(t, t));
  EXPECT_EQ(stbf.getNumAvailableTokensInBytes(t), 0);

  // Consume one byte in t + 1s: tokens: -1800 + (1 * 100) - 1 = -1701
  EXPECT_EQ(stbf.consumeWithBorrowNonBlockingAndUpdateState(1, t + 1s), 1);
  EXPECT_EQ(stbf.getNumAvailableTokensInBytes(t + 1s), 0);
  EXPECT_EQ(stbf.getNumEmptyIntervalsTracked(), 1);
  EXPECT_TRUE(stbf.bucketEmptyAt(t + 1s));
  EXPECT_FALSE(stbf.bucketEmptyThroughoutWindow(t, t + 1s));
  EXPECT_TRUE(stbf.bucketEmptyThroughoutWindow(t + 1s, t + 1s));
  // It takes ~17 seconds for the bucket to pay its debt
  EXPECT_TRUE(stbf.bucketEmptyThroughoutWindow(t + 1s, t + 18s));
  EXPECT_FALSE(stbf.bucketEmptyThroughoutWindow(t + 1s, t + 19s));
  EXPECT_GT(stbf.getNumAvailableTokensInBytes(t + 19s), 0);
}

/*
 * Add one interval and remove part of it from the deque
 */

TEST_F(SimulatedTBFTest, AddAndForgetOneEmptyInterval) {
  SimulatedTBF::Config config;
  config.rateBytesPerSecond = 100;
  config.burstSizeBytes = 200;
  SimulatedTBF stbf(config);
  const TimePoint t = Clock::now();

  // Put the bucket in debt:
  // At t = 10s, tokens = (200) + (100 * 10) + (-200 * 10) = -800
  for (int i = 0; i < 10; i++) {
    EXPECT_EQ(
        stbf.consumeWithBorrowNonBlockingAndUpdateState(
            config.burstSizeBytes, t + std::chrono::seconds{i}),
        config.burstSizeBytes);
    EXPECT_EQ(
        stbf.getNumAvailableTokensInBytes(t + std::chrono::seconds{i}), 0);
  }
  EXPECT_EQ(stbf.getNumEmptyIntervalsTracked(), 1);
  // First consume doesn't put the bucket in debt
  EXPECT_FALSE(stbf.bucketEmptyAt(t));
  EXPECT_FALSE(stbf.bucketEmptyThroughoutWindow(t, t));
  // Second consume starts when bucket has 100 tokens
  EXPECT_FALSE(stbf.bucketEmptyAt(t + 1s));
  EXPECT_FALSE(stbf.bucketEmptyThroughoutWindow(t, t + 1s));
  EXPECT_FALSE(stbf.bucketEmptyThroughoutWindow(t + 1s, t + 1s));
  EXPECT_FALSE(stbf.bucketEmptyThroughoutWindow(t + 1s, t + 2s));

  EXPECT_TRUE(stbf.bucketEmptyThroughoutWindow(t + 2s, t + 9s));
  // It takes 8 seconds for the bucket to pay its debt
  EXPECT_TRUE(stbf.bucketEmptyThroughoutWindow(t + 9s, t + 18s));
  EXPECT_FALSE(stbf.bucketEmptyAt(t + 19s));

  stbf.forgetEmptyIntervalsPriorTo(t + 5s);
  EXPECT_EQ(stbf.getNumEmptyIntervalsTracked(), 1);
  EXPECT_THROW(
      (void)stbf.bucketEmptyThroughoutWindow(t + 1s, t + 1s),
      QuicInternalException);
  EXPECT_THROW(
      (void)stbf.bucketEmptyThroughoutWindow(t + 1s, t + 5s),
      QuicInternalException);
  EXPECT_THROW(
      (void)stbf.bucketEmptyThroughoutWindow(t + 1s, t + 9s),
      QuicInternalException);
  EXPECT_TRUE(stbf.bucketEmptyThroughoutWindow(t + 5s + 1us, t + 9s));
  EXPECT_TRUE(stbf.bucketEmptyThroughoutWindow(t + 6s, t + 9s));

  stbf.forgetEmptyIntervalsPriorTo(t + 1s);
  EXPECT_EQ(stbf.getNumEmptyIntervalsTracked(), 1);
  EXPECT_TRUE(stbf.bucketEmptyThroughoutWindow(t + 5s + 1us, t + 9s));

  stbf.forgetEmptyIntervalsPriorTo(t + 20s);
  EXPECT_EQ(stbf.getNumEmptyIntervalsTracked(), 0);
  EXPECT_THROW(
      (void)stbf.bucketEmptyThroughoutWindow(t + 6s, t + 9s),
      QuicInternalException);
}

/*
 * Add two intervals and remove part of the newest interval from the deque
 */

TEST_F(SimulatedTBFTest, AddTwoEmptyIntervalsAndForgetOne) {
  SimulatedTBF::Config config;
  config.rateBytesPerSecond = 100;
  config.burstSizeBytes = 200;
  SimulatedTBF stbf(config);
  const TimePoint t = Clock::now();

  // Add the first interval:
  // At t = 5s, tokens = (200) + (100 * 5) + (-200 * 5) = -300
  for (int i = 0; i < 5; i++) {
    EXPECT_EQ(
        stbf.consumeWithBorrowNonBlockingAndUpdateState(
            config.burstSizeBytes, t + std::chrono::seconds{i}),
        config.burstSizeBytes);
    EXPECT_EQ(
        stbf.getNumAvailableTokensInBytes(t + std::chrono::seconds{i}), 0);
  }

  EXPECT_EQ(stbf.getNumEmptyIntervalsTracked(), 1);
  EXPECT_FALSE(stbf.bucketEmptyAt(t));
  EXPECT_FALSE(stbf.bucketEmptyAt(t + 1s));
  EXPECT_TRUE(stbf.bucketEmptyThroughoutWindow(t + 2s, t + 4s));
  // It takes 3 seconds for the bucket to pay its debt
  EXPECT_TRUE(stbf.bucketEmptyThroughoutWindow(t + 2s, t + 8s));
  EXPECT_FALSE(stbf.bucketEmptyAt(t + 9s));
  EXPECT_EQ(stbf.getNumAvailableTokensInBytes(t + 8s), 0);
  EXPECT_NEAR(
      stbf.getNumAvailableTokensInBytes(t + 9s),
      config.rateBytesPerSecond,
      0.01);

  // Add the second interval:
  // At t = 8s, it has zero tokens. Start consuming at t = 10s, where it has 200
  // tokens (rateBytesPerSecond * 2)
  EXPECT_NEAR(
      stbf.getNumAvailableTokensInBytes(t + 10s),
      config.rateBytesPerSecond * 2,
      0.01);
  for (int i = 0; i < 5; i++) {
    EXPECT_EQ(
        stbf.consumeWithBorrowNonBlockingAndUpdateState(
            config.burstSizeBytes, t + 10s + std::chrono::seconds{i}),
        config.burstSizeBytes);
  }
  EXPECT_EQ(stbf.getNumEmptyIntervalsTracked(), 2);
  EXPECT_FALSE(stbf.bucketEmptyAt(t + 11s));
  EXPECT_EQ(stbf.getNumAvailableTokensInBytes(t + 12s), 0);
  EXPECT_TRUE(stbf.bucketEmptyThroughoutWindow(t + 12s, t + 18s));
  EXPECT_EQ(stbf.getNumAvailableTokensInBytes(t + 18s), 0);
  EXPECT_FALSE(stbf.bucketEmptyAt(t + 19s));

  stbf.forgetEmptyIntervalsPriorTo(t + 13s);
  EXPECT_EQ(stbf.getNumEmptyIntervalsTracked(), 1);
  EXPECT_TRUE(stbf.bucketEmptyThroughoutWindow(t + 13s + 1us, t + 18s));
}

/*
 * Run multiple consumes to update a single interval at the deque
 */
TEST_F(SimulatedTBFTest, MultipleConsumeSingleInterval) {
  SimulatedTBF::Config config;
  config.rateBytesPerSecond = 100;
  config.burstSizeBytes = 200;
  SimulatedTBF stbf(config);
  const TimePoint t = Clock::now();

  // Consume and drain completely: tokens = -200 at t = 0
  EXPECT_EQ(
      stbf.consumeWithBorrowNonBlockingAndUpdateState(config.burstSizeBytes, t),
      config.burstSizeBytes);
  EXPECT_EQ(stbf.getNumAvailableTokensInBytes(t), 0);
  EXPECT_EQ(stbf.getNumEmptyIntervalsTracked(), 0);
  EXPECT_EQ(
      stbf.consumeWithBorrowNonBlockingAndUpdateState(config.burstSizeBytes, t),
      config.burstSizeBytes);
  EXPECT_EQ(stbf.getNumAvailableTokensInBytes(t), 0);
  EXPECT_EQ(stbf.getNumEmptyIntervalsTracked(), 0);
  EXPECT_FALSE(stbf.bucketEmptyAt(t));
  EXPECT_FALSE(stbf.bucketEmptyAt(t + 1s));

  // Consume more tokens at a later t to put the bucket more in debt:
  // tokens = -200 + 100 - 200 = -300
  EXPECT_EQ(
      stbf.consumeWithBorrowNonBlockingAndUpdateState(
          config.burstSizeBytes, t + 1s),
      config.burstSizeBytes);
  EXPECT_EQ(stbf.getNumAvailableTokensInBytes(t + 1s), 0);
  EXPECT_EQ(stbf.getNumEmptyIntervalsTracked(), 1);
  EXPECT_FALSE(stbf.bucketEmptyAt(t));
  EXPECT_TRUE(stbf.bucketEmptyAt(t + 1s));
  EXPECT_FALSE(stbf.bucketEmptyThroughoutWindow(t, t + 1s));
  EXPECT_FALSE(stbf.bucketEmptyThroughoutWindow(t, t + 4s));
  // It takes 3 seconds for the bucket to pay its debt
  EXPECT_EQ(stbf.getNumAvailableTokensInBytes(t + 4s), 0);
  EXPECT_TRUE(stbf.bucketEmptyThroughoutWindow(t + 1s, t + 4s));
  EXPECT_NEAR(
      stbf.getNumAvailableTokensInBytes(t + 5s),
      config.rateBytesPerSecond,
      0.01);
  EXPECT_FALSE(stbf.bucketEmptyAt(t + 5s));

  // After 3s, right when bucket would exit debt, consume 200 more bytes
  EXPECT_EQ(
      stbf.consumeWithBorrowNonBlockingAndUpdateState(
          config.burstSizeBytes, t + 4s),
      config.burstSizeBytes);
  EXPECT_EQ(stbf.getNumAvailableTokensInBytes(t + 4s), 0);
  EXPECT_EQ(stbf.getNumEmptyIntervalsTracked(), 1);
  EXPECT_TRUE(stbf.bucketEmptyThroughoutWindow(t + 1s, t + 6s));
  EXPECT_EQ(stbf.getNumAvailableTokensInBytes(t + 6s), 0);
  EXPECT_FALSE(stbf.bucketEmptyAt(t + 7s));
  EXPECT_NEAR(
      stbf.getNumAvailableTokensInBytes(t + 7s),
      config.rateBytesPerSecond,
      0.01);
}

/*
 * Run multiple consumes to create multiple (disjoint) intervals in the
 * deque
 */
TEST_F(SimulatedTBFTest, MultipleConsumeMultipleIntervals) {
  SimulatedTBF::Config config;
  config.rateBytesPerSecond = 100;
  config.burstSizeBytes = 200;
  SimulatedTBF stbf(config);
  const TimePoint t = Clock::now();

  // Consume and drain completely: tokens = -200 at t = 0
  EXPECT_EQ(
      stbf.consumeWithBorrowNonBlockingAndUpdateState(config.burstSizeBytes, t),
      config.burstSizeBytes);
  EXPECT_EQ(stbf.getNumAvailableTokensInBytes(t), 0);
  EXPECT_EQ(
      stbf.consumeWithBorrowNonBlockingAndUpdateState(config.burstSizeBytes, t),
      config.burstSizeBytes);
  EXPECT_EQ(stbf.getNumAvailableTokensInBytes(t), 0);
  EXPECT_EQ(stbf.getNumEmptyIntervalsTracked(), 0);

  // Consume more tokens to put the bucket more in debt:
  // tokens = -200 + 100 - 200 = -300
  EXPECT_EQ(
      stbf.consumeWithBorrowNonBlockingAndUpdateState(
          config.burstSizeBytes, t + 1s),
      config.burstSizeBytes);
  EXPECT_EQ(stbf.getNumAvailableTokensInBytes(t + 1s), 0);
  EXPECT_EQ(stbf.getNumEmptyIntervalsTracked(), 1);
  EXPECT_TRUE(stbf.bucketEmptyAt(t + 1s));
  // It takes 3 seconds for the bucket to pay its debt
  EXPECT_TRUE(stbf.bucketEmptyThroughoutWindow(t + 1s, t + 4s));
  EXPECT_NEAR(
      stbf.getNumAvailableTokensInBytes(t + 5s),
      config.rateBytesPerSecond,
      0.01);
  EXPECT_FALSE(stbf.bucketEmptyAt(t + 5s));

  // Let the bucket to gain 400 tokens after 4s.
  // At t = 5s, tokens = -300 + (4s * 100) - 50 = 50
  EXPECT_EQ(stbf.consumeWithBorrowNonBlockingAndUpdateState(50, t + 5s), 50);
  EXPECT_NEAR(stbf.getNumAvailableTokensInBytes(t + 5s), 50, 0.01);
  EXPECT_EQ(stbf.getNumEmptyIntervalsTracked(), 1);
  EXPECT_TRUE(stbf.bucketEmptyThroughoutWindow(t + 1s, t + 4s));
  EXPECT_FALSE(stbf.bucketEmptyAt(t + 5s));

  // At t=5s, consume 150 more tokens to put the bucket in debt again
  // tokens = 50 - 150 = -100
  EXPECT_EQ(stbf.consumeWithBorrowNonBlockingAndUpdateState(150, t + 5s), 150);
  EXPECT_EQ(stbf.getNumAvailableTokensInBytes(t + 5s), 0);
  EXPECT_EQ(stbf.getNumEmptyIntervalsTracked(), 1);
  EXPECT_FALSE(stbf.bucketEmptyAt(t + 5s));

  EXPECT_EQ(stbf.getNumAvailableTokensInBytes(t + 6s), 0);
  // At t=6s, consume 200 tokens to create a new interval
  EXPECT_EQ(
      stbf.consumeWithBorrowNonBlockingAndUpdateState(
          config.burstSizeBytes, t + 6s),
      config.burstSizeBytes);
  EXPECT_EQ(stbf.getNumAvailableTokensInBytes(t + 6s), 0);
  EXPECT_EQ(stbf.getNumEmptyIntervalsTracked(), 2);
  EXPECT_TRUE(stbf.bucketEmptyThroughoutWindow(t + 1s, t + 4s));
  EXPECT_FALSE(stbf.bucketEmptyAt(t + 5s));
  EXPECT_FALSE(stbf.bucketEmptyThroughoutWindow(t + 5s, t + 6s));
  EXPECT_TRUE(stbf.bucketEmptyThroughoutWindow(t + 6s, t + 8s));
  EXPECT_EQ(stbf.getNumAvailableTokensInBytes(t + 8s), 0);
  EXPECT_FALSE(stbf.bucketEmptyAt(t + 9s));
  EXPECT_NEAR(
      stbf.getNumAvailableTokensInBytes(t + 9s),
      config.rateBytesPerSecond,
      0.01);
}

/*
 * Run multiple consumes to create a single interval and fill the capped debt
 * buffer
 */
TEST_F(SimulatedTBFTest, MultipleConsumeSingleIntervalWithDebtBuffCapped) {
  SimulatedTBF::Config config;
  config.rateBytesPerSecond = 100;
  config.burstSizeBytes = 200;
  config.maybeMaxDebtQueueSizeBytes = 200;
  SimulatedTBF stbf(config);
  const TimePoint t = Clock::now();

  // Consume and drain completely: tokens = -200 at t = 0
  EXPECT_EQ(
      stbf.consumeWithBorrowNonBlockingAndUpdateState(config.burstSizeBytes, t),
      config.burstSizeBytes);
  EXPECT_EQ(stbf.getNumAvailableTokensInBytes(t), 0);
  EXPECT_EQ(
      stbf.consumeWithBorrowNonBlockingAndUpdateState(config.burstSizeBytes, t),
      config.burstSizeBytes);
  EXPECT_EQ(stbf.getNumAvailableTokensInBytes(t), 0);
  EXPECT_EQ(stbf.getNumEmptyIntervalsTracked(), 0);

  // Try to consume 200 more bytes 1s later to put the bucket more in debt and
  // create an interval, however the debt queue has only 100 bytes left, so stbf
  // should drop and not consume the entire 200 bytes.
  // tokens at t = 1s: -200 + 100 = -100
  EXPECT_EQ(
      stbf.consumeWithBorrowNonBlockingAndUpdateState(
          config.burstSizeBytes, t + 1s),
      0);
  EXPECT_EQ(stbf.getNumAvailableTokensInBytes(t + 1s), 0);
  EXPECT_EQ(stbf.getNumEmptyIntervalsTracked(), 0);
  EXPECT_FALSE(stbf.bucketEmptyAt(t + 1s));

  // Try to consume only 100 bytes this time
  EXPECT_EQ(
      stbf.consumeWithBorrowNonBlockingAndUpdateState(
          config.burstSizeBytes - 100, t + 1s),
      config.burstSizeBytes - 100);
  EXPECT_EQ(stbf.getNumAvailableTokensInBytes(t + 1s), 0);
  EXPECT_EQ(stbf.getNumEmptyIntervalsTracked(), 1);
  EXPECT_TRUE(stbf.bucketEmptyAt(t + 1s));

  // Debt buffer can only hold 200 bytes, so it takes only 2 seconds for the
  // bucket to pay its debt
  EXPECT_TRUE(stbf.bucketEmptyThroughoutWindow(t + 1s, t + 3s));
  EXPECT_FALSE(stbf.bucketEmptyAt(t + 4s));
  EXPECT_EQ(stbf.getNumAvailableTokensInBytes(t + 3s), 0);

  // Consume 200 more bytes 2s later to extend the existing interval
  EXPECT_EQ(
      stbf.consumeWithBorrowNonBlockingAndUpdateState(
          config.burstSizeBytes, t + 3s),
      config.burstSizeBytes);
  EXPECT_EQ(stbf.getNumEmptyIntervalsTracked(), 1);
  EXPECT_TRUE(stbf.bucketEmptyThroughoutWindow(t + 1s, t + 5s));
  EXPECT_EQ(stbf.getNumAvailableTokensInBytes(t + 5s), 0);
  EXPECT_FALSE(stbf.bucketEmptyAt(t + 6s));
  EXPECT_NEAR(
      stbf.getNumAvailableTokensInBytes(t + 6s),
      config.rateBytesPerSecond,
      0.01);
  // Since the queue is full, any subsequent consume at t + 3s should return
  // zero (i.e., no more bytes can be consumed)
  EXPECT_EQ(
      stbf.consumeWithBorrowNonBlockingAndUpdateState(
          config.burstSizeBytes, t + 3s),
      0);
}

} // namespace quic::test
