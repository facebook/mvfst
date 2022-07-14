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
  const auto rateBytesPerSecond = 100;
  const auto burstBytes = 200;
  SimulatedTBF stbf(rateBytesPerSecond, burstBytes);
  EXPECT_EQ(stbf.getRateBytesPerSecond(), rateBytesPerSecond);
  EXPECT_EQ(stbf.getBurstSizeBytes(), burstBytes);
  EXPECT_FALSE(stbf.getMaxDebtQueueSizeBytes().has_value());
  EXPECT_EQ(stbf.getNumEmptyIntervalsTracked(), 0);
}

/*
 * Case with no consume operations, should have no empty intervals.
 */
TEST_F(SimulatedTBFTest, NoConsumeCheckNoEmptyIntervals) {
  const auto rateBytesPerSecond = 100;
  const auto burstBytes = 200;
  SimulatedTBF stbf(rateBytesPerSecond, burstBytes);
  const TimePoint t = Clock::now();
  EXPECT_EQ(stbf.getNumEmptyIntervalsTracked(), 0);
  EXPECT_FALSE(stbf.bucketEmptyAt(t));
  EXPECT_FALSE(stbf.bucketEmptyThroughoutWindow(t, t));
  EXPECT_FALSE(stbf.bucketEmptyThroughoutWindow(t, t + 20s));
}

/*
 * Case with consuming more than the specified burst size should throw an
 * exception
 */
TEST_F(SimulatedTBFTest, ConsumeMoreThanBurstSize) {
  const auto rateBytesPerSecond = 100;
  const auto burstBytes = 200;
  SimulatedTBF stbf(rateBytesPerSecond, burstBytes);
  const TimePoint t = Clock::now();
  EXPECT_EQ(stbf.getNumEmptyIntervalsTracked(), 0);
  EXPECT_THROW(
      stbf.consumeWithBorrowNonBlockingAndUpdateState(burstBytes + 1, t),
      QuicInternalException);
  EXPECT_EQ(stbf.getNumEmptyIntervalsTracked(), 0);
  EXPECT_FALSE(stbf.bucketEmptyAt(t));
  EXPECT_FALSE(stbf.bucketEmptyThroughoutWindow(t, t));
  EXPECT_NO_THROW(
      stbf.consumeWithBorrowNonBlockingAndUpdateState(burstBytes, t));
}

/*
 * Check the size and content of the deque after some consumes that eventually
 * put the bucket in debt
 */
TEST_F(SimulatedTBFTest, MultiConsumeWithEmptyInterval) {
  const auto rateBytesPerSecond = 100;
  const auto burstBytes = 200;
  SimulatedTBF stbf(rateBytesPerSecond, burstBytes);
  const TimePoint t = Clock::now();

  // Consume but not drain completely: burstBytes - (burstBytes - 10) = 10
  stbf.consumeWithBorrowNonBlockingAndUpdateState(burstBytes - 10, t - 1s);
  EXPECT_EQ(stbf.getNumEmptyIntervalsTracked(), 0);
  EXPECT_FALSE(stbf.bucketEmptyAt(t - 1s));

  // Drain the bucket completely at t: 10 - burstBytes + 1 *
  // rateBytesPerSecond = -90
  stbf.consumeWithBorrowNonBlockingAndUpdateState(burstBytes, t);
  // No interval added because bucket had 10 token before consuming
  EXPECT_EQ(stbf.getNumEmptyIntervalsTracked(), 0);
  EXPECT_FALSE(stbf.bucketEmptyThroughoutWindow(t - 1s, t));
  EXPECT_FALSE(stbf.bucketEmptyThroughoutWindow(t, t));
  EXPECT_FALSE(stbf.bucketEmptyAt(t));

  // Bucket is in debt now, so any consume after t will put the bucket in debt
  stbf.consumeWithBorrowNonBlockingAndUpdateState(1, t + 1ms);
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
  EXPECT_FALSE(stbf.bucketEmptyAt(t + 911ms));
}

/*
 * Check the size and content of the deque after multiple consumes at increasing
 * time intervals, where none of them put the bucket in debt.
 */
TEST_F(SimulatedTBFTest, MultiConsumeNoEmptyInterval) {
  const auto rateBytesPerSecond = 100;
  const auto burstBytes = 200;
  SimulatedTBF stbf(rateBytesPerSecond, burstBytes);
  const TimePoint t = Clock::now();

  // Consume 100 bytes every seconds
  for (int i = 0; i < 10; i++) {
    stbf.consumeWithBorrowNonBlockingAndUpdateState(
        100, t + std::chrono::seconds{i});
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
  const auto rateBytesPerSecond = 100;
  const auto burstBytes = 200;
  SimulatedTBF stbf(rateBytesPerSecond, burstBytes);
  const TimePoint t = Clock::now();

  // Put the bucket in debt:
  // At t = 10s, tokens = (200) - (200 * 10) = -1800
  for (int i = 0; i < 10; i++) {
    stbf.consumeWithBorrowNonBlockingAndUpdateState(burstBytes, t);
  }
  // No interval created because at time t, bucket had 200 tokens (burst size)
  EXPECT_EQ(stbf.getNumEmptyIntervalsTracked(), 0);
  EXPECT_FALSE(stbf.bucketEmptyAt(t));
  EXPECT_FALSE(stbf.bucketEmptyThroughoutWindow(t, t));

  // Consume one byte in t + 1s: tokens: -1800 + (1 * 100) - 1 = -1701
  stbf.consumeWithBorrowNonBlockingAndUpdateState(1, t + 1s);
  EXPECT_EQ(stbf.getNumEmptyIntervalsTracked(), 1);
  EXPECT_TRUE(stbf.bucketEmptyAt(t + 1s));
  EXPECT_FALSE(stbf.bucketEmptyThroughoutWindow(t, t + 1s));
  EXPECT_TRUE(stbf.bucketEmptyThroughoutWindow(t + 1s, t + 1s));
  // It takes ~17 seconds for the bucket to pay its debt
  EXPECT_TRUE(stbf.bucketEmptyThroughoutWindow(t + 1s, t + 18s));
  EXPECT_FALSE(stbf.bucketEmptyThroughoutWindow(t + 1s, t + 19s));
}

/*
 * Add one interval and remove part of it from the deque
 */

TEST_F(SimulatedTBFTest, AddAndForgetOneEmptyInterval) {
  const auto rateBytesPerSecond = 100;
  const auto burstBytes = 200;
  SimulatedTBF stbf(rateBytesPerSecond, burstBytes);
  const TimePoint t = Clock::now();

  // Put the bucket in debt:
  // At t = 10s, tokens = (200) + (100 * 10) + (-200 * 10) = -800
  for (int i = 0; i < 10; i++) {
    stbf.consumeWithBorrowNonBlockingAndUpdateState(
        burstBytes, t + std::chrono::seconds{i});
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
  const auto rateBytesPerSecond = 100;
  const auto burstBytes = 200;
  SimulatedTBF stbf(rateBytesPerSecond, burstBytes);
  const TimePoint t = Clock::now();

  // Add the first interval:
  // At t = 5s, tokens = (200) + (100 * 5) + (-200 * 5) = -300
  for (int i = 0; i < 5; i++) {
    stbf.consumeWithBorrowNonBlockingAndUpdateState(
        burstBytes, t + std::chrono::seconds{i});
  }

  EXPECT_EQ(stbf.getNumEmptyIntervalsTracked(), 1);
  EXPECT_FALSE(stbf.bucketEmptyAt(t));
  EXPECT_FALSE(stbf.bucketEmptyAt(t + 1s));
  EXPECT_TRUE(stbf.bucketEmptyThroughoutWindow(t + 2s, t + 4s));
  // It takes 3 seconds for the bucket to pay its debt
  EXPECT_TRUE(stbf.bucketEmptyThroughoutWindow(t + 2s, t + 8s));
  EXPECT_FALSE(stbf.bucketEmptyAt(t + 9s));

  // Add the second interval:
  // At t = 8s, it has zero tokens. Start consuming at t = 10s
  for (int i = 0; i < 5; i++) {
    stbf.consumeWithBorrowNonBlockingAndUpdateState(
        burstBytes, t + 10s + std::chrono::seconds{i});
  }
  EXPECT_EQ(stbf.getNumEmptyIntervalsTracked(), 2);
  EXPECT_FALSE(stbf.bucketEmptyAt(t + 11s));
  EXPECT_TRUE(stbf.bucketEmptyThroughoutWindow(t + 12s, t + 18s));
  EXPECT_FALSE(stbf.bucketEmptyAt(t + 19s));

  stbf.forgetEmptyIntervalsPriorTo(t + 13s);
  EXPECT_EQ(stbf.getNumEmptyIntervalsTracked(), 1);
  EXPECT_TRUE(stbf.bucketEmptyThroughoutWindow(t + 13s + 1us, t + 18s));
}

/*
 * Run multiple consumes to update a single interval at the deque
 */
TEST_F(SimulatedTBFTest, MultipleConsumeSingleInterval) {
  const auto rateBytesPerSecond = 100;
  const auto burstBytes = 200;
  SimulatedTBF stbf(rateBytesPerSecond, burstBytes);
  const TimePoint t = Clock::now();

  // Consume and drain completely: tokens = -200 at t = 0
  stbf.consumeWithBorrowNonBlockingAndUpdateState(burstBytes, t);
  EXPECT_EQ(stbf.getNumEmptyIntervalsTracked(), 0);
  stbf.consumeWithBorrowNonBlockingAndUpdateState(burstBytes, t);
  EXPECT_EQ(stbf.getNumEmptyIntervalsTracked(), 0);
  EXPECT_FALSE(stbf.bucketEmptyAt(t));
  EXPECT_FALSE(stbf.bucketEmptyAt(t + 1s));

  // Consume more tokens at a later t to put the bucket more in debt:
  // tokens = -200 + 100 - 200 = -300
  stbf.consumeWithBorrowNonBlockingAndUpdateState(burstBytes, t + 1s);
  EXPECT_EQ(stbf.getNumEmptyIntervalsTracked(), 1);
  EXPECT_FALSE(stbf.bucketEmptyAt(t));
  EXPECT_TRUE(stbf.bucketEmptyAt(t + 1s));
  EXPECT_FALSE(stbf.bucketEmptyThroughoutWindow(t, t + 1s));
  EXPECT_FALSE(stbf.bucketEmptyThroughoutWindow(t, t + 4s));
  // It takes 3 seconds for the bucket to pay its debt
  EXPECT_TRUE(stbf.bucketEmptyThroughoutWindow(t + 1s, t + 4s));
  EXPECT_FALSE(stbf.bucketEmptyAt(t + 5s));

  // After 3s, right when bucket would exit debt, consume 200 more bytes
  stbf.consumeWithBorrowNonBlockingAndUpdateState(burstBytes, t + 4s);
  EXPECT_EQ(stbf.getNumEmptyIntervalsTracked(), 1);
  EXPECT_TRUE(stbf.bucketEmptyThroughoutWindow(t + 1s, t + 6s));
  EXPECT_FALSE(stbf.bucketEmptyAt(t + 7s));
}

/*
 * Run multiple consumes to create multiple (disjoint) intervals in the
 * deque
 */
TEST_F(SimulatedTBFTest, MultipleConsumeMultipleIntervals) {
  const auto rateBytesPerSecond = 100;
  const auto burstBytes = 200;
  SimulatedTBF stbf(rateBytesPerSecond, burstBytes);
  const TimePoint t = Clock::now();

  // Consume and drain completely: tokens = -200 at t = 0
  stbf.consumeWithBorrowNonBlockingAndUpdateState(burstBytes, t);
  stbf.consumeWithBorrowNonBlockingAndUpdateState(burstBytes, t);
  EXPECT_EQ(stbf.getNumEmptyIntervalsTracked(), 0);

  // Consume more tokens to put the bucket more in debt:
  // tokens = -200 + 100 - 200 = -300
  stbf.consumeWithBorrowNonBlockingAndUpdateState(burstBytes, t + 1s);
  EXPECT_EQ(stbf.getNumEmptyIntervalsTracked(), 1);
  EXPECT_TRUE(stbf.bucketEmptyAt(t + 1s));
  // It takes 3 seconds for the bucket to pay its debt
  EXPECT_TRUE(stbf.bucketEmptyThroughoutWindow(t + 1s, t + 4s));
  EXPECT_FALSE(stbf.bucketEmptyAt(t + 5s));

  // Let the bucket to gain 400 tokens after 4s.
  // At t = 5s, tokens = -300 + (4s * 100) - 50 = 50
  stbf.consumeWithBorrowNonBlockingAndUpdateState(50, t + 5s);
  EXPECT_EQ(stbf.getNumEmptyIntervalsTracked(), 1);
  EXPECT_TRUE(stbf.bucketEmptyThroughoutWindow(t + 1s, t + 4s));
  EXPECT_FALSE(stbf.bucketEmptyAt(t + 5s));

  // At t=5s, consume 150 more tokens to put the bucket in debt again
  // tokens = 50 - 150 = -100
  stbf.consumeWithBorrowNonBlockingAndUpdateState(burstBytes, t + 5s);
  EXPECT_EQ(stbf.getNumEmptyIntervalsTracked(), 1);
  EXPECT_FALSE(stbf.bucketEmptyAt(t + 5s));

  // At t=6s, consume 200 tokens to create a new interval
  stbf.consumeWithBorrowNonBlockingAndUpdateState(burstBytes, t + 6s);
  EXPECT_EQ(stbf.getNumEmptyIntervalsTracked(), 2);
  EXPECT_TRUE(stbf.bucketEmptyThroughoutWindow(t + 1s, t + 4s));
  EXPECT_FALSE(stbf.bucketEmptyAt(t + 5s));
  EXPECT_FALSE(stbf.bucketEmptyThroughoutWindow(t + 5s, t + 6s));
  EXPECT_TRUE(stbf.bucketEmptyThroughoutWindow(t + 6s, t + 8s));
  EXPECT_FALSE(stbf.bucketEmptyAt(t + 9s));
}

/*
 * Run multiple consumes to create a single interval and fill the capped debt
 * buffer
 */
TEST_F(SimulatedTBFTest, MultipleConsumeSingleIntervalWithDebtBuffCapped) {
  const auto rateBytesPerSecond = 100;
  const auto burstBytes = 200;
  const auto maxDebtQSizeBytes = 200;
  SimulatedTBF stbf(rateBytesPerSecond, burstBytes, maxDebtQSizeBytes);
  const TimePoint t = Clock::now();

  // Consume and drain completely: tokens = -200 at t = 0
  stbf.consumeWithBorrowNonBlockingAndUpdateState(burstBytes, t);
  stbf.consumeWithBorrowNonBlockingAndUpdateState(burstBytes, t);
  EXPECT_EQ(stbf.getNumEmptyIntervalsTracked(), 0);

  // Try to consume 200 more bytes 1s later to put the bucket more in debt and
  // create an interval, however the debt queue has only 100 bytes left, so stbf
  // should drop the entire 200 bytes before trying to consume it.
  // tokens at t = 1s: -200 + 100 = -100
  stbf.consumeWithBorrowNonBlockingAndUpdateState(burstBytes, t + 1s);
  EXPECT_EQ(stbf.getNumEmptyIntervalsTracked(), 0);
  EXPECT_FALSE(stbf.bucketEmptyAt(t + 1s));

  // Try to consume only 100 bytes this time
  stbf.consumeWithBorrowNonBlockingAndUpdateState(burstBytes - 100, t + 1s);
  EXPECT_EQ(stbf.getNumEmptyIntervalsTracked(), 1);
  EXPECT_TRUE(stbf.bucketEmptyAt(t + 1s));

  // Debt buffer can only hold 200 bytes, so it takes only 2 seconds for the
  // bucket to pay its debt
  EXPECT_TRUE(stbf.bucketEmptyThroughoutWindow(t + 1s, t + 3s));
  EXPECT_FALSE(stbf.bucketEmptyAt(t + 4s));

  // Consume 200 more bytes 2s later to extend the existing interval
  stbf.consumeWithBorrowNonBlockingAndUpdateState(burstBytes, t + 3s);
  EXPECT_EQ(stbf.getNumEmptyIntervalsTracked(), 1);
  EXPECT_TRUE(stbf.bucketEmptyThroughoutWindow(t + 1s, t + 5s));
  EXPECT_FALSE(stbf.bucketEmptyAt(t + 6s));
}

} // namespace quic::test
