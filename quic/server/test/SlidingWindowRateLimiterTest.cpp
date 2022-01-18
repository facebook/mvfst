/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <gtest/gtest.h>

#include <quic/server/SlidingWindowRateLimiter.h>

using namespace quic;

TEST(SlidingWindowRateLimiterTest, BasicExceedsCount) {
  SlidingWindowRateLimiter limiter([]() { return 10; }, 60s);
  auto now = Clock::now();
  for (int i = 0; i < 10; i++) {
    EXPECT_FALSE(limiter.check(now));
    now += 1s;
  }
  EXPECT_TRUE(limiter.check(now));
}

TEST(SlidingWindowRateLimiterTest, SlidingNoExceedsCount) {
  SlidingWindowRateLimiter limiter([]() { return 10; }, 60s);
  auto now = Clock::now();
  auto prevStart = now;

  for (int i = 0; i < 9; i++) {
    EXPECT_FALSE(limiter.check(now));
    now += 1s;
  }
  EXPECT_FALSE(limiter.check(prevStart + 60s));
}

TEST(SlidingWindowRateLimiterTest, SlidingExceedsCount) {
  SlidingWindowRateLimiter limiter([]() { return 10; }, 60s);
  auto now = Clock::now();
  auto prevStart = now;

  for (int i = 0; i < 10; i++) {
    limiter.check(now);
    now += 1s;
  }
  // This makes the current window start at 60s, with one check at 7s.
  // 10/60 * 53 = 8.83
  // 8.83 + 1 !> 10
  EXPECT_FALSE(limiter.check(prevStart + 67s));
  EXPECT_FALSE(limiter.check(prevStart + 68s));
  for (int i = 0; i < 8; i++) {
    EXPECT_FALSE(limiter.check(prevStart + 119s));
  }
}

TEST(SlidingWindowRateLimiterTest, QuiescentWindowNoExceeds) {
  SlidingWindowRateLimiter limiter([]() { return 10; }, 60s);
  auto now = Clock::now();
  auto prevStart = now;

  for (int i = 0; i < 10; i++) {
    limiter.check(now);
    now += 1s;
  }
  now = prevStart + 120s;
  for (int i = 0; i < 10; i++) {
    EXPECT_FALSE(limiter.check(now));
    now += 1s;
  }
}
