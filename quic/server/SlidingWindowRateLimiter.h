// Copyright 2004-present Facebook. All Rights Reserved.

#pragma once

#include <quic/server/RateLimiter.h>

namespace quic {

/*
 * Simple "sliding window" rate limiter. This enforces a rate limit of count
 * events per window. The window "slides" by multiplying the average rate of
 * the previous full window by the amount of time that the current sliding
 * window occurred in the previous window.
 * E.g.
 * Limit of 100 events per 10s. The previous window had 50 events. The current
 * window has had 5 events. We check an event 3 seconds into our current
 * window. The sliding window has 3 seconds in our current window, and 7
 * seconds in the previous window. We psuedo-count for the current sliding
 * window is: 50/10 * 7 + 5 + 1 = 41.
 */
class SlidingWindowRateLimiter : public RateLimiter {
 public:
  SlidingWindowRateLimiter(uint64_t count, std::chrono::seconds window)
      : count_(count), window_(window) {}

  bool check(TimePoint time) override;

 private:
  const uint64_t count_;
  const std::chrono::microseconds window_;
  folly::Optional<TimePoint> currentWindowStartPoint_{folly::none};
  uint64_t countInPrevWindow_{0};
  uint64_t countInCurWindow_{0};
};

} // namespace quic
