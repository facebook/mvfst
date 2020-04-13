// Copyright 2004-present Facebook. All Rights Reserved.

#pragma once

#include <chrono>

#include <quic/QuicConstants.h>

namespace quic {

/*
 * Basic rate limiter interface that is driven solely by a monotonically
 * clocked events.
 */
class RateLimiter {
 public:
  RateLimiter() = default;

  virtual ~RateLimiter() = default;

  /*
   * Check if an event at a certain time should be rate limited. Returns true
   * if it should be rate limited.
   */
  virtual bool check(TimePoint time) = 0;
};

} // namespace quic
