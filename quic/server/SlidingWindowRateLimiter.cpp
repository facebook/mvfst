// Copyright 2004-present Facebook. All Rights Reserved.

#include "SlidingWindowRateLimiter.h"

#include <cmath>

namespace quic {

bool SlidingWindowRateLimiter::check(TimePoint time) {
  // This is the first time point.
  if (!currentWindowStartPoint_) {
    currentWindowStartPoint_ = time;
  }
  auto timeElapsedSinceCurWindow =
      std::chrono::duration_cast<std::chrono::microseconds>(
          time - currentWindowStartPoint_.value());
  // A full window has elapsed.
  if (timeElapsedSinceCurWindow > window_) {
    double windowsElapsed = timeElapsedSinceCurWindow.count() / window_.count();
    currentWindowStartPoint_.value() +=
        std::chrono::microseconds(uint64_t(window_.count() * windowsElapsed));
    // If more than one window has elapsed, there were zero in the previous
    // window.
    countInPrevWindow_ = windowsElapsed == 1 ? countInCurWindow_ : 0;
    countInCurWindow_ = 0;
    timeElapsedSinceCurWindow =
        std::chrono::duration_cast<std::chrono::microseconds>(
            time - currentWindowStartPoint_.value());
  }
  // The weighted count accounts for the "sliding" window by using the
  // previous windows average rate over the time that has elapsed in the
  // current window.
  double weightedCount = countInPrevWindow_ *
          (static_cast<double>((window_ - timeElapsedSinceCurWindow).count()) /
           window_.count()) +
      countInCurWindow_ + 1;
  bool limited = std::trunc(weightedCount) > count_;
  countInCurWindow_ = limited ? countInCurWindow_ : countInCurWindow_ + 1;
  return limited;
}

} // namespace quic
