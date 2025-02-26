/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <quic/state/PendingPathRateLimiter.h>

namespace quic {

void PendingPathRateLimiter::onPacketSent(uint64_t sentBytes) {
  // Allow for up to one packet's worth of data to go into "negative" credit.
  if (sentBytes > credit_) {
    credit_ = 0;
  } else {
    credit_ -= sentBytes;
  }
}

uint64_t PendingPathRateLimiter::currentCredit(
    TimePoint checkTime,
    std::chrono::microseconds rtt) noexcept {
  if ((!lastChecked_.has_value()) || (checkTime > *lastChecked_ + rtt)) {
    lastChecked_ = checkTime;
    credit_ = maxCredit_;
  }
  return credit_;
}
} // namespace quic
