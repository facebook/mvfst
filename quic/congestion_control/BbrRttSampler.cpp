/*
 * Copyright (c) Facebook, Inc. and its affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 *
 */

// Copyright 2004-present Facebook.  All rights reserved.

#include <quic/congestion_control/BbrRttSampler.h>

namespace quic {

BbrRttSampler::BbrRttSampler(std::chrono::seconds expiration)
    : expiration_(expiration) {}

std::chrono::microseconds BbrRttSampler::minRtt() const noexcept {
  return minRtt_;
}

bool BbrRttSampler::newRttSample(
    std::chrono::microseconds rttSample,
    TimePoint sampledTime) noexcept {
  if (minRttExpired(sampledTime) || minRtt_ > rttSample ||
      UNLIKELY(minRtt_ == 0us)) {
    minRtt_ = rttSample;
    minRttTimestamp_ = sampledTime;
    return true;
  }
  return false;
}

bool BbrRttSampler::minRttExpired(TimePoint currentTime) const noexcept {
  return currentTime > minRttTimestamp_ + expiration_;
}

void BbrRttSampler::timestampMinRtt(TimePoint timestamp) noexcept {
  minRttTimestamp_ = timestamp;
}

} // namespace quic
