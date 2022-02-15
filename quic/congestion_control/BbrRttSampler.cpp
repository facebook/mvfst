/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <quic/congestion_control/BbrRttSampler.h>

namespace quic {

BbrRttSampler::BbrRttSampler(std::chrono::seconds expiration)
    : expiration_(expiration), rttSampleExpired_{true} {}

std::chrono::microseconds BbrRttSampler::minRtt() const noexcept {
  return minRtt_;
}

bool BbrRttSampler::newRttSample(
    std::chrono::microseconds rttSample,
    TimePoint sampledTime) noexcept {
  rttSampleExpired_ = minRttTimestamp_.has_value()
      ? sampledTime > *minRttTimestamp_ + expiration_
      : false;
  if (rttSampleExpired_ || minRtt_ > rttSample) {
    minRtt_ = rttSample;
    minRttTimestamp_ = sampledTime;
    return true;
  }
  return false;
}

bool BbrRttSampler::minRttExpired() const noexcept {
  return rttSampleExpired_;
}

void BbrRttSampler::timestampMinRtt(TimePoint timestamp) noexcept {
  minRttTimestamp_ = timestamp;
}

} // namespace quic
