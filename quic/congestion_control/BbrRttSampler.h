/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#pragma once

#include <quic/QuicConstants.h>
#include <quic/congestion_control/Bbr.h>

namespace quic {

class BbrRttSampler : public BbrCongestionController::MinRttSampler {
 public:
  explicit BbrRttSampler(std::chrono::seconds expiration);
  ~BbrRttSampler() override = default;

  std::chrono::microseconds minRtt() const noexcept override;
  bool minRttExpired() const noexcept override;
  bool newRttSample(
      std::chrono::microseconds rttSample,
      TimePoint sampledTime) noexcept override;
  void timestampMinRtt(TimePoint timestamp) noexcept override;

 private:
  std::chrono::seconds expiration_;
  std::chrono::microseconds minRtt_{kDefaultMinRtt};
  folly::Optional<TimePoint> minRttTimestamp_;
  bool rttSampleExpired_;
};
} // namespace quic
