/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#pragma once

#include <quic/congestion_control/Pacer.h>

namespace quic {

/*
 * Pacer which does not ever collect additional tokens, and rather paces purely
 * based on the minimum batch size.
 */
class TokenlessPacer : public Pacer {
 public:
  explicit TokenlessPacer(
      const QuicConnectionStateBase& conn,
      uint64_t minCwndInMss);

  void refreshPacingRate(
      uint64_t cwndBytes,
      std::chrono::microseconds rtt,
      TimePoint currentTime = Clock::now()) override;

  void setPacingRate(uint64_t rateBps) override;

  void setMaxPacingRate(uint64_t maxRateBytesPerSec) override;

  void reset() override;

  void setRttFactor(uint8_t numerator, uint8_t denominator) override;

  std::chrono::microseconds getTimeUntilNextWrite(
      TimePoint currentTime = Clock::now()) const override;

  uint64_t updateAndGetWriteBatchSize(TimePoint currentTime) override;

  void setPacingRateCalculator(PacingRateCalculator pacingRateCalculator);

  uint64_t getCachedWriteBatchSize() const override;

  void onPacketSent() override;
  void onPacketsLoss() override;

  void setExperimental(bool experimental) override;

 private:
  const QuicConnectionStateBase& conn_;
  uint64_t minCwndInMss_;
  uint64_t batchSize_;
  uint64_t maxPacingRateBytesPerSec_{std::numeric_limits<uint64_t>::max()};
  std::chrono::microseconds writeInterval_{0};
  PacingRateCalculator pacingRateCalculator_;
  folly::Optional<TimePoint> lastWriteTime_;
  uint8_t rttFactorNumerator_{1};
  uint8_t rttFactorDenominator_{1};
  bool experimental_{false};

  // Experimental
  // Maximum factor the batchSize can be multiplied by to account for pacer
  // timer delays. I.e., if the pacing function is late by up to 5 intervals, it
  // will be allowed to write 5 times as many packets
  static constexpr int maxBurstIntervals{5};
};
} // namespace quic
