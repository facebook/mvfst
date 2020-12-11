/*
 * Copyright (c) Facebook, Inc. and its affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 *
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

  void setPacingRate(QuicConnectionStateBase& conn, uint64_t rate_bps) override;

  void reset() override;

  void setRttFactor(uint8_t numerator, uint8_t denominator) override;

  std::chrono::microseconds getTimeUntilNextWrite() const override;

  uint64_t updateAndGetWriteBatchSize(TimePoint currentTime) override;

  void setPacingRateCalculator(PacingRateCalculator pacingRateCalculator);

  uint64_t getCachedWriteBatchSize() const override;

  void onPacketSent() override;
  void onPacketsLoss() override;

 private:
  const QuicConnectionStateBase& conn_;
  uint64_t minCwndInMss_;
  uint64_t batchSize_;
  std::chrono::microseconds writeInterval_{0};
  PacingRateCalculator pacingRateCalculator_;
  folly::Optional<TimePoint> lastWriteTime_;
  uint8_t rttFactorNumerator_{1};
  uint8_t rttFactorDenominator_{1};
};
} // namespace quic
