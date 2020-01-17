/*
 * Copyright (c) Facebook, Inc. and its affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 *
 */

#pragma once

#include <quic/congestion_control/Bandwidth.h>
#include <quic/state/StateData.h>

namespace quic {

/**
 * Returns a pair consisting of the length of the burst interval and the number
 * of packets in a burst interval.
 */
using PacingRateCalculator = folly::Function<PacingRate(
    const QuicConnectionStateBase&,
    uint64_t cwndBytes,
    uint64_t minCwndInMss,
    std::chrono::microseconds rtt)>;

class DefaultPacer : public Pacer {
 public:
  explicit DefaultPacer(
      const QuicConnectionStateBase& conn,
      uint64_t minCwndInMss);

  void refreshPacingRate(uint64_t cwndBytes, std::chrono::microseconds rtt)
      override;

  std::chrono::microseconds getTimeUntilNextWrite() const override;

  uint64_t updateAndGetWriteBatchSize(TimePoint currentTime) override;

  void setPacingRateCalculator(PacingRateCalculator pacingRateCalculator);

  uint64_t getCachedWriteBatchSize() const override;

  void setAppLimited(bool limited) override;

  void onPacketSent(uint64_t bytesSent) override;
  void onPacketsLoss() override;

  // Only used for test:
  bool isPacingLimited() const noexcept;

 private:
  const QuicConnectionStateBase& conn_;
  uint64_t minCwndInMss_;
  uint64_t batchSize_;
  std::chrono::microseconds writeInterval_{0};
  folly::Optional<TimePoint> scheduledWriteTime_;
  PacingRateCalculator pacingRateCalculator_;
  uint64_t cachedBatchSize_;
  bool appLimited_{false};
  uint64_t tokens_;
  uint64_t bytesSentSincePacingRateUpdate_{0};
  folly::Optional<TimePoint> lastPacingRateUpdate_;
  bool pacingLimited_{false};
  TimePoint nextWriteTime_;
  TimePoint lastWriteTime_;
  bool firstUpdate_{true};
};
} // namespace quic
