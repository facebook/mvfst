/*
 * Copyright (c) Facebook, Inc. and its affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 *
 */

#include <quic/congestion_control/Pacer.h>

#include <quic/congestion_control/CongestionControlFunctions.h>

namespace quic {

DefaultPacer::DefaultPacer(
    const QuicConnectionStateBase& conn,
    uint64_t minCwndInMss)
    : conn_(conn),
      minCwndInMss_(minCwndInMss),
      batchSize_(conn.transportSettings.writeConnectionDataPacketsLimit),
      pacingRateCalculator_(calculatePacingRateWrapper) {}

void DefaultPacer::refreshPacingRate(
    uint64_t cwndBytes,
    std::chrono::microseconds rtt) {
  if (rtt < conn_.transportSettings.pacingTimerTickInterval) {
    writeInterval_ = 0us;
    batchSize_ = conn_.transportSettings.writeConnectionDataPacketsLimit;
    return;
  }
  const PacingRate pacingRate =
      pacingRateCalculator_(conn_, cwndBytes, minCwndInMss_, rtt);
  writeInterval_ = pacingRate.interval;
  batchSize_ = pacingRate.burstSize;
}

void DefaultPacer::onPacedWriteScheduled(TimePoint currentTime) {
  scheduledWriteTime_ = currentTime;
}

std::chrono::microseconds DefaultPacer::getTimeUntilNextWrite() const {
  return writeInterval_;
}

uint64_t DefaultPacer::updateAndGetWriteBatchSize(TimePoint currentTime) {
  SCOPE_EXIT {
    scheduledWriteTime_.clear();
  };
  if (writeInterval_ == 0us) {
    return batchSize_;
  }
  if (!scheduledWriteTime_ || *scheduledWriteTime_ >= currentTime) {
    return batchSize_;
  }
  auto adjustedInterval = std::chrono::duration_cast<std::chrono::microseconds>(
      currentTime - *scheduledWriteTime_ + writeInterval_);
  return std::ceil(
      adjustedInterval.count() * batchSize_ * 1.0 / writeInterval_.count());
}

void DefaultPacer::setPacingRateCalculator(
    PacingRateCalculator pacingRateCalculator) {
  pacingRateCalculator_ = std::move(pacingRateCalculator);
}

} // namespace quic
