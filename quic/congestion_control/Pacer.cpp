/*
 * Copyright (c) Facebook, Inc. and its affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 *
 */

#include <quic/congestion_control/Pacer.h>

#include <quic/congestion_control/CongestionControlFunctions.h>
#include <quic/logging/QuicLogger.h>

namespace quic {

DefaultPacer::DefaultPacer(
    const QuicConnectionStateBase& conn,
    uint64_t minCwndInMss)
    : conn_(conn),
      minCwndInMss_(minCwndInMss),
      batchSize_(conn.transportSettings.writeConnectionDataPacketsLimit),
      pacingRateCalculator_(calculatePacingRate),
      cachedBatchSize_(conn.transportSettings.writeConnectionDataPacketsLimit) {
}

// TODO: we choose to keep refershing pacing rate even when we are app-limited,
// so that when we exit app-limited, we have an updated pacing rate. But I don't
// really know if this is a good idea.
void DefaultPacer::refreshPacingRate(
    uint64_t cwndBytes,
    std::chrono::microseconds rtt) {
  SCOPE_EXIT {
    if (conn_.qLogger) {
      conn_.qLogger->addPacingMetricUpdate(batchSize_, writeInterval_);
    }
    QUIC_TRACE(
        pacing_update, conn_, writeInterval_.count(), (uint64_t)batchSize_);
    cachedBatchSize_ = batchSize_;
  };
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
  return appLimited_ ? 0us : writeInterval_;
}

uint64_t DefaultPacer::updateAndGetWriteBatchSize(TimePoint currentTime) {
  SCOPE_EXIT {
    scheduledWriteTime_.clear();
  };
  if (appLimited_) {
    cachedBatchSize_ = conn_.transportSettings.writeConnectionDataPacketsLimit;
    return cachedBatchSize_;
  }
  if (writeInterval_ == 0us) {
    return batchSize_;
  }
  if (!scheduledWriteTime_ || *scheduledWriteTime_ >= currentTime) {
    return batchSize_;
  }
  auto adjustedInterval = std::chrono::duration_cast<std::chrono::microseconds>(
      currentTime - *scheduledWriteTime_ + writeInterval_);
  cachedBatchSize_ = std::ceil(
      adjustedInterval.count() * batchSize_ * 1.0 / writeInterval_.count());
  return cachedBatchSize_;
}

uint64_t DefaultPacer::getCachedWriteBatchSize() const {
  return cachedBatchSize_;
}

void DefaultPacer::setPacingRateCalculator(
    PacingRateCalculator pacingRateCalculator) {
  pacingRateCalculator_ = std::move(pacingRateCalculator);
}

void DefaultPacer::setAppLimited(bool limited) {
  appLimited_ = limited;
}

} // namespace quic
