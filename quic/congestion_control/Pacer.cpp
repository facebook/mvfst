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
      cachedBatchSize_(conn.transportSettings.writeConnectionDataPacketsLimit),
      tokens_(conn.transportSettings.writeConnectionDataPacketsLimit) {}

// TODO: we choose to keep refershing pacing rate even when we are app-limited,
// so that when we exit app-limited, we have an updated pacing rate. But I don't
// really know if this is a good idea.
void DefaultPacer::refreshPacingRate(
    uint64_t cwndBytes,
    std::chrono::microseconds rtt) {
  if (rtt < conn_.transportSettings.pacingTimerTickInterval) {
    writeInterval_ = 0us;
    batchSize_ = conn_.transportSettings.writeConnectionDataPacketsLimit;
  } else {
    const PacingRate pacingRate =
        pacingRateCalculator_(conn_, cwndBytes, minCwndInMss_, rtt);
    writeInterval_ = pacingRate.interval;
    batchSize_ = pacingRate.burstSize;
    tokens_ = batchSize_;
  }
  if (conn_.qLogger) {
    conn_.qLogger->addPacingMetricUpdate(batchSize_, writeInterval_);
  }
  QUIC_TRACE(
      pacing_update, conn_, writeInterval_.count(), (uint64_t)batchSize_);
  cachedBatchSize_ = batchSize_;
}

// rate_bps is *bytes* per second
void DefaultPacer::setPacingRate(
    QuicConnectionStateBase& conn,
    uint64_t rate_bps) {
  batchSize_ = conn_.transportSettings.writeConnectionDataPacketsLimit;
  cachedBatchSize_ = batchSize_;
  tokens_ = batchSize_;

  // This calculates the necessary time interval between writes to achieve
  // the desired rate. The number of bytes we write in each batch divided
  // by the rate (bytes per second) yields the correct interval in *seconds*.
  // Since the writeInterval_ must be expressed in microseconds,
  // we multiply the numerator by 1,000,000.
  uint64_t interval = (batchSize_ * conn.udpSendPacketLen * 1000000) / rate_bps;
  writeInterval_ = std::max(
      std::chrono::microseconds(interval),
      conn.transportSettings.pacingTimerTickInterval);
}

void DefaultPacer::resetPacingTokens() {
  tokens_ = batchSize_;
  lastWriteTime_.reset();
}

void DefaultPacer::onPacketSent() {
  if (tokens_) {
    --tokens_;
  }
}

void DefaultPacer::onPacketsLoss() {
  tokens_ = 0UL;
  lastWriteTime_.reset();
}

std::chrono::microseconds DefaultPacer::getTimeUntilNextWrite() const {
  return tokens_ ? 0us : writeInterval_;
}

uint64_t DefaultPacer::updateAndGetWriteBatchSize(TimePoint currentTime) {
  SCOPE_EXIT {
    lastWriteTime_ = currentTime;
  };
  if (writeInterval_ == 0us) {
    return batchSize_;
  }
  if (!lastWriteTime_) {
    return tokens_;
  }
  /**
   * Don't let `+ writeInterval_` confuse you. A few lines later we use
   * `cachedBatchSize_ - batchSize_` instead of `cachedBatchSize_` to increase
   * token_.
   */
  auto adjustedInterval = std::chrono::duration_cast<std::chrono::microseconds>(
      currentTime - *lastWriteTime_ + writeInterval_);
  cachedBatchSize_ = std::ceil(
      adjustedInterval.count() * batchSize_ * 1.0 / writeInterval_.count());
  if (cachedBatchSize_ < batchSize_) {
    LOG(ERROR)
        << "Quic pacer batch size calculation: cachedBatchSize < batchSize";
  }
  tokens_ +=
      (cachedBatchSize_ > batchSize_ ? cachedBatchSize_ - batchSize_ : 0);
  return tokens_;
}

uint64_t DefaultPacer::getCachedWriteBatchSize() const {
  return cachedBatchSize_;
}

void DefaultPacer::setPacingRateCalculator(
    PacingRateCalculator pacingRateCalculator) {
  pacingRateCalculator_ = std::move(pacingRateCalculator);
}
} // namespace quic
