/*
 * Copyright (c) Facebook, Inc. and its affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 *
 */

#include <quic/congestion_control/TokenlessPacer.h>

#include <quic/congestion_control/CongestionControlFunctions.h>
#include <quic/logging/QuicLogger.h>

namespace quic {

TokenlessPacer::TokenlessPacer(
    const QuicConnectionStateBase& conn,
    uint64_t minCwndInMss)
    : conn_(conn),
      minCwndInMss_(minCwndInMss),
      batchSize_(conn.transportSettings.writeConnectionDataPacketsLimit),
      pacingRateCalculator_(calculatePacingRate) {}

void TokenlessPacer::refreshPacingRate(
    uint64_t cwndBytes,
    std::chrono::microseconds rtt,
    TimePoint /*currentTime*/) {
  if (rtt < conn_.transportSettings.pacingTimerTickInterval) {
    writeInterval_ = 0us;
    batchSize_ = conn_.transportSettings.writeConnectionDataPacketsLimit;
  } else {
    const PacingRate pacingRate =
        pacingRateCalculator_(conn_, cwndBytes, minCwndInMss_, rtt);
    writeInterval_ = pacingRate.interval;
    batchSize_ = pacingRate.burstSize;
  }
  if (conn_.qLogger) {
    conn_.qLogger->addPacingMetricUpdate(batchSize_, writeInterval_);
  }
  QUIC_TRACE(
      pacing_update, conn_, writeInterval_.count(), (uint64_t)batchSize_);
  lastWriteTime_.reset();
}

// rate_bps is *bytes* per second
void TokenlessPacer::setPacingRate(
    QuicConnectionStateBase& conn,
    uint64_t rate_bps) {
  batchSize_ = conn_.transportSettings.writeConnectionDataPacketsLimit;
  uint64_t interval = (batchSize_ * conn.udpSendPacketLen * 1000000) / rate_bps;
  writeInterval_ = std::max(
      std::chrono::microseconds(interval),
      conn.transportSettings.pacingTimerTickInterval);
}

void TokenlessPacer::resetPacingTokens() {
  // We call this after idle, so we actually want to start writing immediately.
  lastWriteTime_.reset();
}

void TokenlessPacer::onPacketSent() {}

void TokenlessPacer::onPacketsLoss() {}

std::chrono::microseconds TokenlessPacer::getTimeUntilNextWrite() const {
  auto now = Clock::now();
  // If we don't have a lastWriteTime_, we want to write immediately.
  auto timeSinceLastWrite =
      std::chrono::duration_cast<std::chrono::microseconds>(
          now - lastWriteTime_.value_or(now - 2 * writeInterval_));
  if (timeSinceLastWrite >= writeInterval_) {
    return 0us;
  }
  return std::max(
      writeInterval_ - timeSinceLastWrite,
      conn_.transportSettings.pacingTimerTickInterval);
}

uint64_t TokenlessPacer::updateAndGetWriteBatchSize(TimePoint currentTime) {
  lastWriteTime_ = currentTime;
  return batchSize_;
}

uint64_t TokenlessPacer::getCachedWriteBatchSize() const {
  return batchSize_;
}

void TokenlessPacer::setPacingRateCalculator(
    PacingRateCalculator pacingRateCalculator) {
  pacingRateCalculator_ = std::move(pacingRateCalculator);
}
} // namespace quic
