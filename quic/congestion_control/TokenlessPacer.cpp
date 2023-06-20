/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <quic/congestion_control/TokenlessPacer.h>

#include <quic/congestion_control/CongestionControlFunctions.h>

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
  if (rtt == kDefaultMinRtt) {
    return;
  }
  uint64_t targetRateBytesPerSec = (rtt == 0us)
      ? std::numeric_limits<uint64_t>::max()
      : cwndBytes * 1s / rtt;
  if (targetRateBytesPerSec > maxPacingRateBytesPerSec_) {
    return setPacingRate(maxPacingRateBytesPerSec_);
  } else if (rtt < conn_.transportSettings.pacingTickInterval) {
    writeInterval_ = 0us;
    batchSize_ = conn_.transportSettings.writeConnectionDataPacketsLimit;
  } else {
    rtt *= rttFactorNumerator_;
    rtt /= rttFactorDenominator_;
    const PacingRate pacingRate =
        pacingRateCalculator_(conn_, cwndBytes, minCwndInMss_, rtt);
    writeInterval_ = pacingRate.interval;
    batchSize_ = pacingRate.burstSize;
  }
  if (conn_.qLogger) {
    conn_.qLogger->addPacingMetricUpdate(batchSize_, writeInterval_);
  }
  if (!experimental_) {
    lastWriteTime_.reset();
  }
}

// rate_bps is *bytes* per second
void TokenlessPacer::setPacingRate(uint64_t rateBps) {
  if (rateBps > maxPacingRateBytesPerSec_) {
    rateBps = maxPacingRateBytesPerSec_;
  }

  if (rateBps == 0) {
    batchSize_ = 0;
    writeInterval_ = conn_.transportSettings.pacingTickInterval;
  } else {
    batchSize_ = conn_.transportSettings.writeConnectionDataPacketsLimit;
    uint64_t interval =
        (batchSize_ * conn_.udpSendPacketLen * 1000000) / rateBps;
    writeInterval_ = std::max(
        std::chrono::microseconds(interval),
        conn_.transportSettings.pacingTickInterval);
  }

  if (conn_.qLogger) {
    conn_.qLogger->addPacingMetricUpdate(batchSize_, writeInterval_);
  }
  if (!experimental_) {
    lastWriteTime_.reset();
  }
}

void TokenlessPacer::setMaxPacingRate(uint64_t maxRateBytesPerSec) {
  maxPacingRateBytesPerSec_ = maxRateBytesPerSec;
  // Current rate in bytes per sec =
  //         batchSize * packetLen * (1 second / writeInterval)
  // if writeInterval = 0, current rate is std::numeric_limits<uint64_t>::max()
  uint64_t currentRateBytesPerSec = (writeInterval_ == 0us)
      ? std::numeric_limits<uint64_t>::max()
      : (batchSize_ * conn_.udpSendPacketLen * std::chrono::seconds(1)) /
          writeInterval_;
  if (currentRateBytesPerSec > maxPacingRateBytesPerSec_) {
    // Current rate is faster than max. Enforce the maxPacingRate.
    return setPacingRate(maxPacingRateBytesPerSec_);
  }
}

void TokenlessPacer::reset() {
  // We call this after idle, so we actually want to start writing immediately.
  lastWriteTime_.reset();
}

void TokenlessPacer::setRttFactor(uint8_t numerator, uint8_t denominator) {
  rttFactorNumerator_ = numerator;
  rttFactorDenominator_ = denominator;
}

void TokenlessPacer::onPacketSent() {}

void TokenlessPacer::onPacketsLoss() {}

std::chrono::microseconds TokenlessPacer::getTimeUntilNextWrite(
    TimePoint now) const {
  // If we don't have a lastWriteTime_, we want to write immediately.
  auto timeSinceLastWrite =
      std::chrono::duration_cast<std::chrono::microseconds>(
          now - lastWriteTime_.value_or(now - 2 * writeInterval_));
  if (timeSinceLastWrite >= writeInterval_) {
    return 0us;
  }
  return std::max(
      writeInterval_ - timeSinceLastWrite,
      conn_.transportSettings.pacingTickInterval);
}

uint64_t TokenlessPacer::updateAndGetWriteBatchSize(TimePoint currentTime) {
  auto sendBatch = batchSize_;
  if (lastWriteTime_.hasValue() && writeInterval_ > 0us &&
      conn_.congestionController &&
      !conn_.congestionController->isAppLimited()) {
    // The pacer timer is expected to trigger every writeInterval_
    auto timeSinceLastWrite =
        std::chrono::duration_cast<std::chrono::microseconds>(
            currentTime - lastWriteTime_.value());
    if (conn_.congestionController &&
        !conn_.congestionController->isAppLimited() &&
        timeSinceLastWrite > (writeInterval_ * 110 / 100)) {
      // Log if connection is not application-limited and the timer has been
      // delayed by more than 10% of the expected write interval
      QUIC_STATS(conn_.statsCallback, onPacerTimerLagged);
    }
    if (experimental_) {
      sendBatch = (timeSinceLastWrite / writeInterval_ >= maxBurstIntervals)
          ? batchSize_ * maxBurstIntervals
          : batchSize_ * timeSinceLastWrite / writeInterval_;
    }
  }
  lastWriteTime_ = currentTime;
  return sendBatch;
}

uint64_t TokenlessPacer::getCachedWriteBatchSize() const {
  return batchSize_;
}

void TokenlessPacer::setPacingRateCalculator(
    PacingRateCalculator pacingRateCalculator) {
  pacingRateCalculator_ = std::move(pacingRateCalculator);
}

void TokenlessPacer::setExperimental(bool experimental) {
  experimental_ = experimental;
}
} // namespace quic
