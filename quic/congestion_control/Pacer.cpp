/*
 * Copyright (c) Facebook, Inc. and its affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 *
 */

#include <quic/congestion_control/Pacer.h>

#include <quic/common/TimeUtil.h>
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
      tokens_(conn.transportSettings.writeConnectionDataPacketsLimit),
      nextWriteTime_(Clock::now()),
      lastWriteTime_(Clock::now()) {}

// TODO: we choose to keep refershing pacing rate even when we are app-limited,
// so that when we exit app-limited, we have an updated pacing rate. But I don't
// really know if this is a good idea.
void DefaultPacer::refreshPacingRate(
    uint64_t cwndBytes,
    std::chrono::microseconds rtt) {
  auto currentTime = Clock::now();
  if (rtt < conn_.transportSettings.pacingTimerTickInterval) {
    writeInterval_ = 0us;
    batchSize_ = conn_.transportSettings.writeConnectionDataPacketsLimit;
  } else {
    const auto pacingRate =
        pacingRateCalculator_(conn_, cwndBytes, minCwndInMss_, rtt);
    writeInterval_ = pacingRate.interval;
    batchSize_ = pacingRate.burstSize;
    lastPacingRateUpdate_ = currentTime;
    bytesSentSincePacingRateUpdate_ = 0;
  }
  if (conn_.qLogger) {
    conn_.qLogger->addPacingMetricUpdate(batchSize_, writeInterval_);
  }
  QUIC_TRACE(
      pacing_update, conn_, writeInterval_.count(), (uint64_t)batchSize_);
  cachedBatchSize_ = batchSize_;
  tokens_ = batchSize_;
  nextWriteTime_ = currentTime;
  if (firstUpdate_) {
    firstUpdate_ = false;
    lastWriteTime_ = currentTime;
  }
}

void DefaultPacer::onPacketSent(uint64_t bytesSent) {
  if (tokens_) {
    --tokens_;
  }
  bytesSentSincePacingRateUpdate_ += bytesSent;
  if (writeInterval_ != 0us && cachedBatchSize_ && !appLimited_ &&
      lastPacingRateUpdate_) {
    Bandwidth expectedBandwidth(
        cachedBatchSize_ * conn_.udpSendPacketLen, writeInterval_);
    if (expectedBandwidth) {
      Bandwidth actualPacingBandwidth(
          bytesSentSincePacingRateUpdate_,
          std::chrono::duration_cast<std::chrono::microseconds>(
              Clock::now() - *lastPacingRateUpdate_));
      pacingLimited_ = actualPacingBandwidth < expectedBandwidth;
    }
  } else {
    pacingLimited_ = false;
  }
  if (!pacingLimited_) {
    lastWriteTime_ = Clock::now();
  }
}

bool DefaultPacer::isPacingLimited() const noexcept {
  return pacingLimited_;
}

void DefaultPacer::onPacketsLoss() {
  tokens_ = 0UL;
}

std::chrono::microseconds DefaultPacer::getTimeUntilNextWrite() const {
  return (writeInterval_ == 0us || appLimited_ || tokens_ ||
          Clock::now() + conn_.transportSettings.pacingTimerTickInterval >=
              nextWriteTime_)
      ? 0us
      : timeMax(
            conn_.transportSettings.pacingTimerTickInterval,
            timeMin(
                writeInterval_,
                std::chrono::duration_cast<std::chrono::microseconds>(
                    nextWriteTime_ - Clock::now())));
}

uint64_t DefaultPacer::updateAndGetWriteBatchSize(TimePoint currentTime) {
  SCOPE_EXIT {
    lastWriteTime_ = nextWriteTime_;
    nextWriteTime_ += writeInterval_;
  };
  if (appLimited_ || writeInterval_ == 0us) {
    return conn_.transportSettings.writeConnectionDataPacketsLimit;
  }
  auto adjustedInterval = std::chrono::duration_cast<std::chrono::microseconds>(
      timeMax(currentTime - lastWriteTime_, writeInterval_));
  return std::ceil(
      adjustedInterval.count() * batchSize_ * 1.0 / writeInterval_.count());
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
