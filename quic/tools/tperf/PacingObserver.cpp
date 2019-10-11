/*
 * Copyright (c) Facebook, Inc. and its affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 *
 */

#include <quic/tools/tperf/PacingObserver.h>

namespace quic {
QLogPacingObserver::QLogPacingObserver(const std::shared_ptr<QLogger>& logger)
    : logger_(logger),
      lastSampledTime_(Clock::now()),
      expectedRate_(0, 0us, "packets") {}

void QLogPacingObserver::onNewPacingRate(
    uint64_t packetsPerInterval,
    std::chrono::microseconds interval) {
  Bandwidth actualSendRate(
      packetsSentSinceLastUpdate_,
      std::chrono::duration_cast<std::chrono::microseconds>(
          Clock::now() - lastSampledTime_),
      "packets");
  auto logger = logger_.lock();
  if (logger) {
    logger->addPacingObservation(
        actualSendRate.conciseDescribe(),
        expectedRate_.conciseDescribe(),
        (actualSendRate > expectedRate_ ? "Pacing above expect"
                                        : "Pacing below expect"));
  }
  expectedRate_ = Bandwidth(packetsPerInterval, interval, "packets");
  packetsSentSinceLastUpdate_ = 0;
  lastSampledTime_ = Clock::now();
}

void QLogPacingObserver::onPacketSent() {
  ++packetsSentSinceLastUpdate_;
}
} // namespace quic
