/*
 * Copyright (c) Facebook, Inc. and its affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 *
 */

#pragma once

#include <quic/QuicConstants.h>
#include <quic/congestion_control/Bandwidth.h>
#include <quic/logging/QLogger.h>

namespace quic {

class QLogPacingObserver : public PacingObserver {
 public:
  explicit QLogPacingObserver(const std::shared_ptr<QLogger>& logger);
  void onNewPacingRate(
      uint64_t packetsPerInterval,
      std::chrono::microseconds interval) override;
  void onPacketSent() override;

 private:
  std::weak_ptr<QLogger> logger_;
  uint64_t packetsSentSinceLastUpdate_{0};
  TimePoint lastSampledTime_;
  Bandwidth expectedRate_;
};
} // namespace quic
