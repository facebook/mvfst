/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#pragma once

#include <quic/congestion_control/CongestionController.h>
#include <quic/state/AckEvent.h>
#include <quic/state/TransportSettings.h>

namespace quic {

/**
 * Simple congestion controller with a static congestion window.
 *
 * getWritableBytes() returns CWND - bytesInflight, with bytesInFlight changing
 * based on packet sent/ack/loss events.
 *
 * Although capable of being used in production, intended to be used for
 * testing and experiments.
 */
struct StaticCwndCongestionController : public CongestionController {
  /**
   * Helper struct to make it clear that CWND should be passed in # of bytes.
   */
  struct CwndInBytes {
    explicit CwndInBytes(uint64_t bytes) : bytes(bytes) {}
    const uint64_t bytes;
  };

  explicit StaticCwndCongestionController(CwndInBytes cwnd);

  void onRemoveBytesFromInflight(uint64_t bytesToRemove) override;

  void onPacketSent(const OutstandingPacketWrapper& packet) override;

  void onPacketAckOrLoss(
      const AckEvent* FOLLY_NULLABLE ackEvent,
      const LossEvent* FOLLY_NULLABLE lossEvent) override;

  FOLLY_NODISCARD uint64_t getWritableBytes() const noexcept override;

  FOLLY_NODISCARD uint64_t getCongestionWindow() const noexcept override;

  FOLLY_NODISCARD CongestionControlType type() const noexcept override;

  FOLLY_NODISCARD bool isInBackgroundMode() const override;

  FOLLY_NODISCARD bool isAppLimited() const override;

  void setAppLimited() noexcept override;

  void setAppIdle(bool, TimePoint) noexcept override {}

  void setBandwidthUtilizationFactor(float) noexcept override {}

  void getStats(CongestionControllerStats&) const override {}

 private:
  uint64_t inflightBytes_{0}; // initially zero bytes inflight
  bool isAppLimited_{true}; // initially starts true
  const uint64_t congestionWindowInBytes_;
};

} // namespace quic
