/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#pragma once

#include <quic/congestion_control/CongestionController.h>
#include <quic/congestion_control/modular/Bbr2Shared.h>
#include <chrono>
#include <cstdint>
#include <memory>

namespace quic {

/**
 * Bbr2ProbeRtt is a modular congestion controller component that:
 * 1. Maintains the minRtt value
 * 2. Decides when the minRtt needs to be refreshed (when ProbeRTT should be
 *    entered)
 * 3. Manages the connection while ProbeRTT is ongoing
 *
 * A parent controller queries shouldEnterProbeRtt() to decide when to hand
 * over control by setting Bbr2ProbeRtt as the connection's congestion
 * controller.
 */
class Bbr2ProbeRtt : public CongestionController {
 public:
  explicit Bbr2ProbeRtt(
      QuicConnectionStateBase& conn,
      std::shared_ptr<Bbr2Shared> shared,
      std::unique_ptr<CongestionController> previousController);

  // CongestionController interface
  void onRemoveBytesFromInflight(uint64_t) override {}

  [[nodiscard]] uint64_t getWritableBytes() const noexcept override {
    return shared_->getWritableBytes();
  }

  [[nodiscard]] uint64_t getCongestionWindow() const noexcept override {
    return shared_->cwndBytes_;
  }

  [[nodiscard]] CongestionControlType type() const noexcept override {
    return shared_->type();
  }

  [[nodiscard]] bool isAppLimited() const override {
    return shared_->appLimited_;
  }

  [[nodiscard]] Optional<Bandwidth> getBandwidth() const override {
    return shared_->getBandwidth();
  }

  [[nodiscard]] uint64_t getBDP() const override {
    return shared_->getBDP();
  }

  void setAppLimited() noexcept override {
    shared_->setAppLimited();
  }

  void setAppIdle(bool, TimePoint) noexcept override {}

  void onPacketSent(const OutstandingPacketWrapper& packet) override;
  void onPacketAckOrLoss(
      const AckEvent* FOLLY_NULLABLE ackEvent,
      const LossEvent* FOLLY_NULLABLE lossEvent) override;

  void getStats(CongestionControllerStats& stats) const override {
    shared_->getStats(stats);
  }

  // Finish ACK processing - applies pacing and cwnd.
  // Called after transitioning into this module to complete the current ack.
  void finishAckProcessing(const AckEvent& ackEvent);

 private:
  // Cwnd management
  [[nodiscard]] uint64_t calculateCwnd() const;

  // ProbeRTT state management
  void enterProbeRtt();
  void handleProbeRtt();
  void checkProbeRttDone();
  void exitProbeRtt();
  [[nodiscard]] uint64_t getProbeRTTCwnd() const;

  QuicConnectionStateBase& conn_;
  std::shared_ptr<Bbr2Shared> shared_;

  // ProbeRTT execution state
  Optional<TimePoint> probeRttDoneTimestamp_;

  // Previous controller to return to after ProbeRtt completes
  bool completedProbeRtt_{false};
  std::unique_ptr<CongestionController> previousController_;
};

} // namespace quic
