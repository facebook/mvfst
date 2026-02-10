/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#pragma once

#include <quic/congestion_control/Bandwidth.h>
#include <quic/congestion_control/CongestionController.h>
#include <quic/congestion_control/modular/Bbr2Shared.h>
#include <chrono>
#include <cstdint>
#include <memory>

namespace quic {

/**
 * Bbr2ProbeBw is a modular congestion controller component that handles
 * the ProbeBW phases of BBR2 (Down, Cruise, Refill, Up). It uses Bbr2Shared
 * for common state and operations.
 *
 * This module is responsible for:
 * - ProbeBW state machine (cycling through Down → Cruise → Refill → Up)
 * - Long-term inflight model (adapting inflight bounds based on loss)
 * - Short-term model updates during ProbeBW
 *
 * The parent controller should transition to this module after Drain completes
 * and transition away when ProbeRTT is needed.
 */
class Bbr2ProbeBw : public CongestionController {
 public:
  explicit Bbr2ProbeBw(
      QuicConnectionStateBase& conn,
      std::shared_ptr<Bbr2Shared> shared);

  void onRemoveBytesFromInflight(uint64_t) override {}

  void onPacketSent(const OutstandingPacketWrapper& packet) override;

  void onPacketAckOrLoss(
      const AckEvent* FOLLY_NULLABLE ackEvent,
      const LossEvent* FOLLY_NULLABLE lossEvent) override;

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

  void getStats(CongestionControllerStats& stats) const override {
    shared_->getStats(stats);
  }

  void setAppIdle(bool, TimePoint) noexcept override {}

  // Finish ACK processing - applies pacing and cwnd.
  // Called after transitioning into this module to complete the current ack.
  void finishAckProcessing(const AckEvent& ackEvent);

 private:
  // ProbeBw cycle control
  void startProbeBwDown();
  void startProbeBwCruise();
  void startProbeBwRefill();
  void startProbeBwUp();
  void updateProbeBwCyclePhase();
  bool checkTimeToProbeBW();
  bool checkTimeToCruise();
  bool checkTimeToGoDown();
  bool hasElapsedInPhase(std::chrono::microseconds interval);

  // Full bandwidth detection (for ProbeBw_Up → ProbeBw_Down transition)
  void checkFullBwReached();
  void resetFullBw();

  // Long-term inflight model
  void adaptLongTermModel();
  bool checkInflightTooHigh();
  bool isInflightTooHigh();
  void handleInFlightTooHigh();
  void probeInflightLongTermUpward();
  void raiseInflightLongTermSlope();
  [[nodiscard]] uint64_t getTargetInflightWithHeadroom() const;

  // Cwnd
  [[nodiscard]] uint64_t calculateCwnd() const;
  void updatePacingAndCwndGain();

  // Short-term model (ProbeBw-specific)
  void resetShortTermModel();
  void updateCongestionSignals();

  // Utility
  [[nodiscard]] uint64_t addQuantizationBudget(uint64_t input) const;
  bool isRenoCoexistenceProbeTime();

  QuicConnectionStateBase& conn_;
  std::shared_ptr<Bbr2Shared> shared_;

  // Short-term model (response to loss)
  Optional<Bandwidth> bandwidthShortTerm_;
  Optional<uint64_t> inflightShortTerm_;

  // ProbeBw cycle timing
  TimePoint probeBWCycleStart_;
  uint64_t roundsSinceBwProbe_{0};
  std::chrono::milliseconds bwProbeWait_{0};

  // ProbeBw_Up state
  uint64_t probeUpCount_{0};
  uint64_t probeUpRounds_{0};
  uint64_t probeUpAcks_{0};
  bool canUpdateLongtermLossModel_{false};

  // Cwnd gain (local to ProbeBw)
  float cwndGain_{2.0};

  // Full bandwidth detection (for ProbeBw_Up → ProbeBw_Down transition)
  bool fullBwNow_{false};
  Bandwidth fullBw_;
  uint64_t fullBwCount_{0};
};

} // namespace quic
