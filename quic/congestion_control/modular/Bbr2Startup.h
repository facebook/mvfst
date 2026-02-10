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
#include <quic/congestion_control/third_party/windowed_filter.h>
#include <quic/state/StateData.h>
#include <quic/state/TransportSettings.h>
#include <cstdint>
#include <memory>

namespace quic {

/**
 * Bbr2Startup is a modular congestion controller component that handles
 * the Startup and Drain phases of BBR2. It uses Bbr2Shared for common
 * state and operations.
 *
 * After Drain completes, the parent controller should transition to
 * Bbr2ProbeBw.
 */
class Bbr2Startup : public CongestionController {
 public:
  explicit Bbr2Startup(QuicConnectionStateBase& conn);

  void onRemoveBytesFromInflight(uint64_t) override {}

  void onPacketSent(const OutstandingPacketWrapper& packet) override {
    shared_->onPacketSent(packet);
  }

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

  void setAppIdle(bool, TimePoint) noexcept override {}

  void getStats(CongestionControllerStats& stats) const override {
    shared_->getStats(stats);
  }

 private:
  // Startup/Drain state management
  void enterStartup();
  void checkStartupDone();
  void checkStartupHighLoss();
  void checkFullBwReached();
  void resetFullBw();
  void enterDrain();
  [[nodiscard]] bool isDrainComplete() const noexcept;

  // Cwnd/pacing (startup-specific)
  [[nodiscard]] uint64_t calculateCwnd() const;
  void setPacing();
  void updatePacingGain();

  // Congestion signals (startup-specific)
  void resetShortTermModel();
  void updateCongestionSignals();

  QuicConnectionStateBase& conn_;
  std::shared_ptr<Bbr2Shared> shared_;

  // Full bandwidth detection
  bool fullBwReached_{false};
  bool fullBwNow_{false};
  Bandwidth fullBw_;
  uint64_t fullBwCount_{0};

  // Short term model - used for drain
  Optional<Bandwidth> bandwidthShortTerm_;
  Optional<uint64_t> inflightShortTerm_;
};

} // namespace quic
