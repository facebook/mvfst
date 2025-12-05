/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#pragma once

#include <quic/QuicException.h>
#include <quic/congestion_control/CongestionController.h>
#include <quic/state/AckEvent.h>
#include <quic/state/StateData.h>

#include <limits>

namespace quic {

class NewReno : public CongestionController {
 public:
  explicit NewReno(QuicConnectionStateBase& conn);
  void onRemoveBytesFromInflight(uint64_t) override;
  void onPacketSent(const OutstandingPacketWrapper& packet) override;
  void onPacketAckOrLoss(
      const AckEvent* FOLLY_NULLABLE,
      const LossEvent* FOLLY_NULLABLE) override;

  void onPacketAckOrLoss(Optional<AckEvent> ack, Optional<LossEvent> loss) {
    onPacketAckOrLoss(
        ack.has_value() ? &ack.value() : nullptr,
        loss.has_value() ? &loss.value() : nullptr);
  }

  [[nodiscard]] uint64_t getWritableBytes() const noexcept override;
  [[nodiscard]] uint64_t getCongestionWindow() const noexcept override;
  void setAppIdle(bool, TimePoint) noexcept override;
  void setAppLimited() override;

  [[nodiscard]] CongestionControlType type() const noexcept override;

  [[nodiscard]] bool inSlowStart() const noexcept;

  [[nodiscard]] uint64_t getBytesInFlight() const noexcept;

  [[nodiscard]] bool isAppLimited() const noexcept override;

  void getStats(CongestionControllerStats& /*stats*/) const override {}

 private:
  void onPacketLoss(const LossEvent&);
  void onAckEvent(const AckEvent&);
  void onPacketAcked(const CongestionController::AckEvent::AckPacket&);

 private:
  QuicConnectionStateBase& conn_;
  uint64_t ssthresh_;
  uint64_t cwndBytes_;
  Optional<TimePoint> endOfRecovery_;
};
} // namespace quic
