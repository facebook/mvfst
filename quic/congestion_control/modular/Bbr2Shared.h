/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#pragma once

#include <quic/congestion_control/Bandwidth.h>
#include <quic/congestion_control/CongestionController.h>
#include <quic/congestion_control/third_party/windowed_filter.h>
#include <quic/state/StateData.h>
#include <quic/state/TransportSettings.h>
#include <chrono>
#include <cstdint>

namespace quic {

/**
 * Unified BBR2 state enum shared across all modules.
 */
enum class Bbr2State : uint8_t {
  Startup = 0,
  Drain = 1,
  ProbeBw_Down = 2,
  ProbeBw_Cruise = 3,
  ProbeBw_Refill = 4,
  ProbeBw_Up = 5,
  ProbeRtt = 6,
};

std::string bbr2StateToString(Bbr2State state);

// Shared BBR2 constants
constexpr float kLossThreshold = 0.02; // 2% loss threshold
constexpr float kBeta =
    0.7; // Multiplicative decrease factor for short-term model
constexpr std::chrono::microseconds kBbr2ProbeRttDuration = 200ms;

/**
 * Bbr2Shared is a helper class that holds shared state and common operations
 * for all BBR2 modules (Startup, ProbeBw, ProbeRtt). It is NOT a
 * CongestionController itself - modules take a reference to this class and
 * delegate common operations to it.
 *
 * Common functionality includes:
 * - BBR2 state management
 * - Congestion window management
 * - Bandwidth sampling and tracking
 * - Pacing and send quantum
 * - Round counting
 * - MinRTT tracking and ProbeRTT timing
 * - App-limited and idle state tracking
 * - ACK aggregation
 * - Loss/congestion signal tracking
 * - Recovery state management
 */
class Bbr2Shared {
  // Friend classes can access private members directly
  friend class Bbr2Startup;
  friend class Bbr2ProbeBw;
  friend class Bbr2ProbeRtt;

 public:
  // Recovery state enum (shared across all modules)
  enum class RecoveryState : uint8_t {
    NOT_RECOVERY = 0,
    CONSERVATIVE = 1,
    GROWTH = 2,
  };

  explicit Bbr2Shared(QuicConnectionStateBase& conn);

  // ===== Congestion Window =====
  [[nodiscard]] CongestionControlType type() const noexcept {
    return CongestionControlType::BBR2Modular;
  }

  [[nodiscard]] uint64_t getWritableBytes() const noexcept;
  void applyCwnd(uint64_t cwndValue);
  void saveCwnd();
  void restoreCwnd();

  // ===== Bandwidth Model =====
  [[nodiscard]] Optional<Bandwidth> getBandwidth() const;
  [[nodiscard]] Bandwidth getMaxBw() const;
  [[nodiscard]] uint64_t getBDP() const;
  [[nodiscard]] uint64_t getBDPWithGain(float gain = 1.0) const;
  [[nodiscard]] uint64_t getTargetInflightWithGain(float gain = 1.0) const;
  [[nodiscard]] uint64_t addQuantizationBudget(uint64_t input) const;
  void updateBandwidthSampleFromAck(const AckEvent& ackEvent);
  void updateMaxBwFilter(Bandwidth sample);
  void updateMaxBwFilterFromLatest();
  void boundBwForModel(Optional<Bandwidth> upperBound = std::nullopt);
  void incrementCycleCount();

  // ===== Pacing & Send Quantum =====
  void setPacing(
      std::pair<uint8_t, uint8_t> rttFactor,
      Optional<uint64_t> minPacingWindow = std::nullopt);
  void setSendQuantum();

  // ===== Round Tracking =====
  void startRound();
  void updateRound();

  // ===== MinRTT & ProbeRTT Timing =====
  void updateMinRtt();
  [[nodiscard]] bool shouldEnterProbeRtt() const noexcept;
  void resetProbeRttExpired();

  // ===== App-Limited & Idle State =====
  void setAppLimited() noexcept;
  void updateAppLimitedState(const AckEvent& ackEvent);

  // ===== ACK Aggregation =====
  void updateAckAggregation();
  [[nodiscard]] uint64_t getMaxExtraAcked() const noexcept;

  // ===== Loss & Congestion Signals =====
  void resetCongestionSignals();
  void updateLatestDeliverySignals();
  void advanceLatestDeliverySignals();
  void updateLossSignals(
      const CongestionController::LossEvent* FOLLY_NULLABLE lossEvent);

  // ===== Short-Term Model Helper =====
  void updateShortTermModelOnLoss(
      Optional<Bandwidth>& bandwidthShortTerm,
      Optional<uint64_t>& inflightShortTerm);

  // ===== Recovery State =====
  void onPacketLoss(
      const CongestionController::LossEvent& lossEvent,
      uint64_t ackedBytes);
  void updateRecoveryOnAck();

  // ===== Last Acked Packet State =====
  void updateLastAckedPacketState();

  // ===== Phased ACK Processing =====
  // These functions group common ACK processing sequences used by all modules.
  // They should be called in order: sample -> update model -> finalize ->
  // apply.

  // Initializes ACK processing state, clears app-limited if acked past it,
  // samples bandwidth from acked packets, and records last acked packet
  // metadata.
  void sampleBandwidthFromAck(const AckEvent& ackEvent);

  // Updates core model state: delivery signals (bandwidth/inflight latest),
  // round tracking, recovery state, loss signals, max bandwidth filter,
  // and ACK aggregation.
  void updateModelFromDeliveryAndLoss(
      const CongestionController::LossEvent* FOLLY_NULLABLE lossEvent);

  // Updates MinRTT from latest RTT sample and advances delivery signals
  // to prepare for the next round.
  void finalizeMinRttAndDeliverySignals();

  // Completes ACK processing: applies cwnd and send quantum, resets per-round
  // cwnd-limited tracking, clears idle restart flag, and logs metrics/state.
  // This is the final step in ACK processing and must be called at the end
  // of the normal processing path (not on early returns for state transitions).
  void completeAckProcessing(
      uint64_t cwnd,
      const AckEvent& ackEvent,
      uint64_t inflightLongTerm,
      uint64_t inflightShortTerm,
      Optional<Bandwidth> bandwidthShortTerm);

  // ===== Packet Events =====
  void onPacketSent(const OutstandingPacketWrapper& packet);

  // ===== Stats =====
  void getStats(CongestionControllerStats& stats) const;

 private:
  QuicConnectionStateBase& conn_;

  // Note: fields are ordered for efficient packing

  // Congestion window
  uint64_t cwndBytes_;
  uint64_t previousCwndBytes_{0};
  uint64_t sendQuantum_{64 * 1024};

  // Round tracking
  uint64_t roundCount_{0};
  uint64_t nextRoundDelivered_{0};

  // MinRTT tracking
  std::chrono::microseconds minRtt_{kDefaultMinRtt};
  Optional<TimePoint> minRttTimestamp_;

  // Bandwidth model
  WindowedFilter<Bandwidth, MaxFilter<Bandwidth>, uint64_t, uint64_t>
      maxBwFilter_;
  Bandwidth bandwidth_;
  uint64_t cycleCount_{0};

  // ProbeRTT timing
  Optional<TimePoint> probeRttMinTimestamp_;
  std::chrono::microseconds probeRttMinValue_{kDefaultMinRtt};

  // App-limited & idle state
  TimePoint appLimitedLastSendTime_;

  // ACK aggregation
  Optional<TimePoint> extraAckedStartTimestamp_;
  uint64_t extraAckedDelivered_{0};
  WindowedFilter<uint64_t, MaxFilter<uint64_t>, uint64_t, uint64_t>
      maxExtraAckedFilter_;
  uint64_t latestExtraAcked_{0};

  // Loss & congestion signals
  Optional<uint64_t> inflightLongTerm_;
  Bandwidth bandwidthLatest_;
  uint64_t inflightLatest_{0};
  uint64_t lossBytesInRound_{0};
  uint64_t lossEventsInRound_{0};
  uint64_t lossRoundEndBytesSent_{0};
  uint64_t lossEventsInLastRound_{0};
  PacketNum largestLostPacketNumInRound_{0};

  // Recovery state
  uint64_t recoveryWindow_{0};
  TimePoint recoveryStartTime_;

  // Current ACK state
  const AckEvent* currentAckEvent_{nullptr};
  Bandwidth currentBwSample_;
  uint64_t currentAckMaxInflightBytes_{0};

  // Last acked packet state
  uint64_t inflightBytesAtLastAckedPacket_{0};

  float pacingGain_{1.0};
  float lossPctInLastRound_{0.0f};

  Bbr2State state_{Bbr2State::Startup};
  RecoveryState recoveryState_{RecoveryState::NOT_RECOVERY};
  bool roundStart_{false};
  bool probeRttExpired_{false};
  bool appLimited_{false};
  bool idleRestart_{false};
  bool lossRoundStart_{false};
  bool cwndLimitedInRound_{false};
  bool lastAckedPacketAppLimited_{false};
  bool returnedFromProbeRtt_{false};
};

} // namespace quic
