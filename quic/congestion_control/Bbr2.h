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
#include <sys/types.h>
#include <chrono>
#include <cstdint>
#include <optional>
#include <ratio>

namespace quic {
class Bbr2CongestionController : public CongestionController {
 public:
  enum class State : uint8_t {
    Startup = 0,
    Drain = 1,
    ProbeBw_Down = 2,
    ProbeBw_Cruise = 3,
    ProbeBw_Refill = 4,
    ProbeBw_Up = 5,
    ProbeRTT = 6
  };

  explicit Bbr2CongestionController(QuicConnectionStateBase& conn);
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

  FOLLY_NODISCARD folly::Optional<Bandwidth> getBandwidth() const override;

  void setAppLimited() noexcept override;

  void getStats(CongestionControllerStats& /*stats*/) const override;

  void setAppIdle(bool, TimePoint) noexcept override {}

  void setBandwidthUtilizationFactor(float) noexcept override {}

  [[nodiscard]] State getState() const noexcept;

 private:
  void resetCongestionSignals();
  void resetLowerBounds();
  void updateLatestDeliverySignals(const AckEvent& ackEvent);
  void updateCongestionSignals(const LossEvent* FOLLY_NULLABLE lossEvent);
  void updateAckAggregation(const AckEvent& ackEvent);
  void advanceLatestDeliverySignals(const AckEvent& ackEvent);
  void boundBwForModel();
  void adaptUpperBounds(
      uint64_t ackedBytes,
      uint64_t inflightBytesAtLargestAckedPacket,
      uint64_t lostBytes);

  void startRound();
  void updateRound(const AckEvent& ackEvent);

  void setPacing();
  void setCwnd(uint64_t ackedBytes, uint64_t lostBytes);
  void saveCwnd();
  void restoreCwnd();
  void setSendQuantum();

  void enterStartup();
  void checkStartupDone();
  void checkStartupFullBandwidth();
  void checkStartupHighLoss();

  void enterDrain();
  void checkDrain();

  void enterProbeRtt();
  void handleProbeRtt();
  void checkProbeRtt(uint64_t ackedBytes);
  void checkProbeRttDone();
  void exitProbeRtt();
  void updateMinRtt();
  uint64_t getProbeRTTCwnd();
  void boundCwndForProbeRTT();

  void enterProbeBW();
  void startProbeBwDown();
  void startProbeBwCruise();
  void updateProbeBwCyclePhase(
      uint64_t ackedBytes,
      uint64_t inflightBytesAtLargestAckedPacket,
      uint64_t lostBytes);
  void startProbeBwRefill();
  void startProbeBwUp();
  bool checkTimeToProbeBW();
  bool checkTimeToCruise();
  bool hasElapsedInPhase(std::chrono::microseconds interval);
  bool checkInflightTooHigh(
      uint64_t inflightBytesAtLargestAckedPacket,
      uint64_t lostBytes);
  bool isInflightTooHigh(
      uint64_t inflightBytesAtLargestAckedPacket,
      uint64_t lostBytes);
  void handleInFlightTooHigh(uint64_t inflightBytesAtLargestAckedPacket);
  void raiseInflightHiSlope();
  void probeInflightHiUpward(uint64_t ackedBytes);

  [[nodiscard]] uint64_t getTargetInflightWithGain(float gain = 1.0) const;
  [[nodiscard]] uint64_t getTargetInflightWithHeadroom() const;
  [[nodiscard]] uint64_t getBDPWithGain(float gain = 1.0) const;
  [[nodiscard]] uint64_t addQuantizationBudget(uint64_t input) const;

  bool isProbeBwState(const Bbr2CongestionController::State state);
  Bandwidth getBandwidthSampleFromAck(const AckEvent& ackEvent);
  bool isRenoCoexistenceProbeTime();

  QuicConnectionStateBase& conn_;
  bool appLimited_{false};
  TimePoint appLimitedLastSendTime_;
  State state_{State::Startup};

  // Data Rate Model Parameters
  WindowedFilter<Bandwidth, MaxFilter<Bandwidth>, uint64_t, uint64_t>
      maxBwFilter_;
  Bandwidth bandwidth_;
  folly::Optional<Bandwidth> bandwidthHi_, bandwidthLo_;
  uint64_t cycleCount_{0}; // TODO: this can be one bit

  // Data Volume Model Parameters
  std::chrono::microseconds minRtt_{kDefaultMinRtt};
  folly::Optional<TimePoint> minRttTimestamp_;

  folly::Optional<TimePoint> probeRttMinTimestamp_;
  std::chrono::microseconds probeRttMinValue_{kDefaultMinRtt};
  folly::Optional<TimePoint> probeRttDoneTimestamp_;

  bool probeRttExpired_{false};

  uint64_t sendQuantum_{64 * 1024};
  folly::Optional<uint64_t> inflightLo_, inflightHi_;
  folly::Optional<TimePoint> extraAckedStartTimestamp_;
  uint64_t extraAckedDelivered_{0};
  WindowedFilter<uint64_t, MaxFilter<uint64_t>, uint64_t, uint64_t>
      maxExtraAckedFilter_;

  // Responding to congestion
  Bandwidth bandwidthLatest_;
  uint64_t inflightLatest_{0};
  uint64_t lossBytesInRound_{0};
  uint64_t lossEventsInRound_{0};
  bool lossRoundStart_{false};
  uint64_t lossRoundEndBytesSent_{0};
  float lossPctInLastRound_{0.0f};
  uint64_t lossEventsInLastRound_{0};
  bool inLossRecovery_{false};

  // Cwnd
  uint64_t cwndBytes_;
  uint64_t previousCwndBytes_{0};
  bool cwndLimitedInRound_{false};

  bool idleRestart_{false};
  bool inPacketConservation_{false};
  TimePoint packetConservationStartTime_;

  // Round counting
  uint64_t nextRoundDelivered_{0};
  bool roundStart_{false};
  uint64_t roundCount_{0};

  bool filledPipe_{false};
  Bandwidth filledPipeBandwidth_;
  uint64_t filledPipeCount_{0};

  float pacingGain_{1.0};
  float cwndGain_{1.0};

  uint64_t probeUpCount_{0};
  TimePoint probeBWCycleStart_;
  uint64_t roundsSinceBwProbe_;
  std::chrono::milliseconds bwProbeWait_;
  bool bwProbeShouldHandleLoss_{false};
  uint64_t probeUpRounds_{0};
  uint64_t probeUpAcks_{0};
};

std::string bbr2StateToString(Bbr2CongestionController::State state);
} // namespace quic
