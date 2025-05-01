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

  [[nodiscard]] uint64_t getWritableBytes() const noexcept override;

  [[nodiscard]] uint64_t getCongestionWindow() const noexcept override;

  [[nodiscard]] CongestionControlType type() const noexcept override;

  [[nodiscard]] bool isAppLimited() const override;

  [[nodiscard]] Optional<Bandwidth> getBandwidth() const override;

  [[nodiscard]] uint64_t getBDP() const override;

  void setAppLimited() noexcept override;

  void getStats(CongestionControllerStats& /*stats*/) const override;

  void setAppIdle(bool, TimePoint) noexcept override {}

  [[nodiscard]] State getState() const noexcept;

 private:
  void resetCongestionSignals();
  void resetShortTermModel();
  void updateLatestDeliverySignals();
  void updateCongestionSignals(const LossEvent* FOLLY_NULLABLE lossEvent);
  void updateAckAggregation();
  void advanceLatestDeliverySignals();
  void boundBwForModel();
  void adaptLongTermModel();

  void startRound();
  void updateRound();

  void setPacing();
  void setCwnd();
  void saveCwnd();
  void restoreCwnd();
  void setSendQuantum();

  void enterStartup();
  void checkStartupDone();
  void checkStartupHighLoss();

  void checkFullBwReached();
  void resetFullBw();

  void enterDrain();
  void checkDrain();

  void enterProbeRtt();
  void handleProbeRtt();
  void checkProbeRtt();
  void checkProbeRttDone();
  void exitProbeRtt();
  void updateMinRtt();
  uint64_t getProbeRTTCwnd();
  void boundCwndForProbeRTT();

  void enterProbeBW();
  void startProbeBwDown();
  void startProbeBwCruise();
  void updateProbeBwCyclePhase();
  void startProbeBwRefill();
  void startProbeBwUp();
  bool checkTimeToProbeBW();
  bool checkTimeToCruise();
  bool checkTimeToGoDown();
  bool hasElapsedInPhase(std::chrono::microseconds interval);
  bool checkInflightTooHigh();
  bool isInflightTooHigh();
  void handleInFlightTooHigh();
  void raiseInflightLongTermSlope();
  void probeInflightLongTermUpward();

  void updatePacingAndCwndGain();

  void updateRecoveryOnAck();
  void onPacketLoss(const LossEvent& lossEvent, uint64_t ackedBytes);

  [[nodiscard]] uint64_t getTargetInflightWithGain(float gain = 1.0) const;
  [[nodiscard]] uint64_t getTargetInflightWithHeadroom() const;
  [[nodiscard]] uint64_t getBDPWithGain(float gain = 1.0) const;
  [[nodiscard]] uint64_t addQuantizationBudget(uint64_t input) const;

  bool isProbeBwState(const Bbr2CongestionController::State state);
  bool isProbingBandwidth(const Bbr2CongestionController::State state);
  void updateBandwidthSampleFromAck(const AckEvent& ackEvent);
  bool isRenoCoexistenceProbeTime();

  [[nodiscard]] bool isInRecovery() const;

  enum class RecoveryState : uint8_t {
    NOT_RECOVERY = 0,
    CONSERVATIVE = 1,
    GROWTH = 2,
  };

  QuicConnectionStateBase& conn_;
  bool appLimited_{false};
  TimePoint appLimitedLastSendTime_;
  State state_{State::Startup};

  // Data Rate Model Parameters
  WindowedFilter<Bandwidth, MaxFilter<Bandwidth>, uint64_t, uint64_t>
      maxBwFilter_;
  Bandwidth bandwidth_;
  Optional<Bandwidth> bandwidthShortTerm_;
  uint64_t cycleCount_{0}; // TODO: this can be one bit

  // Data Volume Model Parameters
  std::chrono::microseconds minRtt_{kDefaultMinRtt};
  Optional<TimePoint> minRttTimestamp_;

  Optional<TimePoint> probeRttMinTimestamp_;
  std::chrono::microseconds probeRttMinValue_{kDefaultMinRtt};
  Optional<TimePoint> probeRttDoneTimestamp_;

  bool probeRttExpired_{false};

  uint64_t sendQuantum_{64 * 1024};
  Optional<uint64_t> inflightShortTerm_, inflightLongTerm_;
  Optional<TimePoint> extraAckedStartTimestamp_;
  uint64_t extraAckedDelivered_{0};
  WindowedFilter<uint64_t, MaxFilter<uint64_t>, uint64_t, uint64_t>
      maxExtraAckedFilter_;
  uint64_t latestExtraAcked_{0};

  // Responding to congestion
  Bandwidth bandwidthLatest_;
  uint64_t inflightLatest_{0};
  uint64_t lossBytesInRound_{0};
  uint64_t lossEventsInRound_{0};
  bool lossRoundStart_{false};
  uint64_t lossRoundEndBytesSent_{0};
  float lossPctInLastRound_{0.0f};
  uint64_t lossEventsInLastRound_{0};
  PacketNum largestLostPacketNumInRound_{0};

  // Cwnd
  uint64_t cwndBytes_;
  uint64_t previousCwndBytes_{0};
  bool cwndLimitedInRound_{false};

  bool idleRestart_{false};

  RecoveryState recoveryState_{RecoveryState::NOT_RECOVERY};
  uint64_t recoveryWindow_{0};
  TimePoint recoveryStartTime_;

  // Round counting
  uint64_t nextRoundDelivered_{0};
  bool roundStart_{false};
  uint64_t roundCount_{0};

  bool fullBwReached_{false};
  bool fullBwNow_{false};
  Bandwidth fullBw_;
  uint64_t fullBwCount_{0};

  float pacingGain_{1.0};
  float cwndGain_{1.0};

  uint64_t probeUpCount_{0};
  TimePoint probeBWCycleStart_;
  uint64_t roundsSinceBwProbe_;
  std::chrono::milliseconds bwProbeWait_;
  bool canUpdateLongtermLossModel_{false};
  uint64_t probeUpRounds_{0};
  uint64_t probeUpAcks_{0};

  // State used in processing the current ack
  const AckEvent* currentAckEvent_{nullptr};
  Bandwidth currentBwSample_;
  uint64_t currentAckMaxInflightBytes_{0};
  uint64_t inflightBytesAtLastAckedPacket_{0};
  bool lastAckedPacketAppLimited_{false};
};

std::string bbr2StateToString(Bbr2CongestionController::State state);
} // namespace quic
