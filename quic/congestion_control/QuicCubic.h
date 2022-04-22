/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#pragma once

#include <quic/QuicException.h>
#include <quic/congestion_control/CongestionControlFunctions.h>
#include <quic/congestion_control/CongestionController.h>
#include <quic/state/AckEvent.h>
#include <quic/state/StateData.h>

namespace quic {

constexpr float kCubicHystartPacingGain = 2.0f;
constexpr float kCubicRecoveryPacingGain = 1.25f;

enum class CubicStates : uint8_t {
  Hystart,
  Steady,
  FastRecovery,
};

/**
 *
 *  |--------|                              |-----|
 *  |      [Ack]                          [Ack]   |
 *  |        |                              |     |
 *  -->Hystart------------[Ack]---------->Cubic<--|
 *        |                                 |     |
 *        |                                 |     |
 *        |                ->[ACK/Loss]     |     |
 *        |                |     |          |     |
 *        |                |     |          |     |
 *        -[Loss]---->Fast Recovery<--[Loss]-     |
 *                             |                  |
 *                             |                  |
 *                             |                  |
 *                             |->-----[Ack]------|
 *
 */

class Cubic : public CongestionController {
 public:
  static constexpr uint64_t INIT_SSTHRESH =
      std::numeric_limits<uint64_t>::max();
  /**
   * initSsthresh:      the initial value of ssthresh
   * ssreduction:       how should cwnd be reduced when loss happens during slow
   *                    start
   * tcpFriendly:       if cubic cwnd calculation should be friendly to Reno TCP
   * spreadacrossRtt:   if the pacing bursts should be spread across RTT or all
   *                    close to the beginning of an RTT round
   */
  explicit Cubic(
      QuicConnectionStateBase& conn,
      uint64_t initCwndBytes = 0,
      uint64_t initSsthresh = INIT_SSTHRESH,
      bool tcpFriendly = true,
      bool ackTrain = false);

  CubicStates state() const noexcept;

  enum class ExitReason : uint8_t {
    SSTHRESH,
    EXITPOINT,
  };

  // if hybrid slow start exit point is found
  enum class HystartFound : uint8_t {
    No,
    FoundByAckTrainMethod,
    FoundByDelayIncreaseMethod
  };

  void onPacketAckOrLoss(
      const AckEvent* FOLLY_NULLABLE,
      const LossEvent* FOLLY_NULLABLE) override;
  void onPacketAckOrLoss(
      folly::Optional<AckEvent> ack,
      folly::Optional<LossEvent> loss) {
    onPacketAckOrLoss(ack.get_pointer(), loss.get_pointer());
  }
  void onRemoveBytesFromInflight(uint64_t) override;
  void onPacketSent(const OutstandingPacket& packet) override;

  uint64_t getWritableBytes() const noexcept override;
  uint64_t getCongestionWindow() const noexcept override;
  void setAppIdle(bool idle, TimePoint eventTime) noexcept override;
  void setAppLimited() override;

  void setBandwidthUtilizationFactor(
      float /*bandwidthUtilizationFactor*/) noexcept override {}

  bool isInBackgroundMode() const noexcept override {
    return false;
  }

  bool isAppLimited() const noexcept override;

  void getStats(CongestionControllerStats& stats) const override;

  void handoff(uint64_t newCwnd, uint64_t newInflight) noexcept;

  CongestionControlType type() const noexcept override;

 protected:
  CubicStates state_{CubicStates::Hystart};

 private:
  bool isAppIdle() const noexcept;
  void onPacketAcked(const AckEvent& ack);
  void onPacketAckedInHystart(const AckEvent& ack);
  void onPacketAckedInSteady(const AckEvent& ack);
  void onPacketAckedInRecovery(const AckEvent& ack);

  void onPacketLoss(const LossEvent& loss);
  void onPacketLossInRecovery(const LossEvent& loss);
  void onPersistentCongestion();

  float pacingGain() const noexcept;

  void startHystartRttRound(TimePoint time) noexcept;

  void cubicReduction(TimePoint lossTime) noexcept;
  void updateTimeToOrigin() noexcept;
  int64_t calculateCubicCwndDelta(TimePoint timePoint) noexcept;
  uint64_t calculateCubicCwnd(int64_t delta) noexcept;

  bool isRecovered(TimePoint packetSentTime) noexcept;

  QuicConnectionStateBase& conn_;
  uint64_t cwndBytes_;
  // the value of cwndBytes_ at last loss event
  folly::Optional<uint64_t> lossCwndBytes_;
  // the value of ssthresh_ at the last loss event
  folly::Optional<uint64_t> lossSsthresh_;
  uint64_t ssthresh_;

  struct HystartState {
    // If AckTrain method will be used to exit SlowStart
    bool ackTrain{false};
    // If we are currently in a RTT round
    bool inRttRound{false};
    // If we have found the exit point
    HystartFound found{HystartFound::No};
    // The starting timestamp of a RTT round
    TimePoint roundStart;
    // Last timestamp when closed space Ack happens
    TimePoint lastJiffy;
    // The minimal of sampled RTT in current RTT round. Hystart only samples
    // first a few RTTs in a round
    folly::Optional<std::chrono::microseconds> currSampledRtt;
    // End value of currSampledRtt at the end of a RTT round:
    folly::Optional<std::chrono::microseconds> lastSampledRtt;
    // Estimated minimal delay of a path
    folly::Optional<std::chrono::microseconds> delayMin;
    // Ack sampling count
    uint8_t ackCount{0};
    // When a packet with sent time >= rttRoundEndTarget is acked, end the
    // current RTT round
    TimePoint rttRoundEndTarget;
  };

  struct SteadyState {
    // time takes for cwnd to increase to lastMaxCwndBytes
    double timeToOrigin{0.0};
    // The cwnd value that timeToOrigin is calculated based on
    folly::Optional<uint64_t> originPoint;
    bool tcpFriendly{true};
    folly::Optional<TimePoint> lastReductionTime;
    // This is Wmax, it could be different from lossCwndBytes if cwnd never
    // reaches last lastMaxCwndBytes before loss event:
    folly::Optional<uint64_t> lastMaxCwndBytes;
    uint64_t estRenoCwnd;
    // cache reduction/increase factors based on numEmulatedConnections_
    float reductionFactor{kDefaultCubicReductionFactor};
    float lastMaxReductionFactor{kDefaultLastMaxReductionFactor};
    float tcpEstimationIncreaseFactor{kCubicTCPFriendlyEstimateIncreaseFactor};
  };

  struct RecoveryState {
    // The time point after which Quic will no longer be in current recovery
    folly::Optional<TimePoint> endOfRecovery;
  };

  // if quiescenceStart_ has a value, then the connection is app limited
  folly::Optional<TimePoint> quiescenceStart_;

  HystartState hystartState_;
  SteadyState steadyState_;
  RecoveryState recoveryState_;
};

folly::StringPiece cubicStateToString(CubicStates state);

} // namespace quic
