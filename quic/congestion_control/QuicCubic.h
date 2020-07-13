/*
 * Copyright (c) Facebook, Inc. and its affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 *
 */

#pragma once

#include <quic/QuicException.h>
#include <quic/congestion_control/CongestionControlFunctions.h>
#include <quic/logging/QuicLogger.h>
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
  /**
   * initSsthresh:      the initial value of ssthresh
   * ssreduction:       how should cwnd be reduced when loss happens during slow
   *                    start
   * tcpFriendly:       if cubic cwnd calculation should be friendly to Reno TCP
   * spreadacrossRtt:   if the pacing bursts should be spread across RTT or all
   *                    close to the beginning of an RTT round
   */
  // TODO: We haven't experimented with setting ackTrain and tcpFriendly
  explicit Cubic(
      QuicConnectionStateBase& conn,
      uint64_t initSsthresh = std::numeric_limits<uint64_t>::max(),
      bool tcpFriendly = true,
      bool ackTrain = false,
      bool spreadAcrossRtt = false);

  class CubicBuilder {
   public:
    std::unique_ptr<Cubic> build(QuicConnectionStateBase& conn);
    CubicBuilder& setAckTrain(bool ackTrain) noexcept;
    CubicBuilder& setTcpFriendly(bool tcpFriendly) noexcept;
    CubicBuilder& setPacingSpreadAcrossRtt(bool spreadAcrossRtt) noexcept;

   private:
    bool tcpFriendly_{true};
    bool ackTrain_{false};
    bool spreadAcrossRtt_{false};
  };

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

  void onPacketAckOrLoss(folly::Optional<AckEvent>, folly::Optional<LossEvent>)
      override;
  void onRemoveBytesFromInflight(uint64_t) override;
  void onPacketSent(const OutstandingPacket& packet) override;

  uint64_t getWritableBytes() const noexcept override;
  uint64_t getCongestionWindow() const noexcept override;
  void setAppIdle(bool idle, TimePoint eventTime) noexcept override;
  void setAppLimited() override;

  bool isAppLimited() const noexcept override;

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

  // When spreadAcrossRtt_ is set to true, the pacing writes will be distributed
  // evenly across an RTT. Otherwise, we will use the first N number of pacing
  // intervals to send all N bursts.
  bool spreadAcrossRtt_{false};
};

folly::StringPiece cubicStateToString(CubicStates state);

} // namespace quic
