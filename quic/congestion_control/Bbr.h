/*
 * Copyright (c) Facebook, Inc. and its affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 *
 */

// Copyright 2004-present Facebook.  All rights reserved.
#pragma once

#include <quic/congestion_control/Bandwidth.h>
#include <quic/congestion_control/third_party/windowed_filter.h>
#include <quic/state/StateData.h>
#include <quic/state/TransportSettings.h>

namespace quic {

// Cwnd and pacing gain during STARSTUP
constexpr float kStartupGain = 2.885f; // 2/ln(2)
// Cwnd gain during ProbeBw
constexpr float kProbeBwGain = 2.0f;
// The expected of bandwidth growth in each round trip time during STARTUP
constexpr float kExpectedStartupGrowth = 1.25f;
// How many rounds of rtt to stay in STARUP when the bandwidth isn't growing as
// fast as kExpectedStartupGrowth
constexpr uint8_t kStartupSlowGrowRoundLimit = 3;
// Number of pacing cycles
constexpr uint8_t kNumOfCycles = 8;
// Pacing cycles
constexpr std::array<float, kNumOfCycles> kPacingGainCycles =
    {1.25, 0.75, 1.0, 1.0, 1.0, 1.0, 1.0, 1.0};
// During ProbeRtt, we need to stay in low inflight condition for at least
// kProbeRttDuration.
constexpr std::chrono::milliseconds kProbeRttDuration{200};
// The cwnd gain to use when BbrConfig.largeProbeRttCwnd is set.
constexpr float kLargeProbeRttCwndGain = 0.75f;
// Bandwidth WindowFilter length, in unit of RTT. This value is from Chromium
// code. I don't know why.
constexpr uint64_t kBandwidthWindowLength = kNumOfCycles + 2;
// RTT Sampler default expiration
constexpr std::chrono::seconds kDefaultRttSamplerExpiration{10};
// 64K, used in sendQuantum calculation:
constexpr uint64_t k64K = 64 * 1024;

// TODO: rate based startup mode
// TODO: send extra bandwidth probers when pipe isn't sufficiently full
class BbrCongestionController : public CongestionController {
 public:
  /**
   * A class to collect RTT samples, tracks the minimal one among them, and
   * expire the min rtt sample after some period of time.
   */
  class MinRttSampler {
   public:
    virtual ~MinRttSampler() = default;
    virtual std::chrono::microseconds minRtt() const = 0;

    /**
     * Returns: true iff we have min rtt sample and it has expired.
     */
    virtual bool minRttExpired() const = 0;

    /**
     * rttSample: current rtt sample
     * sampledTime: the time point this sample is collected
     *
     * return: whether min rtt is updated by the new sample
     */
    virtual bool newRttSample(
        std::chrono::microseconds rttSample,
        TimePoint sampledTime) noexcept = 0;

    /**
     * Mark timestamp as the minrtt time stamp. Min rtt will expire at
     * timestampe + expiration_duration.
     */
    virtual void timestampMinRtt(TimePoint timestamp) noexcept = 0;
  };

  class BandwidthSampler {
   public:
    virtual ~BandwidthSampler() = default;

    virtual Bandwidth getBandwidth() const = 0;

    virtual void onPacketAcked(
        const CongestionController::AckEvent&,
        uint64_t roundTripCounter) = 0;

    virtual void onAppLimited() = 0;
    virtual bool isAppLimited() const = 0;
  };

  explicit BbrCongestionController(QuicConnectionStateBase& conn);

  // TODO: these should probably come in as part of a builder. but I'm not sure
  // if the sampler interface is here to stay atm, so bear with me
  void setRttSampler(std::unique_ptr<MinRttSampler> sampler) noexcept;
  void setBandwidthSampler(std::unique_ptr<BandwidthSampler> sampler) noexcept;

  enum class BbrState : uint8_t {
    Startup,
    Drain,
    ProbeBw,
    ProbeRtt,
  };

  enum class RecoveryState : uint8_t {
    NOT_RECOVERY = 0,
    CONSERVATIVE = 1,
    GROWTH = 2,
  };

  void onRemoveBytesFromInflight(uint64_t bytesToRemove) override;
  void onPacketSent(const OutstandingPacket&) override;
  void onPacketAckOrLoss(
      folly::Optional<AckEvent> ackEvent,
      folly::Optional<LossEvent> lossEvent) override;
  uint64_t getWritableBytes() const noexcept override;

  uint64_t getCongestionWindow() const noexcept override;
  CongestionControlType type() const noexcept override;
  void setAppIdle(bool idle, TimePoint eventTime) noexcept override;
  void setAppLimited() override;

  bool isAppLimited() const noexcept override;

  // TODO: some of these do not have to be in public API.
  bool inRecovery() const noexcept;
  BbrState state() const noexcept;

 private:
  /* prevInflightBytes: the inflightBytes value before the current
   *                    onPacketAckOrLoss invocation.
   * hasLoss: whether current onPacketAckOrLoss has loss.
   */
  void
  onPacketAcked(const AckEvent& ack, uint64_t prevInflightBytes, bool hasLoss);
  void onPacketLoss(const LossEvent&, uint64_t ackedBytes);
  void updatePacing() noexcept;

  /**
   * Update the ack aggregation states
   *
   * return: the excessive bytes from ack aggregation.
   *
   * Ack Aggregation: starts when ack arrival rate is slower than estimated
   * bandwidth, lasts until it's faster than estimated bandwidth.
   */
  uint64_t updateAckAggregation(const AckEvent& ack);
  /**
   * Check if we have found the bottleneck link bandwidth with the current ack.
   */
  void detectBottleneckBandwidth(bool);

  bool shouldExitStartup() noexcept;
  bool shouldExitDrain() noexcept;
  bool shouldProbeRtt(TimePoint ackTime) noexcept;
  void transitToDrain() noexcept;
  void transitToProbeBw(TimePoint congestionEventTime);
  void transitToProbeRtt() noexcept;
  void transitToStartup() noexcept;

  // Pick a random pacing cycle except 1
  size_t pickRandomCycle();

  // Special handling of AckEvent when connection is in ProbeRtt state
  void handleAckInProbeRtt(bool newRoundTrip, TimePoint ackTime) noexcept;
  /**
   * Special handling of AckEvent when connection is in ProbeBw state.
   *
   * prevInflightBytes: the inflightBytes value before the current
   *                    onPacketAckOrLoss invocation.
   * hasLoss: whether the current onpacketAckOrLoss has loss.
   */
  void handleAckInProbeBw(
      TimePoint ackTime,
      uint64_t prevInflightBytes,
      bool hasLoss) noexcept;

  /*
   * Return if we are at the start of a new round trip.
   */
  bool updateRoundTripCounter(TimePoint largestAckedSentTime) noexcept;
  void updateRecoveryWindowWithAck(uint64_t bytesAcked) noexcept;

  uint64_t calculateTargetCwnd(float gain) const noexcept;
  void updateCwnd(uint64_t ackedBytes, uint64_t excessiveBytes) noexcept;
  std::chrono::microseconds minRtt() const noexcept;
  Bandwidth bandwidth() const noexcept;

  QuicConnectionStateBase& conn_;
  BbrState state_{BbrState::Startup};
  RecoveryState recoveryState_{RecoveryState::NOT_RECOVERY};

  // Number of round trips the connection has witnessed
  uint64_t roundTripCounter_{0};
  // When a packet with send time later than endOfRoundTrip_ is acked, the
  // current round strip is ended.
  TimePoint endOfRoundTrip_;
  // When a packet with send time later than endOfRecovery_ is acked, the
  // connection is no longer in recovery
  folly::Optional<TimePoint> endOfRecovery_;
  // Cwnd in bytes
  uint64_t cwnd_;
  // Initial cwnd in bytes
  uint64_t initialCwnd_;
  // Congestion window when the connection is in recovery
  uint64_t recoveryWindow_;
  // Number of bytes we expect to send over one RTT when paced write.
  uint64_t pacingWindow_{0};

  float cwndGain_{kStartupGain};
  float pacingGain_{kStartupGain};

  // Whether we have found the bottleneck link bandwidth
  bool btlbwFound_{false};
  uint64_t sendQuantum_{0};

  std::unique_ptr<MinRttSampler> minRttSampler_;
  std::unique_ptr<BandwidthSampler> bandwidthSampler_;

  Bandwidth previousStartupBandwidth_;

  // Counter of continuous round trips in STARTUP that bandwidth isn't growing
  // fast enough
  uint8_t slowStartupRoundCounter_{0};

  // Current cycle index in kPacingGainCycles
  size_t pacingCycleIndex_{0};
  // The starting time of this pacing cycle. The cycle index will proceed by 1
  // when we are one minrtt away from this time point.
  TimePoint cycleStart_;

  // Once in ProbeRtt state, we cannot exit ProbeRtt before at least we spend
  // some duration with low inflight bytes. earliestTimeToExitProbeRtt_ is that
  // time point.
  folly::Optional<TimePoint> earliestTimeToExitProbeRtt_;
  // We also cannot exit ProbeRtt if are not at least at the low inflight bytes
  // mode for one RTT round. probeRttRound_ tracks that.
  folly::Optional<uint64_t> probeRttRound_;

  WindowedFilter<
      uint64_t /* ack bytes count */,
      MaxFilter<uint64_t>,
      uint64_t /* roundtrip count */,
      uint64_t /* roundtrip count */>
      maxAckHeightFilter_;
  folly::Optional<TimePoint> ackAggregationStartTime_;
  uint64_t aggregatedAckBytes_{0};

  bool appLimitedSinceProbeRtt_{false};
  // The connection was very inactive and we are leaving that.
  bool exitingQuiescene_{false};

  friend std::ostream& operator<<(
      std::ostream& os,
      const BbrCongestionController& bbr);
};

std::ostream& operator<<(std::ostream& os, const BbrCongestionController& bbr);

std::string bbrStateToString(BbrCongestionController::BbrState state);

std::string bbrRecoveryStateToString(
    BbrCongestionController::RecoveryState recoveryState);
} // namespace quic
