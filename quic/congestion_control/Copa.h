/*
 * Copyright (c) Facebook, Inc. and its affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 *
 */

#pragma once

#include <folly/Optional.h>
#include <quic/QuicException.h>
#include <quic/congestion_control/third_party/windowed_filter.h>
#include <quic/state/StateData.h>

#include <limits>

namespace quic {

using namespace std::chrono_literals;
constexpr std::chrono::microseconds kMinRTTWindowLength{10s};

/**
 * Algorithm description https://fb.quip.com/kgubABy1yuYR
 * Original paper
 * https://www.usenix.org/system/files/conference/nsdi18/nsdi18-arun.pdf
 */

class Copa : public CongestionController {
 public:
  explicit Copa(QuicConnectionStateBase& conn);
  void onRemoveBytesFromInflight(uint64_t) override;
  void onPacketSent(const OutstandingPacket& packet) override;
  void onPacketAckOrLoss(folly::Optional<AckEvent>, folly::Optional<LossEvent>)
      override;

  uint64_t getWritableBytes() const noexcept override;
  uint64_t getCongestionWindow() const noexcept override;
  CongestionControlType type() const noexcept override;

  bool inSlowStart();

  uint64_t getBytesInFlight() const noexcept;

  void setConnectionEmulation(uint8_t) noexcept override;
  void setAppIdle(bool, TimePoint) noexcept override;
  void setAppLimited() override;

  // pacing related functions, not implemented for copa
  bool canBePaced() const noexcept override;

  uint64_t getPacingRate(TimePoint currentTime) noexcept override;

  void markPacerTimeoutScheduled(TimePoint currentTime) noexcept override;

  std::chrono::microseconds getPacingInterval() const noexcept override;

  void setMinimalPacingInterval(std::chrono::microseconds) noexcept override;

  bool isAppLimited() const noexcept override;

 private:
  void onPacketAcked(const AckEvent&);
  void onPacketLoss(const LossEvent&);

  struct VelocityState {
    uint64_t velocity{1};
    enum Direction {
      None,
      Up, // cwnd is increasing
      Down, // cwnd is decreasing
    };
    Direction direction{None};
    // number of rtts direction has remained same
    uint64_t numTimesDirectionSame{0};
    // updated every srtt
    uint64_t lastRecordedCwndBytes;
    folly::Optional<TimePoint> lastCwndRecordTime{folly::none};
  };
  void checkAndUpdateDirection(const TimePoint ackTime);
  void changeDirection(
      VelocityState::Direction newDirection,
      const TimePoint ackTime);
  QuicConnectionStateBase& conn_;
  uint64_t bytesInFlight_{0};
  uint64_t cwndBytes_;

  bool isSlowStart_;
  // time at which cwnd was last doubled during slow start
  folly::Optional<TimePoint> lastCwndDoubleTime_{folly::none};

  WindowedFilter<
      std::chrono::microseconds,
      MinFilter<std::chrono::microseconds>,
      uint64_t,
      uint64_t>
      minRTTFilter_; // To get min RTT over 10 seconds

  WindowedFilter<
      std::chrono::microseconds,
      MinFilter<std::chrono::microseconds>,
      uint64_t,
      uint64_t>
      standingRTTFilter_; // To get min RTT over srtt/2

  VelocityState velocityState_;
  /**
   * latencyFactor_ determines how latency sensitive the algorithm is. Lower
   * means it will maximime throughput at expense of delay. Higher value means
   * it will minimize delay at expense of throughput.
   */
  double latencyFactor_{0.50};
};
} // namespace quic
