/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#pragma once

#include <quic/QuicConstants.h>
#include <quic/state/OutstandingPacket.h>
#include <quic/state/PacketEvent.h>

namespace quic {

struct AckEvent;

struct BbrStats {
  uint8_t state;
};

struct CopaStats {
  double deltaParam;
  bool useRttStanding;
};

struct CubicStats {
  uint8_t state;
  uint64_t ssthresh;
};

union CongestionControllerStats {
  struct BbrStats bbrStats;
  struct CopaStats copaStats;
  struct CubicStats cubicStats;
};

struct CongestionController {
 public:
  using AckEvent = quic::AckEvent;

  struct State {
    uint64_t writableBytes{0};
    uint64_t congestionWindowBytes{0};
  };

  // Helper struct to group multiple lost packets into one event
  struct LossEvent {
    folly::Optional<PacketNum> largestLostPacketNum;
    std::vector<PacketNum> lostPacketNumbers;
    uint64_t lostBytes{0};
    uint32_t lostPackets{0};
    const TimePoint lossTime;
    // The packet sent time of the lost packet with largest packet sent time in
    // this LossEvent
    folly::Optional<TimePoint> largestLostSentTime;
    // The packet sent time of the lost packet with smallest packet sent time in
    // the LossEvent
    folly::Optional<TimePoint> smallestLostSentTime;
    // Whether this LossEvent also indicates persistent congestion
    bool persistentCongestion{false};

    explicit LossEvent(TimePoint time = Clock::now()) : lossTime(time) {}

    void addLostPacket(const OutstandingPacket& packet) {
      if (std::numeric_limits<uint64_t>::max() - lostBytes <
          packet.metadata.encodedSize) {
        throw QuicInternalException(
            "LossEvent: lostBytes overflow",
            LocalErrorCode::LOST_BYTES_OVERFLOW);
      }
      PacketNum packetNum = packet.packet.header.getPacketSequenceNum();
      largestLostPacketNum =
          std::max(packetNum, largestLostPacketNum.value_or(packetNum));
      lostPacketNumbers.push_back(packetNum);
      lostBytes += packet.metadata.encodedSize;
      lostPackets++;
      largestLostSentTime = std::max(
          packet.metadata.time,
          largestLostSentTime.value_or(packet.metadata.time));
      smallestLostSentTime = std::min(
          packet.metadata.time,
          smallestLostSentTime.value_or(packet.metadata.time));
    }
  };

  virtual ~CongestionController() = default;

  /**
   * Take bytes out of flight without mutating other states of the controller
   */
  virtual void onRemoveBytesFromInflight(uint64_t) = 0;
  virtual void onPacketSent(const OutstandingPacket& packet) = 0;
  virtual void onPacketAckOrLoss(
      const AckEvent* FOLLY_NULLABLE ackEvent,
      const LossEvent* FOLLY_NULLABLE lossEvent) = 0;

  /**
   * Return the number of bytes that the congestion controller
   * will allow you to write.
   */
  FOLLY_NODISCARD virtual uint64_t getWritableBytes() const = 0;

  /**
   * Return the number of bytes of cwnd of the congestion
   * controller.
   */
  FOLLY_NODISCARD virtual uint64_t getCongestionWindow() const = 0;

  /**
   * Notify congestion controller that the connection has become idle or active
   * in the sense that there are active non-control streams.
   * idle: true if the connection has become app-idle, false if the
   *          connection has become not app-idle.
   * eventTime: the time point when the app-idle state changed.
   */
  virtual void setAppIdle(bool idle, TimePoint eventTime) = 0;

  /**
   * Notify congestion controller that the connection has become app-limited or
   * not app-limited.
   */
  virtual void setAppLimited() = 0;

  FOLLY_NODISCARD virtual CongestionControlType type() const = 0;

  /**
   * Set the congestion controller to use only a fraction of the available
   * bandwidth (best-effort for implementations that support it)
   * bandwidthUtilizationFactor:
   *   < 1.0 indicates backgrounded flow
   *   = 1.0 indicates normal operation.
   *   > 1.0 maps to =1.0
   */
  virtual void setBandwidthUtilizationFactor(
      float bandwidthUtilizationFactor) noexcept = 0;

  /**
   * Whether the congestion controller is making use of all of the available
   * bandwidth. Returns true if bandwidthUtilizationFactor < 1.0.
   */
  FOLLY_NODISCARD virtual bool isInBackgroundMode() const = 0;

  /**
   * Whether the congestion controller thinks it's currently in app-limited
   * state.
   */
  FOLLY_NODISCARD virtual bool isAppLimited() const = 0;

  virtual void getStats(CongestionControllerStats& stats) const = 0;

  /**
   * Get current state of congestion controller.
   */
  FOLLY_NODISCARD State getState() const {
    State state;
    state.congestionWindowBytes = getCongestionWindow();
    state.writableBytes = getWritableBytes();
    return state;
  }

  /**
   * Enable experimental settings of the congestion controller
   */
  virtual void setExperimental(bool /*experimental*/) {}
};

} // namespace quic
