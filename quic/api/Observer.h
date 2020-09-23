/*
 * Copyright (c) Facebook, Inc. and its affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 *
 */
#pragma once

#include <quic/QuicException.h>
#include <quic/common/SmallVec.h>
#include <quic/state/OutstandingPacket.h>

namespace quic {
class QuicSocket;
/**
 * ===== Instrumentation Observer API =====
 */

/**
 * Observer of socket instrumentation events.
 */
class InstrumentationObserver {
 public:
  struct LostPacket {
    explicit LostPacket(
        bool lostbytimeout,
        bool lostbyreorder,
        const quic::OutstandingPacket& pkt)
        : lostByTimeout(lostbytimeout),
          lostByReorderThreshold(lostbyreorder),
          packet(pkt) {}
    bool lostByTimeout{false};
    bool lostByReorderThreshold{false};
    const quic::OutstandingPacket packet;
  };

  struct ObserverLossEvent {
    explicit ObserverLossEvent(TimePoint time = Clock::now())
        : lossTime(time) {}

    bool hasPackets() {
      return lostPackets.size() > 0;
    }

    void addLostPacket(
        bool lostByTimeout,
        bool lostByReorder,
        const quic::OutstandingPacket& packet) {
      lostPackets.emplace_back(lostByTimeout, lostByReorder, packet);
    }
    const TimePoint lossTime;
    std::vector<LostPacket> lostPackets;
  };

  struct PacketRTT {
    explicit PacketRTT(
        TimePoint rcvTimeIn,
        std::chrono::microseconds rttSampleIn,
        std::chrono::microseconds ackDelayIn,
        const quic::OutstandingPacket& pkt)
        : rcvTime(rcvTimeIn),
          rttSample(rttSampleIn),
          ackDelay(ackDelayIn),
          metadata(pkt.metadata),
          lastAckedPacketInfo(pkt.lastAckedPacketInfo) {}
    TimePoint rcvTime;
    std::chrono::microseconds rttSample;
    std::chrono::microseconds ackDelay;
    const quic::OutstandingPacketMetadata metadata;
    const folly::Optional<OutstandingPacket::LastAckedPacketInfo>
        lastAckedPacketInfo;
  };

  virtual ~InstrumentationObserver() = default;

  /**
   * observerDetach() will be invoked when the observer is uninstalled.
   *
   * No further callbacks will be invoked after observerDetach().
   *
   * @param socket      Socket where observer was uninstalled.
   */
  virtual void observerDetach(QuicSocket* /* socket */) noexcept = 0;

  /**
   * appRateLimited() is invoked when the socket is app rate limited.
   *
   * @param socket      Socket that has become application rate limited.
   */
  virtual void appRateLimited(QuicSocket* /* socket */) {}

  /**
   * packetLossDetected() is invoked when a packet loss is detected.
   *
   * @param packet   const reference to the packet that was determined to be
   * lost.
   */
  virtual void packetLossDetected(
      const struct ObserverLossEvent& /* lossEvent */) {}

  /**
   * rttSampleGenerated() is invoked when a RTT sample is made.
   *
   * @param packet   const reference to the packet with the RTT
   */
  virtual void rttSampleGenerated(const PacketRTT& /* RTT sample */) {}
};

// Container for instrumentation observers.
// Avoids heap allocation for up to 2 observers being installed.
using InstrumentationObserverVec = SmallVec<InstrumentationObserver*, 2>;

/**
 * ===== Lifecycle Observer API =====
 */

/**
 * Observer of socket lifecycle events.
 */
class LifecycleObserver {
 public:
  virtual ~LifecycleObserver() = default;

  /**
   * observerAttach() will be invoked when an observer is added.
   *
   * @param socket      Socket where observer was installed.
   */
  virtual void observerAttach(QuicSocket* /* socket */) noexcept = 0;

  /**
   * observerDetach() will be invoked if the observer is uninstalled prior
   * to socket destruction.
   *
   * No further callbacks will be invoked after observerDetach().
   *
   * @param socket      Socket where observer was uninstalled.
   */
  virtual void observerDetach(QuicSocket* /* socket */) noexcept = 0;

  /**
   * destroy() will be invoked when the QuicSocket's destructor is invoked.
   *
   * No further callbacks will be invoked after destroy().
   *
   * @param socket      Socket being destroyed.
   */
  virtual void destroy(QuicSocket* /* socket */) noexcept = 0;

  /**
   * close() will be invoked when the socket is being closed.
   *
   * If the callback handler does not unsubscribe itself upon being called,
   * then it may be called multiple times (e.g., by a call to close() by
   * the application, and then again when closeNow() is called on
   * destruction).
   *
   * @param socket      Socket being closed.
   * @param errorOpt    Error information, if connection closed due to error.
   */
  virtual void close(
      QuicSocket* /* socket */,
      const folly::Optional<
          std::pair<QuicErrorCode, std::string>>& /* errorOpt */) noexcept = 0;
};

} // namespace quic
