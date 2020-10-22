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
#include <quic/d6d/Types.h>
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

  struct PMTUBlackholeEvent {
    explicit PMTUBlackholeEvent(
        TimePoint blackholeTimeIn,
        std::chrono::microseconds timeSinceLastNonSearchStateIn,
        D6DMachineState lastNonSearchStateIn,
        D6DMachineState currentStateIn,
        uint64_t udpSendPacketLenIn,
        uint64_t lastProbeSizeIn,
        uint64_t blackholeDetectionWindowIn,
        uint64_t blackholeDetectionThresholdIn,
        const quic::OutstandingPacket& pkt)
        : blackholeTime(blackholeTimeIn),
          timeSinceLastNonSearchState(timeSinceLastNonSearchStateIn),
          lastNonSearchState(lastNonSearchStateIn),
          currentState(currentStateIn),
          udpSendPacketLen(udpSendPacketLenIn),
          lastProbeSize(lastProbeSizeIn),
          blackholeDetectionWindow(blackholeDetectionWindowIn),
          blackholeDetectionThreshold(blackholeDetectionThresholdIn),
          triggeringPacketMetadata(pkt.metadata) {}
    TimePoint blackholeTime;
    // How long since last "stable" state
    std::chrono::microseconds timeSinceLastNonSearchState;
    D6DMachineState lastNonSearchState;
    D6DMachineState currentState;
    uint64_t udpSendPacketLen;
    uint64_t lastProbeSize;
    uint64_t blackholeDetectionWindow;
    uint64_t blackholeDetectionThreshold;
    // The metadata of the packet that triggerred blackhole signal
    const quic::OutstandingPacketMetadata triggeringPacketMetadata;
  };

  struct PMTUUpperBoundEvent {
    explicit PMTUUpperBoundEvent(
        TimePoint upperBoundTimeIn,
        std::chrono::microseconds timeSinceLastNonSearchStateIn,
        D6DMachineState lastNonSearchStateIn,
        uint64_t upperBoundPMTUIn,
        uint64_t cumulativeProbesSentIn,
        ProbeSizeRaiserType probeSizeRaiserTypeIn)
        : upperBoundTime(upperBoundTimeIn),
          timeSinceLastNonSearchState(timeSinceLastNonSearchStateIn),
          lastNonSearchState(lastNonSearchStateIn),
          upperBoundPMTU(upperBoundPMTUIn),
          cumulativeProbesSent(cumulativeProbesSentIn),
          probeSizeRaiserType(probeSizeRaiserTypeIn) {}
    TimePoint upperBoundTime;
    // How long it took to reach upperbound
    std::chrono::microseconds timeSinceLastNonSearchState;
    D6DMachineState lastNonSearchState;
    uint64_t upperBoundPMTU;
    uint64_t cumulativeProbesSent;
    ProbeSizeRaiserType probeSizeRaiserType;
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
   * @param socket   Socket when the callback is processed.
   * @param packet   const reference to the packet that was determined to be
   * lost.
   */
  virtual void packetLossDetected(
      QuicSocket*, /* socket */
      const struct ObserverLossEvent& /* lossEvent */) {}

  /**
   * rttSampleGenerated() is invoked when a RTT sample is made.
   *
   * @param socket   Socket when the callback is processed.
   * @param packet   const reference to the packet with the RTT.
   */
  virtual void rttSampleGenerated(
      QuicSocket*, /* socket */
      const PacketRTT& /* RTT sample */) {}

  /**
   * pmtuProbingStarted() is invoked when server starts d6d.
   *
   * @param socket   Socket when the callback is processed.
   */
  virtual void pmtuProbingStarted(QuicSocket* /* socket */) {}

  /**
   * pmtuBlackholeDetected() is invoked when a PMTU blackhole is detected.
   *
   * @param pmtuBlackholeEvent const reference to the PMTU blackhole event
   */
  virtual void pmtuBlackholeDetected(
      QuicSocket*, /* socket */
      const PMTUBlackholeEvent& /* pmtuBlackholeEvent */) {}

  /**
   * pmtuUpperBoundDetected() is invoked when a PMTU upperbound is detected.
   *
   * @param pmtuUpperBoundEvent const reference to the PMTU upperbound event
   */
  virtual void pmtuUpperBoundDetected(
      QuicSocket*, /* socket */
      const PMTUUpperBoundEvent& /* pmtuUpperBoundEvent */) {}
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
