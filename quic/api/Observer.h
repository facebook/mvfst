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

namespace folly {
class EventBase;
}

namespace quic {
class QuicSocket;

/**
 * ===== Observer API =====
 */

/**
 * Observer of socket events.
 */
class Observer {
 public:
  /**
   * Observer configuration.
   *
   * Specifies events observer wants to receive.
   */
  struct Config {
    virtual ~Config() = default;

    // following flags enable support for various callbacks.
    // observer and socket lifecycle callbacks are always enabled.
    bool evbEvents{false};
    bool packetsWrittenEvents{false};
    bool appRateLimitedEvents{false};
    bool lossEvents{false};
    bool spuriousLossEvents{false};
    bool pmtuEvents{false};
    bool rttSamples{false};
    bool knobFrameEvents{false};
    bool packetsRemovedEvents{false};

    virtual void enableAllEvents() {
      evbEvents = true;
      packetsWrittenEvents = true;
      appRateLimitedEvents = true;
      rttSamples = true;
      lossEvents = true;
      spuriousLossEvents = true;
      pmtuEvents = true;
      knobFrameEvents = true;
      packetsRemovedEvents = true;
    }

    /**
     * Returns a config where all events are enabled.
     */
    static Config getConfigAllEventsEnabled() {
      Config config = {};
      config.enableAllEvents();
      return config;
    }
  };

  /**
   * Constructor for observer, uses default config (all callbacks disabled).
   */
  Observer() : Observer(Config()) {}

  /**
   * Constructor for observer.
   *
   * @param config      Config, defaults to auxilary instrumentaton disabled.
   */
  explicit Observer(const Config& observerConfig)
      : observerConfig_(observerConfig) {}

  virtual ~Observer() = default;

  /**
   * Returns observers configuration.
   */
  const Config& getConfig() {
    return observerConfig_;
  }

  struct AppLimitedEvent {
    AppLimitedEvent(
        const std::deque<OutstandingPacket>& outstandingPackets,
        const uint64_t writeCount)
        : outstandingPackets(outstandingPackets), writeCount(writeCount) {}

    // Cannot support copy ctors safely
    AppLimitedEvent(const AppLimitedEvent&) = delete;
    AppLimitedEvent(AppLimitedEvent&&) = delete;

    // Reference to the current list of outstanding packets
    const std::deque<OutstandingPacket>& outstandingPackets;
    // The current write number for the write() call that
    // caused this appLimitedEvent. Used by Observers to identify specific
    // packets from the outstandingPacket list (above).
    const uint64_t writeCount;
  };

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

  struct LossEvent {
    explicit LossEvent(TimePoint time = Clock::now()) : lossTime(time) {}

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

  struct SpuriousLossEvent {
    explicit SpuriousLossEvent(const TimePoint rcvTimeIn = Clock::now())
        : rcvTime(rcvTimeIn) {}

    bool hasPackets() {
      return spuriousPackets.size() > 0;
    }

    void addSpuriousPacket(const quic::OutstandingPacket& pkt) {
      spuriousPackets.emplace_back(pkt.lostByTimeout, pkt.lostByReorder, pkt);
    }
    const TimePoint rcvTime;
    std::vector<LostPacket> spuriousPackets;
  };

  struct KnobFrameEvent {
    explicit KnobFrameEvent(TimePoint rcvTimeIn, quic::KnobFrame knobFrame)
        : rcvTime(rcvTimeIn), knobFrame(std::move(knobFrame)) {}
    const TimePoint rcvTime;
    const quic::KnobFrame knobFrame;
  };

  /**
   * observerAttach() will be invoked when an observer is added.
   *
   * @param socket      Socket where observer was installed.
   */
  virtual void observerAttach(QuicSocket* /* socket */) noexcept {}

  /**
   * observerDetach() will be invoked if the observer is uninstalled prior
   * to socket destruction.
   *
   * No further callbacks will be invoked after observerDetach().
   *
   * @param socket      Socket where observer was uninstalled.
   */
  virtual void observerDetach(QuicSocket* /* socket */) noexcept {}

  /**
   * destroy() will be invoked when the QuicSocket's destructor is invoked.
   *
   * No further callbacks will be invoked after destroy().
   *
   * @param socket      Socket being destroyed.
   */
  virtual void destroy(QuicSocket* /* socket */) noexcept {}

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
          std::pair<QuicErrorCode, std::string>>& /* errorOpt */) noexcept {}

  /**
   * evbAttach() will be invoked when a new event base is attached to this
   * socket. This will be called from the new event base's thread.
   *
   * @param socket    Socket on which the new event base was attached.
   * @param evb       The new event base that is getting attached.
   */
  virtual void evbAttach(
      QuicSocket* /* socket */,
      folly::EventBase* /* evb */) noexcept {}

  /**
   * evbDetach() will be invoked when an existing event base is detached
   * from the socket. This will be called from the existing event base's thread.
   *
   * @param socket    Socket on which the existing EVB is getting detached.
   * @param evb       The existing event base that is getting detached.
   */
  virtual void evbDetach(
      QuicSocket* /* socket */,
      folly::EventBase* /* evb */) noexcept {}

  /**
   * startWritingFromAppLimited() is invoked when the socket is currenty
   * app rate limited and is being asked to write a new set of Bytes.
   . This callback is invoked BEFORE we write the
   * new bytes to the socket, this is done so that Observers can collect
   * metadata about the connection BEFORE the start of a potential Write Block.
   *
   * @param socket   Socket that has potentially sent application data.
                             reference to the number of outstanding packets
                             BEFORE the call to write() socket data.

   */
  virtual void startWritingFromAppLimited(
      QuicSocket* /* socket */,
      const AppLimitedEvent& /* appLimitedEvent */) {}

  /**
   * packetsWritten() is invoked when the socket writes retransmittable packets
   * to the wire, those packets will be present in the outstanding packets list.
   * Observers can use this callback (which will always be invoked AFTER
   * startWritingFromAppLimited) to *update* the transport's metadata within the
   * currently tracked WriteBlock.
   *
   * If an Observer receives startWritingFromAppLimited but doesn't receive
   * packetsWritten (and instead directly receives appRateLimited), it means the
   * socket witnessed non-app data writes - this scenario is irrelevant and
   * should not be used to construct Write Blocks.
   *
   * @param socket   Socket that has sent application data.
   * @param appLimitedEvent  The AppLimitedEvent details which contains a const
                             reference to the number of outstanding packets
   */
  virtual void packetsWritten(
      QuicSocket* /* socket */,
      const AppLimitedEvent& /* appLimitedEvent */) {}

  /**
   * appRateLimited() is invoked when the socket is app rate limited.
   *
   * @param socket      Socket that has become application rate limited.
   * @param appLimitedEvent  The AppLimitedEvent details which contains a const
                             reference to the number of outstanding packets
   */
  virtual void appRateLimited(
      QuicSocket* /* socket */,
      const AppLimitedEvent& /* appLimitedEvent */) {}

  /**
   * packetLossDetected() is invoked when a packet loss is detected.
   *
   * @param socket   Socket when the callback is processed.
   * @param packet   const reference to the packet that was determined to be
   * lost.
   */
  virtual void packetLossDetected(
      QuicSocket*, /* socket */
      const struct LossEvent& /* lossEvent */) {}

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

  /**
   * spuriousLossDetected() is invoked when an ACK arrives for a packet that is
   * declared lost
   *
   * @param socket   Socket when the callback is processed.
   * @param packet   const reference to the lost packet.
   */
  virtual void spuriousLossDetected(
      QuicSocket*, /* socket */
      const SpuriousLossEvent& /* lost packet */) {}

  /**
   * knobFrameReceived() is invoked when a knob frame is received.
   *
   * @param socket   Socket when the callback is processed.
   * @param event    const reference to the KnobFrameEvent.
   */
  virtual void knobFrameReceived(
      QuicSocket*, /* socket */
      const KnobFrameEvent& /* event */) {}

  /**
   * packetsRemoved() is invoked when packets are removed from the
   * OutstandingPacket queue. Using shared pointer avoids copying the vector for
   * every observer called.
   *
   * @param socket         Socket when the callback is processed.
   * @param removedPackets Vector with the removed packets.
   */
  virtual void packetsRemoved(
      QuicSocket*, /* socket */
      const std::shared_ptr<
          std::vector<OutstandingPacket>> /* removedPackets */) {}

 protected:
  // observer configuration; cannot be changed post instantiation
  const Config observerConfig_;
};

// Container for instrumentation observers.
// Avoids heap allocation for up to 2 observers being installed.
using ObserverVec = SmallVec<Observer*, 2>;

} // namespace quic
