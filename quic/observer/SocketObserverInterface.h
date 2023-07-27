/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#pragma once

#include <quic/QuicException.h>
#include <quic/common/SmallCollections.h>
#include <quic/state/AckEvent.h>
#include <quic/state/OutstandingPacket.h>
#include <quic/state/QuicStreamUtilities.h>

#include <utility>

namespace folly {
class EventBase;
}

namespace quic {
class QuicSocket;
class QuicTransportBase;

/**
 * Observer of socket events.
 */
class SocketObserverInterface {
 public:
  enum class Events {
    evbEvents = 1,
    packetsWrittenEvents = 2,
    appRateLimitedEvents = 3,
    rttSamples = 4,
    lossEvents = 5,
    spuriousLossEvents = 6,
    knobFrameEvents = 8,
    streamEvents = 9,
    acksProcessedEvents = 10,
    packetsReceivedEvents = 11,
  };
  virtual ~SocketObserverInterface() = default;

  /**
   * Event structures.
   */

  struct CloseStartedEvent {
    // Error code provided when close() or closeNow() called.
    //
    // The presence of an error code does NOT indicate that a "problem" caused
    // the socket to close, since an error code can be an application timeout.
    folly::Optional<QuicError> maybeCloseReason;

    // Default equality comparator available in C++20.
    //
    // mvfst currently supports C++17 onwards. However, we can enable this for
    // unit tests and other code that we expect to run in C++20.
#if FOLLY_CPLUSPLUS >= 202002L
    friend auto operator<=>(
        const CloseStartedEvent&,
        const CloseStartedEvent&) = default;
#elif _WIN32
    friend auto operator!=(
        const CloseStartedEvent& right,
        const CloseStartedEvent& left) {
      return right.maybeCloseReason != left.maybeCloseReason;
    }
    friend auto operator==(
        const CloseStartedEvent& right,
        const CloseStartedEvent& left) {
      return right.maybeCloseReason == left.maybeCloseReason;
    }
#endif
  };

  struct ClosingEvent {
    // Default equality comparator available in C++20.
    //
    // mvfst currently supports C++17 onwards. However, we can enable this for
    // unit tests and other code that we expect to run in C++20.
#if FOLLY_CPLUSPLUS >= 202002L
    friend auto operator<=>(const ClosingEvent&, const ClosingEvent&) = default;
#endif
  };

  struct WriteEvent {
    [[nodiscard]] const std::deque<OutstandingPacketWrapper>&
    getOutstandingPackets() const {
      return outstandingPackets;
    }

    // Reference to the current list of outstanding packets.
    const std::deque<OutstandingPacketWrapper>& outstandingPackets;

    // Monotonically increasing number assigned to each write operation.
    const uint64_t writeCount;

    // Timestamp when packet was last written.
    const folly::Optional<TimePoint> maybeLastPacketSentTime;

    // CWND in bytes.
    //
    // Optional to handle cases where congestion controller not used.
    const folly::Optional<uint64_t> maybeCwndInBytes;

    // Writable bytes.
    //
    // Optional to handle cases where congestion controller not used.
    const folly::Optional<uint64_t> maybeWritableBytes;

    struct BuilderFields {
      folly::Optional<
          std::reference_wrapper<const std::deque<OutstandingPacketWrapper>>>
          maybeOutstandingPacketsRef;
      folly::Optional<uint64_t> maybeWriteCount;
      folly::Optional<TimePoint> maybeLastPacketSentTime;
      folly::Optional<uint64_t> maybeCwndInBytes;
      folly::Optional<uint64_t> maybeWritableBytes;
      explicit BuilderFields() = default;
    };

    struct Builder : public BuilderFields {
      Builder&& setOutstandingPackets(
          const std::deque<OutstandingPacketWrapper>& outstandingPacketsIn);
      Builder&& setWriteCount(const uint64_t writeCountIn);
      Builder&& setLastPacketSentTime(const TimePoint& lastPacketSentTimeIn);
      Builder&& setLastPacketSentTime(
          const folly::Optional<TimePoint>& maybeLastPacketSentTimeIn);
      Builder&& setCwndInBytes(
          const folly::Optional<uint64_t>& maybeCwndInBytesIn);
      Builder&& setWritableBytes(
          const folly::Optional<uint64_t>& maybeWritableBytesIn);
      WriteEvent build() &&;
      explicit Builder() = default;
    };

    // Do not support copy or move given that outstanding packets is a ref.
    WriteEvent(WriteEvent&&) = delete;
    WriteEvent& operator=(const WriteEvent&) = delete;
    WriteEvent& operator=(WriteEvent&& rhs) = delete;

    // Use builder to construct.
    explicit WriteEvent(const BuilderFields& builderFields);

   protected:
    // Allow QuicTransportBase to use the copy constructor for enqueuing
    friend class QuicTransportBase;
    WriteEvent(const WriteEvent&) = default;
  };

  struct AppLimitedEvent : public WriteEvent {
    struct Builder : public WriteEvent::BuilderFields {
      Builder&& setOutstandingPackets(
          const std::deque<OutstandingPacketWrapper>& outstandingPacketsIn);
      Builder&& setWriteCount(const uint64_t writeCountIn);
      Builder&& setLastPacketSentTime(const TimePoint& lastPacketSentTimeIn);
      Builder&& setLastPacketSentTime(
          const folly::Optional<TimePoint>& maybeLastPacketSentTimeIn);
      Builder&& setCwndInBytes(
          const folly::Optional<uint64_t>& maybeCwndInBytesIn);
      Builder&& setWritableBytes(
          const folly::Optional<uint64_t>& maybeWritableBytesIn);
      AppLimitedEvent build() &&;
      explicit Builder() = default;
    };

    // Use builder to construct.
    explicit AppLimitedEvent(BuilderFields&& builderFields);
  };

  struct PacketsWrittenEvent : public WriteEvent {
    /**
     * For each new OutstandingPacketWrapper (ACK eliciting packet), invoke
     * function.
     */
    void invokeForEachNewOutstandingPacketOrdered(
        const std::function<void(const OutstandingPacketWrapper&)>& fn) const;

    // Number of packets just written, including ACK eliciting packets.
    const uint64_t numPacketsWritten;

    // Number of ACK eliciting packets written.
    // These packets will appear in outstandingPackets.
    const uint64_t numAckElicitingPacketsWritten;

    // Number of bytes written.
    const uint64_t numBytesWritten;

    struct BuilderFields : public WriteEvent::BuilderFields {
      folly::Optional<uint64_t> maybeNumPacketsWritten;
      folly::Optional<uint64_t> maybeNumAckElicitingPacketsWritten;
      folly::Optional<uint64_t> maybeNumBytesWritten;
      explicit BuilderFields() = default;
    };

    struct Builder : public BuilderFields {
      Builder&& setOutstandingPackets(
          const std::deque<OutstandingPacketWrapper>& outstandingPacketsIn);
      Builder&& setWriteCount(const uint64_t writeCountIn);
      Builder&& setLastPacketSentTime(const TimePoint& lastPacketSentTimeIn);
      Builder&& setLastPacketSentTime(
          const folly::Optional<TimePoint>& maybeLastPacketSentTimeIn);
      Builder&& setNumPacketsWritten(const uint64_t numPacketsWrittenIn);
      Builder&& setNumAckElicitingPacketsWritten(
          const uint64_t numAckElicitingPacketsWrittenIn);
      Builder&& setNumBytesWritten(const uint64_t numBytesWrittenIn);
      Builder&& setCwndInBytes(
          const folly::Optional<uint64_t>& maybeCwndInBytesIn);
      Builder&& setWritableBytes(
          const folly::Optional<uint64_t>& maybeWritableBytesIn);
      PacketsWrittenEvent build() &&;
      explicit Builder() = default;
    };

    // Use builder to construct.
    explicit PacketsWrittenEvent(BuilderFields&& builderFields);
  };

  struct PacketsReceivedEvent {
    /**
     * Packet received.
     */
    struct ReceivedPacket {
      // Packet receive timestamp.
      //
      // If socket receive (RX) timestamps are used this will be the timestamp
      // provided by the kernel mapped to the steady_clock timespace and made
      // later than or equal to previous timestamps.
      const TimePoint packetReceiveTime;

      // Number of bytes in the received packet.
      const uint64_t packetNumBytes;

      struct BuilderFields {
        folly::Optional<TimePoint> maybePacketReceiveTime;
        folly::Optional<uint64_t> maybePacketNumBytes;
        explicit BuilderFields() = default;
      };

      struct Builder : public BuilderFields {
        Builder&& setPacketReceiveTime(const TimePoint packetReceiveTimeIn);
        Builder&& setPacketNumBytes(const uint64_t packetNumBytesIn);
        ReceivedPacket build() &&;
        explicit Builder() = default;
      };

      // Use builder to construct.
      explicit ReceivedPacket(BuilderFields&& builderFields);
    };

    // Receive loop timestamp.
    const TimePoint receiveLoopTime;

    // Number of packets received.
    const uint64_t numPacketsReceived;

    // Number of bytes received.
    const uint64_t numBytesReceived;

    // Details for each received packet.
    std::vector<ReceivedPacket> receivedPackets;

    struct BuilderFields {
      folly::Optional<TimePoint> maybeReceiveLoopTime;
      folly::Optional<uint64_t> maybeNumPacketsReceived;
      folly::Optional<uint64_t> maybeNumBytesReceived;
      std::vector<ReceivedPacket> receivedPackets;
      explicit BuilderFields() = default;
    };

    struct Builder : public BuilderFields {
      Builder&& setReceiveLoopTime(const TimePoint receiveLoopTimeIn);
      Builder&& setNumPacketsReceived(const uint64_t numPacketsReceivedIn);
      Builder&& setNumBytesReceived(const uint64_t numBytesReceivedIn);
      Builder&& addReceivedPacket(ReceivedPacket&& packetIn);
      PacketsReceivedEvent build() &&;
      explicit Builder() = default;
    };

    // Use builder to construct.
    explicit PacketsReceivedEvent(BuilderFields&& builderFields);
  };

  struct AcksProcessedEvent {
    [[nodiscard]] const std::vector<AckEvent>& getAckEvents() const {
      return ackEvents;
    }

    // Reference to last processed set of ack events.
    const std::vector<AckEvent>& ackEvents;

    struct BuilderFields {
      folly::Optional<std::reference_wrapper<const std::vector<AckEvent>>>
          maybeAckEventsRef;
      explicit BuilderFields() = default;
    };

    struct Builder : public BuilderFields {
      Builder&& setAckEvents(const std::vector<AckEvent>& ackEventsIn);
      AcksProcessedEvent build() &&;
      explicit Builder() = default;
    };

    // Use builder to construct.
    explicit AcksProcessedEvent(BuilderFields builderFields);
  };

  struct LostPacket {
    explicit LostPacket(
        bool lostByTimeout,
        bool lostByReorderThreshold,
        quic::OutstandingPacketMetadata pktMetadata,
        quic::PacketNum packetNum,
        quic::PacketNumberSpace pnSpace)
        : lostByTimeout(lostByTimeout),
          lostByReorderThreshold(lostByReorderThreshold),
          packetMetadata(std::move(pktMetadata)),
          packetNum(packetNum),
          pnSpace(pnSpace) {}
    bool lostByTimeout{false};
    bool lostByReorderThreshold{false};
    const quic::OutstandingPacketMetadata packetMetadata;
    const quic::PacketNum packetNum;
    const quic::PacketNumberSpace pnSpace;
  };

  struct LossEvent {
    explicit LossEvent(TimePoint time = Clock::now()) : lossTime(time) {}

    bool hasPackets() {
      return lostPackets.size() > 0;
    }

    void addLostPacket(
        const quic::OutstandingPacketMetadata& pktMetadata,
        const quic::PacketNum packetNum,
        const quic::PacketNumberSpace pnSpace) {
      lostPackets.emplace_back(
          pktMetadata.lossTimeoutDividend.has_value(),
          pktMetadata.lossReorderDistance.has_value(),
          pktMetadata,
          packetNum,
          pnSpace);
    }
    const TimePoint lossTime;
    std::vector<LostPacket> lostPackets;
  };

  struct PacketRTT {
    explicit PacketRTT(
        TimePoint rcvTimeIn,
        std::chrono::microseconds rttSampleIn,
        std::chrono::microseconds ackDelayIn,
        const quic::OutstandingPacketWrapper& pkt)
        : rcvTime(rcvTimeIn),
          rttSample(rttSampleIn),
          ackDelay(ackDelayIn),
          metadata(pkt.metadata),
          lastAckedPacketInfo(pkt.lastAckedPacketInfo) {}
    TimePoint rcvTime;
    std::chrono::microseconds rttSample;
    std::chrono::microseconds ackDelay;
    const quic::OutstandingPacketMetadata metadata;
    const folly::Optional<OutstandingPacketWrapper::LastAckedPacketInfo>
        lastAckedPacketInfo;
  };

  struct SpuriousLossEvent {
    explicit SpuriousLossEvent(const TimePoint rcvTimeIn = Clock::now())
        : rcvTime(rcvTimeIn) {}

    bool hasPackets() {
      return spuriousPackets.size() > 0;
    }

    void addSpuriousPacket(
        const quic::OutstandingPacketMetadata& pktMetadata,
        const quic::PacketNum packetNum,
        const quic::PacketNumberSpace pnSpace) {
      spuriousPackets.emplace_back(
          pktMetadata.lossTimeoutDividend.has_value(),
          pktMetadata.lossReorderDistance.has_value(),
          pktMetadata,
          packetNum,
          pnSpace);
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

  struct StreamEvent {
    StreamEvent(
        const StreamId id,
        StreamInitiator initiator,
        StreamDirectionality directionality)
        : streamId(id),
          streamInitiator(initiator),
          streamDirectionality(directionality) {}

    const StreamId streamId;
    const StreamInitiator streamInitiator;
    const StreamDirectionality streamDirectionality;
  };

  using StreamOpenEvent = StreamEvent;
  using StreamCloseEvent = StreamEvent;

  /**
   * Events.
   */

  /**
   * closeStarted() is invoked when socket close begins.
   *
   * The socket may stay open for some time after this event to drain.
   *
   * @param socket   Socket being closed.
   * @param event    CloseStartedEvent with details.
   */
  virtual void closeStarted(
      QuicSocket* /* socket */,
      const CloseStartedEvent& /* event */) noexcept {}

  /**
   * closing() is invoked right before the transport is unbound from UDP socket.
   *
   * closeStarted() should have been invoked prior to this event as this event
   * marks the completion of the socket being closed and the last opportunity
   * to capture state from the socket.
   *
   * Called immediately BEFORE the transport is unbound from the UDP socket to
   * be consistent with TCP sockets, for which the closing() event would mark
   * the last opportunity to get information (such as TCP_INFO) from the socket.
   *
   * @param socket   Socket being closed.
   * @param event    ClosingEvent with details.
   */
  virtual void closing(
      QuicSocket* /* socket */,
      const ClosingEvent& /* event */) noexcept {}

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
   * startWritingFromAppLimited() is invoked when the socket is currently
   * app rate limited and is being given an opportunity to write packets.
   *
   * @param socket   Socket that is starting to write from an app limited state.
   * @param event    AppLimitedEvent with details.
   */
  virtual void startWritingFromAppLimited(
      QuicSocket* /* socket */,
      const AppLimitedEvent& /* event */) {}

  /**
   * packetsWritten() is invoked when packets are written to the UDP socket.
   *
   * @param socket   Socket for which packets were written.
   * @param event    PacketsWrittenEvent with details.
   */
  virtual void packetsWritten(
      QuicSocket* /* socket */,
      const PacketsWrittenEvent& /* event */) {}

  /**
   * appRateLimited() is invoked when the socket becomes app rate limited.
   *
   * @param socket   Socket that has become application rate limited.
   * @param event    AppLimitedEvent with details.
   */
  virtual void appRateLimited(
      QuicSocket* /* socket */,
      const AppLimitedEvent& /* event */) {}

  /**
   * packetsReceived() is invoked when raw packets are received from UDP socket.
   *
   * @param socket   Socket for which packets were received.
   * @param event    PacketsReceivedEvent with details.
   */
  virtual void packetsReceived(
      QuicSocket* /* socket */,
      const PacketsReceivedEvent& /* event */) {}

  /**
   * acksProcessed() is invoked when ACKs from remote are processed.
   *
   * @param socket   Socket when the callback is processed.
   * @param event    Event with information about ACKs processed.
   */
  virtual void acksProcessed(
      QuicSocket*, /* socket */
      const struct AcksProcessedEvent& /* event */) {}

  /**
   * packetLossDetected() is invoked when a packet loss is detected.
   *
   * @param socket   Socket for which packet loss was detected.
   * @param event    LossEvent with details.
   */
  virtual void packetLossDetected(
      QuicSocket*, /* socket */
      const LossEvent& /* event */) {}

  /**
   * rttSampleGenerated() is invoked when a RTT sample is made.
   *
   * @param socket   Socket for which an RTT sample was generated.
   * @param event    PacketRTTEvent with details.
   */
  virtual void rttSampleGenerated(
      QuicSocket*, /* socket */
      const PacketRTT& /* event */) {}

  /**
   * spuriousLossDetected() is invoked when an ACK arrives for a packet that is
   * declared lost
   *
   * @param socket   Socket when the callback is processed.
   * @param packet   const reference to the lost packet.
   */
  virtual void spuriousLossDetected(
      QuicSocket*, /* socket */
      const SpuriousLossEvent& /* event */) {}

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
   * streamOpened() is invoked when a new stream is opened.
   *
   * @param socket   Socket associated with the event.
   * @param event    Event containing details.
   */
  virtual void streamOpened(
      QuicSocket*, /* socket */
      const StreamOpenEvent& /* event */) {}

  /**
   * streamClosed() is invoked when a stream is closed.
   *
   * @param socket   Socket associated with the event.
   * @param event    Event containing details.
   */
  virtual void streamClosed(
      QuicSocket*, /* socket */
      const StreamCloseEvent& /* event */) {}
};

} // namespace quic
