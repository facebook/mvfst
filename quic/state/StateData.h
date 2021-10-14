/*
 * Copyright (c) Facebook, Inc. and its affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 *
 */

#pragma once

#include <quic/QuicConstants.h>
#include <quic/api/Observer.h>
#include <quic/codec/ConnectionIdAlgo.h>
#include <quic/codec/QuicReadCodec.h>
#include <quic/codec/QuicWriteCodec.h>
#include <quic/codec/Types.h>
#include <quic/common/BufAccessor.h>
#include <quic/common/WindowedCounter.h>
#include <quic/d6d/ProbeSizeRaiser.h>
#include <quic/handshake/HandshakeLayer.h>
#include <quic/logging/QLogger.h>
#include <quic/state/AckStates.h>
#include <quic/state/LossState.h>
#include <quic/state/OutstandingPacket.h>
#include <quic/state/PacketEvent.h>
#include <quic/state/PendingPathRateLimiter.h>
#include <quic/state/QuicConnectionStats.h>
#include <quic/state/QuicStreamManager.h>
#include <quic/state/QuicTransportStatsCallback.h>
#include <quic/state/StreamData.h>
#include <quic/state/TransportSettings.h>

#include <folly/Optional.h>
#include <folly/io/IOBuf.h>
#include <folly/io/async/AsyncUDPSocket.h>
#include <folly/io/async/DelayedDestruction.h>
#include <folly/io/async/HHWheelTimer.h>

#include <chrono>
#include <list>
#include <numeric>
#include <queue>

namespace quic {

struct RecvmmsgStorage {
  // Storage for the recvmmsg system call.
  std::vector<struct mmsghdr> msgs;
  std::vector<struct sockaddr_storage> addrs;
  std::vector<struct iovec> iovecs;
  // Buffers we pass to recvmmsg.
  std::vector<Buf> readBuffers;
  // Free buffers which were not used in previous iterations.
  std::vector<Buf> freeBufs;

  void resize(size_t numPackets) {
    if (msgs.size() != numPackets) {
      msgs.resize(numPackets);
      addrs.resize(numPackets);
      readBuffers.resize(numPackets);
      iovecs.resize(numPackets);
      freeBufs.reserve(numPackets);
    }
  }
};

struct NetworkData {
  TimePoint receiveTimePoint;
  std::vector<Buf> packets;
  size_t totalData{0};

  NetworkData() = default;
  NetworkData(Buf&& buf, const TimePoint& receiveTime)
      : receiveTimePoint(receiveTime) {
    if (buf) {
      totalData = buf->computeChainDataLength();
      packets.emplace_back(std::move(buf));
    }
  }

  std::unique_ptr<folly::IOBuf> moveAllData() && {
    std::unique_ptr<folly::IOBuf> buf;
    for (size_t i = 0; i < packets.size(); ++i) {
      if (buf) {
        buf->prependChain(std::move(packets[i]));
      } else {
        buf = std::move(packets[i]);
      }
    }
    return buf;
  }
};

struct NetworkDataSingle {
  Buf data;
  TimePoint receiveTimePoint;
  size_t totalData{0};

  NetworkDataSingle() = default;

  NetworkDataSingle(
      std::unique_ptr<folly::IOBuf> buf,
      const TimePoint& receiveTime)
      : data(std::move(buf)), receiveTimePoint(receiveTime) {
    if (data) {
      totalData += data->computeChainDataLength();
    }
  }
};

struct OutstandingsInfo {
  // Sent packets which have not been acked. These are sorted by PacketNum.
  std::deque<OutstandingPacket> packets;

  // All PacketEvents of this connection. If a OutstandingPacket doesn't have an
  // associatedEvent or if it's not in this set, there is no need to process its
  // frames upon ack or loss.
  folly::F14FastSet<PacketEvent, PacketEventHash> packetEvents;

  // Number of outstanding packets not including cloned
  EnumArray<PacketNumberSpace, uint64_t> packetCount{};

  // Number of packets are clones or cloned.
  EnumArray<PacketNumberSpace, uint64_t> clonedPacketCount{};

  // Number of packets currently declared lost.
  uint64_t declaredLostCount{0};

  // Number of outstanding inflight DSR packet. That is, when a DSR packet is
  // declared lost, this counter will be decreased.
  uint64_t dsrCount{0};

  // Number of packets outstanding and not declared lost.
  uint64_t numOutstanding() {
    return packets.size() - declaredLostCount;
  }

  // Total number of cloned packets.
  uint64_t numClonedPackets() {
    return clonedPacketCount[PacketNumberSpace::Initial] +
        clonedPacketCount[PacketNumberSpace::Handshake] +
        clonedPacketCount[PacketNumberSpace::AppData];
  }
};

struct Pacer {
  virtual ~Pacer() = default;

  /**
   * API for CongestionController to notify Pacer the latest cwnd value in bytes
   * and connection RTT so that Pacer can recalculate pacing rates.
   * Note the third parameter is here for testing purposes.
   */
  virtual void refreshPacingRate(
      uint64_t cwndBytes,
      std::chrono::microseconds rtt,
      TimePoint currentTime = Clock::now()) = 0;

  /**
   * Set the pacers rate to the given value in Bytes per second
   */
  virtual void setPacingRate(uint64_t rateBps) = 0;

  /**
   * Set an upper limit on the rate this pacer can use.
   * - If the pacer is currently using a faster pace, it will be brought down to
   *   maxRateBytesPerSec.
   * - If refreshPacingRate or setPacingRate are called with a value
   * greated than maxRateBytesPerSec, maxRateBytesPerSec will be used instead.
   */
  virtual void setMaxPacingRate(uint64_t maxRateBytesPerSec) = 0;

  /**
   * Resets the pacer, which should have the effect of the next write
   * happening immediately.
   */
  virtual void reset() = 0;

  /**
   * Set the factor by which to multiply the RTT before determining the
   * inter-burst interval. E.g. a numerator of 1 and a denominator of 2
   * would effectively double the pacing rate.
   */
  virtual void setRttFactor(uint8_t numerator, uint8_t denominator) = 0;

  /**
   * API for Trnasport to query the interval before next write
   */
  [[nodiscard]] virtual std::chrono::microseconds getTimeUntilNextWrite(
      TimePoint currentTime = Clock::now()) const = 0;

  /**
   * API for Transport to query a recalculated batch size based on currentTime
   * and previously scheduled write time. The batch size is how many packets the
   * transport can write out per eventbase loop.
   *
   * currentTime: The caller is expected to pass in a TimePoint value so that
   *              the Pacer can compensate the timer drift.
   */
  virtual uint64_t updateAndGetWriteBatchSize(TimePoint currentTime) = 0;

  /**
   * Getter API of the most recent write batch size.
   */
  virtual uint64_t getCachedWriteBatchSize() const = 0;

  virtual void onPacketSent() = 0;
  virtual void onPacketsLoss() = 0;
};

struct PacingRate {
  std::chrono::microseconds interval{0us};
  uint64_t burstSize{0};

  struct Builder {
    Builder&& setInterval(std::chrono::microseconds interval) &&;
    Builder&& setBurstSize(uint64_t burstSize) &&;
    PacingRate build() &&;

   private:
    std::chrono::microseconds interval_{0us};
    uint64_t burstSize_{0};
  };

 private:
  PacingRate(std::chrono::microseconds interval, uint64_t burstSize);
};

struct CongestionController {
  // Helper struct to group multiple lost packets into one event
  struct LossEvent {
    folly::Optional<PacketNum> largestLostPacketNum;
    uint64_t lostBytes;
    uint32_t lostPackets;
    const TimePoint lossTime;
    // The packet sent time of the lost packet with largest packet sent time in
    // this LossEvent
    folly::Optional<TimePoint> largestLostSentTime;
    // The packet sent time of the lost packet with smallest packet sent time in
    // the LossEvent
    folly::Optional<TimePoint> smallestLostSentTime;
    // Whether this LossEvent also indicates persistent congestion
    bool persistentCongestion;

    explicit LossEvent(TimePoint time = Clock::now())
        : lostBytes(0),
          lostPackets(0),
          lossTime(time),
          persistentCongestion(false) {}

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

  struct AckEvent {
    /**
     * The reason that this is an optional type, is that we construct an
     * AckEvent first, then go through the acked packets that are still
     * outstanding, and figure out the largest acked packet along the way.
     */
    folly::Optional<PacketNum> largestAckedPacket;
    TimePoint largestAckedPacketSentTime;
    bool largestAckedPacketAppLimited{false};
    uint64_t ackedBytes{0};
    TimePoint ackTime;
    TimePoint adjustedAckTime;
    // The minimal RTT sample among packets acked by this AckEvent. This RTT
    // includes ack delay.
    folly::Optional<std::chrono::microseconds> mrttSample;
    // If this AckEvent came from an implicit ACK rather than a real one.
    bool implicit{false};

    struct AckPacket {
      // Packet sent time when this acked pakcet was first sent.
      TimePoint sentTime;
      // Packet's encoded size.
      uint32_t encodedSize;
      // LastAckedPacketInfo from this acked packet'r original sent
      // OutstandingPacket structure.
      folly::Optional<OutstandingPacket::LastAckedPacketInfo>
          lastAckedPacketInfo;
      // Total bytes sent on the connection when the acked packet was first
      // sent.
      uint64_t totalBytesSentThen;
      // Whether this packet was sent when CongestionController is in
      // app-limited state.
      bool isAppLimited;

      struct Builder {
        Builder&& setSentTime(TimePoint sentTimeIn);
        Builder&& setEncodedSize(uint32_t encodedSizeIn);
        Builder&& setLastAckedPacketInfo(
            folly::Optional<OutstandingPacket::LastAckedPacketInfo>
                lastAckedPacketInfoIn);
        Builder&& setTotalBytesSentThen(uint64_t totalBytesSentThenIn);
        Builder&& setAppLimited(bool appLimitedIn);
        AckPacket build() &&;
        explicit Builder() = default;

       private:
        TimePoint sentTime;
        uint32_t encodedSize{0};
        folly::Optional<OutstandingPacket::LastAckedPacketInfo>
            lastAckedPacketInfo;
        uint64_t totalBytesSentThen{0};
        bool isAppLimited{false};
      };

     private:
      explicit AckPacket(
          TimePoint sentTimeIn,
          uint32_t encodedSizeIn,
          folly::Optional<OutstandingPacket::LastAckedPacketInfo>
              lastAckedPacketInfoIn,
          uint64_t totalBytesSentThenIn,
          bool isAppLimitedIn);
    };

    std::vector<AckPacket> ackedPackets;
  };

  virtual ~CongestionController() = default;

  /**
   * Take bytes out of flight without mutating other states of the controller
   */
  virtual void onRemoveBytesFromInflight(uint64_t) = 0;
  virtual void onPacketSent(const OutstandingPacket& packet) = 0;
  virtual void onPacketAckOrLoss(
      folly::Optional<AckEvent>,
      folly::Optional<LossEvent>) = 0;

  /**
   * Return the number of bytes that the congestion controller
   * will allow you to write.
   */
  virtual uint64_t getWritableBytes() const = 0;

  /**
   * Return the number of bytes of cwnd of the congestion
   * controller.
   */
  virtual uint64_t getCongestionWindow() const = 0;
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
   *
   */
  virtual void setAppLimited() = 0;
  virtual CongestionControlType type() const = 0;

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
  virtual bool isInBackgroundMode() const = 0;

  /**
   * Whether the congestion controller thinks it's currently in app-limited
   * state.
   */
  virtual bool isAppLimited() const = 0;

  virtual void getStats(CongestionControllerStats& stats) const = 0;
};

struct QuicCryptoStream : public QuicStreamLike {
  ~QuicCryptoStream() override = default;
};

struct QuicCryptoState {
  // Stream to exchange the initial cryptographic material.
  QuicCryptoStream initialStream;

  // Stream to exchange the one rtt key material.
  QuicCryptoStream handshakeStream;

  // Stream to exchange handshake data encrypted with 1-rtt keys.
  QuicCryptoStream oneRttStream;
};

struct ConnectionCloseEvent {
  TransportErrorCode errorCode;
  std::string reasonPhrase;
  PacketNum packetSequenceNum;
};

struct RstStreamEvent {
  RstStreamEvent(StreamId id, uint64_t offset, ApplicationErrorCode error)
      : stream(id), byteOffset(offset), errorCode(error) {}

  StreamId stream;
  uint64_t byteOffset;
  ApplicationErrorCode errorCode;
};

using Resets = folly::F14FastMap<StreamId, RstStreamFrame>;

using FrameList = std::vector<QuicSimpleFrame>;

class Logger;
class CongestionControllerFactory;
class LoopDetectorCallback;
class PendingPathRateLimiter;

struct QuicConnectionStateBase : public folly::DelayedDestruction {
  virtual ~QuicConnectionStateBase() = default;

  explicit QuicConnectionStateBase(QuicNodeType type) : nodeType(type) {
    observers = std::make_shared<ObserverVec>();
  }

  // Accessor to output buffer for continuous memory GSO writes
  BufAccessor* bufAccessor{nullptr};

  std::unique_ptr<Handshake> handshakeLayer;

  // Crypto stream
  std::unique_ptr<QuicCryptoState> cryptoState;

  // Connection Congestion controller
  std::unique_ptr<CongestionController> congestionController;

  // Pacer
  std::unique_ptr<Pacer> pacer;

  // Congestion Controller factory to create specific impl of cc algorithm
  std::shared_ptr<CongestionControllerFactory> congestionControllerFactory;

  std::unique_ptr<QuicStreamManager> streamManager;

  // When server receives early data attempt without valid source address token,
  // server will limit bytes in flight to avoid amplification attack.
  // This limit should be cleared and set back to max after CFIN is received.
  folly::Optional<uint32_t> writableBytesLimit;

  std::unique_ptr<PendingPathRateLimiter> pathValidationLimiter;

  // Outstanding packets, packet events, and associated counters wrapped in one
  // class
  OutstandingsInfo outstandings;

  // The read codec to decrypt and decode packets.
  std::unique_ptr<QuicReadCodec> readCodec;

  // Initial header cipher.
  std::unique_ptr<PacketNumberCipher> initialHeaderCipher;

  // Handshake header cipher.
  std::unique_ptr<PacketNumberCipher> handshakeWriteHeaderCipher;

  // One rtt write header cipher.
  std::unique_ptr<PacketNumberCipher> oneRttWriteHeaderCipher;

  // Write cipher for 1-RTT data
  std::unique_ptr<Aead> oneRttWriteCipher;

  // Write cipher for packets with initial keys.
  std::unique_ptr<Aead> initialWriteCipher;

  // Write cipher for packets with handshake keys.
  std::unique_ptr<Aead> handshakeWriteCipher;

  // Time at which the connection started.
  TimePoint connectionTime;

  // The received active_connection_id_limit transport parameter from the peer.
  uint64_t peerActiveConnectionIdLimit{0};

  // The destination connection id used in client's initial packet.
  folly::Optional<ConnectionId> clientChosenDestConnectionId;

  // The source connection id used in client's initial packet.
  folly::Optional<ConnectionId> clientConnectionId;

  // The current server chosen connection id.
  folly::Optional<ConnectionId> serverConnectionId;

  // Connection ids issued by self.
  std::vector<ConnectionIdData> selfConnectionIds;

  // Connection ids issued by peer - to be used as destination ids.
  std::vector<ConnectionIdData> peerConnectionIds;

  // ConnectionIdAlgo implementation to encode and decode ConnectionId with
  // various info, such as routing related info.
  ConnectionIdAlgo* connIdAlgo{nullptr};

  // Negotiated version.
  folly::Optional<QuicVersion> version;

  // Original advertised version. Only meaningful to clients.
  // TODO: move to client only conn state.
  folly::Optional<QuicVersion> originalVersion;

  // Original address used by the peer when first establishing the connection.
  folly::SocketAddress originalPeerAddress;

  // Current peer address.
  folly::SocketAddress peerAddress;

  // Local address. INADDR_ANY if not set.
  folly::Optional<folly::SocketAddress> localAddress;

  // Local error on the connection.
  folly::Optional<std::pair<QuicErrorCode, std::string>> localConnectionError;

  // Error sent on the connection by the peer.
  folly::Optional<std::pair<QuicErrorCode, std::string>> peerConnectionError;

  // Supported versions in order of preference. Only meaningful to clients.
  // TODO: move to client only conn state.
  std::vector<QuicVersion> supportedVersions;

  // The endpoint attempts to create a new self connection id with sequence
  // number and stateless reset token for itself, and if successful, returns it
  // and updates the connection's state to ensure its peer can use it.
  virtual folly::Optional<ConnectionIdData> createAndAddNewSelfConnId() {
    return folly::none;
  }

  uint64_t nextSelfConnectionIdSequence{0};

  // D6D related events
  struct PendingD6DEvents {
    // If we should schedule/cancel d6d raise timeout, if it's not
    // already scheduled/canceled
    bool scheduleRaiseTimeout{false};

    // If we should schedule/cancel d6d probe timeout, if it's not
    // already scheduled/canceled
    bool scheduleProbeTimeout{false};

    // To send a d6d probe packet
    bool sendProbePacket{false};

    // The delay after which sendD6DProbePacket will be set
    folly::Optional<std::chrono::milliseconds> sendProbeDelay;
  };

  struct PendingEvents {
    Resets resets;
    folly::Optional<PathChallengeFrame> pathChallenge;

    FrameList frames;

    // D6D related events
    PendingD6DEvents d6d;

    std::vector<KnobFrame> knobs;

    // Number of probing packets to send after PTO
    EnumArray<PacketNumberSpace, uint8_t> numProbePackets{};

    FOLLY_NODISCARD bool anyProbePackets() const {
      return numProbePackets[PacketNumberSpace::Initial] +
          numProbePackets[PacketNumberSpace::Handshake] +
          numProbePackets[PacketNumberSpace::AppData];
    }

    // true: schedule timeout if not scheduled
    // false: cancel scheduled timeout
    bool schedulePathValidationTimeout{false};

    // If we should schedule a new Ack timeout, if it's not already scheduled
    bool scheduleAckTimeout{false};

    // Whether a connection level window update is due to send
    bool connWindowUpdate{false};

    // If there is a pending loss detection alarm update
    bool setLossDetectionAlarm{false};

    bool cancelPingTimeout{false};

    // close transport when the next packet number reaches kMaxPacketNum
    bool closeTransport{false};

    // To send a ping frame
    bool sendPing{false};

    // Do we need to send data blocked frame when connection is blocked.
    bool sendDataBlocked{false};
  };

  PendingEvents pendingEvents;

  LossState lossState;

  // This contains the ack and packet number related states for all three
  // packet number space.
  AckStates ackStates;

  struct ConnectionFlowControlState {
    // The size of the connection flow control window.
    uint64_t windowSize{0};
    // The max data we have advertised to the peer.
    uint64_t advertisedMaxOffset{0};
    // The max data the peer has advertised on the connection.
    // This is set to 0 initially so that we can't send any data until we know
    // the peer's flow control offset.
    uint64_t peerAdvertisedMaxOffset{0};
    // The sum of the min(read offsets) of all the streams on the conn.
    uint64_t sumCurReadOffset{0};
    // The sum of the max(offset) observed on all the streams on the conn.
    uint64_t sumMaxObservedOffset{0};
    // The sum of write offsets of all the streams, only including the offsets
    // written on the wire.
    uint64_t sumCurWriteOffset{0};
    // The sum of length of data in all the stream buffers.
    uint64_t sumCurStreamBufferLen{0};
    // The packet number in which we got the last largest max data.
    folly::Optional<PacketNum> largestMaxOffsetReceived;
    // The following are advertised by the peer, and are set to zero initially
    // so that we cannot send any data until we know the peer values.
    // The initial max stream offset for peer-initiated bidirectional streams.
    uint64_t peerAdvertisedInitialMaxStreamOffsetBidiLocal{0};
    // The initial max stream offset for local-initiated bidirectional streams.
    uint64_t peerAdvertisedInitialMaxStreamOffsetBidiRemote{0};
    // The initial max stream offset for unidirectional streams.
    uint64_t peerAdvertisedInitialMaxStreamOffsetUni{0};
    // Time at which the last flow control update was sent by the transport.
    folly::Optional<TimePoint> timeOfLastFlowControlUpdate;
  };

  // Current state of flow control.
  ConnectionFlowControlState flowControlState;

  // The outstanding path challenge
  folly::Optional<PathChallengeFrame> outstandingPathValidation;

  // Settings for transports.
  TransportSettings transportSettings;

  // Value of the negotiated ack delay exponent.
  uint64_t peerAckDelayExponent{kDefaultAckDelayExponent};

  // The value of the peer's min_ack_delay, for creating ACK_FREQUENCY frames.
  folly::Optional<std::chrono::microseconds> peerMinAckDelay;

  // Idle timeout advertised by the peer. Initially sets it to the maximum value
  // until the handshake sets the timeout.
  std::chrono::milliseconds peerIdleTimeout{kMaxIdleTimeout};

  // The max UDP packet size we will be sending, limited by both the received
  // max_packet_size in Transport Parameters and PMTU
  uint64_t udpSendPacketLen{kDefaultUDPSendPacketLen};

  // Peer-advertised max UDP payload size, stored as an opportunistic value to
  // use when receiving the forciblySetUdpPayloadSize transport knob param
  uint64_t peerMaxUdpPayloadSize{kDefaultUDPSendPacketLen};

  struct PacketSchedulingState {
    StreamId nextScheduledControlStream{0};
  };

  PacketSchedulingState schedulingState;

  // Logger for this connection.
  std::shared_ptr<Logger> logger;

  // QLogger for this connection
  std::shared_ptr<QLogger> qLogger;

  // Track stats for various server events
  QuicTransportStatsCallback* statsCallback{nullptr};

  // Meta state of d6d, mostly useful for analytics. D6D can operate without it.
  struct D6DMetaState {
    // Cumulative count of acked packets
    uint64_t totalAckedProbes{0};

    // Cumulative count of lost packets
    uint64_t totalLostProbes{0};

    // Cumulative count of transmitted packets
    uint64_t totalTxedProbes{0};

    // Timepoint of when d6d reaches a non-search state
    // this helps us understand the convergence speed
    TimePoint timeLastNonSearchState;

    // Last non-search state
    D6DMachineState lastNonSearchState;
  };

  struct D6DState {
    // The lastest d6d probe packet transmitted
    folly::Optional<D6DProbePacket> lastProbe;

    // The raise timeout
    std::chrono::seconds raiseTimeout{kDefaultD6DRaiseTimeout};

    // The probe timeout
    std::chrono::seconds probeTimeout{kDefaultD6DProbeTimeout};

    // The number of outstanding probe packets
    uint64_t outstandingProbes{0};

    // The base PMTU to start probing with
    uint16_t basePMTU{kDefaultD6DBasePMTU};

    // The max PMTU, determined by max_packet_size transport parameter
    uint16_t maxPMTU{kDefaultMaxUDPPayload};

    // Current probe size, dynamically adjusted by the probing algorithm
    uint32_t currentProbeSize{kDefaultD6DBasePMTU};

    // Probe size raiser
    std::unique_ptr<ProbeSizeRaiser> raiser;

    // ThresholdCounter to help detect PMTU blackhole
    std::unique_ptr<WindowedCounter<uint64_t, uint64_t>> thresholdCounter{
        nullptr};

    // Meta state
    D6DMetaState meta;

    // Turn off blackhole detection
    bool noBlackholeDetection{false};

    // D6D Machine State
    D6DMachineState state{D6DMachineState::DISABLED};
  };

  D6DState d6d;

  // Debug information. Currently only used to debug busy loop of Transport
  // WriteLooper.
  struct WriteDebugState {
    bool needsWriteLoopDetect{false};
    uint64_t currentEmptyLoopCount{0};
    WriteDataReason writeDataReason{WriteDataReason::NO_WRITE};
    NoWriteReason noWriteReason{NoWriteReason::WRITE_OK};
    std::string schedulerName;
  };

  struct ReadDebugState {
    uint64_t loopCount{0};
    NoReadReason noReadReason{NoReadReason::READ_OK};
  };

  WriteDebugState writeDebugState;
  ReadDebugState readDebugState;

  std::shared_ptr<LoopDetectorCallback> loopDetectorCallback;

  // Measure rtt betwen pathchallenge & path response frame
  // Use this measured rtt as init rtt (from Transport Settings)
  TimePoint pathChallengeStartTime;

  /**
   * Eary data app params functions.
   */
  folly::Function<bool(const folly::Optional<std::string>&, const Buf&) const>
      earlyDataAppParamsValidator;
  folly::Function<Buf()> earlyDataAppParamsGetter;

  /**
   * Selects a previously unused peer-issued connection id to use.
   * If there are no available ids return false and don't change anything.
   * Return true if replacement succeeds.
   */
  bool retireAndSwitchPeerConnectionIds();

  // queue of functions to be called in processCallbacksAfterNetworkData
  std::vector<std::function<void(QuicSocket*)>> pendingCallbacks;

  // Vector of Observers that are attached to this socket.
  std::shared_ptr<const ObserverVec> observers;

  // Type of node owning this connection (client or server).
  QuicNodeType nodeType;

  // Whether or not we received a new packet before a write.
  bool receivedNewPacketBeforeWrite{false};

  // Whether we've set the transporot parameters from transportSettings yet.
  bool transportParametersEncoded{false};

  // Whether a connection can be paced based on its handshake and close states.
  // For example, we may not want to pace a connection that's still handshaking.
  bool canBePaced{false};

  // Flag indicating whether the socket is currently waiting for the app to
  // write data. All new sockets start off in this state where they wait for the
  // application to pump data to the socket.
  bool waitingForAppData{true};

  // Monotonically increasing counter that is incremented each time there is a
  // write on this socket (writeSocketData() is called), This is used to
  // identify specific outstanding packets (based on writeCount and packetNum)
  // in the Observers, to construct Write Blocks
  uint64_t writeCount{0};

  // Number of DSR packets sent by this connection.
  uint64_t dsrPacketCount{0};

  // Whether we successfully used 0-RTT keys in this connection.
  bool usedZeroRtt{false};

  struct DatagramState {
    uint16_t maxReadFrameSize{kDefaultMaxDatagramFrameSize};
    uint16_t maxWriteFrameSize{kDefaultMaxDatagramFrameSize};
    uint32_t maxReadBufferSize{kDefaultMaxDatagramsBuffered};
    uint32_t maxWriteBufferSize{kDefaultMaxDatagramsBuffered};
    // Buffers Incoming Datagrams
    std::deque<BufQueue> readBuffer;
    // Buffers Outgoing Datagrams
    std::deque<BufQueue> writeBuffer;
  };

  DatagramState datagramState;
};

std::ostream& operator<<(std::ostream& os, const QuicConnectionStateBase& st);

struct AckStateVersion {
  uint64_t initialAckStateVersion{kDefaultIntervalSetVersion};
  uint64_t handshakeAckStateVersion{kDefaultIntervalSetVersion};
  uint64_t appDataAckStateVersion{kDefaultIntervalSetVersion};

  AckStateVersion(
      uint64_t initialVersion,
      uint64_t handshakeVersion,
      uint64_t appDataVersion);

  bool operator==(const AckStateVersion& other) const;
  bool operator!=(const AckStateVersion& other) const;
};

} // namespace quic
