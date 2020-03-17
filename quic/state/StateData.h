/*
 * Copyright (c) Facebook, Inc. and its affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 *
 */

#pragma once

#include <quic/QuicConstants.h>
#include <quic/codec/ConnectionIdAlgo.h>
#include <quic/codec/QuicReadCodec.h>
#include <quic/codec/QuicWriteCodec.h>
#include <quic/codec/Types.h>
#include <quic/common/EnumArray.h>
#include <quic/handshake/HandshakeLayer.h>
#include <quic/logging/QLogger.h>
#include <quic/state/AckStates.h>
#include <quic/state/PendingPathRateLimiter.h>
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
  std::vector<struct mmsghdr> msgs;
  std::vector<struct sockaddr_storage> addrs;
  std::vector<Buf> readBuffers;
  std::vector<struct iovec> iovecs;

  void resize(size_t numPackets) {
    msgs.resize(numPackets);
    addrs.resize(numPackets);
    readBuffers.resize(numPackets);
    iovecs.resize(numPackets);
  }
};

struct NetworkData {
  TimePoint receiveTimePoint;
  std::vector<std::unique_ptr<folly::IOBuf>> packets;
  RecvmmsgStorage recvmmsgStorage;
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
  std::unique_ptr<folly::IOBuf> data;
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

/**
 * There are cases that we may clone an outstanding packet and resend it as is.
 * When that happens, we assign a PacketEvent to both the original and cloned
 * packet if no PacketEvent is already associated with the original packet. If
 * the original packet already has a PacketEvent, we copy that value into the
 * cloned packet.
 * A connection maintains a set of PacketEvents. When a packet with a
 * PacketEvent is acked or lost, we search the set. If the PacketEvent is
 * present in the set, we process the ack or loss event (e.g. update RTT, notify
 * CongestionController, and detect loss with this packet) as well as frames in
 * the packet. Then we remove the PacketEvent from the set. If the PacketEvent
 * is absent in the set, we consider all frames contained in the packet are
 * already processed. We will still handle the ack or loss event and update the
 * connection. But no frame will be processed.
 */
using PacketEvent = PacketNum;

// Data structure to represent outstanding retransmittable packets
struct OutstandingPacket {
  // Structure representing the frames that are outstanding including the header
  // that was sent.
  RegularQuicWritePacket packet;
  // Time that the packet was sent.
  TimePoint time;
  // Size of the packet sent on the wire.
  uint32_t encodedSize;
  // Whether this packet has any data from stream 0
  bool isHandshake;
  // Total sent bytes on this connection including this packet itself when this
  // packet is sent.
  uint64_t totalBytesSent;
  // Information regarding the last acked packet on this connection when this
  // packet is sent.
  struct LastAckedPacketInfo {
    TimePoint sentTime;
    TimePoint ackTime;
    // Total sent bytes on this connection when the last acked packet is acked.
    uint64_t totalBytesSent;
    // Total acked bytes on this connection when last acked packet is acked,
    // including the last acked packet.
    uint64_t totalBytesAcked;

    LastAckedPacketInfo(
        TimePoint sentTimeIn,
        TimePoint ackTimeIn,
        uint64_t totalBytesSentIn,
        uint64_t totalBytesAckedIn)
        : sentTime(sentTimeIn),
          ackTime(ackTimeIn),
          totalBytesSent(totalBytesSentIn),
          totalBytesAcked(totalBytesAckedIn) {}
  };
  folly::Optional<LastAckedPacketInfo> lastAckedPacketInfo;

  // PacketEvent associated with this OutstandingPacket. This will be a
  // folly::none if the packet isn't a clone and hasn't been cloned.
  folly::Optional<PacketEvent> associatedEvent;

  /**
   * Whether the packet is sent when congestion controller is in app-limited
   * state.
   */
  bool isAppLimited{false};

  OutstandingPacket(
      RegularQuicWritePacket packetIn,
      TimePoint timeIn,
      uint32_t encodedSizeIn,
      bool isHandshakeIn,
      uint64_t totalBytesSentIn)
      : packet(std::move(packetIn)),
        time(std::move(timeIn)),
        encodedSize(encodedSizeIn),
        isHandshake(isHandshakeIn),
        totalBytesSent(totalBytesSentIn) {}
};

struct Pacer {
  virtual ~Pacer() = default;

  /**
   * API for CongestionController to notify Pacer the latest cwnd value in bytes
   * and connection RTT so that Pacer can recalculate pacing rates.
   */
  virtual void refreshPacingRate(
      uint64_t cwndBytes,
      std::chrono::microseconds rtt) = 0;

  /**
   * Notify the Pacer that a paced write is scheduled.
   *
   * currentTime: the time that the timer is scheduled. NOT the time that a
   *              write is scheduled to happen.
   */
  virtual void onPacedWriteScheduled(TimePoint currentTime) = 0;

  /**
   * API for Trnasport to query the interval before next write
   */
  virtual std::chrono::microseconds getTimeUntilNextWrite() const = 0;

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

  virtual void setAppLimited(bool limited) = 0;
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
          packet.encodedSize) {
        throw QuicInternalException(
            "LossEvent: lostBytes overflow",
            LocalErrorCode::LOST_BYTES_OVERFLOW);
      }
      PacketNum packetNum = packet.packet.header.getPacketSequenceNum();
      largestLostPacketNum =
          std::max(packetNum, largestLostPacketNum.value_or(packetNum));
      lostBytes += packet.encodedSize;
      lostPackets++;
      largestLostSentTime =
          std::max(packet.time, largestLostSentTime.value_or(packet.time));
      smallestLostSentTime =
          std::min(packet.time, smallestLostSentTime.value_or(packet.time));
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
    // The minimal RTT sample among packets acked by this AckEvent. This RTT
    // includes ack delay.
    folly::Optional<std::chrono::microseconds> mrttSample;

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
   * TODO(yangchi): I'm not sure how long I'd like to keep this API. This is a
   * temporary workaround the fact that there are packets we will need to take
   * out of outstandingPackets but not considered loss for congestion control
   * perspective. In long term, we shouldn't take them out of
   * outstandingPackets, then we don't have to do this.
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
   * Whether the congestion controller thinks it's currently in app-limited
   * state.
   */
  virtual bool isAppLimited() const = 0;
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

struct LossState {
  enum class AlarmMethod { EarlyRetransmitOrReordering, Handshake, PTO };
  // Smooth rtt
  std::chrono::microseconds srtt{0us};
  // Latest rtt
  std::chrono::microseconds lrtt{0us};
  // Rtt var
  std::chrono::microseconds rttvar{0us};
  // Number of packet loss timer fired before receiving an ack
  uint32_t ptoCount{0};
  // The number of times the handshake packets have been retransmitted without
  // receiving an ack.
  uint16_t handshakeAlarmCount{0};
  // The time when last handshake packet was sent
  TimePoint lastHandshakePacketSentTime;
  // Latest packet number sent
  // TODO: 0 is a legit PacketNum now, we need to make this optional:
  // TODO: this also needs to be 3 numbers now...
  PacketNum largestSent{0};
  // Reordering threshold used
  uint32_t reorderingThreshold{kReorderingThreshold};
  // Timer for time reordering detection or early retransmit alarm.
  EnumArray<PacketNumberSpace, folly::Optional<TimePoint>> lossTimes;
  // Current method by which the loss detection alarm is set.
  AlarmMethod currentAlarmMethod{AlarmMethod::EarlyRetransmitOrReordering};
  // Total number of packet retransmitted on this connection, including packet
  // clones, retransmitted clones, handshake and rejected zero rtt packets.
  uint32_t rtxCount{0};
  // Total number of retransmission due to PTO
  uint32_t timeoutBasedRtxCount{0};
  // Total number of PTO count
  uint32_t totalPTOCount{0};
  // Total number of bytes sent on this connection. This is after encoding.
  uint64_t totalBytesSent{0};
  // Total number of bytes received on this connection. This is before decoding.
  uint64_t totalBytesRecvd{0};
  // Total number of stream bytes retransmitted, excluding cloning.
  uint64_t totalBytesRetransmitted{0};
  // Total number of stream bytes cloned.
  uint64_t totalStreamBytesCloned{0};
  // Total number of bytes cloned.
  uint64_t totalBytesCloned{0};
  // Total number of bytes acked on this connection. If a packet is acked twice,
  // it won't be count twice. Pure acks packets are NOT included.
  uint64_t totalBytesAcked{0};
  // The total number of bytes sent on this connection when the last time a
  // packet is acked.
  uint64_t totalBytesSentAtLastAck{0};
  // The total number of bytes acked on this connection when the last time a
  // packet is acked.
  uint64_t totalBytesAckedAtLastAck{0};
  // Max ack delay received from peer
  std::chrono::microseconds maxAckDelay{0us};
  // minimum rtt. AckDelay isn't excluded from this.
  std::chrono::microseconds mrtt{kDefaultMinRtt};
  // The sent time of the latest acked packet
  folly::Optional<TimePoint> lastAckedPacketSentTime;
  // The latest time a packet is acked
  folly::Optional<TimePoint> lastAckedTime;
  // The time when last retranmittable packet is sent for every packet number
  // space
  TimePoint lastRetransmittablePacketSentTime;
  // Inflight bytes
  uint64_t inflightBytes{0};
};

class Logger;
class CongestionControllerFactory;
class LoopDetectorCallback;
class PendingPathRateLimiter;

struct QuicConnectionStateBase : public folly::DelayedDestruction {
  virtual ~QuicConnectionStateBase() = default;

  explicit QuicConnectionStateBase(QuicNodeType type) : nodeType(type) {}

  // Type of node owning this connection (client or server).
  QuicNodeType nodeType;

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

  // TODO: We really really should wrap outstandingPackets, all its associated
  // counters and the outstandingPacketEvents into one class.
  // Sent packets which have not been acked. These are sorted by PacketNum.
  std::deque<OutstandingPacket> outstandingPackets;

  // All PacketEvents of this connection. If a OutstandingPacket doesn't have an
  // associatedEvent or if it's not in this set, there is no need to process its
  // frames upon ack or loss.
  // TODO: Enforce only AppTraffic packets to be clonable
  folly::F14FastSet<PacketEvent> outstandingPacketEvents;

  // Number of handshake packets outstanding.
  uint64_t outstandingHandshakePacketsCount{0};

  // Number of packets are clones or cloned.
  uint64_t outstandingClonedPacketsCount{0};

  // The read codec to decrypt and decode packets.
  std::unique_ptr<QuicReadCodec> readCodec;

  // Initial header cipher.
  std::unique_ptr<PacketNumberCipher> initialHeaderCipher;

  // Handshake header cipher.
  std::unique_ptr<PacketNumberCipher> handshakeWriteHeaderCipher;

  // Zero rtt write header cipher.
  std::unique_ptr<PacketNumberCipher> zeroRttWriteHeaderCipher;

  // One rtt write header cipher.
  std::unique_ptr<PacketNumberCipher> oneRttWriteHeaderCipher;

  // Write cipher for 1-RTT data
  std::unique_ptr<Aead> oneRttWriteCipher;

  // Write cipher for packets with initial keys.
  std::unique_ptr<Aead> initialWriteCipher;

  // Write cipher for packets with handshake keys.
  std::unique_ptr<Aead> handshakeWriteCipher;

  // Write cipher for 0-RTT data
  // TODO: move this back into the client state
  std::unique_ptr<Aead> zeroRttWriteCipher;

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

  // Before deadline, transport may treat ENETUNREACH as non-fatal error
  folly::Optional<TimePoint> continueOnNetworkUnreachableDeadline;

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

  // Whether or not we received a new packet before a write.
  bool receivedNewPacketBeforeWrite{false};

  struct PendingEvents {
    Resets resets;

    folly::Optional<PathChallengeFrame> pathChallenge;

    FrameList frames;

    // true: schedule timeout if not scheduled
    // false: cancel scheduled timeout
    bool schedulePathValidationTimeout{false};

    // If we should schedule a new Ack timeout, if it's not already scheduled
    bool scheduleAckTimeout{false};

    // Whether a connection level window update is due to send
    bool connWindowUpdate{false};

    // If there is a pending loss detection alarm update
    bool setLossDetectionAlarm{false};

    // Number of probing packets to send after PTO
    uint8_t numProbePackets{0};

    bool cancelPingTimeout{false};

    // close transport when the next packet number reaches kMaxPacketNum
    bool closeTransport{false};
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

  // Whether we've set the transporot parameters from transportSettings yet.
  bool transportParametersEncoded{false};

  // Value of the negotiated ack delay exponent.
  uint64_t peerAckDelayExponent{kDefaultAckDelayExponent};

  // Idle timeout advertised by the peer. Initially sets it to the maximum value
  // until the handshake sets the timeout.
  std::chrono::milliseconds peerIdleTimeout{kMaxIdleTimeout};

  // The max UDP packet size we will be sending, limited by both the received
  // max_packet_size in Transport Parameters and PMTU
  uint64_t udpSendPacketLen{kDefaultUDPSendPacketLen};

  struct PacketSchedulingState {
    StreamId nextScheduledStream{0};
    StreamId nextScheduledControlStream{0};
  };

  PacketSchedulingState schedulingState;

  // The packet number of the latest packet that contains a MaxDataFrame sent
  // out by us.
  folly::Optional<PacketNum> latestMaxDataPacket;

  // Logger for this connection.
  std::shared_ptr<Logger> logger;

  // QLogger for this connection
  std::shared_ptr<QLogger> qLogger;

  // Track stats for various server events
  QuicTransportStatsCallback* infoCallback{nullptr};

  struct HappyEyeballsState {
    // Delay timer
    folly::HHWheelTimer::Callback* connAttemptDelayTimeout{nullptr};

    // IPv6 peer address
    folly::SocketAddress v6PeerAddress;

    // IPv4 peer address
    folly::SocketAddress v4PeerAddress;

    // The address that this socket will try to connect to after connection
    // attempt delay timeout fires
    folly::SocketAddress secondPeerAddress;

    // The UDP socket that will be used for the second connection attempt
    std::unique_ptr<folly::AsyncUDPSocket> secondSocket;

    // Whether should write to the first UDP socket
    bool shouldWriteToFirstSocket{true};

    // Whether should write to the second UDP socket
    bool shouldWriteToSecondSocket{false};

    // Whether HappyEyeballs has finished
    // The signal of finishing is first successful decryption of a packet
    bool finished{false};
  };

  HappyEyeballsState happyEyeballsState;

  // Whether a connection can be paced based on its handshake and close states.
  // For example, we may not want to pace a connection that's still handshaking.
  bool canBePaced{false};

  // Whether or not both ends agree to use partial reliability
  bool partialReliabilityEnabled{false};

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
