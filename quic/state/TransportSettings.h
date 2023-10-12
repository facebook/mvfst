/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#pragma once

#include <folly/Optional.h>
#include <quic/QuicConstants.h>
#include <quic/state/QuicPriorityQueue.h>
#include <chrono>
#include <cstdint>

namespace quic {

struct CongestionControlConfig {
  // Used by: BBR1
  bool conservativeRecovery{false};

  // Used by: BBR1
  // When largeProbeRttCwnd is true, kLargeProbeRttCwndGain * BDP will be used
  // as cwnd during ProbeRtt state, otherwise, 4MSS will be the ProbeRtt cwnd.
  bool largeProbeRttCwnd{false};

  // Whether ack aggregation is also calculated during Startup phase
  bool enableAckAggregationInStartup{false};

  // Used by: BBR1
  // Whether we should enter ProbeRtt if connection has been app-limited since
  // last time we ProbeRtt.
  bool probeRttDisabledIfAppLimited{false};

  // Used by: BBR1
  // Whether BBR should advance pacing gain cycle when BBR is draining and we
  // haven't reached the drain target.
  bool drainToTarget{false};

  // Used by: Cubic
  // If true, exiting hystart switches to additive increase rather than Cubic
  // congestion avoidance, similar to Linux kernel behavior.
  bool additiveIncreaseAfterHystart{false};

  // Used by: Cubic
  // Whether to clamp the cwnd growth when the connection is not cwnd limited.
  bool onlyGrowCwndWhenLimited{false};

  // Used by: Cubic
  // Whether to leave headroom when deciding that the connection is cwnd
  // limited.
  bool leaveHeadroomForCwndLimited{false};

  // These parameters control how BBR sends ACK_FREQUENCY frames every new RTT.
  //  The first controls how many ack eliciting packets have to be received
  //  to trigger an ACK.
  //  The second controls how often, in terms of min RTT, the peer should ACK.
  //  The third controls the reordering threshold they should use when
  //  delaying an ACK.
  struct AckFrequencyConfig {
    uint64_t ackElicitingThreshold{kDefaultRxPacketsBeforeAckAfterInit};
    uint64_t reorderingThreshold{kReorderingThreshold};
    uint32_t minRttDivisor{2};
    // Threshold to use early in the connection.
    bool useSmallThresholdDuringStartup{false};
  };

  // Used by: BBR1
  folly::Optional<AckFrequencyConfig> ackFrequencyConfig;

  // Used by: BBR2
  // Whether BBR2 should not use inflightHi when settings its cwnd.
  bool ignoreInflightHi{false};

  // Used by: BBR2
  // Whether BBR2 should ignore packet loss (i.e. act more like BBR1)
  bool ignoreLoss{false};

  // Used by: BBR2
  // Whether BBR2 should advance the cycle count on exiting startup
  bool advanceCycleAfterStartup{true};
};

struct DatagramConfig {
  bool enabled{false};
  bool framePerPacket{true};
  bool recvDropOldDataFirst{false};
  bool sendDropOldDataFirst{false};
  uint32_t readBufSize{kDefaultMaxDatagramsBuffered};
  uint32_t writeBufSize{kDefaultMaxDatagramsBuffered};
};

struct AckReceiveTimestampsConfig {
  uint64_t maxReceiveTimestampsPerAck{kMaxReceivedPktsTimestampsStored};
  uint64_t receiveTimestampsExponent{kDefaultReceiveTimestampsExponent};
};

// JSON-serialized transport knobs
struct SerializedKnob {
  uint64_t space;
  uint64_t id;
  std::string blob;
};

struct TransportSettings {
  // The initial flow control window for the whole connection advertised to the
  // peer.
  uint64_t advertisedInitialConnectionFlowControlWindow{
      kDefaultConnectionFlowControlWindow};
  // The initial flow control window size of a stream advertised to the peer.
  uint64_t advertisedInitialBidiLocalStreamFlowControlWindow{
      kDefaultStreamFlowControlWindow};
  uint64_t advertisedInitialBidiRemoteStreamFlowControlWindow{
      kDefaultStreamFlowControlWindow};
  uint64_t advertisedInitialUniStreamFlowControlWindow{
      kDefaultStreamFlowControlWindow};
  uint64_t advertisedInitialMaxStreamsBidi{kDefaultMaxStreamsBidirectional};
  uint64_t advertisedInitialMaxStreamsUni{kDefaultMaxStreamsUnidirectional};
  // Maximum number of packets to buffer while cipher is unavailable.
  uint32_t maxPacketsToBuffer{kDefaultMaxBufferedPackets};
  // Idle timeout to advertise to the peer.
  std::chrono::milliseconds idleTimeout{kDefaultIdleTimeout};
  // Ack delay exponent to use.
  uint64_t ackDelayExponent{kDefaultAckDelayExponent};
  // Default congestion controller type.
  CongestionControlType defaultCongestionController{
      CongestionControlType::Cubic};
  // Param to determine sensitivity of CongestionController to latency. Only
  // used by Copa.
  folly::Optional<double> copaDeltaParam;
  // Whether to use Copa's RTT standing feature. Only used by Copa.
  bool copaUseRttStanding{false};
  // The max UDP packet size we are willing to receive.
  uint64_t maxRecvPacketSize{kDefaultUDPReadBufferSize};
  // Number of buffers to allocate for GRO
  uint32_t numGROBuffers_{kDefaultNumGROBuffers};
  // Can we ignore the path mtu when sending a packet. This is useful for
  // testing.
  bool canIgnorePathMTU{false};
  // Whether or not to use a connected UDP socket on the client. This should
  // only be used in environments where you know your IP address does not
  // change. See AsyncUDPSocket::connect for the caveats.
  bool connectUDP{false};
  // Maximum number of consecutive PTOs before the connection is torn down.
  uint16_t maxNumPTOs{kDefaultMaxNumPTO};
  // Maximum number of connection ids to issue to peer
  uint16_t maxNumMigrationsAllowed{kMaxNumMigrationsAllowed};
  // Whether to listen to socket error
  bool enableSocketErrMsgCallback{true};
  // Whether pacing is enabled.
  bool pacingEnabled{false};
  // Whether pacing should be enabled for the first flight before the 1-RTT
  // cipher is available. Turning this on paces 0-rtt packets.
  bool pacingEnabledFirstFlight{false};
  // The minimum number of packets to burst out during pacing
  uint64_t minBurstPackets{kDefaultMinBurstPackets};
  // This is the smallest interval the pacer will use as its interval.
  std::chrono::microseconds pacingTickInterval{kDefaultPacingTickInterval};
  // This is the size of the buckets in the timer triggering the pacing
  // callbacks. For pacing to work accurately, this should be reasonably smaller
  // than kDefaultPacingTickInterval.
  std::chrono::microseconds pacingTimerResolution{
      kDefaultPacingTimerResolution};
  ZeroRttSourceTokenMatchingPolicy zeroRttSourceTokenMatchingPolicy{
      ZeroRttSourceTokenMatchingPolicy::REJECT_IF_NO_EXACT_MATCH};
  // Scale pacing rate for CC, non-empty indicates override via transport knobs
  std::pair<uint8_t, uint8_t> startupRttFactor{1, 2};
  std::pair<uint8_t, uint8_t> defaultRttFactor{4, 5};
  //
  bool attemptEarlyData{false};
  // Maximum number of packets the connection will write in
  // writeConnectionDataToSocket.
  uint64_t writeConnectionDataPacketsLimit{
      kDefaultWriteConnectionDataPacketLimit};
  // Fraction of RTT that is used to limit how long a write function can loop
  DurationRep writeLimitRttFraction{kDefaultWriteLimitRttFraction};
  // Frequency of sending flow control updates. We can send one update every
  // flowControlRttFrequency * RTT if the flow control changes.
  uint16_t flowControlRttFrequency{2};
  // Frequency of sending flow control updates. We can send one update every
  // flowControlWindowFrequency * window if the flow control changes.
  uint16_t flowControlWindowFrequency{2};
  // batching mode
  QuicBatchingMode batchingMode{QuicBatchingMode::BATCHING_MODE_NONE};
  // use thread local batcher - currently it works only with
  // BATCHING_MODE_SENDMMSG_GSO it will not be enabled if the mode is different
  bool useThreadLocalBatching{false};
  // thread local delay interval
  std::chrono::microseconds threadLocalDelay{kDefaultThreadLocalDelay};
  // maximum number of packets we can batch. This does not apply to
  // BATCHING_MODE_NONE
  uint32_t maxBatchSize{kDefaultQuicMaxBatchSize};
  // Initial congestion window in MSS
  uint64_t initCwndInMss{kInitCwndInMss};
  // Minimum congestion window in MSS
  uint64_t minCwndInMss{kMinCwndInMss};
  // Maximum congestion window in MSS
  uint64_t maxCwndInMss{kDefaultMaxCwndInMss};
  // Limited congestion window in MSS
  uint64_t limitedCwndInMss{kLimitedCwndInMss};
  // The following three parameters control ACK generation. ACKs are sent every
  // time so many retransmittable packets are received. There are two values,
  // one for earlier in the flow and one for after. These are "before" and
  // "after" the init threshold respectively.
  uint64_t rxPacketsBeforeAckInitThreshold{
      kDefaultRxPacketsBeforeAckInitThreshold};
  uint16_t rxPacketsBeforeAckBeforeInit{kDefaultRxPacketsBeforeAckBeforeInit};
  uint16_t rxPacketsBeforeAckAfterInit{kDefaultRxPacketsBeforeAckAfterInit};
  // The minimum amount of time in microseconds by which an ack can be delayed
  // Setting a value here also indicates to the peer that it can send
  // ACK_FREQUENCY and IMMEDIATE_ACK frames
  folly::Optional<std::chrono::microseconds> minAckDelay;
  // Limits the amount of data that should be buffered in a QuicSocket.
  // If the amount of data in the buffer equals or exceeds this amount, then
  // the callback registered through notifyPendingWriteOnConnection() will
  // not be called
  uint64_t totalBufferSpaceAvailable{kDefaultBufferSpaceAvailable};
  // Whether the endpoint allows peer to migrate to new address
  bool disableMigration{true};
  // Whether or not the socket should gracefully drain on close
  bool shouldDrain{true};
  // default stateless reset secret for stateless reset token
  folly::Optional<std::array<uint8_t, kStatelessResetTokenSecretLength>>
      statelessResetTokenSecret;
  // retry token secret used for encryption/decryption
  folly::Optional<std::array<uint8_t, kRetryTokenSecretLength>>
      retryTokenSecret;
  // Default initial RTT
  std::chrono::microseconds initialRtt{kDefaultInitialRtt};
  // The active_connection_id_limit that is sent to the peer.
  uint64_t selfActiveConnectionIdLimit{kDefaultActiveConnectionIdLimit};
  // Maximum size of the batch that should be used when receiving packets from
  // the kernel in one event loop.
  uint16_t maxRecvBatchSize{5};
  // Whether or not we should recv data in a batch.
  bool shouldRecvBatch{false};
  // Whether to use new receive path for recvmmsg.
  bool shouldUseWrapperRecvmmsgForBatchRecv{false};
  // Whether or not use recvmmsg.
  bool shouldUseRecvmmsgForBatchRecv{false};
  // Config struct for congestion controllers
  CongestionControlConfig ccaConfig;
  // A packet is considered loss when a packet that's sent later by at least
  // timeReorderingThreshold * RTT is acked by peer.
  DurationRep timeReorderingThreshDividend{
      kDefaultTimeReorderingThreshDividend};
  DurationRep timeReorderingThreshDivisor{kDefaultTimeReorderingThreshDivisor};
  // A temporary type to control DataPath write style. Will be gone after we
  // are done with experiment.
  DataPathType dataPathType{DataPathType::ChainedMemory};
  // Whether or not we should stop writing a packet after writing a single
  // stream frame to it.
  bool streamFramePerPacket{false};
  // Ensure read callbacks are ordered by Stream ID.
  bool orderedReadCallbacks{false};
  // Quic knobs
  std::vector<SerializedKnob> knobs;
  // Datagram config
  DatagramConfig datagramConfig;
  // Whether or not to opportunistically retransmit 0RTT when the handshake
  // completes.
  bool earlyRetransmit0Rtt{false};
  // Whether to issue new tokens via NewToken frames.
  bool issueNewTokens{false};
  // Used to generate the number of frames to add to short header packets.
  // Packets will have padding frames added such that the total space remaining
  // in a packet is always an increment of paddingModulo, hiding the actual
  // packet size from packet analysis.
  // Padding Modulo of 0 turns off padding for short header packets.
  size_t paddingModulo{kShortHeaderPaddingModulo};
  // Whether to use adaptive loss thresholds for reodering and timeout
  bool useAdaptiveLossReorderingThresholds{false};
  bool useAdaptiveLossTimeThresholds{false};
  // Whether to automatically increase receive conn flow control. The
  // determination is based on the frequency we are sending flow control
  // updates. If there has been less than 2SRTTs between flow control updates
  // this will double the target window.
  bool autotuneReceiveConnFlowControl{false};
  // Enable a keepalive timer. This schedules a timer to send a PING ~15%
  // before an idle timeout. To work effectively this means the idle timer
  // has to be set to something >> the RTT of the connection.
  bool enableKeepalive{false};
  std::string flowPriming = "";
  // Whether or not to enable WritableBytes limit (server only)
  bool enableWritableBytesLimit{false};
  // Whether or not to remove data from the loss buffer on spurious loss.
  bool removeFromLossBufferOnSpurious{false};
  // If set to true, the users won't get new stream notification until an
  // actual stream frame with the new stream id arrives.
  bool notifyOnNewStreamsExplicitly{false};
  // Both peers must support stream groups; negotiated during handshake.
  // 0 means stream groups are disabled.
  uint64_t advertisedMaxStreamGroups{0};
  bool experimentalPacer{false};
  // experimental flag to close ingress SM when invoking stopSending
  bool dropIngressOnStopSending{false};
  bool advertisedKnobFrameSupport{true};
  bool removeStreamAfterEomCallbackUnset{false};

  // The default priority to instantiate streams with.
  Priority defaultPriority{kDefaultPriority};

  // How many times we will a schedule a stream to packets before moving onto
  // the next one in the queue. Only relevant for incremental priority.
  uint64_t priorityQueueWritesPerStream{1};
  // Whether to include ACKs whenever we have data to write and packets to ACK.
  bool opportunisticAcking{true};

  // Local configuration for ACK receive timestamps.
  //
  // Determines the ACK receive timestamp configuration sent to peer,
  // which in turn determines the maximum number of timestamps and
  // timestamp resolution included in ACK messages sent by the peer
  // if the peer supports ACK receive timestamps.
  //
  // If structure is not initialized, ACK receive timestamps are
  // not requested from peer regardless of whether the peer
  // supports them.
  folly::Optional<AckReceiveTimestampsConfig>
      maybeAckReceiveTimestampsConfigSentToPeer;

  // Maximum number of received packet timestamps stored per ACK. This will be
  // controlled by a MC and will be dependent on device capabilities and
  // resources. Hence, this isn't contigent on whether ACK receive timestamps
  // are enabled or not and should not a part of
  //  maybeAckReceiveTimestampsConfigSentToPeer optional.
  uint64_t maxReceiveTimestampsPerAckStored{kMaxReceivedPktsTimestampsStored};
  // Close the connection completely if a migration occurs during the handshake.
  bool closeIfMigrationDuringHandshake{true};
};

} // namespace quic
