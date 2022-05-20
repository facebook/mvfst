/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#pragma once

#include <quic/QuicConstants.h>
#include <quic/codec/QuicConnectionId.h>
#include <quic/d6d/Types.h>
#include <chrono>

namespace quic {

struct BbrConfig {
  bool conservativeRecovery{false};

  /**
   * When largeProbeRttCwnd is true, kLargeProbeRttCwndGain * BDP will be used
   * as cwnd during ProbeRtt state, otherwise, 4MSS will be the ProbeRtt cwnd.
   */
  bool largeProbeRttCwnd{false};

  // Whether ack aggregation is also calculated during Startup phase
  bool enableAckAggregationInStartup{false};

  /**
   * Whether we should enter ProbeRtt if connection has been app-limited since
   * last time we ProbeRtt.
   */
  bool probeRttDisabledIfAppLimited{false};

  /**
   * Whether BBR should advance pacing gain cycle when BBR is draining and we
   * haven't reached the drain target.
   */
  bool drainToTarget{false};
};

struct CcpConfig {
  std::string alg_name = "";
  std::string alg_args = "";
};

struct D6DConfig {
  /**
   * Currently, only server does probing, so this flags means different things
   * for server and client. For server, it means whether it should enable d6d
   * when it receives the base PMTU transport parameter. For client, it means
   * whether it will send the base PMTU transport parameter during handshake.
   * As a result, d6d is activated for a connection only when *both* client and
   * server enables d6d.
   *
   * TODO: Please make sure QuicConnectionStateBase::D6DState::outstandingProbes
   * are mutated correctly throughout Mvfst.
   */
  bool enabled{false};

  /**
   * Base PMTU that client advertises to server. This is needed because
   * depending on the situation there are clients who want to start from a
   * larger/smaller base PMTU. Server makes no use of this value, but should
   * rely on the transport parameter received from client.
   */
  uint16_t advertisedBasePMTU{kDefaultD6DBasePMTU};

  /**
   * The number of "big" packet losses we can tolerate before signalling PMTU
   * blackhole.
   */
  uint64_t blackholeDetectionThreshold{kDefaultD6DBlackholeDetectionThreshold};

  /**
   * The constant pmtu step size used for ConstantStep probe size raiser
   */
  uint16_t probeRaiserConstantStepSize{kDefaultD6DProbeStepSize};

  /**
   * The D6D raise timeout that client advertises to server. We might need to
   * tune this value for different paths. Again, server makes no use of this
   * value, but should rely on the transport parameter.
   */
  std::chrono::seconds advertisedRaiseTimeout{kDefaultD6DRaiseTimeout};

  /**
   * The D6D probe timeout. When it expires, we either send another
   * probe with the same size, or sleep for raise timeout, depending
   * on the d6d state. There are other events (e.g. probe gets acked
   * or probe is determined lost) that might cancel this timeout.
   * Client sends this value as a transport parameter during
   * handshake.
   */
  std::chrono::seconds advertisedProbeTimeout{kDefaultD6DProbeTimeout};

  /**
   * The moving window within which we check if the detection threshold has been
   * crossed
   */
  std::chrono::seconds blackholeDetectionWindow{
      kDefaultD6DBlackholeDetectionWindow};

  /**
   * Default raiser is constant step , since overshot caused by binary
   * search slows down convergence. Might change in the future when we
   * have more context.
   */
  ProbeSizeRaiserType raiserType{ProbeSizeRaiserType::ConstantStep};
};

struct DatagramConfig {
  bool enabled{false};
  bool framePerPacket{true};
  bool recvDropOldDataFirst{false};
  bool sendDropOldDataFirst{false};
  uint32_t readBufSize{kDefaultMaxDatagramsBuffered};
  uint32_t writeBufSize{kDefaultMaxDatagramsBuffered};
};

// JSON-serialized transport knobs
struct SerializedKnob {
  uint64_t space;
  uint64_t id;
  std::string blob;
};

struct TransportSettings {
  // The initial connection window advertised to the peer.
  uint64_t advertisedInitialConnectionWindowSize{kDefaultConnectionWindowSize};
  // The initial window size of the stream advertised to the peer.
  uint64_t advertisedInitialBidiLocalStreamWindowSize{kDefaultStreamWindowSize};
  uint64_t advertisedInitialBidiRemoteStreamWindowSize{
      kDefaultStreamWindowSize};
  uint64_t advertisedInitialUniStreamWindowSize{kDefaultStreamWindowSize};
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
  // Whether to listen to socket error
  bool enableSocketErrMsgCallback{true};
  // Whether pacing is enabled.
  bool pacingEnabled{false};
  // The minimum number of packets to burst out during pacing
  uint64_t minBurstPackets{kDefaultMinBurstPackets};
  // Pacing timer tick interval
  std::chrono::microseconds pacingTimerTickInterval{
      kDefaultPacingTimerTickInterval};
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
  size_t maxRecvBatchSize{5};
  // Whether or not we should recv data in a batch.
  bool shouldRecvBatch{false};
  // Whether or not use recvmmsg when shouldRecvBatch is true.
  bool shouldUseRecvmmsgForBatchRecv{false};
  // Config struct for BBR
  BbrConfig bbrConfig;
  // Config struct for CCP
  CcpConfig ccpConfig;
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
  // Config struct for D6D
  D6DConfig d6dConfig;
  // Quic knobs
  std::vector<SerializedKnob> knobs;
  // Datagram config
  DatagramConfig datagramConfig;
  // Whether or not to opportunistically retransmit 0RTT when the handshake
  // completes.
  bool earlyRetransmit0Rtt{false};
  // Whether to use JumpStarter as the CongestionControllerFactory
  bool useJumpStart{false};
  // Whether to issue new tokens via NewToken frames.
  bool issueNewTokens{false};
  // Used to generate the number of frames to add to short header packets.
  // Packets will have padding frames added such that the total space remaining
  // in a packet is always an increment of paddingModulo, hiding the actual
  // packet size from packet analysis.
  // Padding Modulo of 0 turns off padding for short header packets.
  size_t paddingModulo{kShortHeaderPaddingModulo};
  // Whether to use adaptive loss thresholds for reodering and timeout
  bool useAdaptiveLossThresholds{false};
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
};

} // namespace quic
