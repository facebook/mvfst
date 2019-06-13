/*
 * Copyright (c) Facebook, Inc. and its affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 *
 */

#pragma once

#include <quic/QuicConstants.h>
#include <chrono>

namespace quic {

struct TransportSettings {
  // The initial connection window advertised to the peer.
  uint64_t advertisedInitialConnectionWindowSize{kDefaultConnectionWindowSize};
  // The initial window size of the stream advertised to the peer.
  uint64_t advertisedInitialBidiLocalStreamWindowSize{kDefaultStreamWindowSize};
  uint64_t advertisedInitialBidiRemoteStreamWindowSize{
      kDefaultStreamWindowSize};
  uint64_t advertisedInitialUniStreamWindowSize{kDefaultStreamWindowSize};
  uint64_t advertisedInitialMaxStreamsBidi{
      std::numeric_limits<uint32_t>::max()};
  uint64_t advertisedInitialMaxStreamsUni{std::numeric_limits<uint32_t>::max()};
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
  // used by COPA.
  folly::Optional<double> latencyFactor;
  // The max UDP packet size we are willing to receive.
  uint64_t maxRecvPacketSize{kDefaultUDPReadBufferSize};
  // Can we ignore the path mtu when sending a packet. This is useful for
  // testing.
  bool canIgnorePathMTU{false};
  // Whether or not to use a connected UDP socket on the client. This should
  // only be used in environments where you know your IP address does not
  // change. See AsyncUDPSocket::connect for the caveats.
  bool connectUDP{false};
  // Maximum number of consecutive PTOs before the connection is torn down.
  uint16_t maxNumPTOs{kDefaultMaxNumPTO};
  // Whether to turn off PMTUD on the socket
  bool turnoffPMTUD{false};
  // Whether to listen to socket error
  bool enableSocketErrMsgCallback{true};
  // Whether pacing is enabled.
  bool pacingEnabled{false};
  // Whether pacing is also used in Recovery state in congestion controller
  bool pacingEnabledForRecovery{false};
  // The maximum number of packets to burst out during pacing
  uint64_t maxBurstPackets{kDefaultMaxBurstPackets};
  // Pacing timer tick interval
  std::chrono::microseconds pacingTimerTickInterval{
      kDefaultPacingTimerTickInterval};
  ZeroRttSourceTokenMatchingPolicy zeroRttSourceTokenMatchingPolicy{
      ZeroRttSourceTokenMatchingPolicy::LIMIT_IF_NO_EXACT_MATCH};
  bool attemptEarlyData{true};
  // Maximum number of packets the connection will write in
  // writeConnectionDataToSocket.
  uint64_t writeConnectionDataPacketsLimit{
      kDefaultWriteConnectionDataPacketLimit};
  // Frequency of sending flow control updates. We can send one update every
  // flowControlRttFrequency * RTT if the flow control changes.
  uint16_t flowControlRttFrequency{2};
  // Frequency of sending flow control updates. We can send one update every
  // flowControlWindowFrequency * window if the flow control changes.
  uint16_t flowControlWindowFrequency{2};
  // batching mode
  QuicBatchingMode batchingMode{QuicBatchingMode::BATCHING_MODE_NONE};
  // maximum number of packets we can batch. This does not apply to
  // BATCHING_MODE_NONE
  uint32_t maxBatchSize{kDefaultQuicMaxBatchSize};
  // Sets network unreachable to be a non fatal error. In some environments,
  // EHOSTUNREACH or ENETUNREACH could just be because the routing table is
  // being setup. This option makes those non fatal connection errors.
  bool continueOnNetworkUnreachable{false};
  // Amount of time for which the transport treats ENETUNREACH/EHOSTUNREACH as
  // non-fatal error since the first error is seen. If transport still sees the
  // error after this amount of time, it'll throw and report the error. This is
  // to minimize the negative impact on user experience for real no network
  // case, so that errors are only delayed to be reported for 200ms, which
  // should be invisible to end users.
  // Choosing 150ms because loss timer fires at the 100ms for the first time.
  std::chrono::milliseconds continueOnNetworkUnreachableDuration{150};
  // Initial congestion window in MSS
  uint64_t initCwndInMss{kInitCwndInMss};
  // Minimum congestion window in MSS
  uint64_t minCwndInMss{kMinCwndInMss};
  // Maximum congestion window in MSS
  uint64_t maxCwndInMss{kDefaultMaxCwndInMss};
  // Limited congestion window in MSS
  uint64_t limitedCwndInMss{kLimitedCwndInMss};
  // Limits the amount of data that should be buffered in a QuicSocket.
  // If the amount of data in the buffer equals or exceeds this amount, then
  // the callback registered through notifyPendingWriteOnConnection() will
  // not be called
  uint64_t totalBufferSpaceAvailable{kDefaultBufferSpaceAvailable};
  // Whether or not to advertise partial reliability capability
  bool partialReliabilityEnabled{false};
  // Whether the endpoint allows peer to migrate to new address
  bool disableMigration{true};
  // default stateless reset secret for stateless reset token
  folly::Optional<std::array<uint8_t, kStatelessResetTokenSecretLength>>
      statelessResetTokenSecret;
};

} // namespace quic
