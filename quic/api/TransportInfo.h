/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#pragma once

#include <quic/common/Optional.h>
#include <quic/congestion_control/CongestionController.h>

namespace quic {

/**
 * Information about the transport, similar to what TCP has.
 */
struct TransportInfo {
  // Time when the connection started.
  std::chrono::time_point<std::chrono::steady_clock> connectionTime;
  std::chrono::microseconds srtt{0us};
  std::chrono::microseconds rttvar{0us};
  std::chrono::microseconds lrtt{0us};
  OptionalMicros maybeLrtt;
  OptionalMicros maybeLrttAckDelay;
  OptionalMicros maybeMinRtt;
  OptionalMicros maybeMinRttNoAckDelay;
  uint64_t mss{kDefaultUDPSendPacketLen};
  CongestionControlType congestionControlType{CongestionControlType::None};
  uint64_t writableBytes{0};
  uint64_t congestionWindow{0};
  uint64_t pacingBurstSize{0};
  std::chrono::microseconds pacingInterval{0us};
  uint32_t packetsRetransmitted{0};
  uint32_t totalPacketsSent{0};
  uint32_t totalAckElicitingPacketsSent{0};
  uint32_t totalPacketsMarkedLost{0};
  uint32_t totalPacketsMarkedLostByTimeout{0};
  uint32_t totalPacketsMarkedLostByReorderingThreshold{0};
  uint32_t totalPacketsSpuriouslyMarkedLost{0};
  uint32_t timeoutBasedLoss{0};
  std::chrono::microseconds pto{0us};
  // Number of Bytes (packet header + body) that were sent
  uint64_t bytesSent{0};
  // Number of Bytes (packet header + body) that were acked
  uint64_t bytesAcked{0};
  // Number of Bytes (packet header + body) that were received
  uint64_t bytesRecvd{0};
  // Number of Bytes (packet header + body) that are in-flight
  uint64_t bytesInFlight{0};
  // Number of Bytes (packet header + body) that were retxed
  uint64_t totalBytesRetransmitted{0};
  // Number of Bytes (only the encoded packet's body) that were sent
  uint64_t bodyBytesSent{0};
  // Number of Bytes (only the encoded packet's body) that were acked
  uint64_t bodyBytesAcked{0};
  // Total number of stream bytes sent on this connection.
  // Includes retransmissions of stream bytes.
  uint64_t totalStreamBytesSent{0};
  // Total number of 'new' stream bytes sent on this connection.
  // Does not include retransmissions of stream bytes.
  uint64_t totalNewStreamBytesSent{0};
  uint32_t ptoCount{0};
  uint32_t totalPTOCount{0};
  Optional<uint64_t> largestPacketAckedByPeer;
  Optional<uint64_t> largestPacketSent;
  bool usedZeroRtt{false};
  // State from congestion control module, if one is installed.
  Optional<CongestionController::State> maybeCCState;
};

} // namespace quic
