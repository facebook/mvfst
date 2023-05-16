/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#pragma once

#include <quic/codec/Types.h>
#include <quic/common/EnumArray.h>

namespace quic {

struct LossState {
  enum class AlarmMethod { EarlyRetransmitOrReordering, PTO };
  // Latest packet number sent
  // TODO: this also needs to be 3 numbers now...
  folly::Optional<PacketNum> largestSent;
  // Timer for time reordering detection or early retransmit alarm.
  EnumArray<PacketNumberSpace, folly::Optional<TimePoint>> lossTimes;
  // Max ack delay received from peer.
  std::chrono::microseconds maxAckDelay{0us};
  // minimum rtt. AckDelay isn't excluded from this.
  std::chrono::microseconds mrtt{kDefaultMinRtt};
  // minimum rtt measured from samples with AckDelay excluded.
  folly::Optional<std::chrono::microseconds> maybeMrttNoAckDelay;
  // Last raw RTT value; unlike lrtt, this will always contain any ACK delay.
  folly::Optional<std::chrono::microseconds> maybeLrtt;
  // Last raw ACK delay value.
  folly::Optional<std::chrono::microseconds> maybeLrttAckDelay;
  // Smooth rtt.
  std::chrono::microseconds srtt{0us};
  // Latest rtt.
  std::chrono::microseconds lrtt{0us};
  // Rtt var.
  std::chrono::microseconds rttvar{0us};
  // The sent time of the latest acked packet.
  folly::Optional<TimePoint> lastAckedPacketSentTime;
  // The latest time a packet is acked.
  folly::Optional<TimePoint> lastAckedTime;
  // The latest time a packet is acked, minus ack delay.
  folly::Optional<TimePoint> adjustedLastAckedTime;
  // The time when last retranmittable packet is sent for every packet number.
  // space
  TimePoint lastRetransmittablePacketSentTime;
  // The time when the last packet was sent.
  folly::Optional<TimePoint> maybeLastPacketSentTime;
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

  // Total number of body bytes sent on this connection. This is after encoding.
  uint64_t totalBodyBytesSent{0};
  // Total number of body bytes acked on this connection. If a packet is acked
  // twice, it won't be count twice. Pure acks packets are NOT included (as they
  // have no encoded body bytes).
  uint64_t totalBodyBytesAcked{0};

  // Total number of stream bytes sent on this connection.
  // Includes retransmissions of stream bytes.
  uint64_t totalStreamBytesSent{0};
  // Total number of 'new' stream bytes sent on this connection.
  // Does not include retransmissions of stream bytes.
  //
  // Equal to ConnectionFlowControlState::sumCurWriteOffset, stored here as well
  // to colocate with other related vars to assist with interpreting LossState.
  uint64_t totalNewStreamBytesSent{0};

  // Total number of packets sent on this connection, including retransmissions.
  uint32_t totalPacketsSent{0};
  // Total number of ack-eliciting packets sent on this connection.
  uint32_t totalAckElicitingPacketsSent{0};
  // Total number of packets which were declared lost, including losses that
  // we later detected were spurious (see totalPacketsSpuriouslyMarkedLost).
  uint32_t totalPacketsMarkedLost{0};
  // Total number of packets which were declared lost due to a timeout; a packet
  // can be marked as lost by multiple detection mechanisms.
  uint32_t totalPacketsMarkedLostByTimeout{0};
  // Total number of packets which were declared lost based on the reordering
  // threshold; a packet can be marked as lost by multiple detection mechanisms.
  uint32_t totalPacketsMarkedLostByReorderingThreshold{0};
  // Total number of packets which were declared lost spuriously, i.e. we
  // received an ACK for them later.
  uint32_t totalPacketsSpuriouslyMarkedLost{0};
  // Inflight bytes
  uint64_t inflightBytes{0};
  // Reordering threshold used
  uint32_t reorderingThreshold{kReorderingThreshold};
  // Number of packet loss timer fired before receiving an ack
  uint32_t ptoCount{0};
  // Total number of packet retransmitted on this connection, including packet
  // clones, retransmitted clones, handshake and rejected zero rtt packets.
  uint32_t rtxCount{0};
  // Total number of retransmission due to PTO
  uint32_t timeoutBasedRtxCount{0};
  // Total number of PTO count
  uint32_t totalPTOCount{0};
  // Current method by which the loss detection alarm is set.
  AlarmMethod currentAlarmMethod{AlarmMethod::EarlyRetransmitOrReordering};
  // Whether early retransmission of 0-rtt packets has been attempted
  bool attemptedEarlyRetransmit0Rtt{false};
};
} // namespace quic
