/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#pragma once

#include <folly/Random.h>
#include <quic/QuicConstants.h>
#include <quic/codec/Types.h>
#include <quic/common/IntervalSet.h>

namespace quic {

// Ack and PacketNumber states. This is per-packet number space.
struct AckState : WriteAckFrameState {
  // Largest ack that has been written to a packet
  Optional<PacketNum> largestAckScheduled;
  // Count of outstanding packets received with only non-retransmittable data.
  uint64_t numNonRxPacketsRecvd{0};
  // The receive time of the largest ack packet
  Optional<TimePoint> largestRecvdPacketTime;
  // Largest received packet numbers on the connection.
  Optional<PacketNum> largestRecvdPacketNum;
  // Latest packet number acked by peer
  Optional<PacketNum> largestAckedByPeer;
  // Largest received packet number at the time we sent our last close message.
  Optional<PacketNum> largestReceivedAtLastCloseSent;
  // Packet sequence number for largest non-dsr packet acked by peer.
  Optional<uint64_t> largestNonDsrSequenceNumberAckedByPeer;
  // Next PacketNum we will send for packet in this packet number space
  PacketNum nextPacketNum{0};
  // Incremented for each non-DSR packet.
  uint64_t nonDsrPacketSequenceNumber{0};
  uint64_t reorderThreshold{0};
  Optional<uint64_t> tolerance;
  Optional<uint64_t> ackFrequencySequenceNumber;
  // Flag indicating that if we need to send ack immediately. This will be set
  // to true in either of the following cases:
  // - we got packets with retransmittable data and haven't sent the
  // ack for the first time.
  // - the peer has requested it through an immediate ack frame.
  bool needsToSendAckImmediately{false};
  // Count of outstanding packets received with retransmittable data.
  uint8_t numRxPacketsRecvd{0};
  // Out of the outstanding packets acked by the peer, how many were sent when
  // the connection is using ECN marking. This is used to verify that the peer
  // is correctly echoing the ECN marking in its ACKs. Note that this is a
  // minimum count because it only tracks ack-eliciting packets that we sent
  // (non-ack eliciting packets are not tracked as outstanding packets)
  uint32_t minimumExpectedEcnMarksEchoed{0};
  // The counts of ECN counts echoed by the peer.
  uint32_t ecnECT0CountEchoed{0};
  uint32_t ecnECT1CountEchoed{0};
  uint32_t ecnCECountEchoed{0};
};

struct AckStates {
  explicit AckStates(PacketNum startingNum) {
    initialAckState = std::make_unique<AckState>();
    handshakeAckState = std::make_unique<AckState>();
    initialAckState->nextPacketNum = startingNum;
    handshakeAckState->nextPacketNum = startingNum;
    appDataAckState.nextPacketNum = startingNum;
  }

  AckStates() : AckStates(folly::Random::secureRand32(kMaxInitialPacketNum)) {}

  // AckState for acks to peer packets in Initial packet number space.
  std::unique_ptr<AckState> initialAckState{};
  // AckState for acks to peer packets in Handshake packet number space.
  std::unique_ptr<AckState> handshakeAckState{};
  // AckState for acks to peer packets in AppData packet number space.
  AckState appDataAckState;
  std::chrono::microseconds maxAckDelay{kMaxAckTimeout};
};

} // namespace quic
