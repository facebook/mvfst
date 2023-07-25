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
  folly::Optional<PacketNum> largestAckScheduled;
  // Count of outstanding packets received with only non-retransmittable data.
  uint64_t numNonRxPacketsRecvd{0};
  // The receive time of the largest ack packet
  folly::Optional<TimePoint> largestRecvdPacketTime;
  // Largest received packet numbers on the connection.
  folly::Optional<PacketNum> largestRecvdPacketNum;
  // Latest packet number acked by peer
  folly::Optional<PacketNum> largestAckedByPeer;
  // Largest received packet number at the time we sent our last close message.
  folly::Optional<PacketNum> largestReceivedAtLastCloseSent;
  // Next PacketNum we will send for packet in this packet number space
  PacketNum nextPacketNum{0};
  // Incremented for each non-DSR packet.
  uint64_t nonDsrPacketSequenceNumber{0};
  uint64_t reorderThreshold{0};
  folly::Optional<uint64_t> tolerance;
  folly::Optional<uint64_t> ackFrequencySequenceNumber;
  // Flag indicating that if we need to send ack immediately. This will be set
  // to true in either of the following cases:
  // - we got packets with retransmittable data and haven't sent the
  // ack for the first time.
  // - the peer has requested it through an immediate ack frame.
  bool needsToSendAckImmediately{false};
  // Count of outstanding packets received with retransmittable data.
  uint8_t numRxPacketsRecvd{0};
  // Receive time of the latest packet
  folly::Optional<TimePoint> latestRecvdPacketTime;
  // Packet number of the latest packet
  folly::Optional<PacketNum> latestReceivedPacketNum;
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
