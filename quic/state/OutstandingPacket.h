/*
 * Copyright (c) Facebook, Inc. and its affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 *
 */

#pragma once

#include <quic/codec/Types.h>
#include <quic/state/PacketEvent.h>

namespace quic {

struct OutstandingPacketMetadata {
  // Time that the packet was sent.
  TimePoint time;
  // Size of the packet sent on the wire.
  uint32_t encodedSize;
  // Whether this packet has any data from stream 0
  bool isHandshake;
  // Whether the packet is a d6d probe
  bool isD6DProbe;
  // Total sent bytes on this connection including this packet itself when this
  // packet is sent.
  uint64_t totalBytesSent;
  // Bytes in flight on this connection including this packet itself when this
  // packet is sent.
  uint64_t inflightBytes;

  OutstandingPacketMetadata(
      TimePoint timeIn,
      uint32_t encodedSizeIn,
      bool isHandshakeIn,
      bool isD6DProbeIn,
      uint64_t totalBytesSentIn,
      uint64_t inflightBytesIn)
      : time(std::move(timeIn)),
        encodedSize(encodedSizeIn),
        isHandshake(isHandshakeIn),
        isD6DProbe(isD6DProbeIn),
        totalBytesSent(totalBytesSentIn),
        inflightBytes(inflightBytesIn) {}
};

// Data structure to represent outstanding retransmittable packets
struct OutstandingPacket {
  // Structure representing the frames that are outstanding including the header
  // that was sent.
  RegularQuicWritePacket packet;
  // Structure representing a collection of metrics and important information
  // about the packet.
  OutstandingPacketMetadata metadata;
  // Information regarding the last acked packet on this connection when this
  // packet is sent.
  struct LastAckedPacketInfo {
    TimePoint sentTime;
    TimePoint ackTime;
    TimePoint adjustedAckTime;
    // Total sent bytes on this connection when the last acked packet is acked.
    uint64_t totalBytesSent;
    // Total acked bytes on this connection when last acked packet is acked,
    // including the last acked packet.
    uint64_t totalBytesAcked;

    LastAckedPacketInfo(
        TimePoint sentTimeIn,
        TimePoint ackTimeIn,
        TimePoint adjustedAckTimeIn,
        uint64_t totalBytesSentIn,
        uint64_t totalBytesAckedIn)
        : sentTime(sentTimeIn),
          ackTime(ackTimeIn),
          adjustedAckTime(adjustedAckTimeIn),
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

  // True if spurious loss detection is enabled and this packet was declared
  // lost.
  bool declaredLost{false};

  // True if packet was declared lost due to timeout.
  bool lostByTimeout{false};

  // True if packet was declared lost due to reordering.
  bool lostByReorder{false};

  OutstandingPacket(
      RegularQuicWritePacket packetIn,
      TimePoint timeIn,
      uint32_t encodedSizeIn,
      bool isHandshakeIn,
      uint64_t totalBytesSentIn,
      uint64_t inflightBytesIn)
      : packet(std::move(packetIn)),
        metadata(OutstandingPacketMetadata(
            std::move(timeIn),
            encodedSizeIn,
            isHandshakeIn,
            false,
            totalBytesSentIn,
            inflightBytesIn)) {}

  OutstandingPacket(
      RegularQuicWritePacket packetIn,
      TimePoint timeIn,
      uint32_t encodedSizeIn,
      bool isHandshakeIn,
      bool isD6DProbeIn,
      uint64_t totalBytesSentIn,
      uint64_t inflightBytesIn)
      : packet(std::move(packetIn)),
        metadata(OutstandingPacketMetadata(
            std::move(timeIn),
            encodedSizeIn,
            isHandshakeIn,
            isD6DProbeIn,
            totalBytesSentIn,
            inflightBytesIn)) {}
};
} // namespace quic
