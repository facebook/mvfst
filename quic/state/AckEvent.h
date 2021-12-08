/*
 * Copyright (c) Facebook, Inc. and its affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 *
 */

#pragma once

#include <quic/codec/Types.h>
#include <quic/state/OutstandingPacket.h>

#include <folly/Optional.h>

namespace quic {

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

  /**
   * Container to store information about ACKed packets
   */
  struct AckPacket {
    // Metadata of the previously outstanding (now acked) packet
    OutstandingPacketMetadata outstandingPacketMetadata;

    // LastAckedPacketInfo from this acked packet'r original sent
    // OutstandingPacket structure.
    folly::Optional<OutstandingPacket::LastAckedPacketInfo> lastAckedPacketInfo;

    // Whether this packet was sent when CongestionController is in
    // app-limited state.
    bool isAppLimited;

    struct Builder {
      Builder&& setOutstandingPacketMetadata(
          OutstandingPacketMetadata&& metadata);
      Builder&& setLastAckedPacketInfo(
          folly::Optional<OutstandingPacket::LastAckedPacketInfo>&&
              lastAckedPacketInfoIn);
      Builder&& setAppLimited(bool appLimitedIn);
      AckPacket build() &&;
      explicit Builder() = default;

     private:
      folly::Optional<OutstandingPacketMetadata> outstandingPacketMetadata;
      folly::Optional<OutstandingPacket::LastAckedPacketInfo>
          lastAckedPacketInfo;
      bool isAppLimited{false};
    };

   private:
    explicit AckPacket(
        OutstandingPacketMetadata&& outstandingPacketMetadataIn,
        folly::Optional<OutstandingPacket::LastAckedPacketInfo>
            lastAckedPacketInfoIn,
        bool isAppLimitedIn);
  };

  // Information about each packet ACKed during this event
  std::vector<AckPacket> ackedPackets;
};

} // namespace quic
