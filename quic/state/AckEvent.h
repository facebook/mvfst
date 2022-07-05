/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#pragma once

#include <folly/Optional.h>
#include <folly/container/F14Map.h>
#include <quic/codec/Types.h>
#include <quic/congestion_control/CongestionController.h>
#include <quic/state/OutstandingPacket.h>

namespace quic {

struct AckEvent {
  struct AckPacket;

  /**
   * Returns the AckPacket associated with the AckEvent's RttSample.
   *
   * Can be used to get packet metadata, including send time, app limited state,
   * and other aspects. For RTT measurements, this can be used to determine the
   * number of packets / bytes inflight at the time the corresponding packet was
   * sent, which in turn can be used to infer whether the RTT measurement could
   * have been subject to self-induced congestion.
   *
   * If the OutstandingPacket with the largestAckedPacket packet number had
   * already been acked or removed from the list of list of OutstandingPackets,
   * either due to being marked lost or acked by an earlier AckEvent, then this
   * information will be unavailable.
   *
   * Equivalent to getLargestAckedPacket() unless this is an implicit AckEvent
   * (for which RttSamples are unavailable); this helper exists to make it
   * easier to find this information.
   */
  [[nodiscard]] const AckPacket* FOLLY_NULLABLE
  getRttSampleAckedPacket() const {
    if (!rttSample) {
      return nullptr;
    }
    return getLargestAckedPacket();
  }

  /**
   * Returns the AckPacket associated with the largestAckedPacket.
   *
   * The largestAckedPacket is included in the AckFrame received from sender.
   *
   * Can be used to get packet metadata, including send time, app limited state,
   * and other aspects.
   *
   * If the OutstandingPacket with the largestAckedPacket packet number had
   * already been acked or removed from the list of list of OutstandingPackets,
   * either due to being marked lost or acked by an earlier AckEvent, then this
   * information will be unavailable.
   */
  [[nodiscard]] const AckPacket* FOLLY_NULLABLE getLargestAckedPacket() const {
    for (const auto& packet : ackedPackets) {
      if (packet.packetNum == largestAckedPacket) {
        return &packet;
      }
    }
    return nullptr;
  }

  /**
   * Returns the AckPacket associated with the largestNewlyAckedPacket.
   *
   * Can be used to get packet metadata, including send time, app limited state,
   * and other aspects.
   */
  [[nodiscard]] const AckPacket* FOLLY_NULLABLE
  getLargestNewlyAckedPacket() const {
    if (!largestNewlyAckedPacket.has_value()) {
      return nullptr;
    }
    for (const auto& packet : ackedPackets) {
      if (packet.packetNum == largestNewlyAckedPacket) {
        return &packet;
      }
    }
    return nullptr;
  }

  // ack receive time
  const TimePoint ackTime;

  // ack receive time minus ack delay.
  const TimePoint adjustedAckTime;

  // ack delay
  //
  // the ack delay is the amount of time between the remote receiving
  // largestAckedPacket and the remote generating the AckFrame associated with
  // this AckEvent.
  //
  // different AckFrame can have the same largestAckedPacket with different ack
  // blocks (ranges) in the case of reordering; under such circumstances, you
  // cannot use the ack delay if the largestAckedPacket was already acknowledged
  // by a previous AckFrame.
  const std::chrono::microseconds ackDelay;

  // packet number space that acked packets are in.
  const PacketNumberSpace packetNumberSpace;

  // the largest acked packet included in the AckFrame received from sender.
  //
  // this may not be the same as largestNewlyAckedPacket (below) if the
  // OutstandingPacket with this packet number had already been removed from the
  // list of OutstandingPackets, either due to being marked lost or acked.
  const PacketNum largestAckedPacket;

  // for all packets (newly) acked during this event, sum of encoded sizes
  // encoded size includes header and body
  //
  // this value does not directly translate to the number of stream bytes newly
  // acked; see the DetailsPerStream structure in each of the AckedPackets to
  // determine information about stream bytes.
  uint64_t ackedBytes{0};

  // total number of bytes acked on this connection after ACK processed.
  //
  // this value is the same as lossState.totalBytesAcked and does not
  // include bytea acked via implicit ACKs.
  uint64_t totalBytesAcked{0};

  // the highest packet number newly acked during processing of this event.
  //
  // this may not be the same as the largestAckedPacket if the OutstandingPacket
  // with that packet number had already been acked or removed from the list of
  // list of OutstandingPackets, either due to being marked lost or acked.
  //
  // the reason that this is an optional type is that we construct an
  // AckEvent first, then go through the acked packets that are still
  // outstanding and figure out the largest newly acked packet along the way.
  folly::Optional<PacketNum> largestNewlyAckedPacket;

  // when largestNewlyAckedPacket was sent
  TimePoint largestNewlyAckedPacketSentTime;

  // RTT sample with ack delay included.
  //
  // not available if largestAckedPacket already acked or declared lost
  folly::Optional<std::chrono::microseconds> rttSample;

  // RTT sample with ack delay removed.
  //
  // not available if largestAckedPacket already acked or declared lost
  folly::Optional<std::chrono::microseconds> rttSampleNoAckDelay;

  // Congestion controller state after processing of AckEvent.
  //
  // Optional to handle cases where congestion controller not used.
  folly::Optional<CongestionController::State> ccState;

  /**
   * Booleans grouped together to avoid padding.
   */

  // if this AckEvent came from an implicit ACK rather than a real one
  bool implicit{false};

  // whether the transport was app limited when largestNewlyAckedPacket was sent
  bool largestNewlyAckedPacketAppLimited{false};

  /**
   * Container to store information about ACKed packets
   */
  struct AckPacket {
    // Sequence number of previously outstanding (now acked) packet
    quic::PacketNum packetNum;

    // Metadata of the previously outstanding (now acked) packet
    OutstandingPacketMetadata outstandingPacketMetadata;

    struct StreamDetails {
      uint64_t streamBytesAcked{0};
      uint64_t streamBytesAckedByRetrans{0};
      folly::Optional<uint64_t> maybeNewDeliveryOffset;

      // definition for DupAckedStreamIntervalSet
      // we expect this to be rare, any thus only allocate a single position
      template <class T>
      using DupAckedStreamIntervalSetVec =
          SmallVec<T, 1 /* stack size */, uint16_t>;
      using DupAckedStreamIntervals =
          IntervalSet<uint64_t, 1, DupAckedStreamIntervalSetVec>;

      // Intervals that had already been ACKed.
      //
      // Requires ACK processing for packets spuriously marked lost is enabled
      DupAckedStreamIntervals dupAckedStreamIntervals;
    };

    // Structure with information about each stream with frames in ACKed packet
    class DetailsPerStream
        : private folly::F14FastMap<StreamId, StreamDetails> {
     public:
      /**
       * Record that a frame contained in ACKed packet was marked as delivered.
       *
       * Specifically, during processing of this ACK, we were able to fill in a
       * hole in the stream IntervalSet. This means that the intervals covered
       * by said frame had not been delivered by another packet.
       *
       * If said frame had previously been sent in some previous packet before
       * being sent in the packet that we are processing the ACK for now, then
       * we can conclude that a retransmission enabled this frame to be
       * delivered.
       *
       * See recordFrameAlreadyDelivered for the case where a frame contained in
       * an ACKed packet had already been marked as delivered.
       *
       * @param frame          The frame that is being processed.
       * @param retransmission Whether this frame was being retransmitted in the
       *                       packet being processed. If true, the frame was
       *                       previously sent in some earlier packet.
       */
      void recordFrameDelivered(
          const WriteStreamFrame& frame,
          const bool retransmission);

      /**
       * Record that a frame had already been marked as delivered.
       *
       * This can occur if said frame was sent multiple times (e.g., in multiple
       * packets) and an ACK for a different packet containing the frame was
       * already processed. More specifically,, the hole in the stream
       * IntervalSet associated with this frame was marked as delivered when
       * some other packet's ACK was processed.
       *
       * Note that packet(s) carrying the frame may have been acknowledged at
       * the same time by the remote (e.g., in the same ACK block / message), in
       * which case we cannot discern "which" packet arrived first — we can only
       * state that multiple packets(s) carrying the same frame successfully
       * reached the remote.
       *
       * @param frame          The frame that is being processed and that was
       *                       marked as delivered by some previous packet.
       * @param retransmission Whether this frame was being retransmitted in the
       *                       packet being processed. If true, the frame was
       *                       previously sent in some earlier packet. This is
       *                       generally expected to be true for the "already
       *                       delivered" scenario; the exception would be
       *                       packet reordering.
       */
      void recordFrameAlreadyDelivered(
          const WriteStreamFrame& frame,
          const bool retransmission);

      /**
       * Record a delivery offset update (increase) for a stream ID.
       */
      void recordDeliveryOffsetUpdate(StreamId streamId, uint64_t newOffset);

      [[nodiscard]] auto at(StreamId id) const {
        return folly::F14FastMap<StreamId, StreamDetails>::at(id);
      }

      [[nodiscard]] auto begin() const {
        return cbegin();
      }

      [[nodiscard]] auto end() const {
        return cend();
      }

      using folly::F14FastMap<StreamId, StreamDetails>::cbegin;
      using folly::F14FastMap<StreamId, StreamDetails>::cend;
      using folly::F14FastMap<StreamId, StreamDetails>::const_iterator;
      using folly::F14FastMap<StreamId, StreamDetails>::empty;
      using folly::F14FastMap<StreamId, StreamDetails>::find;
      using folly::F14FastMap<StreamId, StreamDetails>::mapped_type;
      using folly::F14FastMap<StreamId, StreamDetails>::size;
      using folly::F14FastMap<StreamId, StreamDetails>::value_type;
    };

    // Details for each active stream that was impacted by an ACKed frame
    DetailsPerStream detailsPerStream;

    // LastAckedPacketInfo from this acked packet'r original sent
    // OutstandingPacket structure.
    folly::Optional<OutstandingPacket::LastAckedPacketInfo> lastAckedPacketInfo;

    // Whether this packet was sent when CongestionController is in
    // app-limited state.
    bool isAppLimited;

    struct Builder {
      Builder&& setPacketNum(quic::PacketNum packetNumIn);
      Builder&& setOutstandingPacketMetadata(
          OutstandingPacketMetadata&& outstandingPacketMetadataIn);
      Builder&& setDetailsPerStream(DetailsPerStream&& detailsPerStreamIn);
      Builder&& setLastAckedPacketInfo(
          folly::Optional<OutstandingPacket::LastAckedPacketInfo>&&
              lastAckedPacketInfoIn);
      Builder&& setAppLimited(bool appLimitedIn);
      AckPacket build() &&;
      explicit Builder() = default;

     private:
      folly::Optional<quic::PacketNum> packetNum;
      folly::Optional<OutstandingPacketMetadata> outstandingPacketMetadata;
      folly::Optional<DetailsPerStream> detailsPerStream;
      folly::Optional<OutstandingPacket::LastAckedPacketInfo>
          lastAckedPacketInfo;
      bool isAppLimited{false};
    };

   private:
    explicit AckPacket(
        quic::PacketNum packetNumIn,
        OutstandingPacketMetadata&& outstandingPacketMetadataIn,
        DetailsPerStream&& detailsPerStreamIn,
        folly::Optional<OutstandingPacket::LastAckedPacketInfo>
            lastAckedPacketInfoIn,
        bool isAppLimitedIn);
  };

  // Information about each packet ACKed during this event
  std::vector<AckPacket> ackedPackets;

  struct BuilderFields {
    folly::Optional<TimePoint> maybeAckTime;
    folly::Optional<TimePoint> maybeAdjustedAckTime;
    folly::Optional<std::chrono::microseconds> maybeAckDelay;
    folly::Optional<PacketNumberSpace> maybePacketNumberSpace;
    folly::Optional<PacketNum> maybeLargestAckedPacket;
    bool isImplicitAck{false};
    explicit BuilderFields() = default;
  };

  struct Builder : public BuilderFields {
    Builder&& setAckTime(TimePoint ackTimeIn);
    Builder&& setAdjustedAckTime(TimePoint adjustedAckTimeIn);
    Builder&& setAckDelay(std::chrono::microseconds ackDelay);
    Builder&& setPacketNumberSpace(PacketNumberSpace packetNumberSpaceIn);
    Builder&& setLargestAckedPacket(PacketNum largestAckedPacketIn);
    Builder&& setIsImplicitAck(bool isImplicitAckIn);
    AckEvent build() &&;
    explicit Builder() = default;
  };

  // Use builder to construct.
  explicit AckEvent(BuilderFields&& fields);
};

} // namespace quic
