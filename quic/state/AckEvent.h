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
#include <quic/state/OutstandingPacket.h>

namespace quic {

struct AckEvent {
  // ack receive time
  const TimePoint ackTime;

  // ack receive time minus ack delay
  const TimePoint adjustedAckTime;

  // ack delay (equal to ackTime - adjustedAckTime)
  const std::chrono::microseconds ackDelay;

  // packet number space that (newly) acked packets are in
  const PacketNumberSpace packetNumberSpace;

  // for all packets (newly) acked during this event, sum of encoded sizes
  // encoded size includes header and body
  //
  // this value does not directly translate to the number of stream bytes newly
  // acked; see the DetailsPerStream structure in each of the AckedPackets to
  // determine information about stream bytes.
  uint64_t ackedBytes{0};

  // the highest packet number newly acked by this event.
  //
  // this may not be the same as the largestAckedPacket in the ackFrame if the
  // corresponding outstanding packet had already been acked or removed from the
  // list of outstanding packets because we concluded that it was lost.
  //
  // the reason that this is an optional type is that we construct an
  // AckEvent first, then go through the acked packets that are still
  // outstanding and figure out the largest newly acked packet along the way.
  folly::Optional<PacketNum> largestNewlyAckedPacket;

  // when largestNewlyAckedPacket was sent
  TimePoint largestNewlyAckedPacketSentTime;

  // RTT sample, not available if largestAckedPacket was already acked
  folly::Optional<std::chrono::microseconds> rttSample;

  // RTT sample with ack delay removed,
  // not available if largestAckedPacket was already acked
  folly::Optional<std::chrono::microseconds> rttSampleNoAckDelay;

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
    bool isImplicitAck{false};
    explicit BuilderFields() = default;
  };

  struct Builder : public BuilderFields {
    Builder&& setAckTime(TimePoint ackTimeIn);
    Builder&& setAdjustedAckTime(TimePoint adjustedAckTimeIn);
    Builder&& setAckDelay(std::chrono::microseconds ackDelay);
    Builder&& setPacketNumberSpace(PacketNumberSpace packetNumberSpaceIn);
    Builder&& setIsImplicitAck(bool isImplicitAckIn);
    AckEvent build() &&;
    explicit Builder() = default;
  };

  // Use builder to construct.
  explicit AckEvent(BuilderFields&& fields);
};

} // namespace quic
