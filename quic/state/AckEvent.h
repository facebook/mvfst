/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#pragma once

#include <quic/codec/Types.h>
#include <quic/common/Optional.h>
#include <quic/congestion_control/CongestionController.h>
#include <quic/state/OutstandingPacket.h>

namespace quic {

/**
 * What a stream's ACK handling did with one ACKed WriteStreamFrame.
 *
 * processAckFrame installs one on the connection while the ACK visitor handles
 * a stream frame. The stream's ACK handler marks it handled and records the
 * bytes it newly marked delivered while updating its own delivery state, so
 * AckEvent credits exactly those bytes. Bytes the stream had already
 * delivered, holds in its loss buffer, or discarded in a reset are not newly
 * marked delivered and so are not credited.
 */
struct StreamFrameAckDelivery {
  // Set when the stream's ACK handler did its delivery bookkeeping for the
  // frame, even if no byte was newly delivered; unset if it rejected the frame.
  bool handled{false};

  // Bytes newly marked delivered, as inclusive intervals in increasing offset
  // order. A FIN carries no bytes and is not included.
  SmallVec<Interval<uint64_t>, 1> newlyDeliveredIntervals;
};

struct AckEvent {
  struct AckPacket;

  /**
   * Returns the AckPacket associated with the largestAckedPacket.
   *
   * The largestAckedPacket is included in the AckFrame received from sender.
   *
   * Can be used to get packet metadata, including send time, app limited state,
   * and other aspects.
   *
   * If the OutstandingPacketWrapper with the largestAckedPacket packet number
   * had already been acked or removed from the list of list of
   * OutstandingPackets, either due to being marked lost or acked by an earlier
   * AckEvent, then this information will be unavailable.
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
  // OutstandingPacketWrapper with this packet number had already been removed
  // from the list of OutstandingPackets, either due to being marked lost or
  // acked.
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

  // ECN mark counts reported by the peer up to and including this ACK.
  uint64_t ecnECT0Count{0};
  uint64_t ecnECT1Count{0};
  uint64_t ecnCECount{0};

  // the highest packet number newly acked during processing of this event.
  //
  // this may not be the same as the largestAckedPacket if the
  // OutstandingPacketWrapper with that packet number had already been acked or
  // removed from the list of list of OutstandingPackets, either due to being
  // marked lost or acked.
  //
  // the reason that this is an optional type is that we construct an
  // AckEvent first, then go through the acked packets that are still
  // outstanding and figure out the largest newly acked packet along the way.
  Optional<PacketNum> largestNewlyAckedPacket;

  // when largestNewlyAckedPacket was sent
  TimePoint largestNewlyAckedPacketSentTime;

  // RTT sample with ack delay included.
  //
  // not available if largestAckedPacket already acked or declared lost
  OptionalMicros rttSample;

  // RTT sample with ack delay removed.
  //
  // not available if largestAckedPacket already acked or declared lost
  OptionalMicros rttSampleNoAckDelay;

  // Congestion controller state after processing of AckEvent.
  //
  // Optional to handle cases where congestion controller not used.
  Optional<CongestionController::State> ccState;

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
      // Number of stream bytes newly marked delivered by this ACKed packet.
      uint64_t streamBytesAcked{0};

      // Number of newly delivered stream bytes carried by frames whose bytes
      // had been sent before: retransmissions, clones and PTO probes.
      uint64_t streamBytesAckedByRetrans{0};

      // A frame usually contributes a single interval, so reserve one inline.
      template <class T>
      using StreamIntervalSetVec = SmallVec<T, 1 /* stack size */>;
      using StreamIntervals = IntervalSet<uint64_t, 1, StreamIntervalSetVec>;
      using DupAckedStreamIntervals = StreamIntervals;

      // Stream intervals this ACKed packet newly marked delivered, exactly as
      // the stream recorded them; their lengths sum to `streamBytesAcked`.
      // Delivery is reported once per byte, whichever ACK delivers it.
      StreamIntervals newlyDeliveredStreamIntervals;

      // Stream intervals carried by this packet that its ACK did not newly
      // mark delivered, usually because an earlier ACK already did.
      //
      // Requires ACK processing for packets spuriously marked lost is enabled
      DupAckedStreamIntervals dupAckedStreamIntervals;
    };

    // Structure with information about each stream with frames in ACKed packet
    using MapType = InlineMap<StreamId, StreamDetails, 5>;

    class DetailsPerStream : private MapType {
     public:
      /**
       * Record the stream's report of what ACK processing of `frame` newly
       * marked delivered. Bytes of the frame that were not newly delivered are
       * recorded in `dupAckedStreamIntervals`.
       *
       * `retransmission` is whether mvfst sent the frame's bytes as a
       * retransmission, clone or PTO probe, as recorded in
       * `WriteStreamFrame::origin` when the packet was sent.
       *
       * Returns false if the report was not a list of increasing intervals
       * within the frame; only the frame's bytes are then recorded, each at
       * most once.
       */
      bool recordFrameDelivery(
          const WriteStreamFrame& frame,
          const StreamFrameAckDelivery& delivery,
          bool retransmission);

      [[nodiscard]] auto at(StreamId id) const {
        return MapType::at(id);
      }

      [[nodiscard]] auto begin() const {
        return cbegin();
      }

      [[nodiscard]] auto end() const {
        return cend();
      }

      using MapType::cbegin;
      using MapType::cend;
      using MapType::const_iterator;
      using MapType::empty;
      using MapType::find;
      using MapType::mapped_type;
      using MapType::size;
      using MapType::value_type;
    };

    // Details for each active stream that was impacted by an ACKed frame
    DetailsPerStream detailsPerStream;

    // LastAckedPacketInfo from this acked packet'r original sent
    // OutstandingPacketWrapper structure.
    Optional<OutstandingPacketWrapper::LastAckedPacketInfo> lastAckedPacketInfo;
    // Delta RX Timestamp of the current packet relative to the previous packet
    // (or connection start time).
    OptionalMicros receiveRelativeTimeStampUsec;

    // Whether this packet was sent when CongestionController is in
    // app-limited state.
    bool isAppLimited;

    // False when ACK processing skipped this packet's frames because another
    // packet carrying the same frames was already ACKed or declared lost, as
    // with a clone and its original. Such a packet credits no stream bytes.
    bool framesProcessed{true};

    // Whether this packet was the first copy of its frames to reach the peer.
    // Copies are an original packet and its clones; a retransmission of lost
    // data in a new packet is not a copy. This describes physical delivery and
    // is independent of `framesProcessed`: a clone ACKed after its original
    // was declared lost is the first arrival even though its frames are not
    // processed, and its stream bytes are credited only when mvfst later
    // delivers them.
    enum class FirstArrival : uint8_t {
      // Not a clone and never cloned, or the first copy of its clone group to
      // be acknowledged.
      Yes,
      // Another copy was acknowledged by an earlier ACK, or arrived earlier
      // according to the receive timestamps of this ACK.
      No,
      // Several copies were acknowledged by this ACK and receive timestamps
      // do not order this copy relative to the others.
      Unknown,
    };
    FirstArrival firstArrival{FirstArrival::Yes};

    struct Builder {
      Builder&& setPacketNum(quic::PacketNum packetNumIn);
      Builder&& setOutstandingPacketMetadata(
          OutstandingPacketMetadata& outstandingPacketMetadataIn);
      Builder&& setDetailsPerStream(DetailsPerStream&& detailsPerStreamIn);
      Builder&& setLastAckedPacketInfo(
          OutstandingPacketWrapper::LastAckedPacketInfo* lastAckedPacketInfoIn);
      Builder&& setAppLimited(bool appLimitedIn);
      Builder&& setReceiveDeltaTimeStamp(
          OptionalMicros&& receiveRelativeTimeStampUsec);
      Builder&& setFramesProcessed(bool framesProcessedIn);
      Builder&& setFirstArrival(FirstArrival firstArrivalIn);
      AckPacket build() &&;
      void buildInto(std::vector<AckPacket>& ackedPacketsVec) &&;
      explicit Builder() = default;

     private:
      Optional<quic::PacketNum> packetNum;
      OutstandingPacketMetadata* outstandingPacketMetadata{nullptr};
      Optional<DetailsPerStream> detailsPerStream;
      OutstandingPacketWrapper::LastAckedPacketInfo* lastAckedPacketInfo{
          nullptr};
      OptionalMicros receiveRelativeTimeStampUsec;
      bool isAppLimited{false};
      bool framesProcessed{true};
      FirstArrival firstArrival{FirstArrival::Yes};
    };

    // Better to use the Builder to construct. The reason we're not marking this
    // as private is because we need to be able to construct this in-place in
    // the AckEvent::Builder::buildInto, where we use emplace_back to emplace it
    // into the back of a vector.
    explicit AckPacket(
        quic::PacketNum packetNumIn,
        const OutstandingPacketMetadata& outstandingPacketMetadataIn, // NOLINT
        const DetailsPerStream& detailsPerStreamIn, // NOLINT
        Optional<OutstandingPacketWrapper::LastAckedPacketInfo>
            lastAckedPacketInfoIn,
        bool isAppLimitedIn,
        OptionalMicros&& receiveRelativeTimeStampUsec);
  };

  // Information about each packet ACKed during this event
  std::vector<AckPacket> ackedPackets;

  // Packets explicitly acknowledged after having previously been declared
  // lost. They are excluded from ackedPackets and ackedBytes because their
  // inflight and frame state was handled at loss time.
  uint64_t numPacketsSpuriouslyAcked{0};

  // Stream bytes newly delivered by the ACK of packets previously declared
  // lost. Only streams using the unified send buffer process those frames.
  AckPacket::DetailsPerStream spuriousLossDetailsPerStream;

  struct BuilderFields {
    Optional<TimePoint> maybeAckTime;
    Optional<TimePoint> maybeAdjustedAckTime;
    OptionalMicros maybeAckDelay;
    Optional<PacketNumberSpace> maybePacketNumberSpace;
    Optional<PacketNum> maybeLargestAckedPacket;
    bool isImplicitAck{false};
    uint64_t ecnECT0Count{0};
    uint64_t ecnECT1Count{0};
    uint64_t ecnCECount{0};
    explicit BuilderFields() = default;
  };

  struct Builder : public BuilderFields {
    Builder&& setAckTime(TimePoint ackTimeIn);
    Builder&& setAdjustedAckTime(TimePoint adjustedAckTimeIn);
    Builder&& setAckDelay(std::chrono::microseconds ackDelay);
    Builder&& setPacketNumberSpace(PacketNumberSpace packetNumberSpaceIn);
    Builder&& setLargestAckedPacket(PacketNum largestAckedPacketIn);
    Builder&& setIsImplicitAck(bool isImplicitAckIn);
    Builder&& setEcnCounts(
        uint64_t ecnECT0CountIn,
        uint64_t ecnECT1CountIn,
        uint64_t ecnCECountIn);
    AckEvent build() &&;
    explicit Builder() = default;
  };

  // Use builder to construct.
  explicit AckEvent(BuilderFields&& fields);
};

} // namespace quic
