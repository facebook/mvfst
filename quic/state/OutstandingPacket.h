/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#pragma once

#include <folly/io/SocketOptionMap.h>
#include <quic/codec/Types.h>
#include <quic/state/LossState.h>
#include <quic/state/PacketEvent.h>
#include <chrono>

namespace quic {

// Currently only used for TTLD marking, which is a mark indicating
// retransmitted data.
enum class OutstandingPacketMark : uint8_t {
  NONE = 0, // No marking.
  TTLD = 1, // Marked for TTL-D retransmission.
};

struct OutstandingPacketMetadata {
  // Time that the packet was sent.
  TimePoint time;
  // Total sent bytes on this connection including this packet itself when this
  // packet is sent.
  uint64_t totalBytesSent;
  // Total number of ack-eliciting packets sent on this connection.
  uint64_t totalAckElicitingPacketsSent{0};
  // Write Count is the value of the monotonically increasing counter which
  // tracks the number of writes on this socket.
  uint64_t writeCount{0};

  // Has value if the packet is lost by timeout. The value is the loss timeout
  // dividend that was used to declare this packet.
  OptionalIntegral<DurationRep> lossTimeoutDividend;

  // Has value if the packet is lost by reorder. The value is the distance
  // between this packet and the acknowleded packet when it was declared lost
  // due to reordering
  struct StreamDetails {
    template <class T>
    using IntervalSetVec = SmallVec<T, 1 /* stack size */>;
    using StreamIntervals = IntervalSet<uint64_t, 1, IntervalSetVec>;
    StreamIntervals streamIntervals;

    uint64_t streamBytesSent{0};
    uint64_t newStreamBytesSent{0};
    OptionalIntegral<uint64_t> maybeFirstNewStreamByteOffset;
  };

  using MapType = InlineMap<StreamId, StreamDetails, 1>;
  class DetailsPerStream : private MapType {
   public:
    void addFrame(const WriteStreamFrame& frame, const bool newData) {
      auto ret = emplace(
          std::piecewise_construct,
          std::make_tuple(frame.streamId),
          std::make_tuple());
      auto& streamDetails = ret.first->second;

      if (frame.len) { // could be zero byte if just contains a fin
        streamDetails.streamIntervals.insert(
            StreamDetails::StreamIntervals::interval_type(
                frame.offset, frame.offset + frame.len - 1));
      }
      streamDetails.streamBytesSent += frame.len;
      if (newData) {
        streamDetails.newStreamBytesSent += frame.len;
        if (streamDetails.maybeFirstNewStreamByteOffset) {
          streamDetails.maybeFirstNewStreamByteOffset = std::min(
              frame.offset, *streamDetails.maybeFirstNewStreamByteOffset);
        } else {
          streamDetails.maybeFirstNewStreamByteOffset = frame.offset;
        }
      }
    }

    [[nodiscard]] auto at(StreamId id) const {
      return MapType::at(id);
    }

    using MapType::begin;
    using MapType::cbegin;
    using MapType::cend;
    using MapType::const_iterator;
    using MapType::empty;
    using MapType::end;
    using MapType::find;
    using MapType::mapped_type;
    using MapType::size;
    using MapType::value_type;
  };

  // Details about each stream with frames in this packet
  DetailsPerStream detailsPerStream;

  // Total time spent app limited on this connection including when this packet
  // was sent.
  std::chrono::microseconds totalAppLimitedTimeUsecs{0};

  OptionalIntegral<uint16_t> lossReorderDistance;

  // Bytes in flight on this connection including this packet itself when this
  // packet is sent.
  uint32_t inflightBytes;
  // Size of the packet sent on the wire.
  uint16_t encodedSize;
  // Size of only the body within the packet sent on the wire.
  uint16_t encodedBodySize;

  bool scheduledForDestruction : 1;

  OutstandingPacketMark mark : 7;

  OutstandingPacketMetadata(
      TimePoint timeIn,
      uint16_t encodedSizeIn,
      uint16_t encodedBodySizeIn,
      uint64_t totalBytesSentIn,
      uint32_t inflightBytesIn,
      const LossState& lossStateIn,
      uint64_t writeCount,
      DetailsPerStream&& detailsPerStream,
      std::chrono::microseconds totalAppLimitedTimeUsecsIn = 0us)
      : time(timeIn),
        totalBytesSent(totalBytesSentIn),
        totalAckElicitingPacketsSent(lossStateIn.totalAckElicitingPacketsSent),
        writeCount(writeCount),
        detailsPerStream(std::move(detailsPerStream)),
        totalAppLimitedTimeUsecs(totalAppLimitedTimeUsecsIn),
        inflightBytes(inflightBytesIn),
        encodedSize(encodedSizeIn),
        encodedBodySize(encodedBodySizeIn),
        scheduledForDestruction(false),
        mark(OutstandingPacketMark::NONE) {}
};

// Data structure to represent outstanding retransmittable packets
struct OutstandingPacket {
  using Metadata = OutstandingPacketMetadata;

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
  Optional<LastAckedPacketInfo> lastAckedPacketInfo;

  // PacketEvent associated with this OutstandingPacketWrapper. This will be a
  // none if the packet isn't a clone and hasn't been cloned.
  Optional<PacketEvent> associatedEvent;

  OptionalIntegral<uint64_t> nonDsrPacketSequenceNumber;

  // Whether this is a DSR packet. A DSR packet's stream data isn't written
  // by transport directly.
  bool isDSRPacket : 1;

  /**
   * Whether the packet is sent when congestion controller is in app-limited
   * state.
   */
  bool isAppLimited : 1;

  // True if spurious loss detection is enabled and this packet was declared
  // lost.
  bool declaredLost : 1;

  quic::PacketNum getPacketSequenceNum() const {
    return packet.header.getPacketSequenceNum();
  }

 protected:
  OutstandingPacket(
      RegularQuicWritePacket packetIn,
      TimePoint timeIn,
      uint16_t encodedSizeIn,
      uint16_t encodedBodySizeIn,
      uint64_t totalBytesSentIn,
      uint32_t inflightBytesIn,
      const LossState& lossStateIn,
      uint64_t writeCount,
      Metadata::DetailsPerStream&& detailsPerStream,
      std::chrono::microseconds totalAppLimitedTimeUsecs = 0us)
      : packet(std::move(packetIn)),
        metadata(OutstandingPacketMetadata(
            timeIn,
            encodedSizeIn,
            encodedBodySizeIn,
            totalBytesSentIn,
            inflightBytesIn,
            lossStateIn,
            writeCount,
            std::move(detailsPerStream),
            totalAppLimitedTimeUsecs)) {
    // TODO remove when C++20 everywhere.
    isDSRPacket = false;
    isAppLimited = false;
    declaredLost = false;
  }

  OutstandingPacket(OutstandingPacket&&) = default;

  OutstandingPacket& operator=(OutstandingPacket&&) = default;

  OutstandingPacket() = delete;
};

struct OutstandingPacketWrapper : OutstandingPacket {
  std::function<void(const quic::OutstandingPacketWrapper&)> packetDestroyFn_ =
      nullptr;

  OutstandingPacketWrapper(
      RegularQuicWritePacket packetIn,
      TimePoint timeIn,
      uint16_t encodedSizeIn,
      uint16_t encodedBodySizeIn,
      uint64_t totalBytesSentIn,
      uint32_t inflightBytesIn,
      const LossState& lossStateIn,
      uint64_t writeCount,
      Metadata::DetailsPerStream&& detailsPerStream,
      std::chrono::microseconds totalAppLimitedTimeUsecs = 0us,
      std::function<void(const quic::OutstandingPacketWrapper&)>
          packetDestroyFn = nullptr)
      : OutstandingPacket(
            std::move(packetIn),
            timeIn,
            encodedSizeIn,
            encodedBodySizeIn,
            totalBytesSentIn,
            inflightBytesIn,
            lossStateIn,
            writeCount,
            std::move(detailsPerStream),
            totalAppLimitedTimeUsecs),
        packetDestroyFn_(std::move(packetDestroyFn)) {}

  OutstandingPacketWrapper(const OutstandingPacketWrapper& source) = delete;
  OutstandingPacketWrapper& operator=(const OutstandingPacketWrapper&) = delete;

  OutstandingPacketWrapper(OutstandingPacketWrapper&& rhs) noexcept = default;

  OutstandingPacketWrapper& operator=(OutstandingPacketWrapper&& rhs) noexcept {
    // If this->packetDestroyFn_ is populated, then this OutstandingPacket is
    // populated. We must call packetDestroyFn_(this) first, before moving the
    // rest of the fields from the source packet (rhs).

    if (this != &rhs && packetDestroyFn_ != nullptr) {
      packetDestroyFn_(*this);
    }

    packetDestroyFn_ = std::move(rhs.packetDestroyFn_);
    OutstandingPacket::operator=(std::move(rhs));
    return *this;
  }

  ~OutstandingPacketWrapper() {
    if (packetDestroyFn_) {
      packetDestroyFn_(*this);
    }
  }
};
} // namespace quic
