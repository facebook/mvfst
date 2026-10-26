/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <folly/MapUtil.h>
#include <quic/common/MvfstLogging.h>
#include <quic/state/AckEvent.h>
#include <algorithm>
#include <chrono>
#include <utility>

namespace quic {

bool AckEvent::AckPacket::DetailsPerStream::recordFrameDelivery(
    const WriteStreamFrame& frame,
    const StreamFrameAckDelivery& delivery,
    const bool retransmission) {
  if (!frame.len) { // may be FIN only
    return true;
  }
  auto [it, inserted] = emplace(
      std::piecewise_construct,
      std::make_tuple(frame.streamId),
      std::make_tuple());
  (void)inserted;
  auto& streamDetails = it->second;
  const auto frameEnd = frame.offset + frame.len - 1;
  auto nextOffset = frame.offset;
  bool withinFrame = true;
  uint64_t newlyDeliveredBytes{0};
  for (const auto& interval : delivery.newlyDeliveredIntervals) {
    // Streams report increasing subranges of the ACKed frame: the unified send
    // buffer clips them to the frame, and the legacy path CHECKs that the
    // retransmission chunk it delivers has the frame's offset and length.
    // Anything else is clamped so each frame byte is credited at most once.
    if (interval.start < nextOffset || interval.end > frameEnd) {
      withinFrame = false;
    }
    const auto start = std::max(interval.start, nextOffset);
    const auto end = std::min(interval.end, frameEnd);
    if (start > end) {
      continue;
    }
    if (start > nextOffset) {
      streamDetails.redeliveredStreamIntervals.insert(nextOffset, start - 1);
    }
    streamDetails.newlyDeliveredStreamIntervals.insert(start, end);
    newlyDeliveredBytes += end - start + 1;
    nextOffset = end + 1;
  }
  if (nextOffset <= frameEnd) {
    streamDetails.redeliveredStreamIntervals.insert(nextOffset, frameEnd);
  }
  streamDetails.streamBytesAcked += newlyDeliveredBytes;
  if (retransmission) {
    streamDetails.streamBytesAckedByRetrans += newlyDeliveredBytes;
  }
  return withinFrame;
}

AckEvent::AckPacket::AckPacket(
    quic::PacketNum packetNumIn,
    const OutstandingPacketMetadata& outstandingPacketMetadataIn, // NOLINT
    const DetailsPerStream& detailsPerStreamIn, // NOLINT
    Optional<OutstandingPacketWrapper::LastAckedPacketInfo>
        lastAckedPacketInfoIn,
    bool isAppLimitedIn,
    OptionalMicros&& receiveRelativeTimeStampUsec)
    : packetNum(packetNumIn),
      outstandingPacketMetadata(outstandingPacketMetadataIn), // NOLINT
      detailsPerStream(detailsPerStreamIn), // NOLINT
      lastAckedPacketInfo(std::move(lastAckedPacketInfoIn)),
      receiveRelativeTimeStampUsec(std::move(receiveRelativeTimeStampUsec)),
      isAppLimited(isAppLimitedIn) {}

AckEvent::AckPacket::Builder&& AckEvent::AckPacket::Builder::setPacketNum(
    quic::PacketNum packetNumIn) {
  packetNum = packetNumIn;
  return std::move(*this);
}

AckEvent::AckPacket::Builder&&
AckEvent::AckPacket::Builder::setOutstandingPacketMetadata(
    OutstandingPacketMetadata& outstandingPacketMetadataIn) {
  outstandingPacketMetadata = &outstandingPacketMetadataIn;
  return std::move(*this);
}

AckEvent::AckPacket::Builder&&
AckEvent::AckPacket::Builder::setDetailsPerStream(
    DetailsPerStream&& detailsPerStreamIn) {
  detailsPerStream = std::move(detailsPerStreamIn);
  return std::move(*this);
}

AckEvent::AckPacket::Builder&&
AckEvent::AckPacket::Builder::setLastAckedPacketInfo(
    OutstandingPacketWrapper::LastAckedPacketInfo* lastAckedPacketInfoIn) {
  lastAckedPacketInfo = lastAckedPacketInfoIn;
  return std::move(*this);
}

AckEvent::AckPacket::Builder&& AckEvent::AckPacket::Builder::setAppLimited(
    bool appLimitedIn) {
  isAppLimited = appLimitedIn;
  return std::move(*this);
}

AckEvent::AckPacket::Builder&&
AckEvent::AckPacket::Builder::setReceiveDeltaTimeStamp(
    OptionalMicros&& receiveTimeStampIn) {
  receiveRelativeTimeStampUsec = receiveTimeStampIn;
  return std::move(*this);
}

AckEvent::AckPacket::Builder&& AckEvent::AckPacket::Builder::setFramesProcessed(
    bool framesProcessedIn) {
  framesProcessed = framesProcessedIn;
  return std::move(*this);
}

AckEvent::AckPacket::Builder&& AckEvent::AckPacket::Builder::setFirstArrival(
    FirstArrival firstArrivalIn) {
  firstArrival = firstArrivalIn;
  return std::move(*this);
}

AckEvent::AckPacket AckEvent::AckPacket::Builder::build() && {
  MVCHECK(packetNum.has_value());
  MVCHECK(outstandingPacketMetadata);
  MVCHECK(detailsPerStream.has_value());
  auto ackPacket = AckEvent::AckPacket(
      packetNum.value(),
      *outstandingPacketMetadata,
      detailsPerStream.value(),
      lastAckedPacketInfo ? Optional<OutstandingPacket::LastAckedPacketInfo>(
                                *lastAckedPacketInfo)
                          : std::nullopt,
      isAppLimited,
      std::move(receiveRelativeTimeStampUsec));
  ackPacket.framesProcessed = framesProcessed;
  ackPacket.firstArrival = firstArrival;
  return ackPacket;
}

void AckEvent::AckPacket::Builder::buildInto(
    std::vector<AckPacket>& ackedPacketsVec) && {
  MVCHECK(packetNum.has_value());
  MVCHECK(outstandingPacketMetadata);
  MVCHECK(detailsPerStream.has_value());
  auto& ackPacket = ackedPacketsVec.emplace_back(
      packetNum.value(),
      *outstandingPacketMetadata,
      detailsPerStream.value(),
      lastAckedPacketInfo ? Optional<OutstandingPacket::LastAckedPacketInfo>(
                                *lastAckedPacketInfo)
                          : std::nullopt,
      isAppLimited,
      std::move(receiveRelativeTimeStampUsec));
  ackPacket.framesProcessed = framesProcessed;
  ackPacket.firstArrival = firstArrival;
}

AckEvent::Builder&& AckEvent::Builder::setAckTime(TimePoint ackTimeIn) {
  maybeAckTime = ackTimeIn;
  return std::move(*this);
}

AckEvent::Builder&& AckEvent::Builder::setAdjustedAckTime(
    TimePoint adjustedAckTimeIn) {
  maybeAdjustedAckTime = adjustedAckTimeIn;
  return std::move(*this);
}

AckEvent::Builder&& AckEvent::Builder::setAckDelay(
    std::chrono::microseconds ackDelayIn) {
  maybeAckDelay = ackDelayIn;
  return std::move(*this);
}

AckEvent::Builder&& AckEvent::Builder::setPacketNumberSpace(
    PacketNumberSpace packetNumberSpaceIn) {
  maybePacketNumberSpace = packetNumberSpaceIn;
  return std::move(*this);
}

AckEvent::Builder&& AckEvent::Builder::setLargestAckedPacket(
    PacketNum largestAckedPacketIn) {
  maybeLargestAckedPacket = largestAckedPacketIn;
  return std::move(*this);
}

AckEvent::Builder&& AckEvent::Builder::setIsImplicitAck(bool isImplicitAckIn) {
  isImplicitAck = isImplicitAckIn;
  return std::move(*this);
}

AckEvent::Builder&& AckEvent::Builder::setEcnCounts(
    uint64_t ecnECT0CountIn,
    uint64_t ecnECT1CountIn,
    uint64_t ecnCECountIn) {
  ecnECT0Count = ecnECT0CountIn;
  ecnECT1Count = ecnECT1CountIn;
  ecnCECount = ecnCECountIn;
  return std::move(*this);
}

AckEvent AckEvent::Builder::build() && {
  return AckEvent(std::move(*this));
}

AckEvent::AckEvent(AckEvent::BuilderFields&& builderFields)
    : ackTime([&]() {
        MVCHECK(builderFields.maybeAckTime.has_value());
        return builderFields.maybeAckTime.value();
      }()),
      adjustedAckTime([&]() {
        MVCHECK(builderFields.maybeAdjustedAckTime.has_value());
        return builderFields.maybeAdjustedAckTime.value();
      }()),
      ackDelay([&]() {
        MVCHECK(builderFields.maybeAckDelay.has_value());
        return builderFields.maybeAckDelay.value();
      }()),
      packetNumberSpace([&]() {
        MVCHECK(builderFields.maybePacketNumberSpace.has_value());
        return builderFields.maybePacketNumberSpace.value();
      }()),
      largestAckedPacket([&]() {
        MVCHECK(builderFields.maybeLargestAckedPacket.has_value());
        return builderFields.maybeLargestAckedPacket.value();
      }()),
      ecnECT0Count(builderFields.ecnECT0Count),
      ecnECT1Count(builderFields.ecnECT1Count),
      ecnCECount(builderFields.ecnCECount),
      implicit(builderFields.isImplicitAck) {}

} // namespace quic
