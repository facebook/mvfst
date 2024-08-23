/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <folly/MapUtil.h>
#include <quic/state/AckEvent.h>
#include <chrono>
#include <utility>

namespace quic {

void AckEvent::AckPacket::DetailsPerStream::recordFrameDelivered(
    const WriteStreamFrame& frame) {
  if (!frame.len) { // may be FIN only
    return;
  }
  auto [it, inserted] = emplace(
      std::piecewise_construct,
      std::make_tuple(frame.streamId),
      std::make_tuple());
  auto& outstandingPacketStreamDetails = it->second;
  if (frame.fromBufMeta) {
    outstandingPacketStreamDetails.streamPacketIdx = frame.streamPacketIdx;
  }
}

void AckEvent::AckPacket::DetailsPerStream::recordFrameAlreadyDelivered(
    const WriteStreamFrame& frame) {
  if (!frame.len) { // may be FIN only
    return;
  }
  auto [it, inserted] = emplace(
      std::piecewise_construct,
      std::make_tuple(frame.streamId),
      std::make_tuple());

  auto& outstandingPacketStreamDetails = it->second;
  outstandingPacketStreamDetails.dupAckedStreamIntervals.insert(
      frame.offset, frame.offset + frame.len - 1);
  if (frame.fromBufMeta) {
    outstandingPacketStreamDetails.streamPacketIdx = frame.streamPacketIdx;
  }
}

AckEvent::AckPacket::AckPacket(
    quic::PacketNum packetNumIn,
    uint64_t nonDsrPacketSequenceNumberIn,
    const OutstandingPacketMetadata& outstandingPacketMetadataIn, // NOLINT
    const DetailsPerStream& detailsPerStreamIn, // NOLINT
    Optional<OutstandingPacketWrapper::LastAckedPacketInfo>
        lastAckedPacketInfoIn,
    bool isAppLimitedIn,
    OptionalMicros&& receiveRelativeTimeStampUsec)
    : packetNum(packetNumIn),
      nonDsrPacketSequenceNumber(nonDsrPacketSequenceNumberIn),
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
AckEvent::AckPacket::Builder::setNonDsrPacketSequenceNumber(
    uint64_t nonDsrPacketSequenceNumberIn) {
  nonDsrPacketSequenceNumber = nonDsrPacketSequenceNumberIn;
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

AckEvent::AckPacket AckEvent::AckPacket::Builder::build() && {
  CHECK(packetNum.has_value());
  CHECK(outstandingPacketMetadata);
  CHECK(detailsPerStream.has_value());
  return AckEvent::AckPacket(
      packetNum.value(),
      nonDsrPacketSequenceNumber.value(),
      *outstandingPacketMetadata,
      detailsPerStream.value(),
      lastAckedPacketInfo ? Optional<OutstandingPacket::LastAckedPacketInfo>(
                                *lastAckedPacketInfo)
                          : none,
      isAppLimited,
      std::move(receiveRelativeTimeStampUsec));
}

void AckEvent::AckPacket::Builder::buildInto(
    std::vector<AckPacket>& ackedPacketsVec) && {
  CHECK(packetNum.has_value());
  CHECK(outstandingPacketMetadata);
  CHECK(detailsPerStream.has_value());
  ackedPacketsVec.emplace_back(
      packetNum.value(),
      nonDsrPacketSequenceNumber.value(),
      *outstandingPacketMetadata,
      detailsPerStream.value(),
      lastAckedPacketInfo ? Optional<OutstandingPacket::LastAckedPacketInfo>(
                                *lastAckedPacketInfo)
                          : none,
      isAppLimited,
      std::move(receiveRelativeTimeStampUsec));
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
    uint32_t ecnECT0CountIn,
    uint32_t ecnECT1CountIn,
    uint32_t ecnCECountIn) {
  ecnECT0Count = ecnECT0CountIn;
  ecnECT1Count = ecnECT1CountIn;
  ecnCECount = ecnCECountIn;
  return std::move(*this);
}

AckEvent AckEvent::Builder::build() && {
  return AckEvent(std::move(*this));
}

AckEvent::AckEvent(AckEvent::BuilderFields&& builderFields)
    : ackTime(*CHECK_NOTNULL(builderFields.maybeAckTime.get_pointer())),
      adjustedAckTime(
          *CHECK_NOTNULL(builderFields.maybeAdjustedAckTime.get_pointer())),
      ackDelay(builderFields.maybeAckDelay.value()),
      packetNumberSpace(
          *CHECK_NOTNULL(builderFields.maybePacketNumberSpace.get_pointer())),
      largestAckedPacket(
          *CHECK_NOTNULL(builderFields.maybeLargestAckedPacket.get_pointer())),
      ecnECT0Count(builderFields.ecnECT0Count),
      ecnECT1Count(builderFields.ecnECT1Count),
      ecnCECount(builderFields.ecnCECount),
      implicit(builderFields.isImplicitAck) {}

} // namespace quic
