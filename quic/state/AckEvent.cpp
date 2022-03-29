/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <folly/MapUtil.h>
#include <quic/state/AckEvent.h>
#include <utility>

namespace quic {

void AckEvent::AckPacket::DetailsPerStream::recordFrameDelivered(
    const WriteStreamFrame& frame,
    const bool retransmission) {
  if (!frame.len) { // may be FIN only
    return;
  }
  auto [it, inserted] = emplace(
      std::piecewise_construct,
      std::make_tuple(frame.streamId),
      std::make_tuple());
  auto& outstandingPacketStreamDetails = it->second;
  outstandingPacketStreamDetails.streamBytesAcked += frame.len;
  if (retransmission) {
    outstandingPacketStreamDetails.streamBytesAckedByRetrans += frame.len;
  }
}

void AckEvent::AckPacket::DetailsPerStream::recordFrameAlreadyDelivered(
    const WriteStreamFrame& frame,
    const bool /* retransmission */) {
  if (!frame.len) { // may be FIN only
    return;
  }
  auto [it, inserted] = try_emplace(frame.streamId);
  auto& outstandingPacketStreamDetails = it->second;
  outstandingPacketStreamDetails.dupAckedStreamIntervals.insert(
      frame.offset, frame.offset + frame.len - 1);
}

void AckEvent::AckPacket::DetailsPerStream::recordDeliveryOffsetUpdate(
    StreamId streamId,
    uint64_t newOffset) {
  auto [it, inserted] = try_emplace(streamId);
  auto& outstandingPacketStreamDetails = it->second;
  CHECK(
      !outstandingPacketStreamDetails.maybeNewDeliveryOffset.has_value() ||
      outstandingPacketStreamDetails.maybeNewDeliveryOffset.value() <
          newOffset);
  outstandingPacketStreamDetails.maybeNewDeliveryOffset = newOffset;
}

AckEvent::AckPacket::AckPacket(
    quic::PacketNum packetNumIn,
    OutstandingPacketMetadata&& outstandingPacketMetadataIn,
    DetailsPerStream&& detailsPerStreamIn,
    folly::Optional<OutstandingPacket::LastAckedPacketInfo>
        lastAckedPacketInfoIn,
    bool isAppLimitedIn)
    : packetNum(packetNumIn),
      outstandingPacketMetadata(std::move(outstandingPacketMetadataIn)),
      detailsPerStream(std::move(detailsPerStreamIn)),
      lastAckedPacketInfo(std::move(lastAckedPacketInfoIn)),
      isAppLimited(isAppLimitedIn) {}

AckEvent::AckPacket::Builder&& AckEvent::AckPacket::Builder::setPacketNum(
    quic::PacketNum packetNumIn) {
  packetNum = packetNumIn;
  return std::move(*this);
}

AckEvent::AckPacket::Builder&&
AckEvent::AckPacket::Builder::setOutstandingPacketMetadata(
    OutstandingPacketMetadata&& outstandingPacketMetadataIn) {
  outstandingPacketMetadata = std::move(outstandingPacketMetadataIn);
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
    folly::Optional<OutstandingPacket::LastAckedPacketInfo>&&
        lastAckedPacketInfoIn) {
  lastAckedPacketInfo = std::move(lastAckedPacketInfoIn);
  return std::move(*this);
}

AckEvent::AckPacket::Builder&& AckEvent::AckPacket::Builder::setAppLimited(
    bool appLimitedIn) {
  isAppLimited = appLimitedIn;
  return std::move(*this);
}

AckEvent::AckPacket AckEvent::AckPacket::Builder::build() && {
  CHECK(packetNum.has_value());
  CHECK(outstandingPacketMetadata.has_value());
  CHECK(detailsPerStream.has_value());
  return AckEvent::AckPacket(
      packetNum.value(),
      std::move(outstandingPacketMetadata.value()),
      std::move(detailsPerStream.value()),
      std::move(lastAckedPacketInfo),
      isAppLimited);
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

AckEvent AckEvent::Builder::build() && {
  return AckEvent(std::move(*this));
}

AckEvent::AckEvent(AckEvent::BuilderFields&& builderFields)
    : ackTime(*CHECK_NOTNULL(builderFields.maybeAckTime.get_pointer())),
      adjustedAckTime(
          *CHECK_NOTNULL(builderFields.maybeAdjustedAckTime.get_pointer())),
      ackDelay(*CHECK_NOTNULL(builderFields.maybeAckDelay.get_pointer())),
      packetNumberSpace(
          *CHECK_NOTNULL(builderFields.maybePacketNumberSpace.get_pointer())),
      largestAckedPacket(
          *CHECK_NOTNULL(builderFields.maybeLargestAckedPacket.get_pointer())),
      implicit(builderFields.isImplicitAck) {}

} // namespace quic
