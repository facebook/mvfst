/*
 * Copyright (c) Facebook, Inc. and its affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 *
 */

#include <folly/MapUtil.h>
#include <quic/state/AckEvent.h>

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
    OutstandingPacketMetadata&& outstandingPacketMetadataIn,
    DetailsPerStream&& detailsPerStreamIn,
    folly::Optional<OutstandingPacket::LastAckedPacketInfo>
        lastAckedPacketInfoIn,
    bool isAppLimitedIn)
    : outstandingPacketMetadata(std::move(outstandingPacketMetadataIn)),
      detailsPerStream(std::move(detailsPerStreamIn)),
      lastAckedPacketInfo(std::move(lastAckedPacketInfoIn)),
      isAppLimited(isAppLimitedIn) {}

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
  CHECK(outstandingPacketMetadata.has_value());
  CHECK(detailsPerStream.has_value());
  return AckEvent::AckPacket(
      std::move(outstandingPacketMetadata.value()),
      std::move(detailsPerStream.value()),
      std::move(lastAckedPacketInfo),
      isAppLimited);
}

} // namespace quic
