/*
 * Copyright (c) Facebook, Inc. and its affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 *
 */

#include <quic/state/AckEvent.h>

namespace quic {

AckEvent::AckPacket::AckPacket(
    OutstandingPacketMetadata&& outstandingPacketMetadataIn,
    folly::Optional<OutstandingPacket::LastAckedPacketInfo>
        lastAckedPacketInfoIn,
    bool isAppLimitedIn)
    : outstandingPacketMetadata(std::move(outstandingPacketMetadataIn)),
      lastAckedPacketInfo(std::move(lastAckedPacketInfoIn)),
      isAppLimited(isAppLimitedIn) {}

AckEvent::AckPacket::Builder&&
AckEvent::AckPacket::Builder::setOutstandingPacketMetadata(
    OutstandingPacketMetadata&& outstandingPacketMetadataIn) {
  outstandingPacketMetadata = std::move(outstandingPacketMetadataIn);
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
  return AckEvent::AckPacket(
      std::move(outstandingPacketMetadata.value()),
      std::move(lastAckedPacketInfo),
      isAppLimited);
}

} // namespace quic
