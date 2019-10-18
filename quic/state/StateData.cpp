/*
 * Copyright (c) Facebook, Inc. and its affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 *
 */

#include <quic/state/StateData.h>
#include <quic/state/QuicStreamUtilities.h>

namespace quic {

QuicStreamState::QuicStreamState(StreamId idIn, QuicConnectionStateBase& connIn)
    : conn(connIn), id(idIn) {
  // Note: this will set a windowSize for a locally-initiated unidirectional
  // stream even though that value is meaningless.
  flowControlState.windowSize = isUnidirectionalStream(idIn)
      ? conn.transportSettings.advertisedInitialUniStreamWindowSize
      : isLocalStream(connIn.nodeType, idIn)
          ? conn.transportSettings.advertisedInitialBidiLocalStreamWindowSize
          : conn.transportSettings.advertisedInitialBidiRemoteStreamWindowSize;
  flowControlState.advertisedMaxOffset = isUnidirectionalStream(idIn)
      ? conn.transportSettings.advertisedInitialUniStreamWindowSize
      : isLocalStream(connIn.nodeType, idIn)
          ? conn.transportSettings.advertisedInitialBidiLocalStreamWindowSize
          : conn.transportSettings.advertisedInitialBidiRemoteStreamWindowSize;
  // Note: this will set a peerAdvertisedMaxOffset for a peer-initiated
  // unidirectional stream even though that value is meaningless.
  flowControlState.peerAdvertisedMaxOffset = isUnidirectionalStream(idIn)
      ? conn.flowControlState.peerAdvertisedInitialMaxStreamOffsetUni
      : isLocalStream(connIn.nodeType, idIn)
          ? conn.flowControlState.peerAdvertisedInitialMaxStreamOffsetBidiRemote
          : conn.flowControlState.peerAdvertisedInitialMaxStreamOffsetBidiLocal;
  if (isUnidirectionalStream(idIn)) {
    if (isLocalStream(connIn.nodeType, idIn)) {
      recv.state = StreamReceiveStates::Invalid();
    } else {
      send.state = StreamSendStates::Invalid();
    }
  }
}

std::ostream& operator<<(std::ostream& os, const QuicConnectionStateBase& st) {
  if (st.clientConnectionId) {
    os << "client CID=" << *st.clientConnectionId;
  } else {
    os << "client CID=None";
  }
  if (st.serverConnectionId) {
    os << " server CID=" << *st.serverConnectionId;
  } else {
    os << " server CID=None";
  }
  os << " peer address=" << st.peerAddress;
  return os;
}

AckStateVersion::AckStateVersion(
    uint64_t initialVersion,
    uint64_t handshakeVersion,
    uint64_t appDataVersion)
    : initialAckStateVersion(initialVersion),
      handshakeAckStateVersion(handshakeVersion),
      appDataAckStateVersion(appDataVersion) {}

bool AckStateVersion::operator==(const AckStateVersion& other) const {
  return initialAckStateVersion == other.initialAckStateVersion &&
      handshakeAckStateVersion == other.handshakeAckStateVersion &&
      appDataAckStateVersion == other.appDataAckStateVersion;
}

bool AckStateVersion::operator!=(const AckStateVersion& other) const {
  return !operator==(other);
}

PacingRate::PacingRate(
    std::chrono::microseconds intervalIn,
    uint64_t burstSizeIn)
    : interval(intervalIn), burstSize(burstSizeIn) {}

PacingRate::Builder&& PacingRate::Builder::setInterval(
    std::chrono::microseconds intervalIn) && {
  interval_ = intervalIn;
  return std::move(*this);
}

PacingRate::Builder&& PacingRate::Builder::setBurstSize(
    uint64_t burstSizeIn) && {
  burstSize_ = burstSizeIn;
  return std::move(*this);
}

PacingRate PacingRate::Builder::build() && {
  return PacingRate(interval_, burstSize_);
}

CongestionController::AckEvent::AckPacket::AckPacket(
    TimePoint sentTimeIn,
    uint32_t encodedSizeIn,
    folly::Optional<OutstandingPacket::LastAckedPacketInfo>
        lastAckedPacketInfoIn,
    uint64_t totalBytesSentThenIn,
    bool isAppLimitedIn)
    : sentTime(sentTimeIn),
      encodedSize(encodedSizeIn),
      lastAckedPacketInfo(std::move(lastAckedPacketInfoIn)),
      totalBytesSentThen(totalBytesSentThenIn),
      isAppLimited(isAppLimitedIn) {}

CongestionController::AckEvent::AckPacket::Builder&&
CongestionController::AckEvent::AckPacket::Builder::setSentTime(
    TimePoint sentTimeIn) {
  sentTime = sentTimeIn;
  return std::move(*this);
}

CongestionController::AckEvent::AckPacket::Builder&&
CongestionController::AckEvent::AckPacket::Builder::setEncodedSize(
    uint32_t encodedSizeIn) {
  encodedSize = encodedSizeIn;
  return std::move(*this);
}

CongestionController::AckEvent::AckPacket::Builder&&
CongestionController::AckEvent::AckPacket::Builder::setLastAckedPacketInfo(
    folly::Optional<OutstandingPacket::LastAckedPacketInfo>
        lastAckedPacketInfoIn) {
  lastAckedPacketInfo = lastAckedPacketInfoIn;
  return std::move(*this);
}

CongestionController::AckEvent::AckPacket::Builder&&
CongestionController::AckEvent::AckPacket::Builder::setTotalBytesSentThen(
    uint64_t totalBytesSentThenIn) {
  totalBytesSentThen = totalBytesSentThenIn;
  return std::move(*this);
}

CongestionController::AckEvent::AckPacket::Builder&&
CongestionController::AckEvent::AckPacket::Builder::setAppLimited(
    bool appLimitedIn) {
  isAppLimited = appLimitedIn;
  return std::move(*this);
}

CongestionController::AckEvent::AckPacket
CongestionController::AckEvent::AckPacket::Builder::build() && {
  return CongestionController::AckEvent::AckPacket(
      sentTime,
      encodedSize,
      std::move(lastAckedPacketInfo),
      totalBytesSentThen,
      isAppLimited);
}

} // namespace quic
