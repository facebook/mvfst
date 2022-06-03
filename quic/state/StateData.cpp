/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <quic/state/OutstandingPacket.h>
#include <quic/state/QuicStreamUtilities.h>
#include <quic/state/StateData.h>

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
      recvState = StreamRecvState::Invalid;
    } else {
      sendState = StreamSendState::Invalid;
    }
  }
}

QuicStreamState::QuicStreamState(
    StreamId idIn,
    const folly::Optional<StreamGroupId>& groupIdIn,
    QuicConnectionStateBase& connIn)
    : QuicStreamState(idIn, connIn) {
  groupId = groupIdIn;
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

bool QuicConnectionStateBase::retireAndSwitchPeerConnectionIds() {
  const auto end = peerConnectionIds.end();
  auto replacementConnIdDataIt{end};
  auto currentConnIdDataIt{end};

  auto& mainPeerId = nodeType == QuicNodeType::Client ? serverConnectionId
                                                      : clientConnectionId;
  if (!mainPeerId) {
    throw QuicTransportException(
        "Attempting to retire null peer conn id",
        TransportErrorCode::INTERNAL_ERROR);
  }

  // Retrieve the sequence number of the current cId, and find an unused
  // ConnectionIdData.
  for (auto it = peerConnectionIds.begin(); it != end; it++) {
    if (replacementConnIdDataIt != end && currentConnIdDataIt != end) {
      break;
    }

    if (it->connId == mainPeerId) {
      currentConnIdDataIt = it;
    } else if (replacementConnIdDataIt == end) {
      replacementConnIdDataIt = it;
    }
  }
  if (replacementConnIdDataIt == end) {
    return false;
  }
  DCHECK(currentConnIdDataIt != end);
  pendingEvents.frames.push_back(
      RetireConnectionIdFrame(currentConnIdDataIt->sequenceNumber));
  mainPeerId = replacementConnIdDataIt->connId;

  peerConnectionIds.erase(currentConnIdDataIt);
  return true;
}

} // namespace quic
