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
} // namespace quic
