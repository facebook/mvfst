/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <quic/common/TimeUtil.h>
#include <quic/state/QuicAckFrequencyFunctions.h>

namespace quic {

bool canSendAckControlFrames(const QuicConnectionStateBase& conn) {
  return conn.peerMinAckDelay.has_value();
}

void requestPeerAckFrequencyChange(
    QuicConnectionStateBase& conn,
    uint64_t ackElicitingThreshold,
    std::chrono::microseconds maxAckDelay,
    uint64_t reorderThreshold) {
  CHECK(conn.peerMinAckDelay.has_value());
  AckFrequencyFrame frame;
  frame.packetTolerance = ackElicitingThreshold;
  frame.updateMaxAckDelay = maxAckDelay.count();
  frame.reorderThreshold = reorderThreshold;
  frame.sequenceNumber = conn.nextAckFrequencyFrameSequenceNumber++;
  conn.pendingEvents.frames.push_back(frame);
}

std::chrono::microseconds clampMaxAckDelay(
    const QuicConnectionStateBase& conn,
    std::chrono::microseconds maxAckDelay) {
  CHECK(conn.peerMinAckDelay.has_value());
  return timeMax(maxAckDelay, conn.peerMinAckDelay.value());
}

/**
 * Send an IMMEDIATE_ACK frame to request the peer to send an ACK immediately
 */
void requestPeerImmediateAck(QuicConnectionStateBase& conn) {
  CHECK(conn.peerMinAckDelay.has_value());
  conn.pendingEvents.requestImmediateAck = true;
}
} // namespace quic
