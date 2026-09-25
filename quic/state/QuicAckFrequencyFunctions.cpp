/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <quic/common/MvfstLogging.h>
#include <quic/common/TimeUtil.h>
#include <quic/state/QuicAckFrequencyFunctions.h>

namespace quic {
namespace {
constexpr auto kMaxRequestedAckDelay =
    std::chrono::duration_cast<std::chrono::microseconds>(
        std::chrono::milliseconds(kMaxAckDelay - 1));
} // namespace

bool canSendAckControlFrames(const QuicConnectionStateBase& conn) {
  return conn.peerMinAckDelay.has_value();
}

void requestPeerAckFrequencyChange(
    QuicConnectionStateBase& conn,
    uint64_t ackElicitingThreshold,
    std::chrono::microseconds maxAckDelay,
    uint64_t reorderThreshold) {
  MVCHECK(conn.peerMinAckDelay.has_value());
  if (*conn.peerMinAckDelay > kMaxRequestedAckDelay) {
    return;
  }
  maxAckDelay = clampMaxAckDelay(conn, maxAckDelay);
  AckFrequencyFrame frame;
  frame.packetTolerance = ackElicitingThreshold;
  frame.updateMaxAckDelay = maxAckDelay.count();
  frame.reorderThreshold = reorderThreshold;
  frame.sequenceNumber = conn.nextAckFrequencyFrameSequenceNumber++;
  conn.pendingEvents.frames.emplace_back(frame);
  conn.peerMaxAckDelay = timeMax(conn.peerMaxAckDelay, maxAckDelay);
}

std::chrono::microseconds clampMaxAckDelay(
    const QuicConnectionStateBase& conn,
    std::chrono::microseconds maxAckDelay) {
  MVCHECK(conn.peerMinAckDelay.has_value());
  return timeMin(
      timeMax(maxAckDelay, conn.peerMinAckDelay.value()),
      kMaxRequestedAckDelay);
}

/**
 * Send an IMMEDIATE_ACK frame to request the peer to send an ACK immediately
 */
void requestPeerImmediateAck(QuicConnectionStateBase& conn) {
  MVCHECK(conn.peerMinAckDelay.has_value());
  conn.pendingEvents.requestImmediateAck = true;
}
} // namespace quic
