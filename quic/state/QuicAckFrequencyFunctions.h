/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#pragma once

#include <quic/state/StateData.h>

namespace quic {

/**
 * Check whether the peer supports ACK_FREQUENCY and IMMEDIATE_ACK frames
 */
bool canSendAckControlFrames(const QuicConnectionStateBase& conn);

/**
 * Send an ACK_FREQUENCY frame to request the peer to change its ACKing
 * behavior
 */
void requestPeerAckFrequencyChange(
    QuicConnectionStateBase& conn,
    uint64_t ackElicitingThreshold,
    std::chrono::microseconds maxAckDelay,
    uint64_t reorderThreshold);

std::chrono::microseconds clampMaxAckDelay(
    const QuicConnectionStateBase& conn,
    std::chrono::microseconds maxAckDelay);

/**
 * Send an IMMEDIATE_ACK frame to request the peer to send an ACK immediately
 */
void requestPeerImmediateAck(QuicConnectionStateBase& conn);

} // namespace quic
