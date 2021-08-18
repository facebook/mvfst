/*
 * Copyright (c) Facebook, Inc. and its affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 *
 */

#pragma once

#include <quic/QuicConstants.h>
#include <quic/codec/Types.h>
#include <quic/state/StateData.h>
#include <functional>

namespace quic {

using AckVisitor = std::function<
    void(const OutstandingPacket&, const QuicWriteFrame&, const ReadAckFrame&)>;

using LossVisitor = std::function<
    void(QuicConnectionStateBase&, RegularQuicWritePacket&, bool)>;

/**
 * Processes an ack frame and removes any outstanding packets
 * from the connection that have already been sent.
 */
void processAckFrame(
    QuicConnectionStateBase& conn,
    PacketNumberSpace pnSpace,
    const ReadAckFrame& ackFrame,
    const AckVisitor& ackVisitor,
    const LossVisitor& lossVisitor,
    const TimePoint& ackReceiveTime);

/**
 * Clears outstanding packets marked as lost that are not likely to be ACKed
 * (have been lost for >= 1 PTO).
 */
void clearOldOutstandingPackets(
    QuicConnectionStateBase& outstandings,
    TimePoint time,
    PacketNumberSpace pnSpace);

/**
 * Visitor function to be invoked when we receive an ACK of the WriteAckFrame
 * that we sent.
 */
void commonAckVisitorForAckFrame(
    AckState& ackState,
    const WriteAckFrame& frame);

/**
 * Helper function to remove packets from the outstanding queue. If there
 * is at least one observer with the callback for removed packets we move these
 * packets to another container and remove the invalid positions from the
 * outsdanding queue.
 */
std::deque<quic::OutstandingPacket>::iterator removeOutstandingPackets(
    QuicConnectionStateBase& conn,
    std::deque<quic::OutstandingPacket>::iterator begin,
    std::deque<quic::OutstandingPacket>::iterator end);
} // namespace quic
