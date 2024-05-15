/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#pragma once

#include <quic/QuicConstants.h>
#include <quic/codec/Types.h>
#include <quic/state/StateData.h>
#include <functional>

namespace quic {

using AckVisitor = std::function<void(
    const OutstandingPacketWrapper&,
    const QuicWriteFrame&,
    const ReadAckFrame&)>;

using AckedPacketVisitor = std::function<void(
    const OutstandingPacketWrapper&)>; // outstanding packet acked

using AckedFrameVisitor = std::function<void(
    const OutstandingPacketWrapper&, // outstanding packet acked
    const QuicWriteFrame&)>; // outstanding frame acked

/**
 * Processes an ack frame and removes any outstanding packets.
 */
void removeOutstandingsForAck(
    QuicConnectionStateBase& conn,
    PacketNumberSpace pnSpace,
    const ReadAckFrame& frame);

/**
 * Processes an ack frame and removes any outstanding packets
 * from the connection that have already been sent.
 *
 * Returns AckEvent with information about what was observed during processing
 */
AckEvent processAckFrame(
    QuicConnectionStateBase& conn,
    PacketNumberSpace pnSpace,
    const ReadAckFrame& ackFrame,
    const AckedPacketVisitor& ackedPacketVisitor,
    const AckedFrameVisitor& ackedFrameVisitor,
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
 * Parse Receive timestamps from ACK frame into a folly::F14FastMap of packet
 * number to timestamps and return the latest received packet with timestamp if
 * any.
 */
void parseAckReceiveTimestamps(
    const QuicConnectionStateBase& conn,
    const quic::ReadAckFrame& frame,
    folly::F14FastMap<PacketNum, uint64_t>& packetReceiveTimeStamps,
    folly::Optional<PacketNum> firstPacketNum);

/**
 * Update the outgoing ECN marking count for an outstanding packet that has been
 * acked. If a packet is acked and the connection is using ECN/L4S, this
 * function updates the ackState to expect more ECN marks to be echoed by the
 * peer.
 *
 * Note: that we don't track the value of the actual mark sent in the packet.
 * (1) This is fine because we do not allow the ECN mark to change during the
 * lifetime of a connection. It can only be turned off if ECN marking validation
 * fails.
 * (2) This avoids adding more fields to the outstanding packet metadata.
 *
 * Note: Since only ack-eliciting packets are tracked as outstanding packets,
 * the ECN count tracked by this function is only a minimum. Non-ack eliciting
 * packets that are acked will not hit this function.
 */
void incrementEcnCountForAckedPacket(
    QuicConnectionStateBase& conn,
    PacketNumberSpace pnSpace);

/**
 * Update the ECN counts echoed by the pear in its ACK frame
 */
void updateEcnCountEchoed(
    QuicConnectionStateBase& conn,
    PacketNumberSpace pnSpace,
    const ReadAckFrame& readAckFrame);
} // namespace quic
