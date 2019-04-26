/*
 * Copyright (c) Facebook, Inc. and its affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 *
 */

#include <quic/state/AckHandlers.h>

#include <folly/Overload.h>
#include <quic/logging/QuicLogger.h>
#include <quic/loss/QuicLossFunctions.h>
#include <quic/state/QuicStateFunctions.h>

namespace quic {

void processAckFrame(
    QuicConnectionStateBase& conn,
    PacketNumberSpace pnSpace,
    const ReadAckFrame& frame,
    const AckVisitor& ackVisitor,
    const LossVisitor& lossVisitor,
    const TimePoint& ackReceiveTime) {
  DCHECK_GE(
      conn.outstandingPackets.size(), conn.outstandingPureAckPacketsCount);
  // TODO: send error if we get an ack for a packet we've not sent t18721184
  CongestionController::AckEvent ack;
  ack.ackTime = ackReceiveTime;
  auto currentPacketItStart = getFirstOutstandingPacket(conn, pnSpace);
  uint64_t handshakePacketAcked = 0;
  uint64_t pureAckPacketsAcked = 0;
  uint64_t clonedPacketsAcked = 0;
  for (auto ackBlockIt = frame.ackBlocks.crbegin();
       ackBlockIt != frame.ackBlocks.crend();
       ackBlockIt++) {
    auto packetIt = std::lower_bound(
        currentPacketItStart,
        conn.outstandingPackets.end(),
        ackBlockIt->startPacket,
        [&](const auto& packetWithTime, const auto& val) {
          return folly::variant_match(
              packetWithTime.packet.header,
              [&val](const auto& h) { return h.getPacketSequenceNum() < val; });
        });
    if (packetIt == conn.outstandingPackets.end()) {
      // This means that all the packets are less than the start packet.
      // Since we iterate the ACK blocks in order of start packets, our work
      // here is done.
      VLOG(10) << __func__
               << " larger than all outstanding packets outstanding="
               << conn.outstandingPackets.size() << " range=["
               << ackBlockIt->startPacket << ", " << ackBlockIt->endPacket
               << "]"
               << " " << conn;
      break;
    }

    // TODO: only process ACKs from packets which are sent from a greater than
    // or equal to crypto protection level.
    auto packetItEnd = packetIt;
    while (packetItEnd != conn.outstandingPackets.end()) {
      auto currentPacketNum = folly::variant_match(
          packetItEnd->packet.header,
          [](const auto& h) { return h.getPacketSequenceNum(); });
      auto currentPacketNumberSpace = folly::variant_match(
          packetItEnd->packet.header,
          [](const auto& h) { return h.getPacketNumberSpace(); });
      if (pnSpace != currentPacketNumberSpace) {
        packetItEnd++;
        continue;
      }
      if (currentPacketNum > ackBlockIt->endPacket) {
        break;
      }
      VLOG(10) << __func__ << " acked packetNum=" << currentPacketNum
               << " space=" << currentPacketNumberSpace
               << " handshake=" << (int)packetItEnd->isHandshake
               << " pureAck=" << (int)packetItEnd->pureAck << " " << conn;
      if (packetItEnd->isHandshake) {
        ++handshakePacketAcked;
      }
      if (!packetItEnd->pureAck) {
        ack.ackedBytes += packetItEnd->encodedSize;
      } else {
        ++pureAckPacketsAcked;
      }
      if (packetItEnd->associatedEvent) {
        ++clonedPacketsAcked;
      }
      // Update RTT if current packet is the largestAcked in the frame:
      auto ackReceiveTimeOrNow =
          ackReceiveTime > packetItEnd->time ? ackReceiveTime : Clock::now();
      auto rttSample = std::chrono::duration_cast<std::chrono::microseconds>(
          ackReceiveTimeOrNow - packetItEnd->time);
      if (currentPacketNum == frame.largestAcked && !packetItEnd->pureAck) {
        updateRtt(conn, rttSample, frame.ackDelay);
      }
      QUIC_TRACE(
          packet_acked,
          conn,
          toString(currentPacketNumberSpace),
          currentPacketNum);
      // Only invoke AckVisitor if the packet doesn't have an associated
      // PacketEvent; or the PacketEvent is in conn.outstandingPacketEvents
      if (!packetItEnd->associatedEvent ||
          conn.outstandingPacketEvents.count(*packetItEnd->associatedEvent)) {
        for (auto& packetFrame : packetItEnd->packet.frames) {
          ackVisitor(*packetItEnd, packetFrame, frame);
        }
        // Remove this PacketEvent from the outstandingPacketEvents set
        if (packetItEnd->associatedEvent) {
          conn.outstandingPacketEvents.erase(*packetItEnd->associatedEvent);
        }
      }
      ack.largestAckedPacket = std::max(
          ack.largestAckedPacket.value_or(currentPacketNum), currentPacketNum);
      if (ackReceiveTime > packetItEnd->time) {
        ack.mrttSample =
            std::min(ack.mrttSample.value_or(rttSample), rttSample);
      }
      conn.lossState.totalBytesAcked += packetItEnd->encodedSize;
      conn.lossState.totalBytesSentAtLastAck = conn.lossState.totalBytesSent;
      conn.lossState.totalBytesAckedAtLastAck = conn.lossState.totalBytesAcked;
      conn.lossState.lastAckedPacketSentTime = packetItEnd->time;
      conn.lossState.lastAckedTime = ackReceiveTime;
      ack.ackedPackets.push_back(std::move(*packetItEnd));
      packetItEnd = conn.outstandingPackets.erase(packetItEnd);
    }
    currentPacketItStart = packetItEnd;
  }
  DCHECK_GE(conn.outstandingHandshakePacketsCount, handshakePacketAcked);
  conn.outstandingHandshakePacketsCount -= handshakePacketAcked;
  DCHECK_GE(conn.outstandingPureAckPacketsCount, pureAckPacketsAcked);
  conn.outstandingPureAckPacketsCount -= pureAckPacketsAcked;
  DCHECK_GE(conn.outstandingClonedPacketsCount, clonedPacketsAcked);
  conn.outstandingClonedPacketsCount -= clonedPacketsAcked;
  auto updatedOustandingPacketsCount = conn.outstandingPackets.size();
  DCHECK_GE(updatedOustandingPacketsCount, conn.outstandingPureAckPacketsCount);
  DCHECK_GE(
      updatedOustandingPacketsCount, conn.outstandingHandshakePacketsCount);
  DCHECK_GE(updatedOustandingPacketsCount, conn.outstandingClonedPacketsCount);
  auto lossEvent = handleAckForLoss(conn, lossVisitor, ack, pnSpace);
  if (conn.congestionController &&
      (ack.largestAckedPacket.hasValue() || lossEvent)) {
    if (lossEvent) {
      DCHECK(lossEvent->largestLostSentTime && lossEvent->smallestLostSentTime);
      lossEvent->persistentCongestion = isPersistentCongestion(
          conn,
          *lossEvent->smallestLostSentTime,
          *lossEvent->largestLostSentTime);
    }
    conn.congestionController->onPacketAckOrLoss(
        std::move(ack), std::move(lossEvent));
  }
}

void commonAckVisitorForAckFrame(
    AckState& ackState,
    const WriteAckFrame& frame) {
  // Remove ack interval from ackState if an outstandingPacket with a AckFrame
  // is acked.
  // We may remove the current largest acked packet here, but keep its receive
  // time behind. But then right after this updateLargestReceivedPacketNum will
  // update that time stamp. Please note that this assume the peer isn't buggy
  // in the sense that packet numbers it issues are only increasing.
  auto iter = frame.ackBlocks.crbegin();
  while (iter != frame.ackBlocks.crend()) {
    ackState.acks.withdraw(*iter);
    iter++;
  }
  if (!frame.ackBlocks.empty()) {
    auto largestAcked = frame.ackBlocks.back().end;
    if (largestAcked > kAckPurgingThresh) {
      ackState.acks.withdraw({0, largestAcked - kAckPurgingThresh});
    }
  }
}
} // namespace quic
