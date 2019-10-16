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
#include <iterator>

namespace quic {

/**
 * Process ack frame and acked outstanding packets.
 *
 * This function process incoming ack blocks which is sorted in the descending
 * order of packet number. For each ack block, we try to find a continuous range
 * of outstanding packets in the connection's outstanding packets list that is
 * acked by the current ack block. The search is in the reverse order of the
 * outstandingPackets given that the list is sorted in the ascending order of
 * packet number. For each outstanding packet that is acked by current ack
 * frame, ack and loss visitors are invoked on the sent frames. The outstanding
 * packets may contain packets from all three packet number spaces. But ack is
 * always restrained to a single space. So we also need to skip packets that are
 * not in the current packet number space.
 *
 */

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
  // Using kRxPacketsPendingBeforeAckThresh to reseve for ackedPackets container
  // is a hueristic. Other quic implementations may have very different acking
  // policy. It's also possibly that all acked packets are pure acks which leads
  // to different number of packets being acked usually.
  ack.ackedPackets.reserve(kRxPacketsPendingBeforeAckThresh);
  auto currentPacketIt = getLastOutstandingPacket(conn, pnSpace);
  uint64_t handshakePacketAcked = 0;
  uint64_t pureAckPacketsAcked = 0;
  uint64_t clonedPacketsAcked = 0;
  folly::Optional<decltype(conn.lossState.lastAckedPacketSentTime)>
      lastAckedPacketSentTime;
  auto ackBlockIt = frame.ackBlocks.cbegin();
  while (ackBlockIt != frame.ackBlocks.cend() &&
         currentPacketIt != conn.outstandingPackets.rend()) {
    // In reverse order, find the first outstanding packet that has a packet
    // number LE the endPacket of the current ack range.
    auto rPacketIt = std::lower_bound(
        currentPacketIt,
        conn.outstandingPackets.rend(),
        ackBlockIt->endPacket,
        [&](const auto& packetWithTime, const auto& val) {
          return packetWithTime.packet.header.getPacketSequenceNum() > val;
        });
    if (rPacketIt == conn.outstandingPackets.rend()) {
      // This means that all the packets are greater than the end packet.
      // Since we iterate the ACK blocks in reverse order of end packets, our
      // work here is done.
      VLOG(10) << __func__ << " less than all outstanding packets outstanding="
               << conn.outstandingPackets.size() << " range=["
               << ackBlockIt->startPacket << ", " << ackBlockIt->endPacket
               << "]"
               << " " << conn;
      ackBlockIt++;
      break;
    }

    // TODO: only process ACKs from packets which are sent from a greater than
    // or equal to crypto protection level.
    auto eraseEnd = rPacketIt;
    while (rPacketIt != conn.outstandingPackets.rend()) {
      auto currentPacketNum = rPacketIt->packet.header.getPacketSequenceNum();
      auto currentPacketNumberSpace =
          rPacketIt->packet.header.getPacketNumberSpace();
      if (pnSpace != currentPacketNumberSpace) {
        // When the next packet is not in the same packet number space, we need
        // to skip it in current ack processing. If the iterator has moved, that
        // means we have found packets in the current space that are acked by
        // this ack block. So the code erases the current iterator range and
        // move the iterator to be the next search point.
        if (rPacketIt != eraseEnd) {
          auto nextElem =
              conn.outstandingPackets.erase(rPacketIt.base(), eraseEnd.base());
          rPacketIt = std::reverse_iterator<decltype(nextElem)>(nextElem) + 1;
          eraseEnd = rPacketIt;
        } else {
          rPacketIt++;
          eraseEnd = rPacketIt;
        }
        continue;
      }
      if (currentPacketNum < ackBlockIt->startPacket) {
        break;
      }
      VLOG(10) << __func__ << " acked packetNum=" << currentPacketNum
               << " space=" << currentPacketNumberSpace
               << " handshake=" << (int)rPacketIt->isHandshake
               << " pureAck=" << (int)rPacketIt->pureAck << " " << conn;
      if (rPacketIt->isHandshake) {
        ++handshakePacketAcked;
      }
      if (!rPacketIt->pureAck) {
        ack.ackedBytes += rPacketIt->encodedSize;
      } else {
        ++pureAckPacketsAcked;
      }
      if (rPacketIt->associatedEvent) {
        ++clonedPacketsAcked;
      }
      // Update RTT if current packet is the largestAcked in the frame:
      auto ackReceiveTimeOrNow =
          ackReceiveTime > rPacketIt->time ? ackReceiveTime : Clock::now();
      auto rttSample = std::chrono::duration_cast<std::chrono::microseconds>(
          ackReceiveTimeOrNow - rPacketIt->time);
      if (currentPacketNum == frame.largestAcked && !rPacketIt->pureAck) {
        updateRtt(conn, rttSample, frame.ackDelay);
      }
      if (conn.qLogger) {
        conn.qLogger->addPacketAck(currentPacketNumberSpace, currentPacketNum);
      }
      QUIC_TRACE(
          packet_acked,
          conn,
          toString(currentPacketNumberSpace),
          currentPacketNum);
      // Only invoke AckVisitor if the packet doesn't have an associated
      // PacketEvent; or the PacketEvent is in conn.outstandingPacketEvents
      if (!rPacketIt->associatedEvent ||
          conn.outstandingPacketEvents.count(*rPacketIt->associatedEvent)) {
        for (auto& packetFrame : rPacketIt->packet.frames) {
          ackVisitor(*rPacketIt, packetFrame, frame);
        }
        // Remove this PacketEvent from the outstandingPacketEvents set
        if (rPacketIt->associatedEvent) {
          conn.outstandingPacketEvents.erase(*rPacketIt->associatedEvent);
        }
      }
      if (!ack.largestAckedPacket ||
          *ack.largestAckedPacket < currentPacketNum) {
        ack.largestAckedPacket = currentPacketNum;
        ack.largestAckedPacketSentTime = rPacketIt->time;
        ack.largestAckedPacketAppLimited = rPacketIt->isAppLimited;
      }
      if (ackReceiveTime > rPacketIt->time) {
        ack.mrttSample =
            std::min(ack.mrttSample.value_or(rttSample), rttSample);
      }
      conn.lossState.totalBytesAcked += rPacketIt->encodedSize;
      conn.lossState.totalBytesSentAtLastAck = conn.lossState.totalBytesSent;
      conn.lossState.totalBytesAckedAtLastAck = conn.lossState.totalBytesAcked;
      if (!lastAckedPacketSentTime) {
        lastAckedPacketSentTime = rPacketIt->time;
      }
      conn.lossState.lastAckedTime = ackReceiveTime;
      ack.ackedPackets.push_back(std::move(*rPacketIt));
      rPacketIt++;
    }
    // Done searching for acked outstanding packets in current ack block. Erase
    // the current iterator range which is the last batch of continuous
    // outstanding packets that are in this ack block. Move the iterator to be
    // the next search point.
    if (rPacketIt != eraseEnd) {
      auto nextElem =
          conn.outstandingPackets.erase(rPacketIt.base(), eraseEnd.base());
      currentPacketIt = std::reverse_iterator<decltype(nextElem)>(nextElem);
    } else {
      currentPacketIt = rPacketIt;
    }
    ackBlockIt++;
  }
  if (lastAckedPacketSentTime) {
    conn.lossState.lastAckedPacketSentTime = *lastAckedPacketSentTime;
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
