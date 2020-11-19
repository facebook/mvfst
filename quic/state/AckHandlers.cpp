/*
 * Copyright (c) Facebook, Inc. and its affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 *
 */

#include <quic/state/AckHandlers.h>

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
 * outstandings.packets given that the list is sorted in the ascending order of
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
  // TODO: send error if we get an ack for a packet we've not sent t18721184
  CongestionController::AckEvent ack;
  ack.ackTime = ackReceiveTime;
  ack.implicit = frame.implicit;
  if (UNLIKELY(frame.ackDelay < 0us)) {
    LOG(ERROR) << "Quic received negative ack delay=" << frame.ackDelay.count();
    ack.adjustedAckTime = ackReceiveTime;
  } else if (UNLIKELY(frame.ackDelay > 1000s)) {
    LOG(ERROR) << "Quic very long ack delay=" << frame.ackDelay.count();
    ack.adjustedAckTime = ackReceiveTime;
  } else {
    ack.adjustedAckTime = ackReceiveTime - frame.ackDelay;
  }
  // Using kDefaultRxPacketsBeforeAckAfterInit to reseve for ackedPackets
  // container is a hueristic. Other quic implementations may have very
  // different acking policy. It's also possibly that all acked packets are pure
  // acks which leads to different number of packets being acked usually.
  ack.ackedPackets.reserve(kDefaultRxPacketsBeforeAckAfterInit);
  auto currentPacketIt = getLastOutstandingPacketIncludingLost(conn, pnSpace);
  uint64_t initialPacketAcked = 0;
  uint64_t handshakePacketAcked = 0;
  uint64_t clonedPacketsAcked = 0;
  folly::Optional<decltype(conn.lossState.lastAckedPacketSentTime)>
      lastAckedPacketSentTime;
  auto ackBlockIt = frame.ackBlocks.cbegin();
  while (ackBlockIt != frame.ackBlocks.cend() &&
         currentPacketIt != conn.outstandings.packets.rend()) {
    // In reverse order, find the first outstanding packet that has a packet
    // number LE the endPacket of the current ack range.
    auto rPacketIt = std::lower_bound(
        currentPacketIt,
        conn.outstandings.packets.rend(),
        ackBlockIt->endPacket,
        [&](const auto& packetWithTime, const auto& val) {
          return packetWithTime.packet.header.getPacketSequenceNum() > val;
        });
    if (rPacketIt == conn.outstandings.packets.rend()) {
      // This means that all the packets are greater than the end packet.
      // Since we iterate the ACK blocks in reverse order of end packets, our
      // work here is done.
      VLOG(10) << __func__ << " less than all outstanding packets outstanding="
               << conn.outstandings.numOutstanding() << " range=["
               << ackBlockIt->startPacket << ", " << ackBlockIt->endPacket
               << "]"
               << " " << conn;
      ackBlockIt++;
      break;
    }

    // TODO: only process ACKs from packets which are sent from a greater than
    // or equal to crypto protection level.
    auto eraseEnd = rPacketIt;
    while (rPacketIt != conn.outstandings.packets.rend()) {
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
          auto nextElem = conn.outstandings.packets.erase(
              rPacketIt.base(), eraseEnd.base());
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
               << " space=" << currentPacketNumberSpace << " handshake="
               << (int)((rPacketIt->metadata.isHandshake) ? 1 : 0) << " "
               << conn;
      // If we hit a packet which has been lost we need to count the spurious
      // loss and ignore all other processing.
      // TODO also remove any stream data from the loss buffer.
      if (rPacketIt->declaredLost) {
        CHECK_GT(conn.outstandings.declaredLostCount, 0);
        conn.lossState.spuriousLossCount++;
        QUIC_STATS(conn.statsCallback, onPacketSpuriousLoss);
        // Decrement the counter, trust that we will erase this as part of
        // the bulk erase.
        conn.outstandings.declaredLostCount--;
        rPacketIt++;
        continue;
      }
      bool needsProcess = !rPacketIt->associatedEvent ||
          conn.outstandings.packetEvents.count(*rPacketIt->associatedEvent);
      if (rPacketIt->metadata.isHandshake && needsProcess) {
        if (currentPacketNumberSpace == PacketNumberSpace::Initial) {
          ++initialPacketAcked;
        } else {
          CHECK_EQ(PacketNumberSpace::Handshake, currentPacketNumberSpace);
          ++handshakePacketAcked;
        }
      }
      ack.ackedBytes += rPacketIt->metadata.encodedSize;
      if (rPacketIt->associatedEvent) {
        ++clonedPacketsAcked;
      }
      // Update RTT if current packet is the largestAcked in the frame:
      auto ackReceiveTimeOrNow = ackReceiveTime > rPacketIt->metadata.time
          ? ackReceiveTime
          : Clock::now();
      auto rttSample = std::chrono::duration_cast<std::chrono::microseconds>(
          ackReceiveTimeOrNow - rPacketIt->metadata.time);
      if (!ack.implicit && currentPacketNum == frame.largestAcked) {
        InstrumentationObserver::PacketRTT packetRTT(
            ackReceiveTimeOrNow, rttSample, frame.ackDelay, *rPacketIt);
        for (const auto& observer : conn.instrumentationObservers_) {
          conn.pendingCallbacks.emplace_back(
              [observer, packetRTT](QuicSocket* qSocket) {
                observer->rttSampleGenerated(qSocket, packetRTT);
              });
        }
        updateRtt(conn, rttSample, frame.ackDelay);
      }
      // D6D probe acked. Only if it's for the last probe do we
      // trigger state change
      if (rPacketIt->metadata.isD6DProbe) {
        CHECK(conn.d6d.lastProbe);
        if (!rPacketIt->declaredLost) {
          ++conn.d6d.meta.totalAckedProbes;
          if (currentPacketNum == conn.d6d.lastProbe->packetNum) {
            onD6DLastProbeAcked(conn);
          }
        }
      }
      // Only invoke AckVisitor if the packet doesn't have an associated
      // PacketEvent; or the PacketEvent is in conn.outstandings.packetEvents
      if (needsProcess /*!rPacketIt->associatedEvent ||
          conn.outstandings.packetEvents.count(*rPacketIt->associatedEvent)*/) {
        for (auto& packetFrame : rPacketIt->packet.frames) {
          ackVisitor(*rPacketIt, packetFrame, frame);
        }
        // Remove this PacketEvent from the outstandings.packetEvents set
        if (rPacketIt->associatedEvent) {
          conn.outstandings.packetEvents.erase(*rPacketIt->associatedEvent);
        }
      }
      if (!ack.largestAckedPacket ||
          *ack.largestAckedPacket < currentPacketNum) {
        ack.largestAckedPacket = currentPacketNum;
        ack.largestAckedPacketSentTime = rPacketIt->metadata.time;
        ack.largestAckedPacketAppLimited = rPacketIt->isAppLimited;
      }
      if (!ack.implicit && ackReceiveTime > rPacketIt->metadata.time) {
        ack.mrttSample =
            std::min(ack.mrttSample.value_or(rttSample), rttSample);
      }
      if (!ack.implicit) {
        conn.lossState.totalBytesAcked += rPacketIt->metadata.encodedSize;
        conn.lossState.totalBytesSentAtLastAck = conn.lossState.totalBytesSent;
        conn.lossState.totalBytesAckedAtLastAck =
            conn.lossState.totalBytesAcked;
        if (!lastAckedPacketSentTime) {
          lastAckedPacketSentTime = rPacketIt->metadata.time;
        }
        conn.lossState.lastAckedTime = ackReceiveTime;
        conn.lossState.adjustedLastAckedTime = ackReceiveTime - frame.ackDelay;
      }
      ack.ackedPackets.push_back(
          CongestionController::AckEvent::AckPacket::Builder()
              .setSentTime(rPacketIt->metadata.time)
              .setEncodedSize(rPacketIt->metadata.encodedSize)
              .setLastAckedPacketInfo(std::move(rPacketIt->lastAckedPacketInfo))
              .setTotalBytesSentThen(rPacketIt->metadata.totalBytesSent)
              .setAppLimited(rPacketIt->isAppLimited)
              .build());
      rPacketIt++;
    }
    // Done searching for acked outstanding packets in current ack block. Erase
    // the current iterator range which is the last batch of continuous
    // outstanding packets that are in this ack block. Move the iterator to be
    // the next search point.
    if (rPacketIt != eraseEnd) {
      auto nextElem =
          conn.outstandings.packets.erase(rPacketIt.base(), eraseEnd.base());
      currentPacketIt = std::reverse_iterator<decltype(nextElem)>(nextElem);
    } else {
      currentPacketIt = rPacketIt;
    }
    ackBlockIt++;
  }
  if (lastAckedPacketSentTime) {
    conn.lossState.lastAckedPacketSentTime = *lastAckedPacketSentTime;
  }
  CHECK_GE(conn.outstandings.initialPacketsCount, initialPacketAcked);
  conn.outstandings.initialPacketsCount -= initialPacketAcked;
  CHECK_GE(conn.outstandings.handshakePacketsCount, handshakePacketAcked);
  conn.outstandings.handshakePacketsCount -= handshakePacketAcked;
  CHECK_GE(conn.outstandings.clonedPacketsCount, clonedPacketsAcked);
  conn.outstandings.clonedPacketsCount -= clonedPacketsAcked;
  CHECK_GE(
      conn.outstandings.packets.size(), conn.outstandings.declaredLostCount);
  auto updatedOustandingPacketsCount = conn.outstandings.numOutstanding();
  CHECK_GE(
      updatedOustandingPacketsCount,
      conn.outstandings.handshakePacketsCount +
          conn.outstandings.initialPacketsCount);
  CHECK_GE(updatedOustandingPacketsCount, conn.outstandings.clonedPacketsCount);
  auto lossEvent = handleAckForLoss(conn, lossVisitor, ack, pnSpace);
  if (conn.congestionController &&
      (ack.largestAckedPacket.has_value() || lossEvent)) {
    if (lossEvent) {
      CHECK(lossEvent->largestLostSentTime && lossEvent->smallestLostSentTime);
      // TODO it's not clear that we should be using the smallest and largest
      // lost times here. It may perhaps be better to only consider the latest
      // contiguous lost block and determine if that block is larger than the
      // congestion period. Alternatively we could consider every lost block
      // and check if any of them constitute persistent congestion.
      lossEvent->persistentCongestion = isPersistentCongestion(
          conn,
          *lossEvent->smallestLostSentTime,
          *lossEvent->largestLostSentTime);
      if (lossEvent->persistentCongestion) {
        QUIC_STATS(conn.statsCallback, onPersistentCongestion);
      }
    }
    conn.congestionController->onPacketAckOrLoss(
        std::move(ack), std::move(lossEvent));
  }
  clearOldOutstandingPackets(conn, ackReceiveTime, pnSpace);
}

void clearOldOutstandingPackets(
    QuicConnectionStateBase& conn,
    TimePoint time,
    PacketNumberSpace pnSpace) {
  if (conn.outstandings.declaredLostCount) {
    // Reap any old packets declared lost that are unlikely to be ACK'd.
    auto threshold = calculatePTO(conn);
    auto opItr = conn.outstandings.packets.begin();
    auto eraseBegin = opItr;
    while (opItr != conn.outstandings.packets.end()) {
      // This case can happen when we have buffered an undecryptable ACK and
      // are able to decrypt it later.
      if (time < opItr->metadata.time) {
        break;
      }
      if (opItr->packet.header.getPacketNumberSpace() != pnSpace) {
        if (eraseBegin != opItr) {
          // We want to keep [eraseBegin, opItr) within a single PN space.
          opItr = conn.outstandings.packets.erase(eraseBegin, opItr);
        }
        opItr++;
        eraseBegin = opItr;
        continue;
      }
      auto timeSinceSent = time - opItr->metadata.time;
      if (opItr->declaredLost && timeSinceSent > threshold) {
        opItr++;
        conn.outstandings.declaredLostCount--;
      } else {
        break;
      }
    }
    if (eraseBegin != opItr) {
      conn.outstandings.packets.erase(eraseBegin, opItr);
    }
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
    auto largestAcked = frame.ackBlocks.front().end;
    if (largestAcked > kAckPurgingThresh) {
      ackState.acks.withdraw({0, largestAcked - kAckPurgingThresh});
    }
  }
}
} // namespace quic
