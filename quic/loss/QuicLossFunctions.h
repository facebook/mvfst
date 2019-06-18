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
#include <quic/common/TimeUtil.h>
#include <quic/flowcontrol/QuicFlowController.h>
#include <quic/logging/QuicLogger.h>
#include <quic/state/QuicStateFunctions.h>
#include <quic/state/SimpleFrameFunctions.h>
#include <quic/state/StateData.h>

#include <folly/Overload.h>
#include <folly/io/async/AsyncTimeout.h>

namespace quic {

// Forward-declaration
bool hasAckDataToWrite(const QuicConnectionStateBase& conn);
bool hasNonAckDataToWrite(const QuicConnectionStateBase& conn);

std::chrono::microseconds calculatePTO(const QuicConnectionStateBase& conn);

/**
 * Whether conn is having persistent congestion.
 *
 * Persistent congestion requires a time period much longer than crypto timer.
 * This means no handshake packet should be in a persistent congestion range.
 * Thus persistent congestion is per pnSpace, and it's AppData space only.
 *
 */
bool isPersistentCongestion(
    const QuicConnectionStateBase& conn,
    TimePoint lostPeriodStart,
    TimePoint lostPeriodEnd) noexcept;

inline std::ostream& operator<<(
    std::ostream& os,
    const LossState::AlarmMethod& alarmMethod) {
  switch (alarmMethod) {
    case LossState::AlarmMethod::Handshake:
      os << "Handshake";
      break;
    case LossState::AlarmMethod::EarlyRetransmitOrReordering:
      os << "EarlyRetransmitOrReordering";
      break;
    case LossState::AlarmMethod::PTO:
      os << "PTO";
      break;
  }
  return os;
}

template <class ClockType = Clock>
std::pair<std::chrono::milliseconds, LossState::AlarmMethod>
calculateAlarmDuration(const QuicConnectionStateBase& conn) {
  std::chrono::microseconds alarmDuration;
  folly::Optional<LossState::AlarmMethod> alarmMethod;
  TimePoint lastSentPacketTime =
      conn.lossState.lastRetransmittablePacketSentTime;
  auto lossTimeAndSpace = earliestLossTimer(conn);
  if (lossTimeAndSpace.first) {
    if (*lossTimeAndSpace.first > lastSentPacketTime) {
      // We do this so that lastSentPacketTime + alarmDuration = lossTime
      alarmDuration = std::chrono::duration_cast<std::chrono::microseconds>(
          *lossTimeAndSpace.first - lastSentPacketTime);
    } else {
      // This should trigger an immediate alarm.
      alarmDuration = 0us;
    }
    alarmMethod = LossState::AlarmMethod::EarlyRetransmitOrReordering;
  } else if (conn.outstandingHandshakePacketsCount > 0) {
    if (conn.lossState.srtt == 0us) {
      alarmDuration = kDefaultInitialRtt * 2;
    } else {
      alarmDuration = conn.lossState.srtt * 2;
    }
    alarmDuration += conn.lossState.maxAckDelay;
    alarmDuration *=
        1 << std::min(conn.lossState.handshakeAlarmCount, (uint16_t)15);
    alarmMethod = LossState::AlarmMethod::Handshake;
    // Handshake packet loss timer shouldn't be affected by other packets.
    lastSentPacketTime = conn.lossState.lastHandshakePacketSentTime;
    DCHECK_NE(lastSentPacketTime.time_since_epoch().count(), 0);
  } else {
    auto ptoTimeout = calculatePTO(conn);
    ptoTimeout *= 1 << std::min(conn.lossState.ptoCount, (uint32_t)31);
    alarmDuration = ptoTimeout;
    alarmMethod = LossState::AlarmMethod::PTO;
  }
  TimePoint now = ClockType::now();
  std::chrono::milliseconds adjustedAlarmDuration{0};
  // The alarm duration is calculated based on the last packet that was sent
  // rather than the current time.
  if (lastSentPacketTime + alarmDuration > now) {
    adjustedAlarmDuration =
        std::chrono::duration_cast<std::chrono::milliseconds>(
            lastSentPacketTime + alarmDuration - now);
  } else {
    auto lastSentPacketNum = folly::variant_match(
        conn.outstandingPackets.back().packet.header,
        [](const auto& h) { return h.getPacketSequenceNum(); });
    VLOG(10) << __func__ << " alarm already due method=" << *alarmMethod
             << " lastSentPacketNum=" << lastSentPacketNum
             << " lastSentPacketTime="
             << lastSentPacketTime.time_since_epoch().count()
             << " now=" << now.time_since_epoch().count()
             << " alarm=" << alarmDuration.count() << "us"
             << " deadline="
             << (lastSentPacketTime + alarmDuration).time_since_epoch().count()
             << " " << conn;
  }
  DCHECK(alarmMethod.hasValue()) << "Alarm method must have a value";
  return std::make_pair(adjustedAlarmDuration, *alarmMethod);
}

/*
 * This function should be invoked after some event that is possible to change
 * the loss detection timer, for example, write happened, timeout happened or
 * packets are acked.
 */
template <class Timeout, class ClockType = Clock>
void setLossDetectionAlarm(QuicConnectionStateBase& conn, Timeout& timeout) {
  DCHECK_GE(
      conn.outstandingPackets.size(), conn.outstandingPureAckPacketsCount);
  /*
   * We might have new data or lost data to send even if we don't have any
   * outstanding packets. When we get a PTO event, it is possible that only
   * cloned packets might be outstanding. Since cwnd might be set to min cwnd,
   * we might not be able to send data. However we might still have data sitting
   * in the buffers which is unsent or known to be lost. We should set a timer
   * in this case to be able to send this data on the next PTO.
   */
  bool hasDataToWrite = hasAckDataToWrite(conn) || hasNonAckDataToWrite(conn);
  auto totalPacketsOutstanding = conn.outstandingPackets.size();
  if (totalPacketsOutstanding == conn.outstandingPureAckPacketsCount) {
    VLOG(10) << __func__ << " unset alarm pure ack only"
             << " outstanding=" << totalPacketsOutstanding
             << " handshakePackets=" << conn.outstandingHandshakePacketsCount
             << " pureAckPackets=" << conn.outstandingPureAckPacketsCount << " "
             << nodeToString(conn.nodeType) << " " << conn;
    conn.pendingEvents.setLossDetectionAlarm = false;
    timeout.cancelLossTimeout();
    return;
  }
  /*
   * We have this condition to disambiguate the case where we have.
   * (1) All outstanding packets that are clones that are processed and there
   *  is no data to write.
   * (2) All outstanding are clones that are processed and there is data to
   *  write.
   * If there are only clones with no data, then we don't need to set the timer.
   * This will free up the evb. However after a PTO verified event, clones take
   * up space in cwnd. If we have data left to write, we would not be able to
   * write them since we could be blocked by cwnd. So we must set the loss timer
   * so that we can write this data with the slack packet space for the clones.
   */
  if (!hasDataToWrite && conn.outstandingPacketEvents.empty() &&
      totalPacketsOutstanding ==
          (conn.outstandingClonedPacketsCount +
           conn.outstandingPureAckPacketsCount)) {
    VLOG(10) << __func__ << " unset alarm pure ack or processed packets only"
             << " outstanding=" << totalPacketsOutstanding
             << " handshakePackets=" << conn.outstandingHandshakePacketsCount
             << " pureAckPackets=" << conn.outstandingPureAckPacketsCount << " "
             << conn;
    conn.pendingEvents.setLossDetectionAlarm = false;
    timeout.cancelLossTimeout();
    return;
  }
  if (!conn.pendingEvents.setLossDetectionAlarm) {
    VLOG_IF(10, !timeout.isLossTimeoutScheduled())
        << __func__ << " alarm not scheduled"
        << " outstanding=" << totalPacketsOutstanding
        << " handshakePackets=" << conn.outstandingHandshakePacketsCount
        << " pureAckPackets=" << conn.outstandingPureAckPacketsCount << " "
        << nodeToString(conn.nodeType) << " " << conn;
    return;
  }
  timeout.cancelLossTimeout();
  auto alarmDuration = calculateAlarmDuration<ClockType>(conn);
  conn.lossState.currentAlarmMethod = alarmDuration.second;
  VLOG(10) << __func__ << " setting transmission"
           << " alarm=" << alarmDuration.first.count() << "ms"
           << " method=" << conn.lossState.currentAlarmMethod
           << " outstanding=" << totalPacketsOutstanding
           << " handshakePackets=" << conn.outstandingHandshakePacketsCount
           << " pureAckPackets=" << conn.outstandingPureAckPacketsCount << " "
           << nodeToString(conn.nodeType) << " " << conn;
  timeout.scheduleLossTimeout(alarmDuration.first);
  conn.pendingEvents.setLossDetectionAlarm = false;
}

/*
 * This function should be invoked after some event that is possible to
 * trigger loss detection, for example: packets are acked
 */
template <class LossVisitor>
folly::Optional<CongestionController::LossEvent> detectLossPackets(
    QuicConnectionStateBase& conn,
    PacketNum largestAcked,
    const LossVisitor& lossVisitor,
    TimePoint lossTime,
    PacketNumberSpace pnSpace) {
  getLossTime(conn, pnSpace).clear();
  std::chrono::microseconds delayUntilLost =
      std::max(conn.lossState.srtt, conn.lossState.lrtt) * 9 / 8;
  VLOG(10) << __func__ << " outstanding=" << conn.outstandingPackets.size()
           << " largestAcked=" << largestAcked
           << " delayUntilLost=" << delayUntilLost.count() << "us"
           << " " << conn;
  CongestionController::LossEvent lossEvent(lossTime);
  // Note that time based loss detection is also within the same PNSpace.
  auto iter = getFirstOutstandingPacket(conn, pnSpace);
  bool shouldSetTimer = false;
  while (iter != conn.outstandingPackets.end()) {
    auto& pkt = *iter;
    auto currentPacketNum = folly::variant_match(
        pkt.packet.header,
        [](const auto& h) { return h.getPacketSequenceNum(); });
    if (currentPacketNum >= largestAcked) {
      break;
    }
    auto currentPacketNumberSpace = folly::variant_match(
        pkt.packet.header,
        [](const auto& h) { return h.getPacketNumberSpace(); });
    if (currentPacketNumberSpace != pnSpace) {
      iter++;
      continue;
    }
    bool lost = (lossTime - pkt.time) > delayUntilLost;
    lost = lost ||
        (largestAcked - currentPacketNum) > conn.lossState.reorderingThreshold;
    if (!lost) {
      // We can exit early here because if packet N doesn't meet the
      // threshold, then packet N + 1 will not either.
      shouldSetTimer = true;
      break;
    }
    if (!pkt.pureAck) {
      lossEvent.addLostPacket(pkt);
    } else {
      DCHECK_GT(conn.outstandingPureAckPacketsCount, 0);
      --conn.outstandingPureAckPacketsCount;
    }
    if (pkt.associatedEvent) {
      DCHECK_GT(conn.outstandingClonedPacketsCount, 0);
      --conn.outstandingClonedPacketsCount;
    }
    // Invoke LossVisitor if the packet doesn't have a associated PacketEvent;
    // or if the PacketEvent is present in conn.outstandingPacketEvents.
    bool processed = pkt.associatedEvent &&
        !conn.outstandingPacketEvents.count(*pkt.associatedEvent);
    lossVisitor(conn, pkt.packet, processed, currentPacketNum);
    // Remove the PacketEvent from the outstandingPacketEvents set
    if (pkt.associatedEvent) {
      conn.outstandingPacketEvents.erase(*pkt.associatedEvent);
    }
    if (pkt.isHandshake) {
      DCHECK(conn.outstandingHandshakePacketsCount);
      --conn.outstandingHandshakePacketsCount;
    }
    VLOG(10) << __func__ << " lost packetNum=" << currentPacketNum
             << " pureAck=" << pkt.pureAck << " handshake=" << pkt.isHandshake
             << " " << conn;
    iter = conn.outstandingPackets.erase(iter);
  }

  auto earliest = getFirstOutstandingPacket(conn, pnSpace);
  for (; earliest != conn.outstandingPackets.end();
       earliest = getNextOutstandingPacket(conn, pnSpace, earliest + 1)) {
    if (!earliest->pureAck &&
        (!earliest->associatedEvent ||
         conn.outstandingPacketEvents.count(*earliest->associatedEvent))) {
      break;
    }
  }
  if (shouldSetTimer && earliest != conn.outstandingPackets.end()) {
    // We are eligible to set a loss timer and there are a few packets which
    // are unacked, so we can set the early retransmit timer for them.
    VLOG(10) << __func__ << " early retransmit timer outstanding="
             << conn.outstandingPackets.empty() << " delayUntilLost"
             << delayUntilLost.count() << "us"
             << " " << conn;
    getLossTime(conn, pnSpace) = delayUntilLost + earliest->time;
  }
  if (lossEvent.largestLostPacketNum.hasValue()) {
    DCHECK(lossEvent.largestLostSentTime && lossEvent.smallestLostSentTime);
    QUIC_TRACE(
        packets_lost,
        conn,
        *lossEvent.largestLostPacketNum,
        lossEvent.lostBytes,
        lossEvent.lostPackets);

    conn.lossState.rtxCount += lossEvent.lostPackets;
    if (conn.congestionController) {
      return lossEvent;
    }
  }
  return folly::none;
}

void onPTOAlarm(QuicConnectionStateBase& conn);

template <class LossVisitor, class ClockType = Clock>
void onHandshakeAlarm(
    QuicConnectionStateBase& conn,
    const LossVisitor& lossVisitor) {
  // TODO: This code marks all outstanding handshake packets as loss.
  // Alternatively we can experiment with only retransmit them without marking
  // loss
  VLOG(10) << __func__ << " " << conn;
  QUIC_TRACE(
      handshake_alarm,
      conn,
      conn.lossState.largestSent,
      conn.lossState.handshakeAlarmCount,
      (uint64_t)conn.outstandingHandshakePacketsCount,
      (uint64_t)conn.outstandingPackets.size());
  ++conn.lossState.handshakeAlarmCount;
  CongestionController::LossEvent lossEvent(ClockType::now());
  auto iter = conn.outstandingPackets.begin();
  while (iter != conn.outstandingPackets.end()) {
    // the word "handshake" in our code base is unfortunately overloaded.
    if (iter->isHandshake) {
      auto& packet = *iter;
      auto currentPacketNum = folly::variant_match(
          packet.packet.header,
          [](const auto& h) { return h.getPacketSequenceNum(); });
      auto currentPacketNumSpace = folly::variant_match(
          packet.packet.header,
          [](const auto& h) { return h.getPacketNumberSpace(); });
      VLOG(10) << "HandshakeAlarm, removing packetNum=" << currentPacketNum
               << " packetNumSpace=" << currentPacketNumSpace << " " << conn;
      DCHECK(!packet.pureAck);
      lossEvent.addLostPacket(std::move(packet));
      lossVisitor(conn, packet.packet, false, currentPacketNum);
      DCHECK(conn.outstandingHandshakePacketsCount);
      --conn.outstandingHandshakePacketsCount;
      ++conn.lossState.timeoutBasedRtxCount;
      ++conn.lossState.rtxCount;
      iter = conn.outstandingPackets.erase(iter);
    } else {
      iter++;
    }
  }
  if (conn.congestionController && lossEvent.largestLostPacketNum.hasValue()) {
    conn.congestionController->onRemoveBytesFromInflight(lossEvent.lostBytes);
  }
  if (conn.nodeType == QuicNodeType::Client && conn.oneRttWriteCipher) {
    // When sending client finished, we should also send a 1-rtt probe packet to
    // elicit an ack.
    conn.pendingEvents.numProbePackets = kPacketToSendForPTO;
  }
}

/*
 * Function invoked when loss detection timer fires
 */
template <class LossVisitor, class ClockType = Clock>
void onLossDetectionAlarm(
    QuicConnectionStateBase& conn,
    const LossVisitor& lossVisitor) {
  auto now = ClockType::now();
  if (conn.outstandingPackets.empty()) {
    VLOG(10) << "Transmission alarm fired with no outstanding packets " << conn;
    return;
  }
  if (conn.lossState.currentAlarmMethod ==
      LossState::AlarmMethod::EarlyRetransmitOrReordering) {
    auto lossTimeAndSpace = earliestLossTimer(conn);
    CHECK(lossTimeAndSpace.first);
    auto lossEvent = detectLossPackets<LossVisitor>(
        conn,
        getAckState(conn, lossTimeAndSpace.second).largestAckedByPeer,
        lossVisitor,
        now,
        lossTimeAndSpace.second);
    if (conn.congestionController && lossEvent) {
      DCHECK(lossEvent->largestLostSentTime && lossEvent->smallestLostSentTime);
      lossEvent->persistentCongestion = isPersistentCongestion(
          conn,
          *lossEvent->smallestLostSentTime,
          *lossEvent->largestLostSentTime);
      conn.congestionController->onPacketAckOrLoss(
          folly::none, std::move(lossEvent));
    }
  } else if (
      conn.lossState.currentAlarmMethod == LossState::AlarmMethod::Handshake) {
    onHandshakeAlarm<LossVisitor, ClockType>(conn, lossVisitor);
  } else {
    onPTOAlarm(conn);
  }
  conn.pendingEvents.setLossDetectionAlarm =
      (conn.outstandingPackets.size() > conn.outstandingPureAckPacketsCount);
  VLOG(10) << __func__ << " setLossDetectionAlarm="
           << conn.pendingEvents.setLossDetectionAlarm
           << " outstanding=" << conn.outstandingPackets.size()
           << " handshakePackets=" << conn.outstandingHandshakePacketsCount
           << " pureAckPackets=" << conn.outstandingPureAckPacketsCount << " "
           << conn;
}

/*
 * Process streams in a RegularQuicWritePacket for loss
 *
 * processed: whether this packet is a already processed clone
 */
void markPacketLoss(
    QuicConnectionStateBase& conn,
    RegularQuicWritePacket& packet,
    bool processed,
    PacketNum currentPacketNum);

template <class LossVisitor>
folly::Optional<CongestionController::LossEvent> handleAckForLoss(
    QuicConnectionStateBase& conn,
    const LossVisitor& lossVisitor,
    CongestionController::AckEvent& ack,
    PacketNumberSpace pnSpace) {
  auto& largestAcked = getAckState(conn, pnSpace).largestAckedByPeer;
  if (ack.largestAckedPacket.hasValue()) {
    // TODO: Should we NOT reset these counters if the received Ack frame
    // doesn't ack anything that's in OP list?
    conn.lossState.ptoCount = 0;
    conn.lossState.handshakeAlarmCount = 0;
    largestAcked = std::max(largestAcked, *ack.largestAckedPacket);
  }
  auto lossEvent = detectLossPackets(
      conn,
      getAckState(conn, pnSpace).largestAckedByPeer,
      lossVisitor,
      ack.ackTime,
      pnSpace);
  conn.pendingEvents.setLossDetectionAlarm =
      (conn.outstandingPackets.size() > conn.outstandingPureAckPacketsCount);
  VLOG(10) << __func__
           << " largestAckedInPacket=" << ack.largestAckedPacket.value_or(0)
           << " setLossDetectionAlarm="
           << conn.pendingEvents.setLossDetectionAlarm
           << " outstanding=" << conn.outstandingPackets.size()
           << " handshakePackets=" << conn.outstandingHandshakePacketsCount
           << " pureAckPackets=" << conn.outstandingPureAckPacketsCount << " "
           << conn;
  return lossEvent;
}

/**
 * We force mark zero rtt packets as lost during zero rtt rejection.
 */
template <class LossVisitor, class ClockType = Clock>
void markZeroRttPacketsLost(
    QuicConnectionStateBase& conn,
    const LossVisitor& lossVisitor) {
  CongestionController::LossEvent lossEvent(ClockType::now());
  auto iter = getFirstOutstandingPacket(conn, PacketNumberSpace::AppData);
  while (iter != conn.outstandingPackets.end()) {
    DCHECK(
        PacketNumberSpace::AppData ==
        folly::variant_match(iter->packet.header, [](const auto& h) {
          return h.getPacketNumberSpace();
        }));
    auto isZeroRttPacket =
        folly::variant_match(iter->packet.header, [&](const auto& h) {
          return h.getProtectionType() == ProtectionType::ZeroRtt;
        });
    if (isZeroRttPacket) {
      auto& pkt = *iter;
      DCHECK(!pkt.pureAck);
      DCHECK(!pkt.isHandshake);
      auto currentPacketNum = folly::variant_match(
          pkt.packet.header,
          [](const auto& h) { return h.getPacketSequenceNum(); });
      bool processed = pkt.associatedEvent &&
          !conn.outstandingPacketEvents.count(*pkt.associatedEvent);
      lossVisitor(conn, pkt.packet, processed, currentPacketNum);
      // Remove the PacketEvent from the outstandingPacketEvents set
      if (pkt.associatedEvent) {
        conn.outstandingPacketEvents.erase(*pkt.associatedEvent);
        DCHECK_GT(conn.outstandingClonedPacketsCount, 0);
        --conn.outstandingClonedPacketsCount;
      }
      lossEvent.addLostPacket(pkt);
      iter = conn.outstandingPackets.erase(iter);
      iter = getNextOutstandingPacket(conn, PacketNumberSpace::AppData, iter);
    } else {
      iter =
          getNextOutstandingPacket(conn, PacketNumberSpace::AppData, iter + 1);
    }
  }
  conn.lossState.rtxCount += lossEvent.lostPackets;
  if (conn.congestionController && lossEvent.largestLostPacketNum.hasValue()) {
    conn.congestionController->onRemoveBytesFromInflight(lossEvent.lostBytes);
  }
  VLOG(10) << __func__ << " marked=" << lossEvent.lostPackets;
}
} // namespace quic
