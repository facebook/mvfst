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

std::chrono::microseconds calculateRTO(const QuicConnectionStateBase& conn);

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
    case LossState::AlarmMethod::RTO:
      os << "RTO";
      break;
  }
  return os;
}

template <class ClockType = Clock>
std::pair<std::chrono::milliseconds, LossState::AlarmMethod>
calculateAlarmDuration(const QuicConnectionStateBase& conn) {
  std::chrono::microseconds alarmDuration;
  folly::Optional<LossState::AlarmMethod> alarmMethod;
  TimePoint lastSentPacketTime = conn.outstandingPackets.back().time;
  if (conn.outstandingHandshakePacketsCount > 0) {
    if (conn.lossState.srtt == std::chrono::microseconds(0)) {
      alarmDuration = kDefaultInitialRtt * 2;
    } else {
      alarmDuration = conn.lossState.srtt * 2;
    }
    // TODO: kMinTLPTimeout will be gone in later diff
    alarmDuration =
        timeMax(conn.lossState.maxAckDelay + alarmDuration, kMinTLPTimeout);
    alarmDuration *=
        1 << std::min(conn.lossState.handshakeAlarmCount, (uint16_t)15);
    alarmMethod = LossState::AlarmMethod::Handshake;
    // Handshake packet loss timer shouldn't be affected by other packets.
    lastSentPacketTime = conn.lossState.lastHandshakePacketSentTime;
    DCHECK_NE(lastSentPacketTime.time_since_epoch().count(), 0);
  } else if (conn.lossState.lossTime) {
    if (*conn.lossState.lossTime > lastSentPacketTime) {
      alarmDuration = std::chrono::duration_cast<std::chrono::microseconds>(
          *conn.lossState.lossTime - lastSentPacketTime);
    } else {
      // This should trigger an immediate alarm.
      alarmDuration = std::chrono::microseconds(0);
    }
    alarmMethod = LossState::AlarmMethod::EarlyRetransmitOrReordering;
  } else {
    auto rtoTimeout = calculateRTO(conn);
    rtoTimeout *= 1 << std::min(conn.lossState.rtoCount, (uint32_t)31);
    alarmDuration = rtoTimeout;
    alarmMethod = LossState::AlarmMethod::RTO;
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
   * outstanding packets. When we get an RTO event, it is possible that only
   * cloned packets might be outstanding. Since cwnd might be set to min cwnd,
   * we might not be able to send data. However we might still have data sitting
   * in the buffers which is unsent or known to be lost. We should set a timer
   * in this case to be able to send this data on the next RTO.
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
  // TODO: updating outstandingClonedPacketsCount will be in followup diffs.
  /*
   * We have this condition to disambiguate the case where we have.
   * (1) All outstanding packets that are clones that are processed and there
   *  is no data to write.
   * (2) All outstanding are clones that are processed and there is data to
   *  write.
   * If there are only clones with no data, then we don't need to set the timer.
   * This will free up the evb. However after an RTO verified event, clones take
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
template <class LossVisitor, class ClockType = Clock>
folly::Optional<CongestionController::LossEvent> detectLossPackets(
    QuicConnectionStateBase& conn,
    PacketNum largestAcked,
    const LossVisitor& lossVisitor,
    TimePoint lossTime,
    folly::Optional<PacketNum> rtoVerifiedPacket,
    PacketNumberSpace pnSpace) {
  DCHECK(!rtoVerifiedPacket || *rtoVerifiedPacket <= largestAcked);
  conn.lossState.lossTime.clear();
  folly::Optional<std::chrono::microseconds> delayUntilLost;
  // TODO: maybe cache these values for efficiency
  if (conn.lossState.lossMode == LossState::LossMode::TimeLossDetection) {
    delayUntilLost = std::chrono::duration_cast<std::chrono::microseconds>(
        std::max(conn.lossState.srtt, conn.lossState.lrtt) *
        (1 + conn.lossState.timeReorderingFraction));
  } else if (largestAcked == conn.lossState.largestSent) {
    delayUntilLost = std::max(conn.lossState.srtt, conn.lossState.lrtt) * 9 / 8;
  }
  VLOG(10) << __func__ << " outstanding=" << conn.outstandingPackets.size()
           << " largestAcked=" << largestAcked << " delayUntilLost="
           << delayUntilLost.value_or(std::chrono::microseconds::zero()).count()
           << "us"
           << " " << conn;
  CongestionController::LossEvent lossEvent(lossTime);
  auto iter = getFirstOutstandingPacket(conn, pnSpace);
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
    bool lost = false;
    if (delayUntilLost) {
      lost = lost || ((ClockType::now() - pkt.time) > *delayUntilLost);
    }
    if (conn.lossState.lossMode == LossState::LossMode::ReorderingThreshold) {
      lost = lost ||
          (largestAcked - currentPacketNum) >
              conn.lossState.reorderingThreshold;
    }
    if (rtoVerifiedPacket && currentPacketNum <= *rtoVerifiedPacket) {
      lost = true;
    }
    if (!lost) {
      // We can exit early here because if packet N doesn't meet the
      // threshold, then packet N + 1 will not either.
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

  if (!conn.outstandingPackets.empty() && !conn.lossState.lossTime &&
      delayUntilLost) {
    // We are eligible to set a loss timer and there are a few packets which
    // are unacked, so we can set the early retransmit timer for them.
    VLOG(10) << __func__ << " early retransmit timer outstanding="
             << conn.outstandingPackets.empty() << " delayUntilLost"
             << delayUntilLost->count() << "us"
             << " " << conn;
    conn.lossState.lossTime =
        *delayUntilLost + conn.outstandingPackets.front().time;
  }
  // TODO(yangchi): pass the event time in to elimite the process delay
  if (lossEvent.largestLostPacketNum.hasValue()) {
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

void onRTOAlarm(QuicConnectionStateBase& conn);

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
      ++conn.lossState.timeoutBasedRetxCount;
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
    conn.pendingEvents.numProbePackets = kPacketToSendForRTO;
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
  if (conn.lossState.currentAlarmMethod == LossState::AlarmMethod::Handshake) {
    onHandshakeAlarm<LossVisitor, ClockType>(conn, lossVisitor);
  } else if (
      conn.lossState.currentAlarmMethod ==
      LossState::AlarmMethod::EarlyRetransmitOrReordering) {
    auto lossEvent = detectLossPackets<LossVisitor, ClockType>(
        conn,
        getAckState(conn, PacketNumberSpace::AppData).largestAckedByPeer,
        lossVisitor,
        now,
        folly::none,
        PacketNumberSpace::AppData);
    if (conn.congestionController && lossEvent) {
      conn.congestionController->onPacketAckOrLoss(
          folly::none, std::move(lossEvent));
    }
  } else {
    onRTOAlarm(conn);
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
  folly::Optional<PacketNum> rtoVerifiedPacket;
  auto& largestAcked = getAckState(conn, pnSpace).largestAckedByPeer;
  if (ack.largestAckedPacket.hasValue()) {
    // LargestAcked is larger than largest one in largestSentBeforeRto, notify
    // onRTOVerified:
    if (conn.lossState.rtoCount > 0 && conn.lossState.largestSentBeforeRto &&
        *ack.largestAckedPacket > *conn.lossState.largestSentBeforeRto) {
      QUIC_TRACE(
          rto_verified,
          conn,
          *ack.largestAckedPacket,
          *conn.lossState.largestSentBeforeRto,
          (uint64_t)conn.outstandingPackets.size());
      if (conn.congestionController) {
        conn.congestionController->onRTOVerified();
      }
      rtoVerifiedPacket = *ack.largestAckedPacket;
    }
    // TODO: Should we NOT reset these counters if the received Ack
    // frame doesn't ack anything that's in OP list?
    conn.lossState.rtoCount = 0;
    conn.lossState.largestSentBeforeRto = folly::none;
    largestAcked = std::max(largestAcked, *ack.largestAckedPacket);
  }
  auto lossEvent = detectLossPackets(
      conn,
      getAckState(conn, pnSpace).largestAckedByPeer,
      lossVisitor,
      ack.ackTime,
      std::move(rtoVerifiedPacket),
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
