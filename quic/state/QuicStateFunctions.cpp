/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <quic/state/QuicStateFunctions.h>
#include <quic/state/QuicStreamFunctions.h>

#include <quic/common/TimeUtil.h>

namespace {
std::deque<quic::OutstandingPacketWrapper>::reverse_iterator
getPreviousOutstandingPacket(
    quic::QuicConnectionStateBase& conn,
    quic::PacketNumberSpace packetNumberSpace,
    std::deque<quic::OutstandingPacketWrapper>::reverse_iterator from) {
  return std::find_if(
      from, conn.outstandings.packets.rend(), [=](const auto& op) {
        return !op.declaredLost &&
            packetNumberSpace == op.packet.header.getPacketNumberSpace();
      });
}
std::deque<quic::OutstandingPacketWrapper>::reverse_iterator
getPreviousOutstandingPacketIncludingLost(
    quic::QuicConnectionStateBase& conn,
    quic::PacketNumberSpace packetNumberSpace,
    std::deque<quic::OutstandingPacketWrapper>::reverse_iterator from) {
  return std::find_if(
      from, conn.outstandings.packets.rend(), [=](const auto& op) {
        return packetNumberSpace == op.packet.header.getPacketNumberSpace();
      });
}

} // namespace

namespace quic {

void updateRtt(
    QuicConnectionStateBase& conn,
    const std::chrono::microseconds rttSample,
    const std::chrono::microseconds ackDelay) {
  // update mrtt
  //
  // mrtt ignores ack delay. This is the same in the current recovery draft
  // section A.6.
  conn.lossState.mrtt = timeMin(conn.lossState.mrtt, rttSample);

  // update mrttNoAckDelay
  //
  // keep a version of mrtt formed from rtt samples with ACK delay removed
  if (rttSample >= ackDelay) {
    const auto rttSampleNoAckDelay =
        std::chrono::ceil<std::chrono::microseconds>(rttSample - ackDelay);
    conn.lossState.maybeMrttNoAckDelay = (conn.lossState.maybeMrttNoAckDelay)
        ? std::min(*conn.lossState.maybeMrttNoAckDelay, rttSampleNoAckDelay)
        : rttSampleNoAckDelay;
  }

  // update lrtt and lrttAckDelay
  conn.lossState.lrtt = rttSample;
  conn.lossState.maybeLrtt = rttSample;
  conn.lossState.maybeLrttAckDelay = ackDelay;

  // update maxAckDelay
  conn.lossState.maxAckDelay = timeMax(conn.lossState.maxAckDelay, ackDelay);

  // determine the adjusted RTT sample we will use for srtt calculations
  //
  // do NOT subtract the acknowledgment delay from the RTT sample if the
  // resulting value is smaller than the min_rtt; this limits underestimation
  // of the smoothed_rtt due to a misreporting peer.
  //
  // if this is the first RTT sample, then it is also the minRTT and ACK delay
  // will not be subtracted
  const auto adjustedRtt =
      ((rttSample > ackDelay) && (rttSample > conn.lossState.mrtt + ackDelay))
      ? rttSample - ackDelay
      : rttSample;
  if (conn.lossState.srtt == 0us) {
    conn.lossState.srtt = adjustedRtt;
    conn.lossState.rttvar = adjustedRtt / 2;
  } else {
    conn.lossState.rttvar = conn.lossState.rttvar * (kRttBeta - 1) / kRttBeta +
        (conn.lossState.srtt > adjustedRtt
             ? conn.lossState.srtt - adjustedRtt
             : adjustedRtt - conn.lossState.srtt) /
            kRttBeta;
    conn.lossState.srtt = conn.lossState.srtt * (kRttAlpha - 1) / kRttAlpha +
        adjustedRtt / kRttAlpha;
  }

  // inform qlog
  if (conn.qLogger) {
    conn.qLogger->addMetricUpdate(
        rttSample, conn.lossState.mrtt, conn.lossState.srtt, ackDelay);
  }
}

void updateAckSendStateOnRecvPacket(
    QuicConnectionStateBase& conn,
    AckState& ackState,
    uint64_t distanceFromExpectedPacketNum,
    bool pktHasRetransmittableData,
    bool pktHasCryptoData,
    bool initPktNumSpace) {
  DCHECK(!pktHasCryptoData || pktHasRetransmittableData);
  auto thresh = kNonRtxRxPacketsPendingBeforeAck;
  if (pktHasRetransmittableData || ackState.numRxPacketsRecvd) {
    if (ackState.tolerance.hasValue()) {
      thresh = ackState.tolerance.value();
    } else {
      thresh = ackState.largestRecvdPacketNum.value_or(0) >
              conn.transportSettings.rxPacketsBeforeAckInitThreshold
          ? conn.transportSettings.rxPacketsBeforeAckAfterInit
          : conn.transportSettings.rxPacketsBeforeAckBeforeInit;
    }
  }
  bool exceedsReorderThreshold =
      distanceFromExpectedPacketNum > ackState.reorderThreshold;
  if (pktHasRetransmittableData) {
    bool skipCryptoAck =
        conn.nodeType == QuicNodeType::Server && initPktNumSpace;

    if ((pktHasCryptoData && !skipCryptoAck) || exceedsReorderThreshold ||
        ++ackState.numRxPacketsRecvd + ackState.numNonRxPacketsRecvd >=
            thresh) {
      VLOG(10) << conn
               << " ack immediately because packet threshold pktHasCryptoData="
               << pktHasCryptoData << " pktHasRetransmittableData="
               << static_cast<int>(pktHasRetransmittableData)
               << " numRxPacketsRecvd="
               << static_cast<int>(ackState.numRxPacketsRecvd)
               << " numNonRxPacketsRecvd="
               << static_cast<int>(ackState.numNonRxPacketsRecvd);
      conn.pendingEvents.scheduleAckTimeout = false;
      ackState.needsToSendAckImmediately = true;
    } else if (!ackState.needsToSendAckImmediately) {
      VLOG(10) << conn << " scheduling ack timeout pktHasCryptoData="
               << pktHasCryptoData << " pktHasRetransmittableData="
               << static_cast<int>(pktHasRetransmittableData)
               << " numRxPacketsRecvd="
               << static_cast<int>(ackState.numRxPacketsRecvd)
               << " numNonRxPacketsRecvd="
               << static_cast<int>(ackState.numNonRxPacketsRecvd);
      conn.pendingEvents.scheduleAckTimeout = true;
    }
  } else if (
      ++ackState.numNonRxPacketsRecvd + ackState.numRxPacketsRecvd >= thresh) {
    VLOG(10)
        << conn
        << " ack immediately because exceeds nonrx threshold numNonRxPacketsRecvd="
        << static_cast<int>(ackState.numNonRxPacketsRecvd)
        << " numRxPacketsRecvd="
        << static_cast<int>(ackState.numRxPacketsRecvd);
    conn.pendingEvents.scheduleAckTimeout = false;
    ackState.needsToSendAckImmediately = true;
  }
  if (ackState.needsToSendAckImmediately) {
    ackState.numRxPacketsRecvd = 0;
    ackState.numNonRxPacketsRecvd = 0;
  }
}

void updateAckStateOnAckTimeout(QuicConnectionStateBase& conn) {
  VLOG(10) << conn << " ack immediately due to ack timeout";
  conn.ackStates.appDataAckState.needsToSendAckImmediately = true;
  conn.ackStates.appDataAckState.numRxPacketsRecvd = 0;
  conn.ackStates.appDataAckState.numNonRxPacketsRecvd = 0;
  conn.pendingEvents.scheduleAckTimeout = false;
}

void updateAckSendStateOnSentPacketWithAcks(
    QuicConnectionStateBase& conn,
    AckState& ackState,
    PacketNum largestAckScheduled) {
  VLOG(10) << conn << " unset ack immediately due to sending packet with acks";
  conn.pendingEvents.scheduleAckTimeout = false;
  ackState.needsToSendAckImmediately = false;
  // When we send an ack we're most likely going to ack the largest received
  // packet, so reset the counters for numRxPacketsRecvd and
  // numNonRxPacketsRecvd. Since our ack threshold is quite small, we make the
  // critical assumption here that that all the needed acks can fit into one
  // packet if needed. If this is not the case, then some packets may not get
  // acked as a result and the receiver might retransmit them.
  ackState.numRxPacketsRecvd = 0;
  ackState.numNonRxPacketsRecvd = 0;
  ackState.largestAckScheduled = largestAckScheduled;
}

bool isConnectionPaced(const QuicConnectionStateBase& conn) noexcept {
  return (
      conn.transportSettings.pacingEnabled && conn.canBePaced && conn.pacer);
}

AckState& getAckState(
    QuicConnectionStateBase& conn,
    PacketNumberSpace pnSpace) noexcept {
  switch (pnSpace) {
    case PacketNumberSpace::Initial:
      return *CHECK_NOTNULL(conn.ackStates.initialAckState.get());
    case PacketNumberSpace::Handshake:
      return *CHECK_NOTNULL(conn.ackStates.handshakeAckState.get());
    case PacketNumberSpace::AppData:
      return conn.ackStates.appDataAckState;
  }
  folly::assume_unreachable();
}

const AckState& getAckState(
    const QuicConnectionStateBase& conn,
    PacketNumberSpace pnSpace) noexcept {
  switch (pnSpace) {
    case PacketNumberSpace::Initial:
      return *CHECK_NOTNULL(conn.ackStates.initialAckState.get());
    case PacketNumberSpace::Handshake:
      return *CHECK_NOTNULL(conn.ackStates.handshakeAckState.get());
    case PacketNumberSpace::AppData:
      return conn.ackStates.appDataAckState;
  }
  folly::assume_unreachable();
}

const AckState* getAckStatePtr(
    const QuicConnectionStateBase& conn,
    PacketNumberSpace pnSpace) noexcept {
  switch (pnSpace) {
    case PacketNumberSpace::Initial:
      return conn.ackStates.initialAckState.get();
    case PacketNumberSpace::Handshake:
      return conn.ackStates.handshakeAckState.get();
    case PacketNumberSpace::AppData:
      return &conn.ackStates.appDataAckState;
  }
  folly::assume_unreachable();
}

AckStateVersion currentAckStateVersion(
    const QuicConnectionStateBase& conn) noexcept {
  AckStateVersion ret;
  if (conn.ackStates.initialAckState) {
    ret.initialAckStateVersion =
        conn.ackStates.initialAckState->acks.insertVersion();
  }
  if (conn.ackStates.handshakeAckState) {
    ret.handshakeAckStateVersion =
        conn.ackStates.handshakeAckState->acks.insertVersion();
  }
  ret.appDataAckStateVersion =
      conn.ackStates.appDataAckState.acks.insertVersion();
  return ret;
}

PacketNum getNextPacketNum(
    const QuicConnectionStateBase& conn,
    PacketNumberSpace pnSpace) noexcept {
  return getAckState(conn, pnSpace).nextPacketNum;
}

void increaseNextPacketNum(
    QuicConnectionStateBase& conn,
    PacketNumberSpace pnSpace,
    bool dsrPacket) noexcept {
  auto& ackState = getAckState(conn, pnSpace);
  ackState.nextPacketNum++;
  if (!dsrPacket) {
    ackState.nonDsrPacketSequenceNumber++;
  }
  if (ackState.nextPacketNum == kMaxPacketNumber) {
    conn.pendingEvents.closeTransport = true;
  }
}

std::deque<OutstandingPacketWrapper>::iterator getFirstOutstandingPacket(
    QuicConnectionStateBase& conn,
    PacketNumberSpace packetNumberSpace) {
  return getNextOutstandingPacket(
      conn, packetNumberSpace, conn.outstandings.packets.begin());
}

std::deque<OutstandingPacketWrapper>::reverse_iterator getLastOutstandingPacket(
    QuicConnectionStateBase& conn,
    PacketNumberSpace packetNumberSpace) {
  return getPreviousOutstandingPacket(
      conn, packetNumberSpace, conn.outstandings.packets.rbegin());
}

std::deque<OutstandingPacketWrapper>::reverse_iterator
getLastOutstandingPacketIncludingLost(
    QuicConnectionStateBase& conn,
    PacketNumberSpace packetNumberSpace) {
  return getPreviousOutstandingPacketIncludingLost(
      conn, packetNumberSpace, conn.outstandings.packets.rbegin());
}

std::deque<OutstandingPacketWrapper>::iterator getNextOutstandingPacket(
    QuicConnectionStateBase& conn,
    PacketNumberSpace packetNumberSpace,
    std::deque<OutstandingPacketWrapper>::iterator from) {
  return std::find_if(
      from, conn.outstandings.packets.end(), [=](const auto& op) {
        return !op.declaredLost &&
            packetNumberSpace == op.packet.header.getPacketNumberSpace();
      });
}

bool hasReceivedPacketsAtLastCloseSent(
    const QuicConnectionStateBase& conn) noexcept {
  const auto* initialAckState = conn.ackStates.initialAckState.get();
  const auto* handshakeAckState = conn.ackStates.handshakeAckState.get();
  const auto& appDataAckState = conn.ackStates.appDataAckState;
  return (initialAckState && initialAckState->largestReceivedAtLastCloseSent) ||
      (handshakeAckState &&
       handshakeAckState->largestReceivedAtLastCloseSent) ||
      appDataAckState.largestReceivedAtLastCloseSent;
}

bool hasNotReceivedNewPacketsSinceLastCloseSent(
    const QuicConnectionStateBase& conn) noexcept {
  const auto* initialAckState = conn.ackStates.initialAckState.get();
  const auto* handshakeAckState = conn.ackStates.handshakeAckState.get();
  const auto& appDataAckState = conn.ackStates.appDataAckState;

  return (initialAckState ? initialAckState->largestReceivedAtLastCloseSent ==
                  initialAckState->largestRecvdPacketNum
                          : true) &&
      (handshakeAckState ? handshakeAckState->largestReceivedAtLastCloseSent ==
               handshakeAckState->largestRecvdPacketNum
                         : true) &&
      appDataAckState.largestReceivedAtLastCloseSent ==
      appDataAckState.largestRecvdPacketNum;
}

void updateLargestReceivedPacketsAtLastCloseSent(
    QuicConnectionStateBase& conn) noexcept {
  auto* initialAckState = conn.ackStates.initialAckState.get();
  auto* handshakeAckState = conn.ackStates.handshakeAckState.get();
  auto& appDataAckState = conn.ackStates.appDataAckState;

  if (initialAckState) {
    initialAckState->largestReceivedAtLastCloseSent =
        conn.ackStates.initialAckState->largestRecvdPacketNum;
  }
  if (handshakeAckState) {
    handshakeAckState->largestReceivedAtLastCloseSent =
        handshakeAckState->largestRecvdPacketNum;
  }
  appDataAckState.largestReceivedAtLastCloseSent =
      conn.ackStates.appDataAckState.largestRecvdPacketNum;
}

bool hasReceivedPackets(const QuicConnectionStateBase& conn) noexcept {
  const auto* initialAckState = conn.ackStates.initialAckState.get();
  const auto* handshakeAckState = conn.ackStates.handshakeAckState.get();
  const auto& appDataAckState = conn.ackStates.appDataAckState;

  return (initialAckState ? initialAckState->largestRecvdPacketNum : true) ||
      (handshakeAckState ? handshakeAckState->largestRecvdPacketNum : true) ||
      appDataAckState.largestRecvdPacketNum;
}

folly::Optional<TimePoint>& getLossTime(
    QuicConnectionStateBase& conn,
    PacketNumberSpace pnSpace) noexcept {
  return conn.lossState.lossTimes[pnSpace];
}

bool canSetLossTimerForAppData(const QuicConnectionStateBase& conn) noexcept {
  return conn.oneRttWriteCipher != nullptr;
}

std::pair<folly::Optional<TimePoint>, PacketNumberSpace> earliestLossTimer(
    const QuicConnectionStateBase& conn) noexcept {
  bool considerAppData = canSetLossTimerForAppData(conn);
  return earliestTimeAndSpace(conn.lossState.lossTimes, considerAppData);
}

std::pair<folly::Optional<TimePoint>, PacketNumberSpace> earliestTimeAndSpace(
    const EnumArray<PacketNumberSpace, folly::Optional<TimePoint>>& times,
    bool considerAppData) noexcept {
  std::pair<folly::Optional<TimePoint>, PacketNumberSpace> res = {
      folly::none, PacketNumberSpace::Initial};
  for (PacketNumberSpace pns : times.keys()) {
    if (!times[pns]) {
      continue;
    }
    if (pns == PacketNumberSpace::AppData && !considerAppData) {
      continue;
    }
    if (!res.first || *res.first > *times[pns]) {
      res.first = times[pns];
      res.second = pns;
    }
  }
  return res;
}

uint64_t maximumConnectionIdsToIssue(const QuicConnectionStateBase& conn) {
  // Return a min of what peer supports and hardcoded max limit.
  const uint64_t maximumIdsToIssue =
      std::min(conn.peerActiveConnectionIdLimit, kMaxActiveConnectionIdLimit);
  return maximumIdsToIssue;
}

uint64_t updateLargestReceivedPacketNum(
    QuicConnectionStateBase& conn,
    AckState& ackState,
    PacketNum packetNum,
    TimePoint receivedTime) {
  PacketNum expectedNextPacket = 0;
  if (ackState.largestRecvdPacketNum) {
    expectedNextPacket = *ackState.largestRecvdPacketNum + 1;
  }
  ackState.largestRecvdPacketNum = std::max<PacketNum>(
      ackState.largestRecvdPacketNum.value_or(packetNum), packetNum);
  auto preInsertVersion = ackState.acks.insertVersion();
  ackState.acks.insert(packetNum);
  if (preInsertVersion == ackState.acks.insertVersion()) {
    QUIC_STATS(conn.statsCallback, onDuplicatedPacketReceived);
  }
  if (ackState.largestRecvdPacketNum == packetNum) {
    ackState.largestRecvdPacketTime = receivedTime;
  }
  static_assert(Clock::is_steady, "Needs steady clock");

  ackState.lastRecvdPacketInfo.assign({packetNum, receivedTime});

  if (packetNum >= expectedNextPacket) {
    if (ackState.recvdPacketInfos.size() ==
        conn.transportSettings.maxReceiveTimestampsPerAckStored) {
      ackState.recvdPacketInfos.pop_front();
    }
    ackState.recvdPacketInfos.emplace_back(
        RecvdPacketInfo{packetNum, receivedTime});
  }

  if (expectedNextPacket) {
    return (packetNum > expectedNextPacket) ? packetNum - expectedNextPacket
                                            : expectedNextPacket - packetNum;
  } else {
    return 0;
  }
}

bool checkCustomRetransmissionProfilesEnabled(
    const QuicConnectionStateBase& conn) {
  return conn.transportSettings.advertisedMaxStreamGroups > 0;
}

/**
 * Checks if the retransmission policy on the stream group prohibits
 * retransmissions.
 */
bool streamRetransmissionDisabled(
    QuicConnectionStateBase& conn,
    const QuicStreamState& stream) {
  bool noRetransmissions = false;
  if (checkCustomRetransmissionProfilesEnabled(conn) && stream.groupId) {
    // Check stream group retransmission policy.
    const auto it = conn.retransmissionPolicies.find(*stream.groupId);
    if (it != conn.retransmissionPolicies.cend()) {
      const auto& retransmissionPolicy = it->second;
      noRetransmissions = retransmissionPolicy.disableRetransmission;
    }
  }
  return noRetransmissions;
}

} // namespace quic
