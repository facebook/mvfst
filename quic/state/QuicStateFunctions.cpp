/*
 * Copyright (c) Facebook, Inc. and its affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 *
 */

#include <quic/state/QuicStateFunctions.h>

#include <quic/common/TimeUtil.h>
#include <quic/logging/QuicLogger.h>

namespace {
template <typename V, typename A>
std::pair<folly::Optional<V>, A> minOptional(
    std::pair<folly::Optional<V>, A> p1,
    std::pair<folly::Optional<V>, A> p2) {
  if (!p1.first && !p2.first) {
    return std::make_pair(folly::none, p1.second);
  }
  if (!p1.first) {
    return p2;
  }
  if (!p2.first) {
    return p1;
  }
  return *p1.first < *p2.first ? p1 : p2;
}
} // namespace

namespace quic {

void updateRtt(
    QuicConnectionStateBase& conn,
    std::chrono::microseconds rttSample,
    std::chrono::microseconds ackDelay) {
  conn.lossState.mrtt = timeMin(conn.lossState.mrtt, rttSample);
  conn.lossState.maxAckDelay = timeMax(conn.lossState.maxAckDelay, ackDelay);
  if (rttSample > conn.lossState.mrtt + ackDelay) {
    rttSample -= ackDelay;
  }
  conn.lossState.lrtt = rttSample;
  if (conn.lossState.srtt == 0us) {
    conn.lossState.srtt = rttSample;
    conn.lossState.rttvar = rttSample / 2;
  } else {
    conn.lossState.rttvar = conn.lossState.rttvar * (kRttBeta - 1) / kRttBeta +
        (conn.lossState.srtt > rttSample ? conn.lossState.srtt - rttSample
                                         : rttSample - conn.lossState.srtt) /
            kRttBeta;
    conn.lossState.srtt = conn.lossState.srtt * (kRttAlpha - 1) / kRttAlpha +
        rttSample / kRttAlpha;
  }
  QUIC_TRACE(
      update_rtt,
      conn,
      rttSample.count(),
      ackDelay.count(),
      conn.lossState.mrtt.count(),
      conn.lossState.srtt.count());
}

void updateAckSendStateOnRecvPacket(
    QuicConnectionStateBase& conn,
    AckState& ackState,
    bool pktOutOfOrder,
    bool pktHasRetransmittableData,
    bool pktHasCryptoData) {
  DCHECK(!pktHasCryptoData || pktHasRetransmittableData);
  uint8_t thresh =
      ((pktHasRetransmittableData || ackState.numRxPacketsRecvd)
           ? kRxPacketsPendingBeforeAckThresh
           : kNonRxPacketsPendingBeforeAckThresh);
  if (pktHasRetransmittableData) {
    if (pktHasCryptoData || pktOutOfOrder ||
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
      ackState.numRxPacketsRecvd = 0;
      ackState.numNonRxPacketsRecvd = 0;
    } else {
      VLOG(10) << conn << " scheduling ack timeout pktHasCryptoData="
               << pktHasCryptoData << " pktHasRetransmittableData="
               << static_cast<int>(pktHasRetransmittableData)
               << " numRxPacketsRecvd="
               << static_cast<int>(ackState.numRxPacketsRecvd)
               << " numNonRxPacketsRecvd="
               << static_cast<int>(ackState.numNonRxPacketsRecvd);
      conn.pendingEvents.scheduleAckTimeout = true;
      ackState.needsToSendAckImmediately = false;
    }
  } else if (
      ++ackState.numNonRxPacketsRecvd + ackState.numRxPacketsRecvd >= thresh) {
    VLOG(10)
        << conn
        << " ack immediately because exceeds nonrx threshold numNonRxPacketsRecvd="
        << static_cast<int>(ackState.numNonRxPacketsRecvd)
        << " numRxPacketsRecvd="
        << static_cast<int>(ackState.numRxPacketsRecvd);
    // TODO: experiment with outOfOrder and ack timer for NonRxPacket too
    conn.pendingEvents.scheduleAckTimeout = false;
    ackState.needsToSendAckImmediately = true;
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
  // critical assumtion here that that all the needed acks can fit into one
  // packet if needed. If this is not the case, then some packets may not get
  // acked as a result and the receiver might retransmit them.
  ackState.numRxPacketsRecvd = 0;
  ackState.numNonRxPacketsRecvd = 0;
  ackState.largestAckScheduled = largestAckScheduled;
}

bool isConnectionPaced(const QuicConnectionStateBase& conn) noexcept {
  return (
      conn.transportSettings.pacingEnabled && conn.canBePaced &&
      conn.congestionController && conn.congestionController->canBePaced());
}

AckState& getAckState(
    QuicConnectionStateBase& conn,
    PacketNumberSpace pnSpace) noexcept {
  switch (pnSpace) {
    case PacketNumberSpace::Initial:
      return conn.ackStates.initialAckState;
    case PacketNumberSpace::Handshake:
      return conn.ackStates.handshakeAckState;
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
      return conn.ackStates.initialAckState;
    case PacketNumberSpace::Handshake:
      return conn.ackStates.handshakeAckState;
    case PacketNumberSpace::AppData:
      return conn.ackStates.appDataAckState;
  }
  folly::assume_unreachable();
}

AckStateVersion currentAckStateVersion(
    const QuicConnectionStateBase& conn) noexcept {
  return AckStateVersion(
      conn.ackStates.initialAckState.acks.insertVersion(),
      conn.ackStates.handshakeAckState.acks.insertVersion(),
      conn.ackStates.appDataAckState.acks.insertVersion());
}

PacketNum getNextPacketNum(
    const QuicConnectionStateBase& conn,
    PacketNumberSpace pnSpace) noexcept {
  return getAckState(conn, pnSpace).nextPacketNum;
}

void increaseNextPacketNum(
    QuicConnectionStateBase& conn,
    PacketNumberSpace pnSpace) noexcept {
  getAckState(conn, pnSpace).nextPacketNum++;
}

std::deque<OutstandingPacket>::iterator getFirstOutstandingPacket(
    QuicConnectionStateBase& conn,
    PacketNumberSpace packetNumberSpace) {
  return getNextOutstandingPacket(
      conn, packetNumberSpace, conn.outstandingPackets.begin());
}

std::deque<OutstandingPacket>::iterator getNextOutstandingPacket(
    QuicConnectionStateBase& conn,
    PacketNumberSpace packetNumberSpace,
    std::deque<OutstandingPacket>::iterator from) {
  return std::find_if(from, conn.outstandingPackets.end(), [=](const auto& op) {
    return packetNumberSpace ==
        folly::variant_match(op.packet.header, [](const auto& h) {
             return h.getPacketNumberSpace();
           });
  });
}

bool hasReceivedPacketsAtLastCloseSent(
    const QuicConnectionStateBase& conn) noexcept {
  return conn.ackStates.initialAckState.largestReceivedAtLastCloseSent ||
      conn.ackStates.handshakeAckState.largestReceivedAtLastCloseSent ||
      conn.ackStates.appDataAckState.largestReceivedAtLastCloseSent;
}

bool hasNotReceivedNewPacketsSinceLastCloseSent(
    const QuicConnectionStateBase& conn) noexcept {
  DCHECK(
      !conn.ackStates.initialAckState.largestReceivedAtLastCloseSent ||
      *conn.ackStates.initialAckState.largestReceivedAtLastCloseSent <=
          *conn.ackStates.initialAckState.largestReceivedPacketNum);
  DCHECK(
      !conn.ackStates.handshakeAckState.largestReceivedAtLastCloseSent ||
      *conn.ackStates.handshakeAckState.largestReceivedAtLastCloseSent <=
          *conn.ackStates.handshakeAckState.largestReceivedPacketNum);
  DCHECK(
      !conn.ackStates.appDataAckState.largestReceivedAtLastCloseSent ||
      *conn.ackStates.appDataAckState.largestReceivedAtLastCloseSent <=
          *conn.ackStates.appDataAckState.largestReceivedPacketNum);
  return conn.ackStates.initialAckState.largestReceivedAtLastCloseSent ==
      conn.ackStates.initialAckState.largestReceivedPacketNum &&
      conn.ackStates.handshakeAckState.largestReceivedAtLastCloseSent ==
      conn.ackStates.handshakeAckState.largestReceivedPacketNum &&
      conn.ackStates.appDataAckState.largestReceivedAtLastCloseSent ==
      conn.ackStates.appDataAckState.largestReceivedPacketNum;
}

void updateLargestReceivedPacketsAtLastCloseSent(
    QuicConnectionStateBase& conn) noexcept {
  conn.ackStates.initialAckState.largestReceivedAtLastCloseSent =
      conn.ackStates.initialAckState.largestReceivedPacketNum;
  conn.ackStates.handshakeAckState.largestReceivedAtLastCloseSent =
      conn.ackStates.handshakeAckState.largestReceivedPacketNum;
  conn.ackStates.appDataAckState.largestReceivedAtLastCloseSent =
      conn.ackStates.appDataAckState.largestReceivedPacketNum;
}

bool hasReceivedPackets(const QuicConnectionStateBase& conn) noexcept {
  return conn.ackStates.initialAckState.largestReceivedPacketNum ||
      conn.ackStates.handshakeAckState.largestReceivedPacketNum ||
      conn.ackStates.appDataAckState.largestReceivedPacketNum;
}

folly::Optional<TimePoint>& getLossTime(
    QuicConnectionStateBase& conn,
    PacketNumberSpace pnSpace) noexcept {
  switch (pnSpace) {
    case PacketNumberSpace::Initial:
      return conn.lossState.initialLossTime;
    case PacketNumberSpace::Handshake:
      return conn.lossState.handshakeLossTime;
    case PacketNumberSpace::AppData:
      return conn.lossState.appDataLossTime;
  }
  folly::assume_unreachable();
}

std::pair<folly::Optional<TimePoint>, PacketNumberSpace> earliestLossTimer(
    const QuicConnectionStateBase& conn) noexcept {
  return minOptional(
      minOptional(
          std::make_pair(
              conn.lossState.initialLossTime, PacketNumberSpace::Initial),
          std::make_pair(
              conn.lossState.handshakeLossTime, PacketNumberSpace::Handshake)),
      std::make_pair(
          conn.lossState.appDataLossTime, PacketNumberSpace::AppData));
}
} // namespace quic
