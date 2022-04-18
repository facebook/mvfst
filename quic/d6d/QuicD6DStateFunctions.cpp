/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <quic/d6d/QuicD6DStateFunctions.h>
#include <quic/observer/SocketObserverContainer.h>

namespace quic {

inline void scheduleProbeAfterDelay(
    QuicConnectionStateBase& conn,
    std::chrono::milliseconds delay) {
  conn.pendingEvents.d6d.sendProbeDelay = delay;
}

/**
 * A helper function that reports PMTU Upper Bound event.
 * Returns the event timestamp
 */
static TimePoint reportUpperBound(QuicConnectionStateBase& conn) {
  auto& d6d = conn.d6d;
  const auto lastProbeSize = d6d.lastProbe->packetSize;
  const auto now = Clock::now();
  QUIC_STATS(conn.statsCallback, onConnectionPMTUUpperBoundDetected);
  if (conn.getSocketObserverContainer() &&
      conn.getSocketObserverContainer()
          ->hasObserversForEvent<
              SocketObserverInterface::Events::pmtuEvents>()) {
    conn.getSocketObserverContainer()
        ->invokeInterfaceMethod<SocketObserverInterface::Events::pmtuEvents>(
            [event = SocketObserverInterface::PMTUUpperBoundEvent(
                 now,
                 std::chrono::duration_cast<std::chrono::microseconds>(
                     now - d6d.meta.timeLastNonSearchState),
                 d6d.meta.lastNonSearchState,
                 lastProbeSize,
                 d6d.meta.totalTxedProbes,
                 conn.transportSettings.d6dConfig.raiserType)](
                auto observer, auto observed) {
              observer->pmtuUpperBoundDetected(observed, event);
            });
  }
  return now;
}

/**
 * Helper function that reports PMTU blackhole event.
 * Returns the event timestamp
 */
static TimePoint reportBlackhole(
    QuicConnectionStateBase& conn,
    const OutstandingPacket& packet) {
  QUIC_STATS(conn.statsCallback, onConnectionPMTUBlackholeDetected);
  auto& d6d = conn.d6d;
  const auto now = Clock::now();
  if (conn.observerContainer &&
      conn.observerContainer->hasObserversForEvent<
          SocketObserverInterface::Events::pmtuEvents>()) {
    conn.observerContainer
        ->invokeInterfaceMethod<SocketObserverInterface::Events::pmtuEvents>(
            [event = SocketObserverInterface::PMTUBlackholeEvent(
                 now,
                 std::chrono::duration_cast<std::chrono::microseconds>(
                     now - d6d.meta.timeLastNonSearchState),
                 d6d.meta.lastNonSearchState,
                 d6d.state,
                 conn.udpSendPacketLen,
                 d6d.lastProbe->packetSize,
                 d6d.thresholdCounter->getWindow(),
                 d6d.thresholdCounter->getThreshold(),
                 packet)](auto observer, auto observed) {
              observer->pmtuBlackholeDetected(observed, event);
            });
  }
  return now;
}

static void onD6DLastProbeAckedInSearching(
    QuicConnectionStateBase& conn,
    uint32_t lastProbeSize,
    folly::Optional<uint16_t> maybeNextProbeSize) {
  auto& d6d = conn.d6d;
  // Temporary mitigation
  if (lastProbeSize <= conn.udpSendPacketLen) {
    LOG(ERROR) << "D6D lastProbeSize <= udpSendPacketLen";
    return;
  }
  QUIC_STATS(conn.statsCallback, onConnectionPMTURaised);
  conn.udpSendPacketLen = lastProbeSize;
  if (maybeNextProbeSize.hasValue() &&
      *maybeNextProbeSize > conn.udpSendPacketLen &&
      *maybeNextProbeSize <= d6d.maxPMTU) {
    d6d.currentProbeSize = *maybeNextProbeSize;
    scheduleProbeAfterDelay(conn, kDefaultD6DProbeDelayWhenAcked);
  } else {
    // We've reached either the PMTU upper bound or the probe size
    // raiser's internal upper bound, in both cases the search is
    // completed
    d6d.state = D6DMachineState::SEARCH_COMPLETE;
    conn.pendingEvents.d6d.scheduleRaiseTimeout = true;
    conn.pendingEvents.d6d.scheduleProbeTimeout = false;
    reportUpperBound(conn);
  }
}

void onD6DProbeTimeoutExpired(QuicConnectionStateBase& conn) {
  onD6DLastProbeLost(conn);
}

void onD6DRaiseTimeoutExpired(QuicConnectionStateBase& conn) {
  auto& d6d = conn.d6d;
  if (d6d.state == D6DMachineState::SEARCH_COMPLETE) {
    d6d.state = D6DMachineState::SEARCHING;
    conn.pendingEvents.d6d.sendProbePacket = true;
  } else {
    LOG(ERROR) << "d6d: raise timeout expired in state: "
               << toString(d6d.state);
  }
}

void onD6DLastProbeAcked(QuicConnectionStateBase& conn) {
  auto& d6d = conn.d6d;
  const auto lastProbeSize = d6d.lastProbe->packetSize;

  // Reset outstanding probes to 0
  d6d.outstandingProbes = 0;
  auto maybeNextProbeSize = d6d.raiser->raiseProbeSize(lastProbeSize);

  switch (d6d.state) {
    case D6DMachineState::BASE:
      // There could be a series of events leading to receiving ack for probe of
      // size larger basePMTU in BASE state:
      // 1. the connection was in the SEARCHING state, sending probes of size
      // larger than basePMTU
      // 2. blackhole detection signals a false positive due to congestion,
      // setting the state back to BASE
      // 3. the ack for the probe sent prior to the blackhole is received, the
      // next probe size will therefore exceed raiseProbeSize(basePMTU)
      // In such situations, we can be certain that the previous blackhole is a
      // false positive, and we should treat this ack as a valid ack.
      if (lastProbeSize != d6d.basePMTU) {
        // TODO(xtt) report false positive pmtu blackholes
        d6d.state = D6DMachineState::SEARCHING;
        onD6DLastProbeAckedInSearching(conn, lastProbeSize, maybeNextProbeSize);
      } else {
        if (maybeNextProbeSize.hasValue() &&
            *maybeNextProbeSize > conn.udpSendPacketLen &&
            *maybeNextProbeSize <= d6d.maxPMTU) {
          d6d.currentProbeSize = *maybeNextProbeSize;
          d6d.state = D6DMachineState::SEARCHING;
          scheduleProbeAfterDelay(conn, kDefaultD6DProbeDelayWhenAcked);
        } else {
          // This means either the probe size raiser is poorly configured or we
          // have a very small maxPMTU. In either case, we've reached the
          // upperbound, which is sadly only basePMTU
          d6d.state = D6DMachineState::SEARCH_COMPLETE;
          conn.pendingEvents.d6d.scheduleRaiseTimeout = true;
          conn.pendingEvents.d6d.scheduleProbeTimeout = false;
          reportUpperBound(conn);
        }
        d6d.meta.lastNonSearchState = D6DMachineState::BASE;
        d6d.meta.timeLastNonSearchState = Clock::now();
      }
      break;
    case D6DMachineState::SEARCHING:
      onD6DLastProbeAckedInSearching(conn, lastProbeSize, maybeNextProbeSize);
      break;
    case D6DMachineState::ERROR:
      // This means that a smaller probe went through the network.
      // We should try sending base pmtu-sized packet now.
      d6d.currentProbeSize = d6d.basePMTU;
      d6d.state = D6DMachineState::BASE;
      d6d.meta.lastNonSearchState = D6DMachineState::ERROR;
      d6d.meta.timeLastNonSearchState = Clock::now();
      scheduleProbeAfterDelay(conn, kDefaultD6DProbeDelayWhenAcked);
      break;
    default:
      LOG(ERROR) << "d6d: receive probe ack in state: " << toString(d6d.state);
  }
}

void onD6DLastProbeLost(QuicConnectionStateBase& conn) {
  auto& d6d = conn.d6d;
  switch (d6d.state) {
    case D6DMachineState::BASE:
      if (d6d.outstandingProbes >= kDefaultD6DMaxOutstandingProbes) {
        // This indicates serious issue with the effective PMTU, a possible
        // remedy is to probe much smaller
        d6d.state = D6DMachineState::ERROR;
        d6d.currentProbeSize = kMinMaxUDPPayload;
        d6d.meta.lastNonSearchState = D6DMachineState::BASE;
        d6d.meta.timeLastNonSearchState = Clock::now();

        // TODO: reduce udpSendPacketLen below base once we can trust
        // this signal. Currently assuming quic is going to terminate
        // connection prior to this state.
      }
      // In both BASE and ERROR state, we need to keep sending probes
      scheduleProbeAfterDelay(conn, kDefaultD6DProbeDelayWhenLost);
      break;
    case D6DMachineState::SEARCHING:
      if (d6d.outstandingProbes >= kDefaultD6DMaxOutstandingProbes) {
        // We've lost enough consecutive probes, which should indicate
        // that the upper bound is reached
        d6d.state = D6DMachineState::SEARCH_COMPLETE;
        conn.pendingEvents.d6d.scheduleRaiseTimeout = true;
        conn.pendingEvents.d6d.scheduleProbeTimeout = false;
        reportUpperBound(conn);
        return;
      }
      // Otherwise, the loss could be due to congestion, so we keep
      // sending probe
      // TODO: pace d6d probing when there's congestion
      scheduleProbeAfterDelay(conn, kDefaultD6DProbeDelayWhenLost);
      break;
    case D6DMachineState::ERROR:
      // Keep probing with min probe size
      scheduleProbeAfterDelay(conn, kDefaultD6DProbeDelayWhenLost);
      break;
    default:
      LOG(ERROR) << "d6d: probe timeout expired in state: "
                 << toString(d6d.state);
      return;
  }
}

/**
 * D6D blackhole detection mechanism for non-probe packets, which
 * signals blackhole due to invalid PMTU by detetcing consecutive loss
 * of big packets (i.e. packet size greater than base pmtu)
 * https://tools.ietf.org/id/draft-ietf-tsvwg-datagram-plpmtud-21.html#name-black-hole-detection-and-re
 */
void detectPMTUBlackhole(
    QuicConnectionStateBase& conn,
    const OutstandingPacket& packet) {
  auto& d6d = conn.d6d;
  // If d6d is not activated, or it's a d6d probe, or that the packet size is
  // less than base pmtu, then the loss is not caused by pmtu blackhole
  if (d6d.state == D6DMachineState::DISABLED || packet.metadata.isD6DProbe ||
      packet.metadata.encodedSize <= d6d.basePMTU ||
      conn.udpSendPacketLen <= d6d.basePMTU || d6d.noBlackholeDetection) {
    return;
  }

  // We use a windowed threshold counter to detect excessive loss of
  // large packets.
  if (d6d.thresholdCounter &&
      d6d.thresholdCounter->update(
          std::chrono::duration_cast<std::chrono::microseconds>(
              packet.metadata.time.time_since_epoch())
              .count())) {
    LOG(ERROR) << "PMTU blackhole detected on packet loss, reducing PMTU from "
               << conn.udpSendPacketLen << " to base " << d6d.basePMTU;

    auto eventTime = reportBlackhole(conn, packet);
    if (d6d.state != D6DMachineState::SEARCHING) {
      d6d.meta.lastNonSearchState = d6d.state;
      d6d.meta.timeLastNonSearchState = eventTime;
    }
    d6d.state = D6DMachineState::BASE;
    d6d.currentProbeSize = d6d.basePMTU;
    conn.udpSendPacketLen = d6d.basePMTU;
    // Cancel existing raise timeout if any
    conn.pendingEvents.d6d.scheduleRaiseTimeout = false;
  }
}
} // namespace quic
