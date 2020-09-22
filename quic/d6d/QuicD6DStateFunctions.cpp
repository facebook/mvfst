/*
 * Copyright (c) Facebook, Inc. and its affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 *
 */

#include <quic/d6d/QuicD6DStateFunctions.h>

namespace quic {

namespace {
using D6DMachineState = QuicConnectionStateBase::D6DMachineState;

std::string toString(
    const ::quic::QuicConnectionStateBase::D6DMachineState state) {
  switch (state) {
    case D6DMachineState::DISABLED:
      return "DISABLED";
    case D6DMachineState::BASE:
      return "BASE";
    case D6DMachineState::SEARCHING:
      return "SEARCHING";
    case D6DMachineState::SEARCH_COMPLETE:
      return "SEARCH_COMPLETE";
    case D6DMachineState::ERROR:
      return "ERROR";
  }
  folly::assume_unreachable();
}

} // namespace

void onD6DProbeTimeoutExpired(QuicConnectionStateBase& conn) {
  onD6DLastProbeLost(conn);
}

void onD6DRaiseTimeoutExpired(QuicConnectionStateBase& conn) {
  auto& d6d = conn.d6d;
  if (d6d.state == D6DMachineState::SEARCH_COMPLETE) {
    d6d.state = D6DMachineState::SEARCHING;
    conn.pendingEvents.sendD6DProbePacket = true;
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
      // From BASE -> SEARCHING we should have at least one next probe
      // size
      CHECK(maybeNextProbeSize.hasValue());
      d6d.currentProbeSize = *maybeNextProbeSize;
      d6d.state = D6DMachineState::SEARCHING;
      conn.pendingEvents.sendD6DProbePacket = true;
      break;
    case D6DMachineState::SEARCHING:
      CHECK_GT(lastProbeSize, conn.udpSendPacketLen);
      conn.udpSendPacketLen = lastProbeSize;
      if (maybeNextProbeSize.hasValue() &&
          *maybeNextProbeSize < kDefaultMaxUDPPayload) {
        d6d.currentProbeSize = *maybeNextProbeSize;
      } else {
        // We've reached either the PMTU upper bound or the probe size
        // raiser's internal upper bound, in both cases the search is
        // completed
        d6d.state = D6DMachineState::SEARCH_COMPLETE;
        conn.pendingEvents.scheduleD6DRaiseTimeout = true;
        conn.pendingEvents.scheduleD6DProbeTimeout = false;
      }
      break;
    case D6DMachineState::ERROR:
      // This means that a smaller probe went through the network.
      // We should try sending base pmtu-sized packet now.
      d6d.currentProbeSize = d6d.basePMTU;
      d6d.state = D6DMachineState::BASE;
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

        // TODO: reduce udpSendPacketLen below base once we can trust
        // this signal. Currently assuming quic is going to terminate
        // connection prior to this state.
      }
      // In both BASE and ERROR state, we need to keep sending probes
      conn.pendingEvents.sendD6DProbePacket = true;
      break;
    case D6DMachineState::SEARCHING:
      if (d6d.outstandingProbes >= kDefaultD6DMaxOutstandingProbes) {
        // We've lost enough consecutive probes, which should indicate
        // that the upper bound is reached
        d6d.state = D6DMachineState::SEARCH_COMPLETE;
        conn.pendingEvents.scheduleD6DRaiseTimeout = true;
        return;
      }
      // Otherwise, the loss could be due to congestion, so we keep
      // sending probe
      // TODO: pace d6d probing when there's congestion
      conn.pendingEvents.sendD6DProbePacket = true;
      break;
    case D6DMachineState::ERROR:
      // Keep probing with min probe size
      conn.pendingEvents.sendD6DProbePacket = true;
      break;
    default:
      LOG(ERROR) << "d6d: probe timeout expired in state: "
                 << toString(d6d.state);
      return;
  }
}

} // namespace quic
