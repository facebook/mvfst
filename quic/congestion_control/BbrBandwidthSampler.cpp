/*
 * Copyright (c) Facebook, Inc. and its affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 *
 */

// Copyright 2004-present Facebook.  All rights reserved.

#include <quic/congestion_control/BbrBandwidthSampler.h>
#include <quic/logging/QLoggerConstants.h>
#include <quic/logging/QuicLogger.h>

namespace quic {

BbrBandwidthSampler::BbrBandwidthSampler(QuicConnectionStateBase& conn)
    : conn_(conn), windowedFilter_(kBandwidthWindowLength, Bandwidth(), 0) {}

Bandwidth BbrBandwidthSampler::getBandwidth() const noexcept {
  return windowedFilter_.GetBest();
}

void BbrBandwidthSampler::onPacketAcked(
    const CongestionController::AckEvent& ackEvent,
    uint64_t rttCounter) {
  if (appLimited_) {
    if (appLimitedExitTarget_ < ackEvent.largestAckedPacketSentTime) {
      appLimited_ = false;
      QUIC_TRACE(
          bbr_appunlimited,
          conn_,
          *ackEvent.largestAckedPacket,
          appLimitedExitTarget_.time_since_epoch().count());
      if (conn_.qLogger) {
        conn_.qLogger->addAppUnlimitedUpdate();
      }
    }
  }
  // TODO: If i'm smart enough, maybe we don't have to loop through the acked
  // packets. Can we calculate the bandwidth based on aggregated stats?
  bool bandwidthUpdated = false;
  for (auto const& ackedPacket : ackEvent.ackedPackets) {
    if (ackedPacket.encodedSize == 0) {
      continue;
    }
    Bandwidth sendRate, ackRate;
    if (ackedPacket.lastAckedPacketInfo) {
      DCHECK(ackedPacket.sentTime > ackedPacket.lastAckedPacketInfo->sentTime);
      DCHECK_GE(
          ackedPacket.totalBytesSentThen,
          ackedPacket.lastAckedPacketInfo->totalBytesSent);
      sendRate = Bandwidth(
          ackedPacket.totalBytesSentThen -
              ackedPacket.lastAckedPacketInfo->totalBytesSent,
          std::chrono::duration_cast<std::chrono::microseconds>(
              ackedPacket.sentTime -
              ackedPacket.lastAckedPacketInfo->sentTime));

      DCHECK(ackEvent.ackTime > ackedPacket.lastAckedPacketInfo->ackTime);
      DCHECK_GE(
          conn_.lossState.totalBytesAcked,
          ackedPacket.lastAckedPacketInfo->totalBytesAcked);
      auto ackDuration = (ackEvent.adjustedAckTime >
                          ackedPacket.lastAckedPacketInfo->adjustedAckTime)
          ? (ackEvent.adjustedAckTime -
             ackedPacket.lastAckedPacketInfo->adjustedAckTime)
          : (ackEvent.ackTime - ackedPacket.lastAckedPacketInfo->ackTime);
      ackRate = Bandwidth(
          conn_.lossState.totalBytesAcked -
              ackedPacket.lastAckedPacketInfo->totalBytesAcked,
          std::chrono::duration_cast<std::chrono::microseconds>(ackDuration));
    } else if (ackEvent.ackTime > ackedPacket.sentTime) {
      // No previous ack info from outstanding packet, default to taking the
      // total acked bytes / ~RTT.
      //
      // Note that this if condition:
      //   ack.Event.ackTime > ackedPacket.sentTime
      // will almost always be true unless your network is very very fast, or
      // your clock is broken, or isn't steady. Anyway, in the rare cases that
      // it isn't true, divide by zero will crash.
      sendRate = Bandwidth(
          ackEvent.ackedBytes,
          std::chrono::duration_cast<std::chrono::microseconds>(
              ackEvent.ackTime - ackedPacket.sentTime));
    }
    Bandwidth measuredBandwidth = sendRate > ackRate ? sendRate : ackRate;
    // If a sample is from a packet sent during app-limited period, we should
    // still use this sample if it's >= current best value.
    if (measuredBandwidth >= windowedFilter_.GetBest() ||
        !ackedPacket.isAppLimited) {
      windowedFilter_.Update(measuredBandwidth, rttCounter);
      bandwidthUpdated = true;
    }
  }
  if (bandwidthUpdated && conn_.qLogger) {
    auto newBandwidth = getBandwidth();
    conn_.qLogger->addBandwidthEstUpdate(
        newBandwidth.units, newBandwidth.interval);
  }
}

void BbrBandwidthSampler::onAppLimited() {
  appLimited_ = true;
  appLimitedExitTarget_ = Clock::now();
  QUIC_TRACE(
      bbr_applimited, conn_, appLimitedExitTarget_.time_since_epoch().count());
  if (conn_.qLogger) {
    conn_.qLogger->addAppLimitedUpdate();
  }
}

bool BbrBandwidthSampler::isAppLimited() const noexcept {
  return appLimited_;
}
} // namespace quic
