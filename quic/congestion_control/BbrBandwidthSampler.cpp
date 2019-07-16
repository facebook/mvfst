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
    if (appLimitedExitTarget_ < ackEvent.ackedPackets.back().time) {
      appLimited_ = false;
      QUIC_TRACE(
          bbr_appunlimited,
          conn_,
          *ackEvent.largestAckedPacket,
          appLimitedExitTarget_.time_since_epoch().count());
      if (conn_.qLogger) {
        conn_.qLogger->addCongestionMetricUpdate(
            getBandwidth().bytes,
            getBandwidth().bytes,
            kCongestionAppUnlimited.str());
      }
    }
  }
  // TODO: If i'm smart enough, maybe we don't have to loop through the acked
  // packets. Can we calculate the bandwidth based on aggregated stats?
  for (auto const& outstandingPacket : ackEvent.ackedPackets) {
    if (outstandingPacket.encodedSize == 0) {
      continue;
    }
    folly::Optional<Bandwidth> sendRate, ackRate;
    if (outstandingPacket.lastAckedPacketInfo) {
      // TODO: I think I can DCHECK this condition:
      if (outstandingPacket.time >
          outstandingPacket.lastAckedPacketInfo->sentTime) {
        DCHECK_GE(
            outstandingPacket.totalBytesSent,
            outstandingPacket.lastAckedPacketInfo->totalBytesSent);
        sendRate.emplace(
            outstandingPacket.totalBytesSent -
                outstandingPacket.lastAckedPacketInfo->totalBytesSent,
            std::chrono::duration_cast<std::chrono::microseconds>(
                outstandingPacket.time -
                outstandingPacket.lastAckedPacketInfo->sentTime));
      }

      if (ackEvent.ackTime > outstandingPacket.lastAckedPacketInfo->ackTime) {
        DCHECK_GE(
            conn_.lossState.totalBytesAcked,
            outstandingPacket.lastAckedPacketInfo->totalBytesAcked);
        ackRate.emplace(
            conn_.lossState.totalBytesAcked -
                outstandingPacket.lastAckedPacketInfo->totalBytesAcked,
            std::chrono::duration_cast<std::chrono::microseconds>(
                ackEvent.ackTime -
                outstandingPacket.lastAckedPacketInfo->ackTime));
      }
    } else if (ackEvent.ackTime > outstandingPacket.time) {
      // No previous ack info from outstanding packet, fallback to bytes/lrtt.
      // This is a per packet delivery rate. Given there can be multiple packets
      // inflight during the time, this is clearly under estimating bandwidth.
      // But it's better than nothing.
      //
      // Note that this if condition:
      //   ack.Event.ackTime > outstandingPackcet.time
      // will almost always be true unless your network is very very fast, or
      // your clock is broken, or isn't steady. Anyway, in the rare cases that
      // it isn't true, divide by zero will crash.
      sendRate.emplace(
          outstandingPacket.encodedSize,
          std::chrono::duration_cast<std::chrono::microseconds>(
              ackEvent.ackTime - outstandingPacket.time));
    }
    Bandwidth measuredBandwidth;
    if (sendRate && ackRate) {
      measuredBandwidth = *sendRate >= *ackRate ? *sendRate : *ackRate;
    } else if (sendRate) {
      measuredBandwidth = *sendRate;
    } else if (ackRate) {
      measuredBandwidth = *ackRate;
    }
    // If a sample is from a packet sent during app-limited period, we should
    // still use this sample if it's >= current best value.
    if (measuredBandwidth >= windowedFilter_.GetBest() ||
        !outstandingPacket.isAppLimited) {
      windowedFilter_.Update(measuredBandwidth, rttCounter);
    }
  }
}

void BbrBandwidthSampler::onAppLimited() {
  appLimited_ = true;
  appLimitedExitTarget_ = Clock::now();
  QUIC_TRACE(
      bbr_applimited, conn_, appLimitedExitTarget_.time_since_epoch().count());
  if (conn_.qLogger) {
    conn_.qLogger->addCongestionMetricUpdate(
        getBandwidth().bytes,
        getBandwidth().bytes,
        kCongestionAppLimited.str());
  }
}

bool BbrBandwidthSampler::isAppLimited() const noexcept {
  return appLimited_;
}
} // namespace quic
