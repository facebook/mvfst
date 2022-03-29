/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <quic/congestion_control/BbrBandwidthSampler.h>
#include <quic/logging/QLoggerConstants.h>

namespace quic {

BbrBandwidthSampler::BbrBandwidthSampler(QuicConnectionStateBase& conn)
    : conn_(conn),
      windowedFilter_(bandwidthWindowLength(kNumOfCycles), Bandwidth(), 0) {}

Bandwidth BbrBandwidthSampler::getBandwidth() const noexcept {
  return windowedFilter_.GetBest();
}

Bandwidth BbrBandwidthSampler::getLatestSample() const noexcept {
  return latestSample_;
}

void BbrBandwidthSampler::setWindowLength(
    const uint64_t windowLength) noexcept {
  windowedFilter_.SetWindowLength(windowLength);
}

void BbrBandwidthSampler::onPacketAcked(
    const CongestionController::AckEvent& ackEvent,
    uint64_t rttCounter) {
  if (appLimited_) {
    if (appLimitedExitTarget_ < ackEvent.largestNewlyAckedPacketSentTime) {
      appLimited_ = false;
      if (conn_.qLogger) {
        conn_.qLogger->addAppUnlimitedUpdate();
      }
    }
  }
  // TODO: If i'm smart enough, maybe we don't have to loop through the acked
  // packets. Can we calculate the bandwidth based on aggregated stats?
  bool bandwidthUpdated = false;
  for (auto const& ackedPacket : ackEvent.ackedPackets) {
    if (ackedPacket.outstandingPacketMetadata.encodedSize == 0) {
      continue;
    }
    Bandwidth sendRate, ackRate;
    if (ackedPacket.lastAckedPacketInfo) {
      DCHECK(
          ackedPacket.outstandingPacketMetadata.time >
          ackedPacket.lastAckedPacketInfo->sentTime);
      DCHECK_GE(
          ackedPacket.outstandingPacketMetadata.totalBytesSent,
          ackedPacket.lastAckedPacketInfo->totalBytesSent);
      sendRate = Bandwidth(
          ackedPacket.outstandingPacketMetadata.totalBytesSent -
              ackedPacket.lastAckedPacketInfo->totalBytesSent,
          std::chrono::duration_cast<std::chrono::microseconds>(
              ackedPacket.outstandingPacketMetadata.time -
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
    } else if (ackEvent.ackTime > ackedPacket.outstandingPacketMetadata.time) {
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
              ackEvent.ackTime - ackedPacket.outstandingPacketMetadata.time));
    }
    Bandwidth measuredBandwidth = sendRate > ackRate ? sendRate : ackRate;

    // This is a valid sample if the packet was sent while app-limited or
    // it's higher than the current sample.
    if (!ackedPacket.isAppLimited || measuredBandwidth > latestSample_) {
      latestSample_ = measuredBandwidth;
    }

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
  if (conn_.qLogger) {
    conn_.qLogger->addAppLimitedUpdate();
  }
}

bool BbrBandwidthSampler::isAppLimited() const noexcept {
  return appLimited_;
}
} // namespace quic
