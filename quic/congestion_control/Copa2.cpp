/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <quic/congestion_control/Copa2.h>

#include <quic/congestion_control/CongestionControlFunctions.h>
#include <quic/logging/QLoggerConstants.h>

namespace quic {

using namespace std::chrono;

Copa2::Copa2(QuicConnectionStateBase& conn)
    : conn_(conn),
      cwndBytes_(conn.transportSettings.initCwndInMss * conn.udpSendPacketLen),
      minRTTFilter_(kCopa2MinRttWindowLength.count(), 0us, 0) {
  VLOG(10) << __func__ << " writable=" << Copa2::getWritableBytes()
           << " cwnd=" << cwndBytes_
           << " inflight=" << conn_.lossState.inflightBytes << " " << conn_;
}

void Copa2::onRemoveBytesFromInflight(uint64_t bytes) {
  subtractAndCheckUnderflow(conn_.lossState.inflightBytes, bytes);
  VLOG(10) << __func__ << " writable=" << getWritableBytes()
           << " cwnd=" << cwndBytes_
           << " inflight=" << conn_.lossState.inflightBytes << " " << conn_;
  if (conn_.qLogger) {
    conn_.qLogger->addCongestionMetricUpdate(
        conn_.lossState.inflightBytes, getCongestionWindow(), kRemoveInflight);
  }
}

void Copa2::onPacketSent(const OutstandingPacket& packet) {
  addAndCheckOverflow(
      conn_.lossState.inflightBytes, packet.metadata.encodedSize);

  VLOG(10) << __func__ << " writable=" << getWritableBytes()
           << " cwnd=" << cwndBytes_
           << " inflight=" << conn_.lossState.inflightBytes
           << " bytesBufferred=" << conn_.flowControlState.sumCurStreamBufferLen
           << " packetNum=" << packet.packet.header.getPacketSequenceNum()
           << " " << conn_;
  if (conn_.qLogger) {
    conn_.qLogger->addCongestionMetricUpdate(
        conn_.lossState.inflightBytes,
        getCongestionWindow(),
        kCongestionPacketSent);
  }
}

void Copa2::onPacketAckOrLoss(
    const AckEvent* FOLLY_NULLABLE ack,
    const LossEvent* FOLLY_NULLABLE loss) {
  if (loss) {
    onPacketLoss(*loss);
    if (conn_.pacer) {
      conn_.pacer->onPacketsLoss();
    }
  }
  if (ack && ack->largestNewlyAckedPacket.has_value()) {
    if (appLimited_) {
      if (appLimitedExitTarget_ < ack->largestNewlyAckedPacketSentTime) {
        appLimited_ = false;
        if (conn_.qLogger) {
          conn_.qLogger->addAppUnlimitedUpdate();
        }
      }
    }

    onPacketAcked(*ack);
  }
}

// Switch to and from lossy mode
void Copa2::manageLossyMode(folly::Optional<TimePoint> sentTime) {
  if (!sentTime) {
    // Loss happened and we don't know when. Be safe
    lossyMode_ = true;
    numAckedInLossCycle_ = 0;
    numLostInLossCycle_ = 0;
    lossCycleStartTime_ = Clock::now();
    return;
  }

  auto numPktsInLossCycle = numAckedInLossCycle_ + numLostInLossCycle_;
  if (*sentTime < lossCycleStartTime_) {
    // Wait for at-least one RTT before declaring lossyMode_
    return;
  }
  if (numPktsInLossCycle < 2 / lossToleranceParam_ && numLostInLossCycle_ < 2) {
    // Second condition is needed in case there are losses, but not acks
    return;
  }
  VLOG(5) << __func__ << " lossyMode=" << lossyMode_
          << " num lost=" << numLostInLossCycle_
          << " num acked=" << numAckedInLossCycle_ << " " << conn_;
  // Cycle has ended. Take stock of the situation
  DCHECK(numPktsInLossCycle > 0);
  lossyMode_ = numLostInLossCycle_ >= numPktsInLossCycle * lossToleranceParam_;
  numAckedInLossCycle_ = 0;
  numLostInLossCycle_ = 0;
  lossCycleStartTime_ = Clock::now();
}

void Copa2::onPacketLoss(const LossEvent& loss) {
  VLOG(10) << __func__ << " lostBytes=" << loss.lostBytes
           << " lostPackets=" << loss.lostPackets << " cwnd=" << cwndBytes_
           << " inflight=" << conn_.lossState.inflightBytes << " " << conn_;
  if (conn_.qLogger) {
    conn_.qLogger->addCongestionMetricUpdate(
        conn_.lossState.inflightBytes,
        getCongestionWindow(),
        kCongestionPacketLoss);
  }
  DCHECK(loss.largestLostPacketNum.has_value());
  subtractAndCheckUnderflow(conn_.lossState.inflightBytes, loss.lostBytes);
  if (loss.persistentCongestion) {
    VLOG(10) << __func__ << " writable=" << getWritableBytes()
             << " cwnd=" << cwndBytes_
             << " inflight=" << conn_.lossState.inflightBytes << " " << conn_;
    cwndBytes_ = conn_.transportSettings.minCwndInMss * conn_.udpSendPacketLen;
    if (conn_.pacer) {
      // TODO Which min RTT should we use?
      conn_.pacer->refreshPacingRate(cwndBytes_, conn_.lossState.mrtt);
    }
    if (conn_.qLogger) {
      conn_.qLogger->addCongestionMetricUpdate(
          conn_.lossState.inflightBytes,
          getCongestionWindow(),
          kPersistentCongestion);
    }
  }

  numLostInLossCycle_ += loss.lostPackets;
  manageLossyMode(loss.largestLostSentTime);
}

void Copa2::onPacketAcked(const AckEvent& ack) {
  DCHECK(ack.largestNewlyAckedPacket.has_value());
  subtractAndCheckUnderflow(conn_.lossState.inflightBytes, ack.ackedBytes);
  minRTTFilter_.Update(
      conn_.lossState.lrtt,
      std::chrono::duration_cast<microseconds>(ack.ackTime.time_since_epoch())
          .count());
  bytesAckedInCycle_ += ack.ackedBytes;
  for (const auto& ackPkt : ack.ackedPackets) {
    appLimitedInCycle_ = appLimitedInCycle_ || ackPkt.isAppLimited;
  }
  auto rttMin = minRTTFilter_.GetBest();

  numAckedInLossCycle_ += ack.ackedPackets.size();
  manageLossyMode(ack.largestNewlyAckedPacketSentTime);

  auto dParam = rttMin;
  if (lossyMode_) {
    // Looks like a short buffer. Let's become less aggressive
    dParam = duration_cast<microseconds>(rttMin * 2. * lossToleranceParam_);
  }
  // The duration over which we calculate the number of bytes acked
  auto cycleDur = rttMin + dParam;

  if (probeRtt_) {
    // Do we exit probe RTT now?
    if (lastProbeRtt_ + dParam <= ack.ackTime) {
      // Note, probe rtt should ideally never decrease ack rate, since
      // it just barely empties the queue. Hence all ack rate samples
      // are good independent of whether we probed for rtt
      probeRtt_ = false;
    }
  } else {
    // See if we need to enter probe rtt mode
    auto interval = kCopa2ProbeRttInterval /
        (conn_.lossState.lrtt < rttMin + dParam ? 2 : 1);
    if (lastProbeRtt_ + interval <= ack.ackTime) {
      probeRtt_ = true;
      lastProbeRtt_ = ack.ackTime;
    }
  }

  if (!cycleStartTime_) {
    cycleStartTime_ = ack.ackTime;
    return;
  }

  // See if cycle needs to be continued
  if (*cycleStartTime_ + cycleDur > ack.ackTime) {
    return;
  }

  // Cycle has ended. Update cwnd and rate
  auto newCwnd = bytesAckedInCycle_ + alphaParam_ * conn_.udpSendPacketLen;
  if (!appLimitedInCycle_ || cwndBytes_ < newCwnd) {
    // If CC was app limited, don't decrease cwnd
    cwndBytes_ = newCwnd;
  }

  auto minCwnd = conn_.transportSettings.minCwndInMss * conn_.udpSendPacketLen;
  if (probeRtt_ || cwndBytes_ < minCwnd) {
    cwndBytes_ = minCwnd;
  }
  if (conn_.pacer) {
    conn_.pacer->refreshPacingRate(cwndBytes_, rttMin);
  }

  VLOG(5) << __func__ << "updated cwnd=" << cwndBytes_
          << " rttMin=" << rttMin.count()
          << " lrtt=" << conn_.lossState.lrtt.count()
          << " dParam=" << dParam.count() << " " << conn_;

  cycleStartTime_ = ack.ackTime;
  bytesAckedInCycle_ = 0;
  appLimitedInCycle_ = false;
}

uint64_t Copa2::getWritableBytes() const noexcept {
  if (conn_.lossState.inflightBytes > cwndBytes_) {
    return 0;
  } else {
    return cwndBytes_ - conn_.lossState.inflightBytes;
  }
}

uint64_t Copa2::getCongestionWindow() const noexcept {
  return cwndBytes_;
}

CongestionControlType Copa2::type() const noexcept {
  return CongestionControlType::Copa2;
}

bool Copa2::inLossyMode() const noexcept {
  return lossyMode_;
}

bool Copa2::inProbeRtt() const noexcept {
  return probeRtt_;
}

uint64_t Copa2::getBytesInFlight() const noexcept {
  return conn_.lossState.inflightBytes;
}

void Copa2::setAppIdle(bool, TimePoint) noexcept {}

void Copa2::setAppLimited() {
  // BBR uses this logic, so we use it too :)
  if (conn_.lossState.inflightBytes > getCongestionWindow()) {
    return;
  }
  appLimited_ = true;
  appLimitedExitTarget_ = Clock::now();
  if (conn_.qLogger) {
    conn_.qLogger->addAppLimitedUpdate();
  }
}

bool Copa2::isAppLimited() const noexcept {
  return appLimited_;
}

void Copa2::getStats(CongestionControllerStats& /* stats */) const {}

} // namespace quic
