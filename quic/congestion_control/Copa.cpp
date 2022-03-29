/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <quic/congestion_control/Copa.h>

#include <quic/common/TimeUtil.h>
#include <quic/congestion_control/CongestionControlFunctions.h>
#include <quic/logging/QLoggerConstants.h>

namespace quic {

using namespace std::chrono;

Copa::Copa(QuicConnectionStateBase& conn)
    : conn_(conn),
      cwndBytes_(conn.transportSettings.initCwndInMss * conn.udpSendPacketLen),
      isSlowStart_(true),
      minRTTFilter_(kMinRTTWindowLength.count(), 0us, 0),
      standingRTTFilter_(
          100000, /*100ms*/
          0us,
          0) {
  VLOG(10) << __func__ << " writable=" << getWritableBytes()
           << " cwnd=" << cwndBytes_
           << " inflight=" << conn_.lossState.inflightBytes << " " << conn_;
  if (conn_.transportSettings.copaDeltaParam.has_value()) {
    deltaParam_ = conn_.transportSettings.copaDeltaParam.value();
  }
  useRttStanding_ = conn_.transportSettings.copaUseRttStanding;
}

void Copa::onRemoveBytesFromInflight(uint64_t bytes) {
  subtractAndCheckUnderflow(conn_.lossState.inflightBytes, bytes);
  VLOG(10) << __func__ << " writable=" << getWritableBytes()
           << " cwnd=" << cwndBytes_
           << " inflight=" << conn_.lossState.inflightBytes << " " << conn_;
  if (conn_.qLogger) {
    conn_.qLogger->addCongestionMetricUpdate(
        conn_.lossState.inflightBytes, getCongestionWindow(), kRemoveInflight);
  }
}

void Copa::onPacketSent(const OutstandingPacket& packet) {
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

/**
 * Once per window, the sender
 * compares the current cwnd to the cwnd value at
 *  the time that the latest acknowledged packet was
 *  sent (i.e., cwnd at the start of the current window).
 *  If the current cwnd is larger, then set direction to
 *  'up'; if it is smaller, then set direction to 'down'.
 *  Now, if direction is the same as in the previous
 *  window, then double v. If not, then reset v to 1.
 *  However, start doubling v only after the direction
 *  has remained the same for three RTTs
 */
void Copa::checkAndUpdateDirection(const TimePoint ackTime) {
  if (!velocityState_.lastCwndRecordTime.has_value()) {
    velocityState_.lastCwndRecordTime = ackTime;
    velocityState_.lastRecordedCwndBytes = cwndBytes_;
    return;
  }
  auto elapsed_time = ackTime - velocityState_.lastCwndRecordTime.value();

  VLOG(10) << __func__ << " elapsed time for direction update "
           << elapsed_time.count() << ", srtt " << conn_.lossState.srtt.count()
           << " " << conn_;

  if (elapsed_time >= conn_.lossState.srtt) {
    auto newDirection = cwndBytes_ > velocityState_.lastRecordedCwndBytes
        ? VelocityState::Direction::Up
        : VelocityState::Direction::Down;
    if (newDirection != velocityState_.direction) {
      // if direction changes, change velocity to 1
      velocityState_.velocity = 1;
      velocityState_.numTimesDirectionSame = 0;
    } else {
      velocityState_.numTimesDirectionSame++;
      uint64_t velocityDirectionThreshold = 3;
      if (useRttStanding_) {
        velocityDirectionThreshold = 4;
      }
      if (velocityState_.numTimesDirectionSame >= velocityDirectionThreshold) {
        velocityState_.velocity = 2 * velocityState_.velocity;
      }
    }
    VLOG(10) << __func__ << " updated direction from "
             << velocityState_.direction << " to " << newDirection
             << " velocityState_.numTimesDirectionSame "
             << velocityState_.numTimesDirectionSame << " velocity "
             << velocityState_.velocity << " " << conn_;
    velocityState_.direction = newDirection;
    velocityState_.lastCwndRecordTime = ackTime;
    velocityState_.lastRecordedCwndBytes = cwndBytes_;
  }
}

void Copa::changeDirection(
    VelocityState::Direction newDirection,
    const TimePoint ackTime) {
  if (velocityState_.direction == newDirection) {
    return;
  }
  VLOG(10) << __func__ << " Suddenly direction change to " << newDirection
           << " " << conn_;
  velocityState_.direction = newDirection;
  velocityState_.velocity = 1;
  velocityState_.numTimesDirectionSame = 0;
  velocityState_.lastCwndRecordTime = ackTime;
  velocityState_.lastRecordedCwndBytes = cwndBytes_;
}

void Copa::onPacketAckOrLoss(
    const AckEvent* FOLLY_NULLABLE ack,
    const LossEvent* FOLLY_NULLABLE loss) {
  if (loss) {
    onPacketLoss(*loss);
    if (conn_.pacer) {
      conn_.pacer->onPacketsLoss();
    }
  }
  if (ack && ack->largestNewlyAckedPacket.has_value()) {
    onPacketAcked(*ack);
  }
}

void Copa::onPacketAcked(const AckEvent& ack) {
  DCHECK(ack.largestNewlyAckedPacket.has_value());
  subtractAndCheckUnderflow(conn_.lossState.inflightBytes, ack.ackedBytes);
  minRTTFilter_.Update(
      conn_.lossState.lrtt,
      std::chrono::duration_cast<microseconds>(ack.ackTime.time_since_epoch())
          .count());
  auto rttMin = minRTTFilter_.GetBest();
  if (useRttStanding_) {
    standingRTTFilter_.SetWindowLength(conn_.lossState.srtt.count());
  } else {
    standingRTTFilter_.SetWindowLength(conn_.lossState.srtt.count() / 2);
  }
  standingRTTFilter_.Update(
      conn_.lossState.lrtt,
      std::chrono::duration_cast<microseconds>(ack.ackTime.time_since_epoch())
          .count());
  auto rttStandingMicroSec = standingRTTFilter_.GetBest().count();

  VLOG(10) << __func__ << "ack size=" << ack.ackedBytes
           << " num packets acked=" << ack.ackedBytes / conn_.udpSendPacketLen
           << " writable=" << getWritableBytes() << " cwnd=" << cwndBytes_
           << " inflight=" << conn_.lossState.inflightBytes
           << " rttMin=" << rttMin.count()
           << " sRTT=" << conn_.lossState.srtt.count()
           << " lRTT=" << conn_.lossState.lrtt.count()
           << " mRTT=" << conn_.lossState.mrtt.count()
           << " rttvar=" << conn_.lossState.rttvar.count()
           << " packetsBufferred="
           << conn_.flowControlState.sumCurStreamBufferLen
           << " packetsRetransmitted=" << conn_.lossState.rtxCount << " "
           << conn_;

  if (conn_.qLogger) {
    conn_.qLogger->addCongestionMetricUpdate(
        conn_.lossState.inflightBytes,
        getCongestionWindow(),
        kCongestionPacketAck);
  }

  if (rttStandingMicroSec < rttMin.count()) {
    VLOG(3) << __func__ << "delay negative, rttStanding=" << rttStandingMicroSec
            << " rttMin=" << rttMin.count() << " " << conn_;
    return;
  }

  uint64_t delayInMicroSec;
  if (useRttStanding_) {
    delayInMicroSec = rttStandingMicroSec - rttMin.count();
  } else {
    delayInMicroSec =
        duration_cast<microseconds>(conn_.lossState.lrtt - rttMin).count();
  }

  if (rttStandingMicroSec == 0) {
    VLOG(3) << __func__ << "rttStandingMicroSec zero, lrtt = "
            << conn_.lossState.lrtt.count() << " rttMin=" << rttMin.count()
            << " " << conn_;
    return;
  }

  VLOG(10) << __func__
           << " estimated queuing delay microsec =" << delayInMicroSec << " "
           << conn_;

  bool increaseCwnd = false;
  if (delayInMicroSec == 0) {
    // taking care of inf targetRate case here, this happens in beginning where
    // we do want to increase cwnd
    increaseCwnd = true;
  } else {
    auto targetRate = (1.0 * conn_.udpSendPacketLen * 1000000) /
        (deltaParam_ * delayInMicroSec);
    auto currentRate = (1.0 * cwndBytes_ * 1000000) / rttStandingMicroSec;

    VLOG(10) << __func__ << " estimated target rate=" << targetRate
             << " current rate=" << currentRate << " " << conn_;
    increaseCwnd = targetRate >= currentRate;
  }

  if (!(increaseCwnd && isSlowStart_)) {
    // Update direction except for the case where we are in slow start mode,
    checkAndUpdateDirection(ack.ackTime);
  }

  if (increaseCwnd) {
    if (isSlowStart_) {
      // When a flow starts, Copa performs slow-start where
      // cwnd doubles once per RTT until current rate exceeds target rate".
      if (!lastCwndDoubleTime_.has_value()) {
        lastCwndDoubleTime_ = ack.ackTime;
      } else if (
          ack.ackTime - lastCwndDoubleTime_.value() > conn_.lossState.srtt) {
        VLOG(10) << __func__ << " doubling cwnd per RTT from=" << cwndBytes_
                 << " due to slow start"
                 << " " << conn_;
        addAndCheckOverflow(cwndBytes_, cwndBytes_);
        lastCwndDoubleTime_ = ack.ackTime;
      }
    } else {
      if (velocityState_.direction != VelocityState::Direction::Up &&
          velocityState_.velocity > 1.0) {
        // if our current rate is much different than target, we double v every
        // RTT. That could result in a high v at some point in time. If we
        // detect a sudden direction change here, while v is still very high but
        // meant for opposite direction, we should reset it to 1.
        changeDirection(VelocityState::Direction::Up, ack.ackTime);
      }
      uint64_t addition = (ack.ackedPackets.size() * conn_.udpSendPacketLen *
                           conn_.udpSendPacketLen * velocityState_.velocity) /
          (deltaParam_ * cwndBytes_);
      VLOG(10) << __func__ << " increasing cwnd from=" << cwndBytes_ << " by "
               << addition << " " << conn_;
      addAndCheckOverflow(cwndBytes_, addition);
    }
  } else {
    if (velocityState_.direction != VelocityState::Direction::Down &&
        velocityState_.velocity > 1.0) {
      // if our current rate is much different than target, we double v every
      // RTT. That could result in a high v at some point in time. If we detect
      // a sudden direction change here, while v is still very high but meant
      // for opposite direction, we should reset it to 1.
      changeDirection(VelocityState::Direction::Down, ack.ackTime);
    }
    uint64_t reduction = (ack.ackedPackets.size() * conn_.udpSendPacketLen *
                          conn_.udpSendPacketLen * velocityState_.velocity) /
        (deltaParam_ * cwndBytes_);
    VLOG(10) << __func__ << " decreasing cwnd from=" << cwndBytes_ << " by "
             << reduction << " " << conn_;
    isSlowStart_ = false;
    subtractAndCheckUnderflow(
        cwndBytes_,
        std::min<uint64_t>(
            reduction,
            cwndBytes_ -
                conn_.transportSettings.minCwndInMss * conn_.udpSendPacketLen));
  }
  if (conn_.pacer) {
    conn_.pacer->refreshPacingRate(cwndBytes_ * 2, conn_.lossState.srtt);
  }
}

void Copa::onPacketLoss(const LossEvent& loss) {
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
    // TODO See if we should go to slowStart here
    VLOG(10) << __func__ << " writable=" << getWritableBytes()
             << " cwnd=" << cwndBytes_
             << " inflight=" << conn_.lossState.inflightBytes << " " << conn_;
    if (conn_.qLogger) {
      conn_.qLogger->addCongestionMetricUpdate(
          conn_.lossState.inflightBytes,
          getCongestionWindow(),
          kPersistentCongestion);
    }
    cwndBytes_ = conn_.transportSettings.minCwndInMss * conn_.udpSendPacketLen;
    if (conn_.pacer) {
      conn_.pacer->refreshPacingRate(cwndBytes_ * 2, conn_.lossState.srtt);
    }
  }
}

uint64_t Copa::getWritableBytes() const noexcept {
  if (conn_.lossState.inflightBytes > cwndBytes_) {
    return 0;
  } else {
    return cwndBytes_ - conn_.lossState.inflightBytes;
  }
}

uint64_t Copa::getCongestionWindow() const noexcept {
  return cwndBytes_;
}

bool Copa::inSlowStart() {
  return isSlowStart_;
}

CongestionControlType Copa::type() const noexcept {
  return CongestionControlType::Copa;
}

uint64_t Copa::getBytesInFlight() const noexcept {
  return conn_.lossState.inflightBytes;
}

void Copa::setAppIdle(bool, TimePoint) noexcept { /* unsupported */
}

void Copa::setAppLimited() { /* unsupported */
}

bool Copa::isAppLimited() const noexcept {
  return false; // not supported
}

void Copa::getStats(CongestionControllerStats& stats) const {
  stats.copaStats.deltaParam = deltaParam_;
  stats.copaStats.useRttStanding = useRttStanding_;
}

} // namespace quic
