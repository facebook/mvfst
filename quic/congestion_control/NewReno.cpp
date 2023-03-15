/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <quic/congestion_control/NewReno.h>

#include <quic/congestion_control/CongestionControlFunctions.h>
#include <quic/logging/QLoggerConstants.h>

namespace quic {

constexpr int kRenoLossReductionFactorShift = 1;

NewReno::NewReno(QuicConnectionStateBase& conn)
    : conn_(conn),
      ssthresh_(std::numeric_limits<uint32_t>::max()),
      cwndBytes_(conn.transportSettings.initCwndInMss * conn.udpSendPacketLen) {
  cwndBytes_ = boundedCwnd(
      cwndBytes_,
      conn_.udpSendPacketLen,
      conn_.transportSettings.maxCwndInMss,
      conn_.transportSettings.minCwndInMss);
}

void NewReno::onRemoveBytesFromInflight(uint64_t bytes) {
  subtractAndCheckUnderflow(conn_.lossState.inflightBytes, bytes);
  VLOG(10) << __func__ << " writable=" << getWritableBytes()
           << " cwnd=" << cwndBytes_
           << " inflight=" << conn_.lossState.inflightBytes << " " << conn_;
  if (conn_.qLogger) {
    conn_.qLogger->addCongestionMetricUpdate(
        conn_.lossState.inflightBytes, getCongestionWindow(), kRemoveInflight);
  }
}

void NewReno::onPacketSent(const OutstandingPacketWrapper& packet) {
  addAndCheckOverflow(
      conn_.lossState.inflightBytes, packet.metadata.encodedSize);
  VLOG(10) << __func__ << " writable=" << getWritableBytes()
           << " cwnd=" << cwndBytes_
           << " inflight=" << conn_.lossState.inflightBytes
           << " packetNum=" << packet.packet.header.getPacketSequenceNum()
           << " " << conn_;
  if (conn_.qLogger) {
    conn_.qLogger->addCongestionMetricUpdate(
        conn_.lossState.inflightBytes,
        getCongestionWindow(),
        kCongestionPacketSent);
  }
}

void NewReno::onAckEvent(const AckEvent& ack) {
  DCHECK(ack.largestNewlyAckedPacket.has_value() && !ack.ackedPackets.empty());
  subtractAndCheckUnderflow(conn_.lossState.inflightBytes, ack.ackedBytes);
  VLOG(10) << __func__ << " writable=" << getWritableBytes()
           << " cwnd=" << cwndBytes_
           << " inflight=" << conn_.lossState.inflightBytes << " " << conn_;
  if (conn_.qLogger) {
    conn_.qLogger->addCongestionMetricUpdate(
        conn_.lossState.inflightBytes,
        getCongestionWindow(),
        kCongestionPacketAck);
  }
  for (const auto& packet : ack.ackedPackets) {
    onPacketAcked(packet);
  }
  cwndBytes_ = boundedCwnd(
      cwndBytes_,
      conn_.udpSendPacketLen,
      conn_.transportSettings.maxCwndInMss,
      conn_.transportSettings.minCwndInMss);
}

void NewReno::onPacketAcked(
    const CongestionController::AckEvent::AckPacket& packet) {
  if (endOfRecovery_ &&
      packet.outstandingPacketMetadata.time < *endOfRecovery_) {
    return;
  }
  if (cwndBytes_ < ssthresh_) {
    addAndCheckOverflow(
        cwndBytes_, packet.outstandingPacketMetadata.encodedSize);
  } else {
    // TODO: I think this may be a bug in the specs. We should use
    // conn_.udpSendPacketLen for the cwnd calculation. But I need to
    // check how Linux handles this.
    uint64_t additionFactor = (kDefaultUDPSendPacketLen *
                               packet.outstandingPacketMetadata.encodedSize) /
        cwndBytes_;
    addAndCheckOverflow(cwndBytes_, additionFactor);
  }
}

void NewReno::onPacketAckOrLoss(
    const AckEvent* FOLLY_NULLABLE ackEvent,
    const LossEvent* FOLLY_NULLABLE lossEvent) {
  if (lossEvent) {
    onPacketLoss(*lossEvent);
    // When we start to support pacing in NewReno, we need to call onPacketsLoss
    // on the pacer when there is loss.
  }
  if (ackEvent && ackEvent->largestNewlyAckedPacket.has_value()) {
    onAckEvent(*ackEvent);
  }
  // TODO: Pacing isn't supported with NewReno
}

void NewReno::onPacketLoss(const LossEvent& loss) {
  DCHECK(
      loss.largestLostPacketNum.has_value() &&
      loss.largestLostSentTime.has_value());
  subtractAndCheckUnderflow(conn_.lossState.inflightBytes, loss.lostBytes);
  if (!endOfRecovery_ || *endOfRecovery_ < *loss.largestLostSentTime) {
    endOfRecovery_ = Clock::now();
    cwndBytes_ = (cwndBytes_ >> kRenoLossReductionFactorShift);
    cwndBytes_ = boundedCwnd(
        cwndBytes_,
        conn_.udpSendPacketLen,
        conn_.transportSettings.maxCwndInMss,
        conn_.transportSettings.minCwndInMss);
    // This causes us to exit slow start.
    ssthresh_ = cwndBytes_;
    VLOG(10) << __func__ << " exit slow start, ssthresh=" << ssthresh_
             << " packetNum=" << *loss.largestLostPacketNum
             << " writable=" << getWritableBytes() << " cwnd=" << cwndBytes_
             << " inflight=" << conn_.lossState.inflightBytes << " " << conn_;
  } else {
    VLOG(10) << __func__ << " packetNum=" << *loss.largestLostPacketNum
             << " writable=" << getWritableBytes() << " cwnd=" << cwndBytes_
             << " inflight=" << conn_.lossState.inflightBytes << " " << conn_;
  }

  if (conn_.qLogger) {
    conn_.qLogger->addCongestionMetricUpdate(
        conn_.lossState.inflightBytes,
        getCongestionWindow(),
        kCongestionPacketLoss);
  }
  if (loss.persistentCongestion) {
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
  }
}

uint64_t NewReno::getWritableBytes() const noexcept {
  if (conn_.lossState.inflightBytes > cwndBytes_) {
    return 0;
  } else {
    return cwndBytes_ - conn_.lossState.inflightBytes;
  }
}

uint64_t NewReno::getCongestionWindow() const noexcept {
  return cwndBytes_;
}

bool NewReno::inSlowStart() const noexcept {
  return cwndBytes_ < ssthresh_;
}

CongestionControlType NewReno::type() const noexcept {
  return CongestionControlType::NewReno;
}

uint64_t NewReno::getBytesInFlight() const noexcept {
  return conn_.lossState.inflightBytes;
}

void NewReno::setAppIdle(bool, TimePoint) noexcept { /* unsupported */
}

void NewReno::setAppLimited() { /* unsupported */
}

bool NewReno::isAppLimited() const noexcept {
  return false; // unsupported
}

} // namespace quic
