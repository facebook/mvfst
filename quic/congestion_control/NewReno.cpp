/*
 * Copyright (c) Facebook, Inc. and its affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 *
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
  subtractAndCheckUnderflow(bytesInFlight_, bytes);
  VLOG(10) << __func__ << " writable=" << getWritableBytes()
           << " cwnd=" << cwndBytes_ << " inflight=" << bytesInFlight_ << " "
           << conn_;
  if (conn_.qLogger) {
    conn_.qLogger->addCongestionMetricUpdate(
        bytesInFlight_, getCongestionWindow(), kRemoveInflight.str());
  }
}

void NewReno::onPacketSent(const OutstandingPacket& packet) {
  addAndCheckOverflow(bytesInFlight_, packet.encodedSize);
  VLOG(10) << __func__ << " writable=" << getWritableBytes()
           << " cwnd=" << cwndBytes_ << " inflight=" << bytesInFlight_
           << " packetNum="
           << folly::variant_match(
                  packet.packet.header,
                  [](auto& h) { return h.getPacketSequenceNum(); })
           << " " << conn_;
  if (conn_.qLogger) {
    conn_.qLogger->addCongestionMetricUpdate(
        bytesInFlight_, getCongestionWindow(), kCongestionPacketSent.str());
  }
}

void NewReno::onAckEvent(const AckEvent& ack) {
  DCHECK(ack.largestAckedPacket.hasValue() && !ack.ackedPackets.empty());
  subtractAndCheckUnderflow(bytesInFlight_, ack.ackedBytes);
  VLOG(10) << __func__ << " writable=" << getWritableBytes()
           << " cwnd=" << cwndBytes_ << " inflight=" << bytesInFlight_ << " "
           << conn_;
  if (conn_.qLogger) {
    conn_.qLogger->addCongestionMetricUpdate(
        bytesInFlight_, getCongestionWindow(), kCongestionPacketAck.str());
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

void NewReno::onPacketAcked(const OutstandingPacket& packet) {
  if (endOfRecovery_ && packet.time < *endOfRecovery_) {
    return;
  }
  if (cwndBytes_ < ssthresh_) {
    addAndCheckOverflow(cwndBytes_, packet.encodedSize);
  } else {
    // TODO: I think this may be a bug in the specs. We should use
    // conn_.udpSendPacketLen for the cwnd calculation. But I need to
    // check how Linux handles this.
    uint64_t additionFactor =
        (kDefaultUDPSendPacketLen * packet.encodedSize) / cwndBytes_;
    addAndCheckOverflow(cwndBytes_, additionFactor);
  }
}

void NewReno::onPacketAckOrLoss(
    folly::Optional<AckEvent> ackEvent,
    folly::Optional<LossEvent> lossEvent) {
  if (lossEvent) {
    onPacketLoss(*lossEvent);
  }
  if (ackEvent && ackEvent->largestAckedPacket.hasValue()) {
    onAckEvent(*ackEvent);
  }
}

void NewReno::onPacketLoss(const LossEvent& loss) {
  DCHECK(
      loss.largestLostPacketNum.hasValue() &&
      loss.largestLostSentTime.hasValue());
  subtractAndCheckUnderflow(bytesInFlight_, loss.lostBytes);
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
             << " inflight=" << bytesInFlight_ << " " << conn_;
  } else {
    VLOG(10) << __func__ << " packetNum=" << *loss.largestLostPacketNum
             << " writable=" << getWritableBytes() << " cwnd=" << cwndBytes_
             << " inflight=" << bytesInFlight_ << " " << conn_;
  }

  if (conn_.qLogger) {
    conn_.qLogger->addCongestionMetricUpdate(
        bytesInFlight_, getCongestionWindow(), kCongestionPacketLoss.str());
  }
  if (loss.persistentCongestion) {
    VLOG(10) << __func__ << " writable=" << getWritableBytes()
             << " cwnd=" << cwndBytes_ << " inflight=" << bytesInFlight_ << " "
             << conn_;
    if (conn_.qLogger) {
      conn_.qLogger->addCongestionMetricUpdate(
          bytesInFlight_, getCongestionWindow(), kPersistentCongestion.str());
    }
    cwndBytes_ = conn_.transportSettings.minCwndInMss * conn_.udpSendPacketLen;
  }
}

uint64_t NewReno::getWritableBytes() const noexcept {
  if (bytesInFlight_ > cwndBytes_) {
    return 0;
  } else {
    return cwndBytes_ - bytesInFlight_;
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

void NewReno::setConnectionEmulation(uint8_t) noexcept {}

bool NewReno::canBePaced() const noexcept {
  // Pacing is not supported on NewReno currently
  return false;
}

uint64_t NewReno::getBytesInFlight() const noexcept {
  return bytesInFlight_;
}

uint64_t NewReno::getPacingRate(TimePoint /* currentTime */) noexcept {
  // Pacing is not supported on NewReno currently
  return conn_.transportSettings.writeConnectionDataPacketsLimit;
}

void NewReno::markPacerTimeoutScheduled(TimePoint /* currentTime */) noexcept {
  // Pacing is not supported on NewReno currently
}

std::chrono::microseconds NewReno::getPacingInterval() const noexcept {
  // Pacing is not supported on NewReno currently
  return std::chrono::microseconds(
      folly::HHWheelTimerHighRes::DEFAULT_TICK_INTERVAL);
}

void NewReno::setMinimalPacingInterval(std::chrono::microseconds) noexcept {}

void NewReno::setAppIdle(bool, TimePoint) noexcept { /* unsupported */
}

void NewReno::setAppLimited() { /* unsupported */
}

bool NewReno::isAppLimited() const noexcept {
  return false; // unsupported
}

} // namespace quic
