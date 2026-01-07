/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <quic/common/MvfstLogging.h>
#include <quic/congestion_control/NewReno.h>

#include <quic/congestion_control/CongestionControlFunctions.h>
#include <quic/logging/QLoggerConstants.h>
#include <quic/logging/QLoggerMacros.h>

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

void NewReno::onRemoveBytesFromInflight(uint64_t /* bytes */) {
  MVVLOG(10) << __func__ << " writable=" << getWritableBytes()
             << " cwnd=" << cwndBytes_
             << " inflight=" << conn_.lossState.inflightBytes << " " << conn_;
  QLOG(
      conn_,
      addMetricUpdate,
      conn_.lossState.lrtt,
      conn_.lossState.mrtt,
      conn_.lossState.srtt,
      conn_.lossState.maybeLrttAckDelay.value_or(0us),
      conn_.lossState.rttvar,
      getCongestionWindow(),
      conn_.lossState.inflightBytes,
      ssthresh_ == std::numeric_limits<uint32_t>::max()
          ? std::nullopt
          : Optional<uint64_t>(ssthresh_),
      std::nullopt,
      std::nullopt,
      conn_.lossState.ptoCount);
}

void NewReno::onPacketSent(const OutstandingPacketWrapper& packet) {
  MVVLOG(10) << __func__ << " writable=" << getWritableBytes()
             << " cwnd=" << cwndBytes_
             << " inflight=" << conn_.lossState.inflightBytes
             << " packetNum=" << packet.packet.header.getPacketSequenceNum()
             << " " << conn_;
  QLOG(
      conn_,
      addMetricUpdate,
      conn_.lossState.lrtt,
      conn_.lossState.mrtt,
      conn_.lossState.srtt,
      conn_.lossState.maybeLrttAckDelay.value_or(0us),
      conn_.lossState.rttvar,
      getCongestionWindow(),
      conn_.lossState.inflightBytes,
      ssthresh_ == std::numeric_limits<uint32_t>::max()
          ? std::nullopt
          : Optional<uint64_t>(ssthresh_),
      std::nullopt,
      std::nullopt,
      conn_.lossState.ptoCount);
}

void NewReno::onAckEvent(const AckEvent& ack) {
  MVDCHECK(
      ack.largestNewlyAckedPacket.has_value() && !ack.ackedPackets.empty());
  MVVLOG(10) << __func__ << " writable=" << getWritableBytes()
             << " cwnd=" << cwndBytes_
             << " inflight=" << conn_.lossState.inflightBytes << " " << conn_;
  QLOG(
      conn_,
      addMetricUpdate,
      conn_.lossState.lrtt,
      conn_.lossState.mrtt,
      conn_.lossState.srtt,
      conn_.lossState.maybeLrttAckDelay.value_or(0us),
      conn_.lossState.rttvar,
      getCongestionWindow(),
      conn_.lossState.inflightBytes,
      ssthresh_ == std::numeric_limits<uint32_t>::max()
          ? std::nullopt
          : Optional<uint64_t>(ssthresh_),
      std::nullopt,
      std::nullopt,
      conn_.lossState.ptoCount);
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
        cwndBytes_,
        packet.outstandingPacketMetadata.encodedSize,
        conn_.transportSettings.maxCwndInMss * conn_.udpSendPacketLen);
  } else {
    // TODO: I think this may be a bug in the specs. We should use
    // conn_.udpSendPacketLen for the cwnd calculation. But I need to
    // check how Linux handles this.
    uint64_t additionFactor = (kDefaultUDPSendPacketLen *
                               packet.outstandingPacketMetadata.encodedSize) /
        cwndBytes_;
    addAndCheckOverflow(
        cwndBytes_,
        additionFactor,
        conn_.transportSettings.maxCwndInMss * conn_.udpSendPacketLen);
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
  MVDCHECK(
      loss.largestLostPacketNum.has_value() &&
      loss.largestLostSentTime.has_value());
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
    MVVLOG(10) << __func__ << " exit slow start, ssthresh=" << ssthresh_
               << " packetNum=" << *loss.largestLostPacketNum
               << " writable=" << getWritableBytes() << " cwnd=" << cwndBytes_
               << " inflight=" << conn_.lossState.inflightBytes << " " << conn_;
  } else {
    MVVLOG(10) << __func__ << " packetNum=" << *loss.largestLostPacketNum
               << " writable=" << getWritableBytes() << " cwnd=" << cwndBytes_
               << " inflight=" << conn_.lossState.inflightBytes << " " << conn_;
  }

  QLOG(
      conn_,
      addMetricUpdate,
      conn_.lossState.lrtt,
      conn_.lossState.mrtt,
      conn_.lossState.srtt,
      conn_.lossState.maybeLrttAckDelay.value_or(0us),
      conn_.lossState.rttvar,
      getCongestionWindow(),
      conn_.lossState.inflightBytes,
      ssthresh_ == std::numeric_limits<uint32_t>::max()
          ? std::nullopt
          : Optional<uint64_t>(ssthresh_),
      std::nullopt,
      std::nullopt,
      conn_.lossState.ptoCount);
  if (loss.persistentCongestion) {
    MVVLOG(10) << __func__ << " writable=" << getWritableBytes()
               << " cwnd=" << cwndBytes_
               << " inflight=" << conn_.lossState.inflightBytes << " " << conn_;
    QLOG(
        conn_,
        addMetricUpdate,
        conn_.lossState.lrtt,
        conn_.lossState.mrtt,
        conn_.lossState.srtt,
        conn_.lossState.maybeLrttAckDelay.value_or(0us),
        conn_.lossState.rttvar,
        getCongestionWindow(),
        conn_.lossState.inflightBytes,
        ssthresh_ == std::numeric_limits<uint32_t>::max()
            ? std::nullopt
            : Optional<uint64_t>(ssthresh_),
        std::nullopt,
        std::nullopt,
        conn_.lossState.ptoCount);
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

void NewReno::setAppIdle(bool, TimePoint) noexcept { /* unsupported */ }

void NewReno::setAppLimited() { /* unsupported */ }

bool NewReno::isAppLimited() const noexcept {
  return false; // unsupported
}

} // namespace quic
