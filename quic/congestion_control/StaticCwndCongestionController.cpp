/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <quic/congestion_control/CongestionControlFunctions.h>
#include <quic/congestion_control/StaticCwndCongestionController.h>

namespace quic {

StaticCwndCongestionController::StaticCwndCongestionController(
    QuicConnectionStateBase& conn,
    CwndInBytes cwnd,
    PacerIntervalSource pacerIntervalSource)
    : conn_(conn),
      congestionWindowInBytes_(cwnd.bytes),
      pacerIntervalSource_(pacerIntervalSource) {}

void StaticCwndCongestionController::onRemoveBytesFromInflight(
    uint64_t bytesToRemove) {
  subtractAndCheckUnderflow(inflightBytes_, bytesToRemove);
}

void StaticCwndCongestionController::onPacketSent(
    const OutstandingPacketWrapper& packet) {
  isAppLimited_ = false;
  addAndCheckOverflow(inflightBytes_, packet.metadata.encodedSize);
}

void StaticCwndCongestionController::onPacketAckOrLoss(
    const AckEvent* FOLLY_NULLABLE ackEvent,
    const LossEvent* FOLLY_NULLABLE lossEvent) {
  if (ackEvent) {
    subtractAndCheckUnderflow(inflightBytes_, ackEvent->ackedBytes);

    if (conn_.pacer && ackEvent->rttSample) {
      switch (pacerIntervalSource_) {
        case PacerIntervalSource::MinRtt:
          conn_.pacer->refreshPacingRate(
              congestionWindowInBytes_, conn_.lossState.mrtt);
          break;
        case PacerIntervalSource::SmoothedRtt:
          conn_.pacer->refreshPacingRate(
              congestionWindowInBytes_, conn_.lossState.srtt);
          break;
        case PacerIntervalSource::LatestRtt:
          conn_.pacer->refreshPacingRate(
              congestionWindowInBytes_, conn_.lossState.lrtt);
          break;
        case PacerIntervalSource::NoPacing:
          break;
      }
    }
  }
  if (lossEvent) {
    subtractAndCheckUnderflow(inflightBytes_, lossEvent->lostBytes);
  }
}

uint64_t StaticCwndCongestionController::getWritableBytes() const noexcept {
  return getCongestionWindow() > inflightBytes_
      ? getCongestionWindow() - inflightBytes_
      : 0;
}

uint64_t StaticCwndCongestionController::getCongestionWindow() const noexcept {
  if (pacerIntervalSource_ == PacerIntervalSource::NoPacing) {
    return congestionWindowInBytes_;
  } else {
    // Leave enough room for the pacer to send a burst.
    return congestionWindowInBytes_ +
        conn_.transportSettings.minBurstPackets * conn_.udpSendPacketLen;
  }
}

CongestionControlType StaticCwndCongestionController::type() const noexcept {
  return CongestionControlType::StaticCwnd;
}

bool StaticCwndCongestionController::isAppLimited() const {
  return isAppLimited_;
}

void StaticCwndCongestionController::setAppLimited() noexcept {
  isAppLimited_ = true;
}

} // namespace quic
