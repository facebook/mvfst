/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <quic/congestion_control/CongestionControlFunctions.h>
#include <quic/congestion_control/StaticCwndCongestionController.h>

namespace quic {

StaticCwndCongestionController::StaticCwndCongestionController(CwndInBytes cwnd)
    : congestionWindowInBytes_(cwnd.bytes) {}

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
  return congestionWindowInBytes_;
}

CongestionControlType StaticCwndCongestionController::type() const noexcept {
  return CongestionControlType::StaticCwnd;
}

bool StaticCwndCongestionController::isInBackgroundMode() const {
  return false;
}

bool StaticCwndCongestionController::isAppLimited() const {
  return isAppLimited_;
}

void StaticCwndCongestionController::setAppLimited() noexcept {
  isAppLimited_ = true;
}

} // namespace quic
