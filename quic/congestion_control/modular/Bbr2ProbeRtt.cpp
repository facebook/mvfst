/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <quic/congestion_control/modular/Bbr2ProbeRtt.h>

#include <quic/congestion_control/CongestionControlFunctions.h>
#include <chrono>
#include <cstdint>

namespace quic {

constexpr float kProbeRttPacingGain = 1.0;
constexpr float kProbeRttCwndGain = 0.5;

Bbr2ProbeRtt::Bbr2ProbeRtt(
    QuicConnectionStateBase& conn,
    std::shared_ptr<Bbr2Shared> shared,
    std::unique_ptr<CongestionController> previousController)
    : conn_(conn),
      shared_(std::move(shared)),
      previousController_(std::move(previousController)) {
  shared_->pacingGain_ = kProbeRttPacingGain;
  enterProbeRtt();
  handleProbeRtt();
}

void Bbr2ProbeRtt::finishAckProcessing(const AckEvent& ackEvent) {
  // Module-specific pacing (no bandwidth upper bound in ProbeRtt)
  shared_->setPacing(conn_.transportSettings.defaultRttFactor);

  shared_->completeAckProcessing(
      calculateCwnd(),
      ackEvent,
      0, // inflightLongTerm_ not used in ProbeRtt
      0, // inflightShortTerm_ not used in ProbeRtt
      std::nullopt); // bandwidthShortTerm_ not used in ProbeRtt
}

// CongestionController Interface

void Bbr2ProbeRtt::onPacketSent(const OutstandingPacketWrapper& packet) {
  shared_->onPacketSent(packet);

  CHECK(shared_->state_ == Bbr2State::ProbeRtt);
  if (shared_->idleRestart_) {
    checkProbeRttDone();

    if (completedProbeRtt_) {
      // Exit ProbeRtt and return to previous controller
      completedProbeRtt_ = false;
      conn_.congestionController = std::move(previousController_);
      return;
    }
  }
}

void Bbr2ProbeRtt::onPacketAckOrLoss(
    const AckEvent* FOLLY_NULLABLE ackEvent,
    const LossEvent* FOLLY_NULLABLE lossEvent) {
  if (lossEvent && lossEvent->lostPackets > 0) {
    if (conn_.transportSettings.ccaConfig.enableRecoveryInProbeStates) {
      auto ackedBytes = ackEvent ? ackEvent->ackedBytes : 0;
      shared_->onPacketLoss(*lossEvent, ackedBytes);
    }
  }

  if (ackEvent) {
    shared_->currentAckEvent_ = ackEvent;

    if (ackEvent->implicit) {
      shared_->applyCwnd(calculateCwnd());
      return;
    }

    shared_->sampleBandwidthFromAck(*ackEvent);
    shared_->updateModelFromDeliveryAndLoss(lossEvent);

    // Module-specific: (none before post-model)

    shared_->finalizeMinRttAndDeliverySignals();

    // Module-specific: ProbeRtt state management
    CHECK(shared_->state_ == Bbr2State::ProbeRtt);
    handleProbeRtt();

    if (completedProbeRtt_) {
      // Exit ProbeRtt and return to previous controller
      completedProbeRtt_ = false;
      conn_.congestionController = std::move(previousController_);
      return;
    }

    finishAckProcessing(*ackEvent);
  }
}

// Cwnd Management

uint64_t Bbr2ProbeRtt::calculateCwnd() const {
  // During ProbeRTT, bound cwnd to ProbeRTT cwnd
  if (shared_->state_ == Bbr2State::ProbeRtt) {
    return std::min(shared_->cwndBytes_, getProbeRTTCwnd());
  }
  return shared_->cwndBytes_;
}

// ProbeRTT state management

void Bbr2ProbeRtt::enterProbeRtt() {
  shared_->state_ = Bbr2State::ProbeRtt;
  shared_->pacingGain_ = kProbeRttPacingGain;

  shared_->saveCwnd();
  probeRttDoneTimestamp_.reset();
  shared_->startRound();
}

void Bbr2ProbeRtt::handleProbeRtt() {
  // Mark connection as app limited during ProbeRTT
  shared_->setAppLimited();

  if (!probeRttDoneTimestamp_ &&
      conn_.lossState.inflightBytes <= getProbeRTTCwnd()) {
    // Wait for at least ProbeRTTDuration to elapse
    probeRttDoneTimestamp_ = Clock::now() + kBbr2ProbeRttDuration;
    // Wait for at least one round to elapse
    shared_->startRound();
  } else if (probeRttDoneTimestamp_) {
    if (shared_->roundStart_) {
      checkProbeRttDone();
    }
  }
}

void Bbr2ProbeRtt::checkProbeRttDone() {
  auto timeNow = Clock::now();
  if ((probeRttDoneTimestamp_ && timeNow > *probeRttDoneTimestamp_) ||
      conn_.lossState.inflightBytes == 0) {
    shared_->resetProbeRttExpired();
    shared_->restoreCwnd();
    exitProbeRtt();
  }
}

void Bbr2ProbeRtt::exitProbeRtt() {
  // Signal to ProbeBw that it should restart its cycle
  shared_->returnedFromProbeRtt_ = true;
  completedProbeRtt_ = true;
}

uint64_t Bbr2ProbeRtt::getProbeRTTCwnd() const {
  return std::max(
      shared_->getBDPWithGain(kProbeRttCwndGain),
      quic::kMinCwndInMssForBbr * conn_.udpSendPacketLen);
}
} // namespace quic
