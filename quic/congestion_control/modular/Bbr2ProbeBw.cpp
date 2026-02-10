/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <quic/congestion_control/modular/Bbr2ProbeBw.h>

#include <quic/congestion_control/CongestionControlFunctions.h>
#include <quic/congestion_control/modular/Bbr2ProbeRtt.h>
#include <chrono>
#include <cstdint>
#include <limits>

namespace quic {

constexpr float kProbeBwDownPacingGain = 0.9;
constexpr float kProbeBwCruiseRefillPacingGain = 1.0;
constexpr float kProbeBwUpPacingGain = 1.25;

constexpr float kProbeBwCruiseRefillCwndGain = 2.0;
constexpr float kProbeBwDownCwndGain = 2.0;
constexpr float kProbeBwUpCwndGain = 2.25;

constexpr float kHeadroomFactor = 0.15;

Bbr2ProbeBw::Bbr2ProbeBw(
    QuicConnectionStateBase& conn,
    std::shared_ptr<Bbr2Shared> shared)
    : conn_(conn), shared_(std::move(shared)) {
  resetShortTermModel();
  startProbeBwDown();
}

// CongestionController Interface

void Bbr2ProbeBw::onPacketSent(const OutstandingPacketWrapper& packet) {
  shared_->onPacketSent(packet);

  // ProbeBw-specific: update pacing on idle restart
  if (shared_->idleRestart_) {
    shared_->setPacing(conn_.transportSettings.defaultRttFactor);
  }
}

void Bbr2ProbeBw::onPacketAckOrLoss(
    const AckEvent* FOLLY_NULLABLE ackEvent,
    const LossEvent* FOLLY_NULLABLE lossEvent) {
  if (lossEvent && lossEvent->lostPackets > 0) {
    if (conn_.transportSettings.ccaConfig.enableRecoveryInProbeStates) {
      auto ackedBytes = ackEvent ? ackEvent->ackedBytes : 0;
      shared_->onPacketLoss(*lossEvent, ackedBytes);
    }
  }

  // Handle return from ProbeRtt - restart the ProbeBw cycle
  // TODO(jbeshay): This handover mechanism from ProbeBw is hacky. Refactor it
  // to a more generalizable mechanism.
  if (shared_->returnedFromProbeRtt_) {
    shared_->returnedFromProbeRtt_ = false;
    resetShortTermModel();
    startProbeBwDown();
    startProbeBwCruise();
  }

  if (ackEvent) {
    shared_->currentAckEvent_ = ackEvent;

    if (ackEvent->implicit) {
      shared_->applyCwnd(calculateCwnd());
      return;
    }

    shared_->sampleBandwidthFromAck(*ackEvent);
    shared_->updateModelFromDeliveryAndLoss(lossEvent);

    // Increment rounds since last bw probe (for Reno coexistence)
    if (shared_->roundStart_) {
      roundsSinceBwProbe_++;
    }

    // Module-specific: congestion signals and state machine
    updateCongestionSignals();
    updateProbeBwCyclePhase();

    shared_->finalizeMinRttAndDeliverySignals();
    if (shared_->shouldEnterProbeRtt()) {
      auto probeRtt = std::make_unique<Bbr2ProbeRtt>(
          conn_, shared_, std::move(conn_.congestionController));
      auto* probeRttPtr = probeRtt.get();
      conn_.congestionController = std::move(probeRtt);
      probeRttPtr->finishAckProcessing(*ackEvent);
      return;
    }

    // Finish ack processing
    finishAckProcessing(*ackEvent);
  }
}

void Bbr2ProbeBw::finishAckProcessing(const AckEvent& ackEvent) {
  // Bound bandwidth with short-term limit if available
  Optional<Bandwidth> bwUpperBound;
  if (bandwidthShortTerm_.has_value() &&
      !conn_.transportSettings.ccaConfig.ignoreShortTerm) {
    bwUpperBound = bandwidthShortTerm_;
  }
  shared_->boundBwForModel(std::move(bwUpperBound));

  // Module-specific pacing
  shared_->setPacing(conn_.transportSettings.defaultRttFactor);

  shared_->completeAckProcessing(
      calculateCwnd(),
      ackEvent,
      shared_->inflightLongTerm_.value_or(0),
      inflightShortTerm_.value_or(0),
      bandwidthShortTerm_);
}

// Short-term model

void Bbr2ProbeBw::resetShortTermModel() {
  bandwidthShortTerm_.reset();
  inflightShortTerm_.reset();
}

void Bbr2ProbeBw::updateCongestionSignals() {
  if (!shared_->lossRoundStart_) {
    return; // Still within the same round
  }

  // Short-term model update when not probing bandwidth
  auto state = shared_->state_;
  bool isProbingBw =
      (state == Bbr2State::ProbeBw_Up || state == Bbr2State::ProbeBw_Refill);
  if (shared_->lossPctInLastRound_ > 0 && !isProbingBw) {
    shared_->updateShortTermModelOnLoss(
        bandwidthShortTerm_, inflightShortTerm_);
  }
}

// Cwnd

uint64_t Bbr2ProbeBw::calculateCwnd() const {
  const auto& ackedBytes = shared_->currentAckEvent_->ackedBytes;

  auto targetBDP = shared_->getBDPWithGain(cwndGain_);
  targetBDP += shared_->maxExtraAckedFilter_.GetBest();
  auto inflightMax = addQuantizationBudget(targetBDP);

  auto cwndBytes = shared_->cwndBytes_;
  cwndBytes = std::min(cwndBytes + ackedBytes, inflightMax);

  if (shared_->recoveryState_ != Bbr2Shared::RecoveryState::NOT_RECOVERY) {
    cwndBytes = std::min(cwndBytes, shared_->recoveryWindow_);
  }

  cwndBytes = std::max(cwndBytes, kMinCwndInMssForBbr * conn_.udpSendPacketLen);

  // BBRBoundCwndForModel() - Apply ProbeBw model bounds
  auto cap = std::numeric_limits<uint64_t>::max();
  if (shared_->inflightLongTerm_.has_value() &&
      !conn_.transportSettings.ccaConfig.ignoreInflightLongTerm) {
    if (shared_->state_ != Bbr2State::ProbeBw_Cruise) {
      cap = *shared_->inflightLongTerm_;
    } else {
      cap = getTargetInflightWithHeadroom();
    }
  }
  if (inflightShortTerm_.has_value() &&
      !conn_.transportSettings.ccaConfig.ignoreShortTerm) {
    cap = std::min(cap, *inflightShortTerm_);
  }
  cwndBytes = std::min(cwndBytes, cap);

  return cwndBytes;
}

uint64_t Bbr2ProbeBw::addQuantizationBudget(uint64_t input) const {
  input = shared_->addQuantizationBudget(input);
  if (shared_->state_ == Bbr2State::ProbeBw_Up) {
    input += 2 * conn_.udpSendPacketLen;
  }
  return input;
}

void Bbr2ProbeBw::updatePacingAndCwndGain() {
  float pacingGain = 1.0;
  float cwndGain = 2.0;

  switch (shared_->state_) {
    case Bbr2State::ProbeBw_Up:
      pacingGain = kProbeBwUpPacingGain;
      cwndGain = kProbeBwUpCwndGain;
      break;
    case Bbr2State::ProbeBw_Down:
      pacingGain = kProbeBwDownPacingGain;
      cwndGain = kProbeBwDownCwndGain;
      break;
    case Bbr2State::ProbeBw_Cruise:
    case Bbr2State::ProbeBw_Refill:
      pacingGain =
          conn_.transportSettings.ccaConfig.overrideCruisePacingGain > 0
          ? conn_.transportSettings.ccaConfig.overrideCruisePacingGain
          : kProbeBwCruiseRefillPacingGain;
      cwndGain = conn_.transportSettings.ccaConfig.overrideCruiseCwndGain > 0
          ? conn_.transportSettings.ccaConfig.overrideCruiseCwndGain
          : kProbeBwCruiseRefillCwndGain;
      break;
    case Bbr2State::Startup:
    case Bbr2State::Drain:
    case Bbr2State::ProbeRtt:
      // Should not happen - only ProbeBw states expected
      MVLOG_ERROR << fmt::format(
          "Unexpected Bbr2ProbeBw state: {}",
          bbr2StateToString(shared_->state_));
      break;
  }

  shared_->pacingGain_ = pacingGain;
  cwndGain_ = cwndGain;
}

// ProbeBw cycle control

void Bbr2ProbeBw::updateProbeBwCyclePhase() {
  adaptLongTermModel();
  checkFullBwReached();

  switch (shared_->state_) {
    case Bbr2State::ProbeBw_Down:
      if (checkTimeToProbeBW()) {
        return; // Already decided state transition
      }
      if (checkTimeToCruise()) {
        startProbeBwCruise();
      }
      break;
    case Bbr2State::ProbeBw_Cruise:
      if (checkTimeToProbeBW()) {
        return; // Already decided state transition
      }
      break;
    case Bbr2State::ProbeBw_Refill:
      // After one round of REFILL, start UP
      if (shared_->roundStart_) {
        canUpdateLongtermLossModel_ = true;
        startProbeBwUp();
      }
      break;
    case Bbr2State::ProbeBw_Up:
      if (checkTimeToGoDown()) {
        canUpdateLongtermLossModel_ = false;
        startProbeBwDown();
      }
      break;
    case Bbr2State::Startup:
    case Bbr2State::Drain:
    case Bbr2State::ProbeRtt:
      // Should not happen - only ProbeBw states expected
      MVLOG_ERROR << fmt::format(
          "Unexpected Bbr2ProbeBw state: {}",
          bbr2StateToString(shared_->state_));
      break;
  }
}

void Bbr2ProbeBw::startProbeBwDown() {
  shared_->resetCongestionSignals();
  probeUpCount_ = std::numeric_limits<uint64_t>::max();

  // Decide random round-trip bound for wait: between 0-1
  roundsSinceBwProbe_ = folly::Random::rand32() % 2;
  // Decide the random wall clock bound for wait: between 2-3 seconds
  bwProbeWait_ =
      std::chrono::milliseconds(2000 + (folly::Random::rand32() % 1000));

  probeBWCycleStart_ = Clock::now();
  shared_->state_ = Bbr2State::ProbeBw_Down;
  updatePacingAndCwndGain();
  shared_->startRound();

  // Advance the max bw filter if we're not app limited
  if (!shared_->lastAckedPacketAppLimited_) {
    shared_->incrementCycleCount();
  }
}

void Bbr2ProbeBw::startProbeBwCruise() {
  shared_->state_ = Bbr2State::ProbeBw_Cruise;
  updatePacingAndCwndGain();
}

void Bbr2ProbeBw::startProbeBwRefill() {
  resetShortTermModel();
  probeUpRounds_ = 0;
  probeUpAcks_ = 0;
  shared_->state_ = Bbr2State::ProbeBw_Refill;
  updatePacingAndCwndGain();
  shared_->startRound();
}

void Bbr2ProbeBw::startProbeBwUp() {
  probeBWCycleStart_ = Clock::now();
  shared_->state_ = Bbr2State::ProbeBw_Up;
  updatePacingAndCwndGain();
  shared_->startRound();
  resetFullBw();
  raiseInflightLongTermSlope();
}

bool Bbr2ProbeBw::checkTimeToProbeBW() {
  if (hasElapsedInPhase(bwProbeWait_) || isRenoCoexistenceProbeTime()) {
    startProbeBwRefill();
    return true;
  }
  return false;
}

bool Bbr2ProbeBw::checkTimeToCruise() {
  if (conn_.lossState.inflightBytes > getTargetInflightWithHeadroom()) {
    return false; // Not enough headroom
  }
  if (conn_.lossState.inflightBytes <= shared_->getTargetInflightWithGain()) {
    return true; // Inflight <= estimated BDP
  }
  return false;
}

bool Bbr2ProbeBw::checkTimeToGoDown() {
  if (shared_->cwndLimitedInRound_ && shared_->inflightLongTerm_.has_value() &&
      shared_->getTargetInflightWithGain(1.25) >=
          shared_->inflightLongTerm_.value()) {
    resetFullBw();
    fullBw_ = shared_->maxBwFilter_.GetBest();
  } else if (fullBwNow_) {
    return true;
  }
  return false;
}

void Bbr2ProbeBw::resetFullBw() {
  fullBw_ = Bandwidth();
  fullBwNow_ = false;
  fullBwCount_ = 0;
}

void Bbr2ProbeBw::checkFullBwReached() {
  // TODO(jbeshay): There is a significant amount of code duplication between
  // this function and the equivalent in Bbr2Startup. However, we're currently
  // maintaining it separately so we can experiment with different logic for
  // exitting ProbeBw_Up. It doesn't have to be the same as the startup
  // condition.
  if (fullBwNow_ || shared_->lastAckedPacketAppLimited_) {
    return;
  }
  if (!shared_->roundStart_) {
    return;
  }
  if (shared_->maxBwFilter_.GetBest() >= fullBw_ * 1.25) {
    resetFullBw();
    fullBw_ = shared_->maxBwFilter_.GetBest();
    return;
  }
  fullBwCount_++;
  fullBwNow_ = (fullBwCount_ >= 3);
}

bool Bbr2ProbeBw::hasElapsedInPhase(std::chrono::microseconds interval) {
  return Clock::now() > probeBWCycleStart_ + interval;
}

bool Bbr2ProbeBw::isRenoCoexistenceProbeTime() {
  if (!conn_.transportSettings.ccaConfig.enableRenoCoexistence) {
    return false;
  }
  auto renoBdpInPackets =
      std::min(shared_->getTargetInflightWithGain(), shared_->cwndBytes_) /
      conn_.udpSendPacketLen;
  auto roundsBeforeRenoProbe =
      std::min(renoBdpInPackets, decltype(renoBdpInPackets)(63));
  return roundsSinceBwProbe_ >= roundsBeforeRenoProbe;
}

// Long-term inflight model

void Bbr2ProbeBw::adaptLongTermModel() {
  if (!checkInflightTooHigh()) {
    if (!shared_->inflightLongTerm_.has_value()) {
      return;
    }
    // There is loss but it's at safe levels
    if (shared_->inflightBytesAtLastAckedPacket_ >
        *shared_->inflightLongTerm_) {
      shared_->inflightLongTerm_ = shared_->inflightBytesAtLastAckedPacket_;
    }
    if (shared_->state_ == Bbr2State::ProbeBw_Up) {
      probeInflightLongTermUpward();
    }
  }
}

bool Bbr2ProbeBw::checkInflightTooHigh() {
  if (isInflightTooHigh()) {
    if (canUpdateLongtermLossModel_) {
      handleInFlightTooHigh();
    }
    return true;
  }
  return false;
}

bool Bbr2ProbeBw::isInflightTooHigh() {
  // Check if loss rate exceeds threshold
  // Use lossBytesInRound_ directly (not lossPctInLastRound_) as it measures
  // losses against inflightBytesAtLastAckedPacket_, not total bytes sent.
  return static_cast<float>(shared_->lossBytesInRound_) >
      static_cast<float>(shared_->inflightBytesAtLastAckedPacket_) *
      kLossThreshold;
}

void Bbr2ProbeBw::handleInFlightTooHigh() {
  canUpdateLongtermLossModel_ = false;
  if (!shared_->lastAckedPacketAppLimited_) {
    shared_->inflightLongTerm_ = std::max(
        shared_->inflightBytesAtLastAckedPacket_,
        static_cast<uint64_t>(
            static_cast<float>(shared_->getTargetInflightWithGain()) * kBeta));
  }
  if (shared_->state_ == Bbr2State::ProbeBw_Up) {
    startProbeBwDown();
  }
}

uint64_t Bbr2ProbeBw::getTargetInflightWithHeadroom() const {
  if (!shared_->inflightLongTerm_.has_value()) {
    return std::numeric_limits<uint64_t>::max();
  }
  auto headroom = static_cast<uint64_t>(std::max(
      1.0f, kHeadroomFactor * static_cast<float>(*shared_->inflightLongTerm_)));
  return std::max(
      *shared_->inflightLongTerm_ - headroom,
      quic::kMinCwndInMssForBbr * conn_.udpSendPacketLen);
}

void Bbr2ProbeBw::probeInflightLongTermUpward() {
  if (!shared_->inflightLongTerm_.has_value() ||
      !shared_->cwndLimitedInRound_ ||
      shared_->cwndBytes_ < *shared_->inflightLongTerm_) {
    return;
  }
  probeUpAcks_ += shared_->currentAckEvent_->ackedBytes;
  if (probeUpAcks_ >= probeUpCount_) {
    auto delta = probeUpAcks_ / probeUpCount_;
    probeUpAcks_ -= delta * probeUpCount_;
    addAndCheckOverflow(
        *shared_->inflightLongTerm_,
        delta,
        2 * conn_.transportSettings.maxCwndInMss * conn_.udpSendPacketLen);
  }
  if (shared_->roundStart_) {
    raiseInflightLongTermSlope();
  }
}

void Bbr2ProbeBw::raiseInflightLongTermSlope() {
  auto growthThisRound = conn_.udpSendPacketLen << probeUpRounds_;
  probeUpRounds_ = std::min(probeUpRounds_ + 1, decltype(probeUpRounds_)(30));
  probeUpCount_ = std::max(
      shared_->cwndBytes_ / growthThisRound, decltype(shared_->cwndBytes_)(1));
}

} // namespace quic
