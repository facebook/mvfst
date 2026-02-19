/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <quic/congestion_control/modular/Bbr2Startup.h>

#include <quic/congestion_control/CongestionControlFunctions.h>
#include <quic/congestion_control/modular/Bbr2ProbeBw.h>
#include <quic/congestion_control/modular/Bbr2ProbeRtt.h>
#include <chrono>
#include <cstdint>

namespace quic {

constexpr float kStartupPacingGain = 2.885; // 2 / ln(2)
constexpr float kDrainPacingGain = 0.5;
constexpr float kStartupCwndGain = 2.885;

Bbr2Startup::Bbr2Startup(QuicConnectionStateBase& conn)
    : conn_(conn), shared_(std::make_shared<Bbr2Shared>(conn)) {
  shared_->resetCongestionSignals();
  resetFullBw();
  resetShortTermModel();
  // If we explicitly don't want to pace the init cwnd, reset the pacing rate.
  // Otherwise, leave it to the pacer's initial state.
  if (!conn_.transportSettings.ccaConfig.paceInitCwnd) {
    if (conn_.pacer) {
      conn_.pacer->refreshPacingRate(shared_->cwndBytes_, 0us);
    } else {
      LOG(WARNING) << "BBR2 was initialized on a connection without a pacer";
    }
  }
  enterStartup();
}

// Congestion Controller Interface

void Bbr2Startup::onPacketAckOrLoss(
    const AckEvent* FOLLY_NULLABLE ackEvent,
    const LossEvent* FOLLY_NULLABLE lossEvent) {
  if (lossEvent && lossEvent->lostPackets > 0) {
    auto ackedBytes = ackEvent ? ackEvent->ackedBytes : 0;
    if (conn_.transportSettings.ccaConfig.enableRecoveryInStartup) {
      shared_->onPacketLoss(*lossEvent, ackedBytes);
    }
  }

  if (ackEvent) {
    shared_->currentAckEvent_ = ackEvent;

    if (ackEvent->implicit) {
      // Implicit acks should not be used for bandwidth or rtt estimation
      shared_->applyCwnd(calculateCwnd());
      return;
    }

    shared_->sampleBandwidthFromAck(*ackEvent);
    shared_->updateModelFromDeliveryAndLoss(lossEvent);

    // Module-specific: congestion signals and state machine
    updateCongestionSignals();
    checkFullBwReached();
    checkStartupDone();

    checkResumptionState();

    shared_->finalizeMinRttAndDeliverySignals();

    if (isDrainComplete()) {
      // Create ProbeBw controller and set it as the connection's controller
      // NOTE: This destroys 'this' - must return immediately after
      MVCHECK(!isResuming_);
      auto probeBw = std::make_unique<Bbr2ProbeBw>(conn_, shared_);
      auto* probeBwPtr = probeBw.get();
      conn_.congestionController = std::move(probeBw);
      probeBwPtr->finishAckProcessing(*ackEvent);
      return;
    }

    if (!isResuming_ && shared_->shouldEnterProbeRtt()) {
      auto probeRtt = std::make_unique<Bbr2ProbeRtt>(
          conn_, shared_, std::move(conn_.congestionController));
      auto* probeRttPtr = probeRtt.get();
      conn_.congestionController = std::move(probeRtt);
      probeRttPtr->finishAckProcessing(*ackEvent);
      return;
    }

    // Bound bandwidth for model - apply short-term limit in Drain
    Optional<Bandwidth> bwUpperBound;
    if (shared_->state_ != Bbr2State::Startup &&
        bandwidthShortTerm_.has_value() &&
        !conn_.transportSettings.ccaConfig.ignoreShortTerm) {
      bwUpperBound = bandwidthShortTerm_;
    }
    shared_->boundBwForModel(std::move(bwUpperBound));

    // Module-specific pacing
    setPacing();

    shared_->completeAckProcessing(
        calculateCwnd(),
        *ackEvent,
        0, // inflightLongTerm_ not used in Startup
        inflightShortTerm_.value_or(0),
        bandwidthShortTerm_);
  }
}

void Bbr2Startup::setResumeHints(
    uint64_t cwndHintBytes,
    std::chrono::milliseconds rttHint) {
  if (!cwndHintBytes_.has_value()) {
    cwndHintBytes_ = cwndHintBytes;
    rttHint_ = rttHint;
  }
}

// Internals

void Bbr2Startup::resetShortTermModel() {
  bandwidthShortTerm_.reset();
  inflightShortTerm_.reset();
}

void Bbr2Startup::enterStartup() {
  shared_->state_ = Bbr2State::Startup;
  updatePacingGain();
}

void Bbr2Startup::setPacing() {
  if (!conn_.transportSettings.ccaConfig.paceInitCwnd &&
      conn_.lossState.totalBytesSent <
          conn_.transportSettings.initCwndInMss * conn_.udpSendPacketLen) {
    return;
  }

  // Determine minimum pacing window for Startup before full bandwidth reached
  Optional<uint64_t> minPacingWindow;
  if (shared_->state_ == Bbr2State::Startup && !fullBwReached_) {
    minPacingWindow =
        conn_.udpSendPacketLen * conn_.transportSettings.initCwndInMss;
    if (isResuming_) {
      minPacingWindow = std::max(*minPacingWindow, cwndHintBytes_.value() / 2);
    }
  }

  // Choose RTT factor based on state
  auto rttFactor = (shared_->state_ == Bbr2State::Startup)
      ? conn_.transportSettings.startupRttFactor
      : conn_.transportSettings.defaultRttFactor;

  shared_->setPacing(rttFactor, minPacingWindow);
}

uint64_t Bbr2Startup::calculateCwnd() const {
  const auto& ackedBytes = shared_->currentAckEvent_->ackedBytes;

  auto targetBDP = shared_->getBDPWithGain(kStartupCwndGain);
  if (fullBwReached_) {
    targetBDP += shared_->maxExtraAckedFilter_.GetBest();
  } else if (conn_.transportSettings.ccaConfig.enableAckAggregationInStartup) {
    targetBDP += shared_->latestExtraAcked_;
  }
  auto inflightMax = shared_->addQuantizationBudget(targetBDP);

  auto cwndBytes = shared_->cwndBytes_;
  if (fullBwReached_) {
    cwndBytes = std::min(cwndBytes + ackedBytes, inflightMax);
  } else if (
      shared_->state_ == Bbr2State::Startup && isResuming_ &&
      cwndHintBytes_.value() / 2 > inflightMax) {
    auto resumptionBdp =
        uint64_t(cwndHintBytes_.value() * kStartupCwndGain / 2);
    cwndBytes = std::max(cwndBytes, resumptionBdp);
  } else if (
      cwndBytes < inflightMax ||
      conn_.lossState.totalBytesAcked <
          conn_.transportSettings.initCwndInMss * conn_.udpSendPacketLen) {
    cwndBytes += ackedBytes;
  }

  if (shared_->recoveryState_ != Bbr2Shared::RecoveryState::NOT_RECOVERY) {
    cwndBytes = std::min(cwndBytes, shared_->recoveryWindow_);
  }

  cwndBytes = std::max(cwndBytes, kMinCwndInMssForBbr * conn_.udpSendPacketLen);

  // Apply short-term model bounds in Drain
  if (shared_->state_ == Bbr2State::Drain && inflightShortTerm_.has_value() &&
      !conn_.transportSettings.ccaConfig.ignoreShortTerm) {
    cwndBytes = std::min(cwndBytes, *inflightShortTerm_);
  }

  return cwndBytes;
}

void Bbr2Startup::updateCongestionSignals() {
  if (!shared_->lossRoundStart_) {
    return; // we're still within the same round
  }

  // Short-term model update for Startup loss handling
  if (shared_->lossPctInLastRound_ > 0 &&
      shared_->state_ == Bbr2State::Startup) {
    shared_->updateShortTermModelOnLoss(
        bandwidthShortTerm_, inflightShortTerm_);
  }
}

void Bbr2Startup::checkResumptionState() {
  if (shared_->state_ != Bbr2State::Startup ||
      !conn_.transportSettings.useCwndHintsInSessionTicket ||
      !cwndHintBytes_.has_value() || !shared_->roundStart_) {
    return;
  }

  if (!resumeStartRound_.has_value() && shared_->lossEventsInLastRound_ == 0 &&
      conn_.lossState.maybeLrtt.has_value()) {
    // New round, we haven't resumed yet, we have no loss, we have an RTT
    // sample

    // Mark resumption started whether we decide to resume or not so we don't
    // keep doing this check.
    resumeStartRound_ = shared_->roundCount_;

    // Current RTT must be within 0.5x-10x of saved RTT for resumption
    if (rttHint_.has_value()) {
      auto savedRtt = rttHint_.value();
      auto currentRtt = conn_.lossState.maybeLrtt.value();
      if (currentRtt < savedRtt / 2 || currentRtt > savedRtt * 10) {
        // Path has changed significantly, don't resume
        return;
      }
    }

    isResuming_ = true;
  } else if (
      isResuming_ && resumeStartRound_.has_value() &&
      resumeStartRound_.value() + 2 <= shared_->roundCount_) {
    isResuming_ = false;
  }
}

void Bbr2Startup::checkStartupDone() {
  checkStartupHighLoss();

  if (shared_->state_ == Bbr2State::Startup && fullBwReached_) {
    enterDrain();
  }
}

void Bbr2Startup::checkStartupHighLoss() {
  /*
  Our implementation differs from the spec a bit here. The conditions in the
  spec are:
  1. The connection has been in fast recovery for at least one full packet-timed
  round trip.
  2. The loss rate over the time scale of a single full round trip exceeds
  BBRLossThresh (2%).
  3. There are at least BBRStartupFullLossCnt=6
  noncontiguous sequence ranges lost in that round trip.

  For 1,2 we use the loss pct from the last loss round which means we could exit
  before a full RTT.
  */
  if (fullBwReached_ || !shared_->roundStart_ ||
      shared_->lastAckedPacketAppLimited_ ||
      !conn_.transportSettings.ccaConfig.exitStartupOnLoss) {
    return; /* no need to check for a the loss exit condition now */
  }
  if (shared_->lossPctInLastRound_ > kLossThreshold &&
      (shared_->lossEventsInLastRound_ >= 6 || isResuming_)) {
    fullBwReached_ = true;
    shared_->inflightLongTerm_ =
        std::max(shared_->getBDPWithGain(), shared_->inflightLatest_);
  }
}

void Bbr2Startup::checkFullBwReached() {
  if (fullBwNow_ || shared_->lastAckedPacketAppLimited_) {
    return; /* no need to check for a full pipe now */
  }
  if (!shared_->roundStart_) {
    return;
  }
  auto maxBw = shared_->maxBwFilter_.GetBest();
  if (maxBw >= fullBw_ * 1.25) {
    resetFullBw(); // bw still growing, reset tracking
    fullBw_ = maxBw; /* record new baseline level */
    return;
  }
  fullBwCount_++; /* another round w/o much growth */
  fullBwNow_ = (fullBwCount_ >= 3);
  if (fullBwNow_) {
    fullBwReached_ = true;
  }
}

void Bbr2Startup::resetFullBw() {
  fullBw_ = Bandwidth();
  fullBwNow_ = false;
  fullBwCount_ = 0;
}

void Bbr2Startup::enterDrain() {
  shared_->state_ = Bbr2State::Drain;
  updatePacingGain();
  if (isResuming_) {
    auto safeRetreatBw = shared_->maxBwFilter_.GetBest() / 2;
    shared_->maxBwFilter_.Reset(safeRetreatBw, shared_->roundCount_);
    isResuming_ = false;
  }
}

bool Bbr2Startup::isDrainComplete() const noexcept {
  return shared_->state_ == Bbr2State::Drain &&
      conn_.lossState.inflightBytes <= shared_->getTargetInflightWithGain(1.0);
}

void Bbr2Startup::updatePacingGain() {
  float pacingGain = 1.0;

  switch (shared_->state_) {
    case Bbr2State::Startup:
      pacingGain =
          conn_.transportSettings.ccaConfig.overrideStartupPacingGain > 0
          ? conn_.transportSettings.ccaConfig.overrideStartupPacingGain
          : kStartupPacingGain;
      break;
    case Bbr2State::Drain:
      pacingGain = kDrainPacingGain;
      break;
    case Bbr2State::ProbeBw_Down:
    case Bbr2State::ProbeBw_Cruise:
    case Bbr2State::ProbeBw_Refill:
    case Bbr2State::ProbeBw_Up:
    case Bbr2State::ProbeRtt:
      // Should not happen - only Startup/Drain states expected
      MVLOG_ERROR << fmt::format(
          "Unexpected Bbr2Startup state: {}",
          bbr2StateToString(shared_->state_));
      break;
  }

  shared_->pacingGain_ = pacingGain;
}

} // namespace quic
