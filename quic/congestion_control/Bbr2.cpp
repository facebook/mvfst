/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <quic/congestion_control/Bbr2.h>

#include <quic/congestion_control/CongestionControlFunctions.h>
#include <sys/types.h>
#include <chrono>
#include <cstdint>
#include <limits>

namespace quic {

constexpr uint64_t kMaxBwFilterLen = 2; // Measured in number of ProbeBW cycles
constexpr std::chrono::microseconds kProbeRTTInterval = 10s;
constexpr std::chrono::microseconds kProbeRttDuration = 200ms;
constexpr std::chrono::microseconds kMinRttFilterLen = 10s + kProbeRttDuration;
constexpr uint64_t kMaxExtraAckedFilterLen =
    10; // Measured in packet-timed round trips

constexpr float kStartupPacingGain = 2.885; // 2 / ln(2)
constexpr float kDrainPacingGain = 0.5;
constexpr float kProbeBwDownPacingGain = 0.9;
constexpr float kProbeBwCruiseRefillPacingGain = 1.0;
constexpr float kProbeBwUpPacingGain = 1.25;
constexpr float kProbeRttPacingGain = 1.0;

constexpr float kStartupCwndGain = 2.885;
constexpr float kProbeBwCruiseRefillCwndGain = 2.0;
constexpr float kProbeBwDownCwndGain = 2.0;
constexpr float kProbeBwUpCwndGain = 2.25;
constexpr float kProbeRttCwndGain = 0.5;

constexpr float kBeta = 0.7;

constexpr float kLossThreshold = 0.02;
constexpr float kHeadroomFactor = 0.15;

// TODO: Restore this margin
constexpr uint8_t kPacingMarginPercent = 0;

Bbr2CongestionController::Bbr2CongestionController(
    QuicConnectionStateBase& conn)
    : conn_(conn),
      // WindowedFilter window_length is expiry time which inflates the window
      // length by 1
      maxBwFilter_(kMaxBwFilterLen - 1, Bandwidth(), 0),
      probeRttMinTimestamp_(Clock::now()),
      maxExtraAckedFilter_(kMaxExtraAckedFilterLen, 0, 0),
      cwndBytes_(
          conn_.udpSendPacketLen * conn_.transportSettings.initCwndInMss) {
  resetCongestionSignals();
  resetFullBw();
  resetLowerBounds();
  // If we explicitly don't want to pace the init cwnd, reset the pacing rate.
  // Otherwise, leave it to the pacer's initial state.
  if (!conn_.transportSettings.ccaConfig.paceInitCwnd) {
    if (conn_.pacer) {
      conn_.pacer->refreshPacingRate(cwndBytes_, 0us);
    } else {
      LOG(WARNING) << "BBR2 was initialized on a connection without a pacer";
    }
  }
  enterStartup();
}

// Congestion Controller Interface

void Bbr2CongestionController::onRemoveBytesFromInflight(
    uint64_t bytesToRemove) {
  subtractAndCheckUnderflow(conn_.lossState.inflightBytes, bytesToRemove);
}

void Bbr2CongestionController::onPacketSent(
    const OutstandingPacketWrapper& packet) {
  // Handle restart from idle
  if (conn_.lossState.inflightBytes == 0 && isAppLimited()) {
    idleRestart_ = true;
    extraAckedStartTimestamp_ = Clock::now();
    extraAckedDelivered_ = 0;

    if (isProbeBwState(state_)) {
      setPacing();
    } else if (state_ == State::ProbeRTT) {
      checkProbeRttDone();
    }
  }

  addAndCheckOverflow(
      conn_.lossState.inflightBytes, packet.metadata.encodedSize);

  // Maintain cwndLimited flag. We consider the transport being cwnd limited if
  // we are using > 90% of the cwnd.
  if (conn_.lossState.inflightBytes > cwndBytes_ * 9 / 10) {
    cwndLimitedInRound_ |= true;
  }
}

void Bbr2CongestionController::onPacketAckOrLoss(
    const AckEvent* FOLLY_NULLABLE ackEvent,
    const LossEvent* FOLLY_NULLABLE lossEvent) {
  if (conn_.qLogger) {
    conn_.qLogger->addCongestionMetricUpdate(
        conn_.lossState.inflightBytes,
        getCongestionWindow(),
        kCongestionPacketAck,
        bbr2StateToString(state_));
    conn_.qLogger->addNetworkPathModelUpdate(
        inflightHi_.value_or(0),
        inflightLo_.value_or(0),
        0, // bandwidthHi_ no longer available.
        std::chrono::microseconds(1), // bandwidthHi_ no longer available.
        bandwidthLo_.has_value() ? bandwidthLo_->units : 0,
        bandwidthLo_.has_value() ? bandwidthLo_->interval
                                 : std::chrono::microseconds(1));
  }
  if (ackEvent) {
    subtractAndCheckUnderflow(
        conn_.lossState.inflightBytes, ackEvent->ackedBytes);
  }
  if (lossEvent) {
    subtractAndCheckUnderflow(
        conn_.lossState.inflightBytes, lossEvent->lostBytes);
  }
  SCOPE_EXIT {
    VLOG(6) << "State=" << bbr2StateToString(state_)
            << " inflight=" << conn_.lossState.inflightBytes
            << " cwnd=" << getCongestionWindow() << "(gain=" << cwndGain_
            << ")";
  };

  if (lossEvent && lossEvent->lostPackets > 0) {
    auto ackedBytes = ackEvent ? ackEvent->ackedBytes : 0;
    onPacketLoss(*lossEvent, ackedBytes);
  }

  if (ackEvent) {
    currentAckEvent_ = ackEvent;

    if (currentAckEvent_->implicit) {
      // Implicit acks should not be used for bandwidth or rtt estimation
      setCwnd();
      return;
    }

    if (appLimited_ &&
        appLimitedLastSendTime_ <= ackEvent->largestNewlyAckedPacketSentTime) {
      appLimited_ = false;
      if (conn_.qLogger) {
        conn_.qLogger->addAppUnlimitedUpdate();
      }
    }

    currentBwSample_ = getBandwidthSampleFromAck(*ackEvent);
    auto lastAckedPacket = currentAckEvent_->getLargestNewlyAckedPacket();
    inflightBytesAtLastAckedPacket_ = lastAckedPacket
        ? lastAckedPacket->outstandingPacketMetadata.inflightBytes
        : conn_.lossState.inflightBytes;
    lastAckedPacketAppLimited_ =
        lastAckedPacket ? lastAckedPacket->isAppLimited : true;

    // UpdateModelAndState
    updateLatestDeliverySignals();
    updateRound();

    updateRecoveryOnAck();

    updateCongestionSignals(lossEvent);
    updateAckAggregation();
    checkFullBwReached();
    checkStartupDone();
    checkDrain();

    updateProbeBwCyclePhase();
    updateMinRtt();
    checkProbeRtt();
    advanceLatestDeliverySignals();
    boundBwForModel();

    // UpdateControlParameters
    setPacing();
    setSendQuantum();
    setCwnd();

    // Update cwndLimited state before the next ack
    if (roundStart_) {
      cwndLimitedInRound_ = false;
    }
  }
}

uint64_t Bbr2CongestionController::getWritableBytes() const noexcept {
  return getCongestionWindow() > conn_.lossState.inflightBytes
      ? getCongestionWindow() - conn_.lossState.inflightBytes
      : 0;
}

uint64_t Bbr2CongestionController::getCongestionWindow() const noexcept {
  return cwndBytes_;
}

CongestionControlType Bbr2CongestionController::type() const noexcept {
  return CongestionControlType::BBR2;
}

Optional<Bandwidth> Bbr2CongestionController::getBandwidth() const {
  return bandwidth_;
}

bool Bbr2CongestionController::isAppLimited() const {
  return appLimited_;
}

void Bbr2CongestionController::setAppLimited() noexcept {
  appLimited_ = true;
  appLimitedLastSendTime_ = Clock::now();
  if (conn_.qLogger) {
    conn_.qLogger->addAppLimitedUpdate();
  }
}

// Internals

void Bbr2CongestionController::onPacketLoss(
    const LossEvent& lossEvent,
    uint64_t ackedBytes) {
  if ((state_ == State::Startup || state_ == State::Drain) &&
      !conn_.transportSettings.ccaConfig.enableRecoveryInStartup) {
    // Recovery is not enabled in Startup.
    return;
  }
  if ((isProbeBwState(state_) || state_ == State::ProbeRTT) &&
      !conn_.transportSettings.ccaConfig.enableRecoveryInProbeStates) {
    // Recovery is not enabled in Probe states.
    return;
  }

  saveCwnd();
  recoveryStartTime_ = Clock::now();
  if (!isInRecovery()) {
    recoveryState_ = RecoveryState::CONSERVATIVE;
    recoveryWindow_ = conn_.lossState.inflightBytes + ackedBytes;

    // Ensure conservative recovery lasts for at least a whole round trip.
    nextRoundDelivered_ = conn_.lossState.totalBytesAcked;
  }

  if (lossEvent.persistentCongestion) {
    recoveryWindow_ = kMinCwndInMssForBbr * conn_.udpSendPacketLen;
  } else {
    recoveryWindow_ =
        (recoveryWindow_ > kMinCwndInMssForBbr * conn_.udpSendPacketLen)
        ? recoveryWindow_ - lossEvent.lostBytes
        : kMinCwndInMssForBbr * conn_.udpSendPacketLen;
  }

  recoveryWindow_ = boundedCwnd(
      recoveryWindow_,
      conn_.udpSendPacketLen,
      conn_.transportSettings.maxCwndInMss,
      kMinCwndInMssForBbr);
}

void Bbr2CongestionController::updateRecoveryOnAck() {
  if (!isInRecovery()) {
    return;
  }

  if (roundStart_ && recoveryState_ != RecoveryState::GROWTH) {
    recoveryState_ = RecoveryState::GROWTH;
  }

  if (recoveryStartTime_ <= currentAckEvent_->largestNewlyAckedPacketSentTime) {
    recoveryState_ = RecoveryState::NOT_RECOVERY;
    restoreCwnd();
  } else {
    if (recoveryState_ == RecoveryState::GROWTH) {
      recoveryWindow_ += currentAckEvent_->ackedBytes;
    }

    uint64_t recoveryIncrease =
        conn_.transportSettings.ccaConfig.conservativeRecovery
        ? conn_.udpSendPacketLen
        : currentAckEvent_->ackedBytes;
    recoveryWindow_ = std::max(
        recoveryWindow_, conn_.lossState.inflightBytes + recoveryIncrease);
    recoveryWindow_ = boundedCwnd(
        recoveryWindow_,
        conn_.udpSendPacketLen,
        conn_.transportSettings.maxCwndInMss,
        kMinCwndInMssForBbr);
  }
}

void Bbr2CongestionController::resetCongestionSignals() {
  lossBytesInRound_ = 0;
  lossEventsInRound_ = 0;
  largestLostPacketNumInRound_ = 0;
  bandwidthLatest_ = Bandwidth();
  inflightLatest_ = 0;
}

void Bbr2CongestionController::resetLowerBounds() {
  bandwidthLo_.reset();
  inflightLo_.reset();
}
void Bbr2CongestionController::enterStartup() {
  state_ = State::Startup;
  updatePacingAndCwndGain();
}

void Bbr2CongestionController::setPacing() {
  if (!conn_.transportSettings.ccaConfig.paceInitCwnd &&
      conn_.lossState.totalBytesSent <
          conn_.transportSettings.initCwndInMss * conn_.udpSendPacketLen) {
    return;
  }
  uint64_t pacingWindow =
      bandwidth_ * minRtt_ * pacingGain_ * (100 - kPacingMarginPercent) / 100;
  VLOG(6) << "Setting pacing to "
          << Bandwidth(pacingWindow, minRtt_).normalizedDescribe()
          << " from bandwidth_=" << bandwidth_.normalizedDescribe()
          << " pacingGain_=" << pacingGain_
          << " kPacingMarginPercent=" << kPacingMarginPercent
          << " units=" << pacingWindow << " interval=" << minRtt_.count();

  if (state_ == State::Startup && !fullBwReached_) {
    pacingWindow = std::max(
        pacingWindow,
        conn_.udpSendPacketLen * conn_.transportSettings.initCwndInMss);
  }
  conn_.pacer->refreshPacingRate(pacingWindow, minRtt_);
}

void Bbr2CongestionController::setSendQuantum() {
  auto rate = bandwidth_ * pacingGain_ * (100 - kPacingMarginPercent) / 100;
  auto burstInPacerTick = rate * conn_.transportSettings.pacingTickInterval;
  sendQuantum_ =
      std::min(burstInPacerTick, decltype(burstInPacerTick)(64 * 1024));
  sendQuantum_ = std::max(sendQuantum_, 2 * conn_.udpSendPacketLen);
}

void Bbr2CongestionController::setCwnd() {
  // BBRUpdateMaxInflight()
  const auto& ackedBytes = currentAckEvent_->ackedBytes;
  auto targetBDP = getBDPWithGain(cwndGain_);
  if (fullBwReached_) {
    targetBDP += maxExtraAckedFilter_.GetBest();
  } else if (conn_.transportSettings.ccaConfig.enableAckAggregationInStartup) {
    targetBDP += latestExtraAcked_;
  }
  auto inflightMax = addQuantizationBudget(targetBDP);

  if (fullBwReached_) {
    cwndBytes_ = std::min(cwndBytes_ + ackedBytes, inflightMax);
  } else if (
      cwndBytes_ < inflightMax ||
      conn_.lossState.totalBytesAcked <
          conn_.transportSettings.initCwndInMss * conn_.udpSendPacketLen) {
    cwndBytes_ += ackedBytes;
  }

  if (isInRecovery()) {
    cwndBytes_ = std::min(cwndBytes_, recoveryWindow_);
  }

  cwndBytes_ =
      std::max(cwndBytes_, kMinCwndInMssForBbr * conn_.udpSendPacketLen);

  // BBRBoundCwndForProbeRTT()
  if (state_ == State::ProbeRTT) {
    cwndBytes_ = std::min(cwndBytes_, getProbeRTTCwnd());
  }

  // BBRBoundCwndForModel()
  auto cap = std::numeric_limits<uint64_t>::max();
  if (inflightHi_.has_value() &&
      !conn_.transportSettings.ccaConfig.ignoreInflightHi) {
    if (isProbeBwState(state_) && state_ != State::ProbeBw_Cruise) {
      cap = *inflightHi_;
    } else if (state_ == State::ProbeRTT || state_ == State::ProbeBw_Cruise) {
      cap = getTargetInflightWithHeadroom();
    }
  }
  if (inflightLo_.has_value() &&
      !conn_.transportSettings.ccaConfig.ignoreLoss) {
    cap = std::min(cap, *inflightLo_);
  }
  cwndBytes_ = std::min(cwndBytes_, cap);

  cwndBytes_ = boundedCwnd(
      cwndBytes_,
      conn_.udpSendPacketLen,
      conn_.transportSettings.maxCwndInMss,
      kMinCwndInMssForBbr);
}

void Bbr2CongestionController::checkProbeRttDone() {
  auto timeNow = Clock::now();
  if ((probeRttDoneTimestamp_ && timeNow > *probeRttDoneTimestamp_) ||
      conn_.lossState.inflightBytes == 0) {
    // Schedule the next ProbeRTT
    probeRttMinTimestamp_ = timeNow;
    restoreCwnd();
    exitProbeRtt();
  }
}

void Bbr2CongestionController::restoreCwnd() {
  cwndBytes_ = std::max(cwndBytes_, previousCwndBytes_);
  VLOG(6) << "Restored cwnd: " << cwndBytes_;
}
void Bbr2CongestionController::exitProbeRtt() {
  resetLowerBounds();
  if (fullBwReached_) {
    startProbeBwDown();
    startProbeBwCruise();
  } else {
    enterStartup();
  }
}

void Bbr2CongestionController::updateLatestDeliverySignals() {
  lossRoundStart_ = false;

  bandwidthLatest_ = std::max(bandwidthLatest_, currentBwSample_);
  VLOG(6) << "Bandwidth latest=" << bandwidthLatest_.normalizedDescribe()
          << "  AppLimited=" << bandwidthLatest_.isAppLimited;
  inflightLatest_ = std::max(inflightLatest_, bandwidthLatest_.units);

  auto pkt = currentAckEvent_->getLargestNewlyAckedPacket();
  if (pkt &&
      pkt->outstandingPacketMetadata.totalBytesSent > lossRoundEndBytesSent_) {
    // Uses bytes sent instead of ACKed in the spec. This doesn't affect the
    // round counting
    lossPctInLastRound_ = static_cast<float>(lossBytesInRound_) /
        static_cast<float>(conn_.lossState.totalBytesSent -
                           lossRoundEndBytesSent_);
    lossEventsInLastRound_ = lossEventsInRound_;
    lossRoundEndBytesSent_ = conn_.lossState.totalBytesSent;
    lossRoundStart_ = true;
  }
}

void Bbr2CongestionController::updateCongestionSignals(
    const LossEvent* FOLLY_NULLABLE lossEvent) {
  // Update max bandwidth
  if (bandwidthLatest_ > maxBwFilter_.GetBest() ||
      !bandwidthLatest_.isAppLimited) {
    VLOG(6) << "Updating bandwidth filter with sample: "
            << bandwidthLatest_.normalizedDescribe();
    maxBwFilter_.Update(bandwidthLatest_, cycleCount_);
  }

  // Update loss signal
  if (lossEvent && lossEvent->lostBytes > 0 &&
      !lossEvent->lostPacketNumbers.empty()) {
    lossBytesInRound_ += lossEvent->lostBytes;

    // Only count non-contiguous losses as lossEvents
    auto lastLossPn = largestLostPacketNumInRound_;
    for (auto& pn : lossEvent->lostPacketNumbers) {
      if (pn > lastLossPn + 1) {
        lossEventsInRound_ += 1;
      }
      lastLossPn = pn;
    }

    // lossEvent->largestLostPacketNum should always be set if we have losses.
    largestLostPacketNumInRound_ = std::max(
        lossEvent->largestLostPacketNum.value_or(0),
        largestLostPacketNumInRound_);
  }

  if (!lossRoundStart_) {
    return; // we're still within the same round
  }
  if (lossBytesInRound_ > 0 && !isProbingBandwidth(state_)) {
    // InitLowerBounds
    if (!bandwidthLo_.has_value()) {
      bandwidthLo_ = maxBwFilter_.GetBest();
    }
    if (!inflightLo_.has_value()) {
      inflightLo_ = cwndBytes_;
    }

    // LossLowerBounds
    bandwidthLo_ = std::max(bandwidthLatest_, *bandwidthLo_ * kBeta);
    inflightLo_ =
        std::max(inflightLatest_, static_cast<uint64_t>(*inflightLo_ * kBeta));
  }

  lossBytesInRound_ = 0;
  lossEventsInRound_ = 0;
  largestLostPacketNumInRound_ = 0;
}

void Bbr2CongestionController::updateAckAggregation() {
  /* Find excess ACKed beyond expected amount over this interval */
  auto interval =
      Clock::now() - extraAckedStartTimestamp_.value_or(conn_.connectionTime);
  auto expectedDelivered = bandwidth_ *
      std::chrono::duration_cast<std::chrono::microseconds>(interval);
  /* Reset interval if ACK rate is below expected rate: */
  if (extraAckedDelivered_ < expectedDelivered) {
    extraAckedDelivered_ = 0;
    extraAckedStartTimestamp_ = Clock::now();
    expectedDelivered = 0;
  }
  extraAckedDelivered_ += currentAckEvent_->ackedBytes;
  latestExtraAcked_ = extraAckedDelivered_ - expectedDelivered;
  latestExtraAcked_ = std::min(latestExtraAcked_, cwndBytes_);
  maxExtraAckedFilter_.Update(latestExtraAcked_, roundCount_);
}
void Bbr2CongestionController::checkStartupDone() {
  checkStartupHighLoss();

  if (state_ == State::Startup && fullBwReached_) {
    QUIC_STATS(conn_.statsCallback, onBBR2ExitStartup);
    enterDrain();
  }
}

void Bbr2CongestionController::checkStartupHighLoss() {
  /*
  Our implementation differs from the spec a bit here. The conditions in the
  spec are:
  1. The connection has been in fast recovery for at least one full packet-timed
  round trip.
  2. The loss rate over the time scale of a single full round trip exceeds
  BBRLossThresh (2%).
  3. There are at least BBRStartupFullLossCnt=6
  discontiguous sequence ranges lost in that round trip.

  For 1,2 we use the loss pct from the last loss round which means we could exit
  before a full RTT.
  */
  if (fullBwReached_ || !roundStart_ || lastAckedPacketAppLimited_ ||
      !conn_.transportSettings.ccaConfig.exitStartupOnLoss) {
    return; /* no need to check for a the loss exit condition now */
  }
  if (lossPctInLastRound_ > kLossThreshold && lossEventsInLastRound_ >= 6) {
    fullBwReached_ = true;
    inflightHi_ = std::max(getBDPWithGain(), inflightLatest_);
  }
}

void Bbr2CongestionController::checkFullBwReached() {
  if (fullBwNow_ || lastAckedPacketAppLimited_) {
    return; /* no need to check for a full pipe now */
  }
  if (!roundStart_) {
    return;
  }
  if (maxBwFilter_.GetBest() >= fullBw_ * 1.25) {
    resetFullBw(); // bw still growing, reset tracking
    fullBw_ = maxBwFilter_.GetBest(); /* record new baseline level */
    return;
  }
  fullBwCount_++; /* another round w/o much growth */
  fullBwNow_ = (fullBwCount_ >= 3);
  if (fullBwNow_) {
    fullBwReached_ = true;
  }
}

void Bbr2CongestionController::resetFullBw() {
  fullBw_ = Bandwidth();
  fullBwNow_ = false;
  fullBwCount_ = 0;
}

void Bbr2CongestionController::enterDrain() {
  state_ = State::Drain;
  updatePacingAndCwndGain();
}

void Bbr2CongestionController::checkDrain() {
  if (state_ == State::Drain) {
    VLOG(6) << "Current inflight" << conn_.lossState.inflightBytes
            << " target inflight " << getTargetInflightWithGain(1.0);
  }
  if (state_ == State::Drain &&
      conn_.lossState.inflightBytes <= getTargetInflightWithGain(1.0)) {
    enterProbeBW(); /* BBR estimates the queue was drained */
  }
}
void Bbr2CongestionController::updateProbeBwCyclePhase() {
  /* The core state machine logic for ProbeBW: */
  if (!fullBwReached_) {
    return; /* only handling steady-state behavior here */
  }
  adaptUpperBounds();
  if (!isProbeBwState(state_)) {
    return; /* only handling ProbeBW states here: */
  }
  switch (state_) {
    case State::ProbeBw_Down:
      if (checkTimeToProbeBW()) {
        return; /* already decided state transition */
      }
      if (checkTimeToCruise()) {
        startProbeBwCruise();
      }
      break;
    case State::ProbeBw_Cruise:
      if (checkTimeToProbeBW()) {
        return; /* already decided state transition */
      }
      break;
    case State::ProbeBw_Refill:
      /* After one round of REFILL, start UP */
      if (roundStart_) {
        // Enable one reaction to loss per probe bw cycle.
        canUpdateLongtermLossModel_ = true;
        startProbeBwUp();
      }
      break;
    case State::ProbeBw_Up:
      if (checkTimeToGoDown()) {
        canUpdateLongtermLossModel_ = false;
        startProbeBwDown();
      }
      break;
    default:
      throw QuicInternalException(
          "BBR2: Unexpected state in ProbeBW phase: " +
              bbr2StateToString(state_),
          LocalErrorCode::CONGESTION_CONTROL_ERROR);
  }
}

void Bbr2CongestionController::adaptUpperBounds() {
  /* Update BBR.inflight_hi and BBR.bw_hi. */

  if (!checkInflightTooHigh()) {
    if (!inflightHi_.has_value()) {
      // No loss has occurred yet so these values are not set and do not need to
      // be raised.
      return;
    }
    /* There is loss but it's at safe levels. The limits are populated so we
     * update them */
    if (inflightBytesAtLastAckedPacket_ > *inflightHi_) {
      inflightHi_ = inflightBytesAtLastAckedPacket_;
    }
    if (state_ == State::ProbeBw_Up) {
      probeInflightHiUpward();
    }
  }
}

bool Bbr2CongestionController::checkTimeToProbeBW() {
  if (hasElapsedInPhase(bwProbeWait_) || isRenoCoexistenceProbeTime()) {
    startProbeBwRefill();
    return true;
  } else {
    return false;
  }
}

bool Bbr2CongestionController::checkTimeToCruise() {
  if (conn_.lossState.inflightBytes > getTargetInflightWithHeadroom()) {
    return false; /* not enough headroom */
  } else if (conn_.lossState.inflightBytes <= getTargetInflightWithGain()) {
    return true; /* inflight <= estimated BDP */
  }
  // Neither conditions met. Do not cruise yet.
  return false;
}

bool Bbr2CongestionController::checkTimeToGoDown() {
  if (cwndLimitedInRound_ && inflightHi_.has_value() &&
      getTargetInflightWithGain(1.25) >= inflightHi_.value()) {
    resetFullBw();
    fullBw_ = maxBwFilter_.GetBest();
  } else if (fullBwNow_) {
    return true;
  }
  return false;
}

bool Bbr2CongestionController::hasElapsedInPhase(
    std::chrono::microseconds interval) {
  return Clock::now() > probeBWCycleStart_ + interval;
}

// Was the loss percent too high for the last ack received?
bool Bbr2CongestionController::checkInflightTooHigh() {
  if (isInflightTooHigh()) {
    if (canUpdateLongtermLossModel_) {
      handleInFlightTooHigh();
    }
    return true;
  } else {
    return false;
  }
}

bool Bbr2CongestionController::isInflightTooHigh() {
  // TODO: The comparison should ideally use the  bytes lost since the
  // largestAckedPacket was sent, but we don't track that.
  return static_cast<float>(lossBytesInRound_) >
      static_cast<float>(inflightBytesAtLastAckedPacket_) * kLossThreshold;
}

void Bbr2CongestionController::handleInFlightTooHigh() {
  canUpdateLongtermLossModel_ = false;
  if (!lastAckedPacketAppLimited_) {
    inflightHi_ = std::max(
        inflightBytesAtLastAckedPacket_,
        static_cast<uint64_t>(
            static_cast<float>(getTargetInflightWithGain()) * kBeta));
  }
  if (state_ == State::ProbeBw_Up) {
    startProbeBwDown();
  }
}

uint64_t Bbr2CongestionController::getTargetInflightWithHeadroom() const {
  /* Return a volume of data that tries to leave free
   * headroom in the bottleneck buffer or link for
   * other flows, for fairness convergence and lower
   * RTTs and loss */
  if (!inflightHi_.has_value()) {
    return std::numeric_limits<uint64_t>::max();
  } else {
    auto headroom = static_cast<uint64_t>(
        std::max(1.0f, kHeadroomFactor * static_cast<float>(*inflightHi_)));
    return std::max(
        *inflightHi_ - headroom,
        quic::kMinCwndInMssForBbr * conn_.udpSendPacketLen);
  }
}

void Bbr2CongestionController::probeInflightHiUpward() {
  if (!inflightHi_.has_value() || !cwndLimitedInRound_ ||
      cwndBytes_ < *inflightHi_) {
    return; /* no inflight_hi set or not fully using inflight_hi, so don't grow
               it */
  }
  probeUpAcks_ += currentAckEvent_->ackedBytes;
  if (probeUpAcks_ >= probeUpCount_) {
    auto delta = probeUpAcks_ / probeUpCount_;
    probeUpAcks_ -= delta * probeUpCount_;
    addAndCheckOverflow(*inflightHi_, delta);
  }
  if (roundStart_) {
    raiseInflightHiSlope();
  }
}

void Bbr2CongestionController::updateMinRtt() {
  if (idleRestart_) {
    probeRttMinTimestamp_ = Clock::now();
    probeRttMinValue_ = kDefaultMinRtt;
  }
  probeRttExpired_ = probeRttMinTimestamp_
      ? Clock::now() > (probeRttMinTimestamp_.value() + kProbeRTTInterval)
      : true;
  auto& lrtt = conn_.lossState.lrtt;
  if (lrtt > 0us && (lrtt < probeRttMinValue_ || probeRttExpired_)) {
    probeRttMinValue_ = lrtt;
    probeRttMinTimestamp_ = Clock::now();
  }

  auto minRttExpired = minRttTimestamp_
      ? Clock::now() > (minRttTimestamp_.value() + kMinRttFilterLen)
      : true;
  if (probeRttMinValue_ < minRtt_ || minRttExpired) {
    minRtt_ = probeRttMinValue_;
    minRttTimestamp_ = probeRttMinTimestamp_;
  }
}

void Bbr2CongestionController::checkProbeRtt() {
  if (state_ != State::ProbeRTT && probeRttExpired_ && !idleRestart_) {
    enterProbeRtt();
    saveCwnd();
    probeRttDoneTimestamp_.reset();
    startRound();
  }
  if (state_ == State::ProbeRTT) {
    handleProbeRtt();
  }
  if (currentAckEvent_->ackedBytes > 0) {
    idleRestart_ = false;
  }
}

void Bbr2CongestionController::enterProbeRtt() {
  state_ = State::ProbeRTT;
  canUpdateLongtermLossModel_ = false;
  updatePacingAndCwndGain();
}

void Bbr2CongestionController::handleProbeRtt() {
  /* Ignore low rate samples during ProbeRTT: */
  // TODO: I don't understand the logic in the spec in
  // MarkConnectionAppLimited() but just setting app limited is reasonable
  setAppLimited();

  if (!probeRttDoneTimestamp_ &&
      conn_.lossState.inflightBytes <= getProbeRTTCwnd()) {
    /* Wait for at least ProbeRTTDuration to elapse: */
    probeRttDoneTimestamp_ = Clock::now() + kProbeRttDuration;
    /* Wait for at least one round to elapse: */
    // Is this needed? BBR.probe_rtt_round_done = false
    startRound();
  } else if (probeRttDoneTimestamp_) {
    if (roundStart_) {
      checkProbeRttDone();
    }
  }
}

void Bbr2CongestionController::advanceLatestDeliverySignals() {
  if (lossRoundStart_) {
    bandwidthLatest_ = currentBwSample_;
    inflightLatest_ = bandwidthLatest_.units;
  }
}

uint64_t Bbr2CongestionController::getProbeRTTCwnd() {
  return std::max(
      getBDPWithGain(kProbeRttCwndGain),
      quic::kMinCwndInMssForBbr * conn_.udpSendPacketLen);
}
void Bbr2CongestionController::boundCwndForProbeRTT() {
  if (state_ == State::ProbeRTT) {
    cwndBytes_ = std::min(cwndBytes_, getProbeRTTCwnd());
  }
}

void Bbr2CongestionController::boundBwForModel() {
  Bandwidth previousBw = bandwidth_;
  bandwidth_ = maxBwFilter_.GetBest();
  if (state_ != State::Startup) {
    if (bandwidthLo_.has_value() &&
        !conn_.transportSettings.ccaConfig.ignoreLoss) {
      bandwidth_ = std::min(bandwidth_, *bandwidthLo_);
    }
  }
  if (conn_.qLogger && previousBw != bandwidth_) {
    conn_.qLogger->addBandwidthEstUpdate(bandwidth_.units, bandwidth_.interval);
  }
}

uint64_t Bbr2CongestionController::addQuantizationBudget(uint64_t input) const {
  // BBRUpdateOffloadBudget()
  auto offloadBudget = 3 * sendQuantum_;
  input = std::max(input, offloadBudget);
  input = std::max(input, quic::kMinCwndInMssForBbr * conn_.udpSendPacketLen);
  if (state_ == State::ProbeBw_Up) {
    // This number is arbitrary from the spec. It's probably to guarantee that
    // probing up is more aggressive (?)
    input += 2 * conn_.udpSendPacketLen;
  }
  return input;
}

void Bbr2CongestionController::saveCwnd() {
  if (!isInRecovery() && state_ != State::ProbeRTT) {
    previousCwndBytes_ = cwndBytes_;
  } else {
    previousCwndBytes_ = std::max(cwndBytes_, previousCwndBytes_);
  }
  VLOG(6) << "Saved cwnd: " << previousCwndBytes_;
}

uint64_t Bbr2CongestionController::getTargetInflightWithGain(float gain) const {
  return addQuantizationBudget(getBDPWithGain(gain));
}

uint64_t Bbr2CongestionController::getBDPWithGain(float gain) const {
  if (minRtt_ == kDefaultMinRtt) {
    return uint64_t(
        gain * conn_.transportSettings.initCwndInMss * conn_.udpSendPacketLen);
  } else {
    return uint64_t(gain * (minRtt_ * bandwidth_));
  }
}

void Bbr2CongestionController::enterProbeBW() {
  startProbeBwDown();
}

void Bbr2CongestionController::startRound() {
  nextRoundDelivered_ = conn_.lossState.totalBytesAcked;
}
void Bbr2CongestionController::updateRound() {
  auto pkt = currentAckEvent_->getLargestNewlyAckedPacket();
  if (pkt && pkt->lastAckedPacketInfo &&
      pkt->lastAckedPacketInfo->totalBytesAcked >= nextRoundDelivered_) {
    startRound();
    roundCount_++;
    roundsSinceBwProbe_++;
    roundStart_ = true;
  } else {
    roundStart_ = false;
  }
}

void Bbr2CongestionController::startProbeBwDown() {
  resetCongestionSignals();
  probeUpCount_ =
      std::numeric_limits<uint64_t>::max(); /* not growing inflight_hi */
  /* Decide random round-trip bound for wait: */
  roundsSinceBwProbe_ = folly::Random::rand32() % 2;
  /* Decide the random wall clock bound for wait: between 2-3 seconds */
  bwProbeWait_ =
      std::chrono::milliseconds(2000 + (folly::Random::rand32() % 1000));

  probeBWCycleStart_ = Clock::now();
  state_ = State::ProbeBw_Down;
  updatePacingAndCwndGain();
  startRound();

  // This is a new ProbeBW cycle. Advance the max bw filter if we're not app
  // limited
  if (!lastAckedPacketAppLimited_) {
    cycleCount_++;
  }
}
void Bbr2CongestionController::startProbeBwCruise() {
  state_ = State::ProbeBw_Cruise;
  updatePacingAndCwndGain();
}

void Bbr2CongestionController::startProbeBwRefill() {
  resetLowerBounds();
  probeUpRounds_ = 0;
  probeUpAcks_ = 0;
  state_ = State::ProbeBw_Refill;
  updatePacingAndCwndGain();
  startRound();
}
void Bbr2CongestionController::startProbeBwUp() {
  probeBWCycleStart_ = Clock::now();
  state_ = State::ProbeBw_Up;
  updatePacingAndCwndGain();
  startRound();
  resetFullBw();
  raiseInflightHiSlope();
}

void Bbr2CongestionController::raiseInflightHiSlope() {
  auto growthThisRound = conn_.udpSendPacketLen << probeUpRounds_;
  probeUpRounds_ = std::min(probeUpRounds_ + 1, decltype(probeUpRounds_)(30));
  probeUpCount_ =
      std::max(cwndBytes_ / growthThisRound, decltype(cwndBytes_)(1));
}

// Utilities
bool Bbr2CongestionController::isProbeBwState(
    const Bbr2CongestionController::State state) {
  return (
      state == Bbr2CongestionController::State::ProbeBw_Down ||
      state == Bbr2CongestionController::State::ProbeBw_Cruise ||
      state == Bbr2CongestionController::State::ProbeBw_Refill ||
      state == Bbr2CongestionController::State::ProbeBw_Up);
}

bool Bbr2CongestionController::isProbingBandwidth(
    const Bbr2CongestionController::State state) {
  return (
      state == Bbr2CongestionController::State::ProbeBw_Up ||
      state == Bbr2CongestionController::State::ProbeBw_Refill ||
      state == Bbr2CongestionController::State::Startup);
}

Bandwidth Bbr2CongestionController::getBandwidthSampleFromAck(
    const AckEvent& ackEvent) {
  auto ackTime = ackEvent.adjustedAckTime;
  auto bwSample = Bandwidth();
  for (auto const& ackedPacket : ackEvent.ackedPackets) {
    auto pkt = &ackedPacket;
    if (ackedPacket.outstandingPacketMetadata.encodedSize == 0) {
      continue;
    }
    auto& lastAckedPacket = pkt->lastAckedPacketInfo;
    auto lastSentTime =
        lastAckedPacket ? lastAckedPacket->sentTime : conn_.connectionTime;

    auto sendElapsed = pkt->outstandingPacketMetadata.time - lastSentTime;

    auto lastAckTime = lastAckedPacket ? lastAckedPacket->adjustedAckTime
                                       : conn_.connectionTime;
    auto ackElapsed = ackTime - lastAckTime;
    auto interval = std::max(ackElapsed, sendElapsed);
    if (interval == 0us) {
      return Bandwidth();
    }
    auto lastBytesDelivered =
        lastAckedPacket ? lastAckedPacket->totalBytesAcked : 0;
    auto bytesDelivered = ackEvent.totalBytesAcked - lastBytesDelivered;
    Bandwidth bw(
        bytesDelivered,
        std::chrono::duration_cast<std::chrono::microseconds>(interval),
        pkt->isAppLimited || lastSentTime < appLimitedLastSendTime_);
    if (bw > bwSample) {
      bwSample = bw;
    }
  }
  return bwSample;
}

bool Bbr2CongestionController::isRenoCoexistenceProbeTime() {
  if (!conn_.transportSettings.ccaConfig.enableRenoCoexistence) {
    return false;
  }
  auto renoBdpInPackets = std::min(getTargetInflightWithGain(), cwndBytes_) /
      conn_.udpSendPacketLen;
  auto roundsBeforeRenoProbe =
      std::min(renoBdpInPackets, decltype(renoBdpInPackets)(63));
  return roundsSinceBwProbe_ >= roundsBeforeRenoProbe;
}

bool Bbr2CongestionController::isInRecovery() const {
  return recoveryState_ != RecoveryState::NOT_RECOVERY;
}

Bbr2CongestionController::State Bbr2CongestionController::getState()
    const noexcept {
  return state_;
}

void Bbr2CongestionController::getStats(
    CongestionControllerStats& stats) const {
  stats.bbr2Stats.state = uint8_t(state_);
}

void Bbr2CongestionController::updatePacingAndCwndGain() {
  switch (state_) {
    case State::Startup:
      pacingGain_ =
          conn_.transportSettings.ccaConfig.overrideStartupPacingGain > 0
          ? conn_.transportSettings.ccaConfig.overrideStartupPacingGain
          : kStartupPacingGain;
      cwndGain_ = kStartupCwndGain;
      break;
    case State::Drain:
      pacingGain_ = kDrainPacingGain;
      cwndGain_ = kStartupCwndGain;
      break;
    case State::ProbeBw_Up:
      pacingGain_ = kProbeBwUpPacingGain;
      cwndGain_ = kProbeBwUpCwndGain;
      break;
    case State::ProbeBw_Down:
      pacingGain_ = kProbeBwDownPacingGain;
      cwndGain_ = kProbeBwDownCwndGain;
      break;
    case State::ProbeBw_Cruise:
    case State::ProbeBw_Refill:
      pacingGain_ =
          conn_.transportSettings.ccaConfig.overrideCruisePacingGain > 0
          ? conn_.transportSettings.ccaConfig.overrideCruisePacingGain
          : kProbeBwCruiseRefillPacingGain;
      cwndGain_ = conn_.transportSettings.ccaConfig.overrideCruiseCwndGain > 0
          ? conn_.transportSettings.ccaConfig.overrideCruiseCwndGain
          : kProbeBwCruiseRefillCwndGain;
      break;
    case State::ProbeRTT:
      pacingGain_ = kProbeRttPacingGain;
      cwndGain_ = kProbeRttCwndGain;
      break;
  }
}

std::string bbr2StateToString(Bbr2CongestionController::State state) {
  switch (state) {
    case Bbr2CongestionController::State::Startup:
      return "Startup";
    case Bbr2CongestionController::State::Drain:
      return "Drain";
    case Bbr2CongestionController::State::ProbeBw_Down:
      return "ProbeBw_Down";
    case Bbr2CongestionController::State::ProbeBw_Cruise:
      return "ProbeBw_Cruise";
    case Bbr2CongestionController::State::ProbeBw_Refill:
      return "ProbeBw_Refill";
    case Bbr2CongestionController::State::ProbeBw_Up:
      return "ProbeBw_Up";
    case Bbr2CongestionController::State::ProbeRTT:
      return "ProbeRTT";
  }
  folly::assume_unreachable();
}

} // namespace quic
