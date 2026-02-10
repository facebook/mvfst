/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <quic/congestion_control/modular/Bbr2Shared.h>

#include <quic/congestion_control/CongestionControlFunctions.h>
#include <quic/logging/QLoggerConstants.h>
#include <quic/logging/QLoggerMacros.h>
#include <chrono>
#include <cstdint>

namespace quic {

constexpr uint64_t kMaxBwFilterLen = 2; // Measured in number of ProbeBW cycles
constexpr uint64_t kMaxExtraAckedFilterLen =
    10; // Measured in packet-timed round trips

// ProbeRtt timing constants
constexpr std::chrono::microseconds kProbeRTTInterval = 10s;
constexpr std::chrono::microseconds kMinRttFilterLen =
    10s + kBbr2ProbeRttDuration;

// Pacing margin
// TODO: Restore this margin to a non-zero value
constexpr uint8_t kPacingMarginPercent = 0;

Bbr2Shared::Bbr2Shared(QuicConnectionStateBase& conn)
    : conn_(conn),
      cwndBytes_(
          conn_.udpSendPacketLen * conn_.transportSettings.initCwndInMss),
      maxBwFilter_(kMaxBwFilterLen - 1, Bandwidth(), 0),
      probeRttMinTimestamp_(Clock::now()),
      maxExtraAckedFilter_(kMaxExtraAckedFilterLen, 0, 0) {}

std::string bbr2StateToString(Bbr2State state) {
  switch (state) {
    case Bbr2State::Startup:
      return "Startup";
    case Bbr2State::Drain:
      return "Drain";
    case Bbr2State::ProbeBw_Down:
      return "ProbeBw_Down";
    case Bbr2State::ProbeBw_Cruise:
      return "ProbeBw_Cruise";
    case Bbr2State::ProbeBw_Refill:
      return "ProbeBw_Refill";
    case Bbr2State::ProbeBw_Up:
      return "ProbeBw_Up";
    case Bbr2State::ProbeRtt:
      return "ProbeRtt";
    default:
      folly::assume_unreachable();
  }
}

// ===== Congestion Window =====

uint64_t Bbr2Shared::getWritableBytes() const noexcept {
  return cwndBytes_ > conn_.lossState.inflightBytes
      ? cwndBytes_ - conn_.lossState.inflightBytes
      : 0;
}

void Bbr2Shared::applyCwnd(uint64_t cwndValue) {
  cwndBytes_ = boundedCwnd(
      cwndValue,
      conn_.udpSendPacketLen,
      conn_.transportSettings.maxCwndInMss,
      kMinCwndInMssForBbr);
}

void Bbr2Shared::saveCwnd() {
  if (recoveryState_ == RecoveryState::NOT_RECOVERY &&
      state_ != Bbr2State::ProbeRtt) {
    previousCwndBytes_ = cwndBytes_;
  } else {
    previousCwndBytes_ = std::max(cwndBytes_, previousCwndBytes_);
  }
}

void Bbr2Shared::restoreCwnd() {
  cwndBytes_ = std::max(cwndBytes_, previousCwndBytes_);
}

// ===== Bandwidth Model =====

Optional<Bandwidth> Bbr2Shared::getBandwidth() const {
  return bandwidth_;
}

Bandwidth Bbr2Shared::getMaxBw() const {
  return maxBwFilter_.GetBest();
}

uint64_t Bbr2Shared::getBDP() const {
  return getBDPWithGain(1.0);
}

uint64_t Bbr2Shared::getBDPWithGain(float gain) const {
  if (minRtt_ == kDefaultMinRtt) {
    return static_cast<uint64_t>(
        gain * static_cast<float>(conn_.transportSettings.initCwndInMss) *
        static_cast<float>(conn_.udpSendPacketLen));
  } else {
    return static_cast<uint64_t>(
        gain * static_cast<float>(minRtt_ * bandwidth_));
  }
}

uint64_t Bbr2Shared::getTargetInflightWithGain(float gain) const {
  return addQuantizationBudget(getBDPWithGain(gain));
}

uint64_t Bbr2Shared::addQuantizationBudget(uint64_t input) const {
  // BBRUpdateOffloadBudget()
  auto offloadBudget = 3 * sendQuantum_;
  input = std::max(input, offloadBudget);
  input = std::max(input, quic::kMinCwndInMssForBbr * conn_.udpSendPacketLen);
  return input;
}

void Bbr2Shared::updateBandwidthSampleFromAck(const AckEvent& ackEvent) {
  auto ackTime = ackEvent.adjustedAckTime;
  currentBwSample_ = Bandwidth();
  currentAckMaxInflightBytes_ = 0;

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
      continue;
    }
    auto lastBytesDelivered =
        lastAckedPacket ? lastAckedPacket->totalBytesAcked : 0;
    auto bytesDelivered = ackEvent.totalBytesAcked - lastBytesDelivered;
    currentAckMaxInflightBytes_ =
        std::max(currentAckMaxInflightBytes_, bytesDelivered);
    Bandwidth bw(
        bytesDelivered,
        std::chrono::duration_cast<std::chrono::microseconds>(interval),
        pkt->isAppLimited || lastSentTime < appLimitedLastSendTime_);
    if (bw > currentBwSample_) {
      currentBwSample_ = bw;
    }
  }

  // Update max bandwidth filter
  if (currentBwSample_ > maxBwFilter_.GetBest() ||
      !currentBwSample_.isAppLimited) {
    maxBwFilter_.Update(currentBwSample_, cycleCount_);
  }
  bandwidth_ = maxBwFilter_.GetBest();
}

void Bbr2Shared::updateMaxBwFilter(Bandwidth sample) {
  if (sample > maxBwFilter_.GetBest() || !sample.isAppLimited) {
    maxBwFilter_.Update(sample, cycleCount_);
  }
  bandwidth_ = maxBwFilter_.GetBest();
}

void Bbr2Shared::updateMaxBwFilterFromLatest() {
  if (bandwidthLatest_ > maxBwFilter_.GetBest() ||
      !bandwidthLatest_.isAppLimited) {
    maxBwFilter_.Update(bandwidthLatest_, cycleCount_);
  }
  bandwidth_ = maxBwFilter_.GetBest();
}

void Bbr2Shared::boundBwForModel(Optional<Bandwidth> upperBound) {
  Bandwidth previousBw = bandwidth_;
  bandwidth_ = maxBwFilter_.GetBest();
  if (upperBound.has_value()) {
    bandwidth_ = std::min(bandwidth_, *upperBound);
  }
  if (conn_.qLogger && previousBw != bandwidth_) {
    conn_.qLogger->addBandwidthEstUpdate(bandwidth_.units, bandwidth_.interval);
  }
}

void Bbr2Shared::incrementCycleCount() {
  cycleCount_++;
}

// ===== Pacing & Send Quantum =====

void Bbr2Shared::setPacing(
    std::pair<uint8_t, uint8_t> rttFactor,
    Optional<uint64_t> minPacingWindow) {
  auto pacingWindow = static_cast<uint64_t>(
      static_cast<float>(bandwidth_ * minRtt_) * pacingGain_ *
      static_cast<float>(100 - kPacingMarginPercent) / 100.0f);

  if (minPacingWindow.has_value()) {
    pacingWindow = std::max(pacingWindow, *minPacingWindow);
  }

  conn_.pacer->setRttFactor(rttFactor.first, rttFactor.second);
  conn_.pacer->refreshPacingRate(pacingWindow, minRtt_);
}

void Bbr2Shared::setSendQuantum() {
  auto rate = bandwidth_ * pacingGain_ * (100 - kPacingMarginPercent) / 100;
  auto burstInPacerTick = rate * conn_.transportSettings.pacingTickInterval;
  sendQuantum_ =
      std::min(burstInPacerTick, decltype(burstInPacerTick)(64 * 1024));
  sendQuantum_ = std::max(sendQuantum_, 2 * conn_.udpSendPacketLen);
}

// ===== Round Tracking =====

void Bbr2Shared::startRound() {
  nextRoundDelivered_ = conn_.lossState.totalBytesAcked;
}

void Bbr2Shared::updateRound() {
  auto pkt = currentAckEvent_->getLargestNewlyAckedPacket();
  if (pkt && pkt->lastAckedPacketInfo &&
      pkt->lastAckedPacketInfo->totalBytesAcked >= nextRoundDelivered_) {
    startRound();
    roundCount_++;
    roundStart_ = true;
  } else {
    roundStart_ = false;
  }
}

// ===== MinRTT & ProbeRTT Timing =====

void Bbr2Shared::updateMinRtt() {
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

  auto minRttExpired = minRtt_ == kDefaultMinRtt ||
      (probeRttMinTimestamp_ &&
       Clock::now() > (probeRttMinTimestamp_.value() + kMinRttFilterLen));
  if (probeRttMinValue_ < minRtt_ || minRttExpired) {
    minRtt_ = probeRttMinValue_;
    minRttTimestamp_ = probeRttMinTimestamp_;
  }
}

bool Bbr2Shared::shouldEnterProbeRtt() const noexcept {
  return probeRttExpired_ && !idleRestart_;
}

void Bbr2Shared::resetProbeRttExpired() {
  probeRttMinTimestamp_ = Clock::now();
  probeRttExpired_ = false;
}

// ===== App-Limited & Idle State =====

void Bbr2Shared::setAppLimited() noexcept {
  appLimited_ = true;
  appLimitedLastSendTime_ = Clock::now();
  if (conn_.qLogger) {
    conn_.qLogger->addAppLimitedUpdate();
  }
}

void Bbr2Shared::updateAppLimitedState(const AckEvent& ackEvent) {
  if (appLimited_ &&
      appLimitedLastSendTime_ <= ackEvent.largestNewlyAckedPacketSentTime) {
    appLimited_ = false;
    if (conn_.qLogger) {
      conn_.qLogger->addAppUnlimitedUpdate();
    }
  }
}

// ===== ACK Aggregation =====

void Bbr2Shared::updateAckAggregation() {
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

uint64_t Bbr2Shared::getMaxExtraAcked() const noexcept {
  return maxExtraAckedFilter_.GetBest();
}

// ===== Loss & Congestion Signals =====

void Bbr2Shared::resetCongestionSignals() {
  lossBytesInRound_ = 0;
  lossEventsInRound_ = 0;
  largestLostPacketNumInRound_ = 0;
  bandwidthLatest_ = Bandwidth();
  inflightLatest_ = 0;
}

void Bbr2Shared::updateLatestDeliverySignals() {
  lossRoundStart_ = false;

  bandwidthLatest_ = std::max(bandwidthLatest_, currentBwSample_);
  inflightLatest_ = std::max(inflightLatest_, currentAckMaxInflightBytes_);

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

void Bbr2Shared::advanceLatestDeliverySignals() {
  if (lossRoundStart_) {
    bandwidthLatest_ = currentBwSample_;
    inflightLatest_ = currentAckMaxInflightBytes_;
  }
}

void Bbr2Shared::updateLossSignals(
    const CongestionController::LossEvent* FOLLY_NULLABLE lossEvent) {
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

  if (lossRoundStart_) {
    lossBytesInRound_ = 0;
    lossEventsInRound_ = 0;
    largestLostPacketNumInRound_ = 0;
  }
}

// ===== Short-Term Model Helper =====

void Bbr2Shared::updateShortTermModelOnLoss(
    Optional<Bandwidth>& bandwidthShortTerm,
    Optional<uint64_t>& inflightShortTerm) {
  // InitLowerBounds
  if (!bandwidthShortTerm.has_value()) {
    bandwidthShortTerm = maxBwFilter_.GetBest();
  }
  if (!inflightShortTerm.has_value()) {
    inflightShortTerm = cwndBytes_;
  }

  // LossLowerBounds
  auto bwLoBeta =
      (conn_.transportSettings.ccaConfig.overrideBwShortBeta < 0.5 ||
       conn_.transportSettings.ccaConfig.overrideBwShortBeta > 1.0)
      ? kBeta
      : conn_.transportSettings.ccaConfig.overrideBwShortBeta;
  bandwidthShortTerm =
      std::max(bandwidthLatest_, *bandwidthShortTerm * bwLoBeta);
  inflightShortTerm = std::max(
      inflightLatest_, static_cast<uint64_t>(*inflightShortTerm * kBeta));
}

// ===== Recovery State =====

void Bbr2Shared::onPacketLoss(
    const CongestionController::LossEvent& lossEvent,
    uint64_t ackedBytes) {
  saveCwnd();
  recoveryStartTime_ = Clock::now();
  if (recoveryState_ == RecoveryState::NOT_RECOVERY) {
    recoveryState_ = RecoveryState::CONSERVATIVE;
    recoveryWindow_ = conn_.lossState.inflightBytes + ackedBytes;

    // Ensure conservative recovery lasts for at least a whole round trip.
    startRound();
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

void Bbr2Shared::updateRecoveryOnAck() {
  if (recoveryState_ == RecoveryState::NOT_RECOVERY) {
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

// ===== Last Acked Packet State =====

void Bbr2Shared::updateLastAckedPacketState() {
  auto lastAckedPacket = currentAckEvent_->getLargestNewlyAckedPacket();
  inflightBytesAtLastAckedPacket_ = lastAckedPacket
      ? lastAckedPacket->outstandingPacketMetadata.inflightBytes
      : conn_.lossState.inflightBytes;
  lastAckedPacketAppLimited_ =
      lastAckedPacket ? lastAckedPacket->isAppLimited : true;
}

// ===== Phased ACK Processing =====

void Bbr2Shared::sampleBandwidthFromAck(const AckEvent& ackEvent) {
  currentAckEvent_ = &ackEvent;
  updateAppLimitedState(ackEvent);
  updateBandwidthSampleFromAck(ackEvent);
  updateLastAckedPacketState();
}

void Bbr2Shared::updateModelFromDeliveryAndLoss(
    const CongestionController::LossEvent* FOLLY_NULLABLE lossEvent) {
  updateLatestDeliverySignals();
  updateRound();
  updateRecoveryOnAck();
  updateLossSignals(lossEvent);
  updateMaxBwFilterFromLatest();
  updateAckAggregation();
}

void Bbr2Shared::finalizeMinRttAndDeliverySignals() {
  updateMinRtt();
  advanceLatestDeliverySignals();
}

void Bbr2Shared::completeAckProcessing(
    uint64_t cwnd,
    const AckEvent& ackEvent,
    uint64_t inflightLongTerm,
    uint64_t inflightShortTerm,
    Optional<Bandwidth> bandwidthShortTerm) {
  // Apply cwnd and quantum
  setSendQuantum();
  applyCwnd(cwnd);

  if (roundStart_) {
    cwndLimitedInRound_ = false;
  }

  if (ackEvent.ackedBytes > 0) {
    idleRestart_ = false;
  }

  // Log metrics and state
  if (conn_.qLogger) {
    conn_.qLogger->addMetricUpdate(
        conn_.lossState.lrtt,
        conn_.lossState.mrtt,
        conn_.lossState.srtt,
        conn_.lossState.maybeLrttAckDelay.value_or(0us),
        conn_.lossState.rttvar,
        cwndBytes_,
        conn_.lossState.inflightBytes,
        std::nullopt,
        std::nullopt,
        std::nullopt,
        conn_.lossState.ptoCount);
    conn_.qLogger->addNetworkPathModelUpdate(
        inflightLongTerm,
        inflightShortTerm,
        0, // bandwidthHi_ not available
        std::chrono::microseconds(1),
        bandwidthShortTerm.has_value() ? bandwidthShortTerm->units : 0,
        bandwidthShortTerm.has_value() ? bandwidthShortTerm->interval
                                       : std::chrono::microseconds(1));
  }

  QLOG(
      conn_,
      addCongestionStateUpdate,
      std::nullopt,
      bbr2StateToString(state_),
      kCongestionPacketAck);

  VLOG(6) << "State=" << bbr2StateToString(state_)
          << " inflight=" << conn_.lossState.inflightBytes
          << " cwnd=" << cwndBytes_;
}

// ===== Packet Events =====

void Bbr2Shared::onPacketSent(const OutstandingPacketWrapper& packet) {
  bool wasIdle = (conn_.lossState.inflightBytes == packet.metadata.encodedSize);

  // Handle restart from idle
  if (wasIdle && appLimited_) {
    idleRestart_ = true;
    // Reset ack aggregation tracking
    extraAckedStartTimestamp_ = Clock::now();
    extraAckedDelivered_ = 0;
  }

  // Track cwndLimited: we consider the transport being cwnd limited if
  // we are using > 90% of the cwnd.
  if (conn_.lossState.inflightBytes > cwndBytes_ * 9 / 10) {
    cwndLimitedInRound_ = true;
  }
}

// ===== Stats =====

void Bbr2Shared::getStats(CongestionControllerStats& stats) const {
  stats.bbr2Stats.state = uint8_t(state_);
}

} // namespace quic
