/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <quic/congestion_control/Bbr.h>

#include <folly/Random.h>
#include <quic/QuicConstants.h>
#include <quic/common/TimeUtil.h>
#include <quic/congestion_control/CongestionControlFunctions.h>
#include <quic/logging/QLoggerConstants.h>
#include <quic/state/QuicAckFrequencyFunctions.h>
#include <chrono>

using namespace std::chrono_literals;

namespace {
quic::Bandwidth kLowPacingRateForSendQuantum{1200 * 1000, 1s};
quic::Bandwidth kHighPacingRateForSendQuantum{24, 1us};
// See BBRInflight(gain) function in
// https://tools.ietf.org/html/draft-cardwell-iccrg-bbr-congestion-control-00#section-4.2.3.2
uint64_t kQuantaFactor = 3;
} // namespace

namespace quic {

BbrCongestionController::BbrCongestionController(QuicConnectionStateBase& conn)
    : conn_(conn),
      cwnd_(conn.udpSendPacketLen * conn.transportSettings.initCwndInMss),
      initialCwnd_(
          conn.udpSendPacketLen * conn.transportSettings.initCwndInMss),
      recoveryWindow_(
          conn.udpSendPacketLen * conn.transportSettings.maxCwndInMss),
      pacingWindow_(
          conn.udpSendPacketLen * conn.transportSettings.initCwndInMss),
      pacingGainCycles_(kPacingGainCycles.begin(), kPacingGainCycles.end()),
      maxAckHeightFilter_(bandwidthWindowLength(kNumOfCycles), 0, 0) {}

BbrCongestionController::BbrCongestionController(
    QuicConnectionStateBase& conn,
    uint64_t cwndBytes,
    std::chrono::microseconds minRtt)
    : conn_(conn),
      cwnd_(cwndBytes),
      initialCwnd_(
          conn.udpSendPacketLen * conn.transportSettings.initCwndInMss),
      recoveryWindow_(
          conn.udpSendPacketLen * conn.transportSettings.maxCwndInMss),
      pacingWindow_(cwndBytes),
      pacingGainCycles_(kPacingGainCycles.begin(), kPacingGainCycles.end()),
      maxAckHeightFilter_(bandwidthWindowLength(kNumOfCycles), 0, 0) {
  if (conn_.pacer) {
    conn_.pacer->refreshPacingRate(pacingWindow_, minRtt);
  }
}

CongestionControlType BbrCongestionController::type() const noexcept {
  return CongestionControlType::BBR;
}

bool BbrCongestionController::updateRoundTripCounter(
    TimePoint largestAckedSentTime) noexcept {
  if (largestAckedSentTime > endOfRoundTrip_) {
    roundTripCounter_++;
    endOfRoundTrip_ = Clock::now();
    return true;
  }
  return false;
}

void BbrCongestionController::setRttSampler(
    std::unique_ptr<MinRttSampler> sampler) noexcept {
  minRttSampler_ = std::move(sampler);
}

void BbrCongestionController::setBandwidthSampler(
    std::unique_ptr<BandwidthSampler> sampler) noexcept {
  bandwidthSampler_ = std::move(sampler);
}

void BbrCongestionController::onPacketLoss(
    const LossEvent& loss,
    uint64_t ackedBytes) {
  endOfRecovery_ = Clock::now();

  if (!inRecovery()) {
    recoveryState_ = BbrCongestionController::RecoveryState::CONSERVATIVE;
    recoveryWindow_ = conn_.lossState.inflightBytes + ackedBytes;
    recoveryWindow_ = boundedCwnd(
        recoveryWindow_,
        conn_.udpSendPacketLen,
        conn_.transportSettings.maxCwndInMss,
        kMinCwndInMssForBbr);

    // We need to make sure CONSERVATIVE can last for a round trip, so update
    // endOfRoundTrip_ to the latest sent packet.
    endOfRoundTrip_ = Clock::now();
  }

  recoveryWindow_ = recoveryWindow_ >
          loss.lostBytes + conn_.udpSendPacketLen * kMinCwndInMssForBbr
      ? recoveryWindow_ - loss.lostBytes
      : conn_.udpSendPacketLen * kMinCwndInMssForBbr;

  if (loss.persistentCongestion) {
    recoveryWindow_ = conn_.udpSendPacketLen * kMinCwndInMssForBbr;
    if (conn_.qLogger) {
      conn_.qLogger->addCongestionMetricUpdate(
          conn_.lossState.inflightBytes,
          getCongestionWindow(),
          kPersistentCongestion,
          bbrStateToString(state_),
          bbrRecoveryStateToString(recoveryState_));
    }
  }
}

void BbrCongestionController::onPacketSent(
    const OutstandingPacketWrapper& packet) {
  if (!conn_.lossState.inflightBytes && isAppLimited()) {
    exitingQuiescene_ = true;
  }
  addAndCheckOverflow(
      conn_.lossState.inflightBytes, packet.metadata.encodedSize);
  if (!ackAggregationStartTime_) {
    ackAggregationStartTime_ = packet.metadata.time;
  }
}

uint64_t BbrCongestionController::updateAckAggregation(const AckEvent& ack) {
  if (isExperimental_) {
    // Experiment with disabling this ack aggregation logic
    return 0;
  }
  if (!ackAggregationStartTime_) {
    // Ideally one'd DCHECK/CHECK ackAggregationStartTime_ has some value, as we
    // can't possibly get an ack or loss without onPacketSent ever. However
    // there are cases we swap/recreate congestion controller in the middle of a
    // connection for example, connection migration. Then the newly created
    // congestion controller will get an ack or loss before ever get an
    // onPacketSent.
    return 0;
  }
  uint64_t expectedAckBytes = bandwidth() *
      std::chrono::duration_cast<std::chrono::microseconds>(
                                  ack.ackTime - *ackAggregationStartTime_);
  // Ack aggregation starts when we witness ack arrival rate being less than
  // estimated bandwidth,
  if (aggregatedAckBytes_ <= expectedAckBytes) {
    aggregatedAckBytes_ = ack.ackedBytes;
    ackAggregationStartTime_ = ack.ackTime;
    return 0;
  }
  aggregatedAckBytes_ += ack.ackedBytes;
  maxAckHeightFilter_.Update(
      aggregatedAckBytes_ - expectedAckBytes, roundTripCounter_);
  return aggregatedAckBytes_ - expectedAckBytes;
}

void BbrCongestionController::onPacketAckOrLoss(
    const AckEvent* FOLLY_NULLABLE ackEvent,
    const LossEvent* FOLLY_NULLABLE lossEvent) {
  auto prevInflightBytes = conn_.lossState.inflightBytes;
  if (ackEvent) {
    subtractAndCheckUnderflow(
        conn_.lossState.inflightBytes, ackEvent->ackedBytes);
  }
  if (lossEvent) {
    subtractAndCheckUnderflow(
        conn_.lossState.inflightBytes, lossEvent->lostBytes);
  }
  if (lossEvent) {
    onPacketLoss(*lossEvent, ackEvent ? ackEvent->ackedBytes : 0);
    if (conn_.pacer) {
      conn_.pacer->onPacketsLoss();
    }
  }
  if (ackEvent && ackEvent->largestNewlyAckedPacket.has_value()) {
    CHECK(!ackEvent->ackedPackets.empty());
    onPacketAcked(*ackEvent, prevInflightBytes, lossEvent != nullptr);
  }
}

void BbrCongestionController::onPacketAcked(
    const AckEvent& ack,
    uint64_t prevInflightBytes,
    bool hasLoss) {
  SCOPE_EXIT {
    if (conn_.qLogger) {
      conn_.qLogger->addCongestionMetricUpdate(
          conn_.lossState.inflightBytes,
          getCongestionWindow(),
          kCongestionPacketAck,
          bbrStateToString(state_),
          bbrRecoveryStateToString(recoveryState_));
    }
  };
  if (ack.implicit) {
    // This is an implicit ACK during the handshake, we can't trust very
    // much about it except the fact that it does ACK some bytes.
    updateCwnd(ack.ackedBytes, 0);
    return;
  }
  if (ack.rttSample && minRttSampler_) {
    bool updated =
        minRttSampler_->newRttSample(ack.rttSample.value(), ack.ackTime);
    if (updated) {
      appLimitedSinceProbeRtt_ = false;
    }
  }

  bool newRoundTrip =
      updateRoundTripCounter(ack.largestNewlyAckedPacketSentTime);
  bool lastAckedPacketAppLimited =
      ack.ackedPackets.empty() ? false : ack.largestNewlyAckedPacketAppLimited;
  if (bandwidthSampler_) {
    bandwidthSampler_->onPacketAcked(ack, roundTripCounter_);
  }
  if (inRecovery()) {
    CHECK(endOfRecovery_.has_value());
    if (newRoundTrip &&
        recoveryState_ != BbrCongestionController::RecoveryState::GROWTH) {
      recoveryState_ = BbrCongestionController::RecoveryState::GROWTH;
    }
    if (ack.largestNewlyAckedPacketSentTime > *endOfRecovery_) {
      recoveryState_ = BbrCongestionController::RecoveryState::NOT_RECOVERY;
    } else {
      updateRecoveryWindowWithAck(ack.ackedBytes);
    }
  }

  auto excessiveBytes = updateAckAggregation(ack);

  // handleAckInProbeBw() needs to happen before we check exiting Startup and
  // Drain and transitToProbeBw(). Otherwise, we may transitToProbeBw() first
  // then immediately invoke a handleAckInProbeBw() to also transit to next
  // ProbwBw pacing cycle.
  if (state_ == BbrState::ProbeBw) {
    handleAckInProbeBw(ack.ackTime, prevInflightBytes, hasLoss);
  }

  if (newRoundTrip && !lastAckedPacketAppLimited) {
    detectBottleneckBandwidth(lastAckedPacketAppLimited);
  }

  if (shouldExitStartup()) {
    transitToDrain();
  }

  if (shouldExitDrain()) {
    transitToProbeBw(ack.ackTime);
  }

  if (shouldProbeRtt(ack.ackTime)) {
    transitToProbeRtt();
  }
  exitingQuiescene_ = false;

  if (state_ == BbrState::ProbeRtt && minRttSampler_) {
    handleAckInProbeRtt(newRoundTrip, ack.ackTime);
  }

  const auto& ackFrequencyConfig =
      conn_.transportSettings.ccaConfig.ackFrequencyConfig;
  if (newRoundTrip && canSendAckControlFrames(conn_) && ackFrequencyConfig) {
    auto updatedMaxAckDelay =
        std::chrono::duration_cast<std::chrono::milliseconds>(clampMaxAckDelay(
            conn_, conn_.lossState.srtt / ackFrequencyConfig->minRttDivisor));
    // If we are either in STARTUP or haven't sent enough packets, based on
    // config.
    bool shouldUseInitThreshold =
        (ackFrequencyConfig->useSmallThresholdDuringStartup &&
         state_ == BbrState::Startup) ||
        (!ackFrequencyConfig->useSmallThresholdDuringStartup &&
         (conn_.lossState.totalAckElicitingPacketsSent <=
          conn_.transportSettings.rxPacketsBeforeAckInitThreshold));
    // Default to 2 as the init threshold, which has been shown to be
    // a good choice empirically.
    uint32_t ackThreshold =
        shouldUseInitThreshold ? 2 : ackFrequencyConfig->ackElicitingThreshold;
    if ((!lastMaxAckDelay_ || lastMaxAckDelay_.value() != updatedMaxAckDelay) ||
        (!lastAckThreshold_ || lastAckThreshold_.value() != ackThreshold)) {
      requestPeerAckFrequencyChange(
          conn_,
          ackThreshold,
          updatedMaxAckDelay,
          ackFrequencyConfig->reorderingThreshold);
      lastMaxAckDelay_ = updatedMaxAckDelay;
      lastAckThreshold_ = ackThreshold;
    }
  }
  updateCwnd(ack.ackedBytes, excessiveBytes);
  updatePacing();
}

// TODO: We used to check if there is available bandwidth and rtt samples in
// canBePaced function. Now this function is gone, maybe we need to change this
// updatePacing function.
void BbrCongestionController::updatePacing() noexcept {
  // TODO: enable Pacing and BBR together.
  if (!conn_.pacer) {
    return;
  }
  if (conn_.lossState.totalBytesSent < initialCwnd_) {
    return;
  }
  auto bandwidthEstimate = bandwidth();
  if (!bandwidthEstimate) {
    return;
  }
  auto mrtt = minRtt();
  uint64_t targetPacingWindow = bandwidthEstimate * pacingGain_ * mrtt;
  if (btlbwFound_) {
    pacingWindow_ = targetPacingWindow;
  } else {
    pacingWindow_ = std::max(pacingWindow_, targetPacingWindow);
  }
  if (state_ == BbrState::Startup) {
    conn_.pacer->setRttFactor(
        conn_.transportSettings.startupRttFactor.first,
        conn_.transportSettings.startupRttFactor.second);
  } else {
    conn_.pacer->setRttFactor(
        conn_.transportSettings.defaultRttFactor.first,
        conn_.transportSettings.defaultRttFactor.second);
  }
  conn_.pacer->refreshPacingRate(pacingWindow_, mrtt);
  if (state_ == BbrState::Drain) {
    conn_.pacer->reset();
  }
}

void BbrCongestionController::handleAckInProbeBw(
    TimePoint ackTime,
    uint64_t prevInflightBytes,
    bool hasLoss) noexcept {
  bool shouldAdvancePacingGainCycle = ackTime - cycleStart_ > minRtt();
  if (pacingGain_ > 1.0 && !hasLoss &&
      prevInflightBytes < calculateTargetCwnd(pacingGain_)) {
    // pacingGain_ > 1.0 means BBR is probeing bandwidth. So we should let
    // inflight bytes reach the target.
    shouldAdvancePacingGainCycle = false;
  }

  // To avoid calculating target cwnd with 1.0 gain twice.
  folly::Optional<uint64_t> targetCwndCache;

  // If not in background mode, pacingGain_ < 1.0 means BBR is draining the
  // network queue. If inflight bytes is below the target, then draining is
  // complete and this cycle is done.
  // If in background mode, pacingGain_ < 1.0
  // means BBR is intentionally underutilizing the link bandiwdth. The cycle
  // should not be advanced prematurely.
  if (!isInBackgroundMode() && pacingGain_ < 1.0) {
    targetCwndCache = calculateTargetCwnd(1.0);
    if (conn_.lossState.inflightBytes <= *targetCwndCache) {
      shouldAdvancePacingGainCycle = true;
    }
  }

  if (shouldAdvancePacingGainCycle) {
    pacingCycleIndex_ = (pacingCycleIndex_ + 1) % numOfCycles_;
    cycleStart_ = ackTime;
    if (!isInBackgroundMode() &&
        conn_.transportSettings.ccaConfig.drainToTarget && pacingGain_ < 1.0 &&
        pacingGainCycles_[pacingCycleIndex_] == 1.0) {
      auto drainTarget =
          targetCwndCache ? *targetCwndCache : calculateTargetCwnd(1.0);
      if (conn_.lossState.inflightBytes > drainTarget) {
        // Interestingly Chromium doesn't rollback pacingCycleIndex_ in this
        // case.
        // TODO: isn't this a bug? But we don't do drainToTarget today.
        return;
      }
    }
    pacingGain_ = pacingGainCycles_[pacingCycleIndex_];
  }
}

bool BbrCongestionController::shouldExitStartup() noexcept {
  return state_ == BbrState::Startup && btlbwFound_;
}

bool BbrCongestionController::shouldExitDrain() noexcept {
  return state_ == BbrState::Drain &&
      conn_.lossState.inflightBytes <= calculateTargetCwnd(1.0);
}

bool BbrCongestionController::shouldProbeRtt(TimePoint ackTime) noexcept {
  if (conn_.transportSettings.ccaConfig.probeRttDisabledIfAppLimited &&
      appLimitedSinceProbeRtt_) {
    minRttSampler_->timestampMinRtt(ackTime);
    return false;
  }
  // TODO: Another experiment here is that to maintain a min rtt sample since
  // last ProbeRtt, and if it's very close to the minRtt seom sampler, then skip
  // ProbeRtt.
  if (state_ != BbrState::ProbeRtt && minRttSampler_ && !exitingQuiescene_ &&
      minRttSampler_->minRttExpired()) {
    // TODO: also consider connection being quiescent
    return true;
  }
  return false;
}

void BbrCongestionController::handleAckInProbeRtt(
    bool newRoundTrip,
    TimePoint ackTime) noexcept {
  DCHECK(state_ == BbrState::ProbeRtt);
  CHECK(minRttSampler_);

  if (bandwidthSampler_) {
    bandwidthSampler_->onAppLimited();
  }
  if (!earliestTimeToExitProbeRtt_ &&
      conn_.lossState.inflightBytes <
          getCongestionWindow() + conn_.udpSendPacketLen) {
    earliestTimeToExitProbeRtt_ = ackTime + kProbeRttDuration;
    probeRttRound_.reset();
    return;
  }
  if (earliestTimeToExitProbeRtt_) {
    if (!probeRttRound_ && newRoundTrip) {
      probeRttRound_ = roundTripCounter_;
    }
    if (probeRttRound_ && *earliestTimeToExitProbeRtt_ <= ackTime) {
      // We are done with ProbeRtt_, bye.
      minRttSampler_->timestampMinRtt(ackTime);
      if (btlbwFound_) {
        transitToProbeBw(ackTime);
      } else {
        transitToStartup();
      }
    }
  }
  // reset exitingQuiescence is already done before the invocation of
  // handleAckInProbeRtt
}

void BbrCongestionController::transitToStartup() noexcept {
  state_ = BbrState::Startup;
  if (isInBackgroundMode()) {
    pacingGain_ = kStartupGain / 2;
    cwndGain_ = kStartupGain / 2;
  } else {
    pacingGain_ = kStartupGain;
    cwndGain_ = kStartupGain;
  }
}

void BbrCongestionController::transitToProbeRtt() noexcept {
  state_ = BbrState::ProbeRtt;
  pacingGain_ = 1.0f;
  earliestTimeToExitProbeRtt_.reset();
  probeRttRound_.reset();
  if (bandwidthSampler_) {
    bandwidthSampler_->onAppLimited();
  }
  appLimitedSinceProbeRtt_ = false;
}

void BbrCongestionController::transitToDrain() noexcept {
  state_ = BbrState::Drain;
  if (isInBackgroundMode()) {
    pacingGain_ = 1.0f / 2 * kStartupGain;
    cwndGain_ = kStartupGain / 2;
  } else {
    pacingGain_ = 1.0f / kStartupGain;
    cwndGain_ = kStartupGain;
  }
}

void BbrCongestionController::transitToProbeBw(TimePoint congestionEventTime) {
  state_ = BbrState::ProbeBw;
  cwndGain_ = kProbeBwGain;

  pacingGain_ = pacingGainCycles_[pickRandomCycle()];
  cycleStart_ = congestionEventTime;
}

size_t BbrCongestionController::pickRandomCycle() {
  pacingCycleIndex_ =
      (folly::Random::rand32(numOfCycles_ - 1) + 2) % numOfCycles_;
  DCHECK_NE(pacingCycleIndex_, 1);
  return pacingCycleIndex_;
}

void BbrCongestionController::updateRecoveryWindowWithAck(
    uint64_t bytesAcked) noexcept {
  DCHECK(inRecovery());
  if (recoveryState_ == BbrCongestionController::RecoveryState::GROWTH) {
    recoveryWindow_ += bytesAcked;
  }

  uint64_t recoveryIncrease =
      conn_.transportSettings.ccaConfig.conservativeRecovery
      ? conn_.udpSendPacketLen
      : bytesAcked;
  recoveryWindow_ = std::max(
      recoveryWindow_, conn_.lossState.inflightBytes + recoveryIncrease);
  recoveryWindow_ = boundedCwnd(
      recoveryWindow_,
      conn_.udpSendPacketLen,
      conn_.transportSettings.maxCwndInMss,
      kMinCwndInMssForBbr);
}

bool BbrCongestionController::inRecovery() const noexcept {
  return recoveryState_ != BbrCongestionController::RecoveryState::NOT_RECOVERY;
}

BbrCongestionController::BbrState BbrCongestionController::state()
    const noexcept {
  return state_;
}

uint64_t BbrCongestionController::getWritableBytes() const noexcept {
  return getCongestionWindow() > conn_.lossState.inflightBytes
      ? getCongestionWindow() - conn_.lossState.inflightBytes
      : 0;
}

std::chrono::microseconds BbrCongestionController::minRtt() const noexcept {
  return minRttSampler_ ? minRttSampler_->minRtt() : 0us;
}

Bandwidth BbrCongestionController::bandwidth() const noexcept {
  return bandwidthSampler_ ? bandwidthSampler_->getBandwidth() : Bandwidth();
}

uint64_t BbrCongestionController::calculateTargetCwnd(
    float gain) const noexcept {
  auto bandwidthEst = bandwidth();
  auto minRttEst = minRtt();
  if (!bandwidthEst || minRttEst == 0us) {
    return gain * initialCwnd_;
  }
  uint64_t bdp = bandwidthEst * minRttEst;
  return bdp * gain + kQuantaFactor * sendQuantum_;
}

void BbrCongestionController::updateCwnd(
    uint64_t ackedBytes,
    uint64_t excessiveBytes) noexcept {
  if (state_ == BbrCongestionController::BbrState::ProbeRtt) {
    return;
  }

  auto pacingRate = bandwidth() * pacingGain_;
  if (pacingRate < kLowPacingRateForSendQuantum) {
    sendQuantum_ = conn_.udpSendPacketLen;
  } else if (pacingRate < kHighPacingRateForSendQuantum) {
    sendQuantum_ = conn_.udpSendPacketLen * 2;
  } else {
    sendQuantum_ = std::min(pacingRate * 1000us, k64K);
  }
  auto targetCwnd = calculateTargetCwnd(cwndGain_);
  if (btlbwFound_) {
    targetCwnd += maxAckHeightFilter_.GetBest();
  } else if (conn_.transportSettings.ccaConfig.enableAckAggregationInStartup) {
    targetCwnd += excessiveBytes;
  }

  if (btlbwFound_) {
    cwnd_ = std::min(targetCwnd, cwnd_ + ackedBytes);
  } else if (
      cwnd_ < targetCwnd || conn_.lossState.totalBytesAcked < initialCwnd_) {
    // This is a bit strange. The argument here is that if we haven't finished
    // STARTUP, then forget about the gain calculation.
    cwnd_ += ackedBytes;
  }

  cwnd_ = boundedCwnd(
      cwnd_,
      conn_.udpSendPacketLen,
      conn_.transportSettings.maxCwndInMss,
      kMinCwndInMssForBbr);
}

void BbrCongestionController::setAppIdle(
    bool idle,
    TimePoint /* eventTime */) noexcept {
  if (conn_.qLogger) {
    conn_.qLogger->addAppIdleUpdate(kAppIdle, idle);
  }
  /*
   * No-op for bbr.
   * We are not necessarily app-limite when we are app-idle. For example, the
   * control stream can have a high inflight bytes.
   */
}

void BbrCongestionController::setAppLimited() {
  if (conn_.lossState.inflightBytes > getCongestionWindow()) {
    return;
  }
  appLimitedSinceProbeRtt_ = true;
  if (bandwidthSampler_) {
    bandwidthSampler_->onAppLimited();
  }
}

bool BbrCongestionController::isAppLimited() const noexcept {
  return bandwidthSampler_ ? bandwidthSampler_->isAppLimited() : false;
}

void BbrCongestionController::setBandwidthUtilizationFactor(
    float bandwidthUtilizationFactor) noexcept {
  // Limit the range to [0.25,1.0]
  if (bandwidthUtilizationFactor >= 1.0) {
    bandwidthUtilizationFactor = 1.0;
  } else if (bandwidthUtilizationFactor < 0.25) {
    bandwidthUtilizationFactor = 0.25;
  }
  // Avoid making spurious changes to the pacingGainCycles_ and numOfCycles_
  if (bandwidthUtilizationFactor_ == bandwidthUtilizationFactor) {
    return;
  }
  bandwidthUtilizationFactor_ = bandwidthUtilizationFactor;
  if (bandwidthUtilizationFactor_ < 1.0) {
    numOfCycles_ = kBGNumOfCycles;
    pacingGainCycles_.clear();
    pacingGainCycles_.assign(numOfCycles_, bandwidthUtilizationFactor_);
    pacingGainCycles_[0] = 1.25;
    pacingGainCycles_[1] = 0.75;
    if (state_ == BbrState::Startup) {
      pacingGain_ = kStartupGain / 2;
      cwndGain_ = kStartupGain / 2;
    }
  } else {
    numOfCycles_ = kNumOfCycles;
    pacingGainCycles_.clear();
    pacingGainCycles_.assign(
        kPacingGainCycles.begin(), kPacingGainCycles.end());
    if (state_ == BbrState::Startup) {
      pacingGain_ = kStartupGain;
      cwndGain_ = kStartupGain;
    }
  }
  maxAckHeightFilter_.SetWindowLength(bandwidthWindowLength(numOfCycles_));
  if (bandwidthSampler_) {
    bandwidthSampler_->setWindowLength(bandwidthWindowLength(numOfCycles_));
  }
}

bool BbrCongestionController::isInBackgroundMode() const noexcept {
  return bandwidthUtilizationFactor_ < 1.0;
}

void BbrCongestionController::setExperimental(bool experimental) {
  isExperimental_ = experimental;
}

void BbrCongestionController::getStats(CongestionControllerStats& stats) const {
  stats.bbrStats.state = static_cast<uint8_t>(state_);
}

uint64_t BbrCongestionController::getCongestionWindow() const noexcept {
  if (state_ == BbrCongestionController::BbrState::ProbeRtt) {
    if (conn_.transportSettings.ccaConfig.largeProbeRttCwnd) {
      return boundedCwnd(
          calculateTargetCwnd(kLargeProbeRttCwndGain),
          conn_.udpSendPacketLen,
          conn_.transportSettings.maxCwndInMss,
          kMinCwndInMssForBbr);
    }
    return conn_.udpSendPacketLen * kMinCwndInMssForBbr;
  }

  // TODO: For Recovery in Startup, Chromium has another config option to set if
  // cwnd should be using the conservative recovery cwnd, or regular cwnd.
  if (inRecovery()) {
    return std::min(cwnd_, recoveryWindow_);
  }

  return cwnd_;
}

folly::Optional<Bandwidth> BbrCongestionController::getBandwidth()
    const noexcept {
  if (bandwidthSampler_) {
    return bandwidthSampler_->getBandwidth();
  }
  return folly::none;
}

void BbrCongestionController::detectBottleneckBandwidth(bool appLimitedSample) {
  if (btlbwFound_) {
    return;
  }
  if (appLimitedSample) {
    return;
  }

  auto bandwidthTarget = previousStartupBandwidth_ * kExpectedStartupGrowth;
  auto realBandwidth = bandwidth();
  if (realBandwidth >= bandwidthTarget) {
    previousStartupBandwidth_ = realBandwidth;
    slowStartupRoundCounter_ = 0;
    // TODO: ack aggregation expiration controlled by a config flag
    return;
  }

  // TODO: experiment with exit slow start on loss
  if (++slowStartupRoundCounter_ >= kStartupSlowGrowRoundLimit) {
    btlbwFound_ = true;
  }
}

void BbrCongestionController::onRemoveBytesFromInflight(
    uint64_t bytesToRemove) {
  subtractAndCheckUnderflow(conn_.lossState.inflightBytes, bytesToRemove);
}

std::string bbrStateToString(BbrCongestionController::BbrState state) {
  switch (state) {
    case BbrCongestionController::BbrState::Startup:
      return "Startup";
    case BbrCongestionController::BbrState::Drain:
      return "Drain";
    case BbrCongestionController::BbrState::ProbeBw:
      return "ProbeBw";
    case BbrCongestionController::BbrState::ProbeRtt:
      return "ProbeRtt";
  }
  return "BadBbrState";
}

std::string bbrRecoveryStateToString(
    BbrCongestionController::RecoveryState recoveryState) {
  switch (recoveryState) {
    case BbrCongestionController::RecoveryState::NOT_RECOVERY:
      return "NotRecovery";
    case BbrCongestionController::RecoveryState::CONSERVATIVE:
      return "Conservative";
    case BbrCongestionController::RecoveryState::GROWTH:
      return "Growth";
  }
  return "BadBbrRecoveryState";
}

std::ostream& operator<<(std::ostream& os, const BbrCongestionController& bbr) {
  os << "Bbr: state=" << bbrStateToString(bbr.state_)
     << ", recovery=" << bbrRecoveryStateToString(bbr.recoveryState_)
     << ", pacingWindow_=" << bbr.pacingWindow_
     << ", pacingGain_=" << bbr.pacingGain_
     << ", minRtt=" << bbr.minRtt().count()
     << "us, bandwidth=" << bbr.bandwidth();
  return os;
}
} // namespace quic
