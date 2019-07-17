/*
 * Copyright (c) Facebook, Inc. and its affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 *
 */

// Copyright 2004-present Facebook.  All rights reserved.

#include <quic/congestion_control/Bbr.h>
#include <folly/Random.h>
#include <quic/QuicConstants.h>
#include <quic/common/TimeUtil.h>
#include <quic/congestion_control/CongestionControlFunctions.h>
#include <quic/logging/QLoggerConstants.h>
#include <quic/logging/QuicLogger.h>

using namespace std::chrono_literals;

namespace {
quic::Bandwidth kLowPacingRateForSendQuantum{1200 * 1000, 1s};
quic::Bandwidth kHighPacingRateForSendQuantum{24, 1us};
// See BBRInflight(gain) function in
// https://tools.ietf.org/html/draft-cardwell-iccrg-bbr-congestion-control-00#section-4.2.3.2
uint64_t kQuantaFactor = 3;
} // namespace

namespace quic {

BbrCongestionController::BbrCongestionController(
    QuicConnectionStateBase& conn,
    const BbrConfig& config)
    : conn_(conn),
      config_(config),
      cwnd_(conn.udpSendPacketLen * conn.transportSettings.initCwndInMss),
      initialCwnd_(
          conn.udpSendPacketLen * conn.transportSettings.initCwndInMss),
      recoveryWindow_(
          conn.udpSendPacketLen * conn.transportSettings.maxCwndInMss),
      // TODO: experiment with longer window len for ack aggregation filter
      maxAckHeightFilter_(kBandwidthWindowLength, 0, 0) {}

void BbrCongestionController::setConnectionEmulation(uint8_t) noexcept {
  /* unsupported for BBR */
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

void BbrCongestionController::onPacketLoss(const LossEvent& loss) {
  endOfRecovery_ = Clock::now();

  if (!inRecovery()) {
    recoveryState_ = BbrCongestionController::RecoveryState::CONSERVATIVE;
    // 10% cut is what we do in our Quic Cubic implementation. Even though BBR
    // is pacing limited, not cwnd limited, our Quic transport still use
    // getWritableBytes() to decide if it should schedule a write. So without
    // a similar small window drop, BBR will schedule fewer writes compared to
    // Cubic after a loss. When they share a bottleneck link, if they both see
    // losses, Cubic will pick up pretty quickly while BBR will wait, do a
    // send-one-per-ack type of slow sending, undershooting the bandwidth
    // sampler and will take a lot longer to recover from it.
    recoveryWindow_ = (uint64_t)((double)cwnd_ * kBbrReductionFactor);

    // We need to make sure CONSERVATIVE can last for a round trip, so update
    // endOfRoundTrip_ to the latest sent packet.
    endOfRoundTrip_ = Clock::now();

    // TODO: maybe set appLimited in recovery based on config
  }

  recoveryWindow_ = recoveryWindow_ >
          loss.lostBytes + conn_.udpSendPacketLen * kMinCwndInMssForBbr
      ? recoveryWindow_ - loss.lostBytes
      : conn_.udpSendPacketLen * kMinCwndInMssForBbr;

  if (loss.persistentCongestion) {
    recoveryWindow_ = conn_.udpSendPacketLen * kMinCwndInMssForBbr;
    if (conn_.qLogger) {
      conn_.qLogger->addCongestionMetricUpdate(
          inflightBytes_,
          getCongestionWindow(),
          kPersistentCongestion.str(),
          bbrStateToString(state_),
          bbrRecoveryStateToString(recoveryState_));
    }
    QUIC_TRACE(
        bbr_persistent_congestion,
        conn_,
        bbrStateToString(state_),
        bbrRecoveryStateToString(recoveryState_),
        recoveryWindow_,
        inflightBytes_);
  }
}

void BbrCongestionController::onPacketSent(const OutstandingPacket& packet) {
  if (!inflightBytes_ && isAppLimited()) {
    exitingQuiescene_ = true;
  }
  addAndCheckOverflow(inflightBytes_, packet.encodedSize);
  if (!ackAggregationStartTime_) {
    ackAggregationStartTime_ = packet.time;
  }
}

uint64_t BbrCongestionController::updateAckAggregation(const AckEvent& ack) {
  DCHECK(ackAggregationStartTime_);
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
    folly::Optional<AckEvent> ackEvent,
    folly::Optional<LossEvent> lossEvent) {
  auto prevInflightBytes = inflightBytes_;
  if (ackEvent) {
    subtractAndCheckUnderflow(inflightBytes_, ackEvent->ackedBytes);
  }
  if (lossEvent) {
    subtractAndCheckUnderflow(inflightBytes_, lossEvent->lostBytes);
  }
  if (lossEvent) {
    onPacketLoss(*lossEvent);
  }
  if (ackEvent && ackEvent->largestAckedPacket.hasValue()) {
    CHECK(!ackEvent->ackedPackets.empty());
    onPacketAcked(*ackEvent, prevInflightBytes, lossEvent.hasValue());
  }
}

void BbrCongestionController::onPacketAcked(
    const AckEvent& ack,
    uint64_t prevInflightBytes,
    bool hasLoss) {
  if (ack.mrttSample && minRttSampler_) {
    bool updated =
        minRttSampler_->newRttSample(ack.mrttSample.value(), ack.ackTime);
    if (updated) {
      appLimitedSinceProbeRtt_ = false;
    }
  }

  bool newRoundTrip = updateRoundTripCounter(ack.ackedPackets.back().time);
  // TODO: I actually don't know why the last one is so special
  bool lastAckedPacketAppLimited =
      ack.ackedPackets.empty() ? false : ack.ackedPackets.back().isAppLimited;
  if (bandwidthSampler_) {
    bandwidthSampler_->onPacketAcked(ack, roundTripCounter_);
  }
  if (inRecovery()) {
    CHECK(endOfRecovery_.hasValue());
    if (newRoundTrip &&
        recoveryState_ != BbrCongestionController::RecoveryState::GROWTH) {
      recoveryState_ = BbrCongestionController::RecoveryState::GROWTH;
    }
    if (ack.ackedPackets.back().time > *endOfRecovery_) {
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

  if (shouldProbeRtt()) {
    transitToProbeRtt();
  }
  exitingQuiescene_ = false;

  if (state_ == BbrState::ProbeRtt) {
    handleAckInProbeRtt(newRoundTrip, ack.ackTime);
  }

  updateCwnd(ack.ackedBytes, excessiveBytes);
  updatePacing();
  if (conn_.qLogger) {
    conn_.qLogger->addCongestionMetricUpdate(
        inflightBytes_,
        getCongestionWindow(),
        kCongestionPacketAck.str(),
        bbrStateToString(state_),
        bbrRecoveryStateToString(recoveryState_));
  }
  QUIC_TRACE(
      bbr_ack,
      conn_,
      bbrStateToString(state_),
      bbrRecoveryStateToString(recoveryState_),
      getCongestionWindow(),
      cwnd_,
      sendQuantum_,
      inflightBytes_);
}

void BbrCongestionController::updatePacing() noexcept {
  auto bandwidthEstimate = bandwidth();
  if (!bandwidthEstimate) {
    return;
  }
  auto mrtt = minRtt();
  if (mrtt == 0us || mrtt < minimalPacingInterval_) {
    return;
  }
  // TODO(t40615081, yangchi) cloning Handshake packets make this better
  VLOG_IF(10, conn_.lossState.srtt != 0us)
      << "no reliable srtt sample, " << *this;
  uint64_t targetPacingWindow = bandwidthEstimate * pacingGain_ * mrtt;
  if (btlbwFound_) {
    pacingWindow_ = targetPacingWindow;
  } else if (
      !pacingWindow_ &&
      conn_.lossState.mrtt != std::chrono::microseconds::max() &&
      conn_.lossState.mrtt != 0us &&
      conn_.lossState.mrtt >= minimalPacingInterval_) {
    pacingWindow_ = initialCwnd_;
    mrtt = conn_.lossState.mrtt;
  } else {
    pacingWindow_ = std::max(pacingWindow_, targetPacingWindow);
  }
  // TODO: slower pacing if we are in STARTUP and loss has happened
  std::tie(pacingInterval_, pacingBurstSize_) = calculatePacingRate(
      conn_, pacingWindow_, kMinCwndInMssForBbr, minimalPacingInterval_, mrtt);

  if (conn_.transportSettings.pacingEnabled && conn_.qLogger) {
    conn_.qLogger->addPacingMetricUpdate(pacingBurstSize_, pacingInterval_);
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
    // inflightBytes_ reach the target.
    shouldAdvancePacingGainCycle = false;
  }

  if (pacingGain_ < 1.0 && inflightBytes_ <= calculateTargetCwnd(1.0)) {
    // pacingGain_ < 1.0 means BBR is draining the network queue. If
    // inflightBytes_ is below the target, then it's done.
    shouldAdvancePacingGainCycle = true;
  }

  if (shouldAdvancePacingGainCycle) {
    pacingCycleIndex_ = (pacingCycleIndex_ + 1) % kNumOfCycles;
    cycleStart_ = ackTime;
    if (config_.drainToTarget && pacingGain_ < 1.0 &&
        inflightBytes_ > calculateTargetCwnd(1.0) &&
        kPacingGainCycles[pacingCycleIndex_] == 1.0) {
      // Interestingly Chromium doesn't rollback pacingCycleIndex_ in this case.
      return;
    }
    pacingGain_ = kPacingGainCycles[pacingCycleIndex_];
  }
}

bool BbrCongestionController::shouldExitStartup() noexcept {
  return state_ == BbrState::Startup && btlbwFound_;
}

bool BbrCongestionController::shouldExitDrain() noexcept {
  return state_ == BbrState::Drain &&
      inflightBytes_ <= calculateTargetCwnd(1.0);
}

bool BbrCongestionController::shouldProbeRtt() noexcept {
  if (config_.probeRttDisabledIfAppLimited && appLimitedSinceProbeRtt_) {
    minRttSampler_->timestampMinRtt(Clock::now());
    return false;
  }
  // TODO: Another experiment here is that to maintain a min rtt sample since
  // last ProbeRtt, and if it's very close to the minRtt seom sampler, then skip
  // ProbeRtt.
  if (state_ != BbrState::ProbeRtt && minRttSampler_ &&
      minRttSampler_->minRttExpired() && !exitingQuiescene_) {
    // TODO: also consider connection being quiescent
    return true;
  }
  return false;
}

void BbrCongestionController::handleAckInProbeRtt(
    bool newRoundTrip,
    TimePoint ackTime) noexcept {
  DCHECK(state_ == BbrState::ProbeRtt);
  // This is an ugly looking if-else pot. Here is the basic idea: we wait for
  // inflightBytes_ to reach some low level. Then we stay there for
  // max(1 RTT Round, kProbeRttDuration).
  if (!earliestTimeToExitProbeRtt_ &&
      inflightBytes_ < getCongestionWindow() + conn_.udpSendPacketLen) {
    earliestTimeToExitProbeRtt_ = ackTime + kProbeRttDuration;
    probeRttRound_ = folly::none;
  } else if (earliestTimeToExitProbeRtt_) {
    if (!probeRttRound_ && newRoundTrip) {
      probeRttRound_ = roundTripCounter_;
    } else if (newRoundTrip) {
      if (roundTripCounter_ > *probeRttRound_) {
        if (*earliestTimeToExitProbeRtt_ < ackTime) {
          // We are done with ProbeRtt_, bye.
          if (minRttSampler_) {
            minRttSampler_->timestampMinRtt(ackTime);
          }
          if (btlbwFound_) {
            transitToProbeBw(ackTime);
          } else {
            transitToStartup();
          }
        }
      }
    }
  }
  // TODO: need to update quiescence state
}

void BbrCongestionController::transitToStartup() noexcept {
  state_ = BbrState::Startup;
  pacingGain_ = kStartupGain;
  cwndGain_ = kStartupGain;
}

void BbrCongestionController::transitToProbeRtt() noexcept {
  state_ = BbrState::ProbeRtt;
  pacingGain_ = 1.0f;
  earliestTimeToExitProbeRtt_ = folly::none;
  probeRttRound_ = folly::none;
  if (bandwidthSampler_) {
    bandwidthSampler_->onAppLimited();
  }
  appLimitedSinceProbeRtt_ = false;
}

void BbrCongestionController::transitToDrain() noexcept {
  state_ = BbrState::Drain;
  pacingGain_ = 1.0f / kStartupGain;
  cwndGain_ = kStartupGain;
}

void BbrCongestionController::transitToProbeBw(TimePoint congestionEventTime) {
  state_ = BbrState::ProbeBw;
  cwndGain_ = kProbeBwGain;

  pacingGain_ = kPacingGainCycles[pickRandomCycle()];
  cycleStart_ = congestionEventTime;
}

size_t BbrCongestionController::pickRandomCycle() {
  pacingCycleIndex_ =
      (folly::Random::rand32(kNumOfCycles - 1) + 2) % kNumOfCycles;
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
      config_.conservativeRecovery ? conn_.udpSendPacketLen : bytesAcked;
  recoveryWindow_ =
      std::max(recoveryWindow_, inflightBytes_ + recoveryIncrease);
  recoveryWindow_ = boundedCwnd(
      recoveryWindow_,
      conn_.udpSendPacketLen,
      conn_.transportSettings.maxCwndInMss,
      kMinCwndInMssForBbr);
}

bool BbrCongestionController::inRecovery() const noexcept {
  return recoveryState_ != BbrCongestionController::RecoveryState::NOT_RECOVERY;
}

BbrCongestionController::BbrState BbrCongestionController::state() const
    noexcept {
  return state_;
}

uint64_t BbrCongestionController::getWritableBytes() const noexcept {
  return getCongestionWindow() > inflightBytes_
      ? getCongestionWindow() - inflightBytes_
      : 0;
}

std::chrono::microseconds BbrCongestionController::minRtt() const noexcept {
  return minRttSampler_ ? minRttSampler_->minRtt() : 0us;
}

Bandwidth BbrCongestionController::bandwidth() const noexcept {
  return bandwidthSampler_ ? bandwidthSampler_->getBandwidth() : Bandwidth();
}

uint64_t BbrCongestionController::calculateTargetCwnd(float gain) const
    noexcept {
  auto bandwidthEst = bandwidth();
  auto minRttEst = minRtt();
  if (!bandwidthEst || minRttEst == 0us) {
    return boundedCwnd(
        gain * initialCwnd_,
        conn_.udpSendPacketLen,
        conn_.transportSettings.maxCwndInMss,
        kMinCwndInMssForBbr);
  }
  uint64_t bdp = bandwidthEst * minRttEst;
  return boundedCwnd(
      bdp * gain + kQuantaFactor * sendQuantum_,
      conn_.udpSendPacketLen,
      conn_.transportSettings.maxCwndInMss,
      kMinCwndInMssForBbr);
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
    sendQuantum_ = std::min(pacingRate * 1000us, (uint64_t)64 * 1000);
  }
  auto targetCwnd = calculateTargetCwnd(cwndGain_);
  if (btlbwFound_) {
    targetCwnd += maxAckHeightFilter_.GetBest();
  } else if (config_.enableAckAggregationInStartup) {
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
    conn_.qLogger->addAppIdleUpdate(kAppIdle.str(), idle);
  }
  QUIC_TRACE(bbr_appidle, conn_, idle);
  /*
   * No-op for bbr.
   * We are not necessarily app-limite when we are app-idle. For example, the
   * control stream can have a high inflight bytes.
   */
}

void BbrCongestionController::setAppLimited() {
  if (inflightBytes_ > getCongestionWindow()) {
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

uint64_t BbrCongestionController::getCongestionWindow() const noexcept {
  if (state_ == BbrCongestionController::BbrState::ProbeRtt) {
    if (config_.largeProbeRttCwnd) {
      return calculateTargetCwnd(kLargeProbeRttCwndGain);
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
  subtractAndCheckUnderflow(inflightBytes_, bytesToRemove);
}

uint64_t BbrCongestionController::getPacingRate(
    TimePoint /* currentTime */) noexcept {
  return pacingBurstSize_;
}

std::chrono::microseconds BbrCongestionController::getPacingInterval() const
    noexcept {
  return pacingInterval_;
}

void BbrCongestionController::markPacerTimeoutScheduled(TimePoint) noexcept {
  /* This API is going away */
}

void BbrCongestionController::setMinimalPacingInterval(
    std::chrono::microseconds interval) noexcept {
  minimalPacingInterval_ = interval;
}

bool BbrCongestionController::canBePaced() const noexcept {
  if (!bandwidth() || 0us == minRtt()) {
    return false;
  }
  if (conn_.lossState.srtt < minimalPacingInterval_) {
    return false;
  }
  return true;
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

bool operator<(const Bandwidth& lhs, const Bandwidth& rhs) {
  return !(lhs >= rhs);
}

bool operator<=(const Bandwidth& lhs, const Bandwidth& rhs) {
  return lhs < rhs || lhs == rhs;
}

bool operator>(const Bandwidth& lhs, const Bandwidth& rhs) {
  if (lhs.bytes == 0 && rhs.bytes > 0) {
    return false;
  }
  if (lhs.bytes > 0 && rhs.bytes == 0) {
    return true;
  }
  return lhs.bytes * rhs.interval > rhs.bytes * lhs.interval;
}

bool operator>=(const Bandwidth& lhs, const Bandwidth& rhs) {
  return lhs > rhs || lhs == rhs;
}

bool operator==(const Bandwidth& lhs, const Bandwidth& rhs) {
  if (lhs.bytes == 0 && rhs.bytes > 0) {
    return false;
  }
  if (rhs.bytes == 0 && lhs.bytes > 0) {
    return false;
  }
  return lhs.bytes * rhs.interval == rhs.bytes * lhs.interval;
}

std::ostream& operator<<(std::ostream& os, const Bandwidth& bandwidth) {
  os << "bandwidth bytes=" << bandwidth.bytes
     << " interval=" << bandwidth.interval.count() << "us";
  return os;
}

uint64_t operator*(
    std::chrono::microseconds delay,
    const Bandwidth& bandwidth) {
  return bandwidth * delay;
}

} // namespace quic
