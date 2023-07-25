/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <quic/congestion_control/QuicCubic.h>

#include <quic/congestion_control/CongestionControlFunctions.h>
#include <quic/logging/QLoggerConstants.h>
#include <quic/state/QuicStateFunctions.h>

#include <folly/Chrono.h>

namespace quic {

Cubic::Cubic(
    QuicConnectionStateBase& conn,
    uint64_t initCwndBytes,
    uint64_t initSsthresh,
    bool tcpFriendly,
    bool ackTrain)
    : conn_(conn), ssthresh_(initSsthresh) {
  cwndBytes_ = std::min(
      conn.transportSettings.maxCwndInMss * conn.udpSendPacketLen,
      std::max(
          initCwndBytes,
          conn.transportSettings.initCwndInMss * conn.udpSendPacketLen));
  steadyState_.tcpFriendly = tcpFriendly;
  steadyState_.estRenoCwnd = cwndBytes_;
  hystartState_.ackTrain = ackTrain;
  if (conn_.qLogger) {
    conn_.qLogger->addCongestionMetricUpdate(
        conn_.lossState.inflightBytes,
        cwndBytes_,
        kCubicInit,
        cubicStateToString(state_).str());
  }
}

CubicStates Cubic::state() const noexcept {
  return state_;
}

uint64_t Cubic::getWritableBytes() const noexcept {
  auto writableBytes = cwndBytes_ > conn_.lossState.inflightBytes
      ? cwndBytes_ - conn_.lossState.inflightBytes
      : 0;
  return writableBytes;
}

void Cubic::handoff(
    uint64_t newCwnd,
    uint64_t newSsthresh,
    TimePoint lastReductionTime) noexcept {
  cwndBytes_ = newCwnd;
  ssthresh_ = newSsthresh;
  if (cwndBytes_ >= ssthresh_) {
    state_ = CubicStates::Steady;
    steadyState_.lastMaxCwndBytes = cwndBytes_;
    steadyState_.lastReductionTime = lastReductionTime;
  }
}

uint64_t Cubic::getCongestionWindow() const noexcept {
  return cwndBytes_;
}

/**
 * TODO: onPersistentCongestion entirely depends on how long a loss period is,
 * not how much a sender sends during that period. If the connection is app
 * limited and loss happens after that, it looks like a long loss period but it
 * may not really be a persistent congestion. However, to keep this code simple,
 * we decide to just ignore app limited state right now.
 */
void Cubic::onPersistentCongestion() {
  auto minCwnd = conn_.transportSettings.minCwndInMss * conn_.udpSendPacketLen;
  ssthresh_ = std::max(cwndBytes_ / 2, minCwnd);
  cwndBytes_ = minCwnd;
  if (steadyState_.tcpFriendly) {
    steadyState_.estRenoCwnd = 0;
  }
  steadyState_.lastReductionTime.reset();
  steadyState_.lastMaxCwndBytes.reset();
  quiescenceStart_.reset();
  hystartState_.found = Cubic::HystartFound::No;
  hystartState_.inRttRound = false;

  state_ = CubicStates::Hystart;

  if (conn_.qLogger) {
    conn_.qLogger->addCongestionMetricUpdate(
        conn_.lossState.inflightBytes,
        getCongestionWindow(),
        kPersistentCongestion,
        cubicStateToString(state_).str());
  }
}

void Cubic::onPacketSent(const OutstandingPacketWrapper& packet) {
  if (std::numeric_limits<uint64_t>::max() - conn_.lossState.inflightBytes <
      packet.metadata.encodedSize) {
    throw QuicInternalException(
        "Cubic: inflightBytes overflow",
        LocalErrorCode::INFLIGHT_BYTES_OVERFLOW);
  }
  conn_.lossState.inflightBytes += packet.metadata.encodedSize;

  if (conn_.transportSettings.ccaConfig.leaveHeadroomForCwndLimited) {
    // Consider cwndBlocked if inflight bytes >= 0.75 * cwnd
    isCwndBlocked_ =
        conn_.lossState.inflightBytes >= (cwndBytes_ - (cwndBytes_ >> 2));
  } else {
    isCwndBlocked_ = conn_.lossState.inflightBytes >= cwndBytes_;
  }
}

void Cubic::onPacketLoss(const LossEvent& loss) {
  quiescenceStart_.reset();
  DCHECK(
      loss.largestLostPacketNum.has_value() &&
      loss.largestLostSentTime.has_value());
  onRemoveBytesFromInflight(loss.lostBytes);
  // If the loss occurred past the endOfRecovery then we need to move the
  // endOfRecovery back and invoke the state machine, otherwise ignore the loss
  // as it was already accounted for in a recovery period.
  if (*loss.largestLostSentTime >=
      recoveryState_.endOfRecovery.value_or(*loss.largestLostSentTime)) {
    recoveryState_.endOfRecovery = Clock::now();
    cubicReduction(loss.lossTime);
    if (state_ == CubicStates::Hystart || state_ == CubicStates::Steady) {
      state_ = CubicStates::FastRecovery;
    }
    ssthresh_ = cwndBytes_;
    if (conn_.pacer) {
      conn_.pacer->refreshPacingRate(
          cwndBytes_ * pacingGain(), conn_.lossState.srtt);
    }
    if (conn_.qLogger) {
      conn_.qLogger->addCongestionMetricUpdate(
          conn_.lossState.inflightBytes,
          getCongestionWindow(),
          kCubicLoss,
          cubicStateToString(state_).str());
    }

  } else {
    if (conn_.qLogger) {
      conn_.qLogger->addCongestionMetricUpdate(
          conn_.lossState.inflightBytes,
          getCongestionWindow(),
          kCubicSkipLoss,
          cubicStateToString(state_).str());
    }
  }

  if (loss.persistentCongestion) {
    onPersistentCongestion();
  }
}

void Cubic::onRemoveBytesFromInflight(uint64_t bytes) {
  DCHECK_LE(bytes, conn_.lossState.inflightBytes);
  conn_.lossState.inflightBytes -= bytes;
  if (conn_.qLogger) {
    conn_.qLogger->addCongestionMetricUpdate(
        conn_.lossState.inflightBytes,
        getCongestionWindow(),
        kRemoveInflight,
        cubicStateToString(state_).str());
  }
}

void Cubic::setAppIdle(bool idle, TimePoint eventTime) noexcept {
  if (conn_.qLogger) {
    conn_.qLogger->addAppIdleUpdate(kAppIdle, idle);
  }
  bool currentAppIdle = isAppIdle();
  if (!currentAppIdle && idle) {
    quiescenceStart_ = eventTime;
  }
  if (!idle && currentAppIdle && *quiescenceStart_ <= eventTime &&
      steadyState_.lastReductionTime) {
    *steadyState_.lastReductionTime +=
        folly::chrono::ceil<std::chrono::milliseconds>(
            eventTime - *quiescenceStart_);
  }
  if (!idle) {
    quiescenceStart_.reset();
  }
}

void Cubic::setAppLimited() {
  // we use app-idle for Cubic
}

bool Cubic::isAppLimited() const noexcept {
  // Or maybe always false. This doesn't really matter for Cubic. Channeling
  // isAppIdle() makes testing easier.
  return isAppIdle();
}

bool Cubic::isAppIdle() const noexcept {
  return quiescenceStart_.has_value();
}

void Cubic::updateTimeToOrigin() noexcept {
  // TODO: is there a faster way to do cbrt? We should benchmark a few
  // alternatives.
  // TODO: there is a tradeoff between precalculate and cache the result of
  // kDefaultCubicReductionFactor / kTimeScalingFactor, and calculate it every
  // time, as multiplication before division may be a little more accurate.
  // TODO: both kDefaultCubicReductionFactor and kTimeScalingFactor are <1.
  // The following calculation can be converted to pure integer calculation if
  // we change the equation a bit to remove all decimals. It's also possible
  // to remove the cbrt calculation by changing the equation.
  if (conn_.qLogger) {
    conn_.qLogger->addTransportStateUpdate(kRecalculateTimeToOrigin);
  }
  if (*steadyState_.lastMaxCwndBytes <= cwndBytes_) {
    steadyState_.timeToOrigin = 0.0;
    steadyState_.originPoint = steadyState_.lastMaxCwndBytes;
    return;
  }
  // TODO: instead of multiplying by 1000 three times, Chromium shifts by 30
  // for this calculation, which loss a little bit of precision. We probably
  // should also consider that tradeoff.
  /**
   * The unit of timeToOrigin result from the the Cubic paper is in seconds.
   * We want milliseconds, thus multiply by 1000 ^ 3 before take cbrt.
   * We tweak Cubic a bit here. In this code, timeToOrigin is defined as time it
   * takes to grow cwnd from backoffTarget to lastMaxCwndBytes * reductionFactor
   */
  // 2500 = kTimeScalingFactor * 1000
  auto bytesToOrigin = *steadyState_.lastMaxCwndBytes - cwndBytes_;
  if (bytesToOrigin * 1000 * 1000 / conn_.udpSendPacketLen * 2500 >
      std::numeric_limits<double>::max()) {
    LOG(WARNING) << "Quic Cubic: timeToOrigin calculation overflow";
    steadyState_.timeToOrigin = std::numeric_limits<double>::max();
  } else {
    steadyState_.timeToOrigin =
        ::cbrt(bytesToOrigin * 1000 * 1000 / conn_.udpSendPacketLen * 2500);
  }
  steadyState_.originPoint = *steadyState_.lastMaxCwndBytes;
}

int64_t Cubic::calculateCubicCwndDelta(TimePoint ackTime) noexcept {
  // TODO: should we also add a rttMin to timeElapsed?
  if (ackTime < *steadyState_.lastReductionTime) {
    LOG(WARNING) << "Cubic ackTime earlier than reduction time";
    return 0;
  }
  auto timeElapsed = folly::chrono::ceil<std::chrono::milliseconds>(
      ackTime - *steadyState_.lastReductionTime);
  int64_t delta = 0;
  double timeElapsedCount = static_cast<double>(timeElapsed.count());
  if (std::pow((timeElapsedCount - steadyState_.timeToOrigin), 3) >
      std::numeric_limits<double>::max()) {
    // (timeElapsed - timeToOrigin) ^ 3 will overflow/underflow, cut delta
    // to numeric_limit
    LOG(WARNING) << "Quic Cubic: (t-K) ^ 3 overflows";
    delta = timeElapsedCount > steadyState_.timeToOrigin
        ? std::numeric_limits<int64_t>::max()
        : std::numeric_limits<uint64_t>::min();
  } else {
    delta = static_cast<int64_t>(std::floor(
        conn_.udpSendPacketLen * kTimeScalingFactor *
        std::pow((timeElapsedCount - steadyState_.timeToOrigin), 3.0) / 1000 /
        1000 / 1000));
  }
  VLOG(15) << "Cubic steady cwnd increase: current cwnd=" << cwndBytes_
           << ", timeElapsed=" << timeElapsed.count()
           << ", timeToOrigin=" << steadyState_.timeToOrigin
           << ", origin=" << *steadyState_.lastMaxCwndBytes
           << ", cwnd delta=" << delta;
  if (conn_.qLogger) {
    conn_.qLogger->addCongestionMetricUpdate(
        conn_.lossState.inflightBytes,
        getCongestionWindow(),
        kCubicSteadyCwnd,
        cubicStateToString(state_).str());
  }
  return delta;
}

uint64_t Cubic::calculateCubicCwnd(int64_t delta) noexcept {
  // TODO: chromium has a limit on targetCwnd to be no larger than half of acked
  // packet size. Linux also has a limit the cwnd increase to 1 MSS per 2 ACKs.
  if (delta > 0 &&
      (std::numeric_limits<uint64_t>::max() - *steadyState_.lastMaxCwndBytes <
       folly::to<uint64_t>(delta))) {
    LOG(WARNING) << "Quic Cubic: overflow cwnd cut at uint64_t max";
    return conn_.transportSettings.maxCwndInMss * conn_.udpSendPacketLen;
  } else if (
      delta < 0 &&
      (folly::to<uint64_t>(std::abs(delta)) > *steadyState_.lastMaxCwndBytes)) {
    LOG(WARNING) << "Quic Cubic: underflow cwnd cut at minCwndBytes_ " << conn_;
    return conn_.transportSettings.minCwndInMss * conn_.udpSendPacketLen;
  } else {
    return boundedCwnd(
        delta + *steadyState_.lastMaxCwndBytes,
        conn_.udpSendPacketLen,
        conn_.transportSettings.maxCwndInMss,
        conn_.transportSettings.minCwndInMss);
  }
}

void Cubic::cubicReduction(TimePoint lossTime) noexcept {
  if (cwndBytes_ >= steadyState_.lastMaxCwndBytes.value_or(cwndBytes_)) {
    steadyState_.lastMaxCwndBytes = cwndBytes_;
  } else {
    // We need to reduce cwnd before it goes back to previous reduction point.
    // In this case, reduce the steadyState_.lastMaxCwndBytes as well:
    steadyState_.lastMaxCwndBytes =
        folly::to_integral(cwndBytes_ * steadyState_.lastMaxReductionFactor);
  }
  steadyState_.lastReductionTime = lossTime;
  lossCwndBytes_ = cwndBytes_;
  lossSsthresh_ = ssthresh_;
  cwndBytes_ = boundedCwnd(
      cwndBytes_ * steadyState_.reductionFactor,
      conn_.udpSendPacketLen,
      conn_.transportSettings.maxCwndInMss,
      conn_.transportSettings.minCwndInMss);
  if (steadyState_.tcpFriendly) {
    steadyState_.estRenoCwnd = cwndBytes_;
  }
}

void Cubic::onPacketAckOrLoss(
    const AckEvent* FOLLY_NULLABLE ackEvent,
    const LossEvent* FOLLY_NULLABLE lossEvent) {
  // TODO: current code in detectLossPackets only gives back a loss event when
  // largestLostPacketNum isn't a folly::none. But we should probably also check
  // against it here anyway just in case the loss code is changed in the
  // future.
  if (lossEvent) {
    onPacketLoss(*lossEvent);
    if (conn_.pacer) {
      conn_.pacer->onPacketsLoss();
    }
  }
  if (ackEvent && ackEvent->largestNewlyAckedPacket.has_value()) {
    CHECK(!ackEvent->ackedPackets.empty());
    onPacketAcked(*ackEvent);
  }
}

void Cubic::onPacketAcked(const AckEvent& ack) {
  auto currentCwnd = cwndBytes_;
  DCHECK_LE(ack.ackedBytes, conn_.lossState.inflightBytes);
  conn_.lossState.inflightBytes -= ack.ackedBytes;
  if (recoveryState_.endOfRecovery.has_value() &&
      *recoveryState_.endOfRecovery >= ack.largestNewlyAckedPacketSentTime) {
    if (conn_.qLogger) {
      conn_.qLogger->addCongestionMetricUpdate(
          conn_.lossState.inflightBytes,
          getCongestionWindow(),
          kCubicSkipAck,
          cubicStateToString(state_).str());
    }
    return;
  }
  switch (state_) {
    case CubicStates::Hystart:
      onPacketAckedInHystart(ack);
      break;
    case CubicStates::Steady:
      onPacketAckedInSteady(ack);
      break;
    case CubicStates::FastRecovery:
      onPacketAckedInRecovery(ack);
      break;
  }
  if (conn_.pacer) {
    conn_.pacer->refreshPacingRate(
        cwndBytes_ * pacingGain(), conn_.lossState.srtt);
  }
  if (cwndBytes_ == currentCwnd) {
    if (conn_.qLogger) {
      conn_.qLogger->addCongestionMetricUpdate(
          conn_.lossState.inflightBytes,
          getCongestionWindow(),
          kCwndNoChange,
          cubicStateToString(state_).str());
    }
  }
  if (conn_.qLogger) {
    conn_.qLogger->addCongestionMetricUpdate(
        conn_.lossState.inflightBytes,
        getCongestionWindow(),
        kCongestionPacketAck,
        cubicStateToString(state_).str());
  }
}

void Cubic::startHystartRttRound(TimePoint time) noexcept {
  VLOG(20) << "Cubic Hystart: Start a new RTT round";
  hystartState_.roundStart = hystartState_.lastJiffy = time;
  hystartState_.ackCount = 0;
  hystartState_.lastSampledRtt = hystartState_.currSampledRtt;
  hystartState_.currSampledRtt.reset();
  hystartState_.rttRoundEndTarget = Clock::now();
  hystartState_.inRttRound = true;
  hystartState_.found = HystartFound::No;
}

bool Cubic::isRecovered(TimePoint packetSentTime) noexcept {
  CHECK(recoveryState_.endOfRecovery.has_value());
  return packetSentTime > *recoveryState_.endOfRecovery;
}

CongestionControlType Cubic::type() const noexcept {
  return CongestionControlType::Cubic;
}

float Cubic::pacingGain() const noexcept {
  double pacingGain = 1.0f;
  if (state_ == CubicStates::Hystart) {
    pacingGain = kCubicHystartPacingGain;
  } else if (state_ == CubicStates::FastRecovery) {
    pacingGain = kCubicRecoveryPacingGain;
  }
  return pacingGain;
}

void Cubic::onPacketAckedInHystart(const AckEvent& ack) {
  if (conn_.transportSettings.ccaConfig.onlyGrowCwndWhenLimited &&
      !isCwndBlocked_) {
    return;
  }
  if (!hystartState_.inRttRound) {
    startHystartRttRound(ack.ackTime);
  }

  // TODO: Should we not increase cwnd if inflight is less than half of cwnd?
  // Note that we take bytes out of inflightBytes before invoke the state
  // machine. So the inflightBytes here is already reduced.
  if (std::numeric_limits<decltype(cwndBytes_)>::max() - cwndBytes_ <
      ack.ackedBytes) {
    throw QuicInternalException(
        "Cubic Hystart: cwnd overflow", LocalErrorCode::CWND_OVERFLOW);
  }
  VLOG(15) << "Cubic Hystart increase cwnd=" << cwndBytes_ << ", by "
           << ack.ackedBytes;
  cwndBytes_ = boundedCwnd(
      cwndBytes_ + ack.ackedBytes,
      conn_.udpSendPacketLen,
      conn_.transportSettings.maxCwndInMss,
      conn_.transportSettings.minCwndInMss);

  folly::Optional<Cubic::ExitReason> exitReason;
  SCOPE_EXIT {
    if (hystartState_.found != Cubic::HystartFound::No &&
        cwndBytes_ >= kLowSsthreshInMss * conn_.udpSendPacketLen) {
      exitReason = Cubic::ExitReason::EXITPOINT;
    }
    if (exitReason.has_value()) {
      VLOG(15) << "Cubic exit slow start, reason = "
               << (*exitReason == Cubic::ExitReason::SSTHRESH
                       ? "cwnd > ssthresh"
                       : "found exit point");
      hystartState_.inRttRound = false;
      if (!conn_.transportSettings.ccaConfig.additiveIncreaseAfterHystart) {
        ssthresh_ = cwndBytes_;
      }
      /* Now we exit slow start, reset currSampledRtt to be maximal value so
       * that next time we go back to slow start, we won't be using a very old
       * sampled RTT as the lastSampledRtt:
       */
      hystartState_.currSampledRtt.reset();
      steadyState_.lastMaxCwndBytes.reset();
      steadyState_.lastReductionTime.reset();
      quiescenceStart_.reset();
      state_ = CubicStates::Steady;
    } else {
      // No exit yet, but we may still need to end this RTT round
      VLOG(20) << "Cubic Hystart, mayEndHystartRttRound, largestAckedPacketNum="
               << *ack.largestNewlyAckedPacket << ", rttRoundEndTarget="
               << hystartState_.rttRoundEndTarget.time_since_epoch().count();
      if (ack.largestNewlyAckedPacketSentTime >
          hystartState_.rttRoundEndTarget) {
        hystartState_.inRttRound = false;
      }
    }
  };

  if (cwndBytes_ >= ssthresh_) {
    exitReason = Cubic::ExitReason::SSTHRESH;
    return;
  }

  DCHECK_LE(cwndBytes_, ssthresh_);
  if (hystartState_.found != Cubic::HystartFound::No) {
    return;
  }
  if (hystartState_.ackTrain) {
    hystartState_.delayMin = std::min(
        hystartState_.delayMin.value_or(conn_.lossState.lrtt),
        conn_.lossState.lrtt);
    // Within kAckCountingGap since lastJiffy:
    // TODO: we should experiment with subtract ackdelay from
    // (ackTime - lastJiffy) as well
    if (ack.ackTime - hystartState_.lastJiffy <= kAckCountingGap) {
      hystartState_.lastJiffy = ack.ackTime;
      if ((ack.ackTime - hystartState_.roundStart) * 2 >=
          hystartState_.delayMin.value()) {
        hystartState_.found = Cubic::HystartFound::FoundByAckTrainMethod;
      }
    }
  }
  // If AckTrain wasn't used or didn't find the exit point, continue with
  // DelayIncrease.
  if (hystartState_.found == Cubic::HystartFound::No) {
    if (hystartState_.ackCount < kAckSampling) {
      hystartState_.currSampledRtt = std::min(
          conn_.lossState.lrtt,
          hystartState_.currSampledRtt.value_or(conn_.lossState.lrtt));
      // We can return early if ++ackCount not meeting kAckSampling:
      if (++hystartState_.ackCount < kAckSampling) {
        VLOG(20) << "Cubic, AckTrain didn't find exit point. ackCount also "
                 << "smaller than kAckSampling. Return early";
        return;
      }
    }

    if (!hystartState_.lastSampledRtt.has_value() ||
        (*hystartState_.lastSampledRtt >=
         std::chrono::microseconds::max() - kDelayIncreaseLowerBound)) {
      return;
    }
    auto eta = std::min(
        kDelayIncreaseUpperBound,
        std::max(
            kDelayIncreaseLowerBound,
            std::chrono::microseconds(
                hystartState_.lastSampledRtt.value().count() >> 4)));
    // lastSampledRtt + eta may overflow:
    if (*hystartState_.lastSampledRtt >
        std::chrono::microseconds::max() - eta) {
      // No way currSampledRtt can top this either, return
      // TODO: so our rtt is within 16ms (kDelayIncreaseUpperBound) of the
      // microseconds::max(), should we just shut down the connection?
      return;
    }
    VLOG(20) << "Cubic Hystart: looking for DelayIncrease, with eta="
             << eta.count() << "us, currSampledRtt="
             << hystartState_.currSampledRtt.value().count()
             << "us, lastSampledRtt="
             << hystartState_.lastSampledRtt.value().count()
             << "us, ackCount=" << (uint32_t)hystartState_.ackCount;
    if (hystartState_.ackCount >= kAckSampling &&
        *hystartState_.currSampledRtt >= *hystartState_.lastSampledRtt + eta) {
      hystartState_.found = Cubic::HystartFound::FoundByDelayIncreaseMethod;
    }
  }
}

/**
 * Note: The Cubic paper, and linux/chromium implementation differ on the
 * definition of "time to origin", or the variable K in the paper. In the paper,
 * K represents how much time it takes to grow an empty cwnd to Wmax. In Linux
 * implementation, to follow Linux's congestion control interface used by other
 * algorithm as well, "time to origin" is the time it takes to grow cwnd back to
 * Wmax from its current value. Chromium follows Linux implementation. It
 * affects timeElapsed as well. If we want to follow the Linux/Chromium
 * implementation, then
 *    timeElapsed = now() - time of the first Ack since last window reduction.
 * Alternatively, the paper's definition,
 *    timeElapsed = now() - time of last window reduction.
 * Theoretically, both paper and Linux/Chromium should result to the same cwnd.
 */
void Cubic::onPacketAckedInSteady(const AckEvent& ack) {
  if (isAppLimited()) {
    if (conn_.qLogger) {
      conn_.qLogger->addCongestionMetricUpdate(
          conn_.lossState.inflightBytes,
          getCongestionWindow(),
          kAckInQuiescence,
          cubicStateToString(state_).str());
    }
    return;
  }
  if (conn_.transportSettings.ccaConfig.onlyGrowCwndWhenLimited &&
      !isCwndBlocked_) {
    return;
  }
  // TODO: There is a tradeoff between getting an accurate Cwnd by frequently
  // calculating it, and the CPU usage cost. This is worth experimenting. E.g.,
  // Chromium has an option to skips the cwnd calculation if it's configured to
  // NOT to update cwnd after every ack, and cwnd hasn't changed since last ack,
  // and time elapsed is smaller than 30ms since last Ack.
  // TODO: It's worth experimenting to use the larger one between cwndBytes_ and
  // lastMaxCwndBytes as the W_max, i.e., always refresh Wmax = cwnd during max
  // probing
  if (!steadyState_.lastMaxCwndBytes) {
    // lastMaxCwndBytes won't be set when we transit from Hybrid to Steady. In
    // that case, we are at the "origin" already.
    if (conn_.qLogger) {
      conn_.qLogger->addCongestionMetricUpdate(
          conn_.lossState.inflightBytes,
          getCongestionWindow(),
          kResetTimeToOrigin,
          cubicStateToString(state_).str());
    }
    steadyState_.timeToOrigin = 0.0;
    steadyState_.lastMaxCwndBytes = cwndBytes_;
    steadyState_.originPoint = cwndBytes_;
    if (steadyState_.tcpFriendly) {
      steadyState_.estRenoCwnd = cwndBytes_;
    }
  } else if (
      !steadyState_.originPoint ||
      *steadyState_.originPoint != *steadyState_.lastMaxCwndBytes) {
    updateTimeToOrigin();
  }
  if (!steadyState_.lastReductionTime) {
    steadyState_.lastReductionTime = ack.ackTime;
    if (conn_.qLogger) {
      conn_.qLogger->addCongestionMetricUpdate(
          conn_.lossState.inflightBytes,
          getCongestionWindow(),
          kResetLastReductionTime,
          cubicStateToString(state_).str());
    }
  }
  uint64_t newCwnd = calculateCubicCwnd(calculateCubicCwndDelta(ack.ackTime));
  if (conn_.transportSettings.ccaConfig.additiveIncreaseAfterHystart &&
      newCwnd < ssthresh_) {
    auto delta = ack.ackedBytes / 10;
    if (newCwnd < cwndBytes_ + delta) {
      newCwnd = boundedCwnd(
          cwndBytes_ + delta,
          conn_.udpSendPacketLen,
          conn_.transportSettings.maxCwndInMss,
          conn_.transportSettings.minCwndInMss);
    }
  }
  if (newCwnd < cwndBytes_) {
    VLOG(10) << "Cubic steady state calculates a smaller cwnd than last round"
             << ", new cnwd = " << newCwnd << ", current cwnd = " << cwndBytes_;
  } else {
    cwndBytes_ = newCwnd;
  }
  // Reno cwnd estimation for TCP friendly.
  if (steadyState_.tcpFriendly && ack.ackedBytes) {
    /* If tcpFriendly is false, we don't keep track of estRenoCwnd. Right now we
       don't provide an API to change tcpFriendly in the middle of a connection.
       If you change that and start to provide an API to mutate tcpFriendly, you
       should calculate estRenoCwnd even when tcpFriendly is false. */
    steadyState_.estRenoCwnd += steadyState_.tcpEstimationIncreaseFactor *
        ack.ackedBytes * conn_.udpSendPacketLen / steadyState_.estRenoCwnd;
    steadyState_.estRenoCwnd = boundedCwnd(
        steadyState_.estRenoCwnd,
        conn_.udpSendPacketLen,
        conn_.transportSettings.maxCwndInMss,
        conn_.transportSettings.minCwndInMss);
    cwndBytes_ = std::max(cwndBytes_, steadyState_.estRenoCwnd);
    if (conn_.qLogger) {
      conn_.qLogger->addCongestionMetricUpdate(
          conn_.lossState.inflightBytes,
          getCongestionWindow(),
          kRenoCwndEstimation,
          cubicStateToString(state_).str());
    }
  }
}

void Cubic::onPacketAckedInRecovery(const AckEvent& ack) {
  CHECK_EQ(cwndBytes_, ssthresh_);
  if (isRecovered(ack.largestNewlyAckedPacketSentTime)) {
    state_ = CubicStates::Steady;

    // We do a Cubic cwnd pre-calculation here so that all Ack events from
    // this point on in the Steady state will only increase cwnd. We can check
    // this invariant in the Steady handler easily with this extra
    // calculation. Note that we don't to the tcpFriendly calculation here.
    // lastMaxCwndBytes and lastReductionTime are only cleared when Hystart
    // transits to Steady. For state machine to be in FastRecovery, a Loss
    // should have happened, and set values to them.
    DCHECK(steadyState_.lastMaxCwndBytes.has_value());
    DCHECK(steadyState_.lastReductionTime.has_value());
    updateTimeToOrigin();
    cwndBytes_ = calculateCubicCwnd(calculateCubicCwndDelta(ack.ackTime));
    if (conn_.qLogger) {
      conn_.qLogger->addCongestionMetricUpdate(
          conn_.lossState.inflightBytes,
          getCongestionWindow(),
          kPacketAckedInRecovery,
          cubicStateToString(state_).str());
    }
  }
}

void Cubic::getStats(CongestionControllerStats& stats) const {
  stats.cubicStats.state = static_cast<uint8_t>(state_);
  stats.cubicStats.ssthresh = ssthresh_;
  stats.cubicStats.lastLossTimeMs = 0;
  if (steadyState_.lastReductionTime) {
    stats.cubicStats.lastLossTimeMs =
        std::chrono::duration_cast<std::chrono::milliseconds>(
            steadyState_.lastReductionTime.value().time_since_epoch())
            .count();
  }
}

folly::StringPiece cubicStateToString(CubicStates state) {
  switch (state) {
    case CubicStates::Steady:
      return "Steady";
    case CubicStates::Hystart:
      return "Hystart";
    case CubicStates::FastRecovery:
      return "Recovery";
  }
  folly::assume_unreachable();
}

} // namespace quic
