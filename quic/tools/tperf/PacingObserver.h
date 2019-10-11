/*
 * Copyright (c) Facebook, Inc. and its affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 *
 */

#pragma once

#include <quic/QuicConstants.h>
#include <quic/congestion_control/Bandwidth.h>
#include <quic/logging/QLogger.h>
#include <quic/state/StateData.h>

namespace quic {

template <typename BucketEndPredicate>
class BucketedQLogPacingObserver : public PacingObserver {
 public:
  explicit BucketedQLogPacingObserver(
      const std::shared_ptr<QLogger>& logger,
      BucketEndPredicate predicate)
      : logger_(logger), bucketEndPredicate_(std::move(predicate)) {}

  explicit BucketedQLogPacingObserver(const std::shared_ptr<QLogger>& logger)
      : logger_(logger) {}

  template <typename... Args>
  explicit BucketedQLogPacingObserver(
      const std::shared_ptr<QLogger>& logger,
      Args&&... args)
      : logger_(logger), bucketEndPredicate_(std::forward<Args>(args)...) {}

  void onNewPacingRate(
      uint64_t packetsPerInterval,
      std::chrono::microseconds interval) override {
    if (bucketEndPredicate_()) {
      auto avgPacingRate = runningExpectedPacingRateCount_
          ? (runningExpectedPacingRateSum_ / runningExpectedPacingRateCount_)
          : runningExpectedPacingRateSum_;
      Bandwidth actualSendRate(
          packetsSentSinceLastUpdate_,
          std::chrono::duration_cast<std::chrono::microseconds>(
              Clock::now() - lastSampledTime_),
          "packets");
      auto logger = logger_.lock();
      if (logger) {
        double ratio = avgPacingRate
            ? ((double)actualSendRate.normalize() / avgPacingRate.normalize())
            : 1.0;
        logger->addPacingObservation(
            actualSendRate.describe(),
            avgPacingRate.describe(),
            folly::to<std::string>(
                (actualSendRate > avgPacingRate ? "Pacing above expect"
                                                : "Pacing below expect"),
                "ratio=",
                ratio));
      }
      packetsSentSinceLastUpdate_ = 0;
      lastSampledTime_ = Clock::now();
      runningExpectedPacingRateCount_ = 0;
      runningExpectedPacingRateSum_ = Bandwidth(0, 0us, "packets");
    }
    Bandwidth expectedPacingRate(packetsPerInterval, interval, "packets");
    runningExpectedPacingRateSum_ += expectedPacingRate;
    ++runningExpectedPacingRateCount_;
  }

  void onPacketSent() override {
    ++packetsSentSinceLastUpdate_;
  }

 private:
  std::weak_ptr<QLogger> logger_;
  uint64_t packetsSentSinceLastUpdate_{0};
  TimePoint lastSampledTime_;
  BucketEndPredicate bucketEndPredicate_;
  Bandwidth runningExpectedPacingRateSum_{0, 0us, "packets"};
  size_t runningExpectedPacingRateCount_{0};
};

template <typename ClockType>
struct FixedTimeBucket {
  explicit FixedTimeBucket(std::chrono::seconds interval)
      : interval_(interval), bucketBegin_(ClockType::now()) {}

  bool operator()() {
    auto currentTime = ClockType::now();
    auto timeElapsed = currentTime - bucketBegin_;
    if (timeElapsed >= interval_) {
      bucketBegin_ = currentTime;
      return true;
    }
    return false;
  }

 private:
  std::chrono::seconds interval_;
  TimePoint bucketBegin_;
};

template <typename ClockType>
struct RttBucket {
  explicit RttBucket(const QuicConnectionStateBase& conn)
      : conn_(conn), bucketBegin_(ClockType::now()) {}

  bool operator()() {
    auto currentTime = ClockType::now();
    auto timeElapsed = currentTime - bucketBegin_;
    if (timeElapsed >= conn_.lossState.srtt) {
      bucketBegin_ = currentTime;
      return true;
    }
    return false;
  }

 private:
  const QuicConnectionStateBase& conn_;
  TimePoint bucketBegin_;
};

struct PerUpdateBucket {
  bool operator()() {
    return true;
  }
};

using RealClockRttBucket = RttBucket<Clock>;
using RealClockFixedTimeBucket = FixedTimeBucket<Clock>;
using QLogPacingObserver = BucketedQLogPacingObserver<PerUpdateBucket>;
using RttBucketQLogPacingObserver =
    BucketedQLogPacingObserver<RealClockRttBucket>;
using FixedBucketQLogPacingObserver =
    BucketedQLogPacingObserver<RealClockFixedTimeBucket>;

} // namespace quic
