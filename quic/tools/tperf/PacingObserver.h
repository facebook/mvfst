/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#pragma once

#include <quic/QuicConstants.h>
#include <quic/api/QuicSocket.h>
#include <quic/congestion_control/Bandwidth.h>
#include <quic/state/StateData.h>

namespace quic {

template <typename BucketEndPredicate>
class BucketedPacingObserver : public QuicSocketLite::ManagedObserver {
 public:
  explicit BucketedPacingObserver(
      const std::shared_ptr<QLogger>& logger,
      BucketEndPredicate predicate)
      : logger_(logger),
        bucketEndPredicate_(std::move(predicate)),
        lastSampledTime_(Clock::now()) {}

  explicit BucketedPacingObserver(const std::shared_ptr<QLogger>& logger)
      : logger_(logger), lastSampledTime_(Clock::now()) {}

  template <typename... Args>
  explicit BucketedPacingObserver(
      const std::shared_ptr<QLogger>& logger,
      Args&&... args)
      : QuicSocketLite::ManagedObserver(
            EventSetBuilder()
                .enable(Events::packetsWrittenEvents)
                .enable(Events::pacingRateUpdatedEvents)
                .build()),
        logger_(logger),
        bucketEndPredicate_(std::forward<Args>(args)...) {}

  void pacingRateUpdated(
      QuicSocketLite* /* socket */,
      const PacingRateUpdateEvent& event) noexcept override {
    if (bucketEndPredicate_()) {
      auto avgPacingRate = runningExpectedPacingRateCount_
          ? (runningExpectedPacingRateSum_ / runningExpectedPacingRateCount_)
          : runningExpectedPacingRateSum_;
      Bandwidth actualSendRate(
          packetsSentSinceLastUpdate_,
          std::chrono::duration_cast<std::chrono::microseconds>(
              Clock::now() - lastSampledTime_),
          Bandwidth::UnitType::PACKETS);
      auto logger = logger_.lock();

      double ratio = avgPacingRate
          ? ((double)actualSendRate.normalize() / avgPacingRate.normalize())
          : 1.0;

      auto message = fmt::format(
          "Pacing {} expected. Ratio={:.2f}",
          (actualSendRate > avgPacingRate ? "above" : "below"),
          ratio);

      if (ratio < 0.99 || ratio > 1.01) {
        VLOG(2) << message;
      }

      if (logger) {
        logger->addPacingObservation(
            actualSendRate.normalizedDescribe(),
            avgPacingRate.normalizedDescribe(),
            message);
      }
      packetsSentSinceLastUpdate_ = 0;
      lastSampledTime_ = Clock::now();
      runningExpectedPacingRateCount_ = 0;
      runningExpectedPacingRateSum_ =
          Bandwidth(0, 0us, Bandwidth::UnitType::PACKETS);
    }
    Bandwidth expectedPacingRate(
        event.packetsPerInterval, event.interval, Bandwidth::UnitType::PACKETS);
    runningExpectedPacingRateSum_ += expectedPacingRate;
    ++runningExpectedPacingRateCount_;
  }

  void packetsWritten(
      QuicSocketLite* /* socket */,
      const PacketsWrittenEvent& event) override {
    packetsSentSinceLastUpdate_ += event.numPacketsWritten;
  }

 private:
  std::weak_ptr<QLogger> logger_;
  BucketEndPredicate bucketEndPredicate_;
  uint64_t packetsSentSinceLastUpdate_{0};
  TimePoint lastSampledTime_;
  Bandwidth runningExpectedPacingRateSum_{0, 0us, Bandwidth::UnitType::PACKETS};
  size_t runningExpectedPacingRateCount_{0};
};

template <typename ClockType>
struct FixedTimeBucket {
  explicit FixedTimeBucket(std::chrono::milliseconds interval)
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
  std::chrono::milliseconds interval_;
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

namespace {
using RealClockRttBucket = RttBucket<Clock>;
using RealClockFixedTimeBucket = FixedTimeBucket<Clock>;
} // namespace

using PerUpdatePacingObserver = BucketedPacingObserver<PerUpdateBucket>;
using RttBucketPacingObserver = BucketedPacingObserver<RealClockRttBucket>;
using FixedBucketPacingObserver =
    BucketedPacingObserver<RealClockFixedTimeBucket>;

} // namespace quic
