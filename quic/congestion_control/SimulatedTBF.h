/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#pragma once

#include <folly/TokenBucket.h>
#include <glog/logging.h>
#include <quic/QuicConstants.h>
#include <deque>

namespace quic {

struct SimulatedTBFTokenBucketPolicyNoAlignNonConcurrent {
  using align = std::integral_constant<size_t, 0>;
  template <typename T>
  using atom = std::atomic<T>;
  using clock = std::chrono::steady_clock;
  using concurrent = std::false_type;
};

class SimulatedTBF : private folly::BasicDynamicTokenBucket<
                         SimulatedTBFTokenBucketPolicyNoAlignNonConcurrent> {
  struct TimeInterval {
    TimePoint start;
    TimePoint end;

    TimeInterval(const TimePoint& s, const TimePoint& e) : start(s), end(e) {
      if (start > end) {
        throw std::invalid_argument("Trying to construct invalid interval");
      }
    }

    bool operator==(TimeInterval& rhs) const {
      return start == rhs.start && end == rhs.end;
    }

    friend bool operator==(const TimeInterval& a, const TimeInterval& b) {
      return a.start == b.start && a.end == b.end;
    }
  };

 public:
  struct Config {
    double rateBytesPerSecond{0};
    double burstSizeBytes{0};
    folly::Optional<double> maybeMaxDebtQueueSizeBytes;

    // Whether the SimulatedTBF will keep track of when TBF was empty.
    bool trackEmptyIntervals{true};
  };

  explicit SimulatedTBF(Config config);

  /**
   * Models sending of specified number of bytes at the specified time. If the
   * TBF does not have sufficient tokens at the specified time to send all
   * bytes, the TBF will go into debt.
   *
   * @param bytesSent  The number of bytes sent.
   * @param time       The time when the bytes were sent.
   *                   Should be greater than or equal to the previous time
   *                   value passed to this function.
   * @return           The number of bytes consumed from the TBF, including
   *                   bytes will be consumed at a later time interval. As
   *                   a result, this will equal either bytesSent or 0.
   */
  double consumeWithBorrowNonBlockingAndUpdateState(
      double bytesSent,
      TimePoint time);

  /**
   * Returns if the bucket were empty or in debt throughout the specified
   * window.
   *
   * @param windowStartTime  The start of the time window
   * @param windowEndTime    The end of the time window
   * @return                 If bucket were empty or in debt
   *                         throughout the time window (inclusive).
   */
  [[nodiscard]] bool bucketEmptyThroughoutWindow(
      const TimePoint& windowStartTime,
      const TimePoint& windowEndTime) const;

  /**
   * Returns if the bucket were empty or in debt at the specified time in the
   * past.
   *
   * @param time
   * @return      If bucket were empty or in debt
   *              at the specified time.
   */
  [[nodiscard]] bool bucketEmptyAt(const TimePoint& time) const;

  /**
   * Removes all the intervals (or a portion of an interval), in which the
   * bucket were empty or in debt, prior to and including the @param time.
   *
   * @param time  The specified time in which all the intervals prior to that
   * must be removed.
   */
  void forgetEmptyIntervalsPriorTo(const TimePoint& time);

  /**
   * Returns the number of tokens available in bytes at the specified time (now
   * or in future).
   *
   * @param time
   * @return      The number of tokens in bytes.
   *
   */
  [[nodiscard]] double getNumAvailableTokensInBytes(
      const TimePoint& time) const;

  /**
   * Returns the number of intervals in which the bucket were empty or in
   * debt.
   */
  [[nodiscard]] unsigned int getNumEmptyIntervalsTracked() const;

  [[nodiscard]] double getRateBytesPerSecond() const;

  [[nodiscard]] double getBurstSizeBytes() const;

  [[nodiscard]] folly::Optional<double> getMaxDebtQueueSizeBytes() const;

 private:
  struct EmptyIntervalState {
    std::shared_ptr<std::deque<TimeInterval>> emptyBucketTimeIntervals_;
    folly::Optional<TimePoint> maybeLastSendTimeBucketNotEmpty_;
    folly::Optional<TimePoint> maybeLastForgetEmptyIntervalTime_;
  };

  EmptyIntervalState& getEmptyIntervalState();
  [[nodiscard]] const EmptyIntervalState& getEmptyIntervalState() const;

  Config config_;
  double zeroTime_{0};
  folly::Optional<EmptyIntervalState> maybeEmptyIntervalState_;
};
} // namespace quic
