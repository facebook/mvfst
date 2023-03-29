/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <quic/QuicException.h>
#include <quic/congestion_control/SimulatedTBF.h>
#include <chrono>

namespace quic {

SimulatedTBF::SimulatedTBF(Config config) : config_(std::move(config)) {}

double SimulatedTBF::consumeWithBorrowNonBlockingAndUpdateState(
    double toConsume,
    TimePoint sendTime) {
  if (toConsume > config_.burstSizeBytes) {
    throw QuicInternalException(
        "toConsume is greater than burst size",
        LocalErrorCode::INVALID_OPERATION);
  }

  DCHECK(
      !maybeLastSendTimeBucketNotEmpty_.has_value() ||
      sendTime >= maybeLastSendTimeBucketNotEmpty_.value());

  if (!maybeLastForgetEmptyIntervalTime_.has_value()) {
    maybeLastForgetEmptyIntervalTime_.assign(sendTime - 1us);
  }

  double sendTimeDouble =
      std::chrono::duration<double>(
          sendTime.time_since_epoch() // convert to double and seconds
          )
          .count();

  // Check the number of tokens available at sendTime before consuming. Note
  // that available returns zero if bucket is in debt
  auto numTokensAvailable = available(
      config_.rateBytesPerSecond, config_.burstSizeBytes, sendTimeDouble);

  if (numTokensAvailable > 0) {
    maybeLastSendTimeBucketNotEmpty_.assign(sendTime);
  }

  if (config_.maybeMaxDebtQueueSizeBytes.has_value()) {
    DCHECK(config_.maybeMaxDebtQueueSizeBytes.value() >= 0);
    auto currDebtQueueSizeBytes = std::max(
        0.0, (zeroTime_ - sendTimeDouble) * config_.rateBytesPerSecond);
    DCHECK(
        currDebtQueueSizeBytes <= config_.maybeMaxDebtQueueSizeBytes.value());

    if (toConsume > numTokensAvailable +
            (config_.maybeMaxDebtQueueSizeBytes.value() -
             currDebtQueueSizeBytes)) {
      // Not enough space left to consume the entire packet
      return 0;
    }
  }

  folly::Optional<double> maybeDebtPayOffTimeDouble =
      consumeWithBorrowNonBlocking(
          toConsume,
          config_.rateBytesPerSecond,
          config_.burstSizeBytes,
          sendTimeDouble);
  DCHECK(maybeDebtPayOffTimeDouble.hasValue());
  if (maybeDebtPayOffTimeDouble.value() > 0) {
    // Bucket is in debt now after consuming toConsume tokens

    const auto debtPayOffTimeUs =
        std::chrono::duration_cast<std::chrono::microseconds>(
            std::chrono::duration<double>(maybeDebtPayOffTimeDouble.value()));

    DCHECK(maybeLastSendTimeBucketNotEmpty_
               .has_value()); // assuming burst size > 0
    // Check if the previous packets with the same send time were sent when
    // bucket had some tokens. In that case, skip.
    if (sendTime != maybeLastSendTimeBucketNotEmpty_.value()) {
      if (emptyBucketTimeIntervals_.empty() ||
          emptyBucketTimeIntervals_.back().end <
              maybeLastSendTimeBucketNotEmpty_.value()) {
        // Add a new interval to the back of deque
        emptyBucketTimeIntervals_.emplace_back(
            sendTime, sendTime + debtPayOffTimeUs);
      } else {
        // The bucket has been empty before this was called, so extend the end
        // time of the existing interval on the back of the deque
        emptyBucketTimeIntervals_.back().end = sendTime + debtPayOffTimeUs;
      }
    }
  }
  zeroTime_ = sendTimeDouble + maybeDebtPayOffTimeDouble.value();
  return toConsume;
}

[[nodiscard]] bool SimulatedTBF::bucketEmptyThroughoutWindow(
    const TimePoint& startTime,
    const TimePoint& endTime) const {
  LOG_IF(ERROR, endTime < startTime)
      << "Invalid input range: endTime < startTime";
  LOG_IF(ERROR, !maybeLastForgetEmptyIntervalTime_.has_value())
      << "Trying to query a range before sending any bytes.";

  if (maybeLastForgetEmptyIntervalTime_.has_value() &&
      startTime < maybeLastForgetEmptyIntervalTime_.value()) {
    throw QuicInternalException(
        "Invalid input range: part of the input range was already forgotten",
        LocalErrorCode::INVALID_OPERATION);
  }

  for (const auto& interval : emptyBucketTimeIntervals_) {
    if (interval.start <= startTime && endTime <= interval.end) {
      return true;
    } else if (startTime > interval.end) {
      // older interval at the front of the deque, skip
      continue;
    } else {
      return false;
    }
  }
  return false;
}

[[nodiscard]] bool SimulatedTBF::bucketEmptyAt(
    const TimePoint& sendTime) const {
  return bucketEmptyThroughoutWindow(sendTime, sendTime);
}

void SimulatedTBF::forgetEmptyIntervalsPriorTo(const TimePoint& time) {
  maybeLastForgetEmptyIntervalTime_.assign(time);
  while (!emptyBucketTimeIntervals_.empty()) {
    if (emptyBucketTimeIntervals_.front().start > time) {
      return;
    } else if (emptyBucketTimeIntervals_.front().end <= time) {
      emptyBucketTimeIntervals_.pop_front();
    } else {
      emptyBucketTimeIntervals_.front().start =
          time + std::chrono::microseconds{1};
      return;
    }
  }
}

[[nodiscard]] double SimulatedTBF::getNumAvailableTokensInBytes(
    const TimePoint& time) const {
  double timeDouble =
      std::chrono::duration<double>(
          time.time_since_epoch() // convert to double and seconds
          )
          .count();
  return available(
      config_.rateBytesPerSecond, config_.burstSizeBytes, timeDouble);
}

[[nodiscard]] unsigned int SimulatedTBF::getNumEmptyIntervalsTracked() const {
  return emptyBucketTimeIntervals_.size();
}

[[nodiscard]] double SimulatedTBF::getRateBytesPerSecond() const {
  return config_.rateBytesPerSecond;
}

[[nodiscard]] double SimulatedTBF::getBurstSizeBytes() const {
  return config_.burstSizeBytes;
}

[[nodiscard]] folly::Optional<double> SimulatedTBF::getMaxDebtQueueSizeBytes()
    const {
  return config_.maybeMaxDebtQueueSizeBytes;
}

} // namespace quic
