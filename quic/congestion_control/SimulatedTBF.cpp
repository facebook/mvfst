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

SimulatedTBF::SimulatedTBF(Config config) : config_(std::move(config)) {
  if (config_.trackEmptyIntervals) {
    EmptyIntervalState emptyIntervalState = {};
    emptyIntervalState.emptyBucketTimeIntervals_ =
        std::make_shared<std::deque<TimeInterval>>();
    maybeEmptyIntervalState_.assign(emptyIntervalState);
  }
}

double SimulatedTBF::consumeWithBorrowNonBlockingAndUpdateState(
    double toConsume,
    TimePoint sendTime) {
  if (toConsume > config_.burstSizeBytes) {
    throw QuicInternalException(
        "toConsume is greater than burst size",
        LocalErrorCode::INVALID_OPERATION);
  }

  if (config_.trackEmptyIntervals) {
    auto& emptyIntervalState = getEmptyIntervalState();
    DCHECK(
        !emptyIntervalState.maybeLastSendTimeBucketNotEmpty_.has_value() ||
        sendTime >=
            emptyIntervalState.maybeLastSendTimeBucketNotEmpty_.value());
    if (!emptyIntervalState.maybeLastForgetEmptyIntervalTime_.has_value()) {
      emptyIntervalState.maybeLastForgetEmptyIntervalTime_.assign(
          sendTime - 1us);
    }
  }

  const double sendTimeDouble =
      std::chrono::duration<double>(
          sendTime.time_since_epoch() // convert to double and seconds
          )
          .count();

  // Check the number of tokens available at sendTime before consuming.
  // available() returns zero if bucket is in debt.
  const auto numTokensAvailable = available(
      config_.rateBytesPerSecond, config_.burstSizeBytes, sendTimeDouble);
  if (config_.trackEmptyIntervals && numTokensAvailable > 0) {
    auto& emptyIntervalState = getEmptyIntervalState();
    emptyIntervalState.maybeLastSendTimeBucketNotEmpty_.assign(sendTime);
  }

  // If the amount of debt is limited, check if we can consume.
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

  // Send (consume tokens) and determine if any new debt.
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

    // Since we're now in debt, update empty intervals if tracking
    if (config_.trackEmptyIntervals) {
      auto& emptyIntervalState = getEmptyIntervalState();
      DCHECK(emptyIntervalState.maybeLastSendTimeBucketNotEmpty_
                 .has_value()); // assuming burst size > 0
      // Check if the previous packets with the same send time were sent when
      // bucket had some tokens. In that case, skip.
      if (sendTime !=
          emptyIntervalState.maybeLastSendTimeBucketNotEmpty_.value()) {
        if (emptyIntervalState.emptyBucketTimeIntervals_->empty() ||
            emptyIntervalState.emptyBucketTimeIntervals_->back().end <
                emptyIntervalState.maybeLastSendTimeBucketNotEmpty_.value()) {
          // Add a new interval to the back of deque
          emptyIntervalState.emptyBucketTimeIntervals_->emplace_back(
              sendTime, sendTime + debtPayOffTimeUs);
        } else {
          // The bucket has been empty before this was called, so extend the end
          // time of the existing interval on the back of the deque
          emptyIntervalState.emptyBucketTimeIntervals_->back().end =
              sendTime + debtPayOffTimeUs;
        }
      }
    }
  }
  zeroTime_ = sendTimeDouble + maybeDebtPayOffTimeDouble.value();
  return toConsume;
}

[[nodiscard]] bool SimulatedTBF::bucketEmptyThroughoutWindow(
    const TimePoint& startTime,
    const TimePoint& endTime) const {
  const auto& emptyIntervalState =
      getEmptyIntervalState(); // throws if not tracked

  LOG_IF(ERROR, endTime < startTime)
      << "Invalid input range: endTime < startTime";
  LOG_IF(
      ERROR, !emptyIntervalState.maybeLastForgetEmptyIntervalTime_.has_value())
      << "Trying to query a range before sending any bytes.";

  if (emptyIntervalState.maybeLastForgetEmptyIntervalTime_.has_value() &&
      startTime <
          emptyIntervalState.maybeLastForgetEmptyIntervalTime_.value()) {
    throw QuicInternalException(
        "Invalid input range: part of the input range was already forgotten",
        LocalErrorCode::INVALID_OPERATION);
  }

  for (const auto& interval : (*emptyIntervalState.emptyBucketTimeIntervals_)) {
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
  auto& emptyIntervalState = getEmptyIntervalState(); // throws if not tracked

  emptyIntervalState.maybeLastForgetEmptyIntervalTime_.assign(time);
  while (!emptyIntervalState.emptyBucketTimeIntervals_->empty()) {
    if (emptyIntervalState.emptyBucketTimeIntervals_->front().start > time) {
      return;
    } else if (
        emptyIntervalState.emptyBucketTimeIntervals_->front().end <= time) {
      emptyIntervalState.emptyBucketTimeIntervals_->pop_front();
    } else {
      emptyIntervalState.emptyBucketTimeIntervals_->front().start =
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
  const auto& emptyIntervalState =
      getEmptyIntervalState(); // throws if not tracked
  return emptyIntervalState.emptyBucketTimeIntervals_->size();
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

SimulatedTBF::EmptyIntervalState& SimulatedTBF::getEmptyIntervalState() {
  if (!config_.trackEmptyIntervals) {
    throw QuicInternalException(
        "Empty interval tracking not enabled",
        LocalErrorCode::INVALID_OPERATION);
  }
  CHECK(maybeEmptyIntervalState_.has_value());
  return maybeEmptyIntervalState_.value();
}

const SimulatedTBF::EmptyIntervalState& SimulatedTBF::getEmptyIntervalState()
    const {
  if (!config_.trackEmptyIntervals) {
    throw QuicInternalException(
        "Empty interval tracking not enabled",
        LocalErrorCode::INVALID_OPERATION);
  }
  CHECK(maybeEmptyIntervalState_.has_value());
  return maybeEmptyIntervalState_.value();
}

} // namespace quic
