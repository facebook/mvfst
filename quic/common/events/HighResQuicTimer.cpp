/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <quic/common/events/HighResQuicTimer.h>

namespace quic {
HighResQuicTimer::HighResQuicTimer(
    folly::EventBase* eventBase,
    std::chrono::microseconds intervalDuration) {
  wheelTimer_ =
      folly::HHWheelTimerHighRes::newTimer(eventBase, intervalDuration);
}

std::chrono::microseconds HighResQuicTimer::getTickInterval() const {
  return wheelTimer_->getTickInterval();
}

void HighResQuicTimer::scheduleTimeout(
    QuicTimerCallback* callback,
    std::chrono::microseconds timeout) {
  if (!callback) {
    // There is no callback. Nothing to schedule.
    return;
  }
  if (QuicEventBase::getImplHandle(callback)) {
    // This callback is already scheduled.
    return;
  }
  auto* wrapper = new TimerCallbackWrapper(callback, this);
  timerCallbackWrappers_.push_back(*wrapper);
  QuicEventBase::setImplHandle(callback, wrapper);
  return wheelTimer_->scheduleTimeout(wrapper, timeout);
}

bool HighResQuicTimer::isTimerCallbackScheduled(
    QuicTimerCallback* callback) const {
  if (!callback || !QuicEventBase::getImplHandle(callback)) {
    // There is no wrapper. Nothing is scheduled.
    return false;
  }
  auto wrapper = static_cast<TimerCallbackWrapper*>(
      QuicEventBase::getImplHandle(callback));
  return wrapper->isScheduled();
}

void HighResQuicTimer::cancelTimeout(QuicTimerCallback* callback) {
  if (!callback || !QuicEventBase::getImplHandle(callback)) {
    // There is no wrapper. Nothing to cancel.
    return;
  }
  auto wrapper = static_cast<TimerCallbackWrapper*>(
      QuicEventBase::getImplHandle(callback));
  wrapper->cancelTimeout();
  unregisterCallbackInternal(callback);
  delete wrapper;
}

HighResQuicTimer::~HighResQuicTimer() {
  // Resetting the wheel timer cancels all pending timeouts which clears the
  // wrappers.
  wheelTimer_.reset();
  CHECK(timerCallbackWrappers_.empty());
}
} // namespace quic
