/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <quic/common/events/TimerFDQuicTimer.h>

namespace quic {
TimerFDQuicTimer::TimerFDQuicTimer(
    folly::EventBase* eventBase,
    std::chrono::microseconds intervalDuration)
    : timeoutMgr_(eventBase) {
  wheelTimer_ =
      folly::HHWheelTimerHighRes::newTimer(&timeoutMgr_, intervalDuration);
}

std::chrono::microseconds TimerFDQuicTimer::getTickInterval() const {
  return wheelTimer_->getTickInterval();
}

void TimerFDQuicTimer::scheduleTimeout(
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

bool TimerFDQuicTimer::isTimerCallbackScheduled(
    QuicTimerCallback* callback) const {
  if (!callback || !QuicEventBase::getImplHandle(callback)) {
    // There is no wrapper. Nothing is scheduled.
    return false;
  }
  auto wrapper = static_cast<TimerCallbackWrapper*>(
      QuicEventBase::getImplHandle(callback));
  return wrapper->isScheduled();
}

void TimerFDQuicTimer::cancelTimeout(QuicTimerCallback* callback) {
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

TimerFDQuicTimer::~TimerFDQuicTimer() {
  // Resetting the wheel timer cancels all pending timeouts which clears the
  // wrappers.
  wheelTimer_.reset();
  CHECK(timerCallbackWrappers_.empty());
}
} // namespace quic
