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
  auto wrapper = static_cast<TimerCallbackWrapper*>(
      QuicEventBase::getImplHandle(callback));
  if (wrapper == nullptr) {
    // This is the first time this timer callback is getting scheduled. Create a
    // wrapper for it.
    wrapper = new TimerCallbackWrapper(callback);
    QuicEventBase::setImplHandle(callback, wrapper);
  }
  return wheelTimer_->scheduleTimeout(wrapper, timeout);
}

TimerFDQuicTimer::~TimerFDQuicTimer() {
  // Resetting the wheel timer cancels all pending timeouts.
  wheelTimer_.reset();
}
} // namespace quic
