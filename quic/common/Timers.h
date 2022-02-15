/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#pragma once
#include <folly/io/async/HHWheelTimer.h>

#if !FOLLY_MOBILE
#define QUIC_USE_TIMERFD_TIMEOUT_MGR
#include <folly/experimental/STTimerFDTimeoutManager.h>
#endif

namespace quic {
#ifdef QUIC_USE_TIMERFD_TIMEOUT_MGR
class TimerFDTimerHighRes : public folly::DelayedDestruction {
 public:
  using Callback = folly::HHWheelTimerHighRes::Callback;
  using UniquePtr = std::unique_ptr<TimerFDTimerHighRes, Destructor>;
  using SharedPtr = std::shared_ptr<TimerFDTimerHighRes>;

  template <typename... Args>
  static UniquePtr newTimer(Args&&... args) {
    return UniquePtr(new TimerFDTimerHighRes(std::forward<Args>(args)...));
  }

  TimerFDTimerHighRes(
      folly::EventBase* eventBase,
      std::chrono::microseconds intervalDuration);

  std::chrono::microseconds getTickInterval() const {
    return wheelTimer_->getTickInterval();
  }

  void scheduleTimeout(Callback* callback, std::chrono::microseconds timeout) {
    wheelTimer_->scheduleTimeout(callback, timeout);
  }

 private:
  ~TimerFDTimerHighRes() override;

  folly::STTimerFDTimeoutManager timeoutMgr_;
  folly::HHWheelTimerHighRes::UniquePtr wheelTimer_;
};
using TimerHighRes = TimerFDTimerHighRes;
#else
using TimerHighRes = folly::HHWheelTimerHighRes;
#endif
} // namespace quic
