/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#pragma once

#include <quic/common/events/QuicTimer.h>

#include <folly/io/async/EventBase.h>
#include <folly/io/async/HHWheelTimer.h>

#if !FOLLY_MOBILE
#define QUIC_USE_TIMERFD_TIMEOUT_MGR
#include <folly/io/async/STTimerFDTimeoutManager.h>
#endif

namespace quic {

class HighResQuicTimer : public QuicTimer {
 public:
  HighResQuicTimer(
      folly::EventBase* eventBase,
      std::chrono::microseconds intervalDuration);
  ~HighResQuicTimer() override;

  [[nodiscard]] std::chrono::microseconds getTickInterval() const override;

  void scheduleTimeout(
      QuicTimerCallback* callback,
      std::chrono::microseconds timeout) override;

 private:
  class TimerCallbackWrapper : public folly::HHWheelTimerHighRes::Callback,
                               public QuicTimerCallback::TimerCallbackImpl {
   public:
    explicit TimerCallbackWrapper(QuicTimerCallback* callback) {
      callback_ = callback;
    }

    void timeoutExpired() noexcept override {
      callback_->timeoutExpired();
    }

    void callbackCanceled() noexcept override {
      callback_->callbackCanceled();
    }

    // QuicTimerCallback::TimerCallbackImpl
    void cancelImpl() noexcept override {
      folly::HHWheelTimerHighRes::Callback::cancelTimeout();
    }

    // QuicTimerCallback::TimerCallbackImpl
    [[nodiscard]] bool isScheduledImpl() const noexcept override {
      return folly::HHWheelTimerHighRes::Callback::isScheduled();
    }

    // QuicTimerCallback::TimerCallbackImpl
    [[nodiscard]] std::chrono::milliseconds getTimeRemainingImpl()
        const noexcept override {
      // TODO parametrize this type if it's used anywhere outside of tests
      return std::chrono::duration_cast<std::chrono::milliseconds>(
          folly::HHWheelTimerHighRes::Callback::getTimeRemaining());
    }

   private:
    QuicTimerCallback* callback_;
  };

  folly::HHWheelTimerHighRes::UniquePtr wheelTimer_;
#ifdef QUIC_USE_TIMERFD_TIMEOUT_MGR
  folly::STTimerFDTimeoutManager timeoutMgr_;
#endif
};

} // namespace quic
