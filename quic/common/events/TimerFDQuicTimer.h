/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#pragma once

#include <quic/common/events/QuicTimer.h>

#include <folly/experimental/STTimerFDTimeoutManager.h>
#include <folly/io/async/HHWheelTimer.h>

namespace quic {

class TimerFDQuicTimer : public QuicTimer {
 public:
  TimerFDQuicTimer(
      folly::EventBase* eventBase,
      std::chrono::microseconds intervalDuration);
  ~TimerFDQuicTimer() override;

  [[nodiscard]] std::chrono::microseconds getTickInterval() const override;

  void scheduleTimeout(
      QuicTimerCallback* callback,
      std::chrono::microseconds timeout) override;

 private:
  class TimerCallbackWrapper : public folly::HHWheelTimerHighRes::Callback,
                               QuicTimerCallback::TimerCallbackImpl {
   public:
    explicit TimerCallbackWrapper(QuicTimerCallback* callback) {
      callback_ = callback;
    }

    friend class TimerFDQuicTimer;

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

  folly::STTimerFDTimeoutManager timeoutMgr_;
  folly::HHWheelTimerHighRes::UniquePtr wheelTimer_;
};

} // namespace quic
