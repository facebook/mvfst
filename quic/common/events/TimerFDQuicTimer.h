/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#pragma once

#include <quic/common/events/QuicTimer.h>

#include <folly/IntrusiveList.h>
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

  bool isTimerCallbackScheduled(QuicTimerCallback* callback) const override;

  void cancelTimeout(QuicTimerCallback* callback) override;

 private:
  void unregisterCallbackInternal(QuicTimerCallback* callback) {
    QuicEventBase::setImplHandle(callback, nullptr);
  }

  class TimerCallbackWrapper : public folly::HHWheelTimerHighRes::Callback,
                               QuicTimerCallback::TimerCallbackImpl {
   public:
    explicit TimerCallbackWrapper(
        QuicTimerCallback* callback,
        TimerFDQuicTimer* parentTimer) {
      parentTimer_ = parentTimer;
      callback_ = callback;
    }

    friend class TimerFDQuicTimer;

    void timeoutExpired() noexcept override {
      parentTimer_->unregisterCallbackInternal(callback_);
      callback_->timeoutExpired();
      delete this;
    }

    void callbackCanceled() noexcept override {
      parentTimer_->unregisterCallbackInternal(callback_);
      callback_->callbackCanceled();
      delete this;
    }

   private:
    TimerFDQuicTimer* parentTimer_;
    QuicTimerCallback* callback_;
    folly::IntrusiveListHook listHook_;
  };

  folly::IntrusiveList<TimerCallbackWrapper, &TimerCallbackWrapper::listHook_>
      timerCallbackWrappers_;

  folly::STTimerFDTimeoutManager timeoutMgr_;
  folly::HHWheelTimerHighRes::UniquePtr wheelTimer_;
};

} // namespace quic
