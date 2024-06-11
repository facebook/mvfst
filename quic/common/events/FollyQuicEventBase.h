/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#pragma once

#include <functional>

#include <quic/common/events/QuicEventBase.h>

#include <folly/io/async/EventBase.h>
#include <folly/io/async/HHWheelTimer-fwd.h>

FOLLY_GNU_DISABLE_WARNING("-Wdeprecated-declarations")

namespace quic {

/**
 * This is a default event base implementation of QuicEventBaseInterface that
 * mvfst uses by default. It's a wrapper around folly::EventBase.
 */
class FollyQuicEventBase : public QuicEventBase {
 public:
  explicit FollyQuicEventBase(folly::EventBase* evb);
  ~FollyQuicEventBase() override;

  void runInLoop(
      QuicEventBaseLoopCallback* callback,
      bool thisIteration = false) override;

  void runInLoop(folly::Function<void()> cb, bool thisIteration = false)
      override;

  void runAfterDelay(folly::Function<void()> cb, uint32_t milliseconds)
      override;

  void runInEventBaseThreadAndWait(
      folly::Function<void()> fn) noexcept override;

  void runImmediatelyOrRunInEventBaseThreadAndWait(
      folly::Function<void()> fn) noexcept override;

  void runInEventBaseThread(folly::Function<void()> fn) noexcept override;

  void runImmediatelyOrRunInEventBaseThread(
      folly::Function<void()> fn) noexcept override;

  [[nodiscard]] bool isInEventBaseThread() const override;

  bool scheduleTimeoutHighRes(
      QuicTimerCallback* callback,
      std::chrono::microseconds timeout) override;

  bool loopOnce(int flags = 0) override;

  bool loop() override;

  void loopForever() override;

  bool loopIgnoreKeepAlive() override;

  void terminateLoopSoon() override;

  void scheduleTimeout(
      QuicTimerCallback* callback,
      std::chrono::milliseconds timeout) override;

  [[nodiscard]] std::chrono::milliseconds getTimerTickInterval() const override;

  folly::EventBase* getBackingEventBase() {
    return backingEvb_;
  }

 private:
  class TimerCallbackWrapper : public folly::HHWheelTimer::Callback,
                               public folly::AsyncTimeout,
                               public QuicTimerCallback::TimerCallbackImpl {
   public:
    explicit TimerCallbackWrapper(
        QuicTimerCallback* callback,
        FollyQuicEventBase* evb)
        : folly::AsyncTimeout(evb->getBackingEventBase()) {
      callback_ = callback;
    }

    friend class FollyQuicEventBase;

    // folly::AsyncTimeout and folly::HHWheelTimer::Callback
    void timeoutExpired() noexcept override {
      callback_->timeoutExpired();
    }

    // folly::HHWheelTimer::Callback
    void callbackCanceled() noexcept override {
      callback_->callbackCanceled();
    }

    // QuicTimerCallback::TimerCallbackImpl
    void cancelImpl() noexcept override {
      folly::AsyncTimeout::cancelTimeout();
      folly::HHWheelTimer::Callback::cancelTimeout();
    }

    // QuicTimerCallback::TimerCallbackImpl
    [[nodiscard]] bool isScheduledImpl() const noexcept override {
      return folly::AsyncTimeout::isScheduled() ||
          folly::HHWheelTimer::Callback::isScheduled();
    }

    // QuicTimerCallback::TimerCallbackImpl
    [[nodiscard]] std::chrono::milliseconds getTimeRemainingImpl()
        const noexcept override {
      return folly::HHWheelTimer::Callback::getTimeRemaining();
    }

   private:
    // Hide these functions
    [[nodiscard]] bool isScheduled() const {
      return isScheduledImpl();
    }
    void cancelTimeout() noexcept {
      return cancelImpl();
    }
    QuicTimerCallback* callback_;
  };

  class LoopCallbackWrapper
      : public folly::EventBase::LoopCallback,
        public QuicEventBaseLoopCallback::LoopCallbackImpl {
   public:
    explicit LoopCallbackWrapper(QuicEventBaseLoopCallback* callback) {
      callback_ = callback;
    }

    // folly::EventBase::LoopCallback
    void runLoopCallback() noexcept override {
      callback_->runLoopCallback();
    }

    // QuicEventBaseLoopCallback::LoopCallbackImpl
    void cancelImpl() noexcept override {
      folly::EventBase::LoopCallback::cancelLoopCallback();
    }

    // QuicEventBaseLoopCallback::LoopCallbackImpl
    [[nodiscard]] bool isScheduledImpl() const noexcept override {
      return folly::EventBase::LoopCallback::isLoopCallbackScheduled();
    }

   private:
    QuicEventBaseLoopCallback* callback_;
  };

  folly::EventBase* backingEvb_{nullptr};
};

} // namespace quic
