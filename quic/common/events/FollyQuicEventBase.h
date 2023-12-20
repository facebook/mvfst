/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#pragma once

#include <functional>

#include <quic/common/events/QuicEventBase.h>

#include <folly/IntrusiveList.h>
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

  bool isTimeoutScheduled(QuicTimerCallback* callback) const override;

  std::chrono::milliseconds getTimeoutTimeRemaining(
      QuicTimerCallback* callback) const override;

  void cancelTimeout(QuicTimerCallback* callback) override;

  [[nodiscard]] std::chrono::milliseconds getTimerTickInterval() const override;

  void cancelLoopCallback(QuicEventBaseLoopCallback* callback) override;

  bool isLoopCallbackScheduled(
      QuicEventBaseLoopCallback* callback) const override;

  folly::EventBase* getBackingEventBase() {
    return backingEvb_;
  }

 private:
  void unregisterLoopCallbackInternal(QuicEventBaseLoopCallback* callback) {
    auto implHandle =
        static_cast<LoopCallbackWrapper*>(getImplHandle(callback));
    CHECK_NOTNULL(implHandle);
    loopCallbackWrappers_.erase(loopCallbackWrappers_.iterator_to(*implHandle));
    setImplHandle(callback, nullptr);
  }

  void unregisterTimerCallbackInternal(QuicTimerCallback* callback) {
    auto implHandle =
        static_cast<TimerCallbackWrapper*>(getImplHandle(callback));
    CHECK_NOTNULL(implHandle);
    timerCallbackWrappers_.erase(
        timerCallbackWrappers_.iterator_to(*implHandle));
    setImplHandle(callback, nullptr);
  }

  class TimerCallbackWrapper : public folly::HHWheelTimer::Callback,
                               public folly::AsyncTimeout,
                               public QuicTimerCallback::TimerCallbackImpl {
   public:
    explicit TimerCallbackWrapper(
        QuicTimerCallback* callback,
        FollyQuicEventBase* evb)
        : folly::AsyncTimeout(evb->getBackingEventBase()) {
      parentEvb_ = evb;
      callback_ = callback;
    }

    friend class FollyQuicEventBase;

    void timeoutExpired() noexcept override {
      parentEvb_->unregisterTimerCallbackInternal(callback_);
      callback_->timeoutExpired();
      delete this;
    }

    void callbackCanceled() noexcept override {
      parentEvb_->unregisterTimerCallbackInternal(callback_);
      callback_->callbackCanceled();
      delete this;
    }

    bool isScheduled() noexcept {
      return folly::AsyncTimeout::isScheduled() ||
          folly::HHWheelTimer::Callback::isScheduled();
    }

    void cancelTimeout() noexcept {
      folly::AsyncTimeout::cancelTimeout();
      folly::HHWheelTimer::Callback::cancelTimeout();
    }

   private:
    FollyQuicEventBase* parentEvb_;
    QuicTimerCallback* callback_;
    folly::IntrusiveListHook listHook_;
  };

  class LoopCallbackWrapper
      : public folly::EventBase::LoopCallback,
        public QuicEventBaseLoopCallback::LoopCallbackImpl {
   public:
    explicit LoopCallbackWrapper(
        QuicEventBaseLoopCallback* callback,
        FollyQuicEventBase* evb) {
      parentEvb_ = evb;
      callback_ = callback;
    }

    friend class FollyQuicEventBase;

    void runLoopCallback() noexcept override {
      // We need to remove the callback wrapper from the parent evb's map, call
      // the callback, then delete this wrapper.
      parentEvb_->unregisterLoopCallbackInternal(callback_);
      callback_->runLoopCallback();
      delete this;
    }

   private:
    FollyQuicEventBase* parentEvb_;
    QuicEventBaseLoopCallback* callback_;
    folly::IntrusiveListHook listHook_;
  };

  folly::IntrusiveList<LoopCallbackWrapper, &LoopCallbackWrapper::listHook_>
      loopCallbackWrappers_;
  folly::IntrusiveList<TimerCallbackWrapper, &TimerCallbackWrapper::listHook_>
      timerCallbackWrappers_;
  folly::EventBase* backingEvb_{nullptr};
};

} // namespace quic
