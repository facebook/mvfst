/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <quic/common/events/FollyQuicEventBase.h>

namespace quic {

FollyQuicEventBase::FollyQuicEventBase(folly::EventBase* evb) {
  backingEvb_ = evb;
}

FollyQuicEventBase::~FollyQuicEventBase() {
  loopCallbackWrappers_.clear_and_dispose([](LoopCallbackWrapper* wrapper) {
    wrapper->cancelLoopCallback();
    delete wrapper;
  });
  timerCallbackWrappers_.clear_and_dispose([](TimerCallbackWrapper* wrapper) {
    wrapper->cancelTimeout();
    delete wrapper;
  });
}

void FollyQuicEventBase::runInLoop(
    QuicEventBaseLoopCallback* callback,
    bool thisIteration) {
  auto wrapper = static_cast<LoopCallbackWrapper*>(getImplHandle(callback));
  if (!wrapper) {
    wrapper = new LoopCallbackWrapper(callback, this);
    loopCallbackWrappers_.push_back(*wrapper);
    setImplHandle(callback, wrapper);
    return backingEvb_->runInLoop(wrapper, thisIteration);
  } else {
    // This callback is already scheduled.
    return;
  }
}

void FollyQuicEventBase::runInLoop(
    folly::Function<void()> cb,
    bool thisIteration) {
  return backingEvb_->runInLoop(std::move(cb), thisIteration);
}

void FollyQuicEventBase::runAfterDelay(
    folly::Function<void()> cb,
    uint32_t milliseconds) {
  return backingEvb_->runAfterDelay(std::move(cb), milliseconds);
}

void FollyQuicEventBase::runInEventBaseThreadAndWait(
    folly::Function<void()> fn) noexcept {
  return backingEvb_->runInEventBaseThreadAndWait(std::move(fn));
}

void FollyQuicEventBase::runImmediatelyOrRunInEventBaseThreadAndWait(
    folly::Function<void()> fn) noexcept {
  return backingEvb_->runImmediatelyOrRunInEventBaseThreadAndWait(
      std::move(fn));
}

void FollyQuicEventBase::runInEventBaseThread(
    folly::Function<void()> fn) noexcept {
  return backingEvb_->runInEventBaseThread(std::move(fn));
}

bool FollyQuicEventBase::isInEventBaseThread() const {
  return backingEvb_->isInEventBaseThread();
}

bool FollyQuicEventBase::loopOnce(int flags) {
  return backingEvb_->loopOnce(flags);
}

bool FollyQuicEventBase::loop() {
  return backingEvb_->loop();
}

void FollyQuicEventBase::loopForever() {
  return backingEvb_->loopForever();
}

bool FollyQuicEventBase::loopIgnoreKeepAlive() {
  return backingEvb_->loopIgnoreKeepAlive();
}

void FollyQuicEventBase::terminateLoopSoon() {
  return backingEvb_->terminateLoopSoon();
}

bool FollyQuicEventBase::scheduleTimeoutHighRes(
    QuicTimerCallback* timerCallback,
    std::chrono::microseconds timeout) {
  if (!timerCallback) {
    // There is no callback. Nothing to schedule.
    return false;
  }
  auto wrapper =
      static_cast<TimerCallbackWrapper*>(getImplHandle(timerCallback));
  if (wrapper != nullptr) {
    // This callback is already scheduled.
    return false;
  }
  wrapper = new TimerCallbackWrapper(timerCallback, this);
  timerCallbackWrappers_.push_back(*wrapper);
  setImplHandle(timerCallback, wrapper);
  return backingEvb_->scheduleTimeoutHighRes(wrapper, timeout);
}

void FollyQuicEventBase::scheduleTimeout(
    QuicTimerCallback* timerCallback,
    std::chrono::milliseconds timeout) {
  if (!timerCallback) {
    // There is no callback. Nothing to schedule.
    return;
  }
  auto wrapper =
      static_cast<TimerCallbackWrapper*>(getImplHandle(timerCallback));
  if (wrapper != nullptr) {
    // This callback is already scheduled.
    return;
  }
  wrapper = new TimerCallbackWrapper(timerCallback, this);
  timerCallbackWrappers_.push_back(*wrapper);
  setImplHandle(timerCallback, wrapper);
  backingEvb_->timer().scheduleTimeout(wrapper, timeout);
}

bool FollyQuicEventBase::isTimeoutScheduled(
    QuicTimerCallback* timerCallback) const {
  if (!timerCallback || !getImplHandle(timerCallback)) {
    // There is no wrapper. Nothing is scheduled.
    return false;
  }
  auto wrapper =
      static_cast<TimerCallbackWrapper*>(getImplHandle(timerCallback));
  return wrapper->isScheduled();
}

std::chrono::milliseconds FollyQuicEventBase::getTimeoutTimeRemaining(
    QuicTimerCallback* timerCallback) const {
  if (!timerCallback || !getImplHandle(timerCallback)) {
    // There is no wrapper. Nothing to check.
    return std::chrono::milliseconds(0);
  }
  auto wrapper =
      static_cast<TimerCallbackWrapper*>(getImplHandle(timerCallback));
  return wrapper->getTimeRemaining();
}

void FollyQuicEventBase::cancelTimeout(QuicTimerCallback* timerCallback) {
  if (!timerCallback || !getImplHandle(timerCallback)) {
    // There is no wrapper. Nothing to cancel.
    return;
  }
  auto wrapper =
      static_cast<TimerCallbackWrapper*>(getImplHandle(timerCallback));
  unregisterTimerCallbackInternal(timerCallback);
  wrapper->cancelTimeout();
  delete wrapper;
}

std::chrono::milliseconds FollyQuicEventBase::getTimerTickInterval() const {
  return backingEvb_->timer().getTickInterval();
}

void FollyQuicEventBase::cancelLoopCallback(
    QuicEventBaseLoopCallback* callback) {
  auto wrapper = static_cast<LoopCallbackWrapper*>(getImplHandle(callback));
  if (!wrapper) {
    return;
  }
  unregisterLoopCallbackInternal(callback);
  wrapper->cancelLoopCallback();
  delete wrapper;
}

bool FollyQuicEventBase::isLoopCallbackScheduled(
    QuicEventBaseLoopCallback* callback) const {
  auto wrapper =
      static_cast<const LoopCallbackWrapper*>(getImplHandle(callback));
  if (!wrapper) {
    return false;
  }
  return wrapper->isLoopCallbackScheduled();
}

} // namespace quic
