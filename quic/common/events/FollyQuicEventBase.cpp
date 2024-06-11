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

FollyQuicEventBase::~FollyQuicEventBase() = default;

void FollyQuicEventBase::runInLoop(
    QuicEventBaseLoopCallback* callback,
    bool thisIteration) {
  auto wrapper = static_cast<LoopCallbackWrapper*>(getImplHandle(callback));
  if (!wrapper) {
    wrapper = new LoopCallbackWrapper(callback);
    setImplHandle(callback, wrapper);
  }
  return backingEvb_->runInLoop(wrapper, thisIteration);
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

void FollyQuicEventBase::runImmediatelyOrRunInEventBaseThread(
    folly::Function<void()> fn) noexcept {
  return backingEvb_->runImmediatelyOrRunInEventBaseThread(std::move(fn));
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
  if (wrapper == nullptr) {
    // This is the first time this timer callback is getting scheduled. Create a
    // wrapper for it.
    wrapper = new TimerCallbackWrapper(timerCallback, this);
    setImplHandle(timerCallback, wrapper);
  }
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
  if (wrapper == nullptr) {
    // This is the first time this timer callback is getting scheduled. Create a
    // wrapper for it.
    wrapper = new TimerCallbackWrapper(timerCallback, this);
    setImplHandle(timerCallback, wrapper);
  }
  backingEvb_->timer().scheduleTimeout(wrapper, timeout);
}

std::chrono::milliseconds FollyQuicEventBase::getTimerTickInterval() const {
  return backingEvb_->timer().getTickInterval();
}

} // namespace quic
