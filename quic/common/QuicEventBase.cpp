/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#ifndef MVFST_USE_LIBEV

#include <quic/common/QuicEventBase.h>

namespace quic {

void QuicEventBase::setBackingEventBase(QuicBackingEventBase* evb) {
  backingEvb_ = evb;
}

QuicBackingEventBase* QuicEventBase::getBackingEventBase() const {
  return backingEvb_;
}

void QuicEventBase::runInLoop(
    QuicEventBaseLoopCallback* callback,
    bool thisIteration) {
  return backingEvb_->runInLoop(callback, thisIteration);
}

void QuicEventBase::runInLoop(folly::Function<void()> cb, bool thisIteration) {
  return backingEvb_->runInLoop(std::move(cb), thisIteration);
}

void QuicEventBase::runAfterDelay(
    folly::Function<void()> cb,
    uint32_t milliseconds) {
  return backingEvb_->runAfterDelay(std::move(cb), milliseconds);
}

void QuicEventBase::runInEventBaseThreadAndWait(
    folly::Function<void()> fn) noexcept {
  return backingEvb_->runInEventBaseThreadAndWait(std::move(fn));
}

bool QuicEventBase::isInEventBaseThread() const {
  return backingEvb_->isInEventBaseThread();
}

bool QuicEventBase::scheduleTimeoutHighRes(
    QuicAsyncTimeout* obj,
    std::chrono::microseconds timeout) {
  return backingEvb_->scheduleTimeoutHighRes(obj, timeout);
}

bool QuicEventBase::loopOnce(int flags) {
  return backingEvb_->loopOnce(flags);
}

bool QuicEventBase::loop() {
  return backingEvb_->loop();
}

void QuicEventBase::loopForever() {
  return backingEvb_->loopForever();
}

bool QuicEventBase::loopIgnoreKeepAlive() {
  return backingEvb_->loopIgnoreKeepAlive();
}

void QuicEventBase::terminateLoopSoon() {
  return backingEvb_->terminateLoopSoon();
}

void QuicEventBase::scheduleTimeout(
    QuicTimerCallback* callback,
    std::chrono::milliseconds timeout) {
  return backingEvb_->timer().scheduleTimeout(callback, timeout);
}

std::chrono::milliseconds QuicEventBase::getTimerTickInterval() const {
  return backingEvb_->timer().getTickInterval();
}

} // namespace quic

#endif // !MVFST_USE_LIBEV
