/*
 * Copyright (c) Facebook, Inc. and its affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 *
 */

#include <quic/common/FunctionLooper.h>
#include <folly/ScopeGuard.h>

namespace quic {

FunctionLooper::FunctionLooper(
    folly::EventBase* evb,
    folly::Function<void(bool)>&& func)
    : evb_(evb), func_(std::move(func)) {}

void FunctionLooper::setPacingTimer(
    TimerHighRes::SharedPtr pacingTimer) noexcept {
  pacingTimer_ = std::move(pacingTimer);
}

void FunctionLooper::setPacingFunction(
    folly::Function<std::chrono::microseconds()>&& pacingFunc) {
  pacingFunc_ = std::move(pacingFunc);
}

void FunctionLooper::commonLoopBody(bool fromTimer) noexcept {
  inLoopBody_ = true;
  SCOPE_EXIT {
    inLoopBody_ = false;
  };
  func_(fromTimer);
  // callback could cause us to stop ourselves.
  // Someone could have also called run() in the callback.
  if (!running_) {
    return;
  }
  if (!schedulePacingTimeout(fromTimer)) {
    evb_->runInLoop(this);
  }
}

bool FunctionLooper::schedulePacingTimeout(bool /* fromTimer */) noexcept {
  if (pacingFunc_ && pacingTimer_ && !isScheduled()) {
    auto nextPacingTime = (*pacingFunc_)();
    if (nextPacingTime != std::chrono::microseconds::zero()) {
      pacingTimer_->scheduleTimeout(this, nextPacingTime);
      return true;
    }
  }
  return false;
}

void FunctionLooper::runLoopCallback() noexcept {
  folly::DelayedDestruction::DestructorGuard dg(this);
  commonLoopBody(false);
}

void FunctionLooper::run(bool thisIteration) noexcept {
  running_ = true;
  // Caller can call run() in func_. But if we are in pacing mode, we should
  // prevent such loop.
  if (inLoopBody_ || isLoopCallbackScheduled() || isScheduled()) {
    return;
  }
  evb_->runInLoop(this, thisIteration);
}

void FunctionLooper::stop() noexcept {
  running_ = false;
  cancelLoopCallback();
  cancelTimeout();
}

bool FunctionLooper::isRunning() const {
  return running_;
}

void FunctionLooper::attachEventBase(folly::EventBase* evb) {
  DCHECK(!evb_);
  DCHECK(evb && evb->isInEventBaseThread());
  evb_ = evb;
}

void FunctionLooper::detachEventBase() {
  DCHECK(evb_ && evb_->isInEventBaseThread());
  stop();
  cancelTimeout();
  evb_ = nullptr;
}

void FunctionLooper::timeoutExpired() noexcept {
  folly::DelayedDestruction::DestructorGuard dg(this);
  commonLoopBody(true);
}

void FunctionLooper::callbackCanceled() noexcept {
  return;
}

folly::Optional<std::chrono::microseconds>
FunctionLooper::getTimerTickInterval() noexcept {
  if (pacingTimer_) {
    return pacingTimer_->getTickInterval();
  }
  return folly::none;
}
} // namespace quic
