/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <folly/ScopeGuard.h>
#include <glog/logging.h>
#include <quic/common/FunctionLooper.h>

namespace quic {
using namespace std::chrono_literals;

FunctionLooper::FunctionLooper(
    std::shared_ptr<QuicEventBase> evb,
    folly::Function<void()>&& func,
    LooperType type)
    : evb_(std::move(evb)),
      func_(std::move(func)),
      type_(type),
      running_(false),
      inLoopBody_(false),
      fireLoopEarly_(false) {
  CHECK(func_);
}

void FunctionLooper::setPacingTimer(QuicTimer::SharedPtr pacingTimer) noexcept {
  pacingTimer_ = std::move(pacingTimer);
}

bool FunctionLooper::hasPacingTimer() const noexcept {
  return pacingTimer_ != nullptr;
}

void FunctionLooper::setPacingFunction(
    folly::Function<std::chrono::microseconds()>&& pacingFunc) {
  CHECK(pacingFunc);
  pacingFunc_ = std::move(pacingFunc);
}

void FunctionLooper::commonLoopBody() noexcept {
  inLoopBody_ = true;
  SCOPE_EXIT {
    inLoopBody_ = false;
  };
  auto hasBeenRunning = running_;
  func_();
  // callback could cause us to stop ourselves.
  // Someone could have also called run() in the callback.
  VLOG(10) << __func__ << ": " << type_ << " hasBeenRunning=" << hasBeenRunning
           << " running_=" << running_;
  if (!running_) {
    return;
  }
  if (!schedulePacingTimeout()) {
    evb_->runInLoop(this);
  }
}

bool FunctionLooper::schedulePacingTimeout() noexcept {
  if (pacingFunc_ && pacingTimer_ && !isTimerCallbackScheduled()) {
    auto timeUntilWrite = pacingFunc_();
    if (timeUntilWrite != 0us) {
      nextPacingTime_ = Clock::now() + timeUntilWrite;
      pacingTimer_->scheduleTimeout(this, timeUntilWrite);
      return true;
    }
  }
  return false;
}

void FunctionLooper::runLoopCallback() noexcept {
  folly::DelayedDestruction::DestructorGuard dg(this);
  commonLoopBody();
}

void FunctionLooper::run(bool thisIteration) noexcept {
  VLOG(10) << __func__ << ": " << type_;
  running_ = true;
  // Caller can call run() in func_. But if we are in pacing mode, we should
  // prevent such loop.
  if (pacingTimer_ && inLoopBody_) {
    VLOG(4) << __func__ << ": " << type_
            << " in loop body and using pacing - not rescheduling";
    return;
  }
  if (isLoopCallbackScheduled() ||
      (!fireLoopEarly_ && pacingTimer_ && isTimerCallbackScheduled())) {
    VLOG(10) << __func__ << ": " << type_ << " already scheduled";
    return;
  }
  // If we are pacing, we're about to write again, if it's close, just write
  // now.
  if (pacingTimer_ && isTimerCallbackScheduled()) {
    auto n = Clock::now();
    auto timeUntilWrite = nextPacingTime_ < n
        ? 0us
        : std::chrono::duration_cast<std::chrono::milliseconds>(
              nextPacingTime_ - n);
    if (timeUntilWrite <= 1ms) {
      cancelTimerCallback();
      // The next loop is good enough
      thisIteration = false;
    } else {
      return;
    }
  }
  evb_->runInLoop(this, thisIteration);
}

void FunctionLooper::stop() noexcept {
  VLOG(10) << __func__ << ": " << type_;
  running_ = false;
  if (evb_) {
    cancelLoopCallback();
  }
  if (pacingTimer_) {
    cancelTimerCallback();
  }
}

bool FunctionLooper::isRunning() const {
  return running_;
}

bool FunctionLooper::isPacingScheduled() {
  return pacingTimer_ && isTimerCallbackScheduled();
}

bool FunctionLooper::isLoopCallbackScheduled() {
  return QuicEventBaseLoopCallback::isLoopCallbackScheduled();
}

void FunctionLooper::attachEventBase(std::shared_ptr<QuicEventBase> evb) {
  VLOG(10) << __func__ << ": " << type_;
  DCHECK(!evb_);
  DCHECK(evb && evb->isInEventBaseThread());
  evb_ = std::move(evb);
}

void FunctionLooper::detachEventBase() {
  VLOG(10) << __func__ << ": " << type_;
  DCHECK(evb_ && evb_->isInEventBaseThread());
  stop();
  if (pacingTimer_) {
    cancelTimerCallback();
  }
  evb_ = nullptr;
}

void FunctionLooper::timeoutExpired() noexcept {
  folly::DelayedDestruction::DestructorGuard dg(this);
  commonLoopBody();
}

void FunctionLooper::callbackCanceled() noexcept {
  return;
}

OptionalMicros FunctionLooper::getTimerTickInterval() noexcept {
  if (pacingTimer_) {
    return pacingTimer_->getTickInterval();
  }
  return std::nullopt;
}

std::ostream& operator<<(std::ostream& out, const LooperType& rhs) {
  switch (rhs) {
    case LooperType::ReadLooper:
      out << "ReadLooper";
      break;
    case LooperType::PeekLooper:
      out << "PeekLooper";
      break;
    case LooperType::WriteLooper:
      out << "WriteLooper";
      break;
    default:
      out << "unknown";
      break;
  }
  return out;
}
} // namespace quic
