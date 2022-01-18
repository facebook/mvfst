/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <quic/common/FunctionLooper.h>

#include <folly/ScopeGuard.h>

namespace quic {
using namespace std::chrono_literals;

FunctionLooper::FunctionLooper(
    folly::EventBase* evb,
    folly::Function<void(bool)>&& func,
    LooperType type)
    : evb_(evb), func_(std::move(func)), type_(type) {}

void FunctionLooper::setPacingTimer(
    TimerHighRes::SharedPtr pacingTimer) noexcept {
  pacingTimer_ = std::move(pacingTimer);
}

bool FunctionLooper::hasPacingTimer() const noexcept {
  return pacingTimer_ != nullptr;
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
  auto hasBeenRunning = running_;
  func_(fromTimer);
  // callback could cause us to stop ourselves.
  // Someone could have also called run() in the callback.
  VLOG(10) << __func__ << ": " << type_ << " fromTimer=" << fromTimer
           << " hasBeenRunning=" << hasBeenRunning << " running_=" << running_;
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
    if (nextPacingTime != 0us) {
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
  VLOG(10) << __func__ << ": " << type_;
  running_ = true;
  // Caller can call run() in func_. But if we are in pacing mode, we should
  // prevent such loop.
  if (pacingTimer_ && inLoopBody_) {
    VLOG(4) << __func__ << ": " << type_
            << " in loop body and using pacing - not rescheduling";
    return;
  }
  if (isLoopCallbackScheduled() || isScheduled()) {
    VLOG(10) << __func__ << ": " << type_ << " already scheduled";
    return;
  }
  evb_->runInLoop(this, thisIteration);
}

void FunctionLooper::stop() noexcept {
  VLOG(10) << __func__ << ": " << type_;
  running_ = false;
  cancelLoopCallback();
  cancelTimeout();
}

bool FunctionLooper::isRunning() const {
  return running_;
}

void FunctionLooper::attachEventBase(folly::EventBase* evb) {
  VLOG(10) << __func__ << ": " << type_;
  DCHECK(!evb_);
  DCHECK(evb && evb->isInEventBaseThread());
  evb_ = evb;
}

void FunctionLooper::detachEventBase() {
  VLOG(10) << __func__ << ": " << type_;
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
