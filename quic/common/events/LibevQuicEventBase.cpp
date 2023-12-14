/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <quic/common/events/LibevQuicEventBase.h>
#include <chrono>
#include <memory>

namespace {

void libEvCheckCallback(
    struct ev_loop* /* loop */,
    ev_check* w,
    int /* revents */) {
  auto self = static_cast<quic::LibevQuicEventBase*>(w->data);
  CHECK(self != nullptr);
  self->checkCallbacks();
}
} // namespace

namespace quic {
LibevQuicEventBase::LibevQuicEventBase(struct ev_loop* loop) : ev_loop_(loop) {
  loopThreadId_.store(std::this_thread::get_id(), std::memory_order_release);
  ev_check_init(&checkWatcher_, libEvCheckCallback);
  checkWatcher_.data = this;
  ev_check_start(ev_loop_, &checkWatcher_);
}

LibevQuicEventBase::~LibevQuicEventBase() {
  ev_check_stop(ev_loop_, &checkWatcher_);
}

void LibevQuicEventBase::runInLoop(
    folly::Function<void()> cb,
    bool /* thisIteration */) {
  CHECK(isInEventBaseThread());
  cb();
}

void LibevQuicEventBase::runInLoop(
    QuicEventBaseLoopCallback* callback,
    bool /* thisIteration */) {
  CHECK(isInEventBaseThread());
  loopCallbacks_.push_back(callback);
}

void LibevQuicEventBase::runInEventBaseThreadAndWait(
    folly::Function<void()> fn) noexcept {
  fn();
}

void LibevQuicEventBase::cancelLoopCallback(
    QuicEventBaseLoopCallback* callback) {
  auto itr = std::find(loopCallbacks_.begin(), loopCallbacks_.end(), callback);
  if (itr != loopCallbacks_.end()) {
    loopCallbacks_.erase(itr);
  }
}

bool LibevQuicEventBase::isLoopCallbackScheduled(
    QuicEventBaseLoopCallback* callback) const {
  auto itr = std::find(loopCallbacks_.begin(), loopCallbacks_.end(), callback);
  return itr != loopCallbacks_.end();
}

void LibevQuicEventBase::scheduleTimeout(
    QuicTimerCallback* callback,
    std::chrono::milliseconds timeout) {
  CHECK(!isTimeoutScheduled(callback));

  auto evTimer = new LibevQuicTimer(ev_loop_, true /*selfOwned*/);

  evTimer->scheduleTimeout(
      callback, std::chrono::duration_cast<std::chrono::microseconds>(timeout));
  setImplHandle(callback, evTimer);
}

bool LibevQuicEventBase::isTimeoutScheduled(QuicTimerCallback* callback) const {
  auto evTimer = static_cast<LibevQuicTimer*>(getImplHandle(callback));
  return evTimer && evTimer->isTimerCallbackScheduled(callback);
}

void LibevQuicEventBase::cancelTimeout(QuicTimerCallback* callback) {
  auto evTimer = static_cast<LibevQuicTimer*>(getImplHandle(callback));
  if (evTimer) {
    evTimer->cancelTimeout(callback);
  }
}

void LibevQuicEventBase::checkCallbacks() {
  std::vector<QuicEventBaseLoopCallback*> callbacks;
  std::swap(callbacks, loopCallbacks_);
  for (auto cb : callbacks) {
    cb->runLoopCallback();
  }
}

bool LibevQuicEventBase::isInEventBaseThread() const {
  auto tid = loopThreadId_.load(std::memory_order_relaxed);
  return tid == std::this_thread::get_id();
}
} // namespace quic
