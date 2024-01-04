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

void libEvTimeoutCallback(
    struct ev_loop* /* loop */,
    ev_timer* w,
    int /* revents */) {
  auto wrapper =
      static_cast<quic::LibevQuicEventBase::TimerCallbackWrapper*>(w->data);
  CHECK(wrapper != nullptr);
  wrapper->timeoutExpired();
}

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
  auto wrapper = static_cast<LoopCallbackWrapper*>(getImplHandle(callback));
  if (!wrapper) {
    wrapper = new LoopCallbackWrapper(callback);
    QuicEventBase::setImplHandle(callback, wrapper);
  }
  if (!wrapper->listHook_.is_linked()) {
    loopCallbackWrappers_.push_back(*wrapper);
  }
}

void LibevQuicEventBase::runInEventBaseThreadAndWait(
    folly::Function<void()> fn) noexcept {
  fn();
}

void LibevQuicEventBase::scheduleTimeout(
    QuicTimerCallback* timerCallback,
    std::chrono::milliseconds timeout) {
  scheduleTimeout(
      timerCallback,
      std::chrono::duration_cast<std::chrono::microseconds>(timeout));
}

bool LibevQuicEventBase::scheduleTimeoutHighRes(
    QuicTimerCallback* timerCallback,
    std::chrono::microseconds timeout) {
  scheduleTimeout(timerCallback, timeout);
  return true;
}

void LibevQuicEventBase::scheduleTimeout(
    QuicTimerCallback* timerCallback,
    std::chrono::microseconds timeout) {
  if (!timerCallback) {
    // There is no callback. Nothing to schedule.
    return;
  }
  double seconds = timeout.count() / 1000.;
  auto wrapper =
      static_cast<TimerCallbackWrapper*>(getImplHandle(timerCallback));
  if (wrapper == nullptr) {
    // This is the first time this timer callback is getting scheduled. Create a
    // wrapper for it.
    wrapper = new TimerCallbackWrapper(timerCallback, ev_loop_);
    wrapper->ev_timer_.data = wrapper;
    ev_timer_init(
        &wrapper->ev_timer_,
        libEvTimeoutCallback,
        seconds /* after */,
        0. /* repeat */);
    setImplHandle(timerCallback, wrapper);
  } else {
    // We already have a wrapper. Just re-arm it.
    ev_timer_set(&wrapper->ev_timer_, seconds /* after */, 0. /* repeat */);
  }

  ev_timer_start(ev_loop_, &wrapper->ev_timer_);
}

void LibevQuicEventBase::checkCallbacks() {
  // Running the callbacks in the loop callback list may change the contents of
  // the list or completely delete the list (with the event base). We swap the
  // list here to ensure the list survives until the end of the function.
  folly::IntrusiveList<LoopCallbackWrapper, &LoopCallbackWrapper::listHook_>
      currentLoopWrappers;
  loopCallbackWrappers_.swap(currentLoopWrappers);
  while (!currentLoopWrappers.empty()) {
    // runLoopCallback first unlinks the callback wrapper from the list.
    // This allows the callback to schedule itself again on the swapped list.
    currentLoopWrappers.front().runLoopCallback();
  }
}

bool LibevQuicEventBase::isInEventBaseThread() const {
  auto tid = loopThreadId_.load(std::memory_order_relaxed);
  return tid == std::this_thread::get_id();
}
} // namespace quic
