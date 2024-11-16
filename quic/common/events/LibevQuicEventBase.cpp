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

void libEvPrepareCallback(
    struct ev_loop* /* loop */,
    ev_prepare* w,
    int /* revents */) {
  auto self = static_cast<quic::LibevQuicEventBase*>(w->data);
  CHECK(self != nullptr);
  self->checkCallbacks();
}

} // namespace

namespace quic {
LibevQuicEventBase::LibevQuicEventBase(std::unique_ptr<EvLoopWeak> loop)
    : ev_loop_(loop->get()), loopWeak_(std::move(loop)) {
  loopThreadId_.store(std::this_thread::get_id(), std::memory_order_release);
  ev_prepare_init(&prepareWatcher_, libEvPrepareCallback);
  prepareWatcher_.data = this;
  ev_prepare_start(ev_loop_, &prepareWatcher_);
}

LibevQuicEventBase::~LibevQuicEventBase() {
  // If the loop has been destroyed, skip the ev loop operations.
  if (loopWeak_->get()) {
    ev_prepare_stop(ev_loop_, &prepareWatcher_);
  }

  struct FunctionLoopCallbackDisposer {
    void operator()(FunctionLoopCallback* callback) {
      delete callback;
    }
  };

  functionLoopCallbacks_.clear_and_dispose(FunctionLoopCallbackDisposer());
}

void LibevQuicEventBase::runInLoop(
    folly::Function<void()> cb,
    bool thisIteration) {
  CHECK(isInEventBaseThread());
  auto wrapper = new FunctionLoopCallback(std::move(cb));
  functionLoopCallbacks_.push_back(*wrapper);
  runInLoop(wrapper, thisIteration);
}

void LibevQuicEventBase::runInLoop(
    QuicEventBaseLoopCallback* callback,
    bool thisIteration) {
  CHECK(isInEventBaseThread());
  auto wrapper = static_cast<LoopCallbackWrapper*>(getImplHandle(callback));
  if (!wrapper) {
    wrapper = new LoopCallbackWrapper(callback);
    QuicEventBase::setImplHandle(callback, wrapper);
  }
  if (!wrapper->listHook_.is_linked()) {
    if (runOnceCallbackWrappers_ != nullptr && thisIteration) {
      runOnceCallbackWrappers_->push_back(*wrapper);
    } else {
      loopCallbackWrappers_.push_back(*wrapper);
    }
  }
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

void LibevQuicEventBase::scheduleLibevTimeoutImpl(
    QuicTimerCallback* timerCallback,
    std::chrono::microseconds timeout) {
  double seconds = std::chrono::duration<double>(timeout).count();
  auto wrapper =
      static_cast<TimerCallbackWrapper*>(getImplHandle(timerCallback));
  if (wrapper == nullptr) {
    // This is the first time this timer callback is getting scheduled. Create
    // a wrapper for it.
    wrapper = new TimerCallbackWrapper(timerCallback, ev_loop_);
    wrapper->ev_timer_.data = wrapper;
    ev_timer_init(
        &wrapper->ev_timer_,
        libEvTimeoutCallback,
        seconds /* after */,
        0. /* repeat */);
    if (prioritizeTimers_) {
      ev_set_priority(&wrapper->ev_timer_, EV_MAXPRI);
    }
    setImplHandle(timerCallback, wrapper);
  } else {
    // We already have a wrapper. Just re-arm it.
    ev_timer_set(&wrapper->ev_timer_, seconds /* after */, 0. /* repeat */);
  }

  ev_timer_start(ev_loop_, &wrapper->ev_timer_);
}

void LibevQuicEventBase::scheduleTimerFDTimeoutImpl(
    QuicTimerCallback* timerCallback,
    std::chrono::microseconds timeout) {
#if defined(HAS_TIMERFD)
  auto wrapper =
      static_cast<TimerCallbackWrapperTimerFD*>(getImplHandle(timerCallback));
  if (wrapper == nullptr) {
    // This is the first time this timer callback is getting scheduled. Create
    // a wrapper for it.
    wrapper = new TimerCallbackWrapperTimerFD(
        timerCallback, ev_loop_, prioritizeTimers_);
    wrapper->ev_io_watcher_.data = wrapper;
    setImplHandle(timerCallback, wrapper);
  }
  // libev by default bases the timeout on ev_now() which is the time when
  // poll returned for the current set of events. To have parity with this we
  // have to subtract the time between now (ev_time()) and then.
  auto timeElapsed = ev_time() - ev_now(ev_loop_);
  auto timeElapsedMicros =
      std::chrono::microseconds(static_cast<int64_t>(timeElapsed * 1e6));
  auto adjustedTimeout = timeout - timeElapsedMicros;
  if (adjustedTimeout <= std::chrono::microseconds(0)) {
    // The timeout is already passed. Feed an event for it.
    ev_io_start(ev_loop_, &wrapper->ev_io_watcher_);
    ev_feed_event(ev_loop_, &wrapper->ev_io_watcher_, EV_READ);
    return;
  }
  struct itimerspec new_value;
  new_value.it_value.tv_sec = adjustedTimeout.count() / 1000000;
  new_value.it_value.tv_nsec = (adjustedTimeout.count() % 1000000) * 1000;
  new_value.it_interval.tv_sec = 0; // No repeating
  new_value.it_interval.tv_nsec = 0;
  if (timerfd_settime(wrapper->ev_io_watcher_.fd, 0, &new_value, nullptr) ==
      -1) {
    LOG(FATAL) << "Failed to set timerfd time";
  }
  ev_io_start(ev_loop_, &wrapper->ev_io_watcher_);

#else
  LOG(FATAL) << "TimerFD not supported on this platform";
#endif
}

void LibevQuicEventBase::scheduleTimeout(
    QuicTimerCallback* timerCallback,
    std::chrono::microseconds timeout) {
  if (!timerCallback) {
    // There is no callback. Nothing to schedule.
    return;
  }
  if (useTimerFd_) {
    scheduleTimerFDTimeoutImpl(timerCallback, timeout);
  } else {
    scheduleLibevTimeoutImpl(timerCallback, timeout);
  }
}

void LibevQuicEventBase::checkCallbacks() {
  // Keep the event base alive while we are running the callbacks.
  auto self = this->shared_from_this();

  // Running the callbacks in the loop callback list may change the contents
  // of the list. We swap the list here to be able to differentiate between
  // adding callbacks to the current loop and the next one.
  folly::IntrusiveList<LoopCallbackWrapper, &LoopCallbackWrapper::listHook_>
      currentLoopWrappers;
  loopCallbackWrappers_.swap(currentLoopWrappers);

  // We keep a pointer to the list of callbacks we are currently handling. This
  // is where callbacks for thisIteration would be added.
  runOnceCallbackWrappers_ = &currentLoopWrappers;
  while (!currentLoopWrappers.empty()) {
    // runLoopCallback first unlinks the callback wrapper from the list.
    // This allows the callback to schedule itself again in the same loop or the
    // next one.
    currentLoopWrappers.front().runLoopCallback();
  }
  runOnceCallbackWrappers_ = nullptr;
}

bool LibevQuicEventBase::isInEventBaseThread() const {
  auto tid = loopThreadId_.load(std::memory_order_relaxed);
  return tid == std::this_thread::get_id();
}
} // namespace quic
