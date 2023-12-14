/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <quic/common/events/LibevQuicTimer.h>

namespace {
void libEvTimeoutCallback(
    struct ev_loop* /* loop */,
    ev_timer* w,
    int /* revents */) {
  auto quicTimer = static_cast<quic::LibevQuicTimer*>(w->data);
  CHECK(quicTimer != nullptr);
  quicTimer->timeoutExpired();
}
} // namespace

namespace quic {
LibevQuicTimer::LibevQuicTimer(struct ev_loop* libevLoop, bool selfOwned) {
  CHECK(libevLoop != nullptr);
  ev_loop_ = libevLoop;
  selfOwned_ = selfOwned;
  timeoutWatcher_.data = this;
}

LibevQuicTimer::~LibevQuicTimer() {
  ev_timer_stop(ev_loop_, &timeoutWatcher_);
  callback_ = nullptr;
}

void LibevQuicTimer::scheduleTimeout(
    QuicTimerCallback* callback,
    std::chrono::microseconds timeout) {
  CHECK(!callback_)
      << "Another callback is already scheduled on this QuicTimer";
  callback_ = callback;
  QuicEventBase::setImplHandle(callback_, this);

  double seconds = timeout.count() / 10000.;
  ev_timer_init(
      &timeoutWatcher_,
      libEvTimeoutCallback,
      seconds /* after */,
      0. /* repeat */);
  ev_timer_start(ev_loop_, &timeoutWatcher_);
}

bool LibevQuicTimer::isTimerCallbackScheduled(
    QuicTimerCallback* callback) const {
  return callback == callback_;
}

void LibevQuicTimer::cancelTimeout(QuicTimerCallback* callback) {
  CHECK_EQ(callback_, callback);
  QuicEventBase::setImplHandle(callback_, nullptr);
  ev_timer_stop(ev_loop_, &timeoutWatcher_);
  callback_ = nullptr;
  if (selfOwned_) {
    delete this;
  }
}

void LibevQuicTimer::timeoutExpired() noexcept {
  CHECK(callback_);
  QuicEventBase::setImplHandle(callback_, nullptr);
  callback_->timeoutExpired();
  ev_timer_stop(ev_loop_, &timeoutWatcher_);
  callback_ = nullptr;
  if (selfOwned_) {
    delete this;
  }
}
} // namespace quic
