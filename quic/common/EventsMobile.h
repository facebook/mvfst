/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#pragma once

#ifdef MVFST_USE_LIBEV

#include <ev.h>

#include <quic/common/QuicEventBaseInterface.h>
#include <functional>

namespace quic {

class QuicEventBaseLoopCallback {
 public:
  virtual ~QuicEventBaseLoopCallback() = default;
  virtual void runLoopCallback() noexcept = 0;
};

class QuicAsyncTimeout {
 public:
  QuicAsyncTimeout() = default;
};

class QuicTimerCallback {
 public:
  virtual ~QuicTimerCallback() = default;
  virtual void timeoutExpired() noexcept = 0;
  virtual void callbackCanceled() noexcept {
    timeoutExpired();
  }
  bool isScheduled() const {
    return false;
  }

  void cancelTimeout() {}
};

class QuicBackingEventBase {
 public:
  QuicBackingEventBase() = default;

  void runInLoop(folly::Function<void()> /* cb */, bool /* thisIteration */) {}
  void runInLoop(
      QuicEventBaseLoopCallback* /* callback */,
      bool /* thisIteration */) {}
  void runAfterDelay(
      folly::Function<void()> /* cb */,
      uint32_t /* milliseconds */) {}
  void runInEventBaseThreadAndWait(folly::Function<void()> /* fn */) noexcept {}
  bool isInEventBaseThread() const {
    return false;
  }
  bool scheduleTimeoutHighRes(
      QuicAsyncTimeout* /* obj */,
      std::chrono::microseconds /* timeout */) {
    return false;
  }
  bool loopOnce(int /* flags */) {
    return false;
  }
  bool loop() {
    return false;
  }
  void loopForever() {}
  bool loopIgnoreKeepAlive() {
    return false;
  }
  void terminateLoopSoon() {}

  void scheduleTimeout(
      QuicTimerCallback* /* callback */,
      std::chrono::milliseconds /* timeout */) {}

  std::chrono::milliseconds getTimerTickInterval() const {
    return std::chrono::milliseconds(0);
  }

 private:
  QuicHHWheelTimer timer_;
};

} // namespace quic

#endif // MVFST_USE_LIBEV
