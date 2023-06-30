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

class QuicHHWheelTimer {
 public:
  QuicHHWheelTimer() = default;
};

class QuicBackingEventBase {
 public:
  QuicBackingEventBase() = default;

  void runInLoop(std::function<void()> /* cb */, bool /* thisIteration */) {}
  void runInLoop(
      QuicEventBaseLoopCallback* /* callback */,
      bool /* thisIteration */) {}
  void runAfterDelay(
      std::function<void()> /* cb */,
      uint32_t /* milliseconds */) {}
  void runInEventBaseThreadAndWait(std::function<void()> /* fn */) noexcept {}
  bool isInEventBaseThread() const {
    return false;
  }
  bool scheduleTimeoutHighRes(
      QuicAsyncTimeout* /* obj */,
      std::chrono::microseconds /* timeout */) {
    return false;
  }
  QuicHHWheelTimer& timer() {
    return timer_;
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

 private:
  QuicHHWheelTimer timer_;
};

} // namespace quic

#endif // MVFST_USE_LIBEV
