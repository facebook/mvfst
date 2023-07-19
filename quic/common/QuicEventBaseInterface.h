/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#pragma once

#include <folly/Function.h>
#include <chrono>
#include <cstdint>

namespace quic {

/**
 * An interface mvfst expects from event base implementation.
 */
template <
    class LoopCallbackT,
    class BackingEventBaseT,
    class AsyncTimeoutT,
    class TimerCallbackT>
class QuicEventBaseInterface {
 public:
  virtual ~QuicEventBaseInterface() = default;

  virtual void setBackingEventBase(BackingEventBaseT* evb) = 0;
  virtual BackingEventBaseT* getBackingEventBase() const = 0;

  virtual void runInLoop(LoopCallbackT* callback, bool thisIteration) = 0;

  virtual void runInLoop(folly::Function<void()> cb, bool thisIteration) = 0;

  virtual void runAfterDelay(
      folly::Function<void()> cb,
      uint32_t milliseconds) = 0;

  virtual void runInEventBaseThreadAndWait(
      folly::Function<void()> fn) noexcept = 0;

  virtual bool isInEventBaseThread() const = 0;

  virtual bool scheduleTimeoutHighRes(
      AsyncTimeoutT* obj,
      std::chrono::microseconds timeout) = 0;

  virtual bool loopOnce(int flags) = 0;

  virtual bool loop() = 0;

  virtual void loopForever() = 0;

  virtual bool loopIgnoreKeepAlive() = 0;

  virtual void terminateLoopSoon() = 0;

  virtual void scheduleTimeout(
      TimerCallbackT* callback,
      std::chrono::milliseconds timeout) = 0;

  [[nodiscard]] virtual std::chrono::milliseconds getTimerTickInterval()
      const = 0;
};

} // namespace quic
