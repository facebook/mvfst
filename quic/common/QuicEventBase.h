/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#pragma once

#ifdef MVFST_USE_LIBEV
#include <quic/common/QuicLibevEventBase.h>

#else
#include <folly/io/async/EventBase.h> // @manual
FOLLY_GNU_DISABLE_WARNING("-Wdeprecated-declarations")
#endif

#include <quic/common/QuicEventBaseInterface.h>
#include <functional>

namespace quic {

#ifdef MVFST_USE_LIBEV
using QuicBackingEventBase = QuicLibevEventBase;
using QuicTimerCallback = QuicTimer::Callback;
#else
using QuicEventBaseLoopCallback = folly::EventBase::LoopCallback;
using QuicBackingEventBase = folly::EventBase;
using QuicAsyncTimeout = folly::AsyncTimeout;
using QuicTimerCallback = folly::HHWheelTimer::Callback;
#endif

/**
 * This is a default event base implementation of QuicEventBaseInterface that
 * mvfst uses by default. It's using folly::EventBase as <QuicBackingEventBase>
 * implementation underneath.
 */
class QuicEventBase : public QuicEventBaseInterface<
                          QuicEventBaseLoopCallback,
                          QuicBackingEventBase,
                          QuicAsyncTimeout,
                          QuicTimerCallback> {
 public:
  QuicEventBase() = default;
  explicit QuicEventBase(QuicBackingEventBase* evb) : backingEvb_(evb) {}
  ~QuicEventBase() override = default;

  using LoopCallback = QuicEventBaseLoopCallback;

  void setBackingEventBase(QuicBackingEventBase* evb) override;

  [[nodiscard]] QuicBackingEventBase* getBackingEventBase() const override;

  void runInLoop(
      QuicEventBaseLoopCallback* callback,
      bool thisIteration = false) override;

  void runInLoop(folly::Function<void()> cb, bool thisIteration = false)
      override;

  void runAfterDelay(folly::Function<void()> cb, uint32_t milliseconds)
      override;

  void runInEventBaseThreadAndWait(
      folly::Function<void()> fn) noexcept override;

  [[nodiscard]] bool isInEventBaseThread() const override;

  bool scheduleTimeoutHighRes(
      QuicAsyncTimeout* obj,
      std::chrono::microseconds timeout) override;

  bool loopOnce(int flags = 0) override;

  bool loop() override;

  void loopForever() override;

  bool loopIgnoreKeepAlive() override;

  void terminateLoopSoon() override;

  void scheduleTimeout(
      QuicTimerCallback* callback,
      std::chrono::milliseconds timeout) override;

  [[nodiscard]] std::chrono::milliseconds getTimerTickInterval() const override;

 private:
  QuicBackingEventBase* backingEvb_{nullptr};
};

} // namespace quic
