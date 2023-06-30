/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#pragma once

#ifdef MVFST_USE_LIBEV
#include <ev.h>
#else
#include <folly/io/async/EventBase.h>
FOLLY_GNU_DISABLE_WARNING("-Wdeprecated-declarations")
#endif

#include <quic/common/QuicEventBaseInterface.h>
#include <functional>

namespace quic {

class QuicEventBase : public QuicEventBaseInterface<
                          folly::EventBase::LoopCallback,
                          folly::EventBase,
                          folly::AsyncTimeout,
                          folly::HHWheelTimer> {
 public:
  QuicEventBase() = default;
  explicit QuicEventBase(folly::EventBase* evb) : backingEvb_(evb) {}
  ~QuicEventBase() override = default;

  using LoopCallback = folly::EventBase::LoopCallback;

  void setBackingEventBase(folly::EventBase* evb) override;

  [[nodiscard]] folly::EventBase* getBackingEventBase() const override;

  void runInLoop(
      folly::EventBase::LoopCallback* callback,
      bool thisIteration = false) override;

  void runInLoop(std::function<void()> cb, bool thisIteration = false) override;

  void runAfterDelay(std::function<void()> cb, uint32_t milliseconds) override;

  void runInEventBaseThreadAndWait(std::function<void()> fn) noexcept override;

  [[nodiscard]] bool isInEventBaseThread() const override;

  bool scheduleTimeoutHighRes(
      folly::AsyncTimeout* obj,
      std::chrono::microseconds timeout) override;

  folly::HHWheelTimer& timer() override;

  bool loopOnce(int flags = 0) override;

  bool loop() override;

  void loopForever() override;

  bool loopIgnoreKeepAlive() override;

  void terminateLoopSoon() override;

 private:
  folly::EventBase* backingEvb_{nullptr};
};

} // namespace quic
