/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#pragma once

#include <folly/io/async/EventBase.h>
#include <functional>

FOLLY_GNU_DISABLE_WARNING("-Wdeprecated-declarations")

namespace quic {

class QuicEventBase {
 public:
  QuicEventBase() = default;
  explicit QuicEventBase(folly::EventBase* evb) : backingEvb_(evb) {}
  virtual ~QuicEventBase() = default;

  using LoopCallback = folly::EventBase::LoopCallback;

  void setBackingEventBase(folly::EventBase* evb);

  [[nodiscard]] folly::EventBase* getBackingEventBase() const;

  void runInLoop(LoopCallback* callback, bool thisIteration = false);

  void runInLoop(std::function<void()> cb, bool thisIteration = false);

  void runAfterDelay(std::function<void()> cb, uint32_t milliseconds);

  void runInEventBaseThreadAndWait(std::function<void()> fn) noexcept;

  [[nodiscard]] bool isInEventBaseThread() const;

  bool scheduleTimeoutHighRes(
      folly::AsyncTimeout* obj,
      std::chrono::microseconds timeout);

  folly::HHWheelTimer& timer();

  bool loopOnce(int flags = 0);

  bool loop();

  void loopForever();

  bool loopIgnoreKeepAlive();

  void terminateLoopSoon();

 private:
  folly::EventBase* backingEvb_{nullptr};
};

} // namespace quic
