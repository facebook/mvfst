/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#pragma once

#include <quic/common/events/LibevQuicTimer.h>
#include <quic/common/events/QuicEventBase.h>

#include <ev.h>
#include <chrono>
#include <functional>
#include <memory>
#include <thread>
#include <vector>

#include <folly/GLog.h>

namespace quic {
/*
 * This is a partial implementation of a QuicEventBase that uses libev.
 * (It is copied from the previous interface in
 * quic/common/QuicLibevEventBase.h)
 */
class LibevQuicEventBase : public QuicEventBase {
 public:
  explicit LibevQuicEventBase(struct ev_loop* loop);
  ~LibevQuicEventBase() override;

  void runInLoop(
      QuicEventBaseLoopCallback* callback,
      bool thisIteration = false) override;

  void runInLoop(folly::Function<void()> cb, bool thisIteration = false)
      override;

  void runInEventBaseThreadAndWait(
      folly::Function<void()> fn) noexcept override;

  bool isInEventBaseThread() const override;

  void cancelLoopCallback(QuicEventBaseLoopCallback* /*callback*/) override;

  bool isLoopCallbackScheduled(
      QuicEventBaseLoopCallback* /*callback*/) const override;

  void scheduleTimeout(
      QuicTimerCallback* callback,
      std::chrono::milliseconds timeout) override;

  bool isTimeoutScheduled(QuicTimerCallback* callback) const override;

  void cancelTimeout(QuicTimerCallback* callback) override;

  bool loop() override {
    return ev_run(ev_loop_, 0);
  }

  bool loopIgnoreKeepAlive() override {
    return false;
  }

  void runInEventBaseThread(folly::Function<void()> /*fn*/) noexcept override {
    LOG(FATAL) << __func__ << " not supported in LibevQuicEventBase";
  }

  void runImmediatelyOrRunInEventBaseThreadAndWait(
      folly::Function<void()> /*fn*/) noexcept override {
    LOG(FATAL) << __func__ << " not supported in LibevQuicEventBase";
  }

  bool scheduleTimeoutHighRes(
      QuicTimerCallback* /*callback*/,
      std::chrono::microseconds /*timeout*/) override {
    LOG(FATAL) << __func__ << " not supported in LibevQuicEventBase";
    return false;
  }

  void runAfterDelay(folly::Function<void()> /*cb*/, uint32_t /*milliseconds*/)
      override {
    LOG(FATAL) << __func__ << " not supported in LibevQuicEventBase";
  }

  bool loopOnce(int /*flags*/) override {
    LOG(FATAL) << __func__ << " not supported in LibevQuicEventBase";
  }

  void loopForever() override {
    LOG(FATAL) << __func__ << " not supported in LibevQuicEventBase";
  }

  void terminateLoopSoon() override {
    LOG(WARNING) << __func__ << " is not implemented in LibevQuicEventBase";
  }

  [[nodiscard]] std::chrono::milliseconds getTimerTickInterval()
      const override {
    LOG(WARNING) << __func__ << " is not implemented in LibevQuicEventBase";
    return std::chrono::milliseconds(0);
  }

  std::chrono::milliseconds getTimeoutTimeRemaining(
      QuicTimerCallback* /*callback*/) const override {
    LOG(FATAL) << __func__ << " not supported in LibevQuicEventBase";
  }

  struct ev_loop* getLibevLoop() {
    return ev_loop_;
  }

  void checkCallbacks();

  void timeoutExpired(QuicTimerCallback* callback);

 private:
  struct ev_loop* ev_loop_{EV_DEFAULT};

  // TODO: use an intrusive list instead of a vector for loopCallbacks_
  std::vector<QuicEventBaseLoopCallback*> loopCallbacks_;
  ev_check checkWatcher_;
  std::atomic<std::thread::id> loopThreadId_;
};
} // namespace quic
