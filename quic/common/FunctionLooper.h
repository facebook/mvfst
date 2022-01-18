/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#pragma once
#include <ostream>

#include <folly/Function.h>
#include <folly/io/async/EventBase.h>
#include <quic/common/Timers.h>

namespace quic {
enum class LooperType : uint8_t {
  ReadLooper = 1,
  PeekLooper = 2,
  WriteLooper = 3
};

std::ostream& operator<<(std::ostream& /* out */, const LooperType& /*rhs*/);

/**
 * A loop callback that provides convenience functions for calling a functions
 * in multiple evb loops. Calling run() will cause the loop to start and stop()
 * will call the loop to stop.
 */
class FunctionLooper : public folly::EventBase::LoopCallback,
                       public folly::DelayedDestruction,
                       public TimerHighRes::Callback {
 public:
  using Ptr =
      std::unique_ptr<FunctionLooper, folly::DelayedDestruction::Destructor>;

  explicit FunctionLooper(
      folly::EventBase* evb,
      folly::Function<void(bool)>&& func,
      LooperType type);

  void setPacingTimer(TimerHighRes::SharedPtr pacingTimer) noexcept;

  bool hasPacingTimer() const noexcept;

  void runLoopCallback() noexcept override;

  /**
   * Starts running the loop callback in each loop iteration.
   * if this is already scheduled to run, run() will continue to run it.
   */
  void run(bool thisIteration = false) noexcept;

  void setPacingFunction(
      folly::Function<std::chrono::microseconds()>&& pacingFunc);

  /**
   * Stops running the loop in each loop iteration.
   */
  void stop() noexcept;

  /**
   * Whether the looper is running or not. This is not thread-safe and should
   * only be called on the looper's evb.
   */
  bool isRunning() const;

  /**
   * Attaches a new event base to the function looper. Must be invoked on the
   * evb that the looper is to be attached to.
   */
  void attachEventBase(folly::EventBase* evb);

  /**
   * Detaches the current event base from the function looper. Must be called on
   * the current event base thread.
   */
  void detachEventBase();

  void timeoutExpired() noexcept override;

  void callbackCanceled() noexcept override;

  folly::Optional<std::chrono::microseconds> getTimerTickInterval() noexcept;

 private:
  ~FunctionLooper() override = default;
  void commonLoopBody(bool fromTimer) noexcept;
  bool schedulePacingTimeout(bool fromTimer) noexcept;

  folly::EventBase* evb_;
  folly::Function<void(bool)> func_;
  folly::Optional<folly::Function<std::chrono::microseconds()>> pacingFunc_;
  TimerHighRes::SharedPtr pacingTimer_;
  bool running_{false};
  bool inLoopBody_{false};
  const LooperType type_;
};
} // namespace quic
