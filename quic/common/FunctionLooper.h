/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#pragma once
#include <ostream>

#include <folly/Function.h>
#include <folly/io/async/DelayedDestruction.h>
#include <quic/QuicConstants.h>
#include <quic/common/Optional.h>
#include <quic/common/events/QuicEventBase.h>
#include <quic/common/events/QuicTimer.h>

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
class FunctionLooper : public QuicEventBaseLoopCallback,
                       public QuicTimerCallback,
                       public folly::DelayedDestruction {
 public:
  using Ptr =
      std::unique_ptr<FunctionLooper, folly::DelayedDestruction::Destructor>;

  explicit FunctionLooper(
      std::shared_ptr<QuicEventBase> evb,
      folly::Function<void()>&& func,
      LooperType type);

  void setPacingTimer(QuicTimer::SharedPtr pacingTimer) noexcept;

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
   * Whether the pacing timer is scheduled or not. This is not thread-safe and
   * should only be called on the looper's evb.
   */
  bool isPacingScheduled();

  /**
   * Whether the loop callback is scheduled or not. This is not thread-safe and
   * should only be called on the looper's evb.
   */
  bool isLoopCallbackScheduled();

  /**
   * Attaches a new event base to the function looper. Must be invoked on the
   * evb that the looper is to be attached to.
   */
  void attachEventBase(std::shared_ptr<QuicEventBase> evb);

  /**
   * Detaches the current event base from the function looper. Must be called on
   * the current event base thread.
   */
  void detachEventBase();

  void timeoutExpired() noexcept override;

  void callbackCanceled() noexcept override;

  OptionalMicros getTimerTickInterval() noexcept;

  /*
   * Controls whether to fire a loop early when the pacing timer has been
   * missed or is scheduled to fire "soon" (within 1ms).
   */
  void setFireLoopEarly(bool val) {
    fireLoopEarly_ = val;
  }

 private:
  ~FunctionLooper() override = default;
  void commonLoopBody() noexcept;
  bool schedulePacingTimeout() noexcept;

  std::shared_ptr<QuicEventBase> evb_;
  folly::Function<void()> func_;
  folly::Function<std::chrono::microseconds()> pacingFunc_{nullptr};
  QuicTimer::SharedPtr pacingTimer_;
  TimePoint nextPacingTime_;
  const LooperType type_;
  struct {
    bool running_ : 1;
    bool inLoopBody_ : 1;
    bool fireLoopEarly_ : 1;
  };
};
} // namespace quic
