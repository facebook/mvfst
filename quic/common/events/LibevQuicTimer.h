/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#pragma once

#include <quic/common/events/QuicEventBase.h>
#include <quic/common/events/QuicTimer.h>

#include <ev.h>

namespace quic {

class LibevQuicTimer : public QuicTimer,
                       public QuicTimerCallback::TimerCallbackImpl {
 public:
  explicit LibevQuicTimer(struct ev_loop* libevLoop, bool selfOwned = false);
  ~LibevQuicTimer() override;

  void scheduleTimeout(
      QuicTimerCallback* callback,
      std::chrono::microseconds timeout) override;

  bool isTimerCallbackScheduled(QuicTimerCallback* callback) const override;

  void cancelTimeout(QuicTimerCallback* callback) override;

  [[nodiscard]] std::chrono::microseconds getTickInterval() const override {
    LOG(WARNING) << __func__ << " is not implemented in LibevQuicTimer";
    return std::chrono::microseconds(0);
  }

  void timeoutExpired() noexcept;

 private:
  struct ev_loop* ev_loop_{nullptr};
  ev_timer timeoutWatcher_;
  bool selfOwned_{false};

  QuicTimerCallback* callback_{nullptr};
};
} // namespace quic
