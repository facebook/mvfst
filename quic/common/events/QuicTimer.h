/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#pragma once

#include <quic/common/events/QuicEventBase.h>

#include <folly/io/async/DelayedDestruction.h>

namespace quic {

class QuicTimer : public folly::DelayedDestruction {
 public:
  using UniquePtr = std::unique_ptr<QuicTimer, Destructor>;
  using SharedPtr = std::shared_ptr<QuicTimer>;
  using Callback = QuicTimerCallback;

  ~QuicTimer() override = default;

  [[nodiscard]] virtual std::chrono::microseconds getTickInterval() const = 0;

  virtual void scheduleTimeout(
      QuicTimerCallback* callback,
      std::chrono::microseconds timeout) = 0;
};

} // namespace quic
