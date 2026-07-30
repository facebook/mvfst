/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#pragma once

#include <chrono>
#include <type_traits>

#include <folly/Executor.h>
#include <quic/common/events/QuicEventBase.h>

namespace quic {

class QuicExecutor : public folly::Executor {
 public:
  ~QuicExecutor() override = default;

  template <typename T>
    requires std::is_base_of_v<QuicExecutor, T>
  T* getTypedExecutor() {
    auto exec = dynamic_cast<T*>(this);
    if (exec) {
      return exec;
    } else {
      return nullptr;
    }
  }

  virtual void scheduleTimeout(
      QuicTimerCallback* callback,
      std::chrono::milliseconds timeout) = 0;

  // The default is a non-owning token because Executor::keepAliveAcquire()
  // returns false. Backends with a stronger lifetime primitive can override it.
  virtual folly::Executor::KeepAlive<> getKeepAlive() {
    return folly::getKeepAliveToken(static_cast<folly::Executor*>(this));
  }
};

} // namespace quic
