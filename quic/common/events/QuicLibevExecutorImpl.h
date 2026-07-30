/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#pragma once

#include <memory>

#include <folly/IntrusiveList.h>
#include <quic/common/events/LibevQuicEventBase.h>
#include <quic/common/events/QuicExecutor.h>

namespace quic {

class QuicLibevExecutorImpl : public QuicExecutor, public LibevQuicEventBase {
 public:
  explicit QuicLibevExecutorImpl(
      std::unique_ptr<LibevQuicEventBase::EvLoopWeak> loop);

  void add(folly::Func func) override;

  void scheduleTimeout(
      QuicTimerCallback* callback,
      std::chrono::milliseconds timeout) override;
};

} // namespace quic
