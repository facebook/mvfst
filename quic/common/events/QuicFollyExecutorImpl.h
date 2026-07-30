/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#pragma once

#include <folly/io/async/EventBase.h>
#include <quic/common/events/FollyQuicEventBase.h>
#include <quic/common/events/QuicExecutor.h>

namespace quic {

class QuicFollyExecutorImpl : public QuicExecutor, public FollyQuicEventBase {
 public:
  explicit QuicFollyExecutorImpl(folly::EventBase* evb)
      : FollyQuicEventBase(evb) {}

  void add(folly::Func func) override;

  void scheduleTimeout(
      QuicTimerCallback* callback,
      std::chrono::milliseconds timeout) override;

  folly::Executor::KeepAlive<> getKeepAlive() override;
};

} // namespace quic
