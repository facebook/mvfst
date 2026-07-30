/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <quic/common/events/QuicFollyExecutorImpl.h>

namespace quic {

void QuicFollyExecutorImpl::add(folly::Func func) {
  getBackingEventBase()->add(std::move(func));
}

void QuicFollyExecutorImpl::scheduleTimeout(
    QuicTimerCallback* callback,
    std::chrono::milliseconds timeout) {
  FollyQuicEventBase::scheduleTimeout(callback, timeout);
}

folly::Executor::KeepAlive<> QuicFollyExecutorImpl::getKeepAlive() {
  return folly::getKeepAliveToken(getBackingEventBase());
}

} // namespace quic
