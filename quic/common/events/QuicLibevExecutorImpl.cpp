/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <quic/common/events/QuicLibevExecutorImpl.h>

namespace quic {

QuicLibevExecutorImpl::QuicLibevExecutorImpl(
    std::unique_ptr<LibevQuicEventBase::EvLoopWeak> loop)
    : LibevQuicEventBase(std::move(loop)) {}

void QuicLibevExecutorImpl::add(folly::Func func) {
  runInLoop(std::move(func).asStdFunction(), /*thisIteration=*/false);
}

void QuicLibevExecutorImpl::scheduleTimeout(
    QuicTimerCallback* callback,
    std::chrono::milliseconds timeout) {
  LibevQuicEventBase::scheduleTimeout(callback, timeout);
}

} // namespace quic
