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
  if (isInEventBaseThread()) {
    runInLoop(std::move(func).asStdFunction(), /*thisIteration=*/false);
  } else {
    runInEventBaseThread(std::move(func).asStdFunction());
  }
}

void QuicLibevExecutorImpl::scheduleTimeout(
    QuicTimerCallback* callback,
    std::chrono::milliseconds timeout) {
  LibevQuicEventBase::scheduleTimeout(callback, timeout);
}

} // namespace quic
