/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <quic/common/Timers.h>

#ifdef QUIC_USE_TIMERFD_TIMEOUT_MGR
namespace quic {
TimerFDTimerHighRes::TimerFDTimerHighRes(
    folly::EventBase* eventBase,
    std::chrono::microseconds intervalDuration)
    : timeoutMgr_(eventBase) {
  wheelTimer_ =
      folly::HHWheelTimerHighRes::newTimer(&timeoutMgr_, intervalDuration);
}

TimerFDTimerHighRes::~TimerFDTimerHighRes() {
  wheelTimer_.reset();
}
} // namespace quic
#endif
