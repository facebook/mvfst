/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#pragma once

#include <folly/portability/GMock.h>
#include <quic/common/events/QuicEventBase.h>

namespace quic::test {

class QuicEventBaseMock : public QuicEventBase {
 public:
  MOCK_METHOD((void), runInLoop, (QuicEventBaseLoopCallback*, bool));
  MOCK_METHOD((void), runInLoop, (folly::Function<void()>, bool));
  MOCK_METHOD((void), runAfterDelay, (folly::Function<void()>, uint32_t));
  MOCK_METHOD(
      (void),
      runInEventBaseThreadAndWait,
      (folly::Function<void()>),
      (noexcept));
  MOCK_METHOD(
      (void),
      runImmediatelyOrRunInEventBaseThreadAndWait,
      (folly::Function<void()>),
      (noexcept));
  MOCK_METHOD(
      (void),
      runInEventBaseThread,
      (folly::Function<void()>),
      (noexcept));
  MOCK_METHOD((bool), isInEventBaseThread, (), (const));
  MOCK_METHOD(
      (void),
      scheduleTimeout,
      (QuicTimerCallback*, std::chrono::milliseconds));
  MOCK_METHOD(
      (bool),
      scheduleTimeoutHighRes,
      (QuicTimerCallback*, std::chrono::microseconds));
  MOCK_METHOD((bool), loopOnce, (int));
  MOCK_METHOD((bool), loop, ());
  MOCK_METHOD((void), loopForever, ());
  MOCK_METHOD((bool), loopIgnoreKeepAlive, ());
  MOCK_METHOD((void), terminateLoopSoon, ());
  MOCK_METHOD((std::chrono::milliseconds), getTimerTickInterval, (), (const));
};

} // namespace quic::test
