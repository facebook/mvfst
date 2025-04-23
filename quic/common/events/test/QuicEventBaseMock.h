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
  void runInLoop(QuicEventBaseLoopCallback* cb, bool thisIteration) override {
    runInLoopWithCbPtr(cb, thisIteration);
  }

  MOCK_METHOD((void), runInLoopWithCbPtr, (QuicEventBaseLoopCallback*, bool));
  MOCK_METHOD((void), runInLoop, (folly::Function<void()>, bool));
  MOCK_METHOD((void), runAfterDelay, (std::function<void()>, uint32_t));
  MOCK_METHOD(
      (void),
      runInEventBaseThreadAndWait,
      (std::function<void()>),
      (noexcept));
  MOCK_METHOD(
      (void),
      runImmediatelyOrRunInEventBaseThreadAndWait,
      (std::function<void()>),
      (noexcept));
  MOCK_METHOD(
      (void),
      runInEventBaseThread,
      (std::function<void()>),
      (noexcept));
  MOCK_METHOD(
      (void),
      runImmediatelyOrRunInEventBaseThread,
      (std::function<void()>),
      (noexcept));

  bool isInEventBaseThread() const override {
    return true;
  }

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
