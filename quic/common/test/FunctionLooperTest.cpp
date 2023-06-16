/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <quic/common/FunctionLooper.h>

#include <gtest/gtest.h>

using namespace std;
using namespace folly;
using namespace testing;

namespace quic {
namespace test {

class FunctionLooperTest : public Test {};

TEST(FunctionLooperTest, LooperNotRunning) {
  EventBase backingEvb;
  QuicEventBase evb(&backingEvb);
  bool called = false;
  auto func = [&]() { called = true; };
  FunctionLooper::Ptr looper(
      new FunctionLooper(&evb, std::move(func), LooperType::ReadLooper));
  evb.loopOnce();
  EXPECT_FALSE(called);
  evb.loopOnce();
  EXPECT_FALSE(called);
  EXPECT_FALSE(looper->isRunning());
}

TEST(FunctionLooperTest, LooperStarted) {
  EventBase backingEvb;
  QuicEventBase evb(&backingEvb);
  bool called = false;
  auto func = [&]() { called = true; };
  FunctionLooper::Ptr looper(
      new FunctionLooper(&evb, std::move(func), LooperType::ReadLooper));
  looper->run();
  EXPECT_TRUE(looper->isRunning());
  evb.loopOnce();
  EXPECT_TRUE(called);
  called = false;
  evb.loopOnce();
  EXPECT_TRUE(called);
}

TEST(FunctionLooperTest, LooperStopped) {
  EventBase backingEvb;
  QuicEventBase evb(&backingEvb);
  bool called = false;
  auto func = [&]() { called = true; };
  FunctionLooper::Ptr looper(
      new FunctionLooper(&evb, std::move(func), LooperType::ReadLooper));
  looper->run();
  evb.loopOnce();
  EXPECT_TRUE(called);
  called = false;
  looper->stop();
  EXPECT_FALSE(looper->isRunning());
  evb.loopOnce();
  EXPECT_FALSE(called);
}

TEST(FunctionLooperTest, LooperRestarted) {
  EventBase backingEvb;
  QuicEventBase evb(&backingEvb);
  bool called = false;
  auto func = [&]() { called = true; };
  FunctionLooper::Ptr looper(
      new FunctionLooper(&evb, std::move(func), LooperType::ReadLooper));
  looper->run();
  evb.loopOnce();
  EXPECT_TRUE(called);
  called = false;
  looper->stop();
  evb.loopOnce();
  EXPECT_FALSE(called);
  looper->run();
  EXPECT_TRUE(looper->isRunning());
  evb.loopOnce();
  EXPECT_TRUE(called);
}

TEST(FunctionLooperTest, DestroyLooperDuringFunc) {
  EventBase backingEvb;
  QuicEventBase evb(&backingEvb);
  bool called = false;
  FunctionLooper::Ptr* looperPtr = nullptr;

  auto func = [&]() {
    called = true;
    *looperPtr = nullptr;
  };
  FunctionLooper::Ptr looper(
      new FunctionLooper(&evb, std::move(func), LooperType::ReadLooper));
  looperPtr = &looper;

  looper->run();
  evb.loopOnce();
  EXPECT_TRUE(called);
  EXPECT_EQ(looper, nullptr);
}

TEST(FunctionLooperTest, StopLooperDuringFunc) {
  EventBase backingEvb;
  QuicEventBase evb(&backingEvb);
  bool called = false;
  FunctionLooper::Ptr* looperPtr = nullptr;

  auto func = [&]() {
    called = true;
    (*looperPtr)->stop();
  };
  FunctionLooper::Ptr looper(
      new FunctionLooper(&evb, std::move(func), LooperType::ReadLooper));
  looperPtr = &looper;

  looper->run();
  evb.loopOnce();
  EXPECT_TRUE(called);
  called = false;
  evb.loopOnce();
  EXPECT_FALSE(called);
}

TEST(FunctionLooperTest, RunLooperDuringFunc) {
  EventBase backingEvb;
  QuicEventBase evb(&backingEvb);
  bool called = false;
  FunctionLooper::Ptr* looperPtr = nullptr;

  auto func = [&]() {
    called = true;
    (*looperPtr)->run();
  };
  FunctionLooper::Ptr looper(
      new FunctionLooper(&evb, std::move(func), LooperType::ReadLooper));
  looperPtr = &looper;

  looper->run();
  evb.loopOnce();
  EXPECT_TRUE(called);
  called = false;
  evb.loopOnce();
  EXPECT_TRUE(called);
}

TEST(FunctionLooperTest, DetachStopsLooper) {
  EventBase backingEvb;
  QuicEventBase evb(&backingEvb);
  bool called = false;
  auto func = [&]() { called = true; };
  FunctionLooper::Ptr looper(
      new FunctionLooper(&evb, std::move(func), LooperType::ReadLooper));
  looper->run();
  EXPECT_TRUE(looper->isRunning());
  looper->detachEventBase();
  EXPECT_FALSE(looper->isRunning());
  looper->attachEventBase(&evb);
  EXPECT_FALSE(looper->isRunning());
}

TEST(FunctionLooperTest, PacingOnce) {
  EventBase backingEvb;
  QuicEventBase evb(&backingEvb);
  TimerHighRes::SharedPtr pacingTimer(TimerHighRes::newTimer(&backingEvb, 1ms));
  int count = 0;
  auto func = [&]() { ++count; };
  bool firstTime = true;
  auto pacingFunc = [&]() -> auto {
    if (firstTime) {
      firstTime = false;
      return 3600000ms;
    }
    return std::chrono::milliseconds::zero();
  };
  FunctionLooper::Ptr looper(
      new FunctionLooper(&evb, std::move(func), LooperType::ReadLooper));
  looper->setPacingTimer(std::move(pacingTimer));
  looper->setPacingFunction(std::move(pacingFunc));
  looper->run();
  evb.loopOnce();
  EXPECT_EQ(1, count);
  EXPECT_TRUE(looper->isScheduled());
  looper->timeoutExpired();
  EXPECT_EQ(2, count);
  looper->stop();
}

TEST(FunctionLooperTest, KeepPacing) {
  EventBase backingEvb;
  QuicEventBase evb(&backingEvb);
  TimerHighRes::SharedPtr pacingTimer(
      TimerHighRes::newTimer(evb.getBackingEventBase(), 1ms));
  int count = 0;
  auto func = [&]() { ++count; };
  bool stopPacing = false;
  auto pacingFunc = [&]() -> auto {
    if (stopPacing) {
      return std::chrono::milliseconds::zero();
    }
    return 3600000ms;
  };
  FunctionLooper::Ptr looper(
      new FunctionLooper(&evb, std::move(func), LooperType::ReadLooper));
  looper->setPacingTimer(std::move(pacingTimer));
  looper->setPacingFunction(std::move(pacingFunc));
  looper->run();
  evb.loopOnce();
  EXPECT_EQ(1, count);
  EXPECT_TRUE(looper->isScheduled());

  looper->cancelTimeout();
  EXPECT_FALSE(looper->isScheduled());
  looper->timeoutExpired();
  EXPECT_EQ(2, count);
  EXPECT_TRUE(looper->isScheduled());

  looper->cancelTimeout();
  EXPECT_FALSE(looper->isScheduled());
  looper->timeoutExpired();
  EXPECT_EQ(3, count);
  EXPECT_TRUE(looper->isScheduled());

  stopPacing = true;
  looper->cancelTimeout();
  EXPECT_FALSE(looper->isScheduled());
  looper->timeoutExpired();
  EXPECT_EQ(4, count);
  EXPECT_FALSE(looper->isScheduled());

  looper->stop();
}

TEST(FunctionLooperTest, TimerTickSize) {
  EventBase backingEvb;
  QuicEventBase evb(&backingEvb);
  TimerHighRes::SharedPtr pacingTimer(
      TimerHighRes::newTimer(evb.getBackingEventBase(), 123ms));
  FunctionLooper::Ptr looper(new FunctionLooper(
      &evb, [&]() {}, LooperType::ReadLooper));
  looper->setPacingTimer(std::move(pacingTimer));
  EXPECT_EQ(123ms, looper->getTimerTickInterval());
}

TEST(FunctionLooperTest, TimerTickSizeAfterNewEvb) {
  EventBase backingEvb;
  QuicEventBase evb(&backingEvb);
  TimerHighRes::SharedPtr pacingTimer(
      TimerHighRes::newTimer(evb.getBackingEventBase(), 123ms));
  FunctionLooper::Ptr looper(new FunctionLooper(
      &evb, [&]() {}, LooperType::ReadLooper));
  looper->setPacingTimer(std::move(pacingTimer));
  EXPECT_EQ(123ms, looper->getTimerTickInterval());
  looper->detachEventBase();
  EventBase backingEvb2;
  QuicEventBase evb2(&backingEvb2);
  looper->attachEventBase(&evb2);
  EXPECT_EQ(123ms, looper->getTimerTickInterval());
}

TEST(FunctionLooperTest, NoLoopCallbackInPacingMode) {
  EventBase backingEvb;
  QuicEventBase evb(&backingEvb);
  TimerHighRes::SharedPtr pacingTimer(
      TimerHighRes::newTimer(evb.getBackingEventBase(), 1ms));
  auto runFunc = [&]() {};
  auto pacingFunc = [&]() { return 3600000ms; };
  FunctionLooper::Ptr looper(
      new FunctionLooper(&evb, std::move(runFunc), LooperType::ReadLooper));
  looper->setPacingTimer(std::move(pacingTimer));
  looper->setPacingFunction(std::move(pacingFunc));
  // bootstrap the looper
  looper->run();
  // this loop will schedule pacer not looper:
  evb.loopOnce();
  EXPECT_TRUE(looper->isScheduled());
  EXPECT_FALSE(looper->isLoopCallbackScheduled());
  looper->stop();
}

} // namespace test
} // namespace quic
