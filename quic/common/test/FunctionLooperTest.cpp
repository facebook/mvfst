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
  EventBase evb;
  bool called = false;
  auto func = [&](bool) { called = true; };
  FunctionLooper::Ptr looper(
      new FunctionLooper(&evb, std::move(func), LooperType::ReadLooper));
  evb.loopOnce();
  EXPECT_FALSE(called);
  evb.loopOnce();
  EXPECT_FALSE(called);
  EXPECT_FALSE(looper->isRunning());
}

TEST(FunctionLooperTest, LooperStarted) {
  EventBase evb;
  bool called = false;
  auto func = [&](bool) { called = true; };
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
  EventBase evb;
  bool called = false;
  auto func = [&](bool) { called = true; };
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
  EventBase evb;
  bool called = false;
  auto func = [&](bool) { called = true; };
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
  EventBase evb;
  bool called = false;
  FunctionLooper::Ptr* looperPtr = nullptr;

  auto func = [&](bool) {
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
  EventBase evb;
  bool called = false;
  FunctionLooper::Ptr* looperPtr = nullptr;

  auto func = [&](bool) {
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
  EventBase evb;
  bool called = false;
  FunctionLooper::Ptr* looperPtr = nullptr;

  auto func = [&](bool) {
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
  EventBase evb;
  bool called = false;
  auto func = [&](bool) { called = true; };
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
  EventBase evb;
  TimerHighRes::SharedPtr pacingTimer(TimerHighRes::newTimer(&evb, 1ms));
  std::vector<bool> fromTimerVec;
  auto func = [&](bool fromTimer) { fromTimerVec.push_back(fromTimer); };
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
  EXPECT_EQ(1, fromTimerVec.size());
  EXPECT_FALSE(fromTimerVec.back());
  EXPECT_TRUE(looper->isScheduled());
  looper->timeoutExpired();
  EXPECT_EQ(2, fromTimerVec.size());
  EXPECT_TRUE(fromTimerVec.back());
  looper->stop();
}

TEST(FunctionLooperTest, KeepPacing) {
  EventBase evb;
  TimerHighRes::SharedPtr pacingTimer(TimerHighRes::newTimer(&evb, 1ms));
  std::vector<bool> fromTimerVec;
  auto func = [&](bool fromTimer) { fromTimerVec.push_back(fromTimer); };
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
  EXPECT_EQ(1, fromTimerVec.size());
  EXPECT_FALSE(fromTimerVec.back());
  EXPECT_TRUE(looper->isScheduled());

  looper->cancelTimeout();
  EXPECT_FALSE(looper->isScheduled());
  looper->timeoutExpired();
  EXPECT_EQ(2, fromTimerVec.size());
  EXPECT_TRUE(fromTimerVec.back());
  EXPECT_TRUE(looper->isScheduled());

  looper->cancelTimeout();
  EXPECT_FALSE(looper->isScheduled());
  looper->timeoutExpired();
  EXPECT_EQ(3, fromTimerVec.size());
  EXPECT_TRUE(fromTimerVec.back());
  EXPECT_TRUE(looper->isScheduled());

  stopPacing = true;
  looper->cancelTimeout();
  EXPECT_FALSE(looper->isScheduled());
  looper->timeoutExpired();
  EXPECT_EQ(4, fromTimerVec.size());
  EXPECT_TRUE(fromTimerVec.back());
  EXPECT_FALSE(looper->isScheduled());

  looper->stop();
}

TEST(FunctionLooperTest, TimerTickSize) {
  EventBase evb;
  TimerHighRes::SharedPtr pacingTimer(TimerHighRes::newTimer(&evb, 123ms));
  FunctionLooper::Ptr looper(new FunctionLooper(
      &evb, [&](bool) {}, LooperType::ReadLooper));
  looper->setPacingTimer(std::move(pacingTimer));
  EXPECT_EQ(123ms, looper->getTimerTickInterval());
}

TEST(FunctionLooperTest, TimerTickSizeAfterNewEvb) {
  EventBase evb;
  TimerHighRes::SharedPtr pacingTimer(TimerHighRes::newTimer(&evb, 123ms));
  FunctionLooper::Ptr looper(new FunctionLooper(
      &evb, [&](bool) {}, LooperType::ReadLooper));
  looper->setPacingTimer(std::move(pacingTimer));
  EXPECT_EQ(123ms, looper->getTimerTickInterval());
  looper->detachEventBase();
  EventBase evb2;
  looper->attachEventBase(&evb2);
  EXPECT_EQ(123ms, looper->getTimerTickInterval());
}

TEST(FunctionLooperTest, NoLoopCallbackInPacingMode) {
  EventBase evb;
  TimerHighRes::SharedPtr pacingTimer(TimerHighRes::newTimer(&evb, 1ms));
  uint32_t loopCallbackRunCounter = 0, pacingRunCounter = 0;
  auto runFunc = [&](bool fromTimer) {
    if (!fromTimer) {
      loopCallbackRunCounter++;
    } else {
      pacingRunCounter++;
    }
  };
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

TEST(FunctionLooperTest, RunConditions) {
  EventBase evb;
  TimerHighRes::SharedPtr pacingTimer(TimerHighRes::newTimer(&evb, 1ms));
  uint32_t loopCallbackRunCounter = 0, pacingRunCounter = 0;
  FunctionLooper::Ptr* looperPtr = nullptr;
  auto runFunc = [&](bool fromTimer) {
    if (!fromTimer) {
      loopCallbackRunCounter++;
    } else {
      pacingRunCounter++;
    }
    (*looperPtr)->run();
  };
  auto pacingFunc = [&]() { return 3600000ms; };
  FunctionLooper::Ptr looper(
      new FunctionLooper(&evb, std::move(runFunc), LooperType::ReadLooper));
  looperPtr = &looper;
  looper->setPacingTimer(std::move(pacingTimer));
  looper->setPacingFunction(std::move(pacingFunc));
  // Nothing scheduled yet, this run will loop
  looper->run();
  evb.loopOnce();
  EXPECT_EQ(0, pacingRunCounter);
  EXPECT_EQ(1, loopCallbackRunCounter);

  // run() inside runFunc didn't have effect. Loop again won't run anything:
  evb.loopOnce();
  EXPECT_EQ(0, pacingRunCounter);
  EXPECT_EQ(1, loopCallbackRunCounter);

  // Since pacing is scheduled, explicit run() outside of runFunc won't run
  // either:
  looper->run();
  evb.loopOnce();
  EXPECT_EQ(0, pacingRunCounter);
  EXPECT_EQ(1, loopCallbackRunCounter);

  looper->stop();
}
} // namespace test
} // namespace quic
