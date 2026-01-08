/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <quic/common/FunctionLooper.h>
#include <quic/common/events/FollyQuicEventBase.h>
#include <quic/common/events/HighResQuicTimer.h>

#include <gtest/gtest.h>

using namespace std;
using namespace folly;
using namespace testing;

namespace quic::test {

namespace {

// Test helper struct for FunctionLooper callbacks
struct TestContext {
  bool called{false};
  int count{0};
  std::function<void()> onRun; // For per-test custom behavior
  bool firstPacingCall{true};
  bool stopPacing{false};
  FunctionLooper::Ptr* looperPtr{nullptr};
};

// Basic callback that sets called and count
void testCallback(void* ctx) {
  auto* state = static_cast<TestContext*>(ctx);
  state->called = true;
  ++state->count;
  if (state->onRun) {
    state->onRun();
  }
}

// No-op callback for timer tick tests
void noOpCallback(void* /* ctx */) {}

// Pacing callback that returns large time first, then 0
std::chrono::microseconds pacingOnceCallback(void* ctx) {
  auto* state = static_cast<TestContext*>(ctx);
  if (state->firstPacingCall) {
    state->firstPacingCall = false;
    return std::chrono::duration_cast<std::chrono::microseconds>(
        std::chrono::milliseconds(3600000));
  }
  return std::chrono::microseconds::zero();
}

// Pacing callback that returns large time until stopPacing
std::chrono::microseconds keepPacingCallback(void* ctx) {
  auto* state = static_cast<TestContext*>(ctx);
  if (state->stopPacing) {
    return std::chrono::microseconds::zero();
  }
  return std::chrono::duration_cast<std::chrono::microseconds>(
      std::chrono::milliseconds(3600000));
}

// Pacing callback that always returns large time
std::chrono::microseconds alwaysPaceCallback(void* /* ctx */) {
  return std::chrono::duration_cast<std::chrono::microseconds>(
      std::chrono::milliseconds(3600000));
}

} // namespace

class FunctionLooperTest : public Test {};

TEST(FunctionLooperTest, LooperNotRunning) {
  folly::EventBase backingEvb;
  auto evb = std::make_shared<FollyQuicEventBase>(&backingEvb);
  TestContext ctx;
  FunctionLooper::Ptr looper(
      new FunctionLooper(evb, &ctx, &testCallback, LooperType::ReadLooper));
  evb->loopOnce();
  EXPECT_FALSE(ctx.called);
  evb->loopOnce();
  EXPECT_FALSE(ctx.called);
  EXPECT_FALSE(looper->isRunning());
}

TEST(FunctionLooperTest, LooperStarted) {
  folly::EventBase backingEvb;
  auto evb = std::make_shared<FollyQuicEventBase>(&backingEvb);
  TestContext ctx;
  FunctionLooper::Ptr looper(
      new FunctionLooper(evb, &ctx, &testCallback, LooperType::ReadLooper));
  looper->run();
  EXPECT_TRUE(looper->isRunning());
  evb->loopOnce();
  EXPECT_TRUE(ctx.called);
  ctx.called = false;
  evb->loopOnce();
  EXPECT_TRUE(ctx.called);
}

TEST(FunctionLooperTest, LooperStopped) {
  folly::EventBase backingEvb;
  auto evb = std::make_shared<FollyQuicEventBase>(&backingEvb);
  TestContext ctx;
  FunctionLooper::Ptr looper(
      new FunctionLooper(evb, &ctx, &testCallback, LooperType::ReadLooper));
  looper->run();
  evb->loopOnce();
  EXPECT_TRUE(ctx.called);
  ctx.called = false;
  looper->stop();
  EXPECT_FALSE(looper->isRunning());
  evb->loopOnce();
  EXPECT_FALSE(ctx.called);
}

TEST(FunctionLooperTest, LooperRestarted) {
  folly::EventBase backingEvb;
  auto evb = std::make_shared<FollyQuicEventBase>(&backingEvb);
  TestContext ctx;
  FunctionLooper::Ptr looper(
      new FunctionLooper(evb, &ctx, &testCallback, LooperType::ReadLooper));
  looper->run();
  evb->loopOnce();
  EXPECT_TRUE(ctx.called);
  ctx.called = false;
  looper->stop();
  evb->loopOnce();
  EXPECT_FALSE(ctx.called);
  looper->run();
  EXPECT_TRUE(looper->isRunning());
  evb->loopOnce();
  EXPECT_TRUE(ctx.called);
}

TEST(FunctionLooperTest, DestroyLooperDuringFunc) {
  folly::EventBase backingEvb;
  auto evb = std::make_shared<FollyQuicEventBase>(&backingEvb);
  TestContext ctx;
  FunctionLooper::Ptr looper(
      new FunctionLooper(evb, &ctx, &testCallback, LooperType::ReadLooper));
  ctx.looperPtr = &looper;
  ctx.onRun = [&ctx]() { *ctx.looperPtr = nullptr; };

  looper->run();
  evb->loopOnce();
  EXPECT_TRUE(ctx.called);
  EXPECT_EQ(looper, nullptr);
}

TEST(FunctionLooperTest, StopLooperDuringFunc) {
  folly::EventBase backingEvb;
  auto evb = std::make_shared<FollyQuicEventBase>(&backingEvb);
  TestContext ctx;
  FunctionLooper::Ptr looper(
      new FunctionLooper(evb, &ctx, &testCallback, LooperType::ReadLooper));
  ctx.looperPtr = &looper;
  ctx.onRun = [&ctx]() { (*ctx.looperPtr)->stop(); };

  looper->run();
  evb->loopOnce();
  EXPECT_TRUE(ctx.called);
  ctx.called = false;
  evb->loopOnce();
  EXPECT_FALSE(ctx.called);
}

TEST(FunctionLooperTest, RunLooperDuringFunc) {
  folly::EventBase backingEvb;
  auto evb = std::make_shared<FollyQuicEventBase>(&backingEvb);
  TestContext ctx;
  FunctionLooper::Ptr looper(
      new FunctionLooper(evb, &ctx, &testCallback, LooperType::ReadLooper));
  ctx.looperPtr = &looper;
  ctx.onRun = [&ctx]() { (*ctx.looperPtr)->run(); };

  looper->run();
  evb->loopOnce();
  EXPECT_TRUE(ctx.called);
  ctx.called = false;
  evb->loopOnce();
  EXPECT_TRUE(ctx.called);
}

TEST(FunctionLooperTest, DetachStopsLooper) {
  folly::EventBase backingEvb;
  auto evb = std::make_shared<FollyQuicEventBase>(&backingEvb);
  TestContext ctx;
  FunctionLooper::Ptr looper(
      new FunctionLooper(evb, &ctx, &testCallback, LooperType::ReadLooper));
  looper->run();
  EXPECT_TRUE(looper->isRunning());
  looper->detachEventBase();
  EXPECT_FALSE(looper->isRunning());
  looper->attachEventBase(evb);
  EXPECT_FALSE(looper->isRunning());
}

TEST(FunctionLooperTest, PacingOnce) {
  folly::EventBase backingEvb;
  auto evb = std::make_shared<FollyQuicEventBase>(&backingEvb);
  QuicTimer::SharedPtr pacingTimer =
      std::make_shared<HighResQuicTimer>(evb->getBackingEventBase(), 1ms);
  TestContext ctx;
  FunctionLooper::Ptr looper(
      new FunctionLooper(evb, &ctx, &testCallback, LooperType::ReadLooper));
  looper->setPacingTimer(std::move(pacingTimer));
  looper->setPacingCallback(&pacingOnceCallback);
  looper->run();
  evb->loopOnce();
  EXPECT_EQ(1, ctx.count);
  EXPECT_TRUE(looper->isPacingScheduled());
  looper->timeoutExpired();
  EXPECT_EQ(2, ctx.count);
  looper->stop();
}

TEST(FunctionLooperTest, KeepPacing) {
  folly::EventBase backingEvb;
  auto evb = std::make_shared<FollyQuicEventBase>(&backingEvb);
  QuicTimer::SharedPtr pacingTimer =
      std::make_shared<HighResQuicTimer>(evb->getBackingEventBase(), 1ms);
  TestContext ctx;
  FunctionLooper::Ptr looper(
      new FunctionLooper(evb, &ctx, &testCallback, LooperType::ReadLooper));
  looper->setPacingTimer(pacingTimer);
  looper->setPacingCallback(&keepPacingCallback);
  looper->run();
  evb->loopOnce();
  EXPECT_EQ(1, ctx.count);
  EXPECT_TRUE(looper->isPacingScheduled());

  looper->cancelTimerCallback();
  EXPECT_FALSE(looper->isPacingScheduled());
  looper->timeoutExpired();
  EXPECT_EQ(2, ctx.count);
  EXPECT_TRUE(looper->isPacingScheduled());

  looper->cancelTimerCallback();
  EXPECT_FALSE(looper->isPacingScheduled());
  looper->timeoutExpired();
  EXPECT_EQ(3, ctx.count);
  EXPECT_TRUE(looper->isPacingScheduled());

  ctx.stopPacing = true;
  looper->cancelTimerCallback();
  EXPECT_FALSE(looper->isPacingScheduled());
  looper->timeoutExpired();
  EXPECT_EQ(4, ctx.count);
  EXPECT_FALSE(looper->isPacingScheduled());

  looper->stop();
}

TEST(FunctionLooperTest, TimerTickSize) {
  folly::EventBase backingEvb;
  auto evb = std::make_shared<FollyQuicEventBase>(&backingEvb);
  QuicTimer::SharedPtr pacingTimer =
      std::make_shared<HighResQuicTimer>(evb->getBackingEventBase(), 123ms);
  TestContext ctx;
  FunctionLooper::Ptr looper(
      new FunctionLooper(evb, &ctx, &noOpCallback, LooperType::ReadLooper));
  looper->setPacingTimer(std::move(pacingTimer));
  EXPECT_EQ(123ms, looper->getTimerTickInterval());
}

TEST(FunctionLooperTest, TimerTickSizeAfterNewEvb) {
  folly::EventBase backingEvb;
  auto evb = std::make_shared<FollyQuicEventBase>(&backingEvb);
  QuicTimer::SharedPtr pacingTimer =
      std::make_shared<HighResQuicTimer>(evb->getBackingEventBase(), 123ms);
  TestContext ctx;
  FunctionLooper::Ptr looper(
      new FunctionLooper(evb, &ctx, &noOpCallback, LooperType::ReadLooper));
  looper->setPacingTimer(std::move(pacingTimer));
  EXPECT_EQ(123ms, looper->getTimerTickInterval());
  looper->detachEventBase();
  folly::EventBase backingEvb2;
  auto evb2 = std::make_shared<FollyQuicEventBase>(&backingEvb);
  looper->attachEventBase(evb2);
  EXPECT_EQ(123ms, looper->getTimerTickInterval());
}

TEST(FunctionLooperTest, NoLoopCallbackInPacingMode) {
  folly::EventBase backingEvb;
  auto evb = std::make_shared<FollyQuicEventBase>(&backingEvb);
  QuicTimer::SharedPtr pacingTimer =
      std::make_shared<HighResQuicTimer>(evb->getBackingEventBase(), 1ms);
  TestContext ctx;
  FunctionLooper::Ptr looper(
      new FunctionLooper(evb, &ctx, &noOpCallback, LooperType::ReadLooper));
  looper->setPacingTimer(std::move(pacingTimer));
  looper->setPacingCallback(&alwaysPaceCallback);
  // bootstrap the looper
  looper->run();
  // this loop will schedule pacer not looper:
  evb->loopOnce();
  EXPECT_TRUE(looper->isPacingScheduled());
  EXPECT_FALSE(looper->isLoopCallbackScheduled());
  looper->stop();
}

} // namespace quic::test
