/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <ev.h>
#include <folly/portability/GTest.h>
#include <quic/common/events/LibevQuicEventBase.h>
#include <quic/common/events/test/QuicEventBaseTestBase.h>

using namespace ::testing;

struct EvLoop : public quic::LibevQuicEventBase::EvLoopHolder {
  EvLoop() : evLoop_(ev_loop_new(0)) {}

  ~EvLoop() override {
    ev_loop_destroy(evLoop_);
  }

  EvLoop(const EvLoop&) = delete;
  EvLoop& operator=(const EvLoop&) = delete;
  EvLoop(EvLoop&&) = delete;
  EvLoop& operator=(EvLoop&&) = delete;

  struct ev_loop* get() override {
    return evLoop_;
  }

  std::optional<pthread_t> getEventLoopThread() override {
    return pthread_self();
  }

  struct ev_loop* evLoop_;
};

struct SharedEvLoop : public quic::LibevQuicEventBase::EvLoopHolder {
  explicit SharedEvLoop(struct ev_loop* evLoop) : evLoop_(evLoop) {}

  struct ev_loop* get() override {
    return evLoop_;
  }

  std::optional<pthread_t> getEventLoopThread() override {
    return pthread_self();
  }

  struct ev_loop* evLoop_;
};

class LibevQuicEventBaseProvider {
 public:
  static std::shared_ptr<quic::QuicEventBase> makeQuicEvb() {
    return std::make_shared<quic::LibevQuicEventBase>(
        std::make_unique<EvLoop>());
  }
};

using LibevQuicEventBaseType = Types<LibevQuicEventBaseProvider>;

INSTANTIATE_TYPED_TEST_SUITE_P(
    LibevQuicEventBaseTest, // Instance name
    QuicEventBaseTest, // Test case name
    LibevQuicEventBaseType); // Type list

// The rest of the file contains tests that are specific to LibevQuicEventBase
// behavior.

// This test ensures that FunctionLoopCallback wrappers are not leaked.
TEST(LibevQuicEventBaseTest, TestDestroyEvbWithPendingFunctionLoopCallback) {
  auto qEvb =
      std::make_shared<quic::LibevQuicEventBase>(std::make_unique<EvLoop>());
  // Schedule a function callback, don't run it, then destroy the event base.
  // The function callback wrapper should not leak.
  qEvb->runInLoop([&] { FAIL() << "This should not be called"; });
  qEvb.reset();
}

TEST(
    LibevQuicEventBaseTest,
    PrepareCallbackBeforeSharedOwnershipDoesNotBreakEventBase) {
  auto loop = std::make_unique<EvLoop>();
  auto* evLoop = loop->get();
  auto unownedEvb = std::make_unique<quic::LibevQuicEventBase>(std::move(loop));

  unownedEvb->setLoopCallbackPriority(0);
  ev_run(evLoop, EVRUN_NOWAIT);

  auto qEvb = std::shared_ptr<quic::LibevQuicEventBase>(std::move(unownedEvb));
  bool callbackRan = false;
  qEvb->runInLoop([&] { callbackRan = true; });
  qEvb->loop();

  EXPECT_TRUE(callbackRan);
}

TEST(
    LibevQuicEventBaseTest,
    NextIterationCallbackFromLoopCallbackDoesNotWaitForEvents) {
  auto loop = std::make_unique<EvLoop>();
  auto* evLoop = loop->get();
  auto qEvb = std::make_shared<quic::LibevQuicEventBase>(std::move(loop));
  qEvb->setWakeForNextIterationCallbacks(true);
  ev_timer farTimer;
  ev_timer_init(
      &farTimer,
      [](struct ev_loop* l, ev_timer*, int) { ev_break(l, EVBREAK_ALL); },
      3.0,
      0.);
  ev_timer_start(evLoop, &farTimer);
  bool nestedRan = false;
  qEvb->runInLoop([&] {
    qEvb->runInLoop(
        [&] {
          nestedRan = true;
          ev_break(evLoop, EVBREAK_ALL);
        },
        /*thisIteration=*/false);
  });

  const auto start = std::chrono::steady_clock::now();
  ev_run(evLoop, 0);
  const auto elapsed = std::chrono::steady_clock::now() - start;
  ev_timer_stop(evLoop, &farTimer);

  EXPECT_TRUE(nestedRan);
  EXPECT_LT(elapsed, std::chrono::milliseconds(500));
}

TEST(
    LibevQuicEventBaseTest,
    CallbackQueuedFromAnotherEventBaseOnTheLoopDoesNotWaitForEvents) {
  auto loop = std::make_unique<EvLoop>();
  auto* evLoop = loop->get();
  auto first = std::make_shared<quic::LibevQuicEventBase>(std::move(loop));
  auto second = std::make_shared<quic::LibevQuicEventBase>(
      std::make_unique<SharedEvLoop>(evLoop));
  first->setWakeForNextIterationCallbacks(true);
  second->setWakeForNextIterationCallbacks(true);
  first->runInLoop([] {});
  first->setLoopCallbackPriority(EV_MAXPRI);
  ev_timer farTimer;
  ev_timer_init(
      &farTimer,
      [](struct ev_loop* l, ev_timer*, int) { ev_break(l, EVBREAK_ALL); },
      3.0,
      0.);
  ev_timer_start(evLoop, &farTimer);
  bool queuedRan = false;
  second->runInLoop([&] {
    first->runInLoop([&] {
      queuedRan = true;
      ev_break(evLoop, EVBREAK_ALL);
    });
  });

  const auto start = std::chrono::steady_clock::now();
  ev_run(evLoop, 0);
  const auto elapsed = std::chrono::steady_clock::now() - start;
  ev_timer_stop(evLoop, &farTimer);

  EXPECT_TRUE(queuedRan);
  EXPECT_LT(elapsed, std::chrono::milliseconds(500));
}
