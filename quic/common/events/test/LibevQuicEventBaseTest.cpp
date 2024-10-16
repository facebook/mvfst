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

struct EvLoop : public quic::LibevQuicEventBase::EvLoopWeak {
  EvLoop() : evLoop_(ev_loop_new(0)) {}

  ~EvLoop() override {
    ev_loop_destroy(evLoop_);
  }

  struct ev_loop* get() override {
    return evLoop_;
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
