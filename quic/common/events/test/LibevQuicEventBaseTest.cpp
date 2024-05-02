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

class LibevQuicEventBaseProvider {
 public:
  static std::shared_ptr<quic::QuicEventBase> makeQuicEvb() {
    static struct ev_loop* evLoop = ev_loop_new(0);
    return std::make_shared<quic::LibevQuicEventBase>(evLoop);
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
  struct ev_loop* evLoop = ev_loop_new(0);
  auto qEvb = std::make_shared<quic::LibevQuicEventBase>(evLoop);
  // Schedule a function callback, don't run it, then destroy the event base.
  // The function callback wrapper should not leak.
  qEvb->runInLoop([&] { FAIL() << "This should not be called"; });
  qEvb.reset();
  ev_loop_destroy(evLoop);
}
