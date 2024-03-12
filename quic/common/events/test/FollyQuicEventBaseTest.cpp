/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <folly/portability/GTest.h>
#include <quic/common/events/FollyQuicEventBase.h>
#include <quic/common/events/test/QuicEventBaseTestBase.h>

using namespace ::testing;

class FollyQuicEventBaseProvider {
 public:
  static std::shared_ptr<quic::QuicEventBase> makeQuicEvb() {
    static folly::EventBase fEvb;
    return std::make_shared<quic::FollyQuicEventBase>(&fEvb);
  }
};

using FollyQuicEventBaseType = Types<FollyQuicEventBaseProvider>;

INSTANTIATE_TYPED_TEST_SUITE_P(
    FollyQuicEventBaseTest, // Instance name
    QuicEventBaseTest, // Test case name
    FollyQuicEventBaseType); // Type list

// The rest of the file contains tests that are specific to FollyQuicEventBase
// behavior.

// This test covers the corner case in Mvfst server where some
// components work directly on the folly::EventBase and others on the wrapper
// FollyQuicEventBase making it possible for the wrapper to be deleted
// while the event base can still be alive.
TEST(FollyQuicEventBaseTest, TestDeleteEvbInaCallback) {
  class TestCallback : public quic::QuicEventBaseLoopCallback {
   public:
    explicit TestCallback(quic::FollyQuicEventBase* qEvb) : qEvb_(qEvb) {}
    void runLoopCallback() noexcept override {
      // This deletes the FollyQuicEventBase wrapper but leaves the
      // underlying folly::EventBase alive.
      delete qEvb_;
    }

   private:
    quic::FollyQuicEventBase* qEvb_;
  };

  folly::EventBase fevb;
  auto qEvb = new quic::FollyQuicEventBase(&fevb);
  auto cb = new TestCallback(qEvb);
  qEvb->runInLoop(cb, true);
  fevb.loop();
  delete cb;
}
