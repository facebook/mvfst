/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <folly/portability/GTest.h>
#include <quic/common/events/FollyQuicEventBase.h>

using namespace ::testing;

class TestCallback : public quic::QuicEventBaseLoopCallback {
 public:
  TestCallback(quic::FollyQuicEventBase* qEvb) : qEvb_(qEvb) {}
  void runLoopCallback() noexcept {
    delete qEvb_;
  }

 private:
  quic::FollyQuicEventBase* qEvb_;
};

TEST(FollyQuicEventBaseTest, TestDeleteEvbInaCallback) {
  folly::EventBase fevb;
  auto qEvb = new quic::FollyQuicEventBase(&fevb);
  auto cb = new TestCallback(qEvb);
  qEvb->runInLoop(cb, true);
  fevb.loop();
  delete cb;
}
