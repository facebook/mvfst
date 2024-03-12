/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#pragma once

#include <folly/portability/GTest.h>
#include <quic/common/events/QuicEventBase.h>

template <class T>
class QuicEventBaseTestBase : public testing::Test {
 public:
  void SetUp() override {
    qEvb_ = T::makeQuicEvb();
  }

 protected:
  std::shared_ptr<quic::QuicEventBase> qEvb_;
};

template <class T>
class QuicEventBaseTest : public QuicEventBaseTestBase<T> {};

TYPED_TEST_SUITE_P(QuicEventBaseTest);

// Tests start here

TYPED_TEST_P(QuicEventBaseTest, NestedRunInLoopCallbackInThisIteration) {
  // Verify that scheduling a callback within the callback itself gets executed
  // in the loop not on top of the stack.
  class TestCallback : public quic::QuicEventBaseLoopCallback {
   public:
    explicit TestCallback(quic::QuicEventBase* qEvb) : qEvb_(qEvb) {}
    void runLoopCallback() noexcept override {
      auto currenCount = ++callbackCount_;
      if (currenCount == 1) {
        // The first callback schedules itself once again in the same loop.
        qEvb_->runInLoop(this, true);

        // Verify that the nested callback has not been executed yet.
        EXPECT_EQ(callbackCount_, currenCount);
      }
    }

    uint8_t callbackCount_{0};

   private:
    quic::QuicEventBase* qEvb_;
  };

  auto& qEvb = this->qEvb_;

  auto cb = std::make_unique<TestCallback>(qEvb.get());
  qEvb->runInLoop(cb.get());
  qEvb->loopOnce();

  // Verify that the nested callback has been executed.
  EXPECT_EQ(cb->callbackCount_, 2);
}

TYPED_TEST_P(QuicEventBaseTest, NestedRunInLoopFuncInThisIteration) {
  // Verify that scheduling a callback within the callback itself gets executed
  // in the loop not on top of the stack. The nested callback is a function
  // rather than a callback class.
  class TestCallback : public quic::QuicEventBaseLoopCallback {
   public:
    explicit TestCallback(quic::QuicEventBase* qEvb) : qEvb_(qEvb) {}
    void runLoopCallback() noexcept override {
      auto currenCount = ++callbackCount_;
      if (currenCount == 1) {
        // Schedule a function callback that increments the callback count.
        qEvb_->runInLoop([&]() { callbackCount_++; }, true);

        // Verify that the nested callback has not been executed yet.
        EXPECT_EQ(callbackCount_, currenCount);
      }
    }

    uint8_t callbackCount_{0};

   private:
    quic::QuicEventBase* qEvb_;
  };

  auto& qEvb = this->qEvb_;

  auto cb = std::make_unique<TestCallback>(qEvb.get());
  qEvb->runInLoop(cb.get());
  qEvb->loopOnce();

  // Verify that the nested callback has been executed.
  EXPECT_EQ(cb->callbackCount_, 2);
}

TYPED_TEST_P(QuicEventBaseTest, NestedRunInLoopCallbackInNextIteration) {
  // Verify that scheduling a callback within the callback itself gets executed
  // in the loop not on top of the stack.
  class TestCallback : public quic::QuicEventBaseLoopCallback {
   public:
    explicit TestCallback(quic::QuicEventBase* qEvb) : qEvb_(qEvb) {}
    void runLoopCallback() noexcept override {
      auto currenCount = ++callbackCount_;
      if (currenCount == 1) {
        // The first callback schedules itself once again in the next loop.
        qEvb_->runInLoop(this, false);

        // Verify that the nested callback has not been executed yet.
        EXPECT_EQ(callbackCount_, currenCount);
      }
    }

    uint8_t callbackCount_{0};

   private:
    quic::QuicEventBase* qEvb_;
  };

  auto& qEvb = this->qEvb_;

  auto cb = std::make_unique<TestCallback>(qEvb.get());
  qEvb->runInLoop(cb.get());
  qEvb->loopOnce();

  // Verify that only one callback has been executed in the first loop.
  ASSERT_EQ(cb->callbackCount_, 1);

  qEvb->loopOnce();

  // Verify that the nested callback has been executed after the second loop.
  EXPECT_EQ(cb->callbackCount_, 2);
}

TYPED_TEST_P(QuicEventBaseTest, NestedRunInLoopFuncInNextIteration) {
  // Verify that scheduling a callback within the callback itself gets executed
  // in the loop not on top of the stack. The nested callback is a function
  // rather than a callback class.
  class TestCallback : public quic::QuicEventBaseLoopCallback {
   public:
    explicit TestCallback(quic::QuicEventBase* qEvb) : qEvb_(qEvb) {}
    void runLoopCallback() noexcept override {
      auto currenCount = ++callbackCount_;
      if (currenCount == 1) {
        // Schedule a function callback that increments the callback count in
        // the next loop.
        qEvb_->runInLoop([&]() { callbackCount_++; }, false);

        // Verify that the nested callback has not been executed yet.
        EXPECT_EQ(callbackCount_, currenCount);
      }
    }

    uint8_t callbackCount_{0};

   private:
    quic::QuicEventBase* qEvb_;
  };

  auto& qEvb = this->qEvb_;

  auto cb = std::make_unique<TestCallback>(qEvb.get());
  qEvb->runInLoop(cb.get());
  qEvb->loopOnce();

  // Verify that only one callback has been executed in the first loop.
  ASSERT_EQ(cb->callbackCount_, 1);

  qEvb->loopOnce();

  // Verify that the nested callback has been executed after the second loop.
  EXPECT_EQ(cb->callbackCount_, 2);
}

// Tests end here

// All tests must be registered
REGISTER_TYPED_TEST_SUITE_P(
    QuicEventBaseTest,
    NestedRunInLoopCallbackInThisIteration,
    NestedRunInLoopFuncInThisIteration,
    NestedRunInLoopCallbackInNextIteration,
    NestedRunInLoopFuncInNextIteration
    // Add more tests here
);
