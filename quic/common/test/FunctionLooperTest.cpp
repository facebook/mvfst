/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <quic/api/QuicTransportBaseLite.h>
#include <quic/common/events/FollyQuicEventBase.h>
#include <quic/common/events/HighResQuicTimer.h>

#include <gtest/gtest.h>

using namespace std;
using namespace folly;
using namespace testing;

namespace quic::test {

namespace {

/**
 * MockTransportForLooperTest is a minimal mock of QuicTransportBaseLite
 * that allows testing TransportLooper in isolation.
 */
class MockTransportForLooperTest : public QuicTransportBaseLite {
 public:
  MockTransportForLooperTest(std::shared_ptr<QuicEventBase> evb)
      : QuicTransportBaseLite(std::move(evb), nullptr, false) {}

  ~MockTransportForLooperTest() override {
    // Must set closeState_ before base destructor runs
    closeState_ = CloseState::CLOSED;
  }

  // Test state
  bool called{false};
  int count{0};
  std::function<void()> onCallback;
  bool firstPacingCall{true};
  bool stopPacing{false};
  std::chrono::microseconds pacingDelay{std::chrono::hours(1)};

  void onLooperCallback(LooperType /* type */) override {
    called = true;
    ++count;
    if (onCallback) {
      onCallback();
    }
  }

  std::chrono::microseconds getLooperPacingDelay() override {
    if (firstPacingCall) {
      firstPacingCall = false;
      return pacingDelay;
    }
    if (stopPacing) {
      return std::chrono::microseconds::zero();
    }
    return pacingDelay;
  }

  // Required pure virtual implementations
  quic::Expected<void, QuicError> writeData() override {
    return {};
  }

  quic::Expected<void, QuicError> onReadData(
      const folly::SocketAddress& /* localAddress */,
      ReceivedUdpPacket&& /* udpPacket */,
      const folly::SocketAddress& /* peerAddress */) override {
    return {};
  }

  [[nodiscard]] bool hasWriteCipher() const override {
    return true;
  }

  void closeTransport() override {}

  void unbindConnection() override {}

  std::shared_ptr<QuicTransportBaseLite> sharedGuard() override {
    return nullptr;
  }

  [[nodiscard]] Optional<std::vector<uint8_t>> getExportedKeyingMaterial(
      const std::string& /* label */,
      const Optional<folly::ByteRange>& /* context */,
      uint16_t /* keyLength */) const override {
    return std::nullopt;
  }

  [[nodiscard]] Optional<std::vector<TransportParameter>>
  getPeerTransportParams() const override {
    return std::nullopt;
  }

  // Expose loopers for testing
  TransportLooper* getWriteLooperForTest() {
    return writeLooper_.get();
  }

  TransportLooper* getReadLooperForTest() {
    return readLooper_.get();
  }

  // Create a test looper directly
  TransportLooper::Ptr createTestLooper(LooperType type) {
    return TransportLooper::Ptr(new TransportLooper(evb_, this, type));
  }
};

} // namespace

class TransportLooperTest : public Test {};

TEST(TransportLooperTest, LooperNotRunning) {
  folly::EventBase backingEvb;
  auto evb = std::make_shared<FollyQuicEventBase>(&backingEvb);
  MockTransportForLooperTest transport(evb);
  auto looper = transport.createTestLooper(LooperType::ReadLooper);

  evb->loopOnce();
  EXPECT_FALSE(transport.called);
  evb->loopOnce();
  EXPECT_FALSE(transport.called);
  EXPECT_FALSE(looper->isRunning());
}

TEST(TransportLooperTest, LooperStarted) {
  folly::EventBase backingEvb;
  auto evb = std::make_shared<FollyQuicEventBase>(&backingEvb);
  MockTransportForLooperTest transport(evb);
  auto looper = transport.createTestLooper(LooperType::ReadLooper);

  looper->run();
  EXPECT_TRUE(looper->isRunning());
  evb->loopOnce();
  EXPECT_TRUE(transport.called);
  transport.called = false;
  evb->loopOnce();
  EXPECT_TRUE(transport.called);
}

TEST(TransportLooperTest, LooperStopped) {
  folly::EventBase backingEvb;
  auto evb = std::make_shared<FollyQuicEventBase>(&backingEvb);
  MockTransportForLooperTest transport(evb);
  auto looper = transport.createTestLooper(LooperType::ReadLooper);

  looper->run();
  evb->loopOnce();
  EXPECT_TRUE(transport.called);
  transport.called = false;
  looper->stop();
  EXPECT_FALSE(looper->isRunning());
  evb->loopOnce();
  EXPECT_FALSE(transport.called);
}

TEST(TransportLooperTest, LooperRestarted) {
  folly::EventBase backingEvb;
  auto evb = std::make_shared<FollyQuicEventBase>(&backingEvb);
  MockTransportForLooperTest transport(evb);
  auto looper = transport.createTestLooper(LooperType::ReadLooper);

  looper->run();
  evb->loopOnce();
  EXPECT_TRUE(transport.called);
  transport.called = false;
  looper->stop();
  evb->loopOnce();
  EXPECT_FALSE(transport.called);
  looper->run();
  EXPECT_TRUE(looper->isRunning());
  evb->loopOnce();
  EXPECT_TRUE(transport.called);
}

TEST(TransportLooperTest, DestroyLooperDuringCallback) {
  folly::EventBase backingEvb;
  auto evb = std::make_shared<FollyQuicEventBase>(&backingEvb);
  MockTransportForLooperTest transport(evb);
  auto looper = transport.createTestLooper(LooperType::ReadLooper);
  auto* looperPtr = &looper;

  transport.onCallback = [looperPtr]() { *looperPtr = nullptr; };

  looper->run();
  evb->loopOnce();
  EXPECT_TRUE(transport.called);
  EXPECT_EQ(looper, nullptr);
}

TEST(TransportLooperTest, StopLooperDuringCallback) {
  folly::EventBase backingEvb;
  auto evb = std::make_shared<FollyQuicEventBase>(&backingEvb);
  MockTransportForLooperTest transport(evb);
  auto looper = transport.createTestLooper(LooperType::ReadLooper);
  auto* looperPtr = looper.get();

  transport.onCallback = [looperPtr]() { looperPtr->stop(); };

  looper->run();
  evb->loopOnce();
  EXPECT_TRUE(transport.called);
  transport.called = false;
  evb->loopOnce();
  EXPECT_FALSE(transport.called);
}

TEST(TransportLooperTest, RunLooperDuringCallback) {
  folly::EventBase backingEvb;
  auto evb = std::make_shared<FollyQuicEventBase>(&backingEvb);
  MockTransportForLooperTest transport(evb);
  auto looper = transport.createTestLooper(LooperType::ReadLooper);
  auto* looperPtr = looper.get();

  transport.onCallback = [looperPtr]() { looperPtr->run(); };

  looper->run();
  evb->loopOnce();
  EXPECT_TRUE(transport.called);
  transport.called = false;
  evb->loopOnce();
  EXPECT_TRUE(transport.called);
}

TEST(TransportLooperTest, DetachStopsLooper) {
  folly::EventBase backingEvb;
  auto evb = std::make_shared<FollyQuicEventBase>(&backingEvb);
  MockTransportForLooperTest transport(evb);
  auto looper = transport.createTestLooper(LooperType::ReadLooper);

  looper->run();
  EXPECT_TRUE(looper->isRunning());
  looper->detachEventBase();
  EXPECT_FALSE(looper->isRunning());
  looper->attachEventBase(evb);
  EXPECT_FALSE(looper->isRunning());
}

TEST(TransportLooperTest, PacingOnce) {
  folly::EventBase backingEvb;
  auto evb = std::make_shared<FollyQuicEventBase>(&backingEvb);
  QuicTimer::SharedPtr pacingTimer =
      std::make_shared<HighResQuicTimer>(evb->getBackingEventBase(), 1ms);
  MockTransportForLooperTest transport(evb);
  auto looper = transport.createTestLooper(LooperType::ReadLooper);

  looper->setPacingTimer(std::move(pacingTimer));
  looper->enablePacingCallback();
  looper->run();
  evb->loopOnce();
  EXPECT_EQ(1, transport.count);
  EXPECT_TRUE(looper->isPacingScheduled());
  looper->timeoutExpired();
  EXPECT_EQ(2, transport.count);
  looper->stop();
}

TEST(TransportLooperTest, KeepPacing) {
  folly::EventBase backingEvb;
  auto evb = std::make_shared<FollyQuicEventBase>(&backingEvb);
  QuicTimer::SharedPtr pacingTimer =
      std::make_shared<HighResQuicTimer>(evb->getBackingEventBase(), 1ms);
  MockTransportForLooperTest transport(evb);
  auto looper = transport.createTestLooper(LooperType::ReadLooper);

  // Reset firstPacingCall so it always returns the pacing delay
  transport.firstPacingCall = false;

  looper->setPacingTimer(pacingTimer);
  looper->enablePacingCallback();
  looper->run();
  evb->loopOnce();
  EXPECT_EQ(1, transport.count);
  EXPECT_TRUE(looper->isPacingScheduled());

  looper->cancelTimerCallback();
  EXPECT_FALSE(looper->isPacingScheduled());
  looper->timeoutExpired();
  EXPECT_EQ(2, transport.count);
  EXPECT_TRUE(looper->isPacingScheduled());

  looper->cancelTimerCallback();
  EXPECT_FALSE(looper->isPacingScheduled());
  looper->timeoutExpired();
  EXPECT_EQ(3, transport.count);
  EXPECT_TRUE(looper->isPacingScheduled());

  transport.stopPacing = true;
  looper->cancelTimerCallback();
  EXPECT_FALSE(looper->isPacingScheduled());
  looper->timeoutExpired();
  EXPECT_EQ(4, transport.count);
  EXPECT_FALSE(looper->isPacingScheduled());

  looper->stop();
}

TEST(TransportLooperTest, TimerTickSize) {
  folly::EventBase backingEvb;
  auto evb = std::make_shared<FollyQuicEventBase>(&backingEvb);
  QuicTimer::SharedPtr pacingTimer =
      std::make_shared<HighResQuicTimer>(evb->getBackingEventBase(), 123ms);
  MockTransportForLooperTest transport(evb);
  auto looper = transport.createTestLooper(LooperType::ReadLooper);

  looper->setPacingTimer(std::move(pacingTimer));
  EXPECT_EQ(123ms, looper->getTimerTickInterval());
}

TEST(TransportLooperTest, TimerTickSizeAfterNewEvb) {
  folly::EventBase backingEvb;
  auto evb = std::make_shared<FollyQuicEventBase>(&backingEvb);
  QuicTimer::SharedPtr pacingTimer =
      std::make_shared<HighResQuicTimer>(evb->getBackingEventBase(), 123ms);
  MockTransportForLooperTest transport(evb);
  auto looper = transport.createTestLooper(LooperType::ReadLooper);

  looper->setPacingTimer(std::move(pacingTimer));
  EXPECT_EQ(123ms, looper->getTimerTickInterval());
  looper->detachEventBase();
  folly::EventBase backingEvb2;
  auto evb2 = std::make_shared<FollyQuicEventBase>(&backingEvb);
  looper->attachEventBase(evb2);
  EXPECT_EQ(123ms, looper->getTimerTickInterval());
}

TEST(TransportLooperTest, NoLoopCallbackInPacingMode) {
  folly::EventBase backingEvb;
  auto evb = std::make_shared<FollyQuicEventBase>(&backingEvb);
  QuicTimer::SharedPtr pacingTimer =
      std::make_shared<HighResQuicTimer>(evb->getBackingEventBase(), 1ms);
  MockTransportForLooperTest transport(evb);
  auto looper = transport.createTestLooper(LooperType::ReadLooper);

  // Reset firstPacingCall so it always returns the pacing delay
  transport.firstPacingCall = false;

  looper->setPacingTimer(std::move(pacingTimer));
  looper->enablePacingCallback();
  // bootstrap the looper
  looper->run();
  // this loop will schedule pacer not looper:
  evb->loopOnce();
  EXPECT_TRUE(looper->isPacingScheduled());
  EXPECT_FALSE(looper->isLoopCallbackScheduled());
  looper->stop();
}

} // namespace quic::test
