/*
 * Copyright (c) Facebook, Inc. and its affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 *
 */

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <quic/server/state/ServerStateMachine.h>
#include <quic/state/QuicStreamManager.h>
#include <quic/state/test/Mocks.h>

using namespace folly;
using namespace testing;

namespace quic {
namespace test {

class QuicStreamManagerTest : public Test {
 public:
  void SetUp() override {
    conn.flowControlState.peerAdvertisedInitialMaxStreamOffsetBidiLocal =
        kDefaultStreamWindowSize;
    conn.flowControlState.peerAdvertisedInitialMaxStreamOffsetBidiRemote =
        kDefaultStreamWindowSize;
    conn.flowControlState.peerAdvertisedInitialMaxStreamOffsetUni =
        kDefaultStreamWindowSize;
    conn.flowControlState.peerAdvertisedMaxOffset =
        kDefaultConnectionWindowSize;
    conn.streamManager->setMaxLocalBidirectionalStreams(
        kDefaultMaxStreamsBidirectional);
    conn.streamManager->setMaxLocalUnidirectionalStreams(
        kDefaultMaxStreamsUnidirectional);
    auto congestionController =
        std::make_unique<NiceMock<MockCongestionController>>();
    mockController = congestionController.get();
    conn.congestionController = std::move(congestionController);
  }

  QuicServerConnectionState conn;
  MockCongestionController* mockController;
};

TEST_F(QuicStreamManagerTest, TestAppLimitedCreateBidiStream) {
  auto& manager = *conn.streamManager;
  EXPECT_FALSE(manager.isAppLimited());

  // The app limiited state did not change.
  EXPECT_CALL(*mockController, setAppLimited(false, _)).Times(0);
  auto stream = manager.createNextBidirectionalStream();
  StreamId id = stream.value()->id;
  EXPECT_FALSE(manager.isAppLimited());

  EXPECT_CALL(*mockController, setAppLimited(true, _));
  // Force transition to closed state
  stream.value()->state = StreamStates::Closed();
  manager.removeClosedStream(stream.value()->id);
  EXPECT_TRUE(manager.isAppLimited());
  EXPECT_EQ(manager.getStream(id), nullptr);
}

TEST_F(QuicStreamManagerTest, TestAppLimitedCreateUnidiStream) {
  auto& manager = *conn.streamManager;
  EXPECT_FALSE(manager.isAppLimited());
  EXPECT_CALL(*mockController, setAppLimited(false, _)).Times(0);
  auto stream = manager.createNextUnidirectionalStream();
  EXPECT_FALSE(manager.isAppLimited());

  // Force transition to closed state
  EXPECT_CALL(*mockController, setAppLimited(true, _));
  stream.value()->state = StreamStates::Closed();
  manager.removeClosedStream(stream.value()->id);
  EXPECT_TRUE(manager.isAppLimited());
}

TEST_F(QuicStreamManagerTest, TestAppLimitedExistingLocalStream) {
  auto& manager = *conn.streamManager;
  EXPECT_FALSE(manager.isAppLimited());
  EXPECT_CALL(*mockController, setAppLimited(false, _)).Times(0);

  auto stream = manager.createNextUnidirectionalStream();
  EXPECT_FALSE(manager.isAppLimited());

  EXPECT_CALL(*mockController, setAppLimited(true, _));
  manager.setStreamAsControl(*stream.value());
  EXPECT_TRUE(manager.isAppLimited());

  manager.getStream(stream.value()->id);
  EXPECT_TRUE(manager.isAppLimited());
}

TEST_F(QuicStreamManagerTest, TestAppLimitedStreamAsControl) {
  auto& manager = *conn.streamManager;
  EXPECT_FALSE(manager.isAppLimited());

  auto stream = manager.createNextUnidirectionalStream();
  EXPECT_FALSE(manager.isAppLimited());

  EXPECT_CALL(*mockController, setAppLimited(true, _));
  manager.setStreamAsControl(*stream.value());
  EXPECT_TRUE(manager.isAppLimited());

  EXPECT_CALL(*mockController, setAppLimited(false, _));
  manager.createNextUnidirectionalStream();
  EXPECT_FALSE(manager.isAppLimited());
}

TEST_F(QuicStreamManagerTest, TestAppLimitedCreatePeerStream) {
  auto& manager = *conn.streamManager;
  EXPECT_FALSE(manager.isAppLimited());
  StreamId id = 0;
  auto stream = manager.getStream(id);
  EXPECT_FALSE(manager.isAppLimited());

  EXPECT_CALL(*mockController, setAppLimited(true, _));
  manager.setStreamAsControl(*stream);
  EXPECT_TRUE(manager.isAppLimited());

  EXPECT_CALL(*mockController, setAppLimited(false, _));
  StreamId id2 = 4;
  manager.getStream(id2);
  EXPECT_FALSE(manager.isAppLimited());
}

TEST_F(QuicStreamManagerTest, TestAppLimitedExistingPeerStream) {
  auto& manager = *conn.streamManager;
  EXPECT_FALSE(manager.isAppLimited());
  EXPECT_CALL(*mockController, setAppLimited(false, _)).Times(0);

  StreamId id = 0;
  auto stream = manager.getStream(id);
  EXPECT_FALSE(manager.isAppLimited());

  EXPECT_CALL(*mockController, setAppLimited(true, _));
  manager.setStreamAsControl(*stream);
  EXPECT_TRUE(manager.isAppLimited());

  manager.getStream(id);
  EXPECT_TRUE(manager.isAppLimited());
}

TEST_F(QuicStreamManagerTest, TestAppLimitedClosePeerStream) {
  auto& manager = *conn.streamManager;
  EXPECT_FALSE(manager.isAppLimited());
  StreamId id = 0;
  auto stream = manager.getStream(id);
  EXPECT_FALSE(manager.isAppLimited());

  EXPECT_CALL(*mockController, setAppLimited(true, _));
  // Force transition to closed state
  stream->state = StreamStates::Closed();
  manager.removeClosedStream(stream->id);
  EXPECT_TRUE(manager.isAppLimited());
  EXPECT_EQ(manager.getStream(id), nullptr);
}

TEST_F(QuicStreamManagerTest, TestAppLimitedCloseControlStream) {
  auto& manager = *conn.streamManager;
  EXPECT_FALSE(manager.isAppLimited());
  EXPECT_CALL(*mockController, setAppLimited(false, _)).Times(0);

  StreamId id = 0;
  auto stream = manager.getStream(id);
  EXPECT_FALSE(manager.isAppLimited());

  EXPECT_CALL(*mockController, setAppLimited(true, _));
  manager.setStreamAsControl(*stream);
  EXPECT_TRUE(manager.isAppLimited());

  // Force transition to closed state
  stream->state = StreamStates::Closed();
  manager.removeClosedStream(stream->id);
  EXPECT_TRUE(manager.isAppLimited());
}
} // namespace test
} // namespace quic
