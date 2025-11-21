/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <quic/fizz/server/handshake/FizzServerQuicHandshakeContext.h>
#include <quic/priority/HTTPPriorityQueue.h>
#include <quic/server/state/ServerStateMachine.h>
#include <quic/state/QuicStreamManager.h>
#include <quic/state/stream/StreamStateFunctions.h>
#include <quic/state/test/MockQuicStats.h>
#include <quic/state/test/Mocks.h>

using namespace testing;

namespace quic::test {

struct StreamManagerTestParam {
  bool notifyOnNewStreamsExplicitly{false};
  bool isUnidirectional{false};
};

class QuicStreamManagerTest
    : public Test,
      public WithParamInterface<StreamManagerTestParam> {
 public:
  QuicStreamManagerTest()
      : conn(FizzServerQuicHandshakeContext::Builder().build()) {}

  void SetUp() override {
    conn.flowControlState.peerAdvertisedInitialMaxStreamOffsetBidiLocal =
        kDefaultStreamFlowControlWindow;
    conn.flowControlState.peerAdvertisedInitialMaxStreamOffsetBidiRemote =
        kDefaultStreamFlowControlWindow;
    conn.flowControlState.peerAdvertisedInitialMaxStreamOffsetUni =
        kDefaultStreamFlowControlWindow;
    conn.flowControlState.peerAdvertisedMaxOffset =
        kDefaultConnectionFlowControlWindow;

    // Use ASSERT checks in SetUp as failure here invalidates subsequent tests
    ASSERT_TRUE(
        conn.streamManager
            ->setMaxLocalBidirectionalStreams(kDefaultMaxStreamsBidirectional)
            .has_value());
    ASSERT_TRUE(
        conn.streamManager
            ->setMaxLocalUnidirectionalStreams(kDefaultMaxStreamsUnidirectional)
            .has_value());

    auto congestionController =
        std::make_unique<NiceMock<MockCongestionController>>();
    mockController = congestionController.get();
    conn.congestionController = std::move(congestionController);

    conn.transportSettings.notifyOnNewStreamsExplicitly =
        GetParam().notifyOnNewStreamsExplicitly;
    ASSERT_TRUE(
        conn.streamManager->refreshTransportSettings(conn.transportSettings)
            .has_value());
  }

  QuicServerConnectionState conn;
  MockCongestionController* mockController;
};

TEST_P(QuicStreamManagerTest, SkipRedundantPriorityUpdate) {
  auto& manager = *conn.streamManager;
  auto streamResult = manager.createNextBidirectionalStream();
  ASSERT_TRUE(streamResult.has_value());
  auto* stream = streamResult.value();
  auto streamId = stream->id;
  HTTPPriorityQueue::Priority currentPriority(stream->priority);
  EXPECT_TRUE(manager.setStreamPriority(
      streamId,
      HTTPPriorityQueue::Priority(
          (currentPriority->urgency + 1) % (kDefaultMaxPriority + 1),
          !currentPriority->incremental)));
  EXPECT_FALSE(manager.setStreamPriority(
      streamId,
      HTTPPriorityQueue::Priority(
          (currentPriority->urgency + 1) % (kDefaultMaxPriority + 1),
          !currentPriority->incremental)));
}

TEST_P(QuicStreamManagerTest, TestAppIdleCreateBidiStream) {
  auto& manager = *conn.streamManager;
  EXPECT_FALSE(manager.isAppIdle());

  // The app limited state did not change.
  EXPECT_CALL(*mockController, setAppIdle(false, _)).Times(0);
  auto streamResult = manager.createNextBidirectionalStream();
  ASSERT_FALSE(streamResult.hasError());
  ASSERT_TRUE(streamResult.has_value());
  auto* stream = streamResult.value();
  StreamId id = stream->id;
  EXPECT_FALSE(manager.isAppIdle());

  EXPECT_CALL(*mockController, setAppIdle(true, _));
  // Force transition to closed state
  stream->sendState = StreamSendState::Closed;
  stream->recvState = StreamRecvState::Closed;
  ASSERT_FALSE(manager.removeClosedStream(stream->id).hasError());
  EXPECT_TRUE(manager.isAppIdle());

  auto getResult = manager.getStream(id);
  ASSERT_FALSE(getResult.hasError());
  ASSERT_TRUE(getResult.has_value());
  EXPECT_EQ(getResult.value(), nullptr); // Check stream is gone (nullptr)
}

TEST_P(QuicStreamManagerTest, TestAppIdleCreateUnidiStream) {
  auto& manager = *conn.streamManager;
  EXPECT_FALSE(manager.isAppIdle());
  EXPECT_CALL(*mockController, setAppIdle(false, _)).Times(0);
  auto streamResult = manager.createNextUnidirectionalStream();
  ASSERT_FALSE(streamResult.hasError());
  ASSERT_TRUE(streamResult.has_value());
  auto* stream = streamResult.value();
  EXPECT_FALSE(manager.isAppIdle());

  // Force transition to closed state
  EXPECT_CALL(*mockController, setAppIdle(true, _));
  stream->sendState = StreamSendState::Closed;
  stream->recvState = StreamRecvState::Closed;
  ASSERT_FALSE(manager.removeClosedStream(stream->id).hasError());
  EXPECT_TRUE(manager.isAppIdle());
}

TEST_P(QuicStreamManagerTest, TestAppIdleExistingLocalStream) {
  auto& manager = *conn.streamManager;
  EXPECT_FALSE(manager.isAppIdle());
  EXPECT_CALL(*mockController, setAppIdle(false, _)).Times(0);

  auto streamResult = manager.createNextUnidirectionalStream();
  ASSERT_TRUE(streamResult.has_value());
  auto* stream = streamResult.value();
  EXPECT_FALSE(manager.isAppIdle());

  EXPECT_CALL(*mockController, setAppIdle(true, _));
  manager.setStreamAsControl(*stream);
  EXPECT_TRUE(manager.isAppIdle());

  auto getResult = manager.getStream(stream->id);
  ASSERT_TRUE(getResult.has_value());
  EXPECT_NE(getResult.value(), nullptr); // Stream should still exist
  EXPECT_TRUE(manager.isAppIdle());
}

TEST_P(QuicStreamManagerTest, TestAppIdleStreamAsControl) {
  auto& manager = *conn.streamManager;
  EXPECT_FALSE(manager.isAppIdle());

  auto streamResult = manager.createNextUnidirectionalStream();
  ASSERT_TRUE(streamResult.has_value());
  auto* stream = streamResult.value();
  EXPECT_FALSE(manager.isAppIdle());

  EXPECT_CALL(*mockController, setAppIdle(true, _));
  manager.setStreamAsControl(*stream);
  EXPECT_TRUE(manager.isAppIdle());

  EXPECT_CALL(*mockController, setAppIdle(false, _));
  auto streamResult2 = manager.createNextUnidirectionalStream();
  ASSERT_TRUE(streamResult2.has_value());
  EXPECT_FALSE(manager.isAppIdle());
}

TEST_P(QuicStreamManagerTest, TestAppIdleCreatePeerStream) {
  auto& manager = *conn.streamManager;
  EXPECT_FALSE(manager.isAppIdle());
  StreamId id = 0;
  auto streamResult = manager.getStream(id);
  ASSERT_TRUE(streamResult.has_value());
  auto* stream = streamResult.value();
  ASSERT_NE(stream, nullptr);
  EXPECT_FALSE(manager.isAppIdle());

  EXPECT_CALL(*mockController, setAppIdle(true, _));
  manager.setStreamAsControl(*stream);
  EXPECT_TRUE(manager.isAppIdle());

  EXPECT_CALL(*mockController, setAppIdle(false, _));
  StreamId id2 = 4;
  auto streamResult2 = manager.getStream(id2);
  ASSERT_TRUE(streamResult2.has_value());
  ASSERT_NE(streamResult2.value(), nullptr);
  EXPECT_FALSE(manager.isAppIdle());
}

TEST_P(QuicStreamManagerTest, TestAppIdleExistingPeerStream) {
  auto& manager = *conn.streamManager;
  EXPECT_FALSE(manager.isAppIdle());
  EXPECT_CALL(*mockController, setAppIdle(false, _)).Times(0);

  StreamId id = 0;
  auto streamResult = manager.getStream(id);
  ASSERT_TRUE(streamResult.has_value());
  auto* stream = streamResult.value();
  ASSERT_NE(stream, nullptr);
  EXPECT_FALSE(manager.isAppIdle());

  EXPECT_CALL(*mockController, setAppIdle(true, _));
  manager.setStreamAsControl(*stream);
  EXPECT_TRUE(manager.isAppIdle());

  auto getResult = manager.getStream(id);
  ASSERT_TRUE(getResult.has_value());
  EXPECT_NE(getResult.value(), nullptr);
  EXPECT_TRUE(manager.isAppIdle());
}

TEST_P(QuicStreamManagerTest, TestAppIdleClosePeerStream) {
  auto& manager = *conn.streamManager;
  EXPECT_FALSE(manager.isAppIdle());
  StreamId id = 0;
  auto streamResult = manager.getStream(id);
  ASSERT_FALSE(streamResult.hasError());
  ASSERT_TRUE(streamResult.has_value());
  auto* stream = streamResult.value();
  ASSERT_NE(stream, nullptr);
  EXPECT_FALSE(manager.isAppIdle());

  EXPECT_CALL(*mockController, setAppIdle(true, _));
  // Force transition to closed state
  stream->sendState = StreamSendState::Closed;
  stream->recvState = StreamRecvState::Closed;
  ASSERT_FALSE(manager.removeClosedStream(stream->id).hasError());
  EXPECT_TRUE(manager.isAppIdle());

  auto getResult = manager.getStream(id);
  ASSERT_FALSE(getResult.hasError());
  ASSERT_TRUE(getResult.has_value());
  EXPECT_EQ(getResult.value(), nullptr); // Check stream is gone
}

TEST_P(QuicStreamManagerTest, TestAppIdleCloseControlStream) {
  auto& manager = *conn.streamManager;
  EXPECT_FALSE(manager.isAppIdle());
  EXPECT_CALL(*mockController, setAppIdle(false, _)).Times(0);

  StreamId id = 0;
  auto streamResult = manager.getStream(id);
  ASSERT_FALSE(streamResult.hasError());
  ASSERT_TRUE(streamResult.has_value());
  auto* stream = streamResult.value();
  ASSERT_NE(stream, nullptr);
  EXPECT_FALSE(manager.isAppIdle());

  EXPECT_CALL(*mockController, setAppIdle(true, _));
  manager.setStreamAsControl(*stream);
  EXPECT_TRUE(manager.isAppIdle());

  // Force transition to closed state
  stream->sendState = StreamSendState::Closed;
  stream->recvState = StreamRecvState::Closed;
  ASSERT_FALSE(manager.removeClosedStream(stream->id).hasError());
  EXPECT_TRUE(manager.isAppIdle());
}

TEST_P(QuicStreamManagerTest, PeerMaxStreamsLimitSaturated) {
  MockQuicStats mockStats;
  conn.statsCallback = &mockStats;
  auto& manager = *conn.streamManager;
  conn.transportSettings.advertisedInitialMaxStreamsBidi = 10;
  conn.transportSettings.advertisedInitialMaxStreamsUni = 10;
  ASSERT_FALSE(
      manager.refreshTransportSettings(conn.transportSettings).hasError());
  manager.setStreamLimitWindowingFraction(1);

  // open 9 streams which is just below the limit, should not invoke callback
  EXPECT_CALL(mockStats, onPeerMaxBidiStreamsLimitSaturated).Times(0);
  EXPECT_CALL(mockStats, onPeerMaxUniStreamsLimitSaturated).Times(0);
  uint8_t idx = 0;
  for (idx = 0; idx < 9; idx++) {
    ASSERT_FALSE(manager.getStream(idx * detail::kStreamIncrement).hasError());
    ASSERT_FALSE(
        manager.getStream(2 + idx * detail::kStreamIncrement).hasError());
  }
  // peer saturating all bidi & uni streams should invoke callback
  EXPECT_CALL(mockStats, onPeerMaxBidiStreamsLimitSaturated).Times(1);
  EXPECT_CALL(mockStats, onPeerMaxUniStreamsLimitSaturated).Times(1);
  // create last stream that will saturate the limit
  ASSERT_FALSE(manager.getStream(idx * detail::kStreamIncrement).hasError());
  ASSERT_FALSE(
      manager.getStream(2 + idx * detail::kStreamIncrement).hasError());

  // close all opened streams will send peer max streams credit
  for (idx = 0; idx < 10; idx++) {
    auto streamResult1 = manager.getStream(idx * detail::kStreamIncrement);
    ASSERT_FALSE(streamResult1.hasError());
    ASSERT_TRUE(streamResult1.has_value());
    auto* stream1 = streamResult1.value();
    ASSERT_NE(stream1, nullptr);
    stream1->sendState = StreamSendState::Closed;
    stream1->recvState = StreamRecvState::Closed;
    ASSERT_FALSE(manager.removeClosedStream(stream1->id).hasError());

    auto streamResult2 = manager.getStream(2 + idx * detail::kStreamIncrement);
    ASSERT_FALSE(streamResult2.hasError());
    ASSERT_TRUE(streamResult2.has_value());
    auto* stream2 = streamResult2.value();
    ASSERT_NE(stream2, nullptr);
    stream2->sendState = StreamSendState::Closed;
    stream2->recvState = StreamRecvState::Closed;
    ASSERT_FALSE(manager.removeClosedStream(stream2->id).hasError());
  }

  // validate transport will advertise an update
  auto bidiUpdate = manager.remoteBidirectionalStreamLimitUpdate();
  auto uniUpdate = manager.remoteUnidirectionalStreamLimitUpdate();
  ASSERT_TRUE(bidiUpdate.has_value());
  ASSERT_TRUE(uniUpdate.has_value());
  EXPECT_EQ(bidiUpdate.value(), 20);
  EXPECT_EQ(uniUpdate.value(), 20);

  // should not advertise again since no streams were consumed
  EXPECT_FALSE(manager.remoteBidirectionalStreamLimitUpdate());
  EXPECT_FALSE(manager.remoteUnidirectionalStreamLimitUpdate());
}

TEST_P(QuicStreamManagerTest, StreamLimitWindowedUpdate) {
  auto& manager = *conn.streamManager;
  conn.transportSettings.advertisedInitialMaxStreamsBidi = 100;
  conn.transportSettings.advertisedInitialMaxStreamsUni = 100;
  ASSERT_FALSE(
      manager.refreshTransportSettings(conn.transportSettings).hasError());
  manager.setStreamLimitWindowingFraction(4);
  for (int i = 0; i < 100; i++) {
    ASSERT_FALSE(manager.getStream(i * detail::kStreamIncrement).hasError());
    ASSERT_FALSE(
        manager.getStream(2 + i * detail::kStreamIncrement).hasError());
  }
  for (int i = 0; i < 25; i++) {
    auto streamResult1 = manager.getStream(i * detail::kStreamIncrement);
    ASSERT_FALSE(streamResult1.hasError());
    ASSERT_TRUE(streamResult1.has_value());
    auto* stream1 = streamResult1.value();
    ASSERT_NE(stream1, nullptr);
    stream1->sendState = StreamSendState::Closed;
    stream1->recvState = StreamRecvState::Closed;
    ASSERT_FALSE(manager.removeClosedStream(stream1->id).hasError());

    auto streamResult2 = manager.getStream(2 + i * detail::kStreamIncrement);
    ASSERT_FALSE(streamResult2.hasError());
    ASSERT_TRUE(streamResult2.has_value());
    auto* stream2 = streamResult2.value();
    ASSERT_NE(stream2, nullptr);
    stream2->sendState = StreamSendState::Closed;
    stream2->recvState = StreamRecvState::Closed;
    ASSERT_FALSE(manager.removeClosedStream(stream2->id).hasError());
  }
  auto update = manager.remoteBidirectionalStreamLimitUpdate();
  ASSERT_TRUE(update.has_value());
  EXPECT_EQ(update.value(), 125);
  EXPECT_FALSE(manager.remoteBidirectionalStreamLimitUpdate());

  update = manager.remoteUnidirectionalStreamLimitUpdate();
  ASSERT_TRUE(update.has_value());
  EXPECT_EQ(update.value(), 125);
  EXPECT_FALSE(manager.remoteUnidirectionalStreamLimitUpdate());
}

TEST_P(QuicStreamManagerTest, StreamLimitNoWindowedUpdate) {
  auto& manager = *conn.streamManager;
  conn.transportSettings.advertisedInitialMaxStreamsBidi = 100;
  ASSERT_FALSE(
      manager.refreshTransportSettings(conn.transportSettings).hasError());
  manager.setStreamLimitWindowingFraction(4);
  for (int i = 0; i < 100; i++) {
    ASSERT_FALSE(manager.getStream(i * detail::kStreamIncrement).hasError());
  }
  for (int i = 0; i < 24; i++) {
    auto streamResult = manager.getStream(i * detail::kStreamIncrement);
    ASSERT_FALSE(streamResult.hasError());
    ASSERT_TRUE(streamResult.has_value());
    auto* stream = streamResult.value();
    ASSERT_NE(stream, nullptr);
    stream->sendState = StreamSendState::Closed;
    stream->recvState = StreamRecvState::Closed;
    ASSERT_FALSE(manager.removeClosedStream(stream->id).hasError());
  }
  auto update = manager.remoteBidirectionalStreamLimitUpdate();
  EXPECT_FALSE(update.has_value());
}

TEST_P(QuicStreamManagerTest, StreamLimitManyWindowedUpdate) {
  auto& manager = *conn.streamManager;
  conn.transportSettings.advertisedInitialMaxStreamsBidi = 100;
  ASSERT_FALSE(
      manager.refreshTransportSettings(conn.transportSettings).hasError());
  manager.setStreamLimitWindowingFraction(4);
  for (int i = 0; i < 100; i++) {
    ASSERT_FALSE(manager.getStream(i * detail::kStreamIncrement).hasError());
  }
  for (int i = 0; i < 50; i++) {
    auto streamResult = manager.getStream(i * detail::kStreamIncrement);
    ASSERT_FALSE(streamResult.hasError());
    ASSERT_TRUE(streamResult.has_value());
    auto* stream = streamResult.value();
    ASSERT_NE(stream, nullptr);
    stream->sendState = StreamSendState::Closed;
    stream->recvState = StreamRecvState::Closed;
    ASSERT_FALSE(manager.removeClosedStream(stream->id).hasError());
  }
  auto update = manager.remoteBidirectionalStreamLimitUpdate();
  ASSERT_TRUE(update.has_value());
  EXPECT_EQ(update.value(), 150);
  EXPECT_FALSE(manager.remoteBidirectionalStreamLimitUpdate());
  EXPECT_FALSE(manager.remoteUnidirectionalStreamLimitUpdate());
}

TEST_P(QuicStreamManagerTest, StreamLimitIncrementBidi) {
  auto& manager = *conn.streamManager;
  ASSERT_TRUE(manager.setMaxLocalBidirectionalStreams(100, true).has_value());
  ASSERT_TRUE(
      manager.refreshTransportSettings(conn.transportSettings).has_value());
  StreamId max;
  for (int i = 0; i < 100; i++) {
    auto result = manager.createNextBidirectionalStream();
    ASSERT_TRUE(result.has_value());
    max = result.value()->id;
  }
  auto errorResult = manager.createNextBidirectionalStream();
  EXPECT_TRUE(errorResult.hasError());
  EXPECT_EQ(errorResult.error(), LocalErrorCode::STREAM_LIMIT_EXCEEDED);

  ASSERT_TRUE(manager.setMaxLocalBidirectionalStreams(200).has_value());
  auto s = manager.createNextBidirectionalStream();
  EXPECT_TRUE(s.has_value());
  EXPECT_EQ(s.value()->id, max + detail::kStreamIncrement);
}

TEST_P(QuicStreamManagerTest, ConsumeStopSending) {
  auto& manager = *conn.streamManager;
  manager.addStopSending(0, GenericApplicationErrorCode::NO_ERROR);
  EXPECT_EQ(manager.stopSendingStreams().size(), 1);
  auto result = manager.consumeStopSending();
  ASSERT_EQ(result.size(), 1);
  EXPECT_EQ(result.front().first, 0);
  EXPECT_EQ(result.front().second, GenericApplicationErrorCode::NO_ERROR);
  EXPECT_TRUE(manager.stopSendingStreams().empty());
}

TEST_P(QuicStreamManagerTest, StreamLimitIncrementUni) {
  auto& manager = *conn.streamManager;
  ASSERT_TRUE(manager.setMaxLocalUnidirectionalStreams(100, true).has_value());
  ASSERT_TRUE(
      manager.refreshTransportSettings(conn.transportSettings).has_value());
  StreamId max;
  for (int i = 0; i < 100; i++) {
    auto result = manager.createNextUnidirectionalStream();
    ASSERT_TRUE(result.has_value());
    max = result.value()->id;
  }
  auto errorResult = manager.createNextUnidirectionalStream();
  EXPECT_TRUE(errorResult.hasError());
  EXPECT_EQ(errorResult.error(), LocalErrorCode::STREAM_LIMIT_EXCEEDED);

  ASSERT_TRUE(manager.setMaxLocalUnidirectionalStreams(200).has_value());
  auto s = manager.createNextUnidirectionalStream();
  EXPECT_TRUE(s.has_value());
  EXPECT_EQ(s.value()->id, max + detail::kStreamIncrement);
}

TEST_P(QuicStreamManagerTest, NextAcceptableLocalUnidirectionalStreamId) {
  auto& manager = *conn.streamManager;

  const StreamId serverStreamId1 = 0x03;
  const StreamId serverStreamId2 = serverStreamId1 + detail::kStreamIncrement;
  const StreamId serverStreamId3 =
      serverStreamId1 + (detail::kStreamIncrement * 2);

  EXPECT_EQ(
      serverStreamId1, manager.nextAcceptableLocalUnidirectionalStreamId());

  ASSERT_TRUE(manager.createStream(serverStreamId1).has_value());
  EXPECT_EQ(
      serverStreamId2, manager.nextAcceptableLocalUnidirectionalStreamId());

  ASSERT_TRUE(manager.createStream(serverStreamId2).has_value());
  EXPECT_EQ(
      serverStreamId3, manager.nextAcceptableLocalUnidirectionalStreamId());
}

TEST_P(QuicStreamManagerTest, NextAcceptableLocalBidirectionalStreamId) {
  auto& manager = *conn.streamManager;

  const StreamId serverStreamId1 = 0x01;
  const StreamId serverStreamId2 = serverStreamId1 + detail::kStreamIncrement;
  const StreamId serverStreamId3 =
      serverStreamId1 + (detail::kStreamIncrement * 2);

  EXPECT_EQ(
      serverStreamId1, manager.nextAcceptableLocalBidirectionalStreamId());

  ASSERT_TRUE(manager.createStream(serverStreamId1).has_value());
  EXPECT_EQ(
      serverStreamId2, manager.nextAcceptableLocalBidirectionalStreamId());

  ASSERT_TRUE(manager.createStream(serverStreamId2).has_value());
  EXPECT_EQ(
      serverStreamId3, manager.nextAcceptableLocalBidirectionalStreamId());
}

TEST_P(QuicStreamManagerTest, NextAcceptableLocalUnidirectionalStreamIdLimit) {
  auto& manager = *conn.streamManager;
  ASSERT_TRUE(manager.setMaxLocalUnidirectionalStreams(2, true).has_value());

  const StreamId serverStreamId1 = 0x03;
  const StreamId serverStreamId2 = serverStreamId1 + detail::kStreamIncrement;

  EXPECT_EQ(
      serverStreamId1, manager.nextAcceptableLocalUnidirectionalStreamId());

  ASSERT_TRUE(manager.createStream(serverStreamId1).has_value());
  EXPECT_EQ(
      serverStreamId2, manager.nextAcceptableLocalUnidirectionalStreamId());

  ASSERT_TRUE(manager.createStream(serverStreamId2).has_value());
  EXPECT_EQ(std::nullopt, manager.nextAcceptableLocalUnidirectionalStreamId());
}

TEST_P(QuicStreamManagerTest, NextAcceptableLocalBidirectionalStreamIdLimit) {
  auto& manager = *conn.streamManager;
  ASSERT_TRUE(manager.setMaxLocalBidirectionalStreams(2, true).has_value());

  const StreamId serverStreamId1 = 0x01;
  const StreamId serverStreamId2 = serverStreamId1 + detail::kStreamIncrement;

  EXPECT_EQ(
      serverStreamId1, manager.nextAcceptableLocalBidirectionalStreamId());

  ASSERT_TRUE(manager.createStream(serverStreamId1).has_value());
  EXPECT_EQ(
      serverStreamId2, manager.nextAcceptableLocalBidirectionalStreamId());

  ASSERT_TRUE(manager.createStream(serverStreamId2).has_value());
  EXPECT_EQ(std::nullopt, manager.nextAcceptableLocalBidirectionalStreamId());
}

TEST_P(QuicStreamManagerTest, NextAcceptablePeerUnidirectionalStreamId) {
  auto& manager = *conn.streamManager;

  const StreamId clientStreamId1 = 0x02;
  const StreamId clientStreamId2 = clientStreamId1 + detail::kStreamIncrement;
  const StreamId clientStreamId3 =
      clientStreamId1 + (detail::kStreamIncrement * 2);

  EXPECT_EQ(
      clientStreamId1, manager.nextAcceptablePeerUnidirectionalStreamId());

  ASSERT_TRUE(manager.getStream(clientStreamId1).has_value());
  EXPECT_EQ(
      clientStreamId2, manager.nextAcceptablePeerUnidirectionalStreamId());

  ASSERT_TRUE(manager.getStream(clientStreamId2).has_value());
  EXPECT_EQ(
      clientStreamId3, manager.nextAcceptablePeerUnidirectionalStreamId());
}

TEST_P(QuicStreamManagerTest, NextAcceptablePeerBidirectionalStreamId) {
  auto& manager = *conn.streamManager;

  const StreamId clientStreamId1 = 0x00;
  const StreamId clientStreamId2 = clientStreamId1 + detail::kStreamIncrement;
  const StreamId clientStreamId3 =
      clientStreamId1 + (detail::kStreamIncrement * 2);

  EXPECT_EQ(clientStreamId1, manager.nextAcceptablePeerBidirectionalStreamId());

  ASSERT_TRUE(manager.getStream(clientStreamId1).has_value());
  EXPECT_EQ(clientStreamId2, manager.nextAcceptablePeerBidirectionalStreamId());

  ASSERT_TRUE(manager.getStream(clientStreamId2).has_value());
  EXPECT_EQ(clientStreamId3, manager.nextAcceptablePeerBidirectionalStreamId());
}

TEST_P(QuicStreamManagerTest, NextAcceptablePeerUnidirectionalStreamIdLimit) {
  auto& manager = *conn.streamManager;
  conn.transportSettings.advertisedInitialMaxStreamsUni = 2;
  ASSERT_TRUE(
      manager.refreshTransportSettings(conn.transportSettings).has_value());

  const StreamId clientStreamId1 = 0x02;
  const StreamId clientStreamId2 = clientStreamId1 + detail::kStreamIncrement;

  EXPECT_EQ(
      clientStreamId1, manager.nextAcceptablePeerUnidirectionalStreamId());

  ASSERT_TRUE(manager.getStream(clientStreamId1).has_value());
  EXPECT_EQ(
      clientStreamId2, manager.nextAcceptablePeerUnidirectionalStreamId());

  ASSERT_TRUE(manager.getStream(clientStreamId2).has_value());
  EXPECT_EQ(std::nullopt, manager.nextAcceptablePeerUnidirectionalStreamId());
}

TEST_P(QuicStreamManagerTest, NextAcceptablePeerBidirectionalStreamIdLimit) {
  auto& manager = *conn.streamManager;
  conn.transportSettings.advertisedInitialMaxStreamsBidi = 2;
  ASSERT_TRUE(
      manager.refreshTransportSettings(conn.transportSettings).has_value());

  const StreamId clientStreamId1 = 0x00;
  const StreamId clientStreamId2 = clientStreamId1 + detail::kStreamIncrement;

  EXPECT_EQ(clientStreamId1, manager.nextAcceptablePeerBidirectionalStreamId());

  ASSERT_TRUE(manager.getStream(clientStreamId1).has_value());
  EXPECT_EQ(clientStreamId2, manager.nextAcceptablePeerBidirectionalStreamId());

  ASSERT_TRUE(manager.getStream(clientStreamId2).has_value());
  EXPECT_EQ(std::nullopt, manager.nextAcceptablePeerBidirectionalStreamId());
}

TEST_P(QuicStreamManagerTest, TestClearActionable) {
  auto& manager = *conn.streamManager;

  StreamId id = 1;
  auto stream = manager.createNextUnidirectionalStream().value();

  stream->readBuffer.emplace_back(folly::IOBuf::copyBuffer("blah blah"), 0);
  manager.queueFlowControlUpdated(id);
  manager.addDeliverable(id);
  manager.updateReadableStreams(*stream);
  manager.updatePeekableStreams(*stream);
  EXPECT_TRUE(manager.flowControlUpdatedContains(id));
  EXPECT_TRUE(manager.deliverableContains(id));
  EXPECT_FALSE(manager.readableStreams().empty());

  EXPECT_FALSE(manager.peekableStreams().empty());
  manager.clearActionable();
  EXPECT_FALSE(manager.flowControlUpdatedContains(id));
  EXPECT_FALSE(manager.deliverableContains(id));
  EXPECT_TRUE(manager.readableStreams().empty());

  EXPECT_TRUE(manager.peekableStreams().empty());
}

TEST_P(QuicStreamManagerTest, TestUnidirectionalStreamsSeparateSet) {
  conn.transportSettings.unidirectionalStreamsReadCallbacksFirst = true;
  auto& manager = *conn.streamManager;

  auto streamResult = manager.createNextUnidirectionalStream();
  ASSERT_TRUE(streamResult.has_value());
  auto* stream = streamResult.value();
  StreamId id = stream->id; // Use the actual stream ID

  stream->readBuffer.emplace_back(folly::IOBuf::copyBuffer("blah blah"), 0);
  manager.queueFlowControlUpdated(id);
  manager.addDeliverable(id);
  manager.updateReadableStreams(*stream);
  manager.updatePeekableStreams(*stream);

  EXPECT_TRUE(manager.flowControlUpdatedContains(id));
  EXPECT_TRUE(manager.deliverableContains(id));
  EXPECT_TRUE(manager.readableStreams().empty());
  EXPECT_FALSE(manager.readableUnidirectionalStreams().empty());
  EXPECT_FALSE(manager.peekableStreams().empty());
  manager.clearActionable();
  EXPECT_FALSE(manager.flowControlUpdatedContains(id));
  EXPECT_FALSE(manager.deliverableContains(id));
  EXPECT_TRUE(manager.readableStreams().empty());
  EXPECT_TRUE(manager.readableUnidirectionalStreams()
                  .empty()); // Both should be cleared
  EXPECT_TRUE(manager.peekableStreams().empty());
}

TEST_P(
    QuicStreamManagerTest,
    TestUnidirectionalStreamsSeparateSetRemoveStream) {
  conn.transportSettings.unidirectionalStreamsReadCallbacksFirst = true;
  auto& manager = *conn.streamManager;

  auto streamResult = manager.createNextUnidirectionalStream();
  ASSERT_TRUE(streamResult.has_value());
  auto* stream = streamResult.value();

  stream->readBuffer.emplace_back(folly::IOBuf::copyBuffer("blah blah"), 0);
  manager.updateReadableStreams(*stream);
  manager.updatePeekableStreams(*stream);

  EXPECT_TRUE(manager.readableStreams().empty());
  EXPECT_FALSE(manager.readableUnidirectionalStreams().empty());
  EXPECT_FALSE(manager.peekableStreams().empty());

  // Remove data from stream.
  stream->readBuffer.clear();
  manager.updateReadableStreams(*stream);

  EXPECT_TRUE(manager.readableStreams().empty());
  EXPECT_TRUE(manager.readableUnidirectionalStreams().empty());
}

TEST_P(QuicStreamManagerTest, TestUnidirectionalStreamsSeparateSetTwoStreams) {
  conn.transportSettings.unidirectionalStreamsReadCallbacksFirst = true;
  auto& manager = *conn.streamManager;

  auto streamResult = manager.createNextBidirectionalStream();
  ASSERT_TRUE(streamResult.has_value());
  auto* stream = streamResult.value();

  stream->readBuffer.emplace_back(
      folly::IOBuf::copyBuffer("and i'm headers"), 0);

  manager.updateReadableStreams(*stream);
  manager.updatePeekableStreams(*stream);

  EXPECT_EQ(manager.readableStreams().size(), 1);
  EXPECT_EQ(manager.readableUnidirectionalStreams().size(), 0);

  auto streamResult2 = manager.createNextUnidirectionalStream();
  ASSERT_TRUE(streamResult2.has_value());
  auto* stream2 = streamResult2.value();

  stream2->readBuffer.emplace_back(
      folly::IOBuf::copyBuffer("look at me, i am qpack data"), 0);

  manager.updateReadableStreams(*stream2);
  manager.updatePeekableStreams(*stream2);

  EXPECT_EQ(manager.readableStreams().size(), 1);
  EXPECT_EQ(manager.readableUnidirectionalStreams().size(), 1);
}

TEST_P(QuicStreamManagerTest, RemoveResetsUponClosure) {
  auto& manager = *conn.streamManager;
  auto streamResult = manager.createNextBidirectionalStream();
  ASSERT_TRUE(streamResult.has_value());
  auto* stream = streamResult.value();

  auto streamId = stream->id;
  conn.pendingEvents.resets.emplace(
      streamId,
      RstStreamFrame(streamId, GenericApplicationErrorCode::NO_ERROR, 0));
  stream->sendState = StreamSendState::Closed;
  stream->recvState = StreamRecvState::Closed;

  EXPECT_TRUE(conn.pendingEvents.resets.contains(streamId));
  ASSERT_FALSE(manager.removeClosedStream(streamId).hasError());
  EXPECT_FALSE(conn.pendingEvents.resets.contains(streamId));
}

BufPtr createBuffer(uint32_t len) {
  auto buf = folly::IOBuf::create(len);
  buf->append(len);
  return buf;
}

TEST_P(QuicStreamManagerTest, TestReliableResetBasic) {
  auto& manager = *conn.streamManager;

  auto maybeQuicStreamState = manager.createNextBidirectionalStream();
  ASSERT_TRUE(maybeQuicStreamState.has_value());
  auto* quicStreamState = maybeQuicStreamState.value();

  // Assume we've written out 5 bytes to the wire already, and have
  // received acknowledgements for the same.
  quicStreamState->writeBufferStartOffset = 5;
  quicStreamState->currentWriteOffset = 5;
  quicStreamState->ackedIntervals.insert(0, 4);

  // Assume that the application has written an additional 8 bytes to
  // the transport layer
  auto buf = createBuffer(8);
  quicStreamState->pendingWrites = ChainedByteRangeHead(buf->clone());
  quicStreamState->writeBuffer.append(std::move(buf));
  ASSERT_FALSE(
      updateFlowControlOnWriteToStream(*quicStreamState, 8).hasError());

  // A frame of length 4 has been written to the wire
  quicStreamState->currentWriteOffset += 4;
  ChainedByteRangeHead bufWritten1(
      quicStreamState->pendingWrites.splitAtMost(4));
  quicStreamState->retransmissionBuffer.emplace(
      std::piecewise_construct,
      std::forward_as_tuple(5),
      std::forward_as_tuple(
          std::make_unique<WriteStreamBuffer>(
              std::move(bufWritten1), 5, false)));
  ASSERT_FALSE(
      updateFlowControlOnWriteToSocket(*quicStreamState, 4).hasError());

  // A frame of length 2 has been written to the wire
  quicStreamState->currentWriteOffset += 2;
  ChainedByteRangeHead bufWritten2(
      quicStreamState->pendingWrites.splitAtMost(2));
  quicStreamState->retransmissionBuffer.emplace(
      std::piecewise_construct,
      std::forward_as_tuple(9),
      std::forward_as_tuple(
          std::make_unique<WriteStreamBuffer>(
              std::move(bufWritten2), 9, false)));
  ASSERT_FALSE(
      updateFlowControlOnWriteToSocket(*quicStreamState, 2).hasError());

  // The frame of length 4 has been lost
  auto bufferItr = quicStreamState->retransmissionBuffer.find(5);
  ASSERT_NE(bufferItr, quicStreamState->retransmissionBuffer.end());
  quicStreamState->insertIntoLossBuffer(std::move(bufferItr->second));
  quicStreamState->retransmissionBuffer.erase(bufferItr);

  // We send a reliable reset with a reliable size of 7
  ASSERT_FALSE(resetQuicStream(
                   *quicStreamState, GenericApplicationErrorCode::NO_ERROR, 7)
                   .hasError());

  EXPECT_EQ(quicStreamState->writeBuffer.chainLength(), 2);
  EXPECT_EQ(quicStreamState->pendingWrites.chainLength(), 0);
  EXPECT_TRUE(quicStreamState->retransmissionBuffer.empty());
  EXPECT_EQ(quicStreamState->lossBuffer.size(), 1);
  EXPECT_EQ(quicStreamState->lossBuffer[0].offset, 5);
  EXPECT_EQ(quicStreamState->lossBuffer[0].data.chainLength(), 2);
  EXPECT_EQ(quicStreamState->conn.flowControlState.sumCurStreamBufferLen, 0);

  // We send a reliable reset with a reliable size of 6
  ASSERT_FALSE(resetQuicStream(
                   *quicStreamState, GenericApplicationErrorCode::NO_ERROR, 6)
                   .hasError());

  EXPECT_EQ(quicStreamState->writeBuffer.chainLength(), 1);
  EXPECT_EQ(quicStreamState->pendingWrites.chainLength(), 0);
  EXPECT_TRUE(quicStreamState->retransmissionBuffer.empty());
  EXPECT_EQ(quicStreamState->lossBuffer.size(), 1);
  EXPECT_EQ(quicStreamState->lossBuffer[0].offset, 5);
  EXPECT_EQ(quicStreamState->lossBuffer[0].data.chainLength(), 1);
  EXPECT_EQ(quicStreamState->conn.flowControlState.sumCurStreamBufferLen, 0);
}

INSTANTIATE_TEST_SUITE_P(
    QuicStreamManagerTest,
    QuicStreamManagerTest,
    ::testing::Values(
        StreamManagerTestParam{false, false}, // isUnidirectional = false
        StreamManagerTestParam{true, false})); // isUnidirectional = false

class QuicStreamManagerGroupsTest : public QuicStreamManagerTest {
 public:
  auto createNextStreamGroup() {
    auto& manager = *conn.streamManager;
    const bool isUnidirectional = GetParam().isUnidirectional;
    return isUnidirectional ? manager.createNextUnidirectionalStreamGroup()
                            : manager.createNextBidirectionalStreamGroup();
  }

  auto getNumGroups() {
    auto& manager = *conn.streamManager;
    const bool isUnidirectional = GetParam().isUnidirectional;
    return isUnidirectional ? manager.getNumUnidirectionalGroups()
                            : manager.getNumBidirectionalGroups();
  }

  // Helper now returns the Expected from the underlying manager call
  auto createNextStreamInGroup(StreamGroupId groupId) {
    auto& manager = *conn.streamManager;
    const bool isUnidirectional = GetParam().isUnidirectional;
    return isUnidirectional ? manager.createNextUnidirectionalStream(groupId)
                            : manager.createNextBidirectionalStream(groupId);
  }
};

TEST_P(QuicStreamManagerGroupsTest, TestStreamGroupLimits) {
  auto& manager = *conn.streamManager;

  // By default, no group creation happening.
  auto groupIdResult = createNextStreamGroup();
  EXPECT_TRUE(groupIdResult.hasError()); // Expect limit exceeded error
  EXPECT_EQ(groupIdResult.error(), LocalErrorCode::STREAM_LIMIT_EXCEEDED);
  EXPECT_EQ(getNumGroups(), 0);

  // Bump group limits.
  conn.transportSettings.advertisedMaxStreamGroups = 1;
  ASSERT_TRUE(
      manager.refreshTransportSettings(conn.transportSettings).has_value());
  groupIdResult = createNextStreamGroup();
  EXPECT_TRUE(groupIdResult.has_value());
  EXPECT_EQ(getNumGroups(), 1);

  // Try again and it should fail running over the limit.
  groupIdResult = createNextStreamGroup();
  EXPECT_TRUE(groupIdResult.hasError());
  EXPECT_EQ(groupIdResult.error(), LocalErrorCode::STREAM_LIMIT_EXCEEDED);
  EXPECT_EQ(getNumGroups(), 1);
}

TEST_P(QuicStreamManagerGroupsTest, TestStreamsCreationInGroupsNoGroup) {
  auto& manager = *conn.streamManager;
  conn.transportSettings.advertisedMaxStreamGroups = 16;
  ASSERT_TRUE(
      manager.refreshTransportSettings(conn.transportSettings).has_value());

  StreamGroupId nonExistentGroupId = GetParam().isUnidirectional ? 3 : 1;
  auto streamResult = createNextStreamInGroup(nonExistentGroupId);
  // Should fail because group doesn't exist
  EXPECT_TRUE(streamResult.hasError());
  EXPECT_EQ(getNumGroups(), 0);
}

TEST_P(QuicStreamManagerGroupsTest, TestStreamsCreationInGroupsWrongNodeType) {
  auto& manager = *conn.streamManager;
  conn.transportSettings.advertisedMaxStreamGroups = 16;
  ASSERT_TRUE(
      manager.refreshTransportSettings(conn.transportSettings).has_value());

  // Create a valid group first
  auto groupResult = createNextStreamGroup();
  ASSERT_TRUE(groupResult.has_value());

  // Try to create stream with wrong type of group ID (Client ID on Server)
  StreamGroupId wrongTypeGroupId = GetParam().isUnidirectional ? 2 : 0;
  auto streamResult = createNextStreamInGroup(wrongTypeGroupId);
  // Should fail because group ID type mismatch
  EXPECT_TRUE(streamResult.hasError());
}

TEST_P(QuicStreamManagerGroupsTest, TestStreamsCreationInGroupsSuccess) {
  auto& manager = *conn.streamManager;
  conn.transportSettings.advertisedMaxStreamGroups = 16;
  ASSERT_TRUE(
      manager.refreshTransportSettings(conn.transportSettings).has_value());

  auto groupIdResult = createNextStreamGroup();
  ASSERT_TRUE(groupIdResult.has_value());
  EXPECT_EQ(getNumGroups(), 1);

  auto streamResult = createNextStreamInGroup(*groupIdResult);
  EXPECT_TRUE(streamResult.has_value());
}

TEST_P(QuicStreamManagerGroupsTest, TestPeerStreamsWithGroupDisabled) {
  auto& manager = *conn.streamManager;

  const StreamId peerStreamId = GetParam().isUnidirectional ? 2 : 0;
  const StreamGroupId peerGroupId = GetParam().isUnidirectional ? 2 : 0;
  // getStream should fail because groups are disabled by default (max=0)
  auto streamResult = manager.getStream(peerStreamId, peerGroupId);
  EXPECT_TRUE(streamResult.hasError());
  EXPECT_EQ(
      streamResult.error().code,
      TransportErrorCode::STREAM_LIMIT_ERROR); // Or FEATURE?
}

TEST_P(QuicStreamManagerGroupsTest, TestPeerStreamsWithGroup) {
  auto& manager = *conn.streamManager;
  conn.transportSettings.advertisedMaxStreamGroups = 16;
  ASSERT_TRUE(
      manager.refreshTransportSettings(conn.transportSettings).has_value());

  const StreamId peerStreamId = GetParam().isUnidirectional ? 2 : 0;
  const StreamGroupId peerGroupId = GetParam().isUnidirectional ? 2 : 0;
  auto streamResult = manager.getStream(peerStreamId, peerGroupId);
  ASSERT_TRUE(streamResult.has_value());
  auto* stream = streamResult.value();
  EXPECT_NE(stream, nullptr);
  ASSERT_TRUE(stream->groupId.has_value());
  EXPECT_EQ(stream->groupId.value(), peerGroupId);
}

TEST_P(QuicStreamManagerGroupsTest, TestPeerStreamsWithGroupBadGroupId) {
  auto& manager = *conn.streamManager;
  conn.transportSettings.advertisedMaxStreamGroups = 16;
  ASSERT_TRUE(
      manager.refreshTransportSettings(conn.transportSettings).has_value());

  const StreamId peerStreamId = GetParam().isUnidirectional ? 2 : 0;
  // Server group ID when peer is Client (or vice versa)
  const StreamGroupId badPeerGroupId = GetParam().isUnidirectional ? 3 : 1;
  auto streamResult = manager.getStream(peerStreamId, badPeerGroupId);
  // Expect to fail because group id is wrong type for peer
  EXPECT_TRUE(streamResult.hasError());
  EXPECT_EQ(streamResult.error().code, TransportErrorCode::STREAM_STATE_ERROR);
}

TEST_P(QuicStreamManagerGroupsTest, TestPeerStreamsWithGroupAccounting) {
  auto& manager = *conn.streamManager;
  conn.transportSettings.advertisedMaxStreamGroups = 16;
  ASSERT_TRUE(
      manager.refreshTransportSettings(conn.transportSettings).has_value());

  StreamId peerStreamId = GetParam().isUnidirectional ? 2 : 0;
  StreamGroupId peerGroupId = GetParam().isUnidirectional ? 2 : 0;
  auto streamResult = manager.getStream(peerStreamId, peerGroupId);
  ASSERT_TRUE(streamResult.has_value());
  auto* stream = streamResult.value();
  EXPECT_NE(stream, nullptr);
  ASSERT_TRUE(stream->groupId.has_value());
  EXPECT_EQ(stream->groupId.value(), peerGroupId);
  EXPECT_EQ(manager.getNumNewPeerStreamGroups(), 1);
  EXPECT_EQ(manager.getNumPeerStreamGroupsSeen(), 1);

  // Another stream, same group.
  peerStreamId += detail::kStreamIncrement;
  streamResult = manager.getStream(peerStreamId, peerGroupId);
  ASSERT_TRUE(streamResult.has_value());
  stream = streamResult.value();
  EXPECT_NE(stream, nullptr);
  ASSERT_TRUE(stream->groupId.has_value());
  EXPECT_EQ(stream->groupId.value(), peerGroupId);
  EXPECT_EQ(manager.getNumNewPeerStreamGroups(), 1); // Still 1 new group
  EXPECT_EQ(manager.getNumPeerStreamGroupsSeen(), 1); // Still 1 group seen

  // New stream, new group.
  peerStreamId += detail::kStreamIncrement;
  peerGroupId += detail::kStreamGroupIncrement;
  streamResult = manager.getStream(peerStreamId, peerGroupId);
  ASSERT_TRUE(streamResult.has_value());
  stream = streamResult.value();
  EXPECT_NE(stream, nullptr);
  ASSERT_TRUE(stream->groupId.has_value());
  EXPECT_EQ(stream->groupId.value(), peerGroupId);
  EXPECT_EQ(manager.getNumNewPeerStreamGroups(), 2); // Now 2 new groups
  EXPECT_EQ(manager.getNumPeerStreamGroupsSeen(), 2); // Now 2 groups seen

  // New stream, previous group.
  peerStreamId += detail::kStreamIncrement;
  peerGroupId = GetParam().isUnidirectional ? 2 : 0; // Go back to first group
  streamResult = manager.getStream(peerStreamId, peerGroupId);
  ASSERT_TRUE(streamResult.has_value());
  stream = streamResult.value();
  EXPECT_NE(stream, nullptr);
  ASSERT_TRUE(stream->groupId.has_value());
  EXPECT_EQ(stream->groupId.value(), peerGroupId);
  EXPECT_EQ(
      manager.getNumNewPeerStreamGroups(), 2); // Still 2 new groups notified
  EXPECT_EQ(
      manager.getNumPeerStreamGroupsSeen(),
      2); // Still only 2 groups seen total

  // New stream, current group.
  peerStreamId += detail::kStreamIncrement;
  peerGroupId = GetParam().isUnidirectional ? 6 : 4; // Go back to second group
  streamResult = manager.getStream(peerStreamId, peerGroupId);
  ASSERT_TRUE(streamResult.has_value());
  stream = streamResult.value();
  EXPECT_NE(stream, nullptr);
  ASSERT_TRUE(stream->groupId.has_value());
  EXPECT_EQ(stream->groupId.value(), peerGroupId);
  EXPECT_EQ(manager.getNumNewPeerStreamGroups(), 2);
  EXPECT_EQ(manager.getNumPeerStreamGroupsSeen(), 2);
}

INSTANTIATE_TEST_SUITE_P(
    QuicStreamManagerGroupsTest,
    QuicStreamManagerGroupsTest,
    ::testing::Values(
        StreamManagerTestParam{true, false},
        StreamManagerTestParam{true, true}));

} // namespace quic::test
