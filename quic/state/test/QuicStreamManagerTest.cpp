/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <quic/fizz/server/handshake/FizzServerQuicHandshakeContext.h>
#include <quic/server/state/ServerStateMachine.h>
#include <quic/state/QuicPriorityQueue.h>
#include <quic/state/QuicStreamManager.h>
#include <quic/state/QuicStreamUtilities.h>
#include <quic/state/test/Mocks.h>

using namespace testing;

namespace quic {
namespace test {

struct StreamManagerTestParam {
  bool notifyOnNewStreamsExplicitly;
  bool isUnidirectional;
};

class QuicStreamManagerTest
    : public Test,
      public WithParamInterface<StreamManagerTestParam> {
 public:
  QuicStreamManagerTest()
      : conn(FizzServerQuicHandshakeContext::Builder().build()) {}
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

    conn.transportSettings.notifyOnNewStreamsExplicitly =
        GetParam().notifyOnNewStreamsExplicitly;
    conn.streamManager->refreshTransportSettings(conn.transportSettings);
  }

  QuicServerConnectionState conn;
  MockCongestionController* mockController;
};

TEST_P(QuicStreamManagerTest, SkipRedundantPriorityUpdate) {
  auto& manager = *conn.streamManager;
  auto stream = manager.createNextBidirectionalStream();
  auto streamId = stream.value()->id;
  Priority currentPriority = stream.value()->priority;
  EXPECT_TRUE(manager.setStreamPriority(
      streamId,
      (currentPriority.level + 1) % (kDefaultMaxPriority + 1),
      !currentPriority.incremental));
  EXPECT_FALSE(manager.setStreamPriority(
      streamId,
      (currentPriority.level + 1) % (kDefaultMaxPriority + 1),
      !currentPriority.incremental));
}

TEST_P(QuicStreamManagerTest, TestAppIdleCreateBidiStream) {
  auto& manager = *conn.streamManager;
  EXPECT_FALSE(manager.isAppIdle());

  // The app limiited state did not change.
  EXPECT_CALL(*mockController, setAppIdle(false, _)).Times(0);
  auto stream = manager.createNextBidirectionalStream();
  StreamId id = stream.value()->id;
  EXPECT_FALSE(manager.isAppIdle());

  EXPECT_CALL(*mockController, setAppIdle(true, _));
  // Force transition to closed state
  stream.value()->sendState = StreamSendState::Closed;
  stream.value()->recvState = StreamRecvState::Closed;
  manager.removeClosedStream(stream.value()->id);
  EXPECT_TRUE(manager.isAppIdle());
  EXPECT_EQ(manager.getStream(id), nullptr);
}

TEST_P(QuicStreamManagerTest, TestAppIdleCreateUnidiStream) {
  auto& manager = *conn.streamManager;
  EXPECT_FALSE(manager.isAppIdle());
  EXPECT_CALL(*mockController, setAppIdle(false, _)).Times(0);
  auto stream = manager.createNextUnidirectionalStream();
  EXPECT_FALSE(manager.isAppIdle());

  // Force transition to closed state
  EXPECT_CALL(*mockController, setAppIdle(true, _));
  stream.value()->sendState = StreamSendState::Closed;
  stream.value()->recvState = StreamRecvState::Closed;
  manager.removeClosedStream(stream.value()->id);
  EXPECT_TRUE(manager.isAppIdle());
}

TEST_P(QuicStreamManagerTest, TestAppIdleExistingLocalStream) {
  auto& manager = *conn.streamManager;
  EXPECT_FALSE(manager.isAppIdle());
  EXPECT_CALL(*mockController, setAppIdle(false, _)).Times(0);

  auto stream = manager.createNextUnidirectionalStream();
  EXPECT_FALSE(manager.isAppIdle());

  EXPECT_CALL(*mockController, setAppIdle(true, _));
  manager.setStreamAsControl(*stream.value());
  EXPECT_TRUE(manager.isAppIdle());

  manager.getStream(stream.value()->id);
  EXPECT_TRUE(manager.isAppIdle());
}

TEST_P(QuicStreamManagerTest, TestAppIdleStreamAsControl) {
  auto& manager = *conn.streamManager;
  EXPECT_FALSE(manager.isAppIdle());

  auto stream = manager.createNextUnidirectionalStream();
  EXPECT_FALSE(manager.isAppIdle());

  EXPECT_CALL(*mockController, setAppIdle(true, _));
  manager.setStreamAsControl(*stream.value());
  EXPECT_TRUE(manager.isAppIdle());

  EXPECT_CALL(*mockController, setAppIdle(false, _));
  manager.createNextUnidirectionalStream();
  EXPECT_FALSE(manager.isAppIdle());
}

TEST_P(QuicStreamManagerTest, TestAppIdleCreatePeerStream) {
  auto& manager = *conn.streamManager;
  EXPECT_FALSE(manager.isAppIdle());
  StreamId id = 0;
  auto stream = manager.getStream(id);
  EXPECT_FALSE(manager.isAppIdle());

  EXPECT_CALL(*mockController, setAppIdle(true, _));
  manager.setStreamAsControl(*stream);
  EXPECT_TRUE(manager.isAppIdle());

  EXPECT_CALL(*mockController, setAppIdle(false, _));
  StreamId id2 = 4;
  manager.getStream(id2);
  EXPECT_FALSE(manager.isAppIdle());
}

TEST_P(QuicStreamManagerTest, TestAppIdleExistingPeerStream) {
  auto& manager = *conn.streamManager;
  EXPECT_FALSE(manager.isAppIdle());
  EXPECT_CALL(*mockController, setAppIdle(false, _)).Times(0);

  StreamId id = 0;
  auto stream = manager.getStream(id);
  EXPECT_FALSE(manager.isAppIdle());

  EXPECT_CALL(*mockController, setAppIdle(true, _));
  manager.setStreamAsControl(*stream);
  EXPECT_TRUE(manager.isAppIdle());

  manager.getStream(id);
  EXPECT_TRUE(manager.isAppIdle());
}

TEST_P(QuicStreamManagerTest, TestAppIdleClosePeerStream) {
  auto& manager = *conn.streamManager;
  EXPECT_FALSE(manager.isAppIdle());
  StreamId id = 0;
  auto stream = manager.getStream(id);
  EXPECT_FALSE(manager.isAppIdle());

  EXPECT_CALL(*mockController, setAppIdle(true, _));
  // Force transition to closed state
  stream->sendState = StreamSendState::Closed;
  stream->recvState = StreamRecvState::Closed;
  manager.removeClosedStream(stream->id);
  EXPECT_TRUE(manager.isAppIdle());
  EXPECT_EQ(manager.getStream(id), nullptr);
}

TEST_P(QuicStreamManagerTest, TestAppIdleCloseControlStream) {
  auto& manager = *conn.streamManager;
  EXPECT_FALSE(manager.isAppIdle());
  EXPECT_CALL(*mockController, setAppIdle(false, _)).Times(0);

  StreamId id = 0;
  auto stream = manager.getStream(id);
  EXPECT_FALSE(manager.isAppIdle());

  EXPECT_CALL(*mockController, setAppIdle(true, _));
  manager.setStreamAsControl(*stream);
  EXPECT_TRUE(manager.isAppIdle());

  // Force transition to closed state
  stream->sendState = StreamSendState::Closed;
  stream->recvState = StreamRecvState::Closed;
  manager.removeClosedStream(stream->id);
  EXPECT_TRUE(manager.isAppIdle());
}

TEST_P(QuicStreamManagerTest, StreamLimitWindowedUpdate) {
  auto& manager = *conn.streamManager;
  conn.transportSettings.advertisedInitialMaxStreamsBidi = 100;
  conn.transportSettings.advertisedInitialMaxStreamsUni = 100;
  manager.refreshTransportSettings(conn.transportSettings);
  manager.setStreamLimitWindowingFraction(4);
  for (int i = 0; i < 100; i++) {
    manager.getStream(i * detail::kStreamIncrement);
    manager.getStream(2 + i * detail::kStreamIncrement);
  }
  for (int i = 0; i < 25; i++) {
    auto stream = manager.getStream(i * detail::kStreamIncrement);
    stream->sendState = StreamSendState::Closed;
    stream->recvState = StreamRecvState::Closed;
    manager.removeClosedStream(stream->id);
    stream = manager.getStream(2 + i * detail::kStreamIncrement);
    stream->sendState = StreamSendState::Closed;
    stream->recvState = StreamRecvState::Closed;
    manager.removeClosedStream(stream->id);
  }
  auto update = manager.remoteBidirectionalStreamLimitUpdate();
  ASSERT_TRUE(update);
  EXPECT_EQ(update.value(), 125);
  EXPECT_FALSE(manager.remoteBidirectionalStreamLimitUpdate());

  update = manager.remoteUnidirectionalStreamLimitUpdate();
  ASSERT_TRUE(update);
  EXPECT_EQ(update.value(), 125);
  EXPECT_FALSE(manager.remoteUnidirectionalStreamLimitUpdate());
}

TEST_P(QuicStreamManagerTest, StreamLimitNoWindowedUpdate) {
  auto& manager = *conn.streamManager;
  conn.transportSettings.advertisedInitialMaxStreamsBidi = 100;
  manager.refreshTransportSettings(conn.transportSettings);
  manager.setStreamLimitWindowingFraction(4);
  for (int i = 0; i < 100; i++) {
    manager.getStream(i * detail::kStreamIncrement);
  }
  for (int i = 0; i < 24; i++) {
    auto stream = manager.getStream(i * detail::kStreamIncrement);
    stream->sendState = StreamSendState::Closed;
    stream->recvState = StreamRecvState::Closed;
    manager.removeClosedStream(stream->id);
  }
  auto update = manager.remoteBidirectionalStreamLimitUpdate();
  EXPECT_FALSE(update);
}

TEST_P(QuicStreamManagerTest, StreamLimitManyWindowedUpdate) {
  auto& manager = *conn.streamManager;
  conn.transportSettings.advertisedInitialMaxStreamsBidi = 100;
  manager.refreshTransportSettings(conn.transportSettings);
  manager.setStreamLimitWindowingFraction(4);
  for (int i = 0; i < 100; i++) {
    manager.getStream(i * detail::kStreamIncrement);
  }
  for (int i = 0; i < 50; i++) {
    auto stream = manager.getStream(i * detail::kStreamIncrement);
    stream->sendState = StreamSendState::Closed;
    stream->recvState = StreamRecvState::Closed;
    manager.removeClosedStream(stream->id);
  }
  auto update = manager.remoteBidirectionalStreamLimitUpdate();
  ASSERT_TRUE(update);
  EXPECT_EQ(update.value(), 150);
  EXPECT_FALSE(manager.remoteBidirectionalStreamLimitUpdate());
  EXPECT_FALSE(manager.remoteUnidirectionalStreamLimitUpdate());
}

TEST_P(QuicStreamManagerTest, StreamLimitIncrementBidi) {
  auto& manager = *conn.streamManager;
  manager.setMaxLocalBidirectionalStreams(100, true);
  manager.refreshTransportSettings(conn.transportSettings);
  StreamId max;
  for (int i = 0; i < 100; i++) {
    max = manager.createNextBidirectionalStream().value()->id;
  }
  EXPECT_TRUE(manager.createNextBidirectionalStream().hasError());
  manager.setMaxLocalBidirectionalStreams(200);
  auto s = manager.createNextBidirectionalStream();
  EXPECT_TRUE(s.hasValue());
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
  manager.setMaxLocalUnidirectionalStreams(100, true);
  manager.refreshTransportSettings(conn.transportSettings);
  StreamId max;
  for (int i = 0; i < 100; i++) {
    max = manager.createNextUnidirectionalStream().value()->id;
  }
  EXPECT_TRUE(manager.createNextUnidirectionalStream().hasError());
  manager.setMaxLocalUnidirectionalStreams(200);
  auto s = manager.createNextUnidirectionalStream();
  EXPECT_TRUE(s.hasValue());
  EXPECT_EQ(s.value()->id, max + detail::kStreamIncrement);
}

TEST_P(QuicStreamManagerTest, NextAcceptableLocalUnidirectionalStreamId) {
  auto& manager = *conn.streamManager;

  // local is server
  const StreamId serverStreamId1 = 0x03;
  const StreamId serverStreamId2 = serverStreamId1 + detail::kStreamIncrement;
  const StreamId serverStreamId3 =
      serverStreamId1 + (detail::kStreamIncrement * 2);
  for (const auto& id : std::vector<StreamId>{
           serverStreamId1, serverStreamId2, serverStreamId3}) {
    EXPECT_EQ(
        StreamDirectionality::Unidirectional, getStreamDirectionality(id));
    EXPECT_EQ(StreamInitiator::Local, getStreamInitiator(conn.nodeType, id));
  }

  EXPECT_EQ(
      serverStreamId1, manager.nextAcceptableLocalUnidirectionalStreamId());
  EXPECT_EQ(
      serverStreamId1, manager.nextAcceptableLocalUnidirectionalStreamId());

  // create next local stream, then check increase in next acceptable stream ID
  manager.createStream(serverStreamId1);
  EXPECT_EQ(
      serverStreamId2, manager.nextAcceptableLocalUnidirectionalStreamId());
  EXPECT_EQ(
      serverStreamId2, manager.nextAcceptableLocalUnidirectionalStreamId());

  // create next local stream, then check increase in next acceptable stream ID
  manager.createStream(serverStreamId2);
  EXPECT_EQ(
      serverStreamId3, manager.nextAcceptableLocalUnidirectionalStreamId());
  EXPECT_EQ(
      serverStreamId3, manager.nextAcceptableLocalUnidirectionalStreamId());
}

TEST_P(QuicStreamManagerTest, NextAcceptableLocalBidirectionalStreamId) {
  auto& manager = *conn.streamManager;

  // local is server
  const StreamId serverStreamId1 = 0x01;
  const StreamId serverStreamId2 = serverStreamId1 + detail::kStreamIncrement;
  const StreamId serverStreamId3 =
      serverStreamId1 + (detail::kStreamIncrement * 2);
  for (const auto& id : std::vector<StreamId>{
           serverStreamId1, serverStreamId2, serverStreamId3}) {
    EXPECT_EQ(StreamDirectionality::Bidirectional, getStreamDirectionality(id));
    EXPECT_EQ(StreamInitiator::Local, getStreamInitiator(conn.nodeType, id));
  }

  EXPECT_EQ(
      serverStreamId1, manager.nextAcceptableLocalBidirectionalStreamId());
  EXPECT_EQ(
      serverStreamId1, manager.nextAcceptableLocalBidirectionalStreamId());

  // create next local stream, then check increase in next acceptable stream ID
  manager.createStream(serverStreamId1);
  EXPECT_EQ(
      serverStreamId2, manager.nextAcceptableLocalBidirectionalStreamId());
  EXPECT_EQ(
      serverStreamId2, manager.nextAcceptableLocalBidirectionalStreamId());

  // create next local stream, then check increase in next acceptable stream ID
  manager.createStream(serverStreamId2);
  EXPECT_EQ(
      serverStreamId3, manager.nextAcceptableLocalBidirectionalStreamId());
  EXPECT_EQ(
      serverStreamId3, manager.nextAcceptableLocalBidirectionalStreamId());
}

TEST_P(QuicStreamManagerTest, NextAcceptableLocalUnidirectionalStreamIdLimit) {
  auto& manager = *conn.streamManager;
  manager.setMaxLocalUnidirectionalStreams(2, true);

  // local is server
  const StreamId serverStreamId1 = 0x03;
  const StreamId serverStreamId2 = serverStreamId1 + detail::kStreamIncrement;
  for (const auto& id :
       std::vector<StreamId>{serverStreamId1, serverStreamId2}) {
    EXPECT_EQ(
        StreamDirectionality::Unidirectional, getStreamDirectionality(id));
    EXPECT_EQ(StreamInitiator::Local, getStreamInitiator(conn.nodeType, id));
  }

  EXPECT_EQ(
      serverStreamId1, manager.nextAcceptableLocalUnidirectionalStreamId());
  EXPECT_EQ(
      serverStreamId1, manager.nextAcceptableLocalUnidirectionalStreamId());

  // create next local stream, then check increase in next acceptable stream ID
  manager.createStream(serverStreamId1);
  EXPECT_EQ(
      serverStreamId2, manager.nextAcceptableLocalUnidirectionalStreamId());
  EXPECT_EQ(
      serverStreamId2, manager.nextAcceptableLocalUnidirectionalStreamId());

  // create next local stream, then check that limit is applied
  manager.createStream(serverStreamId2);
  EXPECT_EQ(folly::none, manager.nextAcceptableLocalUnidirectionalStreamId());
  EXPECT_EQ(folly::none, manager.nextAcceptableLocalUnidirectionalStreamId());
}

TEST_P(QuicStreamManagerTest, NextAcceptableLocalBidirectionalStreamIdLimit) {
  auto& manager = *conn.streamManager;
  manager.setMaxLocalBidirectionalStreams(2, true);

  // local is server
  const StreamId serverStreamId1 = 0x01;
  const StreamId serverStreamId2 = serverStreamId1 + detail::kStreamIncrement;
  for (const auto& id :
       std::vector<StreamId>{serverStreamId1, serverStreamId2}) {
    EXPECT_EQ(StreamDirectionality::Bidirectional, getStreamDirectionality(id));
    EXPECT_EQ(StreamInitiator::Local, getStreamInitiator(conn.nodeType, id));
  }

  EXPECT_EQ(
      serverStreamId1, manager.nextAcceptableLocalBidirectionalStreamId());
  EXPECT_EQ(
      serverStreamId1, manager.nextAcceptableLocalBidirectionalStreamId());

  // create next local stream, then check increase in next acceptable stream ID
  manager.createStream(serverStreamId1);
  EXPECT_EQ(
      serverStreamId2, manager.nextAcceptableLocalBidirectionalStreamId());
  EXPECT_EQ(
      serverStreamId2, manager.nextAcceptableLocalBidirectionalStreamId());

  // create next local stream, then check that limit is applied
  manager.createStream(serverStreamId2);
  EXPECT_EQ(folly::none, manager.nextAcceptableLocalBidirectionalStreamId());
  EXPECT_EQ(folly::none, manager.nextAcceptableLocalBidirectionalStreamId());
}

TEST_P(QuicStreamManagerTest, NextAcceptablePeerUnidirectionalStreamId) {
  auto& manager = *conn.streamManager;

  // local is server, so remote/peer is client
  const StreamId clientStreamId1 = 0x02;
  const StreamId clientStreamId2 = clientStreamId1 + detail::kStreamIncrement;
  const StreamId clientStreamId3 =
      clientStreamId1 + (detail::kStreamIncrement * 2);
  for (const auto& id : std::vector<StreamId>{
           clientStreamId1, clientStreamId2, clientStreamId3}) {
    EXPECT_EQ(
        StreamDirectionality::Unidirectional, getStreamDirectionality(id));
    EXPECT_EQ(StreamInitiator::Remote, getStreamInitiator(conn.nodeType, id));
  }

  EXPECT_EQ(
      clientStreamId1, manager.nextAcceptablePeerUnidirectionalStreamId());
  EXPECT_EQ(
      clientStreamId1, manager.nextAcceptablePeerUnidirectionalStreamId());

  // open next stream, then check for increase in next acceptable stream ID
  manager.getStream(clientStreamId1);
  EXPECT_EQ(
      clientStreamId2, manager.nextAcceptablePeerUnidirectionalStreamId());
  EXPECT_EQ(
      clientStreamId2, manager.nextAcceptablePeerUnidirectionalStreamId());

  // open next stream, then check for increase in next acceptable stream ID
  manager.getStream(clientStreamId2);
  EXPECT_EQ(
      clientStreamId3, manager.nextAcceptablePeerUnidirectionalStreamId());
  EXPECT_EQ(
      clientStreamId3, manager.nextAcceptablePeerUnidirectionalStreamId());
}

TEST_P(QuicStreamManagerTest, NextAcceptablePeerBidirectionalStreamId) {
  auto& manager = *conn.streamManager;

  // local is server, so remote/peer is client
  const StreamId clientStreamId1 = 0x00;
  const StreamId clientStreamId2 = clientStreamId1 + detail::kStreamIncrement;
  const StreamId clientStreamId3 =
      clientStreamId1 + (detail::kStreamIncrement * 2);
  for (const auto& id : std::vector<StreamId>{
           clientStreamId1, clientStreamId2, clientStreamId3}) {
    EXPECT_EQ(StreamDirectionality::Bidirectional, getStreamDirectionality(id));
    EXPECT_EQ(StreamInitiator::Remote, getStreamInitiator(conn.nodeType, id));
  }

  EXPECT_EQ(clientStreamId1, manager.nextAcceptablePeerBidirectionalStreamId());
  EXPECT_EQ(clientStreamId1, manager.nextAcceptablePeerBidirectionalStreamId());

  // open next stream, then check for increase in next acceptable stream ID
  manager.getStream(clientStreamId1);
  EXPECT_EQ(clientStreamId2, manager.nextAcceptablePeerBidirectionalStreamId());
  EXPECT_EQ(clientStreamId2, manager.nextAcceptablePeerBidirectionalStreamId());

  // open next stream, then check for increase in next acceptable stream ID
  manager.getStream(clientStreamId2);
  EXPECT_EQ(clientStreamId3, manager.nextAcceptablePeerBidirectionalStreamId());
  EXPECT_EQ(clientStreamId3, manager.nextAcceptablePeerBidirectionalStreamId());
}

TEST_P(QuicStreamManagerTest, NextAcceptablePeerUnidirectionalStreamIdLimit) {
  auto& manager = *conn.streamManager;
  conn.transportSettings.advertisedInitialMaxStreamsUni = 2;
  manager.refreshTransportSettings(conn.transportSettings);

  // local is server, so remote/peer is client
  const StreamId clientStreamId1 = 0x02;
  const StreamId clientStreamId2 = clientStreamId1 + detail::kStreamIncrement;
  for (const auto& id :
       std::vector<StreamId>{clientStreamId1, clientStreamId2}) {
    EXPECT_EQ(
        StreamDirectionality::Unidirectional, getStreamDirectionality(id));
    EXPECT_EQ(StreamInitiator::Remote, getStreamInitiator(conn.nodeType, id));
  }

  EXPECT_EQ(
      clientStreamId1, manager.nextAcceptablePeerUnidirectionalStreamId());
  EXPECT_EQ(
      clientStreamId1, manager.nextAcceptablePeerUnidirectionalStreamId());

  // open next stream, then check for increase in next acceptable stream ID
  manager.getStream(clientStreamId1);
  EXPECT_EQ(
      clientStreamId2, manager.nextAcceptablePeerUnidirectionalStreamId());
  EXPECT_EQ(
      clientStreamId2, manager.nextAcceptablePeerUnidirectionalStreamId());

  // open next stream, then check that limit is applied
  manager.getStream(clientStreamId2);
  EXPECT_EQ(folly::none, manager.nextAcceptablePeerUnidirectionalStreamId());
  EXPECT_EQ(folly::none, manager.nextAcceptablePeerUnidirectionalStreamId());
}

TEST_P(QuicStreamManagerTest, NextAcceptablePeerBidirectionalStreamIdLimit) {
  auto& manager = *conn.streamManager;
  conn.transportSettings.advertisedInitialMaxStreamsBidi = 2;
  manager.refreshTransportSettings(conn.transportSettings);

  // local is server, so remote/peer is client
  const StreamId clientStreamId1 = 0x00;
  const StreamId clientStreamId2 = clientStreamId1 + detail::kStreamIncrement;
  for (const auto& id :
       std::vector<StreamId>{clientStreamId1, clientStreamId2}) {
    EXPECT_EQ(StreamDirectionality::Bidirectional, getStreamDirectionality(id));
    EXPECT_EQ(StreamInitiator::Remote, getStreamInitiator(conn.nodeType, id));
  }

  EXPECT_EQ(clientStreamId1, manager.nextAcceptablePeerBidirectionalStreamId());
  EXPECT_EQ(clientStreamId1, manager.nextAcceptablePeerBidirectionalStreamId());

  // open next stream, then check for increase in next acceptable stream ID
  manager.getStream(clientStreamId1);
  EXPECT_EQ(clientStreamId2, manager.nextAcceptablePeerBidirectionalStreamId());
  EXPECT_EQ(clientStreamId2, manager.nextAcceptablePeerBidirectionalStreamId());

  // open next stream, then check that limit is applied
  manager.getStream(clientStreamId2);
  EXPECT_EQ(folly::none, manager.nextAcceptablePeerBidirectionalStreamId());
  EXPECT_EQ(folly::none, manager.nextAcceptablePeerBidirectionalStreamId());
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

TEST_P(QuicStreamManagerTest, WriteBufferMeta) {
  auto& manager = *conn.streamManager;
  auto stream = manager.createNextUnidirectionalStream().value();
  // Add some real data into write buffer
  writeDataToQuicStream(*stream, folly::IOBuf::copyBuffer("prefix"), false);
  // Artificially remove the stream from writable queue, so that any further
  // writable query is about the DSR state.
  manager.removeWritable(*stream);

  BufferMeta bufferMeta(200);
  writeBufMetaToQuicStream(*stream, bufferMeta, true);
  EXPECT_TRUE(stream->hasWritableBufMeta());
  EXPECT_TRUE(manager.hasWritable());

  stream->sendState = StreamSendState::Closed;
  stream->recvState = StreamRecvState::Closed;
  manager.removeClosedStream(stream->id);
  EXPECT_TRUE(manager.writableDSRStreams().empty());
}

TEST_P(QuicStreamManagerTest, NotifyOnStreamPriorityChanges) {
  // Verify that the StreamPriorityChanges callback function is called
  // upon stream creation, priority changes, stream removal.
  // For different steps try local (uni/bi)directional streams and remote
  // streams

  MockQuicStreamPrioritiesObserver mObserver;

  auto& manager = *conn.streamManager;
  manager.setPriorityChangesObserver(&mObserver);
  EXPECT_CALL(mObserver, onStreamPrioritiesChange())
      .Times(2); // On stream creation and on setting the priority
  auto stream = manager.createNextUnidirectionalStream().value();
  EXPECT_EQ(manager.getHighestPriorityLevel(), kDefaultPriority.level);

  manager.setStreamPriority(stream->id, 1, false);
  EXPECT_EQ(manager.getHighestPriorityLevel(), 1);

  EXPECT_CALL(mObserver, onStreamPrioritiesChange())
      .Times(1); // On removing a closed stream
  stream->sendState = StreamSendState::Closed;
  stream->recvState = StreamRecvState::Closed;
  manager.removeClosedStream(stream->id);
  // No active stream. Highest priority should return the max value (least
  // priority).
  EXPECT_EQ(manager.getHighestPriorityLevel(), kDefaultMaxPriority);

  EXPECT_CALL(mObserver, onStreamPrioritiesChange())
      .Times(2); // On stream creation - create two streams - one bidirectional
  auto stream2Id = manager.createNextUnidirectionalStream().value()->id;
  auto stream3 = manager.createNextBidirectionalStream().value();
  EXPECT_EQ(manager.getHighestPriorityLevel(), kDefaultPriority.level);

  EXPECT_CALL(mObserver, onStreamPrioritiesChange())
      .Times(1); // On increasing the priority of one of the streams
  manager.setStreamPriority(stream3->id, 0, false);
  EXPECT_EQ(manager.getHighestPriorityLevel(), 0);

  EXPECT_CALL(mObserver, onStreamPrioritiesChange())
      .Times(1); // On removing a closed stream;
  stream3->sendState = StreamSendState::Closed;
  stream3->recvState = StreamRecvState::Closed;
  manager.removeClosedStream(stream3->id);
  EXPECT_EQ(manager.getHighestPriorityLevel(), kDefaultPriority.level);

  EXPECT_CALL(mObserver, onStreamPrioritiesChange())
      .Times(1); // On stream creation - remote stream
  auto peerStreamId = 20;
  ASSERT_TRUE(isRemoteStream(conn.nodeType, peerStreamId));
  auto stream4 = manager.getStream(peerStreamId);
  EXPECT_NE(stream4, nullptr);
  EXPECT_EQ(manager.getHighestPriorityLevel(), kDefaultPriority.level);

  EXPECT_CALL(mObserver, onStreamPrioritiesChange())
      .Times(0); // Removing streams but observer removed
  manager.resetPriorityChangesObserver();
  stream4->sendState = StreamSendState::Closed;
  stream4->recvState = StreamRecvState::Closed;
  manager.removeClosedStream(stream4->id);
  CHECK_NOTNULL(manager.getStream(stream2Id))->sendState =
      StreamSendState::Closed;
  CHECK_NOTNULL(manager.getStream(stream2Id))->recvState =
      StreamRecvState::Closed;
  manager.removeClosedStream(stream2Id);
}

TEST_P(QuicStreamManagerTest, StreamPriorityExcludesControl) {
  MockQuicStreamPrioritiesObserver mObserver;

  auto& manager = *conn.streamManager;

  EXPECT_EQ(manager.getHighestPriorityLevel(), kDefaultMaxPriority);
  auto stream = manager.createNextUnidirectionalStream().value();
  EXPECT_EQ(manager.getHighestPriorityLevel(), kDefaultPriority.level);

  manager.setStreamPriority(stream->id, 1, false);
  EXPECT_EQ(manager.getHighestPriorityLevel(), 1);

  manager.setStreamAsControl(*stream);
  EXPECT_EQ(manager.getHighestPriorityLevel(), kDefaultMaxPriority);

  stream->sendState = StreamSendState::Closed;
  stream->recvState = StreamRecvState::Closed;
  manager.removeClosedStream(stream->id);
}

INSTANTIATE_TEST_SUITE_P(
    QuicStreamManagerTest,
    QuicStreamManagerTest,
    ::testing::Values(
        StreamManagerTestParam{.notifyOnNewStreamsExplicitly = false},
        StreamManagerTestParam{.notifyOnNewStreamsExplicitly = true}));

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
  auto createNextStreamInGroup(StreamGroupId groupId) {
    auto& manager = *conn.streamManager;
    const bool isUnidirectional = GetParam().isUnidirectional;
    return isUnidirectional ? manager.createNextUnidirectionalStream(groupId)
                            : manager.createNextBidirectionalStream(groupId);
  }
};

TEST_P(QuicStreamManagerGroupsTest, TestStreamGroupLimits) {
  auto& manager = *conn.streamManager;

  // By default, no group creation hapenning.
  auto groupId = createNextStreamGroup();
  EXPECT_FALSE(groupId.hasValue());
  EXPECT_EQ(getNumGroups(), 0);

  // Bump group limits.
  conn.transportSettings.maxStreamGroupsAdvertized = 1;
  manager.refreshTransportSettings(conn.transportSettings);
  groupId = createNextStreamGroup();
  EXPECT_TRUE(groupId.hasValue());
  EXPECT_EQ(getNumGroups(), 1);

  // Try again and it should fail running over the limit.
  groupId = createNextStreamGroup();
  EXPECT_FALSE(groupId.hasValue());
  EXPECT_EQ(getNumGroups(), 1);
}

TEST_P(QuicStreamManagerGroupsTest, TestStreamsCreationInGroupsNoGroup) {
  auto& manager = *conn.streamManager;
  conn.transportSettings.maxStreamGroupsAdvertized = 16;
  manager.refreshTransportSettings(conn.transportSettings);

  // Should throw because no stream groups exist yet.
  EXPECT_THROW(createNextStreamInGroup(1), QuicTransportException);
  EXPECT_EQ(getNumGroups(), 0);
}

TEST_P(QuicStreamManagerGroupsTest, TestStreamsCreationInGroupsWrongNodeType) {
  auto& manager = *conn.streamManager;
  conn.transportSettings.maxStreamGroupsAdvertized = 16;
  manager.refreshTransportSettings(conn.transportSettings);

  // Should throw because client stream group id is provided.
  EXPECT_THROW(createNextStreamInGroup(2), QuicTransportException);
  EXPECT_EQ(getNumGroups(), 0);
}

TEST_P(QuicStreamManagerGroupsTest, TestStreamsCreationInGroupsSuccess) {
  auto& manager = *conn.streamManager;
  conn.transportSettings.maxStreamGroupsAdvertized = 16;
  manager.refreshTransportSettings(conn.transportSettings);

  auto groupId = createNextStreamGroup();
  EXPECT_TRUE(groupId.hasValue());
  EXPECT_EQ(getNumGroups(), 1);

  auto stream = createNextStreamInGroup(*groupId);
  EXPECT_TRUE(stream.hasValue());
}

TEST_P(QuicStreamManagerGroupsTest, TestPeerStreamsWithGroupDisabled) {
  auto& manager = *conn.streamManager;

  const StreamId peerStreamId = 2;
  const StreamGroupId peeGroupId = 0;
  // Throws because no groups are allowed.
  EXPECT_THROW(
      manager.getStream(peerStreamId, peeGroupId), QuicTransportException);
}

TEST_P(QuicStreamManagerGroupsTest, TestPeerStreamsWithGroup) {
  auto& manager = *conn.streamManager;
  conn.transportSettings.maxStreamGroupsAdvertized = 16;
  manager.refreshTransportSettings(conn.transportSettings);

  const StreamId peerStreamId = 2;
  const StreamGroupId peeGroupId = 0;
  auto stream = manager.getStream(peerStreamId, peeGroupId);
  EXPECT_NE(stream, nullptr);
  EXPECT_EQ(stream->groupId, peeGroupId);
}

TEST_P(QuicStreamManagerGroupsTest, TestPeerStreamsWithGroupBadGroupId) {
  auto& manager = *conn.streamManager;
  conn.transportSettings.maxStreamGroupsAdvertized = 16;
  manager.refreshTransportSettings(conn.transportSettings);

  const StreamId peerStreamId = 2;
  const StreamGroupId peeGroupId = 1;
  // Expect to throw because groups id 1 is server id.
  EXPECT_THROW(
      manager.getStream(peerStreamId, peeGroupId), QuicTransportException);
}

TEST_P(QuicStreamManagerGroupsTest, TestPeerStreamsWithGroupAccounting) {
  auto& manager = *conn.streamManager;
  conn.transportSettings.maxStreamGroupsAdvertized = 16;
  manager.refreshTransportSettings(conn.transportSettings);

  StreamId peerStreamId = 2;
  StreamGroupId peeGroupId = 0;
  auto stream = manager.getStream(peerStreamId, peeGroupId);
  EXPECT_NE(stream, nullptr);
  EXPECT_EQ(stream->groupId, peeGroupId);
  EXPECT_EQ(manager.getNumNewPeerStreamGroups(), 1);
  EXPECT_EQ(manager.getNumPeerStreamGroupsSeen(), 1);

  // Another stream, same group.
  peerStreamId = 6;
  peeGroupId = 0;
  stream = manager.getStream(peerStreamId, peeGroupId);
  EXPECT_NE(stream, nullptr);
  EXPECT_EQ(stream->groupId, peeGroupId);
  EXPECT_EQ(manager.getNumNewPeerStreamGroups(), 1);
  EXPECT_EQ(manager.getNumPeerStreamGroupsSeen(), 1);

  // New stream, new group.
  peerStreamId = 10;
  peeGroupId = 4;
  stream = manager.getStream(peerStreamId, peeGroupId);
  EXPECT_NE(stream, nullptr);
  EXPECT_EQ(stream->groupId, peeGroupId);
  EXPECT_EQ(manager.getNumNewPeerStreamGroups(), 2);
  EXPECT_EQ(manager.getNumPeerStreamGroupsSeen(), 2);

  // New stream, previous group.
  peerStreamId = 14;
  peeGroupId = 0;
  stream = manager.getStream(peerStreamId, peeGroupId);
  EXPECT_NE(stream, nullptr);
  EXPECT_EQ(stream->groupId, peeGroupId);
  EXPECT_EQ(manager.getNumNewPeerStreamGroups(), 2);
  EXPECT_EQ(manager.getNumPeerStreamGroupsSeen(), 2);

  // New stream, current group.
  peerStreamId = 18;
  peeGroupId = 4;
  stream = manager.getStream(peerStreamId, peeGroupId);
  EXPECT_NE(stream, nullptr);
  EXPECT_EQ(stream->groupId, peeGroupId);
  EXPECT_EQ(manager.getNumNewPeerStreamGroups(), 2);
  EXPECT_EQ(manager.getNumPeerStreamGroupsSeen(), 2);
}

INSTANTIATE_TEST_SUITE_P(
    QuicStreamManagerGroupsTest,
    QuicStreamManagerGroupsTest,
    ::testing::Values(
        StreamManagerTestParam{
            .notifyOnNewStreamsExplicitly = true,
            .isUnidirectional = false},
        StreamManagerTestParam{
            .notifyOnNewStreamsExplicitly = true,
            .isUnidirectional = true}));

} // namespace test
} // namespace quic
