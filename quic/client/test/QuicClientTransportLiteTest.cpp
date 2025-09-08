/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <gtest/gtest.h>
#include <quic/api/test/Mocks.h>
#include <quic/client/QuicClientTransport.h>
#include <quic/client/test/Mocks.h>
#include <quic/common/events/FollyQuicEventBase.h>
#include <quic/common/events/test/QuicEventBaseMock.h>
#include <quic/common/test/TestUtils.h>
#include <quic/common/udpsocket/test/QuicAsyncUDPSocketMock.h>

using namespace ::testing;

namespace quic::test {

class QuicClientTransportLiteMock : public QuicClientTransportLite {
 public:
  QuicClientTransportLiteMock(
      std::shared_ptr<quic::FollyQuicEventBase> evb,
      std::unique_ptr<QuicAsyncUDPSocketMock> socket,
      std::shared_ptr<MockClientHandshakeFactory> handshakeFactory)
      : QuicTransportBaseLite(evb, std::move(socket)),
        QuicClientTransportLite(evb, nullptr, handshakeFactory) {}

  QuicClientConnectionState* getConn() {
    return clientConn_;
  }

  // Expose the protected method for testing
  quic::Expected<void, QuicError> testMaybeIssueConnectionIds() {
    return maybeIssueConnectionIds();
  }
};

class QuicClientTransportLiteTest : public Test {
 public:
  void SetUp() override {
    qEvb_ = std::make_shared<FollyQuicEventBase>(&evb_);
    auto socket = std::make_unique<QuicAsyncUDPSocketMock>();
    sockPtr_ = socket.get();
    ON_CALL(*socket, setAdditionalCmsgsFunc(_))
        .WillByDefault(Return(quic::Expected<void, QuicError>{}));
    ON_CALL(*socket, close())
        .WillByDefault(Return(quic::Expected<void, QuicError>{}));
    ON_CALL(*socket, bind(_))
        .WillByDefault(Return(quic::Expected<void, QuicError>{}));
    ON_CALL(*socket, connect(_))
        .WillByDefault(Return(quic::Expected<void, QuicError>{}));
    ON_CALL(*socket, setReuseAddr(_))
        .WillByDefault(Return(quic::Expected<void, QuicError>{}));
    ON_CALL(*socket, setReusePort(_))
        .WillByDefault(Return(quic::Expected<void, QuicError>{}));
    ON_CALL(*socket, setRecvTos(_))
        .WillByDefault(Return(quic::Expected<void, QuicError>{}));
    ON_CALL(*socket, getRecvTos()).WillByDefault(Return(false));
    ON_CALL(*socket, getGSO()).WillByDefault(Return(0));
    ON_CALL(*socket, setCmsgs(_))
        .WillByDefault(Return(quic::Expected<void, QuicError>{}));
    ON_CALL(*socket, appendCmsgs(_))
        .WillByDefault(Return(quic::Expected<void, QuicError>{}));
    auto mockFactory = std::make_shared<MockClientHandshakeFactory>();
    EXPECT_CALL(*mockFactory, makeClientHandshakeImpl(_))
        .WillRepeatedly(Invoke(
            [&](QuicClientConnectionState* conn)
                -> std::unique_ptr<quic::ClientHandshake> {
              return std::make_unique<MockClientHandshake>(conn);
            }));
    quicClient_ = std::make_shared<QuicClientTransportLiteMock>(
        qEvb_, std::move(socket), mockFactory);
    quicClient_->getConn()->oneRttWriteCipher = test::createNoOpAead();
    quicClient_->getConn()->oneRttWriteHeaderCipher =
        test::createNoOpHeaderCipher().value();
    ASSERT_FALSE(quicClient_->getState()
                     ->streamManager->setMaxLocalBidirectionalStreams(128)
                     .hasError());
  }

  void TearDown() override {
    EXPECT_CALL(*sockPtr_, close())
        .WillRepeatedly(Return(quic::Expected<void, QuicError>{}));
    quicClient_->closeNow(std::nullopt);
  }

  folly::EventBase evb_;
  std::shared_ptr<FollyQuicEventBase> qEvb_;
  std::shared_ptr<QuicClientTransportLiteMock> quicClient_;
  MockConnectionSetupCallback mockConnectionSetupCallback_;
  QuicAsyncUDPSocketMock* sockPtr_{nullptr};
};

TEST_F(QuicClientTransportLiteTest, TestPriming) {
  auto transportSettings = quicClient_->getTransportSettings();
  transportSettings.isPriming = true;
  CHECK_EQ(*quicClient_->getConn()->originalVersion, QuicVersion::MVFST);
  // Set the UDP Packet length to a value differnt than the expected one
  quicClient_->getConn()->udpSendPacketLen = kDefaultUDPSendPacketLen + 1;
  quicClient_->setTransportSettings(std::move(transportSettings));
  // Check that both Version and UDP Packet length are being set to the expected
  // values for priming
  CHECK_EQ(
      *quicClient_->getConn()->originalVersion, QuicVersion::MVFST_PRIMING);
  CHECK_EQ(quicClient_->getConn()->udpSendPacketLen, kDefaultUDPSendPacketLen);
  quicClient_->setConnectionSetupCallback(&mockConnectionSetupCallback_);
  quicClient_->getConn()->zeroRttWriteCipher = test::createNoOpAead();

  StreamId streamId = quicClient_->createBidirectionalStream().value();
  ASSERT_FALSE(
      quicClient_->writeChain(streamId, folly::IOBuf::copyBuffer("test"), false)
          .hasError());
  EXPECT_CALL(mockConnectionSetupCallback_, onPrimingDataAvailable(_));
  evb_.loopOnce(EVLOOP_NONBLOCK);
}

TEST_F(QuicClientTransportLiteTest, TestMaybeIssueConnectionIdsZeroLengthCid) {
  // Test: No action when clientConnectionId size is 0
  auto conn = quicClient_->getConn();

  // Set up zero-length client connection ID
  auto zeroLengthCidRes = ConnectionId::createRandom(0);
  ASSERT_FALSE(zeroLengthCidRes.hasError());
  conn->clientConnectionId = *zeroLengthCidRes;
  conn->oneRttWriteCipher = test::createNoOpAead();

  // Store initial state
  size_t initialSelfConnectionIdsSize = conn->selfConnectionIds.size();
  size_t initialPendingFramesSize = conn->pendingEvents.frames.size();

  // Call the method
  auto result = quicClient_->testMaybeIssueConnectionIds();

  // Verify success
  EXPECT_FALSE(result.hasError());

  // Verify no connection IDs were issued
  EXPECT_EQ(conn->selfConnectionIds.size(), initialSelfConnectionIdsSize);

  // Verify no frames were sent
  EXPECT_EQ(conn->pendingEvents.frames.size(), initialPendingFramesSize);
}

TEST_F(QuicClientTransportLiteTest, TestMaybeIssueConnectionIdsNoCipher) {
  // Test: No action when oneRttWriteCipher is null
  auto conn = quicClient_->getConn();

  // Set up non-zero client connection ID but no cipher
  auto connIdRes = ConnectionId::createRandom(8);
  ASSERT_FALSE(connIdRes.hasError());
  conn->clientConnectionId = *connIdRes;
  conn->oneRttWriteCipher = nullptr;

  // Store initial state
  size_t initialSelfConnectionIdsSize = conn->selfConnectionIds.size();
  size_t initialPendingFramesSize = conn->pendingEvents.frames.size();

  // Call the method
  auto result = quicClient_->testMaybeIssueConnectionIds();

  // Verify success
  EXPECT_FALSE(result.hasError());

  // Verify no connection IDs were issued
  EXPECT_EQ(conn->selfConnectionIds.size(), initialSelfConnectionIdsSize);

  // Verify no frames were sent
  EXPECT_EQ(conn->pendingEvents.frames.size(), initialPendingFramesSize);
}

TEST_F(QuicClientTransportLiteTest, TestMaybeIssueConnectionIdsSuccess) {
  // Test: Successful connection ID issuance
  auto conn = quicClient_->getConn();

  // Set up non-zero client connection ID and cipher
  auto connIdRes = ConnectionId::createRandom(8);
  ASSERT_FALSE(connIdRes.hasError());
  conn->clientConnectionId = *connIdRes;
  conn->oneRttWriteCipher = test::createNoOpAead();

  // Clear existing connection IDs for predictable testing
  conn->selfConnectionIds.clear();

  // Store initial state
  uint64_t initialSequenceNumber = conn->nextSelfConnectionIdSequence;
  size_t initialPendingFramesSize = conn->pendingEvents.frames.size();

  // Calculate expected number of IDs to issue
  uint64_t expectedMaxIds = maximumConnectionIdsToIssue(*conn);

  // Call the method
  auto result = quicClient_->testMaybeIssueConnectionIds();

  // Verify success
  EXPECT_FALSE(result.hasError());

  // Verify correct number of connection IDs were issued
  EXPECT_EQ(conn->selfConnectionIds.size(), expectedMaxIds);

  // Verify sequence numbers are correct and incremental
  for (size_t i = 0; i < conn->selfConnectionIds.size(); ++i) {
    EXPECT_EQ(
        conn->selfConnectionIds[i].sequenceNumber, initialSequenceNumber + i);
    // Verify connection ID size matches client connection ID size
    EXPECT_EQ(
        conn->selfConnectionIds[i].connId.size(),
        conn->clientConnectionId->size());
    // Verify token is set
    EXPECT_TRUE(conn->selfConnectionIds[i].token.has_value());
  }

  // Verify nextSelfConnectionIdSequence was incremented correctly
  EXPECT_EQ(
      conn->nextSelfConnectionIdSequence,
      initialSequenceNumber + expectedMaxIds);

  // Verify NewConnectionIdFrames were sent
  EXPECT_EQ(
      conn->pendingEvents.frames.size(),
      initialPendingFramesSize + expectedMaxIds);

  // Verify frame contents
  for (size_t i = 0; i < expectedMaxIds; ++i) {
    size_t frameIndex = initialPendingFramesSize + i;
    ASSERT_LT(frameIndex, conn->pendingEvents.frames.size());

    auto& frame = conn->pendingEvents.frames[frameIndex];
    EXPECT_EQ(frame.type(), QuicSimpleFrame::Type::NewConnectionIdFrame);

    auto newConnIdFrame = frame.asNewConnectionIdFrame();
    EXPECT_EQ(newConnIdFrame->sequenceNumber, initialSequenceNumber + i);
    EXPECT_EQ(newConnIdFrame->retirePriorTo, 0);
    EXPECT_EQ(newConnIdFrame->connectionId, conn->selfConnectionIds[i].connId);
    EXPECT_EQ(newConnIdFrame->token, *conn->selfConnectionIds[i].token);
  }
}

TEST_F(QuicClientTransportLiteTest, TestMaybeIssueConnectionIdsAlreadyAtMax) {
  // Test: No additional CIDs when already at maximum
  auto conn = quicClient_->getConn();

  // Set up non-zero client connection ID and cipher
  auto connIdRes = ConnectionId::createRandom(8);
  ASSERT_FALSE(connIdRes.hasError());
  conn->clientConnectionId = *connIdRes;
  conn->oneRttWriteCipher = test::createNoOpAead();

  // Fill selfConnectionIds to maximum capacity
  uint64_t maxIds = maximumConnectionIdsToIssue(*conn);
  conn->selfConnectionIds.clear();
  for (uint64_t i = 0; i < maxIds; ++i) {
    auto cid = ConnectionId::createRandom(8);
    ASSERT_FALSE(cid.hasError());
    conn->selfConnectionIds.emplace_back(*cid, i);
  }

  // Store initial state
  size_t initialSelfConnectionIdsSize = conn->selfConnectionIds.size();
  size_t initialPendingFramesSize = conn->pendingEvents.frames.size();
  uint64_t initialSequenceNumber = conn->nextSelfConnectionIdSequence;

  // Call the method
  auto result = quicClient_->testMaybeIssueConnectionIds();

  // Verify success
  EXPECT_FALSE(result.hasError());

  // Verify no additional connection IDs were issued
  EXPECT_EQ(conn->selfConnectionIds.size(), initialSelfConnectionIdsSize);

  // Verify sequence number didn't change
  EXPECT_EQ(conn->nextSelfConnectionIdSequence, initialSequenceNumber);

  // Verify no frames were sent
  EXPECT_EQ(conn->pendingEvents.frames.size(), initialPendingFramesSize);
}

TEST_F(QuicClientTransportLiteTest, TestMaybeIssueConnectionIdsPartialFill) {
  // Test: Issue only the remaining CIDs needed to reach maximum
  auto conn = quicClient_->getConn();

  // Set up non-zero client connection ID and cipher
  auto connIdRes = ConnectionId::createRandom(8);
  ASSERT_FALSE(connIdRes.hasError());
  conn->clientConnectionId = *connIdRes;
  conn->oneRttWriteCipher = test::createNoOpAead();

  // Add some existing connection IDs (but not at maximum)
  uint64_t maxIds = maximumConnectionIdsToIssue(*conn);
  uint64_t existingIds = maxIds > 1 ? maxIds - 1 : 0;

  conn->selfConnectionIds.clear();
  for (uint64_t i = 0; i < existingIds; ++i) {
    auto cid = ConnectionId::createRandom(8);
    ASSERT_FALSE(cid.hasError());
    conn->selfConnectionIds.emplace_back(*cid, i);
  }

  // Store initial state
  size_t initialSelfConnectionIdsSize = conn->selfConnectionIds.size();
  size_t initialPendingFramesSize = conn->pendingEvents.frames.size();
  uint64_t initialSequenceNumber = conn->nextSelfConnectionIdSequence;

  // Expected number of new IDs to be created
  uint64_t expectedNewIds = maxIds - existingIds;

  // Call the method
  auto result = quicClient_->testMaybeIssueConnectionIds();

  // Verify success
  EXPECT_FALSE(result.hasError());

  // Verify correct total number of connection IDs
  EXPECT_EQ(conn->selfConnectionIds.size(), maxIds);

  // Verify correct number of new IDs were added
  EXPECT_EQ(
      conn->selfConnectionIds.size() - initialSelfConnectionIdsSize,
      expectedNewIds);

  // Verify sequence number was incremented correctly
  EXPECT_EQ(
      conn->nextSelfConnectionIdSequence,
      initialSequenceNumber + expectedNewIds);

  // Verify correct number of frames were sent
  EXPECT_EQ(
      conn->pendingEvents.frames.size(),
      initialPendingFramesSize + expectedNewIds);
}

TEST_F(
    QuicClientTransportLiteTest,
    TestMaybeIssueConnectionIdsSequenceNumbering) {
  // Test: Verify proper sequence number assignment and increment
  auto conn = quicClient_->getConn();

  // Set up non-zero client connection ID and cipher
  auto connIdRes = ConnectionId::createRandom(16); // Use different size
  ASSERT_FALSE(connIdRes.hasError());
  conn->clientConnectionId = *connIdRes;
  conn->oneRttWriteCipher = test::createNoOpAead();

  // Set a specific starting sequence number
  uint64_t startingSequenceNumber = 42;
  conn->nextSelfConnectionIdSequence = startingSequenceNumber;
  conn->selfConnectionIds.clear();

  // Call the method
  auto result = quicClient_->testMaybeIssueConnectionIds();

  // Verify success
  EXPECT_FALSE(result.hasError());

  // Verify all connection IDs have the correct size
  for (const auto& connIdData : conn->selfConnectionIds) {
    EXPECT_EQ(connIdData.connId.size(), 16);
  }

  // Verify sequence numbers are assigned sequentially starting from the initial
  // value
  for (size_t i = 0; i < conn->selfConnectionIds.size(); ++i) {
    EXPECT_EQ(
        conn->selfConnectionIds[i].sequenceNumber, startingSequenceNumber + i);
  }

  // Verify final sequence number
  uint64_t expectedFinalSequence =
      startingSequenceNumber + conn->selfConnectionIds.size();
  EXPECT_EQ(conn->nextSelfConnectionIdSequence, expectedFinalSequence);
}

} // namespace quic::test
