/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <folly/SocketAddress.h>
#include <gtest/gtest.h>
#include <quic/api/test/Mocks.h>
#include <quic/client/QuicClientTransportLite.h>
#include <quic/client/test/Mocks.h>
#include <quic/codec/Types.h>
#include <quic/common/events/FollyQuicEventBase.h>
#include <quic/common/test/TestUtils.h>
#include <quic/common/udpsocket/test/QuicAsyncUDPSocketMock.h>
#include <quic/state/QuicPathManager.h>

using namespace ::testing;

namespace quic::test {

class QuicClientTransportLiteMock : public QuicClientTransportLite {
 public:
  QuicClientTransportLiteMock(
      std::shared_ptr<quic::FollyQuicEventBase> evb,
      std::unique_ptr<QuicAsyncUDPSocketMock> socket,
      std::shared_ptr<MockClientHandshakeFactory> handshakeFactory)
      : QuicTransportBaseLite(evb, std::move(socket)),
        QuicClientTransportLite(evb, nullptr, handshakeFactory) {
    initializePathManagerState(*clientConn_);
    // Set up server connection ID (current peer connection ID)
    clientConn_->serverConnectionId =
        ConnectionId::createAndMaybeCrash({1, 2, 3, 4});
    clientConn_->peerConnectionIds
        .emplace_back(*clientConn_->serverConnectionId, 0)
        .inUse = true;
    // Add peer connection IDs
    clientConn_->peerConnectionIds.emplace_back(
        ConnectionId::createAndMaybeCrash({5, 6, 7, 8}), 1);
    clientConn_->peerConnectionIds.emplace_back(
        ConnectionId::createAndMaybeCrash({9, 10, 11, 12}), 2);
  }

  QuicClientConnectionState* getConn() {
    return clientConn_;
  }
};

class TestPathValidationCallback
    : public QuicPathManager::PathValidationCallback {
 public:
  TestPathValidationCallback(
      QuicClientTransportLite* client = nullptr,
      bool shouldMigrate = false)
      : client(client), shouldMigrate(shouldMigrate) {}

  void onPathValidationResult(const PathInfo& info) override {
    called = true;
    lastId = info.id;
    lastStatus = info.status;
    if (shouldMigrate) {
      client->migrateConnection(info.id);
    }
  }

  QuicClientTransportLite* client;
  bool shouldMigrate;
  bool called{false};
  PathIdType lastId{0};
  PathStatus lastStatus{PathStatus::NotValid};
};

class QuicClientTransportLiteMigrationTest : public Test {
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
    ON_CALL(*socket, address())
        .WillByDefault(Return(
            quic::Expected<folly::SocketAddress, QuicError>{localAddr_}));
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
  }

  void TearDown() override {
    EXPECT_CALL(*sockPtr_, close())
        .WillRepeatedly(Return(quic::Expected<void, QuicError>{}));
    quicClient_->closeNow(std::nullopt);
  }

  // Helper function to create and setup a probe socket mock
  std::unique_ptr<QuicAsyncUDPSocketMock> createProbeSocketMock(
      const folly::SocketAddress& socketLocalAddr) {
    auto probeSock = std::make_unique<QuicAsyncUDPSocketMock>();
    auto* probeSockPtr = probeSock.get();
    ON_CALL(*probeSockPtr, setReuseAddr(_))
        .WillByDefault(Return(quic::Expected<void, QuicError>{}));
    ON_CALL(*probeSockPtr, setRecvTos(_))
        .WillByDefault(Return(quic::Expected<void, QuicError>{}));
    ON_CALL(*probeSockPtr, init(_))
        .WillByDefault(Return(quic::Expected<void, QuicError>{}));
    ON_CALL(*probeSockPtr, applyOptions(_, _))
        .WillByDefault(Return(quic::Expected<void, QuicError>{}));
    ON_CALL(*probeSockPtr, connect(_))
        .WillByDefault(Return(quic::Expected<void, QuicError>{}));
    ON_CALL(*probeSockPtr, bind(_))
        .WillByDefault(Return(quic::Expected<void, QuicError>{}));
    ON_CALL(*probeSockPtr, isBound()).WillByDefault(Return(true));
    ON_CALL(*probeSockPtr, setTosOrTrafficClass(_))
        .WillByDefault(Return(quic::Expected<void, QuicError>{}));
    ON_CALL(*probeSockPtr, address())
        .WillByDefault(Return(
            quic::Expected<folly::SocketAddress, QuicError>{socketLocalAddr}));
    return probeSock;
  }

  // Helper function to validate a path by simulating challenge/response
  void validatePath(PathIdType pathId) {
    // Get challenge data
    auto challengeDataRes =
        quicClient_->getConn()->pathManager->getNewPathChallengeData(pathId);
    ASSERT_FALSE(challengeDataRes.hasError());

    // Simulate sending the path challenge so timestamps are populated
    PathChallengeFrame chall{challengeDataRes.value()};
    quicClient_->getConn()->pathManager->onPathChallengeSent(chall);

    // Simulate receiving the response
    PathResponseFrame resp{challengeDataRes.value()};
    const auto* validated =
        quicClient_->getConn()->pathManager->onPathResponseReceived(
            resp, pathId);
    ASSERT_NE(validated, nullptr);
  }

  folly::EventBase evb_;
  std::shared_ptr<FollyQuicEventBase> qEvb_;
  std::shared_ptr<QuicClientTransportLiteMock> quicClient_;
  QuicAsyncUDPSocketMock* sockPtr_{nullptr};
  folly::SocketAddress localAddr_{"::", 54321};
};

TEST_F(
    QuicClientTransportLiteMigrationTest,
    StartPathProbeSuccessWithoutMigrating) {
  folly::SocketAddress localAddr("::", 12345);
  auto probeSock = createProbeSocketMock(localAddr);

  auto probeSockPtr = probeSock.get();
  // Starting a path probe should initialize the socket:
  EXPECT_CALL(*probeSockPtr, setTosOrTrafficClass(_)).Times(1);
  EXPECT_CALL(*probeSockPtr, setDFAndTurnOffPMTU()).Times(1);
  EXPECT_CALL(*probeSockPtr, setAdditionalCmsgsFunc(_)).Times(1);

  TestPathValidationCallback callback;
  auto res = quicClient_->startPathProbe(std::move(probeSock), &callback);
  ASSERT_TRUE(res.has_value()) << "startPathProbe failed: " << res.error();
  auto pathId = res.value();

  // Validate a path challenge was scheduled
  EXPECT_GE(quicClient_->getConn()->pendingEvents.pathChallenges.size(), 1);

  // Validate the path via PathResponse and ensure callback is invoked
  validatePath(pathId);
  EXPECT_TRUE(callback.called);
  EXPECT_EQ(callback.lastId, pathId);
  EXPECT_EQ(callback.lastStatus, PathStatus::Validated);

  // The path still exists. It wasn't removed in the callback.
  EXPECT_NE(quicClient_->getConn()->pathManager->getPath(pathId), nullptr);

  // Loop once to allow evb callbacks from the path result callback to execute
  qEvb_->loopOnce();

  // Since we didn't migrate in the callback, the probe path should be removed
  EXPECT_EQ(quicClient_->getConn()->pathManager->getPath(pathId), nullptr);
}

TEST_F(
    QuicClientTransportLiteMigrationTest,
    StartPathProbeSuccessWithMigrating) {
  folly::SocketAddress localAddr("::", 12345);
  auto initialPathId = quicClient_->getConn()->currentPathId;
  auto probeSock = createProbeSocketMock(localAddr);

  auto probeSockPtr = probeSock.get();
  // Starting a path probe should initialize the socket:
  EXPECT_CALL(*probeSockPtr, setTosOrTrafficClass(_)).Times(1);
  EXPECT_CALL(*probeSockPtr, setDFAndTurnOffPMTU()).Times(1);
  EXPECT_CALL(*probeSockPtr, setAdditionalCmsgsFunc(_)).Times(1);

  TestPathValidationCallback callback(quicClient_.get(), true);
  auto res = quicClient_->startPathProbe(std::move(probeSock), &callback);
  ASSERT_TRUE(res.has_value()) << "startPathProbe failed: " << res.error();
  auto pathId = res.value();

  // Validate a path challenge was scheduled
  EXPECT_GE(quicClient_->getConn()->pendingEvents.pathChallenges.size(), 1);

  // Validate the path via PathResponse and ensure callback is invoked
  validatePath(pathId);
  EXPECT_TRUE(callback.called);
  EXPECT_EQ(callback.lastId, pathId);
  EXPECT_EQ(callback.lastStatus, PathStatus::Validated);

  // The probed path and the initial path still exist. Neither was removed in
  // the callback.
  EXPECT_NE(quicClient_->getConn()->pathManager->getPath(pathId), nullptr);
  EXPECT_NE(
      quicClient_->getConn()->pathManager->getPath(initialPathId), nullptr);

  // We migrated.
  ASSERT_EQ(quicClient_->getConn()->currentPathId, pathId);
  // This has to be updated manually in the test.
  sockPtr_ = probeSockPtr;

  // The old path is not immediately removed — it's kept until a packet is
  // received on the new path.
  EXPECT_NE(quicClient_->getConn()->pathManager->getPath(pathId), nullptr);
  EXPECT_NE(
      quicClient_->getConn()->pathManager->getPath(initialPathId), nullptr);
}

TEST_F(
    QuicClientTransportLiteMigrationTest,
    MigrateConnectionSwitchesCurrentPath) {
  folly::SocketAddress localAddr("::", 22334);
  auto probeSock = createProbeSocketMock(localAddr);
  auto probeSockPtr = probeSock.get();

  auto startRes = quicClient_->startPathProbe(std::move(probeSock), nullptr);
  ASSERT_TRUE(startRes.has_value());
  auto pathId = startRes.value();

  // Validate the path via PathResponse to allow migration
  validatePath(pathId);

  auto migRes = quicClient_->migrateConnection(pathId);
  ASSERT_TRUE(migRes.has_value()) << "migrateConnection failed";
  EXPECT_EQ(quicClient_->getConn()->currentPathId, pathId);

  // This has to be updated manually in the test state since we've migrated
  sockPtr_ = probeSockPtr;

  // Loop once to allow evb callbacks from the path result callback to execute
  qEvb_->loopOnce();
}

TEST_F(QuicClientTransportLiteMigrationTest, PathProbeTimeout) {
  folly::SocketAddress localAddr("::", 33445);
  auto probeSock = createProbeSocketMock(localAddr);

  TestPathValidationCallback callback;
  auto res = quicClient_->startPathProbe(std::move(probeSock), &callback);
  ASSERT_TRUE(res.has_value()) << "startPathProbe failed: " << res.error();
  auto pathId = res.value();

  // Get challenge data and send it to set up the deadline
  auto challengeDataRes =
      quicClient_->getConn()->pathManager->getNewPathChallengeData(pathId);
  ASSERT_FALSE(challengeDataRes.hasError());

  // Simulate sending the path challenge to set timestamps and deadline
  PathChallengeFrame chall{challengeDataRes.value()};
  quicClient_->getConn()->pathManager->onPathChallengeSent(chall);

  // Get the path to check its deadline
  const auto* pathInfo = quicClient_->getConn()->pathManager->getPath(pathId);
  ASSERT_NE(pathInfo, nullptr);
  ASSERT_TRUE(pathInfo->pathResponseDeadline.has_value());
  EXPECT_EQ(pathInfo->status, PathStatus::Validating);

  // Trigger timeout by calling onPathValidationTimeoutExpired with a time
  // past the deadline
  auto timeoutTime = *pathInfo->pathResponseDeadline + std::chrono::seconds(1);
  quicClient_->getConn()->pathManager->onPathValidationTimeoutExpired(
      timeoutTime);

  // Verify callback was invoked with NotValid status
  EXPECT_TRUE(callback.called);
  EXPECT_EQ(callback.lastId, pathId);
  EXPECT_EQ(callback.lastStatus, PathStatus::NotValid);

  // Verify path status is now NotValid
  pathInfo = quicClient_->getConn()->pathManager->getPath(pathId);
  ASSERT_NE(pathInfo, nullptr);
  EXPECT_EQ(pathInfo->status, PathStatus::NotValid);

  // Loop once to allow evb callbacks from the path result callback to execute
  qEvb_->loopOnce();

  // The path should no longer exist since it's not valid.
  EXPECT_EQ(quicClient_->getConn()->pathManager->getPath(pathId), nullptr);
}

TEST_F(
    QuicClientTransportLiteMigrationTest,
    MigrateToUnvalidatedPathThenTimeout) {
  folly::SocketAddress localAddr("::", 44556);
  auto probeSock = createProbeSocketMock(localAddr);

  TestPathValidationCallback callback;
  auto startRes = quicClient_->startPathProbe(std::move(probeSock), &callback);
  ASSERT_TRUE(startRes.has_value());
  auto pathId = startRes.value();

  // Get challenge data and send it to set up the deadline
  auto challengeDataRes =
      quicClient_->getConn()->pathManager->getNewPathChallengeData(pathId);
  ASSERT_FALSE(challengeDataRes.hasError());

  // Simulate sending the path challenge to set timestamps and deadline
  PathChallengeFrame chall{challengeDataRes.value()};
  quicClient_->getConn()->pathManager->onPathChallengeSent(chall);

  // Verify path is in Validating state
  const auto* pathInfo = quicClient_->getConn()->pathManager->getPath(pathId);
  ASSERT_NE(pathInfo, nullptr);
  ASSERT_TRUE(pathInfo->pathResponseDeadline.has_value());
  EXPECT_EQ(pathInfo->status, PathStatus::Validating);

  // Migrate to the unvalidated path (should be allowed for client)
  auto migRes = quicClient_->migrateConnection(pathId);
  ASSERT_TRUE(migRes.has_value())
      << "migrateConnection to unvalidated path failed: " << migRes.error();
  EXPECT_EQ(quicClient_->getConn()->currentPathId, pathId);

  // Trigger timeout by calling onPathValidationTimeoutExpired with a time
  // past the deadline
  auto timeoutTime = *pathInfo->pathResponseDeadline + std::chrono::seconds(1);
  quicClient_->getConn()->pathManager->onPathValidationTimeoutExpired(
      timeoutTime);

  // Verify callback was invoked with NotValid status
  EXPECT_TRUE(callback.called);
  EXPECT_EQ(callback.lastId, pathId);
  EXPECT_EQ(callback.lastStatus, PathStatus::NotValid);

  // Verify path status is now NotValid
  pathInfo = quicClient_->getConn()->pathManager->getPath(pathId);
  ASSERT_NE(pathInfo, nullptr);
  EXPECT_EQ(pathInfo->status, PathStatus::NotValid);
}

TEST_F(
    QuicClientTransportLiteMigrationTest,
    CannotStartProbeWithUnboundSocket) {
  folly::SocketAddress localAddr("::", 55555);
  auto probeSock = std::make_unique<QuicAsyncUDPSocketMock>();
  auto* probeSockPtr = probeSock.get();

  // Simulate the socket is not bound
  ON_CALL(*probeSockPtr, isBound()).WillByDefault(Return(false));

  auto res = quicClient_->startPathProbe(std::move(probeSock), nullptr);
  EXPECT_TRUE(res.hasError());
  EXPECT_EQ(res.error().code, LocalErrorCode::INTERNAL_ERROR);
  EXPECT_TRUE(res.error().message.find("not bound") != std::string::npos);
}

TEST_F(
    QuicClientTransportLiteMigrationTest,
    CannotStartProbeWithSocketAddressFamilyMismatch) {
  // The main socket is IPv6 ("::"), so use IPv4 for mismatch
  folly::SocketAddress localAddr("127.0.0.1", 55556);
  auto probeSock = createProbeSocketMock(localAddr);

  // Simulate the probe socket is bound
  auto* probeSockPtr = probeSock.get();
  ON_CALL(*probeSockPtr, isBound()).WillByDefault(Return(true));

  auto res = quicClient_->startPathProbe(std::move(probeSock), nullptr);
  EXPECT_EQ(res.error().code, LocalErrorCode::INTERNAL_ERROR);
  EXPECT_TRUE(
      res.error().message.find("address family mismatch") != std::string::npos);
}

TEST_F(
    QuicClientTransportLiteMigrationTest,
    CannotStartProbeWhenPeerDisablesActiveMigration) {
  folly::SocketAddress localAddr("::", 56565);
  auto probeSock = createProbeSocketMock(localAddr);

  quicClient_->getConn()->peerSupportsActiveConnectionMigration = false;

  auto res = quicClient_->startPathProbe(std::move(probeSock), nullptr);
  EXPECT_TRUE(res.hasError());
  EXPECT_EQ(res.error().code, LocalErrorCode::INTERNAL_ERROR);
  EXPECT_TRUE(
      res.error().message.find(
          "Peer does not support active connection migration") !=
      std::string::npos);
}

TEST_F(
    QuicClientTransportLiteMigrationTest,
    CannotStartProbeWithoutOneRttCipher) {
  folly::SocketAddress localAddr("::", 57575);
  auto probeSock = createProbeSocketMock(localAddr);

  quicClient_->getConn()->oneRttWriteCipher = nullptr;
  quicClient_->getConn()->oneRttWriteHeaderCipher = nullptr;

  auto res = quicClient_->startPathProbe(std::move(probeSock), nullptr);
  EXPECT_TRUE(res.hasError());
  EXPECT_EQ(res.error().code, LocalErrorCode::INTERNAL_ERROR);
  EXPECT_TRUE(
      res.error().message.find(
          "Cannot initiate probe before handshake is complete") !=
      std::string::npos);
}

TEST_F(QuicClientTransportLiteMigrationTest, CannotStartProbeWithoutSocket) {
  auto res = quicClient_->startPathProbe(nullptr, nullptr);
  EXPECT_EQ(res.error().code, LocalErrorCode::INTERNAL_ERROR);
}

TEST_F(
    QuicClientTransportLiteMigrationTest,
    StartPathProbeAssignsConnectionId) {
  auto conn = quicClient_->getConn();

  // Create a probe socket
  folly::SocketAddress localAddr("::", 12345);
  auto probeSock = createProbeSocketMock(localAddr);

  // Start the path probe
  TestPathValidationCallback callback;
  auto res = quicClient_->startPathProbe(std::move(probeSock), &callback);
  ASSERT_TRUE(res.has_value()) << "startPathProbe failed: " << res.error();
  auto pathId = res.value();

  // Verify the path was created and has a destination connection ID assigned
  auto pathInfo = conn->pathManager->getPath(pathId);
  ASSERT_NE(pathInfo, nullptr);
  ASSERT_TRUE(pathInfo->destinationConnectionId.has_value())
      << "Path should have a destination connection ID assigned";

  // Verify the assigned CID is one of the peer CIDs and is marked as in use
  auto assignedCid = pathInfo->destinationConnectionId.value();
  bool foundInUse = false;
  for (const auto& cidData : conn->peerConnectionIds) {
    if (cidData.connId == assignedCid) {
      EXPECT_TRUE(cidData.inUse)
          << "Assigned connection ID should be marked as in use";
      foundInUse = true;
      break;
    }
  }
  EXPECT_TRUE(foundInUse)
      << "Assigned CID should be one of the peer connection IDs";

  // Verify it's not the current server connection ID
  EXPECT_NE(assignedCid, *conn->serverConnectionId)
      << "Assigned CID should be different from current server connection ID";
}

TEST_F(
    QuicClientTransportLiteMigrationTest,
    StartPathProbeFailsWhenNoAvailableConnectionIds) {
  auto conn = quicClient_->getConn();

  // Mark all peer connection IDs as in use
  for (auto& cidData : conn->peerConnectionIds) {
    cidData.inUse = true;
  }

  // Create a probe socket
  folly::SocketAddress localAddr("::", 12345);
  auto probeSock = createProbeSocketMock(localAddr);

  // Attempt to start the path probe - should fail due to no available CIDs
  TestPathValidationCallback callback;
  auto res = quicClient_->startPathProbe(std::move(probeSock), &callback);

  // Verify startPathProbe returns an error
  ASSERT_TRUE(res.hasError()) << "Expected startPathProbe to fail";
  EXPECT_EQ(res.error().code, LocalErrorCode::INTERNAL_ERROR)
      << "Expected INTERNAL_ERROR when no connection IDs available";
  EXPECT_TRUE(
      res.error().message.find("available") != std::string::npos ||
      res.error().message.find("connection id") != std::string::npos)
      << "Error message should mention connection IDs or availability";
}

} // namespace quic::test
