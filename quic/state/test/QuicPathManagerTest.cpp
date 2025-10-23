/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <quic/state/QuicPathManager.h>

#include <folly/SocketAddress.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <quic/QuicConstants.h>
#include <quic/codec/Types.h>
#include <quic/common/udpsocket/test/QuicAsyncUDPSocketMock.h>
#include <quic/congestion_control/CongestionControllerFactory.h>
#include <quic/state/StateData.h>
#include <quic/state/test/Mocks.h>

using namespace testing;

namespace quic::test {

class MockQuicConnectionStateBase : public QuicConnectionStateBase {
 public:
  MockQuicConnectionStateBase()
      : QuicConnectionStateBase(QuicNodeType::Client) {
    // Initialize essential fields for testing
    currentPathId = 0;
    udpSendPacketLen = 1200;

    // Initialize transport settings
    transportSettings.initialRtt = std::chrono::milliseconds(100);
    transportSettings.limitedCwndInMss = 3;

    // Initialize loss state
    lossState.srtt = std::chrono::milliseconds(100);
    lossState.lrtt = std::chrono::milliseconds(100);
    lossState.rttvar = std::chrono::milliseconds(50);
    lossState.mrtt = std::chrono::milliseconds(10);
    lossState.maxAckDelay = std::chrono::milliseconds(25);
  }

  // Note: Using inherited currentPathId, lossState, and pendingEvents fields
  // from QuicConnectionStateBase
};

class QuicPathManagerTest : public ::testing::Test {
 protected:
  void SetUp() override {
    connState_ = std::make_unique<MockQuicConnectionStateBase>();
    manager_ = std::make_unique<QuicPathManager>(*connState_);
  }

  std::unique_ptr<MockQuicConnectionStateBase> connState_;
  std::unique_ptr<QuicPathManager> manager_;

  // Helper addresses for testing
  const folly::SocketAddress localAddr1_{"192.168.1.100", 8080};
  const folly::SocketAddress peerAddr1_{"192.168.1.1", 443};
  const folly::SocketAddress localAddr2_{"192.168.1.100", 8081};
  const folly::SocketAddress peerAddr2_{"192.168.1.2", 443};
};

// Basic Path Management Tests

TEST_F(QuicPathManagerTest, AddPath) {
  auto result1 = manager_->addPath(localAddr1_, peerAddr1_);
  ASSERT_TRUE(result1.has_value());
  PathIdType id1 = result1.value();

  auto result2 = manager_->addPath(localAddr2_, peerAddr2_);
  ASSERT_TRUE(result2.has_value());
  PathIdType id2 = result2.value();

  EXPECT_NE(id1, id2);

  // Verify paths exist
  auto path1 = manager_->getPath(id1);
  ASSERT_NE(path1, nullptr);
  EXPECT_EQ(path1->id, id1);
  EXPECT_EQ(path1->peerAddress, peerAddr1_);
  EXPECT_EQ(path1->status, PathStatus::NotValid);
  EXPECT_EQ(path1->socket, nullptr);

  auto path2 = manager_->getPath(id2);
  ASSERT_NE(path2, nullptr);
  EXPECT_EQ(path2->id, id2);
  EXPECT_EQ(path2->peerAddress, peerAddr2_);
  EXPECT_EQ(path2->status, PathStatus::NotValid);
}

TEST_F(QuicPathManagerTest, AddPathWithSocket) {
  auto socket = std::make_unique<QuicAsyncUDPSocketMock>();
  auto* socketPtr = socket.get();

  auto result = manager_->addPath(localAddr1_, peerAddr1_, std::move(socket));
  ASSERT_TRUE(result.has_value());
  PathIdType id = result.value();

  auto path = manager_->getPath(id);
  ASSERT_NE(path, nullptr);
  EXPECT_EQ(path->socket.get(), socketPtr);
}

TEST_F(QuicPathManagerTest, AddDuplicatePath) {
  auto result1 = manager_->addPath(localAddr1_, peerAddr1_);
  ASSERT_TRUE(result1.has_value());

  // Adding same path should fail
  auto result2 = manager_->addPath(localAddr1_, peerAddr1_);
  EXPECT_FALSE(result2.has_value());
  EXPECT_EQ(result2.error().code, LocalErrorCode::PATH_MANAGER_ERROR);
}

TEST_F(QuicPathManagerTest, AddValidatedPath) {
  auto result = manager_->addValidatedPath(localAddr1_, peerAddr1_);
  ASSERT_TRUE(result.has_value());
  PathIdType id = result.value();

  auto path = manager_->getPath(id);
  ASSERT_NE(path, nullptr);
  EXPECT_EQ(path->status, PathStatus::Validated);
}

TEST_F(QuicPathManagerTest, AddValidatedPathDuplicate) {
  auto result1 = manager_->addValidatedPath(localAddr1_, peerAddr1_);
  ASSERT_TRUE(result1.has_value());

  auto result2 = manager_->addValidatedPath(localAddr1_, peerAddr1_);
  EXPECT_FALSE(result2.has_value());
  EXPECT_EQ(result2.error().code, LocalErrorCode::PATH_MANAGER_ERROR);
}

TEST_F(QuicPathManagerTest, GetOrAddPathExisting) {
  auto result = manager_->addPath(localAddr1_, peerAddr1_);
  ASSERT_TRUE(result.has_value());
  PathIdType originalId = result.value();

  const auto& pathRes = manager_->getOrAddPath(localAddr1_, peerAddr1_);
  ASSERT_FALSE(pathRes.hasError());
  auto& path = pathRes.value().get();
  EXPECT_EQ(path.id, originalId);
}

TEST_F(QuicPathManagerTest, GetOrAddPathNew) {
  const auto& pathRes = manager_->getOrAddPath(localAddr1_, peerAddr1_);
  ASSERT_FALSE(pathRes.hasError());
  auto& path = pathRes.value().get();
  EXPECT_EQ(path.status, PathStatus::NotValid);
  EXPECT_EQ(path.peerAddress, peerAddr1_);

  // Verify it was actually added
  auto retrievedPath = manager_->getPath(path.id);
  ASSERT_NE(retrievedPath, nullptr);
  EXPECT_EQ(retrievedPath->id, path.id);
}

TEST_F(QuicPathManagerTest, RemovePath) {
  auto result = manager_->addPath(localAddr1_, peerAddr1_);
  ASSERT_TRUE(result.has_value());
  PathIdType id = result.value();

  // Path should exist before removal
  EXPECT_NE(manager_->getPath(id), nullptr);

  // Remove should succeed
  EXPECT_FALSE(manager_->removePath(id).hasError());

  // Path should no longer exist
  EXPECT_EQ(manager_->getPath(id), nullptr);

  // Removing again should fail
  EXPECT_TRUE(manager_->removePath(id).hasError());
}

TEST_F(QuicPathManagerTest, RemoveCurrentPath) {
  auto result = manager_->addPath(localAddr1_, peerAddr1_);
  ASSERT_TRUE(result.has_value());
  PathIdType id = result.value();

  // Set as current path
  connState_->currentPathId = id;

  // Should not be able to remove current path
  EXPECT_TRUE(manager_->removePath(id).hasError());

  // Path should still exist
  EXPECT_NE(manager_->getPath(id), nullptr);
}

TEST_F(QuicPathManagerTest, RemovePathWithSocket) {
  auto socket = std::make_unique<QuicAsyncUDPSocketMock>();

  auto result = manager_->addPath(localAddr1_, peerAddr1_, std::move(socket));
  ASSERT_TRUE(result.has_value());
  PathIdType id = result.value();

  EXPECT_TRUE(manager_->removePath(id));
}

TEST_F(QuicPathManagerTest, GetPathById) {
  auto result = manager_->addPath(localAddr1_, peerAddr1_);
  ASSERT_TRUE(result.has_value());
  PathIdType id = result.value();

  auto path = manager_->getPath(id);
  ASSERT_NE(path, nullptr);
  EXPECT_EQ(path->id, id);
  EXPECT_EQ(path->peerAddress, peerAddr1_);
}

TEST_F(QuicPathManagerTest, GetPathByIdNotFound) {
  auto path = manager_->getPath(999);
  EXPECT_EQ(path, nullptr);
}

TEST_F(QuicPathManagerTest, GetPathByAddress) {
  auto result = manager_->addPath(localAddr1_, peerAddr1_);
  ASSERT_TRUE(result.has_value());
  PathIdType id = result.value();

  const folly::SocketAddress localAddr1Copy{"192.168.1.100", 8080};
  const folly::SocketAddress peerAddr1Copy{"192.168.1.1", 443};
  auto path = manager_->getPath(localAddr1Copy, peerAddr1Copy);
  ASSERT_NE(path, nullptr);
  EXPECT_EQ(path->id, id);
}

TEST_F(QuicPathManagerTest, GetPathByAddressNotFound) {
  auto path = manager_->getPath(localAddr1_, peerAddr1_);
  EXPECT_EQ(path, nullptr);
}

TEST_F(QuicPathManagerTest, AddRemoveAndGetPathByAddress) {
  auto result = manager_->addPath(localAddr1_, peerAddr1_);
  ASSERT_TRUE(result.has_value());
  PathIdType id = result.value();

  // Remove the path
  EXPECT_TRUE(manager_->removePath(id));

  // Try to get the path by address after removal
  auto path = manager_->getPath(localAddr1_, peerAddr1_);
  EXPECT_EQ(path, nullptr);
}

// Path Challenge/Response Tests

TEST_F(QuicPathManagerTest, GetNewPathChallengeData) {
  auto result = manager_->addPath(localAddr1_, peerAddr1_);
  ASSERT_TRUE(result.has_value());
  PathIdType id = result.value();

  auto challengeResult = manager_->getNewPathChallengeData(id);
  ASSERT_TRUE(challengeResult.has_value());

  EXPECT_NE(challengeResult.value(), 0);

  // Verify path has outstanding challenge data
  auto path = manager_->getPath(id);
  ASSERT_NE(path, nullptr);
  ASSERT_TRUE(path->outstandingChallengeData.has_value());
  EXPECT_EQ(path->outstandingChallengeData.value(), challengeResult.value());
}

TEST_F(QuicPathManagerTest, GetNewPathChallengeDataNonExistentPath) {
  auto result = manager_->getNewPathChallengeData(999);
  EXPECT_FALSE(result.has_value());
  EXPECT_EQ(result.error().code, LocalErrorCode::PATH_NOT_EXISTS);
}

TEST_F(QuicPathManagerTest, GetPathByChallengeData) {
  auto result = manager_->addPath(localAddr1_, peerAddr1_);
  ASSERT_TRUE(result.has_value());
  PathIdType id = result.value();

  auto challengeResult = manager_->getNewPathChallengeData(id);
  ASSERT_TRUE(challengeResult.has_value());

  auto path = manager_->getPathByChallengeData(challengeResult.value());
  ASSERT_NE(path, nullptr);
  EXPECT_EQ(path->id, id);
}

TEST_F(QuicPathManagerTest, GetPathByChallengeDataNotFound) {
  auto path = manager_->getPathByChallengeData(12345);
  EXPECT_EQ(path, nullptr);
}

TEST_F(QuicPathManagerTest, OnPathChallengeSent) {
  auto result = manager_->addPath(localAddr1_, peerAddr1_);
  ASSERT_TRUE(result.has_value());
  PathIdType id = result.value();

  auto challengeResult = manager_->getNewPathChallengeData(id);
  ASSERT_TRUE(challengeResult.has_value());

  // Add challenge to pending events
  PathChallengeFrame challenge(challengeResult.value());

  connState_->pendingEvents.pathChallenges.emplace(id, challenge);

  manager_->onPathChallengeSent(challenge);

  // Verify path status updated
  auto path = manager_->getPath(id);
  ASSERT_NE(path, nullptr);
  EXPECT_EQ(path->status, PathStatus::Validating);
  EXPECT_TRUE(path->lastChallengeSentTimestamp.has_value());
  EXPECT_TRUE(path->pathResponseDeadline.has_value());

  // Verify pending events updated
  EXPECT_TRUE(connState_->pendingEvents.schedulePathValidationTimeout);
}

TEST_F(QuicPathManagerTest, OnPathResponseReceived) {
  auto result = manager_->addPath(localAddr1_, peerAddr1_);
  ASSERT_TRUE(result.has_value());
  PathIdType id = result.value();

  // Set up path challenge
  auto challengeResult = manager_->getNewPathChallengeData(id);
  ASSERT_TRUE(challengeResult.has_value());

  PathChallengeFrame challenge(challengeResult.value());

  connState_->pendingEvents.pathChallenges.emplace(id, challenge);
  manager_->onPathChallengeSent(challenge);

  // Send path response
  PathResponseFrame response(challengeResult.value());
  response.pathData = challengeResult.value();

  auto validatedPath = manager_->onPathResponseReceived(response, id);
  ASSERT_NE(validatedPath, nullptr);
  EXPECT_EQ(validatedPath->id, id);
  EXPECT_EQ(validatedPath->status, PathStatus::Validated);
  EXPECT_TRUE(validatedPath->rttSample.has_value());
  EXPECT_FALSE(validatedPath->outstandingChallengeData.has_value());
  EXPECT_FALSE(validatedPath->lastChallengeSentTimestamp.has_value());
  EXPECT_FALSE(validatedPath->pathResponseDeadline.has_value());
}

TEST_F(QuicPathManagerTest, OnPathResponseReceivedStaleResponse) {
  PathResponseFrame response(12345); // Non-existent challenge data

  auto validatedPath = manager_->onPathResponseReceived(response, 0);
  EXPECT_EQ(validatedPath, nullptr);
}

TEST_F(QuicPathManagerTest, GetEarliestChallengeTimeout) {
  // No pending responses initially
  auto timeout = manager_->getEarliestChallengeTimeout();
  EXPECT_FALSE(timeout.has_value());

  // Add a path and send challenge
  auto result = manager_->addPath(localAddr1_, peerAddr1_);
  ASSERT_TRUE(result.has_value());
  PathIdType id = result.value();

  auto challengeResult = manager_->getNewPathChallengeData(id);
  ASSERT_TRUE(challengeResult.has_value());

  PathChallengeFrame challenge(challengeResult.value());

  connState_->pendingEvents.pathChallenges.emplace(id, challenge);
  manager_->onPathChallengeSent(challenge);

  // Should now have a timeout
  timeout = manager_->getEarliestChallengeTimeout();
  EXPECT_TRUE(timeout.has_value());
}

TEST_F(QuicPathManagerTest, OnPathValidationTimeoutExpired) {
  auto result = manager_->addPath(localAddr1_, peerAddr1_);
  ASSERT_TRUE(result.has_value());
  PathIdType id = result.value();

  // Set up path challenge
  auto challengeResult = manager_->getNewPathChallengeData(id);
  ASSERT_TRUE(challengeResult.has_value());

  PathChallengeFrame challenge(challengeResult.value());

  connState_->pendingEvents.pathChallenges.emplace(id, challenge);
  manager_->onPathChallengeSent(challenge);

  // Manually set deadline to past time to trigger timeout
  auto path = manager_->getPath(id);
  ASSERT_NE(path, nullptr);
  auto pathInfo = const_cast<PathInfo*>(path);
  pathInfo->pathResponseDeadline =
      std::chrono::steady_clock::now() - std::chrono::seconds(1);

  manager_->onPathValidationTimeoutExpired();

  // Path should be marked as NotValid
  path = manager_->getPath(id);
  ASSERT_NE(path, nullptr);
  EXPECT_EQ(path->status, PathStatus::NotValid);
  EXPECT_FALSE(path->outstandingChallengeData.has_value());
  EXPECT_FALSE(path->lastChallengeSentTimestamp.has_value());
  EXPECT_FALSE(path->pathResponseDeadline.has_value());
}

// Callback Tests

// Define a callback class inheriting from
// QuicPathManager::PathValidationCallback
class TestCallback : public QuicPathManager::PathValidationCallback {
 public:
  bool invoked{false};
  PathIdType pathId{0};
  PathStatus status{PathStatus::NotValid};

  void onPathValidationResult(const PathInfo& pathInfo) override {
    invoked = true;
    pathId = pathInfo.id;
    status = pathInfo.status;
  }

  ~TestCallback() override = default;
};

TEST_F(QuicPathManagerTest, PathValidationCallbackOnValidation) {
  TestCallback callback;
  manager_->setPathValidationCallback(&callback);

  // Add path and validate it
  auto result = manager_->addPath(localAddr1_, peerAddr1_);
  ASSERT_TRUE(result.has_value());
  PathIdType id = result.value();

  auto challengeResult = manager_->getNewPathChallengeData(id);
  ASSERT_TRUE(challengeResult.has_value());

  PathChallengeFrame challenge(challengeResult.value());

  connState_->pendingEvents.pathChallenges.emplace(id, challenge);
  manager_->onPathChallengeSent(challenge);

  PathResponseFrame response(challengeResult.value());

  manager_->onPathResponseReceived(response, id);

  EXPECT_TRUE(callback.invoked);
  EXPECT_EQ(callback.pathId, id);
  EXPECT_EQ(callback.status, PathStatus::Validated);
}

TEST_F(QuicPathManagerTest, PathValidationCallbackOnTimeout) {
  TestCallback callback;
  manager_->setPathValidationCallback(&callback);

  // Add path and start validation
  auto result = manager_->addPath(localAddr1_, peerAddr1_);
  ASSERT_TRUE(result.has_value());
  PathIdType id = result.value();

  auto challengeResult = manager_->getNewPathChallengeData(id);
  ASSERT_TRUE(challengeResult.has_value());

  PathChallengeFrame challenge(challengeResult.value());

  connState_->pendingEvents.pathChallenges.emplace(id, challenge);
  manager_->onPathChallengeSent(challenge);

  // Simulate validation timeout expiration (failure)
  // Manually set deadline to past time to trigger timeout
  auto path = manager_->getPath(id);
  ASSERT_NE(path, nullptr);
  auto pathInfo = const_cast<PathInfo*>(path);
  pathInfo->pathResponseDeadline =
      std::chrono::steady_clock::now() - std::chrono::seconds(1);

  manager_->onPathValidationTimeoutExpired();

  // Callback should be invoked with NotValid status
  EXPECT_TRUE(callback.invoked);
  EXPECT_EQ(callback.pathId, id);
  EXPECT_EQ(callback.status, PathStatus::NotValid);
}

// Congestion Control State Tests

TEST_F(QuicPathManagerTest, CacheCurrentCongestionAndRttState) {
  auto result = manager_->addPath(localAddr1_, peerAddr1_);
  ASSERT_TRUE(result.has_value());
  PathIdType id = result.value();

  connState_->currentPathId = id;
  connState_->congestionController =
      std::make_unique<MockCongestionController>();

  manager_->cacheCurrentCongestionAndRttState();

  auto path = manager_->getPath(id);
  ASSERT_NE(path, nullptr);
  EXPECT_TRUE(path->cachedCCAndRttState.has_value());
  EXPECT_EQ(path->cachedCCAndRttState->srtt, connState_->lossState.srtt);
  EXPECT_EQ(path->cachedCCAndRttState->lrtt, connState_->lossState.lrtt);
  EXPECT_EQ(path->cachedCCAndRttState->rttvar, connState_->lossState.rttvar);
  EXPECT_EQ(path->cachedCCAndRttState->mrtt, connState_->lossState.mrtt);
}

TEST_F(QuicPathManagerTest, RestoreCongestionControlAndRttStateWithCache) {
  auto result = manager_->addValidatedPath(localAddr1_, peerAddr1_);
  ASSERT_TRUE(result.has_value());
  PathIdType id = result.value();

  connState_->currentPathId = id;
  connState_->congestionController =
      std::make_unique<MockCongestionController>();

  // Cache the state
  manager_->cacheCurrentCongestionAndRttState();

  // Clear the congestion controller to simulate migration
  connState_->congestionController.reset();

  // Restore should succeed and return true
  bool ccaRestored =
      manager_->maybeRestoreCongestionControlAndRttStateForCurrentPath();
  EXPECT_TRUE(ccaRestored);
  EXPECT_NE(connState_->congestionController, nullptr);
}

TEST_F(QuicPathManagerTest, RestoreCongestionControlAndRttStateWithRttSample) {
  auto result = manager_->addPath(localAddr1_, peerAddr1_);
  ASSERT_TRUE(result.has_value());
  PathIdType id = result.value();

  connState_->currentPathId = id;

  // Set RTT sample on path
  auto path = manager_->getPath(id);
  ASSERT_NE(path, nullptr);
  auto pathInfo = const_cast<PathInfo*>(path);
  pathInfo->rttSample = std::chrono::microseconds(200000); // 200ms

  // Restore should use RTT sample
  bool ccaRestored =
      manager_->maybeRestoreCongestionControlAndRttStateForCurrentPath();
  EXPECT_FALSE(ccaRestored); // No CC was restored
  EXPECT_EQ(connState_->lossState.srtt, std::chrono::microseconds(200000));
  EXPECT_EQ(connState_->lossState.lrtt, std::chrono::microseconds(200000));
  EXPECT_EQ(connState_->lossState.rttvar, std::chrono::microseconds(0));
  EXPECT_EQ(connState_->lossState.mrtt, std::chrono::microseconds(200000));
}

TEST_F(QuicPathManagerTest, RestoreCongestionControlAndRttStateReset) {
  auto result = manager_->addPath(localAddr1_, peerAddr1_);
  ASSERT_TRUE(result.has_value());
  PathIdType id = result.value();

  connState_->currentPathId = id;

  // No cached state or RTT sample - should reset to defaults
  bool ccaRestored =
      manager_->maybeRestoreCongestionControlAndRttStateForCurrentPath();
  EXPECT_FALSE(ccaRestored);
  EXPECT_EQ(connState_->lossState.srtt, std::chrono::microseconds(0));
  EXPECT_EQ(connState_->lossState.lrtt, std::chrono::microseconds(0));
  EXPECT_EQ(connState_->lossState.rttvar, std::chrono::microseconds(0));
  EXPECT_EQ(connState_->lossState.mrtt, kDefaultMinRtt);
}

// Writable Bytes Tests

TEST_F(QuicPathManagerTest, OnPathPacketSent) {
  // Create a path but we need it to be unvalidated for writableBytes tracking
  // We'll simulate receiving a path challenge first, which creates an
  // unvalidated path
  auto result = manager_->addPath(localAddr1_, peerAddr1_);
  ASSERT_TRUE(result.has_value());
  PathIdType id = result.value();

  // First simulate that this path received a packet to give it writableBytes
  manager_->onPathPacketReceived(id);

  auto path = manager_->getPath(id);
  ASSERT_NE(path, nullptr);
  uint64_t initialWritableBytes = path->writableBytes;

  // Send a packet to decrement writable bytes
  manager_->onPathPacketSent(id, 100);

  path = manager_->getPath(id);
  ASSERT_NE(path, nullptr);
  // The writable bytes should be decremented by the packet size
  EXPECT_EQ(path->writableBytes, initialWritableBytes - 100);
}

TEST_F(QuicPathManagerTest, OnPathPacketSentValidatedPath) {
  auto result = manager_->addValidatedPath(localAddr1_, peerAddr1_);
  ASSERT_TRUE(result.has_value());
  PathIdType id = result.value();

  auto path = manager_->getPath(id);
  ASSERT_NE(path, nullptr);
  uint64_t initialWritableBytes = path->writableBytes;

  // Validated paths should not have writable bytes decremented
  manager_->onPathPacketSent(id, 100);

  path = manager_->getPath(id);
  ASSERT_NE(path, nullptr);
  EXPECT_EQ(path->writableBytes, initialWritableBytes);
}

TEST_F(QuicPathManagerTest, OnPathPacketReceived) {
  auto result = manager_->addPath(localAddr1_, peerAddr1_);
  ASSERT_TRUE(result.has_value());
  PathIdType id = result.value();

  auto path = manager_->getPath(id);
  ASSERT_NE(path, nullptr);
  uint64_t initialWritableBytes = path->writableBytes;

  manager_->onPathPacketReceived(id);

  path = manager_->getPath(id);
  ASSERT_NE(path, nullptr);
  uint64_t expectedIncrease = connState_->transportSettings.limitedCwndInMss *
      connState_->udpSendPacketLen;
  EXPECT_EQ(path->writableBytes, initialWritableBytes + expectedIncrease);
}

TEST_F(QuicPathManagerTest, OnPathPacketReceivedValidatedPath) {
  auto result = manager_->addValidatedPath(localAddr1_, peerAddr1_);
  ASSERT_TRUE(result.has_value());
  PathIdType id = result.value();

  auto path = manager_->getPath(id);
  ASSERT_NE(path, nullptr);
  uint64_t initialWritableBytes = path->writableBytes;

  // Validated paths should not have writable bytes incremented
  manager_->onPathPacketReceived(id);

  path = manager_->getPath(id);
  ASSERT_NE(path, nullptr);
  EXPECT_EQ(path->writableBytes, initialWritableBytes);
}

// Edge Cases and Error Conditions

TEST_F(QuicPathManagerTest, OnPathPacketSentNonExistentPath) {
  // Should not crash when called with non-existent path
  manager_->onPathPacketSent(999, 100);
}

TEST_F(QuicPathManagerTest, OnPathPacketReceivedNonExistentPath) {
  // Should not crash when called with non-existent path
  manager_->onPathPacketReceived(999);
}

TEST_F(QuicPathManagerTest, WritableBytesUnderflow) {
  auto result = manager_->addPath(localAddr1_, peerAddr1_);
  ASSERT_TRUE(result.has_value());
  PathIdType id = result.value();

  auto path = manager_->getPath(id);
  ASSERT_NE(path, nullptr);
  uint64_t initialWritableBytes = path->writableBytes;

  // Send more bytes than available
  manager_->onPathPacketSent(id, initialWritableBytes + 100);

  path = manager_->getPath(id);
  ASSERT_NE(path, nullptr);
  EXPECT_EQ(path->writableBytes, 0); // Should not underflow
}

TEST_F(QuicPathManagerTest, WritableBytesMaxLimit) {
  auto result = manager_->addPath(localAddr1_, peerAddr1_);
  ASSERT_TRUE(result.has_value());
  PathIdType id = result.value();

  // Increase writable bytes to near maximum
  for (int i = 0; i < 100; ++i) {
    manager_->onPathPacketReceived(id);
  }

  auto path = manager_->getPath(id);
  ASSERT_NE(path, nullptr);
  uint64_t maxLimit = kDefaultMaxCwndInMss * connState_->udpSendPacketLen;
  EXPECT_LE(path->writableBytes, maxLimit);
}

// Connection ID Management Tests

TEST_F(QuicPathManagerTest, AssignDestinationCidForPath_Success) {
  // Setup: Initialize current peer connection ID (required for
  // getNextAvailablePeerConnectionId)
  connState_->serverConnectionId =
      ConnectionId::createAndMaybeCrash({0, 0, 0, 0});

  // Add peer connection IDs
  connState_->peerConnectionIds.emplace_back(
      ConnectionId::createAndMaybeCrash({1, 2, 3, 4}), 1);
  connState_->peerConnectionIds.emplace_back(
      ConnectionId::createAndMaybeCrash({5, 6, 7, 8}), 2);

  // Create a new path
  auto result = manager_->addPath(localAddr1_, peerAddr1_);
  ASSERT_TRUE(result.has_value());
  PathIdType pathId = result.value();

  // Verify path doesn't have a destination CID initially
  auto path = manager_->getPath(pathId);
  ASSERT_NE(path, nullptr);
  EXPECT_FALSE(path->destinationConnectionId.has_value());

  // Assign a destination CID to the path
  auto assignResult = manager_->assignDestinationCidForPath(pathId);
  EXPECT_FALSE(assignResult.hasError());

  // Verify the path now has a destination CID
  path = manager_->getPath(pathId);
  ASSERT_TRUE(path->destinationConnectionId.has_value());

  // Verify the assigned CID is one of the peer CIDs and is marked as in use
  auto assignedCid = path->destinationConnectionId.value();
  auto cidIt = std::find_if(
      connState_->peerConnectionIds.begin(),
      connState_->peerConnectionIds.end(),
      [&assignedCid](const auto& cidData) {
        return cidData.connId == assignedCid;
      });
  ASSERT_NE(cidIt, connState_->peerConnectionIds.end());
  EXPECT_TRUE(cidIt->inUse);
}

TEST_F(QuicPathManagerTest, AssignDestinationCidForPath_CurrentPathError) {
  // Setup: Initialize current peer connection ID
  connState_->serverConnectionId =
      ConnectionId::createAndMaybeCrash({0, 0, 0, 0});

  // Add peer connection IDs
  connState_->peerConnectionIds.emplace_back(
      ConnectionId::createAndMaybeCrash({1, 2, 3, 4}), 1);

  // Try to assign CID to current path - should fail
  auto assignResult =
      manager_->assignDestinationCidForPath(connState_->currentPathId);
  EXPECT_TRUE(assignResult.hasError());
  EXPECT_EQ(assignResult.error().code, LocalErrorCode::PATH_MANAGER_ERROR);
}

TEST_F(QuicPathManagerTest, AssignDestinationCidForPath_NonExistentPath) {
  // Setup: Initialize current peer connection ID
  connState_->serverConnectionId =
      ConnectionId::createAndMaybeCrash({0, 0, 0, 0});

  // Add peer connection IDs
  connState_->peerConnectionIds.emplace_back(
      ConnectionId::createAndMaybeCrash({1, 2, 3, 4}), 1);

  // Try to assign CID to non-existent path
  PathIdType nonExistentPathId = 99999;
  auto assignResult = manager_->assignDestinationCidForPath(nonExistentPathId);
  EXPECT_TRUE(assignResult.hasError());
  EXPECT_EQ(assignResult.error().code, LocalErrorCode::PATH_NOT_EXISTS);
}

TEST_F(QuicPathManagerTest, AssignDestinationCidForPath_NoAvailableCids) {
  // Setup: Initialize current peer connection ID
  connState_->serverConnectionId =
      ConnectionId::createAndMaybeCrash({0, 0, 0, 0});

  // Add peer connection IDs but mark all as in use
  connState_->peerConnectionIds.emplace_back(
      ConnectionId::createAndMaybeCrash({1, 2, 3, 4}), 1);
  connState_->peerConnectionIds[0].inUse = true;

  // Create a new path
  auto result = manager_->addPath(localAddr1_, peerAddr1_);
  ASSERT_TRUE(result.has_value());
  PathIdType pathId = result.value();

  // Try to assign CID when none are available - should fail
  auto assignResult = manager_->assignDestinationCidForPath(pathId);
  EXPECT_TRUE(assignResult.hasError());
  EXPECT_EQ(assignResult.error().code, LocalErrorCode::INTERNAL_ERROR);
}

TEST_F(QuicPathManagerTest, SetDestinationCidForPath_Success) {
  // Create a new path
  auto result = manager_->addPath(localAddr1_, peerAddr1_);
  ASSERT_TRUE(result.has_value());
  PathIdType pathId = result.value();

  // Set a specific destination CID for the path
  auto customCid = ConnectionId::createAndMaybeCrash({9, 9, 9, 9});
  auto setResult = manager_->setDestinationCidForPath(pathId, customCid);
  EXPECT_FALSE(setResult.hasError());

  // Verify the path has the specified CID
  auto path = manager_->getPath(pathId);
  ASSERT_NE(path, nullptr);
  ASSERT_TRUE(path->destinationConnectionId.has_value());
  EXPECT_EQ(path->destinationConnectionId.value(), customCid);
}

TEST_F(QuicPathManagerTest, SetDestinationCidForPath_NonExistentPath) {
  // Try to set CID for non-existent path
  PathIdType nonExistentPathId = 99999;
  auto customCid = ConnectionId::createAndMaybeCrash({9, 9, 9, 9});
  auto setResult =
      manager_->setDestinationCidForPath(nonExistentPathId, customCid);
  EXPECT_TRUE(setResult.hasError());
  EXPECT_EQ(setResult.error().code, LocalErrorCode::PATH_NOT_EXISTS);
}

TEST_F(QuicPathManagerTest, RemovePath_RetiresPeerConnectionId) {
  // Setup: Initialize current peer connection ID
  connState_->serverConnectionId =
      ConnectionId::createAndMaybeCrash({0, 0, 0, 0});

  // Add peer connection IDs
  connState_->peerConnectionIds.emplace_back(
      ConnectionId::createAndMaybeCrash({1, 2, 3, 4}), 1);

  // Create a new path and assign a CID
  auto result = manager_->addPath(localAddr1_, peerAddr1_);
  ASSERT_TRUE(result.has_value());
  PathIdType pathId = result.value();

  auto assignResult = manager_->assignDestinationCidForPath(pathId);
  ASSERT_FALSE(assignResult.hasError());

  auto path = manager_->getPath(pathId);
  ASSERT_NE(path, nullptr);
  ASSERT_TRUE(path->destinationConnectionId.has_value());
  auto assignedCid = path->destinationConnectionId.value();

  // Clear pending frames before deletion
  connState_->pendingEvents.frames.clear();

  // Remove the path
  auto removeResult = manager_->removePath(pathId);
  EXPECT_FALSE(removeResult.hasError());

  // Verify RETIRE_CONNECTION_ID frame was generated
  bool foundRetireFrame = false;
  for (const auto& frame : connState_->pendingEvents.frames) {
    if (frame.asRetireConnectionIdFrame()) {
      foundRetireFrame = true;
      break;
    }
  }
  EXPECT_TRUE(foundRetireFrame);

  // Verify the CID was removed from peerConnectionIds
  auto cidStillExists = std::find_if(
                            connState_->peerConnectionIds.begin(),
                            connState_->peerConnectionIds.end(),
                            [&assignedCid](const auto& cidData) {
                              return cidData.connId == assignedCid;
                            }) != connState_->peerConnectionIds.end();
  EXPECT_FALSE(cidStillExists);
}

TEST_F(QuicPathManagerTest, RemovePath_WithoutDestinationCid) {
  // Create a new path without assigning a destination CID
  auto result = manager_->addPath(localAddr1_, peerAddr1_);
  ASSERT_TRUE(result.has_value());
  PathIdType pathId = result.value();

  // Clear pending frames before deletion
  connState_->pendingEvents.frames.clear();

  // Remove the path - should succeed without retiring CID
  auto removeResult = manager_->removePath(pathId);
  EXPECT_FALSE(removeResult.hasError());

  // Verify no RETIRE_CONNECTION_ID frame was generated
  bool foundRetireFrame = false;
  for (const auto& frame : connState_->pendingEvents.frames) {
    if (frame.asRetireConnectionIdFrame()) {
      foundRetireFrame = true;
      break;
    }
  }
  EXPECT_FALSE(foundRetireFrame);
}

TEST_F(QuicPathManagerTest, SwitchCurrentPath_CachesOldCid_Client) {
  // Setup for client
  connState_->nodeType = QuicNodeType::Client;
  connState_->serverConnectionId = ConnectionId::createAndMaybeCrash({1, 2, 3});

  auto result = manager_->addPath(localAddr1_, peerAddr1_);
  ASSERT_TRUE(result.has_value());
  PathIdType oldPathId = connState_->currentPathId = result.value();
  auto oldCid = *connState_->serverConnectionId;

  // Add peer connection IDs
  connState_->peerConnectionIds.emplace_back(
      ConnectionId::createAndMaybeCrash({1, 2, 3}), 0);
  connState_->peerConnectionIds.emplace_back(
      ConnectionId::createAndMaybeCrash({4, 5, 6}), 1);

  // Create a new path with a destination CID
  result = manager_->addPath(localAddr2_, peerAddr2_);
  ASSERT_TRUE(result.has_value());
  PathIdType newPathId = result.value();

  auto newCid = ConnectionId::createAndMaybeCrash({4, 5, 6});
  auto setResult = manager_->setDestinationCidForPath(newPathId, newCid);
  ASSERT_FALSE(setResult.hasError());

  // Switch to the new path
  auto switchResult = manager_->switchCurrentPath(newPathId);
  EXPECT_FALSE(switchResult.hasError());

  // Verify the server connection ID was updated
  EXPECT_EQ(*connState_->serverConnectionId, newCid);

  // Verify the old CID was cached in the old path
  auto oldPath = manager_->getPath(oldPathId);
  ASSERT_NE(oldPath, nullptr);
  EXPECT_EQ(oldPath->destinationConnectionId, oldCid);
}

TEST_F(QuicPathManagerTest, SwitchCurrentPath_CachesOldCid_Server) {
  // Setup for server
  connState_->nodeType = QuicNodeType::Server;
  connState_->clientConnectionId = ConnectionId::createAndMaybeCrash({1, 2, 3});

  auto result = manager_->addPath(localAddr1_, peerAddr1_);
  ASSERT_TRUE(result.has_value());
  PathIdType oldPathId = connState_->currentPathId = result.value();
  auto oldCid = *connState_->clientConnectionId;

  // Add peer connection IDs
  connState_->peerConnectionIds.emplace_back(
      ConnectionId::createAndMaybeCrash({1, 2, 3}), 0);
  connState_->peerConnectionIds.emplace_back(
      ConnectionId::createAndMaybeCrash({7, 8, 9}), 1);

  // Create a new path with a destination CID
  result = manager_->addPath(localAddr2_, peerAddr2_);
  ASSERT_TRUE(result.has_value());
  PathIdType newPathId = result.value();

  auto newCid = ConnectionId::createAndMaybeCrash({7, 8, 9});
  auto setResult = manager_->setDestinationCidForPath(newPathId, newCid);
  ASSERT_FALSE(setResult.hasError());

  // Switch to the new path
  auto switchResult = manager_->switchCurrentPath(newPathId);
  EXPECT_FALSE(switchResult.hasError());

  // Verify the client connection ID was updated
  EXPECT_EQ(*connState_->clientConnectionId, newCid);

  // Verify the old CID was cached in the old path
  auto oldPath = manager_->getPath(oldPathId);
  ASSERT_NE(oldPath, nullptr);
  EXPECT_EQ(oldPath->destinationConnectionId, oldCid);
}

TEST_F(QuicPathManagerTest, SwitchCurrentPath_WithoutDestinationCid) {
  // Create a new path without a destination CID
  auto result = manager_->addPath(localAddr2_, peerAddr2_);
  ASSERT_TRUE(result.has_value());
  PathIdType newPathId = result.value();

  // Mark the new path as validated

  // Clear pending frames
  connState_->pendingEvents.frames.clear();

  // Switch to the new path - should succeed without retiring CID
  auto switchResult = manager_->switchCurrentPath(newPathId);
  EXPECT_FALSE(switchResult.hasError());

  // Verify no RETIRE_CONNECTION_ID frame was generated
  bool foundRetireFrame = false;
  for (const auto& frame : connState_->pendingEvents.frames) {
    if (frame.asRetireConnectionIdFrame()) {
      foundRetireFrame = true;
      break;
    }
  }
  EXPECT_FALSE(foundRetireFrame);
}

TEST_F(QuicPathManagerTest, MultiplePathsWithDifferentDestinationCids) {
  // Setup: Initialize current peer connection ID
  connState_->serverConnectionId =
      ConnectionId::createAndMaybeCrash({0, 0, 0, 0});

  // Add multiple peer connection IDs
  connState_->peerConnectionIds.emplace_back(
      ConnectionId::createAndMaybeCrash({1, 1, 1, 1}), 1);
  connState_->peerConnectionIds.emplace_back(
      ConnectionId::createAndMaybeCrash({2, 2, 2, 2}), 2);
  connState_->peerConnectionIds.emplace_back(
      ConnectionId::createAndMaybeCrash({3, 3, 3, 3}), 3);

  // Create multiple paths
  auto result1 = manager_->addPath(localAddr1_, peerAddr1_);
  auto result2 = manager_->addPath(localAddr2_, peerAddr2_);
  ASSERT_TRUE(result1.has_value());
  ASSERT_TRUE(result2.has_value());

  // Assign CIDs to both paths
  auto assign1 = manager_->assignDestinationCidForPath(result1.value());
  auto assign2 = manager_->assignDestinationCidForPath(result2.value());
  EXPECT_FALSE(assign1.hasError());
  EXPECT_FALSE(assign2.hasError());

  // Verify each path has a different destination CID
  auto path1 = manager_->getPath(result1.value());
  auto path2 = manager_->getPath(result2.value());
  ASSERT_NE(path1, nullptr);
  ASSERT_NE(path2, nullptr);
  ASSERT_TRUE(path1->destinationConnectionId.has_value());
  ASSERT_TRUE(path2->destinationConnectionId.has_value());
  EXPECT_NE(
      path1->destinationConnectionId.value(),
      path2->destinationConnectionId.value());

  // Verify both CIDs are marked as in use
  int inUseCount = 0;
  for (const auto& cidData : connState_->peerConnectionIds) {
    if (cidData.inUse) {
      inUseCount++;
    }
  }
  EXPECT_EQ(inUseCount, 2);
}

} // namespace quic::test
