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

} // namespace quic::test
