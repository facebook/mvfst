/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <quic/server/test/QuicServerTransportTestUtil.h>

#include <quic/QuicConstants.h>
#include <quic/codec/QuicPacketBuilder.h>

#include <quic/logging/FileQLogger.h>
#include <quic/priority/HTTPPriorityQueue.h>

#include <quic/state/test/Mocks.h>

using namespace testing;
using namespace folly;

namespace quic {
class PathManagerTestAccessor {
 public:
  static PathInfo& getNonConstPathInfo(
      QuicConnectionStateBase& conn,
      PathIdType pathId) {
    return conn.pathManager->pathIdToInfo_.at(pathId);
  }
};
} // namespace quic

namespace quic::test {

struct MigrationParam {
  Optional<uint64_t> clientSentActiveConnIdTransportParam;
};

class QuicServerTransportAllowMigrationTest
    : public QuicServerTransportAfterStartTestBase,
      public WithParamInterface<MigrationParam> {
 public:
  void SetUpChild() override {
    QuicServerTransportAfterStartTestBase::SetUpChild();
    // Add peer connection IDs
    server->getNonConstConn().peerConnectionIds.emplace_back(
        ConnectionId::createAndMaybeCrash({5, 6, 7, 8}), 1);
    server->getNonConstConn().peerConnectionIds.emplace_back(
        ConnectionId::createAndMaybeCrash({9, 10, 11, 12}), 2);
  }

  void TearDown() override {
    if (server) {
      server->closeNow(std::nullopt);
    }
  }

  bool getDisableMigration() override {
    return false;
  }

  void initializeServerHandshake() override {
    fakeHandshake = new FakeServerHandshake(
        server->getNonConstConn(),
        FizzServerQuicHandshakeContext::Builder().build(),
        false,
        false,
        GetParam().clientSentActiveConnIdTransportParam);
    ON_CALL(*fakeHandshake, writeNewSessionTicket)
        .WillByDefault(Return(quic::Expected<void, QuicError>{}));
  }

  PathChallengeFrame* getFirstOutstandingPathChallenge() {
    auto match =
        findFrameInPacketFunc<QuicSimpleFrame::Type::PathChallengeFrame>();
    auto outstandingPacket =
        findOutstandingPacket(server->getConnectionState(), match);
    if (outstandingPacket) {
      auto& packet = outstandingPacket->packet;
      auto& frames = packet.frames;
      for (auto& frame : frames) {
        if (auto simpleFrame = frame.asQuicSimpleFrame()) {
          if (simpleFrame->type() ==
              QuicSimpleFrame::Type::PathChallengeFrame) {
            return simpleFrame->asPathChallengeFrame();
          }
        }
      }
    }
    return nullptr;
  }

  PathResponseFrame* getFirstOutstandingPathResponse() {
    auto match =
        findFrameInPacketFunc<QuicSimpleFrame::Type::PathResponseFrame>();
    auto outstandingPacket =
        findOutstandingPacket(server->getConnectionState(), match);
    if (outstandingPacket) {
      auto& packet = outstandingPacket->packet;
      auto& frames = packet.frames;
      for (auto& frame : frames) {
        if (auto simpleFrame = frame.asQuicSimpleFrame()) {
          if (simpleFrame->type() == QuicSimpleFrame::Type::PathResponseFrame) {
            return simpleFrame->asPathResponseFrame();
          }
        }
      }
    }
    return nullptr;
  }

  quic::PacketBuilderInterface::Packet makePacketWithPathChallegeFrame(
      uint64_t pathChallengeData) {
    ShortHeader header(
        ProtectionType::KeyPhaseZero,
        *server->getConn().serverConnectionId,
        clientNextAppDataPacketNum++);
    RegularQuicPacketBuilder builder(
        server->getConn().udpSendPacketLen,
        std::move(header),
        0 /* largestAcked */);
    CHECK(!builder.encodePacketHeader().hasError());
    CHECK(builder.canBuildPacket());

    CHECK(!writeSimpleFrame(PathChallengeFrame(pathChallengeData), builder)
               .hasError());
    auto packet = std::move(builder).buildPacket();
    return packet;
  }

  quic::PacketBuilderInterface::Packet makePacketWithPathResponseFrame(
      uint64_t pathChallengeData) {
    ShortHeader header(
        ProtectionType::KeyPhaseZero,
        *server->getConn().serverConnectionId,
        clientNextAppDataPacketNum++);
    RegularQuicPacketBuilder builder(
        server->getConn().udpSendPacketLen,
        std::move(header),
        0 /* largestAcked */);
    CHECK(!builder.encodePacketHeader().hasError());
    CHECK(builder.canBuildPacket());

    CHECK(!writeSimpleFrame(PathResponseFrame(pathChallengeData), builder)
               .hasError());
    auto packet = std::move(builder).buildPacket();
    return packet;
  }
};

INSTANTIATE_TEST_SUITE_P(
    QuicServerTransportMigrationTests,
    QuicServerTransportAllowMigrationTest,
    Values(
        MigrationParam{std::nullopt},
        MigrationParam{2},
        MigrationParam{4},
        MigrationParam{9},
        MigrationParam{50}));

TEST_P(
    QuicServerTransportAllowMigrationTest,
    SendsCorrectNumberOfNewConnectionIdsBasedOnParam) {
  auto& conn = server->getNonConstConn();

  auto expectedPeerLimit =
      GetParam().clientSentActiveConnIdTransportParam.value_or(
          kDefaultActiveConnectionIdLimit);
  ASSERT_EQ(conn.peerActiveConnectionIdLimit, expectedPeerLimit);

  // The server should issue active_connection_id_limit - 1
  // NEW_CONNECTION_IDs, since one is in use for the handshake.
  auto expectedCountCIDIssued =
      std::min(kMaxActiveConnectionIdLimit, expectedPeerLimit) - 1;
  ASSERT_GE(expectedCountCIDIssued, 0);

  // Count the number of NEW_CONNECTION_ID frames in outstanding packets.
  size_t numNewConnIdFrames = 0;
  for (const auto& pkt : conn.outstandings.packets) {
    for (const auto& frame : pkt.packet.frames) {
      if (auto simpleFrame = frame.asQuicSimpleFrame()) {
        if (simpleFrame->type() ==
            QuicSimpleFrame::Type::NewConnectionIdFrame) {
          ++numNewConnIdFrames;
        }
      }
    }
  }

  EXPECT_EQ(numNewConnIdFrames, expectedCountCIDIssued);
}

TEST_P(
    QuicServerTransportAllowMigrationTest,
    ReceiveProbeFromNewPeerAddressWithoutMigratingLongGracePeriod) {
  auto qLogger = std::make_shared<FileQLogger>(VantagePoint::Server);
  auto& conn = server->getNonConstConn();
  conn.qLogger = qLogger;
  conn.transportSettings.disableMigration = false;

  EXPECT_CALL(*quicStats_, onConnectionMigration).Times(0);
  EXPECT_CALL(*quicStats_, onPathAdded).Times(1);
  EXPECT_CALL(*quicStats_, onPathValidationSuccess).Times(1);
  EXPECT_CALL(*quicStats_, onPathValidationFailure).Times(0);

  // Add additional peer id so PathResponse completes.
  conn.peerConnectionIds.emplace_back(
      ConnectionId::createAndMaybeCrash({1, 2, 3, 4}), 1);

  // Deliver a path challenge from a new peer address
  auto incomingPathChallengeData = 123;
  folly::SocketAddress newPeer("100.101.102.103", 23456);
  {
    auto packet = makePacketWithPathChallegeFrame(incomingPathChallengeData);
    auto packetData = packetToBuf(packet);
    deliverData(std::move(packetData), true, &newPeer);
  }

  // Step 1: New path is created and is validating
  auto newPath = conn.pathManager->getPath(server->getLocalAddress(), newPeer);
  ASSERT_TRUE(newPath);
  EXPECT_NE(conn.currentPathId, newPath->id);
  EXPECT_EQ(newPath->status, PathStatus::Validating);

  // A path response and a new path challege should be outstanding for the path
  auto outstandingResponse = getFirstOutstandingPathResponse();
  ASSERT_TRUE(outstandingResponse);
  EXPECT_EQ(outstandingResponse->pathData, incomingPathChallengeData);

  auto outstandingChallenge = getFirstOutstandingPathChallenge();
  ASSERT_TRUE(outstandingChallenge);
  // The outstanding challenge data can be used to retrieve the path
  auto sameNewpath =
      conn.pathManager->getPathByChallengeData(outstandingChallenge->pathData);
  ASSERT_TRUE(sameNewpath);
  EXPECT_EQ(sameNewpath->id, newPath->id);

  // Step 2: Deliver a path response to validate the new peer
  {
    // Set a very high srtt to ensure that the new path is not immediately
    // deleted. The grace period for the client to migrate is
    // kProbedPathGracePeriodInSRTT * SRTT
    conn.lossState.srtt = 10s;

    auto packet =
        makePacketWithPathResponseFrame(outstandingChallenge->pathData);
    auto packetData = packetToBuf(packet);
    deliverData(std::move(packetData), true, &newPeer);
  }
  EXPECT_NE(conn.currentPathId, newPath->id);
  EXPECT_EQ(newPath->status, PathStatus::Validated);
  EXPECT_TRUE(newPath->pathValidationTime.has_value());
}

TEST_P(
    QuicServerTransportAllowMigrationTest,
    ReceiveProbeFromNewPeerAddressWithoutMigratingShortGracePeriod) {
  auto qLogger = std::make_shared<FileQLogger>(VantagePoint::Server);
  auto& conn = server->getNonConstConn();
  conn.qLogger = qLogger;
  conn.transportSettings.disableMigration = false;

  EXPECT_CALL(*quicStats_, onConnectionMigration).Times(0);
  EXPECT_CALL(*quicStats_, onPathAdded).Times(1);
  EXPECT_CALL(*quicStats_, onPathValidationSuccess).Times(1);
  EXPECT_CALL(*quicStats_, onPathValidationFailure).Times(0);

  // Add additional peer id so PathResponse completes.
  conn.peerConnectionIds.emplace_back(
      ConnectionId::createAndMaybeCrash({1, 2, 3, 4}), 1);

  // Deliver a path challenge from a new peer address
  auto incomingPathChallengeData = 123;
  folly::SocketAddress newPeer("100.101.102.103", 23456);
  {
    auto packet = makePacketWithPathChallegeFrame(incomingPathChallengeData);
    auto packetData = packetToBuf(packet);
    deliverData(std::move(packetData), true, &newPeer);
  }

  // Step 1: New path is created and is validating
  auto newPath = conn.pathManager->getPath(server->getLocalAddress(), newPeer);
  auto newPathId = newPath->id;
  ASSERT_TRUE(newPath);
  EXPECT_NE(conn.currentPathId, newPath->id);
  EXPECT_EQ(newPath->status, PathStatus::Validating);

  // A path response and a new path challege should be outstanding for the path
  auto outstandingResponse = getFirstOutstandingPathResponse();
  ASSERT_TRUE(outstandingResponse);
  EXPECT_EQ(outstandingResponse->pathData, incomingPathChallengeData);

  auto outstandingChallenge = getFirstOutstandingPathChallenge();
  ASSERT_TRUE(outstandingChallenge);
  // The outstanding challenge data can be used to retrieve the path
  auto sameNewpath =
      conn.pathManager->getPathByChallengeData(outstandingChallenge->pathData);
  ASSERT_TRUE(sameNewpath);
  EXPECT_EQ(sameNewpath->id, newPath->id);

  // Step 2: Deliver a path response to validate the new peer
  {
    // Set no grace period for the client to migrate. This should immediately
    // delete the validated non primary path.
    conn.lossState.srtt = 0s;

    auto packet =
        makePacketWithPathResponseFrame(outstandingChallenge->pathData);
    auto packetData = packetToBuf(packet);
    deliverData(std::move(packetData), true, &newPeer);
  }
  // The client didn't migrate before the grace period so the path was deleted.
  EXPECT_FALSE(conn.pathManager->getPath(newPathId));
}

TEST_P(
    QuicServerTransportAllowMigrationTest,
    ReceiveProbeFromNewPeerAddressWithMigrating) {
  auto qLogger = std::make_shared<FileQLogger>(VantagePoint::Server);
  auto& conn = server->getNonConstConn();
  conn.qLogger = qLogger;
  conn.transportSettings.disableMigration = false;

  EXPECT_CALL(*quicStats_, onConnectionMigration).Times(1);
  EXPECT_CALL(*quicStats_, onPathAdded).Times(1);
  EXPECT_CALL(*quicStats_, onPathValidationSuccess).Times(1);
  EXPECT_CALL(*quicStats_, onPathValidationFailure).Times(0);

  // Add additional peer id so PathResponse completes.
  conn.peerConnectionIds.emplace_back(
      ConnectionId::createAndMaybeCrash({1, 2, 3, 4}), 1);

  // Deliver a path challenge from a new peer address
  auto incomingPathChallengeData = 123;
  folly::SocketAddress newPeer("100.101.102.103", 23456);
  {
    auto packet = makePacketWithPathChallegeFrame(incomingPathChallengeData);
    auto packetData = packetToBuf(packet);
    deliverData(std::move(packetData), true, &newPeer);
  }

  // Step 1: New path is created and is validating
  auto newPath = conn.pathManager->getPath(server->getLocalAddress(), newPeer);
  ASSERT_TRUE(newPath);
  EXPECT_NE(conn.currentPathId, newPath->id);
  EXPECT_EQ(newPath->status, PathStatus::Validating);
  EXPECT_GE(newPath->writableBytes, conn.udpSendPacketLen);

  // A path response and a new path challege should be outstanding for the path
  auto outstandingResponse = getFirstOutstandingPathResponse();
  ASSERT_TRUE(outstandingResponse);
  EXPECT_EQ(outstandingResponse->pathData, incomingPathChallengeData);

  auto outstandingChallenge = getFirstOutstandingPathChallenge();
  ASSERT_TRUE(outstandingChallenge);
  // The outstanding challenge data can be used to retrieve the path
  auto sameNewpath =
      conn.pathManager->getPathByChallengeData(outstandingChallenge->pathData);
  ASSERT_TRUE(sameNewpath);
  EXPECT_EQ(sameNewpath->id, newPath->id);

  // Step 2: Client migrates to the new path before the server's path is
  // validated
  {
    auto data = IOBuf::copyBuffer("migration migration migration");
    auto streamPacket = packetToBuf(createStreamPacket(
        *clientConnectionId,
        *server->getConn().serverConnectionId,
        clientNextAppDataPacketNum++,
        2,
        *data,
        0 /* cipherOverhead */,
        0 /* largestAcked */));
    deliverData(std::move(streamPacket), true, &newPeer);
  }
  EXPECT_EQ(conn.currentPathId, newPath->id);
  EXPECT_EQ(newPath->status, PathStatus::Validating);

  // Step 3: Client sends the path response
  {
    auto packetData = packetToBuf(
        makePacketWithPathResponseFrame(outstandingChallenge->pathData));
    deliverData(std::move(packetData), true, &newPeer);
  }
  EXPECT_EQ(conn.currentPathId, newPath->id);
  EXPECT_EQ(newPath->status, PathStatus::Validated);
}

TEST_P(
    QuicServerTransportAllowMigrationTest,
    ReceiveReorderedDataFromChangedPeerAddress) {
  auto& conn = server->getConn();
  auto initialPathId = conn.currentPathId;

  auto data = IOBuf::copyBuffer("bad data");
  auto firstPacket = packetToBuf(createStreamPacket(
      *clientConnectionId,
      *server->getConn().serverConnectionId,
      clientNextAppDataPacketNum++,
      2,
      *data,
      0 /* cipherOverhead */,
      0 /* largestAcked */));
  auto secondPacket = packetToBuf(createStreamPacket(
      *clientConnectionId,
      *server->getConn().serverConnectionId,
      clientNextAppDataPacketNum++,
      6,
      *data,
      0 /* cipherOverhead */,
      0 /* largestAcked */));

  EXPECT_CALL(*quicStats_, onConnectionMigration).Times(0);
  EXPECT_CALL(*quicStats_, onPathAdded).Times(1);

  // Receive second packet first
  deliverData(std::move(secondPacket));
  EXPECT_EQ(conn.currentPathId, initialPathId);

  auto peerAddress = server->getConn().peerAddress;

  // Receive first packet later from a different address
  folly::SocketAddress newPeer("100.101.102.103", 23456);
  deliverData(std::move(firstPacket), true, &newPeer);

  // No migration for reordered packet
  EXPECT_EQ(conn.peerAddress, peerAddress);
  EXPECT_EQ(conn.currentPathId, initialPathId);
}

TEST_P(
    QuicServerTransportAllowMigrationTest,
    MigrateToNewPeerAndBackWithoutProbing) {
  auto data = IOBuf::copyBuffer("bad data");
  auto packetData = packetToBuf(createStreamPacket(
      *clientConnectionId,
      *server->getConn().serverConnectionId,
      clientNextAppDataPacketNum++,
      2,
      *data,
      0 /* cipherOverhead */,
      0 /* largestAcked */));

  auto& conn = server->getConn();

  ASSERT_FALSE(conn.fallbackPathId.has_value());

  auto peerAddress = conn.peerAddress;
  auto firstPathId = conn.currentPathId;
  auto firstCongestionController = conn.congestionController.get();
  auto firstSrtt = conn.lossState.srtt;
  auto firstLrtt = conn.lossState.lrtt;
  auto firstRttvar = conn.lossState.rttvar;
  auto firstMrtt = conn.lossState.mrtt;

  EXPECT_CALL(*quicStats_, onConnectionMigration).Times(2);
  EXPECT_CALL(*quicStats_, onPathAdded).Times(2);
  EXPECT_CALL(*quicStats_, onPathValidationSuccess).Times(1);

  folly::SocketAddress newPeer("100.101.102.103", 23456);
  deliverData(std::move(packetData), false, &newPeer);

  auto newPathId = conn.currentPathId;
  ASSERT_NE(firstPathId, newPathId);
  auto newPath = conn.pathManager->getPath(newPathId);
  ASSERT_TRUE(newPath);
  EXPECT_EQ(newPath->status, PathStatus::NotValid);

  ASSERT_TRUE(conn.fallbackPathId.has_value());
  EXPECT_EQ(conn.fallbackPathId.value(), firstPathId);

  ASSERT_TRUE(conn.pendingEvents.pathChallenges.contains(newPathId));
  auto pathChallengeData =
      conn.pendingEvents.pathChallenges.at(newPathId).pathData;
  EXPECT_EQ(conn.peerAddress, newPeer);
  EXPECT_EQ(conn.lossState.srtt, 0us);
  EXPECT_EQ(conn.lossState.lrtt, 0us);
  EXPECT_EQ(conn.lossState.rttvar, 0us);
  EXPECT_EQ(conn.lossState.mrtt, kDefaultMinRtt);
  EXPECT_TRUE(conn.congestionController);
  EXPECT_NE(conn.congestionController.get(), firstCongestionController);

  auto firstPath = conn.pathManager->getPath(firstPathId);
  ASSERT_TRUE(firstPath);
  EXPECT_EQ(firstPath->status, PathStatus::Validated);
  EXPECT_EQ(firstPath->peerAddress, clientAddr);
  EXPECT_EQ(
      firstPath->cachedCCAndRttState->congestionController.get(),
      firstCongestionController);
  EXPECT_EQ(firstPath->cachedCCAndRttState->srtt, firstSrtt);
  EXPECT_EQ(firstPath->cachedCCAndRttState->lrtt, firstLrtt);
  EXPECT_EQ(firstPath->cachedCCAndRttState->rttvar, firstRttvar);
  EXPECT_EQ(firstPath->cachedCCAndRttState->mrtt, firstMrtt);

  loopForWrites();
  EXPECT_FALSE(conn.pendingEvents.pathChallenges.contains(newPathId));
  EXPECT_EQ(newPath->status, PathStatus::Validating);
  EXPECT_TRUE(conn.pendingEvents.schedulePathValidationTimeout);
  EXPECT_TRUE(server->pathValidationTimeout().isTimerCallbackScheduled());

  EXPECT_NE(newPath->writableBytes, 0);

  ShortHeader header(
      ProtectionType::KeyPhaseZero,
      *conn.serverConnectionId,
      clientNextAppDataPacketNum++);
  RegularQuicPacketBuilder builder(
      conn.udpSendPacketLen, std::move(header), 0 /* largestAcked */);
  ASSERT_FALSE(builder.encodePacketHeader().hasError());
  ASSERT_TRUE(builder.canBuildPacket());

  ASSERT_FALSE(writeSimpleFrame(PathResponseFrame(pathChallengeData), builder)
                   .hasError());
  auto packet = std::move(builder).buildPacket();
  deliverData(packetToBuf(packet), false, &newPeer);
  EXPECT_EQ(newPath->status, PathStatus::Validated);
  EXPECT_FALSE(conn.pendingEvents.schedulePathValidationTimeout);
  EXPECT_FALSE(server->pathValidationTimeout().isTimerCallbackScheduled());

  // Loop once to allow any paths to be removed (this happens in the eventbase)
  evb.loopOnce();
  ASSERT_FALSE(conn.fallbackPathId.has_value());

  // The first path should be removed because we are now on a validated path
  EXPECT_FALSE(conn.pathManager->getPath(firstPathId));

  // receiving data from the original peer address would trigger another
  // migration and a new path validation since the path was deleted.
  auto nextPacketData = packetToBuf(createStreamPacket(
      *clientConnectionId,
      *conn.serverConnectionId,
      clientNextAppDataPacketNum++,
      6,
      *data,
      0 /* cipherOverhead */,
      0 /* largestAcked */));

  deliverData(std::move(nextPacketData), false);
  ASSERT_NE(conn.currentPathId, firstPathId);
  ASSERT_NE(conn.currentPathId, newPathId);

  // Path will need revalidation
  EXPECT_TRUE(conn.pendingEvents.pathChallenges.contains(conn.currentPathId));
}

TEST_P(
    QuicServerTransportAllowMigrationTest,
    MigrateToNewPeerRespondOnFallbackPath) {
  auto data = IOBuf::copyBuffer("migration data");
  auto packetData = packetToBuf(createStreamPacket(
      *clientConnectionId,
      *server->getConn().serverConnectionId,
      clientNextAppDataPacketNum++,
      2,
      *data,
      0 /* cipherOverhead */,
      0 /* largestAcked */));

  auto& conn = server->getConn();

  ASSERT_FALSE(conn.fallbackPathId.has_value());

  EXPECT_CALL(*quicStats_, onConnectionMigration).Times(1);
  EXPECT_CALL(*quicStats_, onPathAdded).Times(1);
  EXPECT_CALL(*quicStats_, onPathValidationSuccess).Times(1);
  EXPECT_CALL(*quicStats_, onPathValidationFailure).Times(0);

  auto peerAddress = conn.peerAddress;
  auto firstPathId = conn.currentPathId;
  auto firstCongestionController = conn.congestionController.get();
  auto firstSrtt = conn.lossState.srtt;
  auto firstLrtt = conn.lossState.lrtt;
  auto firstRttvar = conn.lossState.rttvar;
  auto firstMrtt = conn.lossState.mrtt;

  // Step 1: Client migrates to new peer address
  folly::SocketAddress newPeer("100.101.102.103", 23456);
  deliverData(std::move(packetData), false, &newPeer);

  auto newPathId = conn.currentPathId;
  ASSERT_NE(firstPathId, newPathId);
  auto newPath = conn.pathManager->getPath(newPathId);
  ASSERT_TRUE(newPath);
  EXPECT_EQ(newPath->status, PathStatus::NotValid);

  ASSERT_TRUE(conn.fallbackPathId.has_value());
  EXPECT_EQ(conn.fallbackPathId.value(), firstPathId);

  ASSERT_TRUE(conn.pendingEvents.pathChallenges.contains(newPathId));
  auto pathChallengeData =
      conn.pendingEvents.pathChallenges.at(newPathId).pathData;
  EXPECT_EQ(conn.peerAddress, newPeer);
  EXPECT_EQ(conn.lossState.srtt, 0us);
  EXPECT_EQ(conn.lossState.lrtt, 0us);
  EXPECT_EQ(conn.lossState.rttvar, 0us);
  EXPECT_EQ(conn.lossState.mrtt, kDefaultMinRtt);
  EXPECT_TRUE(conn.congestionController);
  EXPECT_NE(conn.congestionController.get(), firstCongestionController);

  auto firstPath = conn.pathManager->getPath(firstPathId);
  ASSERT_TRUE(firstPath);
  EXPECT_EQ(firstPath->status, PathStatus::Validated);
  EXPECT_EQ(firstPath->peerAddress, clientAddr);
  EXPECT_EQ(
      firstPath->cachedCCAndRttState->congestionController.get(),
      firstCongestionController);
  EXPECT_EQ(firstPath->cachedCCAndRttState->srtt, firstSrtt);
  EXPECT_EQ(firstPath->cachedCCAndRttState->lrtt, firstLrtt);
  EXPECT_EQ(firstPath->cachedCCAndRttState->rttvar, firstRttvar);
  EXPECT_EQ(firstPath->cachedCCAndRttState->mrtt, firstMrtt);

  // Step 2: Server sends path challenge
  loopForWrites();
  EXPECT_FALSE(conn.pendingEvents.pathChallenges.contains(newPathId));
  EXPECT_EQ(newPath->status, PathStatus::Validating);
  EXPECT_TRUE(conn.pendingEvents.schedulePathValidationTimeout);
  EXPECT_TRUE(server->pathValidationTimeout().isTimerCallbackScheduled());

  EXPECT_NE(newPath->writableBytes, 0);

  // Step 3: Client responds with path response on the fallback (initial) path
  packetData = packetToBuf(makePacketWithPathResponseFrame(pathChallengeData));
  // Deliver the path response on the fallback (original) path, not the new path
  deliverData(std::move(packetData), false, &clientAddr);

  // Allow any path removal to execute (it is scheduled on the eventbase)
  evb.loopOnce();

  // The new path should be validated even though the response came on a
  // different path
  EXPECT_EQ(newPath->status, PathStatus::Validated);
  EXPECT_FALSE(conn.pendingEvents.schedulePathValidationTimeout);
  EXPECT_FALSE(server->pathValidationTimeout().isTimerCallbackScheduled());

  // The current path should still be the new path
  EXPECT_EQ(conn.currentPathId, newPathId);
  EXPECT_EQ(conn.peerAddress, newPeer);

  // The fallback path should be removed since the current path is validated.
  EXPECT_FALSE(conn.fallbackPathId.has_value());
  EXPECT_FALSE(conn.pathManager->getPath(firstPathId));
}

TEST_P(QuicServerTransportAllowMigrationTest, ResetPathRttPathResponse) {
  auto& conn = server->getConn();

  auto data = IOBuf::copyBuffer("bad data");
  auto packetData = packetToBuf(createStreamPacket(
      *clientConnectionId,
      *server->getConn().serverConnectionId,
      clientNextAppDataPacketNum++,
      2,
      *data,
      0 /* cipherOverhead */,
      0 /* largestAcked */));

  auto peerAddress = server->getConn().peerAddress;
  auto srtt = server->getConn().lossState.srtt;
  auto lrtt = server->getConn().lossState.lrtt;
  auto rttvar = server->getConn().lossState.rttvar;

  auto firstPath = conn.pathManager->getPath(conn.currentPathId);
  ASSERT_TRUE(firstPath);

  EXPECT_CALL(*quicStats_, onConnectionMigration).Times(1);
  EXPECT_CALL(*quicStats_, onPathAdded).Times(1);
  EXPECT_CALL(*quicStats_, onPathValidationSuccess).Times(1);
  EXPECT_CALL(*quicStats_, onPathValidationFailure).Times(0);

  folly::SocketAddress newPeer("100.101.102.103", 23456);
  deliverData(std::move(packetData), false, &newPeer);

  auto newPath = conn.pathManager->getPath(conn.currentPathId);
  ASSERT_TRUE(newPath);
  EXPECT_EQ(newPath->peerAddress, newPeer);
  // We haven't written the path challenge yet, so the path is not validating
  // yet
  EXPECT_EQ(newPath->status, PathStatus::NotValid);

  ASSERT_NO_THROW(conn.pendingEvents.pathChallenges.at(newPath->id));
  auto pathChallengeData =
      conn.pendingEvents.pathChallenges.at(newPath->id).pathData;
  EXPECT_EQ(conn.peerAddress, newPeer);
  EXPECT_EQ(conn.lossState.srtt, 0us);
  EXPECT_EQ(conn.lossState.lrtt, 0us);
  EXPECT_EQ(conn.lossState.rttvar, 0us);

  ASSERT_TRUE(firstPath->cachedCCAndRttState);
  EXPECT_EQ(firstPath->cachedCCAndRttState->srtt, srtt);
  EXPECT_EQ(firstPath->cachedCCAndRttState->lrtt, lrtt);
  EXPECT_EQ(firstPath->cachedCCAndRttState->rttvar, rttvar);

  loopForWrites();
  EXPECT_THROW(
      conn.pendingEvents.pathChallenges.at(newPath->id), std::out_of_range);
  EXPECT_EQ(newPath->status, PathStatus::Validating);
  EXPECT_TRUE(conn.pendingEvents.schedulePathValidationTimeout);
  EXPECT_TRUE(server->pathValidationTimeout().isTimerCallbackScheduled());

  ShortHeader header(
      ProtectionType::KeyPhaseZero,
      *server->getConn().serverConnectionId,
      clientNextAppDataPacketNum++);
  RegularQuicPacketBuilder builder(
      server->getConn().udpSendPacketLen,
      std::move(header),
      0 /* largestAcked */);
  ASSERT_FALSE(builder.encodePacketHeader().hasError());
  ASSERT_TRUE(builder.canBuildPacket());

  ASSERT_FALSE(writeSimpleFrame(PathResponseFrame(pathChallengeData), builder)
                   .hasError());
  auto packet = std::move(builder).buildPacket();
  deliverData(packetToBuf(packet), false, &newPeer);
  EXPECT_EQ(newPath->status, PathStatus::Validated);
  EXPECT_FALSE(conn.pendingEvents.schedulePathValidationTimeout);
  EXPECT_FALSE(server->pathValidationTimeout().isTimerCallbackScheduled());

  // After Pathresponse frame is received, srtt,lrtt = sampleRtt;
  // sampleRtt = time from send of PathChallenge to receiving PathResponse
  EXPECT_NE(conn.lossState.srtt, 0us);
  EXPECT_NE(conn.lossState.lrtt, 0us);
  EXPECT_NE(conn.lossState.rttvar, 0us);
}

TEST_P(QuicServerTransportAllowMigrationTest, IgnoreInvalidPathResponse) {
  auto& conn = server->getConn();

  auto data = IOBuf::copyBuffer("bad data");
  auto packetData = packetToBuf(createStreamPacket(
      *clientConnectionId,
      *server->getConn().serverConnectionId,
      clientNextAppDataPacketNum++,
      2,
      *data,
      0 /* cipherOverhead */,
      0 /* largestAcked */));

  auto peerAddress = server->getConn().peerAddress;

  folly::SocketAddress newPeer("100.101.102.103", 23456);
  ASSERT_FALSE(conn.pathManager->getPath(server->getLocalAddress(), newPeer));

  EXPECT_CALL(*quicStats_, onConnectionMigration).Times(1);
  EXPECT_CALL(*quicStats_, onPathAdded).Times(1);
  EXPECT_CALL(*quicStats_, onPathValidationSuccess).Times(0);
  EXPECT_CALL(*quicStats_, onPathValidationFailure).Times(0);

  deliverData(std::move(packetData), false, &newPeer);

  auto newPath = conn.pathManager->getPath(server->getLocalAddress(), newPeer);
  ASSERT_TRUE(newPath);
  ASSERT_EQ(conn.currentPathId, newPath->id);

  EXPECT_NO_THROW(conn.pendingEvents.pathChallenges.at(newPath->id));
  EXPECT_GE(newPath->writableBytes, conn.udpSendPacketLen);
  EXPECT_EQ(conn.peerAddress, newPeer);

  loopForWrites();
  ASSERT_EQ(newPath->status, PathStatus::Validating);

  auto outstandingChallenge = getFirstOutstandingPathChallenge();
  ASSERT_TRUE(outstandingChallenge);

  auto invalidPathResponsePkt =
      makePacketWithPathResponseFrame(outstandingChallenge->pathData ^ 1);
  deliverData(packetToBuf(invalidPathResponsePkt), false, &newPeer);

  // The invalid response should not impact the state of the path
  EXPECT_EQ(newPath->status, PathStatus::Validating);
  EXPECT_TRUE(conn.pendingEvents.schedulePathValidationTimeout);
  EXPECT_TRUE(server->pathValidationTimeout().isTimerCallbackScheduled());
}

TEST_P(
    QuicServerTransportAllowMigrationTest,
    ReceivePathResponseFromDifferentPeerAddress) {
  auto& conn = server->getConn();
  auto data = IOBuf::copyBuffer("bad data");
  auto packetData = packetToBuf(createStreamPacket(
      *clientConnectionId,
      *server->getConn().serverConnectionId,
      clientNextAppDataPacketNum++,
      2,
      *data,
      0 /* cipherOverhead */,
      0 /* largestAcked */));

  auto peerAddress = server->getConn().peerAddress;

  EXPECT_CALL(*quicStats_, onConnectionMigration).Times(1);
  EXPECT_CALL(*quicStats_, onPathAdded).Times(2);
  EXPECT_CALL(*quicStats_, onPathValidationSuccess).Times(1);
  EXPECT_CALL(*quicStats_, onPathValidationFailure).Times(0);

  folly::SocketAddress newPeer("100.101.102.103", 23456);
  deliverData(std::move(packetData), false, &newPeer);

  auto newPath = conn.pathManager->getPath(server->getLocalAddress(), newPeer);
  ASSERT_TRUE(newPath);
  ASSERT_EQ(conn.currentPathId, newPath->id);

  EXPECT_NO_THROW(conn.pendingEvents.pathChallenges.at(newPath->id));
  loopForWrites();
  EXPECT_THROW(
      conn.pendingEvents.pathChallenges.at(newPath->id), std::out_of_range);
  ASSERT_EQ(newPath->status, PathStatus::Validating);

  auto outstandingChallenge = getFirstOutstandingPathChallenge();
  ASSERT_TRUE(outstandingChallenge);

  folly::SocketAddress newPeer2("200.101.102.103", 23456);
  auto pathResponsePkt =
      makePacketWithPathResponseFrame(outstandingChallenge->pathData);
  deliverData(packetToBuf(pathResponsePkt), false, &newPeer2);

  // The response should be accepted. The spec says that the peer initiating the
  // path validation MUST NOT enforce that the response come on the same path.
  // https://www.rfc-editor.org/rfc/rfc9000.html#section-8.2.2
  EXPECT_EQ(conn.currentPathId, newPath->id);
  EXPECT_EQ(newPath->status, PathStatus::Validated);
  EXPECT_FALSE(conn.pendingEvents.schedulePathValidationTimeout);
  EXPECT_FALSE(server->pathValidationTimeout().isTimerCallbackScheduled());
}

TEST_P(QuicServerTransportAllowMigrationTest, RetiringConnIdIssuesNewIds) {
  auto& conn = server->getNonConstConn();
  // reset queued packets
  conn.outstandings.reset();
  auto initialServerConnId = conn.selfConnectionIds[0];
  auto nextConnId = conn.selfConnectionIds[1].connId;
  EXPECT_EQ(initialServerConnId.sequenceNumber, 0);

  auto data = IOBuf::copyBuffer("hi there!");
  auto packetStreamData = packetToBuf(createStreamPacket(
      *clientConnectionId,
      *serverConnectionId,
      clientNextAppDataPacketNum++,
      2,
      *data,
      0 /* cipherOverhead */,
      0 /* largestAcked */));

  ShortHeader header(
      ProtectionType::KeyPhaseZero, nextConnId, clientNextAppDataPacketNum++);
  RegularQuicPacketBuilder builder(
      conn.udpSendPacketLen, std::move(header), 0 /* largestAcked */);
  ASSERT_FALSE(builder.encodePacketHeader().hasError());

  // build packet containing a frame retiring the initial server conn id
  ASSERT_TRUE(builder.canBuildPacket());
  RetireConnectionIdFrame retireConnIdFrame(initialServerConnId.sequenceNumber);
  ASSERT_FALSE(
      writeSimpleFrame(QuicSimpleFrame(retireConnIdFrame), builder).hasError());
  auto retireConnIdPacket = std::move(builder).buildPacket();

  /**
   * Deliver both packets (one containing stream data and the other
   containing a
   * RETIRE_CONNECTION_ID frame). The RETIRE_CONNECTION_ID frame should
   result
   * in invoking onConnectionIdRetired().
   */
  EXPECT_CALL(
      routingCallback, onConnectionIdRetired(_, initialServerConnId.connId));
  deliverData(std::move(packetStreamData), false);
  deliverData(packetToBuf(retireConnIdPacket));
  // received a RETIRE_CONN_ID frame for seq no 0, expect next seq to be 1
  EXPECT_EQ(conn.selfConnectionIds[0].sequenceNumber, 1);

  // server should have written NEW_CONNECTION_ID frame since we've retired one
  auto numNewConnIdFrames = std::count_if(
      conn.outstandings.packets.begin(),
      conn.outstandings.packets.end(),
      findFrameInPacketFunc<QuicSimpleFrame::Type::NewConnectionIdFrame>());
  EXPECT_EQ(numNewConnIdFrames, 1);
}

TEST_P(QuicServerTransportAllowMigrationTest, RetiringInvalidConnId) {
  auto& conn = server->getNonConstConn();
  // reset queued packets
  conn.outstandings.reset();

  ShortHeader header(
      ProtectionType::KeyPhaseZero,
      *serverConnectionId,
      clientNextAppDataPacketNum++);
  RegularQuicPacketBuilder builder(
      conn.udpSendPacketLen, std::move(header), 0 /* largestAcked */);
  ASSERT_FALSE(builder.encodePacketHeader().hasError());

  // build packet containing a frame retiring an invalid conn id / seq no
  ASSERT_TRUE(builder.canBuildPacket());
  RetireConnectionIdFrame retireConnIdFrame(conn.nextSelfConnectionIdSequence);
  ASSERT_FALSE(
      writeSimpleFrame(QuicSimpleFrame(retireConnIdFrame), builder).hasError());
  auto retireConnIdPacket = std::move(builder).buildPacket();

  // retiring invalid conn id should not invoke onConnectionIdRetired()
  EXPECT_CALL(routingCallback, onConnectionIdRetired(_, _)).Times(0);
  deliverData(packetToBuf(retireConnIdPacket));
  // no changes should have been made to selfConnectionIds
  EXPECT_EQ(conn.selfConnectionIds[0].sequenceNumber, 0);
  EXPECT_TRUE(conn.connIdsRetiringSoon->empty());

  // verify that we don't issue a new conn id
  auto numNewConnIdFrames = std::count_if(
      conn.outstandings.packets.begin(),
      conn.outstandings.packets.end(),
      findFrameInPacketFunc<QuicSimpleFrame::Type::NewConnectionIdFrame>());
  EXPECT_EQ(numNewConnIdFrames, 0);
}

TEST_P(QuicServerTransportAllowMigrationTest, RetireConnIdOfContainingPacket) {
  /**
   * From RFC9000:
   * The sequence number specified in a RETIRE_CONNECTION_ID frame MUST NOT
   * refer to the Destination Connection ID field of the packet in which the
   * frame is contained.  The peer MAY treat this as a connection error of
   type
   * PROTOCOL_VIOLATION.
   */

  auto& conn = server->getNonConstConn();
  // reset queued packets
  conn.outstandings.reset();

  ShortHeader header(
      ProtectionType::KeyPhaseZero,
      *serverConnectionId,
      clientNextAppDataPacketNum++);
  RegularQuicPacketBuilder builder(
      conn.udpSendPacketLen, std::move(header), 0 /* largestAcked */);
  ASSERT_FALSE(builder.encodePacketHeader().hasError());

  // build packet containing a frame retiring conn id of containing packet
  ASSERT_TRUE(builder.canBuildPacket());
  RetireConnectionIdFrame retireConnIdFrame(0);
  ASSERT_FALSE(
      writeSimpleFrame(QuicSimpleFrame(retireConnIdFrame), builder).hasError());
  auto retireConnIdPacket = std::move(builder).buildPacket();

  // parsing packet should throw an error
  EXPECT_THROW(
      deliverData(packetToBuf(retireConnIdPacket)), std::runtime_error);
}

TEST_P(
    QuicServerTransportAllowMigrationTest,
    RetireConnIdFrameZeroLengthSrcConnId) {
  /**
   * From RFC9000:
   * An endpoint cannot send this frame if it was provided with a zero-length
   * connection ID by its peer. An endpoint that provides a zero- length
   * connection ID MUST treat receipt of a RETIRE_CONNECTION_ID frame as a
   * connection error of type PROTOCOL_VIOLATION.
   */
  auto& conn = server->getNonConstConn();
  // reset queued packets
  conn.outstandings.reset();
  // simulate that the client has a zero-length conn id
  conn.clientConnectionId = ConnectionId::createZeroLength();

  ShortHeader header(
      ProtectionType::KeyPhaseZero,
      *serverConnectionId,
      clientNextAppDataPacketNum++);
  RegularQuicPacketBuilder builder(
      conn.udpSendPacketLen, std::move(header), 0 /* largestAcked */);
  ASSERT_FALSE(builder.encodePacketHeader().hasError());

  // build packet containing a RETIRE_CONNECTION_ID frame
  ASSERT_TRUE(builder.canBuildPacket());
  RetireConnectionIdFrame retireConnIdFrame(0);
  ASSERT_FALSE(
      writeSimpleFrame(QuicSimpleFrame(retireConnIdFrame), builder).hasError());
  auto retireConnIdPacket = std::move(builder).buildPacket();

  // parsing packet should throw an error
  EXPECT_THROW(
      deliverData(packetToBuf(retireConnIdPacket)), std::runtime_error);
}

TEST_P(
    QuicServerTransportAllowMigrationTest,
    RestoreCachedStateOnlyForValidatedPaths) {
  auto& conn = server->getNonConstConn();
  auto initialPath = conn.pathManager->getPath(conn.currentPathId);
  ASSERT_TRUE(initialPath);
  ASSERT_TRUE(initialPath->status == PathStatus::Validated);
  conn.lossState.srtt = 200ms;
  conn.lossState.lrtt = 220ms;
  conn.lossState.rttvar = 20ms;
  auto firstCongestionController = conn.congestionController.get();

  auto data = IOBuf::copyBuffer("bad data");
  auto packetData = packetToBuf(createStreamPacket(
      *clientConnectionId,
      *server->getConn().serverConnectionId,
      clientNextAppDataPacketNum++,
      2,
      *data,
      0 /* cipherOverhead */,
      0 /* largestAcked */));

  // Migrate to unvalidated peer
  folly::SocketAddress newPeer("100.101.102.103", 23456);
  deliverData(std::move(packetData), true, &newPeer);

  ASSERT_EQ(conn.peerAddress, newPeer);
  ASSERT_NE(conn.currentPathId, initialPath->id);
  auto newPath = conn.pathManager->getPath(conn.currentPathId);
  ASSERT_TRUE(newPath);
  // The cached state is empty. cca is reset. rtt is unchanged.
  EXPECT_EQ(conn.lossState.srtt, 200ms);
  EXPECT_EQ(conn.lossState.lrtt, 220ms);
  EXPECT_EQ(conn.lossState.rttvar, 20ms);
  EXPECT_NE(conn.congestionController.get(), firstCongestionController);
  conn.lossState.srtt = 100ms;
  conn.lossState.lrtt = 110ms;
  conn.lossState.rttvar = 10ms;

  // Migrate back to validated peer
  packetData = packetToBuf(createStreamPacket(
      *clientConnectionId,
      *server->getConn().serverConnectionId,
      clientNextAppDataPacketNum++,
      2,
      *data,
      0 /* cipherOverhead */,
      0 /* largestAcked */));
  deliverData(std::move(packetData), true, &clientAddr);
  // The cached state is restored since the path is validated
  ASSERT_EQ(conn.peerAddress, clientAddr);
  ASSERT_EQ(conn.currentPathId, initialPath->id);
  EXPECT_EQ(conn.lossState.srtt, 200ms);
  EXPECT_EQ(conn.lossState.lrtt, 220ms);
  EXPECT_EQ(conn.lossState.rttvar, 20ms);
  EXPECT_EQ(conn.congestionController.get(), firstCongestionController);

  // The unvalidated path has cached state
  EXPECT_EQ(newPath->cachedCCAndRttState->srtt, 100ms);
  EXPECT_EQ(newPath->cachedCCAndRttState->lrtt, 110ms);
  EXPECT_EQ(newPath->cachedCCAndRttState->rttvar, 10ms);
  EXPECT_NE(newPath->cachedCCAndRttState->congestionController.get(), nullptr);
  EXPECT_NE(
      newPath->cachedCCAndRttState->congestionController.get(),
      firstCongestionController);

  // Migrate to unvalidated peer again
  packetData = packetToBuf(createStreamPacket(
      *clientConnectionId,
      *server->getConn().serverConnectionId,
      clientNextAppDataPacketNum++,
      2,
      *data,
      0 /* cipherOverhead */,
      0 /* largestAcked */));
  deliverData(std::move(packetData), true, &newPeer);
  // The cached state is not used since the path is not validated. cca is reset.
  // rtt is unchanged.
  ASSERT_EQ(conn.peerAddress, newPeer);
  ASSERT_NE(conn.currentPathId, initialPath->id);
  EXPECT_EQ(conn.lossState.srtt, 200ms);
  EXPECT_EQ(conn.lossState.lrtt, 220ms);
  EXPECT_EQ(conn.lossState.rttvar, 20ms);
  EXPECT_NE(conn.congestionController.get(), firstCongestionController);
}

TEST_P(QuicServerTransportAllowMigrationTest, MigrateToStaleValidatedPeer) {
  auto& conn = server->getNonConstConn();
  auto initialPath = conn.pathManager->getPath(conn.currentPathId);
  ASSERT_TRUE(initialPath);
  ASSERT_TRUE(initialPath->status == PathStatus::Validated);
  auto firstCongestionController = conn.congestionController.get();

  auto data = IOBuf::copyBuffer("bad data");
  auto packetData = packetToBuf(createStreamPacket(
      *clientConnectionId,
      *server->getConn().serverConnectionId,
      clientNextAppDataPacketNum++,
      2,
      *data,
      0 /* cipherOverhead */,
      0 /* largestAcked */));

  // Migrate to unvalidated peer
  folly::SocketAddress newPeer("100.101.102.103", 23456);
  deliverData(std::move(packetData), true, &newPeer);

  ASSERT_EQ(conn.peerAddress, newPeer);
  ASSERT_NE(conn.currentPathId, initialPath->id);
  auto newPath = conn.pathManager->getPath(conn.currentPathId);
  ASSERT_TRUE(newPath);
  // The cached state is empty. The rtt/cca state is reset
  EXPECT_EQ(conn.lossState.srtt, 0us);
  EXPECT_EQ(conn.lossState.lrtt, 0us);
  EXPECT_EQ(conn.lossState.rttvar, 0us);
  EXPECT_NE(conn.congestionController.get(), firstCongestionController);
  EXPECT_EQ(
      conn.congestionController->type(), firstCongestionController->type());

  // Make the cached state stale for the initial path.
  auto& nonConstInitialPath =
      quic::PathManagerTestAccessor::getNonConstPathInfo(conn, initialPath->id);
  nonConstInitialPath.cachedCCAndRttState->srtt = 200ms;
  nonConstInitialPath.cachedCCAndRttState->lrtt = 220ms;
  nonConstInitialPath.cachedCCAndRttState->rttvar = 20ms;
  nonConstInitialPath.cachedCCAndRttState->congestionController =
      conn.congestionControllerFactory->makeCongestionController(
          conn, CongestionControlType::NewReno);
  auto cachedCongestionController =
      nonConstInitialPath.cachedCCAndRttState->congestionController.get();
  nonConstInitialPath.cachedCCAndRttState->recordTime =
      Clock::now() - 2 * kTimeToRetainLastCongestionAndRttState;

  // Migrate back to validated peer
  packetData = packetToBuf(createStreamPacket(
      *clientConnectionId,
      *server->getConn().serverConnectionId,
      clientNextAppDataPacketNum++,
      2,
      *data,
      0 /* cipherOverhead */,
      0 /* largestAcked */));
  deliverData(std::move(packetData), true, &clientAddr);
  // The cached state is not restored because it's too old
  ASSERT_EQ(conn.peerAddress, clientAddr);
  ASSERT_EQ(conn.currentPathId, initialPath->id);
  EXPECT_EQ(conn.lossState.srtt, 0us);
  EXPECT_EQ(conn.lossState.lrtt, 0us);
  EXPECT_EQ(conn.lossState.rttvar, 0us);
  EXPECT_TRUE(conn.congestionController);
  EXPECT_NE(conn.congestionController.get(), cachedCongestionController);
  EXPECT_EQ(
      conn.congestionController->type(),
      conn.transportSettings.defaultCongestionController);
}

TEST_P(QuicServerTransportAllowMigrationTest, ClientPortChangeNATRebinding) {
  auto& conn = server->getNonConstConn();

  StreamId streamId = server->createBidirectionalStream().value();
  auto data1 = IOBuf::copyBuffer("Aloha");
  auto serverWriteChain10 = server->writeChain(streamId, data1->clone(), false);
  loopForWrites();
  PacketNum packetNum1 =
      getFirstOutstandingPacket(
          server->getNonConstConn(), PacketNumberSpace::AppData)
          ->packet.header.getPacketSequenceNum();
  AckBlocks acks = {{packetNum1, packetNum1}};
  auto packet1 = createAckPacket(
      server->getNonConstConn(),
      ++clientNextAppDataPacketNum,
      acks,
      PacketNumberSpace::AppData);
  deliverData(packetToBuf(packet1));
  auto firstPath = conn.pathManager->getPath(conn.currentPathId);
  ASSERT_TRUE(firstPath);

  auto data = IOBuf::copyBuffer("bad data");
  auto packetData = packetToBuf(createStreamPacket(
      *clientConnectionId,
      *server->getConn().serverConnectionId,
      clientNextAppDataPacketNum++,
      2,
      *data,
      0 /* cipherOverhead */,
      0 /* largestAcked */));

  auto congestionController = server->getConn().congestionController.get();
  conn.lossState.lrtt = 100ms;
  conn.lossState.srtt = 120ms;
  conn.lossState.rttvar = 20ms;
  conn.lossState.mrtt = 80ms;

  folly::SocketAddress newPeer(
      clientAddr.getIPAddress(), clientAddr.getPort() + 1);
  deliverData(std::move(packetData), true, &newPeer);

  auto newPath = conn.pathManager->getPath(server->getLocalAddress(), newPeer);
  ASSERT_TRUE(newPath);
  EXPECT_EQ(conn.currentPathId, newPath->id);
  EXPECT_EQ(newPath->status, PathStatus::Validating);
  EXPECT_EQ(conn.peerAddress, newPeer);

  // No state is cached for the first path
  EXPECT_FALSE(firstPath->cachedCCAndRttState);
  // The cc and rtt state is maintained for nat rebinding
  EXPECT_EQ(conn.lossState.srtt, 120ms);
  EXPECT_EQ(conn.lossState.lrtt, 100ms);
  EXPECT_EQ(conn.lossState.rttvar, 20ms);
  EXPECT_EQ(conn.lossState.mrtt, 80ms);

  EXPECT_EQ(conn.congestionController.get(), congestionController);
}

TEST_P(QuicServerTransportAllowMigrationTest, ClientAddressChangeNATRebinding) {
  auto& conn = server->getNonConstConn();

  StreamId streamId = server->createBidirectionalStream().value();
  auto data1 = IOBuf::copyBuffer("Aloha");
  auto serverWriteChain10 = server->writeChain(streamId, data1->clone(), false);
  loopForWrites();
  PacketNum packetNum1 =
      getFirstOutstandingPacket(
          server->getNonConstConn(), PacketNumberSpace::AppData)
          ->packet.header.getPacketSequenceNum();
  AckBlocks acks = {{packetNum1, packetNum1}};
  auto packet1 = createAckPacket(
      server->getNonConstConn(),
      ++clientNextAppDataPacketNum,
      acks,
      PacketNumberSpace::AppData);
  deliverData(packetToBuf(packet1));
  auto firstPath = conn.pathManager->getPath(conn.currentPathId);
  ASSERT_TRUE(firstPath);

  auto data = IOBuf::copyBuffer("bad data");
  auto packetData = packetToBuf(createStreamPacket(
      *clientConnectionId,
      *server->getConn().serverConnectionId,
      clientNextAppDataPacketNum++,
      2,
      *data,
      0 /* cipherOverhead */,
      0 /* largestAcked */));

  auto congestionController = server->getConn().congestionController.get();
  conn.lossState.lrtt = 100ms;
  conn.lossState.srtt = 120ms;
  conn.lossState.rttvar = 20ms;
  conn.lossState.mrtt = 80ms;

  // Current address is 127.0.0.1:1000
  folly::SocketAddress newPeer("127.0.0.100", clientAddr.getPort());
  deliverData(std::move(packetData), true, &newPeer);

  auto newPath = conn.pathManager->getPath(server->getLocalAddress(), newPeer);
  ASSERT_TRUE(newPath);
  EXPECT_EQ(conn.currentPathId, newPath->id);
  EXPECT_EQ(newPath->status, PathStatus::Validating);
  EXPECT_EQ(conn.peerAddress, newPeer);

  // No state is cached for the first path
  EXPECT_FALSE(firstPath->cachedCCAndRttState);
  // The cc and rtt state is maintained for nat rebinding
  EXPECT_EQ(conn.lossState.srtt, 120ms);
  EXPECT_EQ(conn.lossState.lrtt, 100ms);
  EXPECT_EQ(conn.lossState.rttvar, 20ms);
  EXPECT_EQ(conn.lossState.mrtt, 80ms);

  EXPECT_EQ(conn.congestionController.get(), congestionController);
}

TEST_P(QuicServerTransportAllowMigrationTest, ClientAddressChangeOutOfSubnet) {
  auto& conn = server->getNonConstConn();

  StreamId streamId = server->createBidirectionalStream().value();
  auto data1 = IOBuf::copyBuffer("Aloha");
  auto serverWriteChain10 = server->writeChain(streamId, data1->clone(), false);
  loopForWrites();
  PacketNum packetNum1 =
      getFirstOutstandingPacket(
          server->getNonConstConn(), PacketNumberSpace::AppData)
          ->packet.header.getPacketSequenceNum();
  AckBlocks acks = {{packetNum1, packetNum1}};
  auto packet1 = createAckPacket(
      server->getNonConstConn(),
      ++clientNextAppDataPacketNum,
      acks,
      PacketNumberSpace::AppData);
  deliverData(packetToBuf(packet1));
  auto firstPath = conn.pathManager->getPath(conn.currentPathId);
  ASSERT_TRUE(firstPath);

  auto data = IOBuf::copyBuffer("bad data");
  auto packetData = packetToBuf(createStreamPacket(
      *clientConnectionId,
      *server->getConn().serverConnectionId,
      clientNextAppDataPacketNum++,
      2,
      *data,
      0 /* cipherOverhead */,
      0 /* largestAcked */));

  auto congestionController = server->getConn().congestionController.get();
  conn.lossState.lrtt = 100ms;
  conn.lossState.srtt = 120ms;
  conn.lossState.rttvar = 20ms;
  conn.lossState.mrtt = 80ms;

  // Current address is 127.0.0.1:1000. New address is out of the /24 subnet.
  // This won't count as NAT rebinding.
  folly::SocketAddress newPeer("127.0.1.1", clientAddr.getPort());
  deliverData(std::move(packetData), true, &newPeer);

  auto newPath = conn.pathManager->getPath(server->getLocalAddress(), newPeer);
  ASSERT_TRUE(newPath);
  EXPECT_EQ(conn.currentPathId, newPath->id);
  EXPECT_EQ(newPath->status, PathStatus::Validating);
  EXPECT_EQ(conn.peerAddress, newPeer);

  // State is cached for the first path
  EXPECT_TRUE(firstPath->cachedCCAndRttState);
  // The rtt state is unchanged since we have nothing to restore. cca is reset.
  EXPECT_EQ(conn.lossState.lrtt, 100ms);
  EXPECT_EQ(conn.lossState.srtt, 120ms);
  EXPECT_EQ(conn.lossState.rttvar, 20ms);
  EXPECT_EQ(conn.lossState.mrtt, 80ms);
  EXPECT_NE(conn.congestionController.get(), congestionController);
}

TEST_P(
    QuicServerTransportAllowMigrationTest,
    PathValidationTimeoutForNonPrimaryPath) {
  auto qLogger = std::make_shared<FileQLogger>(VantagePoint::Server);
  auto& conn = server->getNonConstConn();
  conn.qLogger = qLogger;

  // Add additional peer id so PathResponse completes.
  conn.peerConnectionIds.emplace_back(
      ConnectionId::createAndMaybeCrash({1, 2, 3, 4}), 1);

  // Deliver a path challenge from a new peer address
  auto incomingPathChallengeData = 123;
  folly::SocketAddress newPeer("100.101.102.103", 23456);
  {
    auto packet = makePacketWithPathChallegeFrame(incomingPathChallengeData);
    auto packetData = packetToBuf(packet);
    deliverData(std::move(packetData), true, &newPeer);
  }

  // Step 1: New path is created and is validating
  auto newPath = conn.pathManager->getPath(server->getLocalAddress(), newPeer);
  ASSERT_TRUE(newPath);
  auto newPathId = newPath->id;
  EXPECT_NE(conn.currentPathId, newPath->id);
  EXPECT_EQ(newPath->status, PathStatus::Validating);
  EXPECT_TRUE(newPath->outstandingChallengeData);
  EXPECT_TRUE(newPath->firstChallengeSentTimestamp);
  EXPECT_TRUE(newPath->lastChallengeSentTimestamp);

  // A path challenge was sent out
  auto outstandingChallenge = getFirstOutstandingPathChallenge();
  ASSERT_TRUE(outstandingChallenge);

  // Cancel the timeout and trigger it immediately to test its impact
  ASSERT_TRUE(server->pathValidationTimeout().isTimerCallbackScheduled());
  server->pathValidationTimeout().cancelTimerCallback();
  auto& nonConstNewPath =
      quic::PathManagerTestAccessor::getNonConstPathInfo(conn, newPath->id);
  nonConstNewPath.pathResponseDeadline = Clock::now() - 1ms;
  server->pathValidationTimeout().timeoutExpired();

  EXPECT_EQ(newPath->status, PathStatus::NotValid);
  EXPECT_FALSE(newPath->outstandingChallengeData);
  EXPECT_FALSE(newPath->firstChallengeSentTimestamp);
  EXPECT_FALSE(newPath->lastChallengeSentTimestamp);

  // This is a probe path that failed validation. It will be removed at the end
  // of the event loop.
  evb.loopOnce();
  EXPECT_FALSE(conn.pathManager->getPath(newPathId));
}

TEST_P(
    QuicServerTransportAllowMigrationTest,
    PathValidationTimeoutForCurrentPathWithFallback) {
  auto qLogger = std::make_shared<FileQLogger>(VantagePoint::Server);
  auto& conn = server->getNonConstConn();
  conn.qLogger = qLogger;

  auto firstPath = conn.pathManager->getPath(conn.currentPathId);
  ASSERT_TRUE(firstPath);
  auto firstCongestionController = conn.congestionController.get();

  // Add additional peer id so PathResponse completes.
  conn.peerConnectionIds.emplace_back(
      ConnectionId::createAndMaybeCrash({1, 2, 3, 4}), 1);

  // Deliver a stream packet from a new peer address
  folly::SocketAddress newPeer("100.101.102.103", 23456);
  {
    auto data = IOBuf::copyBuffer("bad data");
    auto packetData = packetToBuf(createStreamPacket(
        *clientConnectionId,
        *server->getConn().serverConnectionId,
        clientNextAppDataPacketNum++,
        2,
        *data,
        0 /* cipherOverhead */,
        0 /* largestAcked */));

    // Migrate to unvalidated peer
    deliverData(std::move(packetData), true, &newPeer);
  }

  // Step 1: New path is created and is validating
  auto newPath = conn.pathManager->getPath(server->getLocalAddress(), newPeer);
  ASSERT_TRUE(newPath);
  EXPECT_EQ(conn.currentPathId, newPath->id);
  EXPECT_EQ(newPath->status, PathStatus::Validating);
  EXPECT_TRUE(newPath->outstandingChallengeData);
  EXPECT_TRUE(newPath->firstChallengeSentTimestamp);
  EXPECT_TRUE(newPath->lastChallengeSentTimestamp);

  // First congestion controller is cached
  EXPECT_EQ(
      firstPath->cachedCCAndRttState->congestionController.get(),
      firstCongestionController);
  EXPECT_NE(conn.congestionController.get(), firstCongestionController);

  // Cancel the path validation timeout and trigger it immediately
  ASSERT_TRUE(server->pathValidationTimeout().isTimerCallbackScheduled());
  server->pathValidationTimeout().cancelTimerCallback();
  auto& nonConstNewPath =
      quic::PathManagerTestAccessor::getNonConstPathInfo(conn, newPath->id);
  nonConstNewPath.pathResponseDeadline = Clock::now() - 1ms;
  server->pathValidationTimeout().timeoutExpired();

  EXPECT_EQ(newPath->status, PathStatus::NotValid);
  EXPECT_FALSE(newPath->outstandingChallengeData);
  EXPECT_FALSE(newPath->firstChallengeSentTimestamp);
  EXPECT_FALSE(newPath->lastChallengeSentTimestamp);

  // The connection falls back to the firstPath
  EXPECT_EQ(conn.currentPathId, firstPath->id);
  // Congestion controller is restored
  EXPECT_EQ(conn.congestionController.get(), firstCongestionController);
}

TEST_P(
    QuicServerTransportAllowMigrationTest,
    PathValidationTimeoutForCurrentPathWithNoFallback) {
  auto qLogger = std::make_shared<FileQLogger>(VantagePoint::Server);
  auto& conn = server->getNonConstConn();
  conn.qLogger = qLogger;

  auto firstPath = conn.pathManager->getPath(conn.currentPathId);
  ASSERT_TRUE(firstPath);

  // Add additional peer id so PathResponse completes.
  conn.peerConnectionIds.emplace_back(
      ConnectionId::createAndMaybeCrash({1, 2, 3, 4}), 1);

  // Deliver a stream packet from a new peer address
  folly::SocketAddress newPeer("100.101.102.103", 23456);
  {
    auto data = IOBuf::copyBuffer("bad data");
    auto packetData = packetToBuf(createStreamPacket(
        *clientConnectionId,
        *server->getConn().serverConnectionId,
        clientNextAppDataPacketNum++,
        2,
        *data,
        0 /* cipherOverhead */,
        0 /* largestAcked */));

    // Migrate to unvalidated peer
    deliverData(std::move(packetData), true, &newPeer);
  }

  // Step 1: New path is created and is validating
  auto newPath = conn.pathManager->getPath(server->getLocalAddress(), newPeer);
  ASSERT_TRUE(newPath);
  EXPECT_EQ(conn.currentPathId, newPath->id);
  EXPECT_EQ(newPath->status, PathStatus::Validating);

  // The fallback path is reaped
  ASSERT_FALSE(conn.pathManager->removePath(firstPath->id).hasError());

  // Cancel the path validation timeout and trigger it immediately
  ASSERT_TRUE(server->pathValidationTimeout().isTimerCallbackScheduled());
  server->pathValidationTimeout().cancelTimerCallback();
  auto& nonConstNewPath =
      quic::PathManagerTestAccessor::getNonConstPathInfo(conn, newPath->id);
  nonConstNewPath.pathResponseDeadline = Clock::now() - 1ms;
  server->pathValidationTimeout().timeoutExpired();

  // There is no fallback path. The connection is closed
  ASSERT_TRUE(server->isClosed());
  EXPECT_EQ(
      server->getConn().localConnectionError->code,
      QuicErrorCode(TransportErrorCode::INVALID_MIGRATION));
}

TEST_P(
    QuicServerTransportAllowMigrationTest,
    PathValidationTimeoutResetUnderlyingTransportInCallback) {
  auto qLogger = std::make_shared<FileQLogger>(VantagePoint::Server);
  auto& conn = server->getNonConstConn();
  conn.qLogger = qLogger;

  auto firstPath = conn.pathManager->getPath(conn.currentPathId);
  ASSERT_TRUE(firstPath);

  // Add additional peer id so PathResponse completes.
  conn.peerConnectionIds.emplace_back(
      ConnectionId::createAndMaybeCrash({1, 2, 3, 4}), 1);

  // Deliver a stream packet from a new peer address
  folly::SocketAddress newPeer("100.101.102.103", 23456);
  {
    auto data = IOBuf::copyBuffer("bad data");
    auto packetData = packetToBuf(createStreamPacket(
        *clientConnectionId,
        *server->getConn().serverConnectionId,
        clientNextAppDataPacketNum++,
        2,
        *data,
        0 /* cipherOverhead */,
        0 /* largestAcked */));

    // Migrate to unvalidated peer
    deliverData(std::move(packetData), true, &newPeer);
  }

  // Step 1: New path is created and is validating
  auto newPath = conn.pathManager->getPath(server->getLocalAddress(), newPeer);
  ASSERT_TRUE(newPath);
  EXPECT_EQ(conn.currentPathId, newPath->id);
  EXPECT_EQ(newPath->status, PathStatus::Validating);

  // Deliver a path probe packet from a new peer address
  auto incomingPathChallengeData = 123;
  folly::SocketAddress newPeer2("100.101.102.104", 23456);
  {
    auto packet = makePacketWithPathChallegeFrame(incomingPathChallengeData);
    auto packetData = packetToBuf(packet);
    deliverData(std::move(packetData), true, &newPeer2);
  }

  // The fallback path is reaped
  ASSERT_FALSE(conn.pathManager->removePath(firstPath->id).hasError());

  // Delete the underlying transport in the PathValidationResult path.
  // This will crash if the pathValidationTimeout does not keep a pointer to the
  // transport.
  EXPECT_CALL(routingCallback, onConnectionUnbound(_, _, _))
      .WillOnce(Invoke([&](QuicServerTransport*, const auto&, const auto&) {
        server.reset();
      }));

  // Cancel the path validation timeout and trigger it immediately
  ASSERT_TRUE(server->pathValidationTimeout().isTimerCallbackScheduled());
  server->pathValidationTimeout().cancelTimerCallback();
  auto& nonConstNewPath =
      quic::PathManagerTestAccessor::getNonConstPathInfo(conn, newPath->id);
  nonConstNewPath.pathResponseDeadline = Clock::now() - 1ms;
  server->pathValidationTimeout().timeoutExpired();

  // The server transport has been deleted.
  ASSERT_EQ(server.get(), nullptr);
}

TEST_P(QuicServerTransportAllowMigrationTest, ReapOldValidatedPaths) {
  auto qLogger = std::make_shared<FileQLogger>(VantagePoint::Server);
  auto& conn = server->getNonConstConn();
  conn.qLogger = qLogger;

  auto pathIdRes = conn.pathManager->addPath(
      server->getLocalAddress(), folly::SocketAddress("1.2.3.4", 23456));
  ASSERT_FALSE(pathIdRes.hasError());
  auto& path =
      PathManagerTestAccessor::getNonConstPathInfo(conn, pathIdRes.value());
  // Path was validated but is old
  path.status = PathStatus::Validated;
  path.pathValidationTime = Clock::now() - kTimeToRetainOldPaths * 2;

  // Deliver any data to the socket. This should trigger the reaping logic.
  {
    auto data = IOBuf::copyBuffer("bad data");
    auto packetData = packetToBuf(createStreamPacket(
        *clientConnectionId,
        *server->getConn().serverConnectionId,
        clientNextAppDataPacketNum++,
        2,
        *data,
        0 /* cipherOverhead */,
        0 /* largestAcked */));

    // Migrate to unvalidated peer
    deliverData(std::move(packetData), true, &clientAddr);
  }

  auto pathFound = conn.pathManager->getPath(pathIdRes.value());
  EXPECT_FALSE(pathFound);
}

TEST_P(QuicServerTransportAllowMigrationTest, ReapUnusedNotValidPaths) {
  auto qLogger = std::make_shared<FileQLogger>(VantagePoint::Server);
  auto& conn = server->getNonConstConn();
  conn.qLogger = qLogger;

  auto pathIdRes = conn.pathManager->addPath(
      server->getLocalAddress(), folly::SocketAddress("1.2.3.4", 23456));
  ASSERT_FALSE(pathIdRes.hasError());
  auto& path =
      PathManagerTestAccessor::getNonConstPathInfo(conn, pathIdRes.value());
  // Path was validated but is old
  path.status = PathStatus::NotValid;

  // Deliver any data to the socket. This should trigger the reaping logic.
  {
    auto data = IOBuf::copyBuffer("bad data");
    auto packetData = packetToBuf(createStreamPacket(
        *clientConnectionId,
        *server->getConn().serverConnectionId,
        clientNextAppDataPacketNum++,
        2,
        *data,
        0 /* cipherOverhead */,
        0 /* largestAcked */));

    // Migrate to unvalidated peer
    deliverData(std::move(packetData), true, &clientAddr);
  }

  auto pathFound = conn.pathManager->getPath(pathIdRes.value());
  EXPECT_FALSE(pathFound);
}

TEST_P(QuicServerTransportAllowMigrationTest, DoNotReapUnusedValidatingPath) {
  auto qLogger = std::make_shared<FileQLogger>(VantagePoint::Server);
  auto& conn = server->getNonConstConn();
  conn.qLogger = qLogger;

  auto pathIdRes = conn.pathManager->addPath(
      server->getLocalAddress(), folly::SocketAddress("1.2.3.4", 23456));
  ASSERT_FALSE(pathIdRes.hasError());
  auto& path =
      PathManagerTestAccessor::getNonConstPathInfo(conn, pathIdRes.value());
  // Path is validating. A path challenge frame has been sent for it.
  path.status = PathStatus::Validating;
  path.outstandingChallengeData = 123;

  // Deliver any data to the socket. This should trigger the reaping logic.
  {
    auto data = IOBuf::copyBuffer("bad data");
    auto packetData = packetToBuf(createStreamPacket(
        *clientConnectionId,
        *server->getConn().serverConnectionId,
        clientNextAppDataPacketNum++,
        2,
        *data,
        0 /* cipherOverhead */,
        0 /* largestAcked */));

    // Migrate to unvalidated peer
    deliverData(std::move(packetData), true, &clientAddr);
  }

  auto pathFound = conn.pathManager->getPath(pathIdRes.value());
  EXPECT_TRUE(pathFound);
}

TEST_P(QuicServerTransportAllowMigrationTest, DoNotReapUnusedNewPath) {
  auto qLogger = std::make_shared<FileQLogger>(VantagePoint::Server);
  auto& conn = server->getNonConstConn();
  conn.qLogger = qLogger;

  auto pathIdRes = conn.pathManager->addPath(
      server->getLocalAddress(), folly::SocketAddress("1.2.3.4", 23456));
  ASSERT_FALSE(pathIdRes.hasError());
  auto& path =
      PathManagerTestAccessor::getNonConstPathInfo(conn, pathIdRes.value());
  // Path is new. It has an outstanding path challenge but it hasn't been sent
  // out yet
  path.status = PathStatus::NotValid;
  path.outstandingChallengeData = 123;

  // Deliver any data to the socket. This should trigger the reaping logic.
  {
    auto data = IOBuf::copyBuffer("bad data");
    auto packetData = packetToBuf(createStreamPacket(
        *clientConnectionId,
        *server->getConn().serverConnectionId,
        clientNextAppDataPacketNum++,
        2,
        *data,
        0 /* cipherOverhead */,
        0 /* largestAcked */));

    // Migrate to unvalidated peer
    deliverData(std::move(packetData), true, &clientAddr);
  }

  auto pathFound = conn.pathManager->getPath(pathIdRes.value());
  EXPECT_TRUE(pathFound);
}

TEST_P(
    QuicServerTransportAllowMigrationTest,
    MigrationUpdatesDestinationConnectionId) {
  auto& conn = server->getNonConstConn();

  // Add multiple peer connection IDs
  auto newCid1 = ConnectionId::createAndMaybeCrash({1, 2, 3, 4});
  auto newCid2 = ConnectionId::createAndMaybeCrash({5, 6, 7, 8});
  conn.peerConnectionIds.emplace_back(newCid1, 1);
  conn.peerConnectionIds.emplace_back(newCid2, 2);

  // Create a new path
  folly::SocketAddress newPeer("100.101.102.103", 23456);

  // Deliver a path challenge from the new peer address
  auto incomingPathChallengeData = 456;
  {
    auto packet = makePacketWithPathChallegeFrame(incomingPathChallengeData);
    auto packetData = packetToBuf(packet);
    deliverData(std::move(packetData), true, &newPeer);
  }

  // Verify new path was created
  auto newPath = conn.pathManager->getPath(server->getLocalAddress(), newPeer);
  ASSERT_TRUE(newPath);
  EXPECT_NE(conn.currentPathId, newPath->id);

  // Verify a destination CID was assigned to the new path
  // (This should happen automatically during path validation)
  EXPECT_TRUE(newPath->destinationConnectionId.has_value());

  // Get the challenge to send back
  auto outstandingChallenge = getFirstOutstandingPathChallenge();
  ASSERT_TRUE(outstandingChallenge);

  // Client migrates and validates the path
  {
    auto data = IOBuf::copyBuffer("migration data");
    auto streamPacket = packetToBuf(createStreamPacket(
        *clientConnectionId,
        *server->getConn().serverConnectionId,
        clientNextAppDataPacketNum++,
        2,
        *data,
        0 /* cipherOverhead */,
        0 /* largestAcked */));
    deliverData(std::move(streamPacket), true, &newPeer);
  }

  // Send path response to validate
  {
    auto packetData = packetToBuf(
        makePacketWithPathResponseFrame(outstandingChallenge->pathData));
    deliverData(std::move(packetData), true, &newPeer);
  }

  // Verify migration succeeded
  EXPECT_EQ(conn.currentPathId, newPath->id);
  EXPECT_EQ(newPath->status, PathStatus::Validated);
}

TEST_P(QuicServerTransportAllowMigrationTest, InitialClientCidMarkedInUse) {
  auto& conn = server->getNonConstConn();

  // Verify the initial client connection ID is marked as in use
  ASSERT_FALSE(conn.peerConnectionIds.empty());

  // The initial CID should be in the peerConnectionIds and marked as in use
  bool foundInUseCid = false;
  for (const auto& cidData : conn.peerConnectionIds) {
    if (cidData.connId == *conn.clientConnectionId &&
        cidData.sequenceNumber == kInitialConnectionIdSequenceNumber) {
      EXPECT_TRUE(cidData.inUse);
      foundInUseCid = true;
      break;
    }
  }
  EXPECT_TRUE(foundInUseCid);
}

} // namespace quic::test
