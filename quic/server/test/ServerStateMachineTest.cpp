// Copyright 2004-present Facebook. All Rights Reserved.

#include <quic/server/state/ServerStateMachine.h>

#include <folly/portability/GMock.h>
#include <folly/portability/GTest.h>

#include <quic/codec/DefaultConnectionIdAlgo.h>
#include <quic/codec/QuicConnectionId.h>
#include <quic/codec/test/Mocks.h>
#include <quic/common/test/TestUtils.h>
#include <quic/fizz/server/handshake/FizzServerQuicHandshakeContext.h>
#include <quic/server/test/Mocks.h>

using namespace testing;

namespace quic {

namespace {
void assertServerConnIdParamsEq(
    ServerConnectionIdParams& first,
    ServerConnectionIdParams& second) {
  EXPECT_EQ(first.version, second.version);
  EXPECT_EQ(first.hostId, second.hostId);
  EXPECT_EQ(first.processId, second.processId);
  EXPECT_EQ(first.workerId, second.workerId);
}
} // namespace

namespace test {
TEST(ServerStateMachineTest, TestAddConnId) {
  QuicServerConnectionState serverState(
      std::make_shared<FizzServerQuicHandshakeContext>());
  ServerConnectionIdParams originalParams(12, 1, 37);

  auto algo = std::make_unique<DefaultConnectionIdAlgo>();

  serverState.connIdAlgo = algo.get();
  serverState.serverConnIdParams = originalParams;
  serverState.serverAddr = folly::SocketAddress("0.0.0.0", 42069);

  std::array<uint8_t, kStatelessResetTokenSecretLength> secret;
  serverState.transportSettings.statelessResetTokenSecret = secret;
  EXPECT_EQ(serverState.selfConnectionIds.size(), 0);
  serverState.peerActiveConnectionIdLimit = 2;
  auto newConnId1 = serverState.createAndAddNewSelfConnId();
  auto newConnId2 = serverState.createAndAddNewSelfConnId();
  auto newConnId3 = serverState.createAndAddNewSelfConnId();

  // Sequence numbers correctly set.
  EXPECT_EQ(newConnId1->sequenceNumber, 0);
  EXPECT_EQ(newConnId2->sequenceNumber, 1);
  EXPECT_EQ(newConnId3->sequenceNumber, 2);

  // All three conn ids are different from each other.
  EXPECT_NE(newConnId1->connId, newConnId2->connId);
  EXPECT_NE(newConnId2->connId, newConnId3->connId);
  EXPECT_NE(newConnId3->connId, newConnId1->connId);

  EXPECT_EQ(newConnId1->token->size(), kStatelessResetTokenLength);
  EXPECT_EQ(newConnId2->token->size(), kStatelessResetTokenLength);
  EXPECT_EQ(newConnId3->token->size(), kStatelessResetTokenLength);

  auto params1 = *serverState.connIdAlgo->parseConnectionId(newConnId1->connId);
  auto params2 = *serverState.connIdAlgo->parseConnectionId(newConnId2->connId);
  auto params3 = *serverState.connIdAlgo->parseConnectionId(newConnId3->connId);

  // Server connection id params are correctly encoded/decoded.
  assertServerConnIdParamsEq(originalParams, params1);
  assertServerConnIdParamsEq(params1, params2);
  assertServerConnIdParamsEq(params2, params3);

  EXPECT_EQ(serverState.selfConnectionIds.size(), 3);
  EXPECT_EQ(serverState.nextSelfConnectionIdSequence, 3);
}

TEST(ServerStateMachineTest, TestCidRejected) {
  QuicServerConnectionState serverConn(
      std::make_shared<FizzServerQuicHandshakeContext>());
  MockServerConnectionIdRejector mockRejector;
  ServerConnectionIdParams serverCidParams(10, 11, 12);
  MockConnectionIdAlgo mockCidAlgo;

  serverConn.connIdAlgo = &mockCidAlgo;
  serverConn.connIdRejector = &mockRejector;
  serverConn.serverConnIdParams = serverCidParams;
  serverConn.peerActiveConnectionIdLimit = 10;
  std::array<uint8_t, kStatelessResetTokenSecretLength> secret;
  serverConn.transportSettings.statelessResetTokenSecret = secret;
  serverConn.serverAddr = folly::SocketAddress("0.0.0.0", 225);

  auto firstCid = getTestConnectionId(0);
  auto secondCid = getTestConnectionId(1);
  EXPECT_CALL(mockCidAlgo, encodeConnectionId(serverCidParams))
      .WillOnce(Return(firstCid))
      .WillOnce(Return(secondCid));
  EXPECT_CALL(mockRejector, rejectConnectionIdNonConst(_))
      .WillOnce(Invoke([&](const ConnectionId& inputCid) {
        EXPECT_EQ(inputCid, firstCid);
        return true;
      }))
      .WillOnce(Invoke([&](const ConnectionId& inputCid) {
        EXPECT_EQ(inputCid, secondCid);
        return false;
      }));
  serverConn.createAndAddNewSelfConnId();
}

TEST(ServerStateMachineTest, TestCidRejectedThenFail) {
  QuicServerConnectionState serverConn(
      std::make_shared<FizzServerQuicHandshakeContext>());
  MockServerConnectionIdRejector mockRejector;
  ServerConnectionIdParams serverCidParams(10, 11, 12);
  MockConnectionIdAlgo mockCidAlgo;

  serverConn.connIdAlgo = &mockCidAlgo;
  serverConn.connIdRejector = &mockRejector;
  serverConn.serverConnIdParams = serverCidParams;
  serverConn.peerActiveConnectionIdLimit = 10;
  std::array<uint8_t, kStatelessResetTokenSecretLength> secret;
  serverConn.transportSettings.statelessResetTokenSecret = secret;
  serverConn.serverAddr = folly::SocketAddress("0.0.0.0", 770);

  auto firstCid = getTestConnectionId(0);
  EXPECT_CALL(mockCidAlgo, encodeConnectionId(serverCidParams))
      .WillOnce(Return(firstCid))
      .WillOnce(Return(folly::makeUnexpected(QuicInternalException(
          "Tumbledown", quic::LocalErrorCode::INTERNAL_ERROR))));
  EXPECT_CALL(mockRejector, rejectConnectionIdNonConst(_))
      .WillOnce(Invoke([&](const ConnectionId& inputCid) {
        EXPECT_EQ(inputCid, firstCid);
        return true;
      }));
  serverConn.createAndAddNewSelfConnId();
}

TEST(ServerStateMachineTest, TestCidRejectedGiveUp) {
  QuicServerConnectionState serverConn(
      std::make_shared<FizzServerQuicHandshakeContext>());
  MockServerConnectionIdRejector mockRejector;
  ServerConnectionIdParams serverCidParams(10, 11, 12);
  MockConnectionIdAlgo mockCidAlgo;

  serverConn.connIdAlgo = &mockCidAlgo;
  serverConn.connIdRejector = &mockRejector;
  serverConn.serverConnIdParams = serverCidParams;
  serverConn.peerActiveConnectionIdLimit = 10;
  std::array<uint8_t, kStatelessResetTokenSecretLength> secret;
  serverConn.transportSettings.statelessResetTokenSecret = secret;
  serverConn.serverAddr = folly::SocketAddress("0.0.0.0", 770);

  auto firstCid = getTestConnectionId(0);
  EXPECT_CALL(mockCidAlgo, encodeConnectionId(serverCidParams))
      .WillRepeatedly(Return(firstCid));
  size_t rejectCounter = 0;
  EXPECT_CALL(mockRejector, rejectConnectionIdNonConst(_))
      .WillRepeatedly(Invoke([&](const ConnectionId& inputCid) {
        EXPECT_EQ(inputCid, firstCid);
        rejectCounter++;
        return true;
      }));
  serverConn.createAndAddNewSelfConnId();
  EXPECT_EQ(rejectCounter, 16);
}

} // namespace test
} // namespace quic
