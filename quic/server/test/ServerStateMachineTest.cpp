/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

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
      FizzServerQuicHandshakeContext::Builder().build());
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
      FizzServerQuicHandshakeContext::Builder().build());
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
      FizzServerQuicHandshakeContext::Builder().build());
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
      FizzServerQuicHandshakeContext::Builder().build());
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

TEST(ServerStateMachineTest, TestProcessMaxRecvPacketSizeParamBelowMin) {
  QuicServerConnectionState serverConn(
      FizzServerQuicHandshakeContext::Builder().build());
  std::vector<TransportParameter> transportParams;
  transportParams.push_back(
      encodeIntegerParameter(TransportParameterId::max_packet_size, 1000));
  ClientTransportParameters clientTransportParams = {
      std::move(transportParams)};
  try {
    processClientInitialParams(serverConn, clientTransportParams);
    FAIL() << "Expect transport exception due to max packet size too small";
  } catch (QuicTransportException& e) {
    EXPECT_EQ(e.errorCode(), TransportErrorCode::TRANSPORT_PARAMETER_ERROR);
  }
}

TEST(ServerStateMachineTest, TestProcessMaxDatagramSizeBelowMin) {
  QuicServerConnectionState serverConn(
      FizzServerQuicHandshakeContext::Builder().build());
  std::vector<TransportParameter> transportParams;
  transportParams.push_back(encodeIntegerParameter(
      TransportParameterId::max_datagram_frame_size,
      kMaxDatagramPacketOverhead - 1));
  ClientTransportParameters clientTransportParams = {
      std::move(transportParams)};
  try {
    processClientInitialParams(serverConn, clientTransportParams);
    FAIL()
        << "Expect transport exception due to max datagram frame size too small";
  } catch (QuicTransportException& e) {
    EXPECT_EQ(e.errorCode(), TransportErrorCode::TRANSPORT_PARAMETER_ERROR);
  }
}

TEST(ServerStateMachineTest, TestProcessMaxDatagramSizeOk) {
  QuicServerConnectionState serverConn(
      FizzServerQuicHandshakeContext::Builder().build());
  std::vector<TransportParameter> transportParams;
  transportParams.push_back(encodeIntegerParameter(
      TransportParameterId::max_datagram_frame_size,
      kMaxDatagramPacketOverhead + 1));
  ClientTransportParameters clientTransportParams = {
      std::move(transportParams)};
  processClientInitialParams(serverConn, clientTransportParams);
  EXPECT_EQ(
      serverConn.datagramState.maxWriteFrameSize,
      kMaxDatagramPacketOverhead + 1);
}

TEST(ServerStateMachineTest, TestProcessMaxDatagramSizeZeroOk) {
  QuicServerConnectionState serverConn(
      FizzServerQuicHandshakeContext::Builder().build());
  std::vector<TransportParameter> transportParams;
  transportParams.push_back(
      encodeIntegerParameter(TransportParameterId::max_datagram_frame_size, 0));
  ClientTransportParameters clientTransportParams = {
      std::move(transportParams)};
  processClientInitialParams(serverConn, clientTransportParams);
  EXPECT_EQ(serverConn.datagramState.maxWriteFrameSize, 0);
}

struct MaxPacketSizeTestUnit {
  uint64_t maxPacketSize;
  bool canIgnorePathMTU;
  folly::Optional<uint64_t> d6dBasePMTU;
  uint64_t expectUdpSendPacketLen;
  uint64_t expectD6DBasePMTU;
};

void runMaxPacketSizeTestWithFixture(
    const std::vector<MaxPacketSizeTestUnit>& fixture) {
  for (size_t i = 0; i < fixture.size(); i++) {
    const auto& unit = fixture[i];
    QuicServerConnectionState serverConn(
        FizzServerQuicHandshakeContext::Builder().build());
    std::vector<TransportParameter> transportParams;
    transportParams.push_back(encodeIntegerParameter(
        TransportParameterId::max_packet_size, unit.maxPacketSize));
    if (unit.d6dBasePMTU) {
      transportParams.push_back(encodeIntegerParameter(
          static_cast<TransportParameterId>(kD6DBasePMTUParameterId),
          *unit.d6dBasePMTU));
      serverConn.transportSettings.d6dConfig.enabled = true;
    }
    ClientTransportParameters clientTransportParams = {
        std::move(transportParams)};

    serverConn.transportSettings.canIgnorePathMTU = unit.canIgnorePathMTU;
    processClientInitialParams(serverConn, clientTransportParams);

    EXPECT_EQ(serverConn.udpSendPacketLen, unit.expectUdpSendPacketLen)
        << "Test unit " << i;
    EXPECT_EQ(serverConn.d6d.maxPMTU, unit.expectD6DBasePMTU)
        << "Test unit " << i;
  }
}

TEST(ServerStateMachineTest, TestProcessMaxRecvPacketSizeParams) {
  std::vector<MaxPacketSizeTestUnit> fixture = {
      {kDefaultMaxUDPPayload + 1,
       false,
       folly::none,
       kDefaultUDPSendPacketLen,
       kDefaultMaxUDPPayload},
      {kDefaultMaxUDPPayload - 10,
       false,
       folly::none,
       kDefaultUDPSendPacketLen,
       kDefaultMaxUDPPayload},
      {kDefaultMaxUDPPayload + 1,
       true,
       folly::none,
       kDefaultUDPSendPacketLen,
       kDefaultMaxUDPPayload},
      {kDefaultMaxUDPPayload - 10,
       true,
       folly::none,
       kDefaultMaxUDPPayload - 10,
       kDefaultMaxUDPPayload},
      {kDefaultMaxUDPPayload + 1,
       false,
       kDefaultUDPSendPacketLen,
       kDefaultUDPSendPacketLen,
       kDefaultMaxUDPPayload},
      {kDefaultMaxUDPPayload - 10,
       false,
       kDefaultUDPSendPacketLen,
       kDefaultUDPSendPacketLen,
       kDefaultMaxUDPPayload - 10},
      {kDefaultMaxUDPPayload + 1,
       true,
       kDefaultUDPSendPacketLen,
       kDefaultUDPSendPacketLen,
       kDefaultMaxUDPPayload},
      {kDefaultMaxUDPPayload - 10,
       true,
       kDefaultUDPSendPacketLen,
       kDefaultMaxUDPPayload - 10,
       kDefaultMaxUDPPayload - 10},
  };

  runMaxPacketSizeTestWithFixture(fixture);
}

struct maxStreamGroupsAdvertizedtestStruct {
  uint64_t peerMaxGroupsIn;
  folly::Optional<uint64_t> expectedTransportSettingVal;
};

class ServerStateMachineMaxStreamGroupsAdvertizedParamTest
    : public Test,
      public ::testing::WithParamInterface<
          maxStreamGroupsAdvertizedtestStruct> {};

TEST_P(
    ServerStateMachineMaxStreamGroupsAdvertizedParamTest,
    TestMaxStreamGroupsAdvertizedParam) {
  QuicServerConnectionState serverConn(
      FizzServerQuicHandshakeContext::Builder().build());
  std::vector<TransportParameter> transportParams;

  if (GetParam().peerMaxGroupsIn > 0) {
    auto streamGroupsEnabledParam =
        std::make_unique<CustomIntegralTransportParameter>(
            kStreamGroupsEnabledCustomParamId, GetParam().peerMaxGroupsIn);
    CHECK(setCustomTransportParameter(
        std::move(streamGroupsEnabledParam), transportParams));
  }
  ClientTransportParameters clientTransportParams = {
      std::move(transportParams)};
  processClientInitialParams(serverConn, clientTransportParams);

  EXPECT_EQ(
      serverConn.peerMaxStreamGroupsAdvertized,
      GetParam().expectedTransportSettingVal);
}

INSTANTIATE_TEST_SUITE_P(
    ServerStateMachineMaxStreamGroupsAdvertizedParamTest,
    ServerStateMachineMaxStreamGroupsAdvertizedParamTest,
    ::testing::Values(
        maxStreamGroupsAdvertizedtestStruct{0, folly::none},
        maxStreamGroupsAdvertizedtestStruct{16, 16}));

} // namespace test
} // namespace quic
