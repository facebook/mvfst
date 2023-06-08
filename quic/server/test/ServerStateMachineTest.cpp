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
#include <quic/state/test/MockQuicStats.h>
#include <chrono>

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
  quic::MockQuicStats mockQuicStats;
  serverState.statsCallback = &mockQuicStats;

  std::array<uint8_t, kStatelessResetTokenSecretLength> secret;
  serverState.transportSettings.statelessResetTokenSecret = secret;
  EXPECT_EQ(serverState.selfConnectionIds.size(), 0);
  serverState.peerActiveConnectionIdLimit = 2;
  EXPECT_CALL(mockQuicStats, onConnectionIdCreated(1)).Times(1);
  auto newConnId1 = serverState.createAndAddNewSelfConnId();
  EXPECT_CALL(mockQuicStats, onConnectionIdCreated(1)).Times(1);
  auto newConnId2 = serverState.createAndAddNewSelfConnId();
  EXPECT_CALL(mockQuicStats, onConnectionIdCreated(1)).Times(1);
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
  quic::MockQuicStats mockQuicStats;
  serverConn.statsCallback = &mockQuicStats;

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
  EXPECT_CALL(mockQuicStats, onConnectionIdCreated(2)).Times(1);
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
  quic::MockQuicStats mockQuicStats;
  serverConn.statsCallback = &mockQuicStats;

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
  EXPECT_CALL(mockQuicStats, onConnectionIdCreated(_)).Times(0);
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
  quic::MockQuicStats mockQuicStats;
  serverConn.statsCallback = &mockQuicStats;

  auto firstCid = getTestConnectionId(0);
  EXPECT_CALL(mockCidAlgo, encodeConnectionId(serverCidParams))
      .WillRepeatedly(Return(firstCid));
  EXPECT_CALL(mockRejector, rejectConnectionIdNonConst(_))
      .WillRepeatedly(Invoke([&](const ConnectionId& inputCid) {
        EXPECT_EQ(inputCid, firstCid);
        return true;
      }));
  EXPECT_CALL(mockQuicStats, onConnectionIdCreated(32)).Times(1);
  serverConn.createAndAddNewSelfConnId();
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

TEST(ServerStateMachineTest, TestProcessMinAckDelayNotSet) {
  QuicServerConnectionState serverConn(
      FizzServerQuicHandshakeContext::Builder().build());
  std::vector<TransportParameter> transportParams;
  ClientTransportParameters clientTransportParams = {
      std::move(transportParams)};
  processClientInitialParams(serverConn, clientTransportParams);
  EXPECT_FALSE(serverConn.peerAdvertisedKnobFrameSupport);
}

TEST(ServerStateMachineTest, TestProcessMinAckDelaySet) {
  QuicServerConnectionState serverConn(
      FizzServerQuicHandshakeContext::Builder().build());
  std::vector<TransportParameter> transportParams;
  transportParams.push_back(
      encodeIntegerParameter(TransportParameterId::min_ack_delay, 1000));
  ClientTransportParameters clientTransportParams = {
      std::move(transportParams)};
  processClientInitialParams(serverConn, clientTransportParams);
  ASSERT_TRUE(serverConn.peerMinAckDelay.has_value());
  ASSERT_EQ(
      serverConn.peerMinAckDelay.value(), std::chrono::microseconds(1000));
}

TEST(ServerStateMachineTest, TestEncodeMinAckDelayParamSet) {
  QuicServerConnectionState serverConn(
      FizzServerQuicHandshakeContext::Builder().build());
  serverConn.transportSettings.minAckDelay = std::chrono::microseconds(1000);
  auto customTransportParams =
      quic::setSupportedExtensionTransportParameters(serverConn);
  auto minAckDelayParam = getIntegerParameter(
      TransportParameterId::min_ack_delay, customTransportParams);
  ASSERT_TRUE(minAckDelayParam.has_value());
  EXPECT_EQ(minAckDelayParam.value(), 1000);
}

TEST(ServerStateMachineTest, TestEncodeMinAckDelayParamNotSet) {
  QuicServerConnectionState serverConn(
      FizzServerQuicHandshakeContext::Builder().build());
  serverConn.transportSettings.advertisedKnobFrameSupport = false;
  auto customTransportParams =
      quic::setSupportedExtensionTransportParameters(serverConn);
  EXPECT_THAT(
      customTransportParams,
      Not(Contains(testing::Field(
          &TransportParameter::parameter,
          testing::Eq(TransportParameterId::min_ack_delay)))));
}

TEST(ServerStateMachineTest, TestProcessKnobFramesSupportedParamEnabled) {
  QuicServerConnectionState serverConn(
      FizzServerQuicHandshakeContext::Builder().build());
  std::vector<TransportParameter> transportParams;
  transportParams.push_back(
      encodeIntegerParameter(TransportParameterId::knob_frames_supported, 1));
  ClientTransportParameters clientTransportParams = {
      std::move(transportParams)};
  processClientInitialParams(serverConn, clientTransportParams);
  EXPECT_TRUE(serverConn.peerAdvertisedKnobFrameSupport);
}

TEST(ServerStateMachineTest, TestProcessKnobFramesSupportedParamDisabled) {
  QuicServerConnectionState serverConn(
      FizzServerQuicHandshakeContext::Builder().build());
  std::vector<TransportParameter> transportParams;
  transportParams.push_back(
      encodeIntegerParameter(TransportParameterId::knob_frames_supported, 0));
  ClientTransportParameters clientTransportParams = {
      std::move(transportParams)};
  processClientInitialParams(serverConn, clientTransportParams);
  EXPECT_FALSE(serverConn.peerAdvertisedKnobFrameSupport);
}

TEST(ServerStateMachineTest, TestEncodeKnobFrameSupportedParamEnabled) {
  QuicServerConnectionState serverConn(
      FizzServerQuicHandshakeContext::Builder().build());
  serverConn.transportSettings.advertisedKnobFrameSupport = true;
  auto customTransportParams =
      quic::setSupportedExtensionTransportParameters(serverConn);
  auto knobFrameSupportedParam = getIntegerParameter(
      TransportParameterId::knob_frames_supported, customTransportParams);
  ASSERT_TRUE(knobFrameSupportedParam.has_value());
  EXPECT_EQ(knobFrameSupportedParam.value(), 1);
}

TEST(ServerStateMachineTest, TestEncodeKnobFrameSupportedParamDisabled) {
  QuicServerConnectionState serverConn(
      FizzServerQuicHandshakeContext::Builder().build());
  serverConn.transportSettings.advertisedKnobFrameSupport = false;
  auto customTransportParams =
      quic::setSupportedExtensionTransportParameters(serverConn);
  EXPECT_THAT(
      customTransportParams,
      Not(Contains(testing::Field(
          &TransportParameter::parameter,
          testing::Eq(TransportParameterId::knob_frames_supported)))));
}

struct advertisedMaxStreamGroupstestStruct {
  uint64_t peerMaxGroupsIn;
  folly::Optional<uint64_t> expectedTransportSettingVal;
};

class ServerStateMachineAdvertisedMaxStreamGroupsParamTest
    : public Test,
      public ::testing::WithParamInterface<
          advertisedMaxStreamGroupstestStruct> {};

TEST_P(
    ServerStateMachineAdvertisedMaxStreamGroupsParamTest,
    TestAdvertisedMaxStreamGroupsParam) {
  QuicServerConnectionState serverConn(
      FizzServerQuicHandshakeContext::Builder().build());
  std::vector<TransportParameter> transportParams;

  if (GetParam().peerMaxGroupsIn > 0) {
    CustomIntegralTransportParameter streamGroupsEnabledParam(
        static_cast<uint64_t>(TransportParameterId::stream_groups_enabled),
        GetParam().peerMaxGroupsIn);
    CHECK(
        setCustomTransportParameter(streamGroupsEnabledParam, transportParams));
  }
  ClientTransportParameters clientTransportParams = {
      std::move(transportParams)};
  processClientInitialParams(serverConn, clientTransportParams);

  EXPECT_EQ(
      serverConn.peerAdvertisedMaxStreamGroups,
      GetParam().expectedTransportSettingVal);
}

INSTANTIATE_TEST_SUITE_P(
    ServerStateMachineAdvertisedMaxStreamGroupsParamTest,
    ServerStateMachineAdvertisedMaxStreamGroupsParamTest,
    ::testing::Values(
        advertisedMaxStreamGroupstestStruct{0, folly::none},
        advertisedMaxStreamGroupstestStruct{16, 16}));

} // namespace test
} // namespace quic
