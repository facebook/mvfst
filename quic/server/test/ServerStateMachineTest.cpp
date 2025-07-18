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
      .WillOnce(Return(quic::make_unexpected(
          QuicError(quic::TransportErrorCode::INTERNAL_ERROR, "Tumbledown"))));
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
  auto encodeResult =
      encodeIntegerParameter(TransportParameterId::max_packet_size, 1000);
  ASSERT_FALSE(encodeResult.hasError());
  transportParams.push_back(encodeResult.value());
  ClientTransportParameters clientTransportParams = {
      std::move(transportParams)};
  auto result = processClientInitialParams(serverConn, clientTransportParams);
  ASSERT_TRUE(result.hasError());
  EXPECT_EQ(result.error().code, TransportErrorCode::TRANSPORT_PARAMETER_ERROR);
}

TEST(ServerStateMachineTest, TestProcessMaxDatagramSizeBelowMin) {
  QuicServerConnectionState serverConn(
      FizzServerQuicHandshakeContext::Builder().build());
  std::vector<TransportParameter> transportParams;
  auto encodeResult = encodeIntegerParameter(
      TransportParameterId::max_datagram_frame_size,
      kMaxDatagramPacketOverhead - 1);
  ASSERT_FALSE(encodeResult.hasError());
  transportParams.push_back(encodeResult.value());
  ClientTransportParameters clientTransportParams = {
      std::move(transportParams)};
  auto result = processClientInitialParams(serverConn, clientTransportParams);
  ASSERT_TRUE(result.hasError());
  EXPECT_EQ(result.error().code, TransportErrorCode::TRANSPORT_PARAMETER_ERROR);
}

TEST(ServerStateMachineTest, TestProcessMaxDatagramSizeOk) {
  QuicServerConnectionState serverConn(
      FizzServerQuicHandshakeContext::Builder().build());
  std::vector<TransportParameter> transportParams;
  auto encodeResult = encodeIntegerParameter(
      TransportParameterId::max_datagram_frame_size,
      kMaxDatagramPacketOverhead + 1);
  ASSERT_FALSE(encodeResult.hasError());
  transportParams.push_back(encodeResult.value());
  ClientTransportParameters clientTransportParams = {
      std::move(transportParams)};
  auto result = processClientInitialParams(serverConn, clientTransportParams);
  ASSERT_FALSE(result.hasError());
  EXPECT_EQ(
      serverConn.datagramState.maxWriteFrameSize,
      kMaxDatagramPacketOverhead + 1);
}

TEST(ServerStateMachineTest, TestProcessMaxDatagramSizeZeroOk) {
  QuicServerConnectionState serverConn(
      FizzServerQuicHandshakeContext::Builder().build());
  std::vector<TransportParameter> transportParams;
  auto encodeResult =
      encodeIntegerParameter(TransportParameterId::max_datagram_frame_size, 0);
  ASSERT_FALSE(encodeResult.hasError());
  transportParams.push_back(encodeResult.value());
  ClientTransportParameters clientTransportParams = {
      std::move(transportParams)};
  auto result = processClientInitialParams(serverConn, clientTransportParams);
  ASSERT_FALSE(result.hasError());
  EXPECT_EQ(serverConn.datagramState.maxWriteFrameSize, 0);
}

TEST(ServerStateMachineTest, TestProcessMinAckDelayNotSet) {
  QuicServerConnectionState serverConn(
      FizzServerQuicHandshakeContext::Builder().build());
  std::vector<TransportParameter> transportParams;
  ClientTransportParameters clientTransportParams = {
      std::move(transportParams)};
  auto result = processClientInitialParams(serverConn, clientTransportParams);
  ASSERT_FALSE(result.hasError());
  EXPECT_FALSE(serverConn.peerMinAckDelay.has_value());
}

TEST(ServerStateMachineTest, TestProcessMinAckDelaySet) {
  QuicServerConnectionState serverConn(
      FizzServerQuicHandshakeContext::Builder().build());
  std::vector<TransportParameter> transportParams;
  auto encodeResult =
      encodeIntegerParameter(TransportParameterId::min_ack_delay, 1000);
  ASSERT_FALSE(encodeResult.hasError());
  transportParams.push_back(encodeResult.value());
  ClientTransportParameters clientTransportParams = {
      std::move(transportParams)};
  auto result = processClientInitialParams(serverConn, clientTransportParams);
  ASSERT_FALSE(result.hasError());
  ASSERT_TRUE(serverConn.peerMinAckDelay.has_value());
  ASSERT_EQ(
      serverConn.peerMinAckDelay.value(), std::chrono::microseconds(1000));
}

TEST(ServerStateMachineTest, TestEncodeMinAckDelayParamSet) {
  QuicServerConnectionState serverConn(
      FizzServerQuicHandshakeContext::Builder().build());
  serverConn.transportSettings.minAckDelay = std::chrono::microseconds(1000);
  auto customTransportParams = getSupportedExtTransportParams(serverConn);
  auto minAckDelayParamResult = getIntegerParameter(
      TransportParameterId::min_ack_delay, customTransportParams);
  ASSERT_FALSE(minAckDelayParamResult.hasError());
  auto minAckDelayParam = minAckDelayParamResult.value();
  ASSERT_TRUE(minAckDelayParam.has_value());
  EXPECT_EQ(minAckDelayParam.value(), 1000);
}

TEST(ServerStateMachineTest, TestEncodeMinAckDelayParamNotSet) {
  QuicServerConnectionState serverConn(
      FizzServerQuicHandshakeContext::Builder().build());
  serverConn.transportSettings.advertisedKnobFrameSupport = false;
  auto customTransportParams = getSupportedExtTransportParams(serverConn);
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
  auto encodeResult =
      encodeIntegerParameter(TransportParameterId::knob_frames_supported, 1);
  ASSERT_FALSE(encodeResult.hasError());
  transportParams.push_back(encodeResult.value());
  ClientTransportParameters clientTransportParams = {
      std::move(transportParams)};
  auto result = processClientInitialParams(serverConn, clientTransportParams);
  ASSERT_FALSE(result.hasError());
  EXPECT_TRUE(serverConn.peerAdvertisedKnobFrameSupport);
}

TEST(ServerStateMachineTest, TestProcessKnobFramesSupportedParamDisabled) {
  QuicServerConnectionState serverConn(
      FizzServerQuicHandshakeContext::Builder().build());
  std::vector<TransportParameter> transportParams;
  auto encodeResult =
      encodeIntegerParameter(TransportParameterId::knob_frames_supported, 0);
  ASSERT_FALSE(encodeResult.hasError());
  transportParams.push_back(encodeResult.value());
  ClientTransportParameters clientTransportParams = {
      std::move(transportParams)};
  auto result = processClientInitialParams(serverConn, clientTransportParams);
  ASSERT_FALSE(result.hasError());
  EXPECT_FALSE(serverConn.peerAdvertisedKnobFrameSupport);
}

TEST(ServerStateMachineTest, TestEncodeKnobFrameSupportedParamEnabled) {
  QuicServerConnectionState serverConn(
      FizzServerQuicHandshakeContext::Builder().build());
  serverConn.transportSettings.advertisedKnobFrameSupport = true;
  auto customTransportParams = getSupportedExtTransportParams(serverConn);
  auto knobFrameSupportedParamResult = getIntegerParameter(
      TransportParameterId::knob_frames_supported, customTransportParams);
  ASSERT_FALSE(knobFrameSupportedParamResult.hasError());
  auto knobFrameSupportedParam = knobFrameSupportedParamResult.value();
  ASSERT_TRUE(knobFrameSupportedParam.has_value());
  EXPECT_EQ(knobFrameSupportedParam.value(), 1);
}

TEST(ServerStateMachineTest, TestEncodeKnobFrameSupportedParamDisabled) {
  QuicServerConnectionState serverConn(
      FizzServerQuicHandshakeContext::Builder().build());
  serverConn.transportSettings.advertisedKnobFrameSupport = false;
  auto customTransportParams = getSupportedExtTransportParams(serverConn);
  EXPECT_THAT(
      customTransportParams,
      Not(Contains(testing::Field(
          &TransportParameter::parameter,
          testing::Eq(TransportParameterId::knob_frames_supported)))));
}

TEST(ServerStateMachineTest, TestProcessExtendedAckSupportParam) {
  QuicServerConnectionState serverConn(
      FizzServerQuicHandshakeContext::Builder().build());
  std::vector<TransportParameter> transportParams;
  auto encodeResult =
      encodeIntegerParameter(TransportParameterId::extended_ack_features, 7);
  ASSERT_FALSE(encodeResult.hasError());
  transportParams.push_back(encodeResult.value());
  ClientTransportParameters clientTransportParams = {
      std::move(transportParams)};
  auto result = processClientInitialParams(serverConn, clientTransportParams);
  ASSERT_FALSE(result.hasError());
  EXPECT_EQ(serverConn.peerAdvertisedExtendedAckFeatures, 7);
}

TEST(ServerStateMachineTest, TestProcessExtendedAckSupportParamNotSent) {
  QuicServerConnectionState serverConn(
      FizzServerQuicHandshakeContext::Builder().build());
  std::vector<TransportParameter> transportParams;
  ClientTransportParameters clientTransportParams = {
      std::move(transportParams)};
  auto result = processClientInitialParams(serverConn, clientTransportParams);
  ASSERT_FALSE(result.hasError());
  EXPECT_EQ(serverConn.peerAdvertisedExtendedAckFeatures, 0);
}

TEST(
    ServerStateMachineTest,
    TestProcessReliableStreamResetSupportedParamEnabled) {
  QuicServerConnectionState serverConn(
      FizzServerQuicHandshakeContext::Builder().build());
  std::vector<TransportParameter> transportParams;
  transportParams.push_back(
      encodeEmptyParameter(TransportParameterId::reliable_stream_reset));
  ClientTransportParameters clientTransportParams = {
      std::move(transportParams)};
  auto result = processClientInitialParams(serverConn, clientTransportParams);
  ASSERT_FALSE(result.hasError());
  EXPECT_TRUE(serverConn.peerAdvertisedReliableStreamResetSupport);
}

TEST(
    ServerStateMachineTest,
    TestProcessReliableStreamResetSupportedParamDisabled) {
  QuicServerConnectionState serverConn(
      FizzServerQuicHandshakeContext::Builder().build());
  std::vector<TransportParameter> transportParams;
  ClientTransportParameters clientTransportParams = {
      std::move(transportParams)};
  auto result = processClientInitialParams(serverConn, clientTransportParams);
  ASSERT_FALSE(result.hasError());
  EXPECT_FALSE(serverConn.peerAdvertisedReliableStreamResetSupport);
}

TEST(ServerStateMachineTest, TestProcessReliableStreamResetNonEmptyParam) {
  QuicServerConnectionState serverConn(
      FizzServerQuicHandshakeContext::Builder().build());
  std::vector<TransportParameter> transportParams;
  auto encodeResult =
      encodeIntegerParameter(TransportParameterId::reliable_stream_reset, 0);
  ASSERT_FALSE(encodeResult.hasError());
  transportParams.push_back(encodeResult.value());
  ClientTransportParameters clientTransportParams = {
      std::move(transportParams)};
  auto result = processClientInitialParams(serverConn, clientTransportParams);
  ASSERT_TRUE(result.hasError());
  EXPECT_EQ(result.error().code, TransportErrorCode::TRANSPORT_PARAMETER_ERROR);
}

TEST(
    ServerStateMachineTest,
    TestEncodeReliableStreamResetSupportedParamEnabled) {
  QuicServerConnectionState serverConn(
      FizzServerQuicHandshakeContext::Builder().build());
  serverConn.transportSettings.advertisedReliableResetStreamSupport = true;
  auto customTransportParams = getSupportedExtTransportParams(serverConn);
  EXPECT_THAT(
      customTransportParams,
      Contains(testing::Field(
          &TransportParameter::parameter,
          testing::Eq(TransportParameterId::reliable_stream_reset))));
  auto it = findParameter(
      customTransportParams, TransportParameterId::reliable_stream_reset);
  EXPECT_TRUE(it->value->empty());
}

TEST(
    ServerStateMachineTest,
    TestEncodeReliableStreamResetSupportedParamDisabled) {
  QuicServerConnectionState serverConn(
      FizzServerQuicHandshakeContext::Builder().build());
  serverConn.transportSettings.advertisedReliableResetStreamSupport = false;
  auto customTransportParams = getSupportedExtTransportParams(serverConn);
  EXPECT_THAT(
      customTransportParams,
      Not(Contains(testing::Field(
          &TransportParameter::parameter,
          testing::Eq(TransportParameterId::reliable_stream_reset)))));
}

TEST(ServerStateMachineTest, TestProcessActiveConnectionIdLimitNotSet) {
  QuicServerConnectionState serverConn(
      FizzServerQuicHandshakeContext::Builder().build());
  std::vector<TransportParameter> transportParams;
  ClientTransportParameters clientTransportParams = {
      std::move(transportParams)};
  auto result = processClientInitialParams(serverConn, clientTransportParams);
  ASSERT_FALSE(result.hasError());
  // Check that the value is the default specified in RFC9000 when the transport
  // parameter is absent
  // https://datatracker.ietf.org/doc/html/rfc9000#section-18.2-6.2.1
  EXPECT_EQ(serverConn.peerActiveConnectionIdLimit, 2);
}

TEST(ServerStateMachineTest, TestProcessActiveConnectionIdLimitSet) {
  QuicServerConnectionState serverConn(
      FizzServerQuicHandshakeContext::Builder().build());
  std::vector<TransportParameter> transportParams;
  auto encodeResult = encodeIntegerParameter(
      TransportParameterId::active_connection_id_limit,
      kMaxActiveConnectionIdLimit + 1);
  ASSERT_FALSE(encodeResult.hasError());
  transportParams.push_back(encodeResult.value());
  ClientTransportParameters clientTransportParams = {
      std::move(transportParams)};
  auto result = processClientInitialParams(serverConn, clientTransportParams);
  ASSERT_FALSE(result.hasError());
  // This tests for max + 1. The maximum value will be enforced on sending the
  // new connection id frames, not in parsing the parameters.
  EXPECT_EQ(
      serverConn.peerActiveConnectionIdLimit, kMaxActiveConnectionIdLimit + 1);
}

struct advertisedMaxStreamGroupstestStruct {
  uint64_t peerMaxGroupsIn;
  OptionalIntegral<uint64_t> expectedTransportSettingVal;
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
    auto encodeResult = encodeIntegerParameter(
        TransportParameterId::stream_groups_enabled,
        GetParam().peerMaxGroupsIn);
    ASSERT_FALSE(encodeResult.hasError());
    transportParams.push_back(encodeResult.value());
  }
  ClientTransportParameters clientTransportParams = {
      std::move(transportParams)};
  auto result = processClientInitialParams(serverConn, clientTransportParams);
  ASSERT_FALSE(result.hasError());

  EXPECT_EQ(
      serverConn.peerAdvertisedMaxStreamGroups,
      GetParam().expectedTransportSettingVal);
}

INSTANTIATE_TEST_SUITE_P(
    ServerStateMachineAdvertisedMaxStreamGroupsParamTest,
    ServerStateMachineAdvertisedMaxStreamGroupsParamTest,
    ::testing::Values(
        advertisedMaxStreamGroupstestStruct{0, std::nullopt},
        advertisedMaxStreamGroupstestStruct{16, 16}));

} // namespace test
} // namespace quic
