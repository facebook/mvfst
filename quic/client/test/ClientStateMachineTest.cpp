/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <quic/api/QuicTransportFunctions.h>
#include <quic/api/test/MockQuicSocket.h>
#include <quic/client/handshake/CachedServerTransportParameters.h>
#include <quic/client/handshake/ClientHandshake.h>
#include <quic/client/state/ClientStateMachine.h>
#include <quic/client/test/Mocks.h>
#include <quic/common/events/FollyQuicEventBase.h>
#include <quic/common/udpsocket/FollyQuicAsyncUDPSocket.h>
#include <quic/fizz/client/handshake/FizzClientQuicHandshakeContext.h>
#include <quic/handshake/TransportParameters.h>

using namespace ::testing;

namespace quic::test {

namespace {
// Use non-default values to test for nops
constexpr auto idleTimeout = kDefaultIdleTimeout + 1s;
constexpr auto maxRecvPacketSize = 1420;
constexpr auto initialMaxData = kDefaultConnectionFlowControlWindow + 2;
constexpr auto initialMaxStreamDataBidiLocal =
    kDefaultStreamFlowControlWindow + 3;
constexpr auto initialMaxStreamDataBidiRemote =
    kDefaultStreamFlowControlWindow + 4;
constexpr auto initialMaxStreamDataUni = kDefaultStreamFlowControlWindow + 5;
constexpr auto initialMaxStreamsBidi = kDefaultMaxStreamsBidirectional + 6;
constexpr auto initialMaxStreamsUni = kDefaultMaxStreamsUnidirectional + 7;
constexpr auto knobFrameSupport = true;
constexpr auto extendedAckSupport = 3;
constexpr auto ackReceiveTimestampsEnabled = true;
constexpr auto maxReceiveTimestampsPerAck = 10;
constexpr auto ackReceiveTimestampsExponent = 0;
const CachedServerTransportParameters kParams{
    .idleTimeout = std::chrono::milliseconds(idleTimeout).count(),
    .maxRecvPacketSize = maxRecvPacketSize,
    .initialMaxData = initialMaxData,
    .initialMaxStreamDataBidiLocal = initialMaxStreamDataBidiLocal,
    .initialMaxStreamDataBidiRemote = initialMaxStreamDataBidiRemote,
    .initialMaxStreamDataUni = initialMaxStreamDataUni,
    .initialMaxStreamsBidi = initialMaxStreamsBidi,
    .initialMaxStreamsUni = initialMaxStreamsUni,
    .maxReceiveTimestampsPerAck = maxReceiveTimestampsPerAck,
    .receiveTimestampsExponent = ackReceiveTimestampsExponent,
    .extendedAckFeatures = extendedAckSupport,
    .knobFrameSupport = knobFrameSupport,
    .ackReceiveTimestampsEnabled = ackReceiveTimestampsEnabled};
} // namespace

class ClientStateMachineTest : public Test {
 public:
  void SetUp() override {
    mockFactory_ = std::make_shared<MockClientHandshakeFactory>();
    EXPECT_CALL(*mockFactory_, makeClientHandshakeImpl(_))
        .WillRepeatedly(Invoke(
            [&](QuicClientConnectionState* conn)
                -> std::unique_ptr<quic::ClientHandshake> {
              auto handshake = std::make_unique<MockClientHandshake>(conn);
              mockHandshake_ = handshake.get();
              return handshake;
            }));
    client_ = std::make_unique<QuicClientConnectionState>(mockFactory_);
  }

  std::shared_ptr<MockClientHandshakeFactory> mockFactory_;
  MockClientHandshake* mockHandshake_;
  std::unique_ptr<QuicClientConnectionState> client_;
};

TEST_F(ClientStateMachineTest, TestUpdateTransportParamsNotIgnorePathMTU) {
  ASSERT_FALSE(
      updateTransportParamsFromCachedEarlyParams(*client_, kParams).hasError());
  EXPECT_EQ(client_->udpSendPacketLen, kDefaultUDPSendPacketLen);
}

TEST_F(ClientStateMachineTest, TestUpdateTransportParamsFromCachedEarlyParams) {
  client_->transportSettings.canIgnorePathMTU = true;
  client_->peerAdvertisedKnobFrameSupport = false;
  client_->peerAdvertisedExtendedAckFeatures = 0;
  client_->maybePeerAckReceiveTimestampsConfig = {
      .maxReceiveTimestampsPerAck = 10, .receiveTimestampsExponent = 0};

  ASSERT_FALSE(
      updateTransportParamsFromCachedEarlyParams(*client_, kParams).hasError());
  EXPECT_EQ(client_->peerIdleTimeout, idleTimeout);
  EXPECT_NE(client_->udpSendPacketLen, maxRecvPacketSize);
  EXPECT_EQ(client_->flowControlState.peerAdvertisedMaxOffset, initialMaxData);
  EXPECT_EQ(
      client_->flowControlState.peerAdvertisedInitialMaxStreamOffsetBidiLocal,
      initialMaxStreamDataBidiLocal);
  EXPECT_EQ(
      client_->flowControlState.peerAdvertisedInitialMaxStreamOffsetBidiRemote,
      initialMaxStreamDataBidiRemote);
  EXPECT_EQ(
      client_->flowControlState.peerAdvertisedInitialMaxStreamOffsetUni,
      initialMaxStreamDataUni);
  EXPECT_EQ(client_->peerAdvertisedKnobFrameSupport, knobFrameSupport);
  EXPECT_EQ(client_->peerAdvertisedExtendedAckFeatures, extendedAckSupport);
  ASSERT_TRUE(client_->maybePeerAckReceiveTimestampsConfig.has_value());
  EXPECT_EQ(
      client_->maybePeerAckReceiveTimestampsConfig.value()
          .maxReceiveTimestampsPerAck,
      maxReceiveTimestampsPerAck);
  EXPECT_EQ(
      client_->maybePeerAckReceiveTimestampsConfig.value()
          .receiveTimestampsExponent,
      ackReceiveTimestampsExponent);

  for (unsigned long i = 0; i < initialMaxStreamsBidi; i++) {
    EXPECT_TRUE(
        client_->streamManager->createNextBidirectionalStream().has_value());
  }
  EXPECT_TRUE(
      client_->streamManager->createNextBidirectionalStream().hasError());
  for (unsigned long i = 0; i < initialMaxStreamsUni; i++) {
    EXPECT_TRUE(
        client_->streamManager->createNextUnidirectionalStream().has_value());
  }
  EXPECT_TRUE(
      client_->streamManager->createNextUnidirectionalStream().hasError());
}

TEST_F(ClientStateMachineTest, PreserveHappyeyabllsDuringUndo) {
  folly::EventBase evb;
  auto qEvb = std::make_shared<FollyQuicEventBase>(&evb);
  auto randomCid = ConnectionId::createRandom(8);
  ASSERT_TRUE(randomCid.has_value());
  client_->clientConnectionId = randomCid.value();
  client_->happyEyeballsState.finished = true;
  client_->happyEyeballsState.secondSocket =
      std::make_unique<FollyQuicAsyncUDPSocket>(qEvb);
  auto newConn = undoAllClientStateForRetry(std::move(client_));
  EXPECT_TRUE(newConn->happyEyeballsState.finished);
  EXPECT_NE(nullptr, newConn->happyEyeballsState.secondSocket);
}

TEST_F(ClientStateMachineTest, PreserveObserverContainer) {
  auto socket = std::make_shared<MockQuicSocket>();
  const auto observerContainer =
      std::make_shared<SocketObserverContainer>(socket.get());
  SocketObserverContainer::ManagedObserver obs;
  observerContainer->addObserver(&obs);
  auto randomCid = ConnectionId::createRandom(8);
  ASSERT_TRUE(randomCid.has_value());
  client_->clientConnectionId = randomCid.value();

  client_->observerContainer = observerContainer;
  EXPECT_EQ(
      1,
      CHECK_NOTNULL(client_->observerContainer.lock().get())->numObservers());
  EXPECT_THAT(
      CHECK_NOTNULL(client_->observerContainer.lock().get())->findObservers(),
      UnorderedElementsAre(&obs));

  auto newConn = undoAllClientStateForRetry(std::move(client_));
  EXPECT_EQ(newConn->observerContainer.lock(), observerContainer);
  EXPECT_EQ(
      1,
      CHECK_NOTNULL(newConn->observerContainer.lock().get())->numObservers());
  EXPECT_THAT(
      CHECK_NOTNULL(newConn->observerContainer.lock().get())->findObservers(),
      UnorderedElementsAre(&obs));
}

TEST_F(ClientStateMachineTest, PreserveObserverContainerNullptr) {
  auto randomCid = ConnectionId::createRandom(8);
  ASSERT_TRUE(randomCid.has_value());
  client_->clientConnectionId = randomCid.value();

  ASSERT_THAT(client_->observerContainer.lock(), IsNull());

  auto newConn = undoAllClientStateForRetry(std::move(client_));
  EXPECT_THAT(newConn->observerContainer.lock(), IsNull());
}

TEST_F(ClientStateMachineTest, TestProcessMaxDatagramSizeBelowMin) {
  QuicClientConnectionState clientConn(
      FizzClientQuicHandshakeContext::Builder().build());
  std::vector<TransportParameter> transportParams;
  auto paramResult = encodeIntegerParameter(
      TransportParameterId::max_datagram_frame_size,
      kMaxDatagramPacketOverhead - 1);
  ASSERT_FALSE(paramResult.hasError());
  transportParams.push_back(std::move(paramResult.value()));
  ServerTransportParameters serverTransportParams = {
      std::move(transportParams)};

  auto result =
      processServerInitialParams(clientConn, serverTransportParams, 0);
  ASSERT_TRUE(result.hasError());
  EXPECT_EQ(result.error().code, TransportErrorCode::TRANSPORT_PARAMETER_ERROR);
}

TEST_F(ClientStateMachineTest, TestProcessMaxDatagramSizeZeroOk) {
  QuicClientConnectionState clientConn(
      FizzClientQuicHandshakeContext::Builder().build());
  std::vector<TransportParameter> transportParams;
  auto paramResult =
      encodeIntegerParameter(TransportParameterId::max_datagram_frame_size, 0);
  ASSERT_FALSE(paramResult.hasError());
  transportParams.push_back(std::move(paramResult.value()));
  ServerTransportParameters serverTransportParams = {
      std::move(transportParams)};
  ASSERT_FALSE(processServerInitialParams(clientConn, serverTransportParams, 0)
                   .hasError());
  EXPECT_EQ(clientConn.datagramState.maxWriteFrameSize, 0);
}

TEST_F(ClientStateMachineTest, TestProcessMaxDatagramSizeOk) {
  QuicClientConnectionState clientConn(
      FizzClientQuicHandshakeContext::Builder().build());
  std::vector<TransportParameter> transportParams;
  auto paramResult = encodeIntegerParameter(
      TransportParameterId::max_datagram_frame_size,
      kMaxDatagramPacketOverhead + 1);
  ASSERT_FALSE(paramResult.hasError());
  transportParams.push_back(std::move(paramResult.value()));
  ServerTransportParameters serverTransportParams = {
      std::move(transportParams)};
  ASSERT_FALSE(processServerInitialParams(clientConn, serverTransportParams, 0)
                   .hasError());
  EXPECT_EQ(
      clientConn.datagramState.maxWriteFrameSize,
      kMaxDatagramPacketOverhead + 1);
}

TEST_F(ClientStateMachineTest, TestProcessKnobFramesSupportedParamEnabled) {
  QuicClientConnectionState clientConn(
      FizzClientQuicHandshakeContext::Builder().build());
  std::vector<TransportParameter> transportParams;
  auto paramResult =
      encodeIntegerParameter(TransportParameterId::knob_frames_supported, 1);
  ASSERT_FALSE(paramResult.hasError());
  transportParams.push_back(std::move(paramResult.value()));
  ServerTransportParameters serverTransportParams = {
      std::move(transportParams)};
  ASSERT_FALSE(processServerInitialParams(clientConn, serverTransportParams, 0)
                   .hasError());
  EXPECT_TRUE(clientConn.peerAdvertisedKnobFrameSupport);
}

TEST_F(ClientStateMachineTest, TestProcessKnobFramesSupportedParamDisabled) {
  QuicClientConnectionState clientConn(
      FizzClientQuicHandshakeContext::Builder().build());
  std::vector<TransportParameter> transportParams;
  auto paramResult =
      encodeIntegerParameter(TransportParameterId::knob_frames_supported, 0);
  ASSERT_FALSE(paramResult.hasError());
  transportParams.push_back(std::move(paramResult.value()));
  ServerTransportParameters serverTransportParams = {
      std::move(transportParams)};
  ASSERT_FALSE(processServerInitialParams(clientConn, serverTransportParams, 0)
                   .hasError());
  EXPECT_FALSE(clientConn.peerAdvertisedKnobFrameSupport);
}

TEST_F(ClientStateMachineTest, TestProcessExtendedAckSupportedParam) {
  QuicClientConnectionState clientConn(
      FizzClientQuicHandshakeContext::Builder().build());
  std::vector<TransportParameter> transportParams;
  auto paramResult =
      encodeIntegerParameter(TransportParameterId::extended_ack_features, 3);
  ASSERT_FALSE(paramResult.hasError());
  transportParams.push_back(std::move(paramResult.value()));
  ServerTransportParameters serverTransportParams = {
      std::move(transportParams)};
  ASSERT_FALSE(processServerInitialParams(clientConn, serverTransportParams, 0)
                   .hasError());
  EXPECT_EQ(clientConn.peerAdvertisedExtendedAckFeatures, 3);
}

TEST_F(ClientStateMachineTest, TestProcessExtendedAckSupportedParamDefault) {
  QuicClientConnectionState clientConn(
      FizzClientQuicHandshakeContext::Builder().build());
  std::vector<TransportParameter> transportParams;
  ServerTransportParameters serverTransportParams = {
      std::move(transportParams)};
  ASSERT_FALSE(processServerInitialParams(clientConn, serverTransportParams, 0)
                   .hasError());
  EXPECT_EQ(clientConn.peerAdvertisedExtendedAckFeatures, 0);
}

TEST_F(
    ClientStateMachineTest,
    TestProcessReliableStreamResetSupportedParamEnabled) {
  QuicClientConnectionState clientConn(
      FizzClientQuicHandshakeContext::Builder().build());
  std::vector<TransportParameter> transportParams;
  transportParams.push_back(
      encodeEmptyParameter(TransportParameterId::reliable_stream_reset));
  ServerTransportParameters serverTransportParams = {
      std::move(transportParams)};
  ASSERT_FALSE(processServerInitialParams(clientConn, serverTransportParams, 0)
                   .hasError());
  EXPECT_TRUE(clientConn.peerAdvertisedReliableStreamResetSupport);
}

TEST_F(
    ClientStateMachineTest,
    TestProcessReliableStreamResetSupportedParamDisabled) {
  QuicClientConnectionState clientConn(
      FizzClientQuicHandshakeContext::Builder().build());
  std::vector<TransportParameter> transportParams;
  ServerTransportParameters serverTransportParams = {
      std::move(transportParams)};
  ASSERT_FALSE(processServerInitialParams(clientConn, serverTransportParams, 0)
                   .hasError());
  EXPECT_FALSE(clientConn.peerAdvertisedReliableStreamResetSupport);
}

TEST_F(ClientStateMachineTest, TestProcessReliableStreamResetNonEmptyParam) {
  QuicClientConnectionState clientConn(
      FizzClientQuicHandshakeContext::Builder().build());
  std::vector<TransportParameter> transportParams;
  auto paramResult =
      encodeIntegerParameter(TransportParameterId::reliable_stream_reset, 0);
  ASSERT_FALSE(paramResult.hasError());
  transportParams.push_back(std::move(paramResult.value()));
  ServerTransportParameters serverTransportParams = {
      std::move(transportParams)};
  auto result =
      processServerInitialParams(clientConn, serverTransportParams, 0);
  EXPECT_TRUE(result.hasError());
  EXPECT_EQ(result.error().code, TransportErrorCode::TRANSPORT_PARAMETER_ERROR);
}

TEST_F(
    ClientStateMachineTest,
    TestEncodeReliableStreamResetSupportedParamEnabled) {
  QuicClientConnectionState clientConn(
      FizzClientQuicHandshakeContext::Builder().build());
  clientConn.transportSettings.advertisedReliableResetStreamSupport = true;
  auto customTransportParams = getSupportedExtTransportParams(clientConn);
  EXPECT_THAT(
      customTransportParams,
      Contains(
          testing::Field(
              &TransportParameter::parameter,
              testing::Eq(TransportParameterId::reliable_stream_reset))));
  auto it = findParameter(
      customTransportParams, TransportParameterId::reliable_stream_reset);
  EXPECT_TRUE(it->value->empty());
}

TEST_F(
    ClientStateMachineTest,
    TestEncodeReliableStreamResetSupportedParamDisabled) {
  QuicClientConnectionState clientConn(
      FizzClientQuicHandshakeContext::Builder().build());
  clientConn.transportSettings.advertisedReliableResetStreamSupport = false;
  auto customTransportParams = getSupportedExtTransportParams(clientConn);
  EXPECT_THAT(
      customTransportParams,
      Not(Contains(
          testing::Field(
              &TransportParameter::parameter,
              testing::Eq(TransportParameterId::reliable_stream_reset)))));
}

} // namespace quic::test
