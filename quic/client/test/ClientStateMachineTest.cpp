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
#include <quic/common/QuicAsyncUDPSocketWrapper.h>
#include <quic/fizz/client/handshake/FizzClientQuicHandshakeContext.h>
#include <quic/handshake/CryptoFactory.h>
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
const CachedServerTransportParameters kParams{
    std::chrono::milliseconds(idleTimeout).count(),
    maxRecvPacketSize,
    initialMaxData,
    initialMaxStreamDataBidiLocal,
    initialMaxStreamDataBidiRemote,
    initialMaxStreamDataUni,
    initialMaxStreamsBidi,
    initialMaxStreamsUni,
    knobFrameSupport};
} // namespace

class ClientStateMachineTest : public Test {
 public:
  void SetUp() override {
    mockFactory_ = std::make_shared<MockClientHandshakeFactory>();
    EXPECT_CALL(*mockFactory_, _makeClientHandshake(_))
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
  updateTransportParamsFromCachedEarlyParams(*client_, kParams);
  EXPECT_EQ(client_->udpSendPacketLen, kDefaultUDPSendPacketLen);
}

TEST_F(ClientStateMachineTest, TestUpdateTransportParamsFromCachedEarlyParams) {
  client_->transportSettings.canIgnorePathMTU = true;
  client_->peerAdvertisedKnobFrameSupport = false;

  updateTransportParamsFromCachedEarlyParams(*client_, kParams);
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

  for (unsigned long i = 0; i < initialMaxStreamsBidi; i++) {
    EXPECT_TRUE(
        client_->streamManager->createNextBidirectionalStream().hasValue());
  }
  EXPECT_TRUE(
      client_->streamManager->createNextBidirectionalStream().hasError());
  for (unsigned long i = 0; i < initialMaxStreamsUni; i++) {
    EXPECT_TRUE(
        client_->streamManager->createNextUnidirectionalStream().hasValue());
  }
  EXPECT_TRUE(
      client_->streamManager->createNextUnidirectionalStream().hasError());
}

TEST_F(ClientStateMachineTest, PreserveHappyeyabllsDuringUndo) {
  folly::EventBase evb;
  client_->clientConnectionId = ConnectionId::createRandom(8);
  client_->happyEyeballsState.finished = true;
  client_->happyEyeballsState.secondSocket =
      std::make_unique<QuicAsyncUDPSocketWrapperImpl>(&evb);
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

  client_->clientConnectionId = ConnectionId::createRandom(8);
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
  client_->clientConnectionId = ConnectionId::createRandom(8);
  ASSERT_THAT(client_->observerContainer.lock(), IsNull());

  auto newConn = undoAllClientStateForRetry(std::move(client_));
  EXPECT_THAT(newConn->observerContainer.lock(), IsNull());
}

TEST_F(ClientStateMachineTest, TestProcessMaxDatagramSizeBelowMin) {
  QuicClientConnectionState clientConn(
      FizzClientQuicHandshakeContext::Builder().build());
  std::vector<TransportParameter> transportParams;
  transportParams.push_back(encodeIntegerParameter(
      TransportParameterId::max_datagram_frame_size,
      kMaxDatagramPacketOverhead - 1));
  ServerTransportParameters serverTransportParams = {
      std::move(transportParams)};
  try {
    processServerInitialParams(clientConn, serverTransportParams, 0);
    FAIL()
        << "Expect transport exception due to max datagram frame size too small";
  } catch (QuicTransportException& e) {
    EXPECT_EQ(e.errorCode(), TransportErrorCode::TRANSPORT_PARAMETER_ERROR);
  }
}

TEST_F(ClientStateMachineTest, TestProcessMaxDatagramSizeZeroOk) {
  QuicClientConnectionState clientConn(
      FizzClientQuicHandshakeContext::Builder().build());
  std::vector<TransportParameter> transportParams;
  transportParams.push_back(
      encodeIntegerParameter(TransportParameterId::max_datagram_frame_size, 0));
  ServerTransportParameters serverTransportParams = {
      std::move(transportParams)};
  processServerInitialParams(clientConn, serverTransportParams, 0);
  EXPECT_EQ(clientConn.datagramState.maxWriteFrameSize, 0);
}

TEST_F(ClientStateMachineTest, TestProcessMaxDatagramSizeOk) {
  QuicClientConnectionState clientConn(
      FizzClientQuicHandshakeContext::Builder().build());
  std::vector<TransportParameter> transportParams;
  transportParams.push_back(encodeIntegerParameter(
      TransportParameterId::max_datagram_frame_size,
      kMaxDatagramPacketOverhead + 1));
  ServerTransportParameters serverTransportParams = {
      std::move(transportParams)};
  processServerInitialParams(clientConn, serverTransportParams, 0);
  EXPECT_EQ(
      clientConn.datagramState.maxWriteFrameSize,
      kMaxDatagramPacketOverhead + 1);
}

TEST_F(ClientStateMachineTest, TestProcessKnobFramesSupportedParamEnabled) {
  QuicClientConnectionState clientConn(
      FizzClientQuicHandshakeContext::Builder().build());
  std::vector<TransportParameter> transportParams;
  auto knobFrameSupportParam =
      std::make_unique<CustomIntegralTransportParameter>(
          static_cast<uint64_t>(TransportParameterId::knob_frames_supported),
          1);
  transportParams.push_back(knobFrameSupportParam->encode());
  ServerTransportParameters serverTransportParams = {
      std::move(transportParams)};
  processServerInitialParams(clientConn, serverTransportParams, 0);
  EXPECT_TRUE(clientConn.peerAdvertisedKnobFrameSupport);
}

TEST_F(ClientStateMachineTest, TestProcessKnobFramesSupportedParamDisabled) {
  QuicClientConnectionState clientConn(
      FizzClientQuicHandshakeContext::Builder().build());
  std::vector<TransportParameter> transportParams;
  auto knobFrameSupportParam =
      std::make_unique<CustomIntegralTransportParameter>(
          static_cast<uint64_t>(TransportParameterId::knob_frames_supported),
          0);
  transportParams.push_back(knobFrameSupportParam->encode());
  ServerTransportParameters serverTransportParams = {
      std::move(transportParams)};
  processServerInitialParams(clientConn, serverTransportParams, 0);
  EXPECT_FALSE(clientConn.peerAdvertisedKnobFrameSupport);
}

struct maxStreamGroupsAdvertizedtestStruct {
  uint64_t peerMaxGroupsIn;
  folly::Optional<uint64_t> expectedTransportSettingVal;
};
class ClientStateMachineMaxStreamGroupsAdvertizedParamTest
    : public ClientStateMachineTest,
      public ::testing::WithParamInterface<
          maxStreamGroupsAdvertizedtestStruct> {};

TEST_P(
    ClientStateMachineMaxStreamGroupsAdvertizedParamTest,
    TestMaxStreamGroupsAdvertizedParam) {
  QuicClientConnectionState clientConn(
      FizzClientQuicHandshakeContext::Builder().build());
  std::vector<TransportParameter> transportParams;

  if (GetParam().peerMaxGroupsIn > 0) {
    CustomIntegralTransportParameter streamGroupsEnabledParam(
        static_cast<uint64_t>(TransportParameterId::stream_groups_enabled),
        GetParam().peerMaxGroupsIn);
    CHECK(
        setCustomTransportParameter(streamGroupsEnabledParam, transportParams));
  }
  ServerTransportParameters serverTransportParams = {
      std::move(transportParams)};
  processServerInitialParams(clientConn, serverTransportParams, 0);

  EXPECT_EQ(
      clientConn.peerAdvertisedMaxStreamGroups,
      GetParam().expectedTransportSettingVal);
}

INSTANTIATE_TEST_SUITE_P(
    ClientStateMachineMaxStreamGroupsAdvertizedParamTest,
    ClientStateMachineMaxStreamGroupsAdvertizedParamTest,
    ::testing::Values(
        maxStreamGroupsAdvertizedtestStruct{0, folly::none},
        maxStreamGroupsAdvertizedtestStruct{16, 16}));

} // namespace quic::test
