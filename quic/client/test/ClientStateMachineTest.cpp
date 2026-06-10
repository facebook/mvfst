/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <fizz/record/Types.h>
#include <fizz/util/Status.h>
#include <quic/api/QuicTransportFunctions.h>
#include <quic/api/test/MockQuicSocket.h>
#include <quic/client/handshake/CachedServerTransportParameters.h>
#include <quic/client/handshake/CachedServerTransportParametersSerialization.h>
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
  client_->maybePeerReceiveTimestampsConfig = PeerReceiveTimestampsConfig{
      .version = AckReceiveTimestampsVersion::LegacyMvfst,
      .maxReceiveTimestampsPerAck = 10,
      .exponent = 0};

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
  ASSERT_TRUE(client_->maybePeerReceiveTimestampsConfig.has_value());
  EXPECT_EQ(
      client_->maybePeerReceiveTimestampsConfig->version,
      AckReceiveTimestampsVersion::LegacyMvfst);
  EXPECT_EQ(
      client_->maybePeerReceiveTimestampsConfig->maxReceiveTimestampsPerAck,
      maxReceiveTimestampsPerAck);
  EXPECT_EQ(
      client_->maybePeerReceiveTimestampsConfig->exponent,
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

// draft-ietf-quic-receive-ts-02 transport-parameter parsing on the client.

namespace {
// Builds a `ServerTransportParameters` blob with the requested timestamp TPs
// encoded; `std::nullopt` skips that TP.
ServerTransportParameters buildServerTpsWithTimestampParams(
    Optional<uint64_t> legacyEnabled,
    Optional<uint64_t> legacyMax,
    Optional<uint64_t> legacyExponent,
    Optional<uint64_t> draftMax,
    Optional<uint64_t> draftExponent) {
  std::vector<TransportParameter> transportParams;
  auto push = [&](TransportParameterId id, Optional<uint64_t> value) {
    if (!value.has_value()) {
      return;
    }
    auto r = encodeIntegerParameter(id, *value);
    CHECK(!r.hasError());
    transportParams.push_back(std::move(r.value()));
  };
  push(TransportParameterId::ack_receive_timestamps_enabled, legacyEnabled);
  push(TransportParameterId::max_receive_timestamps_per_ack, legacyMax);
  push(TransportParameterId::receive_timestamps_exponent, legacyExponent);
  push(TransportParameterId::draft_02_max_receive_timestamps_per_ack, draftMax);
  push(
      TransportParameterId::draft_02_receive_timestamps_exponent,
      draftExponent);
  return ServerTransportParameters{std::move(transportParams)};
}
} // namespace

TEST_F(ClientStateMachineTest, ProcessServerParamsDraft02MaxOnly) {
  QuicClientConnectionState clientConn(
      FizzClientQuicHandshakeContext::Builder().build());
  clientConn.transportSettings.enableIetfAckReceiveTimestamps = true;
  auto serverParams = buildServerTpsWithTimestampParams(
      /*legacyEnabled=*/std::nullopt,
      /*legacyMax=*/std::nullopt,
      /*legacyExponent=*/std::nullopt,
      /*draftMax=*/4,
      /*draftExponent=*/std::nullopt);

  ASSERT_FALSE(
      processServerInitialParams(clientConn, serverParams, 0).hasError());

  ASSERT_TRUE(clientConn.maybePeerReceiveTimestampsConfig.has_value());
  EXPECT_EQ(
      clientConn.maybePeerReceiveTimestampsConfig->version,
      AckReceiveTimestampsVersion::DraftIetf02);
  EXPECT_EQ(
      clientConn.maybePeerReceiveTimestampsConfig->maxReceiveTimestampsPerAck,
      4);
  EXPECT_EQ(clientConn.maybePeerReceiveTimestampsConfig->exponent, 0);
}

TEST_F(ClientStateMachineTest, ProcessServerParamsDraft02MaxAndExponent) {
  QuicClientConnectionState clientConn(
      FizzClientQuicHandshakeContext::Builder().build());
  clientConn.transportSettings.enableIetfAckReceiveTimestamps = true;
  auto serverParams = buildServerTpsWithTimestampParams(
      std::nullopt,
      std::nullopt,
      std::nullopt,
      /*draftMax=*/8,
      /*draftExponent=*/5);

  ASSERT_FALSE(
      processServerInitialParams(clientConn, serverParams, 0).hasError());

  ASSERT_TRUE(clientConn.maybePeerReceiveTimestampsConfig.has_value());
  EXPECT_EQ(
      clientConn.maybePeerReceiveTimestampsConfig->version,
      AckReceiveTimestampsVersion::DraftIetf02);
  EXPECT_EQ(
      clientConn.maybePeerReceiveTimestampsConfig->maxReceiveTimestampsPerAck,
      8);
  EXPECT_EQ(clientConn.maybePeerReceiveTimestampsConfig->exponent, 5);
}

TEST_F(ClientStateMachineTest, ProcessServerParamsDraft02ExponentTooLarge) {
  QuicClientConnectionState clientConn(
      FizzClientQuicHandshakeContext::Builder().build());
  auto serverParams = buildServerTpsWithTimestampParams(
      std::nullopt,
      std::nullopt,
      std::nullopt,
      /*draftMax=*/4,
      /*draftExponent=*/21);

  auto result = processServerInitialParams(clientConn, serverParams, 0);
  ASSERT_TRUE(result.hasError());
  EXPECT_EQ(result.error().code, TransportErrorCode::TRANSPORT_PARAMETER_ERROR);
}

TEST_F(ClientStateMachineTest, ProcessServerParamsDraft02ExponentWithoutMax) {
  QuicClientConnectionState clientConn(
      FizzClientQuicHandshakeContext::Builder().build());
  auto serverParams = buildServerTpsWithTimestampParams(
      std::nullopt,
      std::nullopt,
      std::nullopt,
      /*draftMax=*/std::nullopt,
      /*draftExponent=*/3);

  ASSERT_FALSE(
      processServerInitialParams(clientConn, serverParams, 0).hasError());

  EXPECT_FALSE(clientConn.maybePeerReceiveTimestampsConfig.has_value());
}

TEST_F(ClientStateMachineTest, ProcessServerParamsLegacyOnly) {
  QuicClientConnectionState clientConn(
      FizzClientQuicHandshakeContext::Builder().build());
  auto serverParams = buildServerTpsWithTimestampParams(
      /*legacyEnabled=*/1,
      /*legacyMax=*/9,
      /*legacyExponent=*/3,
      std::nullopt,
      std::nullopt);

  ASSERT_FALSE(
      processServerInitialParams(clientConn, serverParams, 0).hasError());

  ASSERT_TRUE(clientConn.maybePeerReceiveTimestampsConfig.has_value());
  EXPECT_EQ(
      clientConn.maybePeerReceiveTimestampsConfig->version,
      AckReceiveTimestampsVersion::LegacyMvfst);
  EXPECT_EQ(
      clientConn.maybePeerReceiveTimestampsConfig->maxReceiveTimestampsPerAck,
      9);
  EXPECT_EQ(clientConn.maybePeerReceiveTimestampsConfig->exponent, 3);
}

TEST_F(ClientStateMachineTest, ProcessServerParamsBothFormatsDraftPreferred) {
  QuicClientConnectionState clientConn(
      FizzClientQuicHandshakeContext::Builder().build());
  clientConn.transportSettings.enableIetfAckReceiveTimestamps = true;
  auto serverParams = buildServerTpsWithTimestampParams(
      /*legacyEnabled=*/1,
      /*legacyMax=*/9,
      /*legacyExponent=*/3,
      /*draftMax=*/4,
      /*draftExponent=*/2);

  ASSERT_FALSE(
      processServerInitialParams(clientConn, serverParams, 0).hasError());

  ASSERT_TRUE(clientConn.maybePeerReceiveTimestampsConfig.has_value());
  EXPECT_EQ(
      clientConn.maybePeerReceiveTimestampsConfig->version,
      AckReceiveTimestampsVersion::DraftIetf02);
  EXPECT_EQ(
      clientConn.maybePeerReceiveTimestampsConfig->maxReceiveTimestampsPerAck,
      4);
  EXPECT_EQ(clientConn.maybePeerReceiveTimestampsConfig->exponent, 2);
}

TEST_F(ClientStateMachineTest, ProcessServerParamsNoTimestampTps) {
  QuicClientConnectionState clientConn(
      FizzClientQuicHandshakeContext::Builder().build());
  auto serverParams = buildServerTpsWithTimestampParams(
      std::nullopt, std::nullopt, std::nullopt, std::nullopt, std::nullopt);

  ASSERT_FALSE(
      processServerInitialParams(clientConn, serverParams, 0).hasError());

  EXPECT_FALSE(clientConn.maybePeerReceiveTimestampsConfig.has_value());
}

// A legacy cache without the draft-02 trailer must throw inside
// `readCachedServerTransportParameters`. The production caller
// (`PersistentQuicPskCache::getPsk`) feeds a cursor whose tail contains app
// params written via `fizz::detail::writeBuf<uint16_t>`; making the trailer
// optional via `canAdvance` would silently consume the app-params length
// bytes as the trailer and corrupt both. The outer `try/catch` discards the
// cache, and the next connection does a full handshake.
TEST_F(ClientStateMachineTest, DeserializeLegacyCachedTransportParamsThrows) {
  // Build a legacy buffer using the same fizz primitives as the production
  // writer. `to<std::string>()` collects chained IOBufs into a contiguous
  // byte range, mirroring `PersistentQuicPskCache::putPsk`.
  auto legacyOut = folly::IOBuf::create(0);
  {
    folly::io::Appender appender(legacyOut.get(), 512);
    fizz::Error err;
    FIZZ_THROW_ON_ERROR(
        fizz::detail::write(err, uint64_t{12345}, appender), err);
    FIZZ_THROW_ON_ERROR(
        fizz::detail::write(err, uint64_t{1450}, appender), err);
    FIZZ_THROW_ON_ERROR(
        fizz::detail::write(err, uint64_t{65536}, appender), err);
    FIZZ_THROW_ON_ERROR(
        fizz::detail::write(err, uint64_t{32768}, appender), err);
    FIZZ_THROW_ON_ERROR(
        fizz::detail::write(err, uint64_t{32768}, appender), err);
    FIZZ_THROW_ON_ERROR(
        fizz::detail::write(err, uint64_t{32768}, appender), err);
    FIZZ_THROW_ON_ERROR(fizz::detail::write(err, uint64_t{100}, appender), err);
    FIZZ_THROW_ON_ERROR(fizz::detail::write(err, uint64_t{100}, appender), err);
    FIZZ_THROW_ON_ERROR(fizz::detail::write(err, uint8_t{1}, appender), err);
    FIZZ_THROW_ON_ERROR(fizz::detail::write(err, uint8_t{1}, appender), err);
    FIZZ_THROW_ON_ERROR(fizz::detail::write(err, uint64_t{7}, appender), err);
    FIZZ_THROW_ON_ERROR(fizz::detail::write(err, uint64_t{3}, appender), err);
    FIZZ_THROW_ON_ERROR(
        fizz::detail::write(err, ExtendedAckFeatureMaskType{2}, appender), err);
    // Intentionally no draft-02 trailer.
  }
  std::string legacyBytes = legacyOut->to<std::string>();

  auto buf = folly::IOBuf::wrapBuffer(legacyBytes.data(), legacyBytes.length());
  folly::io::Cursor cursor(buf.get());
  CachedServerTransportParameters params;
  EXPECT_ANY_THROW(readCachedServerTransportParameters(cursor, params));
}

// A buffer written with the draft-02 trailer round-trips with all trailer
// fields preserved.
TEST_F(
    ClientStateMachineTest,
    RoundTripCachedTransportParamsWithDraft02Trailer) {
  CachedServerTransportParameters in;
  in.idleTimeout = 12345;
  in.maxRecvPacketSize = 1450;
  in.ackReceiveTimestampsEnabled = true;
  in.maxReceiveTimestampsPerAck = 7;
  in.receiveTimestampsExponent = 3;
  in.extendedAckFeatures = 2;
  in.cachedReceiveTimestampsVersion = AckReceiveTimestampsVersion::DraftIetf02;
  in.draft02MaxReceiveTimestampsPerAck = 11;
  in.draft02ReceiveTimestampsExponent = 5;

  auto out = folly::IOBuf::create(0);
  {
    folly::io::Appender appender(out.get(), 512);
    writeCachedServerTransportParameters(in, appender);
  }
  std::string bytes = out->to<std::string>();

  auto buf = folly::IOBuf::wrapBuffer(bytes.data(), bytes.length());
  folly::io::Cursor cursor(buf.get());
  CachedServerTransportParameters roundTripped;
  ASSERT_NO_THROW(readCachedServerTransportParameters(cursor, roundTripped));

  EXPECT_EQ(roundTripped.idleTimeout, 12345);
  EXPECT_EQ(roundTripped.maxReceiveTimestampsPerAck, 7);
  EXPECT_EQ(
      roundTripped.cachedReceiveTimestampsVersion,
      AckReceiveTimestampsVersion::DraftIetf02);
  EXPECT_EQ(roundTripped.draft02MaxReceiveTimestampsPerAck, 11);
  EXPECT_EQ(roundTripped.draft02ReceiveTimestampsExponent, 5);
}

// On 0-RTT reject, `processServerInitialParams` runs against the real server
// TPs after `updateTransportParamsFromCachedEarlyParams` has populated the
// peer receive-timestamps fields from cache. When the real server advertises
// no timestamp support, the populate block must clear the cached value so
// `updateNegotiatedAckFeatures` does not enable a wire format the server
// never agreed to.
TEST_F(
    ClientStateMachineTest,
    ProcessServerParamsClearsStalePeerReceiveTimestampsConfig) {
  QuicClientConnectionState clientConn(
      FizzClientQuicHandshakeContext::Builder().build());
  clientConn.maybePeerReceiveTimestampsConfig = PeerReceiveTimestampsConfig{
      .version = AckReceiveTimestampsVersion::DraftIetf02,
      .maxReceiveTimestampsPerAck = 5,
      .exponent = 2,
  };
  ServerTransportParameters serverParams = buildServerTpsWithTimestampParams(
      std::nullopt, std::nullopt, std::nullopt, std::nullopt, std::nullopt);

  ASSERT_FALSE(
      processServerInitialParams(clientConn, serverParams, 0).hasError());

  EXPECT_FALSE(clientConn.maybePeerReceiveTimestampsConfig.has_value());
}

TEST_F(
    ClientStateMachineTest,
    UpdateTransportParamsFromCachedEarlyParamsDraft02) {
  client_->transportSettings.canIgnorePathMTU = true;
  client_->transportSettings.enableIetfAckReceiveTimestamps = true;
  CachedServerTransportParameters params{};
  params.idleTimeout = std::chrono::milliseconds(kDefaultIdleTimeout).count();
  params.cachedReceiveTimestampsVersion =
      AckReceiveTimestampsVersion::DraftIetf02;
  params.draft02MaxReceiveTimestampsPerAck = 6;
  params.draft02ReceiveTimestampsExponent = 4;

  ASSERT_FALSE(
      updateTransportParamsFromCachedEarlyParams(*client_, params).hasError());

  ASSERT_TRUE(client_->maybePeerReceiveTimestampsConfig.has_value());
  EXPECT_EQ(
      client_->maybePeerReceiveTimestampsConfig->version,
      AckReceiveTimestampsVersion::DraftIetf02);
  EXPECT_EQ(
      client_->maybePeerReceiveTimestampsConfig->maxReceiveTimestampsPerAck, 6);
  EXPECT_EQ(client_->maybePeerReceiveTimestampsConfig->exponent, 4);
}

} // namespace quic::test
