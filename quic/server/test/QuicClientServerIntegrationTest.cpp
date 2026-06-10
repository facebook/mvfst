/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <quic/api/test/Mocks.h>
#include <quic/client/QuicClientTransport.h>
#include <quic/common/events/FollyQuicEventBase.h>
#include <quic/common/test/TestClientUtils.h>
#include <quic/common/test/TestUtils.h>
#include <quic/fizz/client/handshake/FizzClientQuicHandshakeContext.h>
#include <quic/server/QuicServer.h>

#include <folly/portability/GMock.h>
#include <folly/portability/GTest.h>
#include <memory>
#include <mutex>

using namespace testing;

namespace quic::test {

// dummy/no-op callback to install on QuicServerTransport
class MockMergedConnectionCallbacks : public MockConnectionSetupCallback,
                                      public MockConnectionCallback {};

// Shared between the test fixture and `QuicTransportFactory` so tests can
// reach into the server-side connection state after the handshake completes.
// The mutex guards `transport`: the factory writes it on the server worker
// thread while the test thread reads via `get()` after `clientConnect()`.
class ServerTransportCapture {
 public:
  void set(std::shared_ptr<QuicServerTransport> t) {
    std::lock_guard<std::mutex> g(mutex_);
    transport_ = t;
  }

  std::shared_ptr<QuicServerTransport> get() const {
    std::lock_guard<std::mutex> g(mutex_);
    return transport_.lock();
  }

 private:
  mutable std::mutex mutex_;
  std::weak_ptr<QuicServerTransport> transport_;
};

class QuicTransportFactory : public quic::QuicServerTransportFactory {
 public:
  explicit QuicTransportFactory(std::shared_ptr<ServerTransportCapture> capture)
      : capture_(std::move(capture)) {}

  // no-op quic server transport factory
  quic::QuicServerTransport::Ptr make(
      folly::EventBase* evb,
      std::unique_ptr<FollyAsyncUDPSocketAlias> socket,
      const quic::SocketAddress& /* peerAddr */,
      quic::QuicVersion /*quicVersion*/,
      std::shared_ptr<const fizz::server::FizzServerContext> ctx) noexcept
      override {
    // delete mocked object as soon as terminal callback is rx'd
    auto noopCb = new MockMergedConnectionCallbacks();
    EXPECT_CALL(*noopCb, onConnectionEnd())
        .Times(AtMost(1))
        .WillRepeatedly([noopCb] { delete noopCb; });
    EXPECT_CALL(*noopCb, onConnectionError(_))
        .Times(AtMost(1))
        .WillRepeatedly([noopCb] { delete noopCb; });
    auto transport = quic::QuicServerTransport::make(
        evb, std::move(socket), noopCb, noopCb, ctx);
    if (capture_) {
      capture_->set(transport);
    }
    return transport;
  }

 private:
  std::shared_ptr<ServerTransportCapture> capture_;
};

// Copy of the server-side connection-state fields the tests assert on. The
// server worker EventBase mutates these fields during the handshake, so the
// test thread must not read them directly off the raw connection-state
// pointer. `snapshotServerConnState()` copies them out on the worker thread.
struct ServerConnStateSnapshot {
  bool hasConn{false};
  AckReceiveTimestampsVersion negotiatedOutgoing{
      AckReceiveTimestampsVersion::None};
  bool hasPeerConfig{false};
  AckReceiveTimestampsVersion peerConfigVersion{
      AckReceiveTimestampsVersion::None};
  uint64_t peerMaxReceiveTimestampsPerAck{0};
};

class ServerTransportParameters : public testing::Test {
 public:
  void SetUp() override {
    qEvb_ = std::make_shared<FollyQuicEventBase>(&evb_);
    serverCapture_ = std::make_shared<ServerTransportCapture>();
  }

  void TearDown() override {
    if (client_) {
      client_->close(std::nullopt);
    }
    if (server_) {
      server_->shutdown();
    }
    evb_.loop();
  }

  void clientConnect() {
    CHECK(client_) << "client not initialized";
    MockConnectionSetupCallback setupCb;
    MockConnectionCallback connCb;
    EXPECT_CALL(setupCb, onReplaySafe()).WillOnce(Invoke([&] {
      evb_.terminateLoopSoon();
    }));
    client_->start(&setupCb, &connCb);

    evb_.loopForever();
  }

  // start server with the transport settings that unit test can set accordingly
  void startServer() {
    serverTs_.statelessResetTokenSecret = getRandSecret();
    server_ = QuicServer::createQuicServer(serverTs_);
    // set server configs
    server_->setFizzContext(quic::test::createServerCtx());
    server_->setQuicServerTransportFactory(
        std::make_unique<QuicTransportFactory>(serverCapture_));
    // start server
    server_->start(quic::SocketAddress("::1", 0), 1);
    server_->waitUntilInitialized();
  }

  // Snapshot the server-side connection-state fields. Call after
  // `clientConnect()`. The fields are read on the server worker EventBase to
  // avoid racing the handshake, then returned by value.
  ServerConnStateSnapshot snapshotServerConnState() {
    ServerConnStateSnapshot snapshot;
    auto transport = serverCapture_->get();
    if (!transport) {
      return snapshot;
    }
    transport->getEventBase()->runInEventBaseThreadAndWait([&] {
      auto* serverConn =
          dynamic_cast<const QuicServerConnectionState*>(transport->getState());
      if (!serverConn) {
        return;
      }
      snapshot.hasConn = true;
      snapshot.negotiatedOutgoing =
          serverConn->negotiatedOutgoingAckReceiveTimestampsVersion;
      if (serverConn->maybePeerReceiveTimestampsConfig.has_value()) {
        snapshot.hasPeerConfig = true;
        snapshot.peerConfigVersion =
            serverConn->maybePeerReceiveTimestampsConfig->version;
        snapshot.peerMaxReceiveTimestampsPerAck =
            serverConn->maybePeerReceiveTimestampsConfig
                ->maxReceiveTimestampsPerAck;
      }
    });
    return snapshot;
  }

  // create new quic client
  std::shared_ptr<QuicClientTransport> createQuicClient() {
    // server must be already started
    CHECK(server_)
        << "::startServer() must be invoked prior to ::createQuicClient()";
    auto fizzClientContext =
        FizzClientQuicHandshakeContext::Builder()
            .setFizzClientContext(quic::test::createClientCtx())
            .setCertificateVerifier(createTestCertificateVerifier())
            .build();
    auto client = std::make_shared<QuicClientTransport>(
        qEvb_,
        std::make_unique<FollyQuicAsyncUDPSocket>(qEvb_),
        std::move(fizzClientContext));
    client->addNewPeerAddress(server_->getAddress());
    client->setHostname("::1");
    client->setSupportedVersions({QuicVersion::MVFST});
    return client;
  }

  std::shared_ptr<QuicClientTransport> client_;
  std::shared_ptr<QuicServer> server_;
  std::shared_ptr<ServerTransportCapture> serverCapture_;
  TransportSettings serverTs_{};
  folly::EventBase evb_;
  std::shared_ptr<FollyQuicEventBase> qEvb_;
};

/**
 * Tests the parameters that are sent with the default TransportSettings. Test
 * will need to be modified when we begin sending a new transport parameter on
 * the wire by default.
 */
TEST_F(ServerTransportParameters, InvariantlyAdvertisedParameters) {
  startServer();

  // create & connect client
  client_ = createQuicClient();
  clientConnect();

  // validate all the parameters we unconditionally advertise
  auto clientConn =
      dynamic_cast<const QuicClientConnectionState*>(client_->getState());
  const auto& serverTransportParams =
      clientConn->clientHandshakeLayer->getServerTransportParams();
  CHECK(serverTransportParams.has_value());

  using _id = TransportParameterId;
  auto expectedParams = {
      _id::initial_max_stream_data_bidi_local,
      _id::initial_max_stream_data_bidi_remote,
      _id::initial_max_stream_data_uni,
      _id::initial_max_data,
      _id::initial_max_streams_bidi,
      _id::initial_max_streams_uni,
      _id::idle_timeout,
      _id::ack_delay_exponent,
      _id::max_packet_size,
      _id::stateless_reset_token,
      _id::disable_migration,
      _id::active_connection_id_limit,
      _id::ack_receive_timestamps_enabled};

  // validate equality of expected params and params sent by server
  EXPECT_EQ(serverTransportParams->parameters.size(), expectedParams.size());
  for (auto paramId : expectedParams) {
    auto param = findParameter(serverTransportParams->parameters, paramId);
    EXPECT_NE(param, serverTransportParams->parameters.end());
  }
}

TEST_F(ServerTransportParameters, DatagramTestDisabled) {
  // turn off datagram support
  serverTs_.datagramConfig.enabled = false;
  startServer();

  // create & connect client
  client_ = createQuicClient();
  clientConnect();

  // validate no datagram support was advertised by server
  auto clientConn =
      dynamic_cast<const QuicClientConnectionState*>(client_->getState());
  const auto& serverTransportParams =
      clientConn->clientHandshakeLayer->getServerTransportParams();
  CHECK(serverTransportParams.has_value());

  auto param = getIntegerParameter(
      TransportParameterId::max_datagram_frame_size,
      serverTransportParams->parameters);
  ASSERT_TRUE(param.has_value());
  EXPECT_FALSE(param.value().has_value());
}

TEST_F(ServerTransportParameters, DatagramTestEnabled) {
  // turn on datagram support
  serverTs_.datagramConfig.enabled = true;
  startServer();

  // create & connect client
  client_ = createQuicClient();
  clientConnect();

  // validate datagram support was advertised by server
  auto clientConn =
      dynamic_cast<const QuicClientConnectionState*>(client_->getState());
  const auto& serverTransportParams =
      clientConn->clientHandshakeLayer->getServerTransportParams();
  CHECK(serverTransportParams.has_value());

  auto param = getIntegerParameter(
      TransportParameterId::max_datagram_frame_size,
      serverTransportParams->parameters);
  ASSERT_TRUE(param.has_value());
  CHECK(param.value().has_value());
  // also validate value because why not
  EXPECT_EQ(param.value(), kMaxDatagramFrameSize);
}

TEST_F(ServerTransportParameters, disableMigrationParam) {
  // turn off migration
  serverTs_.disableMigration = true;
  startServer();

  // create & connect client
  client_ = createQuicClient();
  clientConnect();
  auto clientConn =
      dynamic_cast<const QuicClientConnectionState*>(client_->getState());

  const auto& serverTransportParams =
      clientConn->clientHandshakeLayer->getServerTransportParams();
  CHECK(serverTransportParams.has_value());

  // validate disable_migration parameter was rx'd
  auto it = findParameter(
      serverTransportParams->parameters,
      TransportParameterId::disable_migration);
  EXPECT_NE(it, serverTransportParams->parameters.end());
}

// draft-ietf-quic-receive-ts-02 end-to-end negotiation matrix. Each test
// configures client + server `TransportSettings`, runs the real handshake,
// and asserts the advertised TPs, the client's
// `negotiatedOutgoingAckReceiveTimestampsVersion`, and the client's
// `maybePeerReceiveTimestampsConfig`.

namespace {

constexpr uint64_t kTestTimestampsMax = 5;
// Matches `kDefaultReceiveTimestampsExponent` so the matrix runs against
// the production default.
constexpr uint64_t kTestTimestampsExponent = 3;

AckReceiveTimestampsConfig testAckRxTsConfig() {
  return AckReceiveTimestampsConfig{
      .maxReceiveTimestampsPerAck = kTestTimestampsMax,
      .receiveTimestampsExponent = kTestTimestampsExponent};
}

bool serverAdvertisedLegacyAckReceiveTimestamps(
    const ::quic::ServerTransportParameters& params) {
  auto it = findParameter(
      params.parameters, TransportParameterId::ack_receive_timestamps_enabled);
  return it != params.parameters.end();
}

bool serverAdvertisedDraft02AckReceiveTimestamps(
    const ::quic::ServerTransportParameters& params) {
  auto it = findParameter(
      params.parameters,
      TransportParameterId::draft_02_max_receive_timestamps_per_ack);
  return it != params.parameters.end();
}

} // namespace

// Scenario A: both endpoints advertise legacy + draft-02. Negotiated
// outgoing version is draft-02 (higher-priority wire format when both
// available).
TEST_F(
    ServerTransportParameters,
    AckRxTsBothEndpointsDualAdvertiseNegotiatesDraft02) {
  serverTs_.enableIetfAckReceiveTimestamps = true;
  serverTs_.advertiseLegacyAckReceiveTimestamps = true;
  serverTs_.maybeAckReceiveTimestampsConfigSentToPeer = testAckRxTsConfig();
  startServer();

  client_ = createQuicClient();
  auto clientTs = client_->getTransportSettings();
  clientTs.enableIetfAckReceiveTimestamps = true;
  clientTs.advertiseLegacyAckReceiveTimestamps = true;
  clientTs.maybeAckReceiveTimestampsConfigSentToPeer = testAckRxTsConfig();
  client_->setTransportSettings(std::move(clientTs));
  clientConnect();

  auto clientConn =
      dynamic_cast<const QuicClientConnectionState*>(client_->getState());
  const auto& serverTransportParams =
      clientConn->clientHandshakeLayer->getServerTransportParams();
  CHECK(serverTransportParams.has_value());
  EXPECT_TRUE(
      serverAdvertisedLegacyAckReceiveTimestamps(*serverTransportParams));
  EXPECT_TRUE(
      serverAdvertisedDraft02AckReceiveTimestamps(*serverTransportParams));
  EXPECT_EQ(
      clientConn->negotiatedOutgoingAckReceiveTimestampsVersion,
      AckReceiveTimestampsVersion::DraftIetf02);
  ASSERT_TRUE(clientConn->maybePeerReceiveTimestampsConfig.has_value());
  EXPECT_EQ(
      clientConn->maybePeerReceiveTimestampsConfig->version,
      AckReceiveTimestampsVersion::DraftIetf02);

  auto serverConn = snapshotServerConnState();
  ASSERT_TRUE(serverConn.hasConn);
  EXPECT_EQ(
      serverConn.negotiatedOutgoing, AckReceiveTimestampsVersion::DraftIetf02);
  ASSERT_TRUE(serverConn.hasPeerConfig);
  EXPECT_EQ(
      serverConn.peerConfigVersion, AckReceiveTimestampsVersion::DraftIetf02);
}

// Scenario B: dual-advertise client + legacy-only server. Negotiated
// outgoing version on the client is Legacy because the server did not
// advertise draft-02. Connection succeeds.
TEST_F(
    ServerTransportParameters,
    AckRxTsDualAdvertiseClientLegacyServerNegotiatesLegacy) {
  serverTs_.enableIetfAckReceiveTimestamps = false;
  serverTs_.advertiseLegacyAckReceiveTimestamps = true;
  serverTs_.maybeAckReceiveTimestampsConfigSentToPeer = testAckRxTsConfig();
  startServer();

  client_ = createQuicClient();
  auto clientTs = client_->getTransportSettings();
  clientTs.enableIetfAckReceiveTimestamps = true;
  clientTs.advertiseLegacyAckReceiveTimestamps = true;
  clientTs.maybeAckReceiveTimestampsConfigSentToPeer = testAckRxTsConfig();
  client_->setTransportSettings(std::move(clientTs));
  clientConnect();

  auto clientConn =
      dynamic_cast<const QuicClientConnectionState*>(client_->getState());
  const auto& serverTransportParams =
      clientConn->clientHandshakeLayer->getServerTransportParams();
  CHECK(serverTransportParams.has_value());
  EXPECT_TRUE(
      serverAdvertisedLegacyAckReceiveTimestamps(*serverTransportParams));
  EXPECT_FALSE(
      serverAdvertisedDraft02AckReceiveTimestamps(*serverTransportParams));
  EXPECT_EQ(
      clientConn->negotiatedOutgoingAckReceiveTimestampsVersion,
      AckReceiveTimestampsVersion::LegacyMvfst);
  ASSERT_TRUE(clientConn->maybePeerReceiveTimestampsConfig.has_value());
  EXPECT_EQ(
      clientConn->maybePeerReceiveTimestampsConfig->version,
      AckReceiveTimestampsVersion::LegacyMvfst);

  // Server side: client advertised both formats, parser records the peer
  // version as DraftIetf02 ("draft-02 wins" in the TP decode), but server's
  // `enableIetf=false` means it can't speak draft-02 — so outgoing stays
  // None. The peer-version-vs-local-capability mismatch is tracked by Task
  // #28; closing it would let the server fall back to LegacyMvfst here.
  auto serverConn = snapshotServerConnState();
  ASSERT_TRUE(serverConn.hasConn);
  EXPECT_EQ(serverConn.negotiatedOutgoing, AckReceiveTimestampsVersion::None);
  ASSERT_TRUE(serverConn.hasPeerConfig);
  EXPECT_EQ(
      serverConn.peerConfigVersion, AckReceiveTimestampsVersion::DraftIetf02);
}

// Scenario C: client advertises only draft-02 (legacy off); server
// advertises only legacy. No overlapping wire format, so no negotiated
// outgoing version and no timestamp frames. The client-side peer config is
// populated from the server's legacy TPs, but the outgoing-version branch
// in `updateNegotiatedAckFeatures` requires
// `advertiseLegacyAckReceiveTimestamps` locally. Receive-path gate coverage
// is tracked in Task #21 and Task #29.
TEST_F(
    ServerTransportParameters,
    AckRxTsClientLegacyOffServerLegacyNegotiatesNone) {
  serverTs_.enableIetfAckReceiveTimestamps = false;
  serverTs_.advertiseLegacyAckReceiveTimestamps = true;
  serverTs_.maybeAckReceiveTimestampsConfigSentToPeer = testAckRxTsConfig();
  startServer();

  client_ = createQuicClient();
  auto clientTs = client_->getTransportSettings();
  clientTs.enableIetfAckReceiveTimestamps = true;
  clientTs.advertiseLegacyAckReceiveTimestamps = false;
  clientTs.maybeAckReceiveTimestampsConfigSentToPeer = testAckRxTsConfig();
  client_->setTransportSettings(std::move(clientTs));
  clientConnect();

  auto clientConn =
      dynamic_cast<const QuicClientConnectionState*>(client_->getState());
  EXPECT_EQ(
      clientConn->negotiatedOutgoingAckReceiveTimestampsVersion,
      AckReceiveTimestampsVersion::None);
  ASSERT_TRUE(clientConn->maybePeerReceiveTimestampsConfig.has_value());
  EXPECT_EQ(
      clientConn->maybePeerReceiveTimestampsConfig->version,
      AckReceiveTimestampsVersion::LegacyMvfst);
  EXPECT_EQ(
      clientConn->maybePeerReceiveTimestampsConfig->maxReceiveTimestampsPerAck,
      kTestTimestampsMax);
}

// Scenario D: legacy-only client + dual-advertise server. The TP parser
// always picks DraftIetf02 as the peer version when both formats are
// advertised, regardless of whether the LOCAL endpoint can speak draft-02.
// With local `enableIetfAckReceiveTimestamps=false`, the draft-02 outgoing
// branch is gated off and the legacy branch is skipped (peerVersion isn't
// LegacyMvfst), so the client ends up with no negotiated outgoing version.
// Asymmetric: server-side sees client's legacy-only advertise and emits
// legacy frames to client; client emits nothing. Task #28 tracks the parser
// fix — closing that gap would let scenario D produce mutual LEGACY.
TEST_F(
    ServerTransportParameters,
    AckRxTsLegacyClientDualAdvertiseServerNoOutgoingVersion) {
  serverTs_.enableIetfAckReceiveTimestamps = true;
  serverTs_.advertiseLegacyAckReceiveTimestamps = true;
  serverTs_.maybeAckReceiveTimestampsConfigSentToPeer = testAckRxTsConfig();
  startServer();

  client_ = createQuicClient();
  auto clientTs = client_->getTransportSettings();
  clientTs.enableIetfAckReceiveTimestamps = false;
  clientTs.advertiseLegacyAckReceiveTimestamps = true;
  clientTs.maybeAckReceiveTimestampsConfigSentToPeer = testAckRxTsConfig();
  client_->setTransportSettings(std::move(clientTs));
  clientConnect();

  auto clientConn =
      dynamic_cast<const QuicClientConnectionState*>(client_->getState());
  EXPECT_EQ(
      clientConn->negotiatedOutgoingAckReceiveTimestampsVersion,
      AckReceiveTimestampsVersion::None);
  ASSERT_TRUE(clientConn->maybePeerReceiveTimestampsConfig.has_value());
  EXPECT_EQ(
      clientConn->maybePeerReceiveTimestampsConfig->version,
      AckReceiveTimestampsVersion::DraftIetf02);

  auto serverConn = snapshotServerConnState();
  ASSERT_TRUE(serverConn.hasConn);
  EXPECT_EQ(
      serverConn.negotiatedOutgoing, AckReceiveTimestampsVersion::LegacyMvfst);
  ASSERT_TRUE(serverConn.hasPeerConfig);
  EXPECT_EQ(
      serverConn.peerConfigVersion, AckReceiveTimestampsVersion::LegacyMvfst);
}

// Scenario E: neither side advertises receive timestamps. Negotiated
// outgoing version stays None and no peer config is populated.
TEST_F(ServerTransportParameters, AckRxTsBothEndpointsDisabledNoNegotiation) {
  serverTs_.advertiseLegacyAckReceiveTimestamps = false;
  serverTs_.enableIetfAckReceiveTimestamps = false;
  startServer();
  client_ = createQuicClient();
  auto clientTs = client_->getTransportSettings();
  clientTs.advertiseLegacyAckReceiveTimestamps = false;
  clientTs.enableIetfAckReceiveTimestamps = false;
  client_->setTransportSettings(std::move(clientTs));
  clientConnect();

  auto clientConn =
      dynamic_cast<const QuicClientConnectionState*>(client_->getState());
  const auto& serverTransportParams =
      clientConn->clientHandshakeLayer->getServerTransportParams();
  CHECK(serverTransportParams.has_value());
  EXPECT_FALSE(
      serverAdvertisedLegacyAckReceiveTimestamps(*serverTransportParams));
  EXPECT_FALSE(
      serverAdvertisedDraft02AckReceiveTimestamps(*serverTransportParams));
  EXPECT_EQ(
      clientConn->negotiatedOutgoingAckReceiveTimestampsVersion,
      AckReceiveTimestampsVersion::None);
  EXPECT_FALSE(clientConn->maybePeerReceiveTimestampsConfig.has_value());

  auto serverConn = snapshotServerConnState();
  ASSERT_TRUE(serverConn.hasConn);
  EXPECT_EQ(serverConn.negotiatedOutgoing, AckReceiveTimestampsVersion::None);
  EXPECT_FALSE(serverConn.hasPeerConfig);
}

// draft-ietf-quic-receive-ts-02 spec: negotiation is ONE-WAY per direction.
// Endpoint A's outbound (A sending ACK_RECEIVE_TIMESTAMPS frames to B)
// is governed by B's advertisement that B wants timestamps. A's OWN
// advertisement governs only the B->A direction, independently. The old
// implementation gated outbound on BOTH sides' advertisements, which was
// over-restrictive and divergent from the spec.

// Client advertises draft-02 (asking for timestamps from server); server
// does NOT advertise. Expected: server sends timestamps to client; client
// does not send timestamps to server.
TEST_F(
    ServerTransportParameters,
    AckRxTsDraft02OneWayClientAdvertisesServerDoesNot) {
  // Server: enableIetf on (kill-switch open), but no config-sent-to-peer so
  // server advertises NO timestamp TPs.
  serverTs_.enableIetfAckReceiveTimestamps = true;
  serverTs_.advertiseLegacyAckReceiveTimestamps = false;
  serverTs_.maybeAckReceiveTimestampsConfigSentToPeer = std::nullopt;
  startServer();

  client_ = createQuicClient();
  auto clientTs = client_->getTransportSettings();
  clientTs.enableIetfAckReceiveTimestamps = true;
  clientTs.advertiseLegacyAckReceiveTimestamps = false;
  clientTs.maybeAckReceiveTimestampsConfigSentToPeer = testAckRxTsConfig();
  client_->setTransportSettings(std::move(clientTs));
  clientConnect();

  auto clientConn =
      dynamic_cast<const QuicClientConnectionState*>(client_->getState());
  const auto& serverTransportParams =
      clientConn->clientHandshakeLayer->getServerTransportParams();
  CHECK(serverTransportParams.has_value());
  // Server advertised nothing.
  EXPECT_FALSE(
      serverAdvertisedLegacyAckReceiveTimestamps(*serverTransportParams));
  EXPECT_FALSE(
      serverAdvertisedDraft02AckReceiveTimestamps(*serverTransportParams));
  // Client did not see any peer-receive-timestamps TPs.
  EXPECT_FALSE(clientConn->maybePeerReceiveTimestampsConfig.has_value());
  // Client's outbound stays None (server did not ask for timestamps).
  EXPECT_EQ(
      clientConn->negotiatedOutgoingAckReceiveTimestampsVersion,
      AckReceiveTimestampsVersion::None);

  auto serverConn = snapshotServerConnState();
  ASSERT_TRUE(serverConn.hasConn);
  // Server saw client's draft-02 advertisement.
  ASSERT_TRUE(serverConn.hasPeerConfig);
  EXPECT_EQ(
      serverConn.peerConfigVersion, AckReceiveTimestampsVersion::DraftIetf02);
  // Server's outbound is DraftIetf02 even though server itself did not
  // advertise: spec-conformant one-way negotiation.
  EXPECT_EQ(
      serverConn.negotiatedOutgoing, AckReceiveTimestampsVersion::DraftIetf02);
}

// Inverse: server advertises, client does not.
TEST_F(
    ServerTransportParameters,
    AckRxTsDraft02OneWayServerAdvertisesClientDoesNot) {
  serverTs_.enableIetfAckReceiveTimestamps = true;
  serverTs_.advertiseLegacyAckReceiveTimestamps = false;
  serverTs_.maybeAckReceiveTimestampsConfigSentToPeer = testAckRxTsConfig();
  startServer();

  client_ = createQuicClient();
  auto clientTs = client_->getTransportSettings();
  clientTs.enableIetfAckReceiveTimestamps = true;
  clientTs.advertiseLegacyAckReceiveTimestamps = false;
  clientTs.maybeAckReceiveTimestampsConfigSentToPeer = std::nullopt;
  client_->setTransportSettings(std::move(clientTs));
  clientConnect();

  auto clientConn =
      dynamic_cast<const QuicClientConnectionState*>(client_->getState());
  const auto& serverTransportParams =
      clientConn->clientHandshakeLayer->getServerTransportParams();
  CHECK(serverTransportParams.has_value());
  EXPECT_FALSE(
      serverAdvertisedLegacyAckReceiveTimestamps(*serverTransportParams));
  EXPECT_TRUE(
      serverAdvertisedDraft02AckReceiveTimestamps(*serverTransportParams));
  // Client saw server's draft-02 advertisement.
  ASSERT_TRUE(clientConn->maybePeerReceiveTimestampsConfig.has_value());
  EXPECT_EQ(
      clientConn->maybePeerReceiveTimestampsConfig->version,
      AckReceiveTimestampsVersion::DraftIetf02);
  // Client's outbound is DraftIetf02 even though client itself did not
  // advertise: spec-conformant one-way negotiation.
  EXPECT_EQ(
      clientConn->negotiatedOutgoingAckReceiveTimestampsVersion,
      AckReceiveTimestampsVersion::DraftIetf02);

  auto serverConn = snapshotServerConnState();
  ASSERT_TRUE(serverConn.hasConn);
  // Server did not see any peer-receive-timestamps TPs from client.
  EXPECT_FALSE(serverConn.hasPeerConfig);
  // Server's outbound stays None.
  EXPECT_EQ(serverConn.negotiatedOutgoing, AckReceiveTimestampsVersion::None);
}

// Both endpoints advertise + enableIetf, but client opts out of sending via
// `sendDraft02AckReceiveTimestamps=false`. Asymmetric outcome: server still
// sends draft-02 to client (client advertised); client does NOT send to
// server (operator opt-out, independent of advertisement).
TEST_F(
    ServerTransportParameters,
    AckRxTsDraft02SendDisabledClientReceivesNoSend) {
  serverTs_.enableIetfAckReceiveTimestamps = true;
  serverTs_.advertiseLegacyAckReceiveTimestamps = false;
  serverTs_.maybeAckReceiveTimestampsConfigSentToPeer = testAckRxTsConfig();
  // server's sendDraft02AckReceiveTimestamps defaults to true.
  startServer();

  client_ = createQuicClient();
  auto clientTs = client_->getTransportSettings();
  clientTs.enableIetfAckReceiveTimestamps = true;
  clientTs.advertiseLegacyAckReceiveTimestamps = false;
  clientTs.maybeAckReceiveTimestampsConfigSentToPeer = testAckRxTsConfig();
  clientTs.sendDraft02AckReceiveTimestamps = false;
  client_->setTransportSettings(std::move(clientTs));
  clientConnect();

  auto clientConn =
      dynamic_cast<const QuicClientConnectionState*>(client_->getState());
  // Both sides saw each other's draft-02 advertisement.
  ASSERT_TRUE(clientConn->maybePeerReceiveTimestampsConfig.has_value());
  EXPECT_EQ(
      clientConn->maybePeerReceiveTimestampsConfig->version,
      AckReceiveTimestampsVersion::DraftIetf02);
  // Client's outbound is None: operator opt-out via sendDraft02 = false.
  EXPECT_EQ(
      clientConn->negotiatedOutgoingAckReceiveTimestampsVersion,
      AckReceiveTimestampsVersion::None);

  auto serverConn = snapshotServerConnState();
  ASSERT_TRUE(serverConn.hasConn);
  ASSERT_TRUE(serverConn.hasPeerConfig);
  EXPECT_EQ(
      serverConn.peerConfigVersion, AckReceiveTimestampsVersion::DraftIetf02);
  // Server's outbound stays DraftIetf02: client advertised, server's
  // sendDraft02 defaults to true.
  EXPECT_EQ(
      serverConn.negotiatedOutgoing, AckReceiveTimestampsVersion::DraftIetf02);
}

} // namespace quic::test
