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

using namespace testing;

namespace quic::test {

// dummy/no-op callback to install on QuicServerTransport
class MockMergedConnectionCallbacks : public MockConnectionSetupCallback,
                                      public MockConnectionCallback {};

class QuicTransportFactory : public quic::QuicServerTransportFactory {
  // no-op quic server transport factory
  quic::QuicServerTransport::Ptr make(
      folly::EventBase* evb,
      std::unique_ptr<FollyAsyncUDPSocketAlias> socket,
      const folly::SocketAddress& /* peerAddr */,
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
    return quic::QuicServerTransport::make(
        evb, std::move(socket), noopCb, noopCb, ctx);
  }
};

class ServerTransportParameters : public testing::Test {
 public:
  void SetUp() override {
    qEvb_ = std::make_shared<FollyQuicEventBase>(&evb_);
  }
  void TearDown() override {
    if (client_) {
      client_->close(none);
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
    server_ = QuicServer::createQuicServer();
    // set server configs
    server_->setFizzContext(quic::test::createServerCtx());
    serverTs_.statelessResetTokenSecret = getRandSecret();
    server_->setTransportSettings(serverTs_);
    server_->setQuicServerTransportFactory(
        std::make_unique<QuicTransportFactory>());
    // start server
    server_->start(folly::SocketAddress("::1", 0), 1);
    server_->waitUntilInitialized();
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
      _id::knob_frames_supported,
      _id::ack_receive_timestamps_enabled};

  // validate equality of expected params and params sent by server
  EXPECT_EQ(serverTransportParams->parameters.size(), expectedParams.size());
  for (auto paramId : expectedParams) {
    auto param = findParameter(serverTransportParams->parameters, paramId);
    EXPECT_NE(param, serverTransportParams->parameters.end());
  }

  client_.reset();
}

TEST_F(ServerTransportParameters, DatagramTest) {
  // turn off datagram support to begin with
  serverTs_.datagramConfig.enabled = false;
  startServer();

  {
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
    EXPECT_FALSE(param.has_value());
    client_.reset();
  }

  {
    // now enable datagram support
    serverTs_.datagramConfig.enabled = true;
    server_->setTransportSettings(serverTs_);

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
    CHECK(param.has_value());
    // also validate value because why not
    EXPECT_EQ(param.value(), kMaxDatagramFrameSize);
  }
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

TEST_F(ServerTransportParameters, MaxStreamGroupsParam) {
  // advertise support for stream groups
  serverTs_.advertisedMaxStreamGroups = 1;
  startServer();

  // create & connect client
  client_ = createQuicClient();
  clientConnect();
  auto clientConn =
      dynamic_cast<const QuicClientConnectionState*>(client_->getState());

  const auto& serverTransportParams =
      clientConn->clientHandshakeLayer->getServerTransportParams();
  CHECK(serverTransportParams.has_value());

  // validate stream_groups_enabled parameter was rx'd
  auto it = findParameter(
      serverTransportParams->parameters,
      TransportParameterId::stream_groups_enabled);
  EXPECT_NE(it, serverTransportParams->parameters.end());
}

} // namespace quic::test
