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

#include <folly/io/async/ScopedEventBaseThread.h>
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

// ── ThreadedPacketWriter integration ────────────────────────────────────────

namespace {

constexpr size_t kServerPayloadSize = 1000;

// Reads all bytes from a single unidirectional stream, then terminates the
// given EventBase loop when the FIN arrives.
class StreamFinReadCallback : public StreamReadCallback {
 public:
  StreamFinReadCallback(QuicSocketLite* sock, StreamId id, folly::EventBase* evb)
      : sock_(sock), id_(id), evb_(evb) {}

  void readAvailable(StreamId) noexcept override {
    auto res = sock_->read(id_, 0);
    if (res.hasError()) {
      evb_->terminateLoopSoon();
      return;
    }
    auto& [buf, fin] = res.value();
    if (buf) {
      received_ += buf->computeChainDataLength();
    }
    if (fin) {
      evb_->terminateLoopSoon();
    }
  }

  void readError(StreamId, QuicError) noexcept override {
    evb_->terminateLoopSoon();
  }

  size_t received_{0};

 private:
  QuicSocketLite* sock_;
  StreamId id_;
  folly::EventBase* evb_;
};

// Server-side callback: on full handshake done, opens one unidirectional stream
// and writes kServerPayloadSize bytes with FIN.
class DataSendingServerCallback : public MockConnectionSetupCallback,
                                  public MockConnectionCallback {
 public:
  explicit DataSendingServerCallback(QuicSocketLite* sock) : sock_(sock) {}

  void onFullHandshakeDone() noexcept override {
    auto streamId = sock_->createUnidirectionalStream();
    if (streamId.hasError()) {
      return;
    }
    auto buf = folly::IOBuf::create(kServerPayloadSize);
    buf->append(kServerPayloadSize);
    memset(buf->writableData(), 'x', kServerPayloadSize);
    sock_->writeChain(*streamId, std::move(buf), /*eof=*/true);
  }

 private:
  QuicSocketLite* sock_;
};

class DataSendingTransportFactory : public QuicServerTransportFactory {
  QuicServerTransport::Ptr make(
      folly::EventBase* evb,
      std::unique_ptr<FollyAsyncUDPSocketAlias> socket,
      const folly::SocketAddress&,
      QuicVersion quicVersion,
      std::shared_ptr<const fizz::server::FizzServerContext> ctx) noexcept
      override {
    auto trans =
        QuicServerTransport::make(evb, std::move(socket), nullptr, nullptr, ctx);
    auto cb = std::make_shared<DataSendingServerCallback>(trans.get());
    cbs_.push_back(cb);
    EXPECT_CALL(*cb, onConnectionEnd()).Times(AtMost(1));
    EXPECT_CALL(*cb, onConnectionError(_)).Times(AtMost(1));
    trans->setConnectionSetupCallback(cb.get());
    trans->setConnectionCallback(cb.get());
    return trans;
  }

  std::vector<std::shared_ptr<DataSendingServerCallback>> cbs_;
};

} // namespace

class ThreadedPacketWriterIntegrationTest : public testing::Test {
 public:
  void SetUp() override {
    qEvb_ = std::make_shared<FollyQuicEventBase>(&evb_);
  }

  void TearDown() override {
    if (client_) {
      client_->close(std::nullopt);
    }
    if (server_) {
      server_->shutdown();
    }
    // Per shutdown contract: stop drain EVB before destroying writers/workers.
    drainThread_.reset();
    // Drain any pending producer-EVB callbacks (e.g. onFatalError).
    evb_.loop();
  }

  void startServer() {
    serverTs_.statelessResetTokenSecret = getRandSecret();
    serverTs_.dataPathType = DataPathType::ChainedMemory;
    server_ = QuicServer::createQuicServer(serverTs_);
    server_->setFizzContext(quic::test::createServerCtx());
    server_->setQuicServerTransportFactory(
        std::make_unique<DataSendingTransportFactory>());
    drainThread_ = std::make_unique<folly::ScopedEventBaseThread>();
    server_->setDrainEventBase(drainThread_->getEventBase());
    server_->start(folly::SocketAddress("::1", 0), 1);
    server_->waitUntilInitialized();
  }

  std::shared_ptr<QuicClientTransport> createQuicClient() {
    CHECK(server_);
    auto fizzCtx = FizzClientQuicHandshakeContext::Builder()
                       .setFizzClientContext(quic::test::createClientCtx())
                       .setCertificateVerifier(createTestCertificateVerifier())
                       .build();
    auto client = std::make_shared<QuicClientTransport>(
        qEvb_,
        std::make_unique<FollyQuicAsyncUDPSocket>(qEvb_),
        std::move(fizzCtx));
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
  std::unique_ptr<folly::ScopedEventBaseThread> drainThread_;
  MockConnectionSetupCallback setupCb_;
  MockConnectionCallback connCb_;
  std::unique_ptr<StreamFinReadCallback> readCb_;
};

// Start a real QuicServer with SharedThreadedPacketWriter enabled, connect a
// real client, and verify that the server can send application data through
// the full path: ConnectionPacketWriter → SPSC queue → drain thread →
// writemGSO → kernel → client.
TEST_F(ThreadedPacketWriterIntegrationTest, ServerSendsDataThroughThreadedWriter) {
  startServer();
  client_ = createQuicClient();

  EXPECT_CALL(setupCb_, onReplaySafe());
  EXPECT_CALL(connCb_, onNewUnidirectionalStream(_))
      .WillOnce(Invoke([&](StreamId id) {
        readCb_ =
            std::make_unique<StreamFinReadCallback>(client_.get(), id, &evb_);
        client_->setReadCallback(id, readCb_.get());
      }));

  client_->start(&setupCb_, &connCb_);
  evb_.loopForever(); // terminates when StreamFinReadCallback receives FIN

  ASSERT_NE(readCb_, nullptr);
  EXPECT_EQ(readCb_->received_, kServerPayloadSize);
}

} // namespace quic::test
