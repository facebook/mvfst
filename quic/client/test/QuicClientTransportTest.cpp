/*
 * Copyright (c) Facebook, Inc. and its affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 *
 */
#include <quic/client/QuicClientTransport.h>
#include <quic/server/QuicServer.h>

#include <quic/api/test/Mocks.h>

#include <folly/portability/GMock.h>
#include <folly/portability/GTest.h>

#include <fizz/crypto/aead/test/Mocks.h>
#include <fizz/protocol/clock/test/Mocks.h>
#include <folly/futures/Future.h>
#include <folly/io/Cursor.h>
#include <folly/io/async/ScopedEventBaseThread.h>
#include <folly/io/async/test/MockAsyncUDPSocket.h>
#include <quic/client/handshake/test/MockQuicPskCache.h>
#include <quic/codec/DefaultConnectionIdAlgo.h>
#include <quic/common/test/TestUtils.h>
#include <quic/congestion_control/CongestionControllerFactory.h>
#include <quic/handshake/TransportParameters.h>
#include <quic/handshake/test/Mocks.h>
#include <quic/happyeyeballs/QuicHappyEyeballsFunctions.h>
#include <quic/samples/echo/EchoHandler.h>
#include <quic/samples/echo/EchoServer.h>

using namespace testing;
using namespace folly;
using namespace folly::io;
using namespace quic::samples;
using namespace quic::test;

namespace quic {
namespace test {

MATCHER_P(BufMatches, buf, "") {
  folly::IOBufEqualTo eq;
  return eq(*arg, buf);
}

class DestructionCallback
    : public std::enable_shared_from_this<DestructionCallback> {
 public:
  void markDestroyed() {
    destroyed_ = true;
  }

  bool isDestroyed() {
    return destroyed_;
  }

 private:
  bool destroyed_{false};
};

class TestingQuicClientTransport : public QuicClientTransport {
 public:
  TestingQuicClientTransport(
      folly::EventBase* evb,
      std::unique_ptr<folly::AsyncUDPSocket> socket)
      : QuicClientTransport(evb, std::move(socket)) {}

  ~TestingQuicClientTransport() override {
    if (destructionCallback_) {
      destructionCallback_->markDestroyed();
    }
  }

  const QuicClientConnectionState& getConn() const {
    return *dynamic_cast<QuicClientConnectionState*>(conn_.get());
  }

  QuicClientConnectionState& getNonConstConn() {
    return *dynamic_cast<QuicClientConnectionState*>(conn_.get());
  }

  const std::unordered_map<StreamId, ReadCallbackData>& getReadCallbacks()
      const {
    return readCallbacks_;
  }

  const std::unordered_map<
      StreamId,
      std::deque<std::pair<uint64_t, QuicSocket::DeliveryCallback*>>>&
  getDeliveryCallbacks() const {
    return deliveryCallbacks_;
  }

  auto getConnPendingWriteCallback() const {
    return connWriteCallback_;
  }

  auto getStreamPendingWriteCallbacks() const {
    return pendingWriteCallbacks_;
  }

  auto& idleTimeout() {
    return idleTimeout_;
  }

  auto& lossTimeout() {
    return lossTimeout_;
  }

  auto& ackTimeout() {
    return ackTimeout_;
  }

  auto& happyEyeballsConnAttemptDelayTimeout() {
    return happyEyeballsConnAttemptDelayTimeout_;
  }

  auto& drainTimeout() {
    return drainTimeout_;
  }

  bool isClosed() const {
    return closeState_ == CloseState::CLOSED;
  }

  bool isDraining() const {
    return drainTimeout_.isScheduled();
  }

  auto& serverInitialParamsSet() {
    return serverInitialParamsSet_;
  }

  auto& peerAdvertisedInitialMaxData() {
    return peerAdvertisedInitialMaxData_;
  }

  auto& peerAdvertisedInitialMaxStreamDataBidiLocal() const {
    return peerAdvertisedInitialMaxStreamDataBidiLocal_;
  }

  auto& peerAdvertisedInitialMaxStreamDataBidiRemote() const {
    return peerAdvertisedInitialMaxStreamDataBidiRemote_;
  }

  auto& peerAdvertisedInitialMaxStreamDataUni() const {
    return peerAdvertisedInitialMaxStreamDataUni_;
  }

  void setDestructionCallback(
      std::shared_ptr<DestructionCallback> destructionCallback) {
    destructionCallback_ = destructionCallback;
  }

 private:
  std::shared_ptr<DestructionCallback> destructionCallback_;
};

using StreamPair = std::pair<std::unique_ptr<folly::IOBuf>, StreamId>;

class QuicClientTransportIntegrationTest : public TestWithParam<QuicVersion> {
 public:
  void SetUp() override {
    folly::ssl::init();

    // Fizz is the hostname for the server cert.
    hostname = "Fizz";
    serverCtx = test::createServerCtx();
    serverCtx->setSupportedAlpns({"h1q-fb", "hq"});
    server_ = createServer(ProcessId::ZERO);
    serverAddr = server_->getAddress();
    ON_CALL(clientConnCallback, onTransportReady()).WillByDefault(Invoke([&] {
      connected_ = true;
    }));
    auto sock = std::make_unique<folly::AsyncUDPSocket>(&eventbase_);
    clientCtx = std::make_shared<fizz::client::FizzClientContext>();
    clientCtx->setSupportedAlpns({"h1q-fb"});
    clientCtx->setClock(std::make_shared<fizz::test::MockClock>());
    client = std::make_shared<TestingQuicClientTransport>(
        &eventbase_, std::move(sock));
    client->setSupportedVersions({getVersion()});
    client->setCongestionControllerFactory(
        std::make_shared<DefaultCongestionControllerFactory>());
    client->setHostname(hostname);
    client->setFizzClientContext(clientCtx);
    client->setCertificateVerifier(createTestCertificateVerifier());
    client->addNewPeerAddress(serverAddr);
    pskCache_ = std::make_shared<BasicQuicPskCache>();
    client->setPskCache(pskCache_);
  }

  QuicVersion getVersion() {
    return GetParam();
  }

  std::shared_ptr<QuicServer> createServer(ProcessId processId) {
    auto server = QuicServer::createQuicServer();
    server->setQuicServerTransportFactory(
        std::make_unique<EchoServerTransportFactory>());
    server->setQuicUDPSocketFactory(
        std::make_unique<QuicSharedUDPSocketFactory>());
    server->setFizzContext(serverCtx);
    server->setSupportedVersion({getVersion(), MVFST1});
    folly::SocketAddress addr("::1", 0);
    server->setProcessId(processId);
    server->start(addr, 1);
    server->waitUntilInitialized();
    return server;
  }

  void TearDown() override {
    std::thread t([&] { eventbase_.loopForever(); });
    SCOPE_EXIT {
      t.join();
    };
    if (connected_) {
      verifyTransportParameters();
    }
    server_->shutdown();
    server_ = nullptr;
    eventbase_.runInEventBaseThreadAndWait([&] { client = nullptr; });
    eventbase_.terminateLoopSoon();
  }

  void verifyTransportParameters() {
    EXPECT_EQ(client->getConn().peerIdleTimeout, kDefaultIdleTimeout);
  }

  void expectTransportCallbacks() {
    EXPECT_CALL(clientConnCallback, onReplaySafe());
  }

  folly::Future<StreamPair> sendRequestAndResponse(
      std::unique_ptr<folly::IOBuf> data,
      StreamId streamid,
      MockReadCallback* readCb);

  void sendRequestAndResponseAndWait(
      folly::IOBuf& expectedData,
      std::unique_ptr<folly::IOBuf> sendData,
      StreamId streamid,
      MockReadCallback* readCb);

 protected:
  std::string hostname;
  folly::EventBase eventbase_;
  folly::SocketAddress serverAddr;
  MockConnectionCallback clientConnCallback;
  MockReadCallback readCb;
  std::shared_ptr<TestingQuicClientTransport> client;
  std::shared_ptr<fizz::server::FizzServerContext> serverCtx;
  std::shared_ptr<fizz::client::FizzClientContext> clientCtx;
  std::shared_ptr<QuicPskCache> pskCache_;
  std::shared_ptr<QuicServer> server_;
  bool connected_{false};
};

class StreamData {
 public:
  folly::IOBufQueue data{folly::IOBufQueue::cacheChainLength()};

  folly::Promise<StreamPair> promise;
  StreamId id;

  explicit StreamData(StreamId id) : id(id) {}

  void setException(
      const std::pair<QuicErrorCode, folly::Optional<folly::StringPiece>>&
          err) {
    promise.setException(std::runtime_error(toString(err)));
    delete this;
  }

  void append(std::unique_ptr<folly::IOBuf> buf, bool eof) {
    data.append(std::move(buf));
    if (eof) {
      promise.setValue(std::make_pair(data.move(), id));
      delete this;
    }
  }
};

folly::Future<StreamPair>
QuicClientTransportIntegrationTest::sendRequestAndResponse(
    std::unique_ptr<folly::IOBuf> data,
    StreamId streamId,
    MockReadCallback* readCallback) {
  client->setReadCallback(streamId, readCallback);
  client->writeChain(streamId, data->clone(), true, false);
  auto streamData = new StreamData(streamId);
  auto dataCopy = std::shared_ptr<folly::IOBuf>(std::move(data));
  EXPECT_CALL(*readCallback, readAvailable(streamId))
      .WillRepeatedly(Invoke([c = client.get(),
                              id = streamId,
                              streamData,
                              dataCopy](auto) mutable {
        EXPECT_EQ(
            dynamic_cast<ClientHandshake*>(c->getConn().handshakeLayer.get())
                ->getPhase(),
            ClientHandshake::Phase::Established);
        auto readData = c->read(id, 1000);
        auto copy = readData->first->clone();
        LOG(INFO) << "Client received data="
                  << copy->moveToFbString().toStdString() << " on stream=" << id
                  << " read=" << readData->first->computeChainDataLength()
                  << " sent=" << dataCopy->computeChainDataLength();
        streamData->append(std::move(readData->first), readData->second);
      }));
  ON_CALL(*readCallback, readError(streamId, _))
      .WillByDefault(Invoke([streamData](auto, auto err) mutable {
        streamData->setException(err);
      }));
  return streamData->promise.getFuture().within(10s);
}

void QuicClientTransportIntegrationTest::sendRequestAndResponseAndWait(
    folly::IOBuf& expectedData,
    std::unique_ptr<folly::IOBuf> sendData,
    StreamId streamId,
    MockReadCallback* readCallback) {
  auto f = sendRequestAndResponse(sendData->clone(), streamId, readCallback)
               .thenValue([&](StreamPair buf) {
                 EXPECT_TRUE(folly::IOBufEqualTo()(*buf.first, expectedData));
               })
               .ensure([&] { eventbase_.terminateLoopSoon(); });
  eventbase_.loopForever();
  std::move(f).get(1s);
}

TEST_P(QuicClientTransportIntegrationTest, NetworkTest) {
  expectTransportCallbacks();
  client->start(&clientConnCallback);

  EXPECT_CALL(clientConnCallback, onTransportReady()).WillOnce(Invoke([&] {
    CHECK(client->getConn().oneRttWriteCipher);
    eventbase_.terminateLoopSoon();
  }));
  eventbase_.loopForever();

  auto streamId = client->createBidirectionalStream().value();
  auto data = IOBuf::copyBuffer("hello");
  auto expected = std::shared_ptr<IOBuf>(IOBuf::copyBuffer("echo "));
  expected->prependChain(data->clone());
  sendRequestAndResponseAndWait(*expected, data->clone(), streamId, &readCb);
}

TEST_P(QuicClientTransportIntegrationTest, FlowControlLimitedTest) {
  expectTransportCallbacks();
  client->start(&clientConnCallback);

  EXPECT_CALL(clientConnCallback, onTransportReady()).WillOnce(Invoke([&] {
    CHECK(client->getConn().oneRttWriteCipher);
    eventbase_.terminateLoopSoon();
  }));
  eventbase_.loopForever();

  auto streamId = client->createBidirectionalStream().value();
  client->setStreamFlowControlWindow(streamId, 1024);
  // TODO: change this once we negotiate the flow control window.
  auto data = IOBuf::create(kDefaultStreamWindowSize * 4);
  data->append(kDefaultStreamWindowSize * 4);
  memset(data->writableData(), 'a', data->length());

  auto expected = std::shared_ptr<IOBuf>(IOBuf::copyBuffer("echo "));
  expected->prependChain(data->clone());
  sendRequestAndResponseAndWait(*expected, data->clone(), streamId, &readCb);
}

TEST_P(QuicClientTransportIntegrationTest, ALPNTest) {
  EXPECT_CALL(clientConnCallback, onTransportReady()).WillOnce(Invoke([&] {
    ASSERT_EQ(client->getAppProtocol(), "h1q-fb");
    client->close(folly::none);
    eventbase_.terminateLoopSoon();
  }));
  ASSERT_EQ(client->getAppProtocol(), folly::none);
  client->start(&clientConnCallback);
  eventbase_.loopForever();
}

TEST_P(QuicClientTransportIntegrationTest, TLSAlert) {
  EXPECT_CALL(clientConnCallback, onConnectionError(_))
      .WillOnce(Invoke([&](const auto& errorCode) {
        LOG(ERROR) << "error: " << errorCode.second;
        EXPECT_TRUE(folly::variant_match(
            errorCode.first,
            [](const TransportErrorCode& err) {
              return static_cast<fizz::AlertDescription>(err) ==
                  fizz::AlertDescription::bad_certificate;
            },
            [](const auto&) { return false; }));
        client->close(folly::none);
        eventbase_.terminateLoopSoon();
      }));

  ASSERT_EQ(client->getAppProtocol(), folly::none);

  client->setCertificateVerifier(nullptr);
  client->start(&clientConnCallback);
  eventbase_.loopForever();
}

TEST_P(QuicClientTransportIntegrationTest, BadServerTest) {
  // Point the client to a bad server.
  client->addNewPeerAddress(SocketAddress("127.0.0.1", 14114));
  EXPECT_CALL(clientConnCallback, onConnectionError(_))
      .WillOnce(Invoke([&](const auto& errorCode) {
        LOG(ERROR) << "error: " << errorCode.second;
        EXPECT_TRUE(folly::variant_match(
            errorCode.first,
            [](const LocalErrorCode& err) {
              return err == LocalErrorCode::CONNECT_FAILED;
            },
            [](const auto&) { return false; }));
      }));
  client->start(&clientConnCallback);
  eventbase_.loop();
}

TEST_P(QuicClientTransportIntegrationTest, NetworkTestConnected) {
  expectTransportCallbacks();
  TransportSettings settings;
  settings.connectUDP = true;
  client->setTransportSettings(settings);
  client->start(&clientConnCallback);

  EXPECT_CALL(clientConnCallback, onTransportReady()).WillOnce(Invoke([&] {
    CHECK(client->getConn().oneRttWriteCipher);
    eventbase_.terminateLoopSoon();
  }));
  eventbase_.loopForever();

  auto streamId = client->createBidirectionalStream().value();
  auto data = IOBuf::copyBuffer("hello");
  auto expected = std::shared_ptr<IOBuf>(IOBuf::copyBuffer("echo "));
  expected->prependChain(data->clone());
  sendRequestAndResponseAndWait(*expected, data->clone(), streamId, &readCb);
}

TEST_P(QuicClientTransportIntegrationTest, TestZeroRttSuccess) {
  auto cachedPsk = setupZeroRttOnClientCtx(*clientCtx, hostname, getVersion());
  pskCache_->putPsk(hostname, cachedPsk);
  setupZeroRttOnServerCtx(*serverCtx, cachedPsk);
  // Change the ctx
  server_->setFizzContext(serverCtx);
  folly::Optional<std::string> alpn = std::string("h1q-fb");
  EXPECT_CALL(clientConnCallback, validateEarlyDataAppParams(alpn, _))
      .WillOnce(Return(true));
  client->start(&clientConnCallback);
  CHECK(client->getConn().zeroRttWriteCipher);
  EXPECT_TRUE(client->serverInitialParamsSet());
  EXPECT_EQ(
      client->peerAdvertisedInitialMaxData(), kDefaultConnectionWindowSize);
  EXPECT_EQ(
      client->peerAdvertisedInitialMaxStreamDataBidiLocal(),
      kDefaultStreamWindowSize);
  EXPECT_EQ(
      client->peerAdvertisedInitialMaxStreamDataBidiRemote(),
      kDefaultStreamWindowSize);
  EXPECT_EQ(
      client->peerAdvertisedInitialMaxStreamDataUni(),
      kDefaultStreamWindowSize);
  EXPECT_CALL(clientConnCallback, onTransportReady()).WillOnce(Invoke([&] {
    ASSERT_EQ(client->getAppProtocol(), "h1q-fb");
    CHECK(client->getConn().zeroRttWriteCipher);
    eventbase_.terminateLoopSoon();
  }));
  eventbase_.loopForever();

  EXPECT_TRUE(client->getConn().zeroRttWriteCipher);
  EXPECT_TRUE(client->good());
  EXPECT_FALSE(client->replaySafe());

  auto streamId = client->createBidirectionalStream().value();
  auto data = IOBuf::copyBuffer("hello");
  auto expected = std::shared_ptr<IOBuf>(IOBuf::copyBuffer("echo "));
  expected->prependChain(data->clone());
  EXPECT_CALL(clientConnCallback, onReplaySafe());
  sendRequestAndResponseAndWait(*expected, data->clone(), streamId, &readCb);
  if (getVersion() == QuicVersion::MVFST) {
    EXPECT_TRUE(client->getConn().zeroRttWriteCipher);
  } else {
    EXPECT_FALSE(client->getConn().zeroRttWriteCipher);
  }
}

TEST_P(QuicClientTransportIntegrationTest, TestZeroRttRejection) {
  expectTransportCallbacks();
  auto cachedPsk = setupZeroRttOnClientCtx(*clientCtx, hostname, getVersion());
  pskCache_->putPsk(hostname, cachedPsk);
  // Change the ctx
  server_->setFizzContext(serverCtx);
  EXPECT_CALL(clientConnCallback, validateEarlyDataAppParams(_, _))
      .WillOnce(Return(true));
  client->start(&clientConnCallback);
  CHECK(client->getConn().zeroRttWriteCipher);
  EXPECT_TRUE(client->serverInitialParamsSet());
  EXPECT_EQ(
      client->peerAdvertisedInitialMaxData(), kDefaultConnectionWindowSize);
  EXPECT_EQ(
      client->peerAdvertisedInitialMaxStreamDataBidiLocal(),
      kDefaultStreamWindowSize);
  EXPECT_EQ(
      client->peerAdvertisedInitialMaxStreamDataBidiRemote(),
      kDefaultStreamWindowSize);
  EXPECT_EQ(
      client->peerAdvertisedInitialMaxStreamDataUni(),
      kDefaultStreamWindowSize);
  client->serverInitialParamsSet() = false;

  EXPECT_CALL(clientConnCallback, onTransportReady()).WillOnce(Invoke([&] {
    ASSERT_EQ(client->getAppProtocol(), "h1q-fb");
    CHECK(client->getConn().zeroRttWriteCipher);
    eventbase_.terminateLoopSoon();
  }));
  eventbase_.loopForever();

  EXPECT_TRUE(client->getConn().zeroRttWriteCipher);
  EXPECT_TRUE(client->good());
  EXPECT_FALSE(client->replaySafe());

  auto streamId = client->createBidirectionalStream().value();
  auto data = IOBuf::copyBuffer("hello");
  auto expected = std::shared_ptr<IOBuf>(IOBuf::copyBuffer("echo "));
  expected->prependChain(data->clone());
  sendRequestAndResponseAndWait(*expected, data->clone(), streamId, &readCb);
  // Rejection means that we will unset the zero rtt cipher.
  EXPECT_EQ(client->getConn().zeroRttWriteCipher, nullptr);
  EXPECT_TRUE(client->serverInitialParamsSet());
  EXPECT_EQ(
      client->peerAdvertisedInitialMaxData(), kDefaultConnectionWindowSize);
  EXPECT_EQ(
      client->peerAdvertisedInitialMaxStreamDataBidiLocal(),
      kDefaultStreamWindowSize);
  EXPECT_EQ(
      client->peerAdvertisedInitialMaxStreamDataBidiRemote(),
      kDefaultStreamWindowSize);
  EXPECT_EQ(
      client->peerAdvertisedInitialMaxStreamDataUni(),
      kDefaultStreamWindowSize);
}

TEST_P(QuicClientTransportIntegrationTest, TestZeroRttVersionDoesNotMatch) {
  expectTransportCallbacks();
  auto cachedPsk = setupZeroRttOnClientCtx(*clientCtx, hostname, getVersion());
  pskCache_->putPsk(hostname, cachedPsk);
  // Change the ctx
  server_->setFizzContext(serverCtx);
  // This needs to be a version that's not in getVersion() but in server's
  // supported version list.
  client->getNonConstConn().originalVersion = MVFST1;
  EXPECT_CALL(clientConnCallback, validateEarlyDataAppParams(_, _)).Times(0);
  client->start(&clientConnCallback);
  EXPECT_EQ(client->getConn().zeroRttWriteCipher, nullptr);
  EXPECT_FALSE(client->serverInitialParamsSet());

  EXPECT_CALL(clientConnCallback, onTransportReady()).WillOnce(Invoke([&] {
    EXPECT_FALSE(client->getConn().zeroRttWriteCipher);
    CHECK(client->getConn().oneRttWriteCipher);
    eventbase_.terminateLoopSoon();
  }));
  eventbase_.loopForever();

  auto streamId = client->createBidirectionalStream().value();
  auto data = IOBuf::copyBuffer("hello");
  auto expected = std::shared_ptr<IOBuf>(IOBuf::copyBuffer("echo "));
  expected->prependChain(data->clone());
  sendRequestAndResponseAndWait(*expected, data->clone(), streamId, &readCb);
  EXPECT_TRUE(client->serverInitialParamsSet());
  EXPECT_EQ(
      client->peerAdvertisedInitialMaxData(), kDefaultConnectionWindowSize);
  EXPECT_EQ(
      client->peerAdvertisedInitialMaxStreamDataBidiLocal(),
      kDefaultStreamWindowSize);
  EXPECT_EQ(
      client->peerAdvertisedInitialMaxStreamDataBidiRemote(),
      kDefaultStreamWindowSize);
  EXPECT_EQ(
      client->peerAdvertisedInitialMaxStreamDataUni(),
      kDefaultStreamWindowSize);
}

TEST_P(QuicClientTransportIntegrationTest, TestZeroRttNotAttempted) {
  expectTransportCallbacks();
  auto cachedPsk = setupZeroRttOnClientCtx(*clientCtx, hostname, getVersion());
  pskCache_->putPsk(hostname, cachedPsk);
  // Change the ctx
  server_->setFizzContext(serverCtx);
  client->getNonConstConn().transportSettings.attemptEarlyData = false;
  EXPECT_CALL(clientConnCallback, validateEarlyDataAppParams(_, _)).Times(0);
  client->start(&clientConnCallback);

  EXPECT_CALL(clientConnCallback, onTransportReady()).WillOnce(Invoke([&] {
    EXPECT_FALSE(client->getConn().zeroRttWriteCipher);
    CHECK(client->getConn().oneRttWriteCipher);
    eventbase_.terminateLoopSoon();
  }));
  eventbase_.loopForever();

  auto streamId = client->createBidirectionalStream().value();
  auto data = IOBuf::copyBuffer("hello");
  auto expected = std::shared_ptr<IOBuf>(IOBuf::copyBuffer("echo "));
  expected->prependChain(data->clone());
  sendRequestAndResponseAndWait(*expected, data->clone(), streamId, &readCb);
  EXPECT_TRUE(client->serverInitialParamsSet());
  EXPECT_EQ(
      client->peerAdvertisedInitialMaxData(), kDefaultConnectionWindowSize);
  EXPECT_EQ(
      client->peerAdvertisedInitialMaxStreamDataBidiLocal(),
      kDefaultStreamWindowSize);
  EXPECT_EQ(
      client->peerAdvertisedInitialMaxStreamDataBidiRemote(),
      kDefaultStreamWindowSize);
  EXPECT_EQ(
      client->peerAdvertisedInitialMaxStreamDataUni(),
      kDefaultStreamWindowSize);
}

TEST_P(QuicClientTransportIntegrationTest, TestZeroRttInvalidAppParams) {
  expectTransportCallbacks();
  auto cachedPsk = setupZeroRttOnClientCtx(*clientCtx, hostname, getVersion());
  pskCache_->putPsk(hostname, cachedPsk);
  // Change the ctx
  server_->setFizzContext(serverCtx);
  EXPECT_CALL(clientConnCallback, validateEarlyDataAppParams(_, _))
      .WillOnce(Return(false));
  client->start(&clientConnCallback);

  EXPECT_CALL(clientConnCallback, onTransportReady()).WillOnce(Invoke([&] {
    EXPECT_FALSE(client->getConn().zeroRttWriteCipher);
    CHECK(client->getConn().oneRttWriteCipher);
    eventbase_.terminateLoopSoon();
  }));
  eventbase_.loopForever();

  auto streamId = client->createBidirectionalStream().value();
  auto data = IOBuf::copyBuffer("hello");
  auto expected = std::shared_ptr<IOBuf>(IOBuf::copyBuffer("echo "));
  expected->prependChain(data->clone());
  sendRequestAndResponseAndWait(*expected, data->clone(), streamId, &readCb);
  EXPECT_TRUE(client->serverInitialParamsSet());
  EXPECT_EQ(
      client->peerAdvertisedInitialMaxData(), kDefaultConnectionWindowSize);
  EXPECT_EQ(
      client->peerAdvertisedInitialMaxStreamDataBidiLocal(),
      kDefaultStreamWindowSize);
  EXPECT_EQ(
      client->peerAdvertisedInitialMaxStreamDataBidiRemote(),
      kDefaultStreamWindowSize);
  EXPECT_EQ(
      client->peerAdvertisedInitialMaxStreamDataUni(),
      kDefaultStreamWindowSize);
}

TEST_P(QuicClientTransportIntegrationTest, ChangeEventBase) {
  MockReadCallback readCb2;
  folly::ScopedEventBaseThread newEvb;
  expectTransportCallbacks();
  client->start(&clientConnCallback);

  EXPECT_CALL(clientConnCallback, onTransportReady()).WillOnce(Invoke([&] {
    CHECK(client->getConn().oneRttWriteCipher);
    eventbase_.terminateLoopSoon();
  }));
  eventbase_.loopForever();

  auto streamId = client->createBidirectionalStream().value();
  auto data = IOBuf::copyBuffer("hello");
  auto expected = std::shared_ptr<IOBuf>(IOBuf::copyBuffer("echo "));
  expected->prependChain(data->clone());
  sendRequestAndResponseAndWait(*expected, data->clone(), streamId, &readCb);
  EXPECT_TRUE(client->isDetachable());
  client->detachEventBase();
  folly::Baton<> baton;
  bool responseRecvd = false;
  VLOG(10) << "changing threads";
  newEvb.getEventBase()->runInEventBaseThreadAndWait([&] {
    client->attachEventBase(newEvb.getEventBase());
    auto streamId2 = client->createBidirectionalStream().value();
    sendRequestAndResponse(data->clone(), streamId2, &readCb2)
        .thenValue([&](StreamPair buf) {
          responseRecvd = true;
          EXPECT_TRUE(folly::IOBufEqualTo()(*buf.first, *expected));
        })
        .ensure([&] { baton.post(); });
  });
  baton.wait();
  EXPECT_TRUE(responseRecvd);
}

TEST_P(QuicClientTransportIntegrationTest, ResetClient) {
  expectTransportCallbacks();
  auto server2 = createServer(ProcessId::ONE);
  SCOPE_EXIT {
    server2->shutdown();
    server2 = nullptr;
  };

  client->start(&clientConnCallback);

  EXPECT_CALL(clientConnCallback, onTransportReady()).WillOnce(Invoke([&] {
    CHECK(client->getConn().oneRttWriteCipher);
    eventbase_.terminateLoopSoon();
  }));
  eventbase_.loopForever();

  auto streamId = client->createBidirectionalStream().value();
  auto data = IOBuf::copyBuffer("hello");
  auto expected = std::shared_ptr<IOBuf>(IOBuf::copyBuffer("echo "));
  expected->prependChain(data->clone());
  sendRequestAndResponseAndWait(*expected, data->clone(), streamId, &readCb);

  // change the address to a new server which does not have the connection.
  auto server2Addr = server2->getAddress();
  client->getNonConstConn().peerAddress = server2Addr;

  MockReadCallback readCb2;
  bool resetRecvd = false;
  auto streamId2 = client->createBidirectionalStream().value();
  auto f2 = sendRequestAndResponse(data->clone(), streamId2, &readCb2)
                .thenValue([&](StreamPair) { resetRecvd = false; })
                .thenError(
                    folly::tag_t<std::runtime_error>{},
                    [&](const std::runtime_error& e) {
                      LOG(INFO) << e.what();
                      resetRecvd = true;
                    })
                .ensure([&] { eventbase_.terminateLoopSoon(); });
  eventbase_.loopForever();
  std::move(f2).get(5s);
  EXPECT_TRUE(resetRecvd);
}

TEST_P(QuicClientTransportIntegrationTest, TestStatelessResetToken) {
  folly::Optional<StatelessResetToken> token1, token2;

  expectTransportCallbacks();
  auto server2 = createServer(ProcessId::ONE);
  SCOPE_EXIT {
    server2->shutdown();
    server2 = nullptr;
  };

  client->start(&clientConnCallback);

  EXPECT_CALL(clientConnCallback, onTransportReady()).WillOnce(Invoke([&] {
    token1 = client->getConn().statelessResetToken;
    eventbase_.terminateLoopSoon();
  }));
  eventbase_.loopForever();

  auto streamId = client->createBidirectionalStream().value();
  auto data = IOBuf::copyBuffer("hello");
  auto expected = std::shared_ptr<IOBuf>(IOBuf::copyBuffer("echo "));
  expected->prependChain(data->clone());
  sendRequestAndResponseAndWait(*expected, data->clone(), streamId, &readCb);

  // change the address to a new server which does not have the connection.
  auto server2Addr = server2->getAddress();
  client->getNonConstConn().peerAddress = server2Addr;

  MockReadCallback readCb2;
  bool resetRecvd = false;
  auto streamId2 = client->createBidirectionalStream().value();
  sendRequestAndResponse(data->clone(), streamId2, &readCb2)
      .thenValue([&](StreamPair) { resetRecvd = false; })
      .thenError(
          folly::tag_t<std::runtime_error>{},
          [&](const std::runtime_error& e) {
            LOG(INFO) << e.what();
            resetRecvd = true;
            token2 = client->getConn().statelessResetToken;
          })
      .ensure([&] { eventbase_.terminateLoopSoon(); });
  eventbase_.loopForever();

  EXPECT_TRUE(resetRecvd);
  EXPECT_TRUE(token1.hasValue());
  EXPECT_TRUE(token2.hasValue());
  EXPECT_EQ(token1.value(), token2.value());
}

TEST_P(QuicClientTransportIntegrationTest, PartialReliabilityDisabledTest) {
  expectTransportCallbacks();
  TransportSettings settings;
  settings.connectUDP = true;
  settings.partialReliabilityEnabled = false;
  client->setTransportSettings(settings);

  TransportSettings serverSettings;
  serverSettings.partialReliabilityEnabled = false;
  serverSettings.statelessResetTokenSecret = getRandSecret();
  server_->setTransportSettings(serverSettings);

  client->start(&clientConnCallback);

  EXPECT_CALL(clientConnCallback, onTransportReady()).WillOnce(Invoke([&] {
    CHECK(client->getConn().oneRttWriteCipher);
    eventbase_.terminateLoopSoon();
  }));
  eventbase_.loopForever();

  auto streamId = client->createBidirectionalStream().value();
  auto data = IOBuf::copyBuffer("hello");
  auto expected = std::shared_ptr<IOBuf>(IOBuf::copyBuffer("echo "));
  expected->prependChain(data->clone());
  sendRequestAndResponseAndWait(*expected, data->clone(), streamId, &readCb);
  EXPECT_FALSE(client->isPartiallyReliableTransport());
}

TEST_P(QuicClientTransportIntegrationTest, PartialReliabilityDisabledTest2) {
  expectTransportCallbacks();
  TransportSettings settings;
  settings.connectUDP = true;
  settings.partialReliabilityEnabled = true;
  client->setTransportSettings(settings);

  TransportSettings serverSettings;
  serverSettings.partialReliabilityEnabled = false;
  serverSettings.statelessResetTokenSecret = getRandSecret();
  server_->setTransportSettings(serverSettings);

  client->start(&clientConnCallback);

  EXPECT_CALL(clientConnCallback, onTransportReady()).WillOnce(Invoke([&] {
    CHECK(client->getConn().oneRttWriteCipher);
    eventbase_.terminateLoopSoon();
  }));
  eventbase_.loopForever();

  auto streamId = client->createBidirectionalStream().value();
  auto data = IOBuf::copyBuffer("hello");
  auto expected = std::shared_ptr<IOBuf>(IOBuf::copyBuffer("echo "));
  expected->prependChain(data->clone());
  sendRequestAndResponseAndWait(*expected, data->clone(), streamId, &readCb);
  EXPECT_FALSE(client->isPartiallyReliableTransport());
}

TEST_P(QuicClientTransportIntegrationTest, PartialReliabilityDisabledTest3) {
  expectTransportCallbacks();
  TransportSettings settings;
  settings.connectUDP = true;
  settings.partialReliabilityEnabled = false;
  client->setTransportSettings(settings);

  TransportSettings serverSettings;
  serverSettings.partialReliabilityEnabled = true;
  serverSettings.statelessResetTokenSecret = getRandSecret();
  server_->setTransportSettings(serverSettings);

  client->start(&clientConnCallback);

  EXPECT_CALL(clientConnCallback, onTransportReady()).WillOnce(Invoke([&] {
    CHECK(client->getConn().oneRttWriteCipher);
    eventbase_.terminateLoopSoon();
  }));
  eventbase_.loopForever();

  auto streamId = client->createBidirectionalStream().value();
  auto data = IOBuf::copyBuffer("hello");
  auto expected = std::shared_ptr<IOBuf>(IOBuf::copyBuffer("echo "));
  expected->prependChain(data->clone());
  sendRequestAndResponseAndWait(*expected, data->clone(), streamId, &readCb);
  EXPECT_FALSE(client->isPartiallyReliableTransport());
}

TEST_P(QuicClientTransportIntegrationTest, PartialReliabilityEnabledTest) {
  expectTransportCallbacks();
  TransportSettings settings;
  settings.connectUDP = true;
  settings.partialReliabilityEnabled = true;
  client->setTransportSettings(settings);

  TransportSettings serverSettings;
  serverSettings.partialReliabilityEnabled = true;
  serverSettings.statelessResetTokenSecret = getRandSecret();
  server_->setTransportSettings(serverSettings);

  client->start(&clientConnCallback);

  EXPECT_CALL(clientConnCallback, onTransportReady()).WillOnce(Invoke([&] {
    CHECK(client->getConn().oneRttWriteCipher);
    eventbase_.terminateLoopSoon();
  }));
  eventbase_.loopForever();

  auto streamId = client->createBidirectionalStream().value();
  auto data = IOBuf::copyBuffer("hello");
  auto expected = std::shared_ptr<IOBuf>(IOBuf::copyBuffer("echo "));
  expected->prependChain(data->clone());
  sendRequestAndResponseAndWait(*expected, data->clone(), streamId, &readCb);
  EXPECT_TRUE(client->isPartiallyReliableTransport());
}

INSTANTIATE_TEST_CASE_P(
    QuicClientTransportIntegrationTests,
    QuicClientTransportIntegrationTest,
    ::testing::Values(QuicVersion::MVFST, QuicVersion::QUIC_DRAFT));

// Simulates a simple 1rtt handshake without needing to get any handshake bytes
// from the server.
class FakeOneRttHandshakeLayer : public ClientHandshake {
 public:
  explicit FakeOneRttHandshakeLayer(QuicCryptoState& cryptoState)
      : ClientHandshake(cryptoState) {}

  void connect(
      std::shared_ptr<const fizz::client::FizzClientContext>,
      std::shared_ptr<const fizz::CertificateVerifier>,
      folly::Optional<std::string>,
      folly::Optional<fizz::client::CachedPsk>,
      const std::shared_ptr<ClientTransportParametersExtension>&,
      HandshakeCallback* callback) override {
    connected_ = true;
    writeDataToQuicStream(
        cryptoState_.initialStream, IOBuf::copyBuffer("CHLO"));
    createServerTransportParameters();
    callback_ = callback;
  }

  void createServerTransportParameters() {
    TransportParameter maxStreamDataBidiLocal = encodeIntegerParameter(
        TransportParameterId::initial_max_stream_data_bidi_local,
        maxInitialStreamData);
    TransportParameter maxStreamDataBidiRemote = encodeIntegerParameter(
        TransportParameterId::initial_max_stream_data_bidi_remote,
        maxInitialStreamData);
    TransportParameter maxStreamDataUni = encodeIntegerParameter(
        TransportParameterId::initial_max_stream_data_uni,
        maxInitialStreamData);
    TransportParameter maxStreamsBidi = encodeIntegerParameter(
        TransportParameterId::initial_max_streams_bidi, maxInitialStreamsBidi);
    TransportParameter maxStreamsUni = encodeIntegerParameter(
        TransportParameterId::initial_max_streams_uni, maxInitialStreamsUni);
    TransportParameter maxData = encodeIntegerParameter(
        TransportParameterId::initial_max_data, connWindowSize);
    std::vector<TransportParameter> parameters;
    parameters.push_back(std::move(maxStreamDataBidiLocal));
    parameters.push_back(std::move(maxStreamDataBidiRemote));
    parameters.push_back(std::move(maxStreamDataUni));
    parameters.push_back(std::move(maxStreamsBidi));
    parameters.push_back(std::move(maxStreamsUni));
    parameters.push_back(std::move(maxData));
    parameters.push_back(encodeIntegerParameter(
        TransportParameterId::idle_timeout, kDefaultIdleTimeout.count()));
    parameters.push_back(encodeIntegerParameter(
        TransportParameterId::max_packet_size, maxRecvPacketSize));
    ServerTransportParameters params;
    params.negotiated_version = negotiatedVersion;
    params.supported_versions = {QuicVersion::MVFST, QuicVersion::QUIC_DRAFT};

    StatelessResetToken testStatelessResetToken = generateStatelessResetToken();
    TransportParameter statelessReset;
    statelessReset.parameter = TransportParameterId::stateless_reset_token;
    statelessReset.value = folly::IOBuf::copyBuffer(testStatelessResetToken);
    parameters.push_back(std::move(statelessReset));

    params.parameters = std::move(parameters);
    params_ = std::move(params);
  }

  void setOneRttWriteCipher(std::unique_ptr<fizz::Aead> oneRttWriteCipher) {
    oneRttWriteCipher_ = std::move(oneRttWriteCipher);
  }

  void setOneRttReadCipher(std::unique_ptr<fizz::Aead> oneRttReadCipher) {
    oneRttReadCipher_ = std::move(oneRttReadCipher);
  }

  void setHandshakeReadCipher(std::unique_ptr<fizz::Aead> handshakeReadCipher) {
    handshakeReadCipher_ = std::move(handshakeReadCipher);
  }

  void setHandshakeWriteCipher(
      std::unique_ptr<fizz::Aead> handshakeWriteCipher) {
    handshakeWriteCipher_ = std::move(handshakeWriteCipher);
  }

  void setZeroRttWriteCipher(std::unique_ptr<fizz::Aead> zeroRttWriteCipher) {
    zeroRttWriteCipher_ = std::move(zeroRttWriteCipher);
  }

  void setZeroRttWriteHeaderCipher(
      std::unique_ptr<PacketNumberCipher> zeroRttWriteHeaderCipher) {
    zeroRttWriteHeaderCipher_ = std::move(zeroRttWriteHeaderCipher);
  }

  void setHandshakeReadHeaderCipher(
      std::unique_ptr<PacketNumberCipher> handshakeReadHeaderCipher) {
    handshakeReadHeaderCipher_ = std::move(handshakeReadHeaderCipher);
  }

  void setHandshakeWriteHeaderCipher(
      std::unique_ptr<PacketNumberCipher> handshakeWriteHeaderCipher) {
    handshakeWriteHeaderCipher_ = std::move(handshakeWriteHeaderCipher);
  }

  void setOneRttWriteHeaderCipher(
      std::unique_ptr<PacketNumberCipher> oneRttWriteHeaderCipher) {
    oneRttWriteHeaderCipher_ = std::move(oneRttWriteHeaderCipher);
  }

  void setOneRttReadHeaderCipher(
      std::unique_ptr<PacketNumberCipher> oneRttReadHeaderCipher) {
    oneRttReadHeaderCipher_ = std::move(oneRttReadHeaderCipher);
  }

  void setZeroRttRejected() {
    zeroRttRejected_ = true;
    createServerTransportParameters();
  }

  void doHandshake(std::unique_ptr<folly::IOBuf>, fizz::EncryptionLevel)
      override {
    EXPECT_EQ(writeBuf.get(), nullptr);
    if (getPhase() == Phase::Initial) {
      writeDataToQuicStream(
          cryptoState_.handshakeStream, IOBuf::copyBuffer("ClientFinished"));
      phase_ = Phase::Handshake;
    }
  }

  void setPhase(Phase phase) {
    phase_ = phase;
  }

  bool connectInvoked() {
    return connected_;
  }

  folly::Optional<ServerTransportParameters> getServerTransportParams()
      override {
    return std::move(params_);
  }

  void triggerOnNewCachedPsk() {
    fizz::client::NewCachedPsk psk;
    callback_->onNewCachedPsk(psk);
  }

  std::unique_ptr<folly::IOBuf> writeBuf;

  bool connected_{false};
  QuicVersion negotiatedVersion{QuicVersion::MVFST};
  uint64_t maxRecvPacketSize{2 * 1024};
  uint64_t maxInitialStreamData{kDefaultStreamWindowSize};
  uint64_t connWindowSize{kDefaultConnectionWindowSize};
  uint64_t maxInitialStreamsBidi{std::numeric_limits<uint32_t>::max()};
  uint64_t maxInitialStreamsUni{std::numeric_limits<uint32_t>::max()};
  folly::Optional<ServerTransportParameters> params_;
};

class QuicClientTransportTest : public Test {
 public:
  QuicClientTransportTest() : eventbase_(std::make_unique<folly::EventBase>()) {
    auto socket =
        std::make_unique<folly::test::MockAsyncUDPSocket>(eventbase_.get());
    sock = socket.get();
    client = TestingQuicClientTransport::newClient<TestingQuicClientTransport>(
        eventbase_.get(), std::move(socket));
    destructionCallback = std::make_shared<DestructionCallback>();
    client->setDestructionCallback(destructionCallback);
    client->setSupportedVersions(
        {QuicVersion::MVFST, MVFST1, QuicVersion::QUIC_DRAFT});
    client->setCertificateVerifier(createTestCertificateVerifier());
    connIdAlgo_ = std::make_unique<DefaultConnectionIdAlgo>();
    ON_CALL(*sock, resumeRead(_))
        .WillByDefault(SaveArg<0>(&networkReadCallback));
    ON_CALL(*sock, address()).WillByDefault(ReturnRef(serverAddr));
  }

  virtual void setupCryptoLayer() {
    // Fake that the handshake has already occured and fix the keys.
    mockClientHandshake =
        new FakeOneRttHandshakeLayer(*client->getNonConstConn().cryptoState);
    client->getNonConstConn().clientHandshakeLayer = mockClientHandshake;
    client->getNonConstConn().handshakeLayer.reset(mockClientHandshake);
    handshakeDG = std::make_unique<DelayedDestruction::DestructorGuard>(
        mockClientHandshake);
    setFakeHandshakeCiphers();
    // Allow ignoring path mtu for testing negotiation.
    client->getNonConstConn().transportSettings.canIgnorePathMTU = true;
  }

  virtual void setFakeHandshakeCiphers() {
    auto readAead = test::createNoOpFizzAead();
    auto writeAead = test::createNoOpFizzAead();
    auto handshakeReadAead = test::createNoOpFizzAead();
    auto handshakeWriteAead = test::createNoOpFizzAead();
    mockClientHandshake->setHandshakeReadCipher(std::move(handshakeReadAead));
    mockClientHandshake->setHandshakeWriteCipher(std::move(handshakeWriteAead));
    mockClientHandshake->setOneRttReadCipher(std::move(readAead));
    mockClientHandshake->setOneRttWriteCipher(std::move(writeAead));

    mockClientHandshake->setHandshakeReadHeaderCipher(
        test::createNoOpHeaderCipher());
    mockClientHandshake->setHandshakeWriteHeaderCipher(
        test::createNoOpHeaderCipher());
    mockClientHandshake->setOneRttWriteHeaderCipher(
        test::createNoOpHeaderCipher());
    mockClientHandshake->setOneRttReadHeaderCipher(
        test::createNoOpHeaderCipher());
  }

  virtual void setUpSocketExpectations() {
    EXPECT_CALL(*sock, setReuseAddr(false));
    EXPECT_CALL(*sock, bind(_));
    EXPECT_CALL(*sock, dontFragment(true));
    EXPECT_CALL(*sock, setErrMessageCallback(client.get()));
    EXPECT_CALL(*sock, resumeRead(client.get()));
    EXPECT_CALL(*sock, setErrMessageCallback(nullptr));
    EXPECT_CALL(*sock, write(_, _)).Times(AtLeast(1));
  }

  virtual void start() {
    EXPECT_CALL(clientConnCallback, onTransportReady());
    EXPECT_CALL(clientConnCallback, onReplaySafe());
    setUpSocketExpectations();
    client->start(&clientConnCallback);
    setConnectionIds();
    EXPECT_TRUE(client->idleTimeout().isScheduled());

    EXPECT_EQ(socketWrites.size(), 1);
    EXPECT_TRUE(
        verifyLongHeader(*socketWrites.at(0), LongHeader::Types::Initial));
    socketWrites.clear();
    performFakeHandshake();
    EXPECT_TRUE(
        client->getConn().readCodec->getStatelessResetToken().hasValue());
    EXPECT_TRUE(client->getConn().statelessResetToken.hasValue());
  }

  void setConnectionIds() {
    originalConnId = client->getConn().clientConnectionId;
    ServerConnectionIdParams params(0, 0, 0);
    params.clientConnId = *client->getConn().clientConnectionId;
    serverChosenConnId = connIdAlgo_->encodeConnectionId(params);
  }

  void recvServerHello(const folly::SocketAddress& addr) {
    auto serverHello = IOBuf::copyBuffer("Fake SHLO");
    PacketNum nextPacketNum = initialPacketNum++;
    auto& aead = getInitialCipher();
    auto packet = packetToBufCleartext(
        createCryptoPacket(
            *serverChosenConnId,
            *originalConnId,
            nextPacketNum,
            version,
            ProtectionType::Initial,
            *serverHello,
            aead,
            0 /* largestAcked */),
        aead,
        getInitialHeaderCipher(),
        nextPacketNum);
    deliverData(addr, packet->coalesce());
  }

  void recvServerHello() {
    recvServerHello(serverAddr);
  }

  void recvTicket(folly::Optional<uint64_t> offsetOverride = folly::none) {
    auto negotiatedVersion = *client->getConn().version;
    auto ticket = IOBuf::copyBuffer("NST");
    auto packet = packetToBuf(createCryptoPacket(
        *serverChosenConnId,
        *originalConnId,
        appDataPacketNum++,
        negotiatedVersion,
        ProtectionType::KeyPhaseZero,
        *ticket,
        *createNoOpAead(),
        0 /* largestAcked */,
        offsetOverride
            ? *offsetOverride
            : client->getConn().cryptoState->oneRttStream.currentReadOffset));
    deliverData(packet->coalesce());
  }

  void performFakeHandshake(const folly::SocketAddress& addr) {
    // Create a fake server response to trigger fetching keys.
    recvServerHello(addr);
    assertWritten(false, LongHeader::Types::Handshake);

    verifyTransportParameters(
        kDefaultConnectionWindowSize,
        kDefaultStreamWindowSize,
        kDefaultIdleTimeout,
        kDefaultAckDelayExponent,
        mockClientHandshake->maxRecvPacketSize);
    verifyCiphers();
    socketWrites.clear();
  }

  void performFakeHandshake() {
    performFakeHandshake(serverAddr);
  }

  void verifyTransportParameters(
      uint64_t connFlowControl,
      uint64_t initialStreamFlowControl,
      std::chrono::milliseconds idleTimeout,
      uint64_t ackDelayExponent,
      uint64_t maxPacketSize) {
    EXPECT_EQ(
        client->getConn().flowControlState.peerAdvertisedMaxOffset,
        connFlowControl);
    EXPECT_EQ(
        client->getConn()
            .flowControlState.peerAdvertisedInitialMaxStreamOffsetBidiLocal,
        initialStreamFlowControl);
    EXPECT_EQ(
        client->getConn()
            .flowControlState.peerAdvertisedInitialMaxStreamOffsetBidiRemote,
        initialStreamFlowControl);

    EXPECT_EQ(
        client->getConn()
            .flowControlState.peerAdvertisedInitialMaxStreamOffsetUni,
        initialStreamFlowControl);
    EXPECT_EQ(client->getConn().peerIdleTimeout.count(), idleTimeout.count());
    EXPECT_EQ(client->getConn().peerAckDelayExponent, ackDelayExponent);
    EXPECT_EQ(client->getConn().udpSendPacketLen, maxPacketSize);
  }

  void verifyCiphers() {
    EXPECT_NE(client->getConn().oneRttWriteCipher, nullptr);
    EXPECT_NE(client->getConn().handshakeWriteCipher, nullptr);
    EXPECT_NE(client->getConn().handshakeWriteHeaderCipher, nullptr);
    EXPECT_NE(client->getConn().oneRttWriteHeaderCipher, nullptr);

    EXPECT_NE(client->getConn().readCodec->getHandshakeHeaderCipher(), nullptr);
    EXPECT_NE(client->getConn().readCodec->getOneRttHeaderCipher(), nullptr);
  }

  void deliverDataWithoutErrorCheck(
      const folly::SocketAddress& addr,
      folly::ByteRange data,
      bool writes = true) {
    ASSERT_TRUE(networkReadCallback);
    uint8_t* buf = nullptr;
    size_t len = 0;
    networkReadCallback->getReadBuffer((void**)&buf, &len);
    ASSERT_GT(len, data.size());
    memcpy(buf, data.data(), data.size());
    networkReadCallback->onDataAvailable(addr, data.size(), false);
    if (writes) {
      loopForWrites();
    }
  }

  void deliverDataWithoutErrorCheck(folly::ByteRange data, bool writes = true) {
    deliverDataWithoutErrorCheck(serverAddr, std::move(data), writes);
  }

  void deliverData(
      const folly::SocketAddress& addr,
      folly::ByteRange data,
      bool writes = true) {
    deliverDataWithoutErrorCheck(addr, std::move(data), writes);
    if (client->getConn().localConnectionError) {
      bool idleTimeout = false;
      folly::variant_match(
          client->getConn().localConnectionError->first,
          [&](const LocalErrorCode& err) {
            idleTimeout = (err == LocalErrorCode::IDLE_TIMEOUT);
          },
          [&](const auto&) {});
      if (!idleTimeout) {
        throw std::runtime_error(
            toString(client->getConn().localConnectionError->first));
      }
    }
  }

  void deliverData(folly::ByteRange data, bool writes = true) {
    deliverData(serverAddr, std::move(data), writes);
  }

  void loopForWrites() {
    // Loop the evb once to give writes some time to do their thing.
    eventbase_->loopOnce(EVLOOP_NONBLOCK);
  }

  void assertWritten(
      bool shortHeader,
      folly::Optional<LongHeader::Types> longHeader) {
    size_t numShort = 0;
    size_t numLong = 0;
    size_t numOthers = 0;
    if (!socketWrites.empty()) {
      auto& write = socketWrites.back();
      if (shortHeader && verifyShortHeader(*write)) {
        numShort++;
      } else if (longHeader && verifyLongHeader(*write, *longHeader)) {
        numLong++;
      } else {
        numOthers++;
      }
    }
    if (shortHeader) {
      EXPECT_GT(numShort, 0);
    }
    if (longHeader) {
      EXPECT_GT(numLong, 0);
    }
    EXPECT_EQ(numOthers, 0);
  }

  RegularQuicPacket* parseRegularQuicPacket(CodecResult& codecResult) {
    auto parsedPacket = boost::get<QuicPacket>(&codecResult);
    if (!parsedPacket) {
      return nullptr;
    }
    return boost::get<RegularQuicPacket>(parsedPacket);
  }

  void verifyShortPackets(IntervalSet<PacketNum>& sentPackets) {
    AckStates ackStates;
    for (auto& write : socketWrites) {
      auto packetQueue = bufToQueue(write->clone());
      auto codecResult =
          makeEncryptedCodec(true)->parsePacket(packetQueue, ackStates);
      auto parsedPacket = parseRegularQuicPacket(codecResult);
      if (!parsedPacket) {
        continue;
      }
      PacketNum packetNumSent = folly::variant_match(
          parsedPacket->header,
          [](auto& h) { return h.getPacketSequenceNum(); });
      sentPackets.insert(packetNumSent);
      verifyShortHeader(*write);
    }
  }

  bool verifyLongHeader(
      folly::IOBuf& buf,
      typename LongHeader::Types headerType) {
    AckStates ackStates;
    auto packetQueue = bufToQueue(buf.clone());
    auto codecResult =
        makeEncryptedCodec(true)->parsePacket(packetQueue, ackStates);
    auto parsedPacket = parseRegularQuicPacket(codecResult);
    if (!parsedPacket) {
      return false;
    }
    auto longHeader = boost::get<LongHeader>(&parsedPacket->header);
    return longHeader && longHeader->getHeaderType() == headerType;
  }

  bool verifyShortHeader(folly::IOBuf& buf) {
    AckStates ackStates;
    auto packetQueue = bufToQueue(buf.clone());
    auto codecResult =
        makeEncryptedCodec(true)->parsePacket(packetQueue, ackStates);
    auto parsedPacket = parseRegularQuicPacket(codecResult);
    if (!parsedPacket) {
      return false;
    }
    return boost::get<ShortHeader>(&parsedPacket->header) != nullptr;
  }

  std::unique_ptr<QuicReadCodec> makeHandshakeCodec() {
    QuicFizzFactory fizzFactory;
    auto codec = std::make_unique<QuicReadCodec>(QuicNodeType::Server);
    codec->setClientConnectionId(*originalConnId);
    codec->setInitialReadCipher(getClientInitialCipher(
        &fizzFactory, *client->getConn().initialDestinationConnectionId));
    codec->setInitialHeaderCipher(makeClientInitialHeaderCipher(
        &fizzFactory, *client->getConn().initialDestinationConnectionId));
    codec->setHandshakeReadCipher(test::createNoOpAead());
    codec->setHandshakeHeaderCipher(test::createNoOpHeaderCipher());
    return codec;
  }

  std::unique_ptr<QuicReadCodec> makeEncryptedCodec(
      bool handshakeCipher = false) {
    QuicFizzFactory fizzFactory;
    auto codec = std::make_unique<QuicReadCodec>(QuicNodeType::Server);
    std::unique_ptr<Aead> handshakeReadCipher;
    codec->setClientConnectionId(*originalConnId);
    codec->setOneRttReadCipher(test::createNoOpAead());
    codec->setOneRttHeaderCipher(test::createNoOpHeaderCipher());
    codec->setZeroRttReadCipher(test::createNoOpAead());
    codec->setZeroRttHeaderCipher(test::createNoOpHeaderCipher());
    if (handshakeCipher) {
      codec->setInitialReadCipher(getClientInitialCipher(
          &fizzFactory, *client->getConn().initialDestinationConnectionId));
      codec->setInitialHeaderCipher(makeClientInitialHeaderCipher(
          &fizzFactory, *client->getConn().initialDestinationConnectionId));
      codec->setHandshakeReadCipher(test::createNoOpAead());
      codec->setHandshakeHeaderCipher(test::createNoOpHeaderCipher());
    }
    return codec;
  }

  const Aead& getInitialCipher() {
    return *client->getConn().readCodec->getInitialCipher();
  }

  const PacketNumberCipher& getInitialHeaderCipher() {
    return *client->getConn().readCodec->getInitialHeaderCipher();
  }

 protected:
  std::vector<std::unique_ptr<folly::IOBuf>> socketWrites;
  MockDeliveryCallback deliveryCallback;
  MockReadCallback readCb;
  MockConnectionCallback clientConnCallback;
  folly::test::MockAsyncUDPSocket* sock;
  std::shared_ptr<DestructionCallback> destructionCallback;
  std::unique_ptr<folly::EventBase> eventbase_;
  SocketAddress serverAddr{"127.0.0.1", 443};
  AsyncUDPSocket::ReadCallback* networkReadCallback{nullptr};
  std::unique_ptr<DelayedDestruction::DestructorGuard> handshakeDG;
  FakeOneRttHandshakeLayer* mockClientHandshake;
  std::shared_ptr<TestingQuicClientTransport> client;
  PacketNum initialPacketNum{0}, handshakePacketNum{0}, appDataPacketNum{0};
  std::unique_ptr<ConnectionIdAlgo> connIdAlgo_;
  folly::Optional<ConnectionId> originalConnId;
  folly::Optional<ConnectionId> serverChosenConnId;
  QuicVersion version{QuicVersion::QUIC_DRAFT};
};

TEST_F(QuicClientTransportTest, CustomTransportParam) {
  EXPECT_TRUE(client->setCustomTransportParameter(
      std::make_unique<CustomIntegralTransportParameter>(
          kCustomTransportParameterThreshold, 0)));
  client->closeNow(folly::none);
}

TEST_F(QuicClientTransportTest, CloseSocketOnWriteError) {
  client->addNewPeerAddress(serverAddr);
  EXPECT_CALL(*sock, write(_, _)).WillOnce(SetErrnoAndReturn(EBADF, -1));
  client->start(&clientConnCallback);

  EXPECT_FALSE(client->isClosed());
  EXPECT_CALL(clientConnCallback, onConnectionError(_));
  eventbase_->loopOnce();
  EXPECT_TRUE(client->isClosed());
}

TEST_F(QuicClientTransportTest, AddNewPeerAddressSetsPacketSize) {
  folly::SocketAddress v4Address("0.0.0.0", 0);
  ASSERT_TRUE(v4Address.getFamily() == AF_INET);
  client->addNewPeerAddress(v4Address);
  EXPECT_EQ(kDefaultV4UDPSendPacketLen, client->getConn().udpSendPacketLen);

  folly::SocketAddress v6Address("::", 0);
  ASSERT_TRUE(v6Address.getFamily() == AF_INET6);
  client->addNewPeerAddress(v6Address);
  EXPECT_EQ(kDefaultV6UDPSendPacketLen, client->getConn().udpSendPacketLen);

  client->closeNow(folly::none);
}

TEST_F(QuicClientTransportTest, SocketClosedDuringOnTransportReady) {
  class ConnectionCallbackThatWritesOnTransportReady
      : public QuicSocket::ConnectionCallback {
   public:
    explicit ConnectionCallbackThatWritesOnTransportReady(
        std::shared_ptr<QuicSocket> socket)
        : socket_(std::move(socket)) {}

    void onTransportReady() noexcept override {
      socket_->close(folly::none);
      socket_.reset();
      onTransportReadyMock();
    }

    GMOCK_METHOD1_(, noexcept, , onFlowControlUpdate, void(StreamId));
    GMOCK_METHOD1_(, noexcept, , onNewBidirectionalStream, void(StreamId));
    GMOCK_METHOD1_(, noexcept, , onNewUnidirectionalStream, void(StreamId));
    GMOCK_METHOD2_(
        ,
        noexcept,
        ,
        onStopSending,
        void(StreamId, ApplicationErrorCode));
    GMOCK_METHOD0_(, noexcept, , onTransportReadyMock, void());
    GMOCK_METHOD0_(, noexcept, , onReplaySafe, void());
    GMOCK_METHOD0_(, noexcept, , onConnectionEnd, void());
    GMOCK_METHOD1_(
        ,
        noexcept,
        ,
        onConnectionError,
        void(std::pair<QuicErrorCode, std::string>));

   private:
    std::shared_ptr<QuicSocket> socket_;
  };

  ConnectionCallbackThatWritesOnTransportReady callback(client);
  EXPECT_CALL(callback, onTransportReadyMock());
  EXPECT_CALL(callback, onReplaySafe()).Times(0);
  ON_CALL(*sock, write(_, _))
      .WillByDefault(Invoke(
          [&](const SocketAddress&, const std::unique_ptr<folly::IOBuf>& buf) {
            socketWrites.push_back(buf->clone());
            return buf->computeChainDataLength();
          }));
  ON_CALL(*sock, address()).WillByDefault(ReturnRef(serverAddr));

  client->addNewPeerAddress(serverAddr);
  setupCryptoLayer();
  client->start(&callback);
  setConnectionIds();
  recvServerHello();
}

TEST_F(QuicClientTransportTest, NetworkUnreachableIsFatalToConn) {
  client->addNewPeerAddress(serverAddr);
  setupCryptoLayer();
  EXPECT_CALL(clientConnCallback, onConnectionError(_));
  EXPECT_CALL(*sock, write(_, _)).WillOnce(SetErrnoAndReturn(ENETUNREACH, -1));
  client->start(&clientConnCallback);
  loopForWrites();
}

TEST_F(QuicClientTransportTest, NetworkUnreachableIsNotFatalIfContinue) {
  TransportSettings settings;
  settings.continueOnNetworkUnreachable = true;
  client->setTransportSettings(settings);
  client->addNewPeerAddress(serverAddr);
  EXPECT_CALL(clientConnCallback, onConnectionError(_)).Times(0);
  setupCryptoLayer();
  EXPECT_CALL(*sock, write(_, _)).WillOnce(SetErrnoAndReturn(ENETUNREACH, -1));
  EXPECT_FALSE(client->getConn().continueOnNetworkUnreachableDeadline);
  client->start(&clientConnCallback);
  EXPECT_TRUE(client->getConn().continueOnNetworkUnreachableDeadline);
  ASSERT_FALSE(client->getConn().receivedNewPacketBeforeWrite);
  ASSERT_TRUE(client->idleTimeout().isScheduled());
}

TEST_F(
    QuicClientTransportTest,
    NetworkUnreachableIsFatalIfContinueAfterDeadline) {
  TransportSettings settings;
  settings.continueOnNetworkUnreachable = true;
  client->setTransportSettings(settings);
  client->addNewPeerAddress(serverAddr);
  setupCryptoLayer();
  EXPECT_CALL(*sock, write(_, _))
      .WillRepeatedly(SetErrnoAndReturn(ENETUNREACH, -1));
  EXPECT_FALSE(client->getConn().continueOnNetworkUnreachableDeadline);
  client->start(&clientConnCallback);
  ASSERT_FALSE(client->getConn().receivedNewPacketBeforeWrite);
  ASSERT_TRUE(client->idleTimeout().isScheduled());
  usleep(std::chrono::duration_cast<std::chrono::microseconds>(
             settings.continueOnNetworkUnreachableDuration)
             .count());
  EXPECT_CALL(clientConnCallback, onConnectionError(_));
  loopForWrites();
}

TEST_F(
    QuicClientTransportTest,
    NetworkUnreachableDeadlineIsResetAfterSuccessfulWrite) {
  TransportSettings settings;
  settings.continueOnNetworkUnreachable = true;
  client->setTransportSettings(settings);
  client->addNewPeerAddress(serverAddr);
  EXPECT_CALL(clientConnCallback, onConnectionError(_)).Times(0);
  setupCryptoLayer();
  EXPECT_CALL(*sock, write(_, _))
      .WillOnce(SetErrnoAndReturn(ENETUNREACH, -1))
      .WillOnce(Return(1));
  EXPECT_FALSE(client->getConn().continueOnNetworkUnreachableDeadline);
  client->start(&clientConnCallback);
  EXPECT_TRUE(client->getConn().continueOnNetworkUnreachableDeadline);
  ASSERT_FALSE(client->getConn().receivedNewPacketBeforeWrite);
  ASSERT_TRUE(client->idleTimeout().isScheduled());

  client->lossTimeout().cancelTimeout();
  client->lossTimeout().timeoutExpired();
  EXPECT_FALSE(client->getConn().continueOnNetworkUnreachableDeadline);
}

TEST_F(QuicClientTransportTest, HappyEyeballsWithSingleV4Address) {
  auto& conn = client->getConn();

  client->setHappyEyeballsEnabled(true);

  client->addNewPeerAddress(serverAddr);
  EXPECT_EQ(client->getConn().happyEyeballsState.v4PeerAddress, serverAddr);

  setupCryptoLayer();

  EXPECT_FALSE(conn.happyEyeballsState.finished);
  EXPECT_FALSE(conn.peerAddress.isInitialized());
  client->start(&clientConnCallback);
  EXPECT_FALSE(client->happyEyeballsConnAttemptDelayTimeout().isScheduled());
  EXPECT_TRUE(conn.happyEyeballsState.finished);
  EXPECT_EQ(conn.peerAddress, serverAddr);
}

TEST_F(QuicClientTransportTest, HappyEyeballsWithSingleV6Address) {
  auto& conn = client->getConn();

  client->setHappyEyeballsEnabled(true);

  SocketAddress serverAddrV6{"::1", 443};
  client->addNewPeerAddress(serverAddrV6);
  EXPECT_EQ(client->getConn().happyEyeballsState.v6PeerAddress, serverAddrV6);

  setupCryptoLayer();

  EXPECT_FALSE(conn.happyEyeballsState.finished);
  EXPECT_FALSE(conn.peerAddress.isInitialized());
  client->start(&clientConnCallback);
  EXPECT_FALSE(client->happyEyeballsConnAttemptDelayTimeout().isScheduled());
  EXPECT_TRUE(conn.happyEyeballsState.finished);
  EXPECT_EQ(conn.peerAddress, serverAddrV6);
}

TEST_F(QuicClientTransportTest, IdleTimerResetOnWritingFirstData) {
  client->addNewPeerAddress(serverAddr);
  setupCryptoLayer();
  client->start(&clientConnCallback);
  loopForWrites();
  ASSERT_FALSE(client->getConn().receivedNewPacketBeforeWrite);
  ASSERT_TRUE(client->idleTimeout().isScheduled());
}

class QuicClientTransportHappyEyeballsTest : public QuicClientTransportTest {
 public:
  void SetUp() override {
    auto secondSocket =
        std::make_unique<folly::test::MockAsyncUDPSocket>(eventbase_.get());
    secondSock = secondSocket.get();

    client->setHappyEyeballsEnabled(true);
    client->addNewPeerAddress(serverAddrV4);
    client->addNewPeerAddress(serverAddrV6);
    client->addNewSocket(std::move(secondSocket));

    EXPECT_EQ(client->getConn().happyEyeballsState.v6PeerAddress, serverAddrV6);
    EXPECT_EQ(client->getConn().happyEyeballsState.v4PeerAddress, serverAddrV4);

    setupCryptoLayer();
  }

 protected:
  void firstWinBeforeSecondStart(
      const SocketAddress& firstAddress,
      const SocketAddress& secondAddress) {
    auto& conn = client->getConn();

    EXPECT_CALL(*sock, write(firstAddress, _))
        .Times(AtLeast(1))
        .WillRepeatedly(Invoke([&](const SocketAddress&,
                                   const std::unique_ptr<folly::IOBuf>& buf) {
          socketWrites.push_back(buf->clone());
          return buf->computeChainDataLength();
        }));
    EXPECT_CALL(*secondSock, write(_, _)).Times(0);
    client->start(&clientConnCallback);
    setConnectionIds();

    EXPECT_EQ(conn.peerAddress, firstAddress);
    EXPECT_EQ(conn.happyEyeballsState.secondPeerAddress, secondAddress);
    EXPECT_TRUE(client->happyEyeballsConnAttemptDelayTimeout().isScheduled());
    EXPECT_EQ(socketWrites.size(), 1);
    EXPECT_TRUE(
        verifyLongHeader(*socketWrites.at(0), LongHeader::Types::Initial));

    socketWrites.clear();

    EXPECT_FALSE(conn.happyEyeballsState.finished);
    EXPECT_CALL(clientConnCallback, onTransportReady());
    EXPECT_CALL(clientConnCallback, onReplaySafe());
    EXPECT_CALL(*secondSock, write(_, _)).Times(0);
    EXPECT_CALL(*secondSock, pauseRead());
    EXPECT_CALL(*secondSock, close());
    performFakeHandshake(firstAddress);
    EXPECT_FALSE(client->happyEyeballsConnAttemptDelayTimeout().isScheduled());
    EXPECT_TRUE(conn.happyEyeballsState.finished);
    EXPECT_EQ(conn.originalPeerAddress, firstAddress);
    EXPECT_EQ(conn.peerAddress, firstAddress);
  }

  void firstWinAfterSecondStart(
      const SocketAddress& firstAddress,
      const SocketAddress& secondAddress) {
    auto& conn = client->getConn();

    EXPECT_CALL(*sock, write(firstAddress, _))
        .WillRepeatedly(Invoke([&](const SocketAddress&,
                                   const std::unique_ptr<folly::IOBuf>& buf) {
          socketWrites.push_back(buf->clone());
          return buf->computeChainDataLength();
        }));
    EXPECT_CALL(*secondSock, write(_, _)).Times(0);
    client->start(&clientConnCallback);
    setConnectionIds();

    EXPECT_EQ(conn.peerAddress, firstAddress);
    EXPECT_EQ(conn.happyEyeballsState.secondPeerAddress, secondAddress);
    EXPECT_TRUE(client->happyEyeballsConnAttemptDelayTimeout().isScheduled());
    EXPECT_EQ(socketWrites.size(), 1);
    EXPECT_TRUE(
        verifyLongHeader(*socketWrites.at(0), LongHeader::Types::Initial));

    socketWrites.clear();

    // Manually expire conn attempt timeout
    EXPECT_FALSE(conn.happyEyeballsState.shouldWriteToSecondSocket);
    client->happyEyeballsConnAttemptDelayTimeout().cancelTimeout();
    client->happyEyeballsConnAttemptDelayTimeout().timeoutExpired();
    EXPECT_TRUE(conn.happyEyeballsState.shouldWriteToSecondSocket);
    EXPECT_FALSE(client->happyEyeballsConnAttemptDelayTimeout().isScheduled());

    // Manually expire loss timeout to trigger write to both first and second
    // socket
    EXPECT_CALL(*sock, write(firstAddress, _))
        .WillOnce(Invoke([&](const SocketAddress&,
                             const std::unique_ptr<folly::IOBuf>& buf) {
          socketWrites.push_back(buf->clone());
          return buf->computeChainDataLength();
        }));
    EXPECT_CALL(*secondSock, write(secondAddress, _));
    client->lossTimeout().cancelTimeout();
    client->lossTimeout().timeoutExpired();
    EXPECT_EQ(socketWrites.size(), 1);
    EXPECT_TRUE(
        verifyLongHeader(*socketWrites.at(0), LongHeader::Types::Initial));

    socketWrites.clear();
    EXPECT_FALSE(conn.happyEyeballsState.finished);
    EXPECT_CALL(clientConnCallback, onTransportReady());
    EXPECT_CALL(clientConnCallback, onReplaySafe());
    EXPECT_CALL(*sock, write(firstAddress, _))
        .Times(AtLeast(1))
        .WillRepeatedly(Invoke([&](const SocketAddress&,
                                   const std::unique_ptr<folly::IOBuf>& buf) {
          socketWrites.push_back(buf->clone());
          return buf->computeChainDataLength();
        }));
    EXPECT_CALL(*secondSock, write(_, _)).Times(0);
    EXPECT_CALL(*secondSock, pauseRead());
    EXPECT_CALL(*secondSock, close());
    performFakeHandshake(firstAddress);
    EXPECT_TRUE(conn.happyEyeballsState.finished);
    EXPECT_FALSE(conn.happyEyeballsState.shouldWriteToSecondSocket);
    EXPECT_EQ(conn.originalPeerAddress, firstAddress);
    EXPECT_EQ(conn.peerAddress, firstAddress);
  }

  void secondWin(
      const SocketAddress& firstAddress,
      const SocketAddress& secondAddress) {
    auto& conn = client->getConn();

    EXPECT_CALL(*sock, write(firstAddress, _))
        .WillRepeatedly(Invoke([&](const SocketAddress&,
                                   const std::unique_ptr<folly::IOBuf>& buf) {
          socketWrites.push_back(buf->clone());
          return buf->computeChainDataLength();
        }));
    EXPECT_CALL(*secondSock, write(_, _)).Times(0);
    client->start(&clientConnCallback);
    setConnectionIds();
    EXPECT_EQ(conn.peerAddress, firstAddress);
    EXPECT_EQ(conn.happyEyeballsState.secondPeerAddress, secondAddress);
    EXPECT_TRUE(client->happyEyeballsConnAttemptDelayTimeout().isScheduled());
    EXPECT_EQ(socketWrites.size(), 1);

    EXPECT_TRUE(
        verifyLongHeader(*socketWrites.at(0), LongHeader::Types::Initial));

    socketWrites.clear();

    // Manually expire conn attempt timeout
    EXPECT_FALSE(conn.happyEyeballsState.shouldWriteToSecondSocket);
    client->happyEyeballsConnAttemptDelayTimeout().cancelTimeout();
    client->happyEyeballsConnAttemptDelayTimeout().timeoutExpired();
    EXPECT_TRUE(conn.happyEyeballsState.shouldWriteToSecondSocket);
    EXPECT_FALSE(client->happyEyeballsConnAttemptDelayTimeout().isScheduled());

    // Manually expire loss timeout to trigger write to both first and second
    // socket
    EXPECT_CALL(*sock, write(firstAddress, _));
    EXPECT_CALL(*secondSock, write(secondAddress, _))
        .WillOnce(Invoke([&](const SocketAddress&,
                             const std::unique_ptr<folly::IOBuf>& buf) {
          socketWrites.push_back(buf->clone());
          return buf->computeChainDataLength();
        }));
    client->lossTimeout().cancelTimeout();
    client->lossTimeout().timeoutExpired();
    EXPECT_EQ(socketWrites.size(), 1);
    EXPECT_TRUE(
        verifyLongHeader(*socketWrites.at(0), LongHeader::Types::Initial));

    socketWrites.clear();

    EXPECT_FALSE(conn.happyEyeballsState.finished);
    EXPECT_CALL(clientConnCallback, onTransportReady());
    EXPECT_CALL(clientConnCallback, onReplaySafe());
    EXPECT_CALL(*sock, write(_, _)).Times(0);
    EXPECT_CALL(*sock, pauseRead());
    EXPECT_CALL(*sock, close());
    EXPECT_CALL(*secondSock, write(secondAddress, _))
        .Times(AtLeast(1))
        .WillRepeatedly(Invoke([&](const SocketAddress&,
                                   const std::unique_ptr<folly::IOBuf>& buf) {
          socketWrites.push_back(buf->clone());
          return buf->computeChainDataLength();
        }));
    performFakeHandshake(secondAddress);
    EXPECT_TRUE(conn.happyEyeballsState.finished);
    EXPECT_FALSE(conn.happyEyeballsState.shouldWriteToSecondSocket);
    EXPECT_EQ(conn.originalPeerAddress, secondAddress);
    EXPECT_EQ(conn.peerAddress, secondAddress);
  }

  void secondBindFailure(
      const SocketAddress& firstAddress,
      const SocketAddress& secondAddress) {
    auto& conn = client->getConn();

    EXPECT_CALL(*sock, write(firstAddress, _));
    EXPECT_CALL(*secondSock, bind(_))
        .WillOnce(Invoke(
            [](const folly::SocketAddress&) { throw std::exception(); }));
    client->start(&clientConnCallback);
    EXPECT_EQ(conn.peerAddress, firstAddress);
    EXPECT_EQ(conn.happyEyeballsState.secondPeerAddress, secondAddress);
    EXPECT_FALSE(client->happyEyeballsConnAttemptDelayTimeout().isScheduled());
    EXPECT_FALSE(conn.happyEyeballsState.shouldWriteToSecondSocket);
    EXPECT_TRUE(conn.happyEyeballsState.finished);
  }

  void nonFatalWriteErrorOnFirstBeforeSecondStarts(
      const SocketAddress& firstAddress,
      const SocketAddress& secondAddress) {
    auto& conn = client->getConn();
    TransportSettings settings;
    settings.continueOnNetworkUnreachable = true;
    client->setTransportSettings(settings);
    EXPECT_CALL(*sock, write(firstAddress, _))
        .WillOnce(SetErrnoAndReturn(ENETUNREACH, -1));
    EXPECT_CALL(*secondSock, write(_, _));
    client->start(&clientConnCallback);
    EXPECT_EQ(conn.peerAddress, firstAddress);
    EXPECT_EQ(conn.happyEyeballsState.secondPeerAddress, secondAddress);
    // Continue trying first socket
    EXPECT_TRUE(conn.happyEyeballsState.shouldWriteToFirstSocket);
    EXPECT_TRUE(conn.happyEyeballsState.shouldWriteToSecondSocket);
    EXPECT_FALSE(client->happyEyeballsConnAttemptDelayTimeout().isScheduled());

    EXPECT_CALL(*sock, write(firstAddress, _));
    EXPECT_CALL(*secondSock, write(secondAddress, _));
    client->lossTimeout().cancelTimeout();
    client->lossTimeout().timeoutExpired();
  }

  void fatalWriteErrorOnFirstBeforeSecondStarts(
      const SocketAddress& firstAddress,
      const SocketAddress& secondAddress) {
    auto& conn = client->getConn();
    EXPECT_CALL(*sock, write(firstAddress, _))
        .WillOnce(SetErrnoAndReturn(EBADF, -1));
    // Socket is paused read once during happy eyeballs
    // Socket is paused read for the second time when QuicClientTransport dies
    EXPECT_CALL(*sock, pauseRead()).Times(2);
    EXPECT_CALL(*sock, close()).Times(1);
    EXPECT_CALL(*secondSock, write(_, _));
    client->start(&clientConnCallback);
    EXPECT_EQ(conn.peerAddress, firstAddress);
    EXPECT_EQ(conn.happyEyeballsState.secondPeerAddress, secondAddress);
    // Give up first socket
    EXPECT_FALSE(conn.happyEyeballsState.shouldWriteToFirstSocket);
    EXPECT_TRUE(conn.happyEyeballsState.shouldWriteToSecondSocket);
    EXPECT_FALSE(client->happyEyeballsConnAttemptDelayTimeout().isScheduled());

    EXPECT_CALL(*sock, write(_, _)).Times(0);
    EXPECT_CALL(*secondSock, write(secondAddress, _));
    client->lossTimeout().cancelTimeout();
    client->lossTimeout().timeoutExpired();
  }

  void nonFatalWriteErrorOnFirstAfterSecondStarts(
      const SocketAddress& firstAddress,
      const SocketAddress& secondAddress) {
    auto& conn = client->getConn();

    EXPECT_CALL(*sock, write(firstAddress, _));
    EXPECT_CALL(*secondSock, write(_, _)).Times(0);
    client->start(&clientConnCallback);
    EXPECT_EQ(conn.peerAddress, firstAddress);
    EXPECT_EQ(conn.happyEyeballsState.secondPeerAddress, secondAddress);
    EXPECT_TRUE(client->happyEyeballsConnAttemptDelayTimeout().isScheduled());

    // Manually expire conn attempt timeout
    EXPECT_FALSE(conn.happyEyeballsState.shouldWriteToSecondSocket);
    client->happyEyeballsConnAttemptDelayTimeout().cancelTimeout();
    client->happyEyeballsConnAttemptDelayTimeout().timeoutExpired();
    EXPECT_TRUE(conn.happyEyeballsState.shouldWriteToSecondSocket);
    EXPECT_FALSE(client->happyEyeballsConnAttemptDelayTimeout().isScheduled());

    // Manually expire loss timeout to trigger write to both first and second
    // socket
    EXPECT_CALL(*sock, write(firstAddress, _))
        .WillOnce(SetErrnoAndReturn(EAGAIN, -1));
    EXPECT_CALL(*secondSock, write(secondAddress, _));
    client->lossTimeout().cancelTimeout();
    client->lossTimeout().timeoutExpired();

    EXPECT_TRUE(conn.happyEyeballsState.shouldWriteToFirstSocket);
    EXPECT_TRUE(conn.happyEyeballsState.shouldWriteToSecondSocket);

    EXPECT_CALL(*sock, write(firstAddress, _));
    EXPECT_CALL(*secondSock, write(secondAddress, _));
    client->lossTimeout().cancelTimeout();
    client->lossTimeout().timeoutExpired();
  }

  void fatalWriteErrorOnFirstAfterSecondStarts(
      const SocketAddress& firstAddress,
      const SocketAddress& secondAddress) {
    auto& conn = client->getConn();

    EXPECT_CALL(*sock, write(firstAddress, _));
    EXPECT_CALL(*secondSock, write(_, _)).Times(0);
    client->start(&clientConnCallback);
    EXPECT_EQ(conn.peerAddress, firstAddress);
    EXPECT_EQ(conn.happyEyeballsState.secondPeerAddress, secondAddress);
    EXPECT_TRUE(client->happyEyeballsConnAttemptDelayTimeout().isScheduled());

    // Manually expire conn attempt timeout
    EXPECT_FALSE(conn.happyEyeballsState.shouldWriteToSecondSocket);
    client->happyEyeballsConnAttemptDelayTimeout().cancelTimeout();
    client->happyEyeballsConnAttemptDelayTimeout().timeoutExpired();
    EXPECT_TRUE(conn.happyEyeballsState.shouldWriteToSecondSocket);
    EXPECT_FALSE(client->happyEyeballsConnAttemptDelayTimeout().isScheduled());

    // Manually expire loss timeout to trigger write to both first and second
    // socket
    EXPECT_CALL(*sock, write(firstAddress, _))
        .WillOnce(SetErrnoAndReturn(EBADF, -1));
    // Socket is paused read once during happy eyeballs
    // Socket is paused read for the second time when QuicClientTransport dies
    EXPECT_CALL(*sock, pauseRead()).Times(2);
    EXPECT_CALL(*sock, close()).Times(1);
    EXPECT_CALL(*secondSock, write(secondAddress, _));
    client->lossTimeout().cancelTimeout();
    client->lossTimeout().timeoutExpired();

    EXPECT_FALSE(conn.happyEyeballsState.shouldWriteToFirstSocket);
    EXPECT_TRUE(conn.happyEyeballsState.shouldWriteToSecondSocket);

    EXPECT_CALL(*sock, write(_, _)).Times(0);
    EXPECT_CALL(*secondSock, write(secondAddress, _));
    client->lossTimeout().cancelTimeout();
    client->lossTimeout().timeoutExpired();
  }

  void nonFatalWriteErrorOnSecondAfterSecondStarts(
      const SocketAddress& firstAddress,
      const SocketAddress& secondAddress) {
    auto& conn = client->getConn();

    EXPECT_CALL(*sock, write(firstAddress, _));
    EXPECT_CALL(*secondSock, write(_, _)).Times(0);
    client->start(&clientConnCallback);
    EXPECT_EQ(conn.peerAddress, firstAddress);
    EXPECT_EQ(conn.happyEyeballsState.secondPeerAddress, secondAddress);
    EXPECT_TRUE(client->happyEyeballsConnAttemptDelayTimeout().isScheduled());

    // Manually expire conn attempt timeout
    EXPECT_FALSE(conn.happyEyeballsState.shouldWriteToSecondSocket);
    client->happyEyeballsConnAttemptDelayTimeout().cancelTimeout();
    client->happyEyeballsConnAttemptDelayTimeout().timeoutExpired();
    EXPECT_TRUE(conn.happyEyeballsState.shouldWriteToSecondSocket);
    EXPECT_FALSE(client->happyEyeballsConnAttemptDelayTimeout().isScheduled());

    // Manually expire loss timeout to trigger write to both first and second
    // socket
    EXPECT_CALL(*sock, write(firstAddress, _));
    EXPECT_CALL(*secondSock, write(secondAddress, _))
        .WillOnce(SetErrnoAndReturn(EAGAIN, -1));
    client->lossTimeout().cancelTimeout();
    client->lossTimeout().timeoutExpired();

    EXPECT_TRUE(conn.happyEyeballsState.shouldWriteToFirstSocket);
    EXPECT_TRUE(conn.happyEyeballsState.shouldWriteToSecondSocket);

    EXPECT_CALL(*sock, write(firstAddress, _));
    EXPECT_CALL(*secondSock, write(secondAddress, _));
    client->lossTimeout().cancelTimeout();
    client->lossTimeout().timeoutExpired();
  }

  void fatalWriteErrorOnSecondAfterSecondStarts(
      const SocketAddress& firstAddress,
      const SocketAddress& secondAddress) {
    auto& conn = client->getConn();

    EXPECT_CALL(*sock, write(firstAddress, _));
    EXPECT_CALL(*secondSock, write(_, _)).Times(0);
    client->start(&clientConnCallback);
    EXPECT_EQ(conn.peerAddress, firstAddress);
    EXPECT_EQ(conn.happyEyeballsState.secondPeerAddress, secondAddress);
    EXPECT_TRUE(client->happyEyeballsConnAttemptDelayTimeout().isScheduled());

    // Manually expire conn attempt timeout
    EXPECT_FALSE(conn.happyEyeballsState.shouldWriteToSecondSocket);
    client->happyEyeballsConnAttemptDelayTimeout().cancelTimeout();
    client->happyEyeballsConnAttemptDelayTimeout().timeoutExpired();
    EXPECT_TRUE(conn.happyEyeballsState.shouldWriteToSecondSocket);
    EXPECT_FALSE(client->happyEyeballsConnAttemptDelayTimeout().isScheduled());

    // Manually expire loss timeout to trigger write to both first and second
    // socket
    EXPECT_CALL(*sock, write(firstAddress, _));
    EXPECT_CALL(*secondSock, write(secondAddress, _))
        .WillOnce(SetErrnoAndReturn(EBADF, -1));
    // Socket is paused read once during happy eyeballs
    // Socket is paused read for the second time when QuicClientTransport dies
    EXPECT_CALL(*secondSock, pauseRead()).Times(2);
    EXPECT_CALL(*secondSock, close()).Times(1);
    client->lossTimeout().cancelTimeout();
    client->lossTimeout().timeoutExpired();

    EXPECT_TRUE(conn.happyEyeballsState.shouldWriteToFirstSocket);
    EXPECT_FALSE(conn.happyEyeballsState.shouldWriteToSecondSocket);

    EXPECT_CALL(*sock, write(firstAddress, _));
    EXPECT_CALL(*secondSock, write(_, _)).Times(0);
    client->lossTimeout().cancelTimeout();
    client->lossTimeout().timeoutExpired();
  }

  void nonFatalWriteErrorOnBothAfterSecondStarts(
      const SocketAddress& firstAddress,
      const SocketAddress& secondAddress) {
    auto& conn = client->getConn();

    EXPECT_CALL(*sock, write(firstAddress, _));
    EXPECT_CALL(*secondSock, write(_, _)).Times(0);
    client->start(&clientConnCallback);
    EXPECT_EQ(conn.peerAddress, firstAddress);
    EXPECT_EQ(conn.happyEyeballsState.secondPeerAddress, secondAddress);
    EXPECT_TRUE(client->happyEyeballsConnAttemptDelayTimeout().isScheduled());

    // Manually expire conn attempt timeout
    EXPECT_FALSE(conn.happyEyeballsState.shouldWriteToSecondSocket);
    client->happyEyeballsConnAttemptDelayTimeout().cancelTimeout();
    client->happyEyeballsConnAttemptDelayTimeout().timeoutExpired();
    EXPECT_TRUE(conn.happyEyeballsState.shouldWriteToSecondSocket);
    EXPECT_FALSE(client->happyEyeballsConnAttemptDelayTimeout().isScheduled());

    // Manually expire loss timeout to trigger write to both first and second
    // socket
    EXPECT_CALL(*sock, write(firstAddress, _))
        .WillOnce(SetErrnoAndReturn(EAGAIN, -1));
    EXPECT_CALL(*secondSock, write(secondAddress, _))
        .WillOnce(SetErrnoAndReturn(EAGAIN, -1));
    client->lossTimeout().cancelTimeout();
    client->lossTimeout().timeoutExpired();

    EXPECT_TRUE(conn.happyEyeballsState.shouldWriteToFirstSocket);
    EXPECT_TRUE(conn.happyEyeballsState.shouldWriteToSecondSocket);

    EXPECT_CALL(*sock, write(firstAddress, _));
    EXPECT_CALL(*secondSock, write(secondAddress, _));
    client->lossTimeout().cancelTimeout();
    client->lossTimeout().timeoutExpired();
  }

  void fatalWriteErrorOnBothAfterSecondStarts(
      const SocketAddress& firstAddress,
      const SocketAddress& secondAddress) {
    auto& conn = client->getConn();

    EXPECT_CALL(*sock, write(firstAddress, _));
    EXPECT_CALL(*secondSock, write(_, _)).Times(0);
    client->start(&clientConnCallback);
    EXPECT_EQ(conn.peerAddress, firstAddress);
    EXPECT_EQ(conn.happyEyeballsState.secondPeerAddress, secondAddress);
    EXPECT_TRUE(client->happyEyeballsConnAttemptDelayTimeout().isScheduled());

    // Manually expire conn attempt timeout
    EXPECT_FALSE(conn.happyEyeballsState.shouldWriteToSecondSocket);
    client->happyEyeballsConnAttemptDelayTimeout().cancelTimeout();
    client->happyEyeballsConnAttemptDelayTimeout().timeoutExpired();
    EXPECT_TRUE(conn.happyEyeballsState.shouldWriteToSecondSocket);
    EXPECT_FALSE(client->happyEyeballsConnAttemptDelayTimeout().isScheduled());

    // Manually expire loss timeout to trigger write to both first and second
    // socket
    EXPECT_CALL(*sock, write(firstAddress, _))
        .WillOnce(SetErrnoAndReturn(EBADF, -1));
    EXPECT_CALL(*secondSock, write(secondAddress, _))
        .WillOnce(SetErrnoAndReturn(EBADF, -1));
    EXPECT_CALL(clientConnCallback, onConnectionError(_));
    client->lossTimeout().cancelTimeout();
    client->lossTimeout().timeoutExpired();

    EXPECT_FALSE(conn.happyEyeballsState.shouldWriteToFirstSocket);
    EXPECT_FALSE(conn.happyEyeballsState.shouldWriteToSecondSocket);
  }

 protected:
  folly::test::MockAsyncUDPSocket* secondSock;
  SocketAddress serverAddrV4{"127.0.0.1", 443};
  SocketAddress serverAddrV6{"::1", 443};
};

TEST_F(QuicClientTransportHappyEyeballsTest, V6FirstAndV6WinBeforeV4Start) {
  firstWinBeforeSecondStart(serverAddrV6, serverAddrV4);
}

TEST_F(QuicClientTransportHappyEyeballsTest, V6FirstAndV6WinAfterV4Start) {
  firstWinAfterSecondStart(serverAddrV6, serverAddrV4);
}

TEST_F(QuicClientTransportHappyEyeballsTest, V6FirstAndV4Win) {
  secondWin(serverAddrV6, serverAddrV4);
}

TEST_F(QuicClientTransportHappyEyeballsTest, V6FirstAndV4BindFailure) {
  secondBindFailure(serverAddrV6, serverAddrV4);
}

TEST_F(
    QuicClientTransportHappyEyeballsTest,
    V6FirstAndV6NonFatalErrorBeforeV4Starts) {
  nonFatalWriteErrorOnFirstBeforeSecondStarts(serverAddrV6, serverAddrV4);
}

TEST_F(
    QuicClientTransportHappyEyeballsTest,
    V6FirstAndV6FatalErrorBeforeV4Start) {
  fatalWriteErrorOnFirstBeforeSecondStarts(serverAddrV6, serverAddrV4);
}

TEST_F(
    QuicClientTransportHappyEyeballsTest,
    V6FirstAndV6NonFatalErrorAfterV4Starts) {
  nonFatalWriteErrorOnFirstAfterSecondStarts(serverAddrV6, serverAddrV4);
}

TEST_F(
    QuicClientTransportHappyEyeballsTest,
    V6FirstAndV6FatalErrorAfterV4Start) {
  fatalWriteErrorOnFirstAfterSecondStarts(serverAddrV6, serverAddrV4);
}

TEST_F(
    QuicClientTransportHappyEyeballsTest,
    V6FirstAndV4NonFatalErrorAfterV4Start) {
  nonFatalWriteErrorOnSecondAfterSecondStarts(serverAddrV6, serverAddrV4);
}

TEST_F(
    QuicClientTransportHappyEyeballsTest,
    V6FirstAndV4FatalErrorAfterV4Start) {
  fatalWriteErrorOnSecondAfterSecondStarts(serverAddrV6, serverAddrV4);
}

TEST_F(
    QuicClientTransportHappyEyeballsTest,
    V6FirstAndBothNonFatalErrorAfterV4Start) {
  nonFatalWriteErrorOnBothAfterSecondStarts(serverAddrV6, serverAddrV4);
}

TEST_F(
    QuicClientTransportHappyEyeballsTest,
    V6FirstAndBothFatalErrorAfterV4Start) {
  fatalWriteErrorOnBothAfterSecondStarts(serverAddrV6, serverAddrV4);
}

TEST_F(QuicClientTransportHappyEyeballsTest, V4FirstAndV4WinBeforeV6Start) {
  client->setHappyEyeballsCachedFamily(AF_INET);
  firstWinBeforeSecondStart(serverAddrV4, serverAddrV6);
}

TEST_F(QuicClientTransportHappyEyeballsTest, V4FirstAndV4WinAfterV6Start) {
  client->setHappyEyeballsCachedFamily(AF_INET);
  firstWinAfterSecondStart(serverAddrV4, serverAddrV6);
}

TEST_F(QuicClientTransportHappyEyeballsTest, V4FirstAndV6Win) {
  client->setHappyEyeballsCachedFamily(AF_INET);
  secondWin(serverAddrV4, serverAddrV6);
}

TEST_F(QuicClientTransportHappyEyeballsTest, V4FirstAndV6BindFailure) {
  client->setHappyEyeballsCachedFamily(AF_INET);
  secondBindFailure(serverAddrV4, serverAddrV6);
}

TEST_F(
    QuicClientTransportHappyEyeballsTest,
    V4FirstAndV4NonFatalErrorBeforeV6Start) {
  client->setHappyEyeballsCachedFamily(AF_INET);
  nonFatalWriteErrorOnFirstBeforeSecondStarts(serverAddrV4, serverAddrV6);
}

TEST_F(
    QuicClientTransportHappyEyeballsTest,
    V4FirstAndV4FatalErrorBeforeV6Start) {
  client->setHappyEyeballsCachedFamily(AF_INET);
  fatalWriteErrorOnFirstBeforeSecondStarts(serverAddrV4, serverAddrV6);
}

TEST_F(
    QuicClientTransportHappyEyeballsTest,
    V4FirstAndV4NonFatalErrorAfterV6Start) {
  client->setHappyEyeballsCachedFamily(AF_INET);
  nonFatalWriteErrorOnFirstAfterSecondStarts(serverAddrV4, serverAddrV6);
}

TEST_F(
    QuicClientTransportHappyEyeballsTest,
    V4FirstAndV4FatalErrorAfterV6Start) {
  client->setHappyEyeballsCachedFamily(AF_INET);
  fatalWriteErrorOnFirstAfterSecondStarts(serverAddrV4, serverAddrV6);
}

TEST_F(
    QuicClientTransportHappyEyeballsTest,
    V4FirstAndV6NonFatalErrorAfterV6Start) {
  client->setHappyEyeballsCachedFamily(AF_INET);
  nonFatalWriteErrorOnSecondAfterSecondStarts(serverAddrV4, serverAddrV6);
}

TEST_F(
    QuicClientTransportHappyEyeballsTest,
    V4FirstAndV6FatalErrorAfterV6Start) {
  client->setHappyEyeballsCachedFamily(AF_INET);
  fatalWriteErrorOnSecondAfterSecondStarts(serverAddrV4, serverAddrV6);
}

TEST_F(
    QuicClientTransportHappyEyeballsTest,
    V4FirstAndBothNonFatalErrorAfterV6Start) {
  client->setHappyEyeballsCachedFamily(AF_INET);
  nonFatalWriteErrorOnBothAfterSecondStarts(serverAddrV4, serverAddrV6);
}

TEST_F(
    QuicClientTransportHappyEyeballsTest,
    V4FirstAndBothFatalErrorAfterV6Start) {
  client->setHappyEyeballsCachedFamily(AF_INET);
  fatalWriteErrorOnBothAfterSecondStarts(serverAddrV4, serverAddrV6);
}

class QuicClientTransportAfterStartTest : public QuicClientTransportTest {
 public:
  void SetUp() override {
    client->addNewPeerAddress(serverAddr);
    client->setHostname(hostname_);
    client->setCongestionControllerFactory(
        std::make_shared<DefaultCongestionControllerFactory>());
    ON_CALL(*sock, write(_, _))
        .WillByDefault(Invoke([&](const SocketAddress&,
                                  const std::unique_ptr<folly::IOBuf>& buf) {
          socketWrites.push_back(buf->clone());
          return buf->computeChainDataLength();
        }));
    ON_CALL(*sock, address()).WillByDefault(ReturnRef(serverAddr));

    setupCryptoLayer();
    start();
    client->getNonConstConn().streamManager->setMaxLocalBidirectionalStreams(
        std::numeric_limits<uint32_t>::max());
    client->getNonConstConn().streamManager->setMaxLocalUnidirectionalStreams(
        std::numeric_limits<uint32_t>::max());
  }

 protected:
  std::string hostname_{"TestHost"};
};

class QuicClientTransportVersionAndRetryTest
    : public QuicClientTransportAfterStartTest {
 public:
  ~QuicClientTransportVersionAndRetryTest() override = default;

  void start() override {
    client->start(&clientConnCallback);
    originalConnId = client->getConn().clientConnectionId;
    // create server chosen connId with processId = 0 and workerId = 0
    ServerConnectionIdParams params(0, 0, 0);
    params.clientConnId = *client->getConn().clientConnectionId;
    serverChosenConnId = connIdAlgo_->encodeConnectionId(params);
    // The tests that we do here create streams before crypto is finished,
    // so we initialize the peer streams, to allow for this behavior. TODO: when
    // 0-rtt support exists, remove this.
    client->getNonConstConn()
        .flowControlState.peerAdvertisedInitialMaxStreamOffsetBidiLocal =
        kDefaultStreamWindowSize;
    client->getNonConstConn()
        .flowControlState.peerAdvertisedInitialMaxStreamOffsetBidiRemote =
        kDefaultStreamWindowSize;
    client->getNonConstConn()
        .flowControlState.peerAdvertisedInitialMaxStreamOffsetUni =
        kDefaultStreamWindowSize;
    client->getNonConstConn().flowControlState.peerAdvertisedMaxOffset =
        kDefaultConnectionWindowSize;
  }
};

class QuicClientVersionParamInvalidTest
    : public QuicClientTransportAfterStartTest {
 public:
  ~QuicClientVersionParamInvalidTest() override = default;

  void start() override {
    // force the server to declare that the version negotiated was invalid.;
    mockClientHandshake->negotiatedVersion = MVFST2;

    client->start(&clientConnCallback);
    originalConnId = client->getConn().clientConnectionId;
  }
};

TEST_F(QuicClientTransportAfterStartTest, ReadStream) {
  StreamId streamId = client->createBidirectionalStream().value();

  client->setReadCallback(streamId, &readCb);
  bool dataDelivered = false;
  auto expected = IOBuf::copyBuffer("hello");
  EXPECT_CALL(readCb, readAvailable(streamId)).WillOnce(Invoke([&](auto) {
    auto readData = client->read(streamId, 1000);
    auto copy = readData->first->clone();
    LOG(INFO) << "Client received data=" << copy->moveToFbString().toStdString()
              << " on stream=" << streamId;
    EXPECT_TRUE(folly::IOBufEqualTo()((*readData).first, expected));
    dataDelivered = true;
    eventbase_->terminateLoopSoon();
  }));
  auto packet = packetToBuf(createStreamPacket(
      *serverChosenConnId /* src */,
      *originalConnId /* dest */,
      appDataPacketNum++,
      streamId,
      *expected,
      0 /* cipherOverhead */,
      0 /* largestAcked */));
  deliverData(packet->coalesce());
  if (!dataDelivered) {
    eventbase_->loopForever();
  }
  EXPECT_TRUE(dataDelivered);
  client->close(folly::none);
}

TEST_F(QuicClientTransportAfterStartTest, ReadStreamCoalesced) {
  StreamId streamId = client->createBidirectionalStream().value();

  client->setReadCallback(streamId, &readCb);
  bool dataDelivered = false;
  auto expected = IOBuf::copyBuffer("hello");
  EXPECT_CALL(readCb, readAvailable(streamId)).WillOnce(Invoke([&](auto) {
    auto readData = client->read(streamId, 1000);
    auto copy = readData->first->clone();
    LOG(INFO) << "Client received data=" << copy->moveToFbString().toStdString()
              << " on stream=" << streamId;
    EXPECT_TRUE(folly::IOBufEqualTo()((*readData).first, expected));
    dataDelivered = true;
    eventbase_->terminateLoopSoon();
  }));

  QuicFizzFactory fizzFactory;
  auto garbage = IOBuf::copyBuffer("garbage");
  auto initialCipher =
      getServerInitialCipher(&fizzFactory, *serverChosenConnId);
  auto firstPacketNum = appDataPacketNum++;
  auto packet1 = packetToBufCleartext(
      createStreamPacket(
          *serverChosenConnId /* src */,
          *originalConnId /* dest */,
          firstPacketNum,
          streamId,
          *garbage,
          initialCipher->getCipherOverhead(),
          0 /* largestAcked */,
          std::make_pair(LongHeader::Types::Initial, QuicVersion::MVFST)),
      *initialCipher,
      getInitialHeaderCipher(),
      firstPacketNum);
  packet1->coalesce();
  auto packet2 = packetToBuf(createStreamPacket(
      *serverChosenConnId /* src */,
      *originalConnId /* dest */,
      firstPacketNum,
      streamId,
      *expected,
      0 /* cipherOverhead */,
      0 /* largestAcked */));
  packet1->appendChain(std::move(packet2));
  deliverData(packet1->coalesce());
  if (!dataDelivered) {
    eventbase_->loopForever();
  }
  EXPECT_TRUE(dataDelivered);
  client->close(folly::none);
}

TEST_F(QuicClientTransportAfterStartTest, ReadStreamCoalescedMany) {
  StreamId streamId = client->createBidirectionalStream().value();

  client->setReadCallback(streamId, &readCb);
  auto expected = IOBuf::copyBuffer("hello");
  EXPECT_CALL(readCb, readAvailable(streamId)).Times(0);
  QuicFizzFactory fizzFactory;
  IOBufQueue packets{IOBufQueue::cacheChainLength()};
  for (int i = 0; i < kMaxNumCoalescedPackets; i++) {
    auto garbage = IOBuf::copyBuffer("garbage");
    auto initialCipher =
        getServerInitialCipher(&fizzFactory, *serverChosenConnId);
    auto packetNum = appDataPacketNum++;
    auto packet1 = packetToBufCleartext(
        createStreamPacket(
            *serverChosenConnId /* src */,
            *originalConnId /* dest */,
            packetNum,
            streamId,
            *garbage,
            initialCipher->getCipherOverhead(),
            0 /* largestAcked */,
            std::make_pair(LongHeader::Types::Initial, QuicVersion::MVFST)),
        *initialCipher,
        getInitialHeaderCipher(),
        packetNum);
    packets.append(std::move(packet1));
  }
  auto packet2 = packetToBuf(createStreamPacket(
      *serverChosenConnId /* src */,
      *originalConnId /* dest */,
      appDataPacketNum++,
      streamId,
      *expected,
      0 /* cipherOverhead */,
      0 /* largestAcked */));
  packets.append(std::move(packet2));
  auto data = packets.move();
  deliverData(data->coalesce());
  eventbase_->loopOnce();
  client->close(folly::none);
}

TEST_F(QuicClientTransportAfterStartTest, RecvPathChallenge) {
  auto& conn = client->getNonConstConn();

  ShortHeader header(ProtectionType::KeyPhaseZero, *conn.clientConnectionId, 1);
  RegularQuicPacketBuilder builder(
      conn.udpSendPacketLen, std::move(header), 0 /* largestAcked */);
  PathChallengeFrame pathChallenge(123);
  ASSERT_TRUE(builder.canBuildPacket());
  writeSimpleFrame(QuicSimpleFrame(pathChallenge), builder);

  auto packet = std::move(builder).buildPacket();
  auto data = packetToBuf(packet);

  EXPECT_TRUE(conn.pendingEvents.frames.empty());
  deliverData(data->coalesce(), false);
  EXPECT_EQ(conn.pendingEvents.frames.size(), 1);
  auto& pathResponse =
      boost::get<PathResponseFrame>(conn.pendingEvents.frames[0]);
  EXPECT_EQ(pathResponse.pathData, pathChallenge.pathData);
}

template <class FrameType>
bool verifyFramePresent(
    std::vector<std::unique_ptr<folly::IOBuf>>& socketWrites,
    QuicReadCodec& readCodec) {
  AckStates ackStates;
  for (auto& write : socketWrites) {
    auto packetQueue = bufToQueue(write->clone());
    auto result = readCodec.parsePacket(packetQueue, ackStates);
    auto parsedPacket = boost::get<QuicPacket>(&result);
    if (!parsedPacket) {
      continue;
    }
    auto& regularPacket = boost::get<RegularQuicPacket>(*parsedPacket);
    for (FOLLY_MAYBE_UNUSED auto& frame :
         all_frames<FrameType>(regularPacket.frames)) {
      return true;
    }
  }
  return false;
}

TEST_F(QuicClientTransportAfterStartTest, CloseConnectionWithStreamPending) {
  StreamId streamId = client->createBidirectionalStream().value();

  auto expected = IOBuf::copyBuffer("hello");
  client->setReadCallback(streamId, &readCb);
  client->writeChain(streamId, expected->clone(), true, false);
  loopForWrites();
  // ack all the packets
  ASSERT_FALSE(client->getConn().outstandingPackets.empty());

  IntervalSet<quic::PacketNum> acks;
  auto start = folly::variant_match(
      getFirstOutstandingPacket(
          client->getNonConstConn(), PacketNumberSpace::AppData)
          ->packet.header,
      [](auto& h) { return h.getPacketSequenceNum(); });
  auto end = folly::variant_match(
      getLastOutstandingPacket(
          client->getNonConstConn(), PacketNumberSpace::AppData)
          ->packet.header,
      [](auto& h) { return h.getPacketSequenceNum(); });
  acks.insert(start, end);

  auto ackPacket = packetToBuf(createAckPacket(
      client->getNonConstConn(),
      ++appDataPacketNum,
      acks,
      PacketNumberSpace::AppData));
  deliverData(ackPacket->coalesce());
  socketWrites.clear();

  auto serverReadCodec = makeEncryptedCodec();
  EXPECT_CALL(readCb, readError(streamId, _));
  client->closeGracefully();
  EXPECT_FALSE(
      verifyFramePresent<ConnectionCloseFrame>(socketWrites, *serverReadCodec));

  // close the stream
  auto packet = packetToBuf(createStreamPacket(
      *serverChosenConnId /* src */,
      *originalConnId /* dest */,
      appDataPacketNum++,
      streamId,
      *expected,
      0 /* cipherOverhead */,
      0 /* largestAcked */,
      folly::none,
      true));
  socketWrites.clear();
  deliverData(packet->coalesce());
  EXPECT_TRUE(
      verifyFramePresent<ConnectionCloseFrame>(socketWrites, *serverReadCodec));
}

TEST_F(QuicClientTransportAfterStartTest, CloseConnectionWithNoStreamPending) {
  StreamId streamId = client->createBidirectionalStream().value();

  auto expected = IOBuf::copyBuffer("hello");
  client->setReadCallback(streamId, &readCb);
  client->writeChain(streamId, expected->clone(), true, false);

  loopForWrites();

  // ack all the packets
  ASSERT_FALSE(client->getConn().outstandingPackets.empty());

  IntervalSet<quic::PacketNum> acks;
  auto start = folly::variant_match(
      getFirstOutstandingPacket(
          client->getNonConstConn(), PacketNumberSpace::AppData)
          ->packet.header,
      [](auto& h) { return h.getPacketSequenceNum(); });
  auto end = folly::variant_match(
      getLastOutstandingPacket(
          client->getNonConstConn(), PacketNumberSpace::AppData)
          ->packet.header,
      [](auto& h) { return h.getPacketSequenceNum(); });
  acks.insert(start, end);

  auto ackPacket = packetToBuf(createAckPacket(
      client->getNonConstConn(),
      ++appDataPacketNum,
      acks,
      PacketNumberSpace::AppData));
  deliverData(ackPacket->coalesce());
  socketWrites.clear();

  // close the stream
  auto packet = packetToBuf(createStreamPacket(
      *serverChosenConnId /* src */,
      *originalConnId /* dest */,
      appDataPacketNum++,
      streamId,
      *expected,
      0 /* cipherOverhead */,
      0 /* largestAcked */,
      folly::none,
      true));
  socketWrites.clear();
  deliverData(packet->coalesce());
  EXPECT_CALL(readCb, readError(streamId, _));
  client->close(folly::none);
  EXPECT_TRUE(verifyFramePresent<ConnectionCloseFrame>(
      socketWrites, *makeEncryptedCodec()));
}

class QuicClientTransportAfterStartTestClose
    : public QuicClientTransportAfterStartTest,
      public testing::WithParamInterface<bool> {};

INSTANTIATE_TEST_CASE_P(
    QuicClientTransportAfterStartTest,
    QuicClientTransportAfterStartTestClose,
    Values(true, false));

TEST_P(
    QuicClientTransportAfterStartTestClose,
    CloseConnectionWithErrorCleartext) {
  StreamId streamId = client->createBidirectionalStream().value();

  auto expected = IOBuf::copyBuffer("hello");
  client->setReadCallback(streamId, &readCb);
  client->writeChain(streamId, expected->clone(), true, false);

  loopForWrites();
  socketWrites.clear();
  EXPECT_CALL(readCb, readError(streamId, _));
  if (GetParam()) {
    client->close(std::make_pair(
        QuicErrorCode(GenericApplicationErrorCode::UNKNOWN),
        std::string("stopping")));
    EXPECT_TRUE(verifyFramePresent<ApplicationCloseFrame>(
        socketWrites, *makeHandshakeCodec()));
  } else {
    client->close(folly::none);
    EXPECT_TRUE(verifyFramePresent<ConnectionCloseFrame>(
        socketWrites, *makeHandshakeCodec()));
  }
}

TEST_F(QuicClientTransportAfterStartTest, RecvPostHandshakeData) {
  auto oneRttReadOffset =
      client->getConn().cryptoState->oneRttStream.currentReadOffset;
  recvTicket();
  EXPECT_GT(
      client->getConn().cryptoState->oneRttStream.currentReadOffset,
      oneRttReadOffset);
}

TEST_F(QuicClientTransportAfterStartTest, RecvRetransmittedHandshakeData) {
  recvTicket();
  auto oneRttReadOffset =
      client->getConn().cryptoState->oneRttStream.currentReadOffset;
  // Simulate retransmission of the same ticket.
  recvTicket(0);
  EXPECT_EQ(
      client->getConn().cryptoState->oneRttStream.currentReadOffset,
      oneRttReadOffset);
}

TEST_F(QuicClientTransportAfterStartTest, RecvAckOfCryptoStream) {
  // Simulate ack from server
  auto& cryptoState = client->getConn().cryptoState;
  EXPECT_GT(cryptoState->initialStream.retransmissionBuffer.size(), 0);
  EXPECT_GT(cryptoState->handshakeStream.retransmissionBuffer.size(), 0);
  EXPECT_EQ(cryptoState->oneRttStream.retransmissionBuffer.size(), 0);

  auto& aead = getInitialCipher();
  auto& headerCipher = getInitialHeaderCipher();
  // initial
  {
    IntervalSet<quic::PacketNum> acks;
    auto start = folly::variant_match(
        getFirstOutstandingPacket(
            client->getNonConstConn(), PacketNumberSpace::Initial)
            ->packet.header,
        [](auto& h) { return h.getPacketSequenceNum(); });
    auto end = folly::variant_match(
        getLastOutstandingPacket(
            client->getNonConstConn(), PacketNumberSpace::Initial)
            ->packet.header,
        [](auto& h) { return h.getPacketSequenceNum(); });
    acks.insert(start, end);
    auto pn = initialPacketNum++;
    auto ackPkt = createAckPacket(
        client->getNonConstConn(), pn, acks, PacketNumberSpace::Initial, &aead);
    deliverData(
        packetToBufCleartext(ackPkt, aead, headerCipher, pn)->coalesce());
    EXPECT_EQ(cryptoState->initialStream.retransmissionBuffer.size(), 0);
    EXPECT_GT(cryptoState->handshakeStream.retransmissionBuffer.size(), 0);
    EXPECT_EQ(cryptoState->oneRttStream.retransmissionBuffer.size(), 0);
  }
  // handshake
  {
    IntervalSet<quic::PacketNum> acks;
    auto start = folly::variant_match(
        getFirstOutstandingPacket(
            client->getNonConstConn(), PacketNumberSpace::Handshake)
            ->packet.header,
        [](auto& h) { return h.getPacketSequenceNum(); });
    auto end = folly::variant_match(
        getLastOutstandingPacket(
            client->getNonConstConn(), PacketNumberSpace::Handshake)
            ->packet.header,
        [](auto& h) { return h.getPacketSequenceNum(); });
    acks.insert(start, end);
    auto pn = handshakePacketNum++;
    auto ackPkt = createAckPacket(
        client->getNonConstConn(), pn, acks, PacketNumberSpace::Handshake);
    deliverData(packetToBuf(ackPkt)->coalesce());
    EXPECT_EQ(cryptoState->initialStream.retransmissionBuffer.size(), 0);
    EXPECT_EQ(cryptoState->handshakeStream.retransmissionBuffer.size(), 0);
    EXPECT_EQ(cryptoState->oneRttStream.retransmissionBuffer.size(), 0);
  }
}

TEST_F(QuicClientTransportAfterStartTest, RecvOneRttAck) {
  EXPECT_GT(
      client->getConn().cryptoState->initialStream.retransmissionBuffer.size(),
      0);
  EXPECT_GT(
      client->getConn()
          .cryptoState->handshakeStream.retransmissionBuffer.size(),
      0);

  // Client doesn't send one rtt crypto data today
  EXPECT_EQ(
      client->getConn().cryptoState->oneRttStream.retransmissionBuffer.size(),
      0);
  StreamId streamId = client->createBidirectionalStream().value();

  auto expected = IOBuf::copyBuffer("hello");
  client->setReadCallback(streamId, &readCb);
  client->writeChain(streamId, expected->clone(), true, false);
  loopForWrites();

  IntervalSet<PacketNum> sentPackets;
  verifyShortPackets(sentPackets);

  // Write an AckFrame back to client:
  auto ackPacket = packetToBuf(createAckPacket(
      client->getNonConstConn(),
      ++appDataPacketNum,
      sentPackets,
      PacketNumberSpace::AppData));
  deliverData(ackPacket->coalesce());

  // Should have canceled retransmissions
  EXPECT_EQ(
      client->getConn().cryptoState->initialStream.retransmissionBuffer.size(),
      0);
  EXPECT_EQ(
      client->getConn()
          .cryptoState->handshakeStream.retransmissionBuffer.size(),
      0);
}

TEST_P(QuicClientTransportAfterStartTestClose, CloseConnectionWithError) {
  StreamId streamId = client->createBidirectionalStream().value();

  auto expected = IOBuf::copyBuffer("hello");
  client->setReadCallback(streamId, &readCb);
  client->writeChain(streamId, expected->clone(), true, false);
  loopForWrites();
  auto packet = packetToBuf(createStreamPacket(
      *serverChosenConnId /* src */,
      *originalConnId /* dest */,
      appDataPacketNum++,
      streamId,
      *expected,
      0 /* cipherOverhead */,
      0 /* largestAcked */,
      folly::none,
      true));
  deliverData(packet->coalesce());
  socketWrites.clear();
  if (GetParam()) {
    client->close(std::make_pair(
        QuicErrorCode(GenericApplicationErrorCode::UNKNOWN),
        std::string("stopping")));
    EXPECT_TRUE(verifyFramePresent<ApplicationCloseFrame>(
        socketWrites, *makeEncryptedCodec()));
  } else {
    client->close(folly::none);
    EXPECT_TRUE(verifyFramePresent<ConnectionCloseFrame>(
        socketWrites, *makeEncryptedCodec()));
  }
}

TEST_F(
    QuicClientTransportAfterStartTest,
    HandshakeCipherTimeoutAfterFirstData) {
  StreamId streamId = client->createBidirectionalStream().value();

  EXPECT_NE(client->getConn().readCodec->getInitialCipher(), nullptr);
  auto expected = IOBuf::copyBuffer("hello");
  auto packet = packetToBuf(createStreamPacket(
      *serverChosenConnId /* src */,
      *originalConnId /* dest */,
      appDataPacketNum++,
      streamId,
      *expected,
      0 /* cipherOverhead */,
      0 /* largestAcked */,
      folly::none,
      true));
  deliverData(packet->coalesce());
  EXPECT_NE(client->getConn().readCodec->getInitialCipher(), nullptr);
  EXPECT_TRUE(client->getConn().readCodec->getHandshakeDoneTime().hasValue());
}

TEST_F(QuicClientTransportAfterStartTest, InvalidConnectionId) {
  StreamId streamId = client->createBidirectionalStream().value();

  client->setReadCallback(streamId, &readCb);

  // Test sending packet with original conn id with correct cipher, but wrong
  // conn id.
  PacketNum nextPacket = appDataPacketNum++;
  auto packet = packetToBuf(createStreamPacket(
      *serverChosenConnId /* src */,
      *serverChosenConnId /* dest */,
      nextPacket,
      streamId,
      *IOBuf::create(10),
      0 /* cipherOverhead */,
      0 /* largestAcked */));
  EXPECT_THROW(deliverData(packet->coalesce()), std::runtime_error);
}

TEST_F(QuicClientTransportAfterStartTest, IdleTimerResetOnRecvNewData) {
  // spend some time looping the evb
  for (int i = 0; i < 10; ++i) {
    eventbase_->loopOnce(EVLOOP_NONBLOCK);
  }
  StreamId streamId = client->createBidirectionalStream().value();
  auto expected = IOBuf::copyBuffer("hello");
  auto packet = packetToBuf(createStreamPacket(
      *serverChosenConnId /* src */,
      *originalConnId /* dest */,
      appDataPacketNum++,
      streamId,
      *expected,
      0 /* cipherOverhead */,
      0 /* largestAcked */));

  client->idleTimeout().cancelTimeout();
  ASSERT_FALSE(client->idleTimeout().isScheduled());
  deliverData(packet->coalesce());
  ASSERT_TRUE(client->getConn().receivedNewPacketBeforeWrite);
  ASSERT_TRUE(client->idleTimeout().isScheduled());

  auto packet2 = packetToBuf(createStreamPacket(
      *serverChosenConnId /* src */,
      *originalConnId /* dest */,
      appDataPacketNum++,
      streamId,
      *expected,
      0 /* cipherOverhead */,
      0 /* largestAcked */));
  client->idleTimeout().cancelTimeout();
  ASSERT_FALSE(client->idleTimeout().isScheduled());
  deliverData(packet2->coalesce());
  ASSERT_TRUE(client->getConn().receivedNewPacketBeforeWrite);
  ASSERT_TRUE(client->idleTimeout().isScheduled());
}

TEST_F(QuicClientTransportAfterStartTest, IdleTimerNotResetOnDuplicatePacket) {
  StreamId streamId = client->createBidirectionalStream().value();

  auto expected = IOBuf::copyBuffer("hello");
  auto packet = packetToBuf(createStreamPacket(
      *serverChosenConnId /* src */,
      *originalConnId /* dest */,
      appDataPacketNum++,
      streamId,
      *expected,
      0 /* cipherOverhead */,
      0 /* largestAcked */));

  // Writes may cause idle timer to be set, so don't loop for a write.
  deliverData(packet->coalesce(), false);

  ASSERT_TRUE(client->getConn().receivedNewPacketBeforeWrite);
  ASSERT_TRUE(client->idleTimeout().isScheduled());

  client->idleTimeout().cancelTimeout();
  client->getNonConstConn().receivedNewPacketBeforeWrite = false;
  ASSERT_FALSE(client->idleTimeout().isScheduled());
  // Try delivering the same packet again
  deliverData(packet->coalesce(), false);

  ASSERT_FALSE(client->getConn().receivedNewPacketBeforeWrite);
  ASSERT_FALSE(client->idleTimeout().isScheduled());
  client->closeNow(folly::none);
}

TEST_P(QuicClientTransportAfterStartTestClose, TimeoutsNotSetAfterClose) {
  StreamId streamId = client->createBidirectionalStream().value();

  auto expected = IOBuf::copyBuffer("hello");
  auto packet = packetToBuf(createStreamPacket(
      *serverChosenConnId /* src */,
      *originalConnId /* dest */,
      appDataPacketNum++,
      streamId,
      *expected,
      0 /* cipherOverhead */,
      0 /* largestAcked */));

  if (GetParam()) {
    client->close(std::make_pair(
        QuicErrorCode(TransportErrorCode::INTERNAL_ERROR),
        std::string("how about no")));
  } else {
    client->close(folly::none);
  }
  client->idleTimeout().cancelTimeout();
  ASSERT_FALSE(client->idleTimeout().isScheduled());

  deliverDataWithoutErrorCheck(packet->coalesce());
  ASSERT_FALSE(client->idleTimeout().isScheduled());
  ASSERT_FALSE(client->lossTimeout().isScheduled());
  ASSERT_FALSE(client->ackTimeout().isScheduled());
  ASSERT_TRUE(client->drainTimeout().isScheduled());
}

TEST_F(QuicClientTransportAfterStartTest, IdleTimerNotResetOnWritingOldData) {
  StreamId streamId = client->createBidirectionalStream().value();

  // There should still be outstanding packets
  auto expected = IOBuf::copyBuffer("hello");
  client->idleTimeout().cancelTimeout();
  ASSERT_FALSE(client->idleTimeout().isScheduled());
  client->writeChain(streamId, expected->clone(), false, false);
  loopForWrites();

  ASSERT_FALSE(client->getConn().receivedNewPacketBeforeWrite);
  ASSERT_FALSE(client->idleTimeout().isScheduled());
  client->closeNow(folly::none);
}

TEST_F(QuicClientTransportAfterStartTest, IdleTimerResetNoOutstandingPackets) {
  // This will clear out all the outstanding packets
  IntervalSet<PacketNum> sentPackets;
  for (auto& packet : client->getNonConstConn().outstandingPackets) {
    auto packetNum = folly::variant_match(
        packet.packet.header, [](auto& h) { return h.getPacketSequenceNum(); });
    sentPackets.insert(packetNum);
  }
  auto ackPacket = packetToBuf(createAckPacket(
      client->getNonConstConn(),
      ++appDataPacketNum,
      sentPackets,
      PacketNumberSpace::AppData));
  deliverData(ackPacket->coalesce());

  // Clear out all the outstanding packets to simulate quiescent state.
  client->getNonConstConn().receivedNewPacketBeforeWrite = false;
  client->getNonConstConn().outstandingPackets.clear();
  client->getNonConstConn().outstandingPureAckPacketsCount =
      client->getNonConstConn().outstandingHandshakePacketsCount =
          client->getNonConstConn().outstandingClonedPacketsCount = 0;
  client->idleTimeout().cancelTimeout();
  auto streamId = client->createBidirectionalStream().value();
  auto expected = folly::IOBuf::copyBuffer("hello");
  client->writeChain(streamId, expected->clone(), false, false);
  loopForWrites();
  ASSERT_TRUE(client->idleTimeout().isScheduled());
}

TEST_F(QuicClientTransportAfterStartTest, IdleTimeoutExpired) {
  EXPECT_CALL(*sock, close());
  socketWrites.clear();
  client->idleTimeout().timeoutExpired();

  EXPECT_FALSE(client->idleTimeout().isScheduled());
  EXPECT_TRUE(client->isDraining());
  EXPECT_TRUE(client->isClosed());

  auto serverCodec = makeEncryptedCodec();
  // We expect a conn close in a cleartext packet.
  EXPECT_FALSE(
      verifyFramePresent<ApplicationCloseFrame>(socketWrites, *serverCodec));
  EXPECT_FALSE(
      verifyFramePresent<ConnectionCloseFrame>(socketWrites, *serverCodec));
  EXPECT_TRUE(socketWrites.empty());
}

TEST_F(QuicClientTransportAfterStartTest, RecvDataAfterIdleTimeout) {
  EXPECT_CALL(*sock, close());
  client->idleTimeout().timeoutExpired();

  socketWrites.clear();
  StreamId streamId = 11;
  auto expected = IOBuf::copyBuffer("hello");
  auto packet = packetToBuf(createStreamPacket(
      *serverChosenConnId /* src */,
      *originalConnId /* dest */,
      appDataPacketNum++,
      streamId,
      *expected,
      0 /* cipherOverhead */,
      0 /* largestAcked */));
  deliverData(packet->coalesce());
  EXPECT_TRUE(verifyFramePresent<ConnectionCloseFrame>(
      socketWrites, *makeEncryptedCodec(true)));
}

TEST_F(QuicClientTransportAfterStartTest, InvalidStream) {
  StreamId streamId = 10;
  auto expected = IOBuf::copyBuffer("hello");
  auto packet = packetToBuf(createStreamPacket(
      *serverChosenConnId /* src */,
      *originalConnId /* dest */,
      appDataPacketNum++,
      streamId,
      *expected,
      0 /* cipherOverhead */,
      0 /* largestAcked */));
  EXPECT_THROW(deliverData(packet->coalesce()), std::runtime_error);
}

TEST_F(QuicClientTransportAfterStartTest, WrongCleartextCipher) {
  QuicFizzFactory fizzFactory;
  StreamId streamId = client->createBidirectionalStream().value();

  auto expected = IOBuf::copyBuffer("hello");
  // Test sending packet with wrong connection id, should drop it, it normally
  // throws on getting unencrypted stream data.
  PacketNum nextPacketNum = appDataPacketNum++;

  auto initialCipher =
      getServerInitialCipher(&fizzFactory, *serverChosenConnId);
  auto packet = packetToBufCleartext(
      createStreamPacket(
          *serverChosenConnId /* src */,
          *originalConnId /* dest */,
          nextPacketNum,
          streamId,
          *expected,
          initialCipher->getCipherOverhead(),
          0 /* largestAcked */,
          std::make_pair(LongHeader::Types::Initial, QuicVersion::MVFST)),
      *initialCipher,
      getInitialHeaderCipher(),
      nextPacketNum);
  deliverData(packet->coalesce());
}

TEST_F(
    QuicClientTransportAfterStartTest,
    ReceiveRstStreamNonExistentClientStream) {
  StreamId streamId = 0x04;
  RstStreamFrame rstFrame(streamId, GenericApplicationErrorCode::UNKNOWN, 0);
  ShortHeader header(
      ProtectionType::KeyPhaseZero, *originalConnId, appDataPacketNum++);
  RegularQuicPacketBuilder builder(
      client->getConn().udpSendPacketLen,
      std::move(header),
      0 /* largestAcked */);
  ASSERT_TRUE(builder.canBuildPacket());
  writeFrame(rstFrame, builder);
  auto packet = packetToBuf(std::move(builder).buildPacket());
  EXPECT_THROW(deliverData(packet->coalesce()), std::runtime_error);
}

TEST_F(QuicClientTransportAfterStartTest, ReceiveRstStreamAfterEom) {
  // A RstStreamFrame will be written to sock when we receive a RstStreamFrame
  auto streamId =
      client->createBidirectionalStream(false /* replaySafe */).value();
  client->setReadCallback(streamId, &readCb);

  EXPECT_CALL(readCb, readAvailable(streamId)).WillOnce(Invoke([&](auto id) {
    auto readData = client->read(id, 0);
    EXPECT_TRUE(readData->second);
  }));

  // delivers the eof
  auto data = IOBuf::copyBuffer("hello");
  auto packet = packetToBuf(createStreamPacket(
      *serverChosenConnId /* src */,
      *originalConnId /* dest */,
      appDataPacketNum++,
      streamId,
      *data,
      0 /* cipherOverhead */,
      0 /* largestAcked */));
  deliverData(packet->coalesce());

  EXPECT_CALL(readCb, readError(streamId, _));

  RstStreamFrame rstFrame(
      streamId, GenericApplicationErrorCode::UNKNOWN, data->length());
  ShortHeader header(
      ProtectionType::KeyPhaseZero, *originalConnId, appDataPacketNum++);
  RegularQuicPacketBuilder builder(
      client->getConn().udpSendPacketLen,
      std::move(header),
      0 /* largestAcked */);
  ASSERT_TRUE(builder.canBuildPacket());
  writeFrame(rstFrame, builder);
  auto packet2 = packetToBuf(std::move(builder).buildPacket());
  deliverData(packet2->coalesce());

  EXPECT_TRUE(client->getReadCallbacks().empty());
  client->close(folly::none);
}

TEST_F(
    QuicClientTransportAfterStartTest,
    SetReadCallbackNullRemembersDelivery) {
  // A RstStreamFrame will be written to sock when we receive a RstStreamFrame
  auto streamId =
      client->createBidirectionalStream(false /* replaySafe */).value();
  client->setReadCallback(streamId, &readCb);

  EXPECT_CALL(readCb, readAvailable(streamId)).WillOnce(Invoke([&](auto id) {
    auto readData = client->read(id, 0);
    EXPECT_TRUE(readData->second);
  }));

  // delivers the eof
  auto data = IOBuf::copyBuffer("hello");
  auto packet = packetToBuf(createStreamPacket(
      *serverChosenConnId /* src */,
      *originalConnId /* dest */,
      appDataPacketNum++,
      streamId,
      *data,
      0 /* cipherOverhead */,
      0 /* largestAcked */));
  deliverData(packet->coalesce());

  client->setReadCallback(streamId, nullptr);

  IntervalSet<PacketNum> sentPackets;
  auto writeData = IOBuf::copyBuffer("some data");
  client->writeChain(streamId, writeData->clone(), true, false);
  loopForWrites();
  verifyShortPackets(sentPackets);

  // Write an AckFrame back to client:
  auto packet2 = packetToBuf(createAckPacket(
      client->getNonConstConn(),
      ++appDataPacketNum,
      sentPackets,
      PacketNumberSpace::AppData));
  deliverData(packet2->coalesce());

  ASSERT_EQ(
      client->getNonConstConn().streamManager->getStream(streamId), nullptr);
  client->close(folly::none);
}

TEST_F(QuicClientTransportAfterStartTest, StreamClosedIfReadCallbackNull) {
  // A RstStreamFrame will be written to sock when we receive a RstStreamFrame
  auto streamId =
      client->createBidirectionalStream(false /* replaySafe */).value();

  IntervalSet<PacketNum> sentPackets;
  auto writeData = IOBuf::copyBuffer("some data");
  client->writeChain(streamId, writeData->clone(), true, false);
  loopForWrites();
  verifyShortPackets(sentPackets);

  // Write an AckFrame back to client:
  auto packet2 = packetToBuf(createAckPacket(
      client->getNonConstConn(),
      ++appDataPacketNum,
      sentPackets,
      PacketNumberSpace::AppData));
  deliverData(packet2->coalesce());

  // delivers the eof. Even though there is no read callback, we still need an
  // EOM or error to terminate the stream.
  auto data = IOBuf::copyBuffer("hello");
  auto packet = packetToBuf(createStreamPacket(
      *serverChosenConnId /* src */,
      *originalConnId /* dest */,
      appDataPacketNum++,
      streamId,
      *data,
      0 /* cipherOverhead */,
      0 /* largestAcked */));
  deliverData(packet->coalesce());

  ASSERT_EQ(
      client->getNonConstConn().streamManager->getStream(streamId), nullptr);
  client->close(folly::none);
}

TEST_F(QuicClientTransportAfterStartTest, ReceiveAckInvokesDeliveryCallback) {
  IntervalSet<PacketNum> sentPackets;
  auto streamId =
      client->createBidirectionalStream(false /* replaySafe */).value();
  client->registerDeliveryCallback(streamId, 0, &deliveryCallback);

  auto data = IOBuf::copyBuffer("some data");
  client->writeChain(streamId, data->clone(), true, false);
  loopForWrites();

  verifyShortPackets(sentPackets);

  // Write an AckFrame back to client:
  auto packet = packetToBuf(createAckPacket(
      client->getNonConstConn(),
      ++appDataPacketNum,
      sentPackets,
      PacketNumberSpace::AppData));

  EXPECT_CALL(deliveryCallback, onDeliveryAck(streamId, 0, _)).Times(1);
  deliverData(packet->coalesce());
  client->close(folly::none);
}

TEST_F(QuicClientTransportAfterStartTest, InvokesDeliveryCallbackFinOnly) {
  IntervalSet<PacketNum> sentPackets;
  auto streamId =
      client->createBidirectionalStream(false /* replaySafe */).value();

  auto data = IOBuf::copyBuffer("some data");
  client->writeChain(streamId, nullptr, true, false, &deliveryCallback);
  loopForWrites();

  verifyShortPackets(sentPackets);
  ASSERT_EQ(sentPackets.size(), 1);

  // Write an AckFrame back to client:
  auto packet = packetToBuf(createAckPacket(
      client->getNonConstConn(),
      ++appDataPacketNum,
      sentPackets,
      PacketNumberSpace::AppData));

  EXPECT_CALL(deliveryCallback, onDeliveryAck(streamId, _, _)).Times(1);
  deliverData(packet->coalesce());
  client->close(folly::none);
}

TEST_F(
    QuicClientTransportAfterStartTest,
    RegisterDeliveryCallbackForAlreadyDeliveredOffset) {
  IntervalSet<PacketNum> sentPackets;

  auto streamId =
      client->createBidirectionalStream(false /* replaySafe */).value();

  auto data = IOBuf::copyBuffer("some data");
  client->writeChain(streamId, data->clone(), true, false);

  loopForWrites();
  verifyShortPackets(sentPackets);

  // Write an AckFrame back to client:
  auto packet = packetToBuf(createAckPacket(
      client->getNonConstConn(),
      ++appDataPacketNum,
      sentPackets,
      PacketNumberSpace::AppData));
  deliverData(packet->coalesce());

  // Register a DeliveryCallback for an offset that's already delivered, will
  // callback immediately
  EXPECT_CALL(deliveryCallback, onDeliveryAck(streamId, 0, _)).Times(1);
  client->registerDeliveryCallback(streamId, 0, &deliveryCallback);
  eventbase_->loopOnce();
  client->close(folly::none);
}

TEST_F(QuicClientTransportAfterStartTest, DeliveryCallbackFromWriteChain) {
  IntervalSet<PacketNum> sentPackets;
  auto streamId =
      client->createBidirectionalStream(false /* replaySafe */).value();

  // Write 10 bytes of data, and write EOF on an empty stream. So EOF offset is
  // 10
  auto data = test::buildRandomInputData(10);
  client->writeChain(streamId, data->clone(), true, false, &deliveryCallback);

  loopForWrites();
  verifyShortPackets(sentPackets);

  // Write an AckFrame back to client:
  auto packet = packetToBuf(createAckPacket(
      client->getNonConstConn(),
      ++appDataPacketNum,
      sentPackets,
      PacketNumberSpace::AppData));

  // DeliveryCallback is called, and offset delivered is 10:
  EXPECT_CALL(deliveryCallback, onDeliveryAck(streamId, 10, _)).Times(1);
  deliverData(packet->coalesce());
  client->close(folly::none);
}

TEST_F(QuicClientTransportAfterStartTest, NotifyPendingWrite) {
  MockWriteCallback writeCallback;
  EXPECT_CALL(writeCallback, onConnectionWriteReady(_));
  client->notifyPendingWriteOnConnection(&writeCallback);
  loopForWrites();
  client->close(folly::none);
}

TEST_F(QuicClientTransportAfterStartTest, SwitchEvbWhileAsyncEventPending) {
  MockWriteCallback writeCallback;
  EventBase evb2;
  EXPECT_CALL(writeCallback, onConnectionWriteReady(_)).Times(0);
  client->notifyPendingWriteOnConnection(&writeCallback);
  client->detachEventBase();
  client->attachEventBase(&evb2);
  loopForWrites();
  client->close(folly::none);
}

TEST_F(QuicClientTransportAfterStartTest, StatelessResetClosesTransport) {
  // Make decrypt fail for the reset token
  auto aead = dynamic_cast<const fizz::test::MockAead*>(
      client->getNonConstConn().readCodec->getOneRttReadCipher());
  ASSERT_TRUE(aead);

  // Make the decrypt fail
  EXPECT_CALL(*aead, _tryDecrypt(_, _, _))
      .WillRepeatedly(Invoke([&](auto&, auto, auto) { return folly::none; }));

  auto token = *client->getConn().statelessResetToken;
  StatelessResetPacketBuilder builder(kDefaultUDPSendPacketLen, token);
  auto packet = std::move(builder).buildPacket();
  EXPECT_CALL(clientConnCallback, onConnectionError(_));
  deliverDataWithoutErrorCheck(packet->coalesce());
  EXPECT_TRUE(client->isClosed());
  client.reset();
  EXPECT_TRUE(destructionCallback->isDestroyed());
}

TEST_F(QuicClientTransportAfterStartTest, BadStatelessResetWontCloseTransport) {
  auto aead = dynamic_cast<const fizz::test::MockAead*>(
      client->getNonConstConn().readCodec->getOneRttReadCipher());
  ASSERT_TRUE(aead);
  // Make the decrypt fail
  EXPECT_CALL(*aead, _tryDecrypt(_, _, _))
      .WillRepeatedly(Invoke([&](auto&, auto, auto) { return folly::none; }));
  // Alter the expected token so it definitely won't match the one in conn
  auto token = *client->getConn().statelessResetToken;
  token[0] = ~token[0];
  StatelessResetPacketBuilder builder(kDefaultUDPSendPacketLen, token);
  auto packet = std::move(builder).buildPacket();
  // onConnectionError won't be invoked
  EXPECT_CALL(clientConnCallback, onConnectionError(_)).Times(0);
  deliverDataWithoutErrorCheck(packet->coalesce());
  EXPECT_FALSE(client->isClosed());
  EXPECT_FALSE(client->isDraining());
  client.reset();
  EXPECT_FALSE(destructionCallback->isDestroyed());
}

TEST_F(QuicClientTransportVersionAndRetryTest, RetryPacket) {
  // Create a stream and attempt to send some data to the server
  StreamId streamId = *client->createBidirectionalStream();
  auto write = IOBuf::copyBuffer("ice cream");
  client->writeChain(streamId, write->clone(), true, false, nullptr);
  loopForWrites();

  std::unique_ptr<IOBuf> bytesWrittenToNetwork = nullptr;

  EXPECT_CALL(*sock, write(_, _))
      .WillRepeatedly(Invoke(
          [&](const SocketAddress&, const std::unique_ptr<folly::IOBuf>& buf) {
            bytesWrittenToNetwork = buf->clone();
            return buf->computeChainDataLength();
          }));

  // Make the server send a retry packet to the client. The server chooses a
  // connection id that the client must use in all future initial packets.
  auto serverChosenConnId = getTestConnectionId();

  LongHeader headerIn(
      LongHeader::Types::Retry,
      serverChosenConnId,
      *originalConnId,
      321,
      QuicVersion::MVFST,
      IOBuf::copyBuffer("this is a retry token :)"),
      *client->getConn().initialDestinationConnectionId);

  RegularQuicPacketBuilder builder(
      kDefaultUDPSendPacketLen, std::move(headerIn), 0 /* largestAcked */);
  auto packet = packetToBuf(std::move(builder).buildPacket());

  deliverData(packet->coalesce());

  ASSERT_TRUE(bytesWrittenToNetwork);

  // Check to see that the server receives an initial packet with the following
  // properties:
  // 1. The token in the initial packet matches the token sent in the retry
  // packet
  // 2. The destination connection id matches the connection id that the server
  // chose when it sent the retry packet
  AckStates ackStates;
  auto packetQueue = bufToQueue(bytesWrittenToNetwork->clone());
  auto codecResult =
      makeEncryptedCodec(true)->parsePacket(packetQueue, ackStates);

  auto quicPacket = boost::get<QuicPacket>(&codecResult);
  auto regularQuicPacket = boost::get<RegularQuicPacket>(quicPacket);
  auto header = boost::get<LongHeader>(regularQuicPacket->header);
  EXPECT_EQ(header.getHeaderType(), LongHeader::Types::Initial);
  EXPECT_TRUE(header.hasToken());
  folly::IOBufEqualTo eq;
  EXPECT_TRUE(
      eq(header.getToken()->clone(),
         IOBuf::copyBuffer("this is a retry token :)")));
  EXPECT_EQ(header.getDestinationConnId(), serverChosenConnId);

  eventbase_->loopOnce();
  client->close(folly::none);
}

TEST_F(
    QuicClientTransportVersionAndRetryTest,
    VersionNegotiationPacketNotSupported) {
  StreamId streamId = *client->createBidirectionalStream();

  client->setReadCallback(streamId, &readCb);

  auto write = IOBuf::copyBuffer("no");
  client->writeChain(streamId, write->clone(), true, false, &deliveryCallback);
  loopForWrites();
  auto packet = VersionNegotiationPacketBuilder(
                    *client->getConn().initialDestinationConnectionId,
                    *originalConnId,
                    {MVFST2})
                    .buildPacket();
  EXPECT_CALL(
      readCb,
      readError(streamId, IsError(LocalErrorCode::CONNECTION_ABANDONED)));
  EXPECT_CALL(deliveryCallback, onCanceled(streamId, write->length()));
  EXPECT_THROW(deliverData(packet.second->coalesce()), std::runtime_error);

  EXPECT_EQ(client->getConn().oneRttWriteCipher.get(), nullptr);
  EXPECT_CALL(clientConnCallback, onTransportReady()).Times(0);
  EXPECT_CALL(clientConnCallback, onReplaySafe()).Times(0);
  client->close(folly::none);
}

TEST_F(
    QuicClientTransportVersionAndRetryTest,
    VersionNegotiationPacketCurrentVersion) {
  StreamId streamId = *client->createBidirectionalStream();

  client->setReadCallback(streamId, &readCb);

  auto write = IOBuf::copyBuffer("no");
  client->writeChain(streamId, write->clone(), true, false, &deliveryCallback);
  loopForWrites();

  auto packet = VersionNegotiationPacketBuilder(
                    *client->getConn().initialDestinationConnectionId,
                    *originalConnId,
                    {QuicVersion::MVFST})
                    .buildPacket();
  EXPECT_THROW(deliverData(packet.second->coalesce()), std::runtime_error);
  client->close(folly::none);
}

TEST_F(QuicClientTransportVersionAndRetryTest, UnencryptedStreamData) {
  StreamId streamId = *client->createBidirectionalStream();
  auto expected = IOBuf::copyBuffer("hello");
  PacketNum nextPacketNum = appDataPacketNum++;
  auto packet = packetToBufCleartext(
      createStreamPacket(
          *serverChosenConnId /* src */,
          *originalConnId /* dest */,
          nextPacketNum,
          streamId,
          *expected,
          getInitialCipher().getCipherOverhead(),
          0 /* largestAcked */,
          std::make_pair(LongHeader::Types::Initial, QuicVersion::MVFST)),
      getInitialCipher(),
      getInitialHeaderCipher(),
      nextPacketNum);
  EXPECT_THROW(deliverData(packet->coalesce()), std::runtime_error);
}

TEST_F(QuicClientTransportVersionAndRetryTest, UnencryptedAckData) {
  IntervalSet<PacketNum> acks = {{1, 2}};
  auto expected = IOBuf::copyBuffer("hello");
  PacketNum nextPacketNum = initialPacketNum++;
  LongHeader header(
      LongHeader::Types::Initial,
      getTestConnectionId(),
      *client->getConn().clientConnectionId,
      nextPacketNum,
      version);
  RegularQuicPacketBuilder builder(
      kDefaultUDPSendPacketLen, std::move(header), 0 /* largestAcked */);
  DCHECK(builder.canBuildPacket());
  AckFrameMetaData ackData(acks, 0us, 0);
  writeAckFrame(ackData, builder);
  auto packet = packetToBufCleartext(
      std::move(builder).buildPacket(),
      getInitialCipher(),
      getInitialHeaderCipher(),
      nextPacketNum);
  EXPECT_NO_THROW(deliverData(packet->coalesce()));
}

Buf getHandshakePacketWithFrame(
    QuicWriteFrame frame,
    ConnectionId srcConnId,
    ConnectionId destConnId,
    const Aead& serverWriteCipher,
    const PacketNumberCipher& headerCipher) {
  PacketNum packetNum = folly::Random::rand32();
  LongHeader header(
      LongHeader::Types::Initial,
      srcConnId,
      destConnId,
      packetNum,
      QuicVersion::MVFST);
  RegularQuicPacketBuilder builder(
      kDefaultUDPSendPacketLen,
      std::move(header),
      packetNum / 2 /* largestAcked */);
  builder.setCipherOverhead(serverWriteCipher.getCipherOverhead());
  writeFrame(std::move(frame), builder);
  return packetToBufCleartext(
      std::move(builder).buildPacket(),
      serverWriteCipher,
      headerCipher,
      packetNum);
}

TEST_F(QuicClientTransportVersionAndRetryTest, FrameNotAllowed) {
  StreamId streamId = *client->createBidirectionalStream();
  auto data = IOBuf::copyBuffer("data");

  auto clientConnectionId = *client->getConn().clientConnectionId;
  auto serverConnId = *serverChosenConnId;
  serverConnId.data()[0] = ~serverConnId.data()[0];

  EXPECT_THROW(
      deliverData(getHandshakePacketWithFrame(
                      MaxStreamDataFrame(streamId, 100),
                      serverConnId /* src */,
                      clientConnectionId /* dest */,
                      getInitialCipher(),
                      getInitialHeaderCipher())
                      ->coalesce()),
      std::runtime_error);
  EXPECT_TRUE(client->error());
  EXPECT_EQ(client->getConn().clientConnectionId, *originalConnId);
}

TEST_F(QuicClientTransportAfterStartTest, SendReset) {
  IntervalSet<PacketNum> sentPackets;
  StreamId streamId = client->createBidirectionalStream().value();
  client->setReadCallback(streamId, &readCb);
  client->registerDeliveryCallback(streamId, 100, &deliveryCallback);
  EXPECT_CALL(deliveryCallback, onCanceled(streamId, 100));
  EXPECT_CALL(readCb, readError(streamId, _));
  client->resetStream(streamId, GenericApplicationErrorCode::UNKNOWN);
  loopForWrites();
  verifyShortPackets(sentPackets);

  const auto& readCbs = client->getReadCallbacks();
  const auto& conn = client->getConn();
  // ReadCallbacks are not affected by reseting send state
  EXPECT_EQ(1, readCbs.count(streamId));
  // readable list can still be populated after a reset.
  EXPECT_FALSE(conn.streamManager->writableContains(streamId));
  auto packet = packetToBuf(createAckPacket(
      client->getNonConstConn(),
      ++appDataPacketNum,
      sentPackets,
      PacketNumberSpace::AppData));
  deliverData(packet->coalesce());
  // Stream is not yet closed because ingress state machine is open
  EXPECT_TRUE(conn.streamManager->streamExists(streamId));
  client->close(folly::none);
  EXPECT_TRUE(client->isClosed());
}

RegularQuicWritePacket* findPacketWithStream(
    QuicConnectionStateBase& conn,
    StreamId streamId) {
  auto op = findOutstandingPacket(conn, [=](OutstandingPacket& packet) {
    for (auto& frame : packet.packet.frames) {
      bool tryPacket = folly::variant_match(
          frame,
          [streamId](WriteStreamFrame& streamFrame) {
            return streamFrame.streamId == streamId;
          },
          [](auto&) { return false; });
      if (tryPacket) {
        return true;
      }
    }
    return false;
  });
  if (op) {
    return &(op->packet);
  }
  return nullptr;
}

TEST_F(QuicClientTransportAfterStartTest, ResetClearsPendingLoss) {
  StreamId streamId = client->createBidirectionalStream().value();
  client->setReadCallback(streamId, &readCb);
  SCOPE_EXIT {
    client->close(folly::none);
  };
  client->writeChain(streamId, IOBuf::copyBuffer("hello"), true, false);
  loopForWrites();
  ASSERT_FALSE(client->getConn().outstandingPackets.empty());

  RegularQuicWritePacket* forceLossPacket =
      CHECK_NOTNULL(findPacketWithStream(client->getNonConstConn(), streamId));
  auto packetNum = folly::variant_match(
      forceLossPacket->header,
      [](const auto& h) { return h.getPacketSequenceNum(); });
  markPacketLoss(client->getNonConstConn(), *forceLossPacket, false, packetNum);
  auto& pendingLossStreams = client->getConn().streamManager->lossStreams();
  auto it =
      std::find(pendingLossStreams.begin(), pendingLossStreams.end(), streamId);
  ASSERT_TRUE(it != pendingLossStreams.end());

  client->resetStream(streamId, GenericApplicationErrorCode::UNKNOWN);
  it =
      std::find(pendingLossStreams.begin(), pendingLossStreams.end(), streamId);
  ASSERT_TRUE(it == pendingLossStreams.end());
}

TEST_F(QuicClientTransportAfterStartTest, LossAfterResetStream) {
  StreamId streamId = client->createBidirectionalStream().value();
  client->setReadCallback(streamId, &readCb);
  SCOPE_EXIT {
    client->close(folly::none);
  };
  client->writeChain(streamId, IOBuf::copyBuffer("hello"), true, false);
  loopForWrites();
  ASSERT_FALSE(client->getConn().outstandingPackets.empty());

  client->resetStream(streamId, GenericApplicationErrorCode::UNKNOWN);

  RegularQuicWritePacket* forceLossPacket =
      CHECK_NOTNULL(findPacketWithStream(client->getNonConstConn(), streamId));
  auto packetNum = folly::variant_match(
      forceLossPacket->header,
      [](const auto& h) { return h.getPacketSequenceNum(); });
  markPacketLoss(client->getNonConstConn(), *forceLossPacket, false, packetNum);
  auto stream = CHECK_NOTNULL(
      client->getNonConstConn().streamManager->getStream(streamId));
  ASSERT_TRUE(stream->lossBuffer.empty());
  auto& pendingLossStreams = client->getConn().streamManager->lossStreams();
  auto it =
      std::find(pendingLossStreams.begin(), pendingLossStreams.end(), streamId);
  ASSERT_TRUE(it == pendingLossStreams.end());
}

TEST_F(QuicClientTransportAfterStartTest, SendResetAfterEom) {
  IntervalSet<PacketNum> sentPackets;
  StreamId streamId = client->createBidirectionalStream().value();
  client->setReadCallback(streamId, &readCb);
  client->registerDeliveryCallback(streamId, 100, &deliveryCallback);
  EXPECT_CALL(deliveryCallback, onCanceled(streamId, 100));
  client->writeChain(streamId, IOBuf::copyBuffer("hello"), true, false);

  client->resetStream(streamId, GenericApplicationErrorCode::UNKNOWN);
  loopForWrites();
  verifyShortPackets(sentPackets);
  const auto& readCbs = client->getReadCallbacks();
  const auto& conn = client->getConn();
  // ReadCallback are not affected by reseting send state.
  EXPECT_EQ(1, readCbs.count(streamId));
  // readable list can still be populated after a reset.
  EXPECT_FALSE(conn.streamManager->writableContains(streamId));

  auto packet = packetToBuf(createAckPacket(
      client->getNonConstConn(),
      ++appDataPacketNum,
      sentPackets,
      PacketNumberSpace::AppData));
  deliverData(packet->coalesce());
  // Stream still exists since ingress state machine is still open
  EXPECT_TRUE(conn.streamManager->streamExists(streamId));
  client->close(folly::none);
  EXPECT_TRUE(client->isClosed());
}

TEST_F(QuicClientTransportAfterStartTest, HalfClosedLocalToClosed) {
  IntervalSet<PacketNum> sentPackets;
  StreamId streamId = client->createBidirectionalStream().value();
  client->setReadCallback(streamId, &readCb);
  auto data = test::buildRandomInputData(10);
  client->writeChain(streamId, data->clone(), true, false, &deliveryCallback);
  loopForWrites();

  verifyShortPackets(sentPackets);

  const auto& conn = client->getConn();
  EXPECT_CALL(deliveryCallback, onDeliveryAck(streamId, 10, _)).Times(1);
  auto ackPacket = packetToBuf(createAckPacket(
      client->getNonConstConn(),
      ++appDataPacketNum,
      sentPackets,
      PacketNumberSpace::AppData));
  deliverData(ackPacket->coalesce());
  EXPECT_FALSE(conn.streamManager->deliverableContains(streamId));

  bool dataDelivered = false;
  EXPECT_CALL(readCb, readAvailable(streamId)).WillOnce(Invoke([&](auto) {
    auto readData = client->read(streamId, 100);
    auto copy = readData->first->clone();
    dataDelivered = true;
    eventbase_->terminateLoopSoon();
  }));
  auto packet = packetToBuf(createStreamPacket(
      *serverChosenConnId /* src */,
      *originalConnId /* dest */,
      appDataPacketNum++,
      streamId,
      *data,
      0 /* cipherOverhead */,
      0 /* largestAcked */));
  deliverData(packet->coalesce());
  if (!dataDelivered) {
    eventbase_->loopForever();
  }
  EXPECT_TRUE(dataDelivered);
  const auto& readCbs = client->getReadCallbacks();
  EXPECT_EQ(0, readCbs.count(streamId));
  EXPECT_EQ(0, conn.streamManager->readableStreams().count(streamId));
  EXPECT_FALSE(conn.streamManager->streamExists(streamId));
  client->close(folly::none);
  EXPECT_TRUE(client->isClosed());
}

TEST_F(QuicClientTransportAfterStartTest, SendResetSyncOnAck) {
  IntervalSet<PacketNum> sentPackets;
  StreamId streamId = client->createBidirectionalStream().value();
  StreamId streamId2 = client->createBidirectionalStream().value();

  MockDeliveryCallback deliveryCallback2;
  auto data = IOBuf::copyBuffer("hello");
  client->writeChain(streamId, data->clone(), true, false, &deliveryCallback);
  client->writeChain(streamId2, data->clone(), true, false, &deliveryCallback2);

  EXPECT_CALL(deliveryCallback, onDeliveryAck(streamId, _, _))
      .WillOnce(Invoke([&](auto, auto, auto) {
        client->resetStream(streamId, GenericApplicationErrorCode::UNKNOWN);
        client->resetStream(streamId2, GenericApplicationErrorCode::UNKNOWN);
      }));
  auto packet1 = packetToBuf(createStreamPacket(
      *serverChosenConnId /* src */,
      *originalConnId /* dest */,
      appDataPacketNum++,
      streamId,
      *data,
      0 /* cipherOverhead */,
      0 /* largestAcked */));
  auto packet2 = packetToBuf(createStreamPacket(
      *serverChosenConnId /* src */,
      *originalConnId /* dest */,
      appDataPacketNum++,
      streamId2,
      *data,
      0 /* cipherOverhead */,
      0 /* largestAcked */));
  deliverData(packet1->coalesce());
  deliverData(packet2->coalesce());
  loopForWrites();
  verifyShortPackets(sentPackets);

  const auto& readCbs = client->getReadCallbacks();
  const auto& conn = client->getConn();
  EXPECT_EQ(0, readCbs.count(streamId));
  // readable list can still be populated after a reset.
  EXPECT_FALSE(conn.streamManager->writableContains(streamId));
  auto packet = packetToBuf(createAckPacket(
      client->getNonConstConn(),
      ++appDataPacketNum,
      sentPackets,
      PacketNumberSpace::AppData));
  deliverData(packet->coalesce());
  // Stream should be closed after it received the ack for rst
  EXPECT_FALSE(conn.streamManager->streamExists(streamId));
  client->close(folly::none);
  EXPECT_TRUE(client->isClosed());
}

TEST_F(QuicClientTransportAfterStartTest, HalfClosedRemoteToClosed) {
  StreamId streamId = client->createBidirectionalStream().value();
  client->setReadCallback(streamId, &readCb);
  auto data = test::buildRandomInputData(10);
  auto packet = packetToBuf(createStreamPacket(
      *serverChosenConnId /* src */,
      *originalConnId /* dest */,
      appDataPacketNum++,
      streamId,
      *data,
      0 /* cipherOverhead */,
      0 /* largestAcked */));

  bool dataDelivered = false;
  EXPECT_CALL(readCb, readAvailable(streamId)).WillOnce(Invoke([&](auto) {
    auto readData = client->read(streamId, 100);
    auto copy = readData->first->clone();
    dataDelivered = true;
    eventbase_->terminateLoopSoon();
  }));
  const auto& conn = client->getConn();
  deliverData(packet->coalesce());
  if (!dataDelivered) {
    eventbase_->loopForever();
  }
  EXPECT_TRUE(dataDelivered);
  const auto& readCbs = client->getReadCallbacks();
  EXPECT_EQ(readCbs.count(streamId), 1);
  EXPECT_EQ(conn.streamManager->readableStreams().count(streamId), 0);

  IntervalSet<PacketNum> sentPackets;
  client->writeChain(streamId, data->clone(), true, false, &deliveryCallback);
  loopForWrites();

  verifyShortPackets(sentPackets);

  EXPECT_CALL(deliveryCallback, onDeliveryAck(streamId, 10, _)).Times(1);
  auto ackPacket = packetToBuf(createAckPacket(
      client->getNonConstConn(),
      ++appDataPacketNum,
      sentPackets,
      PacketNumberSpace::AppData));
  deliverData(ackPacket->coalesce());
  EXPECT_FALSE(conn.streamManager->hasDeliverable());
  EXPECT_FALSE(conn.streamManager->streamExists(streamId));
  EXPECT_EQ(readCbs.count(streamId), 0);
  client->close(folly::none);
  EXPECT_TRUE(client->isClosed());
}

TEST_F(QuicClientTransportAfterStartTest, ReceiveConnectionClose) {
  ShortHeader header(
      ProtectionType::KeyPhaseZero, *originalConnId, appDataPacketNum++);
  RegularQuicPacketBuilder builder(
      client->getConn().udpSendPacketLen,
      std::move(header),
      0 /* largestAcked */);
  ConnectionCloseFrame connClose(
      TransportErrorCode::NO_ERROR, "Stand clear of the closing doors, please");
  writeFrame(std::move(connClose), builder);
  auto packet = packetToBuf(std::move(builder).buildPacket());
  EXPECT_CALL(clientConnCallback, onConnectionEnd());
  deliverDataWithoutErrorCheck(packet->coalesce());
  // Now the transport should be closed
  EXPECT_EQ(
      QuicErrorCode(TransportErrorCode::NO_ERROR),
      client->getConn().localConnectionError->first);
  EXPECT_TRUE(client->isClosed());
  EXPECT_TRUE(verifyFramePresent<ConnectionCloseFrame>(
      socketWrites, *makeHandshakeCodec()));
}

TEST_F(QuicClientTransportAfterStartTest, ReceiveApplicationClose) {
  ShortHeader header(
      ProtectionType::KeyPhaseZero, *originalConnId, appDataPacketNum++);
  RegularQuicPacketBuilder builder(
      client->getConn().udpSendPacketLen,
      std::move(header),
      0 /* largestAcked */);
  ApplicationCloseFrame appClose(
      GenericApplicationErrorCode::UNKNOWN,
      "Stand clear of the closing doors, please");
  writeFrame(std::move(appClose), builder);
  auto packet = packetToBuf(std::move(builder).buildPacket());
  EXPECT_FALSE(client->isClosed());
  socketWrites.clear();

  EXPECT_CALL(
      clientConnCallback,
      onConnectionError(IsAppError(GenericApplicationErrorCode::UNKNOWN)));
  deliverDataWithoutErrorCheck(packet->coalesce());
  // Now the transport should be closed
  EXPECT_EQ(
      QuicErrorCode(TransportErrorCode::NO_ERROR),
      client->getConn().localConnectionError->first);
  EXPECT_TRUE(client->isClosed());
  EXPECT_TRUE(verifyFramePresent<ConnectionCloseFrame>(
      socketWrites, *makeHandshakeCodec()));
}

TEST_F(QuicClientTransportAfterStartTest, DestroyWithoutClosing) {
  StreamId streamId = client->createBidirectionalStream().value();

  client->setReadCallback(streamId, &readCb);

  EXPECT_CALL(clientConnCallback, onConnectionError(_)).Times(0);
  EXPECT_CALL(clientConnCallback, onConnectionEnd());

  auto write = IOBuf::copyBuffer("no");
  client->writeChain(streamId, write->clone(), true, false, &deliveryCallback);
  loopForWrites();

  EXPECT_CALL(deliveryCallback, onCanceled(_, _));
  EXPECT_CALL(readCb, readError(_, _));
}

TEST_F(QuicClientTransportAfterStartTest, DestroyWhileDraining) {
  StreamId streamId = client->createBidirectionalStream().value();

  client->setReadCallback(streamId, &readCb);

  auto write = IOBuf::copyBuffer("no");
  client->writeChain(streamId, write->clone(), true, false, &deliveryCallback);

  loopForWrites();
  EXPECT_CALL(clientConnCallback, onConnectionError(_)).Times(0);
  EXPECT_CALL(clientConnCallback, onConnectionEnd()).Times(0);
  // Go into draining with one active stream.

  EXPECT_CALL(deliveryCallback, onCanceled(_, _));
  EXPECT_CALL(readCb, readError(_, _));
  client->close(folly::none);
}

TEST_F(QuicClientTransportAfterStartTest, CloseNowWhileDraining) {
  // Drain first with no active streams
  auto err = std::make_pair<QuicErrorCode, std::string>(
      QuicErrorCode(LocalErrorCode::INTERNAL_ERROR),
      toString(LocalErrorCode::INTERNAL_ERROR));
  client->close(err);
  EXPECT_TRUE(client->isDraining());
  client->closeNow(err);
  EXPECT_FALSE(client->isDraining());
  client.reset();
  EXPECT_TRUE(destructionCallback->isDestroyed());
}

TEST_F(QuicClientTransportAfterStartTest, ExpiredDrainTimeout) {
  auto err = std::make_pair<QuicErrorCode, std::string>(
      QuicErrorCode(LocalErrorCode::INTERNAL_ERROR),
      toString(LocalErrorCode::INTERNAL_ERROR));
  client->close(err);
  EXPECT_TRUE(client->isDraining());
  EXPECT_FALSE(destructionCallback->isDestroyed());
  client->drainTimeout().timeoutExpired();
  client.reset();
  EXPECT_TRUE(destructionCallback->isDestroyed());
}

TEST_F(QuicClientTransportAfterStartTest, WriteThrowsExceptionWhileDraining) {
  // Drain first with no active streams
  auto err = std::make_pair<QuicErrorCode, std::string>(
      QuicErrorCode(LocalErrorCode::INTERNAL_ERROR),
      toString(LocalErrorCode::INTERNAL_ERROR));
  EXPECT_CALL(*sock, write(_, _)).WillRepeatedly(SetErrnoAndReturn(EBADF, -1));
  client->close(err);
  EXPECT_FALSE(client->idleTimeout().isScheduled());
}

TEST_F(QuicClientTransportAfterStartTest, DestroyEvbWhileLossTimeoutActive) {
  StreamId streamId = client->createBidirectionalStream().value();

  client->setReadCallback(streamId, &readCb);

  auto write = IOBuf::copyBuffer("no");
  client->writeChain(streamId, write->clone(), true, false);
  loopForWrites();
  EXPECT_TRUE(client->lossTimeout().isScheduled());
  eventbase_.reset();
}

TEST_F(QuicClientTransportAfterStartTest, SetCongestionControl) {
  // Default: Cubic
  auto cc = client->getConn().congestionController.get();
  EXPECT_EQ(CongestionControlType::Cubic, cc->type());

  // Change to Reno
  client->setCongestionControl(CongestionControlType::NewReno);
  cc = client->getConn().congestionController.get();
  EXPECT_EQ(CongestionControlType::NewReno, cc->type());

  // Change back to Cubic:
  client->setCongestionControl(CongestionControlType::Cubic);
  cc = client->getConn().congestionController.get();
  EXPECT_EQ(CongestionControlType::Cubic, cc->type());
}

TEST_F(
    QuicClientTransportAfterStartTest,
    TestOneRttPacketWillNotRescheduleHandshakeAlarm) {
  EXPECT_TRUE(client->lossTimeout().isScheduled());
  auto timeRemaining1 = client->lossTimeout().getTimeRemaining();

  auto sleepAmountMillis = 10;
  usleep(sleepAmountMillis * 1000);
  auto streamId = client->createBidirectionalStream().value();
  client->writeChain(streamId, IOBuf::copyBuffer("hello"), true, false);
  loopForWrites();

  EXPECT_TRUE(client->lossTimeout().isScheduled());
  auto timeRemaining2 = client->lossTimeout().getTimeRemaining();
  EXPECT_GE(timeRemaining1.count() - timeRemaining2.count(), sleepAmountMillis);
}

TEST_F(QuicClientVersionParamInvalidTest, InvalidVersion) {
  EXPECT_THROW(performFakeHandshake(), std::runtime_error);
}

class QuicClientTransportPskCacheTest
    : public QuicClientTransportAfterStartTest {
 public:
  void SetUp() override {
    mockPskCache_ = std::make_shared<MockQuicPskCache>();
    client->setPskCache(mockPskCache_);
    QuicClientTransportAfterStartTest::SetUp();
  }

 protected:
  std::shared_ptr<MockQuicPskCache> mockPskCache_;
};

TEST_F(QuicClientTransportPskCacheTest, TestOnNewCachedPsk) {
  std::string appParams = "QPACK params";
  EXPECT_CALL(clientConnCallback, serializeEarlyDataAppParams())
      .WillOnce(Invoke([=]() { return folly::IOBuf::copyBuffer(appParams); }));
  EXPECT_CALL(*mockPskCache_, putPsk(hostname_, _))
      .WillOnce(Invoke([=](const std::string&, QuicCachedPsk psk) {
        EXPECT_EQ(psk.appParams, appParams);
      }));
  mockClientHandshake->triggerOnNewCachedPsk();
}

TEST_F(QuicClientTransportPskCacheTest, TestTwoOnNewCachedPsk) {
  std::string appParams1 = "QPACK params1";
  EXPECT_CALL(clientConnCallback, serializeEarlyDataAppParams())
      .WillOnce(Invoke([=]() { return folly::IOBuf::copyBuffer(appParams1); }));
  EXPECT_CALL(*mockPskCache_, putPsk(hostname_, _))
      .WillOnce(Invoke([=](const std::string&, QuicCachedPsk psk) {
        auto& params = psk.transportParams;
        EXPECT_EQ(params.initialMaxData, kDefaultConnectionWindowSize);
        EXPECT_EQ(
            params.initialMaxStreamDataBidiLocal, kDefaultStreamWindowSize);
        EXPECT_EQ(
            params.initialMaxStreamDataBidiRemote, kDefaultStreamWindowSize);
        EXPECT_EQ(params.initialMaxStreamDataUni, kDefaultStreamWindowSize);
        EXPECT_EQ(psk.appParams, appParams1);
      }));
  mockClientHandshake->triggerOnNewCachedPsk();

  client->getNonConstConn().flowControlState.peerAdvertisedMaxOffset = 1234;
  client->getNonConstConn()
      .flowControlState.peerAdvertisedInitialMaxStreamOffsetBidiLocal = 123;
  client->getNonConstConn()
      .flowControlState.peerAdvertisedInitialMaxStreamOffsetBidiRemote = 123;
  client->getNonConstConn()
      .flowControlState.peerAdvertisedInitialMaxStreamOffsetUni = 123;

  std::string appParams2 = "QPACK params2";
  EXPECT_CALL(clientConnCallback, serializeEarlyDataAppParams())
      .WillOnce(Invoke([=]() { return folly::IOBuf::copyBuffer(appParams2); }));
  EXPECT_CALL(*mockPskCache_, putPsk(hostname_, _))
      .WillOnce(Invoke([=](const std::string&, QuicCachedPsk psk) {
        auto& params = psk.transportParams;
        EXPECT_EQ(params.initialMaxData, kDefaultConnectionWindowSize);
        EXPECT_EQ(
            params.initialMaxStreamDataBidiLocal, kDefaultStreamWindowSize);
        EXPECT_EQ(
            params.initialMaxStreamDataBidiRemote, kDefaultStreamWindowSize);
        EXPECT_EQ(params.initialMaxStreamDataUni, kDefaultStreamWindowSize);
        EXPECT_EQ(psk.appParams, appParams2);
      }));
  mockClientHandshake->triggerOnNewCachedPsk();
}

class QuicZeroRttClientTest : public QuicClientTransportAfterStartTest {
 public:
  ~QuicZeroRttClientTest() override = default;

  void setFakeHandshakeCiphers() override {
    auto readAead = test::createNoOpFizzAead();
    auto writeAead = test::createNoOpFizzAead();
    auto zeroAead = test::createNoOpFizzAead();
    auto handshakeReadAead = test::createNoOpFizzAead();
    auto handshakeWriteAead = test::createNoOpFizzAead();
    mockClientHandshake->setOneRttReadCipher(std::move(readAead));
    mockClientHandshake->setOneRttWriteCipher(std::move(writeAead));
    mockClientHandshake->setZeroRttWriteCipher(std::move(zeroAead));
    mockClientHandshake->setHandshakeReadCipher(std::move(handshakeReadAead));
    mockClientHandshake->setHandshakeWriteCipher(std::move(handshakeWriteAead));

    mockClientHandshake->setHandshakeReadHeaderCipher(
        test::createNoOpHeaderCipher());
    mockClientHandshake->setHandshakeWriteHeaderCipher(
        test::createNoOpHeaderCipher());
    mockClientHandshake->setOneRttWriteHeaderCipher(
        test::createNoOpHeaderCipher());
    mockClientHandshake->setOneRttReadHeaderCipher(
        test::createNoOpHeaderCipher());
    mockClientHandshake->setZeroRttWriteHeaderCipher(
        test::createNoOpHeaderCipher());
  }

  void start() override {
    TransportSettings clientSettings;
    // Ignore path mtu to test negotiation.
    clientSettings.canIgnorePathMTU = true;
    client->setTransportSettings(clientSettings);
    mockQuicPskCache_ = std::make_shared<MockQuicPskCache>();
    client->setPskCache(mockQuicPskCache_);
  }

  void startClient() {
    EXPECT_CALL(clientConnCallback, onTransportReady());
    client->start(&clientConnCallback);
    setConnectionIds();
    EXPECT_EQ(socketWrites.size(), 1);
    EXPECT_TRUE(
        verifyLongHeader(*socketWrites.at(0), LongHeader::Types::Initial));
    socketWrites.clear();
  }

  bool zeroRttPacketsOutstanding() {
    for (auto& packet : client->getNonConstConn().outstandingPackets) {
      bool isZeroRtt = folly::variant_match(
          packet.packet.header,
          [](const LongHeader& h) {
            return h.getProtectionType() == ProtectionType::ZeroRtt;
          },
          [](const ShortHeader&) { return false; });
      if (isZeroRtt) {
        return true;
      }
    }
    return false;
  }

 protected:
  std::shared_ptr<MockQuicPskCache> mockQuicPskCache_;
};

TEST_F(QuicZeroRttClientTest, TestReplaySafeCallback) {
  EXPECT_CALL(*mockQuicPskCache_, getPsk(hostname_))
      .WillOnce(InvokeWithoutArgs([]() {
        QuicCachedPsk quicCachedPsk;
        quicCachedPsk.transportParams.negotiatedVersion = QuicVersion::MVFST;
        quicCachedPsk.transportParams.initialMaxStreamDataBidiLocal =
            kDefaultStreamWindowSize;
        quicCachedPsk.transportParams.initialMaxStreamDataBidiRemote =
            kDefaultStreamWindowSize;
        quicCachedPsk.transportParams.initialMaxStreamDataUni =
            kDefaultStreamWindowSize;
        quicCachedPsk.transportParams.initialMaxData =
            kDefaultConnectionWindowSize;
        quicCachedPsk.transportParams.idleTimeout = kDefaultIdleTimeout.count();
        quicCachedPsk.transportParams.maxRecvPacketSize =
            kDefaultUDPReadBufferSize;
        quicCachedPsk.transportParams.initialMaxStreamsBidi =
            std::numeric_limits<uint32_t>::max();
        quicCachedPsk.transportParams.initialMaxStreamsUni =
            std::numeric_limits<uint32_t>::max();
        return quicCachedPsk;
      }));
  EXPECT_CALL(clientConnCallback, validateEarlyDataAppParams(_, _));
  startClient();

  auto initialUDPSendPacketLen = client->getConn().udpSendPacketLen;
  socketWrites.clear();
  auto streamId = client->createBidirectionalStream().value();
  client->writeChain(streamId, IOBuf::copyBuffer("hello"), true, false);
  loopForWrites();
  EXPECT_TRUE(zeroRttPacketsOutstanding());
  assertWritten(false, LongHeader::Types::ZeroRtt);
  EXPECT_CALL(clientConnCallback, onReplaySafe());
  recvServerHello();

  EXPECT_NE(client->getConn().zeroRttWriteCipher, nullptr);

  // All the data is still there.
  EXPECT_TRUE(zeroRttPacketsOutstanding());
  // Transport parameters did not change since zero rtt was accepted.
  verifyTransportParameters(
      kDefaultConnectionWindowSize,
      kDefaultStreamWindowSize,
      kDefaultIdleTimeout,
      kDefaultAckDelayExponent,
      initialUDPSendPacketLen);

  EXPECT_CALL(*mockQuicPskCache_, putPsk(hostname_, _))
      .WillOnce(Invoke([=](const std::string&, QuicCachedPsk psk) {
        auto& params = psk.transportParams;
        EXPECT_EQ(params.initialMaxData, kDefaultConnectionWindowSize);
        EXPECT_EQ(
            params.initialMaxStreamDataBidiLocal, kDefaultStreamWindowSize);
        EXPECT_EQ(
            params.initialMaxStreamDataBidiRemote, kDefaultStreamWindowSize);
        EXPECT_EQ(params.initialMaxStreamDataUni, kDefaultStreamWindowSize);
        EXPECT_EQ(
            params.initialMaxStreamsBidi, std::numeric_limits<uint32_t>::max());
        EXPECT_EQ(
            params.initialMaxStreamsUni, std::numeric_limits<uint32_t>::max());
      }));
  mockClientHandshake->triggerOnNewCachedPsk();
}

TEST_F(QuicZeroRttClientTest, TestZeroRttRejection) {
  EXPECT_CALL(*mockQuicPskCache_, getPsk(hostname_))
      .WillOnce(InvokeWithoutArgs([]() {
        QuicCachedPsk quicCachedPsk;
        quicCachedPsk.transportParams.negotiatedVersion = QuicVersion::MVFST;
        quicCachedPsk.transportParams.initialMaxStreamDataBidiLocal =
            kDefaultStreamWindowSize;
        quicCachedPsk.transportParams.initialMaxStreamDataBidiRemote =
            kDefaultStreamWindowSize;
        quicCachedPsk.transportParams.initialMaxStreamDataUni =
            kDefaultStreamWindowSize;
        quicCachedPsk.transportParams.initialMaxData =
            kDefaultConnectionWindowSize;
        quicCachedPsk.transportParams.idleTimeout = kDefaultIdleTimeout.count();
        quicCachedPsk.transportParams.maxRecvPacketSize =
            kDefaultUDPReadBufferSize;
        quicCachedPsk.transportParams.initialMaxStreamsBidi =
            std::numeric_limits<uint32_t>::max();
        quicCachedPsk.transportParams.initialMaxStreamsUni =
            std::numeric_limits<uint32_t>::max();
        return quicCachedPsk;
      }));
  EXPECT_CALL(clientConnCallback, validateEarlyDataAppParams(_, _));
  startClient();

  socketWrites.clear();
  auto streamId = client->createBidirectionalStream().value();
  client->writeChain(streamId, IOBuf::copyBuffer("hello"), true, false);
  loopForWrites();
  EXPECT_TRUE(zeroRttPacketsOutstanding());
  EXPECT_CALL(clientConnCallback, onReplaySafe());
  mockClientHandshake->setZeroRttRejected();
  EXPECT_CALL(*mockQuicPskCache_, removePsk(hostname_));
  recvServerHello();
  verifyTransportParameters(
      kDefaultConnectionWindowSize,
      kDefaultStreamWindowSize,
      kDefaultIdleTimeout,
      kDefaultAckDelayExponent,
      mockClientHandshake->maxRecvPacketSize);
  // Zero rtt data is declared lost.
  EXPECT_FALSE(zeroRttPacketsOutstanding());
  EXPECT_EQ(client->getConn().zeroRttWriteCipher, nullptr);
}

TEST_F(QuicZeroRttClientTest, TestZeroRttRejectionWithSmallerFlowControl) {
  EXPECT_CALL(*mockQuicPskCache_, getPsk(hostname_))
      .WillOnce(InvokeWithoutArgs([]() {
        QuicCachedPsk quicCachedPsk;
        quicCachedPsk.transportParams.negotiatedVersion = QuicVersion::MVFST;
        quicCachedPsk.transportParams.initialMaxStreamDataBidiLocal =
            kDefaultStreamWindowSize;
        quicCachedPsk.transportParams.initialMaxStreamDataBidiRemote =
            kDefaultStreamWindowSize;
        quicCachedPsk.transportParams.initialMaxStreamDataUni =
            kDefaultStreamWindowSize;
        quicCachedPsk.transportParams.initialMaxData =
            kDefaultConnectionWindowSize;
        quicCachedPsk.transportParams.idleTimeout = kDefaultIdleTimeout.count();
        quicCachedPsk.transportParams.maxRecvPacketSize =
            kDefaultUDPReadBufferSize;
        quicCachedPsk.transportParams.initialMaxStreamsBidi =
            std::numeric_limits<uint32_t>::max();
        quicCachedPsk.transportParams.initialMaxStreamsUni =
            std::numeric_limits<uint32_t>::max();
        return quicCachedPsk;
      }));
  EXPECT_CALL(clientConnCallback, validateEarlyDataAppParams(_, _));
  startClient();

  mockClientHandshake->maxInitialStreamData = 10;
  socketWrites.clear();
  auto streamId = client->createBidirectionalStream().value();
  client->writeChain(streamId, IOBuf::copyBuffer("hello"), true, false);
  loopForWrites();
  EXPECT_TRUE(zeroRttPacketsOutstanding());
  mockClientHandshake->setZeroRttRejected();
  EXPECT_CALL(*mockQuicPskCache_, removePsk(hostname_));
  EXPECT_THROW(recvServerHello(), std::runtime_error);
}

TEST_F(
    QuicZeroRttClientTest,
    TestZeroRttPacketWillNotRescheduleHandshakeAlarm) {
  EXPECT_CALL(*mockQuicPskCache_, getPsk(hostname_))
      .WillOnce(InvokeWithoutArgs([]() {
        QuicCachedPsk quicCachedPsk;
        quicCachedPsk.transportParams.negotiatedVersion = QuicVersion::MVFST;
        quicCachedPsk.transportParams.initialMaxStreamDataBidiLocal =
            kDefaultStreamWindowSize;
        quicCachedPsk.transportParams.initialMaxStreamDataBidiRemote =
            kDefaultStreamWindowSize;
        quicCachedPsk.transportParams.initialMaxStreamDataUni =
            kDefaultStreamWindowSize;
        quicCachedPsk.transportParams.initialMaxData =
            kDefaultConnectionWindowSize;
        quicCachedPsk.transportParams.idleTimeout = kDefaultIdleTimeout.count();
        quicCachedPsk.transportParams.maxRecvPacketSize =
            kDefaultUDPReadBufferSize;
        quicCachedPsk.transportParams.initialMaxStreamsBidi =
            std::numeric_limits<uint32_t>::max();
        quicCachedPsk.transportParams.initialMaxStreamsUni =
            std::numeric_limits<uint32_t>::max();
        return quicCachedPsk;
      }));
  EXPECT_CALL(clientConnCallback, validateEarlyDataAppParams(_, _));
  startClient();

  EXPECT_TRUE(client->lossTimeout().isScheduled());
  auto timeRemaining1 = client->lossTimeout().getTimeRemaining();

  auto initialUDPSendPacketLen = client->getConn().udpSendPacketLen;
  socketWrites.clear();

  auto sleepAmountMillis = 10;
  usleep(sleepAmountMillis * 1000);
  auto streamId = client->createBidirectionalStream().value();
  client->writeChain(streamId, IOBuf::copyBuffer("hello"), true, false);
  loopForWrites();

  EXPECT_TRUE(client->lossTimeout().isScheduled());
  auto timeRemaining2 = client->lossTimeout().getTimeRemaining();
  EXPECT_GE(timeRemaining1.count() - timeRemaining2.count(), sleepAmountMillis);

  EXPECT_TRUE(zeroRttPacketsOutstanding());
  assertWritten(false, LongHeader::Types::ZeroRtt);
  EXPECT_CALL(clientConnCallback, onReplaySafe());
  recvServerHello();

  EXPECT_NE(client->getConn().zeroRttWriteCipher, nullptr);

  // All the data is still there.
  EXPECT_TRUE(zeroRttPacketsOutstanding());
  // Transport parameters did not change since zero rtt was accepted.
  verifyTransportParameters(
      kDefaultConnectionWindowSize,
      kDefaultStreamWindowSize,
      kDefaultIdleTimeout,
      kDefaultAckDelayExponent,
      initialUDPSendPacketLen);
}

class QuicProcessDataTest : public QuicClientTransportAfterStartTest {
 public:
  ~QuicProcessDataTest() override = default;

  void start() override {
    // force the server to declare that the version negotiated was invalid.;
    mockClientHandshake->negotiatedVersion = QuicVersion::QUIC_DRAFT;
    client->setSupportedVersions({QuicVersion::QUIC_DRAFT});
    client->start(&clientConnCallback);
    setConnectionIds();
  }
};

TEST_F(QuicProcessDataTest, ProcessDataWithGarbageAtEnd) {
  auto serverHello = IOBuf::copyBuffer("Fake SHLO");
  PacketNum nextPacketNum = initialPacketNum++;
  auto& aead = getInitialCipher();
  auto packet = createCryptoPacket(
      *serverChosenConnId,
      *originalConnId,
      nextPacketNum,
      QuicVersion::QUIC_DRAFT,
      ProtectionType::Initial,
      *serverHello,
      aead,
      0 /* largestAcked */);
  auto packetData = packetToBufCleartext(
      packet, aead, getInitialHeaderCipher(), nextPacketNum);
  packetData->prependChain(IOBuf::copyBuffer("garbage in"));
  deliverData(serverAddr, packetData->coalesce());
  verifyTransportParameters(
      kDefaultConnectionWindowSize,
      kDefaultStreamWindowSize,
      kDefaultIdleTimeout,
      kDefaultAckDelayExponent,
      mockClientHandshake->maxRecvPacketSize);
}

TEST_F(QuicProcessDataTest, ProcessDataHeaderOnly) {
  auto serverHello = IOBuf::copyBuffer("Fake SHLO");
  PacketNum nextPacketNum = initialPacketNum++;
  auto& aead = getInitialCipher();
  auto largestReceivedPacketNum =
      getAckState(client->getConn(), PacketNumberSpace::Handshake)
          .largestReceivedPacketNum;
  auto packet = createCryptoPacket(
      *serverChosenConnId,
      *originalConnId,
      nextPacketNum,
      QuicVersion::QUIC_DRAFT,
      ProtectionType::Initial,
      *serverHello,
      aead,
      0 /* largestAcked */);
  deliverData(serverAddr, packet.header->coalesce());
  EXPECT_EQ(
      getAckState(client->getConn(), PacketNumberSpace::Handshake)
          .largestReceivedPacketNum,
      largestReceivedPacketNum);
}

TEST(AsyncUDPSocketTest, CloseMultipleTimes) {
  class EmptyReadCallback : public AsyncUDPSocket::ReadCallback {
   public:
    void getReadBuffer(void**, size_t*) noexcept override {}
    void onDataAvailable(
        const folly::SocketAddress&,
        size_t,
        bool) noexcept override {}
    void onReadError(const AsyncSocketException&) noexcept override {}
    void onReadClosed() noexcept override {}
  };

  class EmptyErrMessageCallback : public AsyncUDPSocket::ErrMessageCallback {
   public:
    void errMessage(const cmsghdr&) noexcept override {}
    void errMessageError(const AsyncSocketException&) noexcept override {}
  };

  EventBase evb;
  AsyncUDPSocket socket(&evb);
  TransportSettings transportSettings;
  EmptyErrMessageCallback errMessageCallback;
  EmptyReadCallback readCallback;
  happyEyeballsSetUpSocket(
      socket,
      folly::SocketAddress("127.0.0.1", 12345),
      transportSettings,
      &errMessageCallback,
      &readCallback);

  socket.pauseRead();
  socket.close();
  socket.pauseRead();
  socket.close();
}
} // namespace test
} // namespace quic
