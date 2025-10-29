/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <folly/portability/GMock.h>
#include <folly/portability/GTest.h>

#include <fizz/protocol/clock/test/Mocks.h>
#include <folly/futures/Future.h>
#include <folly/io/SocketOptionMap.h>
#include <folly/io/async/ScopedEventBaseThread.h>
#include <quic/QuicConstants.h>
#include <quic/common/events/FollyQuicEventBase.h>
#include <quic/common/events/HighResQuicTimer.h>
#include <quic/common/udpsocket/FollyQuicAsyncUDPSocket.h>
#include <quic/congestion_control/CongestionControllerFactory.h>
#include <quic/fizz/client/handshake/test/MockQuicPskCache.h>
#include <quic/fizz/client/test/QuicClientTransportTestUtil.h>
#include <quic/fizz/handshake/FizzCryptoFactory.h>
#include <quic/handshake/TransportParameters.h>
#include <quic/handshake/test/Mocks.h>
#include <quic/happyeyeballs/QuicHappyEyeballsFunctions.h>
#include <quic/logging/FileQLogger.h>
#include <quic/logging/test/Mocks.h>
#include <quic/samples/echo/EchoHandler.h>
#include <quic/samples/echo/EchoServer.h>
#include <quic/server/QuicServer.h>

using namespace testing;
using namespace folly;
using namespace quic::samples;

namespace quic::test {

namespace {
std::vector<uint8_t> kInitialDstConnIdVecForRetryTest =
    {0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08};
} // namespace

MATCHER_P(BufMatches, buf, "") {
  folly::IOBufEqualTo eq;
  return eq(*arg, buf);
}

struct TestingParams {
  QuicVersion version;
  uint8_t dstConnIdSize;

  explicit TestingParams(QuicVersion versionIn, uint8_t dstConnIdSizeIn = 8)
      : version(versionIn), dstConnIdSize(dstConnIdSizeIn) {}
};

using StreamPair = std::pair<std::unique_ptr<folly::IOBuf>, StreamId>;

class QuicClientTransportIntegrationTest : public TestWithParam<TestingParams> {
 public:
  QuicClientTransportIntegrationTest() {
    qEvb_ = std::make_shared<FollyQuicEventBase>(&eventbase_);
  }

  void SetUp() override {
    // Fizz is the hostname for the server cert.
    hostname = "Fizz";
    serverCtx = test::createServerCtx();
    serverCtx->setSupportedAlpns({"h3", "hq"});
    server_ = createServer(ProcessId::ZERO);
    serverAddr = server_->getAddress();
    ON_CALL(clientConnSetupCallback, onTransportReady())
        .WillByDefault(Invoke([&] { connected_ = true; }));

    clientCtx = createClientContext();
    verifier = createTestCertificateVerifier();
    client = createClient();
  }

  QuicVersion getVersion() {
    return GetParam().version;
  }

  std::shared_ptr<fizz::client::FizzClientContext> createClientContext() {
    clientCtx = std::make_shared<fizz::client::FizzClientContext>();
    clientCtx->setSupportedAlpns({"h3"});
    clientCtx->setClock(std::make_shared<NiceMock<fizz::test::MockClock>>());
    return clientCtx;
  }

  std::shared_ptr<TestingQuicClientTransport> createClient() {
    pskCache_ = std::make_shared<BasicQuicPskCache>();

    auto sock = std::make_unique<FollyQuicAsyncUDPSocket>(qEvb_);
    auto fizzClientContext = FizzClientQuicHandshakeContext::Builder()
                                 .setFizzClientContext(clientCtx)
                                 .setCertificateVerifier(verifier)
                                 .setPskCache(pskCache_)
                                 .build();
    client = std::make_shared<TestingQuicClientTransport>(
        qEvb_,
        std::move(sock),
        std::move(fizzClientContext),
        GetParam().dstConnIdSize);
    client->setSupportedVersions({getVersion()});
    client->setCongestionControllerFactory(
        std::make_shared<DefaultCongestionControllerFactory>());
    client->setHostname(hostname);
    client->addNewPeerAddress(serverAddr);
    auto transportSettings = client->getTransportSettings();
    transportSettings.attemptEarlyData = true;
    transportSettings.removeStreamAfterEomCallbackUnset = true;
    transportSettings.dataPathType = DataPathType::ContinuousMemory;
    transportSettings.batchingMode = QuicBatchingMode::BATCHING_MODE_GSO;
    client->setTransportSettings(transportSettings);
    return client;
  }

  std::shared_ptr<QuicServer> createServer(
      ProcessId processId,
      bool withRetryPacket = false) {
    quic::TransportSettings transportSettings;
    transportSettings.zeroRttSourceTokenMatchingPolicy =
        ZeroRttSourceTokenMatchingPolicy::LIMIT_IF_NO_EXACT_MATCH;
    std::array<uint8_t, kRetryTokenSecretLength> secret{};
    folly::Random::secureRandom(secret.data(), secret.size());
    transportSettings.retryTokenSecret = secret;
    auto server = QuicServer::createQuicServer(transportSettings);

    auto statsFactory = std::make_unique<NiceMock<MockQuicStatsFactory>>();
    ON_CALL(*statsFactory, make()).WillByDefault(Invoke([&]() {
      auto newStatsCallback = std::make_unique<NiceMock<MockQuicStats>>();
      statsCallbacks_.push_back(newStatsCallback.get());
      return newStatsCallback;
    }));
    if (withRetryPacket) {
      server->setRateLimit([]() { return 0u; }, 1s);
    }
    server->setTransportStatsCallbackFactory(std::move(statsFactory));
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
    EXPECT_CALL(clientConnSetupCallback, onReplaySafe());
    EXPECT_CALL(clientConnSetupCallback, onFullHandshakeDone());
  }

  void expectStatsCallbacks() {
    quicStats_ = std::make_shared<MockQuicStats>();
    EXPECT_CALL(*quicStats_, onNewConnection()).Times(1);
    EXPECT_CALL(*quicStats_, onPacketReceived()).Times(AtLeast(1));
    EXPECT_CALL(*quicStats_, onPacketSent()).Times(AtLeast(1));
    EXPECT_CALL(*quicStats_, onNewQuicStream()).Times(1);
    EXPECT_CALL(*quicStats_, onQuicStreamClosed()).Times(1);
    EXPECT_CALL(*quicStats_, onRead(_)).Times(AtLeast(1));
    EXPECT_CALL(*quicStats_, onWrite(_)).Times(AtLeast(1));
    EXPECT_CALL(*quicStats_, onConnectionClose(_)).Times(1);
    client->setTransportStatsCallback(quicStats_);
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

  void checkTransportSummaryEvent(const std::shared_ptr<FileQLogger>& qLogger) {
    std::vector<int> indices =
        getQLogEventIndices(QLogEventType::TransportSummary, qLogger);
    EXPECT_EQ(indices.size(), 1);
    auto tmp = std::move(qLogger->logs[indices[0]]);
    auto event = dynamic_cast<QLogTransportSummaryEvent*>(tmp.get());

    uint64_t totalCryptoDataWritten = 0;
    uint64_t totalCryptoDataRecvd = 0;

    if (client->getConn().cryptoState) {
      totalCryptoDataWritten +=
          client->getConn().cryptoState->initialStream.currentWriteOffset;
      totalCryptoDataWritten +=
          client->getConn().cryptoState->handshakeStream.currentWriteOffset;
      totalCryptoDataWritten +=
          client->getConn().cryptoState->oneRttStream.currentWriteOffset;
      totalCryptoDataRecvd +=
          client->getConn().cryptoState->initialStream.maxOffsetObserved;
      totalCryptoDataRecvd +=
          client->getConn().cryptoState->handshakeStream.maxOffsetObserved;
      totalCryptoDataRecvd +=
          client->getConn().cryptoState->oneRttStream.maxOffsetObserved;
    }

    EXPECT_EQ(
        event->totalBytesSent, client->getConn().lossState.totalBytesSent);
    EXPECT_EQ(
        event->totalBytesRecvd, client->getConn().lossState.totalBytesRecvd);
    EXPECT_EQ(
        event->sumCurWriteOffset,
        client->getConn().flowControlState.sumCurWriteOffset);
    EXPECT_EQ(
        event->sumMaxObservedOffset,
        client->getConn().flowControlState.sumMaxObservedOffset);
    EXPECT_EQ(
        event->sumCurStreamBufferLen,
        client->getConn().flowControlState.sumCurStreamBufferLen);
    EXPECT_EQ(
        event->totalBytesRetransmitted,
        client->getConn().lossState.totalBytesRetransmitted);
    EXPECT_EQ(
        event->totalStreamBytesCloned,
        client->getConn().lossState.totalStreamBytesCloned);
    EXPECT_EQ(
        event->totalBytesCloned, client->getConn().lossState.totalBytesCloned);
    EXPECT_EQ(event->totalCryptoDataWritten, totalCryptoDataWritten);
    EXPECT_EQ(event->totalCryptoDataRecvd, totalCryptoDataRecvd);
  }

 protected:
  std::string hostname;
  folly::EventBase eventbase_;
  std::shared_ptr<FollyQuicEventBase> qEvb_;
  folly::SocketAddress serverAddr;
  NiceMock<MockConnectionSetupCallback> clientConnSetupCallback;
  NiceMock<MockConnectionCallback> clientConnCallback;
  NiceMock<MockReadCallback> readCb;
  std::shared_ptr<TestingQuicClientTransport> client;
  std::shared_ptr<fizz::server::FizzServerContext> serverCtx;
  std::shared_ptr<fizz::client::FizzClientContext> clientCtx;
  std::shared_ptr<fizz::CertificateVerifier> verifier;
  std::shared_ptr<QuicPskCache> pskCache_;
  std::shared_ptr<QuicServer> server_;
  bool connected_{false};
  std::shared_ptr<MockQuicStats> quicStats_;
  std::vector<MockQuicStats*> statsCallbacks_;
};

class StreamData {
 public:
  BufQueue data;

  folly::Promise<StreamPair> promise;
  StreamId id;

  explicit StreamData(StreamId id) : id(id) {}

  void setException(const QuicError& err) {
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
  auto readCallbackResult = client->setReadCallback(streamId, readCallback);
  if (!readCallbackResult.has_value()) {
    return folly::makeFuture<StreamPair>(
        folly::make_exception_wrapper<std::runtime_error>(
            "setReadCallback failed"));
  }
  auto writeResult = client->writeChain(streamId, data->clone(), true);
  if (!writeResult.has_value()) {
    return folly::makeFuture<StreamPair>(
        folly::make_exception_wrapper<std::runtime_error>("writeChain failed"));
  }
  auto streamData = new StreamData(streamId);
  auto dataCopy = std::shared_ptr<folly::IOBuf>(std::move(data));
  EXPECT_CALL(*readCallback, readAvailable(streamId))
      .WillRepeatedly(
          Invoke([c = client.get(), id = streamId, streamData, dataCopy](
                     auto) mutable {
            auto readData = c->read(id, 1000);
            auto copy = readData->first->clone();
            LOG(INFO) << "Client received data=" << copy->to<std::string>()
                      << " on stream=" << id
                      << " read=" << readData->first->computeChainDataLength()
                      << " sent=" << dataCopy->computeChainDataLength();
            streamData->append(std::move(readData->first), readData->second);
            if (readData->second) {
              auto clearCallbackResult = c->setReadCallback(id, nullptr);
              if (!clearCallbackResult.has_value()) {
                LOG(WARNING) << "Failed to clear read callback: "
                             << toString(clearCallbackResult.error());
              }
            }
          }));
  ON_CALL(*readCallback, readError(streamId, _))
      .WillByDefault(Invoke([streamData, this](auto sid, auto err) mutable {
        streamData->setException(err);
        auto clearErrorCallbackResult = client->setReadCallback(sid, nullptr);
        if (!clearErrorCallbackResult.has_value()) {
          LOG(WARNING) << "Failed to clear read callback on error: "
                       << toString(clearErrorCallbackResult.error());
        }
      }));
  return streamData->promise.getFuture().within(30s);
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
  expectStatsCallbacks();
  EXPECT_CALL(clientConnSetupCallback, onTransportReady()).WillOnce(Invoke([&] {
    CHECK(client->getConn().oneRttWriteCipher);
    EXPECT_EQ(client->getConn().peerConnectionIds.size(), 1);
    EXPECT_EQ(
        *client->getConn().serverConnectionId,
        client->getConn().peerConnectionIds[0].connId);
    eventbase_.terminateLoopSoon();
  }));
  client->start(&clientConnSetupCallback, &clientConnCallback);
  eventbase_.loopForever();

  auto streamId = client->createBidirectionalStream().value();
  auto data = IOBuf::copyBuffer("hello");
  auto expected = std::shared_ptr<IOBuf>(IOBuf::copyBuffer("echo "));
  expected->appendToChain(data->clone());
  sendRequestAndResponseAndWait(*expected, data->clone(), streamId, &readCb);
}

TEST_P(QuicClientTransportIntegrationTest, FlowControlLimitedTest) {
  expectTransportCallbacks();
  EXPECT_CALL(clientConnSetupCallback, onTransportReady()).WillOnce(Invoke([&] {
    CHECK(client->getConn().oneRttWriteCipher);
    eventbase_.terminateLoopSoon();
  }));
  client->start(&clientConnSetupCallback, &clientConnCallback);
  eventbase_.loopForever();

  auto streamId = client->createBidirectionalStream().value();
  auto setStreamFlowControlWindowResult =
      client->setStreamFlowControlWindow(streamId, 256);
  auto data = IOBuf::create(4096);
  data->append(4096);
  memset(data->writableData(), 'a', data->length());

  auto expected = std::shared_ptr<IOBuf>(IOBuf::copyBuffer("echo "));
  expected->appendToChain(data->clone());
  sendRequestAndResponseAndWait(*expected, data->clone(), streamId, &readCb);
}

TEST_P(QuicClientTransportIntegrationTest, ALPNTest) {
  EXPECT_CALL(clientConnSetupCallback, onTransportReady()).WillOnce(Invoke([&] {
    ASSERT_EQ(client->getAppProtocol(), "h3");
    client->close(std::nullopt);
    eventbase_.terminateLoopSoon();
  }));
  ASSERT_EQ(client->getAppProtocol(), std::nullopt);
  client->start(&clientConnSetupCallback, &clientConnCallback);
  eventbase_.loopForever();
}

TEST_P(QuicClientTransportIntegrationTest, TLSAlert) {
  verifier = nullptr;
  client = createClient();

  auto qLogger = std::make_shared<FileQLogger>(VantagePoint::Client);
  client->getNonConstConn().qLogger = qLogger;
  EXPECT_CALL(clientConnSetupCallback, onConnectionSetupError(_))
      .WillOnce(Invoke([&](const auto& errorCode) {
        LOG(ERROR) << "error: " << errorCode.message;
        const TransportErrorCode* transportError =
            errorCode.code.asTransportErrorCode();
        EXPECT_NE(transportError, nullptr);
        client->close(std::nullopt);
        this->checkTransportSummaryEvent(qLogger);

        eventbase_.terminateLoopSoon();
      }));

  ASSERT_EQ(client->getAppProtocol(), std::nullopt);

  client->start(&clientConnSetupCallback, &clientConnCallback);
  eventbase_.loopForever();
}

TEST_P(QuicClientTransportIntegrationTest, BadServerTest) {
  auto qLogger = std::make_shared<FileQLogger>(VantagePoint::Client);
  client->getNonConstConn().qLogger = qLogger;
  // Point the client to a bad server.
  client->addNewPeerAddress(SocketAddress("127.0.0.1", 14114));
  auto tp = client->getTransportSettings();
  tp.maxNumPTOs = 4;
  client->setTransportSettings(tp);
  EXPECT_CALL(clientConnSetupCallback, onConnectionSetupError(_))
      .WillOnce(Invoke([&](const auto& errorCode) {
        LOG(ERROR) << "error: " << errorCode.message;
        const LocalErrorCode* localError = errorCode.code.asLocalErrorCode();
        EXPECT_NE(localError, nullptr);
        this->checkTransportSummaryEvent(qLogger);
      }));
  client->start(&clientConnSetupCallback, &clientConnCallback);
  eventbase_.loop();
}

TEST_P(QuicClientTransportIntegrationTest, NetworkTestConnected) {
  expectTransportCallbacks();
  auto qLogger = std::make_shared<FileQLogger>(VantagePoint::Client);
  client->getNonConstConn().qLogger = qLogger;
  TransportSettings settings;
  settings.connectUDP = true;
  client->setTransportSettings(settings);
  EXPECT_CALL(clientConnSetupCallback, onTransportReady()).WillOnce(Invoke([&] {
    CHECK(client->getConn().oneRttWriteCipher);
    eventbase_.terminateLoopSoon();
  }));
  client->start(&clientConnSetupCallback, &clientConnCallback);
  eventbase_.loopForever();

  auto streamId = client->createBidirectionalStream().value();
  auto data = IOBuf::copyBuffer("hello");
  auto expected = std::shared_ptr<IOBuf>(IOBuf::copyBuffer("echo "));
  expected->appendToChain(data->clone());
  sendRequestAndResponseAndWait(*expected, data->clone(), streamId, &readCb);
}

TEST_P(QuicClientTransportIntegrationTest, SetTransportSettingsAfterStart) {
  expectTransportCallbacks();
  auto qLogger = std::make_shared<FileQLogger>(VantagePoint::Client);
  client->getNonConstConn().qLogger = qLogger;
  TransportSettings settings;
  settings.connectUDP = true;
  client->setTransportSettings(settings);
  EXPECT_CALL(clientConnSetupCallback, onTransportReady()).WillOnce(Invoke([&] {
    CHECK(client->getConn().oneRttWriteCipher);
    eventbase_.terminateLoopSoon();
  }));
  client->start(&clientConnSetupCallback, &clientConnCallback);
  eventbase_.loopForever();

  auto streamId = client->createBidirectionalStream().value();
  auto data = IOBuf::copyBuffer("hello");
  auto expected = std::shared_ptr<IOBuf>(IOBuf::copyBuffer("echo "));
  expected->appendToChain(data->clone());
  sendRequestAndResponseAndWait(*expected, data->clone(), streamId, &readCb);
  settings.connectUDP = false;
  client->setTransportSettings(settings);
  EXPECT_TRUE(client->getTransportSettings().connectUDP);
}

TEST_P(QuicClientTransportIntegrationTest, TestZeroRttSuccess) {
  auto cachedPsk = setupZeroRttOnClientCtx(*clientCtx, hostname);
  pskCache_->putPsk(hostname, cachedPsk);
  setupZeroRttOnServerCtx(*serverCtx, cachedPsk);
  // Change the ctx
  server_->setFizzContext(serverCtx);
  Optional<std::string> alpn = std::string("h3");
  bool performedValidation = false;
  client->setEarlyDataAppParamsFunctions(
      [&](const Optional<std::string>& alpnToValidate, const BufPtr&) {
        performedValidation = true;
        EXPECT_EQ(alpnToValidate, alpn);
        return true;
      },
      []() -> BufPtr { return nullptr; });

  // Set the onTransportReadyCallback before starting the client to guarantee
  // the callback is set by the time the handshake is started
  EXPECT_CALL(clientConnSetupCallback, onTransportReady()).WillOnce(Invoke([&] {
    ASSERT_EQ(client->getAppProtocol(), "h3");
    ASSERT_NE(
        client->getZeroRttState(),
        QuicClientTransport::ZeroRttAttemptState::Rejected);
    // The ZeroRTT onTransportReady() is scheduled on the event base. So if the
    // handshake completed quickly, the callback could happen after ZerRTT has
    // already been accepted. We only check the zeroRTTCipher if the callback is
    // early.
    if (client->getZeroRttState() ==
        QuicClientTransport::ZeroRttAttemptState::NotAttempted) {
      EXPECT_TRUE(client->getConn().zeroRttWriteCipher);
    }
  }));

  client->start(&clientConnSetupCallback, &clientConnCallback);
  EXPECT_TRUE(performedValidation);
  CHECK(client->getConn().zeroRttWriteCipher);
  EXPECT_TRUE(client->serverInitialParamsSet());
  EXPECT_EQ(
      client->peerAdvertisedInitialMaxData(),
      kDefaultConnectionFlowControlWindow);
  EXPECT_EQ(
      client->peerAdvertisedInitialMaxStreamDataBidiLocal(),
      kDefaultStreamFlowControlWindow);
  EXPECT_EQ(
      client->peerAdvertisedInitialMaxStreamDataBidiRemote(),
      kDefaultStreamFlowControlWindow);
  EXPECT_EQ(
      client->peerAdvertisedInitialMaxStreamDataUni(),
      kDefaultStreamFlowControlWindow);
  eventbase_.loopOnce();

  if (client->getZeroRttState() ==
      QuicClientTransport::ZeroRttAttemptState::NotAttempted) {
    EXPECT_TRUE(client->getConn().zeroRttWriteCipher);
    EXPECT_FALSE(client->replaySafe());
    EXPECT_CALL(clientConnSetupCallback, onReplaySafe());
  } else if (
      client->getZeroRttState() ==
      QuicClientTransport::ZeroRttAttemptState::Accepted) {
    EXPECT_FALSE(client->getConn().zeroRttWriteCipher);
    EXPECT_TRUE(client->replaySafe());
  } else {
    FAIL() << "Zero RTT rejected";
  }

  EXPECT_TRUE(client->good());

  auto streamId = client->createBidirectionalStream().value();
  auto data = IOBuf::copyBuffer("hello");
  auto expected = std::shared_ptr<IOBuf>(IOBuf::copyBuffer("echo "));
  expected->appendToChain(data->clone());
  sendRequestAndResponseAndWait(*expected, data->clone(), streamId, &readCb);
  EXPECT_FALSE(client->getConn().zeroRttWriteCipher);
  EXPECT_TRUE(client->getConn().statelessResetToken.has_value());
  EXPECT_EQ(
      client->getZeroRttState(),
      QuicClientTransport::ZeroRttAttemptState::Accepted);
  ;
}

TEST_P(QuicClientTransportIntegrationTest, ZeroRttRetryPacketTest) {
  /**
   * logic extrapolated from TestZeroRttSuccess and RetryPacket tests
   */
  auto retryServer = createServer(ProcessId::ONE, true);
  client->getNonConstConn().peerAddress = retryServer->getAddress();

  SCOPE_EXIT {
    retryServer->shutdown();
    retryServer = nullptr;
  };

  auto cachedPsk = setupZeroRttOnClientCtx(*clientCtx, hostname);
  pskCache_->putPsk(hostname, cachedPsk);
  setupZeroRttOnServerCtx(*serverCtx, cachedPsk);
  // Change the ctx
  retryServer->setFizzContext(serverCtx);

  std::vector<uint8_t> clientConnIdVec = {};
  ConnectionId clientConnId =
      ConnectionId::createAndMaybeCrash(clientConnIdVec);

  ConnectionId initialDstConnId =
      ConnectionId::createAndMaybeCrash(kInitialDstConnIdVecForRetryTest);

  auto qLogger = std::make_shared<FileQLogger>(VantagePoint::Client);
  client->getNonConstConn().qLogger = qLogger;
  client->getNonConstConn().readCodec->setClientConnectionId(clientConnId);
  client->getNonConstConn().initialDestinationConnectionId = initialDstConnId;
  client->getNonConstConn().originalDestinationConnectionId = initialDstConnId;
  client->setCongestionControllerFactory(
      std::make_shared<DefaultCongestionControllerFactory>());
  client->setCongestionControl(CongestionControlType::NewReno);

  Optional<std::string> alpn = std::string("h3");
  bool performedValidation = false;
  client->setEarlyDataAppParamsFunctions(
      [&](const Optional<std::string>& alpnToValidate, const BufPtr&) {
        performedValidation = true;
        EXPECT_EQ(alpnToValidate, alpn);
        return true;
      },
      []() -> BufPtr { return nullptr; });
  EXPECT_CALL(clientConnSetupCallback, onTransportReady()).WillOnce(Invoke([&] {
    ASSERT_EQ(client->getAppProtocol(), "h3");
    CHECK(client->getConn().zeroRttWriteCipher);
  }));
  client->start(&clientConnSetupCallback, &clientConnCallback);
  EXPECT_TRUE(performedValidation);
  CHECK(client->getConn().zeroRttWriteCipher);
  EXPECT_TRUE(client->serverInitialParamsSet());
  EXPECT_EQ(
      client->peerAdvertisedInitialMaxData(),
      kDefaultConnectionFlowControlWindow);
  EXPECT_EQ(
      client->peerAdvertisedInitialMaxStreamDataBidiLocal(),
      kDefaultStreamFlowControlWindow);
  EXPECT_EQ(
      client->peerAdvertisedInitialMaxStreamDataBidiRemote(),
      kDefaultStreamFlowControlWindow);
  EXPECT_EQ(
      client->peerAdvertisedInitialMaxStreamDataUni(),
      kDefaultStreamFlowControlWindow);
  eventbase_.loopOnce();

  EXPECT_TRUE(client->getConn().zeroRttWriteCipher);
  EXPECT_TRUE(client->good());
  EXPECT_FALSE(client->replaySafe());

  auto streamId = client->createBidirectionalStream().value();
  auto data = IOBuf::copyBuffer("hello");
  auto expected = std::shared_ptr<IOBuf>(IOBuf::copyBuffer("echo "));
  expected->appendToChain(data->clone());

  EXPECT_CALL(clientConnSetupCallback, onReplaySafe()).WillOnce(Invoke([&] {
    EXPECT_TRUE(!client->getConn().retryToken.empty());
  }));
  sendRequestAndResponseAndWait(*expected, data->clone(), streamId, &readCb);

  // Check CC is kept after retry recreates QuicClientConnectionState
  EXPECT_TRUE(client->getConn().congestionControllerFactory);
  EXPECT_EQ(
      client->getConn().congestionController->type(),
      CongestionControlType::NewReno);

  EXPECT_FALSE(client->getConn().zeroRttWriteCipher);
  EXPECT_TRUE(client->getConn().statelessResetToken.has_value());
}

TEST_P(QuicClientTransportIntegrationTest, NewTokenReceived) {
  auto newToken = std::make_shared<std::string>("");
  client->setNewTokenCallback([newToken = newToken](std::string token) {
    *newToken = std::move(token);
  });
  EXPECT_CALL(clientConnSetupCallback, onTransportReady()).WillOnce(Invoke([&] {
    CHECK(client->getConn().oneRttWriteCipher);
    eventbase_.terminateLoopSoon();
  }));
  client->start(&clientConnSetupCallback, &clientConnCallback);
  eventbase_.loopForever();

  auto streamId = client->createBidirectionalStream().value();
  auto data = IOBuf::copyBuffer("hello");
  auto expected = std::shared_ptr<IOBuf>(IOBuf::copyBuffer("echo "));
  expected->appendToChain(data->clone());
  sendRequestAndResponseAndWait(*expected, data->clone(), streamId, &readCb);

  EXPECT_FALSE(newToken->empty());
}

TEST_P(QuicClientTransportIntegrationTest, UseNewTokenThenReceiveRetryToken) {
  auto newToken = std::make_shared<std::string>("");
  client->setNewTokenCallback([newToken = newToken](std::string token) {
    *newToken = std::move(token);
  });
  EXPECT_CALL(clientConnSetupCallback, onTransportReady()).WillOnce(Invoke([&] {
    CHECK(client->getConn().oneRttWriteCipher);
    eventbase_.terminateLoopSoon();
  }));
  client->start(&clientConnSetupCallback, &clientConnCallback);
  eventbase_.loopForever();

  auto streamId = client->createBidirectionalStream().value();
  auto data = IOBuf::copyBuffer("hello");
  auto expected = std::shared_ptr<IOBuf>(IOBuf::copyBuffer("echo "));
  expected->appendToChain(data->clone());
  sendRequestAndResponseAndWait(*expected, data->clone(), streamId, &readCb);

  EXPECT_FALSE(newToken->empty());

  /**
   * At this point we have a valid new token, so we're going to do the
   * following:
   * 1. create a new client and set the new token to the one received above

   * 2. create a new server with a rate limit of zero, forcing retry packet (the
   *    new token will get rejected since the token secrets aren't the same, but
   *    this doesn't really affect anything for this test)
   *
   * 3. connect to the new server, verify that the tokens are non-empty and not
   *    equal.
   */
  client = createClient();
  client->setNewToken(*newToken);

  auto retryServer = createServer(ProcessId::ONE, true);
  client->getNonConstConn().peerAddress = retryServer->getAddress();

  SCOPE_EXIT {
    retryServer->shutdown();
    retryServer = nullptr;
  };

  EXPECT_CALL(clientConnSetupCallback, onTransportReady()).WillOnce(Invoke([&] {
    CHECK(client->getConn().oneRttWriteCipher);
    eventbase_.terminateLoopSoon();
  }));
  client->start(&clientConnSetupCallback, &clientConnCallback);
  eventbase_.loopForever();

  EXPECT_FALSE(client->getConn().retryToken.empty());
  EXPECT_NE(*newToken, client->getConn().retryToken);
}

TEST_P(QuicClientTransportIntegrationTest, TestZeroRttRejection) {
  expectTransportCallbacks();
  auto qLogger = std::make_shared<FileQLogger>(VantagePoint::Client);
  client->getNonConstConn().qLogger = qLogger;
  auto cachedPsk = setupZeroRttOnClientCtx(*clientCtx, hostname);
  pskCache_->putPsk(hostname, cachedPsk);
  // Change the ctx
  server_->setFizzContext(serverCtx);
  bool performedValidation = false;
  client->setEarlyDataAppParamsFunctions(
      [&](const Optional<std::string>&, const BufPtr&) {
        performedValidation = true;
        return true;
      },
      []() -> BufPtr { return nullptr; });
  EXPECT_CALL(clientConnSetupCallback, onTransportReady()).WillOnce(Invoke([&] {
    ASSERT_EQ(client->getAppProtocol(), "h3");
    ASSERT_NE(
        client->getZeroRttState(),
        QuicClientTransport::ZeroRttAttemptState::Accepted);
    // The ZeroRTT onTransportReady() is scheduled on the event base. So if the
    // handshake completed quickly, the callback could happen after ZerRTT has
    // already been rejected. We only check the zeroRTTCipher if the callback is
    // early.
    if (client->getZeroRttState() ==
        QuicClientTransport::ZeroRttAttemptState::NotAttempted) {
      EXPECT_TRUE(client->getConn().zeroRttWriteCipher);
    }
  }));
  client->start(&clientConnSetupCallback, &clientConnCallback);
  EXPECT_TRUE(performedValidation);
  CHECK(client->getConn().zeroRttWriteCipher);
  EXPECT_TRUE(client->serverInitialParamsSet());
  EXPECT_EQ(
      client->peerAdvertisedInitialMaxData(),
      kDefaultConnectionFlowControlWindow);
  EXPECT_EQ(
      client->peerAdvertisedInitialMaxStreamDataBidiLocal(),
      kDefaultStreamFlowControlWindow);
  EXPECT_EQ(
      client->peerAdvertisedInitialMaxStreamDataBidiRemote(),
      kDefaultStreamFlowControlWindow);
  EXPECT_EQ(
      client->peerAdvertisedInitialMaxStreamDataUni(),
      kDefaultStreamFlowControlWindow);
  client->serverInitialParamsSet() = false;
  eventbase_.loopOnce();

  if (client->getZeroRttState() ==
      QuicClientTransport::ZeroRttAttemptState::NotAttempted) {
    EXPECT_TRUE(client->getConn().zeroRttWriteCipher);
    EXPECT_FALSE(client->replaySafe());
  } else if (
      client->getZeroRttState() ==
      QuicClientTransport::ZeroRttAttemptState::Rejected) {
    EXPECT_FALSE(client->getConn().zeroRttWriteCipher);
    EXPECT_TRUE(client->replaySafe());
  } else {
    FAIL() << "Zero RTT accpted";
  }
  EXPECT_TRUE(client->good());

  auto streamId = client->createBidirectionalStream().value();
  auto data = IOBuf::copyBuffer("hello");
  auto expected = std::shared_ptr<IOBuf>(IOBuf::copyBuffer("echo "));
  expected->appendToChain(data->clone());
  sendRequestAndResponseAndWait(*expected, data->clone(), streamId, &readCb);
  // Rejection means that we will unset the zero rtt cipher.
  EXPECT_EQ(client->getConn().zeroRttWriteCipher, nullptr);
  EXPECT_TRUE(client->serverInitialParamsSet());
  EXPECT_EQ(
      client->peerAdvertisedInitialMaxData(),
      kDefaultConnectionFlowControlWindow);
  EXPECT_EQ(
      client->peerAdvertisedInitialMaxStreamDataBidiLocal(),
      kDefaultStreamFlowControlWindow);
  EXPECT_EQ(
      client->peerAdvertisedInitialMaxStreamDataBidiRemote(),
      kDefaultStreamFlowControlWindow);
  EXPECT_EQ(
      client->peerAdvertisedInitialMaxStreamDataUni(),
      kDefaultStreamFlowControlWindow);
  EXPECT_TRUE(client->getConn().statelessResetToken.has_value());
  // The psk should be removed from the cache on rejection.
  EXPECT_FALSE(pskCache_->getPsk(hostname).has_value());
}

TEST_P(QuicClientTransportIntegrationTest, TestZeroRttNotAttempted) {
  expectTransportCallbacks();
  auto cachedPsk = setupZeroRttOnClientCtx(*clientCtx, hostname);
  pskCache_->putPsk(hostname, cachedPsk);
  // Change the ctx
  server_->setFizzContext(serverCtx);
  client->getNonConstConn().transportSettings.attemptEarlyData = false;
  client->setEarlyDataAppParamsFunctions(
      [&](const Optional<std::string>&, const BufPtr&) {
        EXPECT_TRUE(false);
        return true;
      },
      []() -> BufPtr { return nullptr; });
  EXPECT_CALL(clientConnSetupCallback, onTransportReady()).WillOnce(Invoke([&] {
    EXPECT_FALSE(client->getConn().zeroRttWriteCipher);
    CHECK(client->getConn().oneRttWriteCipher);
    eventbase_.terminateLoopSoon();
  }));
  client->start(&clientConnSetupCallback, &clientConnCallback);
  eventbase_.loopForever();

  auto streamId = client->createBidirectionalStream().value();
  auto data = IOBuf::copyBuffer("hello");
  auto expected = std::shared_ptr<IOBuf>(IOBuf::copyBuffer("echo "));
  expected->appendToChain(data->clone());
  sendRequestAndResponseAndWait(*expected, data->clone(), streamId, &readCb);
  EXPECT_TRUE(client->serverInitialParamsSet());
  EXPECT_EQ(
      client->peerAdvertisedInitialMaxData(),
      kDefaultConnectionFlowControlWindow);
  EXPECT_EQ(
      client->peerAdvertisedInitialMaxStreamDataBidiLocal(),
      kDefaultStreamFlowControlWindow);
  EXPECT_EQ(
      client->peerAdvertisedInitialMaxStreamDataBidiRemote(),
      kDefaultStreamFlowControlWindow);
  EXPECT_EQ(
      client->peerAdvertisedInitialMaxStreamDataUni(),
      kDefaultStreamFlowControlWindow);
}

TEST_P(QuicClientTransportIntegrationTest, TestZeroRttInvalidAppParams) {
  expectTransportCallbacks();
  auto cachedPsk = setupZeroRttOnClientCtx(*clientCtx, hostname);
  pskCache_->putPsk(hostname, cachedPsk);
  // Change the ctx
  server_->setFizzContext(serverCtx);
  bool performedValidation = false;
  client->setEarlyDataAppParamsFunctions(
      [&](const Optional<std::string>&, const BufPtr&) {
        performedValidation = true;
        return false;
      },
      []() -> BufPtr { return nullptr; });
  EXPECT_CALL(clientConnSetupCallback, onTransportReady()).WillOnce(Invoke([&] {
    EXPECT_FALSE(client->getConn().zeroRttWriteCipher);
    CHECK(client->getConn().oneRttWriteCipher);
    eventbase_.terminateLoopSoon();
  }));
  client->start(&clientConnSetupCallback, &clientConnCallback);
  EXPECT_TRUE(performedValidation);
  eventbase_.loopForever();

  auto streamId = client->createBidirectionalStream().value();
  auto data = IOBuf::copyBuffer("hello");
  auto expected = std::shared_ptr<IOBuf>(IOBuf::copyBuffer("echo "));
  expected->appendToChain(data->clone());
  sendRequestAndResponseAndWait(*expected, data->clone(), streamId, &readCb);
  EXPECT_TRUE(client->serverInitialParamsSet());
  EXPECT_EQ(
      client->peerAdvertisedInitialMaxData(),
      kDefaultConnectionFlowControlWindow);
  EXPECT_EQ(
      client->peerAdvertisedInitialMaxStreamDataBidiLocal(),
      kDefaultStreamFlowControlWindow);
  EXPECT_EQ(
      client->peerAdvertisedInitialMaxStreamDataBidiRemote(),
      kDefaultStreamFlowControlWindow);
  EXPECT_EQ(
      client->peerAdvertisedInitialMaxStreamDataUni(),
      kDefaultStreamFlowControlWindow);
}

TEST_P(QuicClientTransportIntegrationTest, ChangeEventBase) {
  NiceMock<MockReadCallback> readCb2;
  folly::ScopedEventBaseThread newEvb;
  std::shared_ptr<FollyQuicEventBase> newQEvb =
      std::make_shared<FollyQuicEventBase>(newEvb.getEventBase());
  expectTransportCallbacks();
  EXPECT_CALL(clientConnSetupCallback, onTransportReady()).WillOnce(Invoke([&] {
    CHECK(client->getConn().oneRttWriteCipher);
    eventbase_.terminateLoopSoon();
  }));
  client->start(&clientConnSetupCallback, &clientConnCallback);
  eventbase_.loopForever();

  auto streamId = client->createBidirectionalStream().value();
  auto data = IOBuf::copyBuffer("hello");
  auto expected = std::shared_ptr<IOBuf>(IOBuf::copyBuffer("echo "));
  expected->appendToChain(data->clone());
  sendRequestAndResponseAndWait(*expected, data->clone(), streamId, &readCb);
  EXPECT_TRUE(client->isDetachable());
  client->detachEventBase();
  folly::Baton<> baton;
  bool responseRecvd = false;
  VLOG(10) << "changing threads";
  newEvb.getEventBase()->runInEventBaseThreadAndWait([&] {
    client->attachEventBase(newQEvb);
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

  EXPECT_CALL(clientConnSetupCallback, onTransportReady()).WillOnce(Invoke([&] {
    CHECK(client->getConn().oneRttWriteCipher);
    eventbase_.terminateLoopSoon();
  }));
  client->start(&clientConnSetupCallback, &clientConnCallback);
  eventbase_.loopForever();

  auto streamId = client->createBidirectionalStream().value();
  auto data = IOBuf::copyBuffer("hello");
  auto expected = std::shared_ptr<IOBuf>(IOBuf::copyBuffer("echo "));
  expected->appendToChain(data->clone());
  sendRequestAndResponseAndWait(*expected, data->clone(), streamId, &readCb);

  // change the address to a new server which does not have the connection.
  auto server2Addr = server2->getAddress();
  auto& conn = client->getNonConstConn();
  conn.peerAddress = server2Addr;
  auto pathIdRes = conn.pathManager->addValidatedPath(
      client->getLocalAddress(), conn.peerAddress);
  ASSERT_FALSE(pathIdRes.hasError());
  conn.currentPathId = pathIdRes.value();

  NiceMock<MockReadCallback> readCb2;
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
  Optional<StatelessResetToken> token1, token2;

  expectTransportCallbacks();
  auto server2 = createServer(ProcessId::ONE);
  SCOPE_EXIT {
    server2->shutdown();
    server2 = nullptr;
  };

  EXPECT_CALL(clientConnSetupCallback, onTransportReady()).WillOnce(Invoke([&] {
    token1 = client->getConn().statelessResetToken;
    eventbase_.terminateLoopSoon();
  }));
  client->start(&clientConnSetupCallback, &clientConnCallback);
  eventbase_.loopForever();

  auto streamId = client->createBidirectionalStream().value();
  auto data = IOBuf::copyBuffer("hello");
  auto expected = std::shared_ptr<IOBuf>(IOBuf::copyBuffer("echo "));
  expected->appendToChain(data->clone());
  sendRequestAndResponseAndWait(*expected, data->clone(), streamId, &readCb);

  // change the address to a new server which does not have the connection.
  auto server2Addr = server2->getAddress();
  auto& conn = client->getNonConstConn();
  conn.peerAddress = server2Addr;
  auto pathIdRes = conn.pathManager->addValidatedPath(
      client->getLocalAddress(), conn.peerAddress);
  ASSERT_FALSE(pathIdRes.hasError());
  conn.currentPathId = pathIdRes.value();

  NiceMock<MockReadCallback> readCb2;
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

  ASSERT_TRUE(resetRecvd);
  ASSERT_TRUE(token1.has_value());
  ASSERT_TRUE(token2.has_value());
  EXPECT_EQ(token1.value(), token2.value());
}

INSTANTIATE_TEST_SUITE_P(
    QuicClientTransportIntegrationTests,
    QuicClientTransportIntegrationTest,
    ::testing::Values(
        TestingParams(QuicVersion::MVFST),
        TestingParams(QuicVersion::QUIC_V1),
        TestingParams(QuicVersion::QUIC_V1, 0),
        TestingParams(QuicVersion::QUIC_V1_ALIAS),
        TestingParams(QuicVersion::QUIC_V1_ALIAS, 0)));

class QuicClientTransportTest : public QuicClientTransportTestBase {
 public:
  void SetUp() override {
    QuicClientTransportTestBase::SetUp();
  }
};

TEST_F(QuicClientTransportTest, ReadErrorCloseTransprot) {
  client->onReadError(
      folly::AsyncSocketException(
          folly::AsyncSocketException::INTERNAL_ERROR,
          "Where you wanna go",
          -1));
  EXPECT_FALSE(client->isClosed());
  client->onReadError(
      folly::AsyncSocketException(
          folly::AsyncSocketException::INTERNAL_ERROR,
          "He never saw it coming at all",
          -1));
  eventbase_->loopOnce();
  EXPECT_TRUE(client->isClosed());
}

TEST_F(QuicClientTransportTest, FirstPacketProcessedCallback) {
  client->addNewPeerAddress(serverAddr);
  client->start(&clientConnSetupCallback, &clientConnCallback);

  originalConnId = client->getConn().clientConnectionId;
  ServerConnectionIdParams params(0, 0, 0);
  client->getNonConstConn().serverConnectionId =
      *connIdAlgo_->encodeConnectionId(params);

  AckBlocks acks;
  acks.insert(0);
  auto& aead = getInitialCipher();
  auto& headerCipher = getInitialHeaderCipher();
  auto ackPacket = packetToBufCleartext(
      createAckPacket(
          client->getNonConstConn(),
          initialPacketNum,
          acks,
          PacketNumberSpace::Initial,
          &aead),
      aead,
      headerCipher,
      initialPacketNum);
  initialPacketNum++;
  EXPECT_CALL(clientConnSetupCallback, onFirstPeerPacketProcessed()).Times(1);
  deliverData(serverAddr, ackPacket->coalesce());
  EXPECT_FALSE(client->hasWriteCipher());

  // Another ack won't trigger it again:
  auto oneMoreAckPacket = packetToBufCleartext(
      createAckPacket(
          client->getNonConstConn(),
          initialPacketNum,
          acks,
          PacketNumberSpace::Initial,
          &aead),
      aead,
      headerCipher,
      initialPacketNum);
  initialPacketNum++;
  EXPECT_CALL(clientConnSetupCallback, onFirstPeerPacketProcessed()).Times(0);
  deliverData(serverAddr, oneMoreAckPacket->coalesce());
  EXPECT_FALSE(client->hasWriteCipher());

  client->closeNow(std::nullopt);
}

TEST_F(QuicClientTransportTest, CloseSocketOnWriteError) {
  client->addNewPeerAddress(serverAddr);
  EXPECT_CALL(*sock, write(_, _, _)).WillOnce(SetErrnoAndReturn(EBADF, -1));
  EXPECT_CALL(clientConnSetupCallback, onConnectionSetupError(_));
  client->start(&clientConnSetupCallback, &clientConnCallback);

  EXPECT_FALSE(client->isClosed());
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

  client->closeNow(std::nullopt);
}

TEST_F(QuicClientTransportTest, onNetworkSwitchNoReplace) {
  client->getNonConstConn().oneRttWriteCipher = test::createNoOpAead();
  auto mockQLogger = std::make_shared<MockQLogger>(VantagePoint::Client);
  client->setQLogger(mockQLogger);

  EXPECT_CALL(*mockQLogger, addConnectionMigrationUpdate(true)).Times(0);
  client->onNetworkSwitch(nullptr);
  client->closeNow(std::nullopt);
}

TEST_F(QuicClientTransportTest, onNetworkSwitchReplaceAfterHandshake) {
  auto& conn = client->getNonConstConn();
  conn.oneRttWriteCipher = test::createNoOpAead();
  conn.oneRttWriteHeaderCipher = test::createNoOpHeaderCipherNoThrow();
  auto mockQLogger = std::make_shared<MockQLogger>(VantagePoint::Client);
  client->setQLogger(mockQLogger);

  auto originalCid = ConnectionIdData(
      ConnectionId::createAndMaybeCrash(std::vector<uint8_t>{1, 2, 3, 4}), 1);
  auto secondCid = ConnectionIdData(
      ConnectionId::createAndMaybeCrash(std::vector<uint8_t>{5, 6, 7, 8}), 2);
  conn.serverConnectionId = originalCid.connId;
  originalCid.inUse = true;

  conn.peerConnectionIds.push_back(originalCid);
  conn.peerConnectionIds.push_back(secondCid);

  folly::SocketAddress v4Address("0.0.0.0", 0);
  client->addNewPeerAddress(v4Address);
  auto validatedPathId =
      conn.pathManager->addValidatedPath(client->getLocalAddress(), v4Address);
  ASSERT_FALSE(validatedPathId.hasError());
  conn.currentPathId = validatedPathId.value();

  auto newSocket = getMockSocketWithExpectations(qEvb_);
  auto newSocketPtr = newSocket.get();

  EXPECT_CALL(*newSocketPtr, close());
  EXPECT_CALL(*newSocketPtr, isBound()).WillRepeatedly(Return(true));
  EXPECT_CALL(*newSocketPtr, address())
      .WillRepeatedly(Return(folly::SocketAddress("1.2.3.4", 1234)));

  client->setQLogger(mockQLogger);
  EXPECT_CALL(*mockQLogger, addConnectionMigrationUpdate(true));

  ASSERT_TRUE(conn.peerSupportsActiveConnectionMigration);

  client->onNetworkSwitch(std::move(newSocket));
  ASSERT_NE(conn.currentPathId, validatedPathId.value());

  // The client doesn't have a fallback when migrating to unvalidated path.
  ASSERT_FALSE(conn.fallbackPathId.has_value());

  // New path is created. It's not yet valid but has a path challenge pending
  auto newPathRes = conn.pathManager->getPath(
      newSocketPtr->address().value(), conn.peerAddress);
  ASSERT_TRUE(newPathRes);
  EXPECT_EQ(newPathRes->status, PathStatus::NotValid);
  ASSERT_NO_THROW(conn.pendingEvents.pathChallenges.at(conn.currentPathId));

  loopForWrites();

  // The path challenge was written and the path is now validating
  EXPECT_THROW(
      conn.pendingEvents.pathChallenges.at(conn.currentPathId),
      std::out_of_range);
  EXPECT_EQ(newPathRes->status, PathStatus::Validating);

  client->closeNow(std::nullopt);
}

TEST_F(QuicClientTransportTest, onNetworkSwitchReplaceNoHandshake) {
  auto newSocket = getMockSocketWithExpectations(qEvb_);
  auto newSocketPtr = newSocket.get();
  auto mockQLogger = std::make_shared<MockQLogger>(VantagePoint::Client);
  EXPECT_CALL(*mockQLogger, addConnectionMigrationUpdate(true)).Times(0);
  EXPECT_CALL(*newSocketPtr, bind(_)).Times(0);
  client->onNetworkSwitch(std::move(newSocket));
  client->closeNow(std::nullopt);
}

TEST_F(QuicClientTransportTest, SocketClosedDuringOnTransportReady) {
  class ConnectionCallbackThatWritesOnTransportReady
      : public QuicSocket::ConnectionSetupCallback,
        public QuicSocket::ConnectionCallback {
   public:
    explicit ConnectionCallbackThatWritesOnTransportReady(
        std::shared_ptr<QuicSocket> socket)
        : socket_(std::move(socket)) {}

    void onTransportReady() noexcept override {
      socket_->close(std::nullopt);
      socket_.reset();
      onTransportReadyMock();
    }

    MOCK_METHOD(void, onFlowControlUpdate, (StreamId), (noexcept));
    MOCK_METHOD(void, onNewBidirectionalStream, (StreamId), (noexcept));
    MOCK_METHOD(void, onNewUnidirectionalStream, (StreamId), (noexcept));
    MOCK_METHOD(
        void,
        onStopSending,
        (StreamId, ApplicationErrorCode),
        (noexcept));
    MOCK_METHOD(void, onTransportReadyMock, (), (noexcept));
    MOCK_METHOD(void, onReplaySafe, (), (noexcept));
    MOCK_METHOD(void, onConnectionEnd, (), (noexcept));

    void onConnectionSetupError(QuicError error) noexcept override {
      onConnectionError(std::move(error));
    }

    MOCK_METHOD(void, onConnectionError, (QuicError), (noexcept));

   private:
    std::shared_ptr<QuicSocket> socket_;
  };

  ConnectionCallbackThatWritesOnTransportReady callback(client);
  EXPECT_CALL(callback, onTransportReadyMock());
  EXPECT_CALL(callback, onReplaySafe()).Times(0);
  ON_CALL(*sock, write(_, _, _))
      .WillByDefault(Invoke(
          [&](const SocketAddress&, const struct iovec* vec, size_t iovec_len) {
            socketWrites.push_back(
                copyChain(folly::IOBuf::wrapIov(vec, iovec_len)));
            return getTotalIovecLen(vec, iovec_len);
            ;
          }));
  ON_CALL(*sock, address()).WillByDefault(Return(serverAddr));

  client->addNewPeerAddress(serverAddr);
  setupCryptoLayer();
  client->start(&callback, &callback);
  setConnectionIds();
  EXPECT_THROW(recvServerHello(), std::runtime_error);
}

TEST_F(QuicClientTransportTest, NetworkUnreachableIsFatalToConn) {
  client->addNewPeerAddress(serverAddr);
  setupCryptoLayer();
  EXPECT_CALL(clientConnSetupCallback, onConnectionSetupError(_));
  EXPECT_CALL(*sock, write(_, _, _))
      .WillOnce(SetErrnoAndReturn(ENETUNREACH, -1));
  client->start(&clientConnSetupCallback, &clientConnCallback);
  loopForWrites();
}

TEST_F(QuicClientTransportTest, HappyEyeballsWithSingleV4Address) {
  auto& conn = client->getConn();

  client->setHappyEyeballsEnabled(true);

  client->addNewPeerAddress(serverAddr);
  EXPECT_EQ(client->getConn().happyEyeballsState.v4PeerAddress, serverAddr);

  setupCryptoLayer();

  EXPECT_FALSE(conn.happyEyeballsState.finished);
  EXPECT_FALSE(conn.peerAddress.isInitialized());
  client->start(&clientConnSetupCallback, &clientConnCallback);
  EXPECT_FALSE(client->happyEyeballsConnAttemptDelayTimeout()
                   .isTimerCallbackScheduled());
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
  client->start(&clientConnSetupCallback, &clientConnCallback);
  EXPECT_FALSE(client->happyEyeballsConnAttemptDelayTimeout()
                   .isTimerCallbackScheduled());
  EXPECT_TRUE(conn.happyEyeballsState.finished);
  EXPECT_EQ(conn.peerAddress, serverAddrV6);
}

TEST_F(QuicClientTransportTest, IdleTimerResetOnWritingFirstData) {
  client->addNewPeerAddress(serverAddr);
  setupCryptoLayer();
  client->start(&clientConnSetupCallback, &clientConnCallback);
  loopForWrites();
  ASSERT_FALSE(client->getConn().receivedNewPacketBeforeWrite);
  ASSERT_TRUE(client->idleTimeout().isTimerCallbackScheduled());
}

TEST_F(QuicClientTransportTest, SetQLoggerDcid) {
  client->setQLogger(nullptr);
  auto mockQLogger = std::make_shared<MockQLogger>(VantagePoint::Client);

  EXPECT_CALL(
      *mockQLogger, setDcid(client->getConn().clientChosenDestConnectionId));
  client->setQLogger(mockQLogger);
  client->closeNow(std::nullopt);
}

TEST_F(QuicClientTransportTest, CheckQLoggerRefCount) {
  auto mockQLogger1 = std::make_shared<MockQLogger>(VantagePoint::Client);
  auto mockQLogger2 = std::make_shared<MockQLogger>(VantagePoint::Client);
  EXPECT_CALL(
      *mockQLogger2, setDcid(client->getConn().clientChosenDestConnectionId))
      .Times(AtLeast(1));

  // no-op
  client->setQLogger(nullptr);
  CHECK(client->getQLogger() == nullptr);

  // set
  client->setQLogger(mockQLogger1);
  CHECK_EQ(client->getQLogger(), mockQLogger1);
  client->setQLogger(mockQLogger2);
  CHECK_EQ(client->getQLogger(), mockQLogger2);

  // mix set and unset
  client->setQLogger(nullptr);
  CHECK_EQ(client->getQLogger(), mockQLogger2);
  client->setQLogger(mockQLogger1);
  CHECK_EQ(client->getQLogger(), mockQLogger1);
  client->setQLogger(nullptr);
  CHECK_EQ(client->getQLogger(), mockQLogger1);

  // final unset
  client->setQLogger(nullptr);
  CHECK(client->getQLogger() == nullptr);

  client->closeNow(std::nullopt);
}

enum class ServerFirstPacketType : uint8_t { ServerHello, Retry };

class QuicClientTransportHappyEyeballsTest
    : public QuicClientTransportTest,
      public testing::WithParamInterface<ServerFirstPacketType> {
 public:
  void SetUpChild() override {
    auto secondSocket =
        std::make_unique<NiceMock<quic::test::MockAsyncUDPSocket>>(qEvb_);
    secondSock = secondSocket.get();

    client->setHappyEyeballsEnabled(true);
    client->addNewPeerAddress(serverAddrV4);
    client->addNewPeerAddress(serverAddrV6);
    client->addNewSocket(std::move(secondSocket));

    EXPECT_EQ(client->getConn().happyEyeballsState.v6PeerAddress, serverAddrV6);
    EXPECT_EQ(client->getConn().happyEyeballsState.v4PeerAddress, serverAddrV4);

    setupCryptoLayer();

    ON_CALL(*secondSock, address()).WillByDefault(testing::Return(serverAddr));
    ON_CALL(*secondSock, setAdditionalCmsgsFunc(testing::_))
        .WillByDefault(testing::Return(quic::Expected<void, QuicError>{}));
    ON_CALL(*secondSock, getGSO).WillByDefault(testing::Return(0));
    ON_CALL(*secondSock, getGRO).WillByDefault(testing::Return(0));
    ON_CALL(*secondSock, init(testing::_))
        .WillByDefault(testing::Return(quic::Expected<void, QuicError>{}));
    ON_CALL(*secondSock, bind(testing::_))
        .WillByDefault(testing::Return(quic::Expected<void, QuicError>{}));
    ON_CALL(*secondSock, connect(testing::_))
        .WillByDefault(testing::Return(quic::Expected<void, QuicError>{}));
    ON_CALL(*secondSock, close())
        .WillByDefault(testing::Return(quic::Expected<void, QuicError>{}));
    ON_CALL(*secondSock, resumeWrite(testing::_))
        .WillByDefault(testing::Return(quic::Expected<void, QuicError>{}));
    ON_CALL(*secondSock, setGRO(testing::_))
        .WillByDefault(testing::Return(quic::Expected<void, QuicError>{}));
    ON_CALL(*secondSock, setRecvTos(testing::_))
        .WillByDefault(testing::Return(quic::Expected<void, QuicError>{}));
    ON_CALL(*secondSock, getRecvTos()).WillByDefault(testing::Return(false));
    ON_CALL(*secondSock, setTosOrTrafficClass(testing::_))
        .WillByDefault(testing::Return(quic::Expected<void, QuicError>{}));
    ON_CALL(*secondSock, setCmsgs(testing::_))
        .WillByDefault(testing::Return(quic::Expected<void, QuicError>{}));
    ON_CALL(*secondSock, appendCmsgs(testing::_))
        .WillByDefault(testing::Return(quic::Expected<void, QuicError>{}));
    ON_CALL(*secondSock, getTimestamping()).WillByDefault(testing::Return(0));
    ON_CALL(*secondSock, setReuseAddr(testing::_))
        .WillByDefault(testing::Return(quic::Expected<void, QuicError>{}));
    ON_CALL(*secondSock, setDFAndTurnOffPMTU())
        .WillByDefault(testing::Return(quic::Expected<void, QuicError>{}));
    ON_CALL(*secondSock, setErrMessageCallback(testing::_))
        .WillByDefault(testing::Return(quic::Expected<void, QuicError>{}));
    ON_CALL(*secondSock, applyOptions(testing::_, testing::_))
        .WillByDefault(testing::Return(quic::Expected<void, QuicError>{}));
    ON_CALL(*secondSock, setReusePort(testing::_))
        .WillByDefault(testing::Return(quic::Expected<void, QuicError>{}));
    ON_CALL(*secondSock, setRcvBuf(testing::_))
        .WillByDefault(testing::Return(quic::Expected<void, QuicError>{}));
    ON_CALL(*secondSock, setSndBuf(testing::_))
        .WillByDefault(testing::Return(quic::Expected<void, QuicError>{}));
    ON_CALL(*secondSock, setFD(testing::_, testing::_))
        .WillByDefault(testing::Return(quic::Expected<void, QuicError>{}));
  }

 protected:
  void setupInitialDcidForRetry() {
    if (GetParam() == ServerFirstPacketType::Retry) {
      ConnectionId initialDstConnId =
          ConnectionId::createAndMaybeCrash(kInitialDstConnIdVecForRetryTest);
      client->getNonConstConn().originalDestinationConnectionId =
          initialDstConnId;
    }
  }

  void firstWinBeforeSecondStart(
      const SocketAddress& firstAddress,
      const SocketAddress& secondAddress) {
    auto& conn = client->getConn();
    setupInitialDcidForRetry();
    auto firstPacketType = GetParam();
    EXPECT_CALL(*sock, write(firstAddress, _, _))
        .Times(AtLeast(1))
        .WillRepeatedly(Invoke([&](const SocketAddress&,
                                   const struct iovec* vec,
                                   size_t iovec_len) {
          socketWrites.push_back(
              copyChain(folly::IOBuf::wrapIov(vec, iovec_len)));
          return getTotalIovecLen(vec, iovec_len);
        }));
    EXPECT_CALL(*secondSock, write(_, _, _)).Times(0);
    client->start(&clientConnSetupCallback, &clientConnCallback);
    setConnectionIds();

    EXPECT_EQ(conn.peerAddress, firstAddress);
    EXPECT_EQ(conn.happyEyeballsState.secondPeerAddress, secondAddress);
    EXPECT_TRUE(client->happyEyeballsConnAttemptDelayTimeout()
                    .isTimerCallbackScheduled());
    EXPECT_EQ(socketWrites.size(), 1);
    EXPECT_TRUE(
        verifyLongHeader(*socketWrites.at(0), LongHeader::Types::Initial));

    socketWrites.clear();

    EXPECT_FALSE(conn.happyEyeballsState.finished);
    if (firstPacketType == ServerFirstPacketType::ServerHello) {
      EXPECT_CALL(clientConnSetupCallback, onTransportReady());
      EXPECT_CALL(clientConnSetupCallback, onReplaySafe());
    }
    EXPECT_CALL(*secondSock, write(_, _, _)).Times(0);
    EXPECT_CALL(*secondSock, pauseRead());
    EXPECT_CALL(*secondSock, close());
    if (firstPacketType == ServerFirstPacketType::Retry) {
      recvServerRetry(firstAddress);
    } else {
      performFakeHandshake(firstAddress);
    }
    EXPECT_FALSE(client->happyEyeballsConnAttemptDelayTimeout()
                     .isTimerCallbackScheduled());
    EXPECT_TRUE(client->getConn().happyEyeballsState.finished);
    EXPECT_EQ(client->getConn().originalPeerAddress, firstAddress);
    EXPECT_EQ(client->getConn().peerAddress, firstAddress);
  }

  void firstWinAfterSecondStart(
      const SocketAddress& firstAddress,
      const SocketAddress& secondAddress) {
    auto& conn = client->getConn();
    auto firstPacketType = GetParam();
    setupInitialDcidForRetry();

    EXPECT_CALL(*sock, write(firstAddress, _, _))
        .WillRepeatedly(Invoke([&](const SocketAddress&,
                                   const struct iovec* vec,
                                   size_t iovec_len) {
          socketWrites.push_back(
              copyChain(folly::IOBuf::wrapIov(vec, iovec_len)));
          return getTotalIovecLen(vec, iovec_len);
        }));
    EXPECT_CALL(*secondSock, write(_, _, _)).Times(0);
    client->start(&clientConnSetupCallback, &clientConnCallback);
    setConnectionIds();

    EXPECT_EQ(conn.peerAddress, firstAddress);
    EXPECT_EQ(conn.happyEyeballsState.secondPeerAddress, secondAddress);
    EXPECT_TRUE(client->happyEyeballsConnAttemptDelayTimeout()
                    .isTimerCallbackScheduled());
    EXPECT_EQ(socketWrites.size(), 1);
    EXPECT_TRUE(
        verifyLongHeader(*socketWrites.at(0), LongHeader::Types::Initial));

    socketWrites.clear();

    // Manually expire conn attempt timeout
    EXPECT_FALSE(conn.happyEyeballsState.shouldWriteToSecondSocket);
    client->happyEyeballsConnAttemptDelayTimeout().cancelTimerCallback();
    client->happyEyeballsConnAttemptDelayTimeout().timeoutExpired();
    EXPECT_TRUE(conn.happyEyeballsState.shouldWriteToSecondSocket);
    EXPECT_FALSE(client->happyEyeballsConnAttemptDelayTimeout()
                     .isTimerCallbackScheduled());

    // Manually expire loss timeout to trigger write to both first and second
    // socket
    EXPECT_CALL(*sock, write(firstAddress, _, _))
        .WillOnce(Invoke([&](const SocketAddress&,
                             const struct iovec* vec,
                             size_t iovec_len) {
          socketWrites.push_back(
              copyChain(folly::IOBuf::wrapIov(vec, iovec_len)));
          return getTotalIovecLen(vec, iovec_len);
        }));
    EXPECT_CALL(*secondSock, write(secondAddress, _, _));
    client->lossTimeout().cancelTimerCallback();
    client->lossTimeout().timeoutExpired();
    EXPECT_EQ(socketWrites.size(), 1);
    EXPECT_TRUE(
        verifyLongHeader(*socketWrites.at(0), LongHeader::Types::Initial));

    socketWrites.clear();
    EXPECT_FALSE(conn.happyEyeballsState.finished);
    if (firstPacketType == ServerFirstPacketType::ServerHello) {
      EXPECT_CALL(clientConnSetupCallback, onTransportReady());
      EXPECT_CALL(clientConnSetupCallback, onReplaySafe());
    }
    EXPECT_CALL(*sock, write(firstAddress, _, _))
        .Times(AtLeast(1))
        .WillRepeatedly(Invoke([&](const SocketAddress&,
                                   const struct iovec* vec,
                                   size_t iovec_len) {
          socketWrites.push_back(
              copyChain(folly::IOBuf::wrapIov(vec, iovec_len)));
          return getTotalIovecLen(vec, iovec_len);
        }));
    EXPECT_CALL(*secondSock, write(_, _, _)).Times(0);
    EXPECT_CALL(*secondSock, pauseRead());
    EXPECT_CALL(*secondSock, close());
    if (firstPacketType == ServerFirstPacketType::Retry) {
      recvServerRetry(firstAddress);
    } else {
      performFakeHandshake(firstAddress);
    }
    EXPECT_TRUE(client->getConn().happyEyeballsState.finished);
    EXPECT_FALSE(
        client->getConn().happyEyeballsState.shouldWriteToSecondSocket);
    EXPECT_EQ(client->getConn().originalPeerAddress, firstAddress);
    EXPECT_EQ(client->getConn().peerAddress, firstAddress);
  }

  void secondWin(
      const SocketAddress& firstAddress,
      const SocketAddress& secondAddress) {
    auto& conn = client->getConn();
    auto firstPacketType = GetParam();
    setupInitialDcidForRetry();

    EXPECT_CALL(*sock, write(firstAddress, _, _))
        .WillRepeatedly(Invoke([&](const SocketAddress&,
                                   const struct iovec* vec,
                                   size_t iovec_len) {
          socketWrites.push_back(
              copyChain(folly::IOBuf::wrapIov(vec, iovec_len)));
          return getTotalIovecLen(vec, iovec_len);
        }));
    EXPECT_CALL(*secondSock, write(_, _, _)).Times(0);
    client->start(&clientConnSetupCallback, &clientConnCallback);
    setConnectionIds();
    EXPECT_EQ(conn.peerAddress, firstAddress);
    EXPECT_EQ(conn.happyEyeballsState.secondPeerAddress, secondAddress);
    EXPECT_TRUE(client->happyEyeballsConnAttemptDelayTimeout()
                    .isTimerCallbackScheduled());
    EXPECT_EQ(socketWrites.size(), 1);

    EXPECT_TRUE(
        verifyLongHeader(*socketWrites.at(0), LongHeader::Types::Initial));

    socketWrites.clear();

    // Manually expire conn attempt timeout
    EXPECT_FALSE(conn.happyEyeballsState.shouldWriteToSecondSocket);
    client->happyEyeballsConnAttemptDelayTimeout().cancelTimerCallback();
    client->happyEyeballsConnAttemptDelayTimeout().timeoutExpired();
    EXPECT_TRUE(conn.happyEyeballsState.shouldWriteToSecondSocket);
    EXPECT_FALSE(client->happyEyeballsConnAttemptDelayTimeout()
                     .isTimerCallbackScheduled());

    // Manually expire loss timeout to trigger write to both first and second
    // socket
    EXPECT_CALL(*sock, write(firstAddress, _, _));
    EXPECT_CALL(*secondSock, write(secondAddress, _, _))
        .WillOnce(Invoke([&](const SocketAddress&,
                             const struct iovec* vec,
                             size_t iovec_len) {
          socketWrites.push_back(
              copyChain(folly::IOBuf::wrapIov(vec, iovec_len)));
          return getTotalIovecLen(vec, iovec_len);
        }));
    client->lossTimeout().cancelTimerCallback();
    client->lossTimeout().timeoutExpired();
    EXPECT_EQ(socketWrites.size(), 1);
    EXPECT_TRUE(
        verifyLongHeader(*socketWrites.at(0), LongHeader::Types::Initial));

    socketWrites.clear();

    EXPECT_FALSE(conn.happyEyeballsState.finished);
    if (firstPacketType == ServerFirstPacketType::ServerHello) {
      EXPECT_CALL(clientConnSetupCallback, onTransportReady());
      EXPECT_CALL(clientConnSetupCallback, onReplaySafe());
    }
    EXPECT_CALL(*sock, write(_, _, _)).Times(0);
    EXPECT_CALL(*sock, pauseRead());
    EXPECT_CALL(*sock, close());
    EXPECT_CALL(*secondSock, write(secondAddress, _, _))
        .Times(AtLeast(1))
        .WillRepeatedly(Invoke([&](const SocketAddress&,
                                   const struct iovec* vec,
                                   size_t iovec_len) {
          socketWrites.push_back(
              copyChain(folly::IOBuf::wrapIov(vec, iovec_len)));
          return getTotalIovecLen(vec, iovec_len);
        }));
    if (firstPacketType == ServerFirstPacketType::Retry) {
      recvServerRetry(secondAddress);
    } else {
      performFakeHandshake(secondAddress);
    }
    EXPECT_TRUE(client->getConn().happyEyeballsState.finished);
    EXPECT_FALSE(
        client->getConn().happyEyeballsState.shouldWriteToSecondSocket);
    EXPECT_EQ(client->getConn().originalPeerAddress, secondAddress);
    EXPECT_EQ(client->getConn().peerAddress, secondAddress);
  }

  void secondBindFailure(
      const SocketAddress& firstAddress,
      const SocketAddress& secondAddress) {
    auto& conn = client->getConn();
    setupInitialDcidForRetry();

    EXPECT_CALL(*sock, write(firstAddress, _, _));
    EXPECT_CALL(*secondSock, bind(_))
        .WillOnce(Invoke([](const folly::SocketAddress&) {
          return quic::make_unexpected(
              QuicError(TransportErrorCode::INTERNAL_ERROR, "oopsies"));
        }));
    client->start(&clientConnSetupCallback, &clientConnCallback);
    EXPECT_EQ(conn.peerAddress, firstAddress);
    EXPECT_EQ(conn.happyEyeballsState.secondPeerAddress, secondAddress);
    EXPECT_FALSE(client->happyEyeballsConnAttemptDelayTimeout()
                     .isTimerCallbackScheduled());
    EXPECT_FALSE(conn.happyEyeballsState.shouldWriteToSecondSocket);
    EXPECT_TRUE(conn.happyEyeballsState.finished);
  }

  void nonFatalWriteErrorOnFirstBeforeSecondStarts(
      const SocketAddress& firstAddress,
      const SocketAddress& secondAddress) {
    auto& conn = client->getConn();
    TransportSettings settings;
    client->setTransportSettings(settings);
    EXPECT_CALL(*sock, write(firstAddress, _, _))
        .WillOnce(SetErrnoAndReturn(EAGAIN, -1));
    EXPECT_CALL(*secondSock, write(_, _, _));
    client->start(&clientConnSetupCallback, &clientConnCallback);
    EXPECT_EQ(conn.peerAddress, firstAddress);
    EXPECT_EQ(conn.happyEyeballsState.secondPeerAddress, secondAddress);
    // Continue trying first socket
    EXPECT_TRUE(conn.happyEyeballsState.shouldWriteToFirstSocket);
    EXPECT_TRUE(conn.happyEyeballsState.shouldWriteToSecondSocket);
    EXPECT_FALSE(client->happyEyeballsConnAttemptDelayTimeout()
                     .isTimerCallbackScheduled());

    EXPECT_CALL(*sock, write(firstAddress, _, _));
    EXPECT_CALL(*secondSock, write(secondAddress, _, _));
    client->lossTimeout().cancelTimerCallback();
    client->lossTimeout().timeoutExpired();
  }

  void fatalWriteErrorOnFirstBeforeSecondStarts(
      const SocketAddress& firstAddress,
      const SocketAddress& secondAddress) {
    auto& conn = client->getConn();
    EXPECT_CALL(*sock, write(firstAddress, _, _))
        .WillOnce(SetErrnoAndReturn(EBADF, -1));
    // Socket is paused read once during happy eyeballs
    // Socket is paused read for the second time when QuicClientTransport dies
    EXPECT_CALL(*sock, pauseRead()).Times(2);
    EXPECT_CALL(*sock, close()).Times(1);
    EXPECT_CALL(*secondSock, write(_, _, _));
    client->start(&clientConnSetupCallback, &clientConnCallback);
    EXPECT_EQ(conn.peerAddress, firstAddress);
    EXPECT_EQ(conn.happyEyeballsState.secondPeerAddress, secondAddress);
    // Give up first socket
    EXPECT_FALSE(conn.happyEyeballsState.shouldWriteToFirstSocket);
    EXPECT_TRUE(conn.happyEyeballsState.shouldWriteToSecondSocket);
    EXPECT_FALSE(client->happyEyeballsConnAttemptDelayTimeout()
                     .isTimerCallbackScheduled());

    EXPECT_CALL(*sock, write(_, _, _)).Times(0);
    EXPECT_CALL(*secondSock, write(secondAddress, _, _));
    client->lossTimeout().cancelTimerCallback();
    client->lossTimeout().timeoutExpired();
  }

#ifdef FOLLY_HAVE_MSG_ERRQUEUE
  void fatalReadErrorOnFirstBeforeSecondStarts(
      [[maybe_unused]] const SocketAddress& firstAddress,
      [[maybe_unused]] const SocketAddress& secondAddress) {
    auto& conn = client->getConn();
    EXPECT_CALL(*sock, write(firstAddress, _, _));
    // Socket is paused read once during happy eyeballs
    // Socket is paused read for the second time when QuicClientTransport dies
    EXPECT_CALL(*sock, pauseRead()).Times(2);
    EXPECT_CALL(*sock, close()).Times(1);
    client->start(&clientConnSetupCallback, &clientConnCallback);
    EXPECT_EQ(conn.peerAddress, firstAddress);
    EXPECT_EQ(conn.happyEyeballsState.secondPeerAddress, secondAddress);

    // Give up first socket
    union {
      struct cmsghdr hdr;
      unsigned char buf[CMSG_SPACE(sizeof(sock_extended_err))];
    } cmsgbuf;

    cmsgbuf.hdr.cmsg_level = SOL_IPV6;
    cmsgbuf.hdr.cmsg_type = IPV6_RECVERR;

    struct sock_extended_err err{};

    err.ee_errno = EBADF;
    auto dest = (struct sock_extended_err*)CMSG_DATA(&cmsgbuf.hdr);
    *dest = err;
    client->errMessage(cmsgbuf.hdr);
    EXPECT_FALSE(conn.happyEyeballsState.shouldWriteToFirstSocket);
    EXPECT_TRUE(conn.happyEyeballsState.shouldWriteToSecondSocket);
    EXPECT_FALSE(client->happyEyeballsConnAttemptDelayTimeout()
                     .isTimerCallbackScheduled());

    EXPECT_CALL(*sock, write(_, _, _)).Times(0);
    EXPECT_CALL(*secondSock, write(secondAddress, _, _));
    client->lossTimeout().cancelTimerCallback();
    client->lossTimeout().timeoutExpired();
  }

  void fatalReadErrorOnFirstAfterSecondStarts(
      [[maybe_unused]] const SocketAddress& firstAddress,
      [[maybe_unused]] const SocketAddress& secondAddress) {
    auto& conn = client->getConn();

    EXPECT_CALL(*sock, write(firstAddress, _, _));
    EXPECT_CALL(*secondSock, write(_, _, _)).Times(0);
    client->start(&clientConnSetupCallback, &clientConnCallback);
    EXPECT_EQ(conn.peerAddress, firstAddress);
    EXPECT_EQ(conn.happyEyeballsState.secondPeerAddress, secondAddress);
    EXPECT_TRUE(client->happyEyeballsConnAttemptDelayTimeout()
                    .isTimerCallbackScheduled());

    // Manually expire conn attempt timeout
    EXPECT_FALSE(conn.happyEyeballsState.shouldWriteToSecondSocket);
    client->happyEyeballsConnAttemptDelayTimeout().cancelTimerCallback();
    client->happyEyeballsConnAttemptDelayTimeout().timeoutExpired();
    EXPECT_TRUE(conn.happyEyeballsState.shouldWriteToSecondSocket);
    EXPECT_FALSE(client->happyEyeballsConnAttemptDelayTimeout()
                     .isTimerCallbackScheduled());

    EXPECT_CALL(*sock, pauseRead()).Times(2);
    EXPECT_CALL(*sock, close()).Times(1);

    union {
      struct cmsghdr hdr;
      unsigned char buf[CMSG_SPACE(sizeof(sock_extended_err))];
    } cmsgbuf;

    cmsgbuf.hdr.cmsg_level = SOL_IPV6;
    cmsgbuf.hdr.cmsg_type = IPV6_RECVERR;

    struct sock_extended_err err{};

    err.ee_errno = EBADF;
    auto dest = (struct sock_extended_err*)CMSG_DATA(&cmsgbuf.hdr);
    *dest = err;
    client->errMessage(cmsgbuf.hdr);

    EXPECT_FALSE(conn.happyEyeballsState.shouldWriteToFirstSocket);
    EXPECT_TRUE(conn.happyEyeballsState.shouldWriteToSecondSocket);

    EXPECT_CALL(*sock, write(_, _, _)).Times(0);
    EXPECT_CALL(*secondSock, write(secondAddress, _, _)).Times(1);
    client->lossTimeout().cancelTimerCallback();
    client->lossTimeout().timeoutExpired();
  }

  void fatalReadErrorOnSecondAfterSecondStarts(
      [[maybe_unused]] const SocketAddress& firstAddress,
      [[maybe_unused]] const SocketAddress& secondAddress) {
    auto& conn = client->getConn();

    EXPECT_CALL(*sock, write(firstAddress, _, _));
    EXPECT_CALL(*secondSock, write(_, _, _)).Times(0);
    client->start(&clientConnSetupCallback, &clientConnCallback);
    EXPECT_EQ(conn.peerAddress, firstAddress);
    EXPECT_EQ(conn.happyEyeballsState.secondPeerAddress, secondAddress);
    EXPECT_TRUE(client->happyEyeballsConnAttemptDelayTimeout()
                    .isTimerCallbackScheduled());

    // Manually expire conn attempt timeout
    EXPECT_FALSE(conn.happyEyeballsState.shouldWriteToSecondSocket);
    client->happyEyeballsConnAttemptDelayTimeout().cancelTimerCallback();
    client->happyEyeballsConnAttemptDelayTimeout().timeoutExpired();
    EXPECT_TRUE(conn.happyEyeballsState.shouldWriteToSecondSocket);
    EXPECT_FALSE(client->happyEyeballsConnAttemptDelayTimeout()
                     .isTimerCallbackScheduled());

    // Manually expire loss timeout to trigger write to both first and second
    // socket
    EXPECT_CALL(*sock, write(firstAddress, _, _));

    union {
      struct cmsghdr hdr;
      unsigned char buf[CMSG_SPACE(sizeof(sock_extended_err))];
    } cmsgbuf;

    cmsgbuf.hdr.cmsg_level = SOL_IP;
    cmsgbuf.hdr.cmsg_type = IP_RECVERR;

    struct sock_extended_err err{};

    err.ee_errno = EBADF;
    auto dest = (struct sock_extended_err*)CMSG_DATA(&cmsgbuf.hdr);
    *dest = err;
    client->errMessage(cmsgbuf.hdr);
    // Socket is paused read once during happy eyeballs
    EXPECT_CALL(*secondSock, pauseRead()).Times(1);
    EXPECT_CALL(*secondSock, close()).Times(1);
    client->lossTimeout().cancelTimerCallback();
    client->lossTimeout().timeoutExpired();

    EXPECT_TRUE(conn.happyEyeballsState.shouldWriteToFirstSocket);
    EXPECT_FALSE(conn.happyEyeballsState.shouldWriteToSecondSocket);

    EXPECT_CALL(*sock, write(firstAddress, _, _)).Times(1);
    EXPECT_CALL(*secondSock, write(_, _, _)).Times(0);
    client->lossTimeout().cancelTimerCallback();
    client->lossTimeout().timeoutExpired();
  }

  void fatalReadErrorOnBothAfterSecondStarts(
      [[maybe_unused]] const SocketAddress& firstAddress,
      [[maybe_unused]] const SocketAddress& secondAddress) {
    auto& conn = client->getConn();

    EXPECT_CALL(*sock, write(firstAddress, _, _));
    EXPECT_CALL(*secondSock, write(_, _, _)).Times(0);
    client->start(&clientConnSetupCallback, &clientConnCallback);
    EXPECT_EQ(conn.peerAddress, firstAddress);
    EXPECT_EQ(conn.happyEyeballsState.secondPeerAddress, secondAddress);
    EXPECT_TRUE(client->happyEyeballsConnAttemptDelayTimeout()
                    .isTimerCallbackScheduled());

    // Manually expire conn attempt timeout
    EXPECT_FALSE(conn.happyEyeballsState.shouldWriteToSecondSocket);
    client->happyEyeballsConnAttemptDelayTimeout().cancelTimerCallback();
    client->happyEyeballsConnAttemptDelayTimeout().timeoutExpired();
    EXPECT_TRUE(conn.happyEyeballsState.shouldWriteToSecondSocket);
    EXPECT_FALSE(client->happyEyeballsConnAttemptDelayTimeout()
                     .isTimerCallbackScheduled());

    union {
      struct cmsghdr hdr;
      unsigned char buf[CMSG_SPACE(sizeof(sock_extended_err))];
    } cmsgbuf;

    cmsgbuf.hdr.cmsg_level = SOL_IP;
    cmsgbuf.hdr.cmsg_type = IP_RECVERR;

    struct sock_extended_err err{};

    err.ee_errno = EBADF;
    auto dest = (struct sock_extended_err*)CMSG_DATA(&cmsgbuf.hdr);
    *dest = err;
    client->errMessage(cmsgbuf.hdr);
    cmsgbuf.hdr.cmsg_level = SOL_IPV6;
    cmsgbuf.hdr.cmsg_type = IPV6_RECVERR;
    client->errMessage(cmsgbuf.hdr);

    EXPECT_FALSE(conn.happyEyeballsState.shouldWriteToFirstSocket);
    EXPECT_FALSE(conn.happyEyeballsState.shouldWriteToSecondSocket);
  }
#endif

  void nonFatalWriteErrorOnFirstAfterSecondStarts(
      const SocketAddress& firstAddress,
      const SocketAddress& secondAddress) {
    auto& conn = client->getConn();

    EXPECT_CALL(*sock, write(firstAddress, _, _));
    EXPECT_CALL(*secondSock, write(_, _, _)).Times(0);
    client->start(&clientConnSetupCallback, &clientConnCallback);
    EXPECT_EQ(conn.peerAddress, firstAddress);
    EXPECT_EQ(conn.happyEyeballsState.secondPeerAddress, secondAddress);
    EXPECT_TRUE(client->happyEyeballsConnAttemptDelayTimeout()
                    .isTimerCallbackScheduled());

    // Manually expire conn attempt timeout
    EXPECT_FALSE(conn.happyEyeballsState.shouldWriteToSecondSocket);
    client->happyEyeballsConnAttemptDelayTimeout().cancelTimerCallback();
    client->happyEyeballsConnAttemptDelayTimeout().timeoutExpired();
    EXPECT_TRUE(conn.happyEyeballsState.shouldWriteToSecondSocket);
    EXPECT_FALSE(client->happyEyeballsConnAttemptDelayTimeout()
                     .isTimerCallbackScheduled());

    // Manually expire loss timeout to trigger write to both first and second
    // socket
    EXPECT_CALL(*sock, write(firstAddress, _, _))
        .WillOnce(SetErrnoAndReturn(EAGAIN, -1));
    EXPECT_CALL(*secondSock, write(secondAddress, _, _));
    client->lossTimeout().cancelTimerCallback();
    client->lossTimeout().timeoutExpired();

    EXPECT_TRUE(conn.happyEyeballsState.shouldWriteToFirstSocket);
    EXPECT_TRUE(conn.happyEyeballsState.shouldWriteToSecondSocket);

    EXPECT_CALL(*sock, write(firstAddress, _, _)).Times(1);
    EXPECT_CALL(*secondSock, write(secondAddress, _, _)).Times(1);
    client->lossTimeout().cancelTimerCallback();
    client->lossTimeout().timeoutExpired();
  }

  void fatalWriteErrorOnFirstAfterSecondStarts(
      const SocketAddress& firstAddress,
      const SocketAddress& secondAddress) {
    auto& conn = client->getConn();

    EXPECT_CALL(*sock, write(firstAddress, _, _));
    EXPECT_CALL(*secondSock, write(_, _, _)).Times(0);
    client->start(&clientConnSetupCallback, &clientConnCallback);
    EXPECT_EQ(conn.peerAddress, firstAddress);
    EXPECT_EQ(conn.happyEyeballsState.secondPeerAddress, secondAddress);
    EXPECT_TRUE(client->happyEyeballsConnAttemptDelayTimeout()
                    .isTimerCallbackScheduled());

    // Manually expire conn attempt timeout
    EXPECT_FALSE(conn.happyEyeballsState.shouldWriteToSecondSocket);
    client->happyEyeballsConnAttemptDelayTimeout().cancelTimerCallback();
    client->happyEyeballsConnAttemptDelayTimeout().timeoutExpired();
    EXPECT_TRUE(conn.happyEyeballsState.shouldWriteToSecondSocket);
    EXPECT_FALSE(client->happyEyeballsConnAttemptDelayTimeout()
                     .isTimerCallbackScheduled());

    // Manually expire loss timeout to trigger write to both first and second
    // socket
    EXPECT_CALL(*sock, write(firstAddress, _, _))
        .WillOnce(SetErrnoAndReturn(EBADF, -1));
    // Socket is paused read once during happy eyeballs
    // Socket is paused read for the second time when QuicClientTransport dies
    EXPECT_CALL(*sock, pauseRead()).Times(2);
    EXPECT_CALL(*sock, close()).Times(1);
    EXPECT_CALL(*secondSock, write(secondAddress, _, _));
    client->lossTimeout().cancelTimerCallback();
    client->lossTimeout().timeoutExpired();

    EXPECT_FALSE(conn.happyEyeballsState.shouldWriteToFirstSocket);
    EXPECT_TRUE(conn.happyEyeballsState.shouldWriteToSecondSocket);

    EXPECT_CALL(*sock, write(_, _, _)).Times(0);
    EXPECT_CALL(*secondSock, write(secondAddress, _, _)).Times(1);
    client->lossTimeout().cancelTimerCallback();
    client->lossTimeout().timeoutExpired();
  }

  void nonFatalWriteErrorOnSecondAfterSecondStarts(
      const SocketAddress& firstAddress,
      const SocketAddress& secondAddress) {
    auto& conn = client->getConn();

    EXPECT_CALL(*sock, write(firstAddress, _, _));
    EXPECT_CALL(*secondSock, write(_, _, _)).Times(0);
    client->start(&clientConnSetupCallback, &clientConnCallback);
    EXPECT_EQ(conn.peerAddress, firstAddress);
    EXPECT_EQ(conn.happyEyeballsState.secondPeerAddress, secondAddress);
    EXPECT_TRUE(client->happyEyeballsConnAttemptDelayTimeout()
                    .isTimerCallbackScheduled());

    // Manually expire conn attempt timeout
    EXPECT_FALSE(conn.happyEyeballsState.shouldWriteToSecondSocket);
    client->happyEyeballsConnAttemptDelayTimeout().cancelTimerCallback();
    client->happyEyeballsConnAttemptDelayTimeout().timeoutExpired();
    EXPECT_TRUE(conn.happyEyeballsState.shouldWriteToSecondSocket);
    EXPECT_FALSE(client->happyEyeballsConnAttemptDelayTimeout()
                     .isTimerCallbackScheduled());

    // Manually expire loss timeout to trigger write to both first and second
    // socket
    EXPECT_CALL(*sock, write(firstAddress, _, _));
    EXPECT_CALL(*secondSock, write(secondAddress, _, _))
        .WillOnce(SetErrnoAndReturn(EAGAIN, -1));
    client->lossTimeout().cancelTimerCallback();
    client->lossTimeout().timeoutExpired();

    EXPECT_TRUE(conn.happyEyeballsState.shouldWriteToFirstSocket);
    EXPECT_TRUE(conn.happyEyeballsState.shouldWriteToSecondSocket);

    EXPECT_CALL(*sock, write(firstAddress, _, _)).Times(1);
    EXPECT_CALL(*secondSock, write(secondAddress, _, _)).Times(1);
    client->lossTimeout().cancelTimerCallback();
    client->lossTimeout().timeoutExpired();
  }

  void fatalWriteErrorOnSecondAfterSecondStarts(
      const SocketAddress& firstAddress,
      const SocketAddress& secondAddress) {
    auto& conn = client->getConn();

    EXPECT_CALL(*sock, write(firstAddress, _, _));
    EXPECT_CALL(*secondSock, write(_, _, _)).Times(0);
    client->start(&clientConnSetupCallback, &clientConnCallback);
    EXPECT_EQ(conn.peerAddress, firstAddress);
    EXPECT_EQ(conn.happyEyeballsState.secondPeerAddress, secondAddress);
    EXPECT_TRUE(client->happyEyeballsConnAttemptDelayTimeout()
                    .isTimerCallbackScheduled());

    // Manually expire conn attempt timeout
    EXPECT_FALSE(conn.happyEyeballsState.shouldWriteToSecondSocket);
    client->happyEyeballsConnAttemptDelayTimeout().cancelTimerCallback();
    client->happyEyeballsConnAttemptDelayTimeout().timeoutExpired();
    EXPECT_TRUE(conn.happyEyeballsState.shouldWriteToSecondSocket);
    EXPECT_FALSE(client->happyEyeballsConnAttemptDelayTimeout()
                     .isTimerCallbackScheduled());

    // Manually expire loss timeout to trigger write to both first and second
    // socket
    EXPECT_CALL(*sock, write(firstAddress, _, _));
    EXPECT_CALL(*secondSock, write(secondAddress, _, _))
        .WillOnce(SetErrnoAndReturn(EBADF, -1));
    // Socket is paused read once during happy eyeballs
    // Socket is paused read for the second time when QuicClientTransport dies
    EXPECT_CALL(*secondSock, pauseRead()).Times(2);
    EXPECT_CALL(*secondSock, close()).Times(1);
    client->lossTimeout().cancelTimerCallback();
    client->lossTimeout().timeoutExpired();

    EXPECT_TRUE(conn.happyEyeballsState.shouldWriteToFirstSocket);
    EXPECT_FALSE(conn.happyEyeballsState.shouldWriteToSecondSocket);

    EXPECT_CALL(*sock, write(firstAddress, _, _)).Times(1);
    EXPECT_CALL(*secondSock, write(_, _, _)).Times(0);
    client->lossTimeout().cancelTimerCallback();
    client->lossTimeout().timeoutExpired();
  }

  void nonFatalWriteErrorOnBothAfterSecondStarts(
      const SocketAddress& firstAddress,
      const SocketAddress& secondAddress) {
    auto& conn = client->getConn();

    EXPECT_CALL(*sock, write(firstAddress, _, _));
    EXPECT_CALL(*secondSock, write(_, _, _)).Times(0);
    client->start(&clientConnSetupCallback, &clientConnCallback);
    EXPECT_EQ(conn.peerAddress, firstAddress);
    EXPECT_EQ(conn.happyEyeballsState.secondPeerAddress, secondAddress);
    EXPECT_TRUE(client->happyEyeballsConnAttemptDelayTimeout()
                    .isTimerCallbackScheduled());

    // Manually expire conn attempt timeout
    EXPECT_FALSE(conn.happyEyeballsState.shouldWriteToSecondSocket);
    client->happyEyeballsConnAttemptDelayTimeout().cancelTimerCallback();
    client->happyEyeballsConnAttemptDelayTimeout().timeoutExpired();
    EXPECT_TRUE(conn.happyEyeballsState.shouldWriteToSecondSocket);
    EXPECT_FALSE(client->happyEyeballsConnAttemptDelayTimeout()
                     .isTimerCallbackScheduled());

    // Manually expire loss timeout to trigger write to both first and second
    // socket
    EXPECT_CALL(*sock, write(firstAddress, _, _))
        .WillOnce(SetErrnoAndReturn(EAGAIN, -1));
    EXPECT_CALL(*secondSock, write(secondAddress, _, _))
        .WillOnce(SetErrnoAndReturn(EAGAIN, -1));
    client->lossTimeout().cancelTimerCallback();
    client->lossTimeout().timeoutExpired();

    EXPECT_TRUE(conn.happyEyeballsState.shouldWriteToFirstSocket);
    EXPECT_TRUE(conn.happyEyeballsState.shouldWriteToSecondSocket);

    EXPECT_CALL(*sock, write(firstAddress, _, _)).Times(1);
    EXPECT_CALL(*secondSock, write(secondAddress, _, _)).Times(1);
    client->lossTimeout().cancelTimerCallback();
    client->lossTimeout().timeoutExpired();
  }

  void fatalWriteErrorOnBothAfterSecondStarts(
      const SocketAddress& firstAddress,
      const SocketAddress& secondAddress) {
    auto& conn = client->getConn();

    EXPECT_CALL(*sock, write(firstAddress, _, _));
    EXPECT_CALL(*secondSock, write(_, _, _)).Times(0);
    client->start(&clientConnSetupCallback, &clientConnCallback);
    EXPECT_EQ(conn.peerAddress, firstAddress);
    EXPECT_EQ(conn.happyEyeballsState.secondPeerAddress, secondAddress);
    EXPECT_TRUE(client->happyEyeballsConnAttemptDelayTimeout()
                    .isTimerCallbackScheduled());

    // Manually expire conn attempt timeout
    EXPECT_FALSE(conn.happyEyeballsState.shouldWriteToSecondSocket);
    client->happyEyeballsConnAttemptDelayTimeout().cancelTimerCallback();
    client->happyEyeballsConnAttemptDelayTimeout().timeoutExpired();
    EXPECT_TRUE(conn.happyEyeballsState.shouldWriteToSecondSocket);
    EXPECT_FALSE(client->happyEyeballsConnAttemptDelayTimeout()
                     .isTimerCallbackScheduled());

    // Manually expire loss timeout to trigger write to both first and second
    // socket
    EXPECT_CALL(*sock, write(firstAddress, _, _))
        .WillOnce(SetErrnoAndReturn(EBADF, -1));
    EXPECT_CALL(*secondSock, write(secondAddress, _, _))
        .WillOnce(SetErrnoAndReturn(EBADF, -1));
    EXPECT_CALL(clientConnSetupCallback, onConnectionSetupError(_));
    client->lossTimeout().cancelTimerCallback();
    client->lossTimeout().timeoutExpired();

    EXPECT_FALSE(conn.happyEyeballsState.shouldWriteToFirstSocket);
    EXPECT_FALSE(conn.happyEyeballsState.shouldWriteToSecondSocket);
  }

 protected:
  quic::test::MockAsyncUDPSocket* secondSock;
  SocketAddress serverAddrV4{"127.0.0.1", 443};
  SocketAddress serverAddrV6{"::1", 443};
};

INSTANTIATE_TEST_SUITE_P(
    QuicClientTransportHappyEyeballsTests,
    QuicClientTransportHappyEyeballsTest,
    ::testing::Values(
        ServerFirstPacketType::ServerHello,
        ServerFirstPacketType::Retry));

TEST_P(QuicClientTransportHappyEyeballsTest, V6FirstAndV6WinBeforeV4Start) {
  firstWinBeforeSecondStart(serverAddrV6, serverAddrV4);
}

TEST_P(QuicClientTransportHappyEyeballsTest, V6FirstAndV6WinAfterV4Start) {
  firstWinAfterSecondStart(serverAddrV6, serverAddrV4);
}

TEST_P(QuicClientTransportHappyEyeballsTest, V6FirstAndV4Win) {
  secondWin(serverAddrV6, serverAddrV4);
}

TEST_P(QuicClientTransportHappyEyeballsTest, V6FirstAndV4BindFailure) {
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

#ifdef FOLLY_HAVE_MSG_ERRQUEUE
TEST_F(
    QuicClientTransportHappyEyeballsTest,
    V6FirstAndV6FatalReadErrorBeforeV4Start) {
  fatalReadErrorOnFirstBeforeSecondStarts(serverAddrV6, serverAddrV4);
}

TEST_F(
    QuicClientTransportHappyEyeballsTest,
    V6FirstAndV6FatalReadErrorAfterV4Start) {
  fatalReadErrorOnFirstAfterSecondStarts(serverAddrV6, serverAddrV4);
}

TEST_F(
    QuicClientTransportHappyEyeballsTest,
    V6FirstAndBothFatalReadErrorAfterV4Start) {
  fatalReadErrorOnBothAfterSecondStarts(serverAddrV6, serverAddrV4);
}

TEST_F(
    QuicClientTransportHappyEyeballsTest,
    V6FirstAndV4FatalReadErrorAfterV4Start) {
  fatalReadErrorOnSecondAfterSecondStarts(serverAddrV6, serverAddrV4);
}
#endif

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

TEST_P(QuicClientTransportHappyEyeballsTest, V4FirstAndV4WinBeforeV6Start) {
  client->setHappyEyeballsCachedFamily(AF_INET);
  firstWinBeforeSecondStart(serverAddrV4, serverAddrV6);
}

TEST_P(QuicClientTransportHappyEyeballsTest, V4FirstAndV4WinAfterV6Start) {
  client->setHappyEyeballsCachedFamily(AF_INET);
  firstWinAfterSecondStart(serverAddrV4, serverAddrV6);
}

TEST_P(QuicClientTransportHappyEyeballsTest, V4FirstAndV6Win) {
  client->setHappyEyeballsCachedFamily(AF_INET);
  secondWin(serverAddrV4, serverAddrV6);
}

TEST_P(QuicClientTransportHappyEyeballsTest, V4FirstAndV6BindFailure) {
  client->setHappyEyeballsCachedFamily(AF_INET);
  secondBindFailure(serverAddrV4, serverAddrV6);
}

TEST_P(
    QuicClientTransportHappyEyeballsTest,
    V4FirstAndV4NonFatalErrorBeforeV6Start) {
  client->setHappyEyeballsCachedFamily(AF_INET);
  nonFatalWriteErrorOnFirstBeforeSecondStarts(serverAddrV4, serverAddrV6);
}

TEST_P(
    QuicClientTransportHappyEyeballsTest,
    V4FirstAndV4FatalErrorBeforeV6Start) {
  client->setHappyEyeballsCachedFamily(AF_INET);
  fatalWriteErrorOnFirstBeforeSecondStarts(serverAddrV4, serverAddrV6);
}

TEST_P(
    QuicClientTransportHappyEyeballsTest,
    V4FirstAndV4NonFatalErrorAfterV6Start) {
  client->setHappyEyeballsCachedFamily(AF_INET);
  nonFatalWriteErrorOnFirstAfterSecondStarts(serverAddrV4, serverAddrV6);
}

TEST_P(
    QuicClientTransportHappyEyeballsTest,
    V4FirstAndV4FatalErrorAfterV6Start) {
  client->setHappyEyeballsCachedFamily(AF_INET);
  fatalWriteErrorOnFirstAfterSecondStarts(serverAddrV4, serverAddrV6);
}

TEST_P(
    QuicClientTransportHappyEyeballsTest,
    V4FirstAndV6NonFatalErrorAfterV6Start) {
  client->setHappyEyeballsCachedFamily(AF_INET);
  nonFatalWriteErrorOnSecondAfterSecondStarts(serverAddrV4, serverAddrV6);
}

TEST_P(
    QuicClientTransportHappyEyeballsTest,
    V4FirstAndV6FatalErrorAfterV6Start) {
  client->setHappyEyeballsCachedFamily(AF_INET);
  fatalWriteErrorOnSecondAfterSecondStarts(serverAddrV4, serverAddrV6);
}

TEST_P(
    QuicClientTransportHappyEyeballsTest,
    V4FirstAndBothNonFatalErrorAfterV6Start) {
  client->setHappyEyeballsCachedFamily(AF_INET);
  nonFatalWriteErrorOnBothAfterSecondStarts(serverAddrV4, serverAddrV6);
}

TEST_P(
    QuicClientTransportHappyEyeballsTest,
    V4FirstAndBothFatalErrorAfterV6Start) {
  client->setHappyEyeballsCachedFamily(AF_INET);
  fatalWriteErrorOnBothAfterSecondStarts(serverAddrV4, serverAddrV6);
}

class QuicClientTransportAfterStartTest
    : public QuicClientTransportAfterStartTestBase,
      public testing::WithParamInterface<uint8_t> {};

INSTANTIATE_TEST_SUITE_P(
    QuicClientZeroLenConnIds,
    QuicClientTransportAfterStartTest,
    ::Values(0, 8));

class QuicClientTransportVersionAndRetryTest
    : public QuicClientTransportAfterStartTestBase {
 public:
  ~QuicClientTransportVersionAndRetryTest() override = default;

  void start() override {
    client->start(&clientConnSetupCallback, &clientConnCallback);
    originalConnId = client->getConn().clientConnectionId;
    // create server chosen connId with processId = 0 and workerId = 0
    ServerConnectionIdParams params(0, 0, 0);
    serverChosenConnId = *connIdAlgo_->encodeConnectionId(params);
    // The tests that we do here create streams before crypto is finished,
    // so we initialize the peer streams, to allow for this behavior. TODO: when
    // 0-rtt support exists, remove this.
    client->getNonConstConn()
        .flowControlState.peerAdvertisedInitialMaxStreamOffsetBidiLocal =
        kDefaultStreamFlowControlWindow;
    client->getNonConstConn()
        .flowControlState.peerAdvertisedInitialMaxStreamOffsetBidiRemote =
        kDefaultStreamFlowControlWindow;
    client->getNonConstConn()
        .flowControlState.peerAdvertisedInitialMaxStreamOffsetUni =
        kDefaultStreamFlowControlWindow;
    client->getNonConstConn().flowControlState.peerAdvertisedMaxOffset =
        kDefaultConnectionFlowControlWindow;
  }
};

class QuicClientVersionParamInvalidTest
    : public QuicClientTransportAfterStartTestBase {
 public:
  ~QuicClientVersionParamInvalidTest() override = default;

  void start() override {
    // force the server to declare that the version negotiated was invalid.;
    mockClientHandshake->negotiatedVersion = MVFST2;

    client->start(&clientConnSetupCallback, &clientConnCallback);
    originalConnId = client->getConn().clientConnectionId;
  }
};

TEST_F(QuicClientTransportAfterStartTest, ReadStream) {
  StreamId streamId = client->createBidirectionalStream().value();

  auto fizzClientSetReadCallback3 = client->setReadCallback(streamId, &readCb);
  bool dataDelivered = false;
  auto expected = IOBuf::copyBuffer("hello");
  EXPECT_CALL(readCb, readAvailable(streamId)).WillOnce(Invoke([&](auto) {
    auto readData = client->read(streamId, 1000);
    auto copy = readData->first->clone();
    LOG(INFO) << "Client received data=" << copy->to<std::string>()
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
  client->close(std::nullopt);
}

TEST_F(QuicClientTransportAfterStartTest, CleanupReadLoopCounting) {
  auto streamId = client->createBidirectionalStream().value();
  auto& conn = client->getNonConstConn();
  auto mockLoopDetectorCallback = std::make_unique<MockLoopDetectorCallback>();
  conn.loopDetectorCallback = std::move(mockLoopDetectorCallback);

  conn.readDebugState.noReadReason = NoReadReason::RETRIABLE_ERROR;
  conn.readDebugState.loopCount = 20;

  auto data = IOBuf::copyBuffer("Short Trip Home");
  auto packet = packetToBuf(createStreamPacket(
      *serverChosenConnId /* src */,
      *originalConnId /* dest */,
      appDataPacketNum++,
      streamId,
      *data,
      0 /* cipherOverhead */,
      0 /* largestAcked */));
  deliverData(packet->coalesce());
  EXPECT_EQ(NoReadReason::READ_OK, conn.readDebugState.noReadReason);
  EXPECT_EQ(0, conn.readDebugState.loopCount);
}

TEST_F(QuicClientTransportAfterStartTest, StaleReadLoopCounting) {
  auto& conn = client->getNonConstConn();
  auto mockLoopDetectorCallback = std::make_unique<MockLoopDetectorCallback>();
  conn.loopDetectorCallback = std::move(mockLoopDetectorCallback);

  auto data = IOBuf::copyBuffer("Short Trip Home");
  deliverData(data->coalesce());
  EXPECT_EQ(NoReadReason::STALE_DATA, conn.readDebugState.noReadReason);
}

TEST_F(QuicClientTransportAfterStartTest, RetriableErrorLoopCounting) {
  auto& conn = client->getNonConstConn();
  auto mockLoopDetectorCallback = std::make_unique<MockLoopDetectorCallback>();
  auto rawLoopDetectorCallback = mockLoopDetectorCallback.get();
  conn.loopDetectorCallback = std::move(mockLoopDetectorCallback);

  conn.transportSettings.maxRecvBatchSize = 1;
  // Empty socketReads will lead to EAGAIN in mock setup.
  EXPECT_CALL(
      *rawLoopDetectorCallback,
      onSuspiciousReadLoops(1, NoReadReason::RETRIABLE_ERROR));
  client->invokeOnNotifyDataAvailable(*sock);
}

TEST_F(QuicClientTransportAfterStartTest, PartialReadLoopCounting) {
  auto streamId = client->createBidirectionalStream().value();
  auto& conn = client->getNonConstConn();
  auto mockLoopDetectorCallback = std::make_unique<MockLoopDetectorCallback>();
  auto rawLoopDetectorCallback = mockLoopDetectorCallback.get();
  conn.loopDetectorCallback = std::move(mockLoopDetectorCallback);

  auto data = IOBuf::copyBuffer("Short Trip Home");
  auto packet = packetToBuf(createStreamPacket(
      *serverChosenConnId /* src */,
      *originalConnId /* dest */,
      appDataPacketNum++,
      streamId,
      *data,
      0 /* cipherOverhead */,
      0 /* largestAcked */));

  // Read twice in the loop, once success, then fail. Loop detector shouldn't
  // fire.
  conn.transportSettings.maxRecvBatchSize = 2;
  socketReads.emplace_back(packet->coalesce(), serverAddr);
  socketReads.emplace_back(EBADF);
  EXPECT_CALL(*rawLoopDetectorCallback, onSuspiciousReadLoops(_, _)).Times(0);
  client->invokeOnNotifyDataAvailable(*sock);
}

TEST_F(QuicClientTransportAfterStartTest, ReadStreamMultiplePackets) {
  StreamId streamId = client->createBidirectionalStream().value();

  auto fizzClientSetReadCallback4 = client->setReadCallback(streamId, &readCb);
  bool dataDelivered = false;
  auto data = IOBuf::copyBuffer("hello");

  auto expected = data->clone();
  expected->appendToChain(data->clone());
  EXPECT_CALL(readCb, readAvailable(streamId)).WillOnce(Invoke([&](auto) {
    auto readData = client->read(streamId, 1000);
    auto copy = readData->first->clone();
    LOG(INFO) << "Client received data=" << copy->clone()->to<std::string>()
              << " on stream=" << streamId;
    EXPECT_EQ(copy->to<std::string>(), expected->clone()->to<std::string>());
    dataDelivered = true;
    eventbase_->terminateLoopSoon();
  }));
  auto packet1 = packetToBuf(createStreamPacket(
      *serverChosenConnId /* src */,
      *originalConnId /* dest */,
      appDataPacketNum++,
      streamId,
      *data,
      0 /* cipherOverhead */,
      0 /* largestAcked */,
      std::nullopt /* longHeaderOverride */,
      false /* eof */));
  auto packet2 = packetToBuf(createStreamPacket(
      *serverChosenConnId /* src */,
      *originalConnId /* dest */,
      appDataPacketNum++,
      streamId,
      *data,
      0 /* cipherOverhead */,
      0 /* largestAcked */,
      std::nullopt /* longHeaderOverride */,
      true /* eof */,
      std::nullopt /* shortHeaderOverride */,
      data->length() /* offset */));

  socketReads.emplace_back(packet1->coalesce(), serverAddr);
  deliverData(packet2->coalesce());
  if (!dataDelivered) {
    eventbase_->loopForever();
  }
  EXPECT_TRUE(dataDelivered);
  client->close(std::nullopt);
}

TEST_F(QuicClientTransportAfterStartTest, ReadStreamWithRetriableError) {
  StreamId streamId = client->createBidirectionalStream().value();
  auto fizzClientSetReadCallback5 = client->setReadCallback(streamId, &readCb);
  EXPECT_CALL(readCb, readAvailable(_)).Times(0);
  EXPECT_CALL(readCb, readError(_, _)).Times(0);
  deliverNetworkError(EAGAIN);
  auto fizzClientSetReadCallback6 = client->setReadCallback(streamId, nullptr);
  client->close(std::nullopt);
}

TEST_F(QuicClientTransportAfterStartTest, ReadStreamWithNonRetriableError) {
  StreamId streamId = client->createBidirectionalStream().value();
  auto fizzClientSetReadCallback7 = client->setReadCallback(streamId, &readCb);
  EXPECT_CALL(readCb, readAvailable(_)).Times(0);
  // TODO: we currently do not close the socket, but maybe we can in the future.
  EXPECT_CALL(readCb, readError(_, _)).Times(0);
  deliverNetworkError(EBADF);
  auto fizzClientSetReadCallback8 = client->setReadCallback(streamId, nullptr);
  client->close(std::nullopt);
}

TEST_F(
    QuicClientTransportAfterStartTest,
    ReadStreamMultiplePacketsWithRetriableError) {
  StreamId streamId = client->createBidirectionalStream().value();

  auto fizzClientSetReadCallback9 = client->setReadCallback(streamId, &readCb);
  bool dataDelivered = false;
  auto expected = IOBuf::copyBuffer("hello");
  EXPECT_CALL(readCb, readAvailable(streamId)).WillOnce(Invoke([&](auto) {
    auto readData = client->read(streamId, 1000);
    auto copy = readData->first->clone();
    LOG(INFO) << "Client received data=" << copy->to<std::string>()
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

  socketReads.emplace_back(packet->coalesce(), serverAddr);
  deliverNetworkError(EAGAIN);
  if (!dataDelivered) {
    eventbase_->loopForever();
  }
  EXPECT_TRUE(dataDelivered);
  client->close(std::nullopt);
}

TEST_F(
    QuicClientTransportAfterStartTest,
    ReadStreamMultiplePacketsWithNonRetriableError) {
  StreamId streamId = client->createBidirectionalStream().value();

  auto fizzClientSetReadCallback10 = client->setReadCallback(streamId, &readCb);
  auto expected = IOBuf::copyBuffer("hello");
  EXPECT_CALL(readCb, readAvailable(streamId)).Times(0);

  // TODO: we currently do not close the socket, but maybe we can in the future.
  EXPECT_CALL(readCb, readError(_, _)).Times(0);
  auto packet = packetToBuf(createStreamPacket(
      *serverChosenConnId /* src */,
      *originalConnId /* dest */,
      appDataPacketNum++,
      streamId,
      *expected,
      0 /* cipherOverhead */,
      0 /* largestAcked */));

  {
    EXPECT_CALL(*sock, pauseRead()).Times(AtLeast(1));
    socketReads.emplace_back(packet->coalesce(), serverAddr);
    deliverNetworkError(EBADF);
  }
  auto fizzClientSetReadCallback11 = client->setReadCallback(streamId, nullptr);
}

TEST_F(QuicClientTransportAfterStartTest, RecvNewConnectionIdValid) {
  auto& conn = client->getNonConstConn();
  conn.transportSettings.selfActiveConnectionIdLimit = 1;

  ShortHeader header(ProtectionType::KeyPhaseZero, *conn.clientConnectionId, 1);
  RegularQuicPacketBuilder builder(
      conn.udpSendPacketLen, std::move(header), 0 /* largestAcked */);
  ASSERT_FALSE(builder.encodePacketHeader().hasError());
  ASSERT_TRUE(builder.canBuildPacket());

  auto token = StatelessResetToken{1, 9, 2, 0};
  NewConnectionIdFrame newConnId(
      1, 0, ConnectionId::createAndMaybeCrash({2, 4, 2, 3}), token);
  ASSERT_FALSE(
      writeSimpleFrame(QuicSimpleFrame(newConnId), builder).hasError());

  auto packet = std::move(builder).buildPacket();
  auto data = packetToBuf(packet);

  EXPECT_EQ(conn.peerConnectionIds.size(), 1);
  deliverData(data->coalesce(), false);
  EXPECT_EQ(conn.peerConnectionIds.size(), 2);
  EXPECT_EQ(conn.peerConnectionIds[1].connId, newConnId.connectionId);
  EXPECT_EQ(conn.peerConnectionIds[1].sequenceNumber, newConnId.sequenceNumber);
  EXPECT_EQ(conn.peerConnectionIds[1].token, newConnId.token);
}

TEST_F(QuicClientTransportAfterStartTest, ShortHeaderPacketWithNoFrames) {
  auto qLogger = std::make_shared<FileQLogger>(VantagePoint::Client);
  client->getNonConstConn().qLogger = qLogger;
  // Use large packet number to make sure packet is long enough to parse
  PacketNum nextPacket = 0x11111111;
  client->getNonConstConn().clientConnectionId = getTestConnectionId();
  auto aead = dynamic_cast<const MockAead*>(
      client->getNonConstConn().readCodec->getOneRttReadCipher());
  // Override the Aead mock to remove the 20 bytes of dummy data added below
  ON_CALL(*aead, _tryDecrypt(_, _, _))
      .WillByDefault(Invoke([&](auto& buf, auto, auto) {
        buf->trimEnd(20);
        return buf->clone();
      }));
  ShortHeader header(
      ProtectionType::KeyPhaseZero,
      *client->getConn().clientConnectionId,
      nextPacket);
  RegularQuicPacketBuilder builder(
      client->getConn().udpSendPacketLen,
      std::move(header),
      0 /* largestAcked */);
  ASSERT_FALSE(builder.encodePacketHeader().hasError());
  ASSERT_TRUE(builder.canBuildPacket());
  BufPtr buf = packetToBuf(std::move(builder).buildPacket());
  buf->coalesce();
  buf->reserve(0, 200);
  buf->append(20);
  EXPECT_THROW(deliverData(buf->coalesce()), std::runtime_error);
  std::vector<int> indices =
      getQLogEventIndices(QLogEventType::PacketDrop, qLogger);
  EXPECT_EQ(indices.size(), 1);

  auto tmp = std::move(qLogger->logs[indices[0]]);
  auto event = dynamic_cast<QLogPacketDropEvent*>(tmp.get());
  EXPECT_EQ(
      event->dropReason, (+PacketDropReason::PROTOCOL_VIOLATION)._to_string());
}

TEST_F(
    QuicClientTransportAfterStartTest,
    RecvNewConnectionIdTooManyReceivedIds) {
  auto& conn = client->getNonConstConn();
  conn.transportSettings.selfActiveConnectionIdLimit = 0;

  ShortHeader header(ProtectionType::KeyPhaseZero, *conn.clientConnectionId, 1);
  RegularQuicPacketBuilder builder(
      conn.udpSendPacketLen, std::move(header), 0 /* largestAcked */);
  ASSERT_FALSE(builder.encodePacketHeader().hasError());
  ASSERT_TRUE(builder.canBuildPacket());
  NewConnectionIdFrame newConnId(
      1,
      0,
      ConnectionId::createAndMaybeCrash({2, 4, 2, 3}),
      StatelessResetToken());
  ASSERT_FALSE(
      writeSimpleFrame(QuicSimpleFrame(newConnId), builder).hasError());

  auto packet = std::move(builder).buildPacket();
  auto data = packetToBuf(packet);

  EXPECT_EQ(conn.peerConnectionIds.size(), 1);
  deliverData(data->coalesce(), false);
  EXPECT_EQ(conn.peerConnectionIds.size(), 1);
}

TEST_F(QuicClientTransportAfterStartTest, RecvNewConnectionIdInvalidRetire) {
  auto& conn = client->getNonConstConn();
  conn.transportSettings.selfActiveConnectionIdLimit = 1;

  ShortHeader header(ProtectionType::KeyPhaseZero, *conn.clientConnectionId, 1);
  RegularQuicPacketBuilder builder(
      conn.udpSendPacketLen, std::move(header), 0 /* largestAcked */);
  ASSERT_FALSE(builder.encodePacketHeader().hasError());
  ASSERT_TRUE(builder.canBuildPacket());
  NewConnectionIdFrame newConnId(
      1,
      3,
      ConnectionId::createAndMaybeCrash({2, 4, 2, 3}),
      StatelessResetToken());
  ASSERT_FALSE(
      writeSimpleFrame(QuicSimpleFrame(newConnId), builder).hasError());

  auto packet = std::move(builder).buildPacket();
  auto data = packetToBuf(packet);

  EXPECT_EQ(conn.peerConnectionIds.size(), 1);
  EXPECT_THROW(deliverData(data->coalesce()), std::runtime_error);
}

TEST_F(QuicClientTransportAfterStartTest, RecvNewConnectionIdUsing0LenCid) {
  auto& conn = client->getNonConstConn();
  conn.transportSettings.selfActiveConnectionIdLimit = 2;

  conn.serverConnectionId = ConnectionId::createZeroLength();
  conn.peerConnectionIds.pop_back();
  conn.peerConnectionIds.emplace_back(*conn.serverConnectionId, 0);

  ShortHeader header(ProtectionType::KeyPhaseZero, *conn.clientConnectionId, 1);
  RegularQuicPacketBuilder builder(
      conn.udpSendPacketLen, std::move(header), 0 /* largestAcked */);
  ASSERT_FALSE(builder.encodePacketHeader().hasError());
  ASSERT_TRUE(builder.canBuildPacket());
  NewConnectionIdFrame newConnId(
      1,
      0,
      ConnectionId::createAndMaybeCrash({2, 4, 2, 3}),
      StatelessResetToken());
  ASSERT_FALSE(
      writeSimpleFrame(QuicSimpleFrame(newConnId), builder).hasError());

  auto packet = std::move(builder).buildPacket();
  auto data = packetToBuf(packet);

  EXPECT_EQ(conn.peerConnectionIds.size(), 1);
  try {
    deliverData(data->coalesce(), false);
    FAIL();
  } catch (const std::runtime_error& e) {
    EXPECT_EQ(
        std::string(e.what()),
        "TransportError: Protocol violation, Endpoint is already using 0-len connection ids.");
  }
  EXPECT_EQ(conn.peerConnectionIds.size(), 1);
}

TEST_F(
    QuicClientTransportAfterStartTest,
    RecvNewConnectionIdNoopValidDuplicate) {
  auto& conn = client->getNonConstConn();
  conn.transportSettings.selfActiveConnectionIdLimit = 1;

  ConnectionId connId2 = ConnectionId::createAndMaybeCrash({5, 5, 5, 5});
  conn.peerConnectionIds.emplace_back(connId2, 1);

  ShortHeader header(ProtectionType::KeyPhaseZero, *conn.clientConnectionId, 1);
  RegularQuicPacketBuilder builder(
      conn.udpSendPacketLen, std::move(header), 0 /* largestAcked */);
  ASSERT_FALSE(builder.encodePacketHeader().hasError());
  ASSERT_TRUE(builder.canBuildPacket());
  NewConnectionIdFrame newConnId(1, 0, connId2, StatelessResetToken());
  ASSERT_FALSE(
      writeSimpleFrame(QuicSimpleFrame(newConnId), builder).hasError());

  auto packet = std::move(builder).buildPacket();
  auto data = packetToBuf(packet);

  EXPECT_EQ(conn.peerConnectionIds.size(), 2);
  deliverData(data->coalesce(), false);
  EXPECT_EQ(conn.peerConnectionIds.size(), 2);
}

TEST_F(
    QuicClientTransportAfterStartTest,
    RecvNewConnectionIdExceptionInvalidDuplicate) {
  auto& conn = client->getNonConstConn();
  conn.transportSettings.selfActiveConnectionIdLimit = 1;

  ConnectionId connId2 = ConnectionId::createAndMaybeCrash({5, 5, 5, 5});
  conn.peerConnectionIds.emplace_back(connId2, 1);

  ShortHeader header(ProtectionType::KeyPhaseZero, *conn.clientConnectionId, 1);
  RegularQuicPacketBuilder builder(
      conn.udpSendPacketLen, std::move(header), 0 /* largestAcked */);
  ASSERT_FALSE(builder.encodePacketHeader().hasError());
  ASSERT_TRUE(builder.canBuildPacket());
  NewConnectionIdFrame newConnId(2, 0, connId2, StatelessResetToken());
  ASSERT_FALSE(
      writeSimpleFrame(QuicSimpleFrame(newConnId), builder).hasError());

  auto packet = std::move(builder).buildPacket();
  auto data = packetToBuf(packet);

  EXPECT_EQ(conn.peerConnectionIds.size(), 2);
  EXPECT_THROW(deliverData(data->coalesce()), std::runtime_error);
}

TEST_P(QuicClientTransportAfterStartTest, ReadStreamCoalesced) {
  expectQuicStatsPacketDrop(PacketDropReason::PARSE_ERROR_CLIENT);
  uint8_t connIdSize = GetParam();

  client->getNonConstConn().clientConnectionId =
      ConnectionId::createAndMaybeCrash(std::vector<uint8_t>(connIdSize, 1));
  setConnectionIds();

  StreamId streamId = client->createBidirectionalStream().value();
  auto qLogger = std::make_shared<FileQLogger>(VantagePoint::Client);
  client->getNonConstConn().qLogger = qLogger;

  auto fizzClientSetReadCallback12 = client->setReadCallback(streamId, &readCb);
  bool dataDelivered = false;
  auto expected = IOBuf::copyBuffer("hello");
  EXPECT_CALL(readCb, readAvailable(streamId)).WillOnce(Invoke([&](auto) {
    auto readData = client->read(streamId, 1000);
    auto copy = readData->first->clone();
    LOG(INFO) << "Client received data=" << copy->to<std::string>()
              << " on stream=" << streamId;
    EXPECT_TRUE(folly::IOBufEqualTo()((*readData).first, expected));
    dataDelivered = true;
    eventbase_->terminateLoopSoon();
  }));

  FizzCryptoFactory cryptoFactory;
  auto garbage = IOBuf::copyBuffer("garbage");
  auto initialCipherResult = cryptoFactory.getServerInitialCipher(
      *serverChosenConnId, QuicVersion::MVFST);
  ASSERT_FALSE(initialCipherResult.hasError());
  auto& initialCipher = initialCipherResult.value();
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
  client->close(std::nullopt);
  std::vector<int> indices =
      getQLogEventIndices(QLogEventType::PacketDrop, qLogger);
  EXPECT_EQ(indices.size(), 1);
  auto tmp = std::move(qLogger->logs[indices[0]]);
  auto event = dynamic_cast<QLogPacketDropEvent*>(tmp.get());
  EXPECT_EQ(event->packetSize, 65 + (2 * connIdSize));
  EXPECT_EQ(event->dropReason, kParse);
}

TEST_F(QuicClientTransportAfterStartTest, ReadStreamCoalescedMany) {
  StreamId streamId = client->createBidirectionalStream().value();

  auto fizzClientSetReadCallback13 = client->setReadCallback(streamId, &readCb);
  auto expected = IOBuf::copyBuffer("hello");
  EXPECT_CALL(readCb, readAvailable(streamId)).Times(0);
  FizzCryptoFactory cryptoFactory;
  BufQueue packets;
  for (int i = 0; i < kMaxNumCoalescedPackets; i++) {
    auto garbage = IOBuf::copyBuffer("garbage");
    auto initialCipherResult = cryptoFactory.getServerInitialCipher(
        *serverChosenConnId, QuicVersion::MVFST);
    ASSERT_FALSE(initialCipherResult.hasError());
    auto& initialCipher = initialCipherResult.value();

    auto packetNum = appDataPacketNum++;
    auto packet1 = packetToBufCleartext(
        createStreamPacket(
            *serverChosenConnId /* src */,
            *originalConnId /* dest */,
            packetNum,
            streamId,
            *garbage,
            initialCipher.get()->getCipherOverhead(),
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
  client->close(std::nullopt);
}

// TODO: JBESHAY MIGRATION - Rewrite the following two tests with the client
// migration support. According to RFC9000, there is no requirement for the
// client to use a new connection id whenever it receives a path challenge. This
// was probably used as a proxy for detecting that a passive migration
// happened in the older implementation of connection migration.

// TEST_F(QuicClientTransportAfterStartTest,
// RecvPathChallengeNoAvailablePeerIds) {
//   auto& conn = client->getNonConstConn();

//   ShortHeader header(ProtectionType::KeyPhaseZero, *conn.clientConnectionId,
//   1); RegularQuicPacketBuilder builder(
//       conn.udpSendPacketLen, std::move(header), 0 /* largestAcked */);
//   ASSERT_FALSE(builder.encodePacketHeader().hasError());
//   PathChallengeFrame pathChallenge(123);
//   ASSERT_TRUE(builder.canBuildPacket());
//   ASSERT_FALSE(
//       writeSimpleFrame(QuicSimpleFrame(pathChallenge), builder).hasError());

//   auto packet = std::move(builder).buildPacket();
//   auto data = packetToBuf(packet);

//   EXPECT_TRUE(conn.pendingEvents.frames.empty());
//   EXPECT_THROW(deliverData(data->coalesce(), false), std::runtime_error);
// }

// TEST_F(QuicClientTransportAfterStartTest, RecvPathChallengeAvailablePeerId) {
//   auto& conn = client->getNonConstConn();
//   auto originalCid = ConnectionIdData(
//       ConnectionId::createAndMaybeCrash(std::vector<uint8_t>{1, 2, 3, 4}),
//       1);
//   auto secondCid = ConnectionIdData(
//       ConnectionId::createAndMaybeCrash(std::vector<uint8_t>{5, 6, 7, 8}),
//       2);

//   conn.serverConnectionId = originalCid.connId;

//   conn.peerConnectionIds.push_back(originalCid);
//   conn.peerConnectionIds.push_back(secondCid);

//   ShortHeader header(ProtectionType::KeyPhaseZero, *conn.clientConnectionId,
//   1); RegularQuicPacketBuilder builder(
//       conn.udpSendPacketLen, std::move(header), 0 /* largestAcked */);
//   ASSERT_FALSE(builder.encodePacketHeader().hasError());
//   PathChallengeFrame pathChallenge(123);
//   ASSERT_TRUE(builder.canBuildPacket());
//   ASSERT_FALSE(
//       writeSimpleFrame(QuicSimpleFrame(pathChallenge), builder).hasError());

//   auto packet = std::move(builder).buildPacket();
//   auto data = packetToBuf(packet);

//   EXPECT_TRUE(conn.pendingEvents.frames.empty());
//   deliverData(data->coalesce(), false);

//   EXPECT_EQ(conn.pendingEvents.frames.size(), 2);

//   // The RetireConnectionId frame will be enqueued before the PathResponse.
//   auto retireFrame =
//   conn.pendingEvents.frames[0].asRetireConnectionIdFrame();
//   EXPECT_EQ(retireFrame->sequenceNumber, 1);

//   PathResponseFrame& pathResponse =
//       *conn.pendingEvents.frames[1].asPathResponseFrame();
//   EXPECT_EQ(pathResponse.pathData, pathChallenge.pathData);
// }

bool verifyFramePresent(
    std::vector<std::unique_ptr<folly::IOBuf>>& socketWrites,
    QuicReadCodec& readCodec,
    QuicFrame::Type frameType) {
  AckStates ackStates;
  for (auto& write : socketWrites) {
    auto packetQueue = bufToQueue(write->clone());
    auto result = readCodec.parsePacket(packetQueue, ackStates);
    auto regularPacket = result.regularPacket();
    if (!regularPacket) {
      continue;
    }
    for ([[maybe_unused]] auto& frame : regularPacket->frames) {
      if (frame.type() != frameType) {
        continue;
      }
      return true;
    }
  }
  return false;
}

TEST_F(QuicClientTransportAfterStartTest, CloseConnectionWithStreamPending) {
  StreamId streamId = client->createBidirectionalStream().value();
  auto qLogger = std::make_shared<FileQLogger>(VantagePoint::Client);
  client->getNonConstConn().qLogger = qLogger;
  auto expected = IOBuf::copyBuffer("hello");
  auto fizzClientSetReadCallback14 = client->setReadCallback(streamId, &readCb);
  auto fizzClientWriteChain2 =
      client->writeChain(streamId, expected->clone(), true);
  loopForWrites();
  // ack all the packets
  ASSERT_FALSE(client->getConn().outstandings.packets.empty());

  AckBlocks acks;
  auto start = getFirstOutstandingPacket(
                   client->getNonConstConn(), PacketNumberSpace::AppData)
                   ->packet.header.getPacketSequenceNum();
  auto end = getLastOutstandingPacket(
                 client->getNonConstConn(), PacketNumberSpace::AppData)
                 ->packet.header.getPacketSequenceNum();
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
  EXPECT_FALSE(verifyFramePresent(
      socketWrites, *serverReadCodec, QuicFrame::Type::ConnectionCloseFrame));

  // close the stream
  auto packet = packetToBuf(createStreamPacket(
      *serverChosenConnId /* src */,
      *originalConnId /* dest */,
      appDataPacketNum++,
      streamId,
      *expected,
      0 /* cipherOverhead */,
      0 /* largestAcked */,
      std::nullopt,
      true));
  socketWrites.clear();
  deliverData(packet->coalesce());
  EXPECT_TRUE(verifyFramePresent(
      socketWrites, *serverReadCodec, QuicFrame::Type::ConnectionCloseFrame));

  std::vector<int> indices =
      getQLogEventIndices(QLogEventType::ConnectionClose, qLogger);
  // expecting that connection close called twice
  EXPECT_EQ(indices.size(), 2);

  // event called in closeGracefully()
  auto tmp = std::move(qLogger->logs[indices[0]]);
  auto event = dynamic_cast<QLogConnectionCloseEvent*>(tmp.get());
  EXPECT_EQ(event->error, kNoError);
  EXPECT_EQ(event->reason, kGracefulExit);
  EXPECT_TRUE(event->drainConnection);
  EXPECT_FALSE(event->sendCloseImmediately);

  // event called in closeImpl(), right before transport is closed
  auto tmp2 = std::move(qLogger->logs[indices[1]]);
  auto event2 = dynamic_cast<QLogConnectionCloseEvent*>(tmp2.get());
  EXPECT_EQ(event2->error, kNoError);
  auto reason = fmt::format(
      "Server: {}, Peer: isReset: false, Peer: isAbandon: false", kNoError);
  EXPECT_EQ(event2->reason, reason);
  EXPECT_TRUE(event2->drainConnection);
  EXPECT_TRUE(event2->sendCloseImmediately);
}

TEST_F(QuicClientTransportAfterStartTest, CloseConnectionWithNoStreamPending) {
  StreamId streamId = client->createBidirectionalStream().value();

  auto expected = IOBuf::copyBuffer("hello");
  auto fizzClientSetReadCallback15 = client->setReadCallback(streamId, &readCb);
  auto fizzClientWriteChain3 =
      client->writeChain(streamId, expected->clone(), true);

  loopForWrites();

  // ack all the packets
  ASSERT_FALSE(client->getConn().outstandings.packets.empty());

  AckBlocks acks;
  auto start = getFirstOutstandingPacket(
                   client->getNonConstConn(), PacketNumberSpace::AppData)
                   ->packet.header.getPacketSequenceNum();
  auto end = getLastOutstandingPacket(
                 client->getNonConstConn(), PacketNumberSpace::AppData)
                 ->packet.header.getPacketSequenceNum();
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
      std::nullopt,
      true));
  socketWrites.clear();
  deliverData(packet->coalesce());
  EXPECT_CALL(readCb, readError(streamId, _));
  client->close(std::nullopt);
  EXPECT_TRUE(verifyFramePresent(
      socketWrites,
      *makeEncryptedCodec(),
      QuicFrame::Type::ConnectionCloseFrame));
}

class QuicClientTransportAfterStartTestClose
    : public QuicClientTransportAfterStartTestBase,
      public testing::WithParamInterface<bool> {};

INSTANTIATE_TEST_SUITE_P(
    QuicClientTransportAfterStartTestCloseWithError,
    QuicClientTransportAfterStartTestClose,
    Values(true, false));

TEST_P(
    QuicClientTransportAfterStartTestClose,
    CloseConnectionWithErrorCleartext) {
  StreamId streamId = client->createBidirectionalStream().value();
  auto qLogger = std::make_shared<FileQLogger>(VantagePoint::Client);
  client->getNonConstConn().qLogger = qLogger;
  auto expected = IOBuf::copyBuffer("hello");
  auto fizzClientSetReadCallback16 = client->setReadCallback(streamId, &readCb);
  auto fizzClientWriteChain4 =
      client->writeChain(streamId, expected->clone(), true);

  loopForWrites();
  socketWrites.clear();
  EXPECT_CALL(readCb, readError(streamId, _));
  if (GetParam()) {
    client->close(QuicError(
        QuicErrorCode(GenericApplicationErrorCode::UNKNOWN),
        std::string("stopping")));
    EXPECT_TRUE(verifyFramePresent(
        socketWrites,
        *makeHandshakeCodec(),
        QuicFrame::Type::ConnectionCloseFrame));

    std::vector<int> indices =
        getQLogEventIndices(QLogEventType::ConnectionClose, qLogger);
    // expecting that connection close called once
    EXPECT_EQ(indices.size(), 1);
    auto tmp = std::move(qLogger->logs[indices[0]]);
    auto event = dynamic_cast<QLogConnectionCloseEvent*>(tmp.get());
    EXPECT_EQ(event->error, "stopping");
    EXPECT_EQ(event->reason, "stopping");
    EXPECT_TRUE(event->drainConnection);
    EXPECT_TRUE(event->sendCloseImmediately);

  } else {
    client->close(std::nullopt);
    EXPECT_TRUE(verifyFramePresent(
        socketWrites,
        *makeHandshakeCodec(),
        QuicFrame::Type::ConnectionCloseFrame));
    std::vector<int> indices =
        getQLogEventIndices(QLogEventType::ConnectionClose, qLogger);
    // expecting that connection close called once
    EXPECT_EQ(indices.size(), 1);
    auto tmp = std::move(qLogger->logs[indices[0]]);
    auto event = dynamic_cast<QLogConnectionCloseEvent*>(tmp.get());
    EXPECT_EQ(event->error, "No Error");
    EXPECT_EQ(event->reason, "No Error");
    EXPECT_TRUE(event->drainConnection);
    EXPECT_TRUE(event->sendCloseImmediately);
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
    AckBlocks acks;
    auto start = getFirstOutstandingPacket(
                     client->getNonConstConn(), PacketNumberSpace::Initial)
                     ->packet.header.getPacketSequenceNum();
    auto end = getLastOutstandingPacket(
                   client->getNonConstConn(), PacketNumberSpace::Initial)
                   ->packet.header.getPacketSequenceNum();
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
    AckBlocks acks;
    auto start = getFirstOutstandingPacket(
                     client->getNonConstConn(), PacketNumberSpace::Handshake)
                     ->packet.header.getPacketSequenceNum();
    auto end = getLastOutstandingPacket(
                   client->getNonConstConn(), PacketNumberSpace::Handshake)
                   ->packet.header.getPacketSequenceNum();
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
  auto fizzClientSetReadCallback17 = client->setReadCallback(streamId, &readCb);
  auto fizzClientWriteChain5 =
      client->writeChain(streamId, expected->clone(), true);
  loopForWrites();

  AckBlocks sentPackets;
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
  auto fizzClientSetReadCallback18 = client->setReadCallback(streamId, &readCb);
  auto fizzClientWriteChain6 =
      client->writeChain(streamId, expected->clone(), true);
  loopForWrites();
  auto packet = packetToBuf(createStreamPacket(
      *serverChosenConnId /* src */,
      *originalConnId /* dest */,
      appDataPacketNum++,
      streamId,
      *expected,
      0 /* cipherOverhead */,
      0 /* largestAcked */,
      std::nullopt,
      true));
  deliverData(packet->coalesce());
  socketWrites.clear();
  if (GetParam()) {
    client->close(QuicError(
        QuicErrorCode(GenericApplicationErrorCode::UNKNOWN),
        std::string("stopping")));
    EXPECT_TRUE(verifyFramePresent(
        socketWrites,
        *makeHandshakeCodec(),
        QuicFrame::Type::ConnectionCloseFrame));
  } else {
    client->close(std::nullopt);
    EXPECT_TRUE(verifyFramePresent(
        socketWrites,
        *makeHandshakeCodec(),
        QuicFrame::Type::ConnectionCloseFrame));
  }
}

class QuicClientTransportAfterStartTestTimeout
    : public QuicClientTransportAfterStartTestBase,
      public testing::WithParamInterface<QuicVersion> {};

INSTANTIATE_TEST_SUITE_P(
    QuicClientTransportAfterStartTestTimeouts,
    QuicClientTransportAfterStartTestTimeout,
    Values(
        QuicVersion::MVFST,
        QuicVersion::QUIC_V1,
        QuicVersion::QUIC_V1_ALIAS));

TEST_P(
    QuicClientTransportAfterStartTestTimeout,
    HandshakeCipherTimeoutAfterFirstData) {
  client->getNonConstConn().version = GetParam();
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
      std::nullopt,
      true));
  deliverData(packet->coalesce());
  EXPECT_NE(client->getConn().readCodec->getInitialCipher(), nullptr);
  EXPECT_FALSE(client->getConn().readCodec->getHandshakeDoneTime().has_value());
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

  client->idleTimeout().cancelTimerCallback();
  ASSERT_FALSE(client->idleTimeout().isTimerCallbackScheduled());
  deliverData(packet->coalesce());
  ASSERT_TRUE(client->getConn().receivedNewPacketBeforeWrite);
  ASSERT_TRUE(client->idleTimeout().isTimerCallbackScheduled());

  auto packet2 = packetToBuf(createStreamPacket(
      *serverChosenConnId /* src */,
      *originalConnId /* dest */,
      appDataPacketNum++,
      streamId,
      *expected,
      0 /* cipherOverhead */,
      0 /* largestAcked */));
  client->idleTimeout().cancelTimerCallback();
  ASSERT_FALSE(client->idleTimeout().isTimerCallbackScheduled());
  deliverData(packet2->coalesce());
  ASSERT_TRUE(client->getConn().receivedNewPacketBeforeWrite);
  ASSERT_TRUE(client->idleTimeout().isTimerCallbackScheduled());
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
  ASSERT_TRUE(client->idleTimeout().isTimerCallbackScheduled());

  client->idleTimeout().cancelTimerCallback();
  client->getNonConstConn().receivedNewPacketBeforeWrite = false;
  ASSERT_FALSE(client->idleTimeout().isTimerCallbackScheduled());
  quicStats_ = std::make_shared<testing::NiceMock<MockQuicStats>>();
  client->setTransportStatsCallback(quicStats_);
  EXPECT_CALL(*quicStats_, onDuplicatedPacketReceived());
  // Try delivering the same packet again
  deliverData(packet->coalesce(), false);

  ASSERT_FALSE(client->getConn().receivedNewPacketBeforeWrite);
  ASSERT_FALSE(client->idleTimeout().isTimerCallbackScheduled());
  client->closeNow(std::nullopt);
}

TEST_P(QuicClientTransportAfterStartTestClose, TimeoutsNotSetAfterClose) {
  expectQuicStatsPacketDrop(PacketDropReason::CLIENT_STATE_CLOSED);
  auto qLogger = std::make_shared<FileQLogger>(VantagePoint::Client);
  client->getNonConstConn().qLogger = qLogger;
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
    client->close(QuicError(
        QuicErrorCode(TransportErrorCode::INTERNAL_ERROR),
        std::string("how about no")));
  } else {
    client->close(std::nullopt);
  }
  client->idleTimeout().cancelTimerCallback();
  ASSERT_FALSE(client->idleTimeout().isTimerCallbackScheduled());

  deliverDataWithoutErrorCheck(packet->coalesce());
  ASSERT_FALSE(client->idleTimeout().isTimerCallbackScheduled());
  ASSERT_FALSE(client->lossTimeout().isTimerCallbackScheduled());
  ASSERT_FALSE(client->ackTimeout().isTimerCallbackScheduled());
  ASSERT_TRUE(client->drainTimeout().isTimerCallbackScheduled());

  std::vector<int> indices =
      getQLogEventIndices(QLogEventType::PacketDrop, qLogger);
  EXPECT_EQ(indices.size(), 1);
  auto tmp = std::move(qLogger->logs[indices[0]]);
  auto event = dynamic_cast<QLogPacketDropEvent*>(tmp.get());
  EXPECT_EQ(event->packetSize, 0);
  EXPECT_EQ(event->dropReason, kAlreadyClosed);
}

TEST_F(QuicClientTransportAfterStartTest, IdleTimerNotResetOnWritingOldData) {
  StreamId streamId = client->createBidirectionalStream().value();

  // There should still be outstanding packets
  auto expected = IOBuf::copyBuffer("hello");
  client->idleTimeout().cancelTimerCallback();
  ASSERT_FALSE(client->idleTimeout().isTimerCallbackScheduled());
  auto fizzClientWriteChain7 =
      client->writeChain(streamId, expected->clone(), false);
  loopForWrites();

  ASSERT_FALSE(client->getConn().receivedNewPacketBeforeWrite);
  ASSERT_FALSE(client->idleTimeout().isTimerCallbackScheduled());
  client->closeNow(std::nullopt);
}

TEST_F(QuicClientTransportAfterStartTest, IdleTimerResetNoOutstandingPackets) {
  // Clear out all the outstanding packets to simulate quiescent state.
  client->getNonConstConn().receivedNewPacketBeforeWrite = false;
  client->getNonConstConn().outstandings.reset();
  client->idleTimeout().cancelTimerCallback();
  auto streamId = client->createBidirectionalStream().value();
  auto expected = folly::IOBuf::copyBuffer("hello");
  auto fizzClientWriteChain8 =
      client->writeChain(streamId, expected->clone(), false);
  loopForWrites();
  ASSERT_TRUE(client->idleTimeout().isTimerCallbackScheduled());
}

TEST_F(QuicClientTransportAfterStartTest, IdleTimeoutExpired) {
  EXPECT_CALL(*sock, close());
  socketWrites.clear();
  client->idleTimeout().timeoutExpired();

  EXPECT_FALSE(client->idleTimeout().isTimerCallbackScheduled());
  EXPECT_TRUE(client->isDraining());
  EXPECT_TRUE(client->isClosed());

  auto serverCodec = makeEncryptedCodec();
  // We expect a conn close in a cleartext packet.
  EXPECT_FALSE(verifyFramePresent(
      socketWrites, *serverCodec, QuicFrame::Type::ConnectionCloseFrame));
  EXPECT_FALSE(verifyFramePresent(
      socketWrites, *serverCodec, QuicFrame::Type::ConnectionCloseFrame));
  EXPECT_TRUE(socketWrites.empty());
}

TEST_F(QuicClientTransportAfterStartTest, RecvDataAfterIdleTimeout) {
  expectQuicStatsPacketDrop(PacketDropReason::CLIENT_STATE_CLOSED);
  auto qLogger = std::make_shared<FileQLogger>(VantagePoint::Client);
  client->getNonConstConn().qLogger = qLogger;
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
  EXPECT_TRUE(verifyFramePresent(
      socketWrites,
      *makeEncryptedCodec(true),
      QuicFrame::Type::ConnectionCloseFrame));
  std::vector<int> indices =
      getQLogEventIndices(QLogEventType::PacketDrop, qLogger);
  EXPECT_EQ(indices.size(), 1);
  auto tmp = std::move(qLogger->logs[indices[0]]);
  auto event = dynamic_cast<QLogPacketDropEvent*>(tmp.get());
  EXPECT_EQ(event->packetSize, 0);
  EXPECT_EQ(event->dropReason, kAlreadyClosed);
}

TEST_F(QuicClientTransportAfterStartTest, DropPacketFromUnknownPeerAddress) {
  // Expect the packet to be dropped with PEER_ADDRESS_CHANGE reason
  expectQuicStatsPacketDrop(PacketDropReason::PEER_ADDRESS_CHANGE);

  // Create a valid stream packet
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

  // Deliver the packet from an unknown peer address (different from serverAddr)
  folly::SocketAddress unknownPeer("::1", 54321);
  deliverDataWithoutErrorCheck(unknownPeer, packet->coalesce(), false);

  // No data was delivered
  auto readData = client->read(streamId, 0);
  ASSERT_TRUE(readData.has_value());
  EXPECT_EQ(readData.value().first, nullptr);

  // Verify that the connection is still open and not closed
  EXPECT_FALSE(client->isClosed());
  EXPECT_FALSE(client->getConn().localConnectionError.has_value());

  client->closeNow(std::nullopt);
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
  FizzCryptoFactory cryptoFactory;
  StreamId streamId = client->createBidirectionalStream().value();

  auto expected = IOBuf::copyBuffer("hello");
  // Test sending packet with wrong connection id, should drop it, it normally
  // throws on getting unencrypted stream data.
  PacketNum nextPacketNum = appDataPacketNum++;

  auto initialCipherResult = cryptoFactory.getServerInitialCipher(
      *serverChosenConnId, QuicVersion::MVFST);
  ASSERT_FALSE(initialCipherResult.hasError());
  auto& initialCipher = initialCipherResult.value();
  auto packet = packetToBufCleartext(
      createStreamPacket(
          *serverChosenConnId /* src */,
          *originalConnId /* dest */,
          nextPacketNum,
          streamId,
          *expected,
          initialCipher.get()->getCipherOverhead(),
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
  ASSERT_FALSE(builder.encodePacketHeader().hasError());
  ASSERT_TRUE(builder.canBuildPacket());
  ASSERT_FALSE(writeFrame(rstFrame, builder).hasError());
  auto packet = packetToBuf(std::move(builder).buildPacket());
  EXPECT_THROW(deliverData(packet->coalesce()), std::runtime_error);
}

TEST_F(QuicClientTransportAfterStartTest, ReceiveReliableRst) {
  auto streamId =
      client->createBidirectionalStream(false /* replaySafe */).value();
  auto fizzClientSetReadCallback19 = client->setReadCallback(streamId, &readCb);
  RstStreamFrame rstFrame(streamId, GenericApplicationErrorCode::UNKNOWN, 5, 5);
  ShortHeader header(
      ProtectionType::KeyPhaseZero, *originalConnId, appDataPacketNum++);
  RegularQuicPacketBuilder builder(
      client->getConn().udpSendPacketLen,
      std::move(header),
      0 /* largestAcked */);
  ASSERT_FALSE(builder.encodePacketHeader().hasError());
  ASSERT_TRUE(builder.canBuildPacket());
  ASSERT_FALSE(writeFrame(rstFrame, builder).hasError());
  auto packet = packetToBuf(std::move(builder).buildPacket());
  deliverDataWithoutErrorCheck(packet->coalesce());
  EXPECT_EQ(
      QuicErrorCode(TransportErrorCode::PROTOCOL_VIOLATION),
      client->getConn().localConnectionError->code);
}

TEST_F(
    QuicClientTransportAfterStartTest,
    ReceiveRstStreamNonExistentAndOtherFrame) {
  StreamId serverUnidirectional = 0x03;

  // Deliver reset on peer unidirectional stream to close the stream.
  RstStreamFrame rstFrame(
      serverUnidirectional, GenericApplicationErrorCode::UNKNOWN, 0);
  ShortHeader header(
      ProtectionType::KeyPhaseZero, *originalConnId, appDataPacketNum++);
  RegularQuicPacketBuilder builder(
      client->getConn().udpSendPacketLen,
      std::move(header),
      0 /* largestAcked */);
  ASSERT_FALSE(builder.encodePacketHeader().hasError());
  ASSERT_FALSE(writeFrame(rstFrame, builder).hasError());
  auto packet = packetToBuf(std::move(builder).buildPacket());
  deliverData(packet->coalesce());

  auto streamId =
      client->createBidirectionalStream(false /* replaySafe */).value();

  ShortHeader header2(
      ProtectionType::KeyPhaseZero, *originalConnId, appDataPacketNum++);
  RegularQuicPacketBuilder builder2(
      client->getConn().udpSendPacketLen,
      std::move(header),
      0 /* largestAcked */);
  ASSERT_FALSE(builder2.encodePacketHeader().hasError());
  ASSERT_FALSE(writeFrame(rstFrame, builder2).hasError());

  auto data = folly::IOBuf::copyBuffer("hello");
  ASSERT_TRUE(writeStreamFrameHeader(
                  builder2,
                  streamId,
                  0,
                  data->computeChainDataLength(),
                  data->computeChainDataLength(),
                  false,
                  std::nullopt /* skipLenHint */)
                  .has_value());
  writeStreamFrameData(builder2, data->clone(), data->computeChainDataLength());
  auto packetObject = std::move(builder2).buildPacket();
  auto packet2 = packetToBuf(std::move(packetObject));
  deliverData(packet2->coalesce());

  auto readData = client->read(streamId, 0);
  ASSERT_TRUE(readData.has_value());
  ASSERT_NE(readData.value().first, nullptr);
  EXPECT_TRUE(folly::IOBufEqualTo()(*readData.value().first, *data));
}

TEST_F(QuicClientTransportAfterStartTest, ReceiveRstStreamAfterEom) {
  // A RstStreamFrame will be written to sock when we receive a RstStreamFrame
  auto streamId =
      client->createBidirectionalStream(false /* replaySafe */).value();
  auto fizzClientSetReadCallback20 = client->setReadCallback(streamId, &readCb);

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
      client->getConn().udpSendPacketLen, std::move(header), 0);
  ASSERT_FALSE(builder.encodePacketHeader().hasError());
  ASSERT_TRUE(builder.canBuildPacket());
  ASSERT_FALSE(writeFrame(rstFrame, builder).hasError());
  auto packet2 = packetToBuf(std::move(builder).buildPacket());
  deliverData(packet2->coalesce());

  EXPECT_TRUE(client->getReadCallbacks().empty());
  client->close(std::nullopt);
}

TEST_F(
    QuicClientTransportAfterStartTest,
    SetReadCallbackNullRemembersDelivery) {
  // A RstStreamFrame will be written to sock when we receive a RstStreamFrame
  auto streamId =
      client->createBidirectionalStream(false /* replaySafe */).value();
  auto fizzClientSetReadCallback21 = client->setReadCallback(streamId, &readCb);

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

  auto fizzClientSetReadCallback22 = client->setReadCallback(streamId, nullptr);

  AckBlocks sentPackets;
  auto writeData = IOBuf::copyBuffer("some data");
  auto fizzClientWriteChain9 =
      client->writeChain(streamId, writeData->clone(), true);
  loopForWrites();
  verifyShortPackets(sentPackets);

  // Write an AckFrame back to client:
  auto packet2 = packetToBuf(createAckPacket(
      client->getNonConstConn(),
      ++appDataPacketNum,
      sentPackets,
      PacketNumberSpace::AppData));
  deliverData(packet2->coalesce());

  auto streamResult =
      client->getNonConstConn().streamManager->getStream(streamId);
  ASSERT_FALSE(streamResult.hasError());
  ASSERT_EQ(streamResult.value(), nullptr);
  client->close(std::nullopt);
}

TEST_F(QuicClientTransportAfterStartTest, StreamClosedIfReadCallbackNull) {
  // A RstStreamFrame will be written to sock when we receive a RstStreamFrame
  auto streamId =
      client->createBidirectionalStream(false /* replaySafe */).value();

  AckBlocks sentPackets;
  auto writeData = IOBuf::copyBuffer("some data");
  auto fizzClientWriteChain10 =
      client->writeChain(streamId, writeData->clone(), true);
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

  auto streamResult =
      client->getNonConstConn().streamManager->getStream(streamId);
  ASSERT_FALSE(streamResult.hasError());
  ASSERT_EQ(streamResult.value(), nullptr);
  client->close(std::nullopt);
}

TEST_F(QuicClientTransportAfterStartTest, ReceiveAckInvokesDeliveryCallback) {
  AckBlocks sentPackets;
  auto streamId =
      client->createBidirectionalStream(false /* replaySafe */).value();
  auto fizzClientRegisterDelivery1 =
      client->registerDeliveryCallback(streamId, 0, &deliveryCallback);

  auto data = IOBuf::copyBuffer("some data");
  auto fizzClientWriteChain11 =
      client->writeChain(streamId, data->clone(), true);
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
  client->close(std::nullopt);
}

TEST_F(QuicClientTransportAfterStartTest, InvokesDeliveryCallbackFinOnly) {
  AckBlocks sentPackets;
  auto streamId =
      client->createBidirectionalStream(false /* replaySafe */).value();

  auto fizzClientWriteChain12 =
      client->writeChain(streamId, nullptr, true, &deliveryCallback);
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
  client->close(std::nullopt);
}

TEST_F(QuicClientTransportAfterStartTest, InvokesDeliveryCallbackRange) {
  AckBlocks sentPackets;
  auto streamId =
      client->createBidirectionalStream(false /* replaySafe */).value();

  auto data = IOBuf::copyBuffer("some data");
  auto fizzClientWriteChain13 =
      client->writeChain(streamId, data->clone(), false, nullptr);
  for (uint64_t offset = 0; offset < data->computeChainDataLength(); offset++) {
    auto fizzClientRegisterDelivery2 =
        client->registerDeliveryCallback(streamId, offset, &deliveryCallback);
    EXPECT_CALL(deliveryCallback, onDeliveryAck(streamId, offset, _)).Times(1);
  }
  ASSERT_TRUE(
      client
          ->registerDeliveryCallback(
              streamId, data->computeChainDataLength(), &deliveryCallback)
          .has_value());
  EXPECT_CALL(
      deliveryCallback,
      onDeliveryAck(streamId, data->computeChainDataLength(), _))
      .Times(0);
  loopForWrites();

  verifyShortPackets(sentPackets);
  ASSERT_EQ(sentPackets.size(), 1);

  // Write an AckFrame back to client:
  auto packet = packetToBuf(createAckPacket(
      client->getNonConstConn(),
      ++appDataPacketNum,
      sentPackets,
      PacketNumberSpace::AppData));

  deliverData(packet->coalesce());
  client->close(std::nullopt);
}

TEST_F(
    QuicClientTransportAfterStartTest,
    RegisterDeliveryCallbackForAlreadyDeliveredOffset) {
  AckBlocks sentPackets;

  auto streamId =
      client->createBidirectionalStream(false /* replaySafe */).value();

  auto data = IOBuf::copyBuffer("some data");
  auto fizzClientWriteChain14 =
      client->writeChain(streamId, data->clone(), true);

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
  auto fizzClientRegisterDelivery3 =
      client->registerDeliveryCallback(streamId, 0, &deliveryCallback);
  eventbase_->loopOnce();
  client->close(std::nullopt);
}

TEST_F(QuicClientTransportAfterStartTest, DeliveryCallbackFromWriteChain) {
  AckBlocks sentPackets;
  auto streamId =
      client->createBidirectionalStream(false /* replaySafe */).value();

  // Write 10 bytes of data, and write EOF on an empty stream. So EOF offset is
  // 10
  auto data = test::buildRandomInputData(10);
  auto fizzClientWriteChain15 =
      client->writeChain(streamId, data->clone(), true, &deliveryCallback);

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
  client->close(std::nullopt);
}

TEST_F(QuicClientTransportAfterStartTest, NotifyPendingWrite) {
  NiceMock<MockWriteCallback> writeCallback;
  EXPECT_CALL(writeCallback, onConnectionWriteReady(_));
  auto fizzClientNotifyPendingWrite1 =
      client->notifyPendingWriteOnConnection(&writeCallback);
  loopForWrites();
  client->close(std::nullopt);
}

TEST_F(QuicClientTransportAfterStartTest, SwitchEvbWhileAsyncEventPending) {
  NiceMock<MockWriteCallback> writeCallback;
  EventBase evb2;
  auto qEvb2 = std::make_shared<FollyQuicEventBase>(&evb2);
  EXPECT_CALL(writeCallback, onConnectionWriteReady(_)).Times(0);
  auto fizzClientNotifyPendingWrite2 =
      client->notifyPendingWriteOnConnection(&writeCallback);
  client->detachEventBase();
  client->attachEventBase(qEvb2);
  loopForWrites();
  client->close(std::nullopt);
}

TEST_F(QuicClientTransportAfterStartTest, StatelessResetClosesTransport) {
  // Make decrypt fail for the reset token
  auto aead = dynamic_cast<const MockAead*>(
      client->getNonConstConn().readCodec->getOneRttReadCipher());
  ASSERT_TRUE(aead);

  // Make the decrypt fail
  EXPECT_CALL(*aead, _tryDecrypt(_, _, _))
      .WillRepeatedly(Invoke([&](auto&, auto, auto) { return std::nullopt; }));

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
  std::unique_ptr<MockAead> currentOneRttReadCipher =
      std::make_unique<MockAead>();
  MockAead* currentOneRttReadCipherRawPtr = currentOneRttReadCipher.get();
  client->getNonConstConn().readCodec->setOneRttReadCipher(
      std::move(currentOneRttReadCipher));

  std::unique_ptr<MockAead> nextOneRttReadCipher = std::make_unique<MockAead>();
  MockAead* nextOneRttReadCipherRawPtr = nextOneRttReadCipher.get();
  client->getNonConstConn().readCodec->setNextOneRttReadCipher(
      std::move(nextOneRttReadCipher));

  // Make the decrypt fail
  ON_CALL(*currentOneRttReadCipherRawPtr, _tryDecrypt(_, _, _))
      .WillByDefault(Invoke([&](auto&, auto, auto) { return std::nullopt; }));
  ON_CALL(*nextOneRttReadCipherRawPtr, _tryDecrypt(_, _, _))
      .WillByDefault(Invoke([&](auto&, auto, auto) { return std::nullopt; }));
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
  std::vector<uint8_t> clientConnIdVec = {};
  ConnectionId clientConnId =
      ConnectionId::createAndMaybeCrash(clientConnIdVec);

  ConnectionId initialDstConnId =
      ConnectionId::createAndMaybeCrash(kInitialDstConnIdVecForRetryTest);

  // Create a stream and attempt to send some data to the server
  auto qLogger = std::make_shared<FileQLogger>(VantagePoint::Client);
  client->getNonConstConn().qLogger = qLogger;
  client->getNonConstConn().readCodec->setClientConnectionId(clientConnId);
  client->getNonConstConn().initialDestinationConnectionId = initialDstConnId;
  client->getNonConstConn().originalDestinationConnectionId = initialDstConnId;

  client->setCongestionControllerFactory(
      std::make_shared<DefaultCongestionControllerFactory>());
  client->setCongestionControl(CongestionControlType::NewReno);

  StreamId streamId = *client->createBidirectionalStream();
  auto write = IOBuf::copyBuffer("ice cream");
  auto fizzClientWriteChain16 =
      client->writeChain(streamId, write->clone(), true, nullptr);
  loopForWrites();

  std::unique_ptr<IOBuf> bytesWrittenToNetwork = nullptr;

  EXPECT_CALL(*sock, write(_, _, _))
      .WillRepeatedly(Invoke(
          [&](const SocketAddress&, const struct iovec* vec, size_t iovec_len) {
            bytesWrittenToNetwork =
                copyChain(folly::IOBuf::wrapIov(vec, iovec_len));
            return getTotalIovecLen(vec, iovec_len);
          }));

  auto serverCid = recvServerRetry(serverAddr);
  ASSERT_TRUE(bytesWrittenToNetwork);

  // Check CC is kept after retry recreates QuicClientConnectionState
  EXPECT_TRUE(client->getConn().congestionControllerFactory);
  EXPECT_EQ(
      client->getConn().congestionController->type(),
      CongestionControlType::NewReno);

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

  auto& regularQuicPacket = *codecResult.regularPacket();
  auto& header = *regularQuicPacket.header.asLong();

  EXPECT_EQ(header.getHeaderType(), LongHeader::Types::Initial);
  EXPECT_TRUE(header.hasToken());
  EXPECT_EQ(header.getToken(), std::string("token"));
  EXPECT_EQ(header.getDestinationConnId(), serverCid);

  eventbase_->loopOnce();
  client->close(std::nullopt);
}

TEST_F(
    QuicClientTransportVersionAndRetryTest,
    VersionNegotiationPacketNotSupported) {
  StreamId streamId = *client->createBidirectionalStream();

  auto fizzClientSetReadCallback23 = client->setReadCallback(streamId, &readCb);

  auto write = IOBuf::copyBuffer("no");
  auto fizzClientWriteChain17 =
      client->writeChain(streamId, write->clone(), true, &deliveryCallback);
  loopForWrites();
  auto packet = VersionNegotiationPacketBuilder(
                    *client->getConn().initialDestinationConnectionId,
                    *originalConnId,
                    {MVFST2})
                    .buildPacket();
  EXPECT_CALL(
      readCb,
      readError(streamId, IsError(LocalErrorCode::NEW_VERSION_NEGOTIATED)));
  EXPECT_CALL(deliveryCallback, onCanceled(streamId, write->length()));
  EXPECT_THROW(deliverData(packet.second->coalesce()), std::runtime_error);

  EXPECT_EQ(client->getConn().oneRttWriteCipher.get(), nullptr);
  EXPECT_CALL(clientConnSetupCallback, onTransportReady()).Times(0);
  EXPECT_CALL(clientConnSetupCallback, onReplaySafe()).Times(0);
  client->close(std::nullopt);
}

TEST_F(
    QuicClientTransportVersionAndRetryTest,
    VersionNegotiationPacketCurrentVersion) {
  StreamId streamId = *client->createBidirectionalStream();

  auto fizzClientSetReadCallback24 = client->setReadCallback(streamId, &readCb);

  auto write = IOBuf::copyBuffer("no");
  auto fizzClientWriteChain18 =
      client->writeChain(streamId, write->clone(), true, &deliveryCallback);
  loopForWrites();

  auto packet = VersionNegotiationPacketBuilder(
                    *client->getConn().initialDestinationConnectionId,
                    *originalConnId,
                    {QuicVersion::MVFST})
                    .buildPacket();
  EXPECT_THROW(deliverData(packet.second->coalesce()), std::runtime_error);
  client->close(std::nullopt);
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
  AckBlocks acks = {{1, 2}};
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
  ASSERT_FALSE(builder.encodePacketHeader().hasError());
  DCHECK(builder.canBuildPacket());
  WriteAckFrameState writeAckState = {.acks = acks};
  WriteAckFrameMetaData ackData = {
      .ackState = writeAckState,
      .ackDelay = 0us,
      .ackDelayExponent = static_cast<uint8_t>(kDefaultAckDelayExponent)};
  ASSERT_FALSE(writeAckFrame(ackData, builder).hasError());
  auto packet = packetToBufCleartext(
      std::move(builder).buildPacket(),
      getInitialCipher(),
      getInitialHeaderCipher(),
      nextPacketNum);
  EXPECT_NO_THROW(deliverData(packet->coalesce()));
}

TEST_F(QuicClientTransportVersionAndRetryTest, UnencryptedPing) {
  PacketNum nextPacketNum = initialPacketNum++;
  LongHeader header(
      LongHeader::Types::Initial,
      getTestConnectionId(),
      *client->getConn().clientConnectionId,
      nextPacketNum,
      version);
  RegularQuicPacketBuilder builder(
      kDefaultUDPSendPacketLen, std::move(header), 0 /* largestAcked */);
  ASSERT_FALSE(builder.encodePacketHeader().hasError());
  DCHECK(builder.canBuildPacket());
  ASSERT_FALSE(writeFrame(PingFrame(), builder).hasError());
  auto packet = packetToBufCleartext(
      std::move(builder).buildPacket(),
      getInitialCipher(),
      getInitialHeaderCipher(),
      nextPacketNum);
  EXPECT_NO_THROW(deliverData(packet->coalesce()));
}

BufPtr getHandshakePacketWithFrame(
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
  CHECK(!builder.encodePacketHeader().hasError());
  builder.accountForCipherOverhead(serverWriteCipher.getCipherOverhead());
  CHECK(!writeFrame(std::move(frame), builder).hasError());
  return packetToBufCleartext(
      std::move(builder).buildPacket(),
      serverWriteCipher,
      headerCipher,
      packetNum);
}

TEST_F(QuicClientTransportVersionAndRetryTest, FrameNotAllowed) {
  StreamId streamId = *client->createBidirectionalStream();
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
  AckBlocks sentPackets;
  StreamId streamId = client->createBidirectionalStream().value();
  auto fizzClientSetReadCallback25 = client->setReadCallback(streamId, &readCb);
  auto fizzClientRegisterDelivery4 =
      client->registerDeliveryCallback(streamId, 100, &deliveryCallback);
  EXPECT_CALL(deliveryCallback, onCanceled(streamId, 100));
  EXPECT_CALL(readCb, readError(streamId, _));
  auto fizzClientResetStream1 =
      client->resetStream(streamId, GenericApplicationErrorCode::UNKNOWN);
  loopForWrites();
  verifyShortPackets(sentPackets);

  const auto& readCbs = client->getReadCallbacks();
  const auto& conn = client->getConn();
  // ReadCallbacks are not affected by resetting send state
  EXPECT_TRUE(readCbs.contains(streamId));
  // readable list can still be populated after a reset.
  EXPECT_FALSE(writableContains(*conn.streamManager, streamId));
  auto packet = packetToBuf(createAckPacket(
      client->getNonConstConn(),
      ++appDataPacketNum,
      sentPackets,
      PacketNumberSpace::AppData));
  deliverData(packet->coalesce());
  // Stream is not yet closed because ingress state machine is open
  EXPECT_TRUE(conn.streamManager->streamExists(streamId));
  client->close(std::nullopt);
  EXPECT_TRUE(client->isClosed());
}

RegularQuicWritePacket* findPacketWithStream(
    QuicConnectionStateBase& conn,
    StreamId streamId) {
  auto op = findOutstandingPacket(conn, [=](OutstandingPacketWrapper& packet) {
    for (auto& frame : packet.packet.frames) {
      bool tryPacket = false;
      WriteStreamFrame* streamFrame = frame.asWriteStreamFrame();
      if (streamFrame) {
        tryPacket = streamFrame->streamId == streamId;
      }
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
  auto fizzClientSetReadCallback26 = client->setReadCallback(streamId, &readCb);
  SCOPE_EXIT {
    client->close(std::nullopt);
  };
  auto fizzClientWriteChain19 =
      client->writeChain(streamId, IOBuf::copyBuffer("hello"), true);
  loopForWrites();
  ASSERT_FALSE(client->getConn().outstandings.packets.empty());

  RegularQuicWritePacket* forceLossPacket =
      CHECK_NOTNULL(findPacketWithStream(client->getNonConstConn(), streamId));
  auto result = markPacketLoss(
      client->getNonConstConn(),
      client->getNonConstConn().currentPathId,
      *forceLossPacket,
      false);
  ASSERT_FALSE(result.hasError());
  ASSERT_TRUE(client->getConn().streamManager->hasLoss());

  auto fizzClientResetStream2 =
      client->resetStream(streamId, GenericApplicationErrorCode::UNKNOWN);
  ASSERT_FALSE(client->getConn().streamManager->hasLoss());
}

TEST_F(QuicClientTransportAfterStartTest, LossAfterResetStream) {
  StreamId streamId = client->createBidirectionalStream().value();
  auto fizzClientSetReadCallback27 = client->setReadCallback(streamId, &readCb);
  SCOPE_EXIT {
    client->close(std::nullopt);
  };
  auto fizzClientWriteChain20 =
      client->writeChain(streamId, IOBuf::copyBuffer("hello"), true);
  loopForWrites();
  ASSERT_FALSE(client->getConn().outstandings.packets.empty());

  auto fizzClientResetStream3 =
      client->resetStream(streamId, GenericApplicationErrorCode::UNKNOWN);

  RegularQuicWritePacket* forceLossPacket =
      CHECK_NOTNULL(findPacketWithStream(client->getNonConstConn(), streamId));
  auto result = markPacketLoss(
      client->getNonConstConn(),
      client->getNonConstConn().currentPathId,
      *forceLossPacket,
      false);
  ASSERT_FALSE(result.hasError());
  auto streamResult =
      client->getNonConstConn().streamManager->getStream(streamId);
  ASSERT_FALSE(streamResult.hasError());
  auto stream = streamResult.value();
  ASSERT_TRUE(stream->lossBuffer.empty());
  ASSERT_FALSE(client->getConn().streamManager->hasLoss());
}

TEST_F(QuicClientTransportAfterStartTest, SendResetAfterEom) {
  AckBlocks sentPackets;
  StreamId streamId = client->createBidirectionalStream().value();
  auto fizzClientSetReadCallback28 = client->setReadCallback(streamId, &readCb);
  auto fizzClientRegisterDelivery5 =
      client->registerDeliveryCallback(streamId, 100, &deliveryCallback);
  EXPECT_CALL(deliveryCallback, onCanceled(streamId, 100));
  auto fizzClientWriteChain21 =
      client->writeChain(streamId, IOBuf::copyBuffer("hello"), true);

  auto fizzClientResetStream4 =
      client->resetStream(streamId, GenericApplicationErrorCode::UNKNOWN);
  loopForWrites();
  verifyShortPackets(sentPackets);
  const auto& readCbs = client->getReadCallbacks();
  const auto& conn = client->getConn();
  // ReadCallback are not affected by resetting send state.
  EXPECT_TRUE(readCbs.contains(streamId));
  // readable list can still be populated after a reset.
  EXPECT_FALSE(writableContains(*conn.streamManager, streamId));

  auto packet = packetToBuf(createAckPacket(
      client->getNonConstConn(),
      ++appDataPacketNum,
      sentPackets,
      PacketNumberSpace::AppData));
  deliverData(packet->coalesce());
  // Stream still exists since ingress state machine is still open
  EXPECT_TRUE(conn.streamManager->streamExists(streamId));
  client->close(std::nullopt);
  EXPECT_TRUE(client->isClosed());
}

TEST_F(QuicClientTransportAfterStartTest, HalfClosedLocalToClosed) {
  client->getNonConstConn()
      .transportSettings.removeStreamAfterEomCallbackUnset = true;

  AckBlocks sentPackets;
  StreamId streamId = client->createBidirectionalStream().value();
  auto fizzClientSetReadCallback29 = client->setReadCallback(streamId, &readCb);
  auto data = test::buildRandomInputData(10);
  auto fizzClientWriteChain22 =
      client->writeChain(streamId, data->clone(), true, &deliveryCallback);
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
  EXPECT_TRUE(readCbs.contains(streamId));
  EXPECT_FALSE(conn.streamManager->readableStreams().contains(streamId));
  EXPECT_TRUE(conn.streamManager->streamExists(streamId));
  client->close(std::nullopt);
  EXPECT_FALSE(readCbs.contains(streamId));
  EXPECT_FALSE(conn.streamManager->streamExists(streamId));
  EXPECT_TRUE(client->isClosed());
}

TEST_F(QuicClientTransportAfterStartTest, SendResetSyncOnAck) {
  AckBlocks sentPackets;
  StreamId streamId = client->createBidirectionalStream().value();
  StreamId streamId2 = client->createBidirectionalStream().value();

  NiceMock<MockDeliveryCallback> deliveryCallback2;
  auto data = IOBuf::copyBuffer("hello");
  auto fizzClientWriteChain23 =
      client->writeChain(streamId, data->clone(), true, &deliveryCallback);
  auto fizzClientWriteChain24 =
      client->writeChain(streamId2, data->clone(), true, &deliveryCallback2);

  EXPECT_CALL(deliveryCallback, onDeliveryAck(streamId, _, _))
      .WillOnce(Invoke([&](auto, auto, auto) {
        auto fizzClientResetStream5 =
            client->resetStream(streamId, GenericApplicationErrorCode::UNKNOWN);
        auto fizzClientResetStream6 = client->resetStream(
            streamId2, GenericApplicationErrorCode::UNKNOWN);
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
  EXPECT_FALSE(readCbs.contains(streamId));
  // readable list can still be populated after a reset.
  EXPECT_FALSE(writableContains(*conn.streamManager, streamId));
  auto packet = packetToBuf(createAckPacket(
      client->getNonConstConn(),
      ++appDataPacketNum,
      sentPackets,
      PacketNumberSpace::AppData));
  deliverData(packet->coalesce());
  // Stream should be closed after it received the ack for rst
  EXPECT_FALSE(conn.streamManager->streamExists(streamId));
  client->close(std::nullopt);
  EXPECT_TRUE(client->isClosed());
}

TEST_F(QuicClientTransportAfterStartTest, HalfClosedRemoteToClosed) {
  client->getNonConstConn()
      .transportSettings.removeStreamAfterEomCallbackUnset = true;

  StreamId streamId = client->createBidirectionalStream().value();
  auto fizzClientSetReadCallback30 = client->setReadCallback(streamId, &readCb);
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
  EXPECT_TRUE(readCbs.contains(streamId));
  EXPECT_FALSE(conn.streamManager->readableStreams().contains(streamId));

  AckBlocks sentPackets;
  auto fizzClientWriteChain25 =
      client->writeChain(streamId, data->clone(), true, &deliveryCallback);
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
  EXPECT_TRUE(conn.streamManager->streamExists(streamId));
  EXPECT_TRUE(readCbs.contains(streamId));
  client->close(std::nullopt);
  EXPECT_FALSE(conn.streamManager->streamExists(streamId));
  EXPECT_FALSE(readCbs.contains(streamId));
  EXPECT_TRUE(client->isClosed());
}

TEST_F(QuicClientTransportAfterStartTest, ReceiveConnectionClose) {
  ShortHeader header(
      ProtectionType::KeyPhaseZero, *originalConnId, appDataPacketNum++);
  RegularQuicPacketBuilder builder(
      client->getConn().udpSendPacketLen, std::move(header), 0);
  ASSERT_FALSE(builder.encodePacketHeader().hasError());
  ConnectionCloseFrame connClose(
      QuicErrorCode(TransportErrorCode::NO_ERROR),
      "Stand clear of the closing doors, please");
  ASSERT_FALSE(writeFrame(std::move(connClose), builder).hasError());
  auto packet = packetToBuf(std::move(builder).buildPacket());
  EXPECT_CALL(clientConnCallback, onConnectionEnd());
  deliverDataWithoutErrorCheck(packet->coalesce());
  // Now the transport should be closed
  EXPECT_EQ(
      QuicErrorCode(TransportErrorCode::NO_ERROR),
      client->getConn().localConnectionError->code);
  EXPECT_TRUE(client->isClosed());
  EXPECT_TRUE(verifyFramePresent(
      socketWrites,
      *makeHandshakeCodec(),
      QuicFrame::Type::ConnectionCloseFrame));
}

TEST_F(QuicClientTransportAfterStartTest, ReceiveApplicationClose) {
  auto qLogger = std::make_shared<FileQLogger>(VantagePoint::Client);
  client->getNonConstConn().qLogger = qLogger;

  ShortHeader header(
      ProtectionType::KeyPhaseZero, *originalConnId, appDataPacketNum++);
  RegularQuicPacketBuilder builder(
      client->getConn().udpSendPacketLen, std::move(header), 0);
  ASSERT_FALSE(builder.encodePacketHeader().hasError());
  ConnectionCloseFrame appClose(
      QuicErrorCode(GenericApplicationErrorCode::UNKNOWN),
      "Stand clear of the closing doors, please");
  ASSERT_FALSE(writeFrame(std::move(appClose), builder).hasError());
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
      client->getConn().localConnectionError->code);
  EXPECT_TRUE(client->isClosed());
  EXPECT_TRUE(verifyFramePresent(
      socketWrites,
      *makeHandshakeCodec(),
      QuicFrame::Type::ConnectionCloseFrame));

  std::vector<int> indices =
      getQLogEventIndices(QLogEventType::TransportStateUpdate, qLogger);
  EXPECT_EQ(indices.size(), 1);
  auto tmp = std::move(qLogger->logs[indices[0]]);
  auto event = dynamic_cast<QLogTransportStateUpdateEvent*>(tmp.get());
  EXPECT_EQ(
      event->update,
      getPeerClose(
          "Client closed by peer reason=Stand clear of the closing doors, please"));
}

TEST_F(QuicClientTransportAfterStartTest, ReceiveApplicationCloseNoError) {
  ShortHeader header(
      ProtectionType::KeyPhaseZero, *originalConnId, appDataPacketNum++);
  RegularQuicPacketBuilder builder(
      client->getConn().udpSendPacketLen, std::move(header), 0);
  ASSERT_FALSE(builder.encodePacketHeader().hasError());
  ConnectionCloseFrame appClose(
      QuicErrorCode(GenericApplicationErrorCode::NO_ERROR), "No Error");
  ASSERT_FALSE(writeFrame(std::move(appClose), builder).hasError());
  auto packet = packetToBuf(std::move(builder).buildPacket());
  EXPECT_FALSE(client->isClosed());
  socketWrites.clear();

  EXPECT_CALL(clientConnCallback, onConnectionError(_)).Times(0);
  EXPECT_CALL(clientConnCallback, onConnectionEnd());
  deliverDataWithoutErrorCheck(packet->coalesce());
  // Now the transport should be closed
  EXPECT_EQ(
      QuicErrorCode(TransportErrorCode::NO_ERROR),
      client->getConn().localConnectionError->code);
  EXPECT_TRUE(client->isClosed());
  EXPECT_TRUE(verifyFramePresent(
      socketWrites,
      *makeHandshakeCodec(),
      QuicFrame::Type::ConnectionCloseFrame));
}

TEST_F(QuicClientTransportAfterStartTest, DestroyWithoutClosing) {
  StreamId streamId = client->createBidirectionalStream().value();

  auto fizzClientSetReadCallback31 = client->setReadCallback(streamId, &readCb);

  EXPECT_CALL(clientConnCallback, onConnectionError(_)).Times(0);
  EXPECT_CALL(clientConnCallback, onConnectionEnd());

  auto write = IOBuf::copyBuffer("no");
  auto fizzClientWriteChain26 =
      client->writeChain(streamId, write->clone(), true, &deliveryCallback);
  loopForWrites();

  EXPECT_CALL(deliveryCallback, onCanceled(_, _));
  EXPECT_CALL(readCb, readError(_, _));
}

TEST_F(QuicClientTransportAfterStartTest, DestroyWhileDraining) {
  StreamId streamId = client->createBidirectionalStream().value();

  auto fizzClientSetReadCallback32 = client->setReadCallback(streamId, &readCb);

  auto write = IOBuf::copyBuffer("no");
  auto fizzClientWriteChain27 =
      client->writeChain(streamId, write->clone(), true, &deliveryCallback);

  loopForWrites();
  EXPECT_CALL(clientConnCallback, onConnectionError(_)).Times(0);
  EXPECT_CALL(clientConnCallback, onConnectionEnd()).Times(0);
  // Go into draining with one active stream.

  EXPECT_CALL(deliveryCallback, onCanceled(_, _));
  EXPECT_CALL(readCb, readError(_, _));
  client->close(std::nullopt);
}

TEST_F(QuicClientTransportAfterStartTest, CloseNowWhileDraining) {
  // Drain first with no active streams
  auto err = QuicError(
      QuicErrorCode(LocalErrorCode::INTERNAL_ERROR),
      toString(LocalErrorCode::INTERNAL_ERROR).str());
  client->close(err);
  EXPECT_TRUE(client->isDraining());
  client->closeNow(err);
  EXPECT_FALSE(client->isDraining());
  client.reset();
  EXPECT_TRUE(destructionCallback->isDestroyed());
}

TEST_F(QuicClientTransportAfterStartTest, ExpiredDrainTimeout) {
  auto err = QuicError(
      QuicErrorCode(LocalErrorCode::INTERNAL_ERROR),
      toString(LocalErrorCode::INTERNAL_ERROR).str());
  client->close(err);
  EXPECT_TRUE(client->isDraining());
  EXPECT_FALSE(destructionCallback->isDestroyed());
  client->drainTimeout().timeoutExpired();
  client.reset();
  EXPECT_TRUE(destructionCallback->isDestroyed());
}

TEST_F(QuicClientTransportAfterStartTest, WriteThrowsExceptionWhileDraining) {
  // Drain first with no active streams
  auto err = QuicError(
      QuicErrorCode(LocalErrorCode::INTERNAL_ERROR),
      toString(LocalErrorCode::INTERNAL_ERROR).str());
  EXPECT_CALL(*sock, write(_, _, _))
      .WillRepeatedly(SetErrnoAndReturn(EBADF, -1));
  client->close(err);
  EXPECT_FALSE(client->idleTimeout().isTimerCallbackScheduled());
}

TEST_F(QuicClientTransportAfterStartTest, DestroyEvbWhileLossTimeoutActive) {
  StreamId streamId = client->createBidirectionalStream().value();

  auto fizzClientSetReadCallback33 = client->setReadCallback(streamId, &readCb);

  auto write = IOBuf::copyBuffer("no");
  auto fizzClientWriteChain28 =
      client->writeChain(streamId, write->clone(), true);
  loopForWrites();
  EXPECT_TRUE(client->lossTimeout().isTimerCallbackScheduled());
  eventbase_.reset();
}

class TestCCFactory : public CongestionControllerFactory {
 public:
  std::unique_ptr<CongestionController> makeCongestionController(
      QuicConnectionStateBase& conn,
      CongestionControlType type) override {
    EXPECT_EQ(type, CongestionControlType::Cubic);
    createdControllers++;
    return std::make_unique<Cubic>(conn);
  }

  int createdControllers{0};
};

TEST_F(
    QuicClientTransportAfterStartTest,
    CongestionControlRecreatedWithNewFactory) {
  // Default: Cubic
  auto cc = client->getConn().congestionController.get();
  EXPECT_EQ(CongestionControlType::Cubic, cc->type());

  // Check Cubic CC instance is recreated with new CC factory
  auto factory = std::make_shared<TestCCFactory>();
  client->setCongestionControllerFactory(factory);
  auto newCC = client->getConn().congestionController.get();
  EXPECT_EQ(nullptr, newCC);
  client->setCongestionControl(CongestionControlType::Cubic);
  newCC = client->getConn().congestionController.get();
  EXPECT_NE(nullptr, newCC);
  EXPECT_EQ(factory->createdControllers, 1);
}

TEST_F(QuicClientTransportAfterStartTest, SetCongestionControl) {
  // Default: Cubic
  auto cc = client->getConn().congestionController.get();
  EXPECT_EQ(CongestionControlType::Cubic, cc->type());

  // Setting CC factory resets CC controller
  client->setCongestionControllerFactory(
      std::make_shared<DefaultCongestionControllerFactory>());
  EXPECT_FALSE(client->getConn().congestionController);

  // Set to Cubic explicitly this time
  client->setCongestionControl(CongestionControlType::Cubic);
  cc = client->getConn().congestionController.get();
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

TEST_F(QuicClientTransportAfterStartTest, SetCongestionControlBbr) {
  // Default: Cubic
  auto cc = client->getConn().congestionController.get();
  EXPECT_EQ(CongestionControlType::Cubic, cc->type());

  // Change to BBR, which requires enable pacing first
  client->setCongestionControllerFactory(
      std::make_shared<DefaultCongestionControllerFactory>());
  client->setPacingTimer(
      std::make_shared<quic::HighResQuicTimer>(
          qEvb_->getBackingEventBase(), 1ms));
  client->getNonConstConn().transportSettings.pacingEnabled = true;
  client->setCongestionControl(CongestionControlType::BBR);
  cc = client->getConn().congestionController.get();
  EXPECT_EQ(CongestionControlType::BBR, cc->type());
}

TEST_F(QuicClientTransportAfterStartTest, PingIsTreatedAsRetransmittable) {
  PingFrame pingFrame;
  ShortHeader header(
      ProtectionType::KeyPhaseZero, *originalConnId, appDataPacketNum++);
  RegularQuicPacketBuilder builder(
      client->getConn().udpSendPacketLen,
      std::move(header),
      0 /* largestAcked */);
  ASSERT_FALSE(builder.encodePacketHeader().hasError());
  ASSERT_FALSE(writeFrame(pingFrame, builder).hasError());
  auto packet = packetToBuf(std::move(builder).buildPacket());
  deliverData(packet->coalesce());
  EXPECT_TRUE(client->getConn().pendingEvents.scheduleAckTimeout);
}

TEST_F(QuicClientTransportAfterStartTest, ReceiveDatagramFrameAndDiscard) {
  ShortHeader header(
      ProtectionType::KeyPhaseZero, *originalConnId, appDataPacketNum++);

  RegularQuicPacketBuilder builder(
      client->getConn().udpSendPacketLen,
      std::move(header),
      0 /* largestAcked */);
  ASSERT_FALSE(builder.encodePacketHeader().hasError());

  EXPECT_CALL(*quicStats_, onDatagramDroppedOnRead()).Times(1);
  StringPiece datagramPayload = "do not rely on me. I am unreliable";
  DatagramFrame datagramFrame(
      datagramPayload.size(), IOBuf::copyBuffer(datagramPayload));
  ASSERT_FALSE(writeFrame(datagramFrame, builder).hasError());
  auto packet = packetToBuf(std::move(builder).buildPacket());
  deliverData(packet->coalesce());
  ASSERT_EQ(client->getConn().datagramState.readBuffer.size(), 0);
}

TEST_F(QuicClientTransportAfterStartTest, ReceiveDatagramFrameAndStore) {
  auto& conn = client->getNonConstConn();
  conn.datagramState.maxReadFrameSize = std::numeric_limits<uint16_t>::max();
  conn.datagramState.maxReadBufferSize = 10;

  EXPECT_CALL(*quicStats_, onDatagramRead(_))
      .Times(conn.datagramState.maxReadBufferSize)
      .WillRepeatedly(Invoke([](uint64_t bytes) { EXPECT_GT(bytes, 0); }));
  EXPECT_CALL(*quicStats_, onDatagramDroppedOnRead())
      .Times(conn.datagramState.maxReadBufferSize);
  for (uint64_t i = 0; i < conn.datagramState.maxReadBufferSize * 2; i++) {
    ShortHeader header(
        ProtectionType::KeyPhaseZero, *originalConnId, appDataPacketNum++);

    RegularQuicPacketBuilder builder(
        client->getConn().udpSendPacketLen,
        std::move(header),
        0 /* largestAcked */);
    ASSERT_FALSE(builder.encodePacketHeader().hasError());

    StringPiece datagramPayload = "do not rely on me. I am unreliable";
    DatagramFrame datagramFrame(
        datagramPayload.size(), IOBuf::copyBuffer(datagramPayload));
    ASSERT_FALSE(writeFrame(datagramFrame, builder).hasError());
    auto packet = packetToBuf(std::move(builder).buildPacket());
    deliverData(packet->coalesce());
    if (i < conn.datagramState.maxReadBufferSize) {
      ASSERT_EQ(client->getConn().datagramState.readBuffer.size(), i + 1);
    }
  }
  ASSERT_EQ(
      client->getConn().datagramState.readBuffer.size(),
      conn.datagramState.maxReadBufferSize);
}

TEST_F(
    QuicClientTransportAfterStartTest,
    ReceiveDatagramFrameAndDiscardOldDataFirst) {
  auto& conn = client->getNonConstConn();
  conn.datagramState.maxReadFrameSize = std::numeric_limits<uint16_t>::max();
  conn.datagramState.maxReadBufferSize = 1;
  auto& transportSettings = client->getNonConstConn().transportSettings;
  transportSettings.datagramConfig.recvDropOldDataFirst = true;

  // Enqueue first datagram
  ShortHeader header1(
      ProtectionType::KeyPhaseZero, *originalConnId, appDataPacketNum++);
  RegularQuicPacketBuilder builder1(
      client->getConn().udpSendPacketLen,
      std::move(header1),
      0 /* largestAcked */);
  ASSERT_FALSE(builder1.encodePacketHeader().hasError());
  StringPiece datagramPayload1 = "first";
  DatagramFrame datagramFrame1(
      datagramPayload1.size(), IOBuf::copyBuffer(datagramPayload1));
  ASSERT_FALSE(writeFrame(datagramFrame1, builder1).hasError());
  auto packet1 = packetToBuf(std::move(builder1).buildPacket());
  EXPECT_CALL(*quicStats_, onDatagramRead(_))
      .Times(1)
      .WillRepeatedly(Invoke([](uint64_t bytes) { EXPECT_GT(bytes, 0); }));
  deliverData(packet1->coalesce());
  ASSERT_EQ(
      client->getConn().datagramState.readBuffer.size(),
      conn.datagramState.maxReadBufferSize);
  // Enqueue second datagram
  ShortHeader header2(
      ProtectionType::KeyPhaseZero, *originalConnId, appDataPacketNum++);
  RegularQuicPacketBuilder builder2(
      client->getConn().udpSendPacketLen,
      std::move(header2),
      0 /* largestAcked */);
  ASSERT_FALSE(builder2.encodePacketHeader().hasError());
  StringPiece datagramPayload2 = "second";
  DatagramFrame datagramFrame2(
      datagramPayload2.size(), IOBuf::copyBuffer(datagramPayload2));
  ASSERT_FALSE(writeFrame(datagramFrame2, builder2).hasError());
  auto packet2 = packetToBuf(std::move(builder2).buildPacket());
  EXPECT_CALL(*quicStats_, onDatagramDroppedOnRead()).Times(1);
  EXPECT_CALL(*quicStats_, onDatagramRead(_))
      .Times(1)
      .WillRepeatedly(Invoke([](uint64_t bytes) { EXPECT_GT(bytes, 0); }));
  deliverData(packet2->coalesce());
  ASSERT_EQ(
      client->getConn().datagramState.readBuffer.size(),
      conn.datagramState.maxReadBufferSize);

  auto payload = client->getConn()
                     .datagramState.readBuffer[0]
                     .bufQueue()
                     .front()
                     ->clone()
                     ->moveToFbString();
  ASSERT_EQ(payload, "second");
}

TEST_F(QuicClientTransportAfterStartTest, OneCloseFramePerRtt) {
  auto streamId = client->createBidirectionalStream().value();
  auto& conn = client->getNonConstConn();
  conn.lossState.srtt = 10s;
  EXPECT_CALL(*sock, write(_, _, _)).WillRepeatedly(Return(100));
  loopForWrites();
  Mock::VerifyAndClearExpectations(sock);

  // Close the client transport. There could be multiple writes given how many
  // ciphers we have.
  EXPECT_CALL(*sock, write(_, _, _))
      .Times(AtLeast(1))
      .WillRepeatedly(Return(10));
  client->close(QuicError(
      QuicErrorCode(LocalErrorCode::INTERNAL_ERROR),
      toString(LocalErrorCode::INTERNAL_ERROR).str()));
  EXPECT_TRUE(conn.lastCloseSentTime.has_value());
  Mock::VerifyAndClearExpectations(sock);

  // Then received some server packet, which won't trigger another close
  EXPECT_CALL(*sock, write(_, _, _)).Times(0);
  auto firstData = folly::IOBuf::copyBuffer(
      "I got a room full of your posters and your pictures, man");
  deliverDataWithoutErrorCheck(packetToBuf(createStreamPacket(
                                               *serverChosenConnId,
                                               *originalConnId,
                                               appDataPacketNum++,
                                               streamId,
                                               *firstData,
                                               0 /* cipherOverhead */,
                                               0 /* largestAcked */))
                                   ->coalesce());
  Mock::VerifyAndClearExpectations(sock);

  // force the clock:
  conn.lastCloseSentTime = Clock::now() - 10s;
  conn.lossState.srtt = 1us;
  // Receive another server packet
  EXPECT_CALL(*sock, write(_, _, _))
      .Times(AtLeast(1))
      .WillRepeatedly(Return(10));
  auto secondData = folly::IOBuf::copyBuffer(
      "Dear Slim, I wrote to you but you still ain't callin'");
  deliverDataWithoutErrorCheck(packetToBuf(createStreamPacket(
                                               *serverChosenConnId,
                                               *originalConnId,
                                               appDataPacketNum++,
                                               streamId,
                                               *secondData,
                                               0 /* cipherOverhead */,
                                               0 /* largestAcked */))
                                   ->coalesce());
}

TEST_F(QuicClientTransportAfterStartTest, RetryPacketAfterRxInitial) {
  ConnectionId initialDstConnId =
      ConnectionId::createAndMaybeCrash(kInitialDstConnIdVecForRetryTest);
  client->getNonConstConn().originalDestinationConnectionId = initialDstConnId;
  recvServerRetry(serverAddr);
  loopForWrites();
  // validate we dropped the retry packet via retryToken str
  EXPECT_TRUE(client->getConn().retryToken.empty());
  client->close(std::nullopt);
}

class QuicClientTransportPskCacheTest
    : public QuicClientTransportAfterStartTestBase {
 public:
  void SetUpChild() override {
    QuicClientTransportAfterStartTestBase::SetUpChild();
  }

  std::shared_ptr<QuicPskCache> getPskCache() override {
    mockPskCache_ = std::make_shared<NiceMock<MockQuicPskCache>>();
    return mockPskCache_;
  }

 protected:
  std::shared_ptr<MockQuicPskCache> mockPskCache_;
};

TEST_F(QuicClientTransportPskCacheTest, TestOnNewCachedPsk) {
  std::string appParams = "APP params";
  client->setEarlyDataAppParamsFunctions(
      [](const Optional<std::string>&, const BufPtr&) { return true; },
      [=]() -> BufPtr { return folly::IOBuf::copyBuffer(appParams); });
  EXPECT_CALL(*mockPskCache_, putPsk(hostname_, _))
      .WillOnce(Invoke([=](const std::string&, QuicCachedPsk psk) {
        EXPECT_EQ(psk.appParams, appParams);
      }));
  mockClientHandshake->triggerOnNewCachedPsk();
}

TEST_F(QuicClientTransportPskCacheTest, TestTwoOnNewCachedPsk) {
  std::string appParams1 = "APP params1";
  client->setEarlyDataAppParamsFunctions(
      [](const Optional<std::string>&, const BufPtr&) { return true; },
      [=]() -> BufPtr { return folly::IOBuf::copyBuffer(appParams1); });
  EXPECT_CALL(*mockPskCache_, putPsk(hostname_, _))
      .WillOnce(Invoke([=](const std::string&, QuicCachedPsk psk) {
        auto& params = psk.transportParams;
        EXPECT_EQ(params.initialMaxData, kDefaultConnectionFlowControlWindow);
        EXPECT_EQ(
            params.initialMaxStreamDataBidiLocal,
            kDefaultStreamFlowControlWindow);
        EXPECT_EQ(
            params.initialMaxStreamDataBidiRemote,
            kDefaultStreamFlowControlWindow);
        EXPECT_EQ(
            params.initialMaxStreamDataUni, kDefaultStreamFlowControlWindow);
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

  std::string appParams2 = "APP params2";
  client->setEarlyDataAppParamsFunctions(
      [](const Optional<std::string>&, const BufPtr&) { return true; },
      [=]() -> BufPtr { return folly::IOBuf::copyBuffer(appParams2); });
  EXPECT_CALL(*mockPskCache_, putPsk(hostname_, _))
      .WillOnce(Invoke([=](const std::string&, QuicCachedPsk psk) {
        auto& params = psk.transportParams;
        EXPECT_EQ(params.initialMaxData, kDefaultConnectionFlowControlWindow);
        EXPECT_EQ(
            params.initialMaxStreamDataBidiLocal,
            kDefaultStreamFlowControlWindow);
        EXPECT_EQ(
            params.initialMaxStreamDataBidiRemote,
            kDefaultStreamFlowControlWindow);
        EXPECT_EQ(
            params.initialMaxStreamDataUni, kDefaultStreamFlowControlWindow);
        EXPECT_EQ(psk.appParams, appParams2);
      }));
  mockClientHandshake->triggerOnNewCachedPsk();
}

class QuicZeroRttClientTest : public QuicClientTransportAfterStartTestBase {
 public:
  ~QuicZeroRttClientTest() override = default;

  void setFakeHandshakeCiphers() override {
    auto readAead = test::createNoOpAead();
    auto writeAead = test::createNoOpAead();
    auto zeroAead = test::createNoOpAead();
    auto handshakeReadAead = test::createNoOpAead();
    auto handshakeWriteAead = test::createNoOpAead();
    mockClientHandshake->setOneRttReadCipher(std::move(readAead));
    mockClientHandshake->setOneRttWriteCipher(std::move(writeAead));
    mockClientHandshake->setZeroRttWriteCipher(std::move(zeroAead));
    mockClientHandshake->setHandshakeReadCipher(std::move(handshakeReadAead));
    mockClientHandshake->setHandshakeWriteCipher(std::move(handshakeWriteAead));

    mockClientHandshake->setHandshakeReadHeaderCipher(
        test::createNoOpHeaderCipherNoThrow());
    mockClientHandshake->setHandshakeWriteHeaderCipher(
        test::createNoOpHeaderCipherNoThrow());
    mockClientHandshake->setOneRttWriteHeaderCipher(
        test::createNoOpHeaderCipherNoThrow());
    mockClientHandshake->setOneRttReadHeaderCipher(
        test::createNoOpHeaderCipherNoThrow());
    mockClientHandshake->setZeroRttWriteHeaderCipher(
        test::createNoOpHeaderCipherNoThrow());
  }

  std::shared_ptr<QuicPskCache> getPskCache() override {
    if (!mockQuicPskCache_) {
      mockQuicPskCache_ = std::make_shared<MockQuicPskCache>();
    }
    return mockQuicPskCache_;
  }

  void start() override {
    TransportSettings clientSettings;
    // Ignore path mtu to test negotiation.
    clientSettings.canIgnorePathMTU = true;
    clientSettings.attemptEarlyData = true;
    client->setTransportSettings(clientSettings);
  }

  void startClient() {
    EXPECT_CALL(clientConnSetupCallback, onTransportReady());
    client->start(&clientConnSetupCallback, &clientConnCallback);
    setConnectionIds();
    EXPECT_EQ(socketWrites.size(), 1);
    EXPECT_TRUE(
        verifyLongHeader(*socketWrites.at(0), LongHeader::Types::Initial));
    socketWrites.clear();
  }

  bool zeroRttPacketsOutstanding() {
    for (auto& packet : client->getNonConstConn().outstandings.packets) {
      bool isZeroRtt =
          packet.packet.header.getProtectionType() == ProtectionType::ZeroRtt;
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
        quicCachedPsk.transportParams.initialMaxStreamDataBidiLocal =
            kDefaultStreamFlowControlWindow;
        quicCachedPsk.transportParams.initialMaxStreamDataBidiRemote =
            kDefaultStreamFlowControlWindow;
        quicCachedPsk.transportParams.initialMaxStreamDataUni =
            kDefaultStreamFlowControlWindow;
        quicCachedPsk.transportParams.initialMaxData =
            kDefaultConnectionFlowControlWindow;
        quicCachedPsk.transportParams.idleTimeout = kDefaultIdleTimeout.count();
        quicCachedPsk.transportParams.maxRecvPacketSize =
            kDefaultUDPReadBufferSize;
        quicCachedPsk.transportParams.initialMaxStreamsBidi =
            std::numeric_limits<uint32_t>::max();
        quicCachedPsk.transportParams.initialMaxStreamsUni =
            std::numeric_limits<uint32_t>::max();
        return quicCachedPsk;
      }));
  bool performedValidation = false;
  client->setEarlyDataAppParamsFunctions(
      [&](const Optional<std::string>&, const BufPtr&) {
        performedValidation = true;
        return true;
      },
      []() -> BufPtr { return nullptr; });
  startClient();
  EXPECT_TRUE(performedValidation);

  socketWrites.clear();
  auto streamId = client->createBidirectionalStream().value();
  auto fizzClientWriteChain29 =
      client->writeChain(streamId, IOBuf::copyBuffer("hello"), true);
  loopForWrites();
  EXPECT_TRUE(zeroRttPacketsOutstanding());
  assertWritten(false, LongHeader::Types::ZeroRtt);
  EXPECT_CALL(clientConnSetupCallback, onReplaySafe());
  mockClientHandshake->setZeroRttRejected(
      false /*rejected*/, false /*canResendZeroRtt*/);
  recvServerHello();

  EXPECT_EQ(client->getConn().zeroRttWriteCipher, nullptr);

  // All the data is still there.
  EXPECT_TRUE(zeroRttPacketsOutstanding());
  // Transport parameters did not change since zero rtt was accepted.
  // Except for max packet size.
  verifyTransportParameters(
      kDefaultConnectionFlowControlWindow,
      kDefaultStreamFlowControlWindow,
      kDefaultIdleTimeout,
      kDefaultAckDelayExponent,
      kDefaultMaxUDPPayload);

  EXPECT_CALL(*mockQuicPskCache_, putPsk(hostname_, _))
      .WillOnce(Invoke([=](const std::string&, QuicCachedPsk psk) {
        auto& params = psk.transportParams;
        EXPECT_EQ(params.initialMaxData, kDefaultConnectionFlowControlWindow);
        EXPECT_EQ(
            params.initialMaxStreamDataBidiLocal,
            kDefaultStreamFlowControlWindow);
        EXPECT_EQ(
            params.initialMaxStreamDataBidiRemote,
            kDefaultStreamFlowControlWindow);
        EXPECT_EQ(
            params.initialMaxStreamDataUni, kDefaultStreamFlowControlWindow);
        EXPECT_EQ(
            params.initialMaxStreamsBidi, std::numeric_limits<uint32_t>::max());
        EXPECT_EQ(
            params.initialMaxStreamsUni, std::numeric_limits<uint32_t>::max());
      }));
  mockClientHandshake->triggerOnNewCachedPsk();
}

TEST_F(QuicZeroRttClientTest, TestEarlyRetransmit0Rtt) {
  EXPECT_CALL(*mockQuicPskCache_, getPsk(hostname_))
      .WillOnce(InvokeWithoutArgs([]() {
        QuicCachedPsk quicCachedPsk;
        quicCachedPsk.transportParams.initialMaxStreamDataBidiLocal =
            kDefaultStreamFlowControlWindow;
        quicCachedPsk.transportParams.initialMaxStreamDataBidiRemote =
            kDefaultStreamFlowControlWindow;
        quicCachedPsk.transportParams.initialMaxStreamDataUni =
            kDefaultStreamFlowControlWindow;
        quicCachedPsk.transportParams.initialMaxData =
            kDefaultConnectionFlowControlWindow;
        quicCachedPsk.transportParams.idleTimeout = kDefaultIdleTimeout.count();
        quicCachedPsk.transportParams.maxRecvPacketSize =
            kDefaultUDPReadBufferSize;
        quicCachedPsk.transportParams.initialMaxStreamsBidi =
            std::numeric_limits<uint32_t>::max();
        quicCachedPsk.transportParams.initialMaxStreamsUni =
            std::numeric_limits<uint32_t>::max();
        return quicCachedPsk;
      }));
  auto tp = client->getTransportSettings();
  tp.earlyRetransmit0Rtt = true;
  client->setTransportSettings(tp);
  bool performedValidation = false;
  client->setEarlyDataAppParamsFunctions(
      [&](const Optional<std::string>&, const BufPtr&) {
        performedValidation = true;
        return true;
      },
      []() -> BufPtr { return nullptr; });
  startClient();
  EXPECT_TRUE(performedValidation);

  socketWrites.clear();
  auto streamId = client->createBidirectionalStream().value();
  auto fizzClientWriteChain30 =
      client->writeChain(streamId, IOBuf::copyBuffer("hello"), true);
  loopForWrites();
  EXPECT_TRUE(zeroRttPacketsOutstanding());
  assertWritten(false, LongHeader::Types::ZeroRtt);
  EXPECT_CALL(clientConnSetupCallback, onReplaySafe());
  mockClientHandshake->setZeroRttRejected(
      false /*rejected*/, false /*canResendZeroRtt*/);
  recvServerHello();

  EXPECT_EQ(client->getConn().zeroRttWriteCipher, nullptr);

  // Zero-rtt data is not immediately marked lost.
  EXPECT_TRUE(zeroRttPacketsOutstanding());

  // The PTO should trigger marking all the zero-rtt data as lost.
  ASSERT_FALSE(onPTOAlarm(client->getNonConstConn()).hasError());
  EXPECT_FALSE(zeroRttPacketsOutstanding());

  // Transport parameters did not change since zero rtt was accepted.
  // Except for max packet size.
  verifyTransportParameters(
      kDefaultConnectionFlowControlWindow,
      kDefaultStreamFlowControlWindow,
      kDefaultIdleTimeout,
      kDefaultAckDelayExponent,
      kDefaultMaxUDPPayload);

  EXPECT_CALL(*mockQuicPskCache_, putPsk(hostname_, _))
      .WillOnce(Invoke([=](const std::string&, QuicCachedPsk psk) {
        auto& params = psk.transportParams;
        EXPECT_EQ(params.initialMaxData, kDefaultConnectionFlowControlWindow);
        EXPECT_EQ(
            params.initialMaxStreamDataBidiLocal,
            kDefaultStreamFlowControlWindow);
        EXPECT_EQ(
            params.initialMaxStreamDataBidiRemote,
            kDefaultStreamFlowControlWindow);
        EXPECT_EQ(
            params.initialMaxStreamDataUni, kDefaultStreamFlowControlWindow);
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
        quicCachedPsk.transportParams.initialMaxStreamDataBidiLocal =
            kDefaultStreamFlowControlWindow;
        quicCachedPsk.transportParams.initialMaxStreamDataBidiRemote =
            kDefaultStreamFlowControlWindow;
        quicCachedPsk.transportParams.initialMaxStreamDataUni =
            kDefaultStreamFlowControlWindow;
        quicCachedPsk.transportParams.initialMaxData =
            kDefaultConnectionFlowControlWindow;
        quicCachedPsk.transportParams.idleTimeout = kDefaultIdleTimeout.count();
        quicCachedPsk.transportParams.maxRecvPacketSize =
            kDefaultUDPReadBufferSize;
        quicCachedPsk.transportParams.initialMaxStreamsBidi =
            std::numeric_limits<uint32_t>::max();
        quicCachedPsk.transportParams.initialMaxStreamsUni =
            std::numeric_limits<uint32_t>::max();
        return quicCachedPsk;
      }));
  bool performedValidation = false;
  client->setEarlyDataAppParamsFunctions(
      [&](const Optional<std::string>&, const BufPtr&) {
        performedValidation = true;
        return true;
      },
      []() -> BufPtr { return nullptr; });
  startClient();
  EXPECT_TRUE(performedValidation);

  socketWrites.clear();
  auto streamId = client->createBidirectionalStream().value();
  auto fizzClientWriteChain31 =
      client->writeChain(streamId, IOBuf::copyBuffer("hello"), true);
  loopForWrites();
  EXPECT_TRUE(zeroRttPacketsOutstanding());
  EXPECT_CALL(clientConnSetupCallback, onReplaySafe());
  mockClientHandshake->setZeroRttRejected(
      true /*rejected*/, true /*canResendZeroRtt*/);
  EXPECT_CALL(*mockQuicPskCache_, removePsk(hostname_));
  recvServerHello();
  verifyTransportParameters(
      kDefaultConnectionFlowControlWindow,
      kDefaultStreamFlowControlWindow,
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
        quicCachedPsk.transportParams.initialMaxStreamDataBidiLocal =
            kDefaultStreamFlowControlWindow;
        quicCachedPsk.transportParams.initialMaxStreamDataBidiRemote =
            kDefaultStreamFlowControlWindow;
        quicCachedPsk.transportParams.initialMaxStreamDataUni =
            kDefaultStreamFlowControlWindow;
        quicCachedPsk.transportParams.initialMaxData =
            kDefaultConnectionFlowControlWindow;
        quicCachedPsk.transportParams.idleTimeout = kDefaultIdleTimeout.count();
        quicCachedPsk.transportParams.maxRecvPacketSize =
            kDefaultUDPReadBufferSize;
        quicCachedPsk.transportParams.initialMaxStreamsBidi =
            std::numeric_limits<uint32_t>::max();
        quicCachedPsk.transportParams.initialMaxStreamsUni =
            std::numeric_limits<uint32_t>::max();
        return quicCachedPsk;
      }));
  bool performedValidation = false;
  client->setEarlyDataAppParamsFunctions(
      [&](const Optional<std::string>&, const BufPtr&) {
        performedValidation = true;
        return true;
      },
      []() -> BufPtr { return nullptr; });
  startClient();
  EXPECT_TRUE(performedValidation);

  mockClientHandshake->maxInitialStreamData = 10;
  socketWrites.clear();
  auto streamId = client->createBidirectionalStream().value();
  auto fizzClientWriteChain32 =
      client->writeChain(streamId, IOBuf::copyBuffer("hello"), true);
  loopForWrites();
  EXPECT_TRUE(zeroRttPacketsOutstanding());
  mockClientHandshake->setZeroRttRejected(
      true /*rejected*/, true /*canResendZeroRtt*/);
  EXPECT_CALL(*mockQuicPskCache_, removePsk(hostname_));
  EXPECT_THROW(recvServerHello(), std::runtime_error);
}

TEST_F(QuicZeroRttClientTest, TestZeroRttRejectionCannotResendZeroRttData) {
  EXPECT_CALL(*mockQuicPskCache_, getPsk(hostname_))
      .WillOnce(InvokeWithoutArgs([]() {
        QuicCachedPsk quicCachedPsk;
        quicCachedPsk.transportParams.initialMaxStreamDataBidiLocal =
            kDefaultStreamFlowControlWindow;
        quicCachedPsk.transportParams.initialMaxStreamDataBidiRemote =
            kDefaultStreamFlowControlWindow;
        quicCachedPsk.transportParams.initialMaxStreamDataUni =
            kDefaultStreamFlowControlWindow;
        quicCachedPsk.transportParams.initialMaxData =
            kDefaultConnectionFlowControlWindow;
        quicCachedPsk.transportParams.idleTimeout = kDefaultIdleTimeout.count();
        quicCachedPsk.transportParams.maxRecvPacketSize =
            kDefaultUDPReadBufferSize;
        quicCachedPsk.transportParams.initialMaxStreamsBidi =
            std::numeric_limits<uint32_t>::max();
        quicCachedPsk.transportParams.initialMaxStreamsUni =
            std::numeric_limits<uint32_t>::max();
        return quicCachedPsk;
      }));
  bool performedValidation = false;
  client->setEarlyDataAppParamsFunctions(
      [&](const Optional<std::string>&, const BufPtr&) {
        performedValidation = true;
        return true;
      },
      []() -> BufPtr { return nullptr; });
  startClient();
  EXPECT_TRUE(performedValidation);

  socketWrites.clear();
  auto streamId = client->createBidirectionalStream().value();
  auto fizzClientWriteChain33 =
      client->writeChain(streamId, IOBuf::copyBuffer("hello"), true);
  loopForWrites();
  EXPECT_TRUE(zeroRttPacketsOutstanding());
  EXPECT_CALL(clientConnSetupCallback, onReplaySafe()).Times(0);
  mockClientHandshake->setZeroRttRejected(
      true /*rejected*/, false /*canResendZeroRtt*/);
  EXPECT_CALL(*mockQuicPskCache_, removePsk(hostname_));
  EXPECT_THROW(recvServerHello(), std::runtime_error);
}

class QuicZeroRttHappyEyeballsClientTransportTest
    : public QuicZeroRttClientTest {
 public:
  void SetUpChild() override {
    client->setHostname(hostname_);

    auto secondSocket =
        std::make_unique<NiceMock<quic::test::MockAsyncUDPSocket>>(qEvb_);
    secondSock = secondSocket.get();
    ON_CALL(*secondSock, address()).WillByDefault(testing::Return(serverAddr));
    ON_CALL(*secondSock, setAdditionalCmsgsFunc(testing::_))
        .WillByDefault(testing::Return(quic::Expected<void, QuicError>{}));
    ON_CALL(*secondSock, getGSO).WillByDefault(testing::Return(0));
    ON_CALL(*secondSock, getGRO).WillByDefault(testing::Return(0));
    ON_CALL(*secondSock, init(testing::_))
        .WillByDefault(testing::Return(quic::Expected<void, QuicError>{}));
    ON_CALL(*secondSock, bind(testing::_))
        .WillByDefault(testing::Return(quic::Expected<void, QuicError>{}));
    ON_CALL(*secondSock, connect(testing::_))
        .WillByDefault(testing::Return(quic::Expected<void, QuicError>{}));
    ON_CALL(*secondSock, close())
        .WillByDefault(testing::Return(quic::Expected<void, QuicError>{}));
    ON_CALL(*secondSock, resumeWrite(testing::_))
        .WillByDefault(testing::Return(quic::Expected<void, QuicError>{}));
    ON_CALL(*secondSock, setGRO(testing::_))
        .WillByDefault(testing::Return(quic::Expected<void, QuicError>{}));
    ON_CALL(*secondSock, setRecvTos(testing::_))
        .WillByDefault(testing::Return(quic::Expected<void, QuicError>{}));
    ON_CALL(*secondSock, getRecvTos()).WillByDefault(testing::Return(false));
    ON_CALL(*secondSock, setTosOrTrafficClass(testing::_))
        .WillByDefault(testing::Return(quic::Expected<void, QuicError>{}));
    ON_CALL(*secondSock, setCmsgs(testing::_))
        .WillByDefault(testing::Return(quic::Expected<void, QuicError>{}));
    ON_CALL(*secondSock, appendCmsgs(testing::_))
        .WillByDefault(testing::Return(quic::Expected<void, QuicError>{}));
    ON_CALL(*secondSock, getTimestamping()).WillByDefault(testing::Return(0));
    ON_CALL(*secondSock, setReuseAddr(testing::_))
        .WillByDefault(testing::Return(quic::Expected<void, QuicError>{}));
    ON_CALL(*secondSock, setDFAndTurnOffPMTU())
        .WillByDefault(testing::Return(quic::Expected<void, QuicError>{}));
    ON_CALL(*secondSock, setAdditionalCmsgsFunc(testing::_))
        .WillByDefault(testing::Return(quic::Expected<void, QuicError>{}));
    ON_CALL(*secondSock, setErrMessageCallback(testing::_))
        .WillByDefault(testing::Return(quic::Expected<void, QuicError>{}));
    ON_CALL(*secondSock, applyOptions(testing::_, testing::_))
        .WillByDefault(testing::Return(quic::Expected<void, QuicError>{}));
    ON_CALL(*secondSock, setReusePort(testing::_))
        .WillByDefault(testing::Return(quic::Expected<void, QuicError>{}));
    ON_CALL(*secondSock, setRcvBuf(testing::_))
        .WillByDefault(testing::Return(quic::Expected<void, QuicError>{}));
    ON_CALL(*secondSock, setSndBuf(testing::_))
        .WillByDefault(testing::Return(quic::Expected<void, QuicError>{}));
    ON_CALL(*secondSock, setFD(testing::_, testing::_))
        .WillByDefault(testing::Return(quic::Expected<void, QuicError>{}));
    client->setHappyEyeballsEnabled(true);
    client->addNewPeerAddress(firstAddress);
    client->addNewPeerAddress(secondAddress);
    client->addNewSocket(std::move(secondSocket));

    EXPECT_EQ(client->getConn().happyEyeballsState.v6PeerAddress, firstAddress);
    EXPECT_EQ(
        client->getConn().happyEyeballsState.v4PeerAddress, secondAddress);

    setupCryptoLayer();
  }

  std::shared_ptr<QuicPskCache> getPskCache() override {
    if (!mockQuicPskCache_) {
      mockQuicPskCache_ = std::make_shared<MockQuicPskCache>();
    }
    return mockQuicPskCache_;
  }

 protected:
  quic::test::MockAsyncUDPSocket* secondSock;
  SocketAddress firstAddress{"::1", 443};
  SocketAddress secondAddress{"127.0.0.1", 443};
};

TEST_F(
    QuicZeroRttHappyEyeballsClientTransportTest,
    ZeroRttDataIsRetransmittedOverSecondSocket) {
  EXPECT_CALL(*mockQuicPskCache_, getPsk(hostname_))
      .WillOnce(InvokeWithoutArgs([]() {
        QuicCachedPsk quicCachedPsk;
        quicCachedPsk.transportParams.initialMaxStreamDataBidiLocal =
            kDefaultStreamFlowControlWindow;
        quicCachedPsk.transportParams.initialMaxStreamDataBidiRemote =
            kDefaultStreamFlowControlWindow;
        quicCachedPsk.transportParams.initialMaxStreamDataUni =
            kDefaultStreamFlowControlWindow;
        quicCachedPsk.transportParams.initialMaxData =
            kDefaultConnectionFlowControlWindow;
        quicCachedPsk.transportParams.idleTimeout = kDefaultIdleTimeout.count();
        quicCachedPsk.transportParams.maxRecvPacketSize =
            kDefaultUDPReadBufferSize;
        quicCachedPsk.transportParams.initialMaxStreamsBidi =
            std::numeric_limits<uint32_t>::max();
        quicCachedPsk.transportParams.initialMaxStreamsUni =
            std::numeric_limits<uint32_t>::max();
        return quicCachedPsk;
      }));
  client->setEarlyDataAppParamsFunctions(
      [&](const Optional<std::string>&, const BufPtr&) { return true; },
      []() -> BufPtr { return nullptr; });

  EXPECT_CALL(*sock, write(firstAddress, _, _))
      .WillRepeatedly(Invoke(
          [&](const SocketAddress&, const struct iovec* vec, size_t iovec_len) {
            socketWrites.push_back(
                copyChain(folly::IOBuf::wrapIov(vec, iovec_len)));
            return getTotalIovecLen(vec, iovec_len);
          }));
  EXPECT_CALL(*secondSock, write(_, _, _)).Times(0);
  startClient();
  socketWrites.clear();
  auto& conn = client->getConn();
  EXPECT_EQ(conn.peerAddress, firstAddress);
  EXPECT_EQ(conn.happyEyeballsState.secondPeerAddress, secondAddress);
  EXPECT_TRUE(client->happyEyeballsConnAttemptDelayTimeout()
                  .isTimerCallbackScheduled());
  // Cancel the delay timer because we want to manually fire it
  client->happyEyeballsConnAttemptDelayTimeout().cancelTimerCallback();

  auto streamId = client->createBidirectionalStream().value();
  auto fizzClientWriteChain34 =
      client->writeChain(streamId, IOBuf::copyBuffer("hello"), true);
  loopForWrites();
  EXPECT_TRUE(zeroRttPacketsOutstanding());
  assertWritten(false, LongHeader::Types::ZeroRtt);
  socketWrites.clear();

  // Manually expire conn attempt timeout
  EXPECT_FALSE(conn.happyEyeballsState.shouldWriteToSecondSocket);
  client->happyEyeballsConnAttemptDelayTimeout().timeoutExpired();
  EXPECT_TRUE(conn.happyEyeballsState.shouldWriteToSecondSocket);
  EXPECT_FALSE(client->happyEyeballsConnAttemptDelayTimeout()
                   .isTimerCallbackScheduled());
  loopForWrites();
  // Declared lost
  EXPECT_FALSE(zeroRttPacketsOutstanding());

  // Manually expire loss timeout to trigger write to both first and second
  // socket
  EXPECT_CALL(*sock, write(firstAddress, _, _))
      .Times(2)
      .WillRepeatedly(Invoke(
          [&](const SocketAddress&, const struct iovec* vec, size_t iovec_len) {
            socketWrites.push_back(
                copyChain(folly::IOBuf::wrapIov(vec, iovec_len)));
            return getTotalIovecLen(vec, iovec_len);
          }));
  EXPECT_CALL(*secondSock, write(secondAddress, _, _))
      .Times(2)
      .WillRepeatedly(Invoke(
          [&](const SocketAddress&, const struct iovec* vec, size_t iovec_len) {
            socketWrites.push_back(
                copyChain(folly::IOBuf::wrapIov(vec, iovec_len)));
            return getTotalIovecLen(vec, iovec_len);
          }));
  client->lossTimeout().cancelTimerCallback();
  client->lossTimeout().timeoutExpired();
  ASSERT_EQ(socketWrites.size(), 4);
  EXPECT_TRUE(
      verifyLongHeader(*socketWrites.at(0), LongHeader::Types::Initial));
  EXPECT_TRUE(
      verifyLongHeader(*socketWrites.at(1), LongHeader::Types::Initial));
  EXPECT_TRUE(
      verifyLongHeader(*socketWrites.at(2), LongHeader::Types::ZeroRtt));
  EXPECT_TRUE(
      verifyLongHeader(*socketWrites.at(3), LongHeader::Types::ZeroRtt));
}

TEST_F(
    QuicZeroRttHappyEyeballsClientTransportTest,
    ZeroRttDataIsRetransmittedOverSecondSocketOnWriteFail) {
  EXPECT_CALL(*mockQuicPskCache_, getPsk(hostname_))
      .WillOnce(InvokeWithoutArgs([]() {
        QuicCachedPsk quicCachedPsk;
        quicCachedPsk.transportParams.initialMaxStreamDataBidiLocal =
            kDefaultStreamFlowControlWindow;
        quicCachedPsk.transportParams.initialMaxStreamDataBidiRemote =
            kDefaultStreamFlowControlWindow;
        quicCachedPsk.transportParams.initialMaxStreamDataUni =
            kDefaultStreamFlowControlWindow;
        quicCachedPsk.transportParams.initialMaxData =
            kDefaultConnectionFlowControlWindow;
        quicCachedPsk.transportParams.idleTimeout = kDefaultIdleTimeout.count();
        quicCachedPsk.transportParams.maxRecvPacketSize =
            kDefaultUDPReadBufferSize;
        quicCachedPsk.transportParams.initialMaxStreamsBidi =
            std::numeric_limits<uint32_t>::max();
        quicCachedPsk.transportParams.initialMaxStreamsUni =
            std::numeric_limits<uint32_t>::max();
        return quicCachedPsk;
      }));
  client->setEarlyDataAppParamsFunctions(
      [&](const Optional<std::string>&, const BufPtr&) { return true; },
      []() -> BufPtr { return nullptr; });

  EXPECT_CALL(*sock, write(firstAddress, _, _))
      .WillOnce(Invoke(
          [&](const SocketAddress&, const struct iovec* vec, size_t iovec_len) {
            socketWrites.push_back(
                copyChain(folly::IOBuf::wrapIov(vec, iovec_len)));
            return getTotalIovecLen(vec, iovec_len);
          }));
  startClient();
  socketWrites.clear();
  auto& conn = client->getConn();
  EXPECT_EQ(conn.peerAddress, firstAddress);
  EXPECT_EQ(conn.happyEyeballsState.secondPeerAddress, secondAddress);
  ASSERT_TRUE(client->happyEyeballsConnAttemptDelayTimeout()
                  .isTimerCallbackScheduled());

  EXPECT_CALL(*sock, write(firstAddress, _, _))
      .WillOnce(Invoke([&](const SocketAddress&, const struct iovec*, size_t) {
        errno = EBADF;
        return -1;
      }));
  auto streamId = client->createBidirectionalStream().value();
  auto fizzClientWriteChain35 =
      client->writeChain(streamId, IOBuf::copyBuffer("hello"), true);
  loopForWrites();
  EXPECT_FALSE(zeroRttPacketsOutstanding());
  ASSERT_FALSE(client->happyEyeballsConnAttemptDelayTimeout()
                   .isTimerCallbackScheduled());

  ASSERT_TRUE(conn.happyEyeballsState.shouldWriteToSecondSocket);
  EXPECT_FALSE(client->happyEyeballsConnAttemptDelayTimeout()
                   .isTimerCallbackScheduled());

  EXPECT_CALL(*secondSock, write(secondAddress, _, _))
      .Times(2)
      .WillRepeatedly(Invoke(
          [&](const SocketAddress&, const struct iovec* vec, size_t iovec_len) {
            socketWrites.push_back(
                copyChain(folly::IOBuf::wrapIov(vec, iovec_len)));
            return getTotalIovecLen(vec, iovec_len);
          }));
  client->lossTimeout().cancelTimerCallback();
  client->lossTimeout().timeoutExpired();
  ASSERT_EQ(socketWrites.size(), 2);
  EXPECT_TRUE(
      verifyLongHeader(*socketWrites.at(0), LongHeader::Types::Initial));
  EXPECT_TRUE(
      verifyLongHeader(*socketWrites.at(1), LongHeader::Types::ZeroRtt));
}

class QuicProcessDataTest : public QuicClientTransportAfterStartTestBase,
                            public testing::WithParamInterface<uint8_t> {
 public:
  ~QuicProcessDataTest() override = default;

  void start() override {
    // force the server to declare that the version negotiated was invalid.;
    mockClientHandshake->negotiatedVersion = QuicVersion::QUIC_V1;
    client->setSupportedVersions({QuicVersion::QUIC_V1});
    client->start(&clientConnSetupCallback, &clientConnCallback);
    setConnectionIds();
  }
};

INSTANTIATE_TEST_SUITE_P(
    QuicClientZeroLenConnIds,
    QuicProcessDataTest,
    ::Values(0, 8));

TEST_F(QuicProcessDataTest, ProcessDataWithGarbageAtEnd) {
  expectQuicStatsPacketDrop(PacketDropReason::PARSE_ERROR_CLIENT);
  auto qLogger = std::make_shared<FileQLogger>(VantagePoint::Client);
  client->getNonConstConn().qLogger = qLogger;
  auto params = mockClientHandshake->getServerTransportParams();
  params->parameters.push_back(encodeConnIdParameter(
      TransportParameterId::initial_source_connection_id, *serverChosenConnId));
  params->parameters.push_back(encodeConnIdParameter(
      TransportParameterId::original_destination_connection_id,
      *client->getConn().initialDestinationConnectionId));
  mockClientHandshake->setServerTransportParams(std::move(*params));
  auto serverHello = IOBuf::copyBuffer("Fake SHLO");
  ChainedByteRangeHead serverHelloRch(serverHello);
  PacketNum nextPacketNum = initialPacketNum++;
  auto& aead = getInitialCipher();
  auto packet = createCryptoPacket(
      *serverChosenConnId,
      *originalConnId,
      nextPacketNum,
      QuicVersion::QUIC_V1,
      ProtectionType::Initial,
      serverHelloRch,
      aead,
      0 /* largestAcked */);
  auto packetData = packetToBufCleartext(
      packet, aead, getInitialHeaderCipher(), nextPacketNum);
  packetData->appendToChain(IOBuf::copyBuffer("garbage in"));
  deliverData(serverAddr, packetData->coalesce());
  verifyTransportParameters(
      kDefaultConnectionFlowControlWindow,
      kDefaultStreamFlowControlWindow,
      kDefaultIdleTimeout,
      kDefaultAckDelayExponent,
      mockClientHandshake->maxRecvPacketSize);
  std::vector<int> indices =
      getQLogEventIndices(QLogEventType::PacketDrop, qLogger);
  EXPECT_EQ(indices.size(), 1);
  auto tmp = std::move(qLogger->logs[indices[0]]);
  auto event = dynamic_cast<QLogPacketDropEvent*>(tmp.get());
  EXPECT_EQ(event->packetSize, 10);
  EXPECT_EQ(event->dropReason, kParse);
}

TEST_F(QuicProcessDataTest, ProcessPendingData) {
  auto params = mockClientHandshake->getServerTransportParams();
  params->parameters.push_back(encodeConnIdParameter(
      TransportParameterId::initial_source_connection_id, *serverChosenConnId));
  params->parameters.push_back(encodeConnIdParameter(
      TransportParameterId::original_destination_connection_id,
      *client->getConn().initialDestinationConnectionId));
  mockClientHandshake->setServerTransportParams(std::move(*params));
  auto serverHello = IOBuf::copyBuffer("Fake SHLO");
  ChainedByteRangeHead serverHelloRch(serverHello);
  PacketNum nextPacketNum = initialPacketNum++;
  auto& aead = getInitialCipher();
  auto packet = createCryptoPacket(
      *serverChosenConnId,
      *originalConnId,
      nextPacketNum,
      QuicVersion::QUIC_V1,
      ProtectionType::Initial,
      serverHelloRch,
      aead,
      0 /* largestAcked */);
  auto packetData = packetToBufCleartext(
      packet, aead, getInitialHeaderCipher(), nextPacketNum);
  deliverData(serverAddr, packetData->coalesce());
  verifyTransportParameters(
      kDefaultConnectionFlowControlWindow,
      kDefaultStreamFlowControlWindow,
      kDefaultIdleTimeout,
      kDefaultAckDelayExponent,
      mockClientHandshake->maxRecvPacketSize);

  mockClientHandshake->setOneRttReadCipher(nullptr);
  mockClientHandshake->setHandshakeReadCipher(nullptr);
  ASSERT_TRUE(client->getConn().pendingOneRttData.empty());
  auto streamId1 = client->createBidirectionalStream().value();

  auto data = folly::IOBuf::copyBuffer("1RTT data!");
  auto streamPacket1 = packetToBuf(createStreamPacket(
      *serverChosenConnId /* src */,
      *originalConnId /* dest */,
      appDataPacketNum++,
      streamId1,
      *data,
      0 /* cipherOverhead */,
      0 /* largestAcked */));
  deliverData(streamPacket1->coalesce());
  EXPECT_EQ(client->getConn().pendingOneRttData.size(), 1);

  auto cryptoData = folly::IOBuf::copyBuffer("Crypto data!");
  ChainedByteRangeHead cryptoDataRch(cryptoData);
  auto cryptoPacket1 = packetToBuf(createCryptoPacket(
      *serverChosenConnId,
      *originalConnId,
      handshakePacketNum++,
      QuicVersion::QUIC_V1,
      ProtectionType::Handshake,
      cryptoDataRch,
      *createNoOpAead(),
      0 /* largestAcked */));
  deliverData(cryptoPacket1->coalesce());
  EXPECT_EQ(client->getConn().pendingOneRttData.size(), 1);
  EXPECT_EQ(client->getConn().pendingHandshakeData.size(), 1);

  mockClientHandshake->setOneRttReadCipher(createNoOpAead());
  auto streamId2 = client->createBidirectionalStream().value();
  auto streamPacket2 = packetToBuf(createStreamPacket(
      *serverChosenConnId /* src */,
      *originalConnId /* dest */,
      appDataPacketNum++,
      streamId2,
      *data,
      0 /* cipherOverhead */,
      0 /* largestAcked */));
  deliverData(streamPacket2->coalesce());
  EXPECT_TRUE(client->getConn().pendingOneRttData.empty());
  EXPECT_EQ(client->getConn().pendingHandshakeData.size(), 1);

  // Set the oneRtt one back to nullptr to make sure we trigger it on handshake
  // only.
  // mockClientHandshake->setOneRttReadCipher(nullptr);
  mockClientHandshake->setHandshakeReadCipher(createNoOpAead());
  auto cryptoPacket2 = packetToBuf(createCryptoPacket(
      *serverChosenConnId,
      *originalConnId,
      handshakePacketNum++,
      QuicVersion::QUIC_V1,
      ProtectionType::Handshake,
      cryptoDataRch,
      *createNoOpAead(),
      0,
      cryptoData->length()));
  deliverData(cryptoPacket2->coalesce());
  EXPECT_TRUE(client->getConn().pendingHandshakeData.empty());
  EXPECT_TRUE(client->getConn().pendingOneRttData.empty());

  // Both stream data and crypto data should be there.
  auto d1 = client->read(streamId1, 1000);
  ASSERT_FALSE(d1.hasError());
  auto d2 = client->read(streamId2, 1000);
  ASSERT_FALSE(d2.hasError());
  EXPECT_TRUE(folly::IOBufEqualTo()(*d1.value().first, *data));
  EXPECT_TRUE(folly::IOBufEqualTo()(*d2.value().first, *data));

  ASSERT_FALSE(
      mockClientHandshake->readBuffers[EncryptionLevel::Handshake].empty());
  auto handshakeReadData =
      mockClientHandshake->readBuffers[EncryptionLevel::Handshake].move();
  cryptoData->appendToChain(cryptoData->clone());
  EXPECT_TRUE(folly::IOBufEqualTo()(*cryptoData, *handshakeReadData));
}

TEST_F(QuicProcessDataTest, ProcessPendingDataBufferLimit) {
  auto params = mockClientHandshake->getServerTransportParams();
  params->parameters.push_back(encodeConnIdParameter(
      TransportParameterId::initial_source_connection_id, *serverChosenConnId));
  params->parameters.push_back(encodeConnIdParameter(
      TransportParameterId::original_destination_connection_id,
      *client->getConn().initialDestinationConnectionId));
  mockClientHandshake->setServerTransportParams(std::move(*params));
  auto serverHello = IOBuf::copyBuffer("Fake SHLO");
  ChainedByteRangeHead serverHelloRch(serverHello);
  PacketNum nextPacketNum = initialPacketNum++;
  auto& aead = getInitialCipher();
  auto packet = createCryptoPacket(
      *serverChosenConnId,
      *originalConnId,
      nextPacketNum,
      QuicVersion::QUIC_V1,
      ProtectionType::Initial,
      serverHelloRch,
      aead,
      0 /* largestAcked */);
  auto packetData = packetToBufCleartext(
      packet, aead, getInitialHeaderCipher(), nextPacketNum);
  deliverData(serverAddr, packetData->coalesce());
  verifyTransportParameters(
      kDefaultConnectionFlowControlWindow,
      kDefaultStreamFlowControlWindow,
      kDefaultIdleTimeout,
      kDefaultAckDelayExponent,
      mockClientHandshake->maxRecvPacketSize);

  client->getNonConstConn().transportSettings.maxPacketsToBuffer = 2;
  auto data = folly::IOBuf::copyBuffer("1RTT data!");
  mockClientHandshake->setOneRttReadCipher(nullptr);
  ASSERT_TRUE(client->getConn().pendingOneRttData.empty());
  auto streamId1 = client->createBidirectionalStream().value();
  auto streamPacket1 = packetToBuf(createStreamPacket(
      *serverChosenConnId /* src */,
      *originalConnId /* dest */,
      appDataPacketNum++,
      streamId1,
      *data,
      0 /* cipherOverhead */,
      0 /* largestAcked */));
  deliverData(streamPacket1->coalesce());
  EXPECT_EQ(client->getConn().pendingOneRttData.size(), 1);

  auto streamId2 = client->createBidirectionalStream().value();
  auto streamPacket2 = packetToBuf(createStreamPacket(
      *serverChosenConnId /* src */,
      *originalConnId /* dest */,
      appDataPacketNum++,
      streamId2,
      *data,
      0 /* cipherOverhead */,
      0 /* largestAcked */));
  deliverData(streamPacket2->coalesce());
  EXPECT_EQ(client->getConn().pendingOneRttData.size(), 2);

  auto streamId3 = client->createBidirectionalStream().value();
  auto streamPacket3 = packetToBuf(createStreamPacket(
      *serverChosenConnId /* src */,
      *originalConnId /* dest */,
      appDataPacketNum++,
      streamId3,
      *data,
      0 /* cipherOverhead */,
      0 /* largestAcked */));
  deliverData(streamPacket3->coalesce());
  EXPECT_EQ(client->getConn().pendingOneRttData.size(), 2);

  mockClientHandshake->setOneRttReadCipher(createNoOpAead());
  auto streamId4 = client->createBidirectionalStream().value();
  auto streamPacket4 = packetToBuf(createStreamPacket(
      *serverChosenConnId /* src */,
      *originalConnId /* dest */,
      appDataPacketNum++,
      streamId4,
      *data,
      0 /* cipherOverhead */,
      0 /* largestAcked */));
  deliverData(streamPacket4->coalesce());
  EXPECT_TRUE(client->getConn().pendingOneRttData.empty());

  // First, second, and fourht stream data should be there.
  auto d1 = client->read(streamId1, 1000);
  ASSERT_FALSE(d1.hasError());
  auto d2 = client->read(streamId2, 1000);
  ASSERT_FALSE(d2.hasError());
  auto d3 = client->read(streamId3, 1000);
  ASSERT_FALSE(d3.hasError());
  EXPECT_EQ(d3.value().first, nullptr);
  auto d4 = client->read(streamId4, 1000);
  ASSERT_FALSE(d4.hasError());
  EXPECT_TRUE(folly::IOBufEqualTo()(*d1.value().first, *data));
  EXPECT_TRUE(folly::IOBufEqualTo()(*d2.value().first, *data));
  EXPECT_TRUE(folly::IOBufEqualTo()(*d4.value().first, *data));
}

TEST_P(QuicProcessDataTest, ProcessDataHeaderOnly) {
  uint8_t connIdSize = GetParam();
  client->getNonConstConn().clientConnectionId =
      ConnectionId::createAndMaybeCrash(std::vector<uint8_t>(connIdSize, 1));
  setConnectionIds();

  auto qLogger = std::make_shared<FileQLogger>(VantagePoint::Client);
  client->getNonConstConn().qLogger = qLogger;
  auto serverHello = IOBuf::copyBuffer("Fake SHLO");
  ChainedByteRangeHead serverHelloRch(serverHello);
  PacketNum nextPacketNum = initialPacketNum++;
  auto& aead = getInitialCipher();
  auto largestRecvdPacketNum =
      getAckState(client->getConn(), PacketNumberSpace::Handshake)
          .largestRecvdPacketNum;
  auto packet = createCryptoPacket(
      *serverChosenConnId,
      *originalConnId,
      nextPacketNum,
      QuicVersion::QUIC_V1,
      ProtectionType::Initial,
      serverHelloRch,
      aead,
      0 /* largestAcked */);

  deliverData(serverAddr, packet.header.coalesce());
  EXPECT_EQ(
      getAckState(client->getConn(), PacketNumberSpace::Handshake)
          .largestRecvdPacketNum,
      largestRecvdPacketNum);

  std::vector<int> indices =
      getQLogEventIndices(QLogEventType::DatagramReceived, qLogger);
  EXPECT_EQ(indices.size(), 1);
  auto tmp = std::move(qLogger->logs[indices[0]]);
  auto event = dynamic_cast<QLogDatagramReceivedEvent*>(tmp.get());
  EXPECT_EQ(event->dataLen, 18 + connIdSize);
}

TEST(AsyncUDPSocketTest, CloseMultipleTimes) {
  class EmptyReadCallback : public QuicAsyncUDPSocket::ReadCallback {
   public:
    void getReadBuffer(void**, size_t*) noexcept override {}

    void onDataAvailable(
        const folly::SocketAddress&,
        size_t,
        bool,
        OnDataAvailableParams) noexcept override {}

    void onReadError(const AsyncSocketException&) noexcept override {}

    void onReadClosed() noexcept override {}

    bool shouldOnlyNotify() override {
      return true;
    }

    void onNotifyDataAvailable(QuicAsyncUDPSocket&) noexcept override {}
  };

  class EmptyErrMessageCallback
      : public QuicAsyncUDPSocket::ErrMessageCallback {
   public:
    void errMessage(const cmsghdr&) noexcept override {}

    void errMessageError(const AsyncSocketException&) noexcept override {}
  };

  EventBase evb;
  auto qEvb = std::make_shared<FollyQuicEventBase>(&evb);
  FollyQuicAsyncUDPSocket socket(qEvb);
  TransportSettings transportSettings;
  EmptyErrMessageCallback errMessageCallback;
  EmptyReadCallback readCallback;
  ASSERT_FALSE(happyEyeballsSetUpSocket(
                   socket,
                   std::nullopt,
                   folly::SocketAddress("127.0.0.1", 12345),
                   transportSettings,
                   0, // tosValue
                   &errMessageCallback,
                   &readCallback,
                   folly::emptySocketOptionMap)
                   .hasError());

  socket.pauseRead();
  ASSERT_TRUE(socket.close().has_value());
  socket.pauseRead();
  ASSERT_TRUE(socket.close().has_value());
}
} // namespace quic::test
