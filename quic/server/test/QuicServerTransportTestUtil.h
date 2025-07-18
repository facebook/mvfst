/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#pragma once

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <quic/api/QuicTransportFunctions.h>
#include <quic/api/test/Mocks.h>
#include <quic/codec/DefaultConnectionIdAlgo.h>
#include <quic/codec/Types.h>
#include <quic/common/TransportKnobs.h>
#include <quic/common/events/FollyQuicEventBase.h>
#include <quic/common/test/TestUtils.h>
#include <quic/common/testutil/MockAsyncUDPSocket.h>
#include <quic/common/udpsocket/FollyQuicAsyncUDPSocket.h>
#include <quic/congestion_control/ServerCongestionControllerFactory.h>
#include <quic/fizz/server/handshake/FizzServerQuicHandshakeContext.h>
#include <quic/server/QuicServerTransport.h>
#include <quic/server/test/Mocks.h>
#include <quic/state/test/MockQuicStats.h>
#include <utility>

namespace quic::test {

class TestingQuicServerTransport : public QuicServerTransport {
 public:
  TestingQuicServerTransport(
      std::shared_ptr<FollyQuicEventBase> evb,
      std::unique_ptr<FollyQuicAsyncUDPSocket> sock,
      ConnectionSetupCallback* connSetupCb,
      ConnectionCallback* connCb,
      std::shared_ptr<const fizz::server::FizzServerContext> ctx)
      : QuicTransportBaseLite(evb, std::move(sock)),
        QuicServerTransport(
            evb,
            nullptr /* Initialized through the QuicTransportBaseLite constructor
                     */
            ,
            connSetupCb,
            connCb,
            std::move(ctx)) {}

  QuicTransportBase* getTransport() {
    return this;
  }

  QuicConnectionStateBase& getConnectionState() {
    return *conn_;
  }

  const QuicServerConnectionState& getConn() const {
    return *dynamic_cast<QuicServerConnectionState*>(conn_.get());
  }

  QuicServerConnectionState& getNonConstConn() {
    return *dynamic_cast<QuicServerConnectionState*>(conn_.get());
  }

  QuicAsyncUDPSocket& getSocket() {
    return *socket_.get();
  }

  auto& idleTimeout() {
    return idleTimeout_;
  }

  auto& keepaliveTimeout() {
    return keepaliveTimeout_;
  }

  auto& drainTimeout() {
    return drainTimeout_;
  }

  auto& ackTimeout() {
    return ackTimeout_;
  }

  auto& lossTimeout() {
    return lossTimeout_;
  }

  auto& pathValidationTimeout() {
    return pathValidationTimeout_;
  }

  bool isClosed() {
    return closeState_ == CloseState::CLOSED;
  }

  bool isDraining() {
    return drainTimeout_.isTimerCallbackScheduled();
  }

  void triggerCryptoEvent() {
    onCryptoEventAvailable();
  }

  auto& writeLooper() {
    return writeLooper_;
  }

  auto& readLooper() {
    return readLooper_;
  }

  void registerKnobParamHandler(
      uint64_t paramId,
      std::function<quic::Expected<void, QuicError>(
          QuicServerTransport*,
          TransportKnobParam::Val)>&& handler) {
    registerTransportKnobParamHandler(paramId, std::move(handler));
  }

  void handleKnobParams(const TransportKnobParams& params) {
    handleTransportKnobParams(params);
  }

  void triggerKnobCallbacks() {
    handleKnobCallbacks();
  }
};

class QuicServerTransportTestBase : public virtual testing::Test {
 public:
  QuicServerTransportTestBase() {
    qEvb_ = std::make_shared<FollyQuicEventBase>(&evb);
  }

  virtual ~QuicServerTransportTestBase() = default;

  void SetUp() {
    clientAddr = folly::SocketAddress("127.0.0.1", 1000);
    serverAddr = folly::SocketAddress("1.2.3.4", 8080);
    clientConnectionId = getTestConnectionId();
    initialDestinationConnectionId = clientConnectionId;
    // change the initialDestinationConnectionId to be different
    // to suss out bugs.
    initialDestinationConnectionId->data()[0] ^= 0x1;
    // set server chosen connId with processId = 0 and workerId = 1
    ServerConnectionIdParams params(0, 0, 1);
    auto sock =
        std::make_unique<testing::NiceMock<quic::test::MockAsyncUDPSocket>>(
            qEvb_);
    socket = sock.get();
    EXPECT_CALL(*sock, write(testing::_, testing::_, testing::_))
        .WillRepeatedly(testing::Invoke([&](const folly::SocketAddress&,
                                            const struct iovec* vec,
                                            size_t iovec_len) {
          serverWrites.push_back(
              copyChain(folly::IOBuf::wrapIov(vec, iovec_len)));
          return getTotalIovecLen(vec, iovec_len);
        }));
    ON_CALL(*sock, address()).WillByDefault(testing::Return(serverAddr));
    ON_CALL(*sock, setAdditionalCmsgsFunc(testing::_))
        .WillByDefault(testing::Return(quic::Expected<void, QuicError>{}));
    ON_CALL(*sock, getGSO).WillByDefault(testing::Return(0));
    ON_CALL(*sock, getGRO).WillByDefault(testing::Return(0));
    ON_CALL(*sock, init(testing::_))
        .WillByDefault(testing::Return(quic::Expected<void, QuicError>{}));
    ON_CALL(*sock, bind(testing::_))
        .WillByDefault(testing::Return(quic::Expected<void, QuicError>{}));
    ON_CALL(*sock, connect(testing::_))
        .WillByDefault(testing::Return(quic::Expected<void, QuicError>{}));
    ON_CALL(*sock, close())
        .WillByDefault(testing::Return(quic::Expected<void, QuicError>{}));
    ON_CALL(*sock, resumeWrite(testing::_))
        .WillByDefault(testing::Return(quic::Expected<void, QuicError>{}));
    ON_CALL(*sock, setGRO(testing::_))
        .WillByDefault(testing::Return(quic::Expected<void, QuicError>{}));
    ON_CALL(*sock, setRecvTos(testing::_))
        .WillByDefault(testing::Return(quic::Expected<void, QuicError>{}));
    ON_CALL(*sock, getRecvTos()).WillByDefault(testing::Return(false));
    ON_CALL(*sock, setTosOrTrafficClass(testing::_))
        .WillByDefault(testing::Return(quic::Expected<void, QuicError>{}));
    ON_CALL(*sock, setCmsgs(testing::_))
        .WillByDefault(testing::Return(quic::Expected<void, QuicError>{}));
    ON_CALL(*sock, appendCmsgs(testing::_))
        .WillByDefault(testing::Return(quic::Expected<void, QuicError>{}));
    ON_CALL(*sock, getTimestamping()).WillByDefault(testing::Return(0));
    ON_CALL(*sock, setReuseAddr(testing::_))
        .WillByDefault(testing::Return(quic::Expected<void, QuicError>{}));
    ON_CALL(*sock, setDFAndTurnOffPMTU())
        .WillByDefault(testing::Return(quic::Expected<void, QuicError>{}));
    ON_CALL(*sock, setErrMessageCallback(testing::_))
        .WillByDefault(testing::Return(quic::Expected<void, QuicError>{}));
    ON_CALL(*sock, applyOptions(testing::_, testing::_))
        .WillByDefault(testing::Return(quic::Expected<void, QuicError>{}));
    ON_CALL(*sock, setReusePort(testing::_))
        .WillByDefault(testing::Return(quic::Expected<void, QuicError>{}));
    ON_CALL(*sock, setRcvBuf(testing::_))
        .WillByDefault(testing::Return(quic::Expected<void, QuicError>{}));
    ON_CALL(*sock, setSndBuf(testing::_))
        .WillByDefault(testing::Return(quic::Expected<void, QuicError>{}));
    ON_CALL(*sock, setFD(testing::_, testing::_))
        .WillByDefault(testing::Return(quic::Expected<void, QuicError>{}));
    supportedVersions = {QuicVersion::MVFST};
    serverCtx = createServerCtx();
    connIdAlgo_ = std::make_unique<DefaultConnectionIdAlgo>();
    ccFactory_ = std::make_shared<ServerCongestionControllerFactory>();
    server = std::make_shared<TestingQuicServerTransport>(
        qEvb_, std::move(sock), &connSetupCallback, &connCallback, serverCtx);
    server->setCongestionControllerFactory(ccFactory_);
    server->setCongestionControl(CongestionControlType::Cubic);
    server->setRoutingCallback(&routingCallback);
    server->setHandshakeFinishedCallback(&handshakeFinishedCallback);
    server->setSupportedVersions(supportedVersions);
    server->setOriginalPeerAddress(clientAddr);
    server->setServerConnectionIdParams(params);
    server->getNonConstConn().transportSettings.statelessResetTokenSecret =
        getRandSecret();
    quicStats_ = std::make_unique<testing::NiceMock<MockQuicStats>>();
    server->setTransportStatsCallback(quicStats_.get());
    initializeServerHandshake();
    server->getNonConstConn().handshakeLayer.reset(fakeHandshake);
    server->getNonConstConn().serverHandshakeLayer = fakeHandshake;
    // Allow ignoring path mtu for testing negotiation.
    server->getNonConstConn().transportSettings.canIgnorePathMTU =
        getCanIgnorePathMTU();
    server->getNonConstConn().transportSettings.disableMigration =
        getDisableMigration();
    server->getNonConstConn().transportSettings.enableKeepalive = true;
    server->setConnectionIdAlgo(connIdAlgo_.get());
    server->setClientConnectionId(*clientConnectionId);
    server->setClientChosenDestConnectionId(*initialDestinationConnectionId);
    VLOG(20) << __func__ << " client connId=" << clientConnectionId->hex()
             << ", server connId="
             << (server->getConn().serverConnectionId
                     ? server->getConn().serverConnectionId->hex()
                     : " (n/a)");
    SetUpChild();
  }

  virtual void SetUpChild() {}

  void startTransport() {
    server->accept();
    setupConnection();
    EXPECT_TRUE(server->idleTimeout().isTimerCallbackScheduled());
    EXPECT_EQ(server->getConn().peerConnectionIds.size(), 1);
    EXPECT_EQ(
        *server->getConn().clientConnectionId,
        server->getConn().peerConnectionIds[0].connId);
  }

  void destroyTransport() {
    server = nullptr;
  }

  QuicTransportBase* getTransport() {
    return server->getTransport();
  }

  std::shared_ptr<TestingQuicServerTransport> getTestTransport() {
    return server;
  }

  const QuicServerConnectionState& getConn() const {
    return server->getConn();
  }

  QuicServerConnectionState& getNonConstConn() {
    return server->getNonConstConn();
  }

  MockConnectionSetupCallback& getConnSetupCallback() {
    return connSetupCallback;
  }

  MockConnectionCallback& getConnCallback() {
    return connCallback;
  }

  std::shared_ptr<FizzServerQuicHandshakeContext> getFizzServerContext() {
    if (!fizzServerContext) {
      fizzServerContext = FizzServerQuicHandshakeContext::Builder()
                              .setFizzServerContext(createServerCtx())
                              .build();
    }

    return fizzServerContext;
  }

  virtual void initializeServerHandshake() {
    fakeHandshake = new FakeServerHandshake(
        server->getNonConstConn(), getFizzServerContext());
    ON_CALL(*fakeHandshake, writeNewSessionTicket)
        .WillByDefault(testing::Return(quic::Expected<void, QuicError>{}));
  }

  virtual bool getDisableMigration() {
    return true;
  }

  virtual bool getCanIgnorePathMTU() {
    return true;
  }

  std::unique_ptr<Aead> getInitialCipher(
      QuicVersion version = QuicVersion::MVFST) {
    FizzCryptoFactory cryptoFactory;
    return cryptoFactory
        .getClientInitialCipher(*initialDestinationConnectionId, version)
        .value();
  }

  std::unique_ptr<PacketNumberCipher> getInitialHeaderCipher(
      QuicVersion version = QuicVersion::MVFST) {
    FizzCryptoFactory cryptoFactory;
    return cryptoFactory
        .makeClientInitialHeaderCipher(*initialDestinationConnectionId, version)
        .value();
  }

  BufPtr recvEncryptedStream(
      StreamId streamId,
      folly::IOBuf& data,
      uint64_t offset = 0,
      bool eof = false) {
    PacketNum packetNum = clientNextAppDataPacketNum++;
    auto packetData = packetToBuf(createStreamPacket(
        clientConnectionId.value_or(getTestConnectionId()),
        *server->getConn().serverConnectionId,
        packetNum,
        streamId,
        data,
        0 /* cipherOverhead */,
        0 /* largestAcked */,
        std::nullopt /* longHeaderOverride */,
        eof,
        std::nullopt,
        offset));
    deliverData(packetData->clone());
    return packetData;
  }

  void recvClientHello(
      bool writes = true,
      QuicVersion version = QuicVersion::MVFST,
      const std::string& msg = "CHLO") {
    auto chlo = folly::IOBuf::copyBuffer(msg);
    auto nextPacketNum = clientNextInitialPacketNum++;
    auto aead = getInitialCipher(version);
    auto headerCipher = getInitialHeaderCipher(version);
    ChainedByteRangeHead chloRch(chlo);
    auto initialPacket = packetToBufCleartext(
        createInitialCryptoPacket(
            *clientConnectionId,
            *initialDestinationConnectionId,
            nextPacketNum,
            version,
            chloRch,
            *aead,
            0 /* largestAcked */),
        *aead,
        *headerCipher,
        nextPacketNum);
    deliverData(initialPacket->clone(), writes);
  }

  void recvClientFinished(
      bool writes = true,
      folly::SocketAddress* peerAddress = nullptr,
      QuicVersion version = QuicVersion::MVFST) {
    auto finished = folly::IOBuf::copyBuffer("FINISHED");
    auto nextPacketNum = clientNextHandshakePacketNum++;
    auto headerCipher = test::createNoOpHeaderCipher().value();
    uint64_t offset =
        getCryptoStream(
            *server->getConn().cryptoState, EncryptionLevel::Handshake)
            ->currentReadOffset;
    auto handshakeCipher = test::createNoOpAead();
    ChainedByteRangeHead finishedRch(finished);
    auto finishedPacket = packetToBufCleartext(
        createCryptoPacket(
            *clientConnectionId,
            *server->getConn().serverConnectionId,
            nextPacketNum,
            version,
            ProtectionType::Handshake,
            finishedRch,
            *handshakeCipher,
            0 /* largestAcked */,
            offset),
        *handshakeCipher,
        *headerCipher,
        nextPacketNum);
    deliverData(finishedPacket->clone(), writes, peerAddress);
  }

  virtual void setupClientReadCodec() {
    FizzCryptoFactory cryptoFactory;
    clientReadCodec = std::make_unique<QuicReadCodec>(QuicNodeType::Client);
    clientReadCodec->setClientConnectionId(*clientConnectionId);
    clientReadCodec->setInitialReadCipher(
        cryptoFactory
            .getServerInitialCipher(
                *initialDestinationConnectionId, QuicVersion::MVFST)
            .value());
    clientReadCodec->setInitialHeaderCipher(
        cryptoFactory
            .makeServerInitialHeaderCipher(
                *initialDestinationConnectionId, QuicVersion::MVFST)
            .value());
    clientReadCodec->setCodecParameters(
        CodecParameters(kDefaultAckDelayExponent, QuicVersion::MVFST));
  }

  virtual void expectWriteNewSessionTicket() {
    server->setEarlyDataAppParamsFunctions(
        [](const Optional<std::string>&, const BufPtr&) { return false; },
        []() -> BufPtr { return nullptr; });
    EXPECT_CALL(*getFakeHandshakeLayer(), writeNewSessionTicket(testing::_))
        .Times(1);
  }

  virtual void setupConnection() {
    EXPECT_EQ(server->getConn().readCodec, nullptr);
    EXPECT_EQ(server->getConn().statsCallback, quicStats_.get());
    // None of these connections should cause the server to get WritableBytes
    // limited.
    EXPECT_CALL(*quicStats_, onConnectionWritableBytesLimited()).Times(0);
    // Not all connections are successful, in which case we don't call
    // onConnectionClose. The best we can test here is that onConnectionClose
    // doesn't get invoked more than once
    EXPECT_CALL(*quicStats_, onConnectionClose(testing::_))
        .Times(testing::AtMost(1));
    setupClientReadCodec();
    recvClientHello();

    folly::IOBufEqualTo eq;
    EXPECT_TRUE(eq(getCryptoStreamData(), folly::IOBuf::copyBuffer("SHLO")));
    serverWrites.clear();

    EXPECT_NE(server->getConn().readCodec, nullptr);
    EXPECT_NE(server->getConn().initialWriteCipher, nullptr);
    EXPECT_NE(server->getConn().initialHeaderCipher, nullptr);
    EXPECT_NE(server->getConn().handshakeWriteCipher, nullptr);
    EXPECT_NE(server->getConn().handshakeWriteHeaderCipher, nullptr);
    EXPECT_NE(server->getConn().readCodec->getHandshakeHeaderCipher(), nullptr);

    EXPECT_FALSE(server->getConn().localConnectionError.has_value());
    EXPECT_EQ(server->getConn().version, QuicVersion::MVFST);
    EXPECT_EQ(server->getConn().serverConnIdParams->processId, 0);
    EXPECT_EQ(server->getConn().serverConnIdParams->workerId, 1);
    EXPECT_TRUE(server->getConn().serverConnectionId.has_value());
    EXPECT_EQ(server->getConn().selfConnectionIds.size(), 1);
    serverConnectionId = *server->getConn().serverConnectionId;
    EXPECT_EQ(
        server->getConn().selfConnectionIds[0].connId, serverConnectionId);
    // the crypto data should have been written in the previous loop, verify
    // that the write loop callback is not scheduled any more since we don't
    // have keys to write acks. This assumes that we will schedule crypto data
    // as soon as we can.
    EXPECT_FALSE(server->writeLooper()->isLoopCallbackScheduled());
    EXPECT_FALSE(server->readLooper()->isLoopCallbackScheduled());

    expectWriteNewSessionTicket();
    // Once oneRtt keys are available, ServerTransport must call the
    // onConnectionIdBound on its 'routingCallback'
    EXPECT_CALL(routingCallback, onConnectionIdBound(testing::_))
        .WillOnce(
            testing::Invoke([&, clientAddr_2 = clientAddr](auto transport) {
              EXPECT_EQ(clientAddr_2, transport->getOriginalPeerAddress());
            }));

    EXPECT_TRUE(server->getConn().pendingEvents.frames.empty());
    EXPECT_EQ(server->getConn().nextSelfConnectionIdSequence, 1);
    EXPECT_CALL(connSetupCallback, onFullHandshakeDone()).Times(1);
    recvClientFinished();

    // We need an extra pump here for some reason.
    loopForWrites();

    // Issue (kMinNumAvailableConnIds - 1) more connection ids on handshake
    // complete
    auto numNewConnIdFrames = 0;
    for (const auto& packet : server->getConn().outstandings.packets) {
      for (const auto& frame : packet.packet.frames) {
        switch (frame.type()) {
          case QuicWriteFrame::Type::QuicSimpleFrame: {
            const auto writeFrame = frame.asQuicSimpleFrame();
            if (writeFrame->type() ==
                QuicSimpleFrame::Type::NewConnectionIdFrame) {
              ++numNewConnIdFrames;
            }
            break;
          }
          default:
            break;
        }
      }
    }
    uint64_t connIdsToIssue =
        maximumConnectionIdsToIssue(server->getConn()) - 1;

    if (server->getConn().transportSettings.disableMigration ||
        (connIdsToIssue == 0)) {
      EXPECT_EQ(numNewConnIdFrames, 0);
      EXPECT_EQ(server->getConn().nextSelfConnectionIdSequence, 1);
    } else {
      EXPECT_EQ(numNewConnIdFrames, connIdsToIssue);
      EXPECT_EQ(
          server->getConn().nextSelfConnectionIdSequence, connIdsToIssue + 1);
    }

    EXPECT_NE(server->getConn().readCodec, nullptr);
    EXPECT_NE(server->getConn().oneRttWriteCipher, nullptr);
    EXPECT_NE(server->getConn().oneRttWriteHeaderCipher, nullptr);
    EXPECT_NE(server->getConn().readCodec->getOneRttHeaderCipher(), nullptr);

    EXPECT_TRUE(getCryptoStream(
                    *server->getConn().cryptoState, EncryptionLevel::Initial)
                    ->readBuffer.empty());
    EXPECT_FALSE(server->getConn().localConnectionError.has_value());
    verifyTransportParameters(kDefaultIdleTimeout);
    serverWrites.clear();

    auto& cryptoState = server->getConn().cryptoState;
    EXPECT_EQ(cryptoState->handshakeStream.retransmissionBuffer.size(), 0);
    EXPECT_EQ(cryptoState->oneRttStream.retransmissionBuffer.size(), 0);
  }

  void verifyTransportParameters(std::chrono::milliseconds idleTimeout) {
    EXPECT_EQ(server->getConn().peerIdleTimeout, idleTimeout);
    if (getCanIgnorePathMTU()) {
      EXPECT_EQ(
          server->getConn().udpSendPacketLen, fakeHandshake->maxRecvPacketSize);
    }
  }

  void deliverDataWithoutErrorCheck(
      NetworkData&& data,
      bool writes = true,
      folly::SocketAddress* peer = nullptr) {
    server->onNetworkData(
        peer == nullptr ? clientAddr : *peer, std::move(data));
    if (writes) {
      loopForWrites();
    }
  }

  void deliverDataWithoutErrorCheck(
      BufPtr data,
      bool writes = true,
      folly::SocketAddress* peer = nullptr) {
    data->coalesce();
    deliverDataWithoutErrorCheck(
        NetworkData(ReceivedUdpPacket(std::move(data))), writes, peer);
  }

  void deliverData(
      NetworkData&& data,
      bool writes = true,
      folly::SocketAddress* peer = nullptr) {
    deliverDataWithoutErrorCheck(std::move(data), writes, peer);
    if (server->getConn().localConnectionError) {
      bool idleTimeout = false;
      const LocalErrorCode* localError =
          server->getConn().localConnectionError->code.asLocalErrorCode();
      if (localError) {
        idleTimeout = (*localError == LocalErrorCode::IDLE_TIMEOUT);
      }
      if (!idleTimeout) {
        throw std::runtime_error(
            toString(server->getConn().localConnectionError->code));
      }
    }
  }

  void deliverData(
      BufPtr data,
      bool writes = true,
      folly::SocketAddress* peer = nullptr) {
    data->coalesce();
    deliverData(NetworkData(ReceivedUdpPacket(std::move(data))), writes, peer);
  }

  void loopForWrites() {
    evb.loopOnce(EVLOOP_NONBLOCK);
  }

  BufPtr getCryptoStreamData() {
    CHECK(!serverWrites.empty());
    auto cryptoBuf = folly::IOBuf::create(0);
    AckStates ackStates;
    for (auto& serverWrite : serverWrites) {
      auto packetQueue = bufToQueue(serverWrite->clone());
      auto result = clientReadCodec->parsePacket(packetQueue, ackStates);
      auto& parsedPacket = *result.regularPacket();
      for (auto& frame : parsedPacket.frames) {
        if (frame.type() != QuicFrame::Type::ReadCryptoFrame) {
          continue;
        }
        cryptoBuf->appendToChain(frame.asReadCryptoFrame()->data->clone());
      }
    }
    return cryptoBuf;
  }

  std::unique_ptr<QuicReadCodec> makeClientEncryptedCodec(
      bool handshakeCipher = false) {
    FizzCryptoFactory cryptoFactory;
    auto readCodec = std::make_unique<QuicReadCodec>(QuicNodeType::Client);
    readCodec->setOneRttReadCipher(test::createNoOpAead());
    readCodec->setOneRttHeaderCipher(test::createNoOpHeaderCipher().value());
    readCodec->setHandshakeReadCipher(test::createNoOpAead());
    readCodec->setHandshakeHeaderCipher(test::createNoOpHeaderCipher().value());
    readCodec->setClientConnectionId(*clientConnectionId);
    readCodec->setCodecParameters(
        CodecParameters(kDefaultAckDelayExponent, QuicVersion::MVFST));
    if (handshakeCipher) {
      readCodec->setInitialReadCipher(
          cryptoFactory
              .getServerInitialCipher(
                  *initialDestinationConnectionId, QuicVersion::MVFST)
              .value());
      readCodec->setInitialHeaderCipher(
          cryptoFactory
              .makeServerInitialHeaderCipher(
                  *initialDestinationConnectionId, QuicVersion::MVFST)
              .value());
    }
    return readCodec;
  }

  FakeServerHandshake* getFakeHandshakeLayer() {
    return CHECK_NOTNULL(dynamic_cast<FakeServerHandshake*>(
        server->getNonConstConn().handshakeLayer.get()));
  }

  void checkTransportStateUpdate(
      const std::shared_ptr<FileQLogger>& qLogger,
      const std::string& msg) {
    std::vector<int> indices =
        getQLogEventIndices(QLogEventType::TransportStateUpdate, qLogger);
    EXPECT_EQ(indices.size(), 1);
    auto tmp = std::move(qLogger->logs[indices[0]]);
    auto event = dynamic_cast<QLogTransportStateUpdateEvent*>(tmp.get());
    EXPECT_EQ(event->update, getPeerClose(msg));
  }

  folly::EventBase evb;
  std::shared_ptr<FollyQuicEventBase> qEvb_;
  folly::SocketAddress serverAddr;
  folly::SocketAddress clientAddr;
  testing::NiceMock<MockConnectionSetupCallback> connSetupCallback;
  testing::NiceMock<MockConnectionCallback> connCallback;
  testing::NiceMock<MockRoutingCallback> routingCallback;
  testing::NiceMock<MockHandshakeFinishedCallback> handshakeFinishedCallback;
  Optional<ConnectionId> clientConnectionId;
  Optional<ConnectionId> initialDestinationConnectionId;
  Optional<ConnectionId> serverConnectionId;
  std::unique_ptr<QuicReadCodec> clientReadCodec;
  std::vector<BufPtr> serverWrites;
  std::shared_ptr<fizz::server::FizzServerContext> serverCtx;

  std::vector<QuicVersion> supportedVersions;
  std::unique_ptr<MockQuicStats> quicStats_;
  std::unique_ptr<ConnectionIdAlgo> connIdAlgo_;
  std::shared_ptr<CongestionControllerFactory> ccFactory_;
  std::shared_ptr<TestingQuicServerTransport> server;
  quic::test::MockAsyncUDPSocket* socket;
  FakeServerHandshake* fakeHandshake{nullptr};
  std::shared_ptr<FizzServerQuicHandshakeContext> fizzServerContext;
  PacketNum clientNextInitialPacketNum{0}, clientNextHandshakePacketNum{0},
      clientNextAppDataPacketNum{0};
};

class QuicServerTransportAfterStartTestBase
    : public QuicServerTransportTestBase {
 public:
  void SetUpChild() override {
    startTransport();
  }
};

} // namespace quic::test
