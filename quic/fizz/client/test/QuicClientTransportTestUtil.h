/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#pragma once

#include <folly/portability/GMock.h>
#include <folly/portability/GTest.h>
#include <quic/api/QuicTransportBase.h>

#include <quic/api/test/Mocks.h>
#include <quic/client/QuicClientTransport.h>
#include <quic/codec/DefaultConnectionIdAlgo.h>
#include <quic/common/QuicAsyncUDPSocketWrapper.h>
#include <quic/common/QuicEventBase.h>
#include <quic/common/test/TestClientUtils.h>
#include <quic/common/test/TestUtils.h>
#include <quic/common/testutil/MockAsyncUDPSocket.h>
#include <quic/fizz/client/handshake/FizzClientHandshake.h>
#include <quic/fizz/client/handshake/FizzClientQuicHandshakeContext.h>
#include <quic/state/test/MockQuicStats.h>

#include <utility>

namespace quic::test {

class TestingQuicClientTransport : public QuicClientTransport {
 public:
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

  TestingQuicClientTransport(
      folly::EventBase* evb,
      std::unique_ptr<QuicAsyncUDPSocketWrapper> socket,
      std::shared_ptr<ClientHandshakeFactory> handshakeFactory,
      size_t connIdSize = kDefaultConnectionIdSize,
      bool useConnectionEndWithErrorCallback = false)
      : QuicClientTransport(
            evb,
            std::move(socket),
            std::move(handshakeFactory),
            connIdSize,
            useConnectionEndWithErrorCallback) {}

  ~TestingQuicClientTransport() override {
    if (destructionCallback_) {
      destructionCallback_->markDestroyed();
    }
  }

  QuicTransportBase* getTransport() {
    return this;
  }

  const QuicClientConnectionState& getConn() const {
    return *dynamic_cast<QuicClientConnectionState*>(conn_.get());
  }

  QuicClientConnectionState& getNonConstConn() {
    return *dynamic_cast<QuicClientConnectionState*>(conn_.get());
  }

  const auto& getReadCallbacks() const {
    return readCallbacks_;
  }

  const auto& getDeliveryCallbacks() const {
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
    return getNonConstConn().serverInitialParamsSet_;
  }

  auto& peerAdvertisedInitialMaxData() {
    return getConn().peerAdvertisedInitialMaxData;
  }

  auto& peerAdvertisedInitialMaxStreamDataBidiLocal() const {
    return getConn().peerAdvertisedInitialMaxStreamDataBidiLocal;
  }

  auto& peerAdvertisedInitialMaxStreamDataBidiRemote() const {
    return getConn().peerAdvertisedInitialMaxStreamDataBidiRemote;
  }

  auto& peerAdvertisedInitialMaxStreamDataUni() const {
    return getConn().peerAdvertisedInitialMaxStreamDataUni;
  }

  void setDestructionCallback(
      std::shared_ptr<DestructionCallback> destructionCallback) {
    destructionCallback_ = std::move(destructionCallback);
  }

  void invokeOnNotifyDataAvailable(QuicAsyncUDPSocketWrapper& sock) {
    onNotifyDataAvailable(sock);
  }

 private:
  std::shared_ptr<DestructionCallback> destructionCallback_;
};

// Simulates a simple 1rtt handshake without needing to get any handshake bytes
// from the server.
class FakeOneRttHandshakeLayer : public FizzClientHandshake {
 public:
  explicit FakeOneRttHandshakeLayer(
      QuicClientConnectionState* conn,
      std::shared_ptr<FizzClientQuicHandshakeContext> fizzContext)
      : FizzClientHandshake(
            conn,
            std::move(fizzContext),
            std::make_unique<FizzCryptoFactory>()) {}

  folly::Optional<CachedServerTransportParameters> connectImpl(
      folly::Optional<std::string> hostname) override {
    // Look up psk
    folly::Optional<QuicCachedPsk> quicCachedPsk = getPsk(hostname);

    folly::Optional<CachedServerTransportParameters> transportParams;
    if (quicCachedPsk) {
      transportParams = quicCachedPsk->transportParams;
    }

    getFizzState().sni() = hostname;

    connected_ = true;
    writeDataToQuicStream(
        getClientConn()->cryptoState->initialStream,
        folly::IOBuf::copyBuffer("CHLO"));
    createServerTransportParameters();
    return transportParams;
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
    StatelessResetToken testStatelessResetToken = generateStatelessResetToken();
    TransportParameter statelessReset;
    statelessReset.parameter = TransportParameterId::stateless_reset_token;
    statelessReset.value = folly::IOBuf::copyBuffer(testStatelessResetToken);
    parameters.push_back(std::move(statelessReset));

    params.parameters = std::move(parameters);
    params_ = std::move(params);
  }

  void setServerTransportParams(ServerTransportParameters params) {
    params_ = std::move(params);
  }

  void setOneRttWriteCipher(std::unique_ptr<Aead> oneRttWriteCipher) {
    oneRttWriteCipher_ = std::move(oneRttWriteCipher);
  }

  void setOneRttReadCipher(std::unique_ptr<Aead> oneRttReadCipher) {
    getClientConn()->readCodec->setOneRttReadCipher(
        std::move(oneRttReadCipher));
  }

  void setHandshakeReadCipher(std::unique_ptr<Aead> handshakeReadCipher) {
    getClientConn()->readCodec->setHandshakeReadCipher(
        std::move(handshakeReadCipher));
  }

  void setHandshakeWriteCipher(std::unique_ptr<Aead> handshakeWriteCipher) {
    getClientConn()->handshakeWriteCipher = std::move(handshakeWriteCipher);
  }

  void setZeroRttWriteCipher(std::unique_ptr<Aead> zeroRttWriteCipher) {
    getClientConn()->zeroRttWriteCipher = std::move(zeroRttWriteCipher);
  }

  void setZeroRttWriteHeaderCipher(
      std::unique_ptr<PacketNumberCipher> zeroRttWriteHeaderCipher) {
    getClientConn()->zeroRttWriteHeaderCipher =
        std::move(zeroRttWriteHeaderCipher);
  }

  void setHandshakeReadHeaderCipher(
      std::unique_ptr<PacketNumberCipher> handshakeReadHeaderCipher) {
    getClientConn()->readCodec->setHandshakeHeaderCipher(
        std::move(handshakeReadHeaderCipher));
  }

  void setHandshakeWriteHeaderCipher(
      std::unique_ptr<PacketNumberCipher> handshakeWriteHeaderCipher) {
    getClientConn()->handshakeWriteHeaderCipher =
        std::move(handshakeWriteHeaderCipher);
  }

  void setOneRttWriteHeaderCipher(
      std::unique_ptr<PacketNumberCipher> oneRttWriteHeaderCipher) {
    oneRttWriteHeaderCipher_ = std::move(oneRttWriteHeaderCipher);
  }

  void setOneRttReadHeaderCipher(
      std::unique_ptr<PacketNumberCipher> oneRttReadHeaderCipher) {
    getClientConn()->readCodec->setOneRttHeaderCipher(
        std::move(oneRttReadHeaderCipher));
  }

  void setZeroRttRejected(bool rejected) {
    setZeroRttRejectedForTest(rejected);
    if (rejected) {
      createServerTransportParameters();
    }
  }

  void doHandshake(std::unique_ptr<folly::IOBuf> buf, EncryptionLevel level)
      override {
    EXPECT_EQ(writeBuf.get(), nullptr);
    QuicClientConnectionState* conn = getClientConn();
    if (!conn->oneRttWriteCipher) {
      conn->oneRttWriteCipher = std::move(oneRttWriteCipher_);
      conn->oneRttWriteHeaderCipher = std::move(oneRttWriteHeaderCipher_);
    }
    if (getPhase() == Phase::Initial) {
      conn->handshakeWriteCipher = test::createNoOpAead();
      conn->handshakeWriteHeaderCipher = test::createNoOpHeaderCipher();
      conn->readCodec->setHandshakeReadCipher(test::createNoOpAead());
      conn->readCodec->setHandshakeHeaderCipher(test::createNoOpHeaderCipher());
      writeDataToQuicStream(
          conn->cryptoState->handshakeStream,
          folly::IOBuf::copyBuffer("ClientFinished"));
      handshakeInitiated();
    }
    readBuffers[level].append(std::move(buf));
  }

  bool connectInvoked() {
    return connected_;
  }

  const folly::Optional<ServerTransportParameters>& getServerTransportParams()
      override {
    return params_;
  }

  void triggerOnNewCachedPsk() {
    fizz::client::NewCachedPsk psk;
    onNewCachedPsk(psk);
  }

  std::unique_ptr<folly::IOBuf> writeBuf;

  bool connected_{false};
  QuicVersion negotiatedVersion{QuicVersion::MVFST};
  uint64_t maxRecvPacketSize{kDefaultMaxUDPPayload};
  uint64_t maxInitialStreamData{kDefaultStreamFlowControlWindow};
  uint64_t connWindowSize{kDefaultConnectionFlowControlWindow};
  uint64_t maxInitialStreamsBidi{std::numeric_limits<uint32_t>::max()};
  uint64_t maxInitialStreamsUni{std::numeric_limits<uint32_t>::max()};
  folly::Optional<ServerTransportParameters> params_;
  EnumArray<EncryptionLevel, BufQueue> readBuffers{};

  std::unique_ptr<Aead> oneRttWriteCipher_;
  std::unique_ptr<PacketNumberCipher> oneRttWriteHeaderCipher_;

  FizzCryptoFactory cryptoFactory_;
  const CryptoFactory& getCryptoFactory() const override {
    return cryptoFactory_;
  }

  // Implement virtual methods we don't intend to use.
  bool isTLSResumed() const override {
    throw std::runtime_error("isTLSResumed not implemented");
  }
  EncryptionLevel getReadRecordLayerEncryptionLevel() override {
    throw std::runtime_error(
        "getReadRecordLayerEncryptionLevel not implemented");
  }
  const folly::Optional<std::string>& getApplicationProtocol() const override {
    throw std::runtime_error("getApplicationProtocol not implemented");
  }
  void processSocketData(folly::IOBufQueue&) override {
    throw std::runtime_error("processSocketData not implemented");
  }
  bool matchEarlyParameters() override {
    throw std::runtime_error("matchEarlyParameters not implemented");
  }
  std::pair<std::unique_ptr<Aead>, std::unique_ptr<PacketNumberCipher>>
  buildCiphers(CipherKind, folly::ByteRange) override {
    throw std::runtime_error("buildCiphers not implemented");
  }
};

class QuicClientTransportTestBase : public virtual testing::Test {
 public:
  QuicClientTransportTestBase()
      : eventbase_(std::make_unique<folly::EventBase>()) {}

  virtual ~QuicClientTransportTestBase() = default;

  struct TestReadData {
    std::unique_ptr<folly::IOBuf> data;
    folly::SocketAddress addr;
    folly::Optional<int> err;

    TestReadData(folly::ByteRange dataIn, folly::SocketAddress addrIn)
        : data(folly::IOBuf::copyBuffer(dataIn)), addr(std::move(addrIn)) {}

    explicit TestReadData(int errIn) : err(errIn) {}
  };

  std::shared_ptr<FizzClientQuicHandshakeContext> getFizzClientContext() {
    if (!fizzClientContext) {
      fizzClientContext =
          FizzClientQuicHandshakeContext::Builder()
              .setCertificateVerifier(createTestCertificateVerifier())
              .setPskCache(getPskCache())
              .build();
    }

    return fizzClientContext;
  }

  virtual std::shared_ptr<QuicPskCache> getPskCache() {
    return nullptr;
  }

  void SetUp() {
    auto socket =
        std::make_unique<testing::NiceMock<quic::test::MockAsyncUDPSocket>>(
            eventbase_.get());
    sock = socket.get();

    client = TestingQuicClientTransport::newClient<TestingQuicClientTransport>(
        eventbase_.get(), std::move(socket), getFizzClientContext());
    destructionCallback =
        std::make_shared<TestingQuicClientTransport::DestructionCallback>();
    client->setDestructionCallback(destructionCallback);
    client->setSupportedVersions(
        {QuicVersion::MVFST,
         MVFST1,
         QuicVersion::QUIC_V1,
         QuicVersion::QUIC_V1_ALIAS,
         QuicVersion::QUIC_DRAFT});
    connIdAlgo_ = std::make_unique<DefaultConnectionIdAlgo>();
    ON_CALL(*sock, resumeRead(testing::_))
        .WillByDefault(testing::SaveArg<0>(&networkReadCallback));
    ON_CALL(*sock, address()).WillByDefault(testing::ReturnRef(serverAddr));
    ON_CALL(*sock, recvmsg(testing::_, testing::_))
        .WillByDefault(testing::Invoke([&](struct msghdr* msg, int) -> ssize_t {
          DCHECK_GT(msg->msg_iovlen, 0);
          if (socketReads.empty()) {
            errno = EAGAIN;
            return -1;
          }
          if (socketReads[0].err) {
            errno = *socketReads[0].err;
            return -1;
          }
          auto testData = std::move(socketReads[0].data);
          testData->coalesce();
          size_t testDataLen = testData->length();
          memcpy(
              msg->msg_iov[0].iov_base, testData->data(), testData->length());
          if (msg->msg_name) {
            socklen_t msg_len = socketReads[0].addr.getAddress(
                static_cast<sockaddr_storage*>(msg->msg_name));
            msg->msg_namelen = msg_len;
          }
          socketReads.pop_front();
          return testDataLen;
        }));
    EXPECT_EQ(client->getConn().selfConnectionIds.size(), 1);
    EXPECT_EQ(
        client->getConn().selfConnectionIds[0].connId,
        *client->getConn().clientConnectionId);
    EXPECT_EQ(client->getConn().peerConnectionIds.size(), 0);
    quicStats_ = std::make_shared<testing::NiceMock<MockQuicStats>>();
    client->setTransportStatsCallback(quicStats_);
    SetUpChild();
  }

  virtual void SetUpChild() {}

  void startTransport() {
    client->addNewPeerAddress(serverAddr);
    client->setHostname(hostname_);
    ON_CALL(*sock, write(testing::_, testing::_))
        .WillByDefault(
            testing::Invoke([&](const folly::SocketAddress&,
                                const std::unique_ptr<folly::IOBuf>& buf) {
              socketWrites.push_back(buf->clone());
              return buf->computeChainDataLength();
            }));
    ON_CALL(*sock, address()).WillByDefault(testing::ReturnRef(serverAddr));

    setupCryptoLayer();
    start();
    client->getNonConstConn().streamManager->setMaxLocalBidirectionalStreams(
        std::numeric_limits<uint32_t>::max());
    client->getNonConstConn().streamManager->setMaxLocalUnidirectionalStreams(
        std::numeric_limits<uint32_t>::max());
  }

  void destroyTransport() {
    client->unbindConnection();
    client = nullptr;
  }

  QuicTransportBase* getTransport() {
    return client->getTransport();
  }

  std::shared_ptr<TestingQuicClientTransport> getTestTransport() {
    return client;
  }

  const QuicClientConnectionState& getConn() const {
    return client->getConn();
  }

  QuicClientConnectionState& getNonConstConn() {
    return client->getNonConstConn();
  }

  MockConnectionSetupCallback& getConnSetupCallback() {
    return clientConnSetupCallback;
  }

  MockConnectionCallback& getConnCallback() {
    return clientConnCallback;
  }

  virtual void setupCryptoLayer() {
    // Fake that the handshake has already occurred and fix the keys.
    mockClientHandshake = new FakeOneRttHandshakeLayer(
        &client->getNonConstConn(), getFizzClientContext());
    client->getNonConstConn().clientHandshakeLayer = mockClientHandshake;
    client->getNonConstConn().handshakeLayer.reset(mockClientHandshake);
    setFakeHandshakeCiphers();
    // Allow ignoring path mtu for testing negotiation.
    client->getNonConstConn().transportSettings.canIgnorePathMTU = true;
  }

  virtual void setFakeHandshakeCiphers() {
    auto readAead = test::createNoOpAead();
    auto writeAead = test::createNoOpAead();
    auto handshakeReadAead = test::createNoOpAead();
    auto handshakeWriteAead = test::createNoOpAead();
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
    EXPECT_CALL(*sock, bind(testing::_, testing::_));
    EXPECT_CALL(*sock, setDFAndTurnOffPMTU());
    EXPECT_CALL(*sock, setErrMessageCallback(client.get()));
    EXPECT_CALL(*sock, resumeRead(client.get()));
    EXPECT_CALL(*sock, setErrMessageCallback(nullptr));
    EXPECT_CALL(*sock, write(testing::_, testing::_))
        .Times(testing::AtLeast(1));
  }

  virtual void start() {
    EXPECT_CALL(clientConnSetupCallback, onTransportReady());
    EXPECT_CALL(clientConnSetupCallback, onReplaySafe());
    setUpSocketExpectations();
    client->start(&clientConnSetupCallback, &clientConnCallback);
    setConnectionIds();
    EXPECT_TRUE(client->idleTimeout().isScheduled());

    EXPECT_EQ(socketWrites.size(), 1);
    EXPECT_TRUE(
        verifyLongHeader(*socketWrites.at(0), LongHeader::Types::Initial));
    socketWrites.clear();
    performFakeHandshake();
    EXPECT_TRUE(
        client->getConn().readCodec->getStatelessResetToken().has_value());
    EXPECT_TRUE(client->getConn().statelessResetToken.has_value());
  }

  void setConnectionIds() {
    originalConnId = client->getConn().clientConnectionId;
    ServerConnectionIdParams params(0, 0, 0);
    serverChosenConnId = *connIdAlgo_->encodeConnectionId(params);
  }

  void recvServerHello(const folly::SocketAddress& addr) {
    auto serverHello = folly::IOBuf::copyBuffer("Fake SHLO");
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

  ConnectionId recvServerRetry(const folly::SocketAddress& addr) {
    // Make the server send a retry packet to the client. The server chooses a
    // connection id that the client must use in all future initial packets.
    std::vector<uint8_t> serverConnIdVec = {
        0xf0, 0x67, 0xa5, 0x50, 0x2a, 0x42, 0x62, 0xb5};
    ConnectionId serverCid(serverConnIdVec);

    std::string retryToken = "token";
    std::string integrityTag =
        "\xd1\x69\x26\xd8\x1f\x6f\x9c\xa2\x95\x3a\x8a\xa4\x57\x5e\x1e\x49";

    folly::IOBuf retryPacketBuf;
    BufAppender appender(&retryPacketBuf, 100);
    appender.writeBE<uint8_t>(0xFF);
    appender.writeBE<QuicVersionType>(static_cast<QuicVersionType>(0xFF00001D));
    appender.writeBE<uint8_t>(0);
    appender.writeBE<uint8_t>(serverConnIdVec.size());
    appender.push(serverConnIdVec.data(), serverConnIdVec.size());
    appender.push((const uint8_t*)retryToken.data(), retryToken.size());
    appender.push((const uint8_t*)integrityTag.data(), integrityTag.size());
    deliverData(addr, retryPacketBuf.coalesce());
    return serverCid;
  }

  void recvServerHello() {
    recvServerHello(serverAddr);
  }

  void recvTicket(folly::Optional<uint64_t> offsetOverride = folly::none) {
    auto negotiatedVersion = *client->getConn().version;
    auto ticket = folly::IOBuf::copyBuffer("NST");
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
        kDefaultConnectionFlowControlWindow,
        kDefaultStreamFlowControlWindow,
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

  void deliverNetworkError(int err) {
    ASSERT_TRUE(networkReadCallback);
    socketReads.emplace_back(err);
    networkReadCallback->onNotifyDataAvailable(*sock);
  }

  void deliverDataWithoutErrorCheck(
      const folly::SocketAddress& addr,
      folly::ByteRange data,
      bool writes = true) {
    ASSERT_TRUE(networkReadCallback);
    socketReads.emplace_back(data, addr);
    networkReadCallback->onNotifyDataAvailable(*sock);
    if (writes) {
      loopForWrites();
    }
  }

  void deliverDataWithoutErrorCheck(
      folly::ByteRange data,
      bool writes = true,
      folly::SocketAddress* peer = nullptr) {
    deliverDataWithoutErrorCheck(
        peer == nullptr ? serverAddr : *peer, data, writes);
  }

  void deliverDataWithoutErrorCheck(
      NetworkData&& data,
      bool writes = true,
      folly::SocketAddress* peer = nullptr) {
    for (const auto& packet : data.packets) {
      deliverDataWithoutErrorCheck(
          peer == nullptr ? serverAddr : *peer, packet.buf->coalesce(), writes);
    }
  }

  void deliverData(
      const folly::SocketAddress& addr,
      folly::ByteRange data,
      bool writes = true) {
    deliverDataWithoutErrorCheck(addr, data, writes);
    if (client->getConn().localConnectionError) {
      bool idleTimeout = false;
      const LocalErrorCode* localError =
          client->getConn().localConnectionError->code.asLocalErrorCode();
      if (localError) {
        idleTimeout = (*localError == LocalErrorCode::IDLE_TIMEOUT);
      }
      if (!idleTimeout) {
        throw std::runtime_error(
            toString(client->getConn().localConnectionError->code));
      }
    }
  }

  void deliverData(
      folly::ByteRange data,
      bool writes = true,
      folly::SocketAddress* peer = nullptr) {
    deliverData(peer == nullptr ? serverAddr : *peer, data, writes);
  }

  void deliverData(
      NetworkData&& data,
      bool writes = true,
      folly::SocketAddress* peer = nullptr) {
    for (const auto& packet : data.packets) {
      deliverData(
          peer == nullptr ? serverAddr : *peer, packet.buf->coalesce(), writes);
    }
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
    return codecResult.regularPacket();
  }

  void verifyShortPackets(AckBlocks& sentPackets) {
    AckStates ackStates;
    for (auto& write : socketWrites) {
      auto packetQueue = bufToQueue(write->clone());
      auto codecResult =
          makeEncryptedCodec(true)->parsePacket(packetQueue, ackStates);
      auto parsedPacket = parseRegularQuicPacket(codecResult);
      if (!parsedPacket) {
        continue;
      }
      PacketNum packetNumSent = parsedPacket->header.getPacketSequenceNum();
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
    auto longHeader = parsedPacket->header.asLong();
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
    return parsedPacket->header.asShort();
  }

  std::unique_ptr<QuicReadCodec> makeHandshakeCodec() {
    FizzCryptoFactory cryptoFactory;
    auto codec = std::make_unique<QuicReadCodec>(QuicNodeType::Server);
    codec->setClientConnectionId(*originalConnId);
    codec->setInitialReadCipher(cryptoFactory.getClientInitialCipher(
        *client->getConn().initialDestinationConnectionId, QuicVersion::MVFST));
    codec->setInitialHeaderCipher(cryptoFactory.makeClientInitialHeaderCipher(
        *client->getConn().initialDestinationConnectionId, QuicVersion::MVFST));
    codec->setHandshakeReadCipher(test::createNoOpAead());
    codec->setHandshakeHeaderCipher(test::createNoOpHeaderCipher());
    return codec;
  }

  std::unique_ptr<QuicReadCodec> makeEncryptedCodec(
      bool handshakeCipher = false) {
    FizzCryptoFactory cryptoFactory;
    auto codec = std::make_unique<QuicReadCodec>(QuicNodeType::Server);
    std::unique_ptr<Aead> handshakeReadCipher;
    codec->setClientConnectionId(*originalConnId);
    codec->setOneRttReadCipher(test::createNoOpAead());
    codec->setOneRttHeaderCipher(test::createNoOpHeaderCipher());
    codec->setZeroRttReadCipher(test::createNoOpAead());
    codec->setZeroRttHeaderCipher(test::createNoOpHeaderCipher());
    if (handshakeCipher) {
      codec->setInitialReadCipher(cryptoFactory.getClientInitialCipher(
          *client->getConn().initialDestinationConnectionId,
          QuicVersion::MVFST));
      codec->setInitialHeaderCipher(cryptoFactory.makeClientInitialHeaderCipher(
          *client->getConn().initialDestinationConnectionId,
          QuicVersion::MVFST));
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

  void expectQuicStatsPacketDrop(PacketDropReason expectedReason) {
    quicStats_ = std::make_shared<testing::NiceMock<MockQuicStats>>();
    EXPECT_CALL(*quicStats_, onPacketDropped(testing::_))
        .WillOnce(testing::Invoke([=](PacketDropReason reason) {
          EXPECT_EQ(expectedReason, reason);
        }));
    client->setTransportStatsCallback(quicStats_);
  }

 protected:
  std::vector<std::unique_ptr<folly::IOBuf>> socketWrites;
  std::deque<TestReadData> socketReads;
  testing::NiceMock<MockDeliveryCallback> deliveryCallback;
  testing::NiceMock<MockReadCallback> readCb;
  testing::NiceMock<MockConnectionSetupCallback> clientConnSetupCallback;
  testing::NiceMock<MockConnectionCallback> clientConnCallback;
  quic::test::MockAsyncUDPSocket* sock;
  std::shared_ptr<TestingQuicClientTransport::DestructionCallback>
      destructionCallback;
  std::unique_ptr<folly::EventBase> eventbase_;
  folly::SocketAddress serverAddr{"127.0.0.1", 443};
  QuicAsyncUDPSocketType::ReadCallback* networkReadCallback{nullptr};
  FakeOneRttHandshakeLayer* mockClientHandshake;
  std::shared_ptr<FizzClientQuicHandshakeContext> fizzClientContext;
  std::shared_ptr<TestingQuicClientTransport> client;
  PacketNum initialPacketNum{0}, handshakePacketNum{0}, appDataPacketNum{0};
  std::unique_ptr<ConnectionIdAlgo> connIdAlgo_;
  folly::Optional<ConnectionId> originalConnId;
  folly::Optional<ConnectionId> serverChosenConnId;
  QuicVersion version{QuicVersion::QUIC_V1};
  std::shared_ptr<testing::NiceMock<MockQuicStats>> quicStats_;
  std::string hostname_{"TestHost"};
};

class QuicClientTransportAfterStartTestBase
    : public QuicClientTransportTestBase {
 public:
  void SetUpChild() override {
    startTransport();
  }
};

} // namespace quic::test
