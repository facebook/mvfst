/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <condition_variable>
#include <mutex>

#include <fizz/crypto/test/TestUtil.h>
#include <fizz/protocol/clock/test/Mocks.h>
#include <fizz/protocol/test/Mocks.h>
#include <fizz/server/Actions.h>
#include <fizz/server/test/Mocks.h>

#include <folly/io/async/SSLContext.h>
#include <folly/io/async/ScopedEventBaseThread.h>
#include <folly/io/async/test/MockAsyncTransport.h>
#include <folly/ssl/Init.h>

#include <quic/client/handshake/ClientTransportParametersExtension.h>
#include <quic/client/state/ClientStateMachine.h>
#include <quic/common/test/TestUtils.h>
#include <quic/fizz/client/handshake/FizzClientHandshake.h>
#include <quic/fizz/client/handshake/FizzClientQuicHandshakeContext.h>
#include <quic/fizz/client/handshake/test/MockQuicPskCache.h>
#include <quic/fizz/handshake/FizzBridge.h>
#include <quic/fizz/handshake/QuicFizzFactory.h>
#include <quic/state/QuicStreamFunctions.h>
#include <quic/state/StateData.h>

using namespace testing;

namespace quic {
namespace test {

class ClientHandshakeTest : public Test, public boost::static_visitor<> {
 public:
  ~ClientHandshakeTest() override = default;

  ClientHandshakeTest() {}

  virtual void setupClientAndServerContext() {
    clientCtx = std::make_shared<fizz::client::FizzClientContext>();
    clientCtx->setClock(std::make_shared<fizz::test::MockClock>());
  }

  QuicVersion getVersion() {
    return QuicVersion::MVFST;
  }

  virtual void connect() {
    handshake->connect(
        hostname,
        std::make_shared<ClientTransportParametersExtension>(
            QuicVersion::MVFST,
            folly::to<uint32_t>(kDefaultConnectionFlowControlWindow),
            folly::to<uint32_t>(kDefaultStreamFlowControlWindow),
            folly::to<uint32_t>(kDefaultStreamFlowControlWindow),
            folly::to<uint32_t>(kDefaultStreamFlowControlWindow),
            folly::to<uint32_t>(kDefaultMaxStreamsBidirectional),
            folly::to<uint32_t>(kDefaultMaxStreamsUnidirectional),
            kDefaultIdleTimeout,
            kDefaultAckDelayExponent,
            kDefaultUDPSendPacketLen,
            kDefaultActiveConnectionIdLimit,
            ConnectionId(std::vector<uint8_t>())));
  }

  void SetUp() override {
    folly::ssl::init();
    dg.reset(new DelayedHolder());
    serverCtx = ::quic::test::createServerCtx();
    serverCtx->setOmitEarlyRecordLayer(true);
    serverCtx->setClock(std::make_shared<fizz::test::MockClock>());
    // Fizz is the name of the identity for our server certificate.
    hostname = "Fizz";
    setupClientAndServerContext();

    verifier = std::make_shared<fizz::test::MockCertificateVerifier>();
    auto handshakeFactory = FizzClientQuicHandshakeContext::Builder()
                                .setFizzClientContext(clientCtx)
                                .setCertificateVerifier(verifier)
                                .setPskCache(getPskCache())
                                .build();
    conn.reset(new QuicClientConnectionState(handshakeFactory));
    conn->readCodec = std::make_unique<QuicReadCodec>(QuicNodeType::Client);

    cryptoState = conn->cryptoState.get();
    handshake = conn->clientHandshakeLayer;
    conn->transportSettings.attemptEarlyData = true;
    std::vector<QuicVersion> supportedVersions = {getVersion()};
    auto serverTransportParameters =
        std::make_shared<ServerTransportParametersExtension>(
            getVersion(),
            folly::to<uint32_t>(kDefaultConnectionFlowControlWindow),
            folly::to<uint32_t>(kDefaultStreamFlowControlWindow),
            folly::to<uint32_t>(kDefaultStreamFlowControlWindow),
            folly::to<uint32_t>(kDefaultStreamFlowControlWindow),
            std::numeric_limits<uint32_t>::max(),
            std::numeric_limits<uint32_t>::max(),
            /*disableMigration=*/true,
            kDefaultIdleTimeout,
            kDefaultAckDelayExponent,
            kDefaultUDPSendPacketLen,
            generateStatelessResetToken(),
            ConnectionId(std::vector<uint8_t>{0xff, 0xfe, 0xfd, 0xfc}),
            ConnectionId(std::vector<uint8_t>()));
    fizzServer.reset(
        new fizz::server::
            FizzServer<ClientHandshakeTest, fizz::server::ServerStateMachine>(
                serverState, serverReadBuf, readAeadOptions, *this, dg.get()));
    connect();
    processHandshake();
    fizzServer->accept(&evb, serverCtx, serverTransportParameters);
  }

  virtual std::shared_ptr<QuicPskCache> getPskCache() {
    return nullptr;
  }

  void clientServerRound() {
    auto writableBytes = getHandshakeWriteBytes();
    serverReadBuf.append(std::move(writableBytes));
    fizzServer->newTransportData();
    evb.loop();
  }

  void serverClientRound() {
    // Fake that the transport has set the version and initial params.
    conn->version = QuicVersion::MVFST;
    conn->serverInitialParamsSet_ = true;
    evb.loop();
    for (auto& write : serverOutput) {
      for (auto& content : write.contents) {
        auto encryptionLevel =
            getEncryptionLevelFromFizz(content.encryptionLevel);
        handshake->doHandshake(std::move(content.data), encryptionLevel);
      }
    }
    processHandshake();
  }

  void processHandshake() {
    auto oneRttWriteCipherTmp = std::move(conn->oneRttWriteCipher);
    auto oneRttReadCipherTmp = conn->readCodec->getOneRttReadCipher();
    auto zeroRttWriteCipherTmp = std::move(conn->zeroRttWriteCipher);
    auto handshakeWriteCipherTmp = std::move(conn->handshakeWriteCipher);
    auto handshakeReadCipherTmp = conn->readCodec->getHandshakeReadCipher();
    if (oneRttWriteCipherTmp) {
      oneRttWriteCipher = std::move(oneRttWriteCipherTmp);
    }
    if (oneRttReadCipherTmp) {
      oneRttReadCipher = oneRttReadCipherTmp;
    }
    if (zeroRttWriteCipherTmp) {
      zeroRttWriteCipher = std::move(zeroRttWriteCipherTmp);
    }
    if (handshakeWriteCipherTmp) {
      handshakeWriteCipher = std::move(handshakeWriteCipherTmp);
    }
    if (handshakeReadCipherTmp) {
      handshakeReadCipher = handshakeReadCipherTmp;
    }
    auto rejected = handshake->getZeroRttRejected();
    if (rejected) {
      zeroRttRejected = std::move(rejected);
    }
  }

  void expectHandshakeCipher(bool expected) {
    EXPECT_EQ(handshakeReadCipher != nullptr, expected);
    EXPECT_EQ(handshakeWriteCipher != nullptr, expected);
  }

  void expectOneRttCipher(bool expected, bool oneRttOnly = false) {
    if (expected) {
      EXPECT_NE(oneRttReadCipher, nullptr);
      EXPECT_NE(oneRttWriteCipher.get(), nullptr);
    } else {
      EXPECT_EQ(oneRttReadCipher, nullptr);
      EXPECT_EQ(oneRttWriteCipher.get(), nullptr);
    }
    if (!oneRttOnly) {
      EXPECT_EQ(zeroRttWriteCipher.get(), nullptr);
    }
  }

  void expectZeroRttCipher(bool expected, bool expectOneRtt) {
    if (expected) {
      EXPECT_NE(zeroRttWriteCipher.get(), nullptr);
    } else {
      EXPECT_EQ(zeroRttWriteCipher.get(), nullptr);
    }
    expectOneRttCipher(expectOneRtt, true);
  }

  Buf getHandshakeWriteBytes() {
    auto buf = folly::IOBuf::create(0);
    if (!cryptoState->initialStream.writeBuffer.empty()) {
      buf->prependChain(cryptoState->initialStream.writeBuffer.move());
    }
    if (!cryptoState->handshakeStream.writeBuffer.empty()) {
      buf->prependChain(cryptoState->handshakeStream.writeBuffer.move());
    }
    if (!cryptoState->oneRttStream.writeBuffer.empty()) {
      buf->prependChain(cryptoState->oneRttStream.writeBuffer.move());
    }
    return buf;
  }

  void operator()(fizz::DeliverAppData&) {
    // do nothing here.
  }

  void operator()(fizz::WriteToSocket& write) {
    serverOutput.push_back(std::move(write));
  }

  void operator()(fizz::server::ReportEarlyHandshakeSuccess&) {
    earlyHandshakeSuccess = true;
  }

  void operator()(fizz::server::ReportHandshakeSuccess&) {
    handshakeSuccess = true;
  }

  void operator()(fizz::ReportError& error) {
    handshakeError = std::move(error);
  }

  void operator()(fizz::WaitForData&) {
    fizzServer->waitForData();
  }

  void operator()(fizz::server::MutateState& mutator) {
    mutator(serverState);
  }

  void operator()(fizz::server::AttemptVersionFallback&) {}

  void operator()(fizz::SecretAvailable&) {}

  void operator()(fizz::EndOfData&) {}

  class DelayedHolder : public folly::DelayedDestruction {};

  folly::EventBase evb;
  std::unique_ptr<
      QuicClientConnectionState,
      folly::DelayedDestruction::Destructor>
      conn{nullptr};
  ClientHandshake* handshake;
  QuicCryptoState* cryptoState;
  std::string hostname;

  fizz::server::ServerStateMachine machine;
  fizz::server::State serverState;
  std::unique_ptr<fizz::server::FizzServer<
      ClientHandshakeTest,
      fizz::server::ServerStateMachine>>
      fizzServer;
  std::vector<fizz::WriteToSocket> serverOutput;
  bool handshakeSuccess{false};
  bool earlyHandshakeSuccess{false};
  folly::Optional<fizz::ReportError> handshakeError;
  folly::IOBufQueue serverReadBuf{folly::IOBufQueue::cacheChainLength()};
  std::unique_ptr<DelayedHolder, folly::DelayedDestruction::Destructor> dg;
  fizz::Aead::AeadOptions readAeadOptions;

  std::unique_ptr<Aead> handshakeWriteCipher;
  const Aead* handshakeReadCipher = nullptr;
  std::unique_ptr<Aead> oneRttWriteCipher;
  const Aead* oneRttReadCipher = nullptr;
  std::unique_ptr<Aead> zeroRttWriteCipher;

  folly::Optional<bool> zeroRttRejected;

  std::shared_ptr<fizz::test::MockCertificateVerifier> verifier;
  std::shared_ptr<fizz::client::FizzClientContext> clientCtx;
  std::shared_ptr<fizz::server::FizzServerContext> serverCtx;
};

TEST_F(ClientHandshakeTest, TestHandshakeSuccess) {
  EXPECT_CALL(*verifier, verify(_));

  clientServerRound();
  EXPECT_EQ(handshake->getPhase(), ClientHandshake::Phase::Initial);
  expectHandshakeCipher(false);

  serverClientRound();
  expectHandshakeCipher(true);

  EXPECT_FALSE(zeroRttRejected.has_value());

  EXPECT_EQ(handshake->getPhase(), ClientHandshake::Phase::OneRttKeysDerived);
  clientServerRound();

  expectOneRttCipher(true);

  EXPECT_EQ(handshake->getPhase(), ClientHandshake::Phase::OneRttKeysDerived);

  handshake->handshakeConfirmed();
  EXPECT_EQ(handshake->getPhase(), ClientHandshake::Phase::Established);
  EXPECT_FALSE(zeroRttRejected.has_value());
  EXPECT_TRUE(handshakeSuccess);
}

TEST_F(ClientHandshakeTest, TestRetryIntegrityVerification) {
  // Example obtained from Appendix-A.4 of the QUIC-TLS draft v29.

  auto version = static_cast<QuicVersion>(0xff00001d);
  uint8_t initialByte = 0xff;

  std::vector<uint8_t> dcidVec = {};
  ConnectionId dcid(dcidVec);

  std::vector<uint8_t> scidVec = {
      0xf0, 0x67, 0xa5, 0x50, 0x2a, 0x42, 0x62, 0xb5};
  ConnectionId scid(scidVec);

  std::string retryToken = R"(token)";
  LongHeader header(
      LongHeader::Types::Retry, scid, dcid, 0, version, retryToken);

  std::string integrityTag =
      "\xd1\x69\x26\xd8\x1f\x6f\x9c\xa2\x95\x3a\x8a\xa4\x57\x5e\x1e\x49";

  RetryPacket retryPacket(
      std::move(header), folly::IOBuf::copyBuffer(integrityTag), initialByte);

  std::vector<uint8_t> odcidVec = {
      0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08};
  ConnectionId odcid(odcidVec);

  EXPECT_TRUE(handshake->verifyRetryIntegrityTag(odcid, retryPacket));
}

TEST_F(ClientHandshakeTest, TestNoErrorAfterAppClose) {
  EXPECT_CALL(*verifier, verify(_));

  clientServerRound();
  serverClientRound();
  clientServerRound();

  fizzServer->appClose();
  evb.loop();

  // RTT 1/2 server -> client
  EXPECT_NO_THROW(serverClientRound());
  expectOneRttCipher(true);
  EXPECT_FALSE(zeroRttRejected.has_value());
  EXPECT_TRUE(handshakeSuccess);
}

TEST_F(ClientHandshakeTest, TestAppBytesInterpretedAsHandshake) {
  EXPECT_CALL(*verifier, verify(_));

  clientServerRound();
  serverClientRound();
  clientServerRound();

  fizz::AppWrite w;
  w.data = folly::IOBuf::copyBuffer("hey");
  fizzServer->appWrite(std::move(w));
  evb.loop();

  // RTT 1/2 server -> client
  serverClientRound();
  expectOneRttCipher(true);
  EXPECT_FALSE(zeroRttRejected.has_value());
  EXPECT_TRUE(handshakeSuccess);
}

class ClientHandshakeCallbackTest : public ClientHandshakeTest {
 public:
  void setupClientAndServerContext() override {
    clientCtx = std::make_shared<fizz::client::FizzClientContext>();
    clientCtx->setSupportedVersions({fizz::ProtocolVersion::tls_1_3});
    serverCtx->setSupportedVersions({fizz::ProtocolVersion::tls_1_3});
    clientCtx->setClock(std::make_shared<fizz::test::MockClock>());
    setupZeroRttOnServerCtx(*serverCtx, psk_);
  }

  void connect() override {
    handshake->connect(
        hostname,
        std::make_shared<ClientTransportParametersExtension>(
            QuicVersion::MVFST,
            folly::to<uint32_t>(kDefaultConnectionFlowControlWindow),
            folly::to<uint32_t>(kDefaultStreamFlowControlWindow),
            folly::to<uint32_t>(kDefaultStreamFlowControlWindow),
            folly::to<uint32_t>(kDefaultStreamFlowControlWindow),
            folly::to<uint32_t>(kDefaultMaxStreamsBidirectional),
            folly::to<uint32_t>(kDefaultMaxStreamsUnidirectional),
            kDefaultIdleTimeout,
            kDefaultAckDelayExponent,
            kDefaultUDPSendPacketLen,
            kDefaultActiveConnectionIdLimit,
            ConnectionId(std::vector<uint8_t>())));
  }

 protected:
  QuicCachedPsk psk_;
};

TEST_F(ClientHandshakeCallbackTest, TestHandshakeSuccess) {
  clientServerRound();
  serverClientRound();
  clientServerRound();

  bool gotEarlyDataParams = false;
  conn->earlyDataAppParamsGetter = [&]() -> Buf {
    gotEarlyDataParams = true;
    return {};
  };

  serverClientRound();
  EXPECT_TRUE(gotEarlyDataParams);
}

class ClientHandshakeHRRTest : public ClientHandshakeTest {
 public:
  ~ClientHandshakeHRRTest() override = default;

  void setupClientAndServerContext() override {
    clientCtx = std::make_shared<fizz::client::FizzClientContext>();
    clientCtx->setSupportedGroups(
        {fizz::NamedGroup::secp256r1, fizz::NamedGroup::x25519});
    clientCtx->setDefaultShares({fizz::NamedGroup::secp256r1});
    clientCtx->setClock(std::make_shared<fizz::test::MockClock>());
    serverCtx = std::make_shared<fizz::server::FizzServerContext>();
    serverCtx->setFactory(std::make_shared<QuicFizzFactory>());
    serverCtx->setSupportedGroups({fizz::NamedGroup::x25519});
    serverCtx->setClock(std::make_shared<fizz::test::MockClock>());
    setupCtxWithTestCert(*serverCtx);
  }
};

TEST_F(ClientHandshakeHRRTest, TestFullHRR) {
  EXPECT_CALL(*verifier, verify(_));

  clientServerRound();
  expectHandshakeCipher(false);

  EXPECT_EQ(handshake->getPhase(), ClientHandshake::Phase::Initial);
  serverClientRound();
  EXPECT_EQ(handshake->getPhase(), ClientHandshake::Phase::Handshake);
  clientServerRound();
  expectOneRttCipher(false);
  EXPECT_EQ(handshake->getPhase(), ClientHandshake::Phase::Handshake);

  serverClientRound();
  expectHandshakeCipher(true);
  EXPECT_EQ(handshake->getPhase(), ClientHandshake::Phase::OneRttKeysDerived);
  clientServerRound();
  expectOneRttCipher(true);
  EXPECT_EQ(handshake->getPhase(), ClientHandshake::Phase::OneRttKeysDerived);
  EXPECT_FALSE(zeroRttRejected.has_value());
  EXPECT_TRUE(handshakeSuccess);
}

TEST_F(ClientHandshakeHRRTest, TestHRROnlyOneRound) {
  EXPECT_CALL(*verifier, verify(_)).Times(0);

  clientServerRound();
  serverClientRound();
  clientServerRound();

  expectOneRttCipher(false);
  EXPECT_FALSE(handshakeSuccess);
}

class ClientHandshakeZeroRttTest : public ClientHandshakeTest {
 public:
  ~ClientHandshakeZeroRttTest() override = default;

  void setupClientAndServerContext() override {
    clientCtx = std::make_shared<fizz::client::FizzClientContext>();
    clientCtx->setSupportedVersions({fizz::ProtocolVersion::tls_1_3});
    clientCtx->setSupportedAlpns({"h3", "hq"});
    clientCtx->setClock(std::make_shared<fizz::test::MockClock>());
    serverCtx->setSupportedVersions({fizz::ProtocolVersion::tls_1_3});
    serverCtx->setSupportedAlpns({"h3"});
    serverCtx->setClock(std::make_shared<fizz::test::MockClock>());
    setupCtxWithTestCert(*serverCtx);
    psk = setupZeroRttOnClientCtx(*clientCtx, hostname);
    setupZeroRttServer();
  }

  std::shared_ptr<QuicPskCache> getPskCache() override {
    auto pskCache = std::make_shared<BasicQuicPskCache>();
    pskCache->putPsk(hostname, psk);
    return pskCache;
  }

  void connect() override {
    handshake->connect(
        hostname,
        std::make_shared<ClientTransportParametersExtension>(
            QuicVersion::MVFST,
            folly::to<uint32_t>(kDefaultConnectionFlowControlWindow),
            folly::to<uint32_t>(kDefaultStreamFlowControlWindow),
            folly::to<uint32_t>(kDefaultStreamFlowControlWindow),
            folly::to<uint32_t>(kDefaultStreamFlowControlWindow),
            folly::to<uint32_t>(kDefaultMaxStreamsBidirectional),
            folly::to<uint32_t>(kDefaultMaxStreamsUnidirectional),
            kDefaultIdleTimeout,
            kDefaultAckDelayExponent,
            kDefaultUDPSendPacketLen,
            kDefaultActiveConnectionIdLimit,
            ConnectionId(std::vector<uint8_t>())));
  }

  virtual void setupZeroRttServer() {
    setupZeroRttOnServerCtx(*serverCtx, psk);
  }

  QuicCachedPsk psk;
};

TEST_F(ClientHandshakeZeroRttTest, TestZeroRttSuccess) {
  clientServerRound();
  EXPECT_EQ(handshake->getPhase(), ClientHandshake::Phase::Initial);
  expectZeroRttCipher(true, false);
  expectHandshakeCipher(false);
  serverClientRound();
  expectHandshakeCipher(true);
  EXPECT_EQ(handshake->getPhase(), ClientHandshake::Phase::OneRttKeysDerived);
  EXPECT_TRUE(zeroRttRejected.has_value());
  EXPECT_FALSE(*zeroRttRejected);
  expectZeroRttCipher(true, true);
  clientServerRound();
  handshake->handshakeConfirmed();
  EXPECT_EQ(handshake->getPhase(), ClientHandshake::Phase::Established);
  EXPECT_EQ(handshake->getApplicationProtocol(), "h3");
}

class ClientHandshakeZeroRttReject : public ClientHandshakeZeroRttTest {
 public:
  ~ClientHandshakeZeroRttReject() override = default;

  void setupZeroRttServer() override {}
};

TEST_F(ClientHandshakeZeroRttReject, TestZeroRttRejection) {
  clientServerRound();
  EXPECT_EQ(handshake->getPhase(), ClientHandshake::Phase::Initial);
  expectZeroRttCipher(true, false);
  expectHandshakeCipher(false);
  serverClientRound();
  expectHandshakeCipher(true);
  EXPECT_EQ(handshake->getPhase(), ClientHandshake::Phase::OneRttKeysDerived);
  EXPECT_TRUE(zeroRttRejected.value_or(false));
  // We will still keep the zero rtt key lying around.
  expectZeroRttCipher(true, true);
  clientServerRound();
  handshake->handshakeConfirmed();
  EXPECT_EQ(handshake->getPhase(), ClientHandshake::Phase::Established);
}

class ClientHandshakeZeroRttRejectFail : public ClientHandshakeZeroRttTest {
 public:
  ~ClientHandshakeZeroRttRejectFail() override = default;

  void setupClientAndServerContext() override {
    // set it up so that the identity will not match.
    hostname = "foobar";
    ClientHandshakeZeroRttTest::setupClientAndServerContext();
  }

  void setupZeroRttServer() override {}
};

TEST_F(ClientHandshakeZeroRttRejectFail, TestZeroRttRejectionParamsDontMatch) {
  clientServerRound();
  EXPECT_EQ(handshake->getPhase(), ClientHandshake::Phase::Initial);
  expectHandshakeCipher(false);
  expectZeroRttCipher(true, false);
  EXPECT_THROW(serverClientRound(), QuicInternalException);
}
} // namespace test
} // namespace quic
