/*
 * Copyright (c) Facebook, Inc. and its affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 *
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

#include <quic/client/handshake/ClientHandshake.h>
#include <quic/client/handshake/test/MockQuicPskCache.h>
#include <quic/common/test/TestUtils.h>
#include <quic/state/QuicStreamFunctions.h>
#include <quic/state/StateData.h>

using namespace std;
using namespace quic;
using namespace folly;
using namespace folly::test;
using namespace folly::ssl;
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
        clientCtx,
        verifier,
        hostname,
        folly::none,
        std::make_shared<ClientTransportParametersExtension>(
            folly::none,
            folly::to<uint32_t>(kDefaultConnectionWindowSize),
            folly::to<uint32_t>(kDefaultStreamWindowSize),
            folly::to<uint32_t>(kDefaultStreamWindowSize),
            folly::to<uint32_t>(kDefaultStreamWindowSize),
            kDefaultIdleTimeout,
            kDefaultAckDelayExponent,
            kDefaultUDPSendPacketLen),
        nullptr);
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
    handshake.reset(new ClientHandshake(cryptoState));
    std::vector<QuicVersion> supportedVersions = {getVersion()};
    auto serverTransportParameters =
        std::make_shared<ServerTransportParametersExtension>(
            folly::none,
            supportedVersions,
            folly::to<uint32_t>(kDefaultConnectionWindowSize),
            folly::to<uint32_t>(kDefaultStreamWindowSize),
            folly::to<uint32_t>(kDefaultStreamWindowSize),
            folly::to<uint32_t>(kDefaultStreamWindowSize),
            std::numeric_limits<uint32_t>::max(),
            std::numeric_limits<uint32_t>::max(),
            kDefaultIdleTimeout,
            kDefaultAckDelayExponent,
            kDefaultUDPSendPacketLen,
            kDefaultPartialReliability,
            generateStatelessResetToken());
    fizzServer.reset(
        new fizz::server::
            FizzServer<ClientHandshakeTest, fizz::server::ServerStateMachine>(
                serverState, serverReadBuf, *this, dg.get()));
    connect();
    processHandshake();
    fizzServer->accept(&evb, serverCtx, serverTransportParameters);
  }

  void clientServerRound() {
    auto writableBytes = getHandshakeWriteBytes();
    serverReadBuf.append(std::move(writableBytes));
    fizzServer->newTransportData();
    evb.loop();
  }

  void serverClientRound() {
    evb.loop();
    for (auto& write : serverOutput) {
      for (auto& content : write.contents) {
        handshake->doHandshake(
            std::move(content.data), content.encryptionLevel);
      }
    }
    processHandshake();
  }

  void processHandshake() {
    auto oneRttWriteCipherTmp = handshake->getOneRttWriteCipher();
    auto oneRttReadCipherTmp = handshake->getOneRttReadCipher();
    auto zeroRttWriteCipherTmp = handshake->getZeroRttWriteCipher();
    auto handshakeWriteCipherTmp = handshake->getHandshakeWriteCipher();
    auto handshakeReadCipherTmp = handshake->getHandshakeReadCipher();
    if (oneRttWriteCipherTmp) {
      oneRttWriteCipher = std::move(oneRttWriteCipherTmp);
    }
    if (oneRttReadCipherTmp) {
      oneRttReadCipher = std::move(oneRttReadCipherTmp);
    }
    if (zeroRttWriteCipherTmp) {
      zeroRttWriteCipher = std::move(zeroRttWriteCipherTmp);
    }
    if (handshakeWriteCipherTmp) {
      handshakeWriteCipher = std::move(handshakeWriteCipherTmp);
    }
    if (handshakeReadCipherTmp) {
      handshakeReadCipher = std::move(handshakeReadCipherTmp);
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
      EXPECT_NE(oneRttReadCipher.get(), nullptr);
      EXPECT_NE(oneRttWriteCipher.get(), nullptr);
    } else {
      EXPECT_EQ(oneRttReadCipher.get(), nullptr);
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
    if (!cryptoState.initialStream.writeBuffer.empty()) {
      buf->prependChain(cryptoState.initialStream.writeBuffer.move());
    }
    if (!cryptoState.handshakeStream.writeBuffer.empty()) {
      buf->prependChain(cryptoState.handshakeStream.writeBuffer.move());
    }
    if (!cryptoState.oneRttStream.writeBuffer.empty()) {
      buf->prependChain(cryptoState.oneRttStream.writeBuffer.move());
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
  std::unique_ptr<ClientHandshake> handshake;
  QuicCryptoState cryptoState;
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

  std::unique_ptr<Aead> handshakeWriteCipher;
  std::unique_ptr<Aead> handshakeReadCipher;
  std::unique_ptr<Aead> oneRttWriteCipher;
  std::unique_ptr<Aead> oneRttReadCipher;
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

  EXPECT_FALSE(zeroRttRejected.hasValue());

  EXPECT_EQ(handshake->getPhase(), ClientHandshake::Phase::OneRttKeysDerived);
  clientServerRound();

  expectOneRttCipher(true);

  EXPECT_EQ(handshake->getPhase(), ClientHandshake::Phase::OneRttKeysDerived);

  handshake->onRecvOneRttProtectedData();
  EXPECT_EQ(handshake->getPhase(), ClientHandshake::Phase::Established);
  EXPECT_FALSE(zeroRttRejected.hasValue());
  EXPECT_TRUE(handshakeSuccess);
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
  EXPECT_FALSE(zeroRttRejected.hasValue());
  EXPECT_TRUE(handshakeSuccess);
}

TEST_F(ClientHandshakeTest, TestAppBytesInterpretedAsHandshake) {
  EXPECT_CALL(*verifier, verify(_));

  clientServerRound();
  serverClientRound();
  clientServerRound();

  fizz::AppWrite w;
  w.data = IOBuf::copyBuffer("hey");
  fizzServer->appWrite(std::move(w));
  evb.loop();

  // RTT 1/2 server -> client
  serverClientRound();
  expectOneRttCipher(true);
  EXPECT_FALSE(zeroRttRejected.hasValue());
  EXPECT_TRUE(handshakeSuccess);
}

class MockClientHandshakeCallback : public ClientHandshake::HandshakeCallback {
 public:
  GMOCK_METHOD1_(
      ,
      noexcept,
      ,
      onNewCachedPsk,
      void(fizz::client::NewCachedPsk&));
};

class ClientHandshakeCallbackTest : public ClientHandshakeTest {
 public:
  void setupClientAndServerContext() override {
    clientCtx = std::make_shared<fizz::client::FizzClientContext>();
    clientCtx->setSupportedVersions({fizz::ProtocolVersion::tls_1_3});
    serverCtx->setSupportedVersions({fizz::ProtocolVersion::tls_1_3});
    clientCtx->setClock(std::make_shared<fizz::test::MockClock>());
    setupZeroRttOnServerCtx(*serverCtx, psk_);
    conn_.version = getVersion();
  }

  void connect() override {
    handshake->connect(
        clientCtx,
        verifier,
        hostname,
        folly::none,
        std::make_shared<ClientTransportParametersExtension>(
            getVersion(),
            folly::to<uint32_t>(kDefaultConnectionWindowSize),
            folly::to<uint32_t>(kDefaultStreamWindowSize),
            folly::to<uint32_t>(kDefaultStreamWindowSize),
            folly::to<uint32_t>(kDefaultStreamWindowSize),
            kDefaultIdleTimeout,
            kDefaultAckDelayExponent,
            kDefaultUDPSendPacketLen),
        &mockClientHandshakeCallback_);
  }

 protected:
  QuicCachedPsk psk_;
  QuicConnectionStateBase conn_{QuicNodeType::Client};
  MockClientHandshakeCallback mockClientHandshakeCallback_;
};

TEST_F(ClientHandshakeCallbackTest, TestHandshakeSuccess) {
  clientServerRound();
  serverClientRound();
  clientServerRound();

  EXPECT_CALL(mockClientHandshakeCallback_, onNewCachedPsk(_));
  serverClientRound();
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
  EXPECT_FALSE(zeroRttRejected.hasValue());
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
    clientCtx->setSupportedAlpns({"h1q-fb", "hq"});
    clientCtx->setClock(std::make_shared<fizz::test::MockClock>());
    serverCtx->setSupportedVersions({fizz::ProtocolVersion::tls_1_3});
    serverCtx->setSupportedAlpns({"h1q-fb"});
    serverCtx->setClock(std::make_shared<fizz::test::MockClock>());
    setupCtxWithTestCert(*serverCtx);
    psk = setupZeroRttOnClientCtx(*clientCtx, hostname, QuicVersion::MVFST);
    setupZeroRttServer();
  }

  void connect() override {
    handshake->connect(
        clientCtx,
        verifier,
        hostname,
        psk.cachedPsk,
        std::make_shared<ClientTransportParametersExtension>(
            getVersion(),
            folly::to<uint32_t>(kDefaultConnectionWindowSize),
            folly::to<uint32_t>(kDefaultStreamWindowSize),
            folly::to<uint32_t>(kDefaultStreamWindowSize),
            folly::to<uint32_t>(kDefaultStreamWindowSize),
            kDefaultIdleTimeout,
            kDefaultAckDelayExponent,
            kDefaultUDPSendPacketLen),
        nullptr);
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
  EXPECT_FALSE(zeroRttRejected.hasValue());
  expectZeroRttCipher(true, true);
  clientServerRound();
  handshake->onRecvOneRttProtectedData();
  EXPECT_EQ(handshake->getPhase(), ClientHandshake::Phase::Established);
  EXPECT_EQ(handshake->getApplicationProtocol(), "h1q-fb");
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
  handshake->onRecvOneRttProtectedData();
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
