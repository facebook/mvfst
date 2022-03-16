/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#pragma once

#include <folly/portability/GMock.h>
#include <quic/client/QuicClientTransport.h>
#include <quic/client/connector/QuicConnector.h>
#include <quic/client/handshake/CachedServerTransportParameters.h>
#include <quic/client/handshake/ClientHandshake.h>
#include <quic/client/handshake/ClientHandshakeFactory.h>
#include <quic/handshake/CryptoFactory.h>
#include <quic/handshake/TransportParameters.h>

namespace quic {
namespace test {

class MockClientHandshakeFactory : public ClientHandshakeFactory {
 public:
  MOCK_METHOD(
      std::unique_ptr<ClientHandshake>,
      _makeClientHandshake,
      (QuicClientConnectionState*));

  std::unique_ptr<ClientHandshake>
      makeClientHandshake(QuicClientConnectionState* conn) && override {
    return _makeClientHandshake(conn);
  }
};

class MockClientHandshake : public ClientHandshake {
 public:
  MockClientHandshake(QuicClientConnectionState* conn)
      : ClientHandshake(conn) {}
  ~MockClientHandshake() override {
    destroy();
  }
  // Legacy workaround for move-only types
  void doHandshake(
      std::unique_ptr<folly::IOBuf> data,
      EncryptionLevel encryptionLevel) override {
    doHandshakeImpl(data.get(), encryptionLevel);
  }
  MOCK_METHOD(void, doHandshakeImpl, (folly::IOBuf*, EncryptionLevel));
  MOCK_METHOD(
      bool,
      verifyRetryIntegrityTag,
      (const ConnectionId&, const RetryPacket&));
  MOCK_METHOD(void, removePsk, (const folly::Optional<std::string>&));
  MOCK_METHOD(const CryptoFactory&, getCryptoFactory, (), (const));
  MOCK_METHOD(bool, isTLSResumed, (), (const));
  MOCK_METHOD(folly::Optional<bool>, getZeroRttRejected, ());
  MOCK_METHOD(
      folly::Optional<ServerTransportParameters>,
      getServerTransportParams,
      ());
  MOCK_METHOD(void, destroy, ());

  MOCK_METHOD(
      folly::Optional<CachedServerTransportParameters>,
      connectImpl,
      (folly::Optional<std::string>));
  MOCK_METHOD(EncryptionLevel, getReadRecordLayerEncryptionLevel, ());
  MOCK_METHOD(void, processSocketData, (folly::IOBufQueue & queue));
  MOCK_METHOD(bool, matchEarlyParameters, ());
  MOCK_METHOD(
      (std::pair<std::unique_ptr<Aead>, std::unique_ptr<PacketNumberCipher>>),
      buildCiphers,
      (ClientHandshake::CipherKind kind, folly::ByteRange secret));
  MOCK_METHOD(
      const folly::Optional<std::string>&,
      getApplicationProtocol,
      (),
      (const));
};

class MockQuicConnectorCallback : public quic::QuicConnector::Callback {
 public:
  MOCK_METHOD(void, onConnectError, (QuicError));
  MOCK_METHOD(void, onConnectSuccess, ());
};

class MockQuicClientTransport : public quic::QuicClientTransport {
 public:
  enum class TestType : uint8_t { Success = 0, Failure, Timeout };

  explicit MockQuicClientTransport(
      TestType testType,
      folly::EventBase* evb,
      std::unique_ptr<folly::AsyncUDPSocket> socket,
      std::shared_ptr<ClientHandshakeFactory> handshakeFactory)
      : QuicClientTransport(
            evb,
            std::move(socket),
            std::move(handshakeFactory)),
        testType_(testType) {}

  void start(ConnectionSetupCallback* connSetupCb, ConnectionCallback*)
      override {
    auto cancelCode = QuicError(
        QuicErrorCode(LocalErrorCode::NO_ERROR),
        toString(LocalErrorCode::NO_ERROR).str());

    switch (testType_) {
      case TestType::Success:
        connSetupCb->onReplaySafe();
        break;
      case TestType::Failure:
        connSetupCb->onConnectionSetupError(std::move(cancelCode));
        break;
      case TestType::Timeout:
        // Do nothing and let it timeout.
        break;
    }
  }

 private:
  TestType testType_;
};

} // namespace test
} // namespace quic
