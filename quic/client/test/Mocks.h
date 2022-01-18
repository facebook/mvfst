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
  MOCK_METHOD1(
      _makeClientHandshake,
      std::unique_ptr<ClientHandshake>(QuicClientConnectionState*));

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
  MOCK_METHOD2(doHandshakeImpl, void(folly::IOBuf*, EncryptionLevel));
  MOCK_METHOD2(
      verifyRetryIntegrityTag,
      bool(const ConnectionId&, const RetryPacket&));
  MOCK_METHOD1(removePsk, void(const folly::Optional<std::string>&));
  MOCK_CONST_METHOD0(getCryptoFactory, const CryptoFactory&());
  MOCK_CONST_METHOD0(isTLSResumed, bool());
  MOCK_METHOD0(getZeroRttRejected, folly::Optional<bool>());
  MOCK_METHOD0(
      getServerTransportParams,
      folly::Optional<ServerTransportParameters>());
  MOCK_METHOD0(destroy, void());

  MOCK_METHOD1(
      connectImpl,
      folly::Optional<CachedServerTransportParameters>(
          folly::Optional<std::string>));
  MOCK_METHOD0(getReadRecordLayerEncryptionLevel, EncryptionLevel());
  MOCK_METHOD1(processSocketData, void(folly::IOBufQueue& queue));
  MOCK_METHOD0(matchEarlyParameters, bool());
  MOCK_METHOD2(
      buildCiphers,
      std::pair<std::unique_ptr<Aead>, std::unique_ptr<PacketNumberCipher>>(
          ClientHandshake::CipherKind kind,
          folly::ByteRange secret));
  MOCK_CONST_METHOD0(
      getApplicationProtocol,
      const folly::Optional<std::string>&());
};

class MockQuicConnectorCallback : public quic::QuicConnector::Callback {
 public:
  MOCK_METHOD1(
      onConnectError,
      void(std::pair<quic::QuicErrorCode, std::string>));
  MOCK_METHOD0(onConnectSuccess, void());
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

  void start(ConnectionSetupCallback* connSetupCb, ConnectionCallbackNew*)
      override {
    auto cancelCode = std::make_pair(
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
