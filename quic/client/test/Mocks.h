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
#include <quic/common/events/FollyQuicEventBase.h>
#include <quic/common/udpsocket/FollyQuicAsyncUDPSocket.h>
#include <quic/handshake/CryptoFactory.h>
#include <quic/handshake/TransportParameters.h>

namespace quic::test {

class MockClientHandshakeFactory : public ClientHandshakeFactory {
 public:
  std::unique_ptr<ClientHandshake>
      makeClientHandshake(QuicClientConnectionState* conn) && override {
    return std::move(*this).makeClientHandshakeImpl(conn);
  }

  MOCK_METHOD(
      std::unique_ptr<ClientHandshake>,
      makeClientHandshakeImpl,
      (QuicClientConnectionState*));
};

class MockClientHandshakeBase : public ClientHandshake {
 public:
  MockClientHandshakeBase(QuicClientConnectionState* conn)
      : ClientHandshake(conn) {}

  ~MockClientHandshakeBase() override {
    destroy();
  }

  // Legacy workaround for move-only types
  folly::Expected<folly::Unit, QuicError> doHandshake(
      BufPtr data,
      EncryptionLevel encryptionLevel) override {
    doHandshakeImpl(data.get(), encryptionLevel);
    return folly::unit;
  }

  MOCK_METHOD(void, doHandshakeImpl, (folly::IOBuf*, EncryptionLevel));
  MOCK_METHOD(
      (folly::Expected<bool, QuicError>),
      verifyRetryIntegrityTag,
      (const ConnectionId&, const RetryPacket&),
      (override));
  MOCK_METHOD(void, removePsk, (const Optional<std::string>&));
  MOCK_METHOD(const CryptoFactory&, getCryptoFactory, (), (const, override));
  MOCK_METHOD(bool, isTLSResumed, (), (const, override));
  MOCK_METHOD(
      Optional<std::vector<uint8_t>>,
      getExportedKeyingMaterial,
      (const std::string& label,
       const Optional<ByteRange>& context,
       uint16_t keyLength),
      (override));
  MOCK_METHOD(Optional<bool>, getZeroRttRejected, ());
  MOCK_METHOD(Optional<bool>, getCanResendZeroRtt, (), (const));
  MOCK_METHOD(
      const Optional<ServerTransportParameters>&,
      getServerTransportParams,
      (),
      (override));
  MOCK_METHOD(void, destroy, ());
  MOCK_METHOD(
      (folly::Expected<std::unique_ptr<Aead>, QuicError>),
      getNextOneRttWriteCipher,
      (),
      (override));
  MOCK_METHOD(
      (folly::Expected<std::unique_ptr<Aead>, QuicError>),
      getNextOneRttReadCipher,
      (),
      (override));

  void handshakeConfirmed() override {
    handshakeConfirmedImpl();
  }

  MOCK_METHOD(void, handshakeConfirmedImpl, ());

  Handshake::TLSSummary getTLSSummary() const override {
    return getTLSSummaryImpl();
  }

  MOCK_METHOD(Handshake::TLSSummary, getTLSSummaryImpl, (), (const));

  // Mock the public connect method
  folly::Expected<folly::Unit, QuicError> connect(
      Optional<std::string> hostname,
      std::shared_ptr<ClientTransportParametersExtension> transportParams) {
    return mockConnect(std::move(hostname), std::move(transportParams));
  }

  MOCK_METHOD(
      (folly::Expected<folly::Unit, QuicError>),
      mockConnect,
      (Optional<std::string>,
       std::shared_ptr<ClientTransportParametersExtension>));
  MOCK_METHOD(
      EncryptionLevel,
      getReadRecordLayerEncryptionLevel,
      (),
      (override));
  MOCK_METHOD(void, processSocketData, (folly::IOBufQueue & queue));
  MOCK_METHOD(bool, matchEarlyParameters, ());
  MOCK_METHOD(
      (folly::Expected<std::unique_ptr<Aead>, QuicError>),
      buildAead,
      (ClientHandshake::CipherKind kind, ByteRange secret));
  MOCK_METHOD(
      (folly::Expected<std::unique_ptr<PacketNumberCipher>, QuicError>),
      buildHeaderCipher,
      (ByteRange secret));
  MOCK_METHOD(
      (folly::Expected<BufPtr, QuicError>),
      getNextTrafficSecret,
      (ByteRange secret),
      (const));
  MOCK_METHOD(
      const Optional<std::string>&,
      getApplicationProtocol,
      (),
      (const, override));
  MOCK_METHOD(
      const std::shared_ptr<const folly::AsyncTransportCertificate>,
      getPeerCertificate,
      (),
      (const, override));
  MOCK_METHOD(Phase, getPhase, (), (const));
  MOCK_METHOD(bool, waitingForData, (), (const));
};

class MockClientHandshake : public MockClientHandshakeBase {
 public:
  MockClientHandshake(QuicClientConnectionState* conn)
      : MockClientHandshakeBase(conn) {}

 private:
  // Implement the private pure virtual methods from ClientHandshake
  folly::Expected<Optional<CachedServerTransportParameters>, QuicError>
  connectImpl(Optional<std::string> /* hostname */) override {
    return Optional<CachedServerTransportParameters>(std::nullopt);
  }

  void processSocketData(folly::IOBufQueue& /* queue */) override {}

  bool matchEarlyParameters() override {
    return false;
  }

  folly::Expected<std::unique_ptr<Aead>, QuicError> buildAead(
      CipherKind /* kind */,
      ByteRange /* secret */) override {
    return folly::makeUnexpected(
        QuicError(TransportErrorCode::INTERNAL_ERROR, "Not implemented"));
  }

  folly::Expected<std::unique_ptr<PacketNumberCipher>, QuicError>
  buildHeaderCipher(ByteRange /* secret */) override {
    return folly::makeUnexpected(
        QuicError(TransportErrorCode::INTERNAL_ERROR, "Not implemented"));
  }

  folly::Expected<BufPtr, QuicError> getNextTrafficSecret(
      ByteRange /* secret */) const override {
    return folly::makeUnexpected(
        QuicError(TransportErrorCode::INTERNAL_ERROR, "Not implemented"));
  }
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
      std::shared_ptr<QuicEventBase> evb,
      std::unique_ptr<QuicAsyncUDPSocket> socket,
      std::shared_ptr<ClientHandshakeFactory> handshakeFactory)
      : QuicTransportBaseLite(evb, std::move(socket)),
        QuicClientTransport(
            evb,
            nullptr /* Initialized through the QuicTransportBaseLite constructor
                     */
            ,
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

} // namespace quic::test
