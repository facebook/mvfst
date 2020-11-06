/*
 * Copyright (c) Facebook, Inc. and its affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 *
 */

#pragma once

#include <folly/portability/GMock.h>
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
      makeClientHandshake,
      std::unique_ptr<ClientHandshake>(QuicClientConnectionState*));
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

} // namespace test
} // namespace quic
