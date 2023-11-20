/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <quic/client/handshake/CachedServerTransportParameters.h>
#include <quic/client/handshake/ClientHandshake.h>
#include <quic/mbed/MbedCryptoFactory.h>

extern "C" {
#include "mbedtls/ssl.h" //@manual
}

namespace quic {

class MbedClientHandshake : public ClientHandshake {
 public:
  explicit MbedClientHandshake(QuicClientConnectionState* conn);
  ~MbedClientHandshake() override;

  const CryptoFactory& getCryptoFactory() const override {
    return crypto_factory;
  }

  const folly::Optional<std::string>& getApplicationProtocol() const override {
    return alpn;
  }

  bool isTLSResumed() const override {
    return false;
  }

  bool verifyRetryIntegrityTag(
      const ConnectionId& /*originalDstConnId*/,
      const RetryPacket& /*retryPacket*/) override {
    return true;
  }

  folly::Optional<CachedServerTransportParameters> connectImpl(
      folly::Optional<std::string> /*hostname*/) override {
    return folly::none;
  }

  EncryptionLevel getReadRecordLayerEncryptionLevel() override {
    return EncryptionLevel::Initial;
  }

  void processSocketData(folly::IOBufQueue& /*queue*/) override {}

  bool matchEarlyParameters() override {
    return false;
  }

  std::pair<std::unique_ptr<Aead>, std::unique_ptr<PacketNumberCipher>>
  buildCiphers(CipherKind kind, folly::ByteRange secret) override;

  /**
   * Struct used to define static c-style callbacks and proxy them to the
   * corresponding methods on this object. This allows us to mark the MbedTLS
   * callback functions as private.
   */
  friend struct MbedTlsQuicMethodCb;

 private:
  // MbedTLS quic callbacks

  // cb invoked when secrets are derived by the tls layer for a given enc level
  int setEncryptionSecrets(
      EncryptionLevel level,
      const uint8_t* readKey,
      const uint8_t* writeKey,
      size_t length);

  // cb invoked when new handshake data is available to send to peer
  int addHandshakeData(
      EncryptionLevel level,
      const uint8_t* data,
      size_t length) {
    writeDataToStream(level, folly::IOBuf::copyBuffer(data, length));
    return 0;
  }

  // cb invoked to inform quic to deliver alert to peer
  int sendAlert(EncryptionLevel /*level*/, uint8_t /*alert*/) {
    return 0;
  }

  // cb invoked on new TLS session ticket post-handshake
  void processNewSession(mbedtls_ssl_session* /*sessionTicket*/) {}

  mbedtls_ssl_config ssl_conf;
  mbedtls_ssl_context ssl_ctx;
  MbedCryptoFactory crypto_factory;
  folly::Optional<std::string> alpn{folly::none};
};

} // namespace quic
