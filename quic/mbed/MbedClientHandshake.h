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
  MbedClientHandshake() = default;

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
  buildCiphers(CipherKind /*kind*/, folly::ByteRange /*secret*/) override {
    return {nullptr, nullptr};
  }

 private:
  MbedCryptoFactory crypto_factory;
  folly::Optional<std::string> alpn{folly::none};
};

} // namespace quic
