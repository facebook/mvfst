/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#pragma once

#include <fizz/client/Actions.h>
#include <fizz/client/AsyncFizzClient.h>
#include <quic/client/handshake/ClientHandshake.h>
#include <quic/fizz/handshake/FizzCryptoFactory.h>

#include <fizz/client/ClientProtocol.h>

namespace quic {

class FizzClientQuicHandshakeContext;
struct QuicCachedPsk;
struct QuicClientConnectionState;

class FizzClientHandshake : public ClientHandshake {
 public:
  FizzClientHandshake(
      QuicClientConnectionState* conn,
      std::shared_ptr<FizzClientQuicHandshakeContext> fizzContext,
      std::unique_ptr<FizzCryptoFactory> cryptoFactory);

  void removePsk(const folly::Optional<std::string>& hostname) override;

  const CryptoFactory& getCryptoFactory() const override;

  const folly::Optional<std::string>& getApplicationProtocol() const override;

  bool verifyRetryIntegrityTag(
      const ConnectionId& originalDstConnId,
      const RetryPacket& retryPacket) override;

  bool isTLSResumed() const override;

  folly::Optional<std::vector<uint8_t>> getExportedKeyingMaterial(
      const std::string& label,
      const folly::Optional<folly::ByteRange>& context,
      uint16_t keyLength) override;

  const fizz::client::State& getState() const {
    return state_;
  }

  void setECHRetryCallback(fizz::client::ECHRetryCallback* cb) {
    echRetryCallback_ = cb;
  }

 protected:
  folly::Optional<QuicCachedPsk> getPsk(
      const folly::Optional<std::string>& hostname) const;

  void onNewCachedPsk(fizz::client::NewCachedPsk& newCachedPsk) noexcept;

  void echRetryAvailable(fizz::client::ECHRetryAvailable& retry);

 private:
  folly::Optional<CachedServerTransportParameters> connectImpl(
      folly::Optional<std::string> hostname) override;

  EncryptionLevel getReadRecordLayerEncryptionLevel() override;
  void processSocketData(folly::IOBufQueue& queue) override;
  bool matchEarlyParameters() override;
  std::unique_ptr<Aead> buildAead(CipherKind kind, folly::ByteRange secret)
      override;
  std::unique_ptr<PacketNumberCipher> buildHeaderCipher(
      folly::ByteRange secret) override;
  Buf getNextTrafficSecret(folly::ByteRange secret) const override;

  class ActionMoveVisitor;
  void processActions(fizz::client::Actions actions);

  fizz::client::State state_;
  fizz::client::ClientStateMachine machine_;

  std::unique_ptr<FizzCryptoFactory> cryptoFactory_;

  std::shared_ptr<FizzClientQuicHandshakeContext> fizzContext_;

  fizz::client::ECHRetryCallback* echRetryCallback_{nullptr};
};

} // namespace quic
