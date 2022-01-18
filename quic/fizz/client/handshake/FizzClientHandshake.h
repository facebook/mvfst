/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#pragma once

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

 protected:
  folly::Optional<QuicCachedPsk> getPsk(
      const folly::Optional<std::string>& hostname) const;

  void onNewCachedPsk(fizz::client::NewCachedPsk& newCachedPsk) noexcept;

  // For tests.
  fizz::client::State& getFizzState() {
    return state_;
  }

 private:
  folly::Optional<CachedServerTransportParameters> connectImpl(
      folly::Optional<std::string> hostname) override;

  EncryptionLevel getReadRecordLayerEncryptionLevel() override;
  void processSocketData(folly::IOBufQueue& queue) override;
  bool matchEarlyParameters() override;
  std::pair<std::unique_ptr<Aead>, std::unique_ptr<PacketNumberCipher>>
  buildCiphers(CipherKind kind, folly::ByteRange secret) override;

  class ActionMoveVisitor;
  void processActions(fizz::client::Actions actions);

  fizz::client::State state_;
  fizz::client::ClientStateMachine machine_;

  std::unique_ptr<FizzCryptoFactory> cryptoFactory_;

  std::shared_ptr<FizzClientQuicHandshakeContext> fizzContext_;
};

} // namespace quic
