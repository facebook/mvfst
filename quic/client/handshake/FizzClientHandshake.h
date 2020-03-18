/*
 * Copyright (c) Facebook, Inc. and its affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 *
 */

#pragma once

#include <quic/client/handshake/ClientHandshake.h>
#include <quic/fizz/handshake/FizzCryptoFactory.h>

namespace quic {

class FizzClientQuicHandshakeContext;
struct QuicClientConnectionState;

class FizzClientHandshake : public ClientHandshake {
 public:
  FizzClientHandshake(
      QuicClientConnectionState* conn,
      std::shared_ptr<FizzClientQuicHandshakeContext> fizzContext);

  folly::Optional<QuicCachedPsk> getPsk(
      const folly::Optional<std::string>& hostname) const override;
  void putPsk(
      const folly::Optional<std::string>& hostname,
      QuicCachedPsk quicCachedPsk) override;
  void removePsk(const folly::Optional<std::string>& hostname) override;

  const CryptoFactory& getCryptoFactory() const override;

  const folly::Optional<std::string>& getApplicationProtocol() const override;

  bool isTLSResumed() const override;

 private:
  void connectImpl(
      folly::Optional<std::string> hostname,
      folly::Optional<fizz::client::CachedPsk> cachedPsk) override;

  EncryptionLevel getReadRecordLayerEncryptionLevel() override;
  void processSocketData(folly::IOBufQueue& queue) override;
  bool matchEarlyParameters() override;
  std::pair<std::unique_ptr<Aead>, std::unique_ptr<PacketNumberCipher>>
  buildCiphers(CipherKind kind, folly::ByteRange secret) override;

  class ActionMoveVisitor;
  void processActions(fizz::client::Actions actions);

  fizz::client::State state_;
  fizz::client::ClientStateMachine machine_;

  FizzCryptoFactory cryptoFactory_;

  std::shared_ptr<FizzClientQuicHandshakeContext> fizzContext_;
};

} // namespace quic
