/*
 * Copyright (c) Facebook, Inc. and its affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 *
 */

#pragma once

#include <quic/client/handshake/ClientHandshake.h>
#include <quic/handshake/FizzCryptoFactory.h>

namespace quic {

class FizzClientQuicHandshakeContext;

class FizzClientHandshake : public ClientHandshake {
 public:
  FizzClientHandshake(
      QuicCryptoState& cryptoState,
      std::shared_ptr<FizzClientQuicHandshakeContext> fizzContext);

  void connect(
      folly::Optional<std::string> hostname,
      folly::Optional<fizz::client::CachedPsk> cachedPsk,
      const std::shared_ptr<ClientTransportParametersExtension>&
          transportParams,
      HandshakeCallback* callback) override;

  const CryptoFactory& getCryptoFactory() const override;

  const folly::Optional<std::string>& getApplicationProtocol() const override;

 private:
  void processSocketData(folly::IOBufQueue& queue) override;
  std::pair<std::unique_ptr<Aead>, std::unique_ptr<PacketNumberCipher>>
  buildCiphers(CipherKind kind, folly::ByteRange secret) override;

  class ActionMoveVisitor;
  void processActions(fizz::client::Actions actions);

  fizz::client::ClientStateMachine machine_;

  FizzCryptoFactory cryptoFactory_;

  std::shared_ptr<FizzClientQuicHandshakeContext> fizzContext_;
};

} // namespace quic
