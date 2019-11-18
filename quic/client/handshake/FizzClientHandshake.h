/*
 * Copyright (c) Facebook, Inc. and its affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 *
 */

#pragma once

#include <quic/client/handshake/ClientHandshake.h>

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

 private:
  std::shared_ptr<FizzClientQuicHandshakeContext> fizzContext_;
};

} // namespace quic
