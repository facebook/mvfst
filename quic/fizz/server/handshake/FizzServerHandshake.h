/*
 * Copyright (c) Facebook, Inc. and its affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 *
 */

#pragma once

#include <quic/server/handshake/ServerHandshake.h>

#include <quic/fizz/handshake/FizzCryptoFactory.h>

namespace quic {

class FizzServerQuicHandshakeContext;
struct QuicServerConnectionState;

class FizzServerHandshake : public ServerHandshake {
 public:
  FizzServerHandshake(
      QuicServerConnectionState* conn,
      std::shared_ptr<FizzServerQuicHandshakeContext> fizzContext);

  const CryptoFactory& getCryptoFactory() const override;

 private:
  void initializeImpl(
      std::shared_ptr<const fizz::server::FizzServerContext> context,
      HandshakeCallback* callback,
      std::unique_ptr<fizz::server::AppTokenValidator> validator) override;

 private:
  FizzCryptoFactory cryptoFactory_;

  std::shared_ptr<FizzServerQuicHandshakeContext> fizzContext_;
};

} // namespace quic
