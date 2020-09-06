/*
 * Copyright (c) Facebook, Inc. and its affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 *
 */

#pragma once

#include <quic/fizz/handshake/FizzCryptoFactory.h>
#include <quic/server/handshake/ServerHandshake.h>

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
      HandshakeCallback* callback,
      std::unique_ptr<fizz::server::AppTokenValidator> validator) override;

  EncryptionLevel getReadRecordLayerEncryptionLevel() override;
  void processSocketData(folly::IOBufQueue& queue) override;

  FizzCryptoFactory cryptoFactory_;

  std::shared_ptr<FizzServerQuicHandshakeContext> fizzContext_;
};

} // namespace quic
