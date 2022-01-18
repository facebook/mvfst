/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#pragma once

#include <quic/fizz/handshake/QuicFizzFactory.h>
#include <quic/handshake/CryptoFactory.h>

namespace quic {

class FizzCryptoFactory : public CryptoFactory {
 public:
  FizzCryptoFactory() : fizzFactory_{std::make_shared<QuicFizzFactory>()} {}

  Buf makeInitialTrafficSecret(
      folly::StringPiece label,
      const ConnectionId& clientDestinationConnId,
      QuicVersion version) const override;

  std::unique_ptr<Aead> makeInitialAead(
      folly::StringPiece label,
      const ConnectionId& clientDestinationConnId,
      QuicVersion version) const override;

  std::unique_ptr<PacketNumberCipher> makePacketNumberCipher(
      folly::ByteRange baseSecret) const override;

  virtual std::unique_ptr<PacketNumberCipher> makePacketNumberCipher(
      fizz::CipherSuite cipher) const;

  std::shared_ptr<fizz::Factory> getFizzFactory() {
    return fizzFactory_;
  }

 protected:
  std::shared_ptr<fizz::Factory> fizzFactory_;
};

} // namespace quic
