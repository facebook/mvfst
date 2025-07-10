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

  [[nodiscard]] quic::Expected<BufPtr, QuicError> makeInitialTrafficSecret(
      folly::StringPiece label,
      const ConnectionId& clientDestinationConnId,
      QuicVersion version) const override;

  [[nodiscard]] quic::Expected<std::unique_ptr<Aead>, QuicError>
  makeInitialAead(
      folly::StringPiece label,
      const ConnectionId& clientDestinationConnId,
      QuicVersion version) const override;

  [[nodiscard]] quic::Expected<std::unique_ptr<PacketNumberCipher>, QuicError>
  makePacketNumberCipher(ByteRange baseSecret) const override;

  [[nodiscard]] virtual quic::
      Expected<std::unique_ptr<PacketNumberCipher>, QuicError>
      makePacketNumberCipher(fizz::CipherSuite cipher) const;

  [[nodiscard]] std::function<bool(ByteRange, ByteRange)>
  getCryptoEqualFunction() const override;

  std::shared_ptr<fizz::Factory> getFizzFactory() {
    return fizzFactory_;
  }

 protected:
  std::shared_ptr<fizz::Factory> fizzFactory_;
};

} // namespace quic
