/*
 * Copyright (c) Facebook, Inc. and its affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 *
 */

#pragma once

#include <quic/handshake/CryptoFactory.h>

#include <quic/handshake/QuicFizzFactory.h>

namespace quic {

class FizzCryptoFactory : public CryptoFactory {
 public:
  explicit FizzCryptoFactory(QuicFizzFactory* factory) : factory_(factory) {}

  Buf makeInitialTrafficSecret(
      folly::StringPiece label,
      const ConnectionId& clientDestinationConnId,
      QuicVersion version) const override;

  std::unique_ptr<Aead> makeInitialAead(
      folly::StringPiece label,
      const ConnectionId& clientDestinationConnId,
      QuicVersion version) const override;

  std::unique_ptr<PacketNumberCipher>
  makePacketNumberCipher(folly::ByteRange baseSecret) const override;

 private:
  QuicFizzFactory* factory_{nullptr};
};

} // namespace quic
