/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#pragma once

#include <quic/handshake/CryptoFactory.h>
#include <quic/handshake/HandshakeLayer.h>

namespace quic {

class MbedCryptoFactory : public CryptoFactory {
 public:
  Buf makeInitialTrafficSecret(
      folly::StringPiece label,
      const ConnectionId& clientDstConnId,
      QuicVersion version) const override;

  std::unique_ptr<Aead> makeInitialAead(
      folly::StringPiece label,
      const ConnectionId& clientDstConnId,
      QuicVersion version) const override;

  std::unique_ptr<PacketNumberCipher> makePacketNumberCipher(
      folly::ByteRange secret) const override;
};

} // namespace quic
