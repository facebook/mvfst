/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#pragma once

#include <quic/handshake/CryptoFactory.h>
#include <quic/handshake/HandshakeLayer.h>
#include <quic/mbed/MbedAead.h>

namespace quic {

class MbedCryptoFactory : public CryptoFactory {
 public:
  /**
   * Given a label (i.e. "client in" or "server in") generates an Aead object,
   * with key & iv derived by ::makeInitialTrafficSecret() below, to
   * encrypt/decrypt quic initial packets
   */
  [[nodiscard]] std::unique_ptr<Aead> makeInitialAead(
      folly::StringPiece label,
      const ConnectionId& clientDstConnId,
      QuicVersion version) const override;

  /**
   * Given a secret, constructs a bit mask to obfuscate header fields in the
   * quic packet (e.g. Packet Number field)
   */
  [[nodiscard]] std::unique_ptr<PacketNumberCipher> makePacketNumberCipher(
      folly::ByteRange secret) const override;

  /**
   * Given a secret, initializes/constructs Aead by expanding the secret to
   * derive key & iv pairs using "quic key" & "quic iv" labels respectively
   */
  [[nodiscard]] std::unique_ptr<Aead> makeQuicAead(
      const CipherType cipher,
      folly::ByteRange secret) const;

 private:
  /**
   * Given a label (i.e. "client in" or "server in") generates a secret that is
   * subsequently passed into hkdf-expand-label to derive key and iv
   * used to initialize/construct Aead object
   */
  [[nodiscard]] Buf makeInitialTrafficSecret(
      folly::StringPiece label,
      const ConnectionId& clientDstConnId,
      QuicVersion version) const override;
};

} // namespace quic
