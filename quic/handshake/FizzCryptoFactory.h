/*
 * Copyright (c) Facebook, Inc. and its affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 *
 */

#pragma once

#include <quic/handshake/CryptoFactory.h>

#include <fizz/protocol/OpenSSLFactory.h>

namespace quic {

class FizzCryptoFactory : public CryptoFactory, public fizz::OpenSSLFactory {
 public:
  FizzCryptoFactory() {}

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

  std::unique_ptr<fizz::PlaintextReadRecordLayer> makePlaintextReadRecordLayer()
      const override;

  std::unique_ptr<fizz::PlaintextWriteRecordLayer>
  makePlaintextWriteRecordLayer() const override;

  std::unique_ptr<fizz::EncryptedReadRecordLayer> makeEncryptedReadRecordLayer(
      fizz::EncryptionLevel encryptionLevel) const override;

  std::unique_ptr<fizz::EncryptedWriteRecordLayer>
  makeEncryptedWriteRecordLayer(
      fizz::EncryptionLevel encryptionLevel) const override;

  virtual std::unique_ptr<PacketNumberCipher> makePacketNumberCipher(
      fizz::CipherSuite cipher) const;
};

} // namespace quic
