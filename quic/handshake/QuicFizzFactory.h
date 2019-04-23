/*
 * Copyright (c) Facebook, Inc. and its affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 *
 */

#pragma once

#include <fizz/protocol/Factory.h>
#include <quic/codec/PacketNumberCipher.h>

namespace quic {

constexpr folly::StringPiece kQuicHkdfLabelPrefix = "quic ";

class QuicFizzFactory : public fizz::Factory {
 public:
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
