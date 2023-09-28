/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#pragma once

#include <quic/codec/PacketNumberCipher.h>
#include <quic/mbed/MbedAead.h>

extern "C" {
#include "mbedtls/cipher.h" //@manual
}

namespace quic {

class MbedPacketNumCipher : public PacketNumberCipher {
 public:
  explicit MbedPacketNumCipher(const CipherType cipherType);
  ~MbedPacketNumCipher() override;

  void setKey(folly::ByteRange key) override;

  const Buf& getKey() const override {
    return key_;
  }

  size_t keyLength() const override {
    return cipher_info->key_bitlen >> 3;
  }

  HeaderProtectionMask mask(folly::ByteRange /*sample*/) const override {
    return HeaderProtectionMask();
  }

 private:
  const mbedtls_cipher_info_t* cipher_info{nullptr};
  mbedtls_cipher_context_t enc_ctx;
  Buf key_{nullptr};
};

} // namespace quic
