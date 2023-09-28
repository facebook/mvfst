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

  HeaderProtectionMask mask(folly::ByteRange sample) const override {
    /**
     * RFC9001:
     * The ciphertext of the packet is sampled and used as input to an
     * encryption algorithm. The output of this algorithm is a 5-byte mask that
     * is applied to the protected header fields using exclusive OR.
     */
    HeaderProtectionMask out_mask;
    size_t out_len{0};
    CHECK_EQ(out_mask.size(), sample.size());

    // ecb mode does not use iv
    if (mbedtls_cipher_crypt(
            /*ctx=*/&enc_ctx,
            /*iv=*/nullptr,
            /*iv_len=*/0,
            /*input=*/sample.data(),
            /*ilen=*/sample.size(),
            /*output=*/out_mask.data(),
            /*olen=*/&out_len) != 0 ||
        out_len != out_mask.size()) {
      throw std::runtime_error("mbedtls: failed to generate mask");
    }

    return out_mask;
  }

 private:
  const mbedtls_cipher_info_t* cipher_info{nullptr};
  mutable mbedtls_cipher_context_t enc_ctx;
  Buf key_{nullptr};
};

} // namespace quic
