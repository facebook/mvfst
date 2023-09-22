/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#pragma once

#include <fizz/crypto/aead/CryptoUtil.h>
#include <quic/handshake/Aead.h>

extern "C" {
#include "mbedtls/cipher.h" //@manual
}

namespace quic {

enum CipherType { AESGCM128 };

class MbedAead : public Aead {
 public:
  MbedAead(const CipherType cipherType, TrafficKey&& key);

  ~MbedAead() override {
    mbedtls_cipher_free(&cipher_ctx);
  }

  folly::Optional<TrafficKey> getKey() const override {
    return TrafficKey{.key = key_.key->clone(), .iv = key_.iv->clone()};
  }

  // does not support inplace encryption just yet
  std::unique_ptr<folly::IOBuf> inplaceEncrypt(
      std::unique_ptr<folly::IOBuf>&& plaintext,
      const folly::IOBuf* assocData,
      uint64_t seqNum) const override;

  // does not support inplace decryption just yet
  folly::Optional<std::unique_ptr<folly::IOBuf>> tryDecrypt(
      std::unique_ptr<folly::IOBuf>&& ciphertext,
      const folly::IOBuf* assocData,
      uint64_t seqNum) const override;

  // returns tag length
  size_t getCipherOverhead() const override;

 private:
  void setCipherKey(const mbedtls_operation_t operation) const {
    // set key for encryption and decryption (we create separate Aead for read
    // and write, i.e. only one of enc or dec operation will ever be called on
    // obj)
    const uint8_t* key_data = key_.key->data();
    const size_t key_bitlen = key_.key->length() << 3;
    CHECK_EQ(
        mbedtls_cipher_setkey(&cipher_ctx, key_data, key_bitlen, operation), 0);
  }

  std::array<uint8_t, MBEDTLS_MAX_IV_LENGTH> getIV(uint64_t seqNum) const {
    return fizz::createIV<MBEDTLS_MAX_IV_LENGTH>(
        /*seqNum=*/seqNum,
        /*ivLength=*/key_.iv->length(),
        /*trafficIvKey=*/folly::ByteRange(key_.iv->data(), key_.iv->length()));
  }

  TrafficKey key_;
  mutable mbedtls_cipher_context_t cipher_ctx;
};

} // namespace quic
