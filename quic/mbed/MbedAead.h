/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#pragma once

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

  std::unique_ptr<folly::IOBuf> inplaceEncrypt(
      std::unique_ptr<folly::IOBuf>&& /*plaintext*/,
      const folly::IOBuf* /*associatedData*/,
      uint64_t /*seqNum*/) const override {
    return nullptr;
  }

  folly::Optional<std::unique_ptr<folly::IOBuf>> tryDecrypt(
      std::unique_ptr<folly::IOBuf>&& /*ciphertext*/,
      const folly::IOBuf* /*associatedData*/,
      uint64_t /*seqNum*/) const override {
    return folly::none;
  }

  // returns tag length
  size_t getCipherOverhead() const override;

 private:
  TrafficKey key_;
  mutable mbedtls_cipher_context_t cipher_ctx;
};

} // namespace quic
