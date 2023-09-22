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

class MbedAead : public Aead {
 public:
  MbedAead() = default;

  folly::Optional<TrafficKey> getKey() const override {
    return folly::none;
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

  size_t getCipherOverhead() const override {
    return 0;
  }
};

} // namespace quic
