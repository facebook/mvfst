/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#pragma once

#include <quic/QuicConstants.h>
#include <quic/QuicException.h>
#include <quic/common/Expected.h>
#include <quic/common/Optional.h>

namespace quic {

struct TrafficKey {
  BufPtr key;
  BufPtr iv;
};

/**
 * Interface for aead algorithms (RFC 5116).
 */
class Aead {
 public:
  virtual ~Aead() = default;

  [[nodiscard]] virtual Optional<TrafficKey> getKey() const = 0;

  /**
   * Encrypts plaintext inplace. Returns quic::Expected with the encrypted
   * buffer or an error.
   */
  [[nodiscard]] virtual quic::Expected<BufPtr, QuicError> inplaceEncrypt(
      BufPtr&& plaintext,
      const Buf* associatedData,
      uint64_t seqNum) const = 0;

  /**
   * Decrypt ciphertext. Will throw if the ciphertext does not decrypt
   * successfully.
   */
  virtual BufPtr decrypt(
      BufPtr&& ciphertext,
      const Buf* associatedData,
      uint64_t seqNum) const {
    auto plaintext = tryDecrypt(std::move(ciphertext), associatedData, seqNum);
    if (!plaintext) {
      throw std::runtime_error("decryption failed");
    }
    return std::move(*plaintext);
  }

  /**
   * Decrypt ciphertext. Will return std::nullopt if the ciphertext does not
   * decrypt successfully. May still throw from errors unrelated to ciphertext.
   */
  virtual Optional<BufPtr> tryDecrypt(
      BufPtr&& ciphertext,
      const Buf* associatedData,
      uint64_t seqNum) const = 0;

  /**
   * Returns the number of bytes the aead will add to the plaintext (size of
   * ciphertext - size of plaintext).
   */
  [[nodiscard]] virtual size_t getCipherOverhead() const = 0;
};
} // namespace quic
