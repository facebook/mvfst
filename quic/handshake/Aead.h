/*
 *  Copyright (c) 2018-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree.
 */

#pragma once

#include <folly/Optional.h>
#include <folly/io/IOBuf.h>

namespace quic {

struct TrafficKey {
  std::unique_ptr<folly::IOBuf> key;
  std::unique_ptr<folly::IOBuf> iv;
};

/**
 * Interface for aead algorithms (RFC 5116).
 */
class Aead {
 public:
  virtual ~Aead() = default;

  /**
   * Encrypts plaintext. Will throw on error.
   */
  virtual std::unique_ptr<folly::IOBuf> encrypt(
      std::unique_ptr<folly::IOBuf>&& plaintext,
      const folly::IOBuf* associatedData,
      uint64_t seqNum) const = 0;

  /**
   * Decrypt ciphertext. Will throw if the ciphertext does not decrypt
   * successfully.
   */
  virtual std::unique_ptr<folly::IOBuf> decrypt(
      std::unique_ptr<folly::IOBuf>&& ciphertext,
      const folly::IOBuf* associatedData,
      uint64_t seqNum) const {
    auto plaintext = tryDecrypt(std::move(ciphertext), associatedData, seqNum);
    if (!plaintext) {
      throw std::runtime_error("decryption failed");
    }
    return std::move(*plaintext);
  }

  /**
   * Decrypt ciphertext. Will return none if the ciphertext does not decrypt
   * successfully. May still throw from errors unrelated to ciphertext.
   */
  virtual folly::Optional<std::unique_ptr<folly::IOBuf>> tryDecrypt(
      std::unique_ptr<folly::IOBuf>&& ciphertext,
      const folly::IOBuf* associatedData,
      uint64_t seqNum) const = 0;

  /**
   * Returns the number of bytes the aead will add to the plaintext (size of
   * ciphertext - size of plaintext).
   */
  virtual size_t getCipherOverhead() const = 0;
};
} // namespace quic
