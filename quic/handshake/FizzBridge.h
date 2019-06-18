/*
 * Copyright (c) Facebook, Inc. and its affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 *
 */

#pragma once

#include <fizz/crypto/aead/Aead.h>
#include <quic/handshake/Aead.h>

#include <memory>
#include <utility>

namespace quic {

class FizzAead final : public Aead {
 public:
  static std::unique_ptr<FizzAead> wrap(
      std::unique_ptr<fizz::Aead> fizzAeadIn) {
    if (!fizzAeadIn) {
      return nullptr;
    }

    return std::unique_ptr<FizzAead>(new FizzAead(std::move(fizzAeadIn)));
  }

  /**
   * Simply forward all calls to fizz::Aead.
   */
  std::unique_ptr<folly::IOBuf> encrypt(
      std::unique_ptr<folly::IOBuf>&& plaintext,
      const folly::IOBuf* associatedData,
      uint64_t seqNum) const override {
    return fizzAead->encrypt(std::move(plaintext), associatedData, seqNum);
  }
  std::unique_ptr<folly::IOBuf> decrypt(
      std::unique_ptr<folly::IOBuf>&& ciphertext,
      const folly::IOBuf* associatedData,
      uint64_t seqNum) const override {
    return fizzAead->decrypt(std::move(ciphertext), associatedData, seqNum);
  }
  folly::Optional<std::unique_ptr<folly::IOBuf>> tryDecrypt(
      std::unique_ptr<folly::IOBuf>&& ciphertext,
      const folly::IOBuf* associatedData,
      uint64_t seqNum) const override {
    return fizzAead->tryDecrypt(std::move(ciphertext), associatedData, seqNum);
  }
  size_t getCipherOverhead() const override {
    return fizzAead->getCipherOverhead();
  }

  // For testing.
  const fizz::Aead* getFizzAead() const {
    return fizzAead.get();
  }

 private:
  std::unique_ptr<fizz::Aead> fizzAead;
  FizzAead(std::unique_ptr<fizz::Aead> fizzAeadIn)
      : fizzAead(std::move(fizzAeadIn)) {}
};

} // namespace quic
