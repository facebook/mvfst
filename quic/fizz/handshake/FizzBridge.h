/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#pragma once

#include <fizz/crypto/aead/Aead.h>
#include <fizz/protocol/Types.h>
#include <quic/QuicConstants.h>
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

  Optional<TrafficKey> getKey() const override;

  /**
   * Forward calls to fizz::Aead, catching any exceptions and converting them to
   * folly::Expected.
   */
  folly::Expected<std::unique_ptr<folly::IOBuf>, QuicError> inplaceEncrypt(
      std::unique_ptr<folly::IOBuf>&& plaintext,
      const folly::IOBuf* associatedData,
      uint64_t seqNum) const override {
    try {
      return fizzAead->inplaceEncrypt(
          std::move(plaintext), associatedData, seqNum);
    } catch (const std::exception& ex) {
      return folly::makeUnexpected(
          QuicError(TransportErrorCode::INTERNAL_ERROR, ex.what()));
    }
  }

  std::unique_ptr<folly::IOBuf> decrypt(
      std::unique_ptr<folly::IOBuf>&& ciphertext,
      const folly::IOBuf* associatedData,
      uint64_t seqNum) const override {
    fizz::Aead::AeadOptions options;
    options.bufferOpt = fizz::Aead::BufferOption::AllowInPlace;
    return fizzAead->decrypt(
        std::move(ciphertext), associatedData, seqNum, options);
  }

  Optional<std::unique_ptr<folly::IOBuf>> tryDecrypt(
      std::unique_ptr<folly::IOBuf>&& ciphertext,
      const folly::IOBuf* associatedData,
      uint64_t seqNum) const override {
    fizz::Aead::AeadOptions options;
    options.bufferOpt = fizz::Aead::BufferOption::AllowInPlace;
    auto result = fizzAead->tryDecrypt(
        std::move(ciphertext), associatedData, seqNum, options);
    if (result.has_value()) {
      return Optional<std::unique_ptr<folly::IOBuf>>(std::move(result.value()));
    } else {
      return Optional<std::unique_ptr<folly::IOBuf>>();
    }
  }

  size_t getCipherOverhead() const override {
    return fizzAead->getCipherOverhead();
  }

 private:
  std::unique_ptr<fizz::Aead> fizzAead;

  explicit FizzAead(std::unique_ptr<fizz::Aead> fizzAeadIn)
      : fizzAead(std::move(fizzAeadIn)) {}
};

EncryptionLevel getEncryptionLevelFromFizz(
    const fizz::EncryptionLevel encryptionLevel);

} // namespace quic
