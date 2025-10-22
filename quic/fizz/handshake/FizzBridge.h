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
   * quic::Expected.
   */
  quic::Expected<BufPtr, QuicError> inplaceEncrypt(
      BufPtr&& plaintext,
      const Buf* associatedData,
      uint64_t seqNum) const override {
    try {
      return fizzAead->inplaceEncrypt(
          std::move(plaintext), associatedData, seqNum);
    } catch (const std::exception& ex) {
      return quic::make_unexpected(
          QuicError(TransportErrorCode::INTERNAL_ERROR, ex.what()));
    }
  }

  BufPtr decrypt(
      BufPtr&& ciphertext,
      const Buf* associatedData,
      uint64_t seqNum) const override {
    fizz::Aead::AeadOptions options;
    options.bufferOpt = fizz::Aead::BufferOption::AllowInPlace;
    return fizzAead->decrypt(
        std::move(ciphertext), associatedData, seqNum, options);
  }

  Optional<BufPtr> tryDecrypt(
      BufPtr&& ciphertext,
      const Buf* associatedData,
      uint64_t seqNum) const override {
    fizz::Aead::AeadOptions options;
    options.bufferOpt = fizz::Aead::BufferOption::AllowInPlace;
    auto result = fizzAead->tryDecrypt(
        std::move(ciphertext), associatedData, seqNum, options);
    if (result.has_value()) {
      return Optional<BufPtr>(std::move(result.value()));
    } else {
      return Optional<BufPtr>();
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
