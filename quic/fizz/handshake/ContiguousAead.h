/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#pragma once

#include <fizz/crypto/aead/Aead.h>
#include <quic/handshake/Aead.h>

#include <array>
#include <cstdint>
#include <span>

namespace quic {

/**
 * Adapts an AES-GCM cipher that works on contiguous buffers to quic::Aead.
 * The packet header used as associated data must be unchained; the payload is
 * coalesced before the cipher runs, and the cipher works in place.
 */
class ContiguousAead : public Aead {
 public:
  static constexpr size_t kKeyLength = 16;
  static constexpr size_t kNonceLength = 12;
  static constexpr size_t kTagLength = 16;

  // Among the suites fizz supports, only TLS_AES_128_GCM_SHA256 has a 16 byte
  // key and a 12 byte IV.
  [[nodiscard]] static bool isAes128GcmKey(const fizz::TrafficKey& key);

  [[nodiscard]] Optional<TrafficKey> getKey() const override;

  [[nodiscard]] quic::Expected<BufPtr, QuicError> inplaceEncrypt(
      BufPtr&& plaintext,
      const Buf* associatedData,
      uint64_t seqNum) const override;

  Optional<BufPtr> tryDecrypt(
      BufPtr&& ciphertext,
      const Buf* associatedData,
      uint64_t seqNum) const override;

  [[nodiscard]] size_t getCipherOverhead() const override {
    return kTagLength;
  }

 protected:
  // The key must satisfy isAes128GcmKey.
  explicit ContiguousAead(fizz::TrafficKey key);

  // Both return false on failure. The output may alias the input.
  [[nodiscard]] virtual bool seal(
      std::span<const uint8_t> nonce,
      std::span<const uint8_t> aad,
      std::span<const uint8_t> plaintext,
      std::span<uint8_t> ciphertext,
      std::span<uint8_t> tag) const = 0;

  [[nodiscard]] virtual bool open(
      std::span<const uint8_t> nonce,
      std::span<const uint8_t> aad,
      std::span<const uint8_t> ciphertext,
      std::span<const uint8_t> tag,
      std::span<uint8_t> plaintext) const = 0;

 private:
  [[nodiscard]] std::array<uint8_t, kNonceLength> makeNonce(
      uint64_t seqNum) const;

  fizz::TrafficKey key_;
};

} // namespace quic
