/*
 * Copyright (c) Facebook, Inc. and its affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 *
 */

#pragma once

#include <folly/Optional.h>
#include <folly/io/Cursor.h>
#include <folly/ssl/OpenSSLPtrTypes.h>

namespace quic {

using HeaderProtectionMask = std::array<uint8_t, 16>;
using Sample = std::array<uint8_t, 16>;

class PacketNumberCipher {
 public:
  virtual ~PacketNumberCipher() = default;

  virtual void setKey(folly::ByteRange key) = 0;

  virtual HeaderProtectionMask mask(folly::ByteRange sample) const = 0;

  /**
   * Decrypts a long header from a sample.
   * sample should be 16 bytes long.
   * initialByte is the initial byte.
   * packetNumberBytes should be supplied with at least 4 bytes.
   */
  virtual void decryptLongHeader(
      folly::ByteRange sample,
      folly::MutableByteRange initialByte,
      folly::MutableByteRange packetNumberBytes) const;

  /**
   * Decrypts a short header from a sample.
   * sample should be 16 bytes long.
   * initialByte is the initial byte.
   * packetNumberBytes should be supplied with at least 4 bytes.
   */
  virtual void decryptShortHeader(
      folly::ByteRange sample,
      folly::MutableByteRange initialByte,
      folly::MutableByteRange packetNumberBytes) const;

  /**
   * Encrypts a long header from a sample.
   * sample should be 16 bytes long.
   * initialByte is the initial byte.
   */
  virtual void encryptLongHeader(
      folly::ByteRange sample,
      folly::MutableByteRange initialByte,
      folly::MutableByteRange packetNumberBytes) const;

  /**
   * Encrypts a short header from a sample.
   * sample should be 16 bytes long.
   * initialByte is the initial byte.
   */
  virtual void encryptShortHeader(
      folly::ByteRange sample,
      folly::MutableByteRange initialByte,
      folly::MutableByteRange packetNumberBytes) const;

  /**
   * Returns the length of key needed for the pn cipher.
   */
  virtual size_t keyLength() const = 0;

 protected:
  virtual void cipherHeader(
      folly::ByteRange sample,
      folly::MutableByteRange initialByte,
      folly::MutableByteRange packetNumberBytes,
      uint8_t initialByteMask,
      uint8_t packetNumLengthMask) const;

  virtual void decipherHeader(
      folly::ByteRange sample,
      folly::MutableByteRange initialByte,
      folly::MutableByteRange packetNumberBytes,
      uint8_t initialByteMask,
      uint8_t packetNumLengthMask) const;
};

class Aes128PacketNumberCipher : public PacketNumberCipher {
 public:
  ~Aes128PacketNumberCipher() override = default;

  void setKey(folly::ByteRange key) override;

  HeaderProtectionMask mask(folly::ByteRange sample) const override;

  size_t keyLength() const override;

 private:
  folly::ssl::EvpCipherCtxUniquePtr encryptCtx_;
};

class Aes256PacketNumberCipher : public PacketNumberCipher {
 public:
  ~Aes256PacketNumberCipher() override = default;

  void setKey(folly::ByteRange key) override;

  HeaderProtectionMask mask(folly::ByteRange sample) const override;

  size_t keyLength() const override;

 private:
  folly::ssl::EvpCipherCtxUniquePtr encryptCtx_;
};
} // namespace quic
