/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#pragma once

#include <folly/io/Cursor.h>
#include <quic/common/BufUtil.h>
#include <quic/common/Optional.h>

namespace quic {

using HeaderProtectionMask = std::array<uint8_t, 16>;
using Sample = std::array<uint8_t, 16>;

class PacketNumberCipher {
 public:
  virtual ~PacketNumberCipher() = default;

  virtual void setKey(ByteRange key) = 0;

  virtual HeaderProtectionMask mask(ByteRange sample) const = 0;

  /**
   * Decrypts a long header from a sample.
   * sample should be 16 bytes long.
   * initialByte is the initial byte.
   * packetNumberBytes should be supplied with at least 4 bytes.
   */
  virtual void decryptLongHeader(
      ByteRange sample,
      folly::MutableByteRange initialByte,
      folly::MutableByteRange packetNumberBytes) const;

  /**
   * Decrypts a short header from a sample.
   * sample should be 16 bytes long.
   * initialByte is the initial byte.
   * packetNumberBytes should be supplied with at least 4 bytes.
   */
  virtual void decryptShortHeader(
      ByteRange sample,
      folly::MutableByteRange initialByte,
      folly::MutableByteRange packetNumberBytes) const;

  /**
   * Encrypts a long header from a sample.
   * sample should be 16 bytes long.
   * initialByte is the initial byte.
   */
  virtual void encryptLongHeader(
      ByteRange sample,
      folly::MutableByteRange initialByte,
      folly::MutableByteRange packetNumberBytes) const;

  /**
   * Encrypts a short header from a sample.
   * sample should be 16 bytes long.
   * initialByte is the initial byte.
   */
  virtual void encryptShortHeader(
      ByteRange sample,
      folly::MutableByteRange initialByte,
      folly::MutableByteRange packetNumberBytes) const;

  /**
   * Returns the length of key needed for the pn cipher.
   */
  virtual size_t keyLength() const = 0;

  /**
   * Get the packet protection key
   */
  virtual const BufPtr& getKey() const = 0;

 protected:
  virtual void cipherHeader(
      ByteRange sample,
      folly::MutableByteRange initialByte,
      folly::MutableByteRange packetNumberBytes,
      uint8_t initialByteMask,
      uint8_t packetNumLengthMask) const;

  virtual void decipherHeader(
      ByteRange sample,
      folly::MutableByteRange initialByte,
      folly::MutableByteRange packetNumberBytes,
      uint8_t initialByteMask,
      uint8_t packetNumLengthMask) const;
};

} // namespace quic
