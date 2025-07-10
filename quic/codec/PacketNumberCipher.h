/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#pragma once

#include <folly/Unit.h>
#include <folly/io/Cursor.h>
#include <quic/QuicException.h>
#include <quic/common/BufUtil.h>
#include <quic/common/Expected.h>
#include <quic/common/Optional.h>

namespace quic {

using HeaderProtectionMask = std::array<uint8_t, 16>;
using Sample = std::array<uint8_t, 16>;

class PacketNumberCipher {
 public:
  virtual ~PacketNumberCipher() = default;

  [[nodiscard]] virtual quic::Expected<void, QuicError> setKey(
      ByteRange key) = 0;

  [[nodiscard]] virtual quic::Expected<HeaderProtectionMask, QuicError> mask(
      ByteRange sample) const = 0;

  /**
   * Decrypts a long header from a sample.
   * sample should be 16 bytes long.
   * initialByte is the initial byte.
   * packetNumberBytes should be supplied with at least 4 bytes.
   */
  [[nodiscard]] virtual quic::Expected<void, QuicError> decryptLongHeader(
      ByteRange sample,
      MutableByteRange initialByte,
      MutableByteRange packetNumberBytes) const;

  /**
   * Decrypts a short header from a sample.
   * sample should be 16 bytes long.
   * initialByte is the initial byte.
   * packetNumberBytes should be supplied with at least 4 bytes.
   */
  [[nodiscard]] virtual quic::Expected<void, QuicError> decryptShortHeader(
      ByteRange sample,
      MutableByteRange initialByte,
      MutableByteRange packetNumberBytes) const;

  /**
   * Encrypts a long header from a sample.
   * sample should be 16 bytes long.
   * initialByte is the initial byte.
   */
  [[nodiscard]] virtual quic::Expected<void, QuicError> encryptLongHeader(
      ByteRange sample,
      MutableByteRange initialByte,
      MutableByteRange packetNumberBytes) const;

  /**
   * Encrypts a short header from a sample.
   * sample should be 16 bytes long.
   * initialByte is the initial byte.
   */
  [[nodiscard]] virtual quic::Expected<void, QuicError> encryptShortHeader(
      ByteRange sample,
      MutableByteRange initialByte,
      MutableByteRange packetNumberBytes) const;

  /**
   * Returns the length of key needed for the pn cipher.
   */
  [[nodiscard]] virtual size_t keyLength() const = 0;

  /**
   * Get the packet protection key
   */
  [[nodiscard]] virtual const BufPtr& getKey() const = 0;

 protected:
  [[nodiscard]] virtual quic::Expected<void, QuicError> cipherHeader(
      ByteRange sample,
      MutableByteRange initialByte,
      MutableByteRange packetNumberBytes,
      uint8_t initialByteMask,
      uint8_t packetNumLengthMask) const;

  [[nodiscard]] virtual quic::Expected<void, QuicError> decipherHeader(
      ByteRange sample,
      MutableByteRange initialByte,
      MutableByteRange packetNumberBytes,
      uint8_t initialByteMask,
      uint8_t packetNumLengthMask) const;
};

} // namespace quic
