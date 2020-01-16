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
#include <folly/lang/Bits.h>
#include <quic/QuicException.h>
#include <quic/common/BufUtil.h>

namespace quic {

constexpr uint64_t kOneByteLimit = 0x3F;
constexpr uint64_t kTwoByteLimit = 0x3FFF;
constexpr uint64_t kFourByteLimit = 0x3FFFFFFF;
constexpr uint64_t kEightByteLimit = 0x3FFFFFFFFFFFFFFF;

/**
 * Encodes the integer and writes it out to appender. Returns the number of
 * bytes written, or an error if value is too large to be represented with the
 * variable length encoding.
 */
folly::Expected<size_t, TransportErrorCode> encodeQuicInteger(
    uint64_t value,
    BufAppender& appender);

folly::Expected<size_t, TransportErrorCode> encodeQuicInteger(
    uint64_t value,
    folly::io::QueueAppender& appender);

/**
 * Reads an integer out of the cursor and returns a pair with the integer and
 * the numbers of bytes read, or folly::none if there are not enough bytes to
 * read the int. It only advances the cursor in case of success.
 */
folly::Optional<std::pair<uint64_t, size_t>> decodeQuicInteger(
    folly::io::Cursor& cursor,
    uint64_t atMost = std::numeric_limits<uint64_t>::max());

/**
 * Returns the length of a quic integer given the first byte
 */
uint8_t decodeQuicIntegerLength(uint8_t firstByte);

/**
 * Returns number of bytes needed to encode value as a QUIC integer, or an error
 * if value is too large to be represented with the variable
 * length encoding
 */
folly::Expected<size_t, TransportErrorCode> getQuicIntegerSize(uint64_t value);

/**
 * Returns number of bytes needed to encode value as a QUIC integer, or throws
 * an exception if value is too large to be represented with the variable
 * length encoding
 */
size_t getQuicIntegerSizeThrows(uint64_t value);

/**
 * A better API for dealing with QUIC integers for encoding.
 */
class QuicInteger {
 public:
  explicit QuicInteger(uint64_t value);

  /**
   * Encodes a QUIC integer to the appender.
   */
  size_t encode(BufAppender& appender) const;

  /**
   * Returns the number of bytes needed to represent the QUIC integer in
   * its encoded form.
   **/
  size_t getSize() const;

  /**
   * Returns the real value of the QUIC integer that it was instantiated with.
   * This should normally never be used.
   */
  uint64_t getValue() const;

 private:
  uint64_t value_;
};
} // namespace quic
