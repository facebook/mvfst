/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#pragma once

#include <folly/Expected.h>
#include <folly/Optional.h>
#include <folly/String.h>
#include <folly/io/Cursor.h>
#include <folly/lang/Bits.h>
#include <quic/QuicException.h>
#include <quic/common/BufUtil.h>

namespace quic {

constexpr uint64_t kOneByteLimit = 0x3F;
constexpr uint64_t kTwoByteLimit = 0x3FFF;
constexpr uint64_t kFourByteLimit = 0x3FFFFFFF;
constexpr uint64_t kEightByteLimit = 0x3FFFFFFFFFFFFFFF;

namespace {
template <typename BufOp>
inline uint8_t encodeOneByte(BufOp bufop, uint64_t value) {
  auto modified = static_cast<uint8_t>(value);
  bufop(modified);
  return sizeof(modified);
}

template <typename BufOp>
inline uint16_t encodeTwoBytes(BufOp bufop, uint64_t value) {
  auto reduced = static_cast<uint16_t>(value);
  uint16_t modified = reduced | 0x4000;
  bufop(modified);
  return sizeof(modified);
}

template <typename BufOp>
inline uint32_t encodeFourBytes(BufOp bufop, uint64_t value) {
  auto reduced = static_cast<uint32_t>(value);
  uint32_t modified = reduced | 0x80000000;
  bufop(modified);
  return sizeof(modified);
}

template <typename BufOp>
inline uint64_t encodeEightBytes(BufOp bufop, uint64_t value) {
  uint64_t modified = value | 0xC000000000000000;
  bufop(modified);
  return sizeof(modified);
}
} // namespace

/**
 * Encodes the integer and writes it out to appender. Returns the number of
 * bytes written, or an error if value is too large to be represented with the
 * variable length encoding.
 */
template <typename BufOp>
folly::Expected<size_t, TransportErrorCode> encodeQuicInteger(
    uint64_t value,
    BufOp bufop) {
  if (value <= kOneByteLimit) {
    return encodeOneByte(std::move(bufop), value);
  } else if (value <= kTwoByteLimit) {
    return encodeTwoBytes(std::move(bufop), value);
  } else if (value <= kFourByteLimit) {
    return encodeFourBytes(std::move(bufop), value);
  } else if (value <= kEightByteLimit) {
    return encodeEightBytes(std::move(bufop), value);
  }
  return folly::makeUnexpected(TransportErrorCode::INTERNAL_ERROR);
}

template <typename BufOp>
folly::Expected<size_t, TransportErrorCode>
encodeQuicInteger(uint64_t value, BufOp bufop, int outputSize) {
  switch (outputSize) {
    case 1:
      CHECK(value <= kOneByteLimit);
      return encodeOneByte(std::move(bufop), value);
    case 2:
      CHECK(value <= kTwoByteLimit);
      return encodeTwoBytes(std::move(bufop), value);
    case 4:
      CHECK(value <= kFourByteLimit);
      return encodeFourBytes(std::move(bufop), value);
    case 8:
      CHECK(value <= kEightByteLimit);
      return encodeEightBytes(std::move(bufop), value);
  }
  return folly::makeUnexpected(TransportErrorCode::INTERNAL_ERROR);
}

/**
 * Reads an integer out of the cursor and returns a pair with the integer and
 * the numbers of bytes read, or folly::none if there are not enough bytes to
 * read the int. It only advances the cursor in case of success.
 */
folly::Optional<std::pair<uint64_t, size_t>> decodeQuicInteger(
    folly::io::Cursor& cursor,
    uint64_t atMost = sizeof(uint64_t));

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
  template <typename BufOp>
  size_t encode(BufOp appender) const {
    auto size = encodeQuicInteger(value_, std::move(appender));
    if (size.hasError()) {
      LOG(ERROR) << "Value too large value=" << value_;
      throw QuicTransportException(
          folly::to<std::string>("Value too large ", value_), size.error());
    }
    return size.value();
  }

  template <typename BufOp>
  size_t encode(BufOp appender, int outputSize) const {
    auto size = encodeQuicInteger(value_, std::move(appender), outputSize);
    if (size.hasError()) {
      LOG(ERROR) << "Value too large value=" << value_;
      throw QuicTransportException(
          folly::to<std::string>("Value too large ", value_), size.error());
    }
    return size.value();
  }

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
