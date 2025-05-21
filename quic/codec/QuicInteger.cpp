/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <quic/codec/QuicInteger.h>

namespace quic {

folly::Expected<size_t, QuicError> getQuicIntegerSize(uint64_t value) {
  if (value <= kOneByteLimit) {
    return 1;
  } else if (value <= kTwoByteLimit) {
    return 2;
  } else if (value <= kFourByteLimit) {
    return 4;
  } else if (value <= kEightByteLimit) {
    return 8;
  }
  return folly::makeUnexpected(
      QuicError(TransportErrorCode::INTERNAL_ERROR, "Cannot encode value"));
}

uint8_t decodeQuicIntegerLength(uint8_t firstByte) {
  return (1 << ((firstByte >> 6) & 0x03));
}

Optional<std::pair<uint64_t, size_t>> decodeQuicInteger(
    Cursor& cursor,
    uint64_t atMost) {
  // checks
  if (atMost == 0 || !cursor.canAdvance(1)) {
    VLOG(10) << "Not enough bytes to decode integer, cursor len="
             << cursor.totalLength();
    return std::nullopt;
  }

  // get 2 msb of first byte that determines variable-length size expected
  const uint8_t firstByte = *cursor.peekBytes().data();
  const uint8_t varintType = (firstByte >> 6) & 0x03;
  const uint8_t bytesExpected = (1 << varintType);

  // simple short-circuit eval for varint type == 0
  if (varintType == 0) {
    cursor.skip(1);
    return std::pair<uint64_t, size_t>(firstByte & 0x3f, 1);
  }

  // not enough bytes to decode, undo cursor
  if (!cursor.canAdvance(bytesExpected) || atMost < bytesExpected) {
    VLOG(10) << "Could not decode integer numBytes=" << bytesExpected;
    return std::nullopt;
  }
  // result storage
  uint64_t result{0};
  // pull number of bytes expected
  cursor.pull(&result, bytesExpected);
  // clear 2msb bits
  constexpr uint64_t msbMask = ~(0b11ull << 62);
  result = folly::Endian::big(result) & msbMask;
  // adjust quic integer
  result >>= (8 - bytesExpected) << 3;

  return std::pair<uint64_t, size_t>{result, bytesExpected};
}

QuicInteger::QuicInteger(uint64_t value) : value_(value) {}

folly::Expected<size_t, QuicError> QuicInteger::getSize() const {
  auto size = getQuicIntegerSize(value_);
  if (size.hasError()) {
    LOG(ERROR) << "Value too large value=" << value_;
    std::string errorMsg = "Value too large ";
    errorMsg += std::to_string(value_);
    return folly::makeUnexpected(
        QuicError(TransportErrorCode::INTERNAL_ERROR, std::move(errorMsg)));
  }
  return size.value();
}

uint64_t QuicInteger::getValue() const {
  return value_;
}
} // namespace quic
