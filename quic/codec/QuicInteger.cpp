/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <quic/codec/QuicInteger.h>

#include <folly/Conv.h>

namespace quic {

folly::Expected<size_t, TransportErrorCode> getQuicIntegerSize(uint64_t value) {
  if (value <= kOneByteLimit) {
    return 1;
  } else if (value <= kTwoByteLimit) {
    return 2;
  } else if (value <= kFourByteLimit) {
    return 4;
  } else if (value <= kEightByteLimit) {
    return 8;
  }
  return folly::makeUnexpected(TransportErrorCode::INTERNAL_ERROR);
}

size_t getQuicIntegerSizeThrows(uint64_t value) {
  if (value <= kOneByteLimit) {
    return 1;
  } else if (value <= kTwoByteLimit) {
    return 2;
  } else if (value <= kFourByteLimit) {
    return 4;
  } else if (value <= kEightByteLimit) {
    return 8;
  }
  throw QuicTransportException(
      folly::to<std::string>("Value too large: ", value),
      TransportErrorCode::INTERNAL_ERROR);
}

uint8_t decodeQuicIntegerLength(uint8_t firstByte) {
  return (1 << ((firstByte >> 6) & 0x03));
}

folly::Optional<std::pair<uint64_t, size_t>> decodeQuicInteger(
    folly::io::Cursor& cursor,
    uint64_t atMost) {
  size_t numBytes = 0;
  size_t advanceLen = 0;
  uint64_t result = 0;

  if (atMost < 1 || !cursor.canAdvance(1)) {
    VLOG(10) << "Not enough bytes to decode integer, cursor len="
             << cursor.totalLength();
    return folly::none;
  }
  const uint8_t firstByte = *cursor.peekBytes().data();
  const uint8_t varintType = (firstByte >> 6) & 0x03;
  const uint8_t unmaskedFirstByte = firstByte & 0x3F;
  uint8_t* resultPtr = reinterpret_cast<uint8_t*>(&result);

  switch (varintType) {
    case 0:
      // short circuit for 1 byte.
      cursor.skip(1);
      return std::make_pair((uint64_t)unmaskedFirstByte, (size_t)1);
    case 1:
      advanceLen = 6;
      numBytes = 1;
      break;
    case 2:
      advanceLen = 4;
      numBytes = 3;
      break;
    case 3:
      numBytes = 7;
      break;
  }
  if (atMost < (numBytes + 1) || !cursor.canAdvance(numBytes + 1)) {
    VLOG(10) << "Could not decode integer numBytes="
             << static_cast<int>(numBytes + 1) << " firstByte=" << std::hex
             << static_cast<int>(firstByte);
    return folly::none;
  }
  cursor.skip(1);
  memcpy(resultPtr + advanceLen, &unmaskedFirstByte, 1);
  cursor.pull(resultPtr + advanceLen + 1, numBytes);
  // make the data dependency on resultPtr explicit to avoid strict
  // aliasing issues.
  return std::make_pair(
      folly::Endian::big(*reinterpret_cast<uint64_t*>(resultPtr)),
      numBytes + 1);
}

QuicInteger::QuicInteger(uint64_t value) : value_(value) {}

size_t QuicInteger::getSize() const {
  auto size = getQuicIntegerSize(value_);
  if (size.hasError()) {
    LOG(ERROR) << "Value too large value=" << value_;
    throw QuicTransportException(
        folly::to<std::string>("Value too large ", value_), size.error());
  }
  return size.value();
}

uint64_t QuicInteger::getValue() const {
  return value_;
}
} // namespace quic
