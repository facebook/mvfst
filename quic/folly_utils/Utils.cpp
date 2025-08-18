/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <quic/folly_utils/Utils.h>

namespace quic::follyutils {

Optional<std::pair<uint64_t, size_t>> decodeQuicInteger(
    folly::io::Cursor& cursor,
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

} // namespace quic::follyutils
