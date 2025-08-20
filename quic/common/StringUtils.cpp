/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <quic/common/StringUtils.h>

#include <quic/QuicConstants.h>
#include <array>

namespace quic {

std::string hexlify(const std::string& input) {
  std::string output;

  static char hexValues[] = "0123456789abcdef";
  auto j = output.size();
  output.resize(2 * input.size() + output.size());
  for (size_t i = 0; i < input.size(); ++i) {
    int ch = input[i];
    output[j++] = hexValues[(ch >> 4) & 0xf];
    output[j++] = hexValues[ch & 0xf];
  }
  return output;
}

quic::Expected<std::string, QuicError> unhexlify(const std::string& input) {
  // Input must have even length
  if (input.size() % 2 != 0) {
    return quic::make_unexpected(QuicError(
        QuicErrorCode(TransportErrorCode::INTERNAL_ERROR),
        "Input string must have even length"));
  }

  // Create hex lookup table.
  static const auto hexTable = []() {
    std::array<unsigned char, 256> table{};
    // Initialize all values to 16 (invalid)
    for (size_t i = 0; i < 256; ++i) {
      table[i] = 16;
    }
    // Set valid hex characters
    for (unsigned char i = 0; i <= 9; ++i) {
      table['0' + i] = i;
    }
    for (unsigned char i = 0; i <= 5; ++i) {
      table['a' + i] = 10 + i;
      table['A' + i] = 10 + i;
    }
    return table;
  }();

  std::string output;
  output.resize(input.size() / 2);
  size_t j = 0;

  for (size_t i = 0; i < input.size(); i += 2) {
    unsigned char highBits = hexTable[static_cast<uint8_t>(input[i])];
    unsigned char lowBits = hexTable[static_cast<uint8_t>(input[i + 1])];

    // Check if either character is not a valid hex digit
    if ((highBits | lowBits) & 0x10) {
      return quic::make_unexpected(QuicError(
          QuicErrorCode(TransportErrorCode::INTERNAL_ERROR),
          "Invalid hex character in input string"));
    }

    output[j++] = static_cast<char>((highBits << 4) + lowBits);
  }

  return output;
}

} // namespace quic
