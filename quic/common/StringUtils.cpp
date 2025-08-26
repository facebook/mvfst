/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <quic/common/StringUtils.h>

#include <quic/QuicConstants.h>
#include <array>

#include <fmt/format.h>
#include <quic/common/StringUtils.h>

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

// There are two variants of `strerror_r` function, one returns
// `int`, and another returns `char*`. Selecting proper version using
// preprocessor macros portably is extremely hard.
//
// For example, on Android function signature depends on `__USE_GNU` and
// `__ANDROID_API__` macros (https://git.io/fjBBE).
//
// So we are using C++ overloading trick: we pass a pointer of
// `strerror_r` to `invoke_strerror_r` function, and C++ compiler
// selects proper function.

[[maybe_unused]] static std::string invoke_strerror_r(
    int (*strerror_r)(int, char*, size_t),
    int err,
    char* buf,
    size_t buflen) {
  // Using XSI-compatible strerror_r
  int r = strerror_r(err, buf, buflen);

  // OSX/FreeBSD use EINVAL and Linux uses -1 so just check for non-zero
  if (r != 0) {
    return fmt::format(
        "Unknown error {} (strerror_r failed with error {})", err, errno);
  } else {
    return buf;
  }
}

[[maybe_unused]] static std::string invoke_strerror_r(
    char* (*strerror_r)(int, char*, size_t),
    int err,
    char* buf,
    size_t buflen) {
  // Using GNU strerror_r
  return strerror_r(err, buf, buflen);
}

std::string errnoStr(int err) {
  int savedErrno = errno;

  char buf[1024];
  buf[0] = '\0';

  std::string result;

  // https://developer.apple.com/library/mac/documentation/Darwin/Reference/ManPages/man3/strerror_r.3.html
  // http://www.kernel.org/doc/man-pages/online/pages/man3/strerror.3.html
#if defined(_WIN32) && (defined(__MINGW32__) || defined(_MSC_VER))
  // mingw64 has no strerror_r, but Windows has strerror_s, which C11 added
  // as well. So maybe we should use this across all platforms (together
  // with strerrorlen_s). Note strerror_r and _s have swapped args.
  int r = strerror_s(buf, sizeof(buf), err);
  if (r != 0) {
    result = fmt::format(
        "Unknown error {} (strerror_r failed with error {})", err, errno);
  } else {
    result.assign(buf);
  }
#else
  // Using any strerror_r
  result.assign(invoke_strerror_r(strerror_r, err, buf, sizeof(buf)));
#endif

  errno = savedErrno;

  return result;
}

} // namespace quic
