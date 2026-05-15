/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <quic/common/LinuxKernelVersion.h>

#ifdef __linux__
#include <sys/utsname.h>
#endif

#include <folly/synchronization/CallOnce.h>

#include <cctype>

namespace quic {

namespace detail {

Optional<std::pair<int, int>> parseLinuxKernelRelease(const char* release) {
  if (release == nullptr || *release == '\0') {
    return std::nullopt;
  }

  auto parseUnsignedDecimal = [](const char*& cursor) -> Optional<int> {
    if (!std::isdigit(static_cast<unsigned char>(*cursor))) {
      return std::nullopt;
    }
    int value = 0;
    while (std::isdigit(static_cast<unsigned char>(*cursor))) {
      int digit = *cursor - '0';
      if (value > (INT32_MAX - digit) / 10) {
        return std::nullopt;
      }
      value = value * 10 + digit;
      ++cursor;
    }
    return value;
  };

  const char* cursor = release;
  auto major = parseUnsignedDecimal(cursor);
  if (!major.has_value() || *cursor != '.') {
    return std::nullopt;
  }
  ++cursor;
  auto minor = parseUnsignedDecimal(cursor);
  if (!minor.has_value()) {
    return std::nullopt;
  }
  return std::make_pair(*major, *minor);
}

} // namespace detail

Optional<std::pair<int, int>> getLinuxKernelVersion() {
#ifdef __linux__
  static folly::once_flag onceFlag;
  static Optional<std::pair<int, int>> cached;
  folly::call_once(onceFlag, [] {
    struct utsname uts{};
    if (uname(&uts) == 0) {
      cached = detail::parseLinuxKernelRelease(uts.release);
    }
  });
  return cached;
#else
  return std::nullopt;
#endif
}

bool isLinuxKernelAtLeast(std::pair<int, int> minVersion) {
  auto version = getLinuxKernelVersion();
  if (!version.has_value()) {
    return false;
  }
  if (version->first != minVersion.first) {
    return version->first > minVersion.first;
  }
  return version->second >= minVersion.second;
}

} // namespace quic
