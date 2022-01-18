/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <quic/congestion_control/Bandwidth.h>

#include <folly/Conv.h>

namespace quic {

std::string Bandwidth::unitName() const noexcept {
  switch (unitType) {
    case UnitType::BYTES:
      return "bytes";
    case UnitType::PACKETS:
      return "packets";
  }
  folly::assume_unreachable();
}

std::string Bandwidth::describe() const noexcept {
  return folly::to<std::string>(
      units, unitName(), " / ", interval.count(), "us");
}

std::string Bandwidth::normalizedDescribe() const noexcept {
  return folly::to<std::string>(normalize(), unitName(), " / s");
}

bool operator<(const Bandwidth& lhs, const Bandwidth& rhs) {
  return !(lhs >= rhs);
}

bool operator<=(const Bandwidth& lhs, const Bandwidth& rhs) {
  return (lhs < rhs) || (lhs == rhs);
}

bool operator>(const Bandwidth& lhs, const Bandwidth& rhs) {
  if (!lhs && !rhs) {
    return false;
  }
  if (!lhs && rhs) {
    return false;
  }
  if (lhs && !rhs) {
    return true;
  }
  return (lhs.units * rhs.interval) > (rhs.units * lhs.interval);
}

bool operator>=(const Bandwidth& lhs, const Bandwidth& rhs) {
  return (lhs > rhs) || (lhs == rhs);
}

bool operator==(const Bandwidth& lhs, const Bandwidth& rhs) {
  if (!lhs && !rhs) {
    return true;
  }
  if (!lhs || !rhs) {
    return false;
  }
  return (lhs.units * rhs.interval) == (rhs.units * lhs.interval);
}

std::ostream& operator<<(std::ostream& os, const Bandwidth& bandwidth) {
  os << bandwidth.describe();
  return os;
}

uint64_t operator*(
    std::chrono::microseconds delay,
    const Bandwidth& bandwidth) {
  return bandwidth * delay;
}
} // namespace quic
