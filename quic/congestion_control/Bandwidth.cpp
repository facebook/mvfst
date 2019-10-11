/*
 * Copyright (c) Facebook, Inc. and its affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 *
 */

#include <quic/congestion_control/Bandwidth.h>
#include <folly/Conv.h>

namespace quic {
const std::string& Bandwidth::unitName() const noexcept {
  return unitName_;
}

std::string Bandwidth::conciseDescribe() const noexcept {
  return folly::to<std::string>(
      units, unitName_, " / ", interval.count(), "us");
}

bool operator<(const Bandwidth& lhs, const Bandwidth& rhs) {
  return !(lhs >= rhs);
}

bool operator<=(const Bandwidth& lhs, const Bandwidth& rhs) {
  return lhs < rhs || lhs == rhs;
}

bool operator>(const Bandwidth& lhs, const Bandwidth& rhs) {
  if (lhs.units == 0 && rhs.units > 0) {
    return false;
  }
  if (lhs.units > 0 && rhs.units == 0) {
    return true;
  }
  return lhs.units * rhs.interval > rhs.units * lhs.interval;
}

bool operator>=(const Bandwidth& lhs, const Bandwidth& rhs) {
  return lhs > rhs || lhs == rhs;
}

bool operator==(const Bandwidth& lhs, const Bandwidth& rhs) {
  if (lhs.units == 0 && rhs.units > 0) {
    return false;
  }
  if (rhs.units == 0 && lhs.units > 0) {
    return false;
  }
  return lhs.units * rhs.interval == rhs.units * lhs.interval;
}

std::ostream& operator<<(std::ostream& os, const Bandwidth& bandwidth) {
  os << "bandwidth " << bandwidth.unitName() << "=" << bandwidth.units
     << " interval=" << bandwidth.interval.count() << "us";
  return os;
}

uint64_t operator*(
    std::chrono::microseconds delay,
    const Bandwidth& bandwidth) {
  return bandwidth * delay;
}
} // namespace quic
