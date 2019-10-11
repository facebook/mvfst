/*
 * Copyright (c) Facebook, Inc. and its affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 *
 */

#include <quic/congestion_control/Bandwidth.h>

namespace quic {
bool operator<(const Bandwidth& lhs, const Bandwidth& rhs) {
  return !(lhs >= rhs);
}

bool operator<=(const Bandwidth& lhs, const Bandwidth& rhs) {
  return lhs < rhs || lhs == rhs;
}

bool operator>(const Bandwidth& lhs, const Bandwidth& rhs) {
  if (lhs.bytes == 0 && rhs.bytes > 0) {
    return false;
  }
  if (lhs.bytes > 0 && rhs.bytes == 0) {
    return true;
  }
  return lhs.bytes * rhs.interval > rhs.bytes * lhs.interval;
}

bool operator>=(const Bandwidth& lhs, const Bandwidth& rhs) {
  return lhs > rhs || lhs == rhs;
}

bool operator==(const Bandwidth& lhs, const Bandwidth& rhs) {
  if (lhs.bytes == 0 && rhs.bytes > 0) {
    return false;
  }
  if (rhs.bytes == 0 && lhs.bytes > 0) {
    return false;
  }
  return lhs.bytes * rhs.interval == rhs.bytes * lhs.interval;
}

std::ostream& operator<<(std::ostream& os, const Bandwidth& bandwidth) {
  os << "bandwidth bytes=" << bandwidth.bytes
     << " interval=" << bandwidth.interval.count() << "us";
  return os;
}

uint64_t operator*(
    std::chrono::microseconds delay,
    const Bandwidth& bandwidth) {
  return bandwidth * delay;
}
} // namespace quic
