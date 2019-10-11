/*
 * Copyright (c) Facebook, Inc. and its affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 *
 */

#include <chrono>
#include <cmath>
#include <ostream>

#pragma once

namespace quic {

using namespace std::chrono_literals;

struct Bandwidth {
  uint64_t bytes;
  std::chrono::microseconds interval;

  explicit Bandwidth()
      : bytes(0), interval(std::chrono::microseconds::zero()) {}

  explicit Bandwidth(
      uint64_t bytesDelievered,
      std::chrono::microseconds deliveryInterval)
      : bytes(bytesDelievered), interval(deliveryInterval) {}

  explicit operator bool() const noexcept {
    return bytes != 0;
  }

  template <
      typename T,
      typename = std::enable_if_t<std::is_arithmetic<T>::value>>
  const Bandwidth operator*(T t) const noexcept {
    return Bandwidth(std::ceil(bytes * t), interval);
  }

  template <typename T, typename = std::enable_if_t<std::is_integral<T>::value>>
  const Bandwidth operator/(T t) const noexcept {
    return Bandwidth(bytes / t, interval);
  }

  uint64_t operator*(std::chrono::microseconds delay) const noexcept {
    return interval == std::chrono::microseconds::zero()
        ? 0
        : bytes * delay / interval;
  }
};

bool operator<(const Bandwidth& lhs, const Bandwidth& rhs);
bool operator<=(const Bandwidth& lhs, const Bandwidth& rhs);
bool operator>(const Bandwidth& lhs, const Bandwidth& rhs);
bool operator>=(const Bandwidth& lhs, const Bandwidth& rhs);
bool operator==(const Bandwidth& lhs, const Bandwidth& rhs);

uint64_t operator*(std::chrono::microseconds delay, const Bandwidth& bandwidth);
std::ostream& operator<<(std::ostream& os, const Bandwidth& bandwidth);
} // namespace quic
