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
  uint64_t units{0};
  std::chrono::microseconds interval{0us};

  explicit Bandwidth()
      : units(0),
        interval(std::chrono::microseconds::zero()),
        unitName_("bytes") {}

  explicit Bandwidth(
      uint64_t unitsDelievered,
      std::chrono::microseconds deliveryInterval)
      : units(unitsDelievered),
        interval(deliveryInterval),
        unitName_("bytes") {}

  explicit Bandwidth(
      uint64_t unitsDelievered,
      std::chrono::microseconds deliveryInterval,
      std::string unitName)
      : units(unitsDelievered),
        interval(deliveryInterval),
        unitName_(std::move(unitName)) {}

  explicit operator bool() const noexcept {
    return units != 0;
  }

  template <
      typename T,
      typename = std::enable_if_t<std::is_arithmetic<T>::value>>
  const Bandwidth operator*(T t) const noexcept {
    return Bandwidth(std::ceil(units * t), interval, unitName());
  }

  template <typename T, typename = std::enable_if_t<std::is_integral<T>::value>>
  const Bandwidth operator/(T t) const noexcept {
    return Bandwidth(units / t, interval, unitName());
  }

  uint64_t operator*(std::chrono::microseconds delay) const noexcept {
    return interval == std::chrono::microseconds::zero()
        ? 0
        : units * delay / interval;
  }

  // Return the number of units one can send over 1 seconds with the current
  // bandwidth value.
  // TODO: 1s may not be the best choice. It can overflow units.
  uint64_t normalize() const noexcept {
    return interval == 0us ? 0 : (1'000'000us * units / interval);
  }

  Bandwidth& operator+=(const Bandwidth& other) {
    units = normalize() + other.normalize();
    interval = 1s;
    return *this;
  }

  Bandwidth operator+(const Bandwidth& other) {
    Bandwidth result(normalize(), 1s, unitName());
    result.units += other.normalize();
    return result;
  }

  const std::string& unitName() const noexcept;

  std::string describe() const noexcept;
  std::string normalizedDescribe() const noexcept;

 private:
  std::string unitName_;
};

bool operator<(const Bandwidth& lhs, const Bandwidth& rhs);
bool operator<=(const Bandwidth& lhs, const Bandwidth& rhs);
bool operator>(const Bandwidth& lhs, const Bandwidth& rhs);
bool operator>=(const Bandwidth& lhs, const Bandwidth& rhs);
bool operator==(const Bandwidth& lhs, const Bandwidth& rhs);

uint64_t operator*(std::chrono::microseconds delay, const Bandwidth& bandwidth);
std::ostream& operator<<(std::ostream& os, const Bandwidth& bandwidth);
} // namespace quic
