/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <chrono>
#include <cmath>
#include <ostream>

#pragma once

namespace quic {

using namespace std::chrono_literals;

struct Bandwidth {
  enum class UnitType : uint8_t {
    BYTES,
    PACKETS,
  };

  uint64_t units{0};
  std::chrono::microseconds interval{0us};
  UnitType unitType{UnitType::BYTES};
  bool isAppLimited{false};

  explicit Bandwidth()
      : units(0), interval(std::chrono::microseconds::zero()) {}

  explicit Bandwidth(
      uint64_t unitsDelievered,
      std::chrono::microseconds deliveryInterval,
      bool appLimited = false)
      : units(unitsDelievered),
        interval(deliveryInterval),
        isAppLimited(appLimited) {}

  explicit Bandwidth(
      uint64_t unitsDelievered,
      std::chrono::microseconds deliveryInterval,
      UnitType unitTypeIn,
      bool appLimited = false)
      : units(unitsDelievered),
        interval(deliveryInterval),
        unitType(unitTypeIn),
        isAppLimited(appLimited) {}

  explicit operator bool() const noexcept {
    return units != 0 && interval != 0us;
  }

  template <
      typename T,
      typename = std::enable_if_t<std::is_arithmetic<T>::value>>
  const Bandwidth operator*(T t) const noexcept {
    return Bandwidth(std::ceil(units * t), interval, unitType, isAppLimited);
  }

  template <typename T, typename = std::enable_if_t<std::is_integral<T>::value>>
  const Bandwidth operator/(T t) const noexcept {
    return Bandwidth(units / t, interval, unitType, isAppLimited);
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
    isAppLimited |= other.isAppLimited;
    return *this;
  }

  Bandwidth operator+(const Bandwidth& other) {
    Bandwidth result(normalize(), 1s, unitType, isAppLimited);
    result.units += other.normalize();
    isAppLimited |= other.isAppLimited;
    return result;
  }

  std::string describe() const noexcept;
  std::string normalizedDescribe() const noexcept;

 private:
  std::string unitName() const noexcept;
};

bool operator<(const Bandwidth& lhs, const Bandwidth& rhs);
bool operator<=(const Bandwidth& lhs, const Bandwidth& rhs);
bool operator>(const Bandwidth& lhs, const Bandwidth& rhs);
bool operator>=(const Bandwidth& lhs, const Bandwidth& rhs);
bool operator==(const Bandwidth& lhs, const Bandwidth& rhs);

template <typename T, typename = std::enable_if_t<std::is_arithmetic<T>::value>>
Bandwidth operator*(T t, const Bandwidth& bandwidth) noexcept;

uint64_t operator*(std::chrono::microseconds delay, const Bandwidth& bandwidth);
std::ostream& operator<<(std::ostream& os, const Bandwidth& bandwidth);
} // namespace quic
