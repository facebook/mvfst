/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#pragma once

#include <folly/Traits.h>
#include <quic/QuicConstants.h>
#include <chrono>
#include <utility>

namespace quic {

// Base cases for time min and max.
template <class T>
T timeMin(T&& arg) {
  return arg;
}

template <class T>
T timeMax(T&& arg) {
  return arg;
}

/**
 * Returns the min of all the types that are passed in
 */
template <class T1, class... Args>
folly::remove_cvref_t<T1> timeMin(T1&& arg1, Args&&... args) {
  auto min = timeMin(std::forward<Args>(args)...);
  if (arg1 < min) {
    return arg1;
  }
  return min;
}

/**
 * Returns the max of all the types that are passed in
 */
template <class T1, class... Args>
folly::remove_cvref_t<T1> timeMax(T1&& arg1, Args&&... args) {
  auto max = timeMax(std::forward<Args>(args)...);
  if (arg1 > max) {
    return arg1;
  }
  return max;
}

template <typename T>
bool timePointInitialized(const T& time) {
  static T epoch;
  return time > epoch;
}

template <typename ClockType = std::chrono::steady_clock>
inline std::chrono::milliseconds millisecondsBetween(
    std::chrono::time_point<ClockType> finish,
    std::chrono::time_point<ClockType> start) {
  return std::chrono::duration_cast<std::chrono::milliseconds>(finish - start);
}

template <typename ClockType = std::chrono::steady_clock>
inline std::chrono::milliseconds millisecondsSince(
    std::chrono::time_point<ClockType> t) {
  return millisecondsBetween(ClockType::now(), t);
}

} // namespace quic
