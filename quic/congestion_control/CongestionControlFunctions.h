/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#pragma once

#include <quic/common/MvfstLogging.h>
#include <quic/state/StateData.h>

#include <chrono>

namespace quic {

uint64_t boundedCwnd(
    uint64_t cwndBytes,
    uint64_t packetLength,
    uint64_t maxCwndInMss,
    uint64_t minCwndInMss) noexcept;

PacingRate calculatePacingRate(
    const QuicConnectionStateBase& conn,
    uint64_t cwnd,
    uint64_t minCwndInMss,
    std::chrono::microseconds rtt);

template <class T1, class T2, class T3 = T1>
void addAndCheckOverflow(
    T1& value,
    const T2& toAdd,
    const T3& maxValue = std::numeric_limits<T1>::max()) {
  if (std::numeric_limits<T1>::max() - static_cast<T1>(toAdd) < value) {
    MVLOG_ERROR << "Overflow prevented, capping at max value";
    value = static_cast<T1>(maxValue);
  } else {
    T1 newValue = value + static_cast<T1>(toAdd);
    if (newValue > static_cast<T1>(maxValue)) {
      MVLOG_ERROR << "Value would exceed max limit, capping at max value";
      value = static_cast<T1>(maxValue);
    } else {
      value = newValue;
    }
  }
}

template <class T1, class T2, class T3 = T1>
void subtractAndCheckUnderflow(
    T1& value,
    const T2& toSub,
    const T3& minValue = 0) {
  if (value < static_cast<T1>(toSub)) {
    MVLOG_ERROR << "Underflow prevented, capping at min value";
    value = static_cast<T1>(minValue);
  } else {
    T1 newValue = value - static_cast<T1>(toSub);
    if (newValue < static_cast<T1>(minValue)) {
      MVLOG_ERROR << "Value would be below min limit, capping at min value";
      value = static_cast<T1>(minValue);
    } else {
      value = newValue;
    }
  }
}
} // namespace quic
