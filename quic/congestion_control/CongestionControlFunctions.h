/*
 * Copyright (c) Facebook, Inc. and its affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 *
 */

#pragma once

#include <quic/state/StateData.h>

#include <chrono>
#include <utility>

namespace quic {

uint64_t boundedCwnd(
    uint64_t cwndBytes,
    uint64_t packetLength,
    uint64_t maxCwndInMss,
    uint64_t minCwndInMss) noexcept;

std::pair<std::chrono::microseconds, uint64_t> calculatePacingRate(
    const QuicConnectionStateBase& conn,
    uint64_t cwnd,
    uint64_t minCwndInMss,
    std::chrono::microseconds rtt);

// TODO: Temporary wrapper to make the transition from CC doing pacing to
// the real pacer easier. Need to remove it after real pacer is used everywhere.
PacingRate calculatePacingRateWrapper(
    const QuicConnectionStateBase& conn,
    uint64_t cwnd,
    uint64_t minCwndInMss,
    std::chrono::microseconds rtt);

template <class T1, class T2>
void addAndCheckOverflow(T1& value, const T2& toAdd) {
  if (UNLIKELY(std::numeric_limits<T1>::max() - toAdd < value)) {
    // TODO: the error code is CWND_OVERFLOW but this function can totally be
    // used for inflight bytes.
    throw quic::QuicInternalException(
        "Overflow bytes in flight", quic::LocalErrorCode::CWND_OVERFLOW);
  }
  value += folly::to<T1>(toAdd);
}

template <class T1, class T2>
void subtractAndCheckUnderflow(T1& value, const T2& toSub) {
  if (UNLIKELY(value < toSub)) {
    // TODO: wrong error code
    throw quic::QuicInternalException(
        "Underflow bytes in flight", quic::LocalErrorCode::CWND_OVERFLOW);
  }
  value -= folly::to<T1>(toSub);
}
} // namespace quic
