/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#pragma once

#include <quic/state/StateData.h>

namespace quic {

/**
 * Returns a pair consisting of the length of the burst interval and the number
 * of packets in a burst interval.
 */
using PacingRateCalculator = folly::Function<PacingRate(
    const QuicConnectionStateBase&,
    uint64_t cwndBytes,
    uint64_t minCwndInMss,
    std::chrono::microseconds rtt)>;
} // namespace quic
