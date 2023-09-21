/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#pragma once

#include <folly/Optional.h>
#include <quic/QuicConstants.h>

/**
 * Namespace for mvfst chrono types.
 *
 * Using a separate namespace for chrono types to minimize type conflicts in
 * tests and other code which may be using `using namespace quic` while also
 * having aliased chrono types.
 */
namespace quic::chrono {

/**
 * Container for storing SystemClock (assumed NTP corrected clock) TimePoints.
 */
struct SystemClockTimePointExt {
  // Raw TimePoint from a SystemClock (assumed NTP corrected clock).
  SystemClock::TimePoint raw;

  // TimePoint guarenteed to be >= previous TP recorded by the same process.
  //
  // SystemClock can go backwards due to NTP correction. This can be problematic
  // in code which assumes that event N+1 will have a timestamp >= event N. This
  // TimePoint field can be populated by a transformation process which ensures
  // that this TimePoint will be greater than or equal to all earlier TimePoint
  // processed by the same transformation process.
  //
  // We keep both the raw TimePoint and the transformed TimePoint to enable us
  // to measure the impact of said correction and for debugging purposes.
  folly::Optional<SystemClock::TimePoint> maybeMonotonic;
};

/**
 * Container for storing SystemClock and SteadyClock TimePoints.
 *
 * In most cases in the QUIC codebase, we want to use SteadyClock TimePoints.
 *
 * Use this container in cases where you need to store SystemClock TimePoints
 * (such as those received via socket RX timestamps) while also having
 * SteadyClock TimePoints to enable accurate relative time calculations.
 */
struct MultiClockTimePoints {
  SystemClockTimePointExt systemClock;
  SteadyClock::TimePoint steadyClock;
};

} // namespace quic::chrono
