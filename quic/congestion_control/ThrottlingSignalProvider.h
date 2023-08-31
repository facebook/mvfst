/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#pragma once

#include <folly/Optional.h>

namespace quic {

class ThrottlingSignalProvider {
 public:
  struct ThrottlingSignal {
    enum class State { Unknown, Throttled, Unthrottled };
    // If a token bucket is found to be policing/shaping the connection, this
    // stores whether at the current time, the connection is being throttled (ie
    // the bucket ran out of tokens) or not.
    State state{State::Unknown};

    // The upper-bound on the amount of byte CCA can send at current time.
    // If a token bucket is found to be policing/shaping the connection, this
    // stores the amount of tokens currently available at throttler's bucket
    // and if the bucket is in debt, it stores zero.
    // Note that this value changes over time and may become stale quickly.
    folly::Optional<uint64_t> maybeBytesToSend;

    // The rate for which CCA can send bytes when the connection is being
    // throttled (ie when the bucket has no tokens).
    // Note that this value changes over time and may become stale quickly.
    folly::Optional<uint64_t> maybeThrottledRateBytesPerSecond;

    // The rate for which CCA can send bytes when the connection is not being
    // throttled (eg during burst or generally when the bucket has tokens).
    // Note that this value changes over time and may become stale quickly.
    folly::Optional<uint64_t> maybeUnthrottledRateBytesPerSecond;
  };

  virtual ~ThrottlingSignalProvider() = default;

  /*
   * Returns the current value of throttling signal, if exists.
   * Its return value changes over time and may become stale quickly.
   */
  virtual folly::Optional<ThrottlingSignal> getCurrentThrottlingSignal() = 0;
};

} // namespace quic
