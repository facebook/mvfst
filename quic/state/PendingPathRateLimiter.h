/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#pragma once
#include <folly/Optional.h>
#include <quic/QuicConstants.h>
#include <chrono>

namespace quic {

/**
 * As of d-23
 * https://tools.ietf.org/html/draft-ietf-quic-transport-23#section-9.3.1, an
 * endpoint must not send more than a minimum congestion window's worth of data
 * per esimtated rtt while handling a peer's migration before the path has been
 * validated.
 */
class PendingPathRateLimiter {
 public:
  explicit PendingPathRateLimiter(uint64_t udpSendPacketLen)
      : maxCredit_(kMinCwndInMss * udpSendPacketLen), credit_(maxCredit_) {}

  virtual ~PendingPathRateLimiter() = default;

  virtual uint64_t currentCredit(
      TimePoint checkTime,
      std::chrono::microseconds rtt) noexcept;

  virtual void onPacketSent(uint64_t sentBytes);

 private:
  const uint64_t maxCredit_;
  uint64_t credit_;
  folly::Optional<TimePoint> lastChecked_;
};

} // namespace quic
