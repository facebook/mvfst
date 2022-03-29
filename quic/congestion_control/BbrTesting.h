/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#pragma once

#include <folly/TokenBucket.h>
#include <quic/congestion_control/Bbr.h>

namespace quic {

struct TokenBucketPolicyNoAlignNonConcurrent {
  using align = std::integral_constant<size_t, 0>;
  template <typename T>
  using atom = std::atomic<T>;
  using clock = std::chrono::steady_clock;
  using concurrent = std::false_type;
};

struct SimulatedTBF {
  SimulatedTBF(uint64_t rate, uint64_t burst)
      : rateBytesPerSecond(rate), burstBytes(burst), tbf() {}

  const uint64_t rateBytesPerSecond;
  const uint64_t burstBytes;
  // Number of times TBF correctly predicted network behavior
  uint64_t correctPredictionCount{0};
  // Number of times TBF incorrectly predicted network behavior
  uint64_t incorrectPredictionCount{0};
  // Number of times TBF predicted there would be no capacity
  uint64_t noCapacityPredictionCount{0};
  // Probability percent that this TBF is in the network path
  uint64_t probability{0};

  folly::BasicDynamicTokenBucket<TokenBucketPolicyNoAlignNonConcurrent> tbf;
};

// A congestion controller for testing modifications to the base BBR
// implementation
class BbrTestingCongestionController : public BbrCongestionController {
 public:
  explicit BbrTestingCongestionController(QuicConnectionStateBase& conn);

  void onPacketSent(const OutstandingPacket& packet) override;
  void onPacketAckOrLoss(
      const AckEvent* FOLLY_NULLABLE ackEvent,
      const LossEvent* FOLLY_NULLABLE lossEvent) override;

 private:
  [[nodiscard]] Bandwidth bandwidth() const noexcept override;

  std::vector<SimulatedTBF> simulatedTBFVec_;
  // for outstanding appdata packets, for each simulated TBF,
  // whether the token bucket predicted there would be tokens
  folly::F14FastMap<PacketNum, std::vector<bool>>
      outstandingPacketTBFStatusMap_;
};
} // namespace quic
