/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#pragma once

#include <quic/congestion_control/Bbr.h>
#include <quic/congestion_control/third_party/windowed_filter.h>
#include <quic/state/StateData.h>

namespace quic {

class BbrBandwidthSampler : public BbrCongestionController::BandwidthSampler {
 public:
  explicit BbrBandwidthSampler(QuicConnectionStateBase& conn);

  Bandwidth getBandwidth() const noexcept override;

  [[nodiscard]] Bandwidth getLatestSample() const noexcept override;

  void onPacketAcked(const CongestionController::AckEvent&, uint64_t rttCounter)
      override;

  /**
   * With BBR, app is no longer the only source of contributing to app-limited
   * state. BBR itself can choose to enter ProbeRTT state and limit its sending
   * rate. BandwidthSampler needs to consider both cases. So the BandwithSampler
   * will listens to app's notification on app-limited, but also needs to track
   * the second type of app-limited, and needs to make its own decision on when
   * to exit app-limited.
   */
  void onAppLimited() override;

  bool isAppLimited() const noexcept override;

  void setWindowLength(const uint64_t windowLength) noexcept override;

 private:
  QuicConnectionStateBase& conn_;
  WindowedFilter<Bandwidth, MaxFilter<Bandwidth>, uint64_t, uint64_t>
      windowedFilter_;
  Bandwidth latestSample_;
  bool appLimited_{false};

  // When a packet with a send time later than appLimitedExitTarget_ is acked,
  // an app-limited connection is considered no longer app-limited.
  TimePoint appLimitedExitTarget_;
};

} // namespace quic
