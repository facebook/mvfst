/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <quic/congestion_control/BbrTesting.h>

namespace quic {

// If draining or cruising, use the latest bandwidth sample instead of the
// one from the sampler's max filter
Bandwidth BbrTestingCongestionController::bandwidth() const noexcept {
  if (bandwidthSampler_) {
    auto latest = state_ == BbrState::Drain || pacingGain_ == 1.0f;
    return latest ? bandwidthSampler_->getLatestSample()
                  : bandwidthSampler_->getBandwidth();
  } else {
    return Bandwidth();
  }
}
} // namespace quic
