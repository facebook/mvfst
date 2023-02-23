/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#pragma once

#include <quic/QuicConstants.h>

namespace quic {

struct QuicStreamGroupRetransmissionPolicy {
  // Params controlling retransmission.
  DurationRep timeReorderingThreshDividend{
      kDefaultTimeReorderingThreshDividend};
  DurationRep timeReorderingThreshDivisor{kDefaultTimeReorderingThreshDivisor};
  uint32_t reorderingThreshold{kReorderingThreshold};

  // Disables retransmission. completely.
  bool disableRetransmission{false};
};

} // namespace quic
