/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#pragma once

#include <quic/congestion_control/Bbr.h>

namespace quic {
// A congestion controller for testing modifications to the base BBR
// implementation
class BbrTestingCongestionController : public BbrCongestionController {
 public:
  explicit BbrTestingCongestionController(QuicConnectionStateBase& conn);
};
} // namespace quic
