/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#pragma once

#include <folly/Optional.h>

namespace quic {

// Abstract class used for raising the probe size. Making it abstract so that
// applications can choose their own implementation
class ProbeSizeRaiser {
 public:
  virtual ~ProbeSizeRaiser() = default;

  // Notify the stepper that probe is lost, useful for updating its internal
  // state
  virtual void onProbeLost(uint16_t lastProbeSize) = 0;

  // Raise and returns the next probe size. Returns folly::none if the
  // raiser cannot do so
  virtual folly::Optional<uint16_t> raiseProbeSize(uint16_t lastProbeSize) = 0;
};

} // namespace quic
