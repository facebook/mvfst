/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#pragma once

#include <quic/d6d/ProbeSizeRaiser.h>

namespace quic {

/**
 * A very naive constant step probe size raiser that does not care
 * about any upper bound, because that's already controlled by d6d
 * state functions.
 **/
class ConstantStepProbeSizeRaiser : public ProbeSizeRaiser {
 public:
  explicit ConstantStepProbeSizeRaiser(uint16_t stepSize)
      : stepSize_(stepSize) {}

  // Do nothing
  void onProbeLost(uint16_t /* lastProbeSize */) override {}

  folly::Optional<uint16_t> raiseProbeSize(uint16_t lastProbeSize) override {
    return lastProbeSize + stepSize_;
  }

 private:
  uint16_t stepSize_;
};

} // namespace quic
