/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#pragma once

#include <glog/logging.h>
#include <quic/d6d/ProbeSizeRaiser.h>

namespace quic {

class BinarySearchProbeSizeRaiser : public ProbeSizeRaiser {
 public:
  explicit BinarySearchProbeSizeRaiser(uint16_t minSize, uint16_t maxSize)
      : minSize_(minSize), maxSize_(maxSize) {}

  void onProbeLost(uint16_t lastProbeSize) override {
    if (!sanityCheck(lastProbeSize)) {
      return;
    }
    maxSize_ = lastProbeSize - 1;
  }

  folly::Optional<uint16_t> raiseProbeSize(uint16_t lastProbeSize) override {
    if (!sanityCheck(lastProbeSize)) {
      return folly::none;
    }
    minSize_ = lastProbeSize;
    if (minSize_ == maxSize_) {
      return folly::none;
    }
    return (minSize_ + maxSize_ + 1) / 2;
  }

 private:
  bool sanityCheck(uint16_t lastProbeSize) {
    if (lastProbeSize < minSize_) {
      VLOG(2)
          << __func__
          << " lastProbeSize is less than minSize, possibly re-odering, skipping";
      return false;
    }
    return true;
  }

  uint16_t minSize_;
  uint16_t maxSize_;
};

} // namespace quic
