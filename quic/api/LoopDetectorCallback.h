/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#pragma once

#include <quic/QuicConstants.h>

namespace quic {

class LoopDetectorCallback {
 public:
  virtual ~LoopDetectorCallback() = default;

  virtual void onSuspiciousWriteLoops(
      uint64_t emptyLoopCount,
      WriteDataReason writeReason,
      NoWriteReason noWriteReason,
      const std::string& scheduler) = 0;

  virtual void onSuspiciousReadLoops(
      uint64_t emptyLoopCount,
      NoReadReason noReadReason) = 0;
};

} // namespace quic
