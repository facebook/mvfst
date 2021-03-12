/*
 * Copyright (c) Facebook, Inc. and its affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 *
 */

#pragma once

#include <quic/dsr/PacketBuilder.h>
#include <quic/state/StateData.h>

namespace quic {
class DSRStreamFrameScheduler {
 public:
  explicit DSRStreamFrameScheduler(QuicConnectionStateBase& conn);

  FOLLY_NODISCARD bool hasPendingData() const;

  // Write a single stream's data into builder.
  bool writeStream(DSRPacketBuilderBase& builder);

 private:
  QuicConnectionStateBase& conn_;
};
} // namespace quic
