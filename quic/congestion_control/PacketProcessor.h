/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#pragma once

#include <quic/congestion_control/CongestionController.h>
#include <quic/state/OutstandingPacket.h>
#include <quic/state/PacketEvent.h>

namespace quic {

class PacketProcessor {
 public:
  virtual ~PacketProcessor() = default;

  virtual void onPacketSent(const OutstandingPacket& packet) = 0;
  virtual void onPacketAck(const AckEvent* FOLLY_NULLABLE ackEvent) = 0;
};
} // namespace quic
