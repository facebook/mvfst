/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#pragma once

#include <folly/io/SocketOptionMap.h>
#include <quic/congestion_control/CongestionController.h>
#include <quic/state/OutstandingPacket.h>
#include <quic/state/PacketEvent.h>

namespace quic {

class PacketProcessor {
 public:
  struct PrewriteRequest {
    folly::Optional<folly::SocketCmsgMap> cmsgs;
  };

  virtual ~PacketProcessor() = default;

  /**
   * Called before a write loop start. The returned PrewriteRequest
   * will apply to that write loop only.
   */
  virtual folly::Optional<PrewriteRequest> prewrite() {
    return folly::none;
  }

  /**
   * Called each time a packet is sent.
   *
   * Every call to onPacketSent() will (eventually) trigger a corresponding call
   * to onPacketDestroyed(), q.v.
   */
  virtual void onPacketSent(const OutstandingPacketWrapper& /* packet */) {}

  /**
   * Called when an OutstandingPacket is ACKed.
   */
  virtual void onPacketAck(const AckEvent* FOLLY_NULLABLE /* ackEvent */) {}

  /**
   * Called when an OutstandingPacket is being destroyed.
   *
   * Knowing when the OutstandingPacket is destroyed enables processors
   * to know when the transport has stopped tracking a packet. This can be
   * useful for a number of reasons. For example:
   *
   *  - When an OutstandingPacket is marked lost it is not immediately
   *    destroyed. Instead, the packet remains alive for some period to
   *    provide an opportunity for spurious loss detection. This callback
   *    enables processors to know when such an opportunity has expired.
   *
   *  - When an OutstandingPacket is destroyed, its metadata can be reviewed by
   *    processors to understand what the packet experienced, including
   *    information about its corresponding AckEvents and LossEvents.
   */
  virtual void onPacketDestroyed(const OutstandingPacketWrapper& /* packet */) {
  }
};
} // namespace quic
