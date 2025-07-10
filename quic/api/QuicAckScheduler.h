/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#pragma once

#include <quic/QuicConstants.h>
#include <quic/state/StateData.h>

namespace quic {

class AckScheduler {
 public:
  AckScheduler(const QuicConnectionStateBase& conn, const AckState& ackState);

  [[nodiscard]] quic::Expected<Optional<PacketNum>, QuicError> writeNextAcks(
      PacketBuilderInterface& builder);

  [[nodiscard]] bool hasPendingAcks() const;

 private:
  const QuicConnectionStateBase& conn_;
  const AckState& ackState_;
};

/**
 * Returns whether or not the Ack scheduler has acks to schedule. This does not
 * tell you when the ACKs can be written.
 */
bool hasAcksToSchedule(const AckState& ackState);

/**
 * Returns the largest packet received which needs to be acked.
 */
Optional<PacketNum> largestAckToSend(const AckState& ackState);

} // namespace quic
