/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#pragma once

#include <quic/dsr/frontend/PacketBuilder.h>
#include <quic/server/state/ServerStateMachine.h>
#include <quic/state/StateData.h>

namespace quic {
class DSRStreamFrameScheduler {
 public:
  explicit DSRStreamFrameScheduler(QuicServerConnectionState& conn);

  FOLLY_NODISCARD bool hasPendingData() const;

  struct SchedulingResult {
    bool writeSuccess{false};
    DSRPacketizationRequestSender* sender{nullptr};

    explicit SchedulingResult(
        bool written,
        DSRPacketizationRequestSender* senderIn)
        : writeSuccess(written), sender(senderIn) {}

    SchedulingResult() : writeSuccess(false), sender(nullptr) {}
  };

  // Write a single stream's data into builder.
  SchedulingResult writeStream(DSRPacketBuilderBase& builder);

 private:
  void enrichInstruction(
      SendInstruction::Builder& builder,
      const QuicStreamState& stream);
  SchedulingResult enrichAndAddSendInstruction(
      uint32_t,
      SchedulingResult,
      DSRPacketBuilderBase&,
      SendInstruction::Builder&,
      const PriorityQueue&,
      const PriorityQueue::LevelItr&,
      QuicStreamState&);

 private:
  QuicServerConnectionState& conn_;
  bool nextStreamNonDsr_{false};
};
} // namespace quic
