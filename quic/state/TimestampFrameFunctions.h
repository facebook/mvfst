/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#pragma once

#include <quic/codec/Types.h>
#include <quic/state/StateData.h>

namespace quic {

class TimestampFramePacketObserver {
 public:
  void operator()(const QuicWriteFrame& frame) noexcept;

  [[nodiscard]] bool hasEligibleFrame() const noexcept {
    return hasEligibleFrame_;
  }

  [[nodiscard]] bool hasAckElicitingFrame() const noexcept {
    return hasAckElicitingFrame_;
  }

  [[nodiscard]] bool hasAckReceiveTimestamps() const noexcept {
    return hasAckReceiveTimestamps_;
  }

  [[nodiscard]] bool matchesPacketSelection(
      TimestampFramePacketSelection packetSelection) const noexcept;

 private:
  [[nodiscard]] static bool isEligibleFrame(
      const QuicWriteFrame& frame) noexcept;
  [[nodiscard]] static bool ackCarriesReceiveTimestamps(
      const WriteAckFrame& frame) noexcept;

  bool hasEligibleFrame_{false};
  bool hasAckElicitingFrame_{false};
  bool hasStreamFrame_{false};
  bool hasAckReceiveTimestamps_{false};
};

[[nodiscard]] bool shouldWriteOneRttTimestampFrame(
    const QuicConnectionStateBase& conn,
    bool ackReceiveTimestampsWritten);

[[nodiscard]] Optional<TimestampFrame> generateOneRttTimestampFrame(
    const QuicConnectionStateBase& conn);

} // namespace quic
