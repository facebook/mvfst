/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <quic/state/TimestampFrameFunctions.h>

#include <algorithm>
#include <chrono>

#include <quic/QuicConstants.h>

namespace quic {

void TimestampFramePacketObserver::operator()(
    const QuicWriteFrame& frame) noexcept {
  const bool isEligible = isEligibleFrame(frame);
  const auto* ackFrame = frame.asWriteAckFrame();
  hasEligibleFrame_ |= isEligible;
  hasAckElicitingFrame_ |= isEligible && !ackFrame;
  hasStreamFrame_ |= frame.type() == QuicWriteFrame::Type::WriteStreamFrame;
  if (ackFrame) {
    hasAckReceiveTimestamps_ |= ackCarriesReceiveTimestamps(*ackFrame);
  }
}

bool TimestampFramePacketObserver::matchesPacketSelection(
    TimestampFramePacketSelection packetSelection) const noexcept {
  switch (packetSelection) {
    case TimestampFramePacketSelection::AllEligiblePackets:
      return hasEligibleFrame_;
    case TimestampFramePacketSelection::AckElicitingPackets:
      return hasAckElicitingFrame_;
    case TimestampFramePacketSelection::StreamPackets:
      return hasStreamFrame_;
  }
  folly::assume_unreachable();
}

bool TimestampFramePacketObserver::isEligibleFrame(
    const QuicWriteFrame& frame) noexcept {
  switch (frame.type()) {
    case QuicWriteFrame::Type::PaddingFrame:
    case QuicWriteFrame::Type::ConnectionCloseFrame:
    case QuicWriteFrame::Type::NoopFrame:
    case QuicWriteFrame::Type::TimestampFrame:
      return false;
    case QuicWriteFrame::Type::RstStreamFrame:
    case QuicWriteFrame::Type::MaxDataFrame:
    case QuicWriteFrame::Type::MaxStreamDataFrame:
    case QuicWriteFrame::Type::DataBlockedFrame:
    case QuicWriteFrame::Type::StreamDataBlockedFrame:
    case QuicWriteFrame::Type::StreamsBlockedFrame:
    case QuicWriteFrame::Type::WriteStreamFrame:
    case QuicWriteFrame::Type::WriteCryptoFrame:
    case QuicWriteFrame::Type::QuicSimpleFrame:
    case QuicWriteFrame::Type::PingFrame:
    case QuicWriteFrame::Type::WriteAckFrame:
    case QuicWriteFrame::Type::DatagramFrame:
    case QuicWriteFrame::Type::ImmediateAckFrame:
      return true;
  }
  folly::assume_unreachable();
}

bool TimestampFramePacketObserver::ackCarriesReceiveTimestamps(
    const WriteAckFrame& frame) noexcept {
  if (frame.frameType == FrameType::ACK_RECEIVE_TIMESTAMPS ||
      frame.frameType == FrameType::ACK_RECEIVE_TIMESTAMPS_DRAFT_02 ||
      frame.frameType == FrameType::ACK_RECEIVE_TIMESTAMPS_DRAFT_02_ECN) {
    return true;
  }
  return frame.frameType == FrameType::ACK_EXTENDED &&
      frame.maybeLatestRecvdPacketTime.has_value();
}

bool shouldWriteOneRttTimestampFrame(
    const QuicConnectionStateBase& conn,
    bool ackReceiveTimestampsWritten) {
  const auto& settings = conn.transportSettings;
  if (settings.oneRttTimestampFrameWriteMode ==
          TimestampFrameWriteMode::Disabled ||
      !conn.peerTimestampFrameState.canReceive) {
    return false;
  }
  return !settings
              .suppressOneRttTimestampFrameWhenAckReceiveTimestampsWritten ||
      !ackReceiveTimestampsWritten;
}

Optional<TimestampFrame> generateOneRttTimestampFrame(
    const QuicConnectionStateBase& conn) {
  const auto now = Clock::now();
  if (now < conn.connectionTime) {
    return std::nullopt;
  }

  const auto timestamp = static_cast<uint64_t>(
      std::chrono::duration_cast<std::chrono::microseconds>(
          now - conn.connectionTime)
          .count());
  const auto exponent = std::min(
      conn.transportSettings.timestampFrameTimestampExponent,
      kMaxTimestampFrameTimestampExponent);
  return TimestampFrame(timestamp >> exponent);
}

} // namespace quic
