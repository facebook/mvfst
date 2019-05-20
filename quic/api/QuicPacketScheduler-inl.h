/*
 * Copyright (c) Facebook, Inc. and its affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 *
 */

#include <quic/codec/QuicPacketRebuilder.h>
#include <quic/state/QuicStateFunctions.h>

namespace quic {

template <typename ClockType>
inline folly::Optional<PacketNum> AckScheduler::writeNextAcks(
    PacketBuilderInterface& builder,
    AckMode mode) {
  switch (mode) {
    case AckMode::Immediate: {
      return writeAcksImpl<ClockType>(builder);
    }
    case AckMode::Pending: {
      return writeAcksIfPending<ClockType>(builder);
    }
  }
  __builtin_unreachable();
}

template <typename ClockType>
inline folly::Optional<PacketNum> AckScheduler::writeAcksIfPending(
    PacketBuilderInterface& builder) {
  if (ackState_.needsToSendAckImmediately) {
    return writeAcksImpl<ClockType>(builder);
  }
  return folly::none;
}

template <typename ClockType>
folly::Optional<PacketNum> AckScheduler::writeAcksImpl(
    PacketBuilderInterface& builder) {
  // Use default ack delay for long headers. Usually long headers are sent
  // before crypto negotiation, so the peer might not know about the ack delay
  // exponent yet, so we use the default.
  uint8_t ackDelayExponentToUse = folly::variant_match(
      builder.getPacketHeader(),
      [](const LongHeader&) { return kDefaultAckDelayExponent; },
      [&](const auto&) { return conn_.transportSettings.ackDelayExponent; });
  auto largestAckedPacketNum = *largestAckToSend(ackState_);
  auto ackingTime = ClockType::now();
  DCHECK(ackState_.largestRecvdPacketTime.hasValue())
      << "Missing received time for the largest acked packet";
  // assuming that we're going to ack the largest received with hightest pri
  auto receivedTime = *ackState_.largestRecvdPacketTime;
  std::chrono::microseconds ackDelay =
      (ackingTime > receivedTime
           ? std::chrono::duration_cast<std::chrono::microseconds>(
                 ackingTime - receivedTime)
           : 0us);
  AckFrameMetaData meta(ackState_.acks, ackDelay, ackDelayExponentToUse);
  auto ackWriteResult = writeAckFrame(meta, builder);
  if (!ackWriteResult) {
    return folly::none;
  }
  return largestAckedPacketNum;
}
} // namespace quic
