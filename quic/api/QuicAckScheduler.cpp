/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <quic/api/QuicAckScheduler.h>

namespace quic {

bool hasAcksToSchedule(const AckState& ackState) {
  Optional<PacketNum> largestAckSend = largestAckToSend(ackState);
  if (!largestAckSend) {
    return false;
  }
  if (!ackState.largestAckScheduled) {
    // Never scheduled an ack, we need to send
    return true;
  }
  return *largestAckSend > *(ackState.largestAckScheduled);
}

Optional<PacketNum> largestAckToSend(const AckState& ackState) {
  if (ackState.acks.empty()) {
    return std::nullopt;
  }
  return ackState.acks.back().end;
}

AckScheduler::AckScheduler(
    const QuicConnectionStateBase& conn,
    const AckState& ackState)
    : conn_(conn), ackState_(ackState) {}

quic::Expected<Optional<PacketNum>, QuicError> AckScheduler::writeNextAcks(
    PacketBuilderInterface& builder) {
  // Use default ack delay for long headers. Usually long headers are sent
  // before crypto negotiation, so the peer might not know about the ack delay
  // exponent yet, so we use the default.
  uint8_t ackDelayExponentToUse =
      builder.getPacketHeader().getHeaderForm() == HeaderForm::Long
      ? kDefaultAckDelayExponent
      : conn_.transportSettings.ackDelayExponent;
  auto largestAckedPacketNum = *largestAckToSend(ackState_);
  auto ackingTime = Clock::now();
  MVDCHECK(
      ackState_.largestRecvdPacketTime.has_value(),
      "Missing received time for the largest acked packet");
  // assuming that we're going to ack the largest received with highest pri
  auto receivedTime = *ackState_.largestRecvdPacketTime;
  std::chrono::microseconds ackDelay =
      (ackingTime > receivedTime
           ? std::chrono::duration_cast<std::chrono::microseconds>(
                 ackingTime - receivedTime)
           : 0us);

  WriteAckFrameMetaData meta = {
      ackState_, /* ackState*/
      ackDelay, /* ackDelay */
      static_cast<uint8_t>(ackDelayExponentToUse), /* ackDelayExponent */
      conn_.connectionTime, /* connect timestamp */
  };

  auto ackWriteResult =
      [&]() -> quic::Expected<Optional<WriteAckFrameResult>, QuicError> {
    uint64_t peerRequestedTimestampsCount =
        conn_.maybePeerAckReceiveTimestampsConfig.has_value()
        ? conn_.maybePeerAckReceiveTimestampsConfig.value()
              .maxReceiveTimestampsPerAck
        : 0;

    if (conn_.negotiatedExtendedAckFeatures > 0) {
      // The peer supports extended ACKs and we have them enabled.
      return writeAckFrame(
          meta,
          builder,
          FrameType::ACK_EXTENDED,
          conn_.transportSettings.maybeAckReceiveTimestampsConfigSentToPeer
              .value_or(AckReceiveTimestampsConfig()),
          peerRequestedTimestampsCount,
          conn_.negotiatedExtendedAckFeatures);
    } else if (
        conn_.transportSettings.readEcnOnIngress &&
        (meta.ackState.ecnECT0CountReceived ||
         meta.ackState.ecnECT1CountReceived ||
         meta.ackState.ecnCECountReceived)) {
      // We have to report ECN counts, but we can't use the extended ACK
      // frame. In this case, we give ACK_ECN precedence over
      // ACK_RECEIVE_TIMESTAMPS.
      return writeAckFrame(meta, builder, FrameType::ACK_ECN);
    } else if (conn_.negotiatedAckReceiveTimestampSupport) {
      // Use ACK_RECEIVE_TIMESTAMPS if its enabled on both endpoints AND the
      // peer requests at least 1 timestamp
      return writeAckFrame(
          meta,
          builder,
          FrameType::ACK_RECEIVE_TIMESTAMPS,
          conn_.transportSettings.maybeAckReceiveTimestampsConfigSentToPeer
              .value(),
          peerRequestedTimestampsCount);
    } else {
      return writeAckFrame(meta, builder, FrameType::ACK);
    }
  }();

  if (!ackWriteResult.has_value()) {
    return quic::make_unexpected(ackWriteResult.error());
  }

  if (!ackWriteResult.value()) {
    return std::nullopt;
  }

  return largestAckedPacketNum;
}

bool AckScheduler::hasPendingAcks() const {
  return hasAcksToSchedule(ackState_);
}
} // namespace quic
