/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <quic/api/QuicAckScheduler.h>

#include <quic/codec/QuicWriteCodec.h>
#include <quic/logging/oops_logger/OopsLogger.h>
#include <quic/state/ConnectionOopsFields.h>

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
  PROTO_OOPS_LOG_BUILDER_IF(
      conn_.nodeType == QuicNodeType::Server &&
          !ackState_.largestRecvdPacketTime.has_value(),
      conn_.oopsLogger,
      proto_oops::makeConnectionSpecificOopsFieldsBuilder(conn_),
      "quic_ack_scheduler",
      "invariant_violation: ACK scheduler missing largest received packet "
      "time");
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
    const uint64_t peerRequestedTimestampsCount =
        conn_.maybePeerReceiveTimestampsConfig.has_value()
        ? conn_.maybePeerReceiveTimestampsConfig->maxReceiveTimestampsPerAck
        : 0;
    const bool ecnRequiresReporting =
        conn_.transportSettings.readEcnOnIngress &&
        (meta.ackState.ecnECT0CountReceived ||
         meta.ackState.ecnECT1CountReceived ||
         meta.ackState.ecnCECountReceived);
    // ACK_RECEIVE_TIMESTAMPS (both draft-02 and legacy mvfst) is 1-RTT only
    // per spec. Initial/Handshake spaces fall through to plain
    // `ACK`/`ACK_ECN`.
    const bool isAppDataSpace =
        builder.getPacketHeader().getPacketNumberSpace() ==
        PacketNumberSpace::AppData;

    // Priority: draft-02 wins over ACK_EXTENDED and ACK_ECN because the
    // draft-02 _ECN variant inlines the ECN counts in a single frame.
    // draft-02 selection implies a populated peer config (both set together in
    // updateNegotiatedAckFeatures). Guard the deref locally so an inconsistent
    // state degrades to a plain ACK instead of a null deref in opt builds.
    if (isAppDataSpace &&
        conn_.negotiatedOutgoingAckReceiveTimestampsVersion ==
            AckReceiveTimestampsVersion::DraftIetf02 &&
        conn_.maybePeerReceiveTimestampsConfig.has_value()) {
      const FrameType ft = ecnRequiresReporting
          ? FrameType::ACK_RECEIVE_TIMESTAMPS_DRAFT_02_ECN
          : FrameType::ACK_RECEIVE_TIMESTAMPS_DRAFT_02;
      return writeAckFrameDraft02(
          meta,
          builder,
          ft,
          conn_.maybePeerReceiveTimestampsConfig->exponent,
          peerRequestedTimestampsCount);
    }

    if (conn_.negotiatedExtendedAckFeatures > 0) {
      return writeAckFrame(
          meta,
          builder,
          FrameType::ACK_EXTENDED,
          conn_.transportSettings.maybeAckReceiveTimestampsConfigSentToPeer
              .value_or(AckReceiveTimestampsConfig()),
          peerRequestedTimestampsCount,
          conn_.negotiatedExtendedAckFeatures);
    } else if (ecnRequiresReporting) {
      // Legacy mvfst format can't carry ECN counts, so prefer ACK_ECN over
      // ACK_RECEIVE_TIMESTAMPS when both apply (draft-02 case above already
      // handles the combined form).
      return writeAckFrame(meta, builder, FrameType::ACK_ECN);
    } else if (isAppDataSpace && conn_.negotiatedAckReceiveTimestampSupport) {
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
