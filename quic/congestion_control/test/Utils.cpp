/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <quic/congestion_control/test/Utils.h>

#include <quic/congestion_control/CongestionControlFunctions.h>

namespace quic::test {

void onPacketsSentWrapper(
    quic::QuicConnectionStateBase* conn,
    quic::CongestionController* cc,
    const quic::OutstandingPacketWrapper& packet) {
  quic::addAndCheckOverflow(
      conn->lossState.inflightBytes,
      packet.metadata.encodedSize,
      2 * conn->transportSettings.maxCwndInMss * conn->udpSendPacketLen);
  cc->onPacketSent(packet);
}

void onPacketAckOrLossWrapper(
    quic::QuicConnectionStateBase* conn,
    quic::CongestionController* cc,
    quic::Optional<quic::AckEvent> ack,
    quic::Optional<quic::CongestionController::LossEvent> loss) {
  if (loss) {
    quic::subtractAndCheckUnderflow(
        conn->lossState.inflightBytes, loss->lostBytes);
  }

  if (ack) {
    quic::subtractAndCheckUnderflow(
        conn->lossState.inflightBytes, ack->ackedBytes);
  }
  quic::AckEvent* ackEvent = (ack ? &(*ack) : nullptr);
  quic::CongestionController::LossEvent* lossEvent =
      (loss ? &(*loss) : nullptr);
  cc->onPacketAckOrLoss(ackEvent, lossEvent);
}

void removeBytesFromInflight(
    quic::QuicConnectionStateBase* conn,
    uint64_t bytesToRemove,
    quic::CongestionController* cc) {
  if (conn) {
    quic::subtractAndCheckUnderflow(
        conn->lossState.inflightBytes, bytesToRemove);
  }
  cc->onRemoveBytesFromInflight(bytesToRemove);
}

} // namespace quic::test
