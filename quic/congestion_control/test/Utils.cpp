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

} // namespace quic::test
