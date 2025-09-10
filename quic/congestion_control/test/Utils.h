/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#pragma once

#include <quic/congestion_control/CongestionController.h>
#include <quic/state/StateData.h>

namespace quic::test {

/**
 * Wrapper function for sending packets that updates inflight bytes
 * and calls the congestion controller's onPacketSent method.
 * This eliminates code duplication across test files.
 */
void onPacketsSentWrapper(
    quic::QuicConnectionStateBase* conn,
    quic::CongestionController* cc,
    const quic::OutstandingPacketWrapper& packet);

void onPacketAckOrLossWrapper(
    quic::QuicConnectionStateBase* conn,
    quic::CongestionController* cc,
    quic::Optional<quic::AckEvent> ack,
    quic::Optional<quic::CongestionController::LossEvent> loss);

void removeBytesFromInflight(
    quic::QuicConnectionStateBase* conn,
    uint64_t bytesToRemove,
    quic::CongestionController* cc);
} // namespace quic::test
