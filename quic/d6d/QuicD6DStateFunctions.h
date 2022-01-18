/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#pragma once
#include <quic/state/StateData.h>

namespace quic {

void onD6DProbeTimeoutExpired(QuicConnectionStateBase& conn);

void onD6DRaiseTimeoutExpired(QuicConnectionStateBase& conn);

void onD6DLastProbeAcked(QuicConnectionStateBase& conn);

void onD6DLastProbeLost(QuicConnectionStateBase& conn);

void detectPMTUBlackhole(
    QuicConnectionStateBase& conn,
    const OutstandingPacket& packet);

} // namespace quic
