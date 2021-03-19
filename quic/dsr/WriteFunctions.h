/*
 * Copyright (c) Facebook, Inc. and its affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 *
 */

#pragma once

#include <quic/api/QuicTransportFunctions.h>
#include <quic/codec/QuicConnectionId.h>
#include <quic/dsr/DSRPacketizationRequestSender.h>
#include <quic/dsr/Scheduler.h>
#include <quic/handshake/Aead.h>
#include <quic/state/StateData.h>

namespace quic {
// TODO: Let stream owns the sender to make them 1:1 mapping instead of having
// a connection to sender 1:1 mapping.
uint64_t writePacketizationRequest(
    QuicConnectionStateBase& connection,
    DSRStreamFrameScheduler& scheduler,
    const ConnectionId& dstCid,
    size_t packetLimit,
    const Aead& aead,
    DSRPacketizationRequestSender& sender);
} // namespace quic
