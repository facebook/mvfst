/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#pragma once

#include <quic/codec/Types.h>
#include <quic/common/Expected.h>
#include <quic/state/StateData.h>

namespace quic {

/*
 * Initiate a send of the given simple frame.
 */
void sendSimpleFrame(QuicConnectionStateBase& conn, QuicSimpleFrame frame);

/*
 * Update connection state and the frame on clone of the given simple frame.
 * Returns the updated simple frame.
 */
Optional<QuicSimpleFrame> updateSimpleFrameOnPacketClone(
    QuicConnectionStateBase& conn,
    PathIdType pathId,
    const QuicSimpleFrame& frame);

/*
 * Update the connection state after sending the given simple frame.
 */
void updateSimpleFrameOnPacketSent(
    QuicConnectionStateBase& conn,
    PathIdType pathId,
    const QuicSimpleFrame& simpleFrame);

/*
 * Update the connection state after loss of a given simple frame.
 */

void updateSimpleFrameOnPacketLoss(
    QuicConnectionStateBase& conn,
    PathIdType pathId,
    const QuicSimpleFrame& frame);

/*
 * Update the connection state on receipt of the given simple frame.
 * Returns true if the frame is NOT a probing frame
 */
[[nodiscard]] quic::Expected<bool, QuicError> updateSimpleFrameOnPacketReceived(
    QuicConnectionStateBase& conn,
    PathIdType pathId,
    const QuicSimpleFrame& frameIn,
    const ConnectionId& dstConnId);
} // namespace quic
