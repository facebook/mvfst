/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#pragma once

#include <quic/state/QuicStreamUtilities.h>
#include <quic/state/stream/StreamStateFunctions.h>

namespace quic {

void sendStopSendingSMHandler(
    QuicStreamState& stream,
    const StopSendingFrame& frame);

void sendRstSMHandler(QuicStreamState& stream, ApplicationErrorCode errorCode);

void sendAckSMHandler(
    QuicStreamState& stream,
    const WriteStreamFrame& ackedFrame);

void sendRstAckSMHandler(QuicStreamState& stream);

} // namespace quic
