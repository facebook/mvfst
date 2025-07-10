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
[[nodiscard]] quic::Expected<void, QuicError> sendStopSendingSMHandler(
    QuicStreamState& stream,
    const StopSendingFrame& frame);

[[nodiscard]] quic::Expected<void, QuicError> sendRstSMHandler(
    QuicStreamState& stream,
    ApplicationErrorCode errorCode,
    const Optional<uint64_t>& reliableSize = std::nullopt);

[[nodiscard]] quic::Expected<void, QuicError> sendAckSMHandler(
    QuicStreamState& stream,
    const WriteStreamFrame& ackedFrame);

[[nodiscard]] quic::Expected<void, QuicError> sendRstAckSMHandler(
    QuicStreamState& stream,
    Optional<uint64_t> reliableSize);

} // namespace quic
