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
[[nodiscard]] folly::Expected<folly::Unit, QuicError> sendStopSendingSMHandler(
    QuicStreamState& stream,
    const StopSendingFrame& frame);

[[nodiscard]] folly::Expected<folly::Unit, QuicError> sendRstSMHandler(
    QuicStreamState& stream,
    ApplicationErrorCode errorCode,
    const Optional<uint64_t>& reliableSize = folly::none);

[[nodiscard]] folly::Expected<folly::Unit, QuicError> sendAckSMHandler(
    QuicStreamState& stream,
    const WriteStreamFrame& ackedFrame);

[[nodiscard]] folly::Expected<folly::Unit, QuicError> sendRstAckSMHandler(
    QuicStreamState& stream,
    folly::Optional<uint64_t> reliableSize);

} // namespace quic
