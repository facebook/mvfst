/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#pragma once

#include <quic/state/StateData.h>

namespace quic {

// Common operations to conduct on QuicStreamState when send reset on it
[[nodiscard]] quic::Expected<void, QuicError> resetQuicStream(
    QuicStreamState& stream,
    ApplicationErrorCode error,
    Optional<uint64_t> reliableSize = std::nullopt);

// Common operations to conduct on QuicStreamState when receive reset on it
[[nodiscard]] quic::Expected<void, QuicError> onResetQuicStream(
    QuicStreamState& stream,
    const RstStreamFrame& frame);

bool isAllDataReceived(const QuicStreamState& stream);

// Returns true if the QUIC layer has read all data up to and including the
// given offset. This function can still return true even if the application has
// not read all of it.
bool isAllDataReceivedUntil(const QuicStreamState& stream, uint64_t offset);

// Retires the receive side of a stream whose application will not read it
// again: buffered ingress is dropped, later ingress is only accounted for flow
// control, and the receive side closes once the peer's final size is known.
[[nodiscard]] quic::Expected<void, QuicError> retireIngress(
    QuicStreamState& stream);

// Closes a retired receive side if the peer's final size is known, counting
// every byte up to the final size as consumed for flow control.
[[nodiscard]] quic::Expected<void, QuicError> maybeCloseRetiredIngress(
    QuicStreamState& stream);
} // namespace quic
