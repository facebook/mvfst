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
void resetQuicStream(
    QuicStreamState& stream,
    ApplicationErrorCode error,
    Optional<uint64_t> reliableSize = folly::none);

// Common operations to conduct on QuicStreamState when receive reset on it
void onResetQuicStream(QuicStreamState& stream, const RstStreamFrame& frame);

bool isAllDataReceived(const QuicStreamState& stream);

// Returns true if the QUIC layer has read all data up to and including the
// given offset. This function can still return true even if the application has
// not read all of it.
bool isAllDataReceivedUntil(const QuicStreamState& stream, uint64_t offset);
} // namespace quic
