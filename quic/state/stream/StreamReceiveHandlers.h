/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#pragma once

#include <quic/state/QuicStreamFunctions.h>
#include <quic/state/QuicStreamUtilities.h>

namespace quic {
[[nodiscard]] folly::Expected<folly::Unit, QuicError>
receiveReadStreamFrameSMHandler(
    QuicStreamState& stream,
    ReadStreamFrame&& frame);

[[nodiscard]] folly::Expected<folly::Unit, QuicError> receiveRstStreamSMHandler(
    QuicStreamState& stream,
    const RstStreamFrame& rst);

} // namespace quic
