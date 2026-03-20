/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#pragma once

#include <quic/common/QuicBuffer.h>
#include <quic/common/QuicIOBufQueue.h>
#include <quic/common/QuicRange.h>
#include <memory>

namespace folly {
class SocketAddress;
} // namespace folly

namespace quic {

using AddressRange = quic::Range<folly::SocketAddress const*>;
using ByteRange = quic::ByteRange;
using MutableByteRange = quic::MutableByteRange;
using BufHelpers = quic::QuicBuffer; // For stuff like BufHelpers::create, etc.
using Buf = quic::QuicBuffer; // Used when we're not wrapping the buffer in an
                              // std::unique_ptr
using BufPtr = std::unique_ptr<quic::QuicBuffer>;
using BufEq = quic::QuicBufferEqualTo;
using IOBufQueue = quic::QuicIOBufQueue;

} // namespace quic
