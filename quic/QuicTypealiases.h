/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#pragma once

#include <folly/io/IOBuf.h>

namespace quic {

using ByteRange = folly::ByteRange;
using MutableByteRange = folly::MutableByteRange;
using BufHelpers = folly::IOBuf; // For stuff like BufHelpers::create, etc.
using Buf = folly::IOBuf; // Used when we're not wrapping the buffer in an
                          // std::unique_ptr
using BufPtr = std::unique_ptr<Buf>;
using BufEq = folly::IOBufEqualTo;

} // namespace quic
