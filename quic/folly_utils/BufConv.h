/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#pragma once

#include <folly/io/IOBuf.h>
#include <quic/common/QuicBuffer.h>

namespace quic::follyutils {

std::unique_ptr<folly::IOBuf> toIOBuf(std::unique_ptr<quic::QuicBuffer>&& buf);

std::unique_ptr<quic::QuicBuffer> toQuicBuf(
    std::unique_ptr<folly::IOBuf>&& buf);

} // namespace quic::follyutils
