/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#pragma once

#include <folly/io/SocketOptionMap.h>
#include <folly/net/NetOps.h>
#include <quic/common/QuicAsyncUDPSocketWrapper.h>

namespace quic {

bool isNetworkUnreachable(int err);

void applySocketOptions(
    QuicAsyncUDPSocketWrapper& sock,
    const folly::SocketOptionMap& options,
    sa_family_t family,
    folly::SocketOptionKey::ApplyPos pos) noexcept;

} // namespace quic
