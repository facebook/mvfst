/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#pragma once

#include <folly/io/async/test/MockAsyncUDPSocket.h>
#include <quic/common/QuicAsyncUDPSocketWrapper.h>

namespace quic::test {

using MockAsyncUDPSocket =
    folly::test::MockAsyncUDPSocketT<quic::QuicAsyncUDPSocketWrapperImpl>;

} // namespace quic::test
