/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#pragma once

#include <quic/common/QuicEventBase.h>

#ifdef MVFST_USE_LIBEV
#include <quic/common/QuicAsyncUDPSocketImpl.h>
#else
#include <folly/io/async/AsyncUDPSocket.h>
#endif

namespace quic {

#ifdef MVFST_USE_LIBEV
using QuicAsyncUDPSocketType = QuicAsyncUDPSocketImpl;
#else
using QuicAsyncUDPSocketType = folly::AsyncUDPSocket;
using NetworkFdType = folly::NetworkSocket;
#endif

int getSocketFd(const QuicAsyncUDPSocketType& s);
NetworkFdType toNetworkFdType(int fd);

class QuicAsyncUDPSocketWrapper {
 public:
  using ReadCallback = QuicAsyncUDPSocketType::ReadCallback;
  using ErrMessageCallback = QuicAsyncUDPSocketType::ErrMessageCallback;
};

} // namespace quic
