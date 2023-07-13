/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#pragma once

#include <folly/Range.h>
#include <folly/SocketAddress.h>
#include <folly/io/IOBuf.h>
#include <folly/io/async/AsyncUDPSocket.h>
#include <folly/portability/Sockets.h>
#include <quic/common/Events.h>

namespace quic {

using QuicAsyncUDPSocketType = folly::AsyncUDPSocket;
using NetworkFdType = folly::NetworkSocket;

int getSocketFd(const QuicAsyncUDPSocketType& s);
NetworkFdType toNetworkFdType(int fd);

class QuicAsyncUDPSocketWrapper {
 public:
  using ReadCallback = QuicAsyncUDPSocketType::ReadCallback;
  using ErrMessageCallback = QuicAsyncUDPSocketType::ErrMessageCallback;
};

} // namespace quic
